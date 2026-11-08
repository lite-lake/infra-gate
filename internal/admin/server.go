package admin

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/lite-lake/infra-gate/internal/blacklist"
	"github.com/lite-lake/infra-gate/internal/cert"
	"github.com/lite-lake/infra-gate/internal/config"
	"github.com/lite-lake/infra-gate/internal/crs"
	"github.com/lite-lake/infra-gate/internal/faillock"
	"github.com/lite-lake/infra-gate/internal/infrastructs/logger"
	"github.com/lite-lake/infra-gate/internal/netutil"
	"github.com/lite-lake/infra-gate/internal/shipper"
	"github.com/lite-lake/infra-gate/internal/waf"
)

// apiKeyHeader 只读 API 认证头（AC 等内部系统轮询只读端点时携带，内部PRD §6.4）
const apiKeyHeader = "X-API-Key"

// AdminServer 管理后台服务器：
// 面板已拆除（内部PRD 迭代 4b），零自有管理页面——仅暴露只读 JSON API 与健康探针，
// 唯一认证通道为 X-API-Key（LITE_ADMIN_READONLY_API_KEYS），终端操作入口为 Admin Center。
// M4（内部PRD §6）：新增来源 IP 允许名单中间件——按直连对端评估（与 allowed_ips
// 边缘 ACL 同口径），未命中 403，含 /api/health、/api/ready 等免认证端点在内全部受限。
type AdminServer struct {
	cfg                *AdminConfig
	gateConfig         *config.Config
	certManager        *cert.Manager
	logger             logger.ILogger
	server             *http.Server
	getBackendHealth   func(hostName string) map[string]bool
	getWAFStats        func() []waf.StatsSnapshot
	getWAFEvents       func(int) []waf.WAFEvent
	findWAFEvent       func(int64) (waf.WAFEvent, bool)
	getBlacklistStats  func() blacklist.StatsSnapshot
	getBlacklistEvents func(int) []blacklist.BlacklistEvent
	getShipperStatus   func() shipper.StatusSnapshot
	getCRSStatus       func(version string) (crs.Status, bool)
	// F11（内部PRD §4.11.1）：WAF 降级/待重启 host 查询（/api/waf/stats 透出）
	getDegradedWAFHosts       func() []string
	getPendingRestartWAFHosts func() []string
	// allowedIPsNets 预解析的允许名单网段（M4）：nil + Unlimited=true = 不限制；
	// 其余情况非空（条目已在 LoadFromEnv fail-fast 校验格式）
	allowedIPsNets []*net.IPNet
	// apiFaillock F13.2（内部PRD §4.13.2）：只读 API 认证失败锁定——
	// 直连对端 IP 维度（admin 已 SetTrustedProxies(nil)），阈值/时长共用
	// config.DefaultAuth* 单一事实源（数据面 M1 三段式同款）；正确 key 永不触发，
	// key 轮换配错时锁 15 分钟 + 告警恰是期望暴露
	apiFaillock *faillock.Limiter
	// notifier F13.2：锁定跳变沿全局告警（admin_api_lockout；接口模式复制
	// auth.LockoutNotifier，main 经 SetNotifier 注入，未注入 no-op）
	notifier adminNotifier
}

// adminNotifier admin 事件通知接口（*notification.Notifier 天然满足；接口化解耦）
type adminNotifier interface {
	SendNotification(event string, details map[string]string) error
}

// NewAdminServer 创建管理后台服务器
func NewAdminServer(cfg *AdminConfig, gateConfig *config.Config, certManager *cert.Manager, log logger.ILogger) *AdminServer {
	// 允许名单预解析一次（条目格式已由 LoadFromEnv 校验）；显式空串逃生口
	//（Unlimited）保持 nil，请求链零开销跳过
	var allowedNets []*net.IPNet
	if !cfg.AllowedIPsUnlimited {
		allowedNets = netutil.ParseTrustedProxies(cfg.AllowedIPs)
	}
	return &AdminServer{
		cfg:            cfg,
		gateConfig:     gateConfig,
		certManager:    certManager,
		logger:         log,
		allowedIPsNets: allowedNets,
		// F13.2：缺省 5 次 / 15 分钟（与数据面密码门共用 config.DefaultAuth*）
		apiFaillock: faillock.NewLimiter(config.DefaultAuthMaxFailures, config.DefaultAuthLockDuration),
	}
}

// buildEngine 装配 admin 引擎（Start 与单测共用，装配链绑定）：
// Recovery → 来源 IP 允许名单（M4）→ Host 校验 → 安全响应头 → 路由注册。
// 单测（allowed_ips_test.go 等）经本函数取得与 Start 完全一致的中间件链——
// Start 侧漏注册/乱序调整中间件时单测同步失败。语句与顺序逐行等价于
// 提取前 Start 内联装配，生产行为零变化。
func (a *AdminServer) buildEngine() *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	engine := gin.New()
	engine.Use(gin.Recovery())
	// M4：来源 IP 允许名单先于 Host 校验（连接层 ACL 最先评估，非名单内来源一律
	// 403，不再泄露 Host 校验等其他面信息）
	engine.Use(a.allowedIPsMiddleware())
	engine.Use(a.hostCheckMiddleware())
	// H7/H10: Admin 安全响应头中间件
	engine.Use(a.securityHeadersMiddleware())

	// 不信任任何代理，c.ClientIP() 直接使用 RemoteAddr（只读 API 日志中的来源 IP 防伪造）
	_ = engine.SetTrustedProxies(nil)

	// F13.4（内部PRD §4.13.4）：访问审计日志——分级全量（admin QPS 极低不采样）：
	// 认证成功 Info（对齐 shipper record 命名）、401/403/429 与 5xx Warn 补全字段、
	// 免认证探针 Debug（防 kuma 刷屏）；绝不记录 X-API-Key 本身
	engine.Use(a.accessLogMiddleware())

	a.registerRoutes(engine)
	return engine
}

// Start 启动管理后台
func (a *AdminServer) Start() error {
	// M4（内部PRD §6/决策 D3）：显式空串逃生口与明文 HTTP 各 Warn 一条——
	// 两者都属「可用性逃生但安全弱化」的运行态，禁止静默
	if a.cfg.AllowedIPsUnlimited {
		a.logger.Warn("Admin IP allowlist DISABLED via LITE_ADMIN_ALLOWED_IPS='': admin endpoints (including unauthenticated probes) are reachable from any source; set explicit IP/CIDR entries to restore the allowlist (内部PRD M4/D3)",
			logger.NewField("env", allowedIPsEnvVar))
	}
	if !a.cfg.HTTPS {
		a.logger.Warn("Admin server runs on plaintext HTTP (LITE_ADMIN_HTTPS=false): X-API-Key and admin payloads are transmitted unencrypted and readable on the wire (内部PRD M4)",
			logger.NewField("env", "LITE_ADMIN_HTTPS"))
	}

	engine := a.buildEngine()

	addr := fmt.Sprintf(":%d", a.cfg.Port)
	a.server = &http.Server{
		Addr:              addr,
		Handler:           engine,
		ReadHeaderTimeout: 10 * time.Second, // H9: Slowloris 防护
		ReadTimeout:       30 * time.Second, // H9: 限制读取完整请求的时间
		WriteTimeout:      30 * time.Second, // H9: 限制写响应的时间
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	if a.cfg.HTTPS {
		return a.startHTTPS(engine)
	}

	go func() {
		a.logger.Info("Admin server starting (HTTP)",
			logger.NewField("addr", addr),
			logger.NewField("domain", a.cfg.Domain))
		if err := a.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			a.logger.Error("Admin server failed", logger.NewField("error", err))
		}
	}()
	return nil
}

func (a *AdminServer) startHTTPS(engine *gin.Engine) error {
	certPair, err := a.certManager.LoadCertificate(a.cfg.Domain, a.gateConfig.SSL)
	if err != nil {
		// 证书加载失败时拒绝启动，而非降级到 HTTP 明文传输只读 API Key
		return fmt.Errorf("failed to load certificate for admin HTTPS server (domain %s): %w", a.cfg.Domain, err)
	}

	tlsConfig := &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return a.certManager.GetCertificate(a.cfg.Domain)
		},
		MinVersion:               tls.VersionTLS12,
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
	}
	a.server.TLSConfig = tlsConfig

	_ = certPair

	go func() {
		a.logger.Info("Admin server starting (HTTPS)",
			logger.NewField("addr", a.server.Addr),
			logger.NewField("domain", a.cfg.Domain))
		if err := a.server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			a.logger.Error("Admin server failed (HTTPS)", logger.NewField("error", err))
		}
	}()
	return nil
}

// SetNotifier 注入 admin 事件通知器（F13.2：admin_api_lockout 锁定告警）。
// main.go 在 adminSrv.Start() 之前调用；未注入（如单测）时告警 no-op
func (a *AdminServer) SetNotifier(n adminNotifier) {
	a.notifier = n
}

// notifyAPILockout F13.2：IP 触发锁定阈值的全局告警（跳变沿去重由
// faillock.RecordFailure 保证——每个锁定会话至多一条）
func (a *AdminServer) notifyAPILockout(clientIP string, failures int) {
	if a.notifier == nil {
		return
	}
	a.logger.Warn("Admin API lockout triggered, sending global notification",
		logger.NewField("client_ip", clientIP),
		logger.NewField("failures", failures))
	_ = a.notifier.SendNotification("admin_api_lockout", map[string]string{
		"client_ip": clientIP,
		"失败次数":      strconv.Itoa(failures),
		"锁定时长":      config.DefaultAuthLockDuration.String(),
		"风险":        "admin 只读 API Key 正被持续爆破，来源 IP 已被锁定",
	})
}

// Stop 关闭管理后台
func (a *AdminServer) Stop() {
	if a.server == nil {
		return
	}
	a.logger.Info("Shutting down admin server...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	a.server.Shutdown(ctx)
}

// allowedIPsMiddleware 来源 IP 允许名单（M4，内部PRD §6/决策 D3）：
//   - 按直连对端（TCP RemoteAddr，不做 XFF 解析）评估——与数据面 allowed_ips 边缘 ACL
//     同口径（"谁能连到管理面"），不受伪造 XFF 影响；
//   - 未命中 → 403 并终止；作用于全部端点，免认证探针（/api/health、/api/ready、
//     /api/shipper/status）同样受限；
//   - LITE_ADMIN_ALLOWED_IPS 未设置 → 默认私网+回环（DefaultAdminAllowedIPs，覆盖
//     mesh 10.61/10.62）；显式空串（AllowedIPsUnlimited）→ 中间件整体跳过（零开销）。
func (a *AdminServer) allowedIPsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if a.cfg.AllowedIPsUnlimited {
			c.Next()
			return
		}
		directIP := c.Request.RemoteAddr
		if host, _, err := net.SplitHostPort(directIP); err == nil {
			directIP = host
		}
		ip := net.ParseIP(directIP)
		if ip == nil || !netutil.IsIPInNetworks(ip, a.allowedIPsNets) {
			a.logger.Warn("Admin request from disallowed source IP",
				logger.NewField("ip", directIP),
				logger.NewField("path", c.Request.URL.Path))
			c.String(http.StatusForbidden, "Forbidden")
			c.Abort()
			return
		}
		c.Next()
	}
}

// hostCheckMiddleware 校验 Host 头（Host 必须等于 LITE_ADMIN_DOMAIN，面板拆除后保留）
func (a *AdminServer) hostCheckMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// F3（内部PRD §4.3.3）：请求 Host 与配置 Domain 双侧 CanonicalHost
		// 归一化比对（大小写/尾点/带端口变体等价）
		host := netutil.CanonicalHost(c.Request.Host)
		if host != netutil.CanonicalHost(a.cfg.Domain) {
			c.String(http.StatusNotFound, "Not Found")
			c.Abort()
			return
		}
		c.Next()
	}
}

// securityHeadersMiddleware H7/H10: Admin 响应安全头
func (a *AdminServer) securityHeadersMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Referrer-Policy", "no-referrer")
		c.Header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'self'")
		if a.cfg.HTTPS {
			c.Header("Strict-Transport-Security", config.DefaultHSTSValue)
		}
		c.Next()
	}
}

// registerRoutes 注册路由。
// 面板拆除（内部PRD 迭代 4b，§9.2）后仅剩：
//   - 免认证健康探针 /api/health、/api/ready 与 shipper 状态探针 /api/shipper/status
//     （供监控探测，仍受 Host 校验约束；shipper 端点见 内部PRD §6.1，
//     配置缺段返回 200 + enabled:false，"组件消失"由监控断言失败告警而非 404/500）
//   - 8 个只读 GET（/api/sites、/api/certs、/api/system、/api/waf/{stats,events,events/:id}、
//     /api/blacklist/{stats,events}），唯一通道为 X-API-Key
//
// 页面路由（/、/sites、/certs、/waf、/blacklist）、/login、/logout 与静态资源全部拆除，访问返回 404。
func (a *AdminServer) registerRoutes(engine *gin.Engine) {
	// 免认证健康检查端点（与 lite-backend /api/health、/api/ready 对齐）：
	// 不走认证，供 Uptime Kuma 等监控探测。仍需通过全局 host 校验（Host = LITE_ADMIN_DOMAIN）
	engine.GET("/api/health", a.handleHealth)
	engine.GET("/api/ready", a.handleReady)
	// shipper 状态探针（内部PRD §6.1）：与 health/ready 同级免认证——
	// 定位是监控探针而非管理面读 API，json-query 断言 enabled/running 字段；
	// 不进 X-API-Key readonlyAPIGroup，Host 校验中间件对它仍然生效
	engine.GET("/api/shipper/status", a.handleAPIShipperStatus)

	// 只读 API 认证（内部PRD §6.4）：仅 X-API-Key 通道，无任何会话回退
	readonlyAPIGroup := engine.Group("/")
	readonlyAPIGroup.Use(a.readonlyAPIAuth())
	{
		readonlyAPIGroup.GET("/api/sites", a.handleAPISites)
		readonlyAPIGroup.GET("/api/certs", a.handleAPICerts)
		readonlyAPIGroup.GET("/api/system", a.handleAPISystem)
		readonlyAPIGroup.GET("/api/waf/stats", a.handleAPIWAFStats)
		readonlyAPIGroup.GET("/api/waf/events", a.handleAPIWAFEvents)
		readonlyAPIGroup.GET("/api/waf/events/:id", a.handleAPIWAFEventDetail)
		readonlyAPIGroup.GET("/api/blacklist/stats", a.handleAPIBlacklistStats)
		readonlyAPIGroup.GET("/api/blacklist/events", a.handleAPIBlacklistEvents)
	}
}

// probePaths 免认证探针路径（审计日志 Debug 级，防 kuma 刷屏）
var probePaths = map[string]bool{
	"/api/health":         true,
	"/api/ready":          true,
	"/api/shipper/status": true,
}

// accessLogMiddleware F13.4 访问审计日志：分级全量记录 admin 面请求。
// 字段对齐 shipper record 命名（method/path/status/client_ip/latency_ms）；
// 绝不记录 X-API-Key 本身（只记认证结果状态码）
func (a *AdminServer) accessLogMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		directIP := netutil.DirectRemoteIP(c.Request)
		fields := []logger.Field{
			logger.NewField("method", c.Request.Method),
			logger.NewField("path", c.Request.URL.Path),
			logger.NewField("status", c.Writer.Status()),
			logger.NewField("client_ip", directIP),
			logger.NewField("latency_ms", time.Since(start).Milliseconds()),
		}
		status := c.Writer.Status()
		switch {
		case probePaths[c.Request.URL.Path] && status < 400:
			a.logger.Debug("Admin access", fields...)
		case status == http.StatusUnauthorized || status == http.StatusForbidden ||
			status == http.StatusTooManyRequests || status >= 500:
			a.logger.Warn("Admin access denied", fields...)
		default:
			a.logger.Info("Admin access", fields...)
		}
	}
}

// readonlyAPIAuth 只读 API 认证中间件（面板拆除后唯一管理面通道）。
// F13.2（内部PRD §4.13.2）三段式（对齐数据面 M1 模式）：
//  1. 锁定检查：直连对端 IP（admin 已 SetTrustedProxies(nil)，XFF 不可污染）
//     IsLocked → 429（不读 key 不暴露正确性）；
//  2. key 校验：命中（常数时间比较，见 AdminConfig.ValidReadOnlyAPIKey）→
//     Reset 清零放行；正确 key 永不触发限速；
//  3. 失败：RecordFailure，跳变沿发 admin_api_lockout 告警 → 401。
//     - 未携带或未命中（含未配置任何 key 的情况）→ 401 JSON，不再回退会话认证。
func (a *AdminServer) readonlyAPIAuth() gin.HandlerFunc {
	// 惰性兜底：部分单测以结构体字面量构造 AdminServer（不经 NewAdminServer），
	// 确保 limiter 恒非 nil（registerRoutes 在启动期单线程调用一次）
	if a.apiFaillock == nil {
		a.apiFaillock = faillock.NewLimiter(config.DefaultAuthMaxFailures, config.DefaultAuthLockDuration)
	}
	return func(c *gin.Context) {
		directIP := netutil.DirectRemoteIP(c.Request)
		now := time.Now()
		if a.apiFaillock.IsLocked(directIP, now) {
			c.Header("Retry-After", "1")
			c.JSON(http.StatusTooManyRequests, gin.H{"code": 429, "message": "too many failed attempts"})
			c.Abort()
			return
		}
		if key := c.GetHeader(apiKeyHeader); key != "" && a.cfg.ValidReadOnlyAPIKey(key) {
			a.apiFaillock.Reset(directIP)
			c.Next()
			return
		}
		failures, locked := a.apiFaillock.RecordFailure(directIP, now)
		a.logger.Warn("只读 API Key 认证失败",
			logger.NewField("ip", directIP),
			logger.NewField("path", c.Request.URL.Path),
			logger.NewField("failures", failures))
		if locked {
			a.notifyAPILockout(directIP, failures)
		}
		c.JSON(http.StatusUnauthorized, gin.H{"code": 401, "message": "invalid api key"})
		c.Abort()
	}
}
