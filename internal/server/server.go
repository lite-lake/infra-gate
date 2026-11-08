package server

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
	"golang.org/x/net/http2"

	"github.com/lite-lake/infra-gate/internal/auth"
	"github.com/lite-lake/infra-gate/internal/blacklist"
	"github.com/lite-lake/infra-gate/internal/cert"
	"github.com/lite-lake/infra-gate/internal/config"
	"github.com/lite-lake/infra-gate/internal/crs"
	"github.com/lite-lake/infra-gate/internal/infrastructs/logger"
	"github.com/lite-lake/infra-gate/internal/middleware"
	"github.com/lite-lake/infra-gate/internal/netutil"
	"github.com/lite-lake/infra-gate/internal/proxy"
	"github.com/lite-lake/infra-gate/internal/resguard"
	"github.com/lite-lake/infra-gate/internal/shipper"
	"github.com/lite-lake/infra-gate/internal/templates"
	"github.com/lite-lake/infra-gate/internal/trace"
	"github.com/lite-lake/infra-gate/internal/waf"
)

// crsRefreshInterval CRS 后台自愈刷新循环间隔（内部PRD §5.4：每 30 分钟重建
// Manager 刷新，受同样下载预算约束；恢复后不热切换规则，下次重启生效，决策 D3）
const crsRefreshInterval = 30 * time.Minute

// Notifier 生命周期事件通知接口。定义于 server 包而非直接引用 *notification.Notifier：
// 避免 server → notification 反向依赖，便于测试注入 fake（与 cert.CertNotifier 同构；
// *notification.Notifier 的 SendNotification 签名天然满足该接口）。
type Notifier interface {
	SendNotification(event string, details map[string]string) error
}

// CRSStateSummary CRS 降级/过期状态摘要（供就绪通知、admin 与测试读取）
type CRSStateSummary struct {
	ConfigKeys []string // 受影响的 WAF configKey
	Versions   []string // 受影响的 CRS 版本
	Hosts      []string // 受影响的虚拟主机名
	LastErrors []string // 最近一次 CRS 失败原因（去重非空）
}

type Server struct {
	config           *config.Config
	proxies          map[string]*proxy.Proxy
	engines          map[int]*gin.Engine
	httpsEngines     map[int]*gin.Engine
	servers          map[int]*http.Server
	httpsServers     map[int]*http.Server
	wafByConfigKey   map[string]*waf.Middleware // configKey → WAF 实例（去重创建）
	wafByHost        map[string]*waf.Middleware // hostName → WAF 实例（路由查找）
	blacklistManager *blacklist.Manager         // IP 黑名单管理器，enabled=false 时保持 nil（零开销路径）
	// authByHost 密码门运行时实例（内部PRD）：仅 Auth 启用的 host 有条目，
	// 请求链检查点查表跳过（Auth==nil 零开销）。
	authByHost map[string]*auth.Manager
	// blacklistWhitelistNets 是 NewServer 时预解析的黑名单本地白名单（PRD §7.3）：
	// 非法条目 Warn+跳过，合法条目转为 []*net.IPNet，供请求链黑名单检查点直接使用，
	// 消除每请求重复解析 whitelist 字符串的开销。nil/空 = 无白名单（不豁免）。
	blacklistWhitelistNets []*net.IPNet
	// trustedProxyNets 是 NewServer 时无条件预解析一次的 TrustedProxies
	// （内部PRD §5.3）：供黑名单检查点与数据面 access log 的 ResolveClientIP
	// 使用，保证全链路"真实客户端 IP"口径一致。条目格式已由 config.Validate fail-fast
	// 校验。nil/空 = 不信任任何代理头（直连对端即真实客户端 IP）。
	// v1.1 定位补充：该网段数据同时是 forwarded_for=append host（mesh 域名）的追加
	// 门槛（proxy 侧由 NewProxy 传入的原始配置自行解析）；缺省 host（forwarded_for=""）
	// 恒为边缘语义，其转发头重建与 trusted_proxies 完全无关。
	trustedProxyNets []*net.IPNet
	certManager      *cert.Manager
	renderer         *templates.Renderer
	// notifier 生命周期事件通知器（内部PRD §5.6）：main.go 在 srv.Start() 之前
	// 经 SetNotifier 注入；未注入（如单测）时全部 no-op，不 panic
	notifier Notifier
	// ── CRS 降级/过期状态追踪（内部PRD §5.4）──
	// degradedConfigs degrade 策略下未创建 WAF 实例的配置（configKey → 配置）：
	// 对应 host 经 wafByHost 缺失自然无 WAF 启动；后台刷新恢复后收缩。
	// staleVersions 以旧缓存启动的 CRS 版本（version → last_error）。
	// wafConfigByKey / hostsByConfigKey 为 NewServer 填充的只读索引。
	// 三者经 crsStateMu 保护（NewServer 填充、自愈循环收缩、查询方法读取）。
	crsStateMu       sync.RWMutex
	degradedConfigs  map[string]config.WAFConfig
	staleVersions    map[string]string
	wafConfigByKey   map[string]config.WAFConfig
	hostsByConfigKey map[string][]string
	// ── CRS 后台自愈刷新循环（内部PRD §5.4/D3）──
	// 存在 degraded/stale 版本时启动；生命周期纳入 shutdownAllServers（blacklist.Stop 模式）
	crsRefreshStopOnce sync.Once
	crsRefreshStopChan chan struct{}
	crsRefreshWG       sync.WaitGroup
	crsRefreshTargets  map[string]config.WAFCRSConfig // version → 刷新用 CRS 配置
	crsRefreshFailures map[string]int                 // version → 连续失败计数（通知带重试计数）
	// pendingRestartConfigs F11.1（内部PRD §4.11.1）：后台刷新成功恢复但
	// 运行中的 WAF 实例仍是旧规则/降级状态的配置（重启后生效）；重启天然清零。
	// 修复观测缺陷：恢复后 crs_state=valid 而 host 仍无 WAF/旧规则，admin API
	// 完全不可见——经 /api/waf/stats 的 pending_restart_hosts 透出 + 30min 重发告警
	pendingRestartConfigs map[string]bool
	// trackerShipper 访问日志旁路 shipper（内部PRD §4.4.1）：
	// 仅 tracker_shipper.enabled=true 时非 nil；nil 时请求链 hook 零开销跳过
	// （等效于 shipper 不存在，旧配置零影响）。
	trackerShipper *shipper.Shipper
	// ── F1 资源治理（内部PRD §4.1）──
	// reqSemaphore 全局 + per-IP 并发信号量（F1a）：nil = resource_governance.enabled=false
	// （逃生口，启动 Warn）；挂点为两个 start*Server 中间件链 ginLogger 之后。
	// IP 口径复用 ResolveClientIP + trustedProxyNets（与黑名单/访问日志一致）。
	reqSemaphore *resguard.Semaphore
	// ipRateLimiter per-IP 令牌桶限速（F1b）：nil 同上；挂 handleRequestForPort
	// 黑名单之后（超速 429 + Retry-After: 1）。
	ipRateLimiter *resguard.RateLimiter
	// wsConnLimiter WS 连接三级上限（F1d）：nil 同上；经 WSConfig 注入各 proxy
	// 实例，handleWebSocket 入口 Acquire / defer Release。
	wsConnLimiter *resguard.ConnLimiter
	serverWG      sync.WaitGroup
	shutdownChan  chan struct{}
	shutdownOnce  sync.Once
	startErrChan  chan error // C1: 捕获监听器启动失败错误
	logger        logger.ILogger
}

func NewServer(cfg *config.Config, log logger.ILogger) (*Server, error) {
	s := &Server{
		config:                cfg,
		proxies:               make(map[string]*proxy.Proxy),
		engines:               make(map[int]*gin.Engine),
		httpsEngines:          make(map[int]*gin.Engine),
		servers:               make(map[int]*http.Server),
		httpsServers:          make(map[int]*http.Server),
		wafByConfigKey:        make(map[string]*waf.Middleware),
		wafByHost:             make(map[string]*waf.Middleware),
		authByHost:            make(map[string]*auth.Manager),
		degradedConfigs:       make(map[string]config.WAFConfig),
		staleVersions:         make(map[string]string),
		wafConfigByKey:        make(map[string]config.WAFConfig),
		hostsByConfigKey:      make(map[string][]string),
		crsRefreshStopChan:    make(chan struct{}),
		crsRefreshTargets:     make(map[string]config.WAFCRSConfig),
		crsRefreshFailures:    make(map[string]int),
		pendingRestartConfigs: make(map[string]bool),
		shutdownChan:          make(chan struct{}),
		startErrChan:          make(chan error, 1), // C1: buffered to avoid blocking sender
		logger:                log,
	}

	// 初始化模板渲染器
	s.renderer = templates.NewRenderer(log)

	// H1：strict_path_check 显式 false 为逃生口，启动 Warn 一条（默认开不提示）
	if !cfg.Server.GetEffectiveStrictPathCheck() {
		log.Warn("server.strict_path_check=false: request path canonicalization is DISABLED, non-canonical paths (../ // .) pass through and path-based ACLs rely on backend normalization",
			logger.NewField("config", "server.strict_path_check"))
	}

	// L3（内部PRD §7.1）：全局 websocket_insecure_skip 已 Deprecated（迁移至
	// per-host web_socket_insecure_skip），配置非零时启动 Warn——该开关打开即整网关
	// WSS 上游证书校验全关，误伤面大；兼容期本值仍作为 per-host nil host 的缺省生效
	if cfg.Server.WebSocketInsecureSkip {
		log.Warn("server.websocket_insecure_skip is DEPRECATED and ENABLED: WebSocket upstream TLS certificate verification is DISABLED for all hosts without a per-host override; migrate to per-host web_socket_insecure_skip (内部PRD L3)",
			logger.NewField("config", "server.websocket_insecure_skip"))
	}

	// 初始化证书管理器
	s.certManager = cert.NewManager("./cache", log)

	// TrustedProxies 预解析一次（无条件，内部PRD §5.3）：黑名单关闭时
	// 数据面 access log 同样需要该口径，不得回退为 gin trust-all 的 param.ClientIP。
	s.trustedProxyNets = netutil.ParseTrustedProxies(cfg.Server.TrustedProxies)

	// F2.5（内部PRD §4.2.5）：trusted_proxies 宽度提示。红线（v4 < /8、
	// v6 < /48）已在 config.Validate 拒绝（allow_wide=true 显式放行时降级到这里
	// Warn）；/8~/23（v6 /48~/63）网段在此 Warn——过宽网段 = XFF 伪造面过大，
	// 内网任意主机可污染解析后 IP 口径。config 包无 logger，Warn 由此处打印。
	for _, entry := range cfg.Server.TrustedProxies {
		if !strings.Contains(entry, "/") {
			continue
		}
		_, network, err := net.ParseCIDR(entry)
		if err != nil {
			continue
		}
		ones, bits := network.Mask.Size()
		hardMin, softMin := 8, 24
		if bits == 128 {
			hardMin, softMin = 48, 64
		}
		if ones < hardMin {
			log.Warn("server.trusted_proxies entry is wider than the red line but explicitly allowed (trusted_proxies_allow_wide=true): XFF spoofing surface is very large",
				logger.NewField("entry", entry),
				logger.NewField("min_prefix", fmt.Sprintf("/%d", hardMin)))
		} else if ones < softMin {
			log.Warn("server.trusted_proxies entry is wider than recommended: XFF spoofing surface is large, consider narrowing",
				logger.NewField("entry", entry),
				logger.NewField("recommended_min_prefix", fmt.Sprintf("/%d", softMin)))
		}
	}

	// F1 资源治理初始化（内部PRD §4.1）：默认开启；enabled=false 为逃生口
	// （strict_path_check 同款哲学，Warn 一条），三个治理器保持 nil = 挂载点零开销
	// 跳过。per-IP 豁免网段（mesh/监控级联）预解析一次，非法条目已在 Validate
	// fail-fast，此处静默容错跳过（防御）。
	if cfg.Server.GetEffectiveResourceGovernanceEnabled() {
		exemptNets := parseIPNetEntries(cfg.Server.ResourceGovernance.PerIPWhitelist)
		s.reqSemaphore = resguard.NewSemaphore(
			cfg.Server.GetEffectiveMaxConcurrentRequests(),
			cfg.Server.GetEffectivePerIPConcurrentRequests(),
			exemptNets)
		s.ipRateLimiter = resguard.NewRateLimiter(
			cfg.Server.GetEffectivePerIPRate(),
			cfg.Server.GetEffectivePerIPBurst(),
			exemptNets)
		s.wsConnLimiter = resguard.NewConnLimiter(
			cfg.Server.GetEffectiveWSMaxGlobal(),
			cfg.Server.GetEffectiveWSMaxPerHost(),
			cfg.Server.GetEffectiveWSMaxPerIP(),
			exemptNets)
		log.Info("Resource governance enabled",
			logger.NewField("max_concurrent_requests", cfg.Server.GetEffectiveMaxConcurrentRequests()),
			logger.NewField("per_ip_concurrent_requests", cfg.Server.GetEffectivePerIPConcurrentRequests()),
			logger.NewField("per_ip_rate", cfg.Server.GetEffectivePerIPRate()),
			logger.NewField("per_ip_burst", cfg.Server.GetEffectivePerIPBurst()),
			logger.NewField("ws_limits", fmt.Sprintf("%d/%d/%d",
				cfg.Server.GetEffectiveWSMaxGlobal(), cfg.Server.GetEffectiveWSMaxPerHost(), cfg.Server.GetEffectiveWSMaxPerIP())),
			logger.NewField("per_ip_whitelist_nets", len(exemptNets)))
	} else {
		log.Warn("server.resource_governance.enabled=false: connection/rate resource governance is DISABLED, a single client can exhaust gateway concurrency and memory (内部PRD F1)",
			logger.NewField("config", "server.resource_governance.enabled"))
	}

	// 初始化 IP 黑名单管理器（PRD §10 生命周期）。
	// 仅 enabled=true 时创建；false 时保持 nil，请求链检查点直接跳过（零开销路径）。
	// NewManager 不返回 error：fail-open 是 blacklist 包内语义（拉取失败空表放行），
	// 其创建/启动失败不会使 NewServer 失败。Start 为异步首刷+定时循环，不阻塞此处。
	if cfg.Blacklist.Enabled {
		s.blacklistManager = blacklist.NewManager(cfg.Blacklist, log)
		s.blacklistManager.Start()
		// 预解析本地白名单（PRD §7.3）：非法条目 Warn+跳过，不阻断启动；
		// 请求链检查点直接使用预解析结果，消除每请求重复解析字符串的开销。
		s.blacklistWhitelistNets = parseBlacklistWhitelist(cfg.Blacklist.Whitelist, log)
		log.Info("Blacklist manager started",
			logger.NewField("default_mode", cfg.Blacklist.DefaultMode),
			logger.NewField("sources", len(cfg.Blacklist.Sources)),
			logger.NewField("whitelist_entries", len(cfg.Blacklist.Whitelist)),
			logger.NewField("whitelist_nets", len(s.blacklistWhitelistNets)))
	}

	// 初始化访问日志旁路 shipper（内部PRD §7.1，默认关）：
	// 仅 enabled=true 时创建并启动 flusher；创建/启动不失败启动（纯旁路组件，
	// 其异常由 hook recover + 缓冲丢弃计数降级，绝不影响代理主链路）。
	if cfg.TrackerShipper.Enabled {
		s.trackerShipper = shipper.New(cfg.TrackerShipper, log)
		s.trackerShipper.Start()
		log.Info("Tracker shipper started",
			logger.NewField("node", cfg.TrackerShipper.NodeName),
			logger.NewField("buffer_size", cfg.TrackerShipper.BufferSize),
			logger.NewField("batch_size", cfg.TrackerShipper.BatchSize),
			logger.NewField("flush_interval", cfg.TrackerShipper.FlushInterval.String()))
	}

	// 收集所有需要创建WAF实例的配置，避免重复创建相同配置的WAF实例
	wafConfigs := make(map[string]config.WAFConfig)
	hostToWAFConfig := make(map[string]string)

	for _, host := range cfg.Hosts {
		// 密码门实例（内部PRD）：仅 Auth 启用的 host 创建，nil 跳过。
		// M3：传入预解析 trusted_proxies（限速键改解析后真实客户端 IP 口径）
		if host.Auth != nil {
			s.authByHost[host.Name] = auth.NewManager(host.Name, host.Auth, s.trustedProxyNets, log)
			log.Info("Auth gate enabled",
				logger.NewField("host", host.Name),
				logger.NewField("ttl", host.Auth.GetEffectiveAuthTTL().String()),
				logger.NewField("max_failures", host.Auth.GetEffectiveMaxFailures()),
				logger.NewField("lock_duration", host.Auth.GetEffectiveLockDuration().String()),
				logger.NewField("public_paths", len(host.Auth.PublicPaths)))
		}

		// F5（内部PRD §4.5.2）：非空放行清单启动 Warn——放行编码的请求体
		// 不进 WAF 正文检测（原样透传），属显式豁免应可见
		if len(host.AllowedContentEncodings) > 0 {
			log.Warn("hosts allowed_content_encodings is non-empty: requests with these encodings bypass WAF request-body inspection",
				logger.NewField("host", host.Name),
				logger.NewField("allowed_content_encodings", strings.Join(host.AllowedContentEncodings, ",")))
		}

		if len(host.Backend) > 0 {
			// H37: 直接传递 time.Duration，避免 int 截断亚秒级 Duration
			healthInterval := host.HealthCheckInterval
			healthTimeout := host.HealthCheckTimeout
			healthCheckEnabled := host.GetEffectiveHealthCheckEnabled()
			preserveHostHeader := host.GetEffectivePreserveHostHeader()
			overrideHost := host.GetEffectiveOverrideHost()
			overrideOrigin := host.GetEffectiveOverrideOrigin()
			gzipEnabled := host.GetEffectiveGZipEnabled(cfg.Server.GZipEnabled)
			stripProxyHeaders := host.GetEffectiveStripProxyHeaders()
			forwardedFor := host.GetEffectiveForwardedFor()
			// L3（内部PRD §7.1）：WSS 跳过校验改 per-host 合并值
			//（per-host 显式配置优先，nil 继承全局）；per-host 显式 true 启动 Warn
			wsInsecureSkip := host.GetEffectiveWebSocketInsecureSkip(cfg.Server.WebSocketInsecureSkip)
			if host.WebSocketInsecureSkip != nil && *host.WebSocketInsecureSkip {
				log.Warn("hosts web_socket_insecure_skip=true: WebSocket upstream TLS certificate verification is DISABLED for this host (内部PRD L3)",
					logger.NewField("host", host.Name))
			}
			// v1.1：forwardedFor 随 stripProxyHeaders 同一通路流入 per-host proxy 实例
			p := proxy.NewProxy(host.Backend, host.HealthCheck, healthInterval, healthTimeout, log, s.renderer, cfg.Server.TrustedProxies, wsInsecureSkip, preserveHostHeader, overrideHost, overrideOrigin, gzipEnabled, healthCheckEnabled, stripProxyHeaders, forwardedFor, proxy.WSConfig{
				HandshakeTimeout: cfg.Server.WebSocket.HandshakeTimeout,
				IdleTimeout:      cfg.Server.WebSocket.IdleTimeout,
				PingInterval:     cfg.Server.WebSocket.PingInterval,
				// F1d（内部PRD §4.1.3）：WS 连接三级上限注入（nil = 不限制）
				ConnLimit:     s.wsConnLimiter,
				ConnLimitHost: host.Name,
			}, proxy.UpstreamConfig{
				// F1c（内部PRD §4.1.4）：连接池/响应头超时按 host 合并
				MaxConnsPerHost:       host.GetEffectiveUpstreamMaxConnsPerHost(cfg.Server.GetEffectiveUpstreamMaxConnsPerHost()),
				ResponseHeaderTimeout: host.GetEffectiveUpstreamResponseHeaderTimeout(cfg.Server.GetEffectiveUpstreamResponseHeaderTimeout()),
			})
			s.proxies[host.Name] = p
		}

		// Get effective WAF configuration for this host
		effectiveWAFConfig := host.GetEffectiveWAFConfig(s.config.WAF)

		// 如果WAF启用且模式不为 disabled，生成配置的哈希键来避免重复创建
		if effectiveWAFConfig.Enabled && effectiveWAFConfig.DefaultMode != config.WAFModeDisabled {
			configKey := s.generateWAFConfigKey(effectiveWAFConfig)
			wafConfigs[configKey] = effectiveWAFConfig
			hostToWAFConfig[host.Name] = configKey
		}
	}

	// 创建唯一的WAF实例
	for configKey, wafConfig := range wafConfigs {
		wafInstance, err := s.createWAFInstance(wafConfig)
		if err != nil {
			if errors.Is(err, waf.ErrWAFDegraded) {
				// degrade 策略（内部PRD §5.4）：该 configKey 不创建实例、
				// 不进 wafByConfigKey；对应 host 经下方映射缺失自然无 WAF 启动
				//（wafByHost 查表 nil 安全）。高优告警在就绪通知（notifyReady）发出。
				s.logger.Error("WAF degraded, hosts mapped to this config will start WITHOUT WAF protection",
					logger.NewField("config_key", configKey),
					logger.NewField("error", err.Error()))
				s.degradedConfigs[configKey] = wafConfig
				continue
			}
			// H2: 返回错误而非调用 log.Fatal，允许 main.go 执行通知和清理（fail 语义）
			if s.blacklistManager != nil {
				// 构造失败：停止已启动的黑名单刷新循环，避免 NewServer 错误路径泄漏 goroutine
				// （main.go 此时会退出进程，但保持 NewServer 库语义下不泄漏后台任务）
				s.blacklistManager.Stop()
			}
			if s.trackerShipper != nil {
				// 同上：错误路径停掉已启动的 shipper flusher，不泄漏后台任务
				s.trackerShipper.Stop()
			}
			return nil, fmt.Errorf("failed to create WAF instance (config_key=%s): %w", configKey, err)
		}
		s.wafByConfigKey[configKey] = wafInstance
		log.Info("WAF instance created",
			logger.NewField("config_key", configKey),
			logger.NewField("crs_enabled", wafConfig.CRS.Enabled),
			logger.NewField("custom_enabled", wafConfig.Custom.Enabled))
	}

	// 将主机映射到对应的WAF实例（degraded configKey 无实例，对应 host 自然无 WAF）
	for hostName, configKey := range hostToWAFConfig {
		if wafInstance, exists := s.wafByConfigKey[configKey]; exists {
			s.wafByHost[hostName] = wafInstance
		}
	}

	// CRS 降级/过期状态索引（内部PRD §5.4/§5.6）：
	// configKey → 配置 / host 反查表供通知与摘要使用；stale 集合从 crs 注册表读取
	// EnsureCRS 发布的状态（唯一真相源）。
	s.wafConfigByKey = wafConfigs
	for hostName, configKey := range hostToWAFConfig {
		s.hostsByConfigKey[configKey] = append(s.hostsByConfigKey[configKey], hostName)
	}
	for configKey, wafConfig := range wafConfigs {
		if _, degraded := s.degradedConfigs[configKey]; degraded {
			continue
		}
		if !wafConfig.CRS.Enabled {
			continue
		}
		v := crs.ResolveVersion(wafConfig.CRS.Version)
		if st, ok := crs.StatusSnapshot(v); ok && st.State == crs.StateStale {
			s.staleVersions[v] = st.LastError
		}
	}

	return s, nil
}

func (s *Server) GetHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		s.handleRequestForPort(c, s.config.Hosts)
	}
}

// GetBackendHealth 返回指定 host 的后端健康状态
func (s *Server) GetBackendHealth(hostName string) map[string]bool {
	if p, exists := s.proxies[hostName]; exists {
		return p.GetBackendHealth()
	}
	return nil
}

// GetWAFStats 返回所有虚拟主机的 WAF 拦截统计
func (s *Server) GetWAFStats() []waf.StatsSnapshot {
	result := make([]waf.StatsSnapshot, 0)
	for _, m := range s.wafByConfigKey {
		result = append(result, m.GetStats())
	}
	return result
}

// GetWAFEvents 返回所有 WAF 实例的最近事件列表（阻断 + 检测）
func (s *Server) GetWAFEvents(limit int) []waf.WAFEvent {
	result := make([]waf.WAFEvent, 0)
	for _, m := range s.wafByConfigKey {
		result = append(result, m.GetEvents(limit)...)
	}
	// 按时间倒序排列
	sort.Slice(result, func(i, j int) bool {
		return result[i].Time.After(result[j].Time)
	})
	if limit > 0 && len(result) > limit {
		result = result[:limit]
	}
	return result
}

// FindWAFEvent 按 ID 查找 WAF 事件
func (s *Server) FindWAFEvent(id int64) (waf.WAFEvent, bool) {
	for _, m := range s.wafByConfigKey {
		if ev, found := m.FindEvent(id); found {
			return ev, true
		}
	}
	return waf.WAFEvent{}, false
}

// GetBlacklistStats 返回 IP 黑名单统计快照（供 admin setter 注入）。
// 未启用黑名单（manager 为 nil）时返回零值快照，不 panic。
func (s *Server) GetBlacklistStats() blacklist.StatsSnapshot {
	if s.blacklistManager == nil {
		return blacklist.StatsSnapshot{}
	}
	return s.blacklistManager.GetStats()
}

// GetBlacklistEvents 返回最近 limit 条黑名单命中事件（供 admin setter 注入）。
// 未启用黑名单（manager 为 nil）时返回空切片，不 panic。
func (s *Server) GetBlacklistEvents(limit int) []blacklist.BlacklistEvent {
	if s.blacklistManager == nil {
		return []blacklist.BlacklistEvent{}
	}
	return s.blacklistManager.GetEvents(limit)
}

// GetTrackerShipperStatus 返回访问日志旁路 shipper 的状态快照（供 admin setter 注入，
// 内部PRD §6.1）。未启用/配置缺段（trackerShipper 为 nil）时返回
// DisabledStatusSnapshot（enabled:false 全零值）——"组件消失"是有效状态不是错误，
// 端点仍返回 200，由监控断言失败产生告警。
func (s *Server) GetTrackerShipperStatus() shipper.StatusSnapshot {
	if s.trackerShipper == nil {
		return shipper.DisabledStatusSnapshot()
	}
	return s.trackerShipper.Snapshot()
}

// SetNotifier 注入生命周期事件通知器（内部PRD §5.6/§7）。
// main.go 必须在 srv.Start() 之前调用：ready / waf_crs_* 通知由 Start 内的
// notifyReady 触发；未注入（如单测）时全部 no-op，不 panic。
// M3：级联注入到各 host 密码门实例（登录失败锁定全局告警，auth.LockoutNotifier
// 与本接口同签名，天然满足）
func (s *Server) SetNotifier(n Notifier) {
	s.notifier = n
	for _, mgr := range s.authByHost {
		mgr.SetNotifier(n)
	}
	// F9.4（内部PRD §4.9.4）：黑名单表龄告警级联注入（blacklist 包
	// 不依赖 notification，经回调解耦）
	if s.blacklistManager != nil {
		s.blacklistManager.SetStaleNotifier(func(age time.Duration) {
			if n == nil {
				return
			}
			_ = n.SendNotification("blacklist_stale", map[string]string{
				"表龄": age.Round(time.Minute).String(),
				"风险": "黑名单数据长时间未成功刷新，拦截能力可能已过期",
			})
		})
	}
}

// GetCRSStatus 返回指定版本的 CRS 状态快照（供 admin setter 注入，读 crs 包注册表；
// 与 GetWAFStats 等同模式）。注册表无该版本时返回 (零值, false)。
func (s *Server) GetCRSStatus(version string) (crs.Status, bool) {
	return crs.StatusSnapshot(version)
}

// GetDegradedCRSSummary 返回 degrade 策略下无 WAF 启动的配置摘要（内部PRD §5.4）。
// 后台刷新恢复后集合收缩，摘要随之变空。
func (s *Server) GetDegradedCRSSummary() CRSStateSummary {
	s.crsStateMu.RLock()
	defer s.crsStateMu.RUnlock()
	sum := CRSStateSummary{
		ConfigKeys: []string{},
		Versions:   []string{},
		Hosts:      []string{},
		LastErrors: []string{},
	}
	for configKey := range s.degradedConfigs {
		sum.ConfigKeys = append(sum.ConfigKeys, configKey)
		version := ""
		if wcfg, ok := s.wafConfigByKey[configKey]; ok {
			version = crs.ResolveVersion(wcfg.CRS.Version)
			sum.Versions = append(sum.Versions, version)
		}
		sum.Hosts = append(sum.Hosts, s.hostsByConfigKey[configKey]...)
		if st, ok := crs.StatusSnapshot(version); ok && st.LastError != "" {
			sum.LastErrors = append(sum.LastErrors, st.LastError)
		}
	}
	sort.Strings(sum.ConfigKeys)
	sort.Strings(sum.Versions)
	sort.Strings(sum.Hosts)
	sort.Strings(sum.LastErrors)
	return sum
}

// GetStaleCRSSummary 返回以旧缓存（哈希不一致/无哈希）启动的配置摘要（PRD §5.1/§5.6）。
func (s *Server) GetStaleCRSSummary() CRSStateSummary {
	s.crsStateMu.RLock()
	defer s.crsStateMu.RUnlock()
	sum := CRSStateSummary{
		ConfigKeys: []string{},
		Versions:   []string{},
		Hosts:      []string{},
		LastErrors: []string{},
	}
	for version := range s.staleVersions {
		sum.Versions = append(sum.Versions, version)
		if st, ok := crs.StatusSnapshot(version); ok {
			sum.LastErrors = append(sum.LastErrors, st.LastError)
		}
		for configKey, wcfg := range s.wafConfigByKey {
			if !wcfg.CRS.Enabled || crs.ResolveVersion(wcfg.CRS.Version) != version {
				continue
			}
			if _, degraded := s.degradedConfigs[configKey]; degraded {
				continue
			}
			sum.ConfigKeys = append(sum.ConfigKeys, configKey)
			sum.Hosts = append(sum.Hosts, s.hostsByConfigKey[configKey]...)
		}
	}
	sort.Strings(sum.ConfigKeys)
	sort.Strings(sum.Versions)
	sort.Strings(sum.Hosts)
	sort.Strings(sum.LastErrors)
	return sum
}

// notifyReady 就绪通知（内部PRD §5.6/§7）：仅在所有监听端口实际绑定成功后
// 由 Start 调用；Start 失败路径不会到达此处。事件：ready（正常就绪）、
// waf_crs_degraded（有 degrade 配置，注明「WAF 未启用，流量无 WAF 防护」高优语义）、
// waf_crs_stale_start（有 stale 配置，注明规则可能过期）。未注入 notifier 时全部 no-op。
func (s *Server) notifyReady() {
	ports := s.listeningPorts()
	portStrs := make([]string, 0, len(ports))
	for _, p := range ports {
		portStrs = append(portStrs, strconv.Itoa(p))
	}
	s.logger.Info("All listeners bound, gateway ready",
		logger.NewField("ports", strings.Join(portStrs, ",")))

	if s.notifier != nil {
		_ = s.notifier.SendNotification("ready", map[string]string{
			"监听端口": strings.Join(portStrs, ", "),
		})
	}

	// degrade 降级启动：必须显式告警，禁止「静默无 WAF」运行（PRD §10.3）
	if degraded := s.GetDegradedCRSSummary(); len(degraded.Hosts) > 0 {
		s.logger.Error("Gateway started with degraded WAF configs, affected hosts have NO WAF protection",
			logger.NewField("host_count", len(degraded.Hosts)),
			logger.NewField("hosts", strings.Join(degraded.Hosts, ", ")))
		if s.notifier != nil {
			_ = s.notifier.SendNotification("waf_crs_degraded", map[string]string{
				"影响host数": strconv.Itoa(len(degraded.Hosts)),
				"影响host":  strings.Join(degraded.Hosts, ", "),
				"原因":      strings.Join(nonEmptyUnique(degraded.LastErrors), "; "),
				"风险":      "WAF 未启用，流量无 WAF 防护",
			})
		}
	}

	if stale := s.GetStaleCRSSummary(); len(stale.Hosts) > 0 {
		s.logger.Warn("Gateway started with stale CRS cache, rules may be outdated",
			logger.NewField("host_count", len(stale.Hosts)),
			logger.NewField("hosts", strings.Join(stale.Hosts, ", ")))
		if s.notifier != nil {
			_ = s.notifier.SendNotification("waf_crs_stale_start", map[string]string{
				"影响host数": strconv.Itoa(len(stale.Hosts)),
				"影响host":  strings.Join(stale.Hosts, ", "),
				"原因":      strings.Join(nonEmptyUnique(stale.LastErrors), "; "),
				// F10.3：普通 stale 文案改为「未经完整性验证」（此前未区分篡改证据）
				"风险": "旧缓存未经完整性验证，规则可能过期或被篡改",
			})
			// F10.3：存在篡改证据的版本额外发高优告警（🚨 级）
			tampered := []string{}
			for _, v := range stale.Versions {
				if st, ok := crs.StatusSnapshot(v); ok && st.Integrity == crs.IntegrityStatusTampered {
					tampered = append(tampered, v)
				}
			}
			if len(tampered) > 0 {
				_ = s.notifier.SendNotification("waf_crs_cache_tampered", map[string]string{
					"CRS版本":  strings.Join(nonEmptyUnique(tampered), ", "),
					"影响host": strings.Join(stale.Hosts, ", "),
					"处置":     "已拒绝加载被篡改缓存（金副本/失败策略兜底）；请立即人工核查宿主机缓存目录写权限",
				})
			}
		}
	}
}

// listeningPorts 返回已启动监听的端口排序列表（HTTP + HTTPS 去重）
func (s *Server) listeningPorts() []int {
	seen := make(map[int]bool)
	for p := range s.servers {
		seen[p] = true
	}
	for p := range s.httpsServers {
		seen[p] = true
	}
	ports := make([]int, 0, len(seen))
	for p := range seen {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	return ports
}

// nonEmptyUnique 过滤空串并去重（保持顺序）
func nonEmptyUnique(in []string) []string {
	out := make([]string, 0, len(in))
	seen := make(map[string]bool)
	for _, v := range in {
		if v != "" && !seen[v] {
			out = append(out, v)
			seen[v] = true
		}
	}
	return out
}

// collectCRSRefreshTargets 汇总需要后台自愈刷新的版本 → CRS 配置（同版本取首个配置）。
// 调用方需持 crsStateMu（或处于 NewServer 后、循环启动前的静默期）。
func (s *Server) collectCRSRefreshTargets() map[string]config.WAFCRSConfig {
	s.crsStateMu.RLock()
	defer s.crsStateMu.RUnlock()
	targets := make(map[string]config.WAFCRSConfig)
	for configKey := range s.degradedConfigs {
		wcfg, ok := s.wafConfigByKey[configKey]
		if !ok || !wcfg.CRS.Enabled {
			continue
		}
		version := crs.ResolveVersion(wcfg.CRS.Version)
		if _, exists := targets[version]; !exists {
			targets[version] = wcfg.CRS
		}
	}
	for version := range s.staleVersions {
		if _, exists := targets[version]; exists {
			continue
		}
		for _, wcfg := range s.wafConfigByKey {
			if wcfg.CRS.Enabled && crs.ResolveVersion(wcfg.CRS.Version) == version {
				targets[version] = wcfg.CRS
				break
			}
		}
	}
	return targets
}

// startCRSRefreshLoop 存在 degraded/stale 版本时启动后台自愈刷新循环（PRD §5.4/D3）。
// 每轮间隔 crsRefreshInterval；恢复后不热切换 WAF 实例，新规则下次重启生效。
// 无 degraded/stale 配置时 no-op（零 goroutine）。
func (s *Server) startCRSRefreshLoop() {
	targets := s.collectCRSRefreshTargets()
	if len(targets) == 0 {
		return
	}
	s.crsRefreshTargets = targets
	versions := make([]string, 0, len(targets))
	for v := range targets {
		versions = append(versions, v)
	}
	sort.Strings(versions)
	s.logger.Info("CRS background refresh loop started",
		logger.NewField("versions", strings.Join(versions, ",")),
		logger.NewField("interval", crsRefreshInterval.String()))
	s.crsRefreshWG.Add(1)
	go s.crsRefreshLoop()
}

// crsRefreshLoop 定时刷新循环：每轮遍历目标版本逐个刷新；Stop 信号随时退出。
func (s *Server) crsRefreshLoop() {
	defer s.crsRefreshWG.Done()
	ticker := time.NewTicker(crsRefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.crsRefreshStopChan:
			return
		case <-ticker.C:
		}
		for _, version := range s.sortedRefreshVersions() {
			select {
			case <-s.crsRefreshStopChan:
				return
			default:
			}
			s.refreshCRSVersion(version)
		}
		// F11.1：仍有「已恢复待重启」配置 → 每 30min 重发告警（重启前持续可见）
		if hosts := s.GetPendingRestartCRSSummary(); len(hosts) > 0 && s.notifier != nil {
			_ = s.notifier.SendNotification("waf_crs_recovered", map[string]string{
				"提醒":     "以下 host 的 CRS 已恢复但需重启网关才生效（pending_restart）",
				"影响host": strings.Join(hosts, ", "),
			})
		}
	}
}

// GetPendingRestartCRSSummary F11.1：返回「CRS 已恢复、重启后生效」的 host 列表
// （admin /api/waf/stats 的 pending_restart_hosts 数据源；重启天然清零）
func (s *Server) GetPendingRestartCRSSummary() []string {
	s.crsStateMu.RLock()
	defer s.crsStateMu.RUnlock()
	hosts := make([]string, 0)
	for configKey := range s.pendingRestartConfigs {
		hosts = append(hosts, s.hostsByConfigKey[configKey]...)
	}
	sort.Strings(hosts)
	return hosts
}

// GetDegradedWAFHosts F11.1：返回当前无 WAF 运行的 host 列表（degraded）
func (s *Server) GetDegradedWAFHosts() []string {
	sum := s.GetDegradedCRSSummary()
	return sum.Hosts
}

// sortedRefreshVersions 返回刷新目标的确定性顺序
func (s *Server) sortedRefreshVersions() []string {
	versions := make([]string, 0, len(s.crsRefreshTargets))
	for v := range s.crsRefreshTargets {
		versions = append(versions, v)
	}
	sort.Strings(versions)
	return versions
}

// noteCRSRecoveredLocked 后台刷新成功的簿记收敛（调用方持 crsStateMu，F11.1）:
// 从 degraded/stale 集合收缩（WAF 实例不热切换，D3：下次重启生效），同时把受
// 影响配置记入 pendingRestartConfigs（重启后生效的可见性；重启天然清零）
func (s *Server) noteCRSRecoveredLocked(version string) {
	for configKey, wcfg := range s.wafConfigByKey {
		if wcfg.CRS.Enabled && crs.ResolveVersion(wcfg.CRS.Version) == version {
			if _, wasDegraded := s.degradedConfigs[configKey]; wasDegraded {
				s.pendingRestartConfigs[configKey] = true
			}
			delete(s.degradedConfigs, configKey)
		}
	}
	if _, wasStale := s.staleVersions[version]; wasStale {
		for configKey, wcfg := range s.wafConfigByKey {
			if wcfg.CRS.Enabled && crs.ResolveVersion(wcfg.CRS.Version) == version {
				s.pendingRestartConfigs[configKey] = true
			}
		}
	}
	delete(s.staleVersions, version)
}

// refreshCRSVersion 刷新单个 CRS 版本：每轮重建 Manager（全新下载预算，PRD §5.4）。
// 成功 → 发布 valid 状态 + 收缩 degraded/stale 集合 + waf_crs_recovered 通知
// （注明规则下次重启生效）；失败 → waf_crs_refresh_failed 通知（带连续失败计数）。
func (s *Server) refreshCRSVersion(version string) {
	crsCfg, ok := s.crsRefreshTargets[version]
	if !ok {
		return
	}
	mgr := crs.NewManager("./cache", s.logger, &crsCfg)
	res := mgr.EnsureCRS(version)

	s.crsStateMu.Lock()
	defer s.crsStateMu.Unlock()

	if res.State == crs.StateValid {
		s.crsRefreshFailures[version] = 0
		// recovered：簿记收敛 + pendingRestart 标记（F11.1，抽方法便于单测）
		s.noteCRSRecoveredLocked(version)
		s.logger.Info("CRS background refresh succeeded, marking version valid (rules take effect after next restart)",
			logger.NewField("version", version),
			logger.NewField("source", res.Source))
		if s.notifier != nil {
			_ = s.notifier.SendNotification("waf_crs_recovered", map[string]string{
				"CRS版本": version,
				"说明":    "CRS 后台刷新成功；新规则将在下次网关重启时生效",
			})
		}
		// F10.3：刷新前存在篡改证据 → 一次性高优告警（已原子替换，事件仍须留痕）
		if prev, ok := crs.StatusSnapshot(version); ok && prev.Integrity == crs.IntegrityStatusTampered {
			_ = s.notifier.SendNotification("waf_crs_cache_tampered", map[string]string{
				"CRS版本": version,
				"状态":    "刷新已原子替换缓存（state=valid），但此前检测到篡改证据，请人工核查宿主机写权限",
			})
		}
		return
	}

	s.crsRefreshFailures[version]++
	failures := s.crsRefreshFailures[version]
	errMsg := ""
	if res.Err != nil {
		errMsg = res.Err.Error()
	}
	s.logger.Warn("CRS background refresh failed",
		logger.NewField("version", version),
		logger.NewField("consecutive_failures", failures),
		logger.NewField("error", errMsg))
	if s.notifier != nil {
		_ = s.notifier.SendNotification("waf_crs_refresh_failed", map[string]string{
			"CRS版本":  version,
			"连续失败次数": strconv.Itoa(failures),
			"错误":     errMsg,
		})
	}
}

// stopCRSRefreshLoop 停止后台自愈刷新循环并等待在途刷新完成（blacklist.Stop 模式，防泄漏）
func (s *Server) stopCRSRefreshLoop() {
	s.crsRefreshStopOnce.Do(func() {
		close(s.crsRefreshStopChan)
	})
	s.crsRefreshWG.Wait()
}

// GetCertManager 返回证书管理器
func (s *Server) GetCertManager() *cert.Manager {
	return s.certManager
}

// GetConfig 返回配置
func (s *Server) GetConfig() *config.Config {
	return s.config
}

func (s *Server) Start() error {
	// Group hosts by port to avoid duplicate servers
	portGroups := make(map[int][]config.HostConfig)
	sslPortGroups := make(map[int][]config.HostConfig)
	// Reconciler 目标收集（内部PRD §7.1）：域名 → GetEffectiveSSLConfig 结果，
	// 多端口共存同域名时合并去重（保留首个出现的配置）
	reconcilerTargets := make(map[string]*cert.CertConfig)

	for _, host := range s.config.Hosts {
		// HTTP端口分组
		portGroups[host.Port] = append(portGroups[host.Port], host)

		// HTTPS端口分组
		if host.SSLPort > 0 {
			// 获取有效的SSL配置（虚拟主机配置优先，如果为空则使用全局配置）
			effectiveSSLConfig := host.GetEffectiveSSLConfig(s.config.SSL)
			if effectiveSSLConfig != nil {
				sslPortGroups[host.SSLPort] = append(sslPortGroups[host.SSLPort], host)
				if _, exists := reconcilerTargets[host.Name]; !exists {
					reconcilerTargets[host.Name] = effectiveSSLConfig
				}
			}
		}
	}

	// Start HTTP servers（内部PRD §5.6：net.Listen 同步绑定，绑定成功即端口
	// 实际监听；绑定失败同步返回错误，确保「ready」只可能发生在全端口监听之后）
	for port, hosts := range portGroups {
		if err := s.startHTTPServer(port, hosts); err != nil {
			// 同步失败路径执行优雅关闭（对齐下方 startErrChan 分支的清理行为）
			s.shutdownAllServers()
			s.serverWG.Wait()
			return fmt.Errorf("failed to start HTTP server on port %d: %w", port, err)
		}
	}

	// Start HTTPS servers
	for port, hosts := range sslPortGroups {
		if err := s.startHTTPSServer(port, hosts); err != nil {
			// C1/H3: HTTPS 启动失败时返回错误，而非仅记录日志
			// P3: 同步失败路径同样执行优雅关闭（对齐下方 startErrChan 分支的清理行为），
			// 消除已启动组件的泄漏：blacklist 刷新 goroutine / HTTP 监听 / 代理健康检查。
			s.shutdownAllServers()
			s.serverWG.Wait()
			return fmt.Errorf("failed to start HTTPS server on port %d: %w", port, err)
		}
	}

	// 全部监听器启动成功后异步启动证书 Reconciler（内部PRD §7.1）：
	// 证书从此只在后台收敛（并发拉取 + 退避重试自愈），绝不阻塞监听器启动；
	// 空 targets 时 StartReconciler 为 no-op。此处之后若异步路径启动失败走
	// shutdownAllServers，其中的 StopReconciler 会幂等清理。
	reconcilerTargetList := make([]cert.CertTarget, 0, len(reconcilerTargets))
	for domain, sslConfig := range reconcilerTargets {
		reconcilerTargetList = append(reconcilerTargetList, cert.CertTarget{Domain: domain, Config: sslConfig})
	}
	s.certManager.StartReconciler(reconcilerTargetList)

	// 全端口实际绑定成功 → 就绪（内部PRD §5.6/§7）：就绪通知（ready /
	// waf_crs_degraded / waf_crs_stale_start）+ 按需启动 CRS 后台自愈刷新循环。
	// 此处之后若异步 accept 路径失败，仍走 startErrChan 分支清理（其中的
	// shutdownAllServers 会停掉刷新循环）。
	s.notifyReady()
	s.startCRSRefreshLoop()

	// Wait for shutdown signal or start error
	// C1: 监听启动失败错误，端口绑定失败时通知 main 退出
	select {
	case err := <-s.startErrChan:
		// 监听器启动失败，执行优雅关闭后返回错误
		s.shutdownAllServers()
		s.serverWG.Wait()
		return err
	case <-s.shutdownChan:
	}

	// Graceful shutdown
	s.shutdownAllServers()

	s.serverWG.Wait()
	return nil
}

// startHTTPServer 启动HTTP服务器：同步绑定端口（绑定失败即时返回错误），绑定成功后
// 以 Serve(ln) 进入异步 accept 循环。就绪语义（内部PRD §5.6）依赖此同步绑定：
// 本函数返回 nil 即该端口已在监听。
func (s *Server) startHTTPServer(port int, hosts []config.HostConfig) error {
	// Create gin engine for this port
	gin.SetMode(gin.ReleaseMode)
	engine := gin.New()
	// 内部PRD §5.3：数据面 engine 不信任任何代理头，gin 的 param.ClientIP
	// 恒为直连对端（防伪造污染）；访问日志 client_ip 由 ginLoggerMiddleware 按
	// trusted_proxies 解析（与 blacklist/WAF 口径一致）。nil 参数不会解析失败。
	_ = engine.SetTrustedProxies(nil)

	// Set up custom logger
	engine.Use(s.ginLoggerMiddleware())
	// C2 访问日志旁路 hook（内部PRD §4.4.1）：紧跟访问日志点，不改文本日志
	engine.Use(s.shipperMiddleware())
	// ★F1a 并发信号量（内部PRD §4.1.1）：ginLogger 之后挂载，503 进访问
	// 日志；占满拒绝（含 WS 连接存活期占用）；enabled=false 时 nil 直通
	engine.Use(s.resguardMiddleware())
	engine.Use(gin.Recovery())

	// Create handler for this port's hosts
	engine.Use(func(c *gin.Context) {
		s.handleRequestForPort(c, hosts)
		c.Abort()
	})

	s.engines[port] = engine

	server := &http.Server{
		Addr:              fmt.Sprintf(":%d", port),
		Handler:           engine,
		ReadHeaderTimeout: 60 * time.Second,   // Slowloris 防护：限制读取请求头的时间
		ReadTimeout:       120 * time.Second,  // P2-42: 限制读取完整请求的时间（含 body）
		WriteTimeout:      1800 * time.Second, // P2-42: 限制写响应的时间（兼容长响应如 SSE，支持 30 分钟流式输出）
		IdleTimeout:       120 * time.Second,  // 回收空闲 keep-alive 连接
		// F1.6（内部PRD §4.1.6）：请求头 1MB 收紧为 32KB（缺省），
		// 可经 server.max_header_bytes 配置
		MaxHeaderBytes: s.config.Server.GetEffectiveMaxHeaderBytes(),
	}

	s.servers[port] = server

	// C1/内部PRD §5.6：同步绑定，失败即时上抛（清理占位，避免泄漏未启动的 server）
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		delete(s.servers, port)
		delete(s.engines, port)
		return fmt.Errorf("failed to bind port %d: %w", port, err)
	}

	s.serverWG.Add(1)
	go func(p int, srv *http.Server, ln net.Listener) {
		defer s.serverWG.Done()
		s.logger.Info("HTTP server starting", logger.NewField("port", p))

		// C1: 仅 accept 循环错误（绑定已同步完成）通知 Start() 返回
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			s.logger.Error("HTTP server failed", logger.NewField("port", p), logger.NewField("error", err))
			select {
			case s.startErrChan <- fmt.Errorf("HTTP server on port %d failed: %w", p, err):
			default:
			}
		}
	}(port, server, listener)
	return nil
}

// startHTTPSServer 启动HTTPS服务器
func (s *Server) startHTTPSServer(port int, hosts []config.HostConfig) error {
	// Create gin engine for this port
	gin.SetMode(gin.ReleaseMode)
	engine := gin.New()
	// 内部PRD §5.3：数据面 engine 不信任任何代理头，gin 的 param.ClientIP
	// 恒为直连对端（防伪造污染）；访问日志 client_ip 由 ginLoggerMiddleware 按
	// trusted_proxies 解析（与 blacklist/WAF 口径一致）。nil 参数不会解析失败。
	_ = engine.SetTrustedProxies(nil)

	// Set up custom logger
	engine.Use(s.ginLoggerMiddleware())
	// C2 访问日志旁路 hook（内部PRD §4.4.1）：紧跟访问日志点，不改文本日志
	engine.Use(s.shipperMiddleware())
	// ★F1a 并发信号量（同 startHTTPServer）
	engine.Use(s.resguardMiddleware())
	engine.Use(gin.Recovery())

	// Create handler for this port's hosts
	engine.Use(func(c *gin.Context) {
		s.handleRequestForPort(c, hosts)
		c.Abort()
	})

	// 证书不在启动路径加载（内部PRD §7.1 / D1）：443 监听器无条件秒开，
	// 全部域名证书由后台 reconciler 异步收敛（缓存秒就绪即插即用，未就绪域名
	// 退避重试自愈），证书问题从此不再是监听器延迟或进程退出的原因。
	// 旧同步预加载循环与 len(loadedDomains)==0 报错分支已删除——单个未就绪域名
	// 曾把 ssl-api 同步签发挂住的 5~6 分钟传导为全站 443 拒绝连接。
	//
	// 创建TLS配置（C2: 回调直接调用 Manager 而非捕获静态 map；
	// GetCertificate 是每次握手实时回调，reconciler 写入内存后下一个握手即生效）
	tlsConfig := &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return s.certManager.GetCertificate(hello.ServerName)
		},
		MinVersion:               tls.VersionTLS12,
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
		},
	}

	s.httpsEngines[port] = engine

	server := &http.Server{
		Addr:              fmt.Sprintf(":%d", port),
		Handler:           engine,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 60 * time.Second,   // Slowloris 防护：限制读取请求头的时间
		ReadTimeout:       120 * time.Second,  // P2-42: 限制读取完整请求的时间（含 body）
		WriteTimeout:      1800 * time.Second, // P2-42: 限制写响应的时间（支持 30 分钟流式输出）
		IdleTimeout:       120 * time.Second,  // 回收空闲 keep-alive 连接
		// F1.6：同 startHTTPServer，1MB 收紧为 32KB（缺省）
		MaxHeaderBytes: s.config.Server.GetEffectiveMaxHeaderBytes(),
	}

	// 检查是否有任何主机启用了HTTP/2
	// P2-43: HTTP/2 在端口级别配置，同一端口上所有主机共享 HTTP/2 支持
	// 如果某些主机显式禁用 HTTP/2 但同端口其他主机启用了，记录警告
	http2Enabled := false
	var http2DisabledHosts []string
	for _, host := range hosts {
		if host.GetEffectiveHTTP2Enabled(s.config.Server.HTTP2Enabled) {
			http2Enabled = true
		} else {
			http2DisabledHosts = append(http2DisabledHosts, host.Name)
		}
	}

	if http2Enabled && len(http2DisabledHosts) > 0 {
		s.logger.Warn("HTTP/2 enabled at port level but some hosts have it disabled (HTTP/2 is per-port, not per-host)",
			logger.NewField("port", port),
			logger.NewField("http2_disabled_hosts", http2DisabledHosts))
	}

	// 如果启用HTTP/2，配置HTTP/2服务器
	if http2Enabled {
		// F1.6（内部PRD §4.1.6）事实修正：x/net v0.62.0 的 http2.Server
		// 没有 MaxHeaderListSize 字段（该字段仅存在于 Transport）；h2 侧头部上限
		// 经 serverConn.maxHeaderListSize() 自动继承 http.Server.MaxHeaderBytes
		//（源码 server.go:501，取 hs.MaxHeaderBytes，回退 DefaultMaxHeaderBytes），
		// 故上方收紧后的 MaxHeaderBytes 对 h2 同样生效，无需也无法在此显式设置
		if err := http2.ConfigureServer(server, nil); err != nil {
			s.logger.Error("Failed to configure HTTP/2 server",
				logger.NewField("port", port),
				logger.NewField("error", err))
			return fmt.Errorf("failed to configure HTTP/2 for port %d: %w", port, err)
		} else {
			s.logger.Info("HTTP/2 support configured for HTTPS server",
				logger.NewField("port", port))
		}
	}

	s.httpsServers[port] = server

	// C1/内部PRD §5.6：同步绑定，失败即时上抛（清理占位）
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		delete(s.httpsServers, port)
		delete(s.httpsEngines, port)
		return fmt.Errorf("failed to bind port %d: %w", port, err)
	}

	s.serverWG.Add(1)
	go func(p int, srv *http.Server, ln net.Listener) {
		defer s.serverWG.Done()
		// 启动日志不再输出已加载域名（预加载已移除）；host 数来自配置，证书由
		// 后台 reconciler 异步加载（内部PRD §7.1）
		s.logger.Info("HTTPS server starting, certificates are loaded asynchronously by background reconciler",
			logger.NewField("port", p),
			logger.NewField("hosts", len(hosts)),
			logger.NewField("http2_enabled", http2Enabled))

		// C1: 仅 accept 循环错误（绑定已同步完成）通知 Start() 返回
		if err := srv.ServeTLS(ln, "", ""); err != nil && err != http.ErrServerClosed {
			s.logger.Error("HTTPS server failed", logger.NewField("port", p), logger.NewField("error", err))
			select {
			case s.startErrChan <- fmt.Errorf("HTTPS server on port %d failed: %w", p, err):
			default:
			}
		}
	}(port, server, listener)

	return nil
}

// shutdownAllServers 优雅关闭所有服务器
// 顺序：先停 HTTP/HTTPS（停止接受新连接）→ 停代理（等待 WebSocket 关闭）→ 停黑名单管理器
// → 停证书 Reconciler → 关证书管理器（内部PRD §14.2：Reconciler 必须先于
// 证书 map 清空/Updater 停止）
// P2-38: HTTP/HTTPS servers 并行关闭，避免多端口关闭时间线性叠加
func (s *Server) shutdownAllServers() {
	var shutdownWG sync.WaitGroup

	// 停止 CRS 后台自愈刷新循环（内部PRD §7：生命周期纳入 Server 关闭，
	// blacklist.Stop 模式，防泄漏）。放在最前：刷新循环与监听器无依赖，先停早释放。
	s.stopCRSRefreshLoop()

	// 并行关闭 HTTP 和 HTTPS 服务器
	for port, srv := range s.servers {
		shutdownWG.Add(1)
		go func(p int, srv *http.Server) {
			defer shutdownWG.Done()
			s.logger.Info("Shutting down HTTP server", logger.NewField("port", p))
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := srv.Shutdown(ctx); err != nil {
				// P2-41: Shutdown 超时后强制关闭，取消所有活跃请求的 context
				s.logger.Warn("HTTP server shutdown timed out, forcing close",
					logger.NewField("port", p),
					logger.NewField("error", err))
				srv.Close()
			}
		}(port, srv)
	}

	for port, srv := range s.httpsServers {
		shutdownWG.Add(1)
		go func(p int, srv *http.Server) {
			defer shutdownWG.Done()
			s.logger.Info("Shutting down HTTPS server", logger.NewField("port", p))
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := srv.Shutdown(ctx); err != nil {
				// P2-41: Shutdown 超时后强制关闭
				s.logger.Warn("HTTPS server shutdown timed out, forcing close",
					logger.NewField("port", p),
					logger.NewField("error", err))
				srv.Close()
			}
		}(port, srv)
	}

	shutdownWG.Wait()

	// 停止访问日志旁路 shipper（内部PRD §4.4.1 优雅收尾）：放在 HTTP/HTTPS
	// 监听器关闭之后——此刻在途请求已结束、不再产生新记录，Stop 尽力清空缓冲发送
	// 后退出（超时放弃）。shipper 为纯旁路组件，Stop 顺序无其他约束。
	if s.trackerShipper != nil {
		s.trackerShipper.Stop()
	}

	// 并行停止所有代理（等待 WebSocket 连接关闭，关闭后端连接池）
	// C5: 并行关闭避免 N 个虚拟主机的 WebSocket 关闭时间线性叠加
	var proxyWG sync.WaitGroup
	for _, p := range s.proxies {
		proxyWG.Add(1)
		go func(p *proxy.Proxy) {
			defer proxyWG.Done()
			p.Stop()
		}(p)
	}
	proxyWG.Wait()

	// 停止 IP 黑名单管理器（等待在途刷新完成）。
	// 放在代理停止之后：此时活跃请求已全部结束，不再有并发 Lookup/RecordHit；
	// 放在证书管理器之前：黑名单是独立内存组件，与证书无依赖，先停早释放。
	if s.blacklistManager != nil {
		s.blacklistManager.Stop()
	}

	// 停止证书 Reconciler（内部PRD §14.2 顺序约束）：在停止黑名单之后、
	// certManager.Shutdown() 之前；StopReconciler nil 安全，未启动时为 no-op。
	// 必须先于 Shutdown（后者清空证书 map 并停止 Updater），避免收敛循环引用已清空组件。
	if s.certManager != nil {
		s.certManager.StopReconciler()
	}

	// 最后关闭证书管理器（此时已无活跃连接）
	if s.certManager != nil {
		s.certManager.Shutdown()
	}
}

func (s *Server) handleRequestForPort(c *gin.Context, hosts []config.HostConfig) {
	r := c.Request

	// ★H1 请求路径规范化强制（全局最先，先于 host 匹配；内部PRD §4.1）：
	// 段级校验拒绝 "." / ".." / 中间空段（//）/ 控制字符段（含 %0A 等编码形态，
	// 校验对象为解码后的 r.URL.Path），非规范路径一律 400 终止，使 public_paths /
	// 保留路径的段边界匹配与后端看到的规范化路径之间不再存在变形空间（审计 H1：
	// ../ 与 // 变形可绕过认证豁免）。strict_path_check=false 为逃生口，本检查
	// 整体跳过（启动已 Warn）。
	if s.config.Server.GetEffectiveStrictPathCheck() && isNonCanonicalRequestPath(r.URL.Path) {
		s.logger.Warn("Request rejected: non-canonical path",
			logger.NewField("method", r.Method),
			logger.NewField("path", r.URL.Path),
			logger.NewField("remote_addr", r.RemoteAddr))
		c.String(http.StatusBadRequest, "Bad Request")
		return
	}

	// ★F3（内部PRD §4.3.3）：Host 规范形态匹配——大小写/尾点/带端口变体
	// 统一归一化后再比对配置名（配置名已在 LoadConfig in-place 归一化），防变体
	// Host 落入通配兜底绕过密码门/IP 白名单。只改局部变量，不回写 r.Host——
	// preserve_host_header / frp customDomains / X-Forwarded-Host 透传不受影响。
	// 非 ASCII Host 归一后保持原样（配置名强制 ASCII）→ 自然 404 fail-closed。
	host := netutil.CanonicalHost(r.Host)

	// 权威 Trace ID（内部PRD §4.1）：直连对端 ∈ trusted_proxies 时按
	// traceparent → X-Lite-Gate-Trace-Id 顺序采信，否则边缘语义重新生成（fail-safe：
	// 未配置 trusted_proxies 恒重新生成）
	traceId, tpFlags, _ := trace.ResolveTraceContext(r, s.trustedProxyNets, s.logger)

	// 回填请求头（决策 D4）：权威 ID 与 traceparent 逐跳写入请求头，下游
	// proxy/websocket 转发时自然携带，访问日志/WAF/blacklist 统一从请求头取值，
	// 双层链路共享同一 ID（此前 ID 只存 gin context，proxy 取不到导致链路断裂）
	r.Header.Set(trace.TraceIdHeader, traceId)
	if tp := trace.BuildTraceParent(traceId, tpFlags); tp != "" {
		r.Header.Set(trace.TraceParentHeader, tp)
	}

	// 响应头唯一注入点（决策 D3，Set 语义）：全路径（含错误页/拦截页/404）前置写入；
	// 唯一例外是 WebSocket 101 手写响应（hijack 后不走 header map，由 websocket.go
	// 写入同一权威 ID）。上游返回的同名响应头由 proxy 复制循环过滤，不再叠加
	c.Header(trace.TraceIdHeader, traceId)

	// Find matching host configuration among hosts for this port
	var matchedHost *config.HostConfig
	var wildcardHost *config.HostConfig

	for _, h := range hosts {
		hostCopy := h
		if hostCopy.Name == host {
			matchedHost = &hostCopy
			break
		} else if hostCopy.Name == "*" {
			wildcardHost = &hostCopy
		}
	}

	// If no exact match found, use wildcard
	if matchedHost == nil && wildcardHost != nil {
		matchedHost = wildcardHost
	}

	if matchedHost == nil {
		s.logger.Warn("No matching host configuration",
			logger.NewField("request_host", host),
			logger.NewField("path", r.URL.Path))
		c.String(http.StatusNotFound, "Not Found")
		return
	}

	// 逐条目跳转 + HSTS 单点下发（内部总体方案 W3-2 / 决策 D8）：位于 host 匹配
	// 成功之后、IP 黑名单之前——命中跳转的请求不进黑名单/allowed_ips/密码门/WAF/代理链路。

	// HSTS 单点下发（收敛历史三处硬编码，内部PRD §5.3 决策 D3）：host 匹配成功后
	// 立即写入，per-host 覆盖值由 GetEffectiveHSTS 决定（nil=默认 DefaultHSTSValue /
	// "off"、""=不下发 / 其他=字面值）。网关负责 TLS 终止，HSTS 由网关管理；空值
	//（off/空串）跳过即不下发。
	// 写在两个提前 return 的 301 分支之前，使全部 HTTPS 响应（正常代理、黑名单拦截页、
	// 密码门、WAF 拦截页、规范化/跳转 301）共享同一 per-host 值；明文 HTTP 一律不带
	// HSTS（r.TLS != nil 守卫不变）。
	if r.TLS != nil {
		if v := matchedHost.GetEffectiveHSTS(); v != "" {
			c.Header("Strict-Transport-Security", v)
		}
	}

	// ① 规范域收敛（redirect_host，http 与 https 都生效）：请求 Host（剥端口后，复用上方
	// net.SplitHostPort 结果）≠ 规范域时 301 → https://<规范域><原始 RequestURI>，
	// 用于 www/别名域收敛到裸域/规范域。最小响应：仅 Location 头，无附加头
	//（HTTPS 下 HSTS 已由上方单点写入，不属于本分支新增）。
	if rh := matchedHost.GetEffectiveRedirectHost(); rh != "" && host != rh {
		c.Header("Location", "https://"+rh+r.URL.RequestURI())
		c.Status(http.StatusMovedPermanently)
		c.Writer.WriteHeaderNow()
		return
	}

	// ② 明文 HTTP → HTTPS（redirect_https）：仅明文 HTTP 监听上生效（r.TLS == nil），
	// 301 → https://<host 配置名><原始 RequestURI>；HTTPS 路径不受影响。
	// L1（内部PRD）：Location 使用 host 配置的规范名称，不再拼接请求 Host
	//（Host 反射）；通配 host 无规范名称，该组合由 config.Validate 启动即拒绝。
	// 逐条目跳转语义：未配置的 host 行为不变，全局 80 端口行为不变（决策 D8）。
	// 明文请求在单点处即被 r.TLS != nil 守卫排除，故本分支 301 不带 HSTS。
	if r.TLS == nil && matchedHost.GetEffectiveRedirectHTTPS() {
		c.Header("Location", "https://"+matchedHost.Name+r.URL.RequestURI())
		c.Status(http.StatusMovedPermanently)
		c.Writer.WriteHeaderNow()
		return
	}

	// ③ C2 shipper 旁路标记（内部PRD §4.4.1"网关自身端点不发送"）：进入 host
	// 代理路径的请求才打标，访问日志 hook 据此过滤网关自身响应（no-match 404 /
	// text host 静态响应等非代理响应不外送）。用 gin context 而非请求头：不随转发
	// 外泄到后端，线上零影响；黑名单/allowed_ips/auth/WAF 拦截的对象仍是代理 host
	// 的真实流量，一并外送（其 status/UA 有观测价值，ingest 侧只打标不丢弃）。
	if len(matchedHost.Backend) > 0 {
		c.Set(ctxKeyShipperProxied, true)
	}

	// IP 黑名单检查（PRD §6.2：host 匹配之后、allowed_ips 之前）。
	// blacklistManager == nil（enabled=false）时此处零开销跳过；
	// host 覆盖为 disabled 时同样跳过。命中即返回，省掉整个 gzip/解压/WAF/代理开销。
	if s.blacklistManager != nil {
		if mode := matchedHost.GetEffectiveBlacklistMode(s.config.Blacklist); mode != config.BlacklistModeDisabled {
			clientIP := netutil.ResolveClientIP(r, s.trustedProxyNets)
			// 本地白名单优先于黑名单查询（豁免监控探针/办公出口，且避免事件刷屏）：
			// 命中则跳过查询与事件记录。使用 NewServer 预解析结果（非法条目已在启动时
			// Warn+跳过）；ParseIP 失败视为未命中白名单。白名单为空时直接短路。
			whitelisted := len(s.blacklistWhitelistNets) > 0 &&
				netutil.IsIPInNetworks(net.ParseIP(clientIP), s.blacklistWhitelistNets)
			if !whitelisted {
				if hit, matched := s.blacklistManager.Lookup(clientIP); hit {
					// 统计与事件（事件在包内按 IP 限速，防扫描器刷屏）
					s.blacklistManager.RecordHit(mode, clientIP, matched, matchedHost.Name, r.URL.Path, traceId)
					if mode != config.BlacklistModeDetect {
						// block 模式：拦截并终止请求（复用 WAF 拦截页观感，PRD §5 决策 3）
						s.logger.WithTraceId(traceId).Warn("Request blocked by IP blacklist",
							logger.NewField("client_ip", clientIP),
							logger.NewField("matched", matched),
							logger.NewField("mode", mode),
							logger.NewField("host", matchedHost.Name),
							logger.NewField("path", r.URL.Path))
						// HTTPS 拦截响应同样携带 HSTS 头：handleRequestForPort 已在黑名单
						// 检查之前统一写入（per-host 值），拦截页也是网关自身响应，此处继承。
						if s.renderer != nil {
							s.renderer.RenderBlocked(c.Writer, traceId,
								fmt.Sprintf("IP 黑名单拦截：来源 IP 位于威胁情报黑名单（命中条目：%s）", matched),
								clientIP)
						} else {
							c.String(http.StatusForbidden, "Forbidden")
						}
						return
					}
					// detect 模式：仅记录，放行（继续走 allowed_ips → gzip/WAF/代理）
				}
			}
		}
	}

	// ★F1b per-IP 速率限制（内部PRD §4.1.2）：黑名单之后、allowed_ips 之前。
	// 超速 429 + Retry-After: 1（快速失败，不进解压/WAF/代理链）。与 auth faillock
	// 正交（后者是登录失败惩罚性锁定）。IP 口径同黑名单（解析后 IP）；豁免网段
	//（mesh/监控级联）跳过。
	if s.ipRateLimiter != nil {
		rateIP := netutil.ResolveClientIP(r, s.trustedProxyNets)
		if !s.ipRateLimiter.Allow(rateIP, time.Now()) {
			s.logger.Warn("Request rate limited",
				logger.NewField("client_ip", rateIP),
				logger.NewField("host", matchedHost.Name),
				logger.NewField("path", r.URL.Path))
			c.Header("Retry-After", "1")
			c.String(http.StatusTooManyRequests, "Too Many Requests")
			return
		}
	}

	// allowed_ips: 边缘连接 ACL，按直连对端（TCP RemoteAddr）评估"谁能连到这个 host"
	// （内部PRD §4.3 决策 D2）。不做 XFF 解析：mesh-only 路由
	// （allowed_ips=mesh 网段）的判定对象是上一跳 gate 的直连 IP，与 WAF/blacklist
	// 按"解析后真实客户端 IP"评估的语义不同。ResolveClientIP 传 nil 恒等于直连对端，
	// 同时消除每请求重复 ParseTrustedProxies 的开销。
	if ip := matchedHost.GetEffectiveAllowedIPs(); len(ip) > 0 {
		directIP := netutil.ResolveClientIP(r, nil)
		if !clientIPInRanges(directIP, ip) {
			s.logger.Warn("Request from disallowed client IP",
				logger.NewField("host", matchedHost.Name),
				logger.NewField("client_ip", directIP),
				logger.NewField("path", r.URL.Path))
			c.String(http.StatusForbidden, "Forbidden")
			return
		}
	}

	// ★ 密码门检查（内部PRD）：插入点在 allowed_ips 之后、WebSocket 判定 /
	// gzip / WAF 之前——未认证请求不进 WAF、不触后端，最省开销；WebSocket 在升级前
	// 拦截（登录后浏览器 WS 握手自动携带 cookie 正常升级）；robots.txt 同样被拦
	// （密码站不向爬虫暴露内容）。保留路径（/_gate-auth/*）命中后直接 return，不再进
	// 中间件链。仅 Auth 启用的 host 有实例，查表未命中零开销跳过。
	if mgr := s.authByHost[matchedHost.Name]; mgr != nil {
		if mgr.Evaluate(c.Writer, r) {
			// gin ResponseWriter 延迟写状态码（首次 body 写入才落盘）：auth 的
			// 303/302/401 响应对 POST 无 body，需显式落盘状态码，否则记录器/真实
			// 响应保持默认 200
			c.Writer.WriteHeaderNow()
			return
		}
	}

	// RFC 6455 规范判断 WebSocket 升级请求
	isWebSocket := netutil.IsWebSocketUpgrade(r)

	// Get effective gzip configuration for this host
	gzipEnabled := matchedHost.GetEffectiveGZipEnabled(s.config.Server.GZipEnabled)

	// Middleware chain (outermost → innermost):
	// 1. GzipHandler — compresses response bodies (outermost, wraps everything)
	// 2. DecompressRequestHandler — decompresses gzip request bodies so WAF sees plaintext
	// 3. WAF — inspects decompressed request body and headers
	// 4. processRequest — proxy or static text handler
	// This order ensures WAF inspects decompressed (plaintext) request bodies,
	// preventing gzip-compressed malicious payloads from bypassing WAF rules.

	// HSTS 头已在 host 匹配后统一单点写入（per-host 覆盖，W3-2），代理主路径直接继承。

	// Check if WAF is enabled for this host
	var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.processRequest(w, r, matchedHost)
	})

	// WAF inspects the decompressed plaintext request
	// WAF applies to all requests including WebSocket; intercept403Writer implements Hijack
	if wafInstance, exists := s.wafByHost[matchedHost.Name]; exists {
		handler = wafInstance.WrapHandler(handler, matchedHost.Name)
	}

	// Decompress gzip/deflate request bodies before WAF inspection
	// Must wrap outside WAF so WAF sees plaintext body, not gzip ciphertext
	// F5（内部PRD §4.5）：解压策略按 host 注入——解压窗口（F1.5，缺省
	// 1MB 与 SecRequestBodyLimit 对齐）与编码放行清单（br/zstd 透传，其余 415）
	handler = middleware.DecompressRequestHandler(handler, middleware.DecompressPolicy{
		MaxDecompressedBytes:    matchedHost.GetEffectiveMaxDecompressedRequestBody(),
		AllowedContentEncodings: matchedHost.AllowedContentEncodings,
	})

	// Apply gzip middleware if enabled - gzip last (compresses response)
	// WebSocket requests skip gzip because it buffers response data, breaking Hijack
	if gzipEnabled && !isWebSocket {
		handler = middleware.GzipHandler(handler, s.config.Server.GZipLevel, s.config.Server.GZipMinSize)
	}

	// Process request
	handler.ServeHTTP(c.Writer, r)
}

// RobotsDenyAllContent is the forced robots.txt body injected by infra-gate
// when robots_deny_all=true. It overrides any robots.txt served by the backend.
// The leading comments explain the origin so misconfigured hosts are easy to trace.
const RobotsDenyAllContent = `# This robots.txt is forcibly injected by infra-gate (robots_deny_all=true).
# It overrides any robots.txt served by the backend service.
# To restore backend behavior, set "robots_deny_all: false" or remove the field on this host.
User-agent: *
Disallow: /
`

func (s *Server) processRequest(w http.ResponseWriter, r *http.Request, host *config.HostConfig) {
	// Get TraceID from request header (since we're not using gin.Context here)
	traceId := trace.GetTraceIdFromRequest(r)

	loggerWithTrace := s.logger
	if traceId != "" {
		loggerWithTrace = s.logger.WithTraceId(traceId)
	}

	// robots_deny_all: 强制覆盖 /robots.txt，拒绝所有搜索引擎爬虫。
	// 此响应由 infra-gate 直接返回，不转发后端——即使后端配置了 robots.txt 也会被覆盖。
	// 排查提示：若该主机出现 Disallow: / 的 robots.txt，请检查 host 配置的 robots_deny_all。
	if host.GetEffectiveRobotsDenyAll() && r.URL.Path == "/robots.txt" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		// 显式落盘 200：请求走 NoRoute 链时 gin 的 serveError 已把 writermem.status
		// 预置为 404，延迟写语义下只 Write body 会让响应用错误的 404 状态码落盘
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(RobotsDenyAllContent))
		return
	}

	// If host has backends, use proxy
	if len(host.Backend) > 0 {
		if p, exists := s.proxies[host.Name]; exists {
			p.ServeHTTP(w, r)
			return
		}
	}

	// H6/H8/H10: 对 infra-gate 自身的响应添加安全头
	// （代理透传请求不注入，由后端应用自行控制）
	const gateCSP = "default-src 'self'; frame-ancestors 'none'; base-uri 'self'"
	gateHeaders := map[string]string{
		"Content-Security-Policy": gateCSP,
		"X-Content-Type-Options":  "nosniff",
		"X-Frame-Options":         "DENY",
		"Referrer-Policy":         "no-referrer",
	}

	// Otherwise, return configured text
	if host.Text != "" {
		w.Header().Set("Content-Type", "text/plain")
		for k, v := range gateHeaders {
			w.Header().Set(k, v)
		}
		// 显式落盘 200：请求走 NoRoute 链时 gin 的 serveError 已把 writermem.status
		// 预置为 404，延迟写语义下只 Write body 会让 text 响应变成"HTTP 404 + 正确
		// body"（backend host 由 ReverseProxy 显式写状态码，不受影响）
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(host.Text))
		return
	}

	loggerWithTrace.Warn("No backend or text configured for host",
		logger.NewField("host", host.Name))

	// 使用模板渲染器渲染系统错误页面
	if s.renderer != nil {
		for k, v := range gateHeaders {
			w.Header().Set(k, v)
		}
		s.renderer.RenderSystemError(w, traceId, "配置错误", "警告", r.URL.Path, "")
	} else {
		for k, v := range gateHeaders {
			w.Header().Set(k, v)
		}
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("Not Found"))
	}
}

func (s *Server) generateWAFConfigKey(wafConfig config.WAFConfig) string {
	// golden_dir 为指针：nil 与空串语义不同（默认启用 vs 显式禁用），键中需区分
	goldenDirKey := "<nil>"
	if wafConfig.CRS.GoldenDir != nil {
		goldenDirKey = *wafConfig.CRS.GoldenDir
	}
	// 内部PRD：failure_policy / retry_count / golden_dir 纳入键，
	// 避免不同策略/预算/金副本配置的 host 共享同一 WAF 实例
	raw := fmt.Sprintf("enabled:%v|default_mode:%v|request_body_access:%v|wl_enabled:%v|wl_ranges:%v|crs_enabled:%v|crs_version:%v|crs_failure_policy:%v|crs_timeout:%v|crs_retry_count:%v|crs_golden_dir:%v|proxy_enabled:%v|proxy_url:%v|proxy_user:%v|proxy_pass:%v|custom_enabled:%v|custom_rules:%v|debug_level:%v|debug_file:%v",
		wafConfig.Enabled,
		wafConfig.DefaultMode,
		wafConfig.GetRequestBodyAccess(),
		wafConfig.Whitelist.Enabled,
		wafConfig.Whitelist.IPRanges,
		wafConfig.CRS.Enabled,
		wafConfig.CRS.Version,
		wafConfig.CRS.FailurePolicy,
		wafConfig.CRS.Download.Timeout,
		wafConfig.CRS.Download.RetryCount,
		goldenDirKey,
		wafConfig.CRS.Download.Proxy.Enabled,
		wafConfig.CRS.Download.Proxy.URL,
		wafConfig.CRS.Download.Proxy.Username,
		wafConfig.CRS.Download.Proxy.Password,
		wafConfig.Custom.Enabled,
		wafConfig.Custom.RulesFile,
		wafConfig.Debug.LogLevel,
		wafConfig.Debug.LogFile)
	hash := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(hash[:])
}

func (s *Server) createWAFInstance(wafConfig config.WAFConfig) (*waf.Middleware, error) {
	wafInstance, stats, err := waf.CreateWAF(wafConfig, s.logger)
	if err != nil {
		return nil, err
	}

	// 创建白名单检查器
	whitelist := waf.CreateFromConfig(wafConfig, s.logger)

	return waf.NewMiddleware(wafInstance, whitelist, wafConfig.Enabled, wafConfig.DefaultMode, s.logger, s.renderer, s.config.Server.TrustedProxies, stats), nil
}

// resguardMiddleware F1a 并发信号量挂点（内部PRD §4.1.1）：全局 +
// per-IP 两阶段试占；全局占满 503 + Retry-After（进访问日志），per-IP 占满同 503。
// Acquire 带 c.Request.Context()：客户端断开自动放行等待者。IP 口径复用
// ResolveClientIP + trustedProxyNets（与黑名单/访问日志一致）。
func (s *Server) resguardMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if s.reqSemaphore == nil {
			c.Next()
			return
		}
		ip := netutil.ResolveClientIP(c.Request, s.trustedProxyNets)
		if !s.reqSemaphore.Acquire(c.Request.Context(), ip) {
			c.Header("Retry-After", "1")
			c.String(http.StatusServiceUnavailable, "Service Unavailable: gateway at capacity")
			c.Abort()
			return
		}
		defer s.reqSemaphore.Release(ip)
		c.Next()
	}
}

// ginLoggerMiddleware 将ILogger适配到gin的日志中间件
func (s *Server) ginLoggerMiddleware() gin.HandlerFunc {
	return gin.LoggerWithConfig(gin.LoggerConfig{
		Formatter: func(param gin.LogFormatterParams) string {
			// TraceID 取回填后的请求头（内部PRD §5.2）：handleRequestForPort
			// 在 handler 链执行前已回填权威 ID，访问日志与 WAF/blacklist 事件取值
			// 来源统一；不再读 gin context 兜底
			traceId := ""
			if param.Request != nil {
				traceId = param.Request.Header.Get(trace.TraceIdHeader)
			}

			// client_ip 与 blacklist/WAF 的取值口径对齐（内部PRD §5.3）：
			// 按 trusted_proxies 预解析真实客户端 IP；trusted 为空时回落直连对端，
			// 伪造 X-Forwarded-For / X-Real-IP 无法污染访问日志
			//（engine 已 SetTrustedProxies(nil)，gin 自带的 param.ClientIP 恒为直连对端，不再使用）。
			resolvedClientIP := ""
			if param.Request != nil {
				resolvedClientIP = netutil.ResolveClientIP(param.Request, s.trustedProxyNets)
			}

			// F12.5（内部PRD §4.12.5）：文本访问日志的 path/UA 用 shipper
			// 同一常量截断（超长 URI/UA 不再整条进文本日志；单条 8KB 兜底在
			// logger.sanitizeLogText 层）
			param.Path = truncateLogText(param.Path, shipper.MaxPathLen)
			param.ErrorMessage = truncateLogText(param.ErrorMessage, shipper.MaxPathLen)
			var ua string
			if param.Request != nil {
				ua = truncateLogText(param.Request.UserAgent(), shipper.MaxUserAgentLen)
			}
			// 使用带TraceID的logger记录请求日志
			loggerWithTrace := s.logger
			if traceId != "" {
				loggerWithTrace = s.logger.WithTraceId(traceId)
			}

			// 根据状态码选择日志级别
			if param.StatusCode >= 500 {
				loggerWithTrace.Error("HTTP Request",
					logger.NewField("method", param.Method),
					logger.NewField("path", param.Path),
					logger.NewField("status", param.StatusCode),
					logger.NewField("latency", param.Latency.String()),
					logger.NewField("client_ip", resolvedClientIP),
					logger.NewField("user_agent", ua),
					logger.NewField("error", param.ErrorMessage))
			} else if param.StatusCode >= 400 {
				loggerWithTrace.Warn("HTTP Request",
					logger.NewField("method", param.Method),
					logger.NewField("path", param.Path),
					logger.NewField("status", param.StatusCode),
					logger.NewField("latency", param.Latency.String()),
					logger.NewField("client_ip", resolvedClientIP),
					logger.NewField("user_agent", ua),
					logger.NewField("error", param.ErrorMessage))
			} else {
				loggerWithTrace.Info("HTTP Request",
					logger.NewField("method", param.Method),
					logger.NewField("path", param.Path),
					logger.NewField("status", param.StatusCode),
					logger.NewField("latency", param.Latency.String()),
					logger.NewField("client_ip", resolvedClientIP),
					logger.NewField("user_agent", ua))
			}

			return "" // 返回空字符串，因为我们已经通过ILogger记录了日志
		},
		Output: gin.DefaultWriter, // 虽然我们不会使用这个输出，但需要设置
	})
}

// ctxKeyShipperProxied 是 shipper 旁路标记的 gin context key（handleRequestForPort
// 在请求进入 host 代理路径时 Set，shipperShip 读取；仅进程内使用，不上线）
const ctxKeyShipperProxied = "shipper.proxied"

// shipperMiddleware C2 访问日志旁路 hook 挂点（内部PRD §4.4.1/D7/D9）：
// 紧跟 ginLoggerMiddleware 注册（同位置旁路），响应完成后组装结构化记录交 shipper
// 有界缓冲。硬约束：
//   - 纯旁路——Ship 内部 recover 包裹 + 非阻塞入队，任何异常等效于本中间件不存在；
//   - 既有文本访问日志（ginLoggerMiddleware）的格式、字段、级别分流零变更。
func (s *Server) shipperMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			// 中间件本体兜底 recover：即使 hook 组装代码意外 panic 也绝不外抛
			// （内层 handler panic 由 gin.Recovery 处理，此处不参与其语义）
			if r := recover(); r != nil {
				s.logger.Warn("Tracker shipper middleware panic suppressed",
					logger.NewField("panic", fmt.Sprint(r)),
					logger.NewField("path", c.Request.URL.Path))
			}
		}()
		start := time.Now()
		c.Next()
		s.shipperShip(c, time.Since(start))
	}
}

// shipperShip 组装单条旁路访问记录（req_class 打标在 Shipper.Ship 的 recover 作用域
// 内完成）。字段取值与既有访问日志同源：
//   - client_ip：netutil.ResolveClientIP + s.trustedProxyNets，与 ginLoggerMiddleware
//     / blacklist / WAF 的真实 IP 口径完全一致（复用同一预解析网段，不另起一套）；
//   - trace_id：回填后的 X-Lite-Gate-Trace-Id 请求头（与文本访问日志同源）；
//   - bytes/Content-Type：c.Writer.Size() / 响应头（PRD D9 指定读点）；
//   - status/latency：与 gin.LoggerWithConfig 相同来源（c.Writer.Status() /
//     中间件计时），文本日志输出不受影响。
//
// 网关自身端点（no-match 404、text host 静态响应等未走 host 代理的请求）不发送；
// admin/health 端点在独立 admin engine 上，本就不经过该中间件链。
func (s *Server) shipperShip(c *gin.Context, latency time.Duration) {
	defer func() {
		// D7：hook 任何路径绝不外抛、绝不阻塞主链路；异常只采样记日志
		if r := recover(); r != nil {
			if s.trackerShipper == nil || s.trackerShipper.LogSampled() {
				s.logger.Warn("Tracker shipper hook panic suppressed",
					logger.NewField("panic", fmt.Sprint(r)),
					logger.NewField("path", c.Request.URL.Path))
			}
		}
	}()

	// shipper 未启用（默认关）：零开销直返
	if s.trackerShipper == nil {
		return
	}

	// 网关自身响应（未走 host 代理路径）不发送
	if !c.GetBool(ctxKeyShipperProxied) {
		return
	}

	r := c.Request
	if r == nil || r.URL == nil {
		return
	}

	s.trackerShipper.Ship(shipper.Record{
		Method:      r.Method,
		Host:        requestHostOnly(r.Host),
		Path:        r.URL.Path,
		Query:       r.URL.RawQuery,
		Status:      c.Writer.Status(),
		Bytes:       max(c.Writer.Size(), 0), // Size() 在未写响应时为 -1，钳为 0
		LatencyMs:   latency.Milliseconds(),
		RefHost:     referrerHost(r.Referer()),
		UserAgent:   r.UserAgent(),
		ContentType: c.Writer.Header().Get("Content-Type"),
		ClientIP:    netutil.ResolveClientIP(r, s.trustedProxyNets),
		TraceId:     r.Header.Get(trace.TraceIdHeader),
		Ts:          time.Now().UnixMilli(),
		// 浏览器一致性头原值透传（内部PRD：网关看到的就是浏览器原始
		// 请求头，信号保真；ingest 侧喂 BotJudgeInput 做 Sec-Fetch/CH-UA 一致性）
		SecFetchDest: strings.TrimSpace(r.Header.Get("Sec-Fetch-Dest")),
		SecFetchMode: strings.TrimSpace(r.Header.Get("Sec-Fetch-Mode")),
		SecFetchSite: strings.TrimSpace(r.Header.Get("Sec-Fetch-Site")),
		SecCHUA:      strings.TrimSpace(r.Header.Get("Sec-CH-UA")),
	})
}

// requestHostOnly Host 归一化：去端口（支持 IPv6 字面量）；空/解析失败原样返回
func requestHostOnly(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}

// referrerHost Referer 归一化：只保留 host 部分；空或解析失败返回空串
func referrerHost(referer string) string {
	if referer == "" {
		return ""
	}
	if u, err := url.Parse(referer); err == nil {
		return u.Host
	}
	return ""
}

// truncateLogText F12.5：文本日志字段截断（UTF-8 边界回扫 + 复制断开请求行引用）
func truncateLogText(s string, max int) string {
	if len(s) <= max {
		return s
	}
	end := max
	for end > 0 && !utf8.RuneStart(s[end]) {
		end--
	}
	return strings.Clone(s[:end]) + shipper.TruncatedMarker
}

func (s *Server) Stop() {
	s.logger.Info("Stopping server...")

	// Signal shutdown (M5: use sync.Once to prevent double close panic)
	// 代理停止在 shutdownAllServers 中执行，确保先停止接受新连接再等待活跃连接
	s.shutdownOnce.Do(func() {
		close(s.shutdownChan)
	})
}

// clientIPInRanges 判断客户端 IP 是否位于任意给定 IP/CIDR 范围内。
// 传入的 ranges 由配置层已校验过合法性；这里防御性忽略无法解析的条目。
// allowed_ips 为空表示不限制，但调用方应在下发前先判断 len(ranges) > 0。
func clientIPInRanges(clientIP string, ranges []string) bool {
	parsedClientIP := net.ParseIP(clientIP)
	if parsedClientIP == nil {
		return false
	}
	nets := netutil.ParseTrustedProxies(ranges)
	return netutil.IsIPInNetworks(parsedClientIP, nets)
}

// isNonCanonicalRequestPath 判断请求路径是否为非规范形态（H1，段级校验）：
// 段为 "." / ".."、空段（首段与末段除外——前导 "/" 与尾斜杠合法；不用 path.Clean
// 比对，Clean("/a/")="/a" 会误杀合法尾斜杠）、或含控制字符（\x00-\x1f、\x7f）。
// 校验对象是解码后的 r.URL.Path：%0A 等编码控制字符同样命中。
func isNonCanonicalRequestPath(path string) bool {
	segments := strings.Split(path, "/")
	last := len(segments) - 1
	for i, seg := range segments {
		switch {
		case seg == "." || seg == "..":
			return true
		case seg == "":
			// 首段（前导 "/" 产生）与末段（尾斜杠产生）的空段合法，中间空段（//）非法
			if i != 0 && i != last {
				return true
			}
		case hasControlChar(seg):
			return true
		}
	}
	return false
}

// hasControlChar 判断字符串是否含 ASCII 控制字符（\x00-\x1f、\x7f）
func hasControlChar(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] <= 0x1f || s[i] == 0x7f {
			return true
		}
	}
	return false
}

// parseBlacklistWhitelist 预解析黑名单本地白名单条目为 []*net.IPNet（NewServer 时调用一次）。
// 解析规则与 netutil.ParseTrustedProxies 一致：含 "/" 走 net.ParseCIDR，
// 单 IP 按 IPv4/IPv6 补全为 /32 或 /128。非法条目记 Warn（带条目内容）并跳过
// （PRD §7.3 承诺 Warn+跳过，不阻断启动）；返回空切片/nil 表示无有效白名单（不豁免）。
func parseBlacklistWhitelist(entries []string, log logger.ILogger) []*net.IPNet {
	var nets []*net.IPNet
	for _, entry := range entries {
		if n := parseIPNetEntry(entry); n != nil {
			nets = append(nets, n)
		} else {
			log.Warn("Invalid blacklist whitelist entry ignored",
				logger.NewField("entry", entry))
		}
	}
	return nets
}

// parseIPNetEntry 解析单条 IP 或 CIDR 为 *net.IPNet，非法返回 nil
func parseIPNetEntry(entry string) *net.IPNet {
	if strings.Contains(entry, "/") {
		_, network, err := net.ParseCIDR(entry)
		if err != nil {
			return nil
		}
		return network
	}
	ip := net.ParseIP(entry)
	if ip == nil {
		return nil
	}
	bits := 32
	if ip.To4() == nil {
		bits = 128
	}
	_, network, err := net.ParseCIDR(fmt.Sprintf("%s/%d", entry, bits))
	if err != nil {
		return nil
	}
	return network
}

// parseIPNetEntries 批量解析 IP/CIDR 条目为 []*net.IPNet（F1 per-IP 豁免网段用）。
// 条目合法性已由 config.Validate fail-fast 保证；此处非法条目静默跳过（防御）。
func parseIPNetEntries(entries []string) []*net.IPNet {
	var nets []*net.IPNet
	for _, entry := range entries {
		if n := parseIPNetEntry(entry); n != nil {
			nets = append(nets, n)
		}
	}
	return nets
}
