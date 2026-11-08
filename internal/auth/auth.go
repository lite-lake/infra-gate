package auth

// 密码门 Manager（内部PRD §4.3）：每 host 一个运行时实例，持有
// HostAuthConfig、派生 HMAC key、登录/登出/拦截入口。
//
// 请求链检查点位置（server.handleRequestForPort）：
//
//	host 匹配 → IP 黑名单 → allowed_ips → ★ auth 检查（本包）★
//	  → WebSocket 判定 → gzip → decompress → WAF → processRequest
//
// 未认证请求不进 WAF、不触后端；Auth==nil 的 host 无实例、检查点查表跳过（零开销）。

import (
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/lite-lake/infra-gate/internal/config"
	"github.com/lite-lake/infra-gate/internal/infrastructs/logger"
	"github.com/lite-lake/infra-gate/internal/netutil"
	"github.com/lite-lake/infra-gate/internal/resguard"
)

// LockoutNotifier 锁定全局告警通知接口（M3，内部PRD §5）。定义于 auth 包而
// 非直接引用 *notification.Notifier：避免 auth → notification 反向依赖，便于测试注入
// fake（与 server.Notifier / cert.CertNotifier 同构；*notification.Notifier 的
// SendNotification 签名天然满足该接口）。
type LockoutNotifier interface {
	SendNotification(event string, details map[string]string) error
}

// Manager per-host 密码门运行时实例。并发安全：limiter 内部持锁，其余字段构造后只读
// （notifier 经 SetNotifier 在 Start 前注入一次，与 server.SetNotifier 同生命周期约定）。
type Manager struct {
	hostName    string
	password    string
	ttl         time.Duration
	publicPaths []string
	key         []byte
	limiter     *limiter
	// peerLimiter 直连对端维度失败锁定（F2.2，内部PRD §4.2.2）：键
	// "peer:"+直连 IP（仅 resolved ≠ direct 即确实经 XFF 解析时记录），阈值
	// peer_max_failures（缺省 max_failures×10）——封堵 trusted_proxies 内伪 XFF
	// 轮换爆破（解析后 IP 维度永不触发的绕过）
	peerLimiter *limiter
	// loginBudget 登录端点全局预算令牌桶（F2.3，内部PRD §4.2.3）：
	// per-host、所有来源共享（公网 IPv6 轮换的统一兜底）；负值配置时 nil（关闭）
	loginBudget    *resguard.RateLimiter
	trustedProxies []*net.IPNet // 限速键解析口径（M3）：与 WAF/blacklist 的真实客户端 IP 同源
	log            logger.ILogger
	notifier       LockoutNotifier // nil = 未注入（单测），锁定告警 no-op
}

// NewManager 创建该 host 的密码门实例。config.Validate 已 fail-fast 保证
// Password 非空、PublicPaths 以 / 开头，此处不重复校验。
// trustedProxies 为 NewServer 预解析的 server.trusted_proxies 网段（可为 nil）：
// 限速键 = ResolveClientIP(r, trustedProxies)，口径与 WAF/blacklist 一致（M3）；
// trusted_proxies 为空时 ResolveClientIP 回落直连对端（netutil 现语义），边缘部署
// 行为与 M3 之前一致。
func NewManager(hostName string, cfg *config.HostAuthConfig, trustedProxies []*net.IPNet, log logger.ILogger) *Manager {
	// public_paths 段边界匹配（H1，内部PRD §11.3）要求条目为无尾斜杠的
	// 目录前缀形态（path == p || HasPrefix(path, p+"/")）。Normalize 掉尾斜杠
	//（如 "/admin/" → "/admin"），保证旧式前缀语义下合法的尾斜杠条目在升级后
	// 子路径（"/admin/x"）仍豁免，不因段边界匹配静默失效
	publicPaths := make([]string, 0, len(cfg.PublicPaths))
	for _, p := range cfg.PublicPaths {
		publicPaths = append(publicPaths, strings.TrimRight(p, "/"))
	}

	m := &Manager{
		hostName:       hostName,
		password:       cfg.Password,
		ttl:            cfg.GetEffectiveAuthTTL(),
		publicPaths:    publicPaths,
		key:            deriveKey(cfg.Password),
		limiter:        newLimiterWithLimits(cfg.GetEffectiveMaxFailures(), cfg.GetEffectiveLockDuration()),
		peerLimiter:    newLimiterWithLimits(cfg.GetEffectivePeerMaxFailures(), cfg.GetEffectiveLockDuration()),
		trustedProxies: trustedProxies,
		log:            log,
	}
	// F2.3 登录全局预算：负值显式关闭（nil）；rate = perMinute/60 token/s
	if perMinute, enabled := cfg.GetEffectiveLoginRatePerMinute(); enabled {
		m.loginBudget = resguard.NewRateLimiter(float64(perMinute)/60.0, config.DefaultLoginRateBurst, nil)
	}
	return m
}

// SetNotifier 注入锁定全局告警通知器（M3）。main.go 在 srv.Start() 之前经
// server.SetNotifier 级联调用；未注入（如单测）时锁定告警 no-op，不 panic
func (m *Manager) SetNotifier(n LockoutNotifier) {
	m.notifier = n
}

// HostName 返回绑定的虚拟主机名
func (m *Manager) HostName() string { return m.hostName }

// Evaluate 密码门检查点入口。返回 true 表示请求已在本检查点处理完毕
// （保留路径已响应，或未认证已拦截），调用方应直接 return；
// 返回 false 表示放行，继续后续中间件链（WS 判定 / gzip / WAF / 代理）。
func (m *Manager) Evaluate(w http.ResponseWriter, r *http.Request) bool {
	path := r.URL.Path

	// 保留路径：/_gate-auth 与 /_gate-auth/*（含无斜杠裸路径 /_gate-auth，H1 补漏——
	// 此前裸路径不命中前缀、会按普通路径拦截/转发）由网关自身处理，不再转发后端
	// （PRD §3 保留路径）
	if path == AuthPathRoot || strings.HasPrefix(path, AuthPathPrefix) {
		m.serveReserved(w, r)
		return true
	}

	// public_paths 段边界豁免（H1，内部PRD）：完整段相等或以其为父目录才
	// 豁免——/adminX 不因前缀误命中 /admin；配合网关入口的路径规范化强制（同 PRD），
	// `../`、`//` 等变形在 host 匹配前已被 400，此处不再有变形空间
	for _, p := range m.publicPaths {
		if path == p || strings.HasPrefix(path, p+"/") {
			return false
		}
	}

	// 有效会话放行：登录后该 host 下所有请求（页面/静态资源/API/WS 握手）
	// 自动携带 cookie，像正常网页一样访问，业务应用无感知（PRD §1.2 目标 4）
	if m.validSession(r) {
		return false
	}

	// 未认证：浏览器导航 302 登录页；API/XHR/WS 升级 401（PRD §6.4）
	m.intercept(w, r)
	return true
}

// validSession 判断请求携带的 cookie 是否为该 host 的有效会话
func (m *Manager) validSession(r *http.Request) bool {
	c, err := r.Cookie(AuthCookieName)
	if err != nil || c.Value == "" {
		return false
	}
	return VerifyToken(c.Value, m.key, m.hostName, time.Now())
}

// clientIPForAuth 防爆破限速的评估对象（M3，内部PRD §5）：解析后真实客户端
// IP（netutil.ResolveClientIP + server.trusted_proxies 口径），与 WAF/blacklist 一致；
// trusted_proxies 为空时函数内回落直连对端（不改其语义）。此前为恒直连对端——
// mesh/内网部署共享出口的合法用户可被单 IP 锁死、分布式爆破却按每直连 IP 独立计数
func (m *Manager) clientIPForAuth(r *http.Request) string {
	return netutil.ResolveClientIP(r, m.trustedProxies)
}

// notifyLockout IP 触发锁定阈值时的全局告警（M3，内部PRD §5）。发送模式对齐
// waf_crs_degraded（server.notifier 异步 best-effort，错误不阻断请求链）；去重策略：
// notifier 本身无冷却机制，由调用方保证——recordFailure 仅在「未锁定 → 锁定」跳变沿
// 返回 locked=true，且锁定期内 handler 的锁定检查（M1 前移）不再走到 recordFailure，
// 故每个锁定会话至多一条，锁过期后再次触发属新会话（重新告警是预期行为）。
// 通知含 host、键 IP、失败次数与锁定时长。
func (m *Manager) notifyLockout(clientIP string, failures int) {
	if m.notifier == nil {
		return
	}
	m.log.Warn("Auth lockout triggered, sending global notification",
		logger.NewField("host", m.hostName),
		logger.NewField("client_ip", clientIP),
		logger.NewField("failures", failures))
	_ = m.notifier.SendNotification("auth_lockout", map[string]string{
		"host":      m.hostName,
		"client_ip": clientIP,
		"失败次数":      strconv.Itoa(failures),
		"锁定时长":      m.limiter.LockDuration().String(),
		"风险":        "登录口令正被持续爆破，来源 IP 已被锁定",
	})
}
