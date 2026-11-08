package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/goccy/go-yaml"
	"github.com/lite-lake/infra-gate/internal/cert"
	"github.com/lite-lake/infra-gate/internal/infrastructs/endpoints"
	"github.com/lite-lake/infra-gate/internal/infrastructs/logger"
	"github.com/lite-lake/infra-gate/internal/netutil"
	"github.com/lite-lake/infra-gate/internal/notification"
)

type ServerConfig struct {
	Port         int  `yaml:"port"`
	GZipEnabled  bool `yaml:"g_zip_enabled"`
	GZipLevel    int  `yaml:"g_zip_level"`
	GZipMinSize  int  `yaml:"g_zip_min_size"`
	HTTP2Enabled bool `yaml:"http2_enabled"`
	// ResourceGovernance F1 连接/速率/内存三层资源治理（内部PRD §4.1/§5）。
	// 零值兼容：旧配置无该段时全部字段取安全默认值（enabled=true、阈值见缺省常量）
	ResourceGovernance ResourceGovernanceConfig `yaml:"resource_governance"`
	// MaxHeaderBytes 数据面端口请求头字节上限（F1.6，内部PRD §4.1.6）：
	// 1MB 收紧为 32KB；<=0 取 DefaultMaxHeaderBytes。HTTP/2 经显式 MaxHeaderListSize
	// 对齐（http2.ConfigureServer(server, nil) 不继承 http.Server.MaxHeaderBytes）
	MaxHeaderBytes int `yaml:"max_header_bytes"`
	// TrustedProxies 可信代理网段（v1.1 定位：forwarded_for=append host 的追加门槛
	// + WAF/blacklist/access log 的真实 IP 解析网段）。对缺省 host（forwarded_for=""）
	// 的转发头重建不再有任何影响——缺省 host 恒为边缘语义，与该配置完全无关。
	// F2.5 宽度红线（内部PRD §4.2.5）：IPv4 前缀 < /8（IPv6 < /48）拒绝启动
	//（trusted_proxies_allow_wide: true 显式放行降为 Warn）；< /24（IPv6 < /64）
	// 由 NewServer 启动 Warn。过宽网段 = XFF 伪造面过大
	TrustedProxies []string `yaml:"trusted_proxies"`
	// TrustedProxiesAllowWide F2.5 红线逃生口：显式 true 时 < /8（IPv6 < /48）的
	// 超宽网段从拒绝启动降级为启动 Warn（受控放行，现网 /24 部署无需配置）
	TrustedProxiesAllowWide *bool `yaml:"trusted_proxies_allow_wide,omitempty"`
	// WebSocketInsecureSkip L3（内部PRD）：Deprecated——全局 WSS 跳过校验迁移至
	// per-host hosts[].web_socket_insecure_skip；兼容期保留一轮作 per-host nil 时的缺省值，
	// 非 nil=false 的 host 生效；配置非零时启动 Warn（整网关 WSS 校验全关误伤面大）
	WebSocketInsecureSkip bool `yaml:"websocket_insecure_skip"`
	// UpstreamMaxConnsPerHost F1c（内部PRD §4.1.4）：上游单 host 连接池上限
	//（现为 0=无上限）；<=0 取缺省 256。per-host 经 hosts[].upstream_max_conns_per_host
	// 覆盖（LLM host 建议 512+）。注意 h2 上游不受该值约束（对端 MAX_CONCURRENT_STREAMS
	// 自然限流，接受现状）
	UpstreamMaxConnsPerHost int `yaml:"upstream_max_conns_per_host"`
	// UpstreamResponseHeaderTimeout F1c：等待后端响应头时长（缺省维持 1800s 零回归，
	// D1）；per-host 经 hosts[].upstream_response_header_timeout 收紧
	UpstreamResponseHeaderTimeout time.Duration   `yaml:"upstream_response_header_timeout"`
	WebSocket                     WebSocketConfig `yaml:"websocket"`
	// H1：请求路径规范化强制（段级校验，非规范路径 400 终止）。nil = true（默认开）；
	// 显式 false 为逃生口（启动 Warn 一条，内部PRD §7.1）
	StrictPathCheck *bool `yaml:"strict_path_check,omitempty"`
}

// GetEffectiveTrustedProxiesAllowWide 返回 trusted_proxies 超宽网段逃生口：nil = false
func (c *ServerConfig) GetEffectiveTrustedProxiesAllowWide() bool {
	if c.TrustedProxiesAllowWide == nil {
		return false
	}
	return *c.TrustedProxiesAllowWide
}

// GetEffectiveStrictPathCheck 返回是否启用 H1 请求路径规范化强制：nil = true（默认开）
func (c *ServerConfig) GetEffectiveStrictPathCheck() bool {
	if c.StrictPathCheck == nil {
		return true
	}
	return *c.StrictPathCheck
}

// ForwardedForAppend 是 host.forwarded_for 的 mesh 追加语义取值（v1.1）：
// 直连对端 ∈ server.trusted_proxies 时继承入站 XFF/Proto/Host 并追加本跳；
// 直连对端不受信或 gate 未配 trusted_proxies 时 fail-safe 回退边缘语义。
const ForwardedForAppend = "append"

// WebSocketConfig 控制 WebSocket 代理的超时和保活参数
type WebSocketConfig struct {
	HandshakeTimeout time.Duration `yaml:"handshake_timeout"` // 握手超时，默认 30s
	IdleTimeout      time.Duration `yaml:"idle_timeout"`      // 空闲超时（无帧读取），默认 5m
	PingInterval     time.Duration `yaml:"ping_interval"`     // 心跳 ping 间隔，默认 30s
}

// F1 资源治理缺省值（内部PRD §5；全部字段 <=0/nil 时回落，安全默认开）
const (
	// DefaultMaxConcurrentRequests 全局 in-flight 请求上限
	DefaultMaxConcurrentRequests = 4096
	// DefaultPerIPConcurrentRequests per-IP in-flight 请求上限
	DefaultPerIPConcurrentRequests = 64
	// DefaultPerIPRate per-IP 速率（token/秒，宽松档：公网浏览器突发友好）
	DefaultPerIPRate = 50.0
	// DefaultPerIPBurst per-IP 突发桶容量
	DefaultPerIPBurst = 100
	// DefaultWSMaxGlobal WS 全局连接上限
	DefaultWSMaxGlobal = 1024
	// DefaultWSMaxPerHost WS per-host 连接上限
	DefaultWSMaxPerHost = 256
	// DefaultWSMaxPerIP WS per-IP 连接上限
	DefaultWSMaxPerIP = 16
	// DefaultMaxHeaderBytes 数据面请求头字节上限（1MB 收紧为 32KB）
	DefaultMaxHeaderBytes = 32 * 1024
	// DefaultUpstreamMaxConnsPerHost 上游单 host 连接池上限（F1c；原 0=无上限）
	DefaultUpstreamMaxConnsPerHost = 256
	// DefaultUpstreamResponseHeaderTimeout 等待后端响应头时长（F1c；维持既有
	// 1800s 硬编码现值零回归，D1）
	DefaultUpstreamResponseHeaderTimeout = 1800 * time.Second
	// DefaultMaxDecompressedRequestBody gzip/deflate 解压后请求体上限（F1.5：
	// 单一事实源，与 WAF SecRequestBodyLimit 1MB 对齐；原 10MB 收紧。WAF-on
	// host 行为零变化——超 1MB 本来就被 Coraza 413）
	DefaultMaxDecompressedRequestBody = 1 << 20
)

// ResourceGovernanceConfig F1 连接/速率/内存三层资源治理配置（内部PRD §4.1/§5）。
// enabled=nil=true（默认开启，对应 H-2 唯一代码级高危）；显式 false 为逃生口
// （strict_path_check 同款哲学，启动 Warn 一条）。全部阈值字段 <=0 时取缺省常量，
// 旧配置零影响（不透传即安全默认）。
type ResourceGovernanceConfig struct {
	// Enabled 总开关；nil = true。false = 并发信号量/per-IP 限速/WS 上限全部不挂载
	Enabled *bool `yaml:"enabled,omitempty"`
	// MaxConcurrentRequests 全局 in-flight 上限（含 WS 连接存活期）
	MaxConcurrentRequests int `yaml:"max_concurrent_requests"`
	// PerIPConcurrentRequests per-IP in-flight 上限
	PerIPConcurrentRequests int `yaml:"per_ip_concurrent_requests"`
	// PerIPWhitelist per-IP 维度豁免网段（mesh/监控；仅豁免 per-IP 并发与限速，
	// 全局上限仍生效——双层 gate 级联必须配上游网段，否则内网聚合流量误伤）
	PerIPWhitelist []string `yaml:"per_ip_whitelist"`
	// PerIPRate per-IP 速率（token/秒）
	PerIPRate float64 `yaml:"per_ip_rate"`
	// PerIPBurst per-IP 突发桶容量
	PerIPBurst int `yaml:"per_ip_burst"`
	// WSMaxGlobal / WSMaxPerHost / WSMaxPerIP WS 连接三级上限
	WSMaxGlobal  int `yaml:"ws_max_global"`
	WSMaxPerHost int `yaml:"ws_max_per_host"`
	WSMaxPerIP   int `yaml:"ws_max_per_ip"`
}

// GetEffectiveResourceGovernanceEnabled 返回资源治理总开关：nil = true（默认开）
func (c *ServerConfig) GetEffectiveResourceGovernanceEnabled() bool {
	if c.ResourceGovernance.Enabled == nil {
		return true
	}
	return *c.ResourceGovernance.Enabled
}

// GetEffectiveMaxConcurrentRequests 返回全局并发上限：<=0 取缺省 4096
func (c *ServerConfig) GetEffectiveMaxConcurrentRequests() int {
	if c.ResourceGovernance.MaxConcurrentRequests <= 0 {
		return DefaultMaxConcurrentRequests
	}
	return c.ResourceGovernance.MaxConcurrentRequests
}

// GetEffectivePerIPConcurrentRequests 返回 per-IP 并发上限：<=0 取缺省 64
func (c *ServerConfig) GetEffectivePerIPConcurrentRequests() int {
	if c.ResourceGovernance.PerIPConcurrentRequests <= 0 {
		return DefaultPerIPConcurrentRequests
	}
	return c.ResourceGovernance.PerIPConcurrentRequests
}

// GetEffectivePerIPRate 返回 per-IP 速率（token/秒）：<=0 取缺省 50
func (c *ServerConfig) GetEffectivePerIPRate() float64 {
	if c.ResourceGovernance.PerIPRate <= 0 {
		return DefaultPerIPRate
	}
	return c.ResourceGovernance.PerIPRate
}

// GetEffectivePerIPBurst 返回 per-IP 突发容量：<=0 取缺省 100
func (c *ServerConfig) GetEffectivePerIPBurst() int {
	if c.ResourceGovernance.PerIPBurst <= 0 {
		return DefaultPerIPBurst
	}
	return c.ResourceGovernance.PerIPBurst
}

// GetEffectiveWSMaxGlobal 返回 WS 全局连接上限：<=0 取缺省 1024
func (c *ServerConfig) GetEffectiveWSMaxGlobal() int {
	if c.ResourceGovernance.WSMaxGlobal <= 0 {
		return DefaultWSMaxGlobal
	}
	return c.ResourceGovernance.WSMaxGlobal
}

// GetEffectiveWSMaxPerHost 返回 WS per-host 连接上限：<=0 取缺省 256
func (c *ServerConfig) GetEffectiveWSMaxPerHost() int {
	if c.ResourceGovernance.WSMaxPerHost <= 0 {
		return DefaultWSMaxPerHost
	}
	return c.ResourceGovernance.WSMaxPerHost
}

// GetEffectiveWSMaxPerIP 返回 WS per-IP 连接上限：<=0 取缺省 16
func (c *ServerConfig) GetEffectiveWSMaxPerIP() int {
	if c.ResourceGovernance.WSMaxPerIP <= 0 {
		return DefaultWSMaxPerIP
	}
	return c.ResourceGovernance.WSMaxPerIP
}

// GetEffectiveMaxHeaderBytes 返回数据面请求头字节上限：<=0 取缺省 32KB
func (c *ServerConfig) GetEffectiveMaxHeaderBytes() int {
	if c.MaxHeaderBytes <= 0 {
		return DefaultMaxHeaderBytes
	}
	return c.MaxHeaderBytes
}

// GetEffectiveUpstreamMaxConnsPerHost 返回上游单 host 连接上限：<=0 取缺省 256
func (c *ServerConfig) GetEffectiveUpstreamMaxConnsPerHost() int {
	if c.UpstreamMaxConnsPerHost <= 0 {
		return DefaultUpstreamMaxConnsPerHost
	}
	return c.UpstreamMaxConnsPerHost
}

// GetEffectiveUpstreamResponseHeaderTimeout 返回等待后端响应头时长：
// <=0 取缺省 1800s（D1：缺省维持零回归）
func (c *ServerConfig) GetEffectiveUpstreamResponseHeaderTimeout() time.Duration {
	if c.UpstreamResponseHeaderTimeout <= 0 {
		return DefaultUpstreamResponseHeaderTimeout
	}
	return c.UpstreamResponseHeaderTimeout
}

// WAF 运行模式常量
const (
	WAFModeBlock    = "block"    // 阻断模式：命中规则时返回 403
	WAFModeDetect   = "detect"   // 检测模式：命中规则时仅记录，不阻断
	WAFModeDisabled = "disabled" // 停用模式：该主机不挂载 WAF 中间件
)

// WAF CRS 失败策略取值（内部PRD §5.4）
const (
	// WAFFailurePolicyDegrade CRS 完全不可用时监听器照常启动、该配置不启用 WAF，
	// 并发高优告警（可用性优先；prod 是否允许属安全决策）
	WAFFailurePolicyDegrade = "degrade"
	// WAFFailurePolicyFail 维持现状：WAF 构造失败 → NewServer 失败 → 进程退出（安全优先，
	// 默认值，空配置等价 fail）
	WAFFailurePolicyFail = "fail"
)

// DefaultCRSGoldenDir CRS 金副本根目录默认值（内部PRD §5.5 方案 A：打进镜像 /app/crs）。
// 显式配置空串可禁用金副本（卷方案 B 或测试场景）。
const DefaultCRSGoldenDir = "/app/crs"

// DefaultCRSDownloadRetryCount CRS tarball 下载默认轮数（内部PRD §5.3：每轮内先直连后代理）
const DefaultCRSDownloadRetryCount = 2

// DefaultCRSDownloadTimeoutSeconds CRS tarball 下载总预算默认值（秒，内部PRD §5.3）
const DefaultCRSDownloadTimeoutSeconds = 60

// DefaultAuthTTL 密码门会话默认有效期（内部PRD 决策 D2）
const DefaultAuthTTL = 24 * time.Hour

// 密码门防爆破缺省值（M3，内部PRD §5）：与既有硬编码现值一致，
// max_failures / lock_duration <=0 时回落（GetEffective 风格）
const (
	// DefaultAuthMaxFailures 登录失败锁定阈值缺省：5 次
	DefaultAuthMaxFailures = 5
	// DefaultAuthLockDuration 登录失败锁定时长缺省：15 分钟
	DefaultAuthLockDuration = 15 * time.Minute
)

// DefaultHSTSValue per-host hsts 未配置（nil）时的默认 HSTS 响应头值
// （内部总体方案 W3-2 / 决策 D8 保持 nil 语义 = 现状；L7（内部PRD）：
// 默认值去除 preload——进 preload 列表后回退极慢，作为全网默认值偏激进，
// 需要 preload 的域名显式配置 hsts 字面值）
const DefaultHSTSValue = "max-age=31536000; includeSubDomains"

// HostAuthConfig 密码门 per-host 配置（内部PRD §5.2）。
// 启用方式：HostConfig.Auth 非 nil；nil = 不启用密码门，请求链零开销跳过。
type HostAuthConfig struct {
	// Password 访问密码（必填，Validate fail-fast）；gate.yaml 明文落盘（决策 D6）
	Password string `yaml:"password"`
	// TTL 会话有效期，<=0 时取 DefaultAuthTTL（24h）
	TTL time.Duration `yaml:"ttl"`
	// PublicPaths 免认证路径（段边界匹配，H1，内部PRD §11.3）：条目为目录
	// 前缀形态（"/admin" 命中 /admin、/admin/、/admin/x，不命中 /adminX）；尾斜杠
	// 条目运行时归一为无尾斜杠形态。空 = 无豁免（全站拦截）
	PublicPaths []string `yaml:"public_paths,omitempty"`
	// MaxFailures 登录失败锁定阈值（M3，内部PRD §5）：失败累计 N 次锁定
	// 来源 IP；<=0 取 DefaultAuthMaxFailures（5，与现值一致）
	MaxFailures int `yaml:"max_failures,omitempty"`
	// LockDuration 登录失败锁定时长（M3）；<=0 取 DefaultAuthLockDuration（15m）
	LockDuration time.Duration `yaml:"lock_duration,omitempty"`
	// PeerMaxFailures 直连对端维度登录失败阈值（F2.2，内部PRD §4.2.2）：
	// trusted_proxies 内伪 XFF 轮换可让解析后 IP 维度永不触发，第二维度按
	// 直连对端（TCP RemoteAddr）计数封顶轮换爆破；<=0 取 max_failures×10（缺省 50，
	// 兼容合法用户经 mesh 代理链聚合的场景）
	PeerMaxFailures int `yaml:"peer_max_failures,omitempty"`
	// LoginRatePerMinute 登录端点全局预算（F2.3，内部PRD §4.2.3）：
	// per-host 令牌桶（所有来源共享，公网 IPv6 轮换的统一兜底），handleLogin
	// 最前置（锁定检查之前、不读 body）；0=缺省 60 次/分（burst 30），负值显式关闭
	LoginRatePerMinute int `yaml:"login_rate_per_minute,omitempty"`
}

// GetEffectiveMaxFailures 返回有效锁定阈值；<=0 时取缺省 5 次（M3）
func (a *HostAuthConfig) GetEffectiveMaxFailures() int {
	if a.MaxFailures <= 0 {
		return DefaultAuthMaxFailures
	}
	return a.MaxFailures
}

// GetEffectiveLockDuration 返回有效锁定时长；<=0 时取缺省 15 分钟（M3）
func (a *HostAuthConfig) GetEffectiveLockDuration() time.Duration {
	if a.LockDuration <= 0 {
		return DefaultAuthLockDuration
	}
	return a.LockDuration
}

// GetEffectivePeerMaxFailures 返回直连对端维度锁定阈值（F2.2）：<=0 时取
// max_failures×10（兼容 mesh 代理链聚合合法用户的场景），下限 10 防误配为 0
func (a *HostAuthConfig) GetEffectivePeerMaxFailures() int {
	if a.PeerMaxFailures <= 0 {
		v := a.GetEffectiveMaxFailures() * 10
		if v < 10 {
			v = 10
		}
		return v
	}
	return a.PeerMaxFailures
}

// DefaultLoginRatePerMinute 登录端点全局预算缺省（次/分钟，F2.3）
const DefaultLoginRatePerMinute = 60

// DefaultLoginRateBurst 登录端点全局预算突发桶容量（F2.3，固定值不进配置：
// 与缺省速率配套，误配大 burst 会削弱兜底语义）
const DefaultLoginRateBurst = 30

// GetEffectiveLoginRatePerMinute 返回登录端点全局预算（F2.3）：
// 负值 = 显式关闭（返回 enabled=false）；0 = 缺省 60 次/分
func (a *HostAuthConfig) GetEffectiveLoginRatePerMinute() (perMinute int, enabled bool) {
	if a.LoginRatePerMinute < 0 {
		return 0, false
	}
	if a.LoginRatePerMinute == 0 {
		return DefaultLoginRatePerMinute, true
	}
	return a.LoginRatePerMinute, true
}

// GetEffectiveAuthTTL 返回有效会话有效期；TTL<=0 时默认 24h（决策 D2）
func (a *HostAuthConfig) GetEffectiveAuthTTL() time.Duration {
	if a.TTL <= 0 {
		return DefaultAuthTTL
	}
	return a.TTL
}

type WAFConfig struct {
	Enabled           bool               `yaml:"enabled"`                       // 总开关。false → 所有主机 WAF 一律不启用
	DefaultMode       string             `yaml:"default_mode"`                  // 默认运行模式：block | detect | disabled
	RequestBodyAccess *bool              `yaml:"request_body_access,omitempty"` // nil=默认 true（扫描请求体），false=跳过请求体扫描（仅检查头部/查询串）
	Whitelist         WAFWhitelistConfig `yaml:"whitelist"`
	CRS               WAFCRSConfig       `yaml:"crs"`
	Custom            WAFCustomConfig    `yaml:"custom"`
	Debug             WAFDebugConfig     `yaml:"debug"`
}

// WAFCRSConfig CRS 规则包配置（内部PRD：新增 failure_policy / golden_dir /
// download.retry_count，支持缓存自愈与可配置降级）
type WAFCRSConfig struct {
	Enabled bool   `yaml:"enabled"`
	Version string `yaml:"version"`
	// FailurePolicy CRS 完全不可用（无可用缓存且刷新失败、无金副本）时的策略：
	// degrade=该配置无 WAF 启动+高优告警；fail=WAF 构造失败进程退出（默认，安全缺省）
	FailurePolicy string `yaml:"failure_policy"`
	// GoldenDir 金副本根目录指针（只读，不写缓存）：nil=默认 DefaultCRSGoldenDir；
	// 显式空串=禁用金副本。查询路径为 <golden_dir>/<version>/
	GoldenDir *string `yaml:"golden_dir,omitempty"`
	// DegradedAcknowledged F11（内部PRD §4.11.2）双钥匙确认：
	// failure_policy=degrade 必须同时显式配 true 才允许启动——无环境概念，
	// 任何环境误配难度上升（degrade = 无 WAF 运行的高危降级，须显式承认）
	DegradedAcknowledged *bool                `yaml:"degrade_acknowledged,omitempty"`
	Download             WAFCRSDownloadConfig `yaml:"download"`
}

// GetEffectiveFailurePolicy 返回有效的 CRS 失败策略：空=WAFFailurePolicyFail（维持现状的安全缺省）
func (c *WAFCRSConfig) GetEffectiveFailurePolicy() string {
	if c.FailurePolicy == "" {
		return WAFFailurePolicyFail
	}
	return c.FailurePolicy
}

// GetEffectiveGoldenDir 返回有效金副本根目录。第二个返回值 false = 金副本已禁用
// （显式配置空串）；nil（未配置）= 默认 DefaultCRSGoldenDir（内部PRD §5.5）
func (c *WAFCRSConfig) GetEffectiveGoldenDir() (string, bool) {
	if c.GoldenDir == nil {
		return DefaultCRSGoldenDir, true
	}
	if *c.GoldenDir == "" {
		return "", false
	}
	return *c.GoldenDir, true
}

type WAFCRSDownloadConfig struct {
	Timeout int `yaml:"timeout"`
	// RetryCount tarball 下载总预算内的最大轮数，<=0 取 DefaultCRSDownloadRetryCount；
	// 每轮内先直连后代理（内部PRD §5.3）
	RetryCount int               `yaml:"retry_count"`
	Proxy      WAFCRSProxyConfig `yaml:"proxy"`
	MirrorURL  endpoints.Config  `yaml:"mirror_url"`
	// PinnedSHA256 H2（内部PRD §7.3）：单版本期望 tarball sha256（最高优先）。
	// 非空时优先于金副本根目录 pins.sha256 清单（两者同时存在记 Info 说明配置优先）；
	// 与清单都无 → 拒绝下载（D2），走既有 stale/degrade 状态机按 failure_policy 处置
	PinnedSHA256 string `yaml:"pinned_sha256,omitempty"`
	// MirrorAllowInsecureHTTP H2：镜像站明文 http 放行开关（内网明文镜像需显式声明）。
	// nil = false（mirror_url 仅允许 https，明文 http 启动校验直接报错）；显式 true 启动 Warn
	MirrorAllowInsecureHTTP *bool `yaml:"mirror_allow_insecure_http,omitempty"`
}

// GetEffectiveRetryCount 返回有效下载轮数：<=0 取默认 2
func (d *WAFCRSDownloadConfig) GetEffectiveRetryCount() int {
	if d.RetryCount <= 0 {
		return DefaultCRSDownloadRetryCount
	}
	return d.RetryCount
}

// GetEffectiveMirrorAllowInsecureHTTP 返回是否放行明文 http 镜像端点：nil = false（仅 https）
func (d *WAFCRSDownloadConfig) GetEffectiveMirrorAllowInsecureHTTP() bool {
	if d.MirrorAllowInsecureHTTP == nil {
		return false
	}
	return *d.MirrorAllowInsecureHTTP
}

// pinnedSHA256HexLen 十六进制 SHA256 摘要长度（pinned_sha256 格式校验用）
const pinnedSHA256HexLen = 64

// GetEffectivePinnedSHA256 返回归一化后的配置 pin（H2）：去首尾空白 → 容忍可选的
// `sha256:` 前缀（与 GitHub Release digest 同款形态， stripping 后参与比较）→ 小写归一。
// 空串/纯空白返回空串 = 未配置。格式合法性由 Validate fail-fast 把关，此处只做归一化
func (d *WAFCRSDownloadConfig) GetEffectivePinnedSHA256() string {
	pin := strings.TrimSpace(d.PinnedSHA256)
	if lower := strings.ToLower(pin); strings.HasPrefix(lower, "sha256:") {
		pin = strings.TrimSpace(pin[len("sha256:"):])
	}
	return strings.ToLower(pin)
}

// validatePinnedSHA256 校验 pinned_sha256 格式（H2 fail-fast）：非空白时归一化后必须是
// 64 位十六进制。畸形 pin 若放行会在每次刷新的完整性校验处反复失败、白白耗尽下载
// 预算且错误难定位，故启动即拒绝；仅写 `sha256:` 前缀无摘要同样拒绝（不静默降级为
// 「未配置」，避免误回退镜像清单）
func validatePinnedSHA256(pin string) error {
	trimmed := strings.TrimSpace(pin)
	if trimmed == "" {
		return nil
	}
	normalized := (&WAFCRSDownloadConfig{PinnedSHA256: trimmed}).GetEffectivePinnedSHA256()
	if len(normalized) != pinnedSHA256HexLen || !isPinnedSHA256Hex(normalized) {
		return fmt.Errorf("waf.crs.download.pinned_sha256 %q must be a %d-char hex sha256 (optional %q prefix allowed), got %d chars after normalization", pin, pinnedSHA256HexLen, "sha256:", len(normalized))
	}
	return nil
}

// isPinnedSHA256Hex 判断字符串是否全为十六进制字符
func isPinnedSHA256Hex(s string) bool {
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

// validateMirrorURLScheme 校验镜像端点 scheme（H2，内部PRD §7.4 fail-fast）：
// 明文 http 仅在 mirror_allow_insecure_http 显式放行时允许（内网明文镜像逃生口，D6）。
// URL 解析失败的条目不在此拦截（交由运行期下载路径报错），此处只做明文 http 的启动拒绝
func validateMirrorURLScheme(mirrorURLs endpoints.Config, allowInsecureHTTP bool) error {
	for _, raw := range mirrorURLs.All() {
		u, err := url.Parse(strings.TrimSpace(raw))
		if err != nil {
			continue
		}
		if u.Scheme == "http" && !allowInsecureHTTP {
			return fmt.Errorf("waf.crs.download.mirror_url %q uses plaintext http; set waf.crs.download.mirror_allow_insecure_http: true to allow (内部PRD H2)", raw)
		}
	}
	return nil
}

// GetEffectiveTimeoutSeconds 返回 tarball 下载总预算（秒）：<=0 取默认 60。
// 内部PRD §5.3：不再做「<180s 提到 180s」的钳制，配置值即总预算。
func (d *WAFCRSDownloadConfig) GetEffectiveTimeoutSeconds() int {
	if d.Timeout <= 0 {
		return DefaultCRSDownloadTimeoutSeconds
	}
	return d.Timeout
}

type WAFCRSProxyConfig struct {
	Enabled  bool   `yaml:"enabled"`
	URL      string `yaml:"url"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type WAFCustomConfig struct {
	Enabled   bool   `yaml:"enabled"`
	RulesFile string `yaml:"rules_file"`
}

type WAFWhitelistConfig struct {
	Enabled  bool     `yaml:"enabled"`
	IPRanges []string `yaml:"ip_ranges"`
}

type WAFDebugConfig struct {
	LogLevel int    `yaml:"log_level"`
	LogFile  string `yaml:"log_file"`
}

// HostWAFOverride 是 per-host 的 WAF 覆盖配置，所有可选字段使用指针类型。
// nil 表示"未设置"，不会覆盖全局配置；非 nil 表示显式覆盖。
// 这解决了值类型无法区分"零值"与"未设置"的问题。
type HostWAFOverride struct {
	DefaultMode       *string                   `yaml:"default_mode,omitempty"`
	RequestBodyAccess *bool                     `yaml:"request_body_access,omitempty"` // nil=继承全局，false=跳过请求体扫描
	Whitelist         *HostWAFWhitelistOverride `yaml:"whitelist,omitempty"`
	CRS               *HostWAFCRSOverride       `yaml:"crs,omitempty"`
	Custom            *HostWAFCustomOverride    `yaml:"custom,omitempty"`
	Debug             *HostWAFDebugOverride     `yaml:"debug,omitempty"`
}

type HostWAFWhitelistOverride struct {
	Enabled  *bool     `yaml:"enabled,omitempty"`
	IPRanges *[]string `yaml:"ip_ranges,omitempty"`
}

type HostWAFCRSOverride struct {
	Enabled *bool   `yaml:"enabled,omitempty"`
	Version *string `yaml:"version,omitempty"`
	// FailurePolicy per-host 失败策略覆盖：nil=继承全局；非空时必须为 degrade|fail
	FailurePolicy *string `yaml:"failure_policy,omitempty"`
	// GoldenDir per-host 金副本根目录覆盖：nil=继承全局；显式空串=该 host 禁用金副本
	GoldenDir *string `yaml:"golden_dir,omitempty"`
	// DegradedAcknowledged F11 双钥匙：per-host override 配 degrade 时必须同时
	// 显式配 true（本字段不继承全局——两把钥匙各自独立）
	DegradedAcknowledged *bool                       `yaml:"degrade_acknowledged,omitempty"`
	Download             *HostWAFCRSDownloadOverride `yaml:"download,omitempty"`
}

type HostWAFCRSDownloadOverride struct {
	Timeout    *int                     `yaml:"timeout,omitempty"`
	RetryCount *int                     `yaml:"retry_count,omitempty"`
	Proxy      *HostWAFCRSProxyOverride `yaml:"proxy,omitempty"`
	MirrorURL  *endpoints.Config        `yaml:"mirror_url,omitempty"`
}

type HostWAFCRSProxyOverride struct {
	Enabled  *bool   `yaml:"enabled,omitempty"`
	URL      *string `yaml:"url,omitempty"`
	Username *string `yaml:"username,omitempty"`
	Password *string `yaml:"password,omitempty"`
}

type HostWAFCustomOverride struct {
	Enabled   *bool   `yaml:"enabled,omitempty"`
	RulesFile *string `yaml:"rules_file,omitempty"`
}

type HostWAFDebugOverride struct {
	LogLevel *int    `yaml:"log_level,omitempty"`
	LogFile  *string `yaml:"log_file,omitempty"`
}

type HostConfig struct {
	Name                string                 `yaml:"name"`
	Port                int                    `yaml:"port"`
	SSLPort             int                    `yaml:"ssl_port,omitempty"`
	SSLConfig           *cert.CertConfig       `yaml:"ssl_config,omitempty"`
	Text                string                 `yaml:"text"`
	Backend             []string               `yaml:"backend"`
	HealthCheck         string                 `yaml:"health_check"`
	HealthCheckInterval time.Duration          `yaml:"health_check_interval"`
	HealthCheckTimeout  time.Duration          `yaml:"health_check_timeout"`
	HealthCheckEnabled  *bool                  `yaml:"health_check_enabled"`  // 改为指针，可以为空，默认启用
	WAF                 *HostWAFOverride       `yaml:"waf,omitempty"`         // per-host WAF 覆盖配置，nil = 继承全局
	Blacklist           *HostBlacklistOverride `yaml:"blacklist,omitempty"`   // per-host IP 黑名单覆盖配置，nil = 继承全局
	GZipEnabled         *bool                  `yaml:"g_zip_enabled"`         // 改为指针，可以为空，用于覆盖服务器配置
	HTTP2Enabled        *bool                  `yaml:"http2_enabled"`         // 改为指针，可以为空，用于覆盖服务器配置
	PreserveHostHeader  *bool                  `yaml:"preserve_host_header"`  // 是否保留原始Host头，默认false（重写为后端主机名）
	OverrideHost        string                 `yaml:"override_host"`         // 自定义Host头值，优先级最高
	OverrideOrigin      string                 `yaml:"override_origin"`       // 自定义Origin头值，用于覆盖客户端Origin
	StripProxyHeaders   *bool                  `yaml:"strip_proxy_headers"`   // 是否剥离所有代理相关头部，默认false
	ForwardedFor        string                 `yaml:"forwarded_for"`         // per-host 转发头策略（v1.1）：""=边缘语义（缺省，恒删头重建），"append"=mesh 追加语义
	RobotsDenyAll       *bool                  `yaml:"robots_deny_all"`       // 强制覆盖 /robots.txt 拒绝所有搜索引擎爬虫，nil=false
	AllowedIPs          []string               `yaml:"allowed_ips,omitempty"` // 仅允许这些来源 IP/CIDR 访问该 host，空=nil=不限制（任何人可访问）
	Auth                *HostAuthConfig        `yaml:"auth,omitempty"`        // 密码门 per-host 配置（内部PRD），nil = 不启用
	// RedirectHTTPS 明文 HTTP 监听上收到请求时不代理，直接 301 → https://<原 host><RequestURI>
	// （内部总体方案 W3-2 / 决策 D8：逐条目跳转语义，不做全局 80 端口行为变更）。nil = false
	RedirectHTTPS *bool `yaml:"redirect_https,omitempty"`
	// RedirectHost 规范域收敛：该 host（http 与 https 都算）请求 Host（剥端口后）≠ 本值时，
	// 301 → https://<RedirectHost><RequestURI>。用于 www/别名域收敛到裸域/规范域；空 = 不启用
	RedirectHost string `yaml:"redirect_host,omitempty"`
	// HSTS 响应头 per-host 覆盖：nil = 默认 DefaultHSTSValue（现状）；"off"（大小写不敏感）或 ""
	// = 不下发；其他值 = 按字面值下发。用于双层网关链路只让边缘层下发一次
	HSTS *string `yaml:"hsts,omitempty"`
	// WebSocketInsecureSkip L3（内部PRD §7.1）：per-host WSS 上游跳过证书校验。
	// nil = 继承全局 ServerConfig.WebSocketInsecureSkip（兼容期，全局字段 Deprecated）；
	// 两处同时配置时 per-host 优先。显式 true（无论来源）启动 Warn
	WebSocketInsecureSkip *bool `yaml:"web_socket_insecure_skip,omitempty"`
	// UpstreamMaxConnsPerHost F1c（内部PRD §4.1.4）：该 host 的上游连接池
	// 上限覆盖；nil = 继承 server 级（缺省 256）
	UpstreamMaxConnsPerHost *int `yaml:"upstream_max_conns_per_host,omitempty"`
	// UpstreamResponseHeaderTimeout F1c：该 host 的响应头等待时长覆盖（收紧用）；
	// nil = 继承 server 级（缺省 1800s 维持不变，D1）
	UpstreamResponseHeaderTimeout *time.Duration `yaml:"upstream_response_header_timeout,omitempty"`
	// MaxDecompressedRequestBody F1.5（内部PRD §4.1.5）：该 host 的解压后
	// 请求体上限；<=0 取缺省 1MB（与 SecRequestBodyLimit 单一事实源对齐）。
	// 仅服务 body 扫描关闭的上传 host 放宽
	MaxDecompressedRequestBody int `yaml:"max_decompressed_request_body,omitempty"`
	// AllowedContentEncodings F5（内部PRD §4.5）：per-host 编码放行清单，
	// 取值 ∈ {br, zstd}（fail-fast）；命中则原样透传（不进 WAF 正文检测）。
	// 空（缺省）= br/zstd/未知编码一律 415 fail-close。非空启动 Warn
	AllowedContentEncodings []string `yaml:"allowed_content_encodings,omitempty"`
}

// GetEffectiveUpstreamMaxConnsPerHost 返回该 host 的上游连接上限：nil 继承 server 级
func (h *HostConfig) GetEffectiveUpstreamMaxConnsPerHost(serverMax int) int {
	if h.UpstreamMaxConnsPerHost == nil || *h.UpstreamMaxConnsPerHost <= 0 {
		return serverMax
	}
	return *h.UpstreamMaxConnsPerHost
}

// GetEffectiveUpstreamResponseHeaderTimeout 返回该 host 的响应头等待时长：
// nil 继承 server 级
func (h *HostConfig) GetEffectiveUpstreamResponseHeaderTimeout(serverTimeout time.Duration) time.Duration {
	if h.UpstreamResponseHeaderTimeout == nil || *h.UpstreamResponseHeaderTimeout <= 0 {
		return serverTimeout
	}
	return *h.UpstreamResponseHeaderTimeout
}

// GetEffectiveMaxDecompressedRequestBody 返回该 host 的解压后请求体上限：
// <=0 取缺省 1MB
func (h *HostConfig) GetEffectiveMaxDecompressedRequestBody() int {
	if h.MaxDecompressedRequestBody <= 0 {
		return DefaultMaxDecompressedRequestBody
	}
	return h.MaxDecompressedRequestBody
}

// GetEffectiveWebSocketInsecureSkip 返回该 host 的 WSS 上游证书校验跳过开关（L3）：
// per-host 显式配置优先，nil = 继承全局值（兼容期缺省）
func (h *HostConfig) GetEffectiveWebSocketInsecureSkip(serverSkip bool) bool {
	if h.WebSocketInsecureSkip == nil {
		return serverSkip
	}
	return *h.WebSocketInsecureSkip
}

// GetEffectiveWAFConfig 获取有效的WAF配置（虚拟主机配置优先，如果为空则使用全局配置）
// per-host 覆盖使用指针类型，nil 表示"未设置"，不会覆盖全局配置
func (h *HostConfig) GetEffectiveWAFConfig(globalWAF WAFConfig) WAFConfig {
	if h.WAF == nil {
		return globalWAF
	}

	effective := globalWAF

	// DefaultMode：per-host 显式设置时覆盖全局配置
	if h.WAF.DefaultMode != nil && *h.WAF.DefaultMode != "" {
		effective.DefaultMode = *h.WAF.DefaultMode
	}

	// RequestBodyAccess：per-host 显式设置时覆盖全局配置；nil = 继承全局（默认扫描请求体）
	if h.WAF.RequestBodyAccess != nil {
		effective.RequestBodyAccess = h.WAF.RequestBodyAccess
	}

	// Whitelist 配置合并
	if h.WAF.Whitelist != nil {
		if h.WAF.Whitelist.Enabled != nil {
			effective.Whitelist.Enabled = *h.WAF.Whitelist.Enabled
		}
		// IPRanges: nil pointer = inherit global; non-nil (even pointing to empty slice) = explicit override
		if h.WAF.Whitelist.IPRanges != nil {
			effective.Whitelist.IPRanges = *h.WAF.Whitelist.IPRanges
		}
	}

	// CRS 配置合并：per-host 显式设置时覆盖全局配置
	if h.WAF.CRS != nil {
		if h.WAF.CRS.Enabled != nil {
			effective.CRS.Enabled = *h.WAF.CRS.Enabled
		}
		if h.WAF.CRS.Version != nil && *h.WAF.CRS.Version != "" {
			effective.CRS.Version = *h.WAF.CRS.Version
		}
		// FailurePolicy：per-host 显式设置时覆盖全局配置
		if h.WAF.CRS.FailurePolicy != nil && *h.WAF.CRS.FailurePolicy != "" {
			effective.CRS.FailurePolicy = *h.WAF.CRS.FailurePolicy
		}
		// GoldenDir：指针整体覆盖（nil=继承全局；显式空串=该 host 禁用金副本）
		if h.WAF.CRS.GoldenDir != nil {
			effective.CRS.GoldenDir = h.WAF.CRS.GoldenDir
		}
		// CRS Download 配置合并
		if h.WAF.CRS.Download != nil {
			if h.WAF.CRS.Download.Timeout != nil {
				effective.CRS.Download.Timeout = *h.WAF.CRS.Download.Timeout
			}
			if h.WAF.CRS.Download.RetryCount != nil {
				effective.CRS.Download.RetryCount = *h.WAF.CRS.Download.RetryCount
			}
			// MirrorURL: per-host 显式设置时覆盖全局配置
			if h.WAF.CRS.Download.MirrorURL != nil && !h.WAF.CRS.Download.MirrorURL.IsEmpty() {
				effective.CRS.Download.MirrorURL = *h.WAF.CRS.Download.MirrorURL
			}
			if h.WAF.CRS.Download.Proxy != nil {
				if h.WAF.CRS.Download.Proxy.Enabled != nil {
					effective.CRS.Download.Proxy.Enabled = *h.WAF.CRS.Download.Proxy.Enabled
				}
				if h.WAF.CRS.Download.Proxy.URL != nil && *h.WAF.CRS.Download.Proxy.URL != "" {
					effective.CRS.Download.Proxy.URL = *h.WAF.CRS.Download.Proxy.URL
				}
				if h.WAF.CRS.Download.Proxy.Username != nil {
					effective.CRS.Download.Proxy.Username = *h.WAF.CRS.Download.Proxy.Username
				}
				if h.WAF.CRS.Download.Proxy.Password != nil {
					effective.CRS.Download.Proxy.Password = *h.WAF.CRS.Download.Proxy.Password
				}
			}
		}
	}

	// Custom 配置合并
	if h.WAF.Custom != nil {
		if h.WAF.Custom.Enabled != nil {
			effective.Custom.Enabled = *h.WAF.Custom.Enabled
		}
		if h.WAF.Custom.RulesFile != nil && *h.WAF.Custom.RulesFile != "" {
			effective.Custom.RulesFile = *h.WAF.Custom.RulesFile
		}
	}

	// Debug 配置合并
	if h.WAF.Debug != nil {
		if h.WAF.Debug.LogLevel != nil {
			effective.Debug.LogLevel = *h.WAF.Debug.LogLevel
		}
		if h.WAF.Debug.LogFile != nil && *h.WAF.Debug.LogFile != "" {
			effective.Debug.LogFile = *h.WAF.Debug.LogFile
		}
	}

	return effective
}

// GetRequestBodyAccess 返回是否扫描请求体。nil 时默认为 true（保持现有行为：启用请求体扫描）
func (c WAFConfig) GetRequestBodyAccess() bool {
	if c.RequestBodyAccess == nil {
		return true
	}
	return *c.RequestBodyAccess
}

// GetEffectiveGZipEnabled 获取有效的GZip配置（虚拟主机配置优先，如果为空则使用服务器配置）
func (h *HostConfig) GetEffectiveGZipEnabled(serverGZipEnabled bool) bool {
	if h.GZipEnabled == nil {
		return serverGZipEnabled
	}
	return *h.GZipEnabled
}

// GetEffectiveHTTP2Enabled 获取有效的HTTP/2配置（虚拟主机配置优先，如果为空则使用服务器配置）
func (h *HostConfig) GetEffectiveHTTP2Enabled(serverHTTP2Enabled bool) bool {
	if h.HTTP2Enabled == nil {
		return serverHTTP2Enabled
	}
	return *h.HTTP2Enabled
}

// GetEffectivePreserveHostHeader 获取有效的PreserveHostHeader配置（虚拟主机配置优先，如果为空则使用默认值false）
func (h *HostConfig) GetEffectivePreserveHostHeader() bool {
	if h.PreserveHostHeader == nil {
		return false
	}
	return *h.PreserveHostHeader
}

// GetEffectiveOverrideHost 获取有效的OverrideHost配置
func (h *HostConfig) GetEffectiveOverrideHost() string {
	return h.OverrideHost
}

// GetEffectiveOverrideOrigin 获取有效的OverrideOrigin配置
func (h *HostConfig) GetEffectiveOverrideOrigin() string {
	return h.OverrideOrigin
}

// GetEffectiveStripProxyHeaders 获取有效的StripProxyHeaders配置（虚拟主机配置优先，如果为空则使用默认值false）
func (h *HostConfig) GetEffectiveStripProxyHeaders() bool {
	if h.StripProxyHeaders == nil {
		return false
	}
	return *h.StripProxyHeaders
}

// GetEffectiveForwardedFor 返回该 host 的转发头策略（v1.1 per-host 转发策略）。
// ""（缺省）= 边缘语义：恒删除入站转发头并按直连对端重建，与 server.trusted_proxies 无关；
// "append" = mesh 追加语义：直连对端受信时继承入站 XFF/Proto/Host 并追加本跳。
// 合法值由 Validate fail-fast 校验。
func (h *HostConfig) GetEffectiveForwardedFor() string {
	return h.ForwardedFor
}

// GetEffectiveRobotsDenyAll 获取有效的RobotsDenyAll配置（虚拟主机配置优先，如果为空则使用默认值false）
// 启用时网关在 processRequest 中强制返回拒绝所有爬虫的 /robots.txt，不转发后端
func (h *HostConfig) GetEffectiveRobotsDenyAll() bool {
	if h.RobotsDenyAll == nil {
		return false
	}
	return *h.RobotsDenyAll
}

// GetEffectiveAllowedIPs 返回该 host 的来源 IP/CIDR 白名单。
// 返回空表示不限制来源（任何来源均可访问）。
func (h *HostConfig) GetEffectiveAllowedIPs() []string {
	return h.AllowedIPs
}

// GetEffectiveRedirectHTTPS 返回该 host 是否启用明文 HTTP → HTTPS 的 301 跳转
// （内部总体方案 W3-2 / 决策 D8）。nil = false（缺省不跳转，保持现状：
// 全局 80 端口行为不变，跳转语义由配置层逐条目声明）
func (h *HostConfig) GetEffectiveRedirectHTTPS() bool {
	if h.RedirectHTTPS == nil {
		return false
	}
	return *h.RedirectHTTPS
}

// GetEffectiveRedirectHost 返回该 host 的规范域收敛目标（内部总体方案 W3-2）。
// 非空时，该 host 上请求 Host（剥端口后）≠ 本值的请求一律 301 到
// https://<本值><原始 RequestURI>（http 与 https 都生效），用于 www/别名域收敛；
// 空 = 不启用收敛（保持现状）
func (h *HostConfig) GetEffectiveRedirectHost() string {
	return h.RedirectHost
}

// GetEffectiveHSTS 返回该 host 的有效 HSTS 响应头值（内部总体方案 W3-2）：
//   - nil（未配置）→ DefaultHSTSValue（保持历史硬编码默认，现状语义）
//   - "off"（大小写不敏感）或 "" → 空串（不下发 HSTS；双层网关链路只让边缘层下发一次）
//   - 其他值 → 按字面值下发
func (h *HostConfig) GetEffectiveHSTS() string {
	if h.HSTS == nil {
		return DefaultHSTSValue
	}
	if strings.EqualFold(*h.HSTS, "off") {
		return ""
	}
	return *h.HSTS
}

// GetEffectiveHealthCheckEnabled 获取有效的健康检查配置（虚拟主机配置优先，如果为空则默认启用）
func (h *HostConfig) GetEffectiveHealthCheckEnabled() bool {
	if h.HealthCheckEnabled == nil {
		return true
	}
	return *h.HealthCheckEnabled
}

// GetEffectiveSSLConfig 获取有效的SSL配置（虚拟主机配置优先，如果为空则使用全局配置）
func (h *HostConfig) GetEffectiveSSLConfig(globalSSL *cert.CertConfig) *cert.CertConfig {
	if h.SSLConfig == nil {
		return globalSSL
	}
	return h.SSLConfig
}

// DefaultShipper* shipper 配置缺省值（内部PRD §7.1）
const (
	DefaultShipperBufferSize            = 10000
	DefaultShipperBatchSize             = 500
	DefaultShipperFlushInterval         = 1 * time.Second
	DefaultShipperFailureSampleLogRatio = 0.01
)

// ShipperConfig 访问日志旁路 shipper 配置（内部PRD §7.1，经 yamlops 逐节点透传）。
// 逐节点默认关（enabled=false）；Config.TrackerShipper 使用零值兼容语义——配置文件
// 未出现 tracker_shipper 段时为零值，等价 enabled=false，旧配置零影响。
type ShipperConfig struct {
	Enabled       bool          `yaml:"enabled"`        // 默认 false；逐节点启用
	Endpoint      string        `yaml:"endpoint"`       // ingest 批量端点（mesh 域名），enabled 时必填
	SharedSecret  string        `yaml:"shared_secret"`  // 共享密钥（X-Lite-Gw-Secret 头），enabled 时必填
	NodeName      string        `yaml:"node_name"`      // 上报网关节点名，enabled 时必填
	BufferSize    int           `yaml:"buffer_size"`    // 有界缓冲容量，<=0 取缺省 10000
	BatchSize     int           `yaml:"batch_size"`     // 批量触发条数，<=0 取缺省 500
	FlushInterval time.Duration `yaml:"flush_interval"` // 定时 flush 间隔，<=0 取缺省 1s
	// FailureSampleLogRatio 丢弃/失败 warn 日志采样比例（0~1），<=0 取缺省 0.01；
	// 采样日志字段仅含 node/批大小/错误摘要，绝不含 client_ip 原文（PRD §10）
	FailureSampleLogRatio float64 `yaml:"failure_sample_log_ratio"`
}

// WithDefaults 返回合并缺省值后的副本（内部PRD §7.1）：
// 零值/非法值字段取缺省（BufferSize 10000 / BatchSize 500 / FlushInterval 1s /
// FailureSampleLogRatio 0.01）。不改变 Enabled 语义。
func (c ShipperConfig) WithDefaults() ShipperConfig {
	if c.BufferSize <= 0 {
		c.BufferSize = DefaultShipperBufferSize
	}
	if c.BatchSize <= 0 {
		c.BatchSize = DefaultShipperBatchSize
	}
	if c.FlushInterval <= 0 {
		c.FlushInterval = DefaultShipperFlushInterval
	}
	if c.FailureSampleLogRatio <= 0 {
		c.FailureSampleLogRatio = DefaultShipperFailureSampleLogRatio
	}
	return c
}

// validate shipper 配置校验（仅 enabled=true 时 fail-fast，未启用节点零影响）
func (c ShipperConfig) validate() error {
	if !c.Enabled {
		return nil
	}
	if c.Endpoint == "" {
		return fmt.Errorf("tracker_shipper.endpoint is required when tracker_shipper.enabled is true")
	}
	if u, err := url.Parse(c.Endpoint); err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("tracker_shipper.endpoint %q must be a valid http(s) URL", c.Endpoint)
	}
	if c.SharedSecret == "" {
		return fmt.Errorf("tracker_shipper.shared_secret is required when tracker_shipper.enabled is true")
	}
	if c.NodeName == "" {
		return fmt.Errorf("tracker_shipper.node_name is required when tracker_shipper.enabled is true")
	}
	if c.FailureSampleLogRatio < 0 || c.FailureSampleLogRatio > 1 {
		return fmt.Errorf("tracker_shipper.failure_sample_log_ratio must be within [0, 1], got %v", c.FailureSampleLogRatio)
	}
	return nil
}

type Config struct {
	Server       ServerConfig                    `yaml:"server"`
	Hosts        []HostConfig                    `yaml:"hosts"`
	Logger       logger.LoggerConfig             `yaml:"logger"`
	WAF          WAFConfig                       `yaml:"waf"`
	Blacklist    BlacklistConfig                 `yaml:"blacklist"`     // IP 黑名单全局配置
	SSL          *cert.CertConfig                `yaml:"ssl,omitempty"` // 全局默认SSL配置
	Notification notification.NotificationConfig `yaml:"notification"`  // 生命周期事件通知配置
	// TrackerShipper 访问日志旁路 shipper（内部PRD §7.1，默认关）。
	// 零值兼容：旧配置文件无该段时 Enabled=false，等价 shipper 不存在。
	TrackerShipper ShipperConfig `yaml:"tracker_shipper"`
	// NormalizeWarnings F3（内部PRD §4.3）：LoadConfig in-place 归一化时
	// 收集的提示（config 包无 logger，由 main 加载后打印）；不参与序列化
	NormalizeWarnings []string `yaml:"-"`
}

// LoadConfig 读取并校验配置文件。F3（内部PRD §4.3）：Unmarshal 后对
// host.Name（"*" 除外）、redirect_host 做 in-place CanonicalHost 归一化——
// 变体写法（大小写/尾点）统一为规范形态，seenNames 查重按规范名生效；in-place
// 使 authByHost/wafByHost/proxies/证书键/JWT host claim 全部自动一致。
// 归一化提示收集到 NormalizeWarnings（由 main 打印，config 包无 logger）。
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// 检查旧的 waf.mode 字段，输出迁移警告
	var rawCheck map[string]interface{}
	if err := yaml.Unmarshal(data, &rawCheck); err == nil {
		if waf, ok := rawCheck["waf"].(map[string]interface{}); ok {
			if _, hasOldMode := waf["mode"]; hasOldMode {
				return nil, fmt.Errorf("waf.mode is deprecated, please rename to waf.default_mode")
			}
		}
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	config.normalizeHostNames()

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return &config, nil
}

// normalizeHostNames F3 in-place 归一化：host.Name（"*" 除外）与 redirect_host。
// 变体写法发生实际改写时记入 NormalizeWarnings
func (c *Config) normalizeHostNames() {
	for i := range c.Hosts {
		h := &c.Hosts[i]
		if h.Name != "*" {
			if canonical := netutil.CanonicalHost(h.Name); canonical != h.Name {
				c.NormalizeWarnings = append(c.NormalizeWarnings,
					fmt.Sprintf("hosts[%d].name %q normalized to canonical form %q (F3, 内部PRD §4.3)", i, h.Name, canonical))
				h.Name = canonical
			}
		}
		if h.RedirectHost != "" {
			if canonical := netutil.CanonicalHost(h.RedirectHost); canonical != h.RedirectHost {
				c.NormalizeWarnings = append(c.NormalizeWarnings,
					fmt.Sprintf("hosts[%d].redirect_host %q normalized to canonical form %q (F3, 内部PRD §4.3)", i, h.RedirectHost, canonical))
				h.RedirectHost = canonical
			}
		}
	}
}

// ContentEncodingBR / ContentEncodingZstd F5 放行清单仅有的合法取值
// （br/zstd 解压依赖不引入，D5——放行 = 原样透传不进 WAF 正文检测）
const (
	ContentEncodingBR   = "br"
	ContentEncodingZstd = "zstd"
)

// boolDeref 指针布尔解引用（nil = false）
func boolDeref(p *bool) bool { return p != nil && *p }

// isASCIIName 判断配置名是否全 ASCII
func isASCIIName(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// backendSetsIntersect 判断两组 backend 地址是否存在元素级交集
func backendSetsIntersect(a, b []string) bool {
	set := make(map[string]bool, len(a))
	for _, s := range a {
		set[s] = true
	}
	for _, s := range b {
		if set[s] {
			return true
		}
	}
	return false
}

// Validate 校验配置的完整性和合理性，在 LoadConfig 中自动调用
func (c *Config) Validate() error {
	if c.Server.Port <= 0 || c.Server.Port > 65535 {
		return fmt.Errorf("server.port must be between 1 and 65535, got %d", c.Server.Port)
	}

	// GZip 校验（全局配置，不需要在 host 循环中重复检查）
	if c.Server.GZipEnabled {
		if c.Server.GZipLevel != 0 && (c.Server.GZipLevel < -2 || c.Server.GZipLevel > 9) {
			return fmt.Errorf("server.g_zip_level must be between -2 and 9 (or 0 for default), got %d", c.Server.GZipLevel)
		}
		if c.Server.GZipMinSize < 0 {
			return fmt.Errorf("server.g_zip_min_size must be non-negative, got %d", c.Server.GZipMinSize)
		}
	}

	// 校验 trusted_proxies（内部PRD §5.4 fail-fast）：逐条校验 CIDR/裸 IP 格式，
	// 非法条目启动即失败（此前 netutil.ParseTrustedProxies 静默跳过，配置错误无告警）；
	// 禁止默认路由网段（trust-all）——信任所有来源意味着 XFF 伪造防线完全失效（决策 D4）。
	// F2.5 宽度红线（内部PRD §4.2.5）：IPv4 前缀 < /8（IPv6 < /48）拒绝启动；
	// trusted_proxies_allow_wide 显式 true 时降级放行（由 NewServer Warn 提示）
	for _, entry := range c.Server.TrustedProxies {
		if strings.Contains(entry, "/") {
			_, network, err := net.ParseCIDR(entry)
			if err != nil {
				return fmt.Errorf("server.trusted_proxies entry %q is not a valid CIDR: %v", entry, err)
			}
			// 0.0.0.0/0、::/0（及等价写法）= 信任所有来源，边缘防伪造底线失效，禁止配置
			if network.IP.Equal(net.IPv4zero) || network.IP.Equal(net.IPv6zero) {
				return fmt.Errorf("server.trusted_proxies entry %q is a trust-all default route (0.0.0.0/0 or ::/0) and is not allowed", entry)
			}
			// F2.5 红线：超宽网段拒绝（/8 与 /48 是「单一边缘代理基础设施」的合理上限；
			// 更宽意味着内网任意主机可伪造 XFF 污染解析后 IP 口径）
			ones, bits := network.Mask.Size()
			minPrefix := 8
			if bits == 128 {
				minPrefix = 48
			}
			if ones < minPrefix && !c.Server.GetEffectiveTrustedProxiesAllowWide() {
				return fmt.Errorf("server.trusted_proxies entry %q is wider than /%d (IPv6: /48) and is not allowed; narrow the range or set server.trusted_proxies_allow_wide: true to acknowledge (内部PRD F2)", entry, minPrefix)
			}
		} else if net.ParseIP(entry) == nil {
			return fmt.Errorf("server.trusted_proxies entry %q is not a valid IP or CIDR", entry)
		}
	}

	// F1（内部PRD §5）：per_ip_whitelist 条目合法性 fail-fast（网段错误会让
	// mesh 级联豁免静默失效，等价于限速误伤内网）
	for _, entry := range c.Server.ResourceGovernance.PerIPWhitelist {
		if strings.Contains(entry, "/") {
			if _, _, err := net.ParseCIDR(entry); err != nil {
				return fmt.Errorf("server.resource_governance.per_ip_whitelist entry %q is not a valid CIDR: %v", entry, err)
			}
		} else if net.ParseIP(entry) == nil {
			return fmt.Errorf("server.resource_governance.per_ip_whitelist entry %q is not a valid IP or CIDR", entry)
		}
	}

	// 校验全局 WAF DefaultMode
	if c.WAF.DefaultMode != "" && c.WAF.DefaultMode != WAFModeBlock && c.WAF.DefaultMode != WAFModeDetect && c.WAF.DefaultMode != WAFModeDisabled {
		return fmt.Errorf("waf.default_mode must be %q, %q or %q, got %q", WAFModeBlock, WAFModeDetect, WAFModeDisabled, c.WAF.DefaultMode)
	}

	// M2: 当 waf.enabled=false 时，校验子配置一致性
	if !c.WAF.Enabled {
		if c.WAF.CRS.Enabled {
			return fmt.Errorf("waf.crs.enabled is true but waf.enabled is false — global WAF is disabled, sub-configs should be disabled too")
		}
		if c.WAF.Custom.Enabled {
			return fmt.Errorf("waf.custom.enabled is true but waf.enabled is false — global WAF is disabled, sub-configs should be disabled too")
		}
		if c.WAF.Whitelist.Enabled {
			return fmt.Errorf("waf.whitelist.enabled is true but waf.enabled is false — global WAF is disabled, sub-configs should be disabled too")
		}
	}

	// M3: per-host CRS 配置合理性校验
	if c.WAF.CRS.Enabled && c.WAF.CRS.Version == "" {
		return fmt.Errorf("waf.crs.version must be set when waf.crs.enabled is true")
	}

	// M3-CRS 自愈（内部PRD §5.4/§5.7）：failure_policy / download 预算字段校验
	if c.WAF.CRS.FailurePolicy != "" && c.WAF.CRS.FailurePolicy != WAFFailurePolicyDegrade && c.WAF.CRS.FailurePolicy != WAFFailurePolicyFail {
		return fmt.Errorf("waf.crs.failure_policy must be %q or %q, got %q", WAFFailurePolicyDegrade, WAFFailurePolicyFail, c.WAF.CRS.FailurePolicy)
	}
	// F11.2（内部PRD §4.11.2）双钥匙：全局 failure_policy=degrade 必须同时
	// 显式配 degrade_acknowledged: true（degrade = 无 WAF 运行的高危降级）
	if c.WAF.CRS.FailurePolicy == WAFFailurePolicyDegrade && !boolDeref(c.WAF.CRS.DegradedAcknowledged) {
		return fmt.Errorf("waf.crs.failure_policy=degrade requires waf.crs.degrade_acknowledged: true (explicitly acknowledge running without WAF when CRS is unavailable; 内部PRD F11)")
	}
	if c.WAF.CRS.Download.Timeout < 0 {
		return fmt.Errorf("waf.crs.download.timeout must be non-negative, got %d", c.WAF.CRS.Download.Timeout)
	}
	if c.WAF.CRS.Download.RetryCount < 0 {
		return fmt.Errorf("waf.crs.download.retry_count must be non-negative, got %d", c.WAF.CRS.Download.RetryCount)
	}

	// H2（内部PRD §7.4）：镜像站必须 https——mirror_url 为明文 http 且未显式
	// 放行（mirror_allow_insecure_http 非 true）→ 启动校验失败（D6：受控逃生口而非硬拒）
	if err := validateMirrorURLScheme(c.WAF.CRS.Download.MirrorURL, c.WAF.CRS.Download.GetEffectiveMirrorAllowInsecureHTTP()); err != nil {
		return err
	}

	// H2：pinned_sha256 格式 fail-fast——畸形 pin 放行会在每次刷新完整性校验处反复
	// 失败并耗尽下载预算；空值合法（= 查镜像清单）
	if err := validatePinnedSHA256(c.WAF.CRS.Download.PinnedSHA256); err != nil {
		return err
	}

	// M3: per-host Custom 配置合理性校验
	if c.WAF.Custom.Enabled && c.WAF.Custom.RulesFile == "" {
		return fmt.Errorf("waf.custom.rules_file must be set when waf.custom.enabled is true")
	}

	// P2-3: 校验通知配置：enabled=true 时 url 必须非空
	if c.Notification.Enabled && c.Notification.URL.IsEmpty() {
		return fmt.Errorf("notification.url must be set when notification.enabled is true")
	}

	// F6.2（内部PRD §4.6.2）：SSL 配置校验真正接线（此前 CertConfig.Validate
	// 是死代码——http 端点/同启冲突/timeout 越界等错误配置静默通过）
	if c.SSL != nil {
		if err := c.SSL.Validate(); err != nil {
			return fmt.Errorf("ssl: %w", err)
		}
	}

	// 校验 IP 黑名单全局配置（仅 enabled=true 时；whitelist 条目由 server 初始化时预解析容错跳过）
	if c.Blacklist.Enabled {
		if err := c.Blacklist.validate(); err != nil {
			return err
		}
	}

	// 访问日志旁路 shipper 配置校验（内部PRD §7.1）：仅 enabled=true 时
	// fail-fast 要求必填字段；未配置/未启用节点零影响
	if err := c.TrackerShipper.validate(); err != nil {
		return err
	}

	// P2-6: 校验 LoggerConfig
	if c.Logger.EnableFile {
		if c.Logger.LogDir == "" {
			return fmt.Errorf("logger.log_dir must be set when logger.enable_file is true")
		}
		if c.Logger.ArchiveDir == "" {
			return fmt.Errorf("logger.archive_dir must be set when logger.enable_file is true")
		}
	}
	if c.Logger.MaxRetentionDays < 0 {
		return fmt.Errorf("logger.max_retention_days must be non-negative, got %d", c.Logger.MaxRetentionDays)
	}

	seenNames := make(map[string]bool)
	for i, host := range c.Hosts {
		if host.Name == "" {
			return fmt.Errorf("hosts[%d].name is required", i)
		}
		if seenNames[host.Name] {
			return fmt.Errorf("hosts[%d].name %q is duplicated", i, host.Name)
		}
		seenNames[host.Name] = true

		// H33: Port 必须在 1-65535 范围内，不允许 0（会绑定随机端口）
		if host.Port < 1 || host.Port > 65535 {
			return fmt.Errorf("hosts[%d].port must be between 1 and 65535, got %d", i, host.Port)
		}
		if host.SSLPort < 0 || host.SSLPort > 65535 {
			return fmt.Errorf("hosts[%d].ssl_port must be between 0 and 65535, got %d", i, host.SSLPort)
		}

		if len(host.Backend) == 0 && host.Text == "" {
			return fmt.Errorf("hosts[%d] (%s) must have either backend or text configured", i, host.Name)
		}

		// F3（内部PRD §4.3.4）：host.Name 非 ASCII 报错（fail-fast）——
		// CanonicalHost 不做 IDNA 映射，非 ASCII 名永远无法被匹配，配置即错误
		if host.Name != "*" && !isASCIIName(host.Name) {
			return fmt.Errorf("hosts[%d].name %q contains non-ASCII characters; use the punycode/ASCII form (IDNA mapping is intentionally not applied)", i, host.Name)
		}

		// F5（内部PRD §4.5.2）：allowed_content_encodings 取值 ∈ {br, zstd}
		//（fail-fast；其余编码不在放行白名单内，配置即错误）
		for _, enc := range host.AllowedContentEncodings {
			if enc != ContentEncodingBR && enc != ContentEncodingZstd {
				return fmt.Errorf("hosts[%d] (%s): allowed_content_encodings entry %q must be %q or %q", i, host.Name, enc, ContentEncodingBR, ContentEncodingZstd)
			}
		}

		// F3.4 辅助防线：通配条目 backend 与任一「auth 启用或 allowed_ips 非空」条目
		// 存在元素级交集 → 启动报错。变体 Host 请求落通配兜底时若与受保护 host 同
		// 后端，密码门/IP 白名单可被间接绕过（同后端、不同匹配名）；现网无该组合，
		// 属便宜的预防性修复
		if host.Name == "*" {
			for j, other := range c.Hosts {
				if j == i || len(other.Backend) == 0 {
					continue
				}
				if other.Auth == nil && len(other.AllowedIPs) == 0 {
					continue
				}
				if backendSetsIntersect(host.Backend, other.Backend) {
					return fmt.Errorf("hosts[%d] (*) wildcard backend overlaps with protected host %q (auth or allowed_ips) sharing a backend — variant Host fallback would bypass its protections (F3, 内部PRD §4.3.4)", j, other.Name)
				}
			}
		}

		// AllowedIPs 合法性校验：必须是合法 IP 或 CIDR
		for _, entry := range host.AllowedIPs {
			if strings.Contains(entry, "/") {
				if _, _, err := net.ParseCIDR(entry); err != nil {
					return fmt.Errorf("hosts[%d] (%s): allowed_ips entry %q is not a valid CIDR: %v", i, host.Name, entry, err)
				}
			} else if net.ParseIP(entry) == nil {
				return fmt.Errorf("hosts[%d] (%s): allowed_ips entry %q is not a valid IP or CIDR", i, host.Name, entry)
			}
		}

		// 密码门配置校验（内部PRD §5.2 fail-fast）：
		// 启用 auth 时 password 必填；public_paths 条目必须以 / 开头（前缀匹配语义）
		if host.Auth != nil {
			if host.Auth.Password == "" {
				return fmt.Errorf("hosts[%d] (%s): auth.password is required when auth is enabled", i, host.Name)
			}
			for _, p := range host.Auth.PublicPaths {
				if !strings.HasPrefix(p, "/") {
					return fmt.Errorf("hosts[%d] (%s): auth.public_paths entry %q must start with /", i, host.Name, p)
				}
			}
		}

		// forwarded_for 合法值校验（v1.1 per-host 转发策略，fail-fast）：
		// 仅允许 ""（缺省=边缘语义）或 "append"（mesh 追加语义）
		if host.ForwardedFor != "" && host.ForwardedFor != ForwardedForAppend {
			return fmt.Errorf("hosts[%d] (%s): forwarded_for must be empty or %q, got %q", i, host.Name, ForwardedForAppend, host.ForwardedFor)
		}

		// L1 fail-fast（内部PRD）：通配 host（name="*"）配置 redirect_https
		// 直接拒绝——通配 host 无规范名称，301 Location 无法取配置名（此前直接拼
		// 请求 Host，属 Host 反射），启动校验拦截该组合
		if host.Name == "*" && host.GetEffectiveRedirectHTTPS() {
			return fmt.Errorf("hosts[%d] (*): redirect_https cannot be enabled on wildcard host: no canonical host name for the Location header", i)
		}

		// P2-1: override_host 优先级高于 preserve_host_header
		// 同时设置时 override_host 生效，preserve_host_header 被忽略（不报错，避免阻断启动）
		// yamlops gate generator 无条件为所有路由设置 preserve_host_header=true，
		// 当服务配置了 override_host 时两者会同时出现，属于正常情况。

		// P2-2: SSL 配置与 ssl_port 一致性校验
		if host.SSLPort > 0 && host.SSLConfig == nil && c.SSL == nil {
			return fmt.Errorf("hosts[%d] (%s): ssl_port is set but no ssl_config (global or per-host) configured", i, host.Name)
		}
		if host.SSLConfig != nil && host.SSLPort == 0 {
			return fmt.Errorf("hosts[%d] (%s): ssl_config is set but ssl_port is 0", i, host.Name)
		}
		// F6.2：per-host ssl_config 校验接线（wrap 上下文）
		if host.SSLConfig != nil {
			if err := host.SSLConfig.Validate(); err != nil {
				return fmt.Errorf("hosts[%d] (%s): ssl_config: %w", i, host.Name, err)
			}
		}

		// 校验虚拟主机 WAF DefaultMode（覆盖全局）
		if host.WAF != nil && host.WAF.DefaultMode != nil && *host.WAF.DefaultMode != "" {
			dm := *host.WAF.DefaultMode
			if dm != WAFModeBlock && dm != WAFModeDetect && dm != WAFModeDisabled {
				return fmt.Errorf("hosts[%d] (%s): waf.default_mode must be %q, %q or %q, got %q", i, host.Name, WAFModeBlock, WAFModeDetect, WAFModeDisabled, dm)
			}
		}

		// 校验虚拟主机黑名单 DefaultMode（覆盖全局；全局关闭时该覆盖不生效，故不校验）
		if c.Blacklist.Enabled && host.Blacklist != nil && host.Blacklist.DefaultMode != nil && *host.Blacklist.DefaultMode != "" {
			dm := *host.Blacklist.DefaultMode
			if !isValidBlacklistMode(dm) {
				return fmt.Errorf("hosts[%d] (%s): blacklist.default_mode must be %q, %q or %q, got %q", i, host.Name, BlacklistModeBlock, BlacklistModeDetect, BlacklistModeDisabled, dm)
			}
		}

		// M3: per-host CRS 子配置合理性校验
		if host.WAF != nil && host.WAF.CRS != nil {
			if host.WAF.CRS.Enabled != nil && *host.WAF.CRS.Enabled {
				if host.WAF.CRS.Version != nil && *host.WAF.CRS.Version == "" {
					return fmt.Errorf("hosts[%d] (%s): waf.crs.version must not be empty when waf.crs.enabled is true", i, host.Name)
				}
			}
			// per-host failure_policy 覆盖校验（内部PRD §5.4，M3 风格 fail-fast）
			if host.WAF.CRS.FailurePolicy != nil && *host.WAF.CRS.FailurePolicy != "" &&
				*host.WAF.CRS.FailurePolicy != WAFFailurePolicyDegrade && *host.WAF.CRS.FailurePolicy != WAFFailurePolicyFail {
				return fmt.Errorf("hosts[%d] (%s): waf.crs.failure_policy must be %q or %q, got %q", i, host.Name, WAFFailurePolicyDegrade, WAFFailurePolicyFail, *host.WAF.CRS.FailurePolicy)
			}
			// F11.2 双钥匙：per-host override 配 degrade 必须同时显式配该 host 的 ack
			if host.WAF.CRS.FailurePolicy != nil && *host.WAF.CRS.FailurePolicy == WAFFailurePolicyDegrade &&
				!boolDeref(host.WAF.CRS.DegradedAcknowledged) {
				return fmt.Errorf("hosts[%d] (%s): waf.crs.failure_policy=degrade requires waf.crs.degrade_acknowledged: true on this host (内部PRD F11)", i, host.Name)
			}
			// per-host download retry_count 覆盖校验
			if host.WAF.CRS.Download != nil && host.WAF.CRS.Download.RetryCount != nil && *host.WAF.CRS.Download.RetryCount < 0 {
				return fmt.Errorf("hosts[%d] (%s): waf.crs.download.retry_count must be non-negative, got %d", i, host.Name, *host.WAF.CRS.Download.RetryCount)
			}
			// H2：per-host 镜像覆盖同样必须 https（放行开关仅全局一级，防 per-host 绕过）
			if host.WAF.CRS.Download != nil && host.WAF.CRS.Download.MirrorURL != nil && !host.WAF.CRS.Download.MirrorURL.IsEmpty() {
				if err := validateMirrorURLScheme(*host.WAF.CRS.Download.MirrorURL, c.WAF.CRS.Download.GetEffectiveMirrorAllowInsecureHTTP()); err != nil {
					return fmt.Errorf("hosts[%d] (%s): %v", i, host.Name, err)
				}
			}
		}

		// P2-5: per-host CRS override 不校验 effective version
		// 计算合并后的 effective CRS 配置，确保 enabled=true 时 version 非空
		if host.WAF != nil && host.WAF.CRS != nil {
			effectiveCRSEnabled := c.WAF.CRS.Enabled
			if host.WAF.CRS.Enabled != nil {
				effectiveCRSEnabled = *host.WAF.CRS.Enabled
			}
			if effectiveCRSEnabled {
				effectiveVersion := c.WAF.CRS.Version
				if host.WAF.CRS.Version != nil && *host.WAF.CRS.Version != "" {
					effectiveVersion = *host.WAF.CRS.Version
				}
				if effectiveVersion == "" {
					return fmt.Errorf("hosts[%d] (%s): effective CRS version is empty but CRS is enabled (neither host nor global version is set)", i, host.Name)
				}
			}
		}

		// M3: per-host Custom 子配置合理性校验
		if host.WAF != nil && host.WAF.Custom != nil {
			if host.WAF.Custom.Enabled != nil && *host.WAF.Custom.Enabled {
				if host.WAF.Custom.RulesFile != nil && *host.WAF.Custom.RulesFile == "" {
					return fmt.Errorf("hosts[%d] (%s): waf.custom.rules_file must not be empty when waf.custom.enabled is true", i, host.Name)
				}
			}
		}

		// P2-4: health_check_enabled=nil 时参数不校验
		// 当 health_check_enabled 为 nil 时，默认启用健康检查，因此参数必须有效
		effectiveHealthCheckEnabled := host.GetEffectiveHealthCheckEnabled()
		if effectiveHealthCheckEnabled {
			if host.HealthCheckInterval <= 0 {
				return fmt.Errorf("hosts[%d] (%s): health_check_interval must be positive when health check is enabled (or not set), got %v", i, host.Name, host.HealthCheckInterval)
			}
			if host.HealthCheckTimeout <= 0 {
				return fmt.Errorf("hosts[%d] (%s): health_check_timeout must be positive when health check is enabled (or not set), got %v", i, host.Name, host.HealthCheckTimeout)
			}
			if host.HealthCheckTimeout >= host.HealthCheckInterval {
				return fmt.Errorf("hosts[%d] (%s): health_check_timeout (%v) must be less than health_check_interval (%v)", i, host.Name, host.HealthCheckTimeout, host.HealthCheckInterval)
			}
			if host.HealthCheck == "" {
				return fmt.Errorf("hosts[%d] (%s): health_check path must be set when health check is enabled (or not set)", i, host.Name)
			}
		}
	}

	return nil
}
