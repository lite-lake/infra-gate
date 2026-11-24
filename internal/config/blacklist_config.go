package config

import (
	"fmt"
	"net/url"
	"time"
)

// Blacklist 运行模式常量
const (
	BlacklistModeBlock    = "block"    // 拦截模式：命中黑名单返回 403（blocked.html）
	BlacklistModeDetect   = "detect"   // 检测模式：命中黑名单仅记录事件与统计，不拦截
	BlacklistModeDisabled = "disabled" // 停用模式：该主机不做黑名单检查
)

// DefaultBlacklistMaxEntries L6：MaxEntries 缺省基数（内部PRD §7.1），
// 与 USTC blackip 实际规模（万级）保持同一量级并留有余量
const DefaultBlacklistMaxEntries = 200000

// BlacklistConfig IP 黑名单全局配置（YAML 中与 waf: 平级）
type BlacklistConfig struct {
	Enabled          bool                    `yaml:"enabled"`            // 总开关。false → 完全不启用黑名单
	DefaultMode      string                  `yaml:"default_mode"`       // 默认运行模式：block | detect | disabled，空 = block
	Sources          []BlacklistSourceConfig `yaml:"sources"`            // 数据源列表（如 USTC blackip）
	UpdateInterval   time.Duration           `yaml:"update_interval"`    // 定时刷新间隔，0 = 默认 1h（校验最低 30m）
	Timeout          time.Duration           `yaml:"timeout"`            // 单次拉取超时，0 = 默认 60s（校验范围 (0, 5m]）
	Proxy            BlacklistProxyConfig    `yaml:"proxy"`              // 拉取代理（与 waf.crs.download.proxy 同构）
	Whitelist        []string                `yaml:"whitelist"`          // 本地豁免 IP/CIDR（非法条目在 server 初始化时预解析 Warn+跳过，不阻断启动）
	IgnorePrivateIPs *bool                   `yaml:"ignore_private_ips"` // 私有/保留网段一律不拦截，nil = 默认 true
	// AllowHTTPSource L6（内部PRD）：允许 http:// 明文数据源（显式放行逃生口，D6）；
	// nil = false（仅 https，明文 http 源启动校验直接报错）
	AllowHTTPSource *bool `yaml:"allow_http_source,omitempty"`
	// MaxEntries L6：防追加式投毒的增长上限基数：新 feed 去重条目数超过
	// max(2×上次成功条目数, MaxEntries) 拒绝替换、保留旧表；<=0 取 DefaultBlacklistMaxEntries
	MaxEntries int `yaml:"max_entries,omitempty"`
	// ── F9 形态围栏（内部PRD §4.9/§5）：不 pin 具体内容，只约束「内容形状」──
	// MinEntries 防污染下限：nil = 1000；显式 0 = 禁用（修小 feed 假安全感）
	MinEntries *int `yaml:"min_entries,omitempty"`
	// CIDRMinPrefixV4 / CIDRMinPrefixV6 单条 CIDR 前缀下限（跳过+计数，不拒表；
	// 实测合法 feed 含 3 条 /12，更严会当天误杀）；<=0 取 12 / 24
	CIDRMinPrefixV4 int `yaml:"cidr_min_prefix_v4,omitempty"`
	CIDRMinPrefixV6 int `yaml:"cidr_min_prefix_v6,omitempty"`
	// MaxV4CoveragePercent 聚合覆盖率上限（拒整表保旧表；现状 0.433%，投毒
	// /1=50%、/8=6.5% 均被拒）；<=0 取 2.0
	MaxV4CoveragePercent float64 `yaml:"max_v4_coverage_percent,omitempty"`
	// MaxV6CIDREntries v6 CIDR 条目独立上限（拒整表）；<=0 取 1000
	MaxV6CIDREntries int `yaml:"max_v6_cidr_entries,omitempty"`
	// CacheTTL 缓存判龄（mtime 超龄忽略+Warn）；<=0 取 72h（对齐 feed 单条
	// 封锁最长 ~3 天语义）
	CacheTTL time.Duration `yaml:"cache_ttl,omitempty"`
	// StalenessThreshold 表龄告警阈值（LastSuccessAt 超龄 Warn + blacklist_stale
	// 通知）；<=0 取 6h（≈6 个刷新周期）
	StalenessThreshold time.Duration `yaml:"staleness_threshold,omitempty"`
}

// BlacklistSourceConfig 单个黑名单数据源
type BlacklistSourceConfig struct {
	Name string `yaml:"name"` // 来源名（磁盘缓存文件名 / stats 展示 / 日志标识）
	URL  string `yaml:"url"`  // 全量列表端点（http/https，纯文本每行一条 IP 或 CIDR）
}

// BlacklistProxyConfig 黑名单拉取代理配置，与 WAFCRSProxyConfig 同构
type BlacklistProxyConfig struct {
	Enabled  bool   `yaml:"enabled"`
	URL      string `yaml:"url"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

// HostBlacklistOverride 是 per-host 的黑名单覆盖配置，可选字段使用指针类型。
// nil 表示"未设置"，不会覆盖全局配置；与 HostWAFOverride 同构。
type HostBlacklistOverride struct {
	DefaultMode *string `yaml:"default_mode,omitempty"` // nil = 继承全局
}

// GetIgnorePrivateIPs 返回是否过滤私有/保留网段。nil = 默认 true（应对 feed 混入保留网段）
func (c BlacklistConfig) GetIgnorePrivateIPs() bool {
	if c.IgnorePrivateIPs == nil {
		return true
	}
	return *c.IgnorePrivateIPs
}

// GetEffectiveAllowHTTPSource 返回是否放行明文 http 数据源：nil = false（仅 https）
func (c BlacklistConfig) GetEffectiveAllowHTTPSource() bool {
	if c.AllowHTTPSource == nil {
		return false
	}
	return *c.AllowHTTPSource
}

// GetEffectiveMaxEntries 返回 L6 增长上限基数：<=0 取 DefaultBlacklistMaxEntries（200000）
func (c BlacklistConfig) GetEffectiveMaxEntries() int {
	if c.MaxEntries <= 0 {
		return DefaultBlacklistMaxEntries
	}
	return c.MaxEntries
}

// F9 缺省常量（内部PRD §4.9/§5）
const (
	DefaultBlacklistMinEntries       = 1000
	DefaultBlacklistCIDRMinPrefixV4  = 12
	DefaultBlacklistCIDRMinPrefixV6  = 24
	DefaultBlacklistMaxV4CoveragePct = 2.0
	DefaultBlacklistMaxV6CIDREntries = 1000
	DefaultBlacklistCacheTTL         = 72 * time.Hour
	DefaultBlacklistStaleness        = 6 * time.Hour
)

// GetEffectiveMinEntries 防污染下限：nil = 1000；显式 0 = 禁用（返回 0 + true）
func (c BlacklistConfig) GetEffectiveMinEntries() (min int, enabled bool) {
	if c.MinEntries == nil {
		return DefaultBlacklistMinEntries, true
	}
	return *c.MinEntries, *c.MinEntries > 0
}

// GetEffectiveCIDRMinPrefixV4 单条 v4 CIDR 前缀下限：<=0 取 12
func (c BlacklistConfig) GetEffectiveCIDRMinPrefixV4() int {
	if c.CIDRMinPrefixV4 <= 0 || c.CIDRMinPrefixV4 > 32 {
		return DefaultBlacklistCIDRMinPrefixV4
	}
	return c.CIDRMinPrefixV4
}

// GetEffectiveCIDRMinPrefixV6 单条 v6 CIDR 前缀下限：<=0 取 24
func (c BlacklistConfig) GetEffectiveCIDRMinPrefixV6() int {
	if c.CIDRMinPrefixV6 <= 0 || c.CIDRMinPrefixV6 > 128 {
		return DefaultBlacklistCIDRMinPrefixV6
	}
	return c.CIDRMinPrefixV6
}

// GetEffectiveMaxV4CoveragePercent 聚合覆盖率上限：<=0 取 2.0
func (c BlacklistConfig) GetEffectiveMaxV4CoveragePercent() float64 {
	if c.MaxV4CoveragePercent <= 0 || c.MaxV4CoveragePercent > 100 {
		return DefaultBlacklistMaxV4CoveragePct
	}
	return c.MaxV4CoveragePercent
}

// GetEffectiveMaxV6CIDREntries v6 CIDR 条目上限：<=0 取 1000
func (c BlacklistConfig) GetEffectiveMaxV6CIDREntries() int {
	if c.MaxV6CIDREntries <= 0 {
		return DefaultBlacklistMaxV6CIDREntries
	}
	return c.MaxV6CIDREntries
}

// GetEffectiveCacheTTL 缓存判龄：<=0 取 72h
func (c BlacklistConfig) GetEffectiveCacheTTL() time.Duration {
	if c.CacheTTL <= 0 {
		return DefaultBlacklistCacheTTL
	}
	return c.CacheTTL
}

// GetEffectiveStalenessThreshold 表龄告警阈值：<=0 取 6h
func (c BlacklistConfig) GetEffectiveStalenessThreshold() time.Duration {
	if c.StalenessThreshold <= 0 {
		return DefaultBlacklistStaleness
	}
	return c.StalenessThreshold
}

// GetEffectiveBlacklistMode 获取该 host 的有效黑名单模式：
// host 显式设置且非空 → 覆盖全局；否则用全局 DefaultMode；全局也为空 → 回退 block
func (h *HostConfig) GetEffectiveBlacklistMode(global BlacklistConfig) string {
	if h.Blacklist != nil && h.Blacklist.DefaultMode != nil && *h.Blacklist.DefaultMode != "" {
		return *h.Blacklist.DefaultMode
	}
	if global.DefaultMode != "" {
		return global.DefaultMode
	}
	return BlacklistModeBlock
}

// isValidBlacklistMode 判断是否为合法的黑名单模式
func isValidBlacklistMode(mode string) bool {
	return mode == BlacklistModeBlock || mode == BlacklistModeDetect || mode == BlacklistModeDisabled
}

// validate 校验黑名单全局配置（仅 enabled=true 时由 Validate 调用）。
// whitelist 条目不在此时校验：非法条目由 server 初始化时预解析并 Warn+跳过，不阻断启动。
func (c BlacklistConfig) validate() error {
	if c.DefaultMode != "" && !isValidBlacklistMode(c.DefaultMode) {
		return fmt.Errorf("blacklist.default_mode must be %q, %q or %q, got %q",
			BlacklistModeBlock, BlacklistModeDetect, BlacklistModeDisabled, c.DefaultMode)
	}

	if len(c.Sources) == 0 {
		return fmt.Errorf("blacklist.sources must not be empty when blacklist.enabled is true")
	}
	seenNames := make(map[string]bool, len(c.Sources))
	allowHTTP := c.GetEffectiveAllowHTTPSource()
	for i, src := range c.Sources {
		if src.Name == "" {
			return fmt.Errorf("blacklist.sources[%d].name must not be empty", i)
		}
		if seenNames[src.Name] {
			return fmt.Errorf("blacklist.sources[%d].name %q is duplicated", i, src.Name)
		}
		seenNames[src.Name] = true

		u, err := url.Parse(src.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			return fmt.Errorf("blacklist.sources[%d] (%s): url %q must be a valid http/https URL", i, src.Name, src.URL)
		}
		// L6（内部PRD）：明文 http 数据源默认拒绝（fail-fast，防明文链路投毒），
		// 内网明文 feed 属既有形态，显式 allow_http_source: true 受控放行（D6）
		if u.Scheme == "http" && !allowHTTP {
			return fmt.Errorf("blacklist.sources[%d] (%s): url %q uses plaintext http; set blacklist.allow_http_source: true to allow (内部PRD L6)", i, src.Name, src.URL)
		}
	}

	// update_interval：0 = 默认 1h（不报错）；非 0 时必须 >= 30m
	if c.UpdateInterval != 0 && c.UpdateInterval < 30*time.Minute {
		return fmt.Errorf("blacklist.update_interval must be at least 30m (or 0 for default 1h), got %v", c.UpdateInterval)
	}

	// timeout：0 = 默认 60s（不报错）；非 0 时必须 ∈ (0, 5m]
	if c.Timeout != 0 && (c.Timeout < 0 || c.Timeout > 5*time.Minute) {
		return fmt.Errorf("blacklist.timeout must be in (0, 5m] (or 0 for default 60s), got %v", c.Timeout)
	}

	return nil
}
