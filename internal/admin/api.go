package admin

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/lite-lake/infra-gate/internal/constants"
	"github.com/lite-lake/infra-gate/internal/crs"
	"github.com/lite-lake/infra-gate/internal/netutil"
	"github.com/lite-lake/infra-gate/internal/waf"
)

const (
	// wafEventsDefaultLimit /api/waf/events 默认返回条数（WAF 事件环形缓冲上限即 200）
	wafEventsDefaultLimit = 100
	// wafEventsMaxLimit /api/waf/events 单次返回上限
	wafEventsMaxLimit = 200
)

// siteInfo 站点信息
type siteInfo struct {
	Name       string          `json:"name"`
	Port       int             `json:"port"`
	SSLPort    int             `json:"ssl_port"`
	Backends   []string        `json:"backends"`
	Health     map[string]bool `json:"health,omitempty"`
	WAFEnabled bool            `json:"waf_enabled"`
	WAFMode    string          `json:"waf_mode"`
	Text       string          `json:"text,omitempty"`
}

// certInfo 证书信息
type certInfo struct {
	Domain       string `json:"domain"`
	Source       string `json:"source"`
	NotBefore    string `json:"not_before"`
	NotAfter     string `json:"not_after"`
	Expired      bool   `json:"expired"`
	ExpiringSoon bool   `json:"expiring_soon"`
	Fingerprint  string `json:"fingerprint"`
}

// sanitizeBackendURL H34: 去除后端 URL 中的敏感信息（用户名/密码/query 凭据），
// 防止通过 admin API 泄露。F7（内部PRD §4.7.3）：收敛为 netutil.RedactURL
// 薄封装（query 整体 ***，比仅剥 userinfo 更严格——后端 URL 的 query 对排障无价值）
func sanitizeBackendURL(rawURL string) string {
	return netutil.RedactURL(rawURL)
}

// handleAPISites 返回站点列表 JSON
func (a *AdminServer) handleAPISites(c *gin.Context) {
	sites := make([]siteInfo, 0, len(a.gateConfig.Hosts))

	for _, host := range a.gateConfig.Hosts {
		effectiveWAF := host.GetEffectiveWAFConfig(a.gateConfig.WAF)
		wafMode := effectiveWAF.DefaultMode
		if wafMode == "" {
			wafMode = "block"
		}
		// H34: 对后端 URL 去除敏感信息（用户名/密码）
		backends := make([]string, 0, len(host.Backend))
		for _, b := range host.Backend {
			backends = append(backends, sanitizeBackendURL(b))
		}
		info := siteInfo{
			Name:       host.Name,
			Port:       host.Port,
			SSLPort:    host.SSLPort,
			Backends:   backends,
			Text:       host.Text,
			WAFEnabled: effectiveWAF.Enabled,
			WAFMode:    wafMode,
		}

		if len(host.Backend) > 0 && a.getBackendHealth != nil {
			info.Health = a.getBackendHealth(host.Name)
		}

		sites = append(sites, info)
	}

	c.JSON(http.StatusOK, gin.H{
		"code": 200,
		"data": sites,
	})
}

// handleAPICerts 返回证书状态 JSON。
// 内部PRD §7.4 要求 loaded/pending 两段可观测，但实现与 §7.4 草图不同：
// data 保持现有 certInfo 数组一字节不变——下游消费者 app-ac-api 的
// gate_aggregator_service.go 把 data 按数组解析，改成 {loaded, pending} 对象会使其
// 解析失败并把整个网关节点标记为不可达（连带 WAF/黑名单面板全挂；其 envelope 只解
// code/data，顶层多余字段被忽略）。因此 pending 平铺在响应顶层，
// pending 为空时输出 []（非 null）= 全部就绪。
func (a *AdminServer) handleAPICerts(c *gin.Context) {
	certsMap := a.certManager.ListCertificates()

	certs := make([]certInfo, 0, len(certsMap))
	for domain, meta := range certsMap {
		info := certInfo{
			Domain:       domain,
			Source:       meta.Source,
			NotBefore:    meta.NotBefore.Format(time.RFC3339),
			NotAfter:     meta.NotAfter.Format(time.RFC3339),
			Expired:      meta.IsExpired(),
			ExpiringSoon: meta.IsExpiringSoon(),
			Fingerprint:  truncateFingerprint(meta.Fingerprint),
		}
		certs = append(certs, info)
	}

	// PendingSnapshot 契约保证非 nil（reconciler 未启动时返回空切片），JSON 输出 []
	pending := a.certManager.PendingSnapshot()

	c.JSON(http.StatusOK, gin.H{
		"code":    200,
		"data":    certs,
		"pending": pending,
	})
}

// handleAPISystem 返回系统信息 JSON
func (a *AdminServer) handleAPISystem(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"code": 200,
		"data": gin.H{
			"version":      constants.Version,
			"gateway_port": a.gateConfig.Server.Port,
			"admin_url":    a.cfg.String(),
		},
	})
}

// crsStatusFields 计算 CRS 可观测字段（内部PRD §5.6，从 crs 注册表读取）。
// crs_state ∈ valid|stale|degraded|disabled；CRS 启用但注册表暂无该版本条目
// （getter 未注入或 EnsureCRS 未执行的理论路径）时输出 "unknown" 防御值。
func (a *AdminServer) crsStatusFields() (state, source string, cacheAge int64, lastError string) {
	state, source, cacheAge, lastError = "disabled", "", 0, ""
	if !a.gateConfig.WAF.CRS.Enabled {
		return
	}
	state = "unknown"
	if a.getCRSStatus == nil {
		return
	}
	st, ok := a.getCRSStatus(crs.ResolveVersion(a.gateConfig.WAF.CRS.Version))
	if !ok {
		return
	}
	return st.State, st.Source, st.CacheAgeSeconds, st.LastError
}

// handleAPIWAFStats 返回 WAF 拦截统计 JSON。
// 内部PRD §5.6：新增 crs_state / crs_source / crs_cache_age_seconds /
// crs_last_error 字段（经 server 注入 getter 从 crs 注册表读取）；既有字段语义不变。
func (a *AdminServer) handleAPIWAFStats(c *gin.Context) {
	crsState, crsSource, crsCacheAge, crsLastError := a.crsStatusFields()

	if a.getWAFStats == nil {
		c.JSON(http.StatusOK, gin.H{"code": 200, "data": gin.H{
			"total_requests":        uint64(0),
			"total_detected":        uint64(0),
			"total_blocked":         uint64(0),
			"total_passed":          uint64(0),
			"blocks_by_host":        []interface{}{},
			"waf_enabled":           a.gateConfig.WAF.Enabled,
			"waf_mode":              a.gateConfig.WAF.DefaultMode,
			"crs_enabled":           a.gateConfig.WAF.CRS.Enabled,
			"crs_version":           a.gateConfig.WAF.CRS.Version,
			"crs_state":             crsState,
			"crs_source":            crsSource,
			"crs_cache_age_seconds": crsCacheAge,
			"crs_last_error":        crsLastError,
			// F11（内部PRD §4.11.1）：degrade 观测透出（additive）
			"degraded_hosts":        a.degradedHostsValue(),
			"pending_restart_hosts": a.pendingRestartHostsValue(),
			"custom_enabled":        a.gateConfig.WAF.Custom.Enabled,
			"whitelist_count":       len(a.gateConfig.WAF.Whitelist.IPRanges),
			"last_block_time":       "",
			"last_block_ip":         "",
			"last_block_path":       "",
			"last_block_rule_id":    0,
			"last_block_message":    "",
			"last_detect_time":      "",
			"last_detect_ip":        "",
			"last_detect_path":      "",
		}})
		return
	}

	snapshots := a.getWAFStats()

	totalRequests := uint64(0)
	totalDetected := uint64(0)
	totalBlocked := uint64(0)
	totalPassed := uint64(0)
	var blocksByHost []gin.H
	for _, snap := range snapshots {
		totalRequests += snap.TotalRequests
		totalDetected += snap.TotalDetected
		totalBlocked += snap.TotalBlocked
		totalPassed += snap.TotalPassed
		for _, hs := range snap.BlocksByHost {
			blocksByHost = append(blocksByHost, gin.H{
				"host":           hs.HostName,
				"total":          hs.TotalBlocks,
				"total_requests": hs.TotalRequests,
				"total_detected": hs.TotalDetected,
				"total_blocked":  hs.TotalBlocked,
			})
		}
	}

	// 默认 mode 为 block
	wafMode := a.gateConfig.WAF.DefaultMode
	if wafMode == "" {
		wafMode = "block"
	}

	data := gin.H{
		"total_requests":        totalRequests,
		"total_detected":        totalDetected,
		"total_blocked":         totalBlocked,
		"total_passed":          totalPassed,
		"blocks_by_host":        blocksByHost,
		"waf_enabled":           a.gateConfig.WAF.Enabled,
		"waf_mode":              wafMode,
		"crs_enabled":           a.gateConfig.WAF.CRS.Enabled,
		"crs_version":           a.gateConfig.WAF.CRS.Version,
		"crs_state":             crsState,
		"crs_source":            crsSource,
		"crs_cache_age_seconds": crsCacheAge,
		"crs_last_error":        crsLastError,
		"custom_enabled":        a.gateConfig.WAF.Custom.Enabled,
		"whitelist_count":       len(a.gateConfig.WAF.Whitelist.IPRanges),
	}

	// Select the snapshot with the most recent LastBlockTime across all WAF instances
	var lastBlockTime *time.Time
	var lastBlockSnap *waf.StatsSnapshot
	for i := range snapshots {
		snap := &snapshots[i]
		if snap.LastBlockTime != nil {
			if lastBlockTime == nil || snap.LastBlockTime.After(*lastBlockTime) {
				lastBlockTime = snap.LastBlockTime
				lastBlockSnap = snap
			}
		}
	}
	if lastBlockSnap != nil {
		data["last_block_time"] = lastBlockSnap.LastBlockTime.Format(time.RFC3339)
		data["last_block_ip"] = lastBlockSnap.LastBlockIP
		data["last_block_path"] = lastBlockSnap.LastBlockPath
		data["last_block_rule_id"] = lastBlockSnap.LastBlockRuleID
		data["last_block_message"] = lastBlockSnap.LastBlockMsg
	}

	// Select the snapshot with the most recent LastDetectTime across all WAF instances
	var lastDetectTime *time.Time
	var lastDetectSnap *waf.StatsSnapshot
	for i := range snapshots {
		snap := &snapshots[i]
		if snap.LastDetectTime != nil {
			if lastDetectTime == nil || snap.LastDetectTime.After(*lastDetectTime) {
				lastDetectTime = snap.LastDetectTime
				lastDetectSnap = snap
			}
		}
	}
	if lastDetectSnap != nil {
		data["last_detect_time"] = lastDetectSnap.LastDetectTime.Format(time.RFC3339)
		data["last_detect_ip"] = lastDetectSnap.LastDetectIP
		data["last_detect_path"] = lastDetectSnap.LastDetectPath
	}

	c.JSON(http.StatusOK, gin.H{
		"code": 200,
		"data": data,
	})
}

// handleAPIWAFEvents 返回最近的 WAF 拦截事件列表 JSON。
// ?limit= 可选，默认 100，上限 200，非法/非正值回退默认（语义与 /api/blacklist/events 对齐）
func (a *AdminServer) handleAPIWAFEvents(c *gin.Context) {
	limit := wafEventsDefaultLimit
	if raw := c.Query("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			limit = n
			if limit > wafEventsMaxLimit {
				limit = wafEventsMaxLimit
			}
		}
	}

	if a.getWAFEvents == nil {
		c.JSON(http.StatusOK, gin.H{"code": 200, "data": []interface{}{}})
		return
	}

	events := a.getWAFEvents(limit)

	c.JSON(http.StatusOK, gin.H{
		"code": 200,
		"data": events,
	})
}

// handleAPIWAFEventDetail 返回单个 WAF 事件详情 JSON
func (a *AdminServer) handleAPIWAFEventDetail(c *gin.Context) {
	if a.findWAFEvent == nil {
		c.JSON(http.StatusOK, gin.H{"code": 200, "data": nil})
		return
	}

	eventIDStr := c.Param("id")
	eventID, err := strconv.ParseInt(eventIDStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": 400, "message": "invalid event id"})
		return
	}

	ev, found := a.findWAFEvent(eventID)
	if !found {
		c.JSON(http.StatusNotFound, gin.H{"code": 404, "message": "event not found or expired"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code": 200,
		"data": ev,
	})
}

func truncateFingerprint(fp string) string {
	if len(fp) > 64 {
		return fp[:64] + "..."
	}
	return fp
}

// SetGetBackendHealth 注入后端健康状态查询函数
func (a *AdminServer) SetGetBackendHealth(fn func(hostName string) map[string]bool) {
	a.getBackendHealth = fn
}

// SetGetWAFStats 注入 WAF 统计查询函数
func (a *AdminServer) SetGetWAFStats(fn func() []waf.StatsSnapshot) {
	a.getWAFStats = fn
}

// SetGetWAFEvents 注入 WAF 事件查询函数
func (a *AdminServer) SetGetWAFEvents(fn func(int) []waf.WAFEvent) {
	a.getWAFEvents = fn
}

// SetFindWAFEvent 注入 WAF 事件详情查询函数
func (a *AdminServer) SetFindWAFEvent(fn func(int64) (waf.WAFEvent, bool)) {
	a.findWAFEvent = fn
}

// SetGetDegradedWAFHosts F11（内部PRD §4.11.1）：注入当前无 WAF 运行的
// host 列表查询（/api/waf/stats 的 degraded_hosts）
func (a *AdminServer) SetGetDegradedWAFHosts(fn func() []string) {
	a.getDegradedWAFHosts = fn
}

// SetGetPendingRestartWAFHosts F11：注入「CRS 已恢复待重启」host 列表查询
// （/api/waf/stats 的 pending_restart_hosts）
func (a *AdminServer) SetGetPendingRestartWAFHosts(fn func() []string) {
	a.getPendingRestartWAFHosts = fn
}

// degradedHostsValue degraded_hosts 字段取值（未注入 getter 时空数组）
func (a *AdminServer) degradedHostsValue() []string {
	if a.getDegradedWAFHosts == nil {
		return []string{}
	}
	return a.getDegradedWAFHosts()
}

// pendingRestartHostsValue pending_restart_hosts 字段取值（未注入 getter 时空数组）
func (a *AdminServer) pendingRestartHostsValue() []string {
	if a.getPendingRestartWAFHosts == nil {
		return []string{}
	}
	return a.getPendingRestartWAFHosts()
}

// SetGetCRSStatus 注入 CRS 状态查询函数（内部PRD §5.6：从 crs 注册表读取，
// 版本键为全局 waf.crs.version 归一化结果）
func (a *AdminServer) SetGetCRSStatus(fn func(version string) (crs.Status, bool)) {
	a.getCRSStatus = fn
}
