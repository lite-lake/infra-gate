package admin

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/lite-lake/infra-gate/internal/blacklist"
	"github.com/lite-lake/infra-gate/internal/config"
)

const (
	// blacklistEventsDefaultLimit /api/blacklist/events 默认返回条数
	blacklistEventsDefaultLimit = 50
	// blacklistEventsMaxLimit /api/blacklist/events 单次返回上限
	blacklistEventsMaxLimit = 200
)

// handleAPIBlacklistStats 返回 IP 黑名单统计 JSON。
// getter 未注入（黑名单未启用/无 server 依赖）时返回全零默认结构，不报错（照 handleAPIWAFStats 的 nil 处理模式）。
func (a *AdminServer) handleAPIBlacklistStats(c *gin.Context) {
	if a.getBlacklistStats == nil {
		c.JSON(http.StatusOK, gin.H{"code": 200, "data": gin.H{
			"enabled":           a.gateConfig.Blacklist.Enabled,
			"default_mode":      effectiveBlacklistMode(a.gateConfig.Blacklist.DefaultMode),
			"sources":           []interface{}{},
			"total_entries":     0,
			"last_success_at":   "",
			"last_attempt_at":   "",
			"loaded_from_cache": false,
			"hit_total_block":   uint64(0),
			"hit_total_detect":  uint64(0),
			"recent_hits":       uint64(0),
		}})
		return
	}

	snap := a.getBlacklistStats()

	sources := make([]gin.H, 0, len(snap.Sources))
	for _, src := range snap.Sources {
		sources = append(sources, gin.H{
			"name": src.Name,
			// H34: 去除 URL 中可能内嵌的用户名/密码，防止通过 admin API 泄露
			"url":           sanitizeBackendURL(src.URL),
			"entries":       src.Entries,
			"invalid_lines": src.InvalidLines,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"code": 200,
		"data": gin.H{
			"enabled":           snap.Enabled,
			"default_mode":      effectiveBlacklistMode(snap.DefaultMode),
			"sources":           sources,
			"total_entries":     snap.TotalEntries,
			"last_success_at":   formatBlacklistTime(snap.LastSuccessAt),
			"last_attempt_at":   formatBlacklistTime(snap.LastAttemptAt),
			"loaded_from_cache": snap.LoadedFromCache,
			"hit_total_block":   snap.HitTotalBlock,
			"hit_total_detect":  snap.HitTotalDetect,
			"recent_hits":       snap.RecentHits,
		},
	})
}

// handleAPIBlacklistEvents 返回最近的 IP 黑名单命中事件列表 JSON。
// ?limit= 可选，默认 50，上限 200，非法/非正值回退默认。
func (a *AdminServer) handleAPIBlacklistEvents(c *gin.Context) {
	limit := blacklistEventsDefaultLimit
	if raw := c.Query("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			limit = n
			if limit > blacklistEventsMaxLimit {
				limit = blacklistEventsMaxLimit
			}
		}
	}

	if a.getBlacklistEvents == nil {
		c.JSON(http.StatusOK, gin.H{"code": 200, "data": []interface{}{}})
		return
	}

	events := a.getBlacklistEvents(limit)

	c.JSON(http.StatusOK, gin.H{
		"code": 200,
		"data": events,
	})
}

// effectiveBlacklistMode 规范化展示用的默认模式：空值回退 block
func effectiveBlacklistMode(mode string) string {
	if mode == "" {
		return config.BlacklistModeBlock
	}
	return mode
}

// formatBlacklistTime 将可选时间格式化为 RFC3339 字符串，nil 返回空串
func formatBlacklistTime(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.Format(time.RFC3339)
}

// SetGetBlacklistStats 注入 IP 黑名单统计查询函数
func (a *AdminServer) SetGetBlacklistStats(fn func() blacklist.StatsSnapshot) {
	a.getBlacklistStats = fn
}

// SetGetBlacklistEvents 注入 IP 黑名单事件查询函数
func (a *AdminServer) SetGetBlacklistEvents(fn func(int) []blacklist.BlacklistEvent) {
	a.getBlacklistEvents = fn
}
