package admin

import (
	"encoding/json"
	"testing"

	"github.com/lite-lake/infra-gate/internal/config"
	"github.com/lite-lake/infra-gate/internal/crs"
)

// parseWAFStatsData 解析 /api/waf/stats 响应的 data 字段
func parseWAFStatsData(t *testing.T, body []byte) map[string]interface{} {
	t.Helper()
	var envelope struct {
		Code int                    `json:"code"`
		Data map[string]interface{} `json:"data"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatalf("parse /api/waf/stats response: %v", err)
	}
	return envelope.Data
}

// TestWAFStatsCRSStateFields 内部PRD §5.6：/api/waf/stats 新增 crs_state /
// crs_source / crs_cache_age_seconds / crs_last_error（从 crs 注册表读取，经 setter 注入）；
// 既有字段（含 crs_enabled / crs_version）语义不变。
func TestWAFStatsCRSStateFields(t *testing.T) {
	// 每个子用例独立版本号，隔离包级状态注册表（PublishStatus 全局）
	version := "v4.19.0-admin-" + t.Name()
	gateCfg := &config.Config{
		WAF: config.WAFConfig{
			Enabled: true,
			CRS: config.WAFCRSConfig{
				Enabled: true,
				Version: version,
			},
		},
	}

	t.Run("registry entry present", func(t *testing.T) {
		crs.PublishStatus(version, crs.Status{
			State:           crs.StateStale,
			Version:         version,
			Source:          crs.SourceCache,
			Dir:             "/tmp/cache",
			CacheAgeSeconds: 3600,
			LastError:       "hash mismatch",
		})

		a := newTestAdminServer(gateCfg)
		a.SetGetCRSStatus(crs.StatusSnapshot)

		data := parseWAFStatsData(t, serveAdminAuthenticatedRequest(t, a, "/api/waf/stats").Body.Bytes())
		if data["crs_state"] != crs.StateStale {
			t.Errorf("crs_state = %v, want stale", data["crs_state"])
		}
		if data["crs_source"] != crs.SourceCache {
			t.Errorf("crs_source = %v, want cache", data["crs_source"])
		}
		if data["crs_cache_age_seconds"] != float64(3600) {
			t.Errorf("crs_cache_age_seconds = %v, want 3600", data["crs_cache_age_seconds"])
		}
		if data["crs_last_error"] != "hash mismatch" {
			t.Errorf("crs_last_error = %v, want hash mismatch", data["crs_last_error"])
		}
		// 既有字段保持
		if data["crs_enabled"] != true || data["crs_version"] != version {
			t.Errorf("existing crs fields changed: crs_enabled=%v crs_version=%v", data["crs_enabled"], data["crs_version"])
		}
	})

	t.Run("crs disabled", func(t *testing.T) {
		disabledCfg := &config.Config{}
		a := newTestAdminServer(disabledCfg)
		data := parseWAFStatsData(t, serveAdminAuthenticatedRequest(t, a, "/api/waf/stats").Body.Bytes())
		if data["crs_state"] != "disabled" {
			t.Errorf("crs_state = %v, want disabled", data["crs_state"])
		}
	})

	t.Run("enabled but no registry entry", func(t *testing.T) {
		// 独立版本号：注册表中无该版本条目 → 防御值 unknown
		unknownCfg := &config.Config{
			WAF: config.WAFConfig{
				Enabled: true,
				CRS: config.WAFCRSConfig{
					Enabled: true,
					Version: version + "-unknown",
				},
			},
		}
		a := newTestAdminServer(unknownCfg)
		a.SetGetCRSStatus(crs.StatusSnapshot)
		data := parseWAFStatsData(t, serveAdminAuthenticatedRequest(t, a, "/api/waf/stats").Body.Bytes())
		if data["crs_state"] != "unknown" {
			t.Errorf("crs_state = %v, want unknown (defensive value before EnsureCRS)", data["crs_state"])
		}
	})

	t.Run("getter not injected", func(t *testing.T) {
		a := newTestAdminServer(gateCfg)
		data := parseWAFStatsData(t, serveAdminAuthenticatedRequest(t, a, "/api/waf/stats").Body.Bytes())
		if data["crs_state"] != "unknown" {
			t.Errorf("crs_state = %v, want unknown (no getter injected)", data["crs_state"])
		}
	})
}
