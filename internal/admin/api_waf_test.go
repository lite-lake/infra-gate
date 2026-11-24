package admin

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/lite-lake/infra-gate/internal/blacklist"
	"github.com/lite-lake/infra-gate/internal/config"
	"github.com/lite-lake/infra-gate/internal/waf"
)

// TestWAFEventsAPILimit /api/waf/events limit 参数边界：
// 缺省 100、自定义生效、非法/非正回退默认、超上限封顶 200（迭代 4 新增，对齐 blacklist 语义）
func TestWAFEventsAPILimit(t *testing.T) {
	tests := []struct {
		query     string
		wantLimit int
	}{
		{"", 100},
		{"?limit=7", 7},
		{"?limit=1", 1},
		{"?limit=200", 200},
		{"?limit=201", 200},
		{"?limit=500", 200},
		{"?limit=abc", 100},
		{"?limit=-3", 100},
		{"?limit=0", 100},
		{"?limit=", 100},
	}

	for _, tt := range tests {
		t.Run("query"+tt.query, func(t *testing.T) {
			a := newTestAdminServer(&config.Config{})

			gotLimit := -1
			a.SetGetWAFEvents(func(limit int) []waf.WAFEvent {
				gotLimit = limit
				return []waf.WAFEvent{}
			})

			// key 通道（面板拆除后唯一认证通道）
			w := serveAdminAuthenticatedRequest(t, a, "/api/waf/events"+tt.query)
			if w.Code != http.StatusOK {
				t.Fatalf("/api/waf/events%s status = %d, want 200", tt.query, w.Code)
			}
			if gotLimit != tt.wantLimit {
				t.Errorf("limit = %d, want %d", gotLimit, tt.wantLimit)
			}
		})
	}
}

// TestWAFEventsAPIKeyChannelLimit 只读 key 通道同样受 limit 参数约束
func TestWAFEventsAPIKeyChannelLimit(t *testing.T) {
	a := newAPIKeyTestServer(t, "k1")

	gotLimit := -1
	a.SetGetWAFEvents(func(limit int) []waf.WAFEvent {
		gotLimit = limit
		return []waf.WAFEvent{}
	})

	w := doAPIKeyRequest(t, a, "/api/waf/events?limit=25", "k1")
	if w.Code != http.StatusOK {
		t.Fatalf("/api/waf/events?limit=25 status = %d, want 200, body=%s", w.Code, w.Body.String())
	}
	if gotLimit != 25 {
		t.Errorf("limit = %d, want 25", gotLimit)
	}
}

// TestWAFEventsAPINilGetter getter 未注入 → data 为空数组（不序列化为 null，形状与迁移前一致）
func TestWAFEventsAPINilGetter(t *testing.T) {
	a := newTestAdminServer(&config.Config{})

	w := serveAdminAuthenticatedRequest(t, a, "/api/waf/events")
	if w.Code != http.StatusOK {
		t.Fatalf("/api/waf/events status = %d, want 200", w.Code)
	}
	if strings.Contains(w.Body.String(), "\"data\":null") {
		t.Errorf("data 不应序列化为 null: %s", w.Body.String())
	}

	body := decodeBlacklistBody(t, w)
	events, ok := body["data"].([]interface{})
	if !ok || len(events) != 0 {
		t.Errorf("data 应为空数组, got %v", body["data"])
	}
}

// TestWAFEventsAPIWithGetter 注入 getter → 断言事件 JSON 字段（响应形状迁移前后零改动）
func TestWAFEventsAPIWithGetter(t *testing.T) {
	a := newTestAdminServer(&config.Config{})

	evTime := time.Date(2026, 9, 9, 11, 59, 58, 0, time.UTC)
	a.SetGetWAFEvents(func(limit int) []waf.WAFEvent {
		return []waf.WAFEvent{{
			ID:       123456789,
			Time:     evTime,
			Type:     waf.EventTypeBlock,
			ClientIP: "1.2.3.4",
			Method:   "GET",
			Path:     "/wp-login.php",
			HostName: "app.example.com",
			RuleID:   942100,
			Message:  "SQL Injection Attack Detected",
			Severity: "CRITICAL",
			TraceID:  "trace-abc-123",
		}}
	})

	w := serveAdminAuthenticatedRequest(t, a, "/api/waf/events?limit=10")
	if w.Code != http.StatusOK {
		t.Fatalf("/api/waf/events status = %d, want 200", w.Code)
	}

	body := decodeBlacklistBody(t, w)
	events, ok := body["data"].([]interface{})
	if !ok || len(events) != 1 {
		t.Fatalf("data 应为长度 1 的数组, got %v", body["data"])
	}
	ev, ok := events[0].(map[string]interface{})
	if !ok {
		t.Fatalf("data[0] 应为对象, got %T", events[0])
	}

	wantFields := map[string]interface{}{
		"id":        float64(123456789),
		"type":      "block",
		"client_ip": "1.2.3.4",
		"method":    "GET",
		"path":      "/wp-login.php",
		"host_name": "app.example.com",
		"rule_id":   float64(942100),
		"message":   "SQL Injection Attack Detected",
		"severity":  "CRITICAL",
		"trace_id":  "trace-abc-123",
	}
	for key, want := range wantFields {
		if got := ev[key]; got != want {
			t.Errorf("data[0].%s = %v, want %v", key, got, want)
		}
	}
	gotTime, ok := ev["time"].(string)
	if !ok || !strings.HasPrefix(gotTime, "2026-09-09T11:59:58") {
		t.Errorf("data[0].time = %v, want RFC3339 前缀 2026-09-09T11:59:58", ev["time"])
	}
}

// TestWAFEventDetailAPI 单事件详情：非法 id → 400，未命中 → 404，命中 → 200（key 通道）
func TestWAFEventDetailAPI(t *testing.T) {
	a := newTestAdminServer(&config.Config{})

	a.SetFindWAFEvent(func(id int64) (waf.WAFEvent, bool) {
		if id == 42 {
			return waf.WAFEvent{ID: 42, Type: waf.EventTypeBlock, ClientIP: "5.6.7.8"}, true
		}
		return waf.WAFEvent{}, false
	})

	// 非法 id
	if w := serveAdminAuthenticatedRequest(t, a, "/api/waf/events/abc"); w.Code != http.StatusBadRequest {
		t.Errorf("/api/waf/events/abc status = %d, want 400", w.Code)
	}
	// 未命中（含已过期）
	if w := serveAdminAuthenticatedRequest(t, a, "/api/waf/events/999"); w.Code != http.StatusNotFound {
		t.Errorf("/api/waf/events/999 status = %d, want 404", w.Code)
	}
	// 命中
	w := serveAdminAuthenticatedRequest(t, a, "/api/waf/events/42")
	if w.Code != http.StatusOK {
		t.Fatalf("/api/waf/events/42 status = %d, want 200", w.Code)
	}
	body := decodeBlacklistBody(t, w)
	ev, ok := body["data"].(map[string]interface{})
	if !ok {
		t.Fatalf("data 应为对象, got %T", body["data"])
	}
	if ev["id"] != float64(42) || ev["client_ip"] != "5.6.7.8" {
		t.Errorf("事件详情字段不符: %v", ev)
	}
}

// TestWAFStatsAPIWithGetter 注入统计 getter → 汇总计数/last block/hosts 明细（响应形状迁移前后零改动）
func TestWAFStatsAPIWithGetter(t *testing.T) {
	a := newTestAdminServer(&config.Config{
		WAF: config.WAFConfig{
			Enabled:     true,
			DefaultMode: "detect",
			CRS:         config.WAFCRSConfig{Enabled: true, Version: "4.0.0"},
			Whitelist:   config.WAFWhitelistConfig{IPRanges: []string{"10.0.0.0/8"}},
		},
	})

	lastBlock := time.Date(2026, 9, 9, 12, 0, 3, 0, time.UTC)
	a.SetGetWAFStats(func() []waf.StatsSnapshot {
		return []waf.StatsSnapshot{
			{
				TotalRequests:   100,
				TotalDetected:   5,
				TotalBlocked:    3,
				TotalPassed:     92,
				BlocksByHost:    []waf.HostStats{{HostName: "a.example.com", TotalRequests: 100, TotalDetected: 5, TotalBlocked: 3, TotalBlocks: 3}},
				LastBlockTime:   &lastBlock,
				LastBlockIP:     "1.2.3.4",
				LastBlockPath:   "/admin",
				LastBlockRuleID: 942100,
				LastBlockMsg:    "SQLi",
			},
		}
	})

	w := serveAdminAuthenticatedRequest(t, a, "/api/waf/stats")
	if w.Code != http.StatusOK {
		t.Fatalf("/api/waf/stats status = %d, want 200", w.Code)
	}

	body := decodeBlacklistBody(t, w)
	data, ok := body["data"].(map[string]interface{})
	if !ok {
		t.Fatalf("data 字段缺失或类型不符: %v", body["data"])
	}
	wantFields := map[string]interface{}{
		"total_requests":     float64(100),
		"total_detected":     float64(5),
		"total_blocked":      float64(3),
		"total_passed":       float64(92),
		"waf_enabled":        true,
		"waf_mode":           "detect",
		"crs_enabled":        true,
		"crs_version":        "4.0.0",
		"whitelist_count":    float64(1),
		"last_block_ip":      "1.2.3.4",
		"last_block_path":    "/admin",
		"last_block_rule_id": float64(942100),
		"last_block_message": "SQLi",
	}
	for key, want := range wantFields {
		if got := data[key]; got != want {
			t.Errorf("data.%s = %v, want %v", key, got, want)
		}
	}
	if got := data["last_block_time"]; got != "2026-09-09T12:00:03Z" {
		t.Errorf("last_block_time = %v, want 2026-09-09T12:00:03Z", got)
	}
	hosts, ok := data["blocks_by_host"].([]interface{})
	if !ok || len(hosts) != 1 {
		t.Fatalf("blocks_by_host 应为长度 1 的数组, got %v", data["blocks_by_host"])
	}
	host := hosts[0].(map[string]interface{})
	if host["host"] != "a.example.com" || host["total_requests"] != float64(100) ||
		host["total_detected"] != float64(5) || host["total_blocked"] != float64(3) {
		t.Errorf("blocks_by_host[0] 字段不符: %v", host)
	}
}

// TestWAFStatsAPINilGetter getter 未注入 → 全零默认结构 + 配置来源的 waf_enabled/crs_version，不报错
func TestWAFStatsAPINilGetter(t *testing.T) {
	a := newTestAdminServer(&config.Config{
		WAF: config.WAFConfig{
			Enabled:     true,
			DefaultMode: "block",
			CRS:         config.WAFCRSConfig{Enabled: true, Version: "4.0.0"},
		},
	})

	w := serveAdminAuthenticatedRequest(t, a, "/api/waf/stats")
	if w.Code != http.StatusOK {
		t.Fatalf("/api/waf/stats status = %d, want 200", w.Code)
	}

	body := decodeBlacklistBody(t, w)
	data := body["data"].(map[string]interface{})
	if data["waf_enabled"] != true || data["crs_version"] != "4.0.0" {
		t.Errorf("配置来源字段不符: waf_enabled=%v crs_version=%v", data["waf_enabled"], data["crs_version"])
	}
	for _, key := range []string{"total_requests", "total_detected", "total_blocked", "total_passed", "whitelist_count"} {
		if got := data[key]; got != float64(0) {
			t.Errorf("%s = %v, want 0", key, got)
		}
	}
}

// TestWAFAPIKeyChannelResponseShapeUnchanged 只读 key 通道响应形状断言（面板拆除后唯一认证通道）
func TestWAFAPIKeyChannelResponseShapeUnchanged(t *testing.T) {
	a := newAPIKeyTestServer(t, "k1")

	a.SetGetWAFEvents(func(limit int) []waf.WAFEvent {
		return []waf.WAFEvent{{ID: 1, Type: waf.EventTypeDetect, ClientIP: "9.9.9.9"}}
	})
	a.SetGetWAFStats(func() []waf.StatsSnapshot {
		return []waf.StatsSnapshot{}
	})
	a.SetFindWAFEvent(func(id int64) (waf.WAFEvent, bool) {
		return waf.WAFEvent{ID: id, Type: waf.EventTypeDetect, ClientIP: "9.9.9.9"}, true
	})
	a.SetGetBlacklistStats(func() blacklist.StatsSnapshot {
		return blacklist.StatsSnapshot{Enabled: true}
	})
	a.SetGetBlacklistEvents(func(limit int) []blacklist.BlacklistEvent {
		return []blacklist.BlacklistEvent{}
	})

	for _, path := range []string{"/api/waf/stats", "/api/waf/events", "/api/waf/events/1", "/api/blacklist/stats", "/api/blacklist/events"} {
		w := doAPIKeyRequest(t, a, path, "k1")
		if w.Code != http.StatusOK {
			t.Errorf("key 通道 %s status = %d, want 200, body=%s", path, w.Code, w.Body.String())
			continue
		}
		body := decodeBlacklistBody(t, w)
		if body["code"] != float64(200) {
			t.Errorf("key 通道 %s body.code = %v, want 200", path, body["code"])
		}
		if _, ok := body["data"]; !ok {
			t.Errorf("key 通道 %s 缺少 data 字段", path)
		}
	}
}
