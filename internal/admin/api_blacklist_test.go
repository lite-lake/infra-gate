package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lite-lake/infra-gate/internal/blacklist"
	"github.com/lite-lake/infra-gate/internal/config"
)

func decodeBlacklistBody(t *testing.T, w *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	var body map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("解析 JSON 失败: %v (body=%s)", err, w.Body.String())
	}
	return body
}

// TestBlacklistStatsAPINilGetter getter 未注入 → 全零默认结构，enabled/default_mode 取自配置，不报错
func TestBlacklistStatsAPINilGetter(t *testing.T) {
	tests := []struct {
		name            string
		cfg             config.BlacklistConfig
		wantEnabled     bool
		wantDefaultMode string
	}{
		{
			name:            "未启用且未配置模式",
			cfg:             config.BlacklistConfig{Enabled: false},
			wantEnabled:     false,
			wantDefaultMode: "block",
		},
		{
			name:            "已启用 detect 模式",
			cfg:             config.BlacklistConfig{Enabled: true, DefaultMode: "detect"},
			wantEnabled:     true,
			wantDefaultMode: "detect",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := newTestAdminServer(&config.Config{Blacklist: tt.cfg})

			w := serveAdminAuthenticatedRequest(t, a, "/api/blacklist/stats")
			if w.Code != http.StatusOK {
				t.Fatalf("/api/blacklist/stats status = %d, want 200", w.Code)
			}

			body := decodeBlacklistBody(t, w)
			if code := body["code"]; code != float64(200) {
				t.Errorf("code = %v, want 200", code)
			}
			data, ok := body["data"].(map[string]interface{})
			if !ok {
				t.Fatalf("data 字段缺失或类型不符: %v", body["data"])
			}

			if got := data["enabled"]; got != tt.wantEnabled {
				t.Errorf("enabled = %v, want %v", got, tt.wantEnabled)
			}
			if got := data["default_mode"]; got != tt.wantDefaultMode {
				t.Errorf("default_mode = %v, want %v", got, tt.wantDefaultMode)
			}
			sources, ok := data["sources"].([]interface{})
			if !ok {
				t.Fatalf("sources 应为空数组，got %T (%v)", data["sources"], data["sources"])
			}
			if len(sources) != 0 {
				t.Errorf("sources 长度 = %d, want 0", len(sources))
			}
			for _, key := range []string{"total_entries", "hit_total_block", "hit_total_detect", "recent_hits"} {
				if got := data[key]; got != float64(0) {
					t.Errorf("%s = %v, want 0", key, got)
				}
			}
			for _, key := range []string{"last_success_at", "last_attempt_at"} {
				if got := data[key]; got != "" {
					t.Errorf("%s = %v, want 空串", key, got)
				}
			}
			if got := data["loaded_from_cache"]; got != false {
				t.Errorf("loaded_from_cache = %v, want false", got)
			}
		})
	}
}

// TestBlacklistStatsAPIWithGetter 注入 getter → 逐字段断言 §11.1 的响应结构
func TestBlacklistStatsAPIWithGetter(t *testing.T) {
	a := newTestAdminServer(&config.Config{})

	successAt := time.Date(2026, 9, 9, 12, 0, 3, 0, time.FixedZone("CST", 8*3600))
	attemptAt := time.Date(2026, 9, 9, 12, 0, 1, 0, time.FixedZone("CST", 8*3600))
	a.SetGetBlacklistStats(func() blacklist.StatsSnapshot {
		return blacklist.StatsSnapshot{
			Enabled:         true,
			DefaultMode:     "detect",
			Sources:         []blacklist.SourceStat{{Name: "ustc", URL: "https://blackip.ustc.edu.cn/list.php?txt", Entries: 14255, InvalidLines: 2}},
			TotalEntries:    14255,
			LastSuccessAt:   &successAt,
			LastAttemptAt:   &attemptAt,
			LoadedFromCache: false,
			HitTotalBlock:   3,
			HitTotalDetect:  27,
			RecentHits:      27,
		}
	})

	w := serveAdminAuthenticatedRequest(t, a, "/api/blacklist/stats")
	if w.Code != http.StatusOK {
		t.Fatalf("/api/blacklist/stats status = %d, want 200", w.Code)
	}

	body := decodeBlacklistBody(t, w)
	data, ok := body["data"].(map[string]interface{})
	if !ok {
		t.Fatalf("data 字段缺失或类型不符: %v", body["data"])
	}

	if got := data["enabled"]; got != true {
		t.Errorf("enabled = %v, want true", got)
	}
	if got := data["default_mode"]; got != "detect" {
		t.Errorf("default_mode = %v, want detect", got)
	}
	if got := data["total_entries"]; got != float64(14255) {
		t.Errorf("total_entries = %v, want 14255", got)
	}
	if got := data["last_success_at"]; got != "2026-09-09T12:00:03+08:00" {
		t.Errorf("last_success_at = %v, want 2026-09-09T12:00:03+08:00", got)
	}
	if got := data["last_attempt_at"]; got != "2026-09-09T12:00:01+08:00" {
		t.Errorf("last_attempt_at = %v, want 2026-09-09T12:00:01+08:00", got)
	}
	if got := data["loaded_from_cache"]; got != false {
		t.Errorf("loaded_from_cache = %v, want false", got)
	}
	if got := data["hit_total_block"]; got != float64(3) {
		t.Errorf("hit_total_block = %v, want 3", got)
	}
	if got := data["hit_total_detect"]; got != float64(27) {
		t.Errorf("hit_total_detect = %v, want 27", got)
	}
	if got := data["recent_hits"]; got != float64(27) {
		t.Errorf("recent_hits = %v, want 27", got)
	}

	sources, ok := data["sources"].([]interface{})
	if !ok || len(sources) != 1 {
		t.Fatalf("sources 应为长度 1 的数组, got %v", data["sources"])
	}
	src, ok := sources[0].(map[string]interface{})
	if !ok {
		t.Fatalf("sources[0] 应为对象, got %T", sources[0])
	}
	if src["name"] != "ustc" {
		t.Errorf("sources[0].name = %v, want ustc", src["name"])
	}
	// F7（内部PRD §4.7）：URL query 整体脱敏（RedactURL 薄封装收敛）
	if src["url"] != "https://blackip.ustc.edu.cn/list.php?***" {
		t.Errorf("sources[0].url = %v, want https://blackip.ustc.edu.cn/list.php?***", src["url"])
	}
	if src["entries"] != float64(14255) {
		t.Errorf("sources[0].entries = %v, want 14255", src["entries"])
	}
	if src["invalid_lines"] != float64(2) {
		t.Errorf("sources[0].invalid_lines = %v, want 2", src["invalid_lines"])
	}
}

// TestBlacklistStatsAPINilSourcesGetter getter 返回 Sources=nil 的快照 → sources 序列化为 [] 而非 null
func TestBlacklistStatsAPINilSourcesGetter(t *testing.T) {
	a := newTestAdminServer(&config.Config{})

	a.SetGetBlacklistStats(func() blacklist.StatsSnapshot {
		return blacklist.StatsSnapshot{Enabled: true}
	})

	w := serveAdminAuthenticatedRequest(t, a, "/api/blacklist/stats")
	if w.Code != http.StatusOK {
		t.Fatalf("/api/blacklist/stats status = %d, want 200", w.Code)
	}
	if strings.Contains(w.Body.String(), "\"sources\":null") {
		t.Errorf("sources 不应序列化为 null: %s", w.Body.String())
	}

	body := decodeBlacklistBody(t, w)
	data := body["data"].(map[string]interface{})
	sources, ok := data["sources"].([]interface{})
	if !ok || len(sources) != 0 {
		t.Errorf("sources 应为空数组, got %v", data["sources"])
	}
}

// TestBlacklistStatsAPISanitizesSourceURL 数据源 URL 内嵌 userinfo 凭据时不出现在响应中（H34 同款防护）
func TestBlacklistStatsAPISanitizesSourceURL(t *testing.T) {
	a := newTestAdminServer(&config.Config{})

	a.SetGetBlacklistStats(func() blacklist.StatsSnapshot {
		return blacklist.StatsSnapshot{
			Enabled: true,
			Sources: []blacklist.SourceStat{
				{Name: "private-feed", URL: "https://user:secret@feed.example.com/list.php?txt", Entries: 100},
			},
		}
	})

	w := serveAdminAuthenticatedRequest(t, a, "/api/blacklist/stats")
	if w.Code != http.StatusOK {
		t.Fatalf("/api/blacklist/stats status = %d, want 200", w.Code)
	}

	raw := w.Body.String()
	for _, leaked := range []string{"user:secret", "secret@", "user@"} {
		if strings.Contains(raw, leaked) {
			t.Errorf("stats 响应泄露了数据源 URL 内嵌凭据 %q: %s", leaked, raw)
		}
	}

	body := decodeBlacklistBody(t, w)
	data := body["data"].(map[string]interface{})
	sources, ok := data["sources"].([]interface{})
	if !ok || len(sources) != 1 {
		t.Fatalf("sources 应为长度 1 的数组, got %v", data["sources"])
	}
	src := sources[0].(map[string]interface{})
	// F7：query 整体脱敏 + userinfo 剥离（RedactURL 语义）
	if got := src["url"]; got != "https://feed.example.com/list.php?***" {
		t.Errorf("sources[0].url = %v, want https://feed.example.com/list.php?***", got)
	}
}

// TestBlacklistEventsAPINilGetter getter 未注入 → data 为空数组
func TestBlacklistEventsAPINilGetter(t *testing.T) {
	a := newTestAdminServer(&config.Config{})

	w := serveAdminAuthenticatedRequest(t, a, "/api/blacklist/events")
	if w.Code != http.StatusOK {
		t.Fatalf("/api/blacklist/events status = %d, want 200", w.Code)
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

// TestBlacklistEventsAPILimit limit 参数：默认 50，自定义生效，非法/非正回退默认，超上限封顶 200
func TestBlacklistEventsAPILimit(t *testing.T) {
	tests := []struct {
		query     string
		wantLimit int
	}{
		{"", 50},
		{"?limit=7", 7},
		{"?limit=1", 1},
		{"?limit=abc", 50},
		{"?limit=-3", 50},
		{"?limit=0", 50},
		{"?limit=500", 200},
		{"?limit=200", 200},
	}

	for _, tt := range tests {
		t.Run("query"+tt.query, func(t *testing.T) {
			a := newTestAdminServer(&config.Config{})

			gotLimit := -1
			a.SetGetBlacklistEvents(func(limit int) []blacklist.BlacklistEvent {
				gotLimit = limit
				return []blacklist.BlacklistEvent{}
			})

			w := serveAdminAuthenticatedRequest(t, a, "/api/blacklist/events"+tt.query)
			if w.Code != http.StatusOK {
				t.Fatalf("/api/blacklist/events%s status = %d, want 200", tt.query, w.Code)
			}
			if gotLimit != tt.wantLimit {
				t.Errorf("limit = %d, want %d", gotLimit, tt.wantLimit)
			}
		})
	}
}

// TestBlacklistEventsAPIWithGetter 注入 getter → 断言事件 JSON 字段
func TestBlacklistEventsAPIWithGetter(t *testing.T) {
	a := newTestAdminServer(&config.Config{})

	evTime := time.Date(2026, 9, 9, 11, 59, 58, 0, time.UTC)
	a.SetGetBlacklistEvents(func(limit int) []blacklist.BlacklistEvent {
		return []blacklist.BlacklistEvent{{
			Time:     evTime,
			ClientIP: "1.2.3.4",
			Matched:  "1.2.3.4",
			Mode:     "detect",
			Host:     "app.example.com",
			Path:     "/wp-login.php",
			TraceID:  "trace-abc-123",
		}}
	})

	w := serveAdminAuthenticatedRequest(t, a, "/api/blacklist/events?limit=10")
	if w.Code != http.StatusOK {
		t.Fatalf("/api/blacklist/events status = %d, want 200", w.Code)
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
		"client_ip": "1.2.3.4",
		"matched":   "1.2.3.4",
		"mode":      "detect",
		"host":      "app.example.com",
		"path":      "/wp-login.php",
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

// TestBlacklistAPIRequiresAuth 未携带 X-API-Key 访问 blacklist API → 401
// （面板拆除后无会话回退，认证唯一通道为只读 key）
func TestBlacklistAPIRequiresAuth(t *testing.T) {
	a := newTestAdminServer(&config.Config{})

	for _, path := range []string{"/api/blacklist/stats", "/api/blacklist/events"} {
		w := serveAdminRequest(t, a, path)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s 未认证访问 status = %d, want 401", path, w.Code)
		}
	}
}
