package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/lite-lake/infra-gate/internal/config"
	"github.com/lite-lake/infra-gate/internal/shipper"
)

func decodeShipperStatusBody(t *testing.T, w *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	var body map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("解析 JSON 失败: %v (body=%s)", err, w.Body.String())
	}
	return body
}

// TestShipperStatusAPINilGetter getter 未注入（配置缺段等效，内部PRD §6.1）→
// 仍返回 200 + enabled:false 全零快照，last_success_send_at 序列化为 null——
// "组件消失"是有效状态不是错误，由监控断言失败产生告警而非 404/500
func TestShipperStatusAPINilGetter(t *testing.T) {
	a := newTestAdminServer(&config.Config{})

	// 免认证探针：不携带 X-API-Key 直接访问（与 /api/health、/api/ready 同组）
	w := serveAdminRequest(t, a, "/api/shipper/status")
	if w.Code != http.StatusOK {
		t.Fatalf("/api/shipper/status 未注入 getter 时 status = %d, want 200", w.Code)
	}

	body := decodeShipperStatusBody(t, w)
	checks := map[string]interface{}{
		"enabled":        false,
		"running":        false,
		"node_name":      "",
		"sent_total":     float64(0),
		"dropped_total":  float64(0),
		"buffer_pending": float64(0),
	}
	for key, want := range checks {
		if got := body[key]; got != want {
			t.Errorf("%s = %v, want %v", key, got, want)
		}
	}
	if got, ok := body["last_success_send_at"]; !ok || got != nil {
		t.Errorf("last_success_send_at = %v (exists=%v), want null", got, ok)
	}
}

// TestShipperStatusAPIWithGetter 注入 getter → 快照逐字段透传（响应体平铺，无 code/data 信封）
func TestShipperStatusAPIWithGetter(t *testing.T) {
	a := newTestAdminServer(&config.Config{})

	lastSuccess := int64(1760000000123)
	a.SetGetShipperStatus(func() shipper.StatusSnapshot {
		return shipper.StatusSnapshot{
			Enabled:           true,
			Running:           true,
			NodeName:          "gate-node2",
			SentTotal:         42,
			DroppedTotal:      7,
			LastSuccessSendAt: &lastSuccess,
			BufferPending:     3,
		}
	})

	w := serveAdminRequest(t, a, "/api/shipper/status")
	if w.Code != http.StatusOK {
		t.Fatalf("/api/shipper/status status = %d, want 200", w.Code)
	}

	body := decodeShipperStatusBody(t, w)
	checks := map[string]interface{}{
		"enabled":              true,
		"running":              true,
		"node_name":            "gate-node2",
		"sent_total":           float64(42),
		"dropped_total":        float64(7),
		"last_success_send_at": float64(1760000000123),
		"buffer_pending":       float64(3),
	}
	for key, want := range checks {
		if got := body[key]; got != want {
			t.Errorf("%s = %v, want %v", key, got, want)
		}
	}
}

// TestShipperStatusAPINoAuthRequired 免认证探针语义：不携带（甚至携带错误）X-API-Key 也放行，
// 定位是监控探针而非管理面读 API（不进 readonlyAPIGroup）
func TestShipperStatusAPINoAuthRequired(t *testing.T) {
	a := newTestAdminServer(&config.Config{})

	for name, headers := range map[string]map[string]string{
		"无 key":  nil,
		"错误 key": {apiKeyHeader: "wrong-key"},
	} {
		w := serveAdminRequestWithHeader(t, a, "/api/shipper/status", headers)
		if w.Code != http.StatusOK {
			t.Errorf("%s 访问 /api/shipper/status status = %d, want 200", name, w.Code)
		}
	}
}

// TestShipperStatusAPIHostCheck Host 校验对免认证探针仍然生效：错误 Host 返回 404
// （仿 TestHealthNoHostCheckBypass 写法）
func TestShipperStatusAPIHostCheck(t *testing.T) {
	a := newTestAdminServer(&config.Config{})

	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.Use(a.hostCheckMiddleware())
	a.registerRoutes(engine)

	req := httptest.NewRequest(http.MethodGet, "/api/shipper/status", nil)
	req.Host = "evil.test"
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("错误 Host 访问 /api/shipper/status status = %d, want 404", w.Code)
	}
	if strings.Contains(w.Body.String(), "\"enabled\"") {
		t.Errorf("错误 Host 拦截后不应输出快照内容: %s", w.Body.String())
	}
}
