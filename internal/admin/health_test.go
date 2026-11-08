package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/lite-lake/infra-gate/internal/config"
	"github.com/lite-lake/infra-gate/internal/infrastructs/logger"
)

// testReadOnlyAPIKey newTestAdminServer 默认配置的只读 API Key（面板拆除后唯一认证通道）
const testReadOnlyAPIKey = "test-readonly-key"

func newTestAdminServer(gateCfg *config.Config) *AdminServer {
	log := logger.NewLogger(logger.LoggerConfig{
		Level:         logger.ErrorLevel,
		EnableConsole: false,
		EnableFile:    false,
	})
	return &AdminServer{
		cfg: &AdminConfig{
			Domain:          "gate.test",
			HTTPS:           true,
			ReadOnlyAPIKeys: []string{testReadOnlyAPIKey},
		},
		gateConfig: gateCfg,
		logger:     log,
	}
}

// serveAdminRequestMethod 发起一次管理端请求（可指定方法与请求头；头值为空串则不设置）。
// 面板拆除后无任何会话/CSRF 处理，仅 host 校验 + 路由注册
func serveAdminRequestMethod(t *testing.T, a *AdminServer, method, path string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.Use(a.hostCheckMiddleware())
	a.registerRoutes(engine)

	req, err := http.NewRequest(method, path, nil)
	if err != nil {
		t.Fatalf("构造请求失败: %v", err)
	}
	req.Host = "gate.test"
	for k, v := range headers {
		if v != "" {
			req.Header.Set(k, v)
		}
	}
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	return w
}

func serveAdminRequest(t *testing.T, a *AdminServer, path string) *httptest.ResponseRecorder {
	t.Helper()
	return serveAdminRequestMethod(t, a, http.MethodGet, path, nil)
}

func serveAdminRequestWithHeader(t *testing.T, a *AdminServer, path string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	return serveAdminRequestMethod(t, a, http.MethodGet, path, headers)
}

// serveAdminAuthenticatedRequest 以默认只读 key 发起 GET（面板拆除后读端点唯一认证方式）
func serveAdminAuthenticatedRequest(t *testing.T, a *AdminServer, path string) *httptest.ResponseRecorder {
	t.Helper()
	return serveAdminRequestWithHeader(t, a, path, map[string]string{apiKeyHeader: testReadOnlyAPIKey})
}

// TestHealthAndReadyUnauthenticated 免认证：无 key 也能访问 /api/health、/api/ready
func TestHealthAndReadyUnauthenticated(t *testing.T) {
	a := newTestAdminServer(&config.Config{
		Hosts: []config.HostConfig{
			{Name: "one.test", Backend: []string{"http://b1:80"}},
		},
	})

	for _, path := range []string{"/api/health", "/api/ready"} {
		w := serveAdminRequest(t, a, path)
		if w.Code != http.StatusOK {
			t.Errorf("%s 未认证访问 status = %d, want 200", path, w.Code)
		}
	}

	// 对照：需认证的只读 API 未携带 key 一律 401（面板拆除后无会话回退）
	w := serveAdminRequest(t, a, "/api/sites")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("/api/sites 未认证访问 status = %d, want 401", w.Code)
	}
}

// TestHealthNoHostCheckBypass host 校验仍然生效：错误 Host 头即使是 health 也返回 404
func TestHealthNoHostCheckBypass(t *testing.T) {
	a := newTestAdminServer(&config.Config{})

	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.Use(a.hostCheckMiddleware())
	a.registerRoutes(engine)

	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	req.Host = "evil.test"
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("错误 Host 访问 /api/health status = %d, want 404", w.Code)
	}
}

func decodeHealthBody(t *testing.T, w *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	var body map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("解析 JSON 失败: %v (body=%s)", err, w.Body.String())
	}
	return body
}

// TestReadyAllHealthy 全部后端健康 → 200 ok
func TestReadyAllHealthy(t *testing.T) {
	a := newTestAdminServer(&config.Config{
		Hosts: []config.HostConfig{
			{Name: "ok.test", Backend: []string{"http://b1:80", "http://b2:80"}},
		},
	})
	a.SetGetBackendHealth(func(hostName string) map[string]bool {
		return map[string]bool{"http://b1:80": true, "http://b2:80": true}
	})

	w := serveAdminRequest(t, a, "/api/ready")
	if w.Code != http.StatusOK {
		t.Errorf("/api/ready status = %d, want 200", w.Code)
	}
	if status := decodeHealthBody(t, w)["status"]; status != "ok" {
		t.Errorf("status = %v, want ok", status)
	}
}

// TestReadyDegraded 任一后端不健康 → 503 degraded
func TestReadyDegraded(t *testing.T) {
	a := newTestAdminServer(&config.Config{
		Hosts: []config.HostConfig{
			{Name: "ok.test", Backend: []string{"http://b1:80"}},
			{Name: "bad.test", Backend: []string{"http://b2:80"}},
		},
	})
	a.SetGetBackendHealth(func(hostName string) map[string]bool {
		if hostName == "bad.test" {
			return map[string]bool{"http://b2:80": false}
		}
		return map[string]bool{"http://b1:80": true}
	})

	w := serveAdminRequest(t, a, "/api/ready")
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("/api/ready status = %d, want 503", w.Code)
	}
	body := decodeHealthBody(t, w)
	if status := body["status"]; status != "degraded" {
		t.Errorf("status = %v, want degraded", status)
	}
	hosts, ok := body["hosts"].(map[string]interface{})
	if !ok {
		t.Fatalf("hosts 字段缺失或类型不符: %v", body["hosts"])
	}
	bad, ok := hosts["bad.test"].(map[string]interface{})
	if !ok || bad["status"] != "unhealthy" {
		t.Errorf("bad.test 状态 = %v, want unhealthy", bad)
	}
}

// TestReadyPendingNoData 健康检查无数据（禁用/启动初期）→ 视为 pending，整体仍 200 ok
func TestReadyPendingNoData(t *testing.T) {
	a := newTestAdminServer(&config.Config{
		Hosts: []config.HostConfig{
			{Name: "nocheck.test", Backend: []string{"http://b1:80"}},
		},
	})
	a.SetGetBackendHealth(func(hostName string) map[string]bool {
		return nil
	})

	w := serveAdminRequest(t, a, "/api/ready")
	if w.Code != http.StatusOK {
		t.Errorf("/api/ready status = %d, want 200", w.Code)
	}
}

// M4（内部PRD §6/决策 D5，出口标准⑥）：/api/ready 响应收敛——
// hosts.<name> 仅含 status / backends_total / backends_healthy 计数；
// 响应体任何位置不得再出现后端地址字符串；status 语义不变
func TestReadyCountsNoBackendAddresses(t *testing.T) {
	a := newTestAdminServer(&config.Config{
		Hosts: []config.HostConfig{
			{Name: "ok.test", Backend: []string{"http://ok-b1:80", "http://ok-b2:80"}},
			{Name: "bad.test", Backend: []string{"http://bad-b1:80", "http://bad-b2:80", "http://bad-b3:80"}},
			{Name: "pend.test", Backend: []string{"http://pend-b1:80"}},
		},
	})
	a.SetGetBackendHealth(func(hostName string) map[string]bool {
		switch hostName {
		case "ok.test":
			return map[string]bool{"http://ok-b1:80": true, "http://ok-b2:80": true}
		case "bad.test":
			// 2 健康 1 不健康 → unhealthy
			return map[string]bool{"http://bad-b1:80": true, "http://bad-b2:80": true, "http://bad-b3:80": false}
		default:
			return nil // pending
		}
	})

	w := serveAdminRequest(t, a, "/api/ready")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("/api/ready status = %d, want 503 (bad.test degraded)", w.Code)
	}
	body := w.Body.String()

	// 响应体任何位置不得出现后端地址字符串
	for _, addr := range []string{"http://ok-b1:80", "http://bad-b3:80", "http://pend-b1:80", "http://"} {
		if strings.Contains(body, addr) {
			t.Errorf("response body must not contain backend address %q (body=%s)", addr, body)
		}
	}
	// 旧 backends 字段（地址→布尔）不得再出现（backends_total/_healthy 是合法键，
	// 断言精确匹配 "backends" 键名）
	if strings.Contains(body, `"backends"`) {
		t.Errorf(`response body must not contain legacy "backends" field (body=%s)`, body)
	}

	hosts, ok := decodeHealthBody(t, w)["hosts"].(map[string]interface{})
	if !ok {
		t.Fatalf("hosts 字段缺失或类型不符")
	}
	type wantInfo struct {
		status  string
		total   float64
		healthy float64
	}
	want := map[string]wantInfo{
		"ok.test":   {"ok", 2, 2},
		"bad.test":  {"unhealthy", 3, 2},
		"pend.test": {"pending", 1, 0},
	}
	for name, wi := range want {
		h, ok := hosts[name].(map[string]interface{})
		if !ok {
			t.Fatalf("hosts[%s] 缺失或类型不符: %v", name, hosts[name])
		}
		if h["status"] != wi.status {
			t.Errorf("hosts[%s].status = %v, want %s", name, h["status"], wi.status)
		}
		if h["backends_total"] != wi.total {
			t.Errorf("hosts[%s].backends_total = %v, want %v", name, h["backends_total"], wi.total)
		}
		if h["backends_healthy"] != wi.healthy {
			t.Errorf("hosts[%s].backends_healthy = %v, want %v", name, h["backends_healthy"], wi.healthy)
		}
	}
}
