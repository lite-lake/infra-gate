package admin

import (
	"net/http"
	"testing"

	"github.com/lite-lake/infra-gate/internal/config"
)

// TestTeardownPageRoutesNotFound 面板拆除验收（内部PRD §12）：
// /、/login、/sites、/certs、/waf、/blacklist 全部页面路由不存在 → 404；
// 携带有效只读 key 与 POST 登录/登出同样 404
func TestTeardownPageRoutesNotFound(t *testing.T) {
	a := newTestAdminServer(&config.Config{})

	paths := []string{"/", "/login", "/sites", "/certs", "/waf", "/blacklist"}
	for _, path := range paths {
		// 无凭据
		if w := serveAdminRequest(t, a, path); w.Code != http.StatusNotFound {
			t.Errorf("%s 无凭据访问 status = %d, want 404（页面已拆除）", path, w.Code)
		}
		// 携带有效 key 也不可达（key 通道仅覆盖只读 API）
		if w := serveAdminAuthenticatedRequest(t, a, path); w.Code != http.StatusNotFound {
			t.Errorf("%s 携带只读 key 访问 status = %d, want 404", path, w.Code)
		}
	}

	// 登录提交（POST /login）与登出（POST /logout）同样不存在
	for _, path := range []string{"/login", "/logout"} {
		w := serveAdminRequestMethod(t, a, http.MethodPost, path, nil)
		if w.Code != http.StatusNotFound {
			t.Errorf("POST %s status = %d, want 404", path, w.Code)
		}
	}
}

// TestReadonlyEndpointsAfterTeardown 拆除后保留能力验收（PRD §12）：
// /api/health、/api/ready 免认证 200；8 个只读 GET（含 ?limit=）携带 key 200
func TestReadonlyEndpointsAfterTeardown(t *testing.T) {
	a := newAPIKeyTestServer(t, testReadOnlyAPIKey)

	// 健康探针（免认证）
	for _, path := range []string{"/api/health", "/api/ready"} {
		w := serveAdminRequest(t, a, path)
		if w.Code != http.StatusOK {
			t.Errorf("%s status = %d, want 200", path, w.Code)
		}
	}

	// 8 个只读端点（key 通道），WAF/黑名单事件端点带 ?limit= 验证参数路径
	for _, path := range []string{
		"/api/sites",
		"/api/certs",
		"/api/system",
		"/api/waf/stats",
		"/api/waf/events?limit=5",
		"/api/waf/events/12345",
		"/api/blacklist/stats",
		"/api/blacklist/events?limit=5",
	} {
		w := serveAdminAuthenticatedRequest(t, a, path)
		if w.Code != http.StatusOK {
			t.Errorf("%s status = %d, want 200, body=%s", path, w.Code, w.Body.String())
		}
	}
}
