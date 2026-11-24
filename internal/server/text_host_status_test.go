package server

// text host / robots_deny_all 分支状态码回归测试（gin NoRoute serveError 预置 404 缺陷）。
//
// 根因：该网关 engine 无显式路由，全部请求走 NoRoute 链；gin v1.12.0 的 serveError
// （gin.go `c.writermem.status = code`）在运行中间件链**之前**就把 writermem.status
// 预置为 404。processRequest 的 text host / robots_deny_all 分支此前只写 header+body、
// 不显式 WriteHeader，gin ResponseWriter 延迟写语义下响应以预置的 404 落盘——
// headers 与 body 均正确但状态码恒为 404。修复：写 body 前显式 w.WriteHeader(http.StatusOK)。
//
// 测试方式：必须经真实 engine.ServeHTTP 触发 serveError 的 404 预置才能复现缺陷；
// 既有测试基建 blDoRequestWithReq（gin.CreateTestContext）不经过该路径，writermem
// 初始状态即为 200，无法暴露此问题。

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/lite-lake/infra-gate/internal/config"
)

// newTextHostServer 构建最小 Server（黑名单/WAF/后端全关，纯静态 host），
// 复用 blacklist_test.go 的基建（mock logger / chdir / NewServer / shutdown）
func newTextHostServer(t *testing.T, hosts ...config.HostConfig) *Server {
	t.Helper()
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Hosts:  hosts,
	}
	return newBLServer(t, cfg)
}

// serveViaNoRoute 用真实 gin engine（NoRoute 链，与 startHTTPServer 同构：
// engine.Use(handleRequestForPort) + 无显式路由）处理一次请求，
// 复现生产路径中 serveError 预置 writermem.status=404 的行为
func serveViaNoRoute(s *Server, hostName, path string) *httptest.ResponseRecorder {
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.Use(func(c *gin.Context) {
		s.handleRequestForPort(c, s.config.Hosts)
		c.Abort()
	})
	req := httptest.NewRequest(http.MethodGet, "http://"+hostName+path, nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	return w
}

// text host 静态响应必须 200 + body 正确（修复前为 404 + 正确 body）
func TestTextHostReturns200ViaNoRouteChain(t *testing.T) {
	chdirToRepoRoot(t)
	s := newTextHostServer(t, config.HostConfig{
		Name:               "*",
		Port:               8080,
		Text:               "crs-test-ok",
		HealthCheckEnabled: boolPtr(false),
	})

	// 通配 host 语义：任意 Host 头都命中（用未注册域名验证仍走 text host）
	w := serveViaNoRoute(s, "any-host.example.com", "/")
	if w.Code != http.StatusOK {
		t.Errorf("text host status = %d, want 200 (NoRoute serveError preset 404 must be overridden)", w.Code)
	}
	if body := w.Body.String(); body != "crs-test-ok" {
		t.Errorf("text host body = %q, want %q", body, "crs-test-ok")
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/plain" {
		t.Errorf("text host Content-Type = %q, want text/plain", ct)
	}
	// 网关自身响应安全头（H6/H8/H10）不受修复影响
	if xfo := w.Header().Get("X-Frame-Options"); xfo != "DENY" {
		t.Errorf("text host X-Frame-Options = %q, want DENY", xfo)
	}
	if xcto := w.Header().Get("X-Content-Type-Options"); xcto != "nosniff" {
		t.Errorf("text host X-Content-Type-Options = %q, want nosniff", xcto)
	}
}

// robots_deny_all 分支同样只 Write body，须显式 200（与 text host 同类缺陷）
func TestRobotsDenyAllReturns200ViaNoRouteChain(t *testing.T) {
	chdirToRepoRoot(t)
	s := newTextHostServer(t, config.HostConfig{
		Name:               "robots.example.com",
		Port:               8080,
		Text:               "static-text-response",
		RobotsDenyAll:      boolPtr(true),
		HealthCheckEnabled: boolPtr(false),
	})

	w := serveViaNoRoute(s, "robots.example.com", "/robots.txt")
	if w.Code != http.StatusOK {
		t.Errorf("robots.txt status = %d, want 200", w.Code)
	}
	if body := w.Body.String(); !strings.Contains(body, "Disallow: /") {
		t.Errorf("robots.txt body should contain Disallow: /, got: %.200s", body)
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/plain; charset=utf-8" {
		t.Errorf("robots.txt Content-Type = %q, want text/plain; charset=utf-8", ct)
	}

	// 非 /robots.txt 路径仍走 text host 分支（两分支互不影响）
	w = serveViaNoRoute(s, "robots.example.com", "/")
	if w.Code != http.StatusOK {
		t.Errorf("text host status = %d, want 200", w.Code)
	}
	if body := w.Body.String(); body != "static-text-response" {
		t.Errorf("text host body = %q, want static text", body)
	}
}
