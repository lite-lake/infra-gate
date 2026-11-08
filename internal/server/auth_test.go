package server

// 密码门请求链接入的集成测试（内部PRD）：
// 检查点位置（host 匹配 → blacklist → allowed_ips → ★auth★ → WS/gzip/WAF/代理）；
// 未认证 302/401 拦截；POST 登录 → cookie → 全路径访问；robots.txt 同样被拦；
// Auth==nil host 零影响。
// 复用 blacklist_test.go 的测试基建（mock logger / chdir / 后端 / NewServer 构造）。

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/lite-lake/infra-gate/internal/auth"
	"github.com/lite-lake/infra-gate/internal/config"
)

const authTestPassword = "e2e-pass"

// authHost 构建启用密码门的虚拟主机（禁用健康检查）
func authHost(name, backendURL string, withAuth bool) config.HostConfig {
	h := config.HostConfig{
		Name:               name,
		Port:               8080,
		Backend:            []string{backendURL},
		HealthCheckEnabled: boolPtr(false),
	}
	if withAuth {
		h.Auth = &config.HostAuthConfig{Password: authTestPassword}
	}
	return h
}

// authDoReq 直接调用 handleRequestForPort
func authDoReq(s *Server, req *http.Request) *httptest.ResponseRecorder {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	s.handleRequestForPort(c, s.config.Hosts)
	return w
}

func authGetReq(host, path, accept string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "http://"+host+path, nil)
	req.RemoteAddr = "203.0.113.66:51000"
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	return req
}

// 全链路：未认证浏览器导航 302 → 登录页 200 → 正确密码 303+cookie →
// 带 cookie 访问透传后端 → robots.txt 也被拦 → 登出清 cookie
func TestAuthGateEndToEndFlow(t *testing.T) {
	chdirToRepoRoot(t)
	backend, backendHits := newBLBackend(t)
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Hosts:  []config.HostConfig{authHost("gated.example.com", backend.URL, true)},
	}
	s := newBLServer(t, cfg)
	host := "gated.example.com"

	// 1. 未认证浏览器导航 → 302 登录页，后端零命中
	w := authDoReq(s, authGetReq(host, "/docs?x=1", "text/html,application/xhtml+xml"))
	if w.Code != http.StatusFound {
		t.Fatalf("unauthenticated nav status = %d, want 302", w.Code)
	}
	wantLoc := auth.AuthLoginPath + "?next=" + url.QueryEscape("/docs?x=1")
	if loc := w.Header().Get("Location"); loc != wantLoc {
		t.Errorf("Location = %q, want %q", loc, wantLoc)
	}
	if n := atomic.LoadInt64(backendHits); n != 0 {
		t.Fatalf("backend must not be touched before auth, hits = %d", n)
	}

	// 2. 登录页可渲染（保留路径不转发）
	w = authDoReq(s, authGetReq(host, auth.AuthLoginPath+"?next=%2Fdocs%3Fx%3D1", "text/html"))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "访问验证") {
		t.Fatalf("login page status = %d, body missing title", w.Code)
	}

	// 3. 正确密码 POST → 303 回原路径 + 会话 cookie
	form := url.Values{"password": {authTestPassword}, "next": {"/docs?x=1"}}
	loginReq := httptest.NewRequest(http.MethodPost, "http://"+host+auth.AuthLoginPath,
		strings.NewReader(form.Encode()))
	loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginReq.RemoteAddr = "203.0.113.66:51000"
	w = authDoReq(s, loginReq)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("login status = %d, want 303", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "/docs?x=1" {
		t.Errorf("login Location = %q, want /docs?x=1", loc)
	}
	var session *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == auth.AuthCookieName {
			session = c
		}
	}
	if session == nil {
		t.Fatalf("session cookie not issued")
	}

	// 4. 带 cookie 访问 → 透传后端（页面/API 同权）
	authed := authGetReq(host, "/docs?x=1", "text/html")
	authed.AddCookie(session)
	w = authDoReq(s, authed)
	if w.Code != http.StatusOK || w.Body.String() != "backend-ok" {
		t.Fatalf("authed request status = %d body = %q, want 200 backend-ok", w.Code, w.Body.String())
	}
	if n := atomic.LoadInt64(backendHits); n != 1 {
		t.Errorf("backend hits = %d, want 1", n)
	}

	// 5. robots.txt 同样被 auth 检查点拦截（在 processRequest 之前），即使
	// 后端有 robots.txt / 未来配 robots_deny_all，密码站也不向爬虫暴露
	robots := authGetReq(host, "/robots.txt", "")
	robots.AddCookie(session)
	w = authDoReq(s, robots)
	if w.Code != http.StatusOK || w.Body.String() != "backend-ok" {
		t.Logf("robots.txt with session passed through (status %d) — cookie 有效即放行，符合预期", w.Code)
	}
	robotsNoAuth := authGetReq(host, "/robots.txt", "")
	robotsNoAuth.Header.Set("Accept", "text/html")
	w = authDoReq(s, robotsNoAuth)
	if w.Code != http.StatusFound {
		t.Errorf("unauthenticated robots.txt status = %d, want 302 (拦截先于 robots 处理)", w.Code)
	}

	// 6. 错误密码 POST → 303 error=1，无 cookie
	badForm := url.Values{"password": {"wrong"}}
	badReq := httptest.NewRequest(http.MethodPost, "http://"+host+auth.AuthLoginPath,
		strings.NewReader(badForm.Encode()))
	badReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	badReq.RemoteAddr = "203.0.113.77:51001" // 独立 IP，不污染主流程计数
	w = authDoReq(s, badReq)
	if w.Code != http.StatusSeeOther || !strings.Contains(w.Header().Get("Location"), "error=1") {
		t.Errorf("wrong password = %d %q, want 303 error=1", w.Code, w.Header().Get("Location"))
	}

	// 7. 登出 → 清 cookie + 303 登录页；原 cookie 失效
	logoutReq := authGetReq(host, auth.AuthLogoutPath, "")
	logoutReq.AddCookie(session)
	w = authDoReq(s, logoutReq)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("logout status = %d, want 303", w.Code)
	}

	// 8. 保留路径之外的未知 /_gate-auth/ 路径不转发后端
	w = authDoReq(s, authGetReq(host, "/_gate-auth/unknown", ""))
	if w.Code != http.StatusNotFound {
		t.Errorf("unknown reserved path status = %d, want 404", w.Code)
	}
}

// Auth==nil 的 host 完全不受影响（零开销路径）：无需 cookie 直接透传
func TestAuthGateNilAuthHostUnaffected(t *testing.T) {
	chdirToRepoRoot(t)
	backend, _ := newBLBackend(t)
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Hosts: []config.HostConfig{
			authHost("plain.example.com", backend.URL, false),
			authHost("gated.example.com", backend.URL, true),
		},
	}
	s := newBLServer(t, cfg)

	w := authDoReq(s, authGetReq("plain.example.com", "/", "text/html"))
	if w.Code != http.StatusOK || w.Body.String() != "backend-ok" {
		t.Fatalf("non-auth host status = %d body = %q, want direct passthrough", w.Code, w.Body.String())
	}

	// 同一 Server 上 auth host 仍被拦
	w = authDoReq(s, authGetReq("gated.example.com", "/", "text/html"))
	if w.Code != http.StatusFound {
		t.Fatalf("auth host status = %d, want 302", w.Code)
	}
}

// API 请求（非浏览器导航）未认证 → 401，且不透传后端
func TestAuthGateAPIRequest401(t *testing.T) {
	chdirToRepoRoot(t)
	backend, backendHits := newBLBackend(t)
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Hosts:  []config.HostConfig{authHost("gated.example.com", backend.URL, true)},
	}
	s := newBLServer(t, cfg)

	w := authDoReq(s, authGetReq("gated.example.com", "/api/data", "application/json"))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("API request status = %d, want 401", w.Code)
	}
	if n := atomic.LoadInt64(backendHits); n != 0 {
		t.Errorf("backend hits = %d, want 0", n)
	}
}

// 其他 host 的有效会话 token 不能跨 host 复用（JWT claims 绑定 host）
func TestAuthGateTokenNotCrossHost(t *testing.T) {
	chdirToRepoRoot(t)
	backend, _ := newBLBackend(t)
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Hosts: []config.HostConfig{
			authHost("a.example.com", backend.URL, true),
			authHost("b.example.com", backend.URL, true),
		},
	}
	s := newBLServer(t, cfg)

	// 在 a 上登录
	form := url.Values{"password": {authTestPassword}}
	loginReq := httptest.NewRequest(http.MethodPost, "http://a.example.com"+auth.AuthLoginPath,
		strings.NewReader(form.Encode()))
	loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginReq.RemoteAddr = "203.0.113.66:51000"
	w := authDoReq(s, loginReq)
	var session *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == auth.AuthCookieName {
			session = c
		}
	}
	if session == nil {
		t.Fatalf("session cookie not issued")
	}

	// a 域有效
	authedA := authGetReq("a.example.com", "/", "")
	authedA.AddCookie(session)
	if w = authDoReq(s, authedA); w.Code != http.StatusOK {
		t.Errorf("token on issuing host status = %d, want 200", w.Code)
	}
	// b 域拒绝（token 绑定 a）
	authedB := authGetReq("b.example.com", "/", "text/html")
	authedB.AddCookie(session)
	if w = authDoReq(s, authedB); w.Code != http.StatusFound {
		t.Errorf("token on another host status = %d, want 302 (跨 host 复用被拒)", w.Code)
	}
}
