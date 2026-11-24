package server

// H1 请求路径规范化强制的请求链测试（内部PRD 迭代 1 出口标准 ①②）：
// 非规范路径（../、//、. 段、控制字符段）在 host 匹配前全局 400；
// 合法尾斜杠 / 根路径放行；strict_path_check=false 逃生口放行；
// /_gate-auth 无斜杠裸路径由网关保留处理（不转发后端）；
// /.;/admin 变形在 public_paths 段边界匹配下 fail-closed（PRD §13 穿透用例）。
// 复用 blacklist_test.go 的测试基建（mock logger / chdir / httptest 后端 /
// NewServer 构造 / blDoRequestWithReq 直调 handleRequestForPort，不启动监听端口）。

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/lite-lake/infra-gate/internal/auth"
	"github.com/lite-lake/infra-gate/internal/config"
)

// pcReq 构造指定 Host 与原始路径（可含编码段）的 GET 请求
func pcReq(host, target string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "http://"+host+target, nil)
	req.RemoteAddr = "203.0.113.99:53000"
	return req
}

// H1 出口标准①：非规范路径 400 / 规范路径放行（表驱动）。
// 编码形态（%0A/%00/%2F）按解码后的 r.URL.Path 校验。
func TestH1PathCanonicalizationEnforced(t *testing.T) {
	chdirToRepoRoot(t)
	backend, hits := newBLBackend(t)
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Hosts: []config.HostConfig{
			{
				Name:               "pc.example.com",
				Port:               8080,
				Backend:            []string{backend.URL},
				HealthCheckEnabled: boolPtr(false),
			},
		},
	}
	s := newBLServer(t, cfg)

	tests := []struct {
		name       string
		target     string
		wantStatus int
	}{
		// 非规范路径 → 400
		{"dotdot segment", "/a/../b", http.StatusBadRequest},
		{"double slash middle", "/a//b", http.StatusBadRequest},
		{"leading double slash encoded", "/%2F%2Fadmin", http.StatusBadRequest},
		{"dot segment root", "/.", http.StatusBadRequest},
		{"dotdot root", "/..", http.StatusBadRequest},
		{"middle dot segment", "/a/./b", http.StatusBadRequest},
		{"encoded LF control char", "/foo%0Abar", http.StatusBadRequest},
		{"encoded NUL control char", "/foo%00bar", http.StatusBadRequest},
		{"dotdot only", "/../..", http.StatusBadRequest},
		// 规范路径 → 放行
		{"root path", "/", http.StatusOK},
		{"trailing slash legal", "/a/", http.StatusOK},
		{"normal path", "/a/b?x=1", http.StatusOK},
		{"reserved login path", auth.AuthLoginPath, http.StatusOK}, // 该 host 未启用 auth，登录页路径直接透传
	}
	for _, tt := range tests {
		w := blDoRequestWithReq(s, pcReq("pc.example.com", tt.target))
		if w.Code != tt.wantStatus {
			t.Errorf("target %q status = %d, want %d", tt.target, w.Code, tt.wantStatus)
		}
	}

	// 仅放行的请求触达后端，非规范请求一律 400 未透传
	if n := atomic.LoadInt64(hits); n != 4 {
		t.Errorf("backend hits = %d, want 4 (only canonical requests proxied)", n)
	}
}

// H1 出口标准①：strict_path_check=false 逃生口——非规范路径放行（行为回退现状）
func TestH1StrictPathCheckDisabledEscapeHatch(t *testing.T) {
	chdirToRepoRoot(t)
	backend, hits := newBLBackend(t)
	cfg := &config.Config{
		Server: config.ServerConfig{
			Port:            8080,
			StrictPathCheck: boolPtr(false),
		},
		Hosts: []config.HostConfig{
			{
				Name:               "pc-off.example.com",
				Port:               8080,
				Backend:            []string{backend.URL},
				HealthCheckEnabled: boolPtr(false),
			},
		},
	}
	s := newBLServer(t, cfg)

	for _, target := range []string{"/a/../b", "/a//b", "/foo%0Abar"} {
		w := blDoRequestWithReq(s, pcReq("pc-off.example.com", target))
		if w.Code != http.StatusOK {
			t.Errorf("escape hatch: target %q status = %d, want 200 (passthrough)", target, w.Code)
		}
	}
	if n := atomic.LoadInt64(hits); n != 3 {
		t.Errorf("backend hits = %d, want 3 (all passthrough with check disabled)", n)
	}
}

// H1 补漏：/_gate-auth（无斜杠裸路径）也是保留路径，由网关自身 404 处理，
// 不再按普通路径拦截/转发后端（内部PRD §H1）
func TestH1GateAuthBarePathHandledByGate(t *testing.T) {
	chdirToRepoRoot(t)
	backend, hits := newBLBackend(t)
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Hosts: []config.HostConfig{
			{
				Name:               "gated.example.com",
				Port:               8080,
				Backend:            []string{backend.URL},
				HealthCheckEnabled: boolPtr(false),
				Auth:               &config.HostAuthConfig{Password: "pw"},
			},
		},
	}
	s := newBLServer(t, cfg)

	// 裸路径 → 网关保留处理 404，不触后端
	w := blDoRequestWithReq(s, pcReq("gated.example.com", auth.AuthPathRoot))
	if w.Code != http.StatusNotFound {
		t.Errorf("bare /_gate-auth status = %d, want 404 (gate-handled reserved path)", w.Code)
	}
	if n := atomic.LoadInt64(hits); n != 0 {
		t.Errorf("backend hits = %d, want 0 (reserved path never forwarded)", n)
	}

	// 对照组：登录页保留路径行为不变（网关 200 登录页）
	w = blDoRequestWithReq(s, pcReq("gated.example.com", auth.AuthLoginPath))
	if w.Code != http.StatusOK {
		t.Errorf("login page status = %d, want 200 (reserved path unchanged)", w.Code)
	}

	// 对照组：普通路径未认证仍 302 拦截
	req := pcReq("gated.example.com", "/docs")
	req.Header.Set("Accept", "text/html")
	w = blDoRequestWithReq(s, req)
	if w.Code != http.StatusFound {
		t.Errorf("unauthenticated nav status = %d, want 302", w.Code)
	}
}

// H1 引擎级验证：请求经真实 gin engine（engine.Use(handleRequestForPort) + 无显式
// 路由，与 startHTTPServer 同构，复用 text_host_status_test.go 的 serveViaNoRoute
// 手法）——证实 gin 对 r.URL.Path 无转义/重写（%2F 解码形态原样到达 H1 检查点），
// 非 canonical 400 与 canonical 放行在全链路（含 serveError 预置 404 的 NoRoute 链）下成立
func TestH1EnforcedViaRealGinEngine(t *testing.T) {
	chdirToRepoRoot(t)
	backend, hits := newBLBackend(t)
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Hosts: []config.HostConfig{
			{
				Name:               "engine.example.com",
				Port:               8080,
				Backend:            []string{backend.URL},
				HealthCheckEnabled: boolPtr(false),
			},
		},
	}
	s := newBLServer(t, cfg)

	// 编码空段（%2F 解码为 / 后命中中间空段）→ 400
	w := serveViaNoRoute(s, "engine.example.com", "/a%2F%2Fb")
	if w.Code != http.StatusBadRequest {
		t.Errorf("engine-level encoded-slash path status = %d, want 400 (gin must not rewrite decoded URL.Path)", w.Code)
	}
	// ../ 变形 → 400
	w = serveViaNoRoute(s, "engine.example.com", "/a/../b")
	if w.Code != http.StatusBadRequest {
		t.Errorf("engine-level dotdot path status = %d, want 400", w.Code)
	}
	// canonical 路径 → 200 放行（serveError 预置 404 被显式状态覆盖）
	w = serveViaNoRoute(s, "engine.example.com", "/a/b/")
	if w.Code != http.StatusOK {
		t.Errorf("engine-level canonical path status = %d, want 200", w.Code)
	}
	if n := atomic.LoadInt64(hits); n != 1 {
		t.Errorf("backend hits = %d, want 1 (only canonical request proxied)", n)
	}
}

// H1 穿透用例（PRD §13 验收 `/.;/`）：public_paths 段边界匹配下，
// /.;/admin 不豁免认证（. 非规范变形已在网关 400，. 段按字面量不匹配
// public_paths）→ fail-closed 拦截，后端零触达
func TestH1SegmentBoundaryPublicPathsFailClosed(t *testing.T) {
	chdirToRepoRoot(t)
	backend, hits := newBLBackend(t)
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Hosts: []config.HostConfig{
			{
				Name:               "pp.example.com",
				Port:               8080,
				Backend:            []string{backend.URL},
				HealthCheckEnabled: boolPtr(false),
				Auth: &config.HostAuthConfig{
					Password:    "pw",
					PublicPaths: []string{"/admin"},
				},
			},
		},
	}
	s := newBLServer(t, cfg)

	tests := []struct {
		name       string
		target     string
		wantStatus int
	}{
		// 合法豁免：段边界完整命中
		{"public path exact", "/admin", http.StatusOK},
		{"public path child", "/admin/sub", http.StatusOK},
		// 变形一律 fail-closed（拦截 302/401，不转发后端）
		{"semicolon dot variant fails closed", "/.;/admin", http.StatusFound},
		{"sibling prefix not exempt", "/adminX", http.StatusFound},
	}
	for _, tt := range tests {
		req := pcReq("pp.example.com", tt.target)
		req.Header.Set("Accept", "text/html") // 浏览器导航 → 302（API 为 401）
		w := blDoRequestWithReq(s, req)
		if w.Code != tt.wantStatus {
			t.Errorf("%s: target %q status = %d, want %d", tt.name, tt.target, w.Code, tt.wantStatus)
		}
	}

	// 仅两笔合法豁免触达后端
	if n := atomic.LoadInt64(hits); n != 2 {
		t.Errorf("backend hits = %d, want 2 (only segment-boundary matches exempted)", n)
	}
}
