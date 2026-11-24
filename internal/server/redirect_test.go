package server

// 逐条目 http→https 301 + www/别名域收敛 + HSTS per-host 的请求链接入测试
// （内部总体方案 W3-2 / 决策 D8：配置层逐条目跳转语义，不做全局 80 端口行为变更）。
// 复用 blacklist_test.go 的测试基建（mock logger / chdir / httptest 后端 /
// NewServer 构造 / blDoRequestWithReq 直调 handleRequestForPort，不启动监听端口）。

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/lite-lake/infra-gate/internal/config"
)

// redirectReq 构造指定 Host 与原始 RequestURI 的 GET 请求；tlsReq 时模拟网关
// TLS 终止（r.TLS 非 nil，同 TestBlacklistBlockResponseHSTSOnTLS 手法）
func redirectReq(host, requestURI string, tlsReq bool) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "http://"+host+requestURI, nil)
	req.RemoteAddr = "203.0.113.88:52000"
	if tlsReq {
		req.TLS = &tls.ConnectionState{}
	}
	return req
}

// assert301Redirect 断言最小 301 响应：状态码、Location、无 Cache-Control、空 body
func assert301Redirect(t *testing.T, w *httptest.ResponseRecorder, wantLocation string) {
	t.Helper()
	if w.Code != http.StatusMovedPermanently {
		t.Fatalf("status = %d, want 301, body=%q", w.Code, w.Body.String())
	}
	if got := w.Header().Get("Location"); got != wantLocation {
		t.Errorf("Location = %q, want %q", got, wantLocation)
	}
	if got := w.Header().Get("Cache-Control"); got != "" {
		t.Errorf("Cache-Control = %q, want absent (最小响应仅 Location)", got)
	}
	if body := w.Body.String(); body != "" {
		t.Errorf("body = %q, want empty (最小响应仅 Location)", body)
	}
}

// 规范域收敛（redirect_host）：别名域/www 命中条目时 http 与 https 都 301 到
// https://<规范域><原始 RequestURI>；规范域本身与带端口 Host（剥端口后相等）不跳转。
func TestRedirectHostConvergence(t *testing.T) {
	chdirToRepoRoot(t)
	backend, hits := newBLBackend(t)
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Hosts: []config.HostConfig{
			{
				Name:               "www.example.com",
				Port:               8080,
				Backend:            []string{backend.URL},
				HealthCheckEnabled: boolPtr(false),
				RedirectHost:       "example.com",
			},
			{
				Name:               "example.com",
				Port:               8080,
				Backend:            []string{backend.URL},
				HealthCheckEnabled: boolPtr(false),
			},
		},
	}
	s := newBLServer(t, cfg)

	// ① 明文 HTTP 命中别名域 → 301 https://example.com（保留 path + query）
	w := blDoRequestWithReq(s, redirectReq("www.example.com", "/docs?x=1", false))
	assert301Redirect(t, w, "https://example.com/docs?x=1")
	if n := atomic.LoadInt64(hits); n != 0 {
		t.Fatalf("redirected request must not reach backend, hits = %d", n)
	}
	if got := w.Header().Get("Strict-Transport-Security"); got != "" {
		t.Errorf("HTTP redirect should not carry HSTS, got %q", got)
	}

	// ② HTTPS 同样收敛（redirect_host 与协议无关）
	w = blDoRequestWithReq(s, redirectReq("www.example.com", "/docs?x=1", true))
	assert301Redirect(t, w, "https://example.com/docs?x=1")

	// ③ 规范域本身命中自己的条目 → 不跳转，正常代理
	w = blDoRequestWithReq(s, redirectReq("example.com", "/", false))
	if w.Code != http.StatusOK {
		t.Fatalf("canonical host status = %d, want 200, body=%q", w.Code, w.Body.String())
	}
	if n := atomic.LoadInt64(hits); n != 1 {
		t.Errorf("canonical host request should proxy to backend, hits = %d", n)
	}

	// ④ 请求 Host 带端口（剥端口后 ≠ redirect_host）→ 仍收敛
	w = blDoRequestWithReq(s, redirectReq("www.example.com:8443", "/", false))
	assert301Redirect(t, w, "https://example.com/")
}

// 明文 HTTP → HTTPS（redirect_https）：仅明文监听生效，HTTPS 路径与未配置 host 不受影响
// （决策 D8：默认行为不变，逐条目声明跳转）。
func TestRedirectHTTPS301OnPlaintextOnly(t *testing.T) {
	chdirToRepoRoot(t)
	backend, hits := newBLBackend(t)
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Hosts: []config.HostConfig{
			{
				Name:               "plain.example.com",
				Port:               8080,
				Backend:            []string{backend.URL},
				HealthCheckEnabled: boolPtr(false),
				RedirectHTTPS:      boolPtr(true),
			},
			{
				Name:               "no-redirect.example.com",
				Port:               8080,
				Backend:            []string{backend.URL},
				HealthCheckEnabled: boolPtr(false),
			},
		},
	}
	s := newBLServer(t, cfg)

	// ① 明文 HTTP → 301 https://<原 host><原始 RequestURI>，不触后端
	w := blDoRequestWithReq(s, redirectReq("plain.example.com", "/docs?x=1", false))
	assert301Redirect(t, w, "https://plain.example.com/docs?x=1")
	if n := atomic.LoadInt64(hits); n != 0 {
		t.Fatalf("redirected request must not reach backend, hits = %d", n)
	}

	// ② 同一 host 的 HTTPS 请求不受影响 → 正常代理
	w = blDoRequestWithReq(s, redirectReq("plain.example.com", "/", true))
	if w.Code != http.StatusOK {
		t.Fatalf("HTTPS status = %d, want 200, body=%q", w.Code, w.Body.String())
	}

	// ③ 未配置 redirect_https 的 host（nil 默认 false）明文 HTTP 照常代理，行为不变
	w = blDoRequestWithReq(s, redirectReq("no-redirect.example.com", "/", false))
	if w.Code != http.StatusOK {
		t.Fatalf("no-redirect host plain HTTP status = %d, want 200 (default unchanged)", w.Code)
	}
	if n := atomic.LoadInt64(hits); n != 2 {
		t.Errorf("backend hits = %d, want 2 (HTTPS + no-redirect plain HTTP)", n)
	}
}

// L1（内部PRD 出口标准④）：redirect_https 的 301 Location 取 host 配置的
// 规范名称（不再拼接请求 Host，消除 Host 反射）；带端口的请求 Host 同样收敛为
// 无端口配置名。
func TestRedirectHTTPS301LocationUsesConfiguredHostName(t *testing.T) {
	chdirToRepoRoot(t)
	backend, hits := newBLBackend(t)
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Hosts: []config.HostConfig{
			{
				Name:               "plain.example.com",
				Port:               8080,
				Backend:            []string{backend.URL},
				HealthCheckEnabled: boolPtr(false),
				RedirectHTTPS:      boolPtr(true),
			},
		},
	}
	s := newBLServer(t, cfg)

	// ① 请求 Host 与配置名一致 → Location = https://<配置名><RequestURI>
	w := blDoRequestWithReq(s, redirectReq("plain.example.com", "/docs?x=1", false))
	assert301Redirect(t, w, "https://plain.example.com/docs?x=1")

	// ② 请求 Host 带端口 → Location 仍为无端口配置名（不反射请求 Host 原文）
	w = blDoRequestWithReq(s, redirectReq("plain.example.com:8443", "/docs", false))
	assert301Redirect(t, w, "https://plain.example.com/docs")

	// ③ 大小写反射面收敛（F3 语义更新，内部PRD §4.3）：变体 Host 经
	// CanonicalHost 归一后命中该条目 → 正常 301，Location 恒为配置名（归一化
	// 规范形态），不反射请求 Host 的大小写/尾点/端口原文
	w = blDoRequestWithReq(s, redirectReq("PLAIN.EXAMPLE.COM", "/docs", false))
	assert301Redirect(t, w, "https://plain.example.com/docs")
	if n := atomic.LoadInt64(hits); n != 0 {
		t.Errorf("redirected requests must not reach backend, hits = %d", n)
	}
}

// HSTS 单点下发 + per-host 覆盖（W3-2 收敛历史三处硬编码）：代理主路径从统一写入点继承；
// nil → 默认值；"off" → 不下发；自定义 → 字面值；HTTP 不下发。
func TestHSTSPerHostUnifiedSinglePoint(t *testing.T) {
	chdirToRepoRoot(t)
	backend, _ := newBLBackend(t)
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Hosts: []config.HostConfig{
			{
				Name:               "default.example.com",
				Port:               8080,
				Backend:            []string{backend.URL},
				HealthCheckEnabled: boolPtr(false),
			},
			{
				Name:               "off.example.com",
				Port:               8080,
				Backend:            []string{backend.URL},
				HealthCheckEnabled: boolPtr(false),
				HSTS:               strPtr("off"),
			},
			{
				Name:               "custom.example.com",
				Port:               8080,
				Backend:            []string{backend.URL},
				HealthCheckEnabled: boolPtr(false),
				HSTS:               strPtr("max-age=60; includeSubDomains"),
			},
		},
	}
	s := newBLServer(t, cfg)

	// nil（未配置）→ 保持现状默认值
	w := blDoRequestWithReq(s, redirectReq("default.example.com", "/", true))
	if w.Code != http.StatusOK {
		t.Fatalf("default host status = %d, want 200", w.Code)
	}
	if got := w.Header().Get("Strict-Transport-Security"); got != config.DefaultHSTSValue {
		t.Errorf("nil HSTS = %q, want default %q", got, config.DefaultHSTSValue)
	}

	// "off" → 不下发（双层网关链路只让边缘层下发一次）
	w = blDoRequestWithReq(s, redirectReq("off.example.com", "/", true))
	if got := w.Header().Get("Strict-Transport-Security"); got != "" {
		t.Errorf("hsts=off response header = %q, want absent", got)
	}

	// 自定义值 → 字面值下发
	w = blDoRequestWithReq(s, redirectReq("custom.example.com", "/", true))
	if got := w.Header().Get("Strict-Transport-Security"); got != "max-age=60; includeSubDomains" {
		t.Errorf("custom HSTS = %q, want literal value", got)
	}

	// 纯 HTTP（r.TLS == nil）→ 不下发
	w = blDoRequestWithReq(s, redirectReq("default.example.com", "/", false))
	if got := w.Header().Get("Strict-Transport-Security"); got != "" {
		t.Errorf("plain HTTP HSTS = %q, want absent", got)
	}
}

// 检查点顺序：跳转先于密码门（命中 redirect_host 的未认证请求 301 而非 302 登录页）；
// 未命中跳转的密码门 host 上，HTTPS 拦截响应继承统一 HSTS（auth 路径收敛验证）。
func TestRedirectPrecedesAuthAndAuthPathInheritsHSTS(t *testing.T) {
	chdirToRepoRoot(t)
	backend, _ := newBLBackend(t)
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Hosts: []config.HostConfig{
			{
				Name:               "www.example.com",
				Port:               8080,
				Backend:            []string{backend.URL},
				HealthCheckEnabled: boolPtr(false),
				RedirectHost:       "example.com",
				Auth:               &config.HostAuthConfig{Password: "pw"},
			},
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

	// ① 未认证 + 别名域 + HTTPS → 301 收敛优先于密码门 302
	req := redirectReq("www.example.com", "/docs", true)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	w := blDoRequestWithReq(s, req)
	assert301Redirect(t, w, "https://example.com/docs")

	// ② 未认证浏览器导航命中密码门 → 302 登录页，且响应继承统一 HSTS（默认值）
	req = redirectReq("gated.example.com", "/docs", true)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	w = blDoRequestWithReq(s, req)
	if w.Code != http.StatusFound {
		t.Fatalf("unauthenticated nav status = %d, want 302", w.Code)
	}
	if !strings.Contains(w.Header().Get("Location"), "/_gate-auth/login") {
		t.Errorf("Location = %q, want login page redirect", w.Header().Get("Location"))
	}
	if got := w.Header().Get("Strict-Transport-Security"); got != config.DefaultHSTSValue {
		t.Errorf("auth intercept HSTS = %q, want default %q (统一单点继承)", got, config.DefaultHSTSValue)
	}
}

// assertRedirectHSTSValues 用 Values（而非 Get）断言 HSTS 条数与值：Get 只看第一条，
// 无法证明 301 响应不是「双发」形态。
func assertRedirectHSTSValues(t *testing.T, h http.Header, want ...string) {
	t.Helper()
	got := h.Values("Strict-Transport-Security")
	if len(got) != len(want) {
		t.Fatalf("Strict-Transport-Security values = %q (%d 条), want %q (%d 条)", got, len(got), want, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("Strict-Transport-Security[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// P0-C（内部PRD §5.3 决策 D3）：HTTPS 下 redirect_host 的 301 最小响应
// 继承 per-host HSTS，含三态；同一 host 的明文 301 仍为 0 条（仅 HTTPS 下发不变式）。
func TestRedirectHostHTTPS301CarriesHSTSPerHost(t *testing.T) {
	tests := []struct {
		name string
		hsts *string
		want []string
	}{
		{"nil uses default", nil, []string{config.DefaultHSTSValue}},
		{"off suppresses", strPtr("off"), nil},
		{"literal preserved", strPtr("max-age=60; includeSubDomains"), []string{"max-age=60; includeSubDomains"}},
	}

	chdirToRepoRoot(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend, _ := newBLBackend(t)
			cfg := &config.Config{
				Server: config.ServerConfig{Port: 8080},
				Hosts: []config.HostConfig{
					{
						Name:               "www.example.com",
						Port:               8080,
						Backend:            []string{backend.URL},
						HealthCheckEnabled: boolPtr(false),
						RedirectHost:       "example.com",
						HSTS:               tt.hsts,
					},
				},
			}
			s := newBLServer(t, cfg)

			// HTTPS 301：携带 per-host HSTS（三态）
			w := blDoRequestWithReq(s, redirectReq("www.example.com", "/docs?x=1", true))
			assert301Redirect(t, w, "https://example.com/docs?x=1")
			assertRedirectHSTSValues(t, w.Header(), tt.want...)

			// 明文 301：仍 0 条（r.TLS == nil 守卫不变）
			w = blDoRequestWithReq(s, redirectReq("www.example.com", "/docs?x=1", false))
			assert301Redirect(t, w, "https://example.com/docs?x=1")
			assertRedirectHSTSValues(t, w.Header())
		})
	}
}

// newUpstreamHSTSBackend 返回真实会下发两份 HSTS 的后端（模拟内层网关/应用各发一份的
// 深层链路形态），供端到端用例串联真实 server 单点写入与真实 proxy 响应头复制循环。
func newUpstreamHSTSBackend(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Strict-Transport-Security", "max-age=111; includeSubDomains")
		w.Header().Add("Strict-Transport-Security", "max-age=222")
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("upstream-ok"))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// P0-A 端到端回归（内部PRD §5.1/§6）：上游真发两份 HSTS，经真实 server
// （HSTS 单点 Set，per-host 三态）→ 真实 proxy（响应头复制循环）两条生产路径串联，
// 断言客户端可见响应恰好 1 条 per-host 值（off 为 0 条），上游那份一份都不落地；
// 明文（r.TLS == nil）同样 0 条（§4.5-B 泄漏不得经透传复发）。
// 与 proxy 包用例（在 recorder 上复刻单点写入）互为独立证据：本用例不再复刻生产逻辑。
func TestUpstreamHSTSDroppedThroughRealServerAndProxy(t *testing.T) {
	tests := []struct {
		name string
		hsts *string
		want []string
	}{
		{"nil uses default", nil, []string{config.DefaultHSTSValue}},
		{"off suppresses", strPtr("off"), nil},
		{"literal preserved", strPtr("max-age=60; includeSubDomains"), []string{"max-age=60; includeSubDomains"}},
	}

	chdirToRepoRoot(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			upstream := newUpstreamHSTSBackend(t)
			cfg := &config.Config{
				Server: config.ServerConfig{Port: 8080},
				Hosts: []config.HostConfig{
					{
						Name:               "chain.example.com",
						Port:               8080,
						Backend:            []string{upstream.URL},
						HealthCheckEnabled: boolPtr(false),
						HSTS:               tt.hsts,
					},
				},
			}
			s := newBLServer(t, cfg)

			// HTTPS：上游双份 HSTS 被丢弃，客户端恰 1 条单点值（off 时 0 条）
			w := blDoRequestWithReq(s, redirectReq("chain.example.com", "/", true))
			if w.Code != http.StatusOK {
				t.Fatalf("HTTPS status = %d, want 200, body=%q", w.Code, w.Body.String())
			}
			if body := w.Body.String(); body != "upstream-ok" {
				t.Fatalf("HTTPS body = %q, want upstream-ok（确认确经代理路径）", body)
			}
			assertRedirectHSTSValues(t, w.Header(), tt.want...)

			// 明文：0 条（仅 HTTPS 下发；上游不得经透传把 HSTS 带到明文响应上）
			w = blDoRequestWithReq(s, redirectReq("chain.example.com", "/", false))
			if w.Code != http.StatusOK {
				t.Fatalf("plain status = %d, want 200, body=%q", w.Code, w.Body.String())
			}
			assertRedirectHSTSValues(t, w.Header())
		})
	}
}

// P0-C：redirect_https 的 301 仅由明文请求触发，故该 301 本身恒为 0 条 HSTS（三态）；
// 同一 host 的 HTTPS 正常响应则继承 per-host HSTS（三态），验证单点前移后两类响应共存。
func TestRedirectHTTPSPlaintext301NoHSTSPerHost(t *testing.T) {
	tests := []struct {
		name string
		hsts *string
		want []string
	}{
		{"nil uses default", nil, []string{config.DefaultHSTSValue}},
		{"off suppresses", strPtr("off"), nil},
		{"literal preserved", strPtr("max-age=60; includeSubDomains"), []string{"max-age=60; includeSubDomains"}},
	}

	chdirToRepoRoot(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend, _ := newBLBackend(t)
			cfg := &config.Config{
				Server: config.ServerConfig{Port: 8080},
				Hosts: []config.HostConfig{
					{
						Name:               "plain.example.com",
						Port:               8080,
						Backend:            []string{backend.URL},
						HealthCheckEnabled: boolPtr(false),
						RedirectHTTPS:      boolPtr(true),
						HSTS:               tt.hsts,
					},
				},
			}
			s := newBLServer(t, cfg)

			// 明文 redirect_https 301：恒 0 条（仅 HTTPS 下发不变式）
			w := blDoRequestWithReq(s, redirectReq("plain.example.com", "/docs?x=1", false))
			assert301Redirect(t, w, "https://plain.example.com/docs?x=1")
			assertRedirectHSTSValues(t, w.Header())

			// 同一 host 的 HTTPS 正常代理响应：继承 per-host HSTS（三态）
			w = blDoRequestWithReq(s, redirectReq("plain.example.com", "/", true))
			if w.Code != http.StatusOK {
				t.Fatalf("HTTPS status = %d, want 200, body=%q", w.Code, w.Body.String())
			}
			assertRedirectHSTSValues(t, w.Header(), tt.want...)
		})
	}
}
