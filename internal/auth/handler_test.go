package auth

// 保留路径 handler 与拦截决策单测（内部PRD §13）：
// 正确密码发 cookie + 303 next；错误密码 303 error=1；锁定中 303 error=rate；
// next 合法/非法校验；logout 清 cookie；text/html → 302、API → 401、WS → 401；
// public_paths 前缀豁免；登录页渲染与转义。

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lite-lake/infra-gate/internal/config"
	"github.com/lite-lake/infra-gate/internal/infrastructs/logger"
	"github.com/lite-lake/infra-gate/internal/netutil"
)

// authTestLogger 实现 logger.ILogger 的空实现（对齐 server 包测试基建模式）
type authTestLogger struct{}

func (l *authTestLogger) Debug(msg string, fields ...logger.Field) {}
func (l *authTestLogger) Info(msg string, fields ...logger.Field)  {}
func (l *authTestLogger) Warn(msg string, fields ...logger.Field)  {}
func (l *authTestLogger) Error(msg string, fields ...logger.Field) {}
func (l *authTestLogger) Fatal(msg string, fields ...logger.Field) {}
func (l *authTestLogger) WithContext(ctx context.Context) logger.ILogger {
	return l
}
func (l *authTestLogger) WithField(key string, value interface{}) logger.ILogger { return l }
func (l *authTestLogger) WithFields(fields map[string]interface{}) logger.ILogger {
	return l
}
func (l *authTestLogger) WithTraceId(traceId string) logger.ILogger { return l }
func (l *authTestLogger) SetLevel(level logger.LogLevel)            {}
func (l *authTestLogger) GetLevel() logger.LogLevel                 { return logger.DebugLevel }
func (l *authTestLogger) Close() error                              { return nil }

const (
	testPassword = "s3cret-pass"
	testTTLs     = int(24 * time.Hour / time.Second)
)

func newTestManager(t *testing.T, publicPaths ...string) *Manager {
	t.Helper()
	cfg := &config.HostAuthConfig{Password: testPassword}
	if len(publicPaths) > 0 {
		cfg.PublicPaths = publicPaths
	}
	// trustedProxies 传 nil = 直连对端口径（缺省，与既有用例的固定 RemoteAddr 匹配）
	return NewManager(testHost, cfg, nil, &authTestLogger{})
}

func newLoginRequest(method, target string, form url.Values, tlsReq bool) *http.Request {
	var req *http.Request
	if form != nil {
		req = httptest.NewRequest(method, target, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req = httptest.NewRequest(method, target, nil)
	}
	if tlsReq {
		req.TLS = &tls.ConnectionState{}
	}
	req.RemoteAddr = "203.0.113.9:40000"
	return req
}

func doEval(m *Manager, req *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	m.Evaluate(w, req)
	return w
}

// getCookie 从响应提取 ltgate_auth cookie
func getCookie(t *testing.T, w *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range w.Result().Cookies() {
		if c.Name == AuthCookieName {
			return c
		}
	}
	t.Fatalf("Set-Cookie %s not found", AuthCookieName)
	return nil
}

func TestLoginSuccessIssuesCookieAndRedirects(t *testing.T) {
	m := newTestManager(t)
	form := url.Values{"password": {testPassword}, "next": {"/dash?page=2"}}
	w := doEval(m, newLoginRequest(http.MethodPost, AuthLoginPath, form, false))

	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "/dash?page=2" {
		t.Errorf("Location = %q, want /dash?page=2", loc)
	}
	c := getCookie(t, w)
	if !c.HttpOnly || c.Secure {
		t.Errorf("cookie flags HttpOnly=%v Secure=%v, want HttpOnly true / Secure false (HTTP)", c.HttpOnly, c.Secure)
	}
	if c.MaxAge != testTTLs {
		t.Errorf("cookie Max-Age = %d, want %d", c.MaxAge, testTTLs)
	}
	if c.Path != "/" {
		t.Errorf("cookie Path = %q, want /", c.Path)
	}
	if !VerifyToken(c.Value, m.key, testHost, time.Now()) {
		t.Errorf("issued cookie token should verify")
	}
	// 登录后携带 cookie 可访问任意路径
	req := httptest.NewRequest(http.MethodGet, "http://"+testHost+"/dash?page=2", nil)
	req.AddCookie(c)
	if w2 := doEval(m, req); w2.Code != http.StatusOK {
		t.Errorf("authed request status = %d, want passthrough 200", w2.Code)
	}
}

func TestLoginSetsSecureCookieOnHTTPS(t *testing.T) {
	m := newTestManager(t)
	form := url.Values{"password": {testPassword}}
	w := doEval(m, newLoginRequest(http.MethodPost, AuthLoginPath, form, true))
	c := getCookie(t, w)
	if !c.Secure {
		t.Errorf("HTTPS login must set Secure cookie（决策 D3）")
	}
}

func TestLoginWrongPasswordRedirectsWithError(t *testing.T) {
	m := newTestManager(t)
	form := url.Values{"password": {"wrong"}, "next": {"/x"}}
	w := doEval(m, newLoginRequest(http.MethodPost, AuthLoginPath, form, false))
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", w.Code)
	}
	loc := w.Header().Get("Location")
	if !strings.Contains(loc, "error=1") || !strings.Contains(loc, "next=%2Fx") {
		t.Errorf("Location = %q, want error=1 + encoded next", loc)
	}
	if cookies := w.Result().Cookies(); len(cookies) > 0 {
		t.Errorf("failed login must not set session cookie, got %v", cookies)
	}
}

func TestLoginLockoutRateLimited(t *testing.T) {
	m := newTestManager(t)
	bad := url.Values{"password": {"wrong"}}
	for i := 0; i < AuthMaxFailures; i++ {
		doEval(m, newLoginRequest(http.MethodPost, AuthLoginPath, bad, false))
	}

	// 锁定后：即便密码正确也返回 rate（不暴露密码是否正确）
	good := url.Values{"password": {testPassword}}
	w := doEval(m, newLoginRequest(http.MethodPost, AuthLoginPath, good, false))
	loc := w.Header().Get("Location")
	if !strings.Contains(loc, "error=rate") {
		t.Errorf("locked IP with correct password: Location = %q, want error=rate", loc)
	}
	if cookies := w.Result().Cookies(); len(cookies) > 0 {
		t.Errorf("locked login must not set cookie")
	}

	// 锁定只影响登录，不影响其他 IP 的正常访问（302 拦截语义）
	other := httptest.NewRequest(http.MethodGet, "http://"+testHost+"/", nil)
	other.Header.Set("Accept", "text/html")
	other.RemoteAddr = "198.51.100.7:40001"
	if w2 := doEval(m, other); w2.Code != http.StatusFound {
		t.Errorf("other IP status = %d, want 302 (normal interception)", w2.Code)
	}
}

func TestLoginSuccessResetsFailures(t *testing.T) {
	m := newTestManager(t)
	for i := 0; i < AuthMaxFailures-1; i++ {
		doEval(m, newLoginRequest(http.MethodPost, AuthLoginPath,
			url.Values{"password": {"wrong"}}, false))
	}
	// 第 5 次尝试用正确密码：成功且计数清零
	doEval(m, newLoginRequest(http.MethodPost, AuthLoginPath,
		url.Values{"password": {testPassword}}, false))
	// 再错 5 次才会锁定（说明此前计数确已清零）
	for i := 0; i < AuthMaxFailures-1; i++ {
		doEval(m, newLoginRequest(http.MethodPost, AuthLoginPath,
			url.Values{"password": {"wrong"}}, false))
	}
	w := doEval(m, newLoginRequest(http.MethodPost, AuthLoginPath,
		url.Values{"password": {"wrong"}}, false))
	if strings.Contains(w.Header().Get("Location"), "error=rate") {
		t.Errorf("counter should have been reset by successful login")
	}
}

func TestNextSanitization(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", "/"},
		{"/ok?x=1", "/ok?x=1"},
		{"//evil.com", "/"},
		{"/\\evil", "/"},
		{"http://evil.com", "/"},
		{"relative", "/"},
		// F4（内部PRD §4.4）：控制字符首部/中部/尾部一律回退 /
		{"/\t/evil.com", "/"},
		{"/\n/evil.com", "/"},
		{"/\r/evil.com", "/"},
		{"/ok\tpath", "/"},
		{"/ok\x00", "/"},
		{"/ok\x1f", "/"},
		{"/ok\x7f", "/"},
		// 误杀对照：合法形态（已编码字符、query、fragment、中文路径）正常回跳
		{"/%E4%B8%AD%E6%96%87", "/%E4%B8%AD%E6%96%87"},
		{"/中文", "/中文"},
		{"/ok?a=1&b=2#frag", "/ok?a=1&b=2#frag"},
	}
	for _, tc := range cases {
		if got := sanitizeNext(tc.in); got != tc.want {
			t.Errorf("sanitizeNext(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestLoginOpenRedirectBlocked(t *testing.T) {
	m := newTestManager(t)
	form := url.Values{"password": {testPassword}, "next": {"//evil.com"}}
	w := doEval(m, newLoginRequest(http.MethodPost, AuthLoginPath, form, false))
	if loc := w.Header().Get("Location"); loc != "/" {
		t.Errorf("open redirect next must fall back to /, got %q", loc)
	}
}

func TestLogoutClearsCookie(t *testing.T) {
	m := newTestManager(t)
	w := doEval(m, newLoginRequest(http.MethodGet, AuthLogoutPath, nil, false))
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != AuthLoginPath {
		t.Errorf("Location = %q, want %s", loc, AuthLoginPath)
	}
	c := getCookie(t, w)
	// Go cookie 解析把线上的 Max-Age=0 归一化为 -1（删除语义）
	if c.MaxAge > 0 || c.Value != "" {
		t.Errorf("logout cookie Max-Age = %d value = %q, want deletion (Max-Age<=0) and empty", c.MaxAge, c.Value)
	}
}

func TestInterceptBrowserNavigation302(t *testing.T) {
	m := newTestManager(t)
	req := httptest.NewRequest(http.MethodGet, "http://"+testHost+"/docs?a=b", nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	w := doEval(m, req)
	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", w.Code)
	}
	want := AuthLoginPath + "?next=" + url.QueryEscape("/docs?a=b")
	if loc := w.Header().Get("Location"); loc != want {
		t.Errorf("Location = %q, want %q", loc, want)
	}
}

func TestInterceptAPI401(t *testing.T) {
	m := newTestManager(t)
	req := httptest.NewRequest(http.MethodGet, "http://"+testHost+"/api/data", nil)
	req.Header.Set("Accept", "application/json")
	w := doEval(m, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain", ct)
	}
}

func TestInterceptWebSocketUpgrade401(t *testing.T) {
	m := newTestManager(t)
	req := httptest.NewRequest(http.MethodGet, "http://"+testHost+"/ws", nil)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	req.Header.Set("Sec-WebSocket-Version", "13")
	w := doEval(m, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (WS must not upgrade)", w.Code)
	}
}

// public_paths 段边界豁免（H1，内部PRD）：完整段相等或为子路径才豁免。
// /healthzX 不再因纯前缀 HasPrefix 误命中 /healthz（出口标准②）
func TestPublicPathsBypass(t *testing.T) {
	m := newTestManager(t, "/healthz", "/metrics")

	// 段边界内：完整段相等 / 子路径 → 豁免透传
	for _, p := range []string{"/healthz", "/healthz/deep", "/metrics", "/metrics/"} {
		req := httptest.NewRequest(http.MethodGet, "http://"+testHost+p, nil)
		if w := doEval(m, req); w.Code != http.StatusOK {
			t.Errorf("public path %s status = %d, want passthrough", p, w.Code)
		}
	}
	// 段边界外：兄弟前缀不再豁免（无 Accept 头 → API 401）
	for _, p := range []string{"/healthzX", "/healthz-2", "/metricsfoo"} {
		req := httptest.NewRequest(http.MethodGet, "http://"+testHost+p, nil)
		if w := doEval(m, req); w.Code != http.StatusUnauthorized {
			t.Errorf("sibling path %s status = %d, want 401 (segment-boundary match, not exempted)", p, w.Code)
		}
	}
	// 前缀不匹配的路径仍被拦截
	req := httptest.NewRequest(http.MethodGet, "http://"+testHost+"/other", nil)
	req.Header.Set("Accept", "text/html")
	if w := doEval(m, req); w.Code != http.StatusFound {
		t.Errorf("/other should be intercepted, status = %d", w.Code)
	}
}

// H1 补漏（内部PRD）：/_gate-auth 无斜杠裸路径为保留路径，
// 网关自身 404 处理，不按普通路径拦截/转发后端
func TestGateAuthBarePathReserved404(t *testing.T) {
	m := newTestManager(t)
	w := doEval(m, newLoginRequest(http.MethodGet, AuthPathRoot, nil, false))
	if w.Code != http.StatusNotFound {
		t.Fatalf("bare /_gate-auth status = %d, want 404 (gate-handled reserved path)", w.Code)
	}
}

// H1 段边界匹配的兼容性回归（内部PRD §11.3）：尾斜杠条目
// （"/healthz/"，Validate 允许的旧式前缀写法）归一为 "/healthz" 后，
// 子路径 "/healthz/x" 仍豁免（旧前缀 HasPrefix 语义），兄弟前缀仍不豁免
func TestPublicPathsTrailingSlashNormalized(t *testing.T) {
	m := newTestManager(t, "/healthz/", "/metrics//")

	// 归一后完整段命中：裸路径、尾斜杠路径、子路径均豁免透传
	for _, p := range []string{"/healthz", "/healthz/", "/healthz/deep", "/metrics", "/metrics/x"} {
		req := httptest.NewRequest(http.MethodGet, "http://"+testHost+p, nil)
		if w := doEval(m, req); w.Code != http.StatusOK {
			t.Errorf("normalized public path %s status = %d, want passthrough", p, w.Code)
		}
	}
	// 兄弟前缀仍不豁免（无 Accept 头 → API 401）
	for _, p := range []string{"/healthzX", "/metricsfoo"} {
		req := httptest.NewRequest(http.MethodGet, "http://"+testHost+p, nil)
		if w := doEval(m, req); w.Code != http.StatusUnauthorized {
			t.Errorf("sibling path %s status = %d, want 401 (normalization must not widen match)", p, w.Code)
		}
	}
}

func TestLoginPageRouteAndRedirects(t *testing.T) {
	m := newTestManager(t)

	// 未登录 GET：200 + HTML + no-store
	req := httptest.NewRequest(http.MethodGet, AuthLoginPath+"?next=%2Fdash", nil)
	req.Header.Set("Accept", "text/html")
	w := doEval(m, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Errorf("Content-Type = %q", ct)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
	body := w.Body.String()
	for _, want := range []string{"访问验证", `name="password"`, `name="next"`, `value="/dash"`} {
		if !strings.Contains(body, want) {
			t.Errorf("login page missing %q", want)
		}
	}

	// 错误态服务端渲染提示
	req = httptest.NewRequest(http.MethodGet, AuthLoginPath+"?error=1", nil)
	w = doEval(m, req)
	if !strings.Contains(w.Body.String(), "密码错误") {
		t.Errorf("error=1 page should render 密码错误")
	}
	req = httptest.NewRequest(http.MethodGet, AuthLoginPath+"?error=rate", nil)
	w = doEval(m, req)
	if !strings.Contains(w.Body.String(), "尝试过于频繁") {
		t.Errorf("error=rate page should render rate hint")
	}

	// 注入值转义检查（XSS）
	req = httptest.NewRequest(http.MethodGet,
		AuthLoginPath+"?next=%2F%22%3E%3Cscript%3Ealert(1)%3C%2Fscript%3E", nil)
	w = doEval(m, req)
	if strings.Contains(w.Body.String(), "<script>alert(1)") {
		t.Errorf("next value must be html-escaped")
	}

	// 已持有效会话 GET 登录页：303 回 next
	token := IssueToken(m.key, testHost, time.Now(), m.ttl)
	req = httptest.NewRequest(http.MethodGet, AuthLoginPath+"?next=%2Fdash", nil)
	req.AddCookie(&http.Cookie{Name: AuthCookieName, Value: token})
	w = doEval(m, req)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/dash" {
		t.Errorf("authed GET login = %d %q, want 303 /dash", w.Code, w.Header().Get("Location"))
	}
}

func TestReservedUnknownPath404NotForwarded(t *testing.T) {
	m := newTestManager(t)
	req := httptest.NewRequest(http.MethodGet, AuthPathPrefix+"anything", nil)
	w := doEval(m, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
}

func TestGateHeadersOnAuthResponses(t *testing.T) {
	m := newTestManager(t)
	req := httptest.NewRequest(http.MethodGet, AuthLoginPath, nil)
	w := doEval(m, req)
	if w.Header().Get("X-Frame-Options") != "DENY" {
		t.Errorf("X-Frame-Options = %q, want DENY", w.Header().Get("X-Frame-Options"))
	}
	if !strings.Contains(w.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Errorf("CSP must include frame-ancestors 'none'")
	}
	if !strings.Contains(w.Header().Get("Content-Security-Policy"), "connect-src 'self'") {
		t.Errorf("CSP must allow same-origin fetch（JS 增强登录依赖 connect-src 'self'）")
	}
	if w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("X-Content-Type-Options missing")
	}
}

// m1CountingBody 记录 Read 调用次数的请求体 wrapper（M1：断言锁定 IP 的 body 未被读取）
type m1CountingBody struct {
	io.ReadCloser
	reads *int32
}

func (b *m1CountingBody) Read(p []byte) (int, error) {
	atomic.AddInt32(b.reads, 1)
	return b.ReadCloser.Read(p)
}

// M1（内部PRD 出口标准③）：登录体 64KB 上限精确边界（off-by-one 锁定）：
// ① 常规 1KB 表单放行走正常错误密码流程（回归对照）；② 恰好 64KB 放行（上限
// 闭区间，MaxBytesReader 语义：读到第 n 字节仍合法）；③④ 64KB+1 / 128KB 一律
// 413 快速失败且无 cookie 副作用
func TestLoginBodyOverLimit413(t *testing.T) {
	// formBody 构造字节数精确可控的表单体（url.Values.Encode 无法精确控制长度）
	formBody := func(totalBytes int) string {
		const prefix = "password="
		return prefix + strings.Repeat("p", totalBytes-len(prefix))
	}
	tests := []struct {
		name string
		body string
		want int
	}{
		{"1KB normal form passes", formBody(1024), http.StatusSeeOther},
		{"exactly 64KB passes (inclusive limit)", formBody(64 * 1024), http.StatusSeeOther},
		{"64KB+1 rejected", formBody(64*1024 + 1), http.StatusRequestEntityTooLarge},
		{"128KB rejected", formBody(128 * 1024), http.StatusRequestEntityTooLarge},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := newTestManager(t) // 每档独立 Manager，失败计数互不串扰
			req := httptest.NewRequest(http.MethodPost, AuthLoginPath, strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.RemoteAddr = "203.0.113.9:40000"
			w := httptest.NewRecorder()
			m.Evaluate(w, req)
			if w.Code != tc.want {
				t.Fatalf("body %d bytes status = %d, want %d", len(tc.body), w.Code, tc.want)
			}
			if tc.want == http.StatusSeeOther {
				// 放行档走的是正常错误密码流程（303 error=1），不是锁定/其他旁路
				if loc := w.Header().Get("Location"); !strings.Contains(loc, "error=1") {
					t.Errorf("boundary-pass Location = %q, want error=1 (normal wrong-password flow)", loc)
				}
			} else if cookies := w.Result().Cookies(); len(cookies) > 0 {
				t.Errorf("oversized login must not set cookies, got %v", cookies)
			}
		})
	}
}

// M1（内部PRD 出口标准③）：已锁定 IP POST 大 body 在读 body 前即被拒
// （计数 wrapper 断言 Read 零调用——锁定检查必须先于任何 body 读取）
func TestLoginLockedIPRejectedBeforeBodyRead(t *testing.T) {
	m := newTestManager(t)
	bad := url.Values{"password": {"wrong"}}
	for i := 0; i < AuthMaxFailures; i++ {
		doEval(m, newLoginRequest(http.MethodPost, AuthLoginPath, bad, false))
	}

	bigForm := url.Values{"password": {strings.Repeat("x", 128*1024)}}
	req := newLoginRequest(http.MethodPost, AuthLoginPath, bigForm, false)
	var reads int32
	req.Body = &m1CountingBody{ReadCloser: req.Body, reads: &reads}

	w := doEval(m, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("locked IP big body status = %d, want 303", w.Code)
	}
	if loc := w.Header().Get("Location"); !strings.Contains(loc, "error=rate") {
		t.Errorf("locked IP Location = %q, want error=rate", loc)
	}
	if n := atomic.LoadInt32(&reads); n != 0 {
		t.Errorf("locked IP body read count = %d, want 0 (lock check must precede body read)", n)
	}
}

// ── M3 单测（内部PRD §5，出口标准①③）：限速键改解析后真实 IP、
// 阈值/时长按 host 配置生效、锁定全局告警每会话至多一条 ──

// lockRecorder fake LockoutNotifier：捕获事件与 details（测试中禁用真实外发）
type lockRecorder struct {
	mu      sync.Mutex
	events  []string
	details []map[string]string
}

func (r *lockRecorder) SendNotification(event string, details map[string]string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, event)
	r.details = append(r.details, details)
	return nil
}

func (r *lockRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.events)
}

func newTestManagerFull(t *testing.T, cfg *config.HostAuthConfig, trustedProxies []string) *Manager {
	t.Helper()
	return NewManager(testHost, cfg, netutil.ParseTrustedProxies(trustedProxies), &authTestLogger{})
}

// 锁定全局告警：达到阈值（lockout 跳变沿）时恰好一条 auth_lockout，含 host、
// 键 IP、失败次数；锁定期内的后续请求（M1 前移的锁定路径）不再追加通知；
// notifier 未注入时 no-op 不 panic（既有用例即此形态，回归印证）
func TestLoginLockoutNotifiesOncePerLockoutSession(t *testing.T) {
	m := newTestManager(t)
	rec := &lockRecorder{}
	m.SetNotifier(rec)

	bad := url.Values{"password": {"wrong"}}
	for i := 0; i < AuthMaxFailures-1; i++ {
		doEval(m, newLoginRequest(http.MethodPost, AuthLoginPath, bad, false))
	}
	if n := rec.count(); n != 0 {
		t.Fatalf("notifications before threshold = %d, want 0", n)
	}
	// 第 5 次失败触发锁定 → 恰好一条告警
	doEval(m, newLoginRequest(http.MethodPost, AuthLoginPath, bad, false))
	if n := rec.count(); n != 1 {
		t.Fatalf("notifications at lockout = %d, want exactly 1", n)
	}
	if rec.events[0] != "auth_lockout" {
		t.Errorf("event = %q, want auth_lockout", rec.events[0])
	}
	d := rec.details[0]
	// 只绑定稳定键（host/client_ip，机器可读口径）+ 结构性条数；中文文案键
	//（失败次数/锁定时长/风险等）属展示文案、允许自由调整，不再断言其存在与取值
	if d["host"] != testHost {
		t.Errorf("details.host = %q, want %q", d["host"], testHost)
	}
	if d["client_ip"] != "203.0.113.9" {
		t.Errorf("details.client_ip = %q, want 203.0.113.9", d["client_ip"])
	}
	if len(d) < 2 {
		t.Errorf("details = %v, want at least 2 stable entries (host/client_ip)", d)
	}

	// 锁定期内再试（即便密码正确走锁定拒绝路径）→ 不追加告警
	doEval(m, newLoginRequest(http.MethodPost, AuthLoginPath,
		url.Values{"password": {testPassword}}, false))
	if n := rec.count(); n != 1 {
		t.Errorf("notifications after locked attempts = %d, want still 1 (per-lockout-session dedup)", n)
	}
}

// max_failures/lock_duration 配置在完整登录链路生效：阈值 2 次 + 正确密码也被锁定拒绝
func TestLoginLockoutCustomThresholdViaHandler(t *testing.T) {
	m := newTestManagerFull(t, &config.HostAuthConfig{
		Password:     testPassword,
		MaxFailures:  2,
		LockDuration: time.Hour,
	}, nil)

	bad := url.Values{"password": {"wrong"}}
	doEval(m, newLoginRequest(http.MethodPost, AuthLoginPath, bad, false))
	// 第 2 次失败即锁定（缺省阈值 5 次时不锁，可区分）
	w := doEval(m, newLoginRequest(http.MethodPost, AuthLoginPath, bad, false))
	if !strings.Contains(w.Header().Get("Location"), "error=1") {
		t.Fatalf("second failure should still be a normal wrong-password response")
	}
	// 锁定生效：正确密码也 rate
	good := url.Values{"password": {testPassword}}
	w = doEval(m, newLoginRequest(http.MethodPost, AuthLoginPath, good, false))
	if !strings.Contains(w.Header().Get("Location"), "error=rate") {
		t.Errorf("locked IP with correct password should get error=rate (max_failures=2 took effect)")
	}
	if cookies := w.Result().Cookies(); len(cookies) > 0 {
		t.Errorf("locked login must not set cookie")
	}
}

// 限速键改解析后真实 IP（trusted_proxies 口径）：受信代理背后两个不同 XFF 客户端
// 各自独立计数——锁死一个不影响另一个（共享出口不再被单 IP 连坐）
func TestLoginRateLimitKeyUsesResolvedClientIP(t *testing.T) {
	m := newTestManagerFull(t, &config.HostAuthConfig{Password: testPassword},
		[]string{"10.99.0.0/16"})

	newXFFReq := func(xff string, form url.Values) *http.Request {
		req := newLoginRequest(http.MethodPost, AuthLoginPath, form, false)
		req.RemoteAddr = "10.99.0.9:51000" // 受信直连对端（上一跳 gate/代理）
		if xff != "" {
			req.Header.Set("X-Forwarded-For", xff)
		}
		return req
	}

	bad := url.Values{"password": {"wrong"}}
	for i := 0; i < AuthMaxFailures; i++ {
		doEval(m, newXFFReq("198.51.100.1", bad))
	}
	// 客户端 A（198.51.100.1）已锁定
	w := doEval(m, newXFFReq("198.51.100.1", bad))
	if !strings.Contains(w.Header().Get("Location"), "error=rate") {
		t.Fatalf("client A should be locked after %d failures", AuthMaxFailures)
	}
	// 客户端 B（同一直连对端、不同 XFF）不受连坐：正确密码正常登录
	w = doEval(m, newXFFReq("198.51.100.2",
		url.Values{"password": {testPassword}}))
	if !strings.Contains(w.Header().Get("Location"), "/") || w.Code != http.StatusSeeOther {
		t.Fatalf("client B status = %d, want 303 (independent counter)", w.Code)
	}
	if c := getCookie(t, w); !VerifyToken(c.Value, m.key, testHost, time.Now()) {
		t.Errorf("client B should receive a valid session cookie")
	}
}

// trusted_proxies 为空时回落直连对端（netutil 现语义，边缘部署行为不变）：
// 伪造不同 XFF 不能绕开锁定——键仍是直连对端
func TestLoginRateLimitKeyFallsBackToDirectPeerWhenUntrusted(t *testing.T) {
	m := newTestManager(t) // trustedProxies = nil

	newSpoofReq := func(xff string) *http.Request {
		req := newLoginRequest(http.MethodPost, AuthLoginPath,
			url.Values{"password": {"wrong"}}, false)
		req.Header.Set("X-Forwarded-For", xff)
		return req
	}
	for i := 0; i < AuthMaxFailures; i++ {
		doEval(m, newSpoofReq("8.8.8.8"))
	}
	// 换个伪造 XFF：直连对端未变，仍应命中同一计数键（锁定）
	w := doEval(m, newSpoofReq("9.9.9.9"))
	if !strings.Contains(w.Header().Get("Location"), "error=rate") {
		t.Errorf("spoofed XFF must not evade lockout when trusted_proxies is empty (key = direct peer)")
	}
}
