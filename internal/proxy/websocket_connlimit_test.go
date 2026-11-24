package proxy

// F1d WS 连接上限挂点测试（内部PRD §4.1.3）：ConnLimit 注入后，
// handleWebSocket 在 wsShutdown 检查之后、hijack 之前 Acquire；超限 503；
// 后端不可达（hijack 后失败路径）同样 Release 成对释放。

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/lite-lake/infra-gate/internal/infrastructs/logger"
)

// fakeConnLimit 记录 Acquire/Release 调用的假实现
type fakeConnLimit struct {
	mu       sync.Mutex
	acquires int
	releases int
	allow    bool
	lastHost string
	lastIP   string
}

func (f *fakeConnLimit) Acquire(host, ip string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.acquires++
	f.lastHost, f.lastIP = host, ip
	return f.allow
}

func (f *fakeConnLimit) Release(host, ip string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.releases++
}

func (f *fakeConnLimit) stats() (int, int, string, string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.acquires, f.releases, f.lastHost, f.lastIP
}

// wsLimitRequest 构造 WS 升级请求（RemoteAddr 固定）
func wsLimitRequest() *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/ws", nil)
	req.RemoteAddr = "203.0.113.9:5555"
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	req.Header.Set("Sec-WebSocket-Version", "13")
	return req
}

func wsLimitProxy(t *testing.T, limit WSConnLimit) *Proxy {
	t.Helper()
	return NewProxy([]string{"http://127.0.0.1:1"}, "/healthz", time.Second, time.Second,
		logger.GetDefaultLogger(), nil, nil, false, false, "", "", false, false, false, "",
		WSConfig{
			HandshakeTimeout: time.Second,
			IdleTimeout:      time.Second,
			PingInterval:     time.Second,
			ConnLimit:        limit,
			ConnLimitHost:    "ws.example.com",
		}, UpstreamConfig{})
}

// wsLimitURL 解析后端 URL（测试辅助，失败即 Fatal）
func wsLimitURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse url %q: %v", raw, err)
	}
	return u
}

// TestWebSocketConnLimitRejects503 超限：503 + Retry-After，Acquire 被调用一次、
// 不 Release（未占用）
func TestWebSocketConnLimitRejects503(t *testing.T) {
	fake := &fakeConnLimit{allow: false}
	p := wsLimitProxy(t, fake)

	w := httptest.NewRecorder()
	p.handleWebSocket(w, wsLimitRequest(), p.backends[0], wsLimitURL(t, "http://127.0.0.1:1"), "trace", logger.GetDefaultLogger())
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", w.Code)
	}
	if ra := w.Header().Get("Retry-After"); ra != "1" {
		t.Errorf("Retry-After = %q, want 1", ra)
	}
	acq, rel, host, ip := fake.stats()
	if acq != 1 || rel != 0 {
		t.Errorf("acquire/release = %d/%d, want 1/0 (rejected, nothing held)", acq, rel)
	}
	if host != "ws.example.com" || ip != "203.0.113.9" {
		t.Errorf("limit keys = (%q, %q), want (ws.example.com, 203.0.113.9)", host, ip)
	}
}

// TestWebSocketConnLimitReleasesOnFailure 放行但后端不可达（hijack 后升级失败）：
// Acquire 与 Release 成对（失败路径不泄漏占用）
func TestWebSocketConnLimitReleasesOnFailure(t *testing.T) {
	fake := &fakeConnLimit{allow: true}
	p := wsLimitProxy(t, fake)

	w := httptest.NewRecorder()
	// 后端 127.0.0.1:1 不可达 → handleWebSocketUpgrade 失败 → 写错误响应后 return
	p.handleWebSocket(w, wsLimitRequest(), p.backends[0], wsLimitURL(t, "http://127.0.0.1:1"), "trace", logger.GetDefaultLogger())
	acq, rel, _, _ := fake.stats()
	if acq != 1 {
		t.Fatalf("acquires = %d, want 1", acq)
	}
	if rel != 1 {
		t.Errorf("releases = %d, want 1 (paired release on failure path)", rel)
	}
}
