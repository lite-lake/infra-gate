package proxy

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/lite-lake/infra-gate/internal/infrastructs/logger"
	"github.com/lite-lake/infra-gate/internal/netutil"
)

// --- v1.1 per-host 转发策略（forwarded_for）测试 ---
//
// 语义基线（内部PRD v1.1）：
// - 缺省 host（forwarded_for=""）恒为边缘语义：删头重建，XFF 单值 = 直连对端，
//   与 server.trusted_proxies 完全无关；
// - append host（mesh 域名）：直连对端 ∈ trusted_proxies 时 XFF = 入站原值 + 直连对端，
//   Proto/Host 继承入站最右合法值；X-Real-IP / Forwarded 等禁用头照删；
//   Port / Forwarded / Via / X-Lite-Gate-Forwarded-For 照常重建/追加；
//   直连对端不受信（或 gate 未配 trusted_proxies）时 fail-safe 回退边缘语义；
// - strip_proxy_headers=true 优先级高于 forwarded_for。

// TestForwardedForAppendOutboundXFF 表驱动：出站 XFF 形态随 forwarded_for / 受信直连 / 入站 XFF 组合变化。
func TestForwardedForAppendOutboundXFF(t *testing.T) {
	tests := []struct {
		name           string
		trustedProxies []string
		forwardedFor   string
		remoteAddr     string
		inboundXFF     string
		wantXFF        string
		wantXFFLines   int
	}{
		{
			name:           "append host + trusted mesh direct + inbound XFF appends direct peer",
			trustedProxies: []string{"10.72.0.0/24"},
			forwardedFor:   forwardedForAppend,
			remoteAddr:     "10.72.0.1:40000",
			inboundXFF:     "1.2.3.4",
			wantXFF:        "1.2.3.4, 10.72.0.1",
			wantXFFLines:   1,
		},
		{
			name:           "append host + trusted mesh direct + multi-hop inbound chain preserved and appended",
			trustedProxies: []string{"10.72.0.0/24"},
			forwardedFor:   forwardedForAppend,
			remoteAddr:     "10.72.0.1:40000",
			inboundXFF:     "203.0.113.7, 10.72.0.99",
			wantXFF:        "203.0.113.7, 10.72.0.99, 10.72.0.1",
			wantXFFLines:   1,
		},
		{
			name:           "append host + trusted mesh direct + no inbound XFF emits single direct peer",
			trustedProxies: []string{"10.72.0.0/24"},
			forwardedFor:   forwardedForAppend,
			remoteAddr:     "10.72.0.1:40000",
			wantXFF:        "10.72.0.1",
			wantXFFLines:   1,
		},
		{
			name:           "append host + untrusted direct falls back to edge (spoofed chain dropped)",
			trustedProxies: []string{"10.72.0.0/24"},
			forwardedFor:   forwardedForAppend,
			remoteAddr:     "203.0.113.9:44423",
			inboundXFF:     "6.6.6.6, 7.7.7.7",
			wantXFF:        "203.0.113.9",
			wantXFFLines:   1,
		},
		{
			name:         "append host + gate without trusted_proxies falls back to edge",
			forwardedFor: forwardedForAppend,
			remoteAddr:   "10.72.0.1:40000",
			inboundXFF:   "1.2.3.4",
			wantXFF:      "10.72.0.1",
			wantXFFLines: 1,
		},
		{
			name:           "default host + trusted mesh direct is always edge (v1.1 behavior change guard)",
			trustedProxies: []string{"10.72.0.0/24"},
			forwardedFor:   "",
			remoteAddr:     "10.72.0.1:40000",
			inboundXFF:     "6.6.6.6",
			wantXFF:        "10.72.0.1",
			wantXFFLines:   1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newForwardEchoProxy(t, tt.trustedProxies, false, tt.forwardedFor)

			req := httptest.NewRequest("GET", "http://mesh.example.com/", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.inboundXFF != "" {
				req.Header.Set("X-Forwarded-For", tt.inboundXFF)
			}

			rec := httptest.NewRecorder()
			p.ServeHTTP(rec, req)

			resp := rec.Result()
			defer resp.Body.Close()

			var echo map[string][]string
			if err := json.NewDecoder(resp.Body).Decode(&echo); err != nil {
				t.Fatalf("decode echo body: %v", err)
			}

			gotLines := echo["X-Forwarded-For"]
			if len(gotLines) != tt.wantXFFLines {
				t.Errorf("outbound X-Forwarded-For lines = %d (%v), want %d", len(gotLines), gotLines, tt.wantXFFLines)
			}
			if got := strings.Join(gotLines, ", "); got != tt.wantXFF {
				t.Errorf("outbound X-Forwarded-For = %q, want %q", got, tt.wantXFF)
			}
		})
	}
}

// TestForwardedForAppendTrustedDirectHeaderShape append host + 受信 mesh 直连的完整出站头形态：
// XFF 追加不重建单值、Proto/Host 继承入站、X-Real-IP 被删、Forwarded/Port 照常重建、
// Via / X-Lite-Gate-Forwarded-For 照旧逐跳追加。
func TestForwardedForAppendTrustedDirectHeaderShape(t *testing.T) {
	p := newForwardEchoProxy(t, []string{"10.72.0.0/24"}, false, forwardedForAppend)

	req := httptest.NewRequest("GET", "http://mesh.example.com/api", nil)
	req.RemoteAddr = "10.72.0.1:40000"
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "mesh.example.com")
	req.Header.Set("X-Real-IP", "6.6.6.6")
	req.Header.Set("Via", "1.1 upstream-proxy")
	req.Header.Set("X-Lite-Gate-Forwarded-For", "10.71.0.5:5000")

	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	var echo map[string][]string
	if err := json.NewDecoder(resp.Body).Decode(&echo); err != nil {
		t.Fatalf("decode echo body: %v", err)
	}

	// XFF：追加形态且仅一行（入站原值 + 直连对端）
	if got := strings.Join(echo["X-Forwarded-For"], ", "); got != "1.2.3.4, 10.72.0.1" {
		t.Errorf("outbound X-Forwarded-For = %q, want %q (append, not single-value rebuild)", got, "1.2.3.4, 10.72.0.1")
	}
	if len(echo["X-Forwarded-For"]) != 1 {
		t.Errorf("outbound X-Forwarded-For lines = %d (%v), want exactly 1 (no duplicate rows)", len(echo["X-Forwarded-For"]), echo["X-Forwarded-For"])
	}

	// Proto/Host：继承入站最右合法值
	if got := strings.Join(echo["X-Forwarded-Proto"], ", "); got != "https" {
		t.Errorf("outbound X-Forwarded-Proto = %q, want inherited %q", got, "https")
	}
	if got := strings.Join(echo["X-Forwarded-Host"], ", "); got != "mesh.example.com" {
		t.Errorf("outbound X-Forwarded-Host = %q, want inherited %q", got, "mesh.example.com")
	}

	// X-Real-IP 全链路禁用：追加语义下同样删除
	if _, ok := echo["X-Real-IP"]; ok {
		t.Errorf("X-Real-IP must be stripped even in append mode, got %v", echo["X-Real-IP"])
	}

	// X-Forwarded-Port：按继承的 proto 重建（https → 443）
	if got := strings.Join(echo["X-Forwarded-Port"], ", "); got != "443" {
		t.Errorf("outbound X-Forwarded-Port = %q, want %q", got, "443")
	}

	// Forwarded：照常重建，for= 为解析后的真实客户端 IP
	wantForwarded := "for=1.2.3.4;by=_;proto=https;host=mesh.example.com"
	if got := strings.Join(echo["Forwarded"], ", "); got != wantForwarded {
		t.Errorf("outbound Forwarded = %q, want %q", got, wantForwarded)
	}

	// Via：逐跳追加
	if got := strings.Join(echo["Via"], ", "); got != "1.1 upstream-proxy, 1.1 lite-gate" {
		t.Errorf("outbound Via = %q, want %q", got, "1.1 upstream-proxy, 1.1 lite-gate")
	}
	if len(echo["Via"]) != 1 {
		t.Errorf("outbound Via lines = %d (%v), want exactly 1", len(echo["Via"]), echo["Via"])
	}

	// X-Lite-Gate-Forwarded-For：逐跳追加
	if got := strings.Join(echo["X-Lite-Gate-Forwarded-For"], ", "); got != "10.71.0.5:5000, 10.72.0.1:40000" {
		t.Errorf("outbound X-Lite-Gate-Forwarded-For = %q, want %q", got, "10.71.0.5:5000, 10.72.0.1:40000")
	}
}

// TestForwardedForAppendInheritFallsBackWhenInboundAbsent append host + 受信直连但入站无
// Proto/Host 时：回退本跳 TLS/Host 推断（无 TLS → http / r.Host），不产生空值。
func TestForwardedForAppendInheritFallsBackWhenInboundAbsent(t *testing.T) {
	p := newForwardEchoProxy(t, []string{"10.72.0.0/24"}, false, forwardedForAppend)

	req := httptest.NewRequest("GET", "http://mesh.example.com/api", nil)
	req.RemoteAddr = "10.72.0.1:40000"

	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	var echo map[string][]string
	if err := json.NewDecoder(resp.Body).Decode(&echo); err != nil {
		t.Fatalf("decode echo body: %v", err)
	}

	if got := strings.Join(echo["X-Forwarded-Proto"], ", "); got != "http" {
		t.Errorf("outbound X-Forwarded-Proto = %q, want fallback %q", got, "http")
	}
	if got := strings.Join(echo["X-Forwarded-Host"], ", "); got != "mesh.example.com" {
		t.Errorf("outbound X-Forwarded-Host = %q, want fallback r.Host %q", got, "mesh.example.com")
	}
	if got := strings.Join(echo["X-Forwarded-Port"], ", "); got != "80" {
		t.Errorf("outbound X-Forwarded-Port = %q, want %q", got, "80")
	}
}

// TestStripProxyHeadersWinsOverForwardedForAppend strip_proxy_headers=true 优先于
// forwarded_for=append：即使 append+受信直连，也一个转发头都不添加。
func TestStripProxyHeadersWinsOverForwardedForAppend(t *testing.T) {
	p := newForwardEchoProxy(t, []string{"10.72.0.0/24"}, true, forwardedForAppend)

	req := httptest.NewRequest("GET", "http://mesh.example.com/", nil)
	req.RemoteAddr = "10.72.0.1:40000"
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("Via", "1.1 evil")
	req.Header.Set("X-Real-IP", "6.6.6.6")

	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	var echo map[string][]string
	if err := json.NewDecoder(resp.Body).Decode(&echo); err != nil {
		t.Fatalf("decode echo body: %v", err)
	}
	if len(echo) != 0 {
		t.Errorf("strip_proxy_headers=true must win over forwarded_for=append, got %v", echo)
	}
}

// TestWebSocketForwardedForAppendTrustedDirect WebSocket 握手头与 HTTP 路径同分支：
// append host + 受信 mesh 直连时，出站 XFF 为追加形态、Proto/Host 继承入站、
// X-Real-IP 不出现、X-Lite-Gate-Forwarded-For 照旧追加。
func TestWebSocketForwardedForAppendTrustedDirect(t *testing.T) {
	captured := make(chan http.Header, 1)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured <- r.Header.Clone()
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "hijack unsupported", http.StatusInternalServerError)
			return
		}
		conn, _, err := hijacker.Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		accept := generateWebSocketAcceptKey(r.Header.Get("Sec-WebSocket-Key"))
		fmt.Fprintf(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", accept)
	}))
	t.Cleanup(backend.Close)

	p := NewProxy(
		[]string{backend.URL},
		"/",
		10, 5,
		logger.GetDefaultLogger(),
		nil,
		[]string{"10.72.0.0/24"},
		false,
		true, // preserveHostHeader：mesh host 典型配置
		"",
		"",
		false,
		false,
		false,
		forwardedForAppend,
		defaultWSConfig(),
		UpstreamConfig{},
	)

	req := httptest.NewRequest("GET", "http://mesh.example.com/ws", nil)
	req.RemoteAddr = "10.72.0.1:41000"
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "mesh.example.com")
	req.Header.Set("X-Real-IP", "6.6.6.6")
	// 伪造的 X-Lite-Gate-* 头：复制循环必须跳过（与 HTTP 路径 Del-重建语义一致），
	// 否则会与新写入的同名头组成重复行（X-Lite-Gate-Forwarded-Host / Trace-Id）
	req.Header.Set("X-Lite-Gate-Forwarded-Host", "spoofed.example.com")
	req.Header.Set("X-Lite-Gate-Trace-Id", "spoofed-trace")

	backendURL, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatalf("parse backend URL: %v", err)
	}

	conn, _, resp, err := p.handleWebSocketUpgrade(req, backendURL, "trace-ws-ff")
	if err != nil {
		t.Fatalf("handleWebSocketUpgrade failed: %v", err)
	}
	defer conn.Close()
	defer resp.Body.Close()

	select {
	case h := <-captured:
		if got := strings.Join(h.Values("X-Forwarded-For"), ", "); got != "1.2.3.4, 10.72.0.1" {
			t.Errorf("WS handshake outbound X-Forwarded-For = %q, want appended %q", got, "1.2.3.4, 10.72.0.1")
		}
		if len(h.Values("X-Forwarded-For")) != 1 {
			t.Errorf("WS handshake outbound X-Forwarded-For lines = %d (%v), want exactly 1", len(h.Values("X-Forwarded-For")), h.Values("X-Forwarded-For"))
		}
		if got := h.Get("X-Forwarded-Proto"); got != "https" {
			t.Errorf("WS handshake outbound X-Forwarded-Proto = %q, want inherited %q", got, "https")
		}
		if got := h.Get("X-Forwarded-Host"); got != "mesh.example.com" {
			t.Errorf("WS handshake outbound X-Forwarded-Host = %q, want inherited %q", got, "mesh.example.com")
		}
		if got := h.Get("X-Real-IP"); got != "" {
			t.Errorf("WS handshake outbound X-Real-IP = %q, want empty (disabled)", got)
		}
		if got := h.Get("X-Lite-Gate-Forwarded-For"); !strings.HasPrefix(got, "10.72.0.1:41000") {
			t.Errorf("WS handshake outbound X-Lite-Gate-Forwarded-For = %q, want prefix %q", got, "10.72.0.1:41000")
		}
		// X-Lite-Gate-Forwarded-Host：入站伪造值被跳过，仅保留本跳重建的单行
		if got := strings.Join(h.Values("X-Lite-Gate-Forwarded-Host"), ", "); got != "mesh.example.com" {
			t.Errorf("WS handshake outbound X-Lite-Gate-Forwarded-Host = %q, want rebuilt single %q", got, "mesh.example.com")
		}
		// X-Lite-Gate-Trace-Id：入站伪造值被跳过，仅保留本跳 traceId
		if got := strings.Join(h.Values("X-Lite-Gate-Trace-Id"), ", "); got != "trace-ws-ff" {
			t.Errorf("WS handshake outbound X-Lite-Gate-Trace-Id = %q, want %q", got, "trace-ws-ff")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for backend to capture WS handshake headers")
	}
}

// TestBuildForwardedHeadersAppendMode 单元级：append 受信分支的 XFF 追加与 Proto/Host
// 继承直接在 buildForwardedHeaders 上验证（HTTP 与 WS 路径共用该函数）。
func TestBuildForwardedHeadersAppendMode(t *testing.T) {
	p := &Proxy{
		trustedProxies: netutil.ParseTrustedProxies([]string{"10.72.0.0/24"}),
		forwardedFor:   forwardedForAppend,
	}

	req := httptest.NewRequest("GET", "http://mesh.example.com/", nil)
	req.RemoteAddr = "10.72.0.1:40000"
	req.Header.Set("X-Forwarded-For", " 203.0.113.7 , 10.72.0.99 ")
	req.Header.Set("X-Forwarded-Proto", "https, http")
	req.Header.Set("X-Forwarded-Host", "edge.example.com, mesh.example.com")

	h := p.buildForwardedHeaders(req)

	// 入站 XFF 原样保留（不做 trim/去重）并追加直连对端
	if want := " 203.0.113.7 , 10.72.0.99 , 10.72.0.1"; h.XForwardedFor != want {
		t.Errorf("outbound X-Forwarded-For = %q, want %q", h.XForwardedFor, want)
	}
	// Proto 继承链最右合法值（http），Host 继承链最右值
	if h.XForwardedProto != "http" {
		t.Errorf("outbound X-Forwarded-Proto = %q, want rightmost legal %q", h.XForwardedProto, "http")
	}
	if h.XForwardedHost != "mesh.example.com" {
		t.Errorf("outbound X-Forwarded-Host = %q, want rightmost %q", h.XForwardedHost, "mesh.example.com")
	}
	// Forwarded for= 为解析后的真实客户端 IP（链最右不可信）
	if !strings.HasPrefix(h.Forwarded, "for=203.0.113.7;") {
		t.Errorf("outbound Forwarded = %q, want prefix %q", h.Forwarded, "for=203.0.113.7;")
	}
}
