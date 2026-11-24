package proxy

// WS 升级非 101 响应透传测试：后端以正常 HTTP 语义拒绝升级
//（401/404 等，如 Vaultwarden /notifications/hub token 失效）时，网关把响应
// 原样透传给客户端（状态行/头/体），不再合成 502；传输层失败（dial refused/
// timeout/TLS）仍走合成 502/504。

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/lite-lake/infra-gate/internal/infrastructs/logger"
)

// wsHijackRecorder 支持 Hijack 的测试 ResponseWriter：hijack 后 handler 直接写
// 裸连接（net.Pipe 客户端端），测试侧从管道另一端读原始响应字节。
type wsHijackRecorder struct {
	header   http.Header
	code     int
	hijacked net.Conn // 管道 server 端，测试侧读取用
}

func newWSHijackRecorder() *wsHijackRecorder {
	return &wsHijackRecorder{header: make(http.Header)}
}

func (h *wsHijackRecorder) Header() http.Header         { return h.header }
func (h *wsHijackRecorder) WriteHeader(code int)        { h.code = code }
func (h *wsHijackRecorder) Write(b []byte) (int, error) { return len(b), nil }
func (h *wsHijackRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	client, server := net.Pipe()
	h.hijacked = server
	return client, bufio.NewReadWriter(bufio.NewReader(client), bufio.NewWriter(client)), nil
}

func wsRelayProxy(t *testing.T, backend string) *Proxy {
	t.Helper()
	return NewProxy([]string{backend}, "/healthz", time.Second, time.Second,
		logger.GetDefaultLogger(), nil, nil, false, false, "", "", false, false, false, "",
		WSConfig{
			HandshakeTimeout: 2 * time.Second,
			IdleTimeout:      time.Second,
			PingInterval:     time.Second,
		}, UpstreamConfig{})
}

// wsRelayRequest 构造 WS 升级请求（带 query，模拟 Bitwarden hub access_token）
func wsRelayRequest(rawQuery string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/notifications/hub?"+rawQuery, nil)
	req.RemoteAddr = "203.0.113.9:5555"
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	req.Header.Set("Sec-WebSocket-Version", "13")
	return req
}

// wsRelayDrain 并发读取 hijack 后 handler 写出的原始响应（net.Pipe 无缓冲，
// 必须边写边读，handler defer Close 后读到 EOF）
func wsRelayDrain(rec *wsHijackRecorder) (*bytes.Buffer, chan struct{}) {
	var buf bytes.Buffer
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(&buf, rec.hijacked)
		close(done)
	}()
	return &buf, done
}

// TestWebSocketRelaysNon101Response 后端 401：401 状态行/头/体原样透传，
// 不再合成 502（回归：此前客户端只看到 502，token 失效被误判网络故障）
func TestWebSocketRelaysNon101Response(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"Invalid token"}`))
	}))
	defer backend.Close()

	p := wsRelayProxy(t, backend.URL)
	u, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatalf("parse url %q: %v", backend.URL, err)
	}

	rec := newWSHijackRecorder()
	buf, done := wsRelayDrain(rec)
	p.handleWebSocket(rec, wsRelayRequest("access_token=expired"), backend.URL, u, "trace-662", logger.GetDefaultLogger())
	<-done

	raw := buf.String()
	if !strings.Contains(raw, "HTTP/1.1 401 Unauthorized") {
		t.Errorf("relayed response missing 401 status line:\n%s", raw)
	}
	if !strings.Contains(raw, "Content-Type: application/json") {
		t.Errorf("relayed response missing backend Content-Type:\n%s", raw)
	}
	if !strings.Contains(raw, `{"message":"Invalid token"}`) {
		t.Errorf("relayed response missing backend body:\n%s", raw)
	}
	if !strings.Contains(raw, "X-Lite-Gate-Trace-Id: trace-662") {
		t.Errorf("relayed response missing trace id:\n%s", raw)
	}
	if got := strings.Count(raw, "X-Lite-Gate-Trace-Id:"); got != 1 {
		// 链式部署下上游 relay 响应自带的 trace 头必须被过滤，逐跳只写本跳单值
		t.Errorf("relayed response trace header count = %d, want 1:\n%s", got, raw)
	}
	if !strings.Contains(raw, "Connection: close") {
		t.Errorf("relayed response missing Connection: close:\n%s", raw)
	}
	if strings.Contains(raw, "502") {
		t.Errorf("relayed response must not be synthetic 502:\n%s", raw)
	}
}

// TestWebSocketRelaysNon101StatusOnlyBody 后端 426（Upgrade Required）无自定义头：
// 同样透传真实状态码
func TestWebSocketRelaysNon101StatusOnlyBody(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUpgradeRequired)
	}))
	defer backend.Close()

	p := wsRelayProxy(t, backend.URL)
	u, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatalf("parse url %q: %v", backend.URL, err)
	}

	rec := newWSHijackRecorder()
	buf, done := wsRelayDrain(rec)
	p.handleWebSocket(rec, wsRelayRequest(""), backend.URL, u, "", logger.GetDefaultLogger())
	<-done

	raw := buf.String()
	if !strings.Contains(raw, "HTTP/1.1 426 Upgrade Required") {
		t.Errorf("relayed response missing 426 status line:\n%s", raw)
	}
	if strings.Contains(raw, "X-Lite-Gate-Trace-Id:") {
		t.Errorf("empty traceId must not emit trace header:\n%s", raw)
	}
	if strings.Contains(raw, "502") {
		t.Errorf("relayed response must not be synthetic 502:\n%s", raw)
	}
}

// TestWebSocketTransportFailureStillSynthetic502 后端不可达（dial refused）：
// 保持既有合成 502 行为不变
func TestWebSocketTransportFailureStillSynthetic502(t *testing.T) {
	const dead = "http://127.0.0.1:1"
	p := wsRelayProxy(t, dead)
	u, err := url.Parse(dead)
	if err != nil {
		t.Fatalf("parse url %q: %v", dead, err)
	}

	rec := newWSHijackRecorder()
	buf, done := wsRelayDrain(rec)
	p.handleWebSocket(rec, wsRelayRequest("access_token=x"), dead, u, "trace-662", logger.GetDefaultLogger())
	<-done

	raw := buf.String()
	if !strings.Contains(raw, "HTTP/1.1 502 Bad Gateway") {
		t.Errorf("transport failure must stay synthetic 502:\n%s", raw)
	}
	if strings.Contains(raw, "401") {
		t.Errorf("transport failure must not relay stale status:\n%s", raw)
	}
}
