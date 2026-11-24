package proxy

// 内部PRD §5.3/§5.4/§5.5：proxy 层测试——
//   - 上游返回的同名响应头（X-Lite-Gate-Trace-Id / traceparent / tracestate）被过滤；
//   - 出站 traceparent 删除重建：trace-id 与权威 ID 一致、parent-id 每跳新生成、flags 继承；
//   - strip_proxy_headers=true 时不发送任何 trace 头；
//   - WebSocket 101 手写响应恰好一个 trace 头（hijack 路径唯一注入），上游握手带新 traceparent。

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lite-lake/infra-gate/internal/trace"
)

const proxyTestTid = "4bf92f3577b34da6a3ce929d0e0e4736"

// backfilledRequest 构造一条已由 server 中间件回填权威 ID 的请求（模拟生产链）
func backfilledRequest(path string) *http.Request {
	req := httptest.NewRequest("GET", "http://app.example.com"+path, nil)
	req.RemoteAddr = "203.0.113.9:44423"
	req.Header.Set(trace.TraceIdHeader, proxyTestTid)
	req.Header.Set(trace.TraceParentHeader, trace.BuildTraceParent(proxyTestTid, "01"))
	return req
}

// TestUpstreamTraceResponseHeadersFiltered 上游返回同名响应头（含重复行）时，
// 复制循环必须全部过滤——响应侧唯一注入点是 server 中间件（决策 D3/D7）
func TestUpstreamTraceResponseHeadersFiltered(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add(trace.TraceIdHeader, "upstream-1")
		w.Header().Add(trace.TraceIdHeader, "upstream-2")
		w.Header().Set(trace.TraceParentHeader, "00-"+proxyTestTid+"-00f067aa0ba902b7-01")
		w.Header().Set(trace.TraceStateHeader, "vendor@1")
		fmt.Fprint(w, "ok")
	}))
	t.Cleanup(backend.Close)

	p := newGateProxy(t, gateProxyOptions{backend: backend.URL})
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, backfilledRequest("/"))

	if n := len(rec.Header().Values(trace.TraceIdHeader)); n != 0 {
		t.Errorf("X-Lite-Gate-Trace-Id count = %d (%v), want 0 (upstream values filtered, injected by server middleware)", n, rec.Header().Values(trace.TraceIdHeader))
	}
	if got := rec.Header().Get(trace.TraceParentHeader); got != "" {
		t.Errorf("response traceparent = %q, want absent (D7)", got)
	}
	if got := rec.Header().Get(trace.TraceStateHeader); got != "" {
		t.Errorf("response tracestate = %q, want absent", got)
	}
}

// TestProxyOutboundTraceParentRebuilt 出站请求的 trace 头删除重建：
// 恰好一行、trace-id 与权威 ID 一致、parent-id 每跳新生成、flags 继承本跳回填值
func TestProxyOutboundTraceParentRebuilt(t *testing.T) {
	echoBackend, echoCh := newCaptureBackend(t)
	p := newGateProxy(t, gateProxyOptions{backend: echoBackend.URL})

	req := backfilledRequest("/")
	// 模拟入站残留的伪造值已被 server 回填覆盖；此处再追加多行验证 Del 兜底
	req.Header.Add(trace.TraceIdHeader, "spoofed-extra")
	req.Header.Add(trace.TraceParentHeader, "00-"+proxyTestTid+"-0000000000000000-00")

	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	got := waitCapture(t, echoCh, "echo backend capture")
	if n := len(got.Header.Values(trace.TraceIdHeader)); n != 1 || got.Header.Get(trace.TraceIdHeader) != proxyTestTid {
		t.Errorf("outbound X-Lite-Gate-Trace-Id = %v, want exactly [%s]", got.Header.Values(trace.TraceIdHeader), proxyTestTid)
	}
	tps := got.Header.Values(trace.TraceParentHeader)
	if len(tps) != 1 {
		t.Fatalf("outbound traceparent lines = %v, want exactly 1", tps)
	}
	tid, pid, flags, ok := trace.ParseTraceParent(tps[0])
	if !ok {
		t.Fatalf("outbound traceparent %q invalid", tps[0])
	}
	if tid != proxyTestTid {
		t.Errorf("outbound traceparent trace-id = %q, want %q", tid, proxyTestTid)
	}
	if pid == "00f067aa0ba902b7" || pid == "0000000000000000" {
		t.Errorf("outbound traceparent parent-id = %q, want freshly generated per hop", pid)
	}
	if flags != "01" {
		t.Errorf("outbound traceparent flags = %q, want inherited 01", flags)
	}
}

// TestProxyLegacyTraceIdNoTraceParent 权威 ID 为旧格式兼容采信（如新版内层采信
// 旧版边缘的 8 位 ID）时无法构建 W3C traceparent——X-Lite-Gate-Trace-Id 照常传播，
// traceparent 跳过（宁缺勿假）
func TestProxyLegacyTraceIdNoTraceParent(t *testing.T) {
	echoBackend, echoCh := newCaptureBackend(t)
	p := newGateProxy(t, gateProxyOptions{backend: echoBackend.URL})

	req := httptest.NewRequest("GET", "http://app.example.com/", nil)
	req.RemoteAddr = "203.0.113.9:44423"
	req.Header.Set(trace.TraceIdHeader, "oldid123")

	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	got := waitCapture(t, echoCh, "echo backend capture")
	if got.Header.Get(trace.TraceIdHeader) != "oldid123" {
		t.Errorf("outbound X-Lite-Gate-Trace-Id = %q, want oldid123 (legacy propagated)", got.Header.Get(trace.TraceIdHeader))
	}
	if tp := got.Header.Get(trace.TraceParentHeader); tp != "" {
		t.Errorf("outbound traceparent = %q, want absent for legacy trace id", tp)
	}
}

// TestProxyStripProxyHeadersNoTraceHeaders strip_proxy_headers=true 时不发送任何 trace 头
func TestProxyStripProxyHeadersNoTraceHeaders(t *testing.T) {
	echoBackend, echoCh := newCaptureBackend(t)
	p := newGateProxy(t, gateProxyOptions{
		backend: echoBackend.URL,
		// gateProxyOptions 无 stripProxyHeaders 字段（既有测试基建），此处直接构造
	})
	p.stripProxyHeaders = true

	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, backfilledRequest("/"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	got := waitCapture(t, echoCh, "echo backend capture")
	if got.Header.Get(trace.TraceIdHeader) != "" {
		t.Errorf("strip=true outbound X-Lite-Gate-Trace-Id = %q, want absent", got.Header.Get(trace.TraceIdHeader))
	}
	if got.Header.Get(trace.TraceParentHeader) != "" {
		t.Errorf("strip=true outbound traceparent = %q, want absent", got.Header.Get(trace.TraceParentHeader))
	}
}

// --- A7：WebSocket 101 手写响应恰好一个 trace 头（hijack 路径不走 header map）---

// TestWebSocket101SingleTraceHeader 原始 TCP 层断言 101 响应字节流：
// X-Lite-Gate-Trace-Id 恰好一行、无 traceparent（D7）；上游握手请求携带
// 权威 ID 与重建的 traceparent。
func TestWebSocket101SingleTraceHeader(t *testing.T) {
	wsBackend, captured := newWSHijackBackend(t)
	p := newGateProxy(t, gateProxyOptions{backend: wsBackend.URL})
	proxyFront := httptest.NewServer(http.HandlerFunc(p.ServeHTTP))
	t.Cleanup(proxyFront.Close)

	conn, err := net.Dial("tcp", strings.TrimPrefix(proxyFront.URL, "http://"))
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	fmt.Fprintf(conn, "GET /ws HTTP/1.1\r\n"+
		"Host: app.example.com\r\n"+
		"Upgrade: websocket\r\n"+
		"Connection: Upgrade\r\n"+
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"+
		"Sec-WebSocket-Version: 13\r\n"+
		"X-Lite-Gate-Trace-Id: %s\r\n"+
		"traceparent: %s\r\n"+
		"X-Forwarded-For: 6.6.6.6\r\n"+
		"\r\n", proxyTestTid, "00-"+proxyTestTid+"-00f067aa0ba902b7-01")

	// 逐行读取 101 响应头（hijack 后的原始字节流）
	reader := bufio.NewReader(conn)
	var statusLine, traceLine, parentLine string
	traceCount, parentCount := 0, 0
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read 101 response: %v", err)
		}
		trimmed := strings.TrimRight(line, "\r\n")
		if statusLine == "" {
			statusLine = trimmed
		}
		if strings.HasPrefix(strings.ToLower(trimmed), "x-lite-gate-trace-id:") {
			traceCount++
			traceLine = trimmed
		}
		if strings.HasPrefix(strings.ToLower(trimmed), "traceparent:") {
			parentCount++
			parentLine = trimmed
		}
		if trimmed == "" {
			break
		}
	}
	if !strings.Contains(statusLine, "101") {
		t.Fatalf("status line = %q, want 101 Switching Protocols", statusLine)
	}
	if traceCount != 1 {
		t.Fatalf("101 response X-Lite-Gate-Trace-Id count = %d, want exactly 1", traceCount)
	}
	if !strings.Contains(traceLine, proxyTestTid) {
		t.Errorf("101 response trace header = %q, want authoritative id %q", traceLine, proxyTestTid)
	}
	if parentCount != 0 {
		t.Errorf("101 response carries traceparent (%q), want absent (D7)", parentLine)
	}

	// 上游握手请求：权威 ID + 重建 traceparent（trace-id 一致、parent-id 新生成）
	select {
	case got := <-captured:
		if got.Header.Get(trace.TraceIdHeader) != proxyTestTid {
			t.Errorf("WS upstream X-Lite-Gate-Trace-Id = %q, want %q", got.Header.Get(trace.TraceIdHeader), proxyTestTid)
		}
		tid, pid, flags, ok := trace.ParseTraceParent(got.Header.Get(trace.TraceParentHeader))
		if !ok {
			t.Fatalf("WS upstream traceparent %q invalid", got.Header.Get(trace.TraceParentHeader))
		}
		if tid != proxyTestTid {
			t.Errorf("WS upstream traceparent trace-id = %q, want %q", tid, proxyTestTid)
		}
		if pid == "00f067aa0ba902b7" || pid == "" {
			t.Errorf("WS upstream traceparent parent-id = %q, want fresh per-hop value", pid)
		}
		if flags != "01" {
			t.Errorf("WS upstream traceparent flags = %q, want 01", flags)
		}
		if xff := got.Header.Get("X-Forwarded-For"); xff == "6.6.6.6" {
			t.Errorf("WS upstream XFF = forged value, want rebuilt")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for WS backend handshake capture")
	}
}
