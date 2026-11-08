package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/lite-lake/infra-gate/internal/config"
	"github.com/lite-lake/infra-gate/internal/infrastructs/logger"
	"github.com/lite-lake/infra-gate/internal/netutil"
)

func TestGenerateWebSocketAcceptKey(t *testing.T) {
	// Test with the example from RFC 6455
	key := "dGhlIHNhbXBsZSBub25jZQ=="
	expected := "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="

	result := generateWebSocketAcceptKey(key)
	if result != expected {
		t.Errorf("generateWebSocketAcceptKey(%q) = %q, want %q", key, result, expected)
	}
}

func TestIsControlFrame(t *testing.T) {
	tests := []struct {
		opcode   byte
		expected bool
	}{
		{0x00, false}, // Continuation frame
		{0x01, false}, // Text frame
		{0x02, false}, // Binary frame
		{0x08, true},  // Close frame
		{0x09, true},  // Ping frame
		{0x0A, true},  // Pong frame
		{0x0B, true},  // Reserved control frame
		{0x0F, true},  // Reserved control frame
	}

	for _, tt := range tests {
		result := isControlFrame(tt.opcode)
		if result != tt.expected {
			t.Errorf("isControlFrame(0x%02X) = %v, want %v", tt.opcode, result, tt.expected)
		}
	}
}

func TestHandleWebSocketUpgradeRequest(t *testing.T) {
	// Create a test request
	req, err := http.NewRequest("GET", "/ws", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	req.Header.Set("Sec-WebSocket-Version", "13")

	// Verify the request has the required headers
	if req.Header.Get("Upgrade") != "websocket" {
		t.Error("Request should have Upgrade: websocket header")
	}
	if req.Header.Get("Sec-WebSocket-Version") != "13" {
		t.Error("Request should have Sec-WebSocket-Version: 13 header")
	}
}

func TestReadWebSocketFrame(t *testing.T) {
	// Test reading a simple unmasked text frame (backend→client, not masked)
	// FIN=1, opcode=1 (text), MASK=0, length=5
	frame := []byte{0x81, 0x05, 'H', 'e', 'l', 'l', 'o'}
	reader := bufio.NewReader(bytes.NewReader(frame))

	result, err := readWebSocketFrame(reader, "backend", false)
	if err != nil {
		t.Fatalf("readWebSocketFrame failed: %v", err)
	}

	if !bytes.Equal(result, frame) {
		t.Errorf("readWebSocketFrame returned wrong data. Got %v, want %v", result, frame)
	}
}

func newTestProxy(t *testing.T, backendHandler http.Handler, clearAcceptEncoding bool) *Proxy {
	t.Helper()
	backend := httptest.NewServer(backendHandler)
	t.Cleanup(backend.Close)

	log := logger.GetDefaultLogger()
	p := NewProxy(
		[]string{backend.URL},
		"/",
		10, 5,
		log,
		nil,
		nil,
		false,
		false,
		"",
		"",
		clearAcceptEncoding,
		false,
		false,
		"",
		defaultWSConfig(),
		UpstreamConfig{},
	)
	return p
}

func TestContentLengthForwarding(t *testing.T) {
	body := `{"message":"hello world"}`
	backendHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, body)
	})

	p := newTestProxy(t, backendHandler, true)

	req := httptest.NewRequest("GET", "/api/test", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	cl := resp.Header.Get("Content-Length")
	if cl == "" {
		t.Error("Content-Length header is missing from response")
	}
	if cl != strconv.Itoa(len(body)) {
		t.Errorf("Content-Length = %q, want %d", cl, len(body))
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll failed: %v", err)
	}
	if string(respBody) != body {
		t.Errorf("response body = %q, want %q", string(respBody), body)
	}
}

func TestContentLengthForwardingNoGzip(t *testing.T) {
	body := `{"message":"hello world"}`
	backendHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, body)
	})

	p := newTestProxy(t, backendHandler, false)

	req := httptest.NewRequest("GET", "/api/test", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	cl := resp.Header.Get("Content-Length")
	if cl == "" {
		t.Error("Content-Length header is missing from response")
	}
	if cl != strconv.Itoa(len(body)) {
		t.Errorf("Content-Length = %q, want %d", cl, len(body))
	}
}

func TestContentLengthRestoredAfterTransportGzipDecompression(t *testing.T) {
	rawBody := `{"message":"hello world decompressed by transport"}`
	backendHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept-Encoding") == "" {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Length", strconv.Itoa(len(rawBody)))
			w.WriteHeader(http.StatusOK)
			io.WriteString(w, rawBody)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, rawBody)
	})

	p := newTestProxy(t, backendHandler, true)

	req := httptest.NewRequest("GET", "/api/test", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	cl := resp.Header.Get("Content-Length")
	if cl == "" {
		t.Error("Content-Length header is missing from response (should have been restored from resp.ContentLength)")
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll failed: %v", err)
	}
	if string(respBody) != rawBody {
		t.Errorf("response body = %q, want %q", string(respBody), rawBody)
	}
}

// --- S1: wsConnWriter 并发写入测试 ---

func TestWsConnWriterConcurrentWriteNoCorruption(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	writer := newWsConnWriter(clientConn)

	const goroutines = 10
	const framesPerGoroutine = 50

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < framesPerGoroutine; j++ {
				frame := []byte{0x81, 0x03, byte('A' + id%26), byte('0' + byte(j%10)), byte('x')}
				if err := writer.writeFrame(frame); err != nil {
					if err != io.ErrClosedPipe {
						t.Errorf("goroutine %d writeFrame failed: %v", id, err)
					}
					return
				}
			}
		}(i)
	}

	// Read all frames and verify each one is intact (5 bytes)
	go func() {
		wg.Wait()
		clientConn.Close()
	}()

	reader := bufio.NewReader(serverConn)
	totalExpected := goroutines * framesPerGoroutine
	received := 0
	for received < totalExpected {
		frame, err := readWebSocketFrame(reader, "backend", false)
		if err != nil {
			if err == io.EOF || err == io.ErrClosedPipe {
				break
			}
			t.Fatalf("readWebSocketFrame failed at frame %d: %v", received, err)
		}
		if len(frame) != 5 {
			t.Errorf("frame %d corrupted: got %d bytes, want 5", received, len(frame))
		}
		received++
	}

	if received != totalExpected {
		t.Errorf("received %d frames, want %d (some frames may have been corrupted/lost)", received, totalExpected)
	}
}

// --- S2: createPongFrameToClient / createPongFrameToBackend 测试 ---

// buildMaskedPingFrame 构造一个带掩码的 ping 帧（模拟客户端发送）
func buildMaskedPingFrame(payload []byte) []byte {
	maskKey := []byte{0x12, 0x34, 0x56, 0x78}
	maskedPayload := make([]byte, len(payload))
	for i := range payload {
		maskedPayload[i] = payload[i] ^ maskKey[i%4]
	}

	// FIN=1, opcode=ping(0x09), MASK=1, length=len(payload)
	frame := []byte{0x89, 0x80 | byte(len(payload))}
	frame = append(frame, maskKey...)
	frame = append(frame, maskedPayload...)
	return frame
}

// buildUnmaskedPingFrame 构造一个不带掩码的 ping 帧（模拟后端发送）
func buildUnmaskedPingFrame(payload []byte) []byte {
	// FIN=1, opcode=ping(0x09), MASK=0, length=len(payload)
	frame := []byte{0x89, byte(len(payload))}
	frame = append(frame, payload...)
	return frame
}

func TestCreatePongFrameToClient(t *testing.T) {
	payload := []byte("hello")
	maskedPing := buildMaskedPingFrame(payload)

	pong, err := createPongFrameToClient(maskedPing)
	if err != nil {
		t.Fatalf("createPongFrameToClient failed: %v", err)
	}

	// Verify opcode is pong
	if (pong[0] & 0x0F) != wsOpcodePong {
		t.Errorf("pong opcode = 0x%02X, want 0x%02X", pong[0]&0x0F, wsOpcodePong)
	}

	// Verify MASK bit is NOT set (server→client frames must not be masked)
	if (pong[1] & 0x80) != 0 {
		t.Error("pong frame to client should NOT have MASK bit set")
	}

	// Verify payload length
	pongPayloadLen := int(pong[1] & 0x7F)
	if pongPayloadLen != len(payload) {
		t.Fatalf("pong payload length = %d, want %d", pongPayloadLen, len(payload))
	}

	// Verify payload is correctly unmasked
	pongPayload := pong[2:]
	if !bytes.Equal(pongPayload, payload) {
		t.Errorf("pong payload = %q, want %q (should be unmasked)", string(pongPayload), string(payload))
	}

	// Verify FIN bit is set
	if (pong[0] & 0x80) == 0 {
		t.Error("pong frame should have FIN bit set")
	}
}

func TestCreatePongFrameToClientUnmaskedInput(t *testing.T) {
	payload := []byte("test")
	unmaskedPing := buildUnmaskedPingFrame(payload)

	pong, err := createPongFrameToClient(unmaskedPing)
	if err != nil {
		t.Fatalf("createPongFrameToClient failed: %v", err)
	}

	// Verify MASK bit is NOT set
	if (pong[1] & 0x80) != 0 {
		t.Error("pong frame to client should NOT have MASK bit set even if input was already unmasked")
	}

	// Verify payload
	pongPayload := pong[2:]
	if !bytes.Equal(pongPayload, payload) {
		t.Errorf("pong payload = %q, want %q", string(pongPayload), string(payload))
	}
}

func TestCreatePongFrameToBackend(t *testing.T) {
	payload := []byte("hello")
	unmaskedPing := buildUnmaskedPingFrame(payload)

	pong, err := createPongFrameToBackend(unmaskedPing)
	if err != nil {
		t.Fatalf("createPongFrameToBackend failed: %v", err)
	}

	// Verify opcode is pong
	if (pong[0] & 0x0F) != wsOpcodePong {
		t.Errorf("pong opcode = 0x%02X, want 0x%02X", pong[0]&0x0F, wsOpcodePong)
	}

	// Verify MASK bit IS set (client→server frames must be masked)
	if (pong[1] & 0x80) == 0 {
		t.Error("pong frame to backend should have MASK bit set")
	}

	// Verify payload length
	pongPayloadLen := int(pong[1] & 0x7F)
	if pongPayloadLen != len(payload) {
		t.Fatalf("pong payload length = %d, want %d", pongPayloadLen, len(payload))
	}

	// Verify mask key exists (4 bytes after header)
	if len(pong) < 2+4+len(payload) {
		t.Fatalf("pong frame too short: %d bytes, expected at least %d", len(pong), 2+4+len(payload))
	}

	maskKey := pong[2 : 2+4]
	maskedPayload := pong[2+4:]

	// Unmask the payload and verify
	unmaskedPayload := make([]byte, len(maskedPayload))
	for i := range maskedPayload {
		unmaskedPayload[i] = maskedPayload[i] ^ maskKey[i%4]
	}

	if !bytes.Equal(unmaskedPayload, payload) {
		t.Errorf("unmasked pong payload = %q, want %q", string(unmaskedPayload), string(payload))
	}

	// Verify FIN bit is set
	if (pong[0] & 0x80) == 0 {
		t.Error("pong frame should have FIN bit set")
	}
}

func TestCreatePongFrameToBackendMaskedInput(t *testing.T) {
	payload := []byte("world")
	maskedPing := buildMaskedPingFrame(payload)

	pong, err := createPongFrameToBackend(maskedPing)
	if err != nil {
		t.Fatalf("createPongFrameToBackend failed: %v", err)
	}

	// Verify MASK bit IS set
	if (pong[1] & 0x80) == 0 {
		t.Error("pong frame to backend should have MASK bit set even if input was already masked")
	}

	// Verify payload by unmasking
	pongPayloadLen := int(pong[1] & 0x7F)
	maskKey := pong[2 : 2+4]
	maskedPayload := pong[2+4:]

	if pongPayloadLen != len(payload) {
		t.Fatalf("pong payload length = %d, want %d", pongPayloadLen, len(payload))
	}

	unmaskedPayload := make([]byte, len(maskedPayload))
	for i := range maskedPayload {
		unmaskedPayload[i] = maskedPayload[i] ^ maskKey[i%4]
	}

	if !bytes.Equal(unmaskedPayload, payload) {
		t.Errorf("unmasked pong payload = %q, want %q", string(unmaskedPayload), string(payload))
	}
}

func TestCreatePongFrameToClientEmptyPayload(t *testing.T) {
	// Masked ping with empty payload (typical keepalive ping)
	maskedPing := []byte{0x89, 0x80, 0x12, 0x34, 0x56, 0x78}

	pong, err := createPongFrameToClient(maskedPing)
	if err != nil {
		t.Fatalf("createPongFrameToClient failed: %v", err)
	}

	if (pong[1] & 0x80) != 0 {
		t.Error("pong frame to client with empty payload should NOT have MASK bit set")
	}

	if len(pong) != 2 {
		t.Errorf("pong frame length = %d, want 2 (header only, no payload)", len(pong))
	}
}

func TestCreatePongFrameToBackendEmptyPayload(t *testing.T) {
	// Unmasked ping with empty payload
	unmaskedPing := []byte{0x89, 0x00}

	pong, err := createPongFrameToBackend(unmaskedPing)
	if err != nil {
		t.Fatalf("createPongFrameToBackend failed: %v", err)
	}

	if (pong[1] & 0x80) == 0 {
		t.Error("pong frame to backend with empty payload should have MASK bit set")
	}

	// Should be: header(2) + maskKey(4) = 6 bytes
	if len(pong) != 6 {
		t.Errorf("pong frame length = %d, want 6 (header + mask key, no payload)", len(pong))
	}
}

// --- 内部PRD 迭代 1：出站转发头语义（决策 D1）测试 ---

// newForwardEchoProxy 构造一个把指定转发头按原样回显为 JSON 的测试代理，
// 供端到端断言出站头形态。trustedProxies / stripProxyHeaders / forwardedFor 直接透传给 NewProxy。
func newForwardEchoProxy(t *testing.T, trustedProxies []string, stripProxyHeaders bool, forwardedFor string) *Proxy {
	t.Helper()
	echoHeaders := []string{
		"X-Forwarded-For", "X-Forwarded-Proto", "X-Forwarded-Host", "X-Forwarded-Port",
		"Forwarded", "Via", "X-Real-IP", "X-Lite-Gate-Forwarded-For", "X-Lite-Gate-Forwarded-Host",
		"X-Lite-Gate-Trace-Id",
	}
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		echo := make(map[string][]string)
		for _, h := range echoHeaders {
			if v := r.Header.Values(h); len(v) > 0 {
				echo[h] = v
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(echo)
	}))
	t.Cleanup(backend.Close)

	return NewProxy(
		[]string{backend.URL},
		"/",
		10, 5,
		logger.GetDefaultLogger(),
		nil,
		trustedProxies,
		false,
		false,
		"",
		"",
		false,
		false,
		stripProxyHeaders,
		forwardedFor,
		defaultWSConfig(),
		UpstreamConfig{},
	)
}

// 场景 1（v1.1 行为变更守卫，内部PRD per-host 转发策略）：
// 缺省 host（forwarded_for=""）恒为边缘语义——即使 gate 配置了 trusted_proxies 且
// 直连对端受信，出站 XFF 也一律单值重建为直连对端 IP，入站链（含受信上一跳带来的
// 合法链）一律丢弃。v1.0 曾在此场景解析受信链（XFF=链中最右不可信 IP），v1.1 废除。
func TestBuildForwardedHeadersOutboundXFFSingleValue(t *testing.T) {
	tests := []struct {
		name           string
		trustedProxies []string
		remoteAddr     string
		inboundXFF     string
		wantXFF        string
	}{
		{
			name:       "untrusted direct ignores inbound chain and uses direct peer",
			remoteAddr: "203.0.113.9:44423",
			inboundXFF: "1.2.3.4, 5.6.7.8",
			wantXFF:    "203.0.113.9",
		},
		{
			name:           "default host with trusted direct is always edge (v1.1): inbound chain dropped, XFF=direct peer",
			trustedProxies: []string{"10.72.0.0/24"},
			remoteAddr:     "10.72.0.1:40000",
			inboundXFF:     "203.0.113.7, 10.72.0.99",
			wantXFF:        "10.72.0.1",
		},
		{
			name:           "default host with trusted direct and all-trusted chain uses direct peer",
			trustedProxies: []string{"10.72.0.0/24"},
			remoteAddr:     "10.72.0.1:40000",
			inboundXFF:     "10.72.0.99, 10.72.0.98",
			wantXFF:        "10.72.0.1",
		},
		{
			name:           "default host with trusted direct without XFF uses direct peer",
			trustedProxies: []string{"10.72.0.0/24"},
			remoteAddr:     "10.72.0.1:40000",
			wantXFF:        "10.72.0.1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// forwardedFor 为零值 ""（缺省 host），锁定恒边缘语义
			p := &Proxy{trustedProxies: netutil.ParseTrustedProxies(tt.trustedProxies)}
			req := httptest.NewRequest("GET", "http://app.example.com/", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.inboundXFF != "" {
				req.Header.Set("X-Forwarded-For", tt.inboundXFF)
			}

			got := p.buildForwardedHeaders(req).XForwardedFor
			if got != tt.wantXFF {
				t.Errorf("outbound X-Forwarded-For = %q, want single value %q", got, tt.wantXFF)
			}
		})
	}
}

// 场景 2（§5.1）：Via / X-Lite-Gate-Forwarded-For 逐跳逗号追加——
// 无入站原值时输出单值（本跳），有入站原值时保留原值并追加本跳，且各只有一行。
func TestViaAndGateForwardedForAppendPerHop(t *testing.T) {
	tests := []struct {
		name          string
		inboundVia    string
		inboundGateFF string
		wantVia       string
		wantGateFF    string
	}{
		{
			name:       "no inbound values emits single hop entries",
			wantVia:    "1.1 lite-gate",
			wantGateFF: "203.0.113.9:44423",
		},
		{
			name:          "inbound values are preserved and appended",
			inboundVia:    "1.1 upstream-proxy",
			inboundGateFF: "10.1.1.1:5000",
			wantVia:       "1.1 upstream-proxy, 1.1 lite-gate",
			wantGateFF:    "10.1.1.1:5000, 203.0.113.9:44423",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newForwardEchoProxy(t, nil, false, "")

			req := httptest.NewRequest("GET", "http://app.example.com/", nil)
			req.RemoteAddr = "203.0.113.9:44423"
			if tt.inboundVia != "" {
				req.Header.Set("Via", tt.inboundVia)
			}
			if tt.inboundGateFF != "" {
				req.Header.Set("X-Lite-Gate-Forwarded-For", tt.inboundGateFF)
			}

			rec := httptest.NewRecorder()
			p.ServeHTTP(rec, req)

			resp := rec.Result()
			defer resp.Body.Close()

			var echo map[string][]string
			if err := json.NewDecoder(resp.Body).Decode(&echo); err != nil {
				t.Fatalf("decode echo body: %v", err)
			}

			if got := strings.Join(echo["Via"], ", "); got != tt.wantVia {
				t.Errorf("outbound Via = %q, want %q", got, tt.wantVia)
			}
			if len(echo["Via"]) != 1 {
				t.Errorf("outbound Via lines = %d (%v), want exactly 1 (old value must be deleted before rebuild)", len(echo["Via"]), echo["Via"])
			}
			if got := strings.Join(echo["X-Lite-Gate-Forwarded-For"], ", "); got != tt.wantGateFF {
				t.Errorf("outbound X-Lite-Gate-Forwarded-For = %q, want %q", got, tt.wantGateFF)
			}
			if len(echo["X-Lite-Gate-Forwarded-For"]) != 1 {
				t.Errorf("outbound X-Lite-Gate-Forwarded-For lines = %d (%v), want exactly 1", len(echo["X-Lite-Gate-Forwarded-For"]), echo["X-Lite-Gate-Forwarded-For"])
			}
			// 同请求的出站 XFF 恒为单值（直连对端，未信任代理）
			if got := strings.Join(echo["X-Forwarded-For"], ", "); got != "203.0.113.9" {
				t.Errorf("outbound X-Forwarded-For = %q, want 203.0.113.9", got)
			}
		})
	}
}

// 场景（内部PRD §4.1）：X-Real-IP 全链路禁用 —— gate 入站删除、永不生成
// （应用禁读由 litecore RemoteIPHeaders 保证）。客户端伪造值不得透传到后端。
func TestInboundXRealIPStripped(t *testing.T) {
	p := newForwardEchoProxy(t, nil, false, "")

	req := httptest.NewRequest("GET", "http://app.example.com/", nil)
	req.RemoteAddr = "203.0.113.9:44423"
	req.Header.Set("X-Real-IP", "6.6.6.6")
	req.Header.Set("X-Forwarded-For", "6.6.6.6")

	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	var echo map[string][]string
	if err := json.NewDecoder(resp.Body).Decode(&echo); err != nil {
		t.Fatalf("decode echo body: %v", err)
	}
	if _, ok := echo["X-Real-IP"]; ok {
		t.Errorf("X-Real-IP 全链路禁用，伪造值不应透传到后端，got %v", echo["X-Real-IP"])
	}
	// 对照：XFF 被删旧重建为单值（直连对端），伪造链不透传
	if got := strings.Join(echo["X-Forwarded-For"], ", "); got != "203.0.113.9" {
		t.Errorf("outbound X-Forwarded-For = %q, want 203.0.113.9", got)
	}
}

// 场景 3（§5.1 不回归）：strip_proxy_headers=true 的 host 不添加任何转发头，
// 且客户端伪造的转发头仍被无条件删除（不重建）。
func TestStripProxyHeadersRemovesAllForwardedHeaders(t *testing.T) {
	p := newForwardEchoProxy(t, nil, true, "")

	req := httptest.NewRequest("GET", "http://app.example.com/", nil)
	req.RemoteAddr = "203.0.113.9:44423"
	req.Header.Set("X-Forwarded-For", "6.6.6.6")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("Forwarded", "for=6.6.6.6")
	req.Header.Set("Via", "1.1 evil")
	req.Header.Set("X-Real-IP", "6.6.6.6")
	req.Header.Set("X-Lite-Gate-Forwarded-For", "10.9.9.9:1")
	req.Header.Set("X-Lite-Gate-Trace-Id", "spoofed-trace")

	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	var echo map[string][]string
	if err := json.NewDecoder(resp.Body).Decode(&echo); err != nil {
		t.Fatalf("decode echo body: %v", err)
	}
	if len(echo) != 0 {
		t.Errorf("strip_proxy_headers=true should emit no proxy headers, got %v", echo)
	}
}

// --- 内部PRD P0-A：上游 HSTS 一律丢弃（网关权威响应头）---

// hstsUpstreamBody 上游响应体标志：用于证明响应确经代理路径来自上游
// （httptest.ResponseRecorder 默认 Code=200，仅断言状态码无法排除「代理未触达上游」）。
const hstsUpstreamBody = "hsts-upstream-ok"

// newHSTSUpstreamProxy 构造上游会返回 HSTS 的测试代理；hstsValues 逐条 Add 到上游
// 响应，多值用于模拟内层网关/应用各自下发一份 HSTS 的深层链路。
func newHSTSUpstreamProxy(t *testing.T, hstsValues ...string) *Proxy {
	t.Helper()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, v := range hstsValues {
			w.Header().Add("Strict-Transport-Security", v)
		}
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(hstsUpstreamBody))
	}))
	t.Cleanup(backend.Close)

	return NewProxy(
		[]string{backend.URL},
		"/",
		10, 5,
		logger.GetDefaultLogger(),
		nil,
		nil,
		false,
		false,
		"",
		"",
		false,
		false,
		false,
		"",
		defaultWSConfig(),
		UpstreamConfig{},
	)
}

// applyServerHSTS 复刻 server.go 的 HSTS 单点写入（r.TLS != nil 且 per-host 值非空时
// Set），用于验证「server 先 Set、proxy 随后复制上游头」这一真实链路语义——
// proxy 包不能反向 import server（会形成循环依赖），故在 recorder 上模拟该写入点。
func applyServerHSTS(rec *httptest.ResponseRecorder, host *config.HostConfig, tlsReq bool) {
	if !tlsReq {
		return
	}
	if v := host.GetEffectiveHSTS(); v != "" {
		rec.Header().Set("Strict-Transport-Security", v)
	}
}

// assertHSTSValues 用 Values（而非 Get）断言 HSTS 条数与逐条值：Get 只看第一条，
// 测不出「Set 之后又被上游 Add 叠加」的双发缺陷。
func assertHSTSValues(t *testing.T, h http.Header, want ...string) {
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

// assertProxiedToUpstream 断言响应体来自上游：若代理在触达上游之前就返回（如 selectBackend
// 失败走错误页），HSTS 断言会因响应里本就没有上游头而「假通过」，此处显式排除该伪覆盖。
func assertProxiedToUpstream(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if got := rec.Body.String(); got != hstsUpstreamBody {
		t.Fatalf("response body = %q, want %q（须确证响应来自上游，而非代理未触达上游）", got, hstsUpstreamBody)
	}
}

// 用例 1：上游返回 HSTS + host hsts 未配置（nil）→ 客户端恰 1 条且等于默认值。
// 上游故意使用不同值，证明网关单点值不会被上游覆盖，且上游那份未被 Add 叠加。
func TestUpstreamHSTSDroppedDefaultValue(t *testing.T) {
	host := &config.HostConfig{Name: "app.example.com"} // HSTS nil = DefaultHSTSValue
	p := newHSTSUpstreamProxy(t, "max-age=12345; includeSubDomains")

	rec := httptest.NewRecorder()
	applyServerHSTS(rec, host, true)

	req := httptest.NewRequest("GET", "http://app.example.com/", nil)
	req.TLS = &tls.ConnectionState{}
	p.ServeHTTP(rec, req)

	assertProxiedToUpstream(t, rec)
	assertHSTSValues(t, rec.Result().Header, config.DefaultHSTSValue)
}

// 用例 2：上游返回 HSTS + host hsts:"off" → 0 条（该 host 彻底不下发）。
func TestUpstreamHSTSDroppedWhenHostOff(t *testing.T) {
	off := "off"
	host := &config.HostConfig{Name: "off.example.com", HSTS: &off}
	p := newHSTSUpstreamProxy(t, "max-age=12345; includeSubDomains")

	rec := httptest.NewRecorder()
	applyServerHSTS(rec, host, true)

	req := httptest.NewRequest("GET", "http://off.example.com/", nil)
	req.TLS = &tls.ConnectionState{}
	p.ServeHTTP(rec, req)

	assertProxiedToUpstream(t, rec)
	assertHSTSValues(t, rec.Result().Header)
}

// 用例 3：上游返回 HSTS + host hsts 字面值 → 恰 1 条且等于该字面值
// （验证值不被上游覆盖）。
func TestUpstreamHSTSDroppedKeepsHostLiteral(t *testing.T) {
	custom := "max-age=60; includeSubDomains"
	host := &config.HostConfig{Name: "custom.example.com", HSTS: &custom}
	p := newHSTSUpstreamProxy(t, "max-age=999999; preload")

	rec := httptest.NewRecorder()
	applyServerHSTS(rec, host, true)

	req := httptest.NewRequest("GET", "http://custom.example.com/", nil)
	req.TLS = &tls.ConnectionState{}
	p.ServeHTTP(rec, req)

	assertProxiedToUpstream(t, rec)
	assertHSTSValues(t, rec.Result().Header, custom)
}

// 用例 4：明文 HTTP（r.TLS == nil）穿双跳——上游响应本身已叠加两份 HSTS
// （模拟内层网关/应用各发一份），网关单点因 r.TLS == nil 不写入 → 客户端 0 条。
// 覆盖 PRD §4.5-B 的明文泄漏：HSTS 不得因上游透传而出现在明文响应上。
func TestUpstreamHSTSDroppedOnPlaintextDoubleHop(t *testing.T) {
	host := &config.HostConfig{Name: "plain.example.com"} // nil，但明文不下发
	p := newHSTSUpstreamProxy(t,
		"max-age=111; includeSubDomains",
		"max-age=222; includeSubDomains")

	rec := httptest.NewRecorder()
	applyServerHSTS(rec, host, false) // r.TLS == nil：server 单点不写

	req := httptest.NewRequest("GET", "http://plain.example.com/", nil)
	p.ServeHTTP(rec, req)

	assertProxiedToUpstream(t, rec)
	assertHSTSValues(t, rec.Result().Header)
}
