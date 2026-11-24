package server

// 内部PRD §5.2/§5.5：server 层 Trace 链路测试——
//   - 回填后请求头存在、响应头恰好一个（全局不变量，普通/错误/拦截路径逐一断言）；
//   - 两级 httptest 拓扑：外层生成 → 内层采信同一 ID，客户端最终响应恰好 1 个头
//     且 = 外层 ID；两层访问日志与后端收到的请求头同值（A1/A2/A3/A4/A5/A9/A10）。
// 复用 blacklist_test.go 的测试基建（chdirToRepoRoot / newBLBackend / blHost /
// blDoRequestWithReq / record logger 模式）。

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lite-lake/infra-gate/internal/config"
	"github.com/lite-lake/infra-gate/internal/infrastructs/logger"
	"github.com/lite-lake/infra-gate/internal/trace"
)

var w3cTraceIdRe = regexp.MustCompile(`^[0-9a-f]{32}$`)

const (
	chainHostName = "trace-chain.example.com"
	testForgedId  = "forged123"
	testValidTid  = "4bf92f3577b34da6a3ce929d0e0e4736"
)

// traceCaptureLogger 捕获 WithTraceId（访问日志取值）与 Debug 被拒记录的测试 logger
type traceCaptureLogger struct {
	mu           sync.Mutex
	traceIds     []string // 每条访问日志携带的 trace_id
	rejectedVals []string // 被拒入站头值（FormatTraceId 转义后）
}

func (l *traceCaptureLogger) Debug(msg string, fields ...logger.Field) {
	if msg != "Rejected untrusted inbound trace header, regenerating" {
		return
	}
	for _, f := range fields {
		if f.Key == "value" {
			l.mu.Lock()
			l.rejectedVals = append(l.rejectedVals, fmt.Sprint(f.Value))
			l.mu.Unlock()
		}
	}
}
func (l *traceCaptureLogger) Info(msg string, fields ...logger.Field)  {}
func (l *traceCaptureLogger) Warn(msg string, fields ...logger.Field)  {}
func (l *traceCaptureLogger) Error(msg string, fields ...logger.Field) {}
func (l *traceCaptureLogger) Fatal(msg string, fields ...logger.Field) {}
func (l *traceCaptureLogger) WithContext(ctx context.Context) logger.ILogger {
	return l
}
func (l *traceCaptureLogger) WithField(key string, value interface{}) logger.ILogger { return l }
func (l *traceCaptureLogger) WithFields(fields map[string]interface{}) logger.ILogger {
	return l
}
func (l *traceCaptureLogger) WithTraceId(traceId string) logger.ILogger {
	l.mu.Lock()
	l.traceIds = append(l.traceIds, traceId)
	l.mu.Unlock()
	return l
}
func (l *traceCaptureLogger) SetLevel(level logger.LogLevel) {}
func (l *traceCaptureLogger) GetLevel() logger.LogLevel      { return logger.DebugLevel }
func (l *traceCaptureLogger) Close() error                   { return nil }

func (l *traceCaptureLogger) traceIdSnapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.traceIds...)
}

func (l *traceCaptureLogger) rejectedSnapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.rejectedVals...)
}

// countTraceHeaders 数响应中 X-Lite-Gate-Trace-Id 头的行数（恰好一个是不变量）
func countTraceHeaders(h http.Header) int {
	return len(h.Values(trace.TraceIdHeader))
}

// newEchoTraceBackend 回显后端：捕获收到的 X-Lite-Gate-Trace-Id / traceparent
// 请求头（经 channel 送回断言），并可附加自定义响应头（如上游同名头场景）
func newEchoTraceBackend(t *testing.T, extraRespHeaders map[string][]string) (*httptest.Server, <-chan http.Header) {
	t.Helper()
	captured := make(chan http.Header, 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured <- r.Header.Clone()
		for k, vs := range extraRespHeaders {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "backend-ok")
	}))
	t.Cleanup(srv.Close)
	return srv, captured
}

func waitHeaderCapture(t *testing.T, ch <-chan http.Header, what string) http.Header {
	t.Helper()
	select {
	case got := <-ch:
		return got
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
		return nil
	}
}

// --- 单层：回填 + 唯一响应头 + 伪造重生成（A1/A2 单层版）---

func TestSingleGateBackfillAndSingleResponseHeader(t *testing.T) {
	chdirToRepoRoot(t)
	backend, captured := newEchoTraceBackend(t, nil)
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Hosts:  []config.HostConfig{blHost("single.example.com", backend.URL, nil)},
	}
	s := newBLServer(t, cfg)

	req := httptest.NewRequest(http.MethodGet, "http://single.example.com/", nil)
	req.RemoteAddr = "203.0.113.9:41000"
	w := blDoRequestWithReq(s, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	// 响应头恰好一个，值为 W3C 32 位小写 hex（新生成）
	if n := countTraceHeaders(w.Header()); n != 1 {
		t.Fatalf("trace header count = %d (%v), want exactly 1", n, w.Header().Values(trace.TraceIdHeader))
	}
	traceId := w.Header().Get(trace.TraceIdHeader)
	if !w3cTraceIdRe.MatchString(traceId) {
		t.Errorf("trace id = %q, want 32 位小写 hex", traceId)
	}

	// 回填生效：后端收到的请求头 = 响应头同一 ID（D4）
	got := waitHeaderCapture(t, captured, "backend capture")
	if got.Get(trace.TraceIdHeader) != traceId {
		t.Errorf("backend received X-Lite-Gate-Trace-Id = %q, want backfilled %q", got.Get(trace.TraceIdHeader), traceId)
	}
	// 阶段二：traceparent 同步回填且 trace-id 一致（A9 单层版）
	tid, _, _, ok := trace.ParseTraceParent(got.Get(trace.TraceParentHeader))
	if !ok || tid != traceId {
		t.Errorf("backend traceparent = %q (tid=%q ok=%v), want trace-id %q", got.Get(trace.TraceParentHeader), tid, ok, traceId)
	}
}

func TestSingleGateForgedTraceIdRegeneratedAndLogged(t *testing.T) {
	chdirToRepoRoot(t)
	backend, _ := newEchoTraceBackend(t, nil)
	log := &traceCaptureLogger{}
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Hosts:  []config.HostConfig{blHost("single.example.com", backend.URL, nil)},
	}
	s := newBLServerWithLogger(t, cfg, log)

	req := httptest.NewRequest(http.MethodGet, "http://single.example.com/", nil)
	req.RemoteAddr = "203.0.113.9:41000"
	req.Header.Set(trace.TraceIdHeader, testForgedId)
	w := blDoRequestWithReq(s, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	// 公网直连（未配置 trusted_proxies）→ 伪造 ID 无视、重新生成，恰好 1 个头
	if n := countTraceHeaders(w.Header()); n != 1 {
		t.Fatalf("trace header count = %d, want exactly 1", n)
	}
	if got := w.Header().Get(trace.TraceIdHeader); got == testForgedId || !w3cTraceIdRe.MatchString(got) {
		t.Errorf("trace id = %q, want regenerated W3C id (≠ forged %q)", got, testForgedId)
	}

	// D5：被拒值记 Debug 日志（转义）
	rejected := log.rejectedSnapshot()
	if len(rejected) != 1 || rejected[0] != testForgedId {
		t.Errorf("rejected debug logs = %v, want [%q]", rejected, testForgedId)
	}
}

// --- A4：受信直连采信入站 ID（含旧格式兼容窗口与 traceparent 采信）---

func TestTrustedDirectPeerAdoptsInboundTraceId(t *testing.T) {
	chdirToRepoRoot(t)
	backend, _ := newEchoTraceBackend(t, nil)
	log := &traceCaptureLogger{}
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080, TrustedProxies: []string{"127.0.0.1"}},
		Hosts:  []config.HostConfig{blHost("trusted.example.com", backend.URL, nil)},
	}
	s := newBLServerWithLogger(t, cfg, log)

	tests := []struct {
		name    string
		headers map[string]string
		wantId  string
	}{
		{
			name:    "trusted 32hex id adopted",
			headers: map[string]string{trace.TraceIdHeader: testValidTid},
			wantId:  testValidTid,
		},
		{
			name:    "trusted legacy id adopted (compat window)",
			headers: map[string]string{trace.TraceIdHeader: "oldstyle7"},
			wantId:  "oldstyle7",
		},
		{
			name:    "trusted valid traceparent adopted",
			headers: map[string]string{trace.TraceParentHeader: "00-" + testValidTid + "-00f067aa0ba902b7-01"},
			wantId:  testValidTid,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://trusted.example.com/", nil)
			req.RemoteAddr = "127.0.0.1:41000" // ∈ trusted_proxies
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}
			w := blDoRequestWithReq(s, req)
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", w.Code)
			}
			if n := countTraceHeaders(w.Header()); n != 1 {
				t.Fatalf("trace header count = %d, want exactly 1", n)
			}
			if got := w.Header().Get(trace.TraceIdHeader); got != tt.wantId {
				t.Errorf("trace id = %q, want adopted %q", got, tt.wantId)
			}
		})
	}

	// 受信直连带非法 traceparent（A10）：忽略并重新生成
	req := httptest.NewRequest(http.MethodGet, "http://trusted.example.com/", nil)
	req.RemoteAddr = "127.0.0.1:41000"
	req.Header.Set(trace.TraceParentHeader, "zz-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	w := blDoRequestWithReq(s, req)
	if n := countTraceHeaders(w.Header()); n != 1 {
		t.Fatalf("invalid traceparent: header count = %d, want exactly 1", n)
	}
	if got := w.Header().Get(trace.TraceIdHeader); !w3cTraceIdRe.MatchString(got) {
		t.Errorf("invalid traceparent → trace id = %q, want regenerated 32hex", got)
	}
	if rejected := log.rejectedSnapshot(); len(rejected) == 0 {
		t.Error("invalid traceparent from trusted peer should be logged as rejected")
	}
}

// --- A5：上游返回同名响应头，客户端仍恰好 1 个（网关权威值）---

func TestUpstreamSameNameTraceHeadersFiltered(t *testing.T) {
	chdirToRepoRoot(t)
	backend, _ := newEchoTraceBackend(t, map[string][]string{
		trace.TraceIdHeader:     {"upstream-id-1", "upstream-id-2"},
		trace.TraceParentHeader: {"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"},
		trace.TraceStateHeader:  {"vendor@1"},
	})
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Hosts:  []config.HostConfig{blHost("upstream.example.com", backend.URL, nil)},
	}
	s := newBLServer(t, cfg)

	req := httptest.NewRequest(http.MethodGet, "http://upstream.example.com/", nil)
	req.RemoteAddr = "203.0.113.9:41000"
	w := blDoRequestWithReq(s, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if n := countTraceHeaders(w.Header()); n != 1 {
		t.Fatalf("trace header count = %d (%v), want exactly 1 (upstream duplicates filtered)", n, w.Header().Values(trace.TraceIdHeader))
	}
	if got := w.Header().Get(trace.TraceIdHeader); got == "upstream-id-1" || got == "upstream-id-2" || !w3cTraceIdRe.MatchString(got) {
		t.Errorf("trace id = %q, want gateway authoritative value (upstream values dropped)", got)
	}
	if got := w.Header().Get(trace.TraceParentHeader); got != "" {
		t.Errorf("response traceparent = %q, want absent (D7)", got)
	}
	if got := w.Header().Get(trace.TraceStateHeader); got != "" {
		t.Errorf("response tracestate = %q, want absent", got)
	}
}

// --- A6：错误/拦截路径响应头恰好一个，错误页展示同值 ---

func TestErrorPathsSingleTraceHeader(t *testing.T) {
	chdirToRepoRoot(t)

	t.Run("no backend and no text renders system error page", func(t *testing.T) {
		cfg := &config.Config{
			Server: config.ServerConfig{Port: 8080},
			Hosts: []config.HostConfig{{
				Name: "nores.example.com", Port: 8080, HealthCheckEnabled: boolPtr(false),
			}},
		}
		s := newBLServer(t, cfg)
		req := httptest.NewRequest(http.MethodGet, "http://nores.example.com/", nil)
		req.RemoteAddr = "203.0.113.9:41000"
		w := blDoRequestWithReq(s, req)
		if n := countTraceHeaders(w.Header()); n != 1 {
			t.Fatalf("trace header count = %d, want exactly 1", n)
		}
		traceId := w.Header().Get(trace.TraceIdHeader)
		if !strings.Contains(w.Body.String(), traceId) {
			t.Errorf("error page body should display same trace id %q, body: %s", traceId, w.Body.String())
		}
	})

	t.Run("upstream down renders upstream error page", func(t *testing.T) {
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		backendURL := backend.URL
		backend.Close() // 立即停掉：触发连接拒绝 502

		cfg := &config.Config{
			Server: config.ServerConfig{Port: 8080},
			Hosts:  []config.HostConfig{blHost("down.example.com", backendURL, nil)},
		}
		s := newBLServer(t, cfg)
		req := httptest.NewRequest(http.MethodGet, "http://down.example.com/", nil)
		req.RemoteAddr = "203.0.113.9:41000"
		w := blDoRequestWithReq(s, req)
		if w.Code != http.StatusBadGateway && w.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 502/503", w.Code)
		}
		if n := countTraceHeaders(w.Header()); n != 1 {
			t.Fatalf("trace header count = %d, want exactly 1", n)
		}
		traceId := w.Header().Get(trace.TraceIdHeader)
		if !strings.Contains(w.Body.String(), traceId) {
			t.Errorf("upstream error page should display same trace id %q", traceId)
		}
	})

	t.Run("robots_deny_all gateway-rendered response", func(t *testing.T) {
		cfg := &config.Config{
			Server: config.ServerConfig{Port: 8080},
			Hosts: []config.HostConfig{{
				Name: "robots.example.com", Port: 8080,
				HealthCheckEnabled: boolPtr(false),
				RobotsDenyAll:      boolPtr(true),
			}},
		}
		s := newBLServer(t, cfg)
		req := httptest.NewRequest(http.MethodGet, "http://robots.example.com/robots.txt", nil)
		req.RemoteAddr = "203.0.113.9:41000"
		w := blDoRequestWithReq(s, req)
		if n := countTraceHeaders(w.Header()); n != 1 {
			t.Fatalf("trace header count = %d, want exactly 1", n)
		}
	})

	t.Run("static text host", func(t *testing.T) {
		cfg := &config.Config{
			Server: config.ServerConfig{Port: 8080},
			Hosts: []config.HostConfig{{
				Name: "text.example.com", Port: 8080, Text: "hello", HealthCheckEnabled: boolPtr(false),
			}},
		}
		s := newBLServer(t, cfg)
		req := httptest.NewRequest(http.MethodGet, "http://text.example.com/", nil)
		req.RemoteAddr = "203.0.113.9:41000"
		w := blDoRequestWithReq(s, req)
		if n := countTraceHeaders(w.Header()); n != 1 {
			t.Fatalf("trace header count = %d, want exactly 1", n)
		}
	})

	t.Run("no matching host 404", func(t *testing.T) {
		backend, _ := newEchoTraceBackend(t, nil)
		cfg := &config.Config{
			Server: config.ServerConfig{Port: 8080},
			Hosts:  []config.HostConfig{blHost("known.example.com", backend.URL, nil)},
		}
		s := newBLServer(t, cfg)
		req := httptest.NewRequest(http.MethodGet, "http://unknown.example.com/", nil)
		req.RemoteAddr = "203.0.113.9:41000"
		w := blDoRequestWithReq(s, req)
		if w.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", w.Code)
		}
		if n := countTraceHeaders(w.Header()); n != 1 {
			t.Fatalf("trace header count = %d, want exactly 1", n)
		}
	})
}

// --- 两级拓扑集成测试（核心防回归用例，PRD §9 矩阵 A1/A2/A3/A5/A9）---
//
// 客户端(公网伪造头) → outer gate（边缘，trusted=nil）→ inner gate（trusted=127.0.0.1，
// 模拟 mesh 上一跳）→ 回显后端。两级均为完整 NewServer + 真实 gin engine
// （startHTTPServer 绑定 :0 占位 + engines[0] 包进 httptest.Server 暴露），
// 中间件链与生产一致（访问日志 → handleRequestForPort → WAF/代理）。

// startGateOnHttptest 把完整 Server 的 gin engine（生产中间件链）挂到 httptest.Server。
// startHTTPServer 以 port=0 绑定一个随机占位监听（不使用），engines[0] 即为完整链。
func startGateOnHttptest(t *testing.T, s *Server) *httptest.Server {
	t.Helper()
	s.startHTTPServer(0, s.config.Hosts)
	engine, ok := s.engines[0]
	if !ok {
		t.Fatal("engine for port 0 not registered")
	}
	front := httptest.NewServer(engine)
	t.Cleanup(front.Close)
	return front
}

func doRemoteGet(t *testing.T, frontURL, hostName string, headers map[string]string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, frontURL, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Host = hostName
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp
}

func TestTwoTierTopologySingleTraceId(t *testing.T) {
	chdirToRepoRoot(t)

	// 回显后端：捕获收到的 trace 请求头
	backend, backendCaptured := newEchoTraceBackend(t, nil)

	// 内层 gate（模拟 mesh 二级跳）：信任 127.0.0.1（外层 gate 出口）
	innerLog := &traceCaptureLogger{}
	innerCfg := &config.Config{
		Server: config.ServerConfig{Port: 8080, TrustedProxies: []string{"127.0.0.1"}},
		Hosts:  []config.HostConfig{blHost(chainHostName, backend.URL, nil)},
	}
	inner := newBLServerWithLogger(t, innerCfg, innerLog)
	innerFront := startGateOnHttptest(t, inner)

	// 外层 gate（公网边缘）：不信任任何直连
	outerLog := &traceCaptureLogger{}
	outerCfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Hosts: []config.HostConfig{{
			Name: chainHostName, Port: 8080, Backend: []string{innerFront.URL},
			HealthCheckEnabled: boolPtr(false),
			// 外层保留 Host：内层按同一域名命中路由
			PreserveHostHeader: boolPtr(true),
		}},
	}
	outer := newBLServerWithLogger(t, outerCfg, outerLog)
	outerFront := startGateOnHttptest(t, outer)

	// A2：双层 + 客户端伪造 ID
	resp := doRemoteGet(t, outerFront.URL, chainHostName, map[string]string{
		trace.TraceIdHeader: testForgedId,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	// 恰好 1 个头，值为外层新生成的 W3C ID（≠伪造值）
	if n := len(resp.Header.Values(trace.TraceIdHeader)); n != 1 {
		t.Fatalf("client trace header count = %d (%v), want exactly 1", n, resp.Header.Values(trace.TraceIdHeader))
	}
	clientTraceId := resp.Header.Get(trace.TraceIdHeader)
	if clientTraceId == testForgedId || !w3cTraceIdRe.MatchString(clientTraceId) {
		t.Fatalf("client trace id = %q, want regenerated W3C id (≠ %q)", clientTraceId, testForgedId)
	}

	// 内层采信外层回填值：后端收到的请求头 = 响应头（A3 全链路一致）
	backendSeen := waitHeaderCapture(t, backendCaptured, "backend capture")
	if got := backendSeen.Get(trace.TraceIdHeader); got != clientTraceId {
		t.Errorf("backend received trace id = %q, want chain-wide %q", got, clientTraceId)
	}
	// A9：后端收到的 traceparent 合法且 trace-id = X-Lite-Gate-Trace-Id
	tid, pid, _, ok := trace.ParseTraceParent(backendSeen.Get(trace.TraceParentHeader))
	if !ok || tid != clientTraceId {
		t.Errorf("backend traceparent = %q (tid=%q ok=%v), want trace-id %q", backendSeen.Get(trace.TraceParentHeader), tid, ok, clientTraceId)
	}
	if pid == "" || pid == "00f067aa0ba902b7" {
		t.Errorf("backend traceparent parent-id = %q, want fresh per-hop value", pid)
	}

	// A3：两层日志（访问日志与 proxy/处理链 logger 派生）取到的 trace_id 全部相同
	// 且 = 响应头值（WithTraceId 每请求会被访问日志/proxy/processRequest 各调用一次）
	for name, log := range map[string]*traceCaptureLogger{"outer": outerLog, "inner": innerLog} {
		ids := log.traceIdSnapshot()
		if len(ids) == 0 {
			t.Errorf("%s gate has no trace id log records", name)
			continue
		}
		for _, id := range ids {
			if id != clientTraceId {
				t.Errorf("%s gate log trace id = %q, want chain-wide %q (all records)", name, id, clientTraceId)
			}
		}
	}

	// A2：外层 Debug 日志记录被拒伪造值
	if rejected := outerLog.rejectedSnapshot(); len(rejected) != 1 || rejected[0] != testForgedId {
		t.Errorf("outer gate rejected logs = %v, want [%q]", rejected, testForgedId)
	}

	// A1：双层、客户端不带 ID → 恰好 1 个头，且全链路同一 ID
	resp = doRemoteGet(t, outerFront.URL, chainHostName, nil)
	if n := len(resp.Header.Values(trace.TraceIdHeader)); n != 1 {
		t.Fatalf("A1 client trace header count = %d, want exactly 1", n)
	}
	idNoInbound := resp.Header.Get(trace.TraceIdHeader)
	if !w3cTraceIdRe.MatchString(idNoInbound) {
		t.Fatalf("A1 trace id = %q, want W3C format", idNoInbound)
	}
	backendSeen = waitHeaderCapture(t, backendCaptured, "A1 backend capture")
	if got := backendSeen.Get(trace.TraceIdHeader); got != idNoInbound {
		t.Errorf("A1 backend received trace id = %q, want %q", got, idNoInbound)
	}
}

// A4/A9/A10 真实直连版：客户端直连内层 gate（RemoteAddr=127.0.0.1 ∈ trusted_proxies）
func TestTwoTierInnerGateTrustedDirectAdoption(t *testing.T) {
	chdirToRepoRoot(t)

	backend, backendCaptured := newEchoTraceBackend(t, nil)
	innerLog := &traceCaptureLogger{}
	innerCfg := &config.Config{
		Server: config.ServerConfig{Port: 8080, TrustedProxies: []string{"127.0.0.1"}},
		Hosts:  []config.HostConfig{blHost(chainHostName, backend.URL, nil)},
	}
	inner := newBLServerWithLogger(t, innerCfg, innerLog)
	innerFront := startGateOnHttptest(t, inner)

	// A4：受信直连带合法 ID → 采信，响应头 = 入站值
	resp := doRemoteGet(t, innerFront.URL, chainHostName, map[string]string{
		trace.TraceIdHeader: testValidTid,
	})
	if n := len(resp.Header.Values(trace.TraceIdHeader)); n != 1 {
		t.Fatalf("A4 trace header count = %d, want exactly 1", n)
	}
	if got := resp.Header.Get(trace.TraceIdHeader); got != testValidTid {
		t.Errorf("A4 trace id = %q, want adopted %q", got, testValidTid)
	}

	// A9：受信直连带合法 traceparent（无 X-Lite 头）→ 采信其 trace-id，
	// 后端收到的 traceparent trace-id 相同、parent-id 每跳新生成
	inboundTP := "00-" + testValidTid + "-00f067aa0ba902b7-01"
	resp = doRemoteGet(t, innerFront.URL, chainHostName, map[string]string{
		trace.TraceParentHeader: inboundTP,
	})
	if n := len(resp.Header.Values(trace.TraceIdHeader)); n != 1 {
		t.Fatalf("A9 trace header count = %d, want exactly 1", n)
	}
	if got := resp.Header.Get(trace.TraceIdHeader); got != testValidTid {
		t.Fatalf("A9 trace id = %q, want adopted from traceparent %q", got, testValidTid)
	}
	backendSeen := waitHeaderCapture(t, backendCaptured, "A9 backend capture")
	tid, pid, _, ok := trace.ParseTraceParent(backendSeen.Get(trace.TraceParentHeader))
	if !ok || tid != testValidTid || pid == "00f067aa0ba902b7" {
		t.Errorf("A9 backend traceparent tid=%q pid=%q ok=%v, want tid=%q fresh pid", tid, pid, ok, testValidTid)
	}

	// A10：受信直连带全零 traceparent → 忽略并重新生成
	resp = doRemoteGet(t, innerFront.URL, chainHostName, map[string]string{
		trace.TraceParentHeader: "00-" + strings.Repeat("0", 32) + "-" + strings.Repeat("0", 16) + "-01",
	})
	if n := len(resp.Header.Values(trace.TraceIdHeader)); n != 1 {
		t.Fatalf("A10 trace header count = %d, want exactly 1", n)
	}
	if got := resp.Header.Get(trace.TraceIdHeader); got == strings.Repeat("0", 32) || !w3cTraceIdRe.MatchString(got) {
		t.Errorf("A10 trace id = %q, want regenerated", got)
	}
}
