package trace

// 内部PRD §5.5：trace 包单测——生成格式（W3C 32 位小写 hex）、
// ParseTraceParent 合法/非法用例、BuildTraceParent 每跳新 parent-id、
// ResolveTraceId 信任判定三分支（受信采信 / 不受信重生成 / 未配置重生成）、
// traceparent 优先于旧头、被拒值 Debug 日志（FormatTraceId 转义）。

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/lite-lake/infra-gate/internal/infrastructs/logger"
)

// captureLogger 捕获 Debug 被拒记录与 WithTraceId 调用的测试 logger
type captureLogger struct {
	mu           sync.Mutex
	rejectedVals []string // 被拒入站头值（已经 FormatTraceId 转义）
	traceIds     []string // WithTraceId 调用记录
}

func (l *captureLogger) appendRejected(v string) {
	l.mu.Lock()
	l.rejectedVals = append(l.rejectedVals, v)
	l.mu.Unlock()
}

func (l *captureLogger) Debug(msg string, fields ...logger.Field) {
	if msg != "Rejected untrusted inbound trace header, regenerating" {
		return
	}
	for _, f := range fields {
		if f.Key == "value" {
			l.appendRejected(fmt.Sprint(f.Value))
		}
	}
}
func (l *captureLogger) Info(msg string, fields ...logger.Field)  {}
func (l *captureLogger) Warn(msg string, fields ...logger.Field)  {}
func (l *captureLogger) Error(msg string, fields ...logger.Field) {}
func (l *captureLogger) Fatal(msg string, fields ...logger.Field) {}
func (l *captureLogger) WithContext(ctx context.Context) logger.ILogger {
	return l
}
func (l *captureLogger) WithField(key string, value interface{}) logger.ILogger { return l }
func (l *captureLogger) WithFields(fields map[string]interface{}) logger.ILogger {
	return l
}
func (l *captureLogger) WithTraceId(traceId string) logger.ILogger {
	l.mu.Lock()
	l.traceIds = append(l.traceIds, traceId)
	l.mu.Unlock()
	return l
}
func (l *captureLogger) SetLevel(level logger.LogLevel) {}
func (l *captureLogger) GetLevel() logger.LogLevel      { return logger.DebugLevel }
func (l *captureLogger) Close() error                   { return nil }

func (l *captureLogger) rejectedSnapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.rejectedVals...)
}

var (
	w3cTraceIdRe = regexp.MustCompile(`^[0-9a-f]{32}$`)
	testValidTP  = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
)

// newTraceRequest 构造指定 RemoteAddr 与头的测试请求
func newTraceRequest(remoteAddr string, headers map[string]string) *http.Request {
	req := httptest.NewRequest("GET", "http://trace.example.com/", nil)
	req.RemoteAddr = remoteAddr
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req
}

// --- 生成格式（阶段二）---

func TestGenerateTraceIdFormat(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 200; i++ {
		id := GenerateTraceId()
		if !w3cTraceIdRe.MatchString(id) {
			t.Fatalf("GenerateTraceId() = %q, want 32 位小写 hex", id)
		}
		if isAllZeroHex(id) {
			t.Fatalf("GenerateTraceId() = %q, 全零非法（W3C）", id)
		}
		if seen[id] {
			t.Fatalf("GenerateTraceId() 重复输出 %q", id)
		}
		seen[id] = true
	}
}

// --- ParseTraceParent ---

func TestParseTraceParent(t *testing.T) {
	valid := "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	tests := []struct {
		name    string
		tp      string
		wantOK  bool
		wantTid string
	}{
		{"valid", valid, true, "4bf92f3577b34da6a3ce929d0e0e4736"},
		{"flags 00", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00", true, "4bf92f3577b34da6a3ce929d0e0e4736"},
		{"version ff forbidden", "ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01", false, ""},
		{"version 01 rejected (strict 00)", "01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01", false, ""},
		{"too short", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-0", false, ""},
		{"too long", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-011", false, ""},
		{"empty", "", false, ""},
		{"non hex trace-id", "00-4bf92f3577b34da6a3ce929d0e0e47zz-00f067aa0ba902b7-01", false, ""},
		{"non hex flags", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-zz", false, ""},
		{"all zero trace-id", "00-00000000000000000000000000000000-00f067aa0ba902b7-01", false, ""},
		{"all zero parent-id", "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01", false, ""},
		{"uppercase rejected", "00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01", false, ""},
		{"dash replaced", "00x4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01", false, ""},
		{"extra dash segment", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-0-1", false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tid, pid, flags, ok := ParseTraceParent(tt.tp)
			if ok != tt.wantOK {
				t.Fatalf("ParseTraceParent(%q) ok = %v, want %v", tt.tp, ok, tt.wantOK)
			}
			if !tt.wantOK {
				return
			}
			if tid != tt.wantTid {
				t.Errorf("trace-id = %q, want %q", tid, tt.wantTid)
			}
			if pid != "00f067aa0ba902b7" {
				t.Errorf("parent-id = %q, want 00f067aa0ba902b7", pid)
			}
			if len(flags) != 2 {
				t.Errorf("flags = %q, want 2 chars", flags)
			}
		})
	}
}

// --- BuildTraceParent ---

func TestBuildTraceParent(t *testing.T) {
	tid := "4bf92f3577b34da6a3ce929d0e0e4736"

	// 默认 flags 01 + 每跳新 parent-id（非全零、16 位小写 hex）
	tp := BuildTraceParent(tid, "")
	gotTid, gotPid, gotFlags, ok := ParseTraceParent(tp)
	if !ok {
		t.Fatalf("BuildTraceParent(%q, \"\") = %q, want valid traceparent", tid, tp)
	}
	if gotTid != tid {
		t.Errorf("trace-id = %q, want %q", gotTid, tid)
	}
	if gotFlags != defaultTraceFlags {
		t.Errorf("flags = %q, want default %q", gotFlags, defaultTraceFlags)
	}
	if len(gotPid) != parentIdHexLen || !isLowerHex(gotPid) || isAllZeroHex(gotPid) {
		t.Errorf("parent-id = %q, want 16 位非全零小写 hex", gotPid)
	}

	// 两次构建 parent-id 必须不同（每跳新生成）
	tp2 := BuildTraceParent(tid, "")
	if tp2 == tp {
		t.Errorf("两次 BuildTraceParent 输出相同 %q，parent-id 应每跳新生成", tp)
	}

	// flags 继承
	if _, _, f, ok := ParseTraceParent(BuildTraceParent(tid, "00")); !ok || f != "00" {
		t.Errorf("inherited flags = %q (ok=%v), want 00", f, ok)
	}

	// 非法 flags 回落默认 01
	for _, bad := range []string{"zz", "000", "0", "FF"} {
		if _, _, f, ok := ParseTraceParent(BuildTraceParent(tid, bad)); !ok || f != defaultTraceFlags {
			t.Errorf("invalid inherited flags %q → %q (ok=%v), want default %q", bad, f, ok, defaultTraceFlags)
		}
	}

	// 旧格式 ID 无法构建 W3C 头：返回空串，调用方跳过（链路由 X-Lite-Gate-Trace-Id 维持）
	if got := BuildTraceParent("oldstyle8", ""); got != "" {
		t.Errorf("BuildTraceParent(legacy id) = %q, want empty", got)
	}
	if got := BuildTraceParent(strings.Repeat("0", 32), ""); got != "" {
		t.Errorf("BuildTraceParent(all-zero id) = %q, want empty", got)
	}
}

// --- ResolveTraceId / ResolveTraceContext：受信采信分支 ---

func TestResolveTraceContextTrustedAdoption(t *testing.T) {
	trusted := mustCIDR(t, "10.71.0.0/24")
	nets := []*net.IPNet{trusted}
	peer := "10.71.0.5:41000"

	t.Run("valid traceparent adopted with inherited flags", func(t *testing.T) {
		log := &captureLogger{}
		tid, flags, reused := ResolveTraceContext(newTraceRequest(peer, map[string]string{
			TraceParentHeader: testValidTP,
		}), nets, log)
		if !reused || tid != "4bf92f3577b34da6a3ce929d0e0e4736" || flags != "01" {
			t.Errorf("got (%q, %q, %v), want adopted trace-id/flags from traceparent", tid, flags, reused)
		}
	})

	t.Run("legacy header adopted (compat window)", func(t *testing.T) {
		tid, _, reused := ResolveTraceContext(newTraceRequest(peer, map[string]string{
			TraceIdHeader: "legacyid01",
		}), nets, &captureLogger{})
		if !reused || tid != "legacyid01" {
			t.Errorf("got (%q, %v), want legacy id adopted", tid, reused)
		}
	})

	t.Run("32hex header adopted", func(t *testing.T) {
		want := "4bf92f3577b34da6a3ce929d0e0e4736"
		tid, _, reused := ResolveTraceContext(newTraceRequest(peer, map[string]string{
			TraceIdHeader: want,
		}), nets, &captureLogger{})
		if !reused || tid != want {
			t.Errorf("got (%q, %v), want %q adopted", tid, reused, want)
		}
	})

	t.Run("traceparent wins over legacy header", func(t *testing.T) {
		tid, _, reused := ResolveTraceContext(newTraceRequest(peer, map[string]string{
			TraceParentHeader: testValidTP,
			TraceIdHeader:     "different01",
		}), nets, &captureLogger{})
		if !reused || tid != "4bf92f3577b34da6a3ce929d0e0e4736" {
			t.Errorf("got (%q, %v), want traceparent trace-id wins", tid, reused)
		}
	})

	t.Run("invalid traceparent falls back to valid legacy header with debug log", func(t *testing.T) {
		log := &captureLogger{}
		tid, _, reused := ResolveTraceContext(newTraceRequest(peer, map[string]string{
			TraceParentHeader: "zz-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
			TraceIdHeader:     "legacyid01",
		}), nets, log)
		if !reused || tid != "legacyid01" {
			t.Errorf("got (%q, %v), want legacy header adopted after invalid traceparent", tid, reused)
		}
		if got := log.rejectedSnapshot(); len(got) != 1 {
			t.Errorf("rejected debug logs = %v, want exactly 1 (invalid traceparent)", got)
		}
	})

	t.Run("no headers regenerates", func(t *testing.T) {
		tid, flags, reused := ResolveTraceContext(newTraceRequest(peer, nil), nets, &captureLogger{})
		if reused || !w3cTraceIdRe.MatchString(tid) || flags != defaultTraceFlags {
			t.Errorf("got (%q, %q, %v), want fresh W3C id, flags 01, reused=false", tid, flags, reused)
		}
	})

	t.Run("all-zero 32hex header rejected", func(t *testing.T) {
		log := &captureLogger{}
		tid, _, reused := ResolveTraceContext(newTraceRequest(peer, map[string]string{
			TraceIdHeader: strings.Repeat("0", 32),
		}), nets, log)
		if reused || !w3cTraceIdRe.MatchString(tid) {
			t.Errorf("got (%q, %v), want regenerated on all-zero id", tid, reused)
		}
		if got := log.rejectedSnapshot(); len(got) != 1 || got[0] != strings.Repeat("0", 32) {
			t.Errorf("rejected debug logs = %v, want [all-zero id]", got)
		}
	})
}

// --- ResolveTraceId / ResolveTraceContext：边缘语义（不受信 / 未配置）---

func TestResolveTraceContextEdgeSemantics(t *testing.T) {
	t.Run("no trusted_proxies ignores valid inbound headers (fail-safe)", func(t *testing.T) {
		log := &captureLogger{}
		tid, _, reused := ResolveTraceContext(newTraceRequest("203.0.113.9:41000", map[string]string{
			TraceIdHeader:     "forged123",
			TraceParentHeader: testValidTP,
		}), nil, log)
		if reused || !w3cTraceIdRe.MatchString(tid) || tid == "forged123" {
			t.Errorf("got (%q, %v), want regenerated W3C id", tid, reused)
		}
		if got := log.rejectedSnapshot(); len(got) != 2 {
			t.Errorf("rejected debug logs = %v, want 2 (both inbound headers)", got)
		}
	})

	t.Run("untrusted direct peer ignores inbound headers", func(t *testing.T) {
		nets := []*net.IPNet{mustCIDR(t, "10.71.0.0/24")}
		tid, _, reused := ResolveTraceContext(newTraceRequest("203.0.113.9:41000", map[string]string{
			TraceIdHeader: "forged123",
		}), nets, &captureLogger{})
		if reused || tid == "forged123" || !w3cTraceIdRe.MatchString(tid) {
			t.Errorf("got (%q, %v), want regenerated", tid, reused)
		}
	})

	t.Run("trusted peer with no headers regenerates without rejected logs", func(t *testing.T) {
		log := &captureLogger{}
		nets := []*net.IPNet{mustCIDR(t, "10.71.0.0/24")}
		_, _, reused := ResolveTraceContext(newTraceRequest("10.71.0.5:41000", nil), nets, log)
		if reused {
			t.Error("reused = true, want false (nothing to adopt)")
		}
		if got := log.rejectedSnapshot(); len(got) != 0 {
			t.Errorf("rejected debug logs = %v, want none", got)
		}
	})
}

// --- D5：被拒值经 FormatTraceId 转义（超长截断，防日志注入回归）---

func TestRejectedValueEscapedViaFormatTraceId(t *testing.T) {
	log := &captureLogger{}
	long := strings.Repeat("x", 100) + "\nEVIL"
	ResolveTraceContext(newTraceRequest("203.0.113.9:41000", map[string]string{
		TraceIdHeader: long,
	}), nil, log)

	got := log.rejectedSnapshot()
	if len(got) != 1 {
		t.Fatalf("rejected debug logs = %d, want 1", len(got))
	}
	if !strings.HasSuffix(got[0], "...[truncated]") {
		t.Errorf("escaped value = %q, want FormatTraceId truncation suffix", got[0])
	}
	if strings.Contains(got[0], "\n") {
		t.Errorf("escaped value contains raw newline: %q", got[0])
	}
}

// --- 兼容采信校验细节 ---

func TestIsValidTraceIdValue(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{"legacy 8 chars", "Ab3xY9zZ", true},
		{"32 lowercase hex", "4bf92f3577b34da6a3ce929d0e0e4736", true},
		{"max legacy length 64", strings.Repeat("a", 64), true},
		{"too long 65", strings.Repeat("a", 65), false},
		{"all zero 32hex", strings.Repeat("0", 32), false},
		{"illegal chars", "abc-def", false},
		{"empty", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isValidTraceIdValue(tt.value); got != tt.want {
				t.Errorf("isValidTraceIdValue(%q) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}

func mustCIDR(t *testing.T, cidr string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("ParseCIDR(%q): %v", cidr, err)
	}
	return n
}
