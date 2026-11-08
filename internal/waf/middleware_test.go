package waf

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lite-lake/infra-gate/internal/config"
	"github.com/lite-lake/infra-gate/internal/infrastructs/logger"
	"github.com/lite-lake/infra-gate/internal/netutil"
)

// mockLogger 实现logger.ILogger接口用于测试
type mockLogger struct{}

func (m *mockLogger) Debug(msg string, fields ...logger.Field) {}
func (m *mockLogger) Info(msg string, fields ...logger.Field)  {}
func (m *mockLogger) Warn(msg string, fields ...logger.Field)  {}
func (m *mockLogger) Error(msg string, fields ...logger.Field) {}
func (m *mockLogger) Fatal(msg string, fields ...logger.Field) {}
func (m *mockLogger) WithContext(ctx context.Context) logger.ILogger {
	return m
}
func (m *mockLogger) WithField(key string, value interface{}) logger.ILogger {
	return m
}
func (m *mockLogger) WithFields(fields map[string]interface{}) logger.ILogger {
	return m
}
func (m *mockLogger) WithTraceId(traceId string) logger.ILogger { return m }
func (m *mockLogger) SetLevel(level logger.LogLevel)            {}
func (m *mockLogger) GetLevel() logger.LogLevel                 { return logger.DebugLevel }
func (m *mockLogger) Close() error                              { return nil }

func newMockLogger() *mockLogger { return &mockLogger{} }

func TestCheckerIsWhitelisted(t *testing.T) {
	checker := NewChecker([]string{
		"192.168.1.100",
		"10.0.0.0/8",
		"::1",
		"2001:db8::/32",
	}, newMockLogger())

	tests := []struct {
		name     string
		clientIP string
		expected bool
	}{
		{"IPv4 exact match", "192.168.1.100", true},
		{"IPv4 no match", "192.168.1.101", false},
		{"IPv4 CIDR match", "10.1.2.3", true},
		{"IPv4 CIDR no match", "11.0.0.1", false},
		{"IPv6 exact match", "::1", true},
		{"IPv6 CIDR match", "2001:db8::1", true},
		{"IPv6 CIDR no match", "2001:db9::1", false},
		{"invalid IP", "not-an-ip", false},
		{"CIDR boundary: network address", "10.0.0.0", true},
		{"CIDR boundary: broadcast address", "10.255.255.255", true},
		{"CIDR boundary: first IP outside", "11.0.0.0", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := checker.IsWhitelisted(tt.clientIP)
			if result != tt.expected {
				t.Errorf("IsWhitelisted(%q) = %v, want %v", tt.clientIP, result, tt.expected)
			}
		})
	}
}

func TestCheckerEmptyWhitelist(t *testing.T) {
	checker := NewChecker([]string{}, newMockLogger())
	if checker.IsWhitelisted("10.0.0.1") {
		t.Error("Empty whitelist should not match any IP")
	}
}

func TestCheckerInvalidEntriesSkipped(t *testing.T) {
	checker := NewChecker([]string{"invalid-cidr", "not-an-ip", "10.0.0.0/8"}, newMockLogger())
	if !checker.IsWhitelisted("10.0.0.1") {
		t.Error("Valid CIDR should still work after invalid entries")
	}
	if checker.IsWhitelisted("192.168.1.1") {
		t.Error("Non-matching IP should not be whitelisted")
	}
}

func TestCreateFromConfigDisabled(t *testing.T) {
	cfg := config.WAFConfig{
		Whitelist: config.WAFWhitelistConfig{
			Enabled: false,
		},
	}
	checker := CreateFromConfig(cfg, newMockLogger())
	if checker.IsWhitelisted("127.0.0.1") {
		t.Error("Disabled whitelist should not match any IP")
	}
}

func TestCreateFromConfigEnabledNoRanges(t *testing.T) {
	cfg := config.WAFConfig{
		Whitelist: config.WAFWhitelistConfig{
			Enabled:  true,
			IPRanges: []string{},
		},
	}
	checker := CreateFromConfig(cfg, newMockLogger())
	if checker.IsWhitelisted("127.0.0.1") {
		t.Error("Empty whitelist should not match any IP")
	}
}

func TestIntercept403WriterWriteHeader403(t *testing.T) {
	rec := httptest.NewRecorder()
	reqMatch := &requestRuleMatch{matched: true, details: []RuleMatchDetail{{Message: "test rule"}}}
	w := &intercept403Writer{
		ResponseWriter: rec,
		traceId:        "test-trace-id",
		logger:         newMockLogger(),
		clientIP:       "10.0.0.1",
		path:           "/admin",
		method:         "GET",
		reqMatch:       reqMatch,
	}

	w.WriteHeader(http.StatusForbidden)

	if !w.wrote403 {
		t.Error("wrote403 should be true after WriteHeader(403) with WAF match")
	}
	if rec.Header().Get("X-Lite-Gate-Trace-Id") != "test-trace-id" {
		t.Error("TraceId should be set in response header")
	}
}

func TestIntercept403WriterBackend403Passthrough(t *testing.T) {
	rec := httptest.NewRecorder()
	// reqMatch.matched = false 模拟后端自行返回的 403（非 WAF 拦截）
	reqMatch := &requestRuleMatch{matched: false}
	w := &intercept403Writer{
		ResponseWriter: rec,
		traceId:        "test-trace-id",
		logger:         newMockLogger(),
		clientIP:       "10.0.0.1",
		path:           "/admin",
		method:         "GET",
		reqMatch:       reqMatch,
	}

	w.WriteHeader(http.StatusForbidden)

	if w.wrote403 {
		t.Error("wrote403 should be false for backend 403 (non-WAF)")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("Response code should be 403, got %d", rec.Code)
	}
	if rec.Header().Get("X-Lite-Gate-Trace-Id") != "" {
		t.Error("TraceId header should not be set for backend 403")
	}
}

func TestIntercept403WriterWriteHeader403NotRepeated(t *testing.T) {
	rec := httptest.NewRecorder()
	reqMatch := &requestRuleMatch{matched: true, details: []RuleMatchDetail{{Message: "test"}}}
	w := &intercept403Writer{
		ResponseWriter: rec,
		logger:         newMockLogger(),
		reqMatch:       reqMatch,
	}

	w.WriteHeader(http.StatusForbidden)
	w.WriteHeader(http.StatusForbidden)

	if rec.Code != http.StatusForbidden {
		t.Errorf("Response code should be 403, got %d", rec.Code)
	}
}

func TestIntercept403WriterWriteHeader200Passthrough(t *testing.T) {
	rec := httptest.NewRecorder()
	w := &intercept403Writer{
		ResponseWriter: rec,
		logger:         newMockLogger(),
	}

	w.WriteHeader(http.StatusOK)

	if w.wrote403 {
		t.Error("wrote403 should be false for status 200")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("Response code should be 200, got %d", rec.Code)
	}
}

func TestIntercept403WriterWriteHeader500Passthrough(t *testing.T) {
	rec := httptest.NewRecorder()
	w := &intercept403Writer{
		ResponseWriter: rec,
		logger:         newMockLogger(),
	}

	w.WriteHeader(http.StatusInternalServerError)

	if w.wrote403 {
		t.Error("wrote403 should be false for status 500")
	}
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("Response code should be 500, got %d", rec.Code)
	}
}

func TestIntercept403WriterHijack(t *testing.T) {
	rec := httptest.NewRecorder()
	w := &intercept403Writer{
		ResponseWriter: rec,
		logger:         newMockLogger(),
	}

	// httptest.ResponseRecorder doesn't implement Hijacker
	_, _, err := w.Hijack()
	if err == nil {
		t.Error("Hijack should fail when underlying writer doesn't support it")
	}
}

func TestIntercept403WriterFlush(t *testing.T) {
	rec := httptest.NewRecorder()
	w := &intercept403Writer{
		ResponseWriter: rec,
		logger:         newMockLogger(),
	}

	// Should not panic
	w.Flush()
}

func TestGetClientIP(t *testing.T) {
	trustedProxies := netutil.ParseTrustedProxies([]string{"10.0.0.0/8"})
	m := &Middleware{
		trustedProxies: trustedProxies,
		logger:         newMockLogger(),
	}

	tests := []struct {
		name       string
		remoteAddr string
		xff        string
		expected   string
	}{
		{"direct, no XFF", "192.168.1.1:1234", "", "192.168.1.1"},
		{"trusted proxy, XFF", "10.0.0.1:1234", "203.0.113.5", "203.0.113.5"},
		{"non-trusted, XFF ignored", "192.168.1.1:1234", "127.0.0.1", "192.168.1.1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{
				RemoteAddr: tt.remoteAddr,
				Header:     make(http.Header),
			}
			if tt.xff != "" {
				req.Header.Set("X-Forwarded-For", tt.xff)
			}

			result := m.getClientIP(req)
			if result != tt.expected {
				t.Errorf("getClientIP() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestGetClientIPNoTrustedProxies(t *testing.T) {
	m := &Middleware{
		trustedProxies: nil,
		logger:         newMockLogger(),
	}

	req := &http.Request{
		RemoteAddr: "192.168.1.1:1234",
		Header:     make(http.Header),
	}
	req.Header.Set("X-Forwarded-For", "127.0.0.1")

	result := m.getClientIP(req)
	if result != "192.168.1.1" {
		t.Errorf("getClientIP() = %q, want %q (should ignore XFF with no trusted proxies)", result, "192.168.1.1")
	}
}

// 验证 intercept403Writer 实现了 http.Hijacker 接口
func TestIntercept403WriterImplementsHijacker(t *testing.T) {
	rec := httptest.NewRecorder()
	w := &intercept403Writer{
		ResponseWriter: rec,
		logger:         newMockLogger(),
	}

	var _ http.Hijacker = w
}

// 验证 intercept403Writer 实现了 http.Flusher 接口
func TestIntercept403WriterImplementsFlusher(t *testing.T) {
	rec := httptest.NewRecorder()
	w := &intercept403Writer{
		ResponseWriter: rec,
		logger:         newMockLogger(),
	}

	var _ http.Flusher = w
}

// 确保 net.IPNet 类型在测试中被引用（避免 import 报错）
var _ = net.IPNet{}

func TestNewMiddlewareWithMode(t *testing.T) {
	mw := NewMiddleware(nil, nil, true, "detect", newMockLogger(), nil, nil, nil)
	if mw.mode != "detect" {
		t.Errorf("mode = %q, want %q", mw.mode, "detect")
	}
	if !mw.wafEnabled {
		t.Error("wafEnabled should be true")
	}
}

func TestNewMiddlewareWithBlockMode(t *testing.T) {
	mw := NewMiddleware(nil, nil, true, "block", newMockLogger(), nil, nil, nil)
	if mw.mode != "block" {
		t.Errorf("mode = %q, want %q", mw.mode, "block")
	}
}

func TestNewMiddlewareWithDisabledMode(t *testing.T) {
	mw := NewMiddleware(nil, nil, true, "disabled", newMockLogger(), nil, nil, nil)
	if mw.mode != "disabled" {
		t.Errorf("mode = %q, want %q", mw.mode, "disabled")
	}
}
