package waf

// F2.4（内部PRD §4.2.4 决策 D4）：WAF 白名单改直连对端口径——
// 白名单命中需直连对端（TCP RemoteAddr）在名单中；伪造 XFF 使「解析后 IP」
// 落在名单内不能绕过 WAF。

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lite-lake/infra-gate/internal/config"
)

// newDirectPeerMiddleware 构造启用白名单的 Middleware（WAF 实例仅在白名单
// 未命中时被使用，故传 nil coraza.WAF：命中路径在 WrapHandler 之前返回）
func newDirectPeerMiddleware(t *testing.T, ipRanges []string) *Middleware {
	t.Helper()
	wcfg := config.WAFConfig{
		Enabled:     true,
		DefaultMode: config.WAFModeBlock,
		Whitelist:   config.WAFWhitelistConfig{Enabled: true, IPRanges: ipRanges},
	}
	return NewMiddleware(nil, CreateFromConfig(wcfg, newMockLogger()), true, config.WAFModeBlock, newMockLogger(), nil, nil, newStatsTracker())
}

// TestWhitelistDirectPeerBypasses 直连对端在名单 → 跳过 WAF（nil WAF 实例
// 不被触碰，handler 直达）。
func TestWhitelistDirectPeerBypasses(t *testing.T) {
	m := newDirectPeerMiddleware(t, []string{"203.0.113.9"})
	called := false
	h := m.WrapHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}), "direct.example.com")

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.RemoteAddr = "203.0.113.9:40000"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if !called || w.Code != http.StatusOK {
		t.Errorf("direct-peer whitelisted request should bypass WAF: called=%v code=%d", called, w.Code)
	}
}

// TestWhitelistForgedXFFNotBypassed 伪造 XFF 使解析后 IP 落在名单内：不命中
// （直连对端 198.51.100.7 不在名单）→ 进入 WAF 检查路径。判定信号：
// 白名单绕过不计数（recordRequest），未绕过则 TotalRequests 增加（nil WAF
// 实例经 coraza 直通属测试构造，不影响计数断言）。
func TestWhitelistForgedXFFNotBypassed(t *testing.T) {
	m := newDirectPeerMiddleware(t, []string{"203.0.113.9"})
	h := m.WrapHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), "direct.example.com")

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.RemoteAddr = "198.51.100.7:40000"
	req.Header.Set("X-Forwarded-For", "203.0.113.9") // 解析后 IP 恰在名单内
	w := httptest.NewRecorder()

	before := m.GetStats().TotalRequests
	h.ServeHTTP(w, req)
	after := m.GetStats().TotalRequests
	if after <= before {
		t.Error("forged XFF matching whitelist must NOT bypass WAF (request should be counted as WAF-inspected)")
	}

	// 对照：直连在名单 → 绕过（不计数）
	req2 := httptest.NewRequest(http.MethodGet, "/x", nil)
	req2.RemoteAddr = "203.0.113.9:40000"
	before = m.GetStats().TotalRequests
	h.ServeHTTP(httptest.NewRecorder(), req2)
	after = m.GetStats().TotalRequests
	if after != before {
		t.Error("direct-peer whitelisted request should bypass WAF and not be counted")
	}
}
