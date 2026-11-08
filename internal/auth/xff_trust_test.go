package auth

// F2 XFF 信任簇测试（内部PRD §4.2/§11 F2）：
//   - 锁定条目不可被容量淘汰驱逐（伪 IP 轮换无法挤出锁定状态）；
//   - 直连对端维度：trusted_proxies 内伪 XFF 轮换爆破在 peer 阈值后被锁定；
//   - 登录端点全局预算：超突发后 429 + Retry-After，负值配置关闭；
//   - 成功登录双维度计数清零。

import (
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/lite-lake/infra-gate/internal/config"
	"github.com/lite-lake/infra-gate/internal/netutil"
)

// F2.1 锁定条目不可淘汰：已随 ratelimit.go 迁移至 internal/faillock 包
//（faillock_test.go TestLimiterLockedEntryNotEvicted，包内测试直接操作内部字段）

// newPeerTestManager 构造带可信代理网段的 Manager（F2.2 用）：
// 直连对端 10.0.0.1 ∈ trusted_proxies，XFF 解析生效（resolved ≠ direct）。
func newPeerTestManager(t *testing.T, cfg *config.HostAuthConfig) *Manager {
	t.Helper()
	nets := netutil.ParseTrustedProxies([]string{"10.0.0.0/8"})
	return NewManager(testHost, cfg, nets, &authTestLogger{})
}

// peerLoginRequest 构造经可信代理直连 + 伪造 XFF 的登录请求
func peerLoginRequest(xffIP string) *http.Request {
	form := url.Values{"password": {"wrong"}}
	req := newLoginRequest(http.MethodPost, AuthLoginPath, form, false)
	req.RemoteAddr = "10.0.0.1:40000"
	req.Header.Set("X-Forwarded-For", xffIP)
	return req
}

// TestPeerDimensionLocksForgedXFFRotation F2.2：解析后 IP 轮换（每个伪 XFF 只
// 失败一次，解析后维度永不触发）时，直连对端维度按 peer 阈值锁定。
func TestPeerDimensionLocksForgedXFFRotation(t *testing.T) {
	cfg := &config.HostAuthConfig{
		Password:        testPassword,
		MaxFailures:     100, // 解析后维度阈值调高：本用例只考察 peer 维度
		PeerMaxFailures: 3,
	}
	m := newPeerTestManager(t, cfg)

	// 3 次轮换失败（每次不同 XFF）：解析后维度各只计 1 次，不锁定
	for i := 0; i < 3; i++ {
		w := doEval(m, peerLoginRequest("198.51.100."+strconv.Itoa(i)))
		if w.Code != http.StatusSeeOther {
			t.Fatalf("failure #%d status = %d, want 303", i+1, w.Code)
		}
		if !strings.Contains(w.Header().Get("Location"), errorParamWrongPassword) {
			t.Fatalf("failure #%d should be wrong-password redirect, got %q", i+1, w.Header().Get("Location"))
		}
	}
	// 第 4 次：peer 维度（3 次阈值）已锁定 → 303 error=rate
	w := doEval(m, peerLoginRequest("198.51.100.99"))
	if w.Code != http.StatusSeeOther || !strings.Contains(w.Header().Get("Location"), errorParamRateLimited) {
		t.Fatalf("post-peer-lock status = %d loc = %q, want 303 rate", w.Code, w.Header().Get("Location"))
	}
}

// TestPeerDimensionNotCountedWithoutXFF F2.2 边界：直连不受信（无 XFF 解析）时
// 不记 peer 维度（resolved == direct，peerKey 为空）。
func TestPeerDimensionNotCountedWithoutXFF(t *testing.T) {
	cfg := &config.HostAuthConfig{Password: testPassword, MaxFailures: 5, PeerMaxFailures: 2}
	// trustedProxies 为 nil：ResolveClientIP 恒直连 → resolved == direct
	m := NewManager(testHost, cfg, nil, &authTestLogger{})
	for i := 0; i < 5; i++ {
		w := doEval(m, newLoginRequest(http.MethodPost, AuthLoginPath, url.Values{"password": {"wrong"}}, false))
		if w.Code != http.StatusSeeOther {
			t.Fatalf("failure #%d status = %d, want 303", i+1, w.Code)
		}
	}
	// 第 6 次：解析后维度（5 次阈值）锁定
	w := doEval(m, newLoginRequest(http.MethodPost, AuthLoginPath, url.Values{"password": {"wrong"}}, false))
	if !strings.Contains(w.Header().Get("Location"), errorParamRateLimited) {
		t.Fatalf("expected lockout after 5 failures, got %q", w.Header().Get("Location"))
	}
}

// TestLoginBudgetRateLimited F2.3：登录全局预算（缺省 60/min burst 30）——
// 第 31 次请求 429 + Retry-After（在锁定检查之前生效）。
func TestLoginBudgetRateLimited(t *testing.T) {
	m := newTestManager(t) // LoginRatePerMinute 缺省 60，burst 固定 30
	form := url.Values{"password": {"wrong"}}

	for i := 0; i < 30; i++ {
		w := doEval(m, newLoginRequest(http.MethodPost, AuthLoginPath, form, false))
		if w.Code == http.StatusTooManyRequests {
			t.Fatalf("request #%d should be within burst, got 429", i+1)
		}
	}
	w := doEval(m, newLoginRequest(http.MethodPost, AuthLoginPath, form, false))
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("request #31 status = %d, want 429 (budget exhausted)", w.Code)
	}
	if ra := w.Header().Get("Retry-After"); ra != "1" {
		t.Errorf("Retry-After = %q, want 1", ra)
	}
}

// TestLoginBudgetDisabledByNegativeConfig F2.3：login_rate_per_minute 负值显式
// 关闭——超突发量请求不出现 429。
func TestLoginBudgetDisabledByNegativeConfig(t *testing.T) {
	cfg := &config.HostAuthConfig{Password: testPassword, MaxFailures: 1000, LoginRatePerMinute: -1}
	m := NewManager(testHost, cfg, nil, &authTestLogger{})
	if m.loginBudget != nil {
		t.Fatal("loginBudget should be nil when login_rate_per_minute < 0")
	}
	form := url.Values{"password": {"wrong"}}
	for i := 0; i < 40; i++ {
		w := doEval(m, newLoginRequest(http.MethodPost, AuthLoginPath, form, false))
		if w.Code == http.StatusTooManyRequests {
			t.Fatalf("request #%d got 429 with budget disabled", i+1)
		}
	}
}

// TestLoginSuccessResetsPeerDimension F2.2：成功登录同时清零两个维度。
func TestLoginSuccessResetsPeerDimension(t *testing.T) {
	cfg := &config.HostAuthConfig{Password: testPassword, MaxFailures: 5, PeerMaxFailures: 4}
	m := newPeerTestManager(t, cfg)

	// 同一直连对端累计 3 次（伪 XFF 轮换）
	for i := 0; i < 3; i++ {
		_ = doEval(m, peerLoginRequest("198.51.100."+strconv.Itoa(i)))
	}
	// 正确密码登录成功（经同一对端 + 固定 XFF）：双维度清零
	form := url.Values{"password": {testPassword}, "next": {"/"}}
	req := peerLoginRequest("198.51.100.1")
	req.Body = io.NopCloser(strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := doEval(m, req)
	if w.Code != http.StatusSeeOther || strings.Contains(w.Header().Get("Location"), "error=") {
		t.Fatalf("login success status = %d loc = %q, want 303 without error", w.Code, w.Header().Get("Location"))
	}
	// 成功后再失败 3 次（阈值 4 未到）：不应锁定
	for i := 0; i < 3; i++ {
		w := doEval(m, peerLoginRequest("198.51.100."+strconv.Itoa(i+50)))
		if strings.Contains(w.Header().Get("Location"), errorParamRateLimited) {
			t.Fatalf("failure #%d after successful reset should not be locked (peer counter was reset)", i+1)
		}
	}
}
