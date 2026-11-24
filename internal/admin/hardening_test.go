package admin

// F13 admin 加固测试（内部PRD §4.13/§11 F13）：
// N-1 次 401 → 第 N 次 429；锁定期正确 key 也 429；探针不受限；
// key <32 拒；prod 逃生口拒启动 / 非 prod 过；审计日志无 key 材料。

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/lite-lake/infra-gate/internal/config"
	"github.com/lite-lake/infra-gate/internal/deployinfo"
	"github.com/lite-lake/infra-gate/internal/infrastructs/logger"
)

const f13LongKey = "0123456789012345678901234567890123456789012" // 43 chars

func f13Server(t *testing.T) *AdminServer {
	t.Helper()
	return NewAdminServer(&AdminConfig{
		Domain:          "admin.example.com",
		HTTPS:           true,
		Port:            30443,
		ReadOnlyAPIKeys: []string{f13LongKey},
		// 测试放通来源 ACL（本用例考察认证限速，非 ACL）
		AllowedIPsUnlimited: true,
	}, &config.Config{Server: config.ServerConfig{Port: 8080}}, nil, logger.GetDefaultLogger())
}

func f13Do(engine *gin.Engine, path, apiKey, remoteAddr string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Host = "admin.example.com"
	req.RemoteAddr = remoteAddr
	if apiKey != "" {
		req.Header.Set(apiKeyHeader, apiKey)
	}
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	return w
}

// TestAdminAPIAuthLockoutAfterFailures N-1 次 401 → 第 N 次（缺省 5）429；
// 锁定期正确 key 也 429（先查锁不读 key）
func TestAdminAPIAuthLockoutAfterFailures(t *testing.T) {
	a := f13Server(t)
	engine := a.buildEngine()

	bad := "wrong-key-000000000000000000000000000000000"
	for i := 1; i < config.DefaultAuthMaxFailures; i++ {
		w := f13Do(engine, "/api/sites", bad, "203.0.113.9:40000")
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("failure #%d status = %d, want 401", i, w.Code)
		}
	}
	// 第 5 次：触发锁定（本次仍 401，跳变沿已发）
	w := f13Do(engine, "/api/sites", bad, "203.0.113.9:40000")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("threshold failure status = %d, want 401", w.Code)
	}
	// 第 6 次（含正确 key）：锁定期 429
	w = f13Do(engine, "/api/sites", f13LongKey, "203.0.113.9:40000")
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("locked-with-valid-key status = %d, want 429 (lock checked before key)", w.Code)
	}
	if ra := w.Header().Get("Retry-After"); ra == "" {
		t.Error("429 should carry Retry-After")
	}
	// 其他来源不受影响（正确 key 正常 200）
	w = f13Do(engine, "/api/sites", f13LongKey, "198.51.100.7:40000")
	if w.Code != http.StatusOK {
		t.Fatalf("other source with valid key status = %d, want 200", w.Code)
	}
	// 成功后原 IP 计数不影响：另一 IP 成功即 Reset
}

// TestAdminProbeNotRateLimited 免认证探针不受限速影响
func TestAdminProbeNotRateLimited(t *testing.T) {
	a := f13Server(t)
	engine := a.buildEngine()
	// 同一来源连续多次打探针（无认证），全部正常
	for i := 0; i < 8; i++ {
		w := f13Do(engine, "/api/health", "", "203.0.113.9:40000")
		if w.Code == http.StatusTooManyRequests {
			t.Fatalf("probe request #%d must not be rate limited", i+1)
		}
	}
}

// TestAdminLockoutNotifier 锁定跳变沿经 SetNotifier 注入的回调上抛一条
func TestAdminLockoutNotifier(t *testing.T) {
	a := f13Server(t)
	events := make([]string, 0, 2)
	a.SetNotifier(fakeAdminNotifier{&events})
	engine := a.buildEngine()

	bad := "wrong-key-000000000000000000000000000000000"
	for i := 0; i < config.DefaultAuthMaxFailures; i++ {
		f13Do(engine, "/api/sites", bad, "203.0.113.9:40000")
	}
	if len(events) != 1 || events[0] != "admin_api_lockout" {
		t.Errorf("lockout events = %v, want exactly one admin_api_lockout", events)
	}
	// 锁定期内再失败不重复告警（跳变沿去重）
	f13Do(engine, "/api/sites", bad, "203.0.113.9:40000")
	if len(events) != 1 {
		t.Errorf("lockout events after repeat = %d, want still 1", len(events))
	}
}

type fakeAdminNotifier struct{ events *[]string }

func (f fakeAdminNotifier) SendNotification(event string, _ map[string]string) error {
	*f.events = append(*f.events, event)
	return nil
}

// TestParseReadOnlyAPIKeysMinLength key <32 拒（fail-fast）
func TestParseReadOnlyAPIKeysMinLength(t *testing.T) {
	if _, err := parseReadOnlyAPIKeys("shortkey"); err == nil {
		t.Error("short key must be rejected")
	}
	keys, err := parseReadOnlyAPIKeys(f13LongKey)
	if err != nil || len(keys) != 1 {
		t.Errorf("43-char key should pass, got %v %v", keys, err)
	}
	if keys2, _ := parseReadOnlyAPIKeys(""); keys2 != nil {
		t.Error("empty config returns nil")
	}
}

// TestAdminEscapeHatchProdRejected prod 逃生口拒启动；非 prod 过
func TestAdminEscapeHatchProdRejected(t *testing.T) {
	t.Setenv("LITE_ADMIN_DOMAIN", "admin.example.com")
	t.Setenv("LITE_ADMIN_HTTPS", "false")
	t.Setenv("LITE_ADMIN_ALLOWED_IPS", "10.0.0.0/8")
	t.Setenv("LITE_ADMIN_READONLY_API_KEYS", f13LongKey)

	// prod：HTTPS=false 拒
	deployinfo.SetForTest(t, deployinfo.DeployInfo{DeployEnv: "prod"})
	if _, err := LoadFromEnv(); err == nil || !strings.Contains(err.Error(), "not allowed in prod") {
		t.Errorf("prod with HTTPS=false should be rejected, got %v", err)
	}

	// prod：HTTPS=true 但 ACL 空串拒
	t.Setenv("LITE_ADMIN_HTTPS", "true")
	t.Setenv("LITE_ADMIN_ALLOWED_IPS", "")
	if _, err := LoadFromEnv(); err == nil {
		t.Error("prod with unlimited ACL should be rejected")
	}

	// dev：同样配置过（保留 Warn 逃生口）
	deployinfo.SetForTest(t, deployinfo.DeployInfo{DeployEnv: "dev"})
	if _, err := LoadFromEnv(); err != nil {
		t.Errorf("dev escape hatch should pass, got %v", err)
	}

	// prod 正常配置过
	t.Setenv("LITE_ADMIN_ALLOWED_IPS", "10.0.0.0/8")
	deployinfo.SetForTest(t, deployinfo.DeployInfo{DeployEnv: "prod"})
	if _, err := LoadFromEnv(); err != nil {
		t.Errorf("prod with normal config should pass, got %v", err)
	}
}
