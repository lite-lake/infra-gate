package admin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lite-lake/infra-gate/internal/cert"
	"github.com/lite-lake/infra-gate/internal/config"
)

// newAPIKeyTestServer 构建带只读 key 配置的测试 AdminServer（keys 传 nil = 未配置任何 key）
func newAPIKeyTestServer(t *testing.T, keys ...string) *AdminServer {
	a := newTestAdminServer(&config.Config{
		Hosts: []config.HostConfig{
			{Name: "one.test", Backend: []string{"http://b1:80"}},
		},
	})
	// /api/certs 处理器依赖证书管理器（空仓库即可，ListCertificates 返回空 map）
	a.certManager = cert.NewManager(t.TempDir(), a.logger)
	a.cfg.ReadOnlyAPIKeys = keys
	return a
}

// doAPIKeyRequest 发起一次只读 API 请求（apiKey 为空串 = 不携带 X-API-Key 头）
func doAPIKeyRequest(t *testing.T, a *AdminServer, path, apiKey string) *httptest.ResponseRecorder {
	t.Helper()
	return serveAdminRequestWithHeader(t, a, path, map[string]string{apiKeyHeader: apiKey})
}

// TestValidReadOnlyAPIKey ValidReadOnlyAPIKey 常数时间比较实现性质：
// 正确 key 在数组任意位置（含最后一把，模拟轮换并存）均命中；错误 key / 空配置不命中
func TestValidReadOnlyAPIKey(t *testing.T) {
	tests := []struct {
		name      string
		keys      []string
		candidate string
		expected  bool
	}{
		{"单把 key 精确命中", []string{"key-a"}, "key-a", true},
		{"多把 key 第一把命中", []string{"key-a", "key-b", "key-c"}, "key-a", true},
		{"多把 key 最后一把命中（轮换并存）", []string{"key-a", "key-b", "key-c"}, "key-c", true},
		{"多把 key 中间一把命中", []string{"key-a", "key-b", "key-c"}, "key-b", true},
		{"错误 key 拒绝", []string{"key-a", "key-b"}, "key-x", false},
		{"大小写敏感", []string{"key-a"}, "KEY-A", false},
		{"前缀匹配不算命中", []string{"key-a"}, "key-a-longer", false},
		{"候选为空串拒绝", []string{"key-a"}, "", false},
		{"未配置任何 key 一律拒绝", nil, "key-a", false},
		{"空数组拒绝", []string{}, "key-a", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &AdminConfig{ReadOnlyAPIKeys: tt.keys}
			if got := cfg.ValidReadOnlyAPIKey(tt.candidate); got != tt.expected {
				t.Errorf("ValidReadOnlyAPIKey(%q) keys=%v = %v, 期望 %v", tt.candidate, tt.keys, got, tt.expected)
			}
		})
	}
}

// TestParseReadOnlyAPIKeys 环境变量解析：逗号分隔、去空白、丢弃空项
func TestParseReadOnlyAPIKeys(t *testing.T) {
	tests := []struct {
		name     string
		raw      string
		expected []string
	}{
		{"单把 key", strings.Repeat("a", 40), []string{strings.Repeat("a", 40)}},
		{"多把 key", strings.Repeat("a", 40) + "," + strings.Repeat("b", 41) + "," + strings.Repeat("c", 42), []string{strings.Repeat("a", 40), strings.Repeat("b", 41), strings.Repeat("c", 42)}},
		{"带空白", " " + strings.Repeat("a", 40) + " , " + strings.Repeat("b", 41) + " ", []string{strings.Repeat("a", 40), strings.Repeat("b", 41)}},
		{"空项丢弃", strings.Repeat("a", 40) + ",," + strings.Repeat("b", 41) + ",", []string{strings.Repeat("a", 40), strings.Repeat("b", 41)}},
		{"空串返回 nil", "", nil},
		{"仅逗号空白返回 nil", " , ,", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseReadOnlyAPIKeys(tt.raw)
			if err != nil {
				t.Fatalf("parseReadOnlyAPIKeys(%q) error: %v", tt.raw, err)
			}
			if tt.expected == nil {
				if got != nil {
					t.Errorf("parseReadOnlyAPIKeys(%q) = %v, 期望 nil", tt.raw, got)
				}
				return
			}
			if len(got) != len(tt.expected) {
				t.Fatalf("parseReadOnlyAPIKeys(%q) = %v, 期望 %v", tt.raw, got, tt.expected)
			}
			for i := range got {
				if got[i] != tt.expected[i] {
					t.Errorf("parseReadOnlyAPIKeys(%q)[%d] = %q, 期望 %q", tt.raw, i, got[i], tt.expected[i])
				}
			}
		})
	}
}

// TestReadonlyAPIAuth 只读端点 X-API-Key 认证行为矩阵（面板拆除后为唯一通道）：
// 有/无 key 配置 × 有头/无头 × 正确/错误 key；另验证 API Key 不开放已拆除的页面路由
func TestReadonlyAPIAuth(t *testing.T) {
	tests := []struct {
		name       string
		keys       []string
		apiKey     string
		path       string
		wantStatus int
	}{
		// 有 key 配置：8 个只读 GET（迭代 9 三端点 + 迭代 4 新增 WAF/黑名单五端点）
		{"有效 key 访问 sites 200", []string{"k1", "k2"}, "k2", "/api/sites", http.StatusOK},
		{"有效 key 访问 certs 200", []string{"k1"}, "k1", "/api/certs", http.StatusOK},
		{"有效 key 访问 system 200", []string{"k1"}, "k1", "/api/system", http.StatusOK},
		{"有效 key 访问 WAF 统计 200", []string{"k1"}, "k1", "/api/waf/stats", http.StatusOK},
		{"有效 key 访问 WAF 事件 200", []string{"k1"}, "k1", "/api/waf/events", http.StatusOK},
		{"有效 key 访问 WAF 事件详情 200", []string{"k1"}, "k1", "/api/waf/events/12345", http.StatusOK},
		{"有效 key 访问黑名单统计 200", []string{"k1"}, "k1", "/api/blacklist/stats", http.StatusOK},
		{"有效 key 访问黑名单事件 200", []string{"k1"}, "k1", "/api/blacklist/events", http.StatusOK},
		// 多把 key 轮换：命中位置不影响（含最后一把）
		{"多把 key 首把访问 WAF 事件 200", []string{"k1", "k2", "k3"}, "k1", "/api/waf/events", http.StatusOK},
		{"多把 key 末把访问黑名单事件 200（轮换并存）", []string{"k1", "k2", "k3"}, "k3", "/api/blacklist/events", http.StatusOK},
		{"错误 key 401", []string{"k1"}, "wrong", "/api/sites", http.StatusUnauthorized},
		{"错误 key 访问 WAF 端点 401", []string{"k1"}, "wrong", "/api/waf/stats", http.StatusUnauthorized},
		{"错误 key 访问黑名单端点 401", []string{"k1"}, "wrong", "/api/blacklist/events", http.StatusUnauthorized},
		// 面板拆除（迭代 4b）后无会话回退：未携带 key 一律 401
		{"未携带 key 访问 sites 401（无会话回退）", []string{"k1"}, "", "/api/sites", http.StatusUnauthorized},
		{"未携带 key 访问 WAF 端点 401（无会话回退）", []string{"k1"}, "", "/api/waf/events", http.StatusUnauthorized},
		{"未携带 key 访问黑名单统计 401（无会话回退）", []string{"k1"}, "", "/api/blacklist/stats", http.StatusUnauthorized},
		{"未配置 key 时携带 key 401", nil, "any", "/api/sites", http.StatusUnauthorized},
		{"未配置 key 时携带 key 访问 WAF 端点 401", nil, "any", "/api/waf/events", http.StatusUnauthorized},
		{"未配置 key 未携带 key 401", nil, "", "/api/sites", http.StatusUnauthorized},
		// 仅只读路由可达：页面路由已整体拆除，即使携带有效 key 也 404（route not found）
		{"有效 key 访问已拆除页面 /sites → 404", []string{"k1"}, "k1", "/sites", http.StatusNotFound},
		{"有效 key 访问已拆除页面 /waf → 404", []string{"k1"}, "k1", "/waf", http.StatusNotFound},
		{"有效 key 访问已拆除页面 /blacklist → 404", []string{"k1"}, "k1", "/blacklist", http.StatusNotFound},
		{"有效 key 访问已拆除仪表盘 / → 404", []string{"k1"}, "k1", "/", http.StatusNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := newAPIKeyTestServer(t, tt.keys...)

			w := doAPIKeyRequest(t, a, tt.path, tt.apiKey)
			if w.Code != tt.wantStatus {
				t.Errorf("%s (key=%q) 状态码 = %d, 期望 %d, body=%s", tt.path, tt.apiKey, w.Code, tt.wantStatus, w.Body.String())
			}
		})
	}
}

// TestReadonlyAPIKeyNoShortCircuit 实现性质补充：多把并存场景命中与否与 key 在配置中的位置无关
// （遍历全部 key 不短路，防时序侧信道泄漏匹配位置）
func TestReadonlyAPIKeyNoShortCircuit(t *testing.T) {
	keys := []string{"k1", "k2", "k3", "k4", "k5", "k6", "k7", "k8"}
	cfg := &AdminConfig{ReadOnlyAPIKeys: keys}
	for i, want := range keys {
		if !cfg.ValidReadOnlyAPIKey(want) {
			t.Errorf("第 %d 把 key %q 应命中", i, want)
		}
	}
	if cfg.ValidReadOnlyAPIKey("k9") {
		t.Errorf("未收录的 key 不应命中")
	}
}
