package admin

// M4 单测（内部PRD §5/§6/§7.2，决策 D3/D5，出口标准①）：
// LITE_ADMIN_ALLOWED_IPS 三态（未设置=默认私网+回环 / 显式空串=不限制 / 自定义条目）
// 与非法条目 fail-fast；允许名单中间件按直连对端评估、全部端点（含免认证探针）受限。

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/lite-lake/infra-gate/internal/config"
	"github.com/lite-lake/infra-gate/internal/infrastructs/logger"
)

// adminNoopLogger 静音 logger（对齐 authTestLogger 模式）
type adminNoopLogger struct{}

func (l *adminNoopLogger) Debug(msg string, fields ...logger.Field) {}
func (l *adminNoopLogger) Info(msg string, fields ...logger.Field)  {}
func (l *adminNoopLogger) Warn(msg string, fields ...logger.Field)  {}
func (l *adminNoopLogger) Error(msg string, fields ...logger.Field) {}
func (l *adminNoopLogger) Fatal(msg string, fields ...logger.Field) {}
func (l *adminNoopLogger) WithContext(ctx context.Context) logger.ILogger {
	return l
}
func (l *adminNoopLogger) WithField(key string, value interface{}) logger.ILogger { return l }
func (l *adminNoopLogger) WithFields(fields map[string]interface{}) logger.ILogger {
	return l
}
func (l *adminNoopLogger) WithTraceId(traceId string) logger.ILogger { return l }
func (l *adminNoopLogger) SetLevel(level logger.LogLevel)            {}
func (l *adminNoopLogger) GetLevel() logger.LogLevel                 { return logger.DebugLevel }
func (l *adminNoopLogger) Close() error                              { return nil }

// LoadFromEnv：LITE_ADMIN_ALLOWED_IPS 三态语义
func TestLoadFromEnvAllowedIPs(t *testing.T) {
	t.Setenv("LITE_ADMIN_DOMAIN", "gate.test")
	tests := []struct {
		name          string
		allowedIPs    string
		set           bool
		wantEntries   []string
		wantUnlimited bool
		wantErr       bool
	}{
		{
			name:        "unset defaults to private+loopback",
			set:         false,
			wantEntries: DefaultAdminAllowedIPs(),
		},
		{
			name:          "explicit empty string disables allowlist",
			allowedIPs:    "",
			set:           true,
			wantEntries:   nil,
			wantUnlimited: true,
		},
		{
			name:          "whitespace-only counts as empty",
			allowedIPs:    "  ",
			set:           true,
			wantEntries:   nil,
			wantUnlimited: true,
		},
		{
			name:        "custom CIDR and bare IP entries",
			allowedIPs:  "192.0.2.0/24, 203.0.113.5",
			set:         true,
			wantEntries: []string{"192.0.2.0/24", "203.0.113.5"},
		},
		{
			name:       "invalid CIDR fails fast",
			allowedIPs: "10.0.0.0/999",
			set:        true,
			wantErr:    true,
		},
		{
			name:       "invalid bare entry fails fast",
			allowedIPs: "not-an-ip",
			set:        true,
			wantErr:    true,
		},
		{
			name:       "no valid entries fails fast",
			allowedIPs: ",,,",
			set:        true,
			wantErr:    true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.set {
				t.Setenv("LITE_ADMIN_ALLOWED_IPS", tc.allowedIPs)
			}
			cfg, err := LoadFromEnv()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("LoadFromEnv should fail on invalid entries, got cfg=%v", cfg)
				}
				return
			}
			if err != nil {
				t.Fatalf("LoadFromEnv: %v", err)
			}
			if !reflect.DeepEqual(cfg.AllowedIPs, tc.wantEntries) {
				t.Errorf("AllowedIPs = %v, want %v", cfg.AllowedIPs, tc.wantEntries)
			}
			if cfg.AllowedIPsUnlimited != tc.wantUnlimited {
				t.Errorf("AllowedIPsUnlimited = %v, want %v", cfg.AllowedIPsUnlimited, tc.wantUnlimited)
			}
		})
	}

	// 未设置 LITE_ADMIN_DOMAIN：不启用 admin，允许名单语义无关
	t.Run("admin disabled without domain", func(t *testing.T) {
		t.Setenv("LITE_ADMIN_DOMAIN", "")
		cfg, err := LoadFromEnv()
		if cfg != nil || err != nil {
			t.Errorf("LoadFromEnv without domain = (%v, %v), want (nil, nil)", cfg, err)
		}
	})
}

// DefaultAdminAllowedIPs 缺省名单内容断言（D3：私网+回环，覆盖 mesh 10.61/10.62）
func TestDefaultAdminAllowedIPs(t *testing.T) {
	want := []string{"127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}
	got := DefaultAdminAllowedIPs()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("DefaultAdminAllowedIPs = %v, want %v", got, want)
	}
}

// newAllowedIPsTestServer 构造 AdminServer 并经真实装配链 buildEngine 取得 engine
// （与 Start 同源共用，装配链绑定：Start/buildEngine 侧漏注册或乱序调整中间件时
// 本文件全部中间件用例同步失败，不再依赖手工 engine.Use 复刻）
func newAllowedIPsTestServer(t *testing.T, cfg *AdminConfig) (*AdminServer, *gin.Engine) {
	t.Helper()
	a := NewAdminServer(cfg, &config.Config{}, nil, &adminNoopLogger{})
	return a, a.buildEngine()
}

func serveWithRemote(t *testing.T, engine *gin.Engine, remote, path string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Host = "gate.test"
	req.RemoteAddr = remote
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	return w
}

// 中间件：默认名单内 200 / 名单外 403，全部端点含免认证探针同样受限
func TestAdminAllowedIPsMiddlewareDefaultList(t *testing.T) {
	tests := []struct {
		name   string
		remote string
		path   string
		want   int
	}{
		{"loopback ipv4 allowed", "127.0.0.1:5000", "/api/health", http.StatusOK},
		{"loopback ipv6 allowed", "[::1]:5000", "/api/health", http.StatusOK},
		{"mesh dev subnet allowed (10.71.x)", "10.71.0.7:9999", "/api/health", http.StatusOK},
		{"mesh prod subnet allowed (10.72.x)", "10.72.0.3:9999", "/api/ready", http.StatusOK},
		{"private 172.16/12 allowed", "172.16.5.5:1000", "/api/health", http.StatusOK},
		{"private 192.168/16 allowed", "192.168.1.10:1000", "/api/health", http.StatusOK},
		{"just outside 172.16/12 denied", "172.32.0.1:1000", "/api/health", http.StatusForbidden},
		{"public source denied", "8.8.8.8:1000", "/api/health", http.StatusForbidden},
		{"public source denied on ready probe", "8.8.8.8:1000", "/api/ready", http.StatusForbidden},
		{"public source denied on shipper probe", "8.8.8.8:1000", "/api/shipper/status", http.StatusForbidden},
		{"public source denied on readonly api", "8.8.8.8:1000", "/api/sites", http.StatusForbidden},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// 默认名单形态 = LoadFromEnv 未设置环境变量时的产物
			a, engine := newAllowedIPsTestServer(t, &AdminConfig{
				Domain:     "gate.test",
				HTTPS:      true,
				AllowedIPs: DefaultAdminAllowedIPs(),
			})
			w := serveWithRemote(t, engine, tc.remote, tc.path, nil)
			if w.Code != tc.want {
				t.Errorf("remote=%s path=%s status = %d, want %d", tc.remote, tc.path, w.Code, tc.want)
			}
			_ = a
		})
	}
}

// 中间件：显式空串逃生口——任意来源（含公网）放行
func TestAdminAllowedIPsMiddlewareUnlimitedEscape(t *testing.T) {
	a, engine := newAllowedIPsTestServer(t, &AdminConfig{
		Domain:              "gate.test",
		HTTPS:               true,
		AllowedIPsUnlimited: true,
	})
	for _, remote := range []string{"8.8.8.8:1000", "203.0.113.77:5555", "127.0.0.1:5000"} {
		w := serveWithRemote(t, engine, remote, "/api/health", nil)
		if w.Code != http.StatusOK {
			t.Errorf("unlimited: remote=%s status = %d, want 200", remote, w.Code)
		}
	}
	_ = a
}

// 中间件：自定义名单取代缺省（自定义条目生效、缺省条目不再豁免）
func TestAdminAllowedIPsMiddlewareCustomList(t *testing.T) {
	a, engine := newAllowedIPsTestServer(t, &AdminConfig{
		Domain:     "gate.test",
		HTTPS:      true,
		AllowedIPs: []string{"192.0.2.0/24", "203.0.113.5"},
	})
	tests := []struct {
		remote string
		want   int
	}{
		{"192.0.2.55:1000", http.StatusOK},       // 自定义 CIDR 内
		{"203.0.113.5:41000", http.StatusOK},     // 自定义裸 IP
		{"127.0.0.1:5000", http.StatusForbidden}, // 缺省回环不再豁免
		{"10.71.0.7:9999", http.StatusForbidden}, // 缺省 mesh 网段不再豁免
	}
	for _, tc := range tests {
		w := serveWithRemote(t, engine, tc.remote, "/api/health", nil)
		if w.Code != tc.want {
			t.Errorf("custom list: remote=%s status = %d, want %d", tc.remote, w.Code, tc.want)
		}
	}
	_ = a
}

// XFF 伪造不影响判定：直连对端在名单内但 XFF 声明名单外地址 → 放行（按直连评估）
func TestAdminAllowedIPsIgnoresXFF(t *testing.T) {
	_, engine := newAllowedIPsTestServer(t, &AdminConfig{
		Domain:     "gate.test",
		HTTPS:      true,
		AllowedIPs: DefaultAdminAllowedIPs(),
	})
	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	req.Host = "gate.test"
	req.RemoteAddr = "10.71.0.7:9999"
	req.Header.Set("X-Forwarded-For", "8.8.8.8")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("evaluation must use direct peer, not spoofable XFF; status = %d, want 200", w.Code)
	}
}
