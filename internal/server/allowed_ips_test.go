package server

// 内部PRD 迭代 1 单测：
//   - allowed_ips 改为按直连对端（TCP RemoteAddr）评估（§4.3/§5.2 决策 D2）；
//   - 数据面 access log client_ip 防伪造头污染（§5.3）。
// 复用 blacklist_test.go 的测试基建（mock logger / chdir / 后端 / NewServer 构造）。

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/lite-lake/infra-gate/internal/config"
	"github.com/lite-lake/infra-gate/internal/netutil"
)

// 场景（§5.2 决策 D2）：allowed_ips 按直连对端评估，不解析 XFF——
//   - 直连为 mesh IP（上一跳 gate）+ 伪造"真实 IP"的 XFF → 放行（评估对象是直连对端）；
//   - 直连为公网 IP + XFF 伪装成 mesh IP → 403（伪造头不能绕过边缘 ACL）。
//
// 配置带 trusted_proxies（模拟内网 gate）以证明即使直连受信，allowed_ips 也不走 XFF 解析。
func TestAllowedIPsEvaluatedByDirectPeer(t *testing.T) {
	chdirToRepoRoot(t)
	backend, backendHits := newBLBackend(t)

	meshOnlyHost := blHost("mesh-only.example.com", backend.URL, nil)
	meshOnlyHost.AllowedIPs = []string{"10.72.0.0/24"}
	cfg := &config.Config{
		Server: config.ServerConfig{
			Port:           8080,
			TrustedProxies: []string{"10.72.0.0/24"},
		},
		Hosts: []config.HostConfig{meshOnlyHost},
	}
	s := newBLServer(t, cfg)

	// 直连 mesh IP + XFF 携带"真实客户端"公网 IP → 放行（不看 XFF）
	req := httptest.NewRequest(http.MethodGet, "http://mesh-only.example.com/", nil)
	req.RemoteAddr = "10.72.0.5:40000"
	req.Header.Set("X-Forwarded-For", "203.0.113.10")
	if w := blDoRequestWithReq(s, req); w.Code != http.StatusOK {
		t.Errorf("direct mesh peer with forged XFF status = %d, want 200 (allowed_ips evaluates direct peer)", w.Code)
	}
	if n := atomic.LoadInt64(backendHits); n != 1 {
		t.Errorf("backend hits after mesh peer request = %d, want 1", n)
	}

	// 直连公网 IP + XFF 伪装成 mesh IP → 403（裸 Forbidden）
	req = httptest.NewRequest(http.MethodGet, "http://mesh-only.example.com/", nil)
	req.RemoteAddr = "203.0.113.50:40000"
	req.Header.Set("X-Forwarded-For", "10.72.0.5")
	w := blDoRequestWithReq(s, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("direct public peer with spoofed mesh XFF status = %d, want 403", w.Code)
	}
	if body := w.Body.String(); body != "Forbidden" {
		t.Errorf("direct public peer body = %q, want plain Forbidden (rejected by allowed_ips)", body)
	}
	if n := atomic.LoadInt64(backendHits); n != 1 {
		t.Errorf("backend hits after spoofed request = %d, want still 1 (403 must not proxy)", n)
	}
}

// 场景（§5.3）：数据面 access log 的 client_ip 与 blacklist/WAF 取值口径一致——
//   - trusted_proxies 为空时，伪造 XFF / X-Real-IP 不得污染日志（取直连对端）；
//   - 配置可信网段且直连受信时按可信链解析；直连不受信时回落直连对端。
func TestGinLoggerClientIPNotPollutedBySpoofedForwardedHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		trustedProxies []string
		remoteAddr     string
		forwardedFor   string
		realIP         string
		wantClientIP   string
	}{
		{
			name:         "empty trusted proxies ignores spoofed XFF and X-Real-IP",
			remoteAddr:   "203.0.113.77:51000",
			forwardedFor: "6.6.6.6",
			realIP:       "7.7.7.7",
			wantClientIP: "203.0.113.77",
		},
		{
			name:           "trusted direct peer resolves XFF like blacklist/WAF",
			trustedProxies: []string{"10.72.0.0/24"},
			remoteAddr:     "10.72.0.9:51000",
			forwardedFor:   "6.6.6.6",
			wantClientIP:   "6.6.6.6",
		},
		{
			name:           "untrusted direct peer falls back to RemoteAddr despite trusted proxies configured",
			trustedProxies: []string{"10.72.0.0/24"},
			remoteAddr:     "203.0.113.77:51000",
			forwardedFor:   "6.6.6.6",
			wantClientIP:   "203.0.113.77",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rl := &blRecordLogger{}
			// 直接构造最小 Server：ginLoggerMiddleware 仅依赖 logger 与 trustedProxyNets
			s := &Server{logger: rl, trustedProxyNets: netutil.ParseTrustedProxies(tt.trustedProxies)}

			req := httptest.NewRequest(http.MethodGet, "http://log.example.com/", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.forwardedFor != "" {
				req.Header.Set("X-Forwarded-For", tt.forwardedFor)
			}
			if tt.realIP != "" {
				req.Header.Set("X-Real-IP", tt.realIP)
			}

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = req

			s.ginLoggerMiddleware()(c)

			got, ok := firstLogFieldValue(rl, "info", "client_ip")
			if !ok {
				t.Fatalf("access log should contain client_ip field")
			}
			if got != tt.wantClientIP {
				t.Errorf("access log client_ip = %q, want %q", got, tt.wantClientIP)
			}
		})
	}
}

// firstLogFieldValue 返回第一条指定级别日志中指定字段的值（fmt.Sprint 比较）
func firstLogFieldValue(r *blRecordLogger, level, key string) (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, rec := range r.records {
		if rec.level != level {
			continue
		}
		for _, f := range rec.fields {
			if f.Key == key {
				return fmt.Sprint(f.Value), true
			}
		}
	}
	return "", false
}
