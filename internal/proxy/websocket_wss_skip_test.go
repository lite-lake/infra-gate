package proxy

// L3 WSS 上游跳过证书校验消费点单测（内部PRD §7.1，出口标准④）：
// proxy 消费点（handleWebSocketUpgrade 的 TLS dial）实际按传入的 per-host 合并值
// 生效——skip=false 时自签证书的上游握手必须失败（校验强制），skip=true 时成功
//（显式放行）。per-host 合并取值语义由 config.GetEffectiveWebSocketInsecureSkip
// 表驱动单测与 server 启动 Warn 单测覆盖。

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/lite-lake/infra-gate/internal/infrastructs/logger"
	"github.com/lite-lake/infra-gate/internal/netutil"
)

// newWSSUpstream 启动自签证书的 TLS 上游，完成规范 101 升级应答
func newWSSUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !netutil.IsWebSocketUpgrade(r) {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		h := w.Header()
		h.Set("Upgrade", "websocket")
		h.Set("Connection", "Upgrade")
		h.Set("Sec-WebSocket-Accept", generateWebSocketAcceptKey(r.Header.Get("Sec-WebSocket-Key")))
		w.WriteHeader(http.StatusSwitchingProtocols)
	}))
	t.Cleanup(upstream.Close)
	return upstream
}

func newWSUpgradeRequest() *http.Request {
	req := httptest.NewRequest(http.MethodGet, "http://client.example/ws", nil)
	req.RemoteAddr = "203.0.113.5:44444"
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	req.Header.Set("Sec-WebSocket-Version", "13")
	return req
}

// 表驱动：skip=true 显式放行自签上游（握手成功返回连接）；skip=false（缺省）
// 证书校验强制，TLS dial 失败——证明消费点真实读取该开关而非恒跳过
func TestWSSUpstreamInsecureSkipConsumption(t *testing.T) {
	upstream := newWSSUpstream(t)
	backendURL, err := url.Parse(upstream.URL) // https://127.0.0.1:<port>，自签 CA 不在系统根
	if err != nil {
		t.Fatalf("parse upstream URL: %v", err)
	}

	tests := []struct {
		name          string
		skip          bool
		wantHandshake bool
		wantErrSubstr string
	}{
		{"skip=true accepts self-signed upstream", true, true, ""},
		{"skip=false enforces verification", false, false, "certificate"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := NewProxy(
				[]string{upstream.URL},
				"",
				time.Second, time.Second,
				logger.GetDefaultLogger(),
				nil,
				nil,
				tc.skip, // ← 消费点：per-host 合并值
				false, "", "", false, false, false, "",
				defaultWSConfig(),
				UpstreamConfig{},
			)
			conn, _, _, hsErr := p.handleWebSocketUpgrade(newWSUpgradeRequest(), backendURL, "")
			if tc.wantHandshake {
				if hsErr != nil {
					t.Fatalf("handshake with skip=true should succeed, got error: %v", hsErr)
				}
				conn.Close()
				return
			}
			if hsErr == nil {
				if conn != nil {
					conn.Close()
				}
				t.Fatalf("handshake with skip=false must fail against untrusted upstream cert")
			}
			if !strings.Contains(hsErr.Error(), tc.wantErrSubstr) {
				t.Errorf("error = %v, want substring %q", hsErr, tc.wantErrSubstr)
			}
		})
	}
}
