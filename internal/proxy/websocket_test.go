package proxy

import (
	"net/url"
	"testing"
)

// wsDialAddr 补默认端口（ws/wss 拨号必须显式端口，http.Transport 的自动补齐
// 不适用于裸 net.Dialer / tls.Dialer）。
func TestWSDialAddr(t *testing.T) {
	tests := []struct {
		name     string
		backend  string
		expected string
	}{
		{"wss 无端口补 443", "https://warden.v-dev.mesh.example.net", "warden.v-dev.mesh.example.net:443"},
		{"wss 显式端口原样", "https://127.0.0.1:8443", "127.0.0.1:8443"},
		{"wss scheme 无端口补 443", "wss://mesh-app.node1.example.net", "mesh-app.node1.example.net:443"},
		{"ws 无端口补 80", "http://svc.example.local", "svc.example.local:80"},
		{"ws scheme 无端口补 80", "ws://svc.example.local", "svc.example.local:80"},
		{"ws 显式端口原样", "http://uptime-kuma-node1:3001", "uptime-kuma-node1:3001"},
		{"IPv6 显式端口原样", "https://[::1]:443", "[::1]:443"},
		{"IPv6 无端口补 443", "wss://[::1]", "[::1]:443"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := url.Parse(tt.backend)
			if err != nil {
				t.Fatalf("url.Parse(%q) error = %v", tt.backend, err)
			}
			if got := wsDialAddr(u); got != tt.expected {
				t.Errorf("wsDialAddr(%q) = %q, want %q", tt.backend, got, tt.expected)
			}
		})
	}
}
