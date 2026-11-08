package netutil

import (
	"net"
	"net/http"
	"testing"
)

func TestResolveClientIP(t *testing.T) {
	trustedProxies := ParseTrustedProxies([]string{"10.0.0.0/8", "172.16.0.0/12"})
	noProxies := []*net.IPNet{}

	tests := []struct {
		name           string
		remoteAddr     string
		xff            string
		xRealIP        string
		xForwarded     string
		trustedProxies []*net.IPNet
		expected       string
	}{
		{
			name:           "direct connection, no trusted proxies",
			remoteAddr:     "192.168.1.1:1234",
			trustedProxies: noProxies,
			expected:       "192.168.1.1",
		},
		{
			name:           "direct connection with XFF, no trusted proxies",
			remoteAddr:     "192.168.1.1:1234",
			xff:            "10.0.0.1",
			trustedProxies: noProxies,
			expected:       "192.168.1.1",
		},
		{
			name:           "trusted proxy, single XFF",
			remoteAddr:     "10.0.0.1:1234",
			xff:            "203.0.113.5",
			trustedProxies: trustedProxies,
			expected:       "203.0.113.5",
		},
		{
			name:           "trusted proxy, multi-layer XFF",
			remoteAddr:     "10.0.0.1:1234",
			xff:            "203.0.113.5, 10.0.0.2, 10.0.0.3",
			trustedProxies: trustedProxies,
			expected:       "203.0.113.5",
		},
		{
			name:           "XFF all trusted proxies, returns direct IP",
			remoteAddr:     "10.0.0.1:1234",
			xff:            "10.0.0.2, 10.0.0.3",
			trustedProxies: trustedProxies,
			expected:       "10.0.0.1",
		},
		{
			name:           "XFF spoofing from non-trusted direct connection",
			remoteAddr:     "192.168.1.1:1234",
			xff:            "127.0.0.1",
			trustedProxies: trustedProxies,
			expected:       "192.168.1.1",
		},
		{
			name:           "mixed trusted and untrusted XFF",
			remoteAddr:     "10.0.0.1:1234",
			xff:            "203.0.113.5, 8.8.8.8, 10.0.0.2",
			trustedProxies: trustedProxies,
			expected:       "8.8.8.8",
		},
		{
			name:           "no XFF, X-Real-IP should not be trusted",
			remoteAddr:     "10.0.0.1:1234",
			xRealIP:        "203.0.113.5",
			trustedProxies: trustedProxies,
			expected:       "10.0.0.1",
		},
		{
			name:           "no XFF, X-Forwarded should not be trusted",
			remoteAddr:     "10.0.0.1:1234",
			xForwarded:     "203.0.113.5",
			trustedProxies: trustedProxies,
			expected:       "10.0.0.1",
		},
		{
			name:           "XFF with invalid IP, skipped",
			remoteAddr:     "10.0.0.1:1234",
			xff:            "invalid, 203.0.113.5",
			trustedProxies: trustedProxies,
			expected:       "203.0.113.5",
		},
		{
			name:           "RemoteAddr without port",
			remoteAddr:     "192.168.1.1",
			trustedProxies: noProxies,
			expected:       "192.168.1.1",
		},
		{
			name:           "CIDR trusted proxy",
			remoteAddr:     "172.16.0.1:1234",
			xff:            "203.0.113.5",
			trustedProxies: trustedProxies,
			expected:       "203.0.113.5",
		},
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
			if tt.xRealIP != "" {
				req.Header.Set("X-Real-IP", tt.xRealIP)
			}
			if tt.xForwarded != "" {
				req.Header.Set("X-Forwarded", tt.xForwarded)
			}

			result := ResolveClientIP(req, tt.trustedProxies)
			if result != tt.expected {
				t.Errorf("ResolveClientIP() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestIsWebSocketUpgrade(t *testing.T) {
	tests := []struct {
		name     string
		method   string
		upgrade  string
		conn     string
		key      string
		version  string
		expected bool
	}{
		{"valid WebSocket upgrade", "GET", "websocket", "Upgrade", "dGhlIHNhbXBsZSBub25jZQ==", "13", true},
		{"valid with mixed case", "GET", "WebSocket", "keep-alive, Upgrade", "dGhlIHNhbXBsZSBub25jZQ==", "13", true},
		{"non-GET method", "POST", "websocket", "Upgrade", "dGhlIHNhbXBsZSBub25jZQ==", "13", false},
		{"missing Connection header", "GET", "websocket", "", "dGhlIHNhbXBsZSBub25jZQ==", "13", false},
		{"missing Upgrade header", "GET", "", "Upgrade", "dGhlIHNhbXBsZSBub25jZQ==", "13", false},
		{"missing Sec-WebSocket-Key", "GET", "websocket", "Upgrade", "", "13", false},
		{"wrong Sec-WebSocket-Version", "GET", "websocket", "Upgrade", "dGhlIHNhbXBsZSBub25jZQ==", "12", false},
		{"spoofed Upgrade header only", "GET", "websocket", "keep-alive", "", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{
				Method:     tt.method,
				RemoteAddr: "192.168.1.1:1234",
				Header:     make(http.Header),
			}
			if tt.upgrade != "" {
				req.Header.Set("Upgrade", tt.upgrade)
			}
			if tt.conn != "" {
				req.Header.Set("Connection", tt.conn)
			}
			if tt.key != "" {
				req.Header.Set("Sec-WebSocket-Key", tt.key)
			}
			if tt.version != "" {
				req.Header.Set("Sec-WebSocket-Version", tt.version)
			}

			result := IsWebSocketUpgrade(req)
			if result != tt.expected {
				t.Errorf("IsWebSocketUpgrade() = %v, want %v", result, tt.expected)
			}
		})
	}
}
