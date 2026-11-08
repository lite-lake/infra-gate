package netutil

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

func ParseTrustedProxies(proxies []string) []*net.IPNet {
	var networks []*net.IPNet
	for _, proxy := range proxies {
		if strings.Contains(proxy, "/") {
			_, network, err := net.ParseCIDR(proxy)
			if err == nil {
				networks = append(networks, network)
			}
		} else {
			ip := net.ParseIP(proxy)
			if ip != nil {
				var bits int
				if ip.To4() != nil {
					bits = 32
				} else {
					bits = 128
				}
				_, network, _ := net.ParseCIDR(proxy + "/" + fmt.Sprintf("%d", bits))
				if network != nil {
					networks = append(networks, network)
				}
			}
		}
	}
	return networks
}

func IsIPInNetworks(ip net.IP, networks []*net.IPNet) bool {
	for _, network := range networks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// ResolveClientIP resolves the real client IP from an http.Request.
// If trustedProxies is empty or the direct connection is not from a trusted proxy,
// it returns the direct connection IP (RemoteAddr) and ignores all forwarding headers.
// When the direct connection is from a trusted proxy, it parses the X-Forwarded-For
// chain from right to left, skipping trusted proxy IPs, and returns the first
// non-trusted IP. If all IPs in the XFF chain are trusted proxies, it returns the
// direct connection IP (not the leftmost XFF entry, which could be spoofed).
// X-Real-IP and X-Forwarded headers are not trusted to prevent IP spoofing.
func ResolveClientIP(r *http.Request, trustedProxies []*net.IPNet) string {
	directIP := r.RemoteAddr
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		directIP = host
	}

	if len(trustedProxies) == 0 {
		return directIP
	}

	directNetIP := net.ParseIP(directIP)
	if directNetIP == nil || !IsIPInNetworks(directNetIP, trustedProxies) {
		return directIP
	}

	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		for i := len(ips) - 1; i >= 0; i-- {
			ip := strings.TrimSpace(ips[i])
			netIP := net.ParseIP(ip)
			if netIP == nil {
				continue
			}
			if IsIPInNetworks(netIP, trustedProxies) {
				continue
			}
			return ip
		}
	}

	return directIP
}

// DirectRemoteIP 返回 TCP 直连对端 IP（RemoteAddr 剥端口，不做任何 XFF 解析）。
// 「边缘连接 ACL」口径（allowed_ips / admin 限速 / WS per-IP 上限共用），
// 与 ResolveClientIP 的「解析后真实客户端 IP」口径相对（内部PRD §3）。
func DirectRemoteIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// IsWebSocketUpgrade 判断请求是否为 RFC 6455 规范的 WebSocket 升级请求
// 必须满足：GET 方法、Connection 头包含 "upgrade"、Upgrade 头包含 "websocket"、
// 存在 Sec-WebSocket-Key、Sec-WebSocket-Version 为 13
func IsWebSocketUpgrade(r *http.Request) bool {
	if r.Method != http.MethodGet {
		return false
	}
	if !headerContainsToken(r.Header.Get("Connection"), "upgrade") {
		return false
	}
	if !headerContainsToken(r.Header.Get("Upgrade"), "websocket") {
		return false
	}
	if r.Header.Get("Sec-WebSocket-Key") == "" {
		return false
	}
	if !strings.EqualFold(r.Header.Get("Sec-WebSocket-Version"), "13") {
		return false
	}
	return true
}

// headerContainsToken 检查 header 值是否包含指定的 token（不区分大小写）
// 处理逗号分隔的列表，如 "keep-alive, Upgrade"
func headerContainsToken(headerValue, token string) bool {
	if headerValue == "" {
		return false
	}
	for _, v := range strings.Split(headerValue, ",") {
		if strings.EqualFold(strings.TrimSpace(v), token) {
			return true
		}
	}
	return false
}
