package netutil

// Host 规范形态（F3，内部PRD §4.3）：Host 大小写/尾点/带端口变体统一
// 归一化，防变体 Host 落入通配兜底条目绕过密码门/IP 白名单。

import (
	"net"
	"strings"
)

// CanonicalHost 返回 Host 头的规范匹配形态：
//  1. 剥端口（"example.com:443" → "example.com"；IPv6 字面量无端口时剥 []
//     括号，"[::1]" → "::1"）；
//  2. ASCII 域名 ToLower（"Example.COM" → "example.com"）；
//  3. 去掉一个尾部 "."（"example.com." → "example.com"）。
//
// 非 ASCII 输入原样返回：配置名经 config.Validate 强制 ASCII，非 ASCII 请求
// Host 自然无法匹配任何条目 → 404 fail-closed。不做 IDNA 映射——punycode 转换
// 会创造新的匹配等价类，反而扩大攻击面。
func CanonicalHost(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	} else if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	if !isASCIIHost(host) {
		return host
	}
	host = strings.ToLower(host)
	return strings.TrimSuffix(host, ".")
}

// isASCIIHost 判断是否全 ASCII（快速逐字节扫描）
func isASCIIHost(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}
