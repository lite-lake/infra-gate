package proxy

import (
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"strings"
)

type UpstreamErrorType string

const (
	UpstreamErrorTimeout           UpstreamErrorType = "timeout"
	UpstreamErrorConnectionRefused UpstreamErrorType = "connection_refused"
	UpstreamErrorDNSFailure        UpstreamErrorType = "dns_failure"
	UpstreamErrorSSL               UpstreamErrorType = "ssl_error"
	UpstreamErrorNoRoute           UpstreamErrorType = "no_route"
	UpstreamErrorUnknown           UpstreamErrorType = "unknown"
)

func detectUpstreamErrorType(err error) (UpstreamErrorType, string) {
	if err == nil {
		return UpstreamErrorUnknown, ""
	}

	errStr := err.Error()

	// H31: 先检查 net.Error（超时/DNS），再检查 SSL 字符串匹配
	// 避免 timeout/DNS 错误的字符串中包含 "TLS" 等关键词被误判为 SSL 错误
	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() {
			return UpstreamErrorTimeout, errStr
		}
		var opErr *net.OpError
		if errors.As(err, &opErr) {
			if opErr.Op == "dial" || opErr.Op == "read" || opErr.Op == "write" {
				var dnsErr *net.DNSError
				if errors.As(opErr.Err, &dnsErr) {
					return UpstreamErrorDNSFailure, errStr
				}
				if strings.Contains(errStr, "connection refused") {
					return UpstreamErrorConnectionRefused, errStr
				}
				if strings.Contains(errStr, "no route to host") {
					return UpstreamErrorNoRoute, errStr
				}
			}
		}
		if strings.Contains(errStr, "no such host") ||
			strings.Contains(errStr, "dial tcp: lookup") ||
			strings.Contains(errStr, "server misbehaving") {
			return UpstreamErrorDNSFailure, errStr
		}
		if strings.Contains(errStr, "connection refused") {
			return UpstreamErrorConnectionRefused, errStr
		}
		if strings.Contains(errStr, "no route to host") {
			return UpstreamErrorNoRoute, errStr
		}
		return UpstreamErrorUnknown, errStr
	}

	// H30/H31: SSL/TLS 错误检测（使用类型断言，在 net.Error 之后）
	// 仅在确认不是 net.Error 后才检查 SSL，避免误判
	var tlsErr *tls.CertificateVerificationError
	if errors.As(err, &tlsErr) {
		return UpstreamErrorSSL, errStr
	}

	var recordErr tls.RecordHeaderError
	if errors.As(err, &recordErr) {
		return UpstreamErrorSSL, errStr
	}

	// H30: 缩小 SSL 字符串匹配范围，仅匹配明确的 SSL 错误特征
	if strings.Contains(errStr, "x509:") ||
		strings.Contains(errStr, "tls: ") ||
		strings.Contains(errStr, "SSLv3") ||
		strings.Contains(errStr, "handshake failure") {
		return UpstreamErrorSSL, errStr
	}

	// P2-55: 直接检查 *net.DNSError（不通过 net.Error 路径）
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return UpstreamErrorDNSFailure, errStr
	}

	// P2-55: 直接检查 *net.OpError（不通过 net.Error 路径）
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		if strings.Contains(errStr, "connection refused") {
			return UpstreamErrorConnectionRefused, errStr
		}
		if strings.Contains(errStr, "no route to host") {
			return UpstreamErrorNoRoute, errStr
		}
	}

	return UpstreamErrorUnknown, errStr
}

func getHTTPStatusCodeForError(errType UpstreamErrorType) int {
	switch errType {
	case UpstreamErrorTimeout:
		return http.StatusGatewayTimeout
	case UpstreamErrorConnectionRefused, UpstreamErrorDNSFailure, UpstreamErrorSSL, UpstreamErrorNoRoute:
		return http.StatusBadGateway
	default:
		return http.StatusBadGateway
	}
}

func getErrorMessageForType(errType UpstreamErrorType) string {
	switch errType {
	case UpstreamErrorTimeout:
		return "上游服务器响应超时"
	case UpstreamErrorConnectionRefused:
		return "无法连接到上游服务器 (连接被拒绝)"
	case UpstreamErrorDNSFailure:
		return "上游服务器DNS解析失败"
	case UpstreamErrorSSL:
		return "上游服务器SSL/TLS连接错误"
	case UpstreamErrorNoRoute:
		return "无法找到上游服务器路由"
	default:
		return "上游服务器连接失败"
	}
}
