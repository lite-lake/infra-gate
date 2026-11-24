package trace

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"time"

	"github.com/lite-lake/infra-gate/internal/infrastructs/logger"
	"github.com/lite-lake/infra-gate/internal/netutil"
)

// TraceIdHeader 是用于传递TraceID的HTTP请求/响应头（网关自有展示头）
const TraceIdHeader = "X-Lite-Gate-Trace-Id"

// TraceParentHeader 是 W3C Trace Context 标准传播头（仅请求侧传播，响应不携带，
// 内部PRD 决策 D7）
const TraceParentHeader = "traceparent"

// TraceStateHeader W3C vendor 扩展头（本期不生成、仅响应侧过滤，PRD §11.4）
const TraceStateHeader = "tracestate"

// defaultTraceFlags 新生成 traceparent 的默认 flags（01 = recorded）
const defaultTraceFlags = "01"

// W3C traceparent 定长字段位（00-<32hex>-<16hex>-<2hex>，共 55 字符小写 hex）
const (
	traceParentLen   = 55
	traceParentVer   = "00"
	traceIdHexLen    = 32
	parentIdHexLen   = 16
	traceFlagsHexLen = 2
)

// traceIdPattern 兼容采信校验（阶段二）：旧格式 [A-Za-z0-9]{1,64}，
// 32 位小写 hex 权威格式天然为其子集（内部PRD §5.1 兼容窗口）
var traceIdPattern = regexp.MustCompile(`^[A-Za-z0-9]{1,64}$`)

// hexLowerPattern 严格小写 hex（W3C trace-id/parent-id/flags 均要求小写）
var hexLowerPattern = regexp.MustCompile(`^[0-9a-f]+$`)

// GetTraceIdFromRequest 从请求中获取TraceID
// 仅读头（供 proxy/ws/访问日志在回填后取值），不做信任判定——信任判定在 ResolveTraceId
func GetTraceIdFromRequest(r *http.Request) string {
	if traceId := r.Header.Get(TraceIdHeader); traceId != "" {
		if traceIdPattern.MatchString(traceId) {
			return traceId
		}
	}
	return ""
}

// ResolveTraceId 判定本跳权威 Trace ID（信任判定 + 采信/生成，内部PRD §4.1）：
//   - 直连对端 ∈ trusted_proxies → 按 traceparent（W3C 校验）→ X-Lite-Gate-Trace-Id
//     （格式校验）顺序采信，均无/非法则重新生成；
//   - trusted_proxies 为空或对端不在网段 → 边缘语义：无视入站，恒重新生成（fail-safe）。
//
// reused 表示是否采信了入站 ID。被拒的入站值经 GetDefaultLogger 记 Debug（值转义，D5）；
// 需要日志落到具体实例 logger 时使用 ResolveTraceContext。
func ResolveTraceId(r *http.Request, trustedNets []*net.IPNet) (traceId string, reused bool) {
	traceId, _, reused = ResolveTraceContext(r, trustedNets, logger.GetDefaultLogger())
	return traceId, reused
}

// ResolveTraceContext 同 ResolveTraceId，额外返回采信/生成对应的 traceparent flags
// （采信 traceparent 时继承其 flags，其余场景为默认 01，供回填阶段二传播头使用），
// 并将 D5 被拒日志写入调用方提供的 logger。
func ResolveTraceContext(r *http.Request, trustedNets []*net.IPNet, log logger.ILogger) (traceId, flags string, reused bool) {
	if isTrustedDirectPeer(r.RemoteAddr, trustedNets) {
		// a. traceparent 优先（W3C 严格校验）
		if tp := r.Header.Get(TraceParentHeader); tp != "" {
			if tid, _, f, ok := ParseTraceParent(tp); ok {
				return tid, f, true
			}
			logRejected(TraceParentHeader, tp, log)
		}
		// b. X-Lite-Gate-Trace-Id（旧格式兼容采信窗口）
		if v := r.Header.Get(TraceIdHeader); v != "" {
			if isValidTraceIdValue(v) {
				return v, defaultTraceFlags, true
			}
			logRejected(TraceIdHeader, v, log)
		}
	} else {
		// 边缘语义：入站 Trace 头一律无视（存在即记 Debug，D5）
		if v := r.Header.Get(TraceIdHeader); v != "" {
			logRejected(TraceIdHeader, v, log)
		}
		if tp := r.Header.Get(TraceParentHeader); tp != "" {
			logRejected(TraceParentHeader, tp, log)
		}
	}
	// c. 重新生成（含受信但均无/非法、不受信、未配置 trusted_proxies）
	return GenerateTraceId(), defaultTraceFlags, false
}

// isTrustedDirectPeer 判断直连对端（TCP RemoteAddr）是否命中 trusted_proxies 网段。
// trustedNets 为空恒为 false（公网边缘 gate 的 fail-safe 边缘语义），
// 判定口径与 proxy.isTrustedDirectPeer / netutil.ParseTrustedProxies 一致。
func isTrustedDirectPeer(remoteAddr string, trustedNets []*net.IPNet) bool {
	if len(trustedNets) == 0 {
		return false
	}
	directIP := remoteAddr
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		directIP = host
	}
	directNetIP := net.ParseIP(directIP)
	return directNetIP != nil && netutil.IsIPInNetworks(directNetIP, trustedNets)
}

// logRejected 记录被拒的入站 Trace 头（D5：Debug 级别，值经 FormatTraceId 转义，
// 不新增统计面、避免攻击刷屏；防日志注入回归）
func logRejected(header, value string, log logger.ILogger) {
	log.Debug("Rejected untrusted inbound trace header, regenerating",
		logger.NewField("header", header),
		logger.NewField("value", FormatTraceId(value)))
}

// GenerateTraceId 生成权威 Trace ID：crypto/rand 16 字节 → 32 位小写 hex（W3C trace-id 格式）。
// 全零非法（W3C §a），命中则重试；crypto/rand 失败（极罕见）回退时间戳保证唯一性，
// 回退值同样满足 32 位小写 hex 格式。
func GenerateTraceId() string {
	b := make([]byte, 16)
	for i := 0; i < 8; i++ {
		if _, err := rand.Read(b); err != nil {
			break
		}
		id := hex.EncodeToString(b)
		if !isAllZeroHex(id) {
			return id
		}
	}
	// crypto/rand 失败/极端全零重试耗尽：时间戳按字节回退（唯一性优先），格式仍合规
	t := time.Now().UnixNano()
	for i := range b {
		b[i] = byte(t >> (uint(i%8) * 8))
	}
	return hex.EncodeToString(b)
}

// ParseTraceParent 严格校验 W3C traceparent（版本 00、55 字符定长、全小写 hex、
// trace-id/parent-id 非全零），合法时返回 trace-id、parent-id 与 flags。
// 非法返回 ok=false（调用方应忽略该头——W3C §3.3 处理规则）。
func ParseTraceParent(tp string) (traceId, parentId, flags string, ok bool) {
	if len(tp) != traceParentLen {
		return "", "", "", false
	}
	if tp[:2] != traceParentVer ||
		tp[2] != '-' || tp[35] != '-' || tp[52] != '-' {
		return "", "", "", false
	}
	traceId = tp[3:35]
	parentId = tp[36:52]
	flags = tp[53:traceParentLen]
	if !isLowerHex(traceId) || !isLowerHex(parentId) || !isLowerHex(flags) {
		return "", "", "", false
	}
	if isAllZeroHex(traceId) || isAllZeroHex(parentId) {
		return "", "", "", false
	}
	return traceId, parentId, flags, true
}

// BuildTraceParent 以权威 traceId 构建本跳出站 traceparent（版本 00、每跳新生成
// 16hex parent-id）。inheritedFlags 为空/非法时使用默认 01；traceId 不满足 W3C
// trace-id 格式（如旧格式兼容采信的 8 位 ID）时返回空串，调用方应跳过该头——
// 宁缺勿假，链路仍由 X-Lite-Gate-Trace-Id 维持。
func BuildTraceParent(traceId, inheritedFlags string) string {
	if !isValidW3CTraceId(traceId) {
		return ""
	}
	flags := defaultTraceFlags
	if len(inheritedFlags) == traceFlagsHexLen && isLowerHex(inheritedFlags) {
		flags = inheritedFlags
	}
	parentId := generateHex(parentIdHexLen / 2)
	for i := 0; i < 8 && isAllZeroHex(parentId); i++ {
		parentId = generateHex(parentIdHexLen / 2)
	}
	return traceParentVer + "-" + traceId + "-" + parentId + "-" + flags
}

// FormatTraceId 用于在日志中安全格式化 TraceID（防止日志注入）
func FormatTraceId(traceId string) string {
	if len(traceId) > 64 {
		return fmt.Sprintf("%s...[truncated]", traceId[:61])
	}
	return traceId
}

// isValidTraceIdValue X-Lite-Gate-Trace-Id 采信校验：旧格式 [A-Za-z0-9]{1,64}，
// 但 32 位全零 hex（W3C 非法值）除外
func isValidTraceIdValue(v string) bool {
	if !traceIdPattern.MatchString(v) {
		return false
	}
	if len(v) == traceIdHexLen && isLowerHex(v) && isAllZeroHex(v) {
		return false
	}
	return true
}

// isValidW3CTraceId 判断是否满足 W3C trace-id：32 位小写 hex 且非全零
func isValidW3CTraceId(v string) bool {
	return len(v) == traceIdHexLen && isLowerHex(v) && !isAllZeroHex(v)
}

// isLowerHex 判断是否全为小写 hex 字符（非空）
func isLowerHex(s string) bool {
	return hexLowerPattern.MatchString(s)
}

// isAllZeroHex 判断是否全为 '0'（W3C 非法值判定）
func isAllZeroHex(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] != '0' {
			return false
		}
	}
	return true
}

// generateHex 生成 n 字节 crypto/rand 的小写 hex（2n 字符）；crypto/rand 失败时
// 回退时间戳按字节填充（非全零，保证 parent-id/trace-id 的 W3C 非全零约束可满足）
func generateHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t := time.Now().UnixNano()
		for i := range b {
			b[i] = byte(t >> (uint(i%8) * 8))
		}
	}
	return hex.EncodeToString(b)
}
