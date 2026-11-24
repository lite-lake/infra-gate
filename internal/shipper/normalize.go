package shipper

// F12 shipper 契约对齐（内部PRD §4.12）：对端 app-tc-api ingest 有每条
// 4KB 冻结上限（GatewayDefaultMaxRecordBytes），单条超限整批 400 → 重试耗尽 →
// 500 条全丢；超长 URI/UA 不只放大内存还毒杀整批遥测。
//
// 本文件在 Ship() 入口 classifyFn 之前执行单点归一化（分类只用前缀/后缀，
// 截断不影响）：
//  1. 字段字节上限 + UTF-8 边界回扫 + 必须复制（Go 的 r.URL.Path 等是请求行
//     子串，纯切片会钉住整个 ~1MB 请求行分配）+ `...[truncated]` 标记；
//  2. 4KB 硬保证：字段上限不够（Go json.Marshal 对 <>& 做 6 倍转义膨胀，
//     1KB 全 < 路径序列化后 6KB 仍炸批）——归一化末尾做无分配投影尺寸校验
//     （线性扫描算精确转义后长度），超限迭代折半三大字段（Query→UA→Path 中
//     最大者，≤3 轮收敛），仍超丢弃由调用方计数。
//
// 全部阈值硬编码不进配置（D12：对端冻结契约，可配 = 可配错炸批）。

import (
	"strings"
	"unicode/utf8"
)

// 字段字节上限（全部 ≥ ingest 落库阈值，零额外落库损失）
const (
	MaxMethodLen      = 16
	MaxHostLen        = 255
	MaxPathLen        = 1024
	MaxQueryLen       = 1024
	MaxUserAgentLen   = 1024
	MaxRefHostLen     = 255
	MaxContentTypeLen = 128
	MaxTraceIdLen     = 64
)

// TruncatedMarker 截断标记（仓内既有约定）
const TruncatedMarker = "...[truncated]"

// maxRecordSerializedBytes 单条记录序列化后硬上限（4KB 契约减去信封开销与
// 安全余量；投影校验按转义后精确长度比较）
const maxRecordSerializedBytes = 3800

// NormalizeRecord 原地归一化单条记录。返回 false 表示折半兜底后仍超单条硬上限，
// 调用方应丢弃并计数（normalized_dropped）。
func NormalizeRecord(rec *Record) bool {
	rec.Method = truncateCopy(rec.Method, MaxMethodLen)
	rec.Host = truncateCopy(rec.Host, MaxHostLen)
	rec.Path = truncateCopy(rec.Path, MaxPathLen)
	rec.Query = truncateCopy(rec.Query, MaxQueryLen)
	rec.UserAgent = truncateCopy(rec.UserAgent, MaxUserAgentLen)
	rec.RefHost = truncateCopy(rec.RefHost, MaxRefHostLen)
	rec.ContentType = truncateCopy(rec.ContentType, MaxContentTypeLen)
	rec.TraceId = truncateCopy(rec.TraceId, MaxTraceIdLen)
	rec.SecFetchDest = truncateCopy(rec.SecFetchDest, MaxContentTypeLen)
	rec.SecFetchMode = truncateCopy(rec.SecFetchMode, MaxContentTypeLen)
	rec.SecFetchSite = truncateCopy(rec.SecFetchSite, MaxContentTypeLen)
	rec.SecCHUA = truncateCopy(rec.SecCHUA, MaxUserAgentLen)

	// 4KB 硬保证：转义后投影尺寸超限 → 迭代折半三大字段中最大者（≤3 轮收敛）
	for round := 0; round < 3 && projectedRecordSize(rec) > maxRecordSerializedBytes; round++ {
		switch largestTextField(rec) {
		case "query":
			rec.Query = halveCopy(rec.Query)
		case "user_agent":
			rec.UserAgent = halveCopy(rec.UserAgent)
		case "path":
			rec.Path = halveCopy(rec.Path)
		default:
			// 三大字段都已很短仍超限（理论上不可达：其余字段上限之和 + 固定
			// 开销远小于 3800）——保守丢弃
			return false
		}
	}
	return projectedRecordSize(rec) <= maxRecordSerializedBytes
}

// truncateCopy 截断到 max 字节（回扫 UTF-8 边界）+ 追加截断标记（标记含在
// max 内）+ 恒定复制（未超限也复制：请求行子串必须断开与 ~1MB 原分配的引用）
func truncateCopy(s string, max int) string {
	if s == "" {
		return s
	}
	if len(s) > max {
		end := max - len(TruncatedMarker)
		if end < 0 {
			end = 0
		}
		for end > 0 && !utf8.RuneStart(s[end]) {
			end--
		}
		return strings.Clone(s[:end] + TruncatedMarker)
	}
	return strings.Clone(s)
}

// halveCopy 折半裁剪（含标记语义同 truncateCopy）
func halveCopy(s string) string {
	half := len(s) / 2
	if half <= 0 {
		return ""
	}
	return truncateCopy(s, half)
}

// largestTextField 返回当前最长的三大字段名（Query → UA → Path 同长优先级）
func largestTextField(rec *Record) string {
	switch {
	case rec.Query != "" && len(rec.Query) >= len(rec.UserAgent) && len(rec.Query) >= len(rec.Path):
		return "query"
	case rec.UserAgent != "" && len(rec.UserAgent) >= len(rec.Path):
		return "user_agent"
	case rec.Path != "":
		return "path"
	default:
		return ""
	}
}

// projectedRecordSize 无分配计算单条记录 JSON 序列化后的近似精确字节数：
// 字符串字段按转义后长度（对齐 encoding/json：`"` `\` 2 字节、`<` `>` `&`
// 与控制字符 6 字节 \u00XX、其余 1 字节），数字字段按最大位数估计，结构
// 开销按保守常量。仅用于上限比较，方向性偏差只会更早触发折半（安全侧）。
func projectedRecordSize(rec *Record) int {
	// 结构开销：14 个字段的键名 + 引号/冒号/逗号 + Envelope 内嵌套缩进余量
	n := 420
	n += escapedLen(rec.Method)
	n += escapedLen(rec.Host)
	n += escapedLen(rec.Path)
	n += escapedLen(rec.Query)
	n += escapedLen(rec.UserAgent)
	n += escapedLen(rec.RefHost)
	n += escapedLen(rec.ContentType)
	n += escapedLen(rec.ClientIP)
	n += escapedLen(rec.TraceId)
	n += escapedLen(rec.ReqClass)
	n += escapedLen(rec.SecFetchDest)
	n += escapedLen(rec.SecFetchMode)
	n += escapedLen(rec.SecFetchSite)
	n += escapedLen(rec.SecCHUA)
	// 数字字段：status(3) bytes(8) latency_ms(8) ts(13)
	n += 32
	return n
}

// escapedLen 计算字符串 JSON 转义后的字节数（无分配线性扫描）
func escapedLen(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '"' || c == '\\':
			n += 2
		case c == '<' || c == '>' || c == '&':
			n += 6 // \u003c 形态
		case c < 0x20:
			n += 6 // \u0000 形态
		default:
			n++
		}
	}
	return n
}

// recordApproxBytes 缓冲字节预算的单条估算（原始字段长度和 + 固定开销；
// 与 Release 扣减必须用同一函数保证守恒）
func recordApproxBytes(r Record) int {
	return len(r.Method) + len(r.Host) + len(r.Path) + len(r.Query) +
		len(r.UserAgent) + len(r.RefHost) + len(r.ContentType) + len(r.ClientIP) +
		len(r.TraceId) + len(r.ReqClass) + len(r.SecFetchDest) + len(r.SecFetchMode) +
		len(r.SecFetchSite) + len(r.SecCHUA) + 256
}

// maxBatchProjectedBytes 批量提前 flush 阈值（硬编码，防误配炸契约：
// 500 条 × 近 4KB = 1.9MB body 会整批 400；768KB 预算 < 对端 1MB body 上限）
const maxBatchProjectedBytes = 768 * 1024

// maxBufferBytes 缓冲字节预算（32MB；超限丢新保旧）
const maxBufferBytes = 32 << 20
