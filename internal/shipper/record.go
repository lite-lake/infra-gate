// Package shipper 实现访问日志旁路发射器（内部PRD §4.2/§4.4.1）：
// 在访问日志点组装结构化记录 → req_class 打标 → 有界缓冲 → 批量 POST ingest。
//
// 硬约束（PRD D7）：纯旁路——缓冲满丢新保旧、发送失败有限退避后丢弃本批、
// 内部 panic 一律 recover 降级，任何路径绝不阻塞、绝不影响代理转发主链路，
// 等效于 shipper 不存在。零新增第三方依赖（纯 Go 标准库）。
package shipper

import "time"

// req_class 取值（内部PRD §4.4.1 打标表，判定顺序固定见 classify.go）
const (
	ReqClassProbe    = "probe"    // 健康检查/探测类（排除路径前缀命中）
	ReqClassDoc      = "doc"      // HTML 页面（响应 CT 前缀 text/html）
	ReqClassAPI      = "api"      // JSON / /api/ 路径
	ReqClassAsset    = "asset"    // 静态资源（图片/JS/CSS/字体/媒体/静态路径）
	ReqClassDownload = "download" // 字节流下载（octet-stream/pdf/压缩包等）
	ReqClassOther    = "other"    // 其余（RSC、txt、未知 CT 等）
)

// Record 单条网关访问记录：字段与 ingest 契约逐一对齐（内部PRD §6.1，
// Sec-Fetch 系透传字段为 内部PRD §2.1 增补），
// JSON tag 全部 snake_case，字段顺序与契约示例一致。请勿擅自增删字段——该结构
// 是与 app-tc-api 之间的线上契约（新增字段必须 omitempty 且旧字段零变动，双向向后兼容）。
type Record struct {
	Method      string `json:"method"`       // 请求方法
	Host        string `json:"host"`         // 请求 Host（去端口）
	Path        string `json:"path"`         // 请求路径
	Query       string `json:"query"`        // 原始查询串（token 清洗在 ingest 侧）
	Status      int    `json:"status"`       // 响应状态码
	Bytes       int    `json:"bytes"`        // 响应字节数（c.Writer.Size()）
	LatencyMs   int64  `json:"latency_ms"`   // 上游延迟（毫秒）
	RefHost     string `json:"ref_host"`     // Referer 归一化 host（无 Referer 为空）
	UserAgent   string `json:"user_agent"`   // User-Agent 原样上送（bot 判定全在 ingest 侧）
	ContentType string `json:"content_type"` // 响应 Content-Type（打标依据留痕）
	ClientIP    string `json:"client_ip"`    // 真实客户端 IP（ingest 侧即哈希，网关侧不落盘）
	TraceId     string `json:"trace_id"`     // 网关回填权威 ID（双网关去重键）
	ReqClass    string `json:"req_class"`    // 内容类别标签（shipper 打标）
	Ts          int64  `json:"ts"`           // 记录时间戳（UnixMilli）

	// 浏览器一致性头透传（内部PRD：C2 无 JS，请求头是 bot 判定唯一可信
	// 来源；字段集与 ingest 侧 BotJudgeInput 实际消费对齐。空串缺省省略，旧版
	// tc 收到多出字段会忽略、新版 tc 收到缺省字段按现状口径降级——双向向后兼容）
	SecFetchDest string `json:"sec_fetch_dest,omitempty"` // Sec-Fetch-Dest 原值
	SecFetchMode string `json:"sec_fetch_mode,omitempty"` // Sec-Fetch-Mode 原值
	SecFetchSite string `json:"sec_fetch_site,omitempty"` // Sec-Fetch-Site 原值
	SecCHUA      string `json:"sec_ch_ua,omitempty"`      // Sec-CH-UA 原值
}

// Envelope 批量信封：POST ingest 的请求体形状（内部PRD §6.1）
type Envelope struct {
	Node     string   `json:"node"`     // 上报网关节点名
	Requests []Record `json:"requests"` // 批量记录（<= batch_size 条）
}

// NewEnvelope 以 records 组装信封（浅拷贝语义：records 所有权移交信封）
func NewEnvelope(node string, records []Record) Envelope {
	return Envelope{Node: node, Requests: records}
}

// nowUnixMilli 时间戳来源注入点（单测可固定时钟断言 ts 字段）
var nowUnixMilli = func() int64 { return time.Now().UnixMilli() }
