package waf

import (
	"crypto/rand"
	"math/big"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

const (
	maxEvents = 200
)

// 单个值的最大截断长度
const maxValueLen = 1024

// instanceIDCharset is the character set used for generating random instance IDs
const instanceIDCharset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

const instanceIDLen = 8

// generateInstanceID generates a random 8-character alphanumeric string.
// Used as a per-process-lifetime prefix for WAF event IDs to ensure uniqueness
// across multiple WAF instances running in the same process.
func generateInstanceID() string {
	b := make([]byte, instanceIDLen)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(instanceIDCharset))))
		if err != nil {
			// Fallback: should never happen with crypto/rand
			b[i] = instanceIDCharset[i%len(instanceIDCharset)]
			continue
		}
		b[i] = instanceIDCharset[n.Int64()]
	}
	return string(b)
}

// EventType 事件类型：阻断或检测
type EventType string

const (
	EventTypeBlock  EventType = "block"
	EventTypeDetect EventType = "detect"
)

// MatchedVar 规则匹配的变量
type MatchedVar struct {
	Variable string `json:"variable"`
	Key      string `json:"key"`
	Value    string `json:"value"`
	Message  string `json:"message"`
	Data     string `json:"data"`
}

// RuleMatchDetail 规则匹配详情，由 ErrorCallback 提取
type RuleMatchDetail struct {
	RuleID       int          `json:"rule_id"`
	Message      string       `json:"message"`
	Severity     string       `json:"severity"`
	AuditLog     string       `json:"audit_log"`
	MatchedVars  []MatchedVar `json:"matched_vars"`
	RuleTags     []string     `json:"rule_tags"`
	RuleOperator string       `json:"rule_operator"`
	RuleFile     string       `json:"rule_file"`
	RuleLine     int          `json:"rule_line"`
}

// RequestSnapshot 请求快照（Body 为原文≤4KB：脱敏延迟到事件落库时，F8）
type RequestSnapshot struct {
	Headers      map[string]string `json:"headers"`
	Body         string            `json:"body"`
	ContentType  string            `json:"content_type"`
	QueryString  string            `json:"query_string"`
	Protocol     string            `json:"protocol"`
	Host         string            `json:"host"`
	TraceID      string            `json:"trace_id"`
	ResponseCode int               `json:"response_code"`
}

// WAFEvent 记录一次 WAF 事件（阻断或检测）
type WAFEvent struct {
	ID       int64     `json:"id"`
	Time     time.Time `json:"time"`
	Type     EventType `json:"type"`
	ClientIP string    `json:"client_ip"`
	Method   string    `json:"method"`
	Path     string    `json:"path"`
	HostName string    `json:"host_name"`
	RuleID   int       `json:"rule_id"`
	Message  string    `json:"message"`
	Severity string    `json:"severity"`
	TraceID  string    `json:"trace_id"`
	// AuditLog 字段已移除（F8.3/D8，内部PRD §4.8.3）：与 MatchedVars
	// 信息重复且为已拼接字符串无法可靠掩码
	MatchedVars  []MatchedVar      `json:"matched_vars,omitempty"`
	RuleTags     []string          `json:"rule_tags,omitempty"`
	RuleOperator string            `json:"rule_operator,omitempty"`
	RuleFile     string            `json:"rule_file,omitempty"`
	RuleLine     int               `json:"rule_line,omitempty"`
	ReqHeaders   map[string]string `json:"request_headers,omitempty"`
	// ReqBody 为脱敏后形态（F8：recordEvent 单点漏斗脱敏）；BodyLen/BodyHash
	// 为原文的长度与加盐 HMAC-SHA256（进程随机盐，离线字典失效，进程内可比对）
	ReqBody        string `json:"request_body,omitempty"`
	ReqContentType string `json:"request_content_type,omitempty"`
	BodyLen        int    `json:"body_len,omitempty"`
	BodyHash       string `json:"body_hash,omitempty"`
	QueryString    string `json:"query_string,omitempty"`
	Protocol       string `json:"protocol,omitempty"`
	ResponseCode   int    `json:"response_code,omitempty"`
}

// HostStats 单个虚拟主机的 WAF 统计
type HostStats struct {
	HostName      string `json:"host_name"`
	TotalBlocks   uint64 `json:"total_blocks"`
	TotalRequests uint64 `json:"total_requests"`
	TotalDetected uint64 `json:"total_detected"`
	TotalBlocked  uint64 `json:"total_blocked"`
}

// StatsSnapshot WAF 统计数据快照
type StatsSnapshot struct {
	TotalRequests   uint64      `json:"total_requests"`
	TotalDetected   uint64      `json:"total_detected"`
	TotalBlocked    uint64      `json:"total_blocked"`
	TotalPassed     uint64      `json:"total_passed"`
	BlocksByHost    []HostStats `json:"blocks_by_host"`
	LastBlockTime   *time.Time  `json:"last_block_time"`
	LastBlockIP     string      `json:"last_block_ip"`
	LastBlockPath   string      `json:"last_block_path"`
	LastBlockRuleID int         `json:"last_block_rule_id"`
	LastBlockMsg    string      `json:"last_block_message"`
	LastDetectTime  *time.Time  `json:"last_detect_time"`
	LastDetectIP    string      `json:"last_detect_ip"`
	LastDetectPath  string      `json:"last_detect_path"`
}

// statsTracker WAF 统计追踪器
// 每个 waf.Middleware 实例持有一个，按虚拟主机名区分
type statsTracker struct {
	// 每个 host 的请求计数（经过 WAF 检查的请求）
	hostRequests sync.Map // map[string]*uint64

	// 每个 host 的拦截计数
	hostCounts sync.Map // map[string]*uint64

	// 每个 host 的检测计数（detect 模式下命中规则但放行）
	hostDetects sync.Map // map[string]*uint64

	// 全局最近一次拦截信息
	lastMu      sync.RWMutex
	lastTime    time.Time
	lastIP      string
	lastPath    string
	lastRuleID  int
	lastMessage string

	// 全局最近一次检测信息
	lastDetectMu   sync.RWMutex
	lastDetectTime time.Time
	lastDetectIP   string
	lastDetectPath string

	// instanceID is a random 8-char prefix generated once per process lifetime.
	// It ensures event IDs are unique across multiple WAF instances running in
	// the same process (e.g. different hosts with different WAF configs).
	// The high 32 bits of eventSeq encode the instanceID hash; the low 32 bits
	// are a monotonically increasing sequence number.
	instanceID string

	// 事件 ID 序列号
	eventSeq int64

	// 环形缓冲区
	eventsMu  sync.RWMutex
	events    []WAFEvent
	eventsIdx int
}

func newStatsTracker() *statsTracker {
	return &statsTracker{
		events:     make([]WAFEvent, 0, maxEvents),
		instanceID: generateInstanceID(),
	}
}

// recordRequest 记录一个经过 WAF 检查的请求
func (st *statsTracker) recordRequest(hostName string) {
	st.atomicInc(&st.hostRequests, hostName)
}

// recordDetect 记录一次检测事件（detect 模式下命中规则但放行）
func (st *statsTracker) recordDetect(hostName, clientIP, method, path string) {
	st.atomicInc(&st.hostDetects, hostName)

	st.lastDetectMu.Lock()
	st.lastDetectTime = time.Now()
	st.lastDetectIP = clientIP
	st.lastDetectPath = path
	st.lastDetectMu.Unlock()
}

func (st *statsTracker) recordBlock(hostName, clientIP, method, path string) uint64 {
	total := st.atomicInc(&st.hostCounts, hostName)

	// 更新 last block 信息
	st.lastMu.Lock()
	st.lastTime = time.Now()
	st.lastIP = clientIP
	st.lastPath = path
	st.lastMu.Unlock()

	return total
}

// updateLastBlockRule updates the last block rule ID and message.
// Called from intercept403Writer when a WAF block actually occurs (not from
// ErrorCallback), ensuring lastRuleID/lastMessage reflect blocks only, not detects.
// P2-31: 此方法与 recordBlock 在同一调用者中被连续调用，存在快照读到
// 新 IP + 旧 RuleID 的窗口。保留单独方法用于向后兼容，但推荐使用 recordBlockWithDetail。
func (st *statsTracker) updateLastBlockRule(detail RuleMatchDetail) {
	st.lastMu.Lock()
	st.lastRuleID = detail.RuleID
	st.lastMessage = detail.Message
	st.lastMu.Unlock()
}

// recordBlockWithDetail 原子地记录 block 事件和规则详情，避免快照读到不一致状态
func (st *statsTracker) recordBlockWithDetail(hostName, clientIP, method, path string, detail RuleMatchDetail) uint64 {
	total := st.atomicInc(&st.hostCounts, hostName)

	// P2-31: 在同一锁内更新所有 last block 字段，保证快照一致性
	st.lastMu.Lock()
	st.lastTime = time.Now()
	st.lastIP = clientIP
	st.lastPath = path
	st.lastRuleID = detail.RuleID
	st.lastMessage = detail.Message
	st.lastMu.Unlock()

	return total
}

// recordRuleMatchDetail records rule match detail for the global stats tracker.
// Note: this is called from ErrorCallback for every rule match (both block and
// detect modes). It does NOT update lastRuleID/lastMessage — those are updated
// only on actual blocks via updateLastBlockRule to avoid detect pollution.
func (st *statsTracker) recordRuleMatchDetail(detail RuleMatchDetail) {
	// Intentionally a no-op for the global tracker: per-request state is now
	// tracked via context (requestRuleMatch). This method is retained for
	// ErrorCallback compatibility but does not modify last block info.
}

// nextEventID generates a globally unique event ID.
// H36: 使用 crypto/rand 生成 32 位 instance hash，避免弱哈希函数碰撞风险
// The high 32 bits of eventSeq encode the instanceID hash; the low 32 bits
// are a monotonically increasing sequence number.
func (st *statsTracker) nextEventID() int64 {
	seq := atomic.AddInt64(&st.eventSeq, 1)
	// H36: 使用 FNV-1a 替代简单 hash*31，减少碰撞
	var hash uint32 = 2166136261
	for _, c := range st.instanceID {
		hash ^= uint32(c)
		hash *= 16777619
	}
	return (int64(hash) << 32) | (seq & 0xFFFFFFFF)
}

// getInstanceID returns the tracker's instance ID (for logging/debugging)
func (st *statsTracker) getInstanceID() string {
	return st.instanceID
}

func (st *statsTracker) recordEvent(ev WAFEvent) {
	// F8（内部PRD §4.8.1）：脱敏延迟到事件落库时——本方法是全部事件
	// 构造点（block 内联构造与 detect buildEvent）的唯一汇入漏斗，未来新增
	// 构造点也无法漏脱敏；99.99% 未命中请求零新增开销（快照早已存在）
	rawBody := ev.ReqBody
	ev.BodyLen = len(rawBody)
	ev.BodyHash = BodyHash(rawBody)
	ev.ReqBody = SanitizeRequestBody(rawBody, ev.ReqContentType)
	maskMatchedVars(ev.MatchedVars)
	st.eventsMu.Lock()
	defer st.eventsMu.Unlock()

	if len(st.events) < maxEvents {
		st.events = append(st.events, ev)
	} else {
		st.events[st.eventsIdx] = ev
		st.eventsIdx = (st.eventsIdx + 1) % maxEvents
	}
}

// atomicInc 原子递增指定 map 中的 host 计数
func (st *statsTracker) atomicInc(m *sync.Map, hostName string) uint64 {
	var counter *uint64
	val, _ := m.Load(hostName)
	if val == nil {
		c := uint64(0)
		val, _ = m.LoadOrStore(hostName, &c)
		counter = val.(*uint64)
	} else {
		counter = val.(*uint64)
	}
	return atomic.AddUint64(counter, 1)
}

func (st *statsTracker) snapshot() StatsSnapshot {
	snap := StatsSnapshot{}

	// P2-30: 先收集所有 host 名，然后按 host 读取三类计数器
	// 减少三次独立 Range 导致的不一致窗口
	hostMap := make(map[string]*HostStats)

	collectHost := func(hostName string) {
		if _, exists := hostMap[hostName]; !exists {
			hostMap[hostName] = &HostStats{HostName: hostName}
		}
	}

	// 收集所有出现过的 host 名
	st.hostRequests.Range(func(key, _ any) bool {
		collectHost(key.(string))
		return true
	})
	st.hostDetects.Range(func(key, _ any) bool {
		collectHost(key.(string))
		return true
	})
	st.hostCounts.Range(func(key, _ any) bool {
		collectHost(key.(string))
		return true
	})

	// 按 host 原子读取三类计数器
	for hostName, hs := range hostMap {
		if val, ok := st.hostRequests.Load(hostName); ok {
			c := atomic.LoadUint64(val.(*uint64))
			hs.TotalRequests = c
			snap.TotalRequests += c
		}
		if val, ok := st.hostDetects.Load(hostName); ok {
			c := atomic.LoadUint64(val.(*uint64))
			hs.TotalDetected = c
			snap.TotalDetected += c
		}
		if val, ok := st.hostCounts.Load(hostName); ok {
			c := atomic.LoadUint64(val.(*uint64))
			hs.TotalBlocked = c
			snap.TotalBlocked += c
		}
	}

	// 转换为 slice
	for _, hs := range hostMap {
		snap.BlocksByHost = append(snap.BlocksByHost, *hs)
	}

	// 放行数 = 总请求数 - 阻断数 - 检测数
	// Clamp to 0 to prevent uint64 underflow in high-concurrency non-atomic snapshot windows
	totalBlockedAndDetected := snap.TotalBlocked + snap.TotalDetected
	if snap.TotalRequests >= totalBlockedAndDetected {
		snap.TotalPassed = snap.TotalRequests - totalBlockedAndDetected
	} else {
		snap.TotalPassed = 0
	}

	// last block
	st.lastMu.RLock()
	if !st.lastTime.IsZero() {
		t := st.lastTime
		snap.LastBlockTime = &t
	}
	snap.LastBlockIP = st.lastIP
	snap.LastBlockPath = st.lastPath
	snap.LastBlockRuleID = st.lastRuleID
	snap.LastBlockMsg = st.lastMessage
	st.lastMu.RUnlock()

	// last detect
	st.lastDetectMu.RLock()
	if !st.lastDetectTime.IsZero() {
		t := st.lastDetectTime
		snap.LastDetectTime = &t
	}
	snap.LastDetectIP = st.lastDetectIP
	snap.LastDetectPath = st.lastDetectPath
	st.lastDetectMu.RUnlock()

	return snap
}

func (st *statsTracker) recentEvents(limit int) []WAFEvent {
	st.eventsMu.RLock()
	defer st.eventsMu.RUnlock()

	n := len(st.events)
	if n == 0 {
		return []WAFEvent{}
	}

	if limit <= 0 || limit > n {
		limit = n
	}

	result := make([]WAFEvent, 0, limit)
	if len(st.events) < maxEvents {
		// 未满，按写入顺序从后取最新的 limit 条
		start := n - limit
		if start < 0 {
			start = 0
		}
		result = append(result, st.events[start:]...)
		return result
	}

	// 已满，eventsIdx 指向下一条要写入的位置（即最老的事件）
	// 最新的事件在 (eventsIdx - 1 + maxEvents) % maxEvents
	// 返回最新的 limit 条，按时间顺序（旧到新）排列
	start := (st.eventsIdx - limit + maxEvents) % maxEvents
	for i := 0; i < limit; i++ {
		idx := (start + i) % maxEvents
		result = append(result, st.events[idx])
	}
	return result
}

// findEvent 按 ID 查找事件
func (st *statsTracker) findEvent(id int64) (WAFEvent, bool) {
	st.eventsMu.RLock()
	defer st.eventsMu.RUnlock()

	for _, ev := range st.events {
		if ev.ID == id {
			return ev, true
		}
	}
	return WAFEvent{}, false
}

// truncateString 截断字符串到最大字节长度，确保不截断多字节 UTF-8 字符
// O(1) relative to input size: only scans back at most 3 bytes from max to find
// a valid UTF-8 rune boundary. Critical because callers (WAF ErrorCallback) may
// pass multi-MB strings — coraza's RequestBodyLimit defaults to 128MB, and the
// previous O(n^2) implementation could peg a CPU core for hours/days on large
// matched values, causing the sustained 100% CPU issue.
func truncateString(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 0 {
		return ""
	}
	end := max
	for end > 0 && !utf8.RuneStart(s[end]) {
		end--
	}
	return s[:end]
}
