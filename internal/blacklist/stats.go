package blacklist

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/lite-lake/infra-gate/internal/config"
)

const (
	// maxEvents 事件环形缓冲容量（仿 waf/stats.go）
	maxEvents = 200
	// maxEventIPs 事件限速 map 的容量上限，超过时清理过期项防膨胀
	maxEventIPs = 10000
	// recentHitWindow recent_hits 的小时桶数量（最近 24 小时）
	recentHitWindow = 24
)

// BlacklistEvent 一次黑名单命中事件
type BlacklistEvent struct {
	Time     time.Time `json:"time"`
	ClientIP string    `json:"client_ip"`
	Matched  string    `json:"matched"`
	Mode     string    `json:"mode"`
	Host     string    `json:"host"`
	Path     string    `json:"path"`
	TraceID  string    `json:"trace_id"`
}

// SourceStat 单个数据源的统计信息
type SourceStat struct {
	Name           string `json:"name"`
	URL            string `json:"url"`
	Entries        int    `json:"entries"`
	InvalidLines   int    `json:"invalid_lines"`
	OversizedLines int    `json:"oversized_lines"` // F9.1：单条前缀超限被跳过的行数
}

// StatsSnapshot 黑名单统计快照（供 admin API 注入）
type StatsSnapshot struct {
	Enabled         bool         `json:"enabled"`
	DefaultMode     string       `json:"default_mode"`
	Sources         []SourceStat `json:"sources"`
	TotalEntries    int          `json:"total_entries"`
	LastSuccessAt   *time.Time   `json:"last_success_at"`
	LastAttemptAt   *time.Time   `json:"last_attempt_at"`
	LoadedFromCache bool         `json:"loaded_from_cache"`
	// F9（additive）：形态围栏观测
	CoveredV4Addrs      uint64  `json:"covered_v4_addrs"`
	V4CoveragePercent   float64 `json:"v4_coverage_percent"`
	V6CIDREntries       int     `json:"v6_cidr_entries"`
	OversizedLinesTotal int     `json:"oversized_lines_total"`
	HitTotalBlock       uint64  `json:"hit_total_block"`
	HitTotalDetect      uint64  `json:"hit_total_detect"`
	RecentHits          uint64  `json:"recent_hits"`
}

// hourBucket 一个小时桶的命中计数（hour 为 unix 小时数，用于过期判断与桶轮转）
type hourBucket struct {
	hour  int64
	count uint64
}

// statsTracker 黑名单统计与事件追踪器。
// 并发模式：命中总计数用 atomic（统计计数不受事件限速影响，全记）；
// 事件环形缓冲 / 小时桶 / 按 IP 限速 map 用单一 mutex，临界区均为纯内存短操作。
type statsTracker struct {
	mu        sync.Mutex
	events    []BlacklistEvent
	eventsIdx int
	buckets   [recentHitWindow]hourBucket
	eventIPs  map[string]int64 // clientIP -> 上次记录事件的 unix 分钟

	// lastEventTime 环形缓冲中最新一条事件的时间（锁内维护），
	// 用于钳制事件时间戳单调不减，保证 admin 事件表展示顺序与时间字段一致
	lastEventTime time.Time

	hitBlock  atomic.Uint64
	hitDetect atomic.Uint64
}

func newStatsTracker() *statsTracker {
	return &statsTracker{
		events:   make([]BlacklistEvent, 0, maxEvents),
		eventIPs: make(map[string]int64),
	}
}

// recordHit 记录一次黑名单命中（统计计数总是记录；事件先过按 IP 限速）
func (st *statsTracker) recordHit(mode, clientIP, matched, host, path, traceID string) {
	st.recordHitAt(mode, clientIP, matched, host, path, traceID, time.Now())
}

// recordHitAt recordHit 的可注入时钟版本（测试用）。
// 限速判定与事件写入在同一次锁内完成：环形缓冲的写入顺序与限速判定顺序一致，
// 消除 admin 事件表的微秒级乱序。
func (st *statsTracker) recordHitAt(mode, clientIP, matched, host, path, traceID string, now time.Time) {
	// 统计计数全记（不受限速影响）
	if mode == config.BlacklistModeDetect {
		st.hitDetect.Add(1)
	} else {
		// block（disabled 模式不会调用 RecordHit）
		st.hitBlock.Add(1)
	}

	hour := now.Unix() / 3600
	minute := now.Unix() / 60

	st.mu.Lock()
	idx := hour % recentHitWindow
	if st.buckets[idx].hour != hour {
		st.buckets[idx] = hourBucket{hour: hour}
	}
	st.buckets[idx].count++

	// 事件记录限速：每 IP 每分钟最多 1 条，防扫描器刷爆环形缓冲与日志
	allowed := true
	if last, ok := st.eventIPs[clientIP]; ok && last == minute {
		allowed = false
	} else {
		st.eventIPs[clientIP] = minute
	}
	if len(st.eventIPs) > maxEventIPs {
		st.pruneEventIPsLocked(minute)
		if len(st.eventIPs) > maxEventIPs {
			// prune 后仍超限（大量同分钟不同 IP）：清空整个 map。
			// 限速语义允许有损——清空后各 IP 可再各记 1 条，但 map 不会无限膨胀
			st.eventIPs = make(map[string]int64)
		}
	}

	if allowed {
		st.appendEventLocked(BlacklistEvent{
			Time:     now,
			ClientIP: clientIP,
			Matched:  matched,
			Mode:     mode,
			Host:     host,
			Path:     path,
			TraceID:  traceID,
		})
	}
	st.mu.Unlock()
}

// pruneEventIPsLocked 清理限速 map 中的过期项（调用方须持有 mu）
func (st *statsTracker) pruneEventIPsLocked(currentMinute int64) {
	for ip, minute := range st.eventIPs {
		if minute < currentMinute {
			delete(st.eventIPs, ip)
		}
	}
}

// appendEventLocked 写入事件环形缓冲（调用方须持有 mu）。
// 时间戳在锁外捕获，并发下获取顺序可能与锁序颠倒；用上一条事件时间兜底钳制，
// 保证缓冲内时间戳单调不减，admin 事件表不会出现乱序。
func (st *statsTracker) appendEventLocked(ev BlacklistEvent) {
	if !ev.Time.After(st.lastEventTime) {
		ev.Time = st.lastEventTime
	}
	st.lastEventTime = ev.Time

	if len(st.events) < maxEvents {
		st.events = append(st.events, ev)
	} else {
		st.events[st.eventsIdx] = ev
		st.eventsIdx = (st.eventsIdx + 1) % maxEvents
	}
}

// recentEvents 返回最新的 limit 条事件（按时间顺序，旧到新）
func (st *statsTracker) recentEvents(limit int) []BlacklistEvent {
	st.mu.Lock()
	defer st.mu.Unlock()

	n := len(st.events)
	if n == 0 {
		return []BlacklistEvent{}
	}

	if limit <= 0 || limit > n {
		limit = n
	}

	result := make([]BlacklistEvent, 0, limit)
	if len(st.events) < maxEvents {
		start := n - limit
		result = append(result, st.events[start:]...)
		return result
	}

	// 已满，eventsIdx 指向下一条要写入的位置（即最老的事件）
	start := (st.eventsIdx - limit + maxEvents) % maxEvents
	for i := 0; i < limit; i++ {
		idx := (start + i) % maxEvents
		result = append(result, st.events[idx])
	}
	return result
}

// recentHits 返回最近 24 小时（当前小时 + 前 23 个小时桶）的命中总数（block+detect）
func (st *statsTracker) recentHits() uint64 {
	return st.recentHitsAt(time.Now())
}

// recentHitsAt recentHits 的可注入时钟版本（测试用，避免真实时钟跨小时边界引入竞态）
func (st *statsTracker) recentHitsAt(now time.Time) uint64 {
	currentHour := now.Unix() / 3600

	st.mu.Lock()
	defer st.mu.Unlock()

	var total uint64
	for _, b := range st.buckets {
		if b.hour >= currentHour-(recentHitWindow-1) {
			total += b.count
		}
	}
	return total
}

// hitCounts 返回 block/detect 命中总计数
func (st *statsTracker) hitCounts() (block, detect uint64) {
	return st.hitBlock.Load(), st.hitDetect.Load()
}
