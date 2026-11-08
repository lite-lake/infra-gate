package resguard

// per-IP 令牌桶限速器（F1b，内部PRD §4.1.2）：连续补充模型（按流逝时间
// 精确补 token，无需定时器），挂 handleRequestForPort 黑名单之后，超速 429 +
// Retry-After: 1。与 auth faillock 正交（后者是登录失败惩罚性锁定，此处是全请求
// 速率治理）。容量上限 + 惰性清理 + 淘汰最旧沿用 auth/ratelimit.go 模式。

import (
	"net"
	"sync"
	"time"
)

const (
	// rateMaxEntries 桶表容量上限；超限先惰性清理，仍超限淘汰最旧
	rateMaxEntries = 65536
	// rateIdleTTL 未活跃桶的闲置回收时长
	rateIdleTTL = 10 * time.Minute
)

// tokenBucket 单个 IP 的令牌桶（连续补充）
type tokenBucket struct {
	tokens   float64
	lastSeen time.Time
}

// RateLimiter per-IP 令牌桶限速器。rate = token/秒，burst = 桶容量；
// 构造后参数不可变（无锁读取安全）。
type RateLimiter struct {
	rate  float64
	burst float64

	exemptNets []*net.IPNet
	mu         sync.Mutex
	buckets    map[string]*tokenBucket
}

// NewRateLimiter 构造限速器；rate/burst <=0 由调用方（config 层）clamp 为缺省，
// 此处防御性回落同款缺省（50 rps / 100 burst）。exempt 为豁免网段（不限速）。
func NewRateLimiter(rate float64, burst int, exempt []*net.IPNet) *RateLimiter {
	if rate <= 0 {
		rate = 50
	}
	if burst <= 0 {
		burst = 100
	}
	return &RateLimiter{
		rate:       rate,
		burst:      float64(burst),
		exemptNets: exempt,
		buckets:    make(map[string]*tokenBucket),
	}
}

// Allow 判定该 IP 当前是否放行一次请求（连续补充：elapsed × rate 补入桶，
// 上限 burst）。豁免网段恒放行（不记账）。now 由调用方传入便于测试。
func (l *RateLimiter) Allow(ip string, now time.Time) bool {
	if l.isExempt(ip) {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.buckets) >= rateMaxEntries {
		l.sweepIdleLocked(now)
	}
	if len(l.buckets) >= rateMaxEntries {
		l.evictOldestLocked()
	}
	b, ok := l.buckets[ip]
	if !ok {
		b = &tokenBucket{tokens: l.burst}
		l.buckets[ip] = b
	} else {
		// 连续补充：距上次判定的时间 × 速率
		b.tokens += now.Sub(b.lastSeen).Seconds() * l.rate
		if b.tokens > l.burst {
			b.tokens = l.burst
		}
	}
	b.lastSeen = now
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// isExempt 豁免判定（ParseIP 失败 = 不豁免）
func (l *RateLimiter) isExempt(ip string) bool {
	if len(l.exemptNets) == 0 {
		return false
	}
	netIP := net.ParseIP(ip)
	if netIP == nil {
		return false
	}
	for _, n := range l.exemptNets {
		if n.Contains(netIP) {
			return true
		}
	}
	return false
}

// sweepIdleLocked 惰性清理闲置桶（调用方持锁）
func (l *RateLimiter) sweepIdleLocked(now time.Time) {
	for ip, b := range l.buckets {
		if now.Sub(b.lastSeen) > rateIdleTTL {
			delete(l.buckets, ip)
		}
	}
}

// evictOldestLocked 容量仍超限时淘汰 lastSeen 最旧的桶（调用方持锁；被淘汰者
// 下次请求重建满桶，攻击面为容量上限失效一次，可接受）
func (l *RateLimiter) evictOldestLocked() {
	oldestIP := ""
	var oldest time.Time
	first := true
	for ip, b := range l.buckets {
		if first || b.lastSeen.Before(oldest) {
			oldestIP, oldest, first = ip, b.lastSeen, false
		}
	}
	if !first {
		delete(l.buckets, oldestIP)
	}
}
