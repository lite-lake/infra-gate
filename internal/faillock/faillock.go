// Package faillock 提供 per-key 认证失败锁定（内部PRD §4.13.1，F13）：
// 从 internal/auth/ratelimit.go 整体迁出并导出，语义零改动——auth 密码门与
// admin 只读 API 认证共用（数据面 M1 三段式模式）。不放 infrastructs
// （该目录只收纯技术设施，按领域组织约定建领域包）。
//
// 语义：纯内存实现，失败累计 N 次锁 15 分钟（阈值/时长构造时固化，缺省经
// config.DefaultAuth* 单一事实源），成功清零；容量上限 + 惰性清理 + 淘汰最旧，
// 锁定中的条目不可淘汰（F2.1，内部PRD §4.2.1）。
package faillock

import (
	"sync"
	"time"

	"github.com/lite-lake/infra-gate/internal/config"
)

// 缺省参数别名（单一事实源为 config.DefaultAuth*）
const (
	// DefaultMaxFailures 锁定阈值缺省（5）
	DefaultMaxFailures = config.DefaultAuthMaxFailures
	// DefaultLockDuration 锁定时长缺省（15 分钟）
	DefaultLockDuration = config.DefaultAuthLockDuration
	// MaxEntries 条目容量上限；超限先惰性清理过期条目，仍超限则淘汰最旧
	MaxEntries = 8192
	// IdleTTL 未锁定条目的闲置回收时长（无锁定概念的计数条目按活跃度回收）
	IdleTTL = 2 * config.DefaultAuthLockDuration
)

// Entry 单个 key 的失败计数与锁定状态
type Entry struct {
	Failures    int
	LockedUntil time.Time // 零值 = 未曾锁定
	LastSeen    time.Time // 最近一次失败时间（闲置回收 / 超限淘汰依据）
}

// Limiter per-key 失败锁定器。锁定期内认证一律拒绝（不暴露凭据是否正确）。
// 阈值/时长构造时固化，运行期不可变（无锁读取安全）。
type Limiter struct {
	mu           sync.Mutex
	entries      map[string]*Entry
	maxFailures  int
	lockDuration time.Duration
}

// NewLimiter 按阈值/时长构造锁定器；<=0 的参数回落缺省（5 次 / 15 分钟，
// 与 config.GetEffective* 同口径）
func NewLimiter(maxFailures int, lockDuration time.Duration) *Limiter {
	if maxFailures <= 0 {
		maxFailures = DefaultMaxFailures
	}
	if lockDuration <= 0 {
		lockDuration = DefaultLockDuration
	}
	return &Limiter{
		entries:      make(map[string]*Entry),
		maxFailures:  maxFailures,
		lockDuration: lockDuration,
	}
}

// IsLocked 返回该 key 当前是否处于锁定期。锁定已过期的条目顺带删除
// （锁到期 = 计数清零重新开始）；未锁定条目保留计数（继续累计至阈值）。
func (l *Limiter) IsLocked(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.entries[key]
	if !ok {
		return false
	}
	if now.Before(e.LockedUntil) {
		return true
	}
	if !e.LockedUntil.IsZero() {
		// 锁定已过期：清空重新计数
		delete(l.entries, key)
	}
	return false
}

// RecordFailure 记一次失败；达到阈值设置 LockedUntil。返回当前累计失败数与
// 是否「本次触发锁定」（false → true 的跳变沿——锁定告警按跳变沿发一条，
// 同一锁定会话内不重复通知）。锁定期内不会走到这里（调用方锁定检查前移），
// 因此跳变沿即等于每个锁定会话一次。
func (l *Limiter) RecordFailure(key string, now time.Time) (failures int, locked bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.entries) >= MaxEntries {
		l.sweepExpiredLocked(now)
	}
	if len(l.entries) >= MaxEntries {
		l.evictOldestLocked(now)
	}
	e, ok := l.entries[key]
	if !ok {
		e = &Entry{}
		l.entries[key] = e
	}
	e.Failures++
	e.LastSeen = now
	if e.Failures >= l.maxFailures {
		alreadyLocked := !e.LockedUntil.IsZero() && now.Before(e.LockedUntil)
		if !alreadyLocked {
			e.LockedUntil = now.Add(l.lockDuration)
			return e.Failures, true
		}
	}
	return e.Failures, false
}

// Reset 成功认证后清零该 key 计数
func (l *Limiter) Reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, key)
}

// LockDuration 返回构造时固化的锁定时长（告警文案用）
func (l *Limiter) LockDuration() time.Duration {
	return l.lockDuration
}

// sweepExpiredLocked 惰性清理过期条目：锁定已过期的、以及长期闲置的未锁定条目（调用方持锁）
func (l *Limiter) sweepExpiredLocked(now time.Time) {
	for key, e := range l.entries {
		if !e.LockedUntil.IsZero() && !now.Before(e.LockedUntil) {
			delete(l.entries, key)
			continue
		}
		if e.LockedUntil.IsZero() && now.Sub(e.LastSeen) > IdleTTL {
			delete(l.entries, key)
		}
	}
}

// evictOldestLocked 容量仍超限时淘汰 LastSeen 最旧的条目（调用方持锁）。
// F2.1：锁定中的条目（LockedUntil > now）不可淘汰——否则攻击者用大量伪造 key
// 轮换可把真正被锁定的条目挤出表，锁定失效。全部条目都锁定时放任软性超上限
// （条目增长由锁定时长自然封顶：最长 15 分钟 ×MaxEntries 级别的峰值后自然回落）
func (l *Limiter) evictOldestLocked(now time.Time) {
	oldestKey := ""
	var oldest time.Time
	first := true
	for key, e := range l.entries {
		if now.Before(e.LockedUntil) {
			continue // 锁定中：不可淘汰
		}
		if first || e.LastSeen.Before(oldest) {
			oldestKey, oldest, first = key, e.LastSeen, false
		}
	}
	if !first {
		delete(l.entries, oldestKey)
	}
}
