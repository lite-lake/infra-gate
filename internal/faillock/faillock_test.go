package faillock

// per-key 失败锁定器单测（自 internal/auth/ratelimit_test.go 随包迁出，语义零改动；
// 原 内部PRD §13 + M3 + F2.1）：阈值锁定、锁定内拒绝、过期解锁重新计数、
// 成功清零、容量上限淘汰（锁定条目不可淘汰）、闲置清理、自定义阈值/时长、
// 缺省回落、跳变沿语义。

import (
	"strconv"
	"testing"
	"time"
)

func TestLimiterLocksAfterThreshold(t *testing.T) {
	l := NewLimiter(0, 0)
	now := time.Now()

	for i := 1; i <= DefaultMaxFailures; i++ {
		if l.IsLocked("1.2.3.4", now) {
			t.Fatalf("locked before %d failures", i)
		}
		_, locked := l.RecordFailure("1.2.3.4", now)
		if want := i >= DefaultMaxFailures; locked != want {
			t.Fatalf("RecordFailure #%d locked = %v, want %v", i, locked, want)
		}
	}
	if !l.IsLocked("1.2.3.4", now) {
		t.Fatalf("key should be locked after %d failures", DefaultMaxFailures)
	}
	// 其他 key 不受影响
	if l.IsLocked("5.6.7.8", now) {
		t.Fatalf("other key must not be locked")
	}
}

func TestLimiterLockExpiryResetsCounter(t *testing.T) {
	l := NewLimiter(0, 0)
	now := time.Now()
	for i := 0; i < DefaultMaxFailures; i++ {
		l.RecordFailure("1.2.3.4", now)
	}
	if !l.IsLocked("1.2.3.4", now) {
		t.Fatalf("should be locked")
	}

	// 锁定期内仍锁定
	if !l.IsLocked("1.2.3.4", now.Add(DefaultLockDuration-time.Second)) {
		t.Fatalf("still within lock window")
	}

	// 锁过期：解锁且计数清零，重新累计
	after := now.Add(DefaultLockDuration + time.Second)
	if l.IsLocked("1.2.3.4", after) {
		t.Fatalf("lock should have expired")
	}
	_, locked := l.RecordFailure("1.2.3.4", after)
	if locked {
		t.Fatalf("counter should reset after lock expiry")
	}
}

func TestLimiterResetOnSuccess(t *testing.T) {
	l := NewLimiter(0, 0)
	now := time.Now()
	for i := 0; i < DefaultMaxFailures-1; i++ {
		l.RecordFailure("1.2.3.4", now)
	}
	l.Reset("1.2.3.4")
	_, locked := l.RecordFailure("1.2.3.4", now)
	if locked {
		t.Fatalf("counter should be cleared after success")
	}
}

func TestLimiterCapacityEviction(t *testing.T) {
	l := &Limiter{entries: make(map[string]*Entry), maxFailures: DefaultMaxFailures, lockDuration: DefaultLockDuration}
	now := time.Now()

	// 直接构造满容量 map（limiter 把 key 当不透明字符串，无需合法 IP 形态）
	base := time.Now()
	for i := 0; i < MaxEntries; i++ {
		l.entries["10.0.0."+strconv.Itoa(i)] = &Entry{Failures: 1, LastSeen: base}
	}
	if len(l.entries) != MaxEntries {
		t.Fatalf("setup: entries = %d", len(l.entries))
	}

	// 最旧条目（LastSeen 更早）超限淘汰时应被选中
	l.entries["10.0.0.1"].LastSeen = base.Add(-time.Hour)

	l.RecordFailure("99.99.99.99", now)
	if len(l.entries) > MaxEntries {
		t.Fatalf("capacity exceeded: %d", len(l.entries))
	}
	if _, ok := l.entries["10.0.0.1"]; ok {
		t.Fatalf("oldest entry should have been evicted")
	}
	if _, ok := l.entries["99.99.99.99"]; !ok {
		t.Fatalf("new entry should be recorded")
	}
}

func TestLimiterSweepsIdleEntries(t *testing.T) {
	l := NewLimiter(0, 0)
	now := time.Now()
	l.RecordFailure("1.2.3.4", now) // 1 次失败，未锁定

	// 闲置超过回收时长后清理（清理由容量路径触发，此处直接调用清扫逻辑）
	future := now.Add(IdleTTL + time.Minute)
	l.mu.Lock()
	l.sweepExpiredLocked(future)
	l.mu.Unlock()
	if _, ok := l.entries["1.2.3.4"]; ok {
		t.Fatalf("idle entry should have been swept")
	}
}

// maxFailures/lockDuration 显式配置生效：阈值 2 次、锁定 30 分钟
func TestLimiterCustomThresholdAndDuration(t *testing.T) {
	l := NewLimiter(2, 30*time.Minute)
	now := time.Now()

	if _, locked := l.RecordFailure("1.2.3.4", now); locked {
		t.Fatalf("locked before custom threshold (2)")
	}
	failures, locked := l.RecordFailure("1.2.3.4", now)
	if failures != 2 || !locked {
		t.Fatalf("failures=%d locked=%v, want 2/true (custom threshold)", failures, locked)
	}
	// 锁定时长 = 配置的 30 分钟而非缺省 15 分钟
	l.mu.Lock()
	until := l.entries["1.2.3.4"].LockedUntil
	l.mu.Unlock()
	if !until.Equal(now.Add(30 * time.Minute)) {
		t.Errorf("LockedUntil = %v, want %v (custom lockDuration)", until, now.Add(30*time.Minute))
	}
	if !l.IsLocked("1.2.3.4", now.Add(29*time.Minute)) {
		t.Errorf("should still be locked at 29m with 30m duration")
	}
	if l.IsLocked("1.2.3.4", now.Add(31*time.Minute)) {
		t.Errorf("lock should expire after custom 30m duration")
	}
}

// <=0 回落缺省（5 次 / 15 分钟）
func TestLimiterNonPositiveFallsBackToDefaults(t *testing.T) {
	tests := []struct {
		name         string
		maxFailures  int
		lockDuration time.Duration
	}{
		{"both zero", 0, 0},
		{"both negative", -3, -time.Minute},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			l := NewLimiter(tc.maxFailures, tc.lockDuration)
			now := time.Now()
			for i := 1; i < DefaultMaxFailures; i++ {
				if _, locked := l.RecordFailure("1.2.3.4", now); locked {
					t.Fatalf("locked before default threshold at failure #%d", i)
				}
			}
			_, locked := l.RecordFailure("1.2.3.4", now)
			if !locked {
				t.Fatalf("should lock at default threshold %d", DefaultMaxFailures)
			}
			l.mu.Lock()
			until := l.entries["1.2.3.4"].LockedUntil
			l.mu.Unlock()
			if !until.Equal(now.Add(DefaultLockDuration)) {
				t.Errorf("LockedUntil = %v, want %v (default duration)", until, now.Add(DefaultLockDuration))
			}
		})
	}
}

// locked 仅在「未锁定 → 锁定」跳变沿为 true（锁定告警去重的实现基础）
func TestLimiterLockedOnlyOnTransition(t *testing.T) {
	l := NewLimiter(2, 5*time.Minute)
	now := time.Now()
	if _, locked := l.RecordFailure("1.2.3.4", now); locked {
		t.Fatalf("first failure must not lock")
	}
	if _, locked := l.RecordFailure("1.2.3.4", now); !locked {
		t.Fatalf("second failure must trigger lock transition")
	}
	// 已锁定状态下再次记失败：不重复报告跳变沿
	_, locked := l.RecordFailure("1.2.3.4", now)
	if locked {
		t.Errorf("RecordFailure within an active lockout must not re-report the transition")
	}
}

// F2.1（内部PRD §4.2.1）：锁定条目不可被容量淘汰驱逐；全锁定时放任
// 软性超上限（锁定保留）。详见同包 xff 场景测试的等价断言（auth 包
// TestLimiterLockedEntryNotEvicted 随包迁移语义）。
func TestLimiterLockedEntryNotEvicted(t *testing.T) {
	l := &Limiter{entries: make(map[string]*Entry), maxFailures: 5, lockDuration: 15 * time.Minute}
	now := time.Now()
	base := time.Now()

	for i := 0; i < MaxEntries; i++ {
		l.entries["10.0.0."+strconv.Itoa(i)] = &Entry{Failures: 1, LastSeen: base}
	}
	// 唯一锁定条目且最旧：不可淘汰
	l.entries["10.0.0.7"].LastSeen = base.Add(-time.Hour)
	l.entries["10.0.0.7"].LockedUntil = now.Add(15 * time.Minute)

	l.RecordFailure("99.99.99.99", now)
	if _, ok := l.entries["10.0.0.7"]; !ok {
		t.Fatal("locked entry must NOT be evicted by capacity eviction")
	}
	if _, ok := l.entries["99.99.99.99"]; !ok {
		t.Fatal("new failure should still be recorded")
	}
}
