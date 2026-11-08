package blacklist

import (
	"fmt"
	"testing"
	"time"

	"github.com/lite-lake/infra-gate/internal/config"
)

func TestRecordHitRateLimitPerIP(t *testing.T) {
	st := newStatsTracker()

	// 同一 IP 高频命中：事件每分钟最多 1 条，统计计数全记
	for i := 0; i < 10; i++ {
		st.recordHit(config.BlacklistModeDetect, "1.2.3.4", "1.2.3.4", "a.example.com", "/wp-login.php", "trace-1")
	}

	events := st.recentEvents(50)
	if len(events) != 1 {
		t.Fatalf("events len = %d, want 1 (rate-limited per IP per minute)", len(events))
	}
	ev := events[0]
	if ev.ClientIP != "1.2.3.4" || ev.Mode != config.BlacklistModeDetect || ev.Host != "a.example.com" || ev.Path != "/wp-login.php" || ev.TraceID != "trace-1" {
		t.Errorf("event content mismatch: %+v", ev)
	}

	block, detect := st.hitCounts()
	if block != 0 || detect != 10 {
		t.Errorf("hitCounts = (block %d, detect %d), want (0, 10)", block, detect)
	}
	if rh := st.recentHits(); rh != 10 {
		t.Errorf("recentHits = %d, want 10 (counters are not rate-limited)", rh)
	}
}

func TestRecordHitDifferentIPsNotLimited(t *testing.T) {
	st := newStatsTracker()

	// 不同 IP 互不限速：各记 1 条事件
	for i := 0; i < 5; i++ {
		st.recordHit(config.BlacklistModeBlock, fmt.Sprintf("9.9.9.%d", i), fmt.Sprintf("9.9.9.%d", i), "h", "/p", "")
	}

	events := st.recentEvents(0)
	if len(events) != 5 {
		t.Fatalf("events len = %d, want 5", len(events))
	}
	block, detect := st.hitCounts()
	if block != 5 || detect != 0 {
		t.Errorf("hitCounts = (block %d, detect %d), want (5, 0)", block, detect)
	}
}

func TestRecordHitModeCounters(t *testing.T) {
	st := newStatsTracker()

	ips := []string{"1.1.1.1", "2.2.2.2"}
	for _, ip := range ips {
		st.recordHit(config.BlacklistModeBlock, ip, ip, "h", "/", "")
	}
	for _, ip := range []string{"3.3.3.3", "4.4.4.4", "5.5.5.5"} {
		st.recordHit(config.BlacklistModeDetect, ip, ip, "h", "/", "")
	}

	block, detect := st.hitCounts()
	if block != 2 || detect != 3 {
		t.Errorf("hitCounts = (block %d, detect %d), want (2, 3)", block, detect)
	}
	if rh := st.recentHits(); rh != 5 {
		t.Errorf("recentHits = %d, want 5 (block + detect)", rh)
	}
	if len(st.recentEvents(0)) != 5 {
		t.Errorf("events len = %d, want 5", len(st.recentEvents(0)))
	}
}

func TestRecentHitsWindow(t *testing.T) {
	st := newStatsTracker()
	now := time.Now()

	// 按时间顺序写入（与真实使用一致）：窗口外、窗口内边界、当前小时
	// -47h 与 -23h 映射到同一个小时桶（相差 24 桶）：推进到 -23h 时必须清零，
	// 否则旧计数 5 会累加进窗口内的桶（正确值应只含 2）
	record := func(at time.Time, n int) {
		for i := 0; i < n; i++ {
			st.recordHitAt(config.BlacklistModeBlock, fmt.Sprintf("10.0.0.%d-%d", at.Unix(), i), "m", "h", "/", "", at)
		}
	}
	record(now.Add(-47*time.Hour), 5) // 窗口外，且与 -23h 同桶（复用时清零）
	record(now.Add(-30*time.Hour), 5) // 窗口外
	record(now.Add(-24*time.Hour), 4) // 窗口外（hour < currentHour-23），且与当前小时同桶
	record(now.Add(-23*time.Hour), 2) // 窗口内最老桶
	record(now.Add(-1*time.Hour), 1)
	record(now, 3)

	// 用注入的同一时刻读取窗口，避免真实时钟跨小时边界把 -23h 桶滑出窗口
	if rh := st.recentHitsAt(now); rh != 6 {
		t.Errorf("recentHits = %d, want 6 (2 + 1 + 3, window = last 24 hourly buckets)", rh)
	}
}

func TestRecentHitsEmpty(t *testing.T) {
	st := newStatsTracker()
	if rh := st.recentHits(); rh != 0 {
		t.Errorf("recentHits = %d, want 0", rh)
	}
	if evs := st.recentEvents(10); len(evs) != 0 {
		t.Errorf("recentEvents len = %d, want 0", len(evs))
	}
}

func TestEventRingBufferOverflow(t *testing.T) {
	st := newStatsTracker()

	// 250 个不同 IP 的事件，环形缓冲容量 200，只保留最新 200 条
	for i := 0; i < 250; i++ {
		st.recordHit(config.BlacklistModeDetect, fmt.Sprintf("10.1.%d.%d", i/255, i%255), "m", "h", fmt.Sprintf("/p/%d", i), "")
	}

	all := st.recentEvents(0)
	if len(all) != maxEvents {
		t.Fatalf("events len = %d, want %d", len(all), maxEvents)
	}

	// 最早的应为第 51 条（0 起算的第 50 个之后），最新为第 250 条
	if all[0].Path != "/p/50" {
		t.Errorf("oldest event path = %q, want /p/50", all[0].Path)
	}
	if all[len(all)-1].Path != "/p/249" {
		t.Errorf("newest event path = %q, want /p/249", all[len(all)-1].Path)
	}

	// limit 取最新 N 条，按时间顺序（旧到新）排列
	last50 := st.recentEvents(50)
	if len(last50) != 50 {
		t.Fatalf("recentEvents(50) len = %d, want 50", len(last50))
	}
	if last50[0].Path != "/p/200" || last50[49].Path != "/p/249" {
		t.Errorf("recentEvents(50) range = [%q, %q], want [/p/200, /p/249]", last50[0].Path, last50[49].Path)
	}

	// limit 超过存量时返回全部
	if got := len(st.recentEvents(500)); got != maxEvents {
		t.Errorf("recentEvents(500) len = %d, want %d", got, maxEvents)
	}
}

func TestPruneEventIPs(t *testing.T) {
	st := newStatsTracker()

	currentMinute := time.Now().Unix() / 60
	st.mu.Lock()
	for i := 0; i < 5; i++ {
		st.eventIPs[fmt.Sprintf("old-%d", i)] = currentMinute - 1
	}
	st.eventIPs["current-1"] = currentMinute
	st.eventIPs["current-2"] = currentMinute
	st.mu.Unlock()

	st.mu.Lock()
	st.pruneEventIPsLocked(currentMinute)
	size := len(st.eventIPs)
	st.mu.Unlock()

	if size != 2 {
		t.Errorf("eventIPs size after prune = %d, want 2 (only current-minute entries)", size)
	}
}

// TestEventIPsHardCapClearsMap 限速 map 硬上限：全部为当前分钟条目时 prune 无从清理，
// prune 后仍超 maxEventIPs 必须清空整个 map（限速语义允许有损），触发命中的事件仍被记录。
func TestEventIPsHardCapClearsMap(t *testing.T) {
	st := newStatsTracker()

	currentMinute := time.Now().Unix() / 60
	st.mu.Lock()
	for i := 0; i < maxEventIPs+10; i++ {
		st.eventIPs[fmt.Sprintf("10.%d.%d.%d", i/65536, (i/256)%256, i%256)] = currentMinute
	}
	st.mu.Unlock()

	// 新命中触发 prune → 仍超限 → 整表清空（含刚写入的 trigger 项）
	st.recordHit(config.BlacklistModeBlock, "trigger-ip", "m", "h", "/p", "trace-cap")

	st.mu.Lock()
	size := len(st.eventIPs)
	st.mu.Unlock()
	if size != 0 {
		t.Errorf("eventIPs size = %d after hard cap, want 0 (map cleared)", size)
	}

	events := st.recentEvents(0)
	if len(events) != 1 || events[0].TraceID != "trace-cap" {
		t.Errorf("trigger event should still be recorded, got %+v", events)
	}
	if block, _ := st.hitCounts(); block != 1 {
		t.Errorf("hitCounts block = %d, want 1", block)
	}
}
