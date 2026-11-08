package resguard

// F1 资源治理单元测试（内部PRD §11 F1）：
//   - 信号量：全局超限拒绝、per-IP 超限拒绝并回滚全局、豁免网段跳过 per-IP、
//     ctx 取消放行等待者、Release 后可重占；
//   - 限速器：burst 内放行、耗尽后拒绝、时间流逝补充、豁免恒放行；
//   - 连接上限：三级全有或全无、Release 释放、豁免跳过 per-IP。

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func mustNets(t *testing.T, cidrs ...string) []*net.IPNet {
	t.Helper()
	var nets []*net.IPNet
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			t.Fatalf("parse cidr %q: %v", c, err)
		}
		nets = append(nets, n)
	}
	return nets
}

// --- Semaphore ---

func TestSemaphoreGlobalFullQueuesAndCtxCancels(t *testing.T) {
	s := NewSemaphore(2, 10, nil)
	ctx := context.Background()
	if !s.Acquire(ctx, "1.1.1.1") || !s.Acquire(ctx, "2.2.2.2") {
		t.Fatal("first two acquires should succeed")
	}
	// 全局占满：第三个 Acquire 排队等待（不立即拒绝）——上游客户端断开由 ctx 放行
	ctx3, cancel := context.WithCancel(ctx)
	acquired := make(chan bool, 1)
	go func() { acquired <- s.Acquire(ctx3, "3.3.3.3") }()
	select {
	case ok := <-acquired:
		t.Fatalf("acquire should be waiting, got %v", ok)
	case <-time.After(50 * time.Millisecond):
	}
	cancel()
	if ok := <-acquired; ok {
		t.Fatal("queued acquire should return false on context cancel")
	}
	// 释放后新 Acquire 可获得槽位
	s.Release("1.1.1.1")
	if !s.Acquire(ctx, "4.4.4.4") {
		t.Fatal("acquire after release should succeed")
	}
}

func TestSemaphorePerIPLimitRollsBackGlobal(t *testing.T) {
	s := NewSemaphore(100, 2, nil)
	ctx := context.Background()
	if !s.Acquire(ctx, "1.1.1.1") || !s.Acquire(ctx, "1.1.1.1") {
		t.Fatal("two per-IP acquires should succeed")
	}
	if s.Acquire(ctx, "1.1.1.1") {
		t.Fatal("third per-IP acquire should be rejected")
	}
	// 回滚验证：per-IP 拒绝不占全局（其他 IP 仍可占）
	if !s.Acquire(ctx, "2.2.2.2") {
		t.Fatal("different IP acquire should succeed after per-IP rejection (global rolled back)")
	}
	s.Release("1.1.1.1")
	if !s.Acquire(ctx, "1.1.1.1") {
		t.Fatal("per-IP acquire should succeed after release")
	}
}

func TestSemaphoreExemptSkipsPerIP(t *testing.T) {
	s := NewSemaphore(100, 2, mustNets(t, "10.72.0.0/24"))
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		if !s.Acquire(ctx, "10.72.0.5") {
			t.Fatalf("exempt ip acquire #%d should succeed (no per-IP accounting)", i+1)
		}
	}
	for i := 0; i < 5; i++ {
		s.Release("10.72.0.5")
	}
}

func TestSemaphoreContextCancelUnblocks(t *testing.T) {
	s := NewSemaphore(1, 10, nil)
	ctx := context.Background()
	if !s.Acquire(ctx, "1.1.1.1") {
		t.Fatal("first acquire should succeed")
	}
	ctx2, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	if s.Acquire(ctx2, "2.2.2.2") {
		t.Fatal("acquire should fail on context cancel")
	}
	if time.Since(start) > time.Second {
		t.Error("acquire should unblock promptly on context cancel")
	}
}

func TestSemaphoreConcurrentAcquireRelease(t *testing.T) {
	s := NewSemaphore(8, 4, nil)
	ctx := context.Background()
	var live atomic.Int64
	var maxLive atomic.Int64
	var wg sync.WaitGroup
	for w := 0; w < 16; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			ip := fmt.Sprintf("10.0.0.%d", w%4)
			for i := 0; i < 50; i++ {
				if s.Acquire(ctx, ip) {
					cur := live.Add(1)
					for {
						old := maxLive.Load()
						if cur <= old || maxLive.CompareAndSwap(old, cur) {
							break
						}
					}
					time.Sleep(time.Millisecond)
					live.Add(-1)
					s.Release(ip)
				}
			}
		}(w)
	}
	wg.Wait()
	if got := maxLive.Load(); got > 8 {
		t.Errorf("max concurrent = %d, want <= global limit 8", got)
	}
}

// --- RateLimiter ---

func TestRateLimiterBurstThenRefill(t *testing.T) {
	l := NewRateLimiter(2, 3, nil) // 2 token/s, burst 3
	base := time.Now()
	for i := 0; i < 3; i++ {
		if !l.Allow("1.1.1.1", base.Add(time.Duration(i)*time.Microsecond)) {
			t.Fatalf("allow #%d within burst should succeed", i+1)
		}
	}
	if l.Allow("1.1.1.1", base.Add(10*time.Microsecond)) {
		t.Fatal("allow beyond burst should be rejected")
	}
	// 1 秒后补充 2 token
	if !l.Allow("1.1.1.1", base.Add(1*time.Second)) {
		t.Fatal("allow after 1s refill should succeed")
	}
	if !l.Allow("1.1.1.1", base.Add(1*time.Second+time.Millisecond)) {
		t.Fatal("second allow after refill should succeed")
	}
	if l.Allow("1.1.1.1", base.Add(1*time.Second+2*time.Millisecond)) {
		t.Fatal("third allow after only 2 tokens refilled should be rejected")
	}
	// 其他 IP 独立计数
	if !l.Allow("2.2.2.2", base.Add(1*time.Second)) {
		t.Fatal("different ip should have its own full bucket")
	}
}

func TestRateLimiterExemptAlwaysAllowed(t *testing.T) {
	l := NewRateLimiter(1, 2, mustNets(t, "10.71.0.0/24"))
	base := time.Now()
	for i := 0; i < 10; i++ {
		if !l.Allow("10.71.0.9", base) {
			t.Fatalf("exempt ip allow #%d should succeed", i+1)
		}
	}
}

// --- ConnLimiter ---

func TestConnLimiterThreeDimensions(t *testing.T) {
	l := NewConnLimiter(10, 2, 1, nil)
	if !l.Acquire("a.example.com", "1.1.1.1") {
		t.Fatal("first acquire should succeed")
	}
	// per-IP 超限（全有或全无：不留半占用）
	if l.Acquire("a.example.com", "1.1.1.1") {
		t.Fatal("second acquire same ip should be rejected (per-ip limit 1)")
	}
	// 上一笔被拒未计数：同 host 第二个 IP 仍可占（per-host 限 2 未到）
	if !l.Acquire("a.example.com", "2.2.2.2") {
		t.Fatal("second distinct-ip acquire same host should succeed (per-host limit 2)")
	}
	// per-host 达 2：第三个 IP 拒绝
	if l.Acquire("a.example.com", "3.3.3.3") {
		t.Fatal("third acquire same host should be rejected (per-host limit 2)")
	}
	// 其他 host 正常
	if !l.Acquire("b.example.com", "3.3.3.3") {
		t.Fatal("other host acquire should succeed")
	}
	l.Release("a.example.com", "1.1.1.1")
	if !l.Acquire("a.example.com", "1.1.1.1") {
		t.Fatal("acquire after release should succeed")
	}
}

func TestConnLimiterGlobalLimit(t *testing.T) {
	l := NewConnLimiter(2, 10, 10, nil)
	if !l.Acquire("a.example.com", "1.1.1.1") || !l.Acquire("b.example.com", "2.2.2.2") {
		t.Fatal("first two acquires should succeed")
	}
	if l.Acquire("c.example.com", "3.3.3.3") {
		t.Fatal("third acquire should be rejected (global limit 2)")
	}
	l.Release("a.example.com", "1.1.1.1")
	if !l.Acquire("c.example.com", "3.3.3.3") {
		t.Fatal("acquire after release should succeed")
	}
}

func TestConnLimiterExemptPerIP(t *testing.T) {
	l := NewConnLimiter(10, 10, 1, mustNets(t, "172.16.0.0/12"))
	for i := 0; i < 3; i++ {
		if !l.Acquire("a.example.com", "172.16.5.5") {
			t.Fatalf("exempt ip acquire #%d should succeed", i+1)
		}
	}
	// 非 exempt IP 受 per-IP 限制
	if !l.Acquire("a.example.com", "9.9.9.9") {
		t.Fatal("non-exempt first acquire should succeed")
	}
	if l.Acquire("a.example.com", "9.9.9.9") {
		t.Fatal("non-exempt second acquire should be rejected (per-ip limit 1)")
	}
}
