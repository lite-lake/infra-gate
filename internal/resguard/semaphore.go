package resguard

// 全局 + per-IP 并发信号量（F1a，内部PRD §4.1.1）：堵 H-2 唯一代码级高危
// （连接/速率层完全无资源治理）。纯内存手写实现（channel + mutex，零新依赖），
// 容量上限 + 惰性清理 + 淘汰最旧沿用 auth/ratelimit.go 模式。
//
// 语义：
//   - 全局上限：channel 容量即上限，Acquire 带 context（客户端断开自动放行等待者）；
//   - per-IP 上限：计数表两阶段试占（先全局后 per-IP，失败回滚全局占位）；
//   - 豁免网段：仅豁免 per-IP 维度（全局上限对豁免网段同样生效）——mesh/监控级联
//     流量在直连 IP 上聚合，按 per-IP 限会误伤，但全局资源占用不豁免。

import (
	"context"
	"net"
	"sync"
	"time"
)

const (
	// semaphoreMaxIPEntries per-IP 计数表容量上限；超限先惰性清理闲置条目，仍超限淘汰最旧
	semaphoreMaxIPEntries = 65536
	// semaphoreIPTTL per-IP 条目闲置回收时长（无活跃计数的条目按 lastSeen 回收）
	semaphoreIPTTL = 10 * time.Minute
)

// ipInflight 单个 IP 的 in-flight 计数
type ipInflight struct {
	count    int
	lastSeen time.Time
}

// Semaphore 全局 + per-IP 并发信号量。构造后阈值不可变（无锁读取安全）；
// Acquire/Release 必须按对调用（同一 ip 字符串）。
type Semaphore struct {
	global     chan struct{}
	perIPLimit int
	exemptNets []*net.IPNet
	mu         sync.Mutex
	entries    map[string]*ipInflight
}

// NewSemaphore 构造信号量。globalLimit/perIPLimit <=0 时拒绝构造（调用方 config 层
// 已保证取缺省，此处防御返回 nil 语义由调用方处理——直接 panic 不合适，返回 nil
// 会让挂载点静默跳过，故要求调用方传正值；简化为按原值使用，<=0 视为不限）。
// exempt 为 per-IP 豁免网段（nil/空 = 无豁免）。
func NewSemaphore(globalLimit, perIPLimit int, exempt []*net.IPNet) *Semaphore {
	if globalLimit <= 0 {
		globalLimit = 1 // 防御：config 层已 clamp，永不应触发；保持非零避免死 channel
	}
	if perIPLimit <= 0 {
		perIPLimit = globalLimit // per-IP 不限语义 = 与全局同限
	}
	return &Semaphore{
		global:     make(chan struct{}, globalLimit),
		perIPLimit: perIPLimit,
		exemptNets: exempt,
		entries:    make(map[string]*ipInflight),
	}
}

// Acquire 两阶段试占：先占全局（ctx 取消/超时返回 false），再占 per-IP（超限立即
// 拒绝并回滚全局占位）。返回 true 后调用方必须 Release(ip)。豁免网段跳过 per-IP
// 计数（Release 同口径跳过，判定函数对同一 ip 字符串确定性一致）。
func (s *Semaphore) Acquire(ctx context.Context, ip string) bool {
	select {
	case s.global <- struct{}{}:
	case <-ctx.Done():
		return false
	}
	if s.isExempt(ip) {
		return true
	}
	now := time.Now()
	s.mu.Lock()
	if len(s.entries) >= semaphoreMaxIPEntries {
		s.sweepIdleLocked(now)
	}
	if len(s.entries) >= semaphoreMaxIPEntries {
		s.evictOldestLocked()
	}
	e, ok := s.entries[ip]
	if !ok {
		e = &ipInflight{}
		s.entries[ip] = e
	}
	if e.count >= s.perIPLimit {
		s.mu.Unlock()
		<-s.global // 回滚全局占位
		return false
	}
	e.count++
	e.lastSeen = now
	s.mu.Unlock()
	return true
}

// Release 释放一次占用（与 Acquire 成对；豁免网段只释放全局）
func (s *Semaphore) Release(ip string) {
	if !s.isExempt(ip) {
		s.mu.Lock()
		if e, ok := s.entries[ip]; ok {
			e.count--
			if e.count <= 0 {
				delete(s.entries, ip)
			}
		}
		s.mu.Unlock()
	}
	<-s.global
}

// isExempt per-IP 维度豁免判定（ParseIP 失败 = 不豁免，fail-safe）
func (s *Semaphore) isExempt(ip string) bool {
	if len(s.exemptNets) == 0 {
		return false
	}
	netIP := net.ParseIP(ip)
	if netIP == nil {
		return false
	}
	for _, n := range s.exemptNets {
		if n.Contains(netIP) {
			return true
		}
	}
	return false
}

// sweepIdleLocked 惰性清理零计数闲置条目（调用方持锁）
func (s *Semaphore) sweepIdleLocked(now time.Time) {
	for ip, e := range s.entries {
		if e.count <= 0 && now.Sub(e.lastSeen) > semaphoreIPTTL {
			delete(s.entries, ip)
		}
	}
}

// evictOldestLocked 容量仍超限时淘汰 lastSeen 最旧的零计数条目（调用方持锁）；
// 全部条目都有活跃计数时不淘汰（放任软性超上限，由全局上限兜底——与
// faillock「锁定条目不可淘汰」同款取舍，资源占用真上限是全局信号量）
func (s *Semaphore) evictOldestLocked() {
	oldestIP := ""
	var oldest time.Time
	first := true
	for ip, e := range s.entries {
		if e.count > 0 {
			continue
		}
		if first || e.lastSeen.Before(oldest) {
			oldestIP, oldest, first = ip, e.lastSeen, false
		}
	}
	if !first {
		delete(s.entries, oldestIP)
	}
}
