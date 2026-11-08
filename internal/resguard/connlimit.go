package resguard

// WS 连接三级上限（F1d，内部PRD §4.1.3）：全局 / per-host / per-IP，
// handleWebSocket 入口（wsShutdown 检查之后、wsWG.Add 之前）Acquire，
// defer Release；超限 503 + Retry-After。全有或全无：任一维度超限立即拒绝，
// 不留下半占用状态。

import (
	"net"
	"sync"
)

// ConnLimiter WS 连接上限器（三级全有或全无）
type ConnLimiter struct {
	mu            sync.Mutex
	global        int
	globalMax     int
	perHostMax    int
	perIPMax      int
	exemptNets    []*net.IPNet
	perHost       map[string]int
	perIP         map[string]int
	perIPLastSeen map[string]struct{}
}

// NewConnLimiter 构造连接上限器；三级上限 <=0 由调用方（config 层）clamp，
// 此处防御性回落（1024 / 256 / 16）。exempt 为 per-IP 维度豁免网段。
func NewConnLimiter(globalMax, perHostMax, perIPMax int, exempt []*net.IPNet) *ConnLimiter {
	if globalMax <= 0 {
		globalMax = 1024
	}
	if perHostMax <= 0 {
		perHostMax = 256
	}
	if perIPMax <= 0 {
		perIPMax = 16
	}
	return &ConnLimiter{
		globalMax:     globalMax,
		perHostMax:    perHostMax,
		perIPMax:      perIPMax,
		exemptNets:    exempt,
		perHost:       make(map[string]int),
		perIP:         make(map[string]int),
		perIPLastSeen: make(map[string]struct{}),
	}
}

// Acquire 三级试占（全局 → per-host → per-IP），任一超限全量拒绝；
// 返回 true 后必须 Release(host, ip)。host 为 host 配置名（有界键空间）。
func (l *ConnLimiter) Acquire(host, ip string) bool {
	exempt := l.isExempt(ip)
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.global >= l.globalMax {
		return false
	}
	if l.perHost[host] >= l.perHostMax {
		return false
	}
	if !exempt && l.perIP[ip] >= l.perIPMax {
		return false
	}
	l.global++
	l.perHost[host]++
	if !exempt {
		l.perIP[ip]++
		l.perIPLastSeen[ip] = struct{}{}
	}
	return true
}

// Release 释放一次连接占用（与 Acquire 成对）
func (l *ConnLimiter) Release(host, ip string) {
	exempt := l.isExempt(ip)
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.global > 0 {
		l.global--
	}
	if l.perHost[host] > 0 {
		l.perHost[host]--
		if l.perHost[host] == 0 {
			delete(l.perHost, host)
		}
	}
	if !exempt {
		if l.perIP[ip] > 0 {
			l.perIP[ip]--
			if l.perIP[ip] == 0 {
				delete(l.perIP, ip)
				delete(l.perIPLastSeen, ip)
			}
		}
	}
}

// isExempt per-IP 维度豁免判定（ParseIP 失败 = 不豁免）
func (l *ConnLimiter) isExempt(ip string) bool {
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
