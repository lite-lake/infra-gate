package proxy

import (
	"fmt"
	"math/rand"

	"github.com/lite-lake/infra-gate/internal/infrastructs/logger"
	"github.com/lite-lake/infra-gate/internal/netutil"
)

// P2-53: 健康检查连续成功/失败阈值
const (
	healthFailureThreshold = 3 // 连续 3 次失败才标记为不健康
	healthSuccessThreshold = 2 // 连续 2 次成功才恢复为健康
)

func (p *Proxy) updateHealthStatus(backend string, isHealthy bool) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	previousStatus := p.healthy[backend]

	// P2-53: 使用连续计数器防止 flapping
	if isHealthy {
		p.healthFailCount[backend] = 0
		p.healthSuccessCount[backend]++
		if p.healthSuccessCount[backend] >= healthSuccessThreshold && !previousStatus {
			p.healthy[backend] = true
			p.logger.Info("Backend health status changed to healthy",
				logger.NewField("backend", netutil.RedactURL(backend)),
				logger.NewField("consecutive_successes", p.healthSuccessCount[backend]))
		}
	} else {
		p.healthSuccessCount[backend] = 0
		p.healthFailCount[backend]++
		if p.healthFailCount[backend] >= healthFailureThreshold && previousStatus {
			p.healthy[backend] = false
			p.logger.Warn("Backend health status changed to unhealthy",
				logger.NewField("backend", netutil.RedactURL(backend)),
				logger.NewField("consecutive_failures", p.healthFailCount[backend]))
		}
	}
}

// GetBackendHealth 返回所有后端的健康状态快照（只读副本）
func (p *Proxy) GetBackendHealth() map[string]bool {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	result := make(map[string]bool, len(p.healthy))
	for k, v := range p.healthy {
		result[k] = v
	}
	return result
}

func (p *Proxy) getHealthyBackends() []string {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	var healthy []string
	for _, backend := range p.backends {
		if p.healthy[backend] {
			healthy = append(healthy, backend)
		}
	}
	return healthy
}

func (p *Proxy) selectBackend() (string, error) {
	healthy := p.getHealthyBackends()
	if len(healthy) == 0 {
		p.logger.Error("No healthy backends available",
			logger.NewField("total_backends", len(p.backends)),
			logger.NewField("unhealthy_backends", len(p.backends)-len(healthy)))
		return "", fmt.Errorf("no healthy backends available")
	}

	// Random selection
	selected := healthy[rand.Intn(len(healthy))]
	p.logger.Debug("Selected backend",
		logger.NewField("backend", netutil.RedactURL(selected)),
		logger.NewField("healthy_count", len(healthy)))
	return selected, nil
}
