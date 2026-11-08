package admin

import (
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/lite-lake/infra-gate/internal/constants"
)

// hostHealthInfo 单个虚拟主机的健康状态摘要。
// M4（内部PRD §6/决策 D5）：原 backends（后端地址 → 布尔清单）收敛为计数——
// 本端点免认证，地址明细等于把内网拓扑暴露给探针；响应体任何位置不再出现后端地址。
type hostHealthInfo struct {
	Status          string `json:"status"`           // ok | unhealthy | pending
	BackendsTotal   int    `json:"backends_total"`   // 配置的后端总数
	BackendsHealthy int    `json:"backends_healthy"` // 健康后端数（pending 时为 0）
}

// handleHealth 存活探针（免认证）：管理面板进程可响应即返回 ok
// 与 lite-backend /api/health 对齐，供 Uptime Kuma / k8s liveness 等免认证探测使用
func (a *AdminServer) handleHealth(c *gin.Context) {
	c.JSON(http.StatusOK, a.baseHealthPayload("ok"))
}

// handleReady 就绪探针（免认证）：聚合网关所有 host 的后端健康状态
// 任一 host 存在不健康后端则返回 503 degraded，全部健康（或无数据待定）返回 200 ok
// 与 lite-backend /api/ready 对齐。M4（内部PRD §6/决策 D5）：hosts.<name>
// 只含 status / backends_total / backends_healthy，不再含后端地址清单
func (a *AdminServer) handleReady(c *gin.Context) {
	hosts := make(map[string]hostHealthInfo)
	degraded := false

	for _, host := range a.gateConfig.Hosts {
		if len(host.Backend) == 0 {
			// 无后端的 host（如纯 text 响应）不参与就绪判定
			continue
		}
		info := hostHealthInfo{
			Status:        "pending",
			BackendsTotal: len(host.Backend),
		}

		var health map[string]bool
		if a.getBackendHealth != nil {
			health = a.getBackendHealth(host.Name)
		}
		if len(health) == 0 {
			// 尚无健康检查数据（启动初期或健康检查被禁用，如隧道路由），标记 pending 不计入 degraded
			hosts[host.Name] = info
			continue
		}

		allOK := true
		for _, ok := range health {
			if ok {
				info.BackendsHealthy++
			} else {
				allOK = false
			}
		}
		if allOK {
			info.Status = "ok"
		} else {
			info.Status = "unhealthy"
			degraded = true
		}
		hosts[host.Name] = info
	}

	payload := a.baseHealthPayload("ok")
	payload["hosts"] = hosts
	if degraded {
		payload["status"] = "degraded"
		c.JSON(http.StatusServiceUnavailable, payload)
		return
	}
	c.JSON(http.StatusOK, payload)
}

// baseHealthPayload 构造健康检查公共字段（与 lite-backend /api/health 字段对齐）
func (a *AdminServer) baseHealthPayload(status string) gin.H {
	return gin.H{
		"status":        status,
		"lite_build_id": os.Getenv("LITE_BUILD_ID"),
		"version":       constants.Version,
		"timestamp":     time.Now().Format(time.RFC3339),
	}
}
