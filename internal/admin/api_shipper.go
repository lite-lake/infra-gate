package admin

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/lite-lake/infra-gate/internal/shipper"
)

// handleAPIShipperStatus 返回 tracker shipper 状态快照 JSON（免认证监控探针，
// 内部PRD §6.1）。语义要点：
//   - 配置缺段/未启用（getter 未注入）仍返回 200 + enabled:false 全零快照——
//     "组件消失"是有效状态不是错误，Uptime Kuma json-query 断言失败即告警，
//     避免 404/500 混入基础设施故障噪音；
//   - 快照平铺为响应体顶层（无 code/data 信封），便于 json-query 直接取字段；
//   - 供 Kuma 断言的字段：enabled / running / last_success_send_at（null=从未成功）。
func (a *AdminServer) handleAPIShipperStatus(c *gin.Context) {
	// 防御分支：getter 未注入（如单测直构 AdminServer）等效未启用，不 panic
	if a.getShipperStatus == nil {
		c.JSON(http.StatusOK, shipper.DisabledStatusSnapshot())
		return
	}
	c.JSON(http.StatusOK, a.getShipperStatus())
}

// SetGetShipperStatus 注入 shipper 状态快照查询函数（main.go 启动时注入
// server.GetTrackerShipperStatus；未注入时端点输出 DisabledStatusSnapshot）
func (a *AdminServer) SetGetShipperStatus(fn func() shipper.StatusSnapshot) {
	a.getShipperStatus = fn
}
