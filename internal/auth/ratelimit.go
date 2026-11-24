package auth

// F13.1（内部PRD §4.13.1）：本文件原为 per-IP 登录失败锁定的完整实现，
// 已整体迁出至 internal/faillock 并导出（admin 只读 API 认证与 auth 密码门
// 共用，语义零改动；锁定不可淘汰等行为随迁）。此处保留薄封装别名，auth 包
// 内调用点零改动；新代码请直接使用 faillock 包。

import (
	"time"

	"github.com/lite-lake/infra-gate/internal/config"
	"github.com/lite-lake/infra-gate/internal/faillock"
)

// 锁定参数缺省（单一事实源为 config.DefaultAuth*）
const (
	// AuthMaxFailures 锁定阈值缺省值
	AuthMaxFailures = config.DefaultAuthMaxFailures
	// AuthLockDuration 锁定时长缺省值
	AuthLockDuration = config.DefaultAuthLockDuration
)

// limiter 类型别名：auth 包内既有调用点（isLocked/recordFailure/reset 等
// 小写形态已全部改为 faillock 导出方法）
type limiter = faillock.Limiter

// newLimiter 缺省参数锁定器（5 次 / 15 分钟）
func newLimiter() *limiter {
	return newLimiterWithLimits(AuthMaxFailures, AuthLockDuration)
}

// newLimiterWithLimits 按配置构造锁定器；<=0 的参数回落缺省
func newLimiterWithLimits(maxFailures int, lockDuration time.Duration) *limiter {
	return faillock.NewLimiter(maxFailures, lockDuration)
}

// lockDurationOf 返回锁定器的锁定时长（告警文案用，薄封装）
func lockDurationOf(l *limiter) time.Duration {
	return l.LockDuration()
}
