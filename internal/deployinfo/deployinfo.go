package deployinfo

import (
	"os"
	"sync"
	"testing"
)

// DeployInfo 部署环境元信息（不可变）
type DeployInfo struct {
	DeployEnv     string // DEPLOY_ENV_NAME，未设置时默认 "local"
	DeployZone    string // DEPLOY_ZONE_NAME
	DeployServer  string // DEPLOY_SERVER_NAME
	DeployService string // DEPLOY_SERVICE_NAME
}

var (
	once     sync.Once
	instance *DeployInfo
)

// Get 返回全局唯一的 DeployInfo 实例（惰性初始化）
func Get() *DeployInfo {
	once.Do(func() {
		instance = &DeployInfo{
			DeployEnv:     getEnvOrDefault("DEPLOY_ENV_NAME", "local"),
			DeployZone:    os.Getenv("DEPLOY_ZONE_NAME"),
			DeployServer:  os.Getenv("DEPLOY_SERVER_NAME"),
			DeployService: os.Getenv("DEPLOY_SERVICE_NAME"),
		}
	})
	return instance
}

// IsSet 判断是否至少有一个 DEPLOY_ 环境变量被设置（即非空且非默认值）
func (d *DeployInfo) IsSet() bool {
	return d.DeployEnv != "local" || d.DeployZone != "" || d.DeployServer != "" || d.DeployService != ""
}

// getEnvOrDefault 获取环境变量值，未设置时返回默认值
func getEnvOrDefault(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

// SetForTest 覆写全局实例（仅测试用）：先触发一次 Get 使 once 完成（防后续
// Get 用环境变量覆盖测试值），再直接覆写 instance；t.Cleanup 恢复为环境派生值
func SetForTest(t testing.TB, di DeployInfo) {
	t.Helper()
	_ = Get()
	instance = &di
	t.Cleanup(func() {
		instance = &DeployInfo{
			DeployEnv:     getEnvOrDefault("DEPLOY_ENV_NAME", "local"),
			DeployZone:    os.Getenv("DEPLOY_ZONE_NAME"),
			DeployServer:  os.Getenv("DEPLOY_SERVER_NAME"),
			DeployService: os.Getenv("DEPLOY_SERVICE_NAME"),
		}
	})
}

// resetForTesting 重置全局单例，仅供测试使用
func resetForTesting() {
	once = sync.Once{}
	instance = nil
}
