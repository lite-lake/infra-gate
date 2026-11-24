package deployinfo

import (
	"os"
	"testing"
)

func TestGet_DefaultValues(t *testing.T) {
	os.Unsetenv("DEPLOY_ENV_NAME")
	os.Unsetenv("DEPLOY_ZONE_NAME")
	os.Unsetenv("DEPLOY_SERVER_NAME")
	os.Unsetenv("DEPLOY_SERVICE_NAME")
	resetForTesting()

	info := Get()

	if info.DeployEnv != "local" {
		t.Errorf("DeployEnv 期望 'local'，实际 '%s'", info.DeployEnv)
	}
	if info.DeployZone != "" {
		t.Errorf("DeployZone 期望空字符串，实际 '%s'", info.DeployZone)
	}
	if info.DeployServer != "" {
		t.Errorf("DeployServer 期望空字符串，实际 '%s'", info.DeployServer)
	}
	if info.DeployService != "" {
		t.Errorf("DeployService 期望空字符串，实际 '%s'", info.DeployService)
	}
	if info.IsSet() {
		t.Error("IsSet() 期望 false，实际 true")
	}
}

func TestGet_WithEnvVars(t *testing.T) {
	t.Setenv("DEPLOY_ENV_NAME", "prod")
	t.Setenv("DEPLOY_ZONE_NAME", "cn-east")
	t.Setenv("DEPLOY_SERVER_NAME", "srv-node1")
	t.Setenv("DEPLOY_SERVICE_NAME", "infra-gate")
	resetForTesting()

	info := Get()

	if info.DeployEnv != "prod" {
		t.Errorf("DeployEnv 期望 'prod'，实际 '%s'", info.DeployEnv)
	}
	if info.DeployZone != "cn-east" {
		t.Errorf("DeployZone 期望 'cn-east'，实际 '%s'", info.DeployZone)
	}
	if info.DeployServer != "srv-node1" {
		t.Errorf("DeployServer 期望 'srv-node1'，实际 '%s'", info.DeployServer)
	}
	if info.DeployService != "infra-gate" {
		t.Errorf("DeployService 期望 'infra-gate'，实际 '%s'", info.DeployService)
	}
	if !info.IsSet() {
		t.Error("IsSet() 期望 true，实际 false")
	}
}

func TestGet_PartialEnvVars(t *testing.T) {
	t.Setenv("DEPLOY_ENV_NAME", "dev")
	os.Unsetenv("DEPLOY_ZONE_NAME")
	os.Unsetenv("DEPLOY_SERVER_NAME")
	os.Unsetenv("DEPLOY_SERVICE_NAME")
	resetForTesting()

	info := Get()

	if info.DeployEnv != "dev" {
		t.Errorf("DeployEnv 期望 'dev'，实际 '%s'", info.DeployEnv)
	}
	if !info.IsSet() {
		t.Error("IsSet() 期望 true（DEPLOY_ENV_NAME 非默认值），实际 false")
	}
}

func TestGet_Singleton(t *testing.T) {
	t.Setenv("DEPLOY_ENV_NAME", "test")
	resetForTesting()

	info1 := Get()
	info2 := Get()

	if info1 != info2 {
		t.Error("Get() 应返回同一个实例指针")
	}
}

func TestGet_EnvNameDefaultLocal(t *testing.T) {
	t.Setenv("DEPLOY_ENV_NAME", "")
	resetForTesting()

	info := Get()

	if info.DeployEnv != "local" {
		t.Errorf("DeployEnv 为空字符串时应使用默认值 'local'，实际 '%s'", info.DeployEnv)
	}
}
