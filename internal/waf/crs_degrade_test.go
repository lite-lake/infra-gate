package waf

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lite-lake/infra-gate/internal/config"
	"github.com/lite-lake/infra-gate/internal/infrastructs/endpoints"
)

// wafStrPtr 测试辅助
func wafStrPtr(s string) *string { return &s }

// unreachableMirrorURL 返回必然连接失败的镜像 URL（已关闭的本地 httptest 端口，
// 连接立即被拒绝，测试不等待超时）
func unreachableMirrorURL(t *testing.T) string {
	t.Helper()
	ts := httptest.NewServer(http.NewServeMux())
	u := ts.URL
	ts.Close()
	return u
}

// degradeTestCRSConfig 构造 CRS 启用、镜像不可达、金副本禁用的 WAF 配置。
// 版本号用不存在的 tag：镜像不可达 + codeload fallback 404 → 刷新必然失败
// （沙箱可直连 GitHub，真实存在的版本会被下载成功而绕过降级路径）。
func degradeTestCRSConfig(t *testing.T, failurePolicy string) config.WAFConfig {
	return config.WAFConfig{
		Enabled:     true,
		DefaultMode: config.WAFModeBlock,
		CRS: config.WAFCRSConfig{
			Enabled:       true,
			Version:       "v0.0.0-waf-degrade-nonexistent",
			FailurePolicy: failurePolicy,
			GoldenDir:     wafStrPtr(""),
			Download: config.WAFCRSDownloadConfig{
				Timeout:    2,
				RetryCount: 1,
				MirrorURL:  endpoints.New(unreachableMirrorURL(t)),
			},
		},
	}
}

// TestCreateWAFCRSUnavailableDegradePolicy CRS 不可用 + failure_policy=degrade →
// 返回 ErrWAFDegraded 哨兵（server 层据此跳过该配置实例、对应 host 无 WAF 启动），
// 不构造 WAF（内部PRD §5.4/§6）。
func TestCreateWAFCRSUnavailableDegradePolicy(t *testing.T) {
	// CreateWAF 内部以 ./cache 为缓存根，chdir 隔离到临时目录
	t.Chdir(t.TempDir())

	_, _, err := CreateWAF(degradeTestCRSConfig(t, config.WAFFailurePolicyDegrade), newMockLogger())
	if err == nil {
		t.Fatal("CreateWAF should fail when CRS unavailable under degrade policy")
	}
	if !errors.Is(err, ErrWAFDegraded) {
		t.Fatalf("error should wrap ErrWAFDegraded, got: %v", err)
	}
}

// TestCreateWAFCRSUnavailableFailPolicy 对照组：failure_policy=fail（默认）→
// 普通错误（非降级哨兵），维持「构造失败 → NewServer 失败 → 进程退出」现状语义。
func TestCreateWAFCRSUnavailableFailPolicy(t *testing.T) {
	t.Chdir(t.TempDir())

	_, _, err := CreateWAF(degradeTestCRSConfig(t, config.WAFFailurePolicyFail), newMockLogger())
	if err == nil {
		t.Fatal("CreateWAF should fail when CRS unavailable under fail policy")
	}
	if errors.Is(err, ErrWAFDegraded) {
		t.Fatalf("error must NOT be degrade sentinel under fail policy: %v", err)
	}
}
