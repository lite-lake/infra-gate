package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/lite-lake/infra-gate/internal/config"
	"github.com/lite-lake/infra-gate/internal/crs"
	"github.com/lite-lake/infra-gate/internal/infrastructs/endpoints"
	"github.com/lite-lake/infra-gate/internal/infrastructs/logger"
)

// srvStrPtr 测试辅助
func srvStrPtr(s string) *string { return &s }

// srvTestLogger 静默日志（Error 级别）
func srvTestLogger() logger.ILogger {
	return logger.NewLogger(logger.LoggerConfig{
		Level:         logger.ErrorLevel,
		EnableConsole: false,
		EnableFile:    false,
	})
}

// srvUnreachableMirrorURL 返回必然连接失败的镜像 URL（已关闭的本地 httptest 端口）
func srvUnreachableMirrorURL(t *testing.T) string {
	t.Helper()
	ts := httptest.NewServer(http.NewServeMux())
	u := ts.URL
	ts.Close()
	return u
}

// crsSelfHealConfig 构造 CRS 启用、镜像不可达、金副本禁用的网关配置
func crsSelfHealConfig(t *testing.T, version, failurePolicy string) *config.Config {
	return &config.Config{
		Server: config.ServerConfig{Port: 18080},
		WAF: config.WAFConfig{
			Enabled:     true,
			DefaultMode: config.WAFModeBlock,
			CRS: config.WAFCRSConfig{
				Enabled:       true,
				Version:       version,
				FailurePolicy: failurePolicy,
				GoldenDir:     srvStrPtr(""),
				Download: config.WAFCRSDownloadConfig{
					Timeout:    2,
					RetryCount: 1,
					MirrorURL:  endpoints.New(srvUnreachableMirrorURL(t)),
				},
			},
		},
		Hosts: []config.HostConfig{
			{Name: "selfheal.test.local", Port: 18080, Text: "ok"},
		},
	}
}

// writeCorazaCRSTree 写入最小且 coraza 可解析的 CRS 结构（20 个合法规则文件 +
// crs-setup.conf.example；stale 旧缓存不经过结构校验，体积可以很小）
func writeCorazaCRSTree(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, "rules"), 0755); err != nil {
		t.Fatalf("mkdir rules: %v", err)
	}
	setup := "# crs-setup fixture (server self-heal test)\n# padding padding padding padding padding padding\nSecAction \"id:900001,phase:1,pass,nolog\"\n"
	if err := os.WriteFile(filepath.Join(dir, "crs-setup.conf.example"), []byte(setup), 0644); err != nil {
		t.Fatalf("write crs-setup: %v", err)
	}
	for i := 0; i < 20; i++ {
		name := filepath.Join(dir, "rules", fmt.Sprintf("REQUEST-910-TEST-%02d.conf", i))
		content := fmt.Sprintf("# fixture rule %d\nSecRule REQUEST_URI \"@contains pad-%d\" \"id:9100%02d,phase:1,pass,nolog\"\n", i, i, i)
		if err := os.WriteFile(name, []byte(content), 0644); err != nil {
			t.Fatalf("write rule %d: %v", i, err)
		}
	}
}

// TestNewServerDegradeSkipsWAFInstance degrade 策略 + CRS 不可用（无缓存、无金副本、
// 镜像不可达）→ NewServer 不失败、不创建 WAF 实例，host 经 wafByHost 缺失自然无 WAF；
// GetDegradedCRSSummary 报告受影响 host（内部PRD §5.4/§6）。
func TestNewServerDegradeSkipsWAFInstance(t *testing.T) {
	// 模板渲染器与 ./cache 均按相对路径解析，测试须在仓库根下运行（同包惯例）
	chdirToRepoRoot(t)
	// 测试产生的 CRS 缓存产物统一收口到 owasp_crs 子目录，结束时清理
	t.Cleanup(func() {
		_ = os.RemoveAll(filepath.Join("cache", "owasp_crs"))
	})

	// 用不存在的版本号：镜像不可达 + codeload fallback 404 → 刷新必然失败 → degrade
	//（沙箱环境可能可直连 GitHub，真实存在的版本号会被下载成功而绕过降级路径）
	version := "v0.0.0-selfheal-nonexistent"
	cfg := crsSelfHealConfig(t, version, config.WAFFailurePolicyDegrade)
	srv, err := NewServer(cfg, srvTestLogger())
	if err != nil {
		t.Fatalf("NewServer must not fail under degrade policy, got: %v", err)
	}
	defer srv.stopCRSRefreshLoop()

	// 无 WAF 实例（degraded configKey 不进 wafByConfigKey）
	if stats := srv.GetWAFStats(); len(stats) != 0 {
		t.Errorf("waf instances = %d, want 0 (degraded config must be skipped)", len(stats))
	}

	degraded := srv.GetDegradedCRSSummary()
	if len(degraded.Hosts) != 1 || degraded.Hosts[0] != "selfheal.test.local" {
		t.Errorf("degraded hosts = %v, want [selfheal.test.local]", degraded.Hosts)
	}
	if len(degraded.Versions) != 1 || degraded.Versions[0] != version {
		t.Errorf("degraded versions = %v, want [%s]", degraded.Versions, version)
	}
	if len(degraded.LastErrors) == 0 {
		t.Error("degraded summary should carry last_error")
	}

	stale := srv.GetStaleCRSSummary()
	if len(stale.Hosts) != 0 {
		t.Errorf("stale hosts = %v, want empty", stale.Hosts)
	}

	// crs 注册表应发布 degraded 状态
	if st, ok := crs.StatusSnapshot(version); !ok || st.State != crs.StateDegraded {
		t.Errorf("crs status = %+v ok=%v, want degraded", st, ok)
	}
}

// TestNewServerStaleStartsWAFWithOldCache 缓存哈希不一致 + 镜像不可达 →
// 用旧缓存正常构造 WAF（stale 启动），GetStaleCRSSummary 报告受影响 host；
// 旧缓存目录保持原样（内部PRD §5.1/§5.4 D4）。
func TestNewServerStaleStartsWAFWithOldCache(t *testing.T) {
	chdirToRepoRoot(t)

	version := "v4.19.0-stale-test"
	cacheVersionDir := filepath.Join("cache", "owasp_crs", version)
	writeCorazaCRSTree(t, cacheVersionDir)
	// F10 适配：不写哈希与 manifest → 宽松档 stale（历史遗留缓存形态，可用性
	// 优先加载旧缓存；「哈希在场不匹配」在 F10 下属严格档、NewServer 硬失败）
	hashFile := filepath.Join("cache", "owasp_crs", version+".sha256")
	_ = os.Remove(hashFile)
	_ = os.Remove(filepath.Join("cache", "owasp_crs", version+".manifest"))
	t.Cleanup(func() {
		_ = os.RemoveAll(cacheVersionDir)
		_ = os.Remove(hashFile)
		_ = os.Remove(filepath.Join("cache", "owasp_crs", version+".manifest"))
	})
	entriesBefore, err := os.ReadDir(cacheVersionDir)
	if err != nil {
		t.Fatalf("read cache dir: %v", err)
	}

	srv, err := NewServer(crsSelfHealConfig(t, version, config.WAFFailurePolicyFail), srvTestLogger())
	if err != nil {
		t.Fatalf("NewServer must not fail on stale cache, got: %v", err)
	}
	defer srv.stopCRSRefreshLoop()

	// WAF 实例用旧缓存规则正常创建
	if stats := srv.GetWAFStats(); len(stats) != 1 {
		t.Errorf("waf instances = %d, want 1 (stale cache still usable)", len(stats))
	}

	stale := srv.GetStaleCRSSummary()
	if len(stale.Hosts) != 1 || stale.Hosts[0] != "selfheal.test.local" {
		t.Errorf("stale hosts = %v, want [selfheal.test.local]", stale.Hosts)
	}
	if len(stale.Versions) != 1 || stale.Versions[0] != version {
		t.Errorf("stale versions = %v, want [%s]", stale.Versions, version)
	}
	if degraded := srv.GetDegradedCRSSummary(); len(degraded.Hosts) != 0 {
		t.Errorf("degraded hosts = %v, want empty", degraded.Hosts)
	}

	// 旧缓存目录未被改动/删除
	entriesAfter, err := os.ReadDir(cacheVersionDir)
	if err != nil {
		t.Fatalf("read cache dir after: %v", err)
	}
	if len(entriesAfter) != len(entriesBefore) {
		t.Errorf("cache dir entries = %d, want %d (old cache must be preserved)", len(entriesAfter), len(entriesBefore))
	}
	if st, ok := crs.StatusSnapshot(version); !ok || st.State != crs.StateStale {
		t.Errorf("crs status = %+v ok=%v, want stale", st, ok)
	}
}

// TestNotifyReadyWithoutNotifierNoPanic 未注入 notifier 时 notifyReady 必须 no-op（不 panic）
func TestNotifyReadyWithoutNotifierNoPanic(t *testing.T) {
	s := &Server{
		servers:      map[int]*http.Server{18080: {}},
		httpsServers: map[int]*http.Server{18443: {}},
		logger:       srvTestLogger(),
	}
	s.notifyReady() // 不得 panic
	if ports := s.listeningPorts(); len(ports) != 2 || ports[0] != 18080 || ports[1] != 18443 {
		t.Errorf("listeningPorts = %v, want [18080 18443]", ports)
	}
}

// fakeServerNotifier 通知收集器（实现 server.Notifier 接口）
type fakeServerNotifier struct {
	mu    sync.Mutex
	sent  map[string][]map[string]string
	order []string
}

func newFakeServerNotifier() *fakeServerNotifier {
	return &fakeServerNotifier{sent: make(map[string][]map[string]string)}
}

func (f *fakeServerNotifier) SendNotification(event string, details map[string]string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent[event] = append(f.sent[event], details)
	f.order = append(f.order, event)
	return nil
}

func (f *fakeServerNotifier) count(event string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.sent[event])
}

// TestNotifyReadyEmitsDegradedAndStaleEvents 注入 notifier 后，就绪通知按序发出
// ready / waf_crs_degraded / waf_crs_stale_start，且内容含影响 host 与风险说明
// （内部PRD §5.6）。
func TestNotifyReadyEmitsDegradedAndStaleEvents(t *testing.T) {
	version := "v4.19.0-ready-test"
	notifier := newFakeServerNotifier()
	s := &Server{
		servers:          map[int]*http.Server{18080: {}},
		httpsServers:     map[int]*http.Server{},
		notifier:         notifier,
		logger:           srvTestLogger(),
		degradedConfigs:  map[string]config.WAFConfig{"ck1": {CRS: config.WAFCRSConfig{Enabled: true, Version: version}}},
		staleVersions:    map[string]string{version: "hash mismatch"},
		wafConfigByKey:   map[string]config.WAFConfig{"ck1": {CRS: config.WAFCRSConfig{Enabled: true, Version: version}}, "ck2": {CRS: config.WAFCRSConfig{Enabled: true, Version: version}}},
		hostsByConfigKey: map[string][]string{"ck1": {"a.test"}, "ck2": {"b.test"}},
	}
	crs.PublishStatus(version, crs.Status{State: crs.StateStale, LastError: "hash mismatch", Version: version})

	s.notifyReady()

	if notifier.count("ready") != 1 {
		t.Errorf("ready events = %d, want 1", notifier.count("ready"))
	}
	if notifier.count("waf_crs_degraded") != 1 {
		t.Fatalf("waf_crs_degraded events = %d, want 1", notifier.count("waf_crs_degraded"))
	}
	if notifier.count("waf_crs_stale_start") != 1 {
		t.Fatalf("waf_crs_stale_start events = %d, want 1", notifier.count("waf_crs_stale_start"))
	}

	degradedDetails := notifier.sent["waf_crs_degraded"][0]
	if degradedDetails["影响host数"] != "1" {
		t.Errorf("degraded 影响host数 = %q, want 1", degradedDetails["影响host数"])
	}
	if degradedDetails["风险"] != "WAF 未启用，流量无 WAF 防护" {
		t.Errorf("degraded 风险 = %q, want WAF 未启用说明", degradedDetails["风险"])
	}
	staleDetails := notifier.sent["waf_crs_stale_start"][0]
	if staleDetails["影响host"] == "" {
		t.Error("stale event should list affected hosts")
	}
	// F10.3：普通 stale 文案改为「未经完整性验证」
	if staleDetails["风险"] != "旧缓存未经完整性验证，规则可能过期或被篡改" {
		t.Errorf("stale 风险 = %q, want 未经完整性验证说明", staleDetails["风险"])
	}
}

// TestNotifyReadyTamperedEmitsHighPriorityAlert F10.3：stale 版本带篡改证据 →
// 额外发 waf_crs_cache_tampered 高优告警
func TestNotifyReadyTamperedEmitsHighPriorityAlert(t *testing.T) {
	version := "v4.19.0-tamper-test"
	notifier := newFakeServerNotifier()
	s := &Server{
		servers:          map[int]*http.Server{18080: {}},
		httpsServers:     map[int]*http.Server{},
		notifier:         notifier,
		logger:           srvTestLogger(),
		degradedConfigs:  map[string]config.WAFConfig{},
		staleVersions:    map[string]string{version: "hash mismatch"},
		wafConfigByKey:   map[string]config.WAFConfig{"ck1": {CRS: config.WAFCRSConfig{Enabled: true, Version: version}}},
		hostsByConfigKey: map[string][]string{"ck1": {"a.test"}},
	}
	crs.PublishStatus(version, crs.Status{State: crs.StateStale, Integrity: crs.IntegrityStatusTampered, Version: version})

	s.notifyReady()

	if notifier.count("waf_crs_stale_start") != 1 {
		t.Fatalf("waf_crs_stale_start events = %d, want 1", notifier.count("waf_crs_stale_start"))
	}
	if notifier.count("waf_crs_cache_tampered") != 1 {
		t.Fatalf("waf_crs_cache_tampered events = %d, want 1", notifier.count("waf_crs_cache_tampered"))
	}
}

// TestPendingRestartVisibleAfterRecovery F11.1：后台刷新恢复后，
// pending_restart 集合经 GetPendingRestartCRSSummary 可见（重启天然清零语义
// 的进程内形态）
func TestPendingRestartVisibleAfterRecovery(t *testing.T) {
	version := "v4.19.0-pending-test"
	s := &Server{
		servers:               map[int]*http.Server{18080: {}},
		httpsServers:          map[int]*http.Server{},
		logger:                srvTestLogger(),
		notifier:              newFakeServerNotifier(),
		degradedConfigs:       map[string]config.WAFConfig{"ck1": {CRS: config.WAFCRSConfig{Enabled: true, Version: version}}},
		staleVersions:         map[string]string{version: "hash mismatch"},
		wafConfigByKey:        map[string]config.WAFConfig{"ck1": {CRS: config.WAFCRSConfig{Enabled: true, Version: version}}},
		hostsByConfigKey:      map[string][]string{"ck1": {"pending.test"}},
		crsRefreshTargets:     make(map[string]config.WAFCRSConfig),
		crsRefreshFailures:    make(map[string]int),
		pendingRestartConfigs: make(map[string]bool),
	}
	crs.PublishStatus(version, crs.Status{State: crs.StateStale, LastError: "hash mismatch", Version: version})
	s.crsRefreshTargets[version] = config.WAFCRSConfig{Enabled: true, Version: version}

	// 恢复前：无 pending
	if hosts := s.GetPendingRestartCRSSummary(); len(hosts) != 0 {
		t.Fatalf("pending hosts before recovery = %v, want empty", hosts)
	}

	// 模拟后台刷新成功的簿记收敛（refreshCRSVersion 成功路径的抽方法）
	s.crsStateMu.Lock()
	s.noteCRSRecoveredLocked(version)
	s.crsStateMu.Unlock()

	hosts := s.GetPendingRestartCRSSummary()
	if len(hosts) != 1 || hosts[0] != "pending.test" {
		t.Fatalf("pending hosts after recovery = %v, want [pending.test]", hosts)
	}
	if _, still := s.degradedConfigs["ck1"]; still {
		t.Error("degraded config should shrink after recovery")
	}
}

// TestGenerateWAFConfigKeyCRSSelfHealFields failure_policy / retry_count / golden_dir
// 必须纳入 configKey：不同策略/预算/金副本配置不得共享 WAF 实例。
func TestGenerateWAFConfigKeyCRSSelfHealFields(t *testing.T) {
	s := &Server{}
	base := config.WAFConfig{
		Enabled:     true,
		DefaultMode: config.WAFModeBlock,
		CRS: config.WAFCRSConfig{
			Enabled: true,
			Version: "v4.19.0",
		},
	}

	keyA := s.generateWAFConfigKey(base)

	degrade := base
	degrade.CRS.FailurePolicy = config.WAFFailurePolicyDegrade
	if s.generateWAFConfigKey(degrade) == keyA {
		t.Error("failure_policy must be part of the WAF config key")
	}

	retry := base
	retry.CRS.Download.RetryCount = 3
	if s.generateWAFConfigKey(retry) == keyA {
		t.Error("retry_count must be part of the WAF config key")
	}

	golden := base
	golden.CRS.GoldenDir = srvStrPtr("/app/crs")
	if s.generateWAFConfigKey(golden) == keyA {
		t.Error("golden_dir (non-nil) must be part of the WAF config key")
	}

	goldenDisabled := base
	goldenDisabled.CRS.GoldenDir = srvStrPtr("")
	if s.generateWAFConfigKey(goldenDisabled) == s.generateWAFConfigKey(golden) {
		t.Error("golden_dir nil vs explicit empty must produce different keys (default vs disabled)")
	}

	if s.generateWAFConfigKey(base) != keyA {
		t.Error("identical configs must produce identical keys")
	}
}

// TestSetNotifierAndSummariesNoWAF 未配置 CRS 的 server：摘要应为空、SetNotifier 后
// notifyReady 只发 ready 事件。
func TestSetNotifierAndSummariesNoWAF(t *testing.T) {
	s := &Server{
		servers:          map[int]*http.Server{},
		httpsServers:     map[int]*http.Server{},
		logger:           srvTestLogger(),
		degradedConfigs:  map[string]config.WAFConfig{},
		staleVersions:    map[string]string{},
		wafConfigByKey:   map[string]config.WAFConfig{},
		hostsByConfigKey: map[string][]string{},
	}
	notifier := newFakeServerNotifier()
	s.SetNotifier(notifier)
	s.notifyReady()

	if notifier.count("ready") != 1 {
		t.Errorf("ready events = %d, want 1", notifier.count("ready"))
	}
	if notifier.count("waf_crs_degraded") != 0 || notifier.count("waf_crs_stale_start") != 0 {
		t.Error("no CRS events expected without degraded/stale configs")
	}
	if sum := s.GetDegradedCRSSummary(); len(sum.Hosts) != 0 {
		t.Errorf("degraded hosts = %v, want empty", sum.Hosts)
	}
	if sum := s.GetStaleCRSSummary(); len(sum.Hosts) != 0 {
		t.Errorf("stale hosts = %v, want empty", sum.Hosts)
	}
}
