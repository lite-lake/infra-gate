package cert

// Reconciler 单元测试（内部PRD §15.1）。
// 真实生产常量（1s tick / 30s~5m 退避 / 60s 拉取超时）会拖垮测试，
// 统一经 resetReconcilerTestGlobals 注入短间隔（PRD §8 将这些值实现为包级 var 即为此目的）。

import (
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lite-lake/infra-gate/internal/infrastructs/endpoints"
	"github.com/lite-lake/infra-gate/internal/infrastructs/logger"
)

// fakeNotifier 测试用通知收集器：实现 CertNotifier 接口，替代 *notification.Notifier
// （cert 包不 import notification 包，正是为支持此类注入）
type fakeNotifier struct {
	mu     sync.Mutex
	events []fakeEvent
}

type fakeEvent struct {
	event   string
	details map[string]string
}

func (f *fakeNotifier) SendNotification(event string, details map[string]string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := make(map[string]string, len(details))
	for k, v := range details {
		cp[k] = v
	}
	f.events = append(f.events, fakeEvent{event: event, details: cp})
	return nil
}

// count 返回指定事件的发送次数
func (f *fakeNotifier) count(event string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, e := range f.events {
		if e.event == event {
			n++
		}
	}
	return n
}

// countAll 返回全部事件次数（断言"静默"用）
func (f *fakeNotifier) countAll() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.events)
}

// first 返回指定事件第一条详情
func (f *fakeNotifier) first(event string) (map[string]string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, e := range f.events {
		if e.event == event {
			return e.details, true
		}
	}
	return nil, false
}

// resetReconcilerTestGlobals 注入短 tick/退避表/拉取超时并注册恢复，
// 避免真实 1s tick / 30s~5m 退避拖垮测试
func resetReconcilerTestGlobals(t *testing.T, tick time.Duration, backoff []time.Duration, attemptTimeout time.Duration) {
	t.Helper()
	origTick, origTable, origTimeout := reconcileTickInterval, retryBackoffTable, reconcileAttemptTimeout
	reconcileTickInterval = tick
	retryBackoffTable = backoff
	reconcileAttemptTimeout = attemptTimeout
	t.Cleanup(func() {
		reconcileTickInterval, retryBackoffTable, reconcileAttemptTimeout = origTick, origTable, origTimeout
	})
}

// shortReconcilerGlobals 集成测试通用的短节奏参数：
// 退避 80ms 起步 —— 前 12 次失败 ≈ 3s 内完成，且第 13 次尝试距第 12 次至少 320ms，
// 给"恰好 2 次通知"的断言留出稳定观测窗口
func shortReconcilerGlobals(t *testing.T) {
	t.Helper()
	resetReconcilerTestGlobals(t,
		10*time.Millisecond,
		[]time.Duration{80 * time.Millisecond, 160 * time.Millisecond, 240 * time.Millisecond, 320 * time.Millisecond},
		2*time.Second)
}

// slowEndpointReconcilerGlobals 慢端点用例（Stop/外部就绪）专用参数：
// attempt 超时必须显著大于 handler sleep，否则客户端按超时错误处理会触发
// loader 内部 3 轮重试（含 2s+4s 硬编码 sleep），单次 attempt 被放大到 ~18s
func slowEndpointReconcilerGlobals(t *testing.T) {
	t.Helper()
	resetReconcilerTestGlobals(t,
		10*time.Millisecond,
		[]time.Duration{80 * time.Millisecond, 160 * time.Millisecond, 240 * time.Millisecond, 320 * time.Millisecond},
		10*time.Second)
}

// waitFor 轮询等待条件成立（Reconciler 为异步组件，断言前需等调度/worker 落账）
func waitFor(t *testing.T, timeout time.Duration, cond func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return cond()
}

// newCertJSONHandler 返回固定下发 domain 证书 JSON 的 httptest handler 与证书 PEM
func newCertJSONHandler(t *testing.T, domain string) (http.HandlerFunc, []byte, []byte) {
	t.Helper()
	// F6.3：远程证书 SAN 必须匹配请求域，按 domain 签发
	certPEM, keyPEM := generateTestCertificateFor(t, domain)
	response := RemoteCertResponse{
		Domain:      domain,
		FullChain:   string(certPEM),
		PrivateKey:  string(keyPEM),
		StartDate:   time.Now().Add(-1 * time.Hour).Format(time.RFC3339),
		ExpiredDate: time.Now().Add(365 * 24 * time.Hour).Format(time.RFC3339),
	}
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(struct {
			Code    int                `json:"code"`
			Message string             `json:"message"`
			Data    RemoteCertResponse `json:"data"`
		}{Code: 200, Message: "success", Data: response})
	}, certPEM, keyPEM
}

// getReconciler 取 Manager 当前持有的 Reconciler（同包访问内部字段）
func getReconciler(t *testing.T, m *Manager) *Reconciler {
	t.Helper()
	m.reconcilerMu.Lock()
	defer m.reconcilerMu.Unlock()
	if m.reconciler == nil {
		t.Fatal("reconciler is not started")
	}
	return m.reconciler
}

// --- 测试 1：退避序列表驱动（不 sleep，直接测退避函数） ---

func TestRetryBackoffSequence(t *testing.T) {
	// 固定标准表，避免受其他测试注入影响
	origTable := retryBackoffTable
	defer func() { retryBackoffTable = origTable }()
	retryBackoffTable = []time.Duration{
		retryBaseInterval,
		2 * retryBaseInterval,
		4 * retryBaseInterval,
		retryCapInterval,
	}

	tests := []struct {
		failures int // 连续失败次数（第 N 次失败）
		want     time.Duration
	}{
		{1, 30 * time.Second},
		{2, 1 * time.Minute},
		{3, 2 * time.Minute},
		{4, 5 * time.Minute},
		{5, 5 * time.Minute}, // 封顶
		{6, 5 * time.Minute}, // 封顶
	}
	for _, tt := range tests {
		if got := retryBackoff(tt.failures); got != tt.want {
			t.Errorf("retryBackoff(%d) = %v, want %v", tt.failures, got, tt.want)
		}
	}
}

// TestRetryBackoffDefaultTable 验证生产默认表恰为 30s/1m/2m/5m（PRD §8）
func TestRetryBackoffDefaultTable(t *testing.T) {
	want := []time.Duration{30 * time.Second, 1 * time.Minute, 2 * time.Minute, 5 * time.Minute}
	if len(retryBackoffTable) != len(want) {
		t.Fatalf("default backoff table len = %d, want %d", len(retryBackoffTable), len(want))
	}
	for i := range want {
		if retryBackoffTable[i] != want[i] {
			t.Errorf("default table[%d] = %v, want %v", i, retryBackoffTable[i], want[i])
		}
	}
}

// TestProductionReconcilerConstants 守卫 PRD §8 生产常量默认值。
// 这些值实现为包级 var 仅为测试注入短节奏；任何测试遗漏恢复或其他改动碰了默认值，
// 本测试（在各测试 t.Cleanup 恢复之后顺序执行）都会第一时间发现。
func TestProductionReconcilerConstants(t *testing.T) {
	if reconcileWorkers != 3 {
		t.Errorf("reconcileWorkers = %d, want 3", reconcileWorkers)
	}
	if reconcileAttemptTimeout != 60*time.Second {
		t.Errorf("reconcileAttemptTimeout = %v, want 60s (D3-A)", reconcileAttemptTimeout)
	}
	if reconcileTickInterval != 1*time.Second {
		t.Errorf("reconcileTickInterval = %v, want 1s", reconcileTickInterval)
	}
	if retryBaseInterval != 30*time.Second {
		t.Errorf("retryBaseInterval = %v, want 30s", retryBaseInterval)
	}
	if retryCapInterval != 5*time.Minute {
		t.Errorf("retryCapInterval = %v, want 5m", retryCapInterval)
	}
	if failedNotifyEvery != 12 {
		t.Errorf("failedNotifyEvery = %d, want 12", failedNotifyEvery)
	}
	if reconcilerStopTimeout != 30*time.Second {
		t.Errorf("reconcilerStopTimeout = %v, want 30s", reconcilerStopTimeout)
	}
}

// --- 测试 2：cert_failed 通知限频判定表（1 发、2-11 不发、12 发、13 不发） ---

func TestShouldNotifyCertFailureRateLimit(t *testing.T) {
	tests := []struct {
		failures int
		want     bool
	}{
		{1, true},
		{2, false}, {3, false}, {4, false}, {5, false},
		{6, false}, {7, false}, {8, false}, {9, false},
		{10, false}, {11, false},
		{12, true},
		{13, false},
	}
	for _, tt := range tests {
		if got := shouldNotifyCertFailure(tt.failures); got != tt.want {
			t.Errorf("shouldNotifyCertFailure(%d) = %v, want %v", tt.failures, got, tt.want)
		}
	}
}

// --- 测试 3：成功路径（写内存 + 注册 Updater + ready 通知，PRD §15.1 三要素） ---

func TestReconcilerSuccessPathNotifiesCertReady(t *testing.T) {
	restoreTransport := configureTestTLSTransport(t)
	defer restoreTransport()
	shortReconcilerGlobals(t)

	const domain = "ready.example.com"
	handler, _, _ := newCertJSONHandler(t, domain)
	srv := httptest.NewTLSServer(handler)
	defer srv.Close()

	manager := NewManager(t.TempDir(), logger.GetDefaultLogger())
	defer manager.Shutdown()

	notifier := &fakeNotifier{}
	manager.SetNotifier(notifier)

	// AutoUpdate 开启：后台加载成功必须走 LoadCertificate 完整成功路径（含注册 Updater），
	// 这是"夜间续期不因异步化而丢失"的回归锚点（PRD §7.2）
	manager.StartReconciler([]CertTarget{{
		Domain: domain,
		Config: &CertConfig{Remote: &RemoteCertConfig{Enabled: true, AutoUpdate: true, Endpoint: endpoints.New(srv.URL), AllowInsecureHTTP: &f6AllowHTTP, VerifyChain: &f6ChainOff}},
	}})

	// 等待：写内存（即插即用）+ pending 移除
	if !waitFor(t, 5*time.Second, func() bool {
		return manager.HasCertificate(domain) && len(manager.PendingSnapshot()) == 0
	}) {
		t.Fatalf("domain not reconciled in time: HasCertificate=%v, pending=%v",
			manager.HasCertificate(domain), manager.PendingSnapshot())
	}

	// cert_ready 恰好一次，details 含域名与 attempts（首试成功 attempts=1）
	if got := notifier.count("cert_ready"); got != 1 {
		t.Fatalf("cert_ready count = %d, want 1", got)
	}
	details, ok := notifier.first("cert_ready")
	if !ok {
		t.Fatal("cert_ready details missing")
	}
	if details["domain"] != domain {
		t.Errorf("cert_ready details domain = %q, want %q", details["domain"], domain)
	}
	if details["attempts"] != "1" {
		t.Errorf("cert_ready details attempts = %q, want \"1\"", details["attempts"])
	}
	if details["not_after"] == "" {
		t.Error("cert_ready details not_after should not be empty")
	}

	// 注册 Updater（PRD §15.1 成功路径三要素之二）：后台加载成功且 AutoUpdate 开启时，
	// 必须已注册夜间续期任务（复用 Manager.LoadCertificate 既有成功路径的证据）
	status := manager.updater.GetUpdateStatus()
	if _, ok := status[domain]; !ok {
		t.Errorf("auto-update task for %s not registered after successful background load, got %v", domain, status)
	}
}

// --- 测试 4：缓存命中静默（预置缓存，拉取成功但无 cert_ready） ---

func TestReconcilerCacheHitIsSilent(t *testing.T) {
	shortReconcilerGlobals(t)

	const domain = "cached.example.com"
	manager := NewManager(t.TempDir(), logger.GetDefaultLogger())
	defer manager.Shutdown()

	// 预置本地缓存（走 loader.saveToCache，与远程拉取落盘同路径）
	certPEM, keyPEM := generateTestCertificate(t)
	meta := &CertMetadata{
		Domain:      domain,
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		UpdatedAt:   time.Now(),
		Source:      "remote",
		Fingerprint: "cache-hit-test-fingerprint",
	}
	if err := manager.loader.saveToCache(domain, certPEM, keyPEM, meta); err != nil {
		t.Fatalf("saveToCache: %v", err)
	}

	notifier := &fakeNotifier{}
	manager.SetNotifier(notifier)

	// remote 指向不可达端点：若缓存探测生效则加载走缓存路径成功，
	// 若误走远程路径则该域名永远无法就绪（双向验证缓存判定）
	manager.StartReconciler([]CertTarget{{
		Domain: domain,
		Config: &CertConfig{Remote: &RemoteCertConfig{Enabled: true, Endpoint: endpoints.New("https://127.0.0.1:1")}},
	}})

	if !waitFor(t, 5*time.Second, func() bool {
		return manager.HasCertificate(domain) && len(manager.PendingSnapshot()) == 0
	}) {
		t.Fatalf("cached domain not reconciled: HasCertificate=%v, pending=%v",
			manager.HasCertificate(domain), manager.PendingSnapshot())
	}

	// 缓存路径静默：无任何通知
	if got := notifier.countAll(); got != 0 {
		t.Errorf("cache hit should be silent, got %d notifications", got)
	}
}

// --- 测试 5：失败重试 + 限频集成（attempts≥12 后 cert_failed 恰好 2 次） ---

func TestReconcilerFailureRetryAndNotifyRateLimit(t *testing.T) {
	restoreTransport := configureTestTLSTransport(t)
	defer restoreTransport()
	shortReconcilerGlobals(t)

	// 恒定 404 的 TLS 端点：loader 对 4xx 客户端错误不做内部重试，单次 attempt 快速失败。
	// 注：不用不可达端点 https://127.0.0.1:1——loader 内部 3 轮重试含硬编码 2s+4s sleep，
	// 12 次收敛需 >70s，不适合单测节奏；"持续失败"语义一致。
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not ready", http.StatusNotFound)
	}))
	defer srv.Close()

	const domain = "failing.example.com"
	manager := NewManager(t.TempDir(), logger.GetDefaultLogger())
	defer manager.Shutdown()

	notifier := &fakeNotifier{}
	manager.SetNotifier(notifier)

	manager.StartReconciler([]CertTarget{{
		Domain: domain,
		Config: &CertConfig{Remote: &RemoteCertConfig{Enabled: true, Endpoint: endpoints.New(srv.URL), AllowInsecureHTTP: &f6AllowHTTP, VerifyChain: &f6ChainOff}},
	}})

	// 等待 attempts≥12（第 12 次失败已落账）
	var attempts int
	if !waitFor(t, 15*time.Second, func() bool {
		snap := manager.PendingSnapshot()
		if len(snap) == 1 && snap[0].Attempts >= 12 {
			attempts = snap[0].Attempts
			return true
		}
		return false
	}) {
		t.Fatalf("attempts did not reach 12 in time, snapshot=%v", manager.PendingSnapshot())
	}

	// 第 12 次失败后的下一次尝试在 ≥320ms 之后：等待同步通知落账，
	// 同时保证不会跑到第 24 次（还需 ≥12×320ms）
	time.Sleep(100 * time.Millisecond)

	if got := notifier.count("cert_failed"); got != 2 {
		t.Errorf("cert_failed count = %d, want exactly 2 (1st and 12th failure); attempts=%d", got, attempts)
	}
	if got := notifier.count("cert_ready"); got != 0 {
		t.Errorf("cert_ready count = %d, want 0", got)
	}

	// pending 状态字段：retrying + 错误摘要 + 下次重试时间
	snap := manager.PendingSnapshot()
	if len(snap) != 1 {
		t.Fatalf("pending len = %d, want 1", len(snap))
	}
	state := snap[0]
	if state.Status != pendingStatusRetrying {
		t.Errorf("status = %q, want %q", state.Status, pendingStatusRetrying)
	}
	if state.LastError == "" {
		t.Error("last_error should not be empty")
	}
	if len(state.LastError) > maxPendingErrorLength {
		t.Errorf("last_error len = %d, should be truncated to %d", len(state.LastError), maxPendingErrorLength)
	}
	if state.NextRetryAt == nil {
		t.Error("next_retry_at should be set after failure")
	}
	if state.ConsecutiveFailures < 12 {
		t.Errorf("consecutive_failures = %d, want >= 12", state.ConsecutiveFailures)
	}
}

// --- 测试 6：60s 超时克隆（副本生效、原 config 零污染） ---

func TestCloneCertConfigWithTimeout(t *testing.T) {
	orig := &CertConfig{
		Remote: &RemoteCertConfig{
			Enabled:           true,
			Endpoint:          endpoints.New("https://ssl.example.com"),
			AutoUpdate:        true,
			UpdateCheckWindow: "00:00-00:59",
			APIKey:            "test-key",
			Timeout:           6 * time.Minute,
		},
	}

	cloned := cloneCertConfigWithTimeout(orig, 60*time.Second)

	// 关键约束：副本 Remote 必须是新指针，原 Remote 结构体零污染
	if cloned.Remote == orig.Remote {
		t.Fatal("cloned Remote must be a different pointer (Updater 长期持有原 config，原地改会污染夜间续期语义)")
	}
	// 副本 Timeout 生效（GetEffectiveTimeout）
	if got := cloned.Remote.GetEffectiveTimeout(); got != 60*time.Second {
		t.Errorf("cloned GetEffectiveTimeout() = %v, want 60s", got)
	}
	// 原 config 零污染：Timeout 值与指针指向内容均不变
	if orig.Remote.Timeout != 6*time.Minute {
		t.Errorf("orig Remote.Timeout = %v, want unchanged 6m", orig.Remote.Timeout)
	}
	if got := orig.Remote.GetEffectiveTimeout(); got != 6*time.Minute {
		t.Errorf("orig GetEffectiveTimeout() = %v, want 6m", got)
	}
	// 其余字段浅拷贝保留
	if cloned.Remote.APIKey != "test-key" || !cloned.Remote.AutoUpdate || cloned.Remote.Enabled != true {
		t.Error("clone should preserve other Remote fields")
	}
	if cloned.Remote.Endpoint.IsEmpty() {
		t.Error("clone should preserve endpoint")
	}

	// 边界：nil config 与 Remote 为 nil
	if got := cloneCertConfigWithTimeout(nil, time.Second); got != nil {
		t.Error("clone(nil) should return nil")
	}
	localOnly := &CertConfig{Local: &LocalCertConfig{Enabled: true}}
	clonedLocal := cloneCertConfigWithTimeout(localOnly, time.Second)
	if clonedLocal.Remote != nil {
		t.Error("clone of local-only config should keep Remote nil")
	}
	if clonedLocal.Local != localOnly.Local {
		t.Error("clone should shallow-copy Local pointer")
	}
}

// --- 测试 7：单域名去重（同一域名不会被两个 worker 同时处理） ---

func TestReconcilerSingleDomainDedup(t *testing.T) {
	restoreTransport := configureTestTLSTransport(t)
	defer restoreTransport()
	shortReconcilerGlobals(t)

	const domain = "dedup.example.com"
	var hits int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		time.Sleep(800 * time.Millisecond) // 慢端点：拉长在途窗口以观测重复派发
		http.Error(w, "not ready", http.StatusNotFound)
	}))
	defer srv.Close()

	manager := NewManager(t.TempDir(), logger.GetDefaultLogger())
	defer manager.Shutdown()

	manager.StartReconciler([]CertTarget{{
		Domain: domain,
		Config: &CertConfig{Remote: &RemoteCertConfig{Enabled: true, Endpoint: endpoints.New(srv.URL), AllowInsecureHTTP: &f6AllowHTTP, VerifyChain: &f6ChainOff}},
	}})

	// 等首个请求进入在途窗口
	if !waitFor(t, 5*time.Second, func() bool { return atomic.LoadInt32(&hits) >= 1 }) {
		t.Fatal("first attempt never reached the endpoint")
	}

	// 在途窗口中点（800ms sleep 过半）：调度 tick 已跑过 ~40 轮，
	// 若无 inflight 去重会重复派发产生并发请求；恰 1 次命中 = 去重生效
	time.Sleep(400 * time.Millisecond)
	if n := atomic.LoadInt32(&hits); n != 1 {
		t.Fatalf("in-flight window hits = %d, want exactly 1 (duplicate dispatch detected)", n)
	}

	// inflight 标记在途时必须为 true
	r := getReconciler(t, manager)
	r.mu.RLock()
	inflight := r.inflight[domain]
	r.mu.RUnlock()
	if !inflight {
		t.Error("domain should be marked inflight while worker is processing it")
	}

	// 退避后第二次重试到来，确认收敛循环未被去重逻辑卡死
	if !waitFor(t, 5*time.Second, func() bool { return atomic.LoadInt32(&hits) >= 2 }) {
		t.Error("retry after backoff never arrived, dedup may have permanently blocked dispatch")
	}
}

// --- 测试 8：Stop() 不悬挂（在途慢请求时 <10s 返回；二次调用 no-op） ---

func TestReconcilerStopWithInflightWorker(t *testing.T) {
	restoreTransport := configureTestTLSTransport(t)
	defer restoreTransport()
	slowEndpointReconcilerGlobals(t)

	const domain = "stop.example.com"
	var hits int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		time.Sleep(2 * time.Second) // 在途请求：Stop 必须等待其完成而非永久悬挂
		http.Error(w, "not ready", http.StatusNotFound)
	}))
	defer srv.Close()

	manager := NewManager(t.TempDir(), logger.GetDefaultLogger())
	defer manager.Shutdown()

	manager.StartReconciler([]CertTarget{{
		Domain: domain,
		Config: &CertConfig{Remote: &RemoteCertConfig{Enabled: true, Endpoint: endpoints.New(srv.URL), AllowInsecureHTTP: &f6AllowHTTP, VerifyChain: &f6ChainOff}},
	}})

	// 等请求在途
	if !waitFor(t, 5*time.Second, func() bool { return atomic.LoadInt32(&hits) >= 1 }) {
		t.Fatal("worker never started processing")
	}

	r := getReconciler(t, manager)
	done := make(chan struct{})
	go func() {
		r.Stop()
		close(done)
	}()
	select {
	case <-done:
		// 慢端点 2s 完成后 worker 退出、wg 归零，Stop 应在 <10s 返回
	case <-time.After(10 * time.Second):
		t.Fatal("Stop() did not return within 10s with an in-flight worker")
	}

	// 二次 Stop：stopOnce 幂等，立即返回
	second := make(chan struct{})
	go func() {
		r.Stop()
		close(second)
	}()
	select {
	case <-second:
	case <-time.After(2 * time.Second):
		t.Error("second Stop() should be a no-op and return immediately")
	}
}

// --- 测试 9：admin 外部路径就绪（内存注入后调度 tick 内静默移除、无通知） ---

func TestReconcilerExternalReadinessSilentRemoval(t *testing.T) {
	restoreTransport := configureTestTLSTransport(t)
	defer restoreTransport()
	slowEndpointReconcilerGlobals(t)

	const domain = "external.example.com"
	var hits int32
	// 慢端点：worker 停留在在途窗口，确保移除由调度 tick 的外部就绪判定完成
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		time.Sleep(2 * time.Second)
		http.Error(w, "not ready", http.StatusNotFound)
	}))
	defer srv.Close()

	manager := NewManager(t.TempDir(), logger.GetDefaultLogger())
	defer manager.Shutdown()

	notifier := &fakeNotifier{}
	manager.SetNotifier(notifier)

	manager.StartReconciler([]CertTarget{{
		Domain: domain,
		Config: &CertConfig{Remote: &RemoteCertConfig{Enabled: true, Endpoint: endpoints.New(srv.URL), AllowInsecureHTTP: &f6AllowHTTP, VerifyChain: &f6ChainOff}},
	}})

	if !waitFor(t, 5*time.Second, func() bool { return atomic.LoadInt32(&hits) >= 1 }) {
		t.Fatal("worker never started processing")
	}
	if len(manager.PendingSnapshot()) != 1 {
		t.Fatalf("pending len = %d, want 1 before external injection", len(manager.PendingSnapshot()))
	}

	// 外部路径直接写入内存（模拟 admin 手动更新成功，等价于 Manager.updateCertInMemory）
	certPEM, keyPEM := generateTestCertificate(t)
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	manager.mutex.Lock()
	manager.certificates[domain] = &CertPair{
		Certificate: &tlsCert,
		Metadata: &CertMetadata{
			Domain:      domain,
			NotBefore:   time.Now().Add(-time.Hour),
			NotAfter:    time.Now().Add(365 * 24 * time.Hour),
			UpdatedAt:   time.Now(),
			Source:      "local",
			Fingerprint: "external-readiness-fingerprint",
		},
	}
	manager.mutex.Unlock()

	// 下一个调度 tick 内静默移除（以内存 map 为准）
	if !waitFor(t, 3*time.Second, func() bool { return len(manager.PendingSnapshot()) == 0 }) {
		t.Fatalf("pending not removed after external readiness: %v", manager.PendingSnapshot())
	}

	// worker 稍后带着失败完成：不得 resurrect pending、不得发任何通知
	time.Sleep(2200 * time.Millisecond)
	if len(manager.PendingSnapshot()) != 0 {
		t.Errorf("pending must stay empty after late failure, got %v", manager.PendingSnapshot())
	}
	if n := notifier.countAll(); n != 0 {
		t.Errorf("external readiness must be silent, got %d notifications", n)
	}
	if !manager.HasCertificate(domain) {
		t.Error("injected certificate must remain in memory")
	}
}

// --- Manager 生命周期补充：StartReconciler 幂等 / 空 targets no-op / StopReconciler nil 安全 ---

func TestManagerReconcilerLifecycle(t *testing.T) {
	restoreTransport := configureTestTLSTransport(t)
	defer restoreTransport()
	shortReconcilerGlobals(t)

	manager := NewManager(t.TempDir(), logger.GetDefaultLogger())
	defer manager.Shutdown()

	// StopReconciler 未启动时 nil 安全
	manager.StopReconciler()
	// PendingSnapshot 空非 nil
	if snap := manager.PendingSnapshot(); snap == nil || len(snap) != 0 {
		t.Errorf("PendingSnapshot without reconciler = %v, want empty non-nil", snap)
	}

	// 空 targets 直接 no-op（不创建 Reconciler）
	manager.StartReconciler(nil)
	manager.reconcilerMu.Lock()
	started := manager.reconciler != nil
	manager.reconcilerMu.Unlock()
	if started {
		t.Fatal("StartReconciler with empty targets must be a no-op")
	}

	handler, _, _ := newCertJSONHandler(t, "lifecycle.example.com")
	srv := httptest.NewTLSServer(handler)
	defer srv.Close()

	targets := []CertTarget{{
		Domain: "lifecycle.example.com",
		Config: &CertConfig{Remote: &RemoteCertConfig{Enabled: true, Endpoint: endpoints.New(srv.URL), AllowInsecureHTTP: &f6AllowHTTP, VerifyChain: &f6ChainOff}},
	}}
	manager.StartReconciler(targets)
	// 重复调用：Warn+忽略，不替换现有 Reconciler
	first := getReconciler(t, manager)
	manager.StartReconciler(targets)
	if second := getReconciler(t, manager); second != first {
		t.Error("duplicate StartReconciler must not replace the running reconciler")
	}

	// StopReconciler 后可再次启动
	manager.StopReconciler()
	manager.reconcilerMu.Lock()
	stillThere := manager.reconciler != nil
	manager.reconcilerMu.Unlock()
	if stillThere {
		t.Error("reconciler pointer must be cleared after StopReconciler")
	}
}
