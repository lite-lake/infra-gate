package shipper

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/lite-lake/infra-gate/internal/config"
)

// receivedBatches 线程安全的批次收集器（模拟 ingest 端点）
type receivedBatches struct {
	mu    sync.Mutex
	items []Envelope
}

func (r *receivedBatches) add(env Envelope) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.items = append(r.items, env)
}

func (r *receivedBatches) total() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, env := range r.items {
		n += len(env.Requests)
	}
	return n
}

func (r *receivedBatches) all() []Envelope {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Envelope, len(r.items))
	copy(out, r.items)
	return out
}

// newTestIngest 启动模拟 ingest（恒 202），返回收集器与 server
func newTestIngest(t *testing.T) (*receivedBatches, *httptest.Server) {
	t.Helper()
	rec := &receivedBatches{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var env Envelope
		body, err := io.ReadAll(req.Body)
		if err == nil {
			_ = json.Unmarshal(body, &env)
		}
		if env.Node != "" {
			rec.add(env)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(srv.Close)
	return rec, srv
}

// waitForTotal 轮询等待收集到 want 条记录（带超时，避免测试悬挂）
func waitForTotal(t *testing.T, rec *receivedBatches, want int) []Envelope {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if rec.total() >= want {
			return rec.all()
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d records, got %d", want, rec.total())
	return nil
}

func newTestShipperConfig(endpoint string) config.ShipperConfig {
	return config.ShipperConfig{
		Enabled:               true,
		Endpoint:              endpoint,
		SharedSecret:          "k",
		NodeName:              "test-node",
		BufferSize:            100,
		BatchSize:             3,
		FlushInterval:         50 * time.Millisecond,
		FailureSampleLogRatio: 0,
	}
}

// TestShipperBatchAndFlush 端到端：凑满 batch_size 立即发批 + 余量按 flush_interval 落批；
// 打标在 Ship 内完成（req_class 正确写入记录）
func TestShipperBatchAndFlush(t *testing.T) {
	rec, srv := newTestIngest(t)
	sh := New(newTestShipperConfig(srv.URL), testLogger())
	sh.Start()
	defer sh.Stop()

	// 5 条：3 条凑满立即发批，2 条余量等 flush_interval 落批
	sh.Ship(Record{Path: "/", ContentType: "text/html", Ts: 1})
	sh.Ship(Record{Path: "/api/x", ContentType: "", Ts: 2})
	sh.Ship(Record{Path: "/health", ContentType: "application/json", Ts: 3})
	sh.Ship(Record{Path: "/app.js", ContentType: "", Ts: 4})
	sh.Ship(Record{Path: "/file", ContentType: "application/octet-stream", Ts: 5})

	envs := waitForTotal(t, rec, 5)

	// 合并后记录数与 req_class 断言
	classes := map[string]int{}
	tsSeen := map[int64]bool{}
	for _, env := range envs {
		if env.Node != "test-node" {
			t.Errorf("envelope node = %q, want test-node", env.Node)
		}
		for _, r := range env.Requests {
			classes[r.ReqClass]++
			tsSeen[r.Ts] = true
		}
	}
	want := map[string]int{ReqClassDoc: 1, ReqClassAPI: 1, ReqClassProbe: 1, ReqClassAsset: 1, ReqClassDownload: 1}
	for class, n := range want {
		if classes[class] != n {
			t.Errorf("req_class %q count = %d, want %d (all=%v)", class, classes[class], n, classes)
		}
	}
	for _, wantTs := range []int64{1, 2, 3, 4, 5} {
		if !tsSeen[wantTs] {
			t.Errorf("record ts %d missing (explicit Ts must be preserved)", wantTs)
		}
	}
	if got := sh.SentRecords(); got < 5 {
		t.Errorf("SentRecords = %d, want >= 5", got)
	}
	if got := sh.DroppedRecords(); got != 0 {
		t.Errorf("DroppedRecords = %d, want 0", got)
	}
}

// TestShipperStopDrains Stop 优雅收尾：缓冲余量被尽力清空发送（PRD §4.4.1）
func TestShipperStopDrains(t *testing.T) {
	rec, srv := newTestIngest(t)
	// flush_interval 拉长：若 Stop 不清空缓冲，记录只能靠超时（不会发生）落批
	cfg := newTestShipperConfig(srv.URL)
	cfg.FlushInterval = time.Hour
	sh := New(cfg, testLogger())
	sh.Start()

	sh.Ship(Record{Path: "/a", Ts: 1})
	sh.Ship(Record{Path: "/b", Ts: 2})

	sh.Stop() // 应在 stopDrainTimeout 内清空缓冲并发送

	envs := waitForTotal(t, rec, 2)
	total := 0
	for _, env := range envs {
		total += len(env.Requests)
	}
	if total != 2 {
		t.Errorf("records received after Stop = %d, want 2 (drain on close)", total)
	}
}

// TestShipperRecoverInjection 打标 panic 注入：不影响调用方、不外抛（PRD D7 recover 包裹）
func TestShipperRecoverInjection(t *testing.T) {
	rec, srv := newTestIngest(t)
	sh := New(newTestShipperConfig(srv.URL), testLogger())
	sh.Start()
	defer sh.Stop()

	orig := classifyFn
	defer func() { classifyFn = orig }()
	classifyFn = func(path, contentType string) string {
		panic("inject: classify exploded")
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Ship must not propagate panic, got: %v", r)
		}
	}()
	// 打标 panic：本条丢失（等效于 shipper 不存在），调用方零感知
	sh.Ship(Record{Path: "/x", Ts: 1})
	// 打标恢复后继续正常工作
	classifyFn = orig
	sh.Ship(Record{Path: "/y", ContentType: "text/html", Ts: 2})

	envs := waitForTotal(t, rec, 1)
	for _, env := range envs {
		for _, r := range env.Requests {
			if r.Ts == 1 {
				t.Errorf("panicked record should be dropped, got delivered: %+v", r)
			}
		}
	}
}

// TestShipperBeforeStart Start 前 Ship 安全（记录进缓冲等待消费，不丢失、不 panic）
func TestShipperBeforeStart(t *testing.T) {
	rec, srv := newTestIngest(t)
	sh := New(newTestShipperConfig(srv.URL), testLogger())

	sh.Ship(Record{Path: "/early", ContentType: "text/html", Ts: 1})
	sh.Start()
	defer sh.Stop()

	envs := waitForTotal(t, rec, 1)
	found := false
	for _, env := range envs {
		for _, r := range env.Requests {
			if r.Ts == 1 && r.ReqClass == ReqClassDoc {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("pre-start record not delivered correctly: %+v", envs)
	}
}

// TestShipperIngestDownShipsNeverBlock ingest 停机：Ship/Stop 不阻塞、记录走丢弃计数
// （D7 降级语义；Send 失败在 flusher goroutine 内消化）
func TestShipperIngestDownShipsNeverBlock(t *testing.T) {
	// 关闭的端口：连接立即拒绝
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close()

	cfg := newTestShipperConfig(url)
	cfg.FlushInterval = 20 * time.Millisecond
	sh := New(cfg, testLogger())
	sh.Start()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 20; i++ {
			sh.Ship(Record{Path: "/x", Ts: int64(i)})
		}
		sh.Stop()
	}()
	select {
	case <-done:
		// Ship×20 + Stop 全部及时返回
	case <-time.After(30 * time.Second):
		t.Fatal("Ship/Stop blocked while ingest unreachable (D7 violation)")
	}
	// 发送失败的批次计入丢弃（client 侧计数）
	if got := sh.client.DroppedBatches(); got == 0 {
		t.Errorf("DroppedBatches = 0, want > 0 (ingest down)")
	}
}

// TestShipperDefaultConfig End to end 缺省配置合并：New 内部 WithDefaults 生效
func TestShipperDefaultConfig(t *testing.T) {
	rec, srv := newTestIngest(t)
	cfg := config.ShipperConfig{
		Enabled:      true,
		Endpoint:     srv.URL,
		SharedSecret: "k",
		NodeName:     "defaults-node",
		// BufferSize/BatchSize/FlushInterval/Ratio 全零值 → 缺省合并
	}
	sh := New(cfg, testLogger())

	if sh.buffer == nil {
		t.Fatal("buffer should be created")
	}
	if sh.batchSize != config.DefaultShipperBatchSize {
		t.Errorf("batchSize = %d, want %d", sh.batchSize, config.DefaultShipperBatchSize)
	}
	if sh.flushInterval != config.DefaultShipperFlushInterval {
		t.Errorf("flushInterval = %v, want %v", sh.flushInterval, config.DefaultShipperFlushInterval)
	}

	sh.Start()
	sh.Ship(Record{Path: "/", ContentType: "text/html", Ts: 1})
	envs := waitForTotal(t, rec, 1)
	if len(envs) == 0 || envs[0].Node != "defaults-node" {
		t.Errorf("envelope node = %+v, want defaults-node", envs)
	}
}

// waitForCondition 轮询等待 cond 成立（带超时，避免测试悬挂）
func waitForCondition(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out waiting for condition")
}

// TestShipperSnapshotSuccessPath 状态快照成功路径（内部PRD §6.1）：
// 发送成功后 running=true、lastSuccessSendAt 非零、sent/pending 计数正确
func TestShipperSnapshotSuccessPath(t *testing.T) {
	rec, srv := newTestIngest(t)
	sh := New(newTestShipperConfig(srv.URL), testLogger())
	sh.Start()
	defer sh.Stop()

	for i := 0; i < 5; i++ {
		sh.Ship(Record{Path: "/s", Ts: int64(i + 1)})
	}
	envs := waitForTotal(t, rec, 5)
	if len(envs) == 0 {
		t.Fatal("no envelopes received")
	}

	snap := sh.Snapshot()
	if !snap.Enabled {
		t.Error("Enabled = false, want true")
	}
	if !snap.Running {
		t.Error("Running = false, want true (flusher alive)")
	}
	if snap.NodeName != "test-node" {
		t.Errorf("NodeName = %q, want test-node", snap.NodeName)
	}
	if snap.SentTotal < 5 {
		t.Errorf("SentTotal = %d, want >= 5", snap.SentTotal)
	}
	if snap.LastSuccessSendAt == nil || *snap.LastSuccessSendAt == 0 {
		t.Errorf("LastSuccessSendAt = %v, want 非 nil 且非零（成功发送后）", snap.LastSuccessSendAt)
	}
	if snap.DroppedTotal != 0 {
		t.Errorf("DroppedTotal = %d, want 0", snap.DroppedTotal)
	}
	// 全部记录已被 flusher 消费外送，缓冲应为空
	if snap.BufferPending != 0 {
		t.Errorf("BufferPending = %d, want 0", snap.BufferPending)
	}
}

// TestShipperSnapshotFailurePath 状态快照失败路径（内部PRD §6.1）：
// endpoint 不可达时 lastSuccessSendAt 保持 nil（null=从未成功）、droppedTotal 含 client
// 丢弃、flusher 仍存活（running=true）
func TestShipperSnapshotFailurePath(t *testing.T) {
	// 关闭的端口：连接立即拒绝
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close()

	cfg := newTestShipperConfig(url)
	cfg.FlushInterval = 20 * time.Millisecond
	sh := New(cfg, testLogger())
	sh.Start()
	defer sh.Stop()

	for i := 0; i < 9; i++ {
		sh.Ship(Record{Path: "/f", Ts: int64(i)})
	}
	waitForCondition(t, 5*time.Second, func() bool { return sh.DroppedTotal() > 0 })

	snap := sh.Snapshot()
	if !snap.Running {
		t.Error("Running = false, want true（发送失败不影响 flusher 存活）")
	}
	if snap.LastSuccessSendAt != nil {
		t.Errorf("LastSuccessSendAt = %v, want nil（失败不写，从未成功发送）", *snap.LastSuccessSendAt)
	}
	if snap.DroppedTotal == 0 {
		t.Error("DroppedTotal = 0, want > 0（endpoint 不可达必有丢弃）")
	}
	// droppedTotal 必须涵盖 client 侧丢弃（缓冲丢弃 + 发送失败丢弃的合计口径）
	if clientDropped := sh.client.DroppedRecords(); clientDropped == 0 || snap.DroppedTotal < clientDropped {
		t.Errorf("DroppedTotal = %d, client DroppedRecords = %d, want DroppedTotal 包含 client 丢弃", snap.DroppedTotal, clientDropped)
	}
}

// TestShipperSnapshotBeforeStart 未启动快照：enabled=true 但 flusher 未运行（running=false）、
// 从未成功发送（last_success_send_at 为 nil）
func TestShipperSnapshotBeforeStart(t *testing.T) {
	_, srv := newTestIngest(t)
	sh := New(newTestShipperConfig(srv.URL), testLogger())

	snap := sh.Snapshot()
	if !snap.Enabled {
		t.Error("Enabled = false, want true（组件已创建）")
	}
	if snap.Running {
		t.Error("Running = true, want false（flusher 未启动）")
	}
	if snap.LastSuccessSendAt != nil {
		t.Errorf("LastSuccessSendAt = %v, want nil（从未成功发送）", *snap.LastSuccessSendAt)
	}
}

// TestDisabledStatusSnapshot 配置缺段快照：enabled:false 全零值 + last_success_send_at
// 序列化为 null（"组件消失"是有效状态不是错误，内部PRD §6.1）
func TestDisabledStatusSnapshot(t *testing.T) {
	snap := DisabledStatusSnapshot()

	if snap.Enabled {
		t.Error("Enabled = true, want false")
	}
	if snap.Running {
		t.Error("Running = true, want false")
	}
	if snap.NodeName != "" {
		t.Errorf("NodeName = %q, want 空串", snap.NodeName)
	}
	if snap.SentTotal != 0 {
		t.Errorf("SentTotal = %d, want 0", snap.SentTotal)
	}
	if snap.DroppedTotal != 0 {
		t.Errorf("DroppedTotal = %d, want 0", snap.DroppedTotal)
	}
	if snap.LastSuccessSendAt != nil {
		t.Errorf("LastSuccessSendAt = %v, want nil", *snap.LastSuccessSendAt)
	}
	if snap.BufferPending != 0 {
		t.Errorf("BufferPending = %d, want 0", snap.BufferPending)
	}

	// JSON 序列化契约：enabled:false 与 last_success_send_at:null 必须如实输出
	//（Uptime Kuma json-query 断言依据）
	b, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	var decoded map[string]interface{}
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatalf("unmarshal snapshot: %v (body=%s)", err, b)
	}
	if got := decoded["enabled"]; got != false {
		t.Errorf("json enabled = %v, want false", got)
	}
	if got, ok := decoded["last_success_send_at"]; !ok || got != nil {
		t.Errorf("json last_success_send_at = %v (exists=%v), want null", got, ok)
	}
}
