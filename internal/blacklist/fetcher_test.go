package blacklist

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lite-lake/infra-gate/internal/config"
	"github.com/lite-lake/infra-gate/internal/infrastructs/logger"
)

// mockLogger 实现 logger.ILogger 接口用于测试（仿 waf/middleware_test.go）
type mockLogger struct{}

func (m *mockLogger) Debug(msg string, fields ...logger.Field) {}
func (m *mockLogger) Info(msg string, fields ...logger.Field)  {}
func (m *mockLogger) Warn(msg string, fields ...logger.Field)  {}
func (m *mockLogger) Error(msg string, fields ...logger.Field) {}
func (m *mockLogger) Fatal(msg string, fields ...logger.Field) {}
func (m *mockLogger) WithContext(ctx context.Context) logger.ILogger {
	return m
}
func (m *mockLogger) WithField(key string, value interface{}) logger.ILogger { return m }
func (m *mockLogger) WithFields(fields map[string]interface{}) logger.ILogger {
	return m
}
func (m *mockLogger) WithTraceId(traceId string) logger.ILogger { return m }
func (m *mockLogger) SetLevel(level logger.LogLevel)            {}
func (m *mockLogger) GetLevel() logger.LogLevel                 { return logger.DebugLevel }
func (m *mockLogger) Close() error                              { return nil }

// logRecord 一条被记录的日志
type logRecord struct {
	level string
	msg   string
}

// recordLogger 可捕获日志调用的测试 logger（用于断言日志级别，如冷启动 fail-open 的 Error）
type recordLogger struct {
	mu      sync.Mutex
	records []logRecord
}

func (r *recordLogger) Debug(msg string, fields ...logger.Field) { r.append("debug", msg) }
func (r *recordLogger) Info(msg string, fields ...logger.Field)  { r.append("info", msg) }
func (r *recordLogger) Warn(msg string, fields ...logger.Field)  { r.append("warn", msg) }
func (r *recordLogger) Error(msg string, fields ...logger.Field) { r.append("error", msg) }
func (r *recordLogger) Fatal(msg string, fields ...logger.Field) { r.append("fatal", msg) }
func (r *recordLogger) WithContext(ctx context.Context) logger.ILogger {
	return r
}
func (r *recordLogger) WithField(key string, value interface{}) logger.ILogger { return r }
func (r *recordLogger) WithFields(fields map[string]interface{}) logger.ILogger {
	return r
}
func (r *recordLogger) WithTraceId(traceId string) logger.ILogger { return r }
func (r *recordLogger) SetLevel(level logger.LogLevel)            {}
func (r *recordLogger) GetLevel() logger.LogLevel                 { return logger.DebugLevel }
func (r *recordLogger) Close() error                              { return nil }

// reset 清空已记录日志
func (r *recordLogger) reset() {
	r.mu.Lock()
	r.records = nil
	r.mu.Unlock()
}

// append 记录一条日志（接口方法共用，加锁保证 -race 下并发安全）
func (r *recordLogger) append(level, msg string) {
	r.mu.Lock()
	r.records = append(r.records, logRecord{level: level, msg: msg})
	r.mu.Unlock()
}

// snapshot 返回已记录日志的副本
func (r *recordLogger) snapshot() []logRecord {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]logRecord(nil), r.records...)
}

// countLevel 统计指定级别的日志条数
func (r *recordLogger) countLevel(level string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, rec := range r.records {
		if rec.level == level {
			n++
		}
	}
	return n
}

// hasLevelContaining 判断是否存在包含子串的指定级别日志
func (r *recordLogger) hasLevelContaining(level, substr string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, rec := range r.records {
		if rec.level == level && strings.Contains(rec.msg, substr) {
			return true
		}
	}
	return false
}

// genV4Lines 生成 n 条互不重复的公网 IPv4 单 IP（1.x.y.z 段，避开保留网段）
func genV4Lines(n int) []string {
	lines := make([]string, 0, n)
	for i := 0; i < n; i++ {
		lines = append(lines, idxIP(i))
	}
	return lines
}

// idxIP 返回 genV4Lines 中第 i 条（0 起算）IP
func idxIP(i int) string {
	return fmt.Sprintf("1.%d.%d.%d", (i>>16)&0xFF, (i>>8)&0xFF, i&0xFF)
}

// flipServer 可动态切换响应内容的测试服务器（并发安全）
type flipServer struct {
	mu     sync.Mutex
	body   string
	status int
	uas    []string
}

func (f *flipServer) set(body string, status int) {
	f.mu.Lock()
	f.body, f.status = body, status
	f.mu.Unlock()
}

func (f *flipServer) userAgents() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.uas...)
}

func (f *flipServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	body, status := f.body, f.status
	f.uas = append(f.uas, r.Header.Get("User-Agent"))
	f.mu.Unlock()

	if status != 0 && status != http.StatusOK {
		w.WriteHeader(status)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
	fmt.Fprint(w, body)
}

// newTestManager 构建指向 flipServer 的 Manager，cacheDir 隔离到临时目录
func newTestManager(t *testing.T, srvURL string) *Manager {
	t.Helper()
	cfg := config.BlacklistConfig{
		Enabled: true,
		Sources: []config.BlacklistSourceConfig{
			{Name: "ustc", URL: srvURL},
		},
	}
	m := NewManager(cfg, &mockLogger{})
	m.cacheDir = t.TempDir()
	return m
}

func TestRefreshRejectsBelowMinEntries(t *testing.T) {
	flip := &flipServer{body: strings.Join(genV4Lines(500), "\n"), status: http.StatusOK}
	srv := httptest.NewServer(flip)
	defer srv.Close()

	m := newTestManager(t, srv.URL)
	m.refresh()

	// 500 < minEntries(1000)：拒绝替换，Store 保持为空（fail-open）
	if hit, _ := m.Lookup("1.0.0.1"); hit {
		t.Error("Lookup should miss: refresh rejected (entries below minimum)")
	}
	stats := m.GetStats()
	if stats.TotalEntries != 0 {
		t.Errorf("TotalEntries = %d, want 0", stats.TotalEntries)
	}
	if stats.LastAttemptAt == nil {
		t.Error("LastAttemptAt should be set even when refresh is rejected")
	}
	if stats.LastSuccessAt != nil {
		t.Error("LastSuccessAt should be nil: refresh never succeeded")
	}
}

func TestRefreshSuccessAndStats(t *testing.T) {
	lines := append(genV4Lines(1200), "not-an-ip", "another-bad-line")
	flip := &flipServer{body: strings.Join(lines, "\n"), status: http.StatusOK}
	srv := httptest.NewServer(flip)
	defer srv.Close()

	m := newTestManager(t, srv.URL)
	m.refresh()

	if hit, matched := m.Lookup(idxIP(1000)); !hit || matched != idxIP(1000) {
		t.Errorf("Lookup(%s) = (%v, %q), want (true, itself)", idxIP(1000), hit, matched)
	}

	stats := m.GetStats()
	if stats.TotalEntries != 1200 {
		t.Errorf("TotalEntries = %d, want 1200", stats.TotalEntries)
	}
	if len(stats.Sources) != 1 {
		t.Fatalf("Sources len = %d, want 1", len(stats.Sources))
	}
	src := stats.Sources[0]
	if src.Name != "ustc" || src.URL != srv.URL {
		t.Errorf("source = (%q, %q), want (ustc, %s)", src.Name, src.URL, srv.URL)
	}
	if src.Entries != 1200 || src.InvalidLines != 2 {
		t.Errorf("source stats = (entries %d, invalid %d), want (1200, 2)", src.Entries, src.InvalidLines)
	}
	if stats.LastSuccessAt == nil || stats.LastAttemptAt == nil {
		t.Error("LastSuccessAt and LastAttemptAt should be set")
	}
	if stats.LoadedFromCache {
		t.Error("LoadedFromCache should be false after a fresh refresh")
	}
	if !stats.Enabled || stats.DefaultMode != config.BlacklistModeBlock {
		t.Errorf("stats = (enabled %v, default_mode %q), want (true, block)", stats.Enabled, stats.DefaultMode)
	}
}

func TestRefreshRejectsShrink(t *testing.T) {
	flip := &flipServer{body: strings.Join(genV4Lines(3000), "\n"), status: http.StatusOK}
	srv := httptest.NewServer(flip)
	defer srv.Close()

	m := newTestManager(t, srv.URL)
	m.refresh()

	if stats := m.GetStats(); stats.TotalEntries != 3000 {
		t.Fatalf("initial TotalEntries = %d, want 3000", stats.TotalEntries)
	}

	// 1200 >= minEntries 但 < 3000*0.5：触发 shrink 防污染，拒绝替换
	flip.set(strings.Join(genV4Lines(1200), "\n"), http.StatusOK)
	m.refresh()

	if stats := m.GetStats(); stats.TotalEntries != 3000 {
		t.Errorf("TotalEntries = %d, want 3000 (shrink rejected, old table kept)", stats.TotalEntries)
	}
	// 索引 2000 的 IP 只在旧表中：若被错误替换则会 miss
	if hit, _ := m.Lookup(idxIP(2000)); !hit {
		t.Error("Lookup should still hit with the old table after shrink rejection")
	}
}

func TestRefreshHTMLDoesNotReplace(t *testing.T) {
	flip := &flipServer{body: strings.Join(genV4Lines(1500), "\n"), status: http.StatusOK}
	srv := httptest.NewServer(flip)
	defer srv.Close()

	m := newTestManager(t, srv.URL)
	m.refresh()
	if hit, _ := m.Lookup("1.0.0.1"); !hit {
		t.Fatal("precondition: Lookup should hit after successful refresh")
	}

	// 上游返回 HTML 错误页：无法解析出足够条目，拒绝替换旧表
	flip.set("<html><head><title>503 Service Unavailable</title></head><body>Service Unavailable</body></html>", http.StatusOK)
	m.refresh()

	if hit, _ := m.Lookup("1.0.0.1"); !hit {
		t.Error("Lookup should still hit: HTML error page must not replace the old table")
	}
	if stats := m.GetStats(); stats.TotalEntries != 1500 {
		t.Errorf("TotalEntries = %d, want 1500", stats.TotalEntries)
	}
}

func TestRefreshFailureKeepsOldTable(t *testing.T) {
	flip := &flipServer{body: strings.Join(genV4Lines(1500), "\n"), status: http.StatusOK}
	srv := httptest.NewServer(flip)
	defer srv.Close()

	m := newTestManager(t, srv.URL)
	m.refresh()

	// 上游 500：拉取失败，保留旧表
	flip.set("", http.StatusInternalServerError)
	m.refresh()

	if hit, _ := m.Lookup("1.0.0.1"); !hit {
		t.Error("Lookup should still hit after a failed refresh round")
	}
	if stats := m.GetStats(); stats.TotalEntries != 1500 {
		t.Errorf("TotalEntries = %d, want 1500", stats.TotalEntries)
	}
}

func TestRefreshSendsCustomUserAgent(t *testing.T) {
	flip := &flipServer{body: strings.Join(genV4Lines(1100), "\n"), status: http.StatusOK}
	srv := httptest.NewServer(flip)
	defer srv.Close()

	m := newTestManager(t, srv.URL)
	m.refresh()

	uas := flip.userAgents()
	if len(uas) == 0 {
		t.Fatal("no request reached the test server")
	}
	for i, ua := range uas {
		if ua != blacklistUserAgent {
			t.Errorf("request %d User-Agent = %q, want %q", i, ua, blacklistUserAgent)
		}
	}
	if !strings.HasPrefix(blacklistUserAgent, "infra-gate/") {
		t.Errorf("blacklistUserAgent = %q, want infra-gate/ prefix", blacklistUserAgent)
	}
}

func TestCacheRoundTrip(t *testing.T) {
	flip := &flipServer{body: strings.Join(genV4Lines(1500), "\n"), status: http.StatusOK}
	srv := httptest.NewServer(flip)
	defer srv.Close()

	m1 := newTestManager(t, srv.URL)
	m1.refresh()

	// 磁盘缓存文件已写入
	cachePath := filepath.Join(m1.cacheDir, cacheFileName("ustc"))
	data, err := os.ReadFile(cachePath)
	if err != nil {
		t.Fatalf("cache file should exist after refresh: %v", err)
	}
	if !strings.Contains(string(data), "1.0.0.0") {
		t.Errorf("cache file content unexpected: %.80s", data)
	}
	// 权限 0644（PRD §12）
	info, err := os.Stat(cachePath)
	if err != nil {
		t.Fatalf("stat cache file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0644 {
		t.Errorf("cache file mode = %o, want 644", perm)
	}
	// 原子写不残留临时文件
	dirEntries, err := os.ReadDir(m1.cacheDir)
	if err != nil {
		t.Fatalf("read cache dir: %v", err)
	}
	if len(dirEntries) != 1 || dirEntries[0].Name() != filepath.Base(cachePath) {
		names := make([]string, 0, len(dirEntries))
		for _, e := range dirEntries {
			names = append(names, e.Name())
		}
		t.Errorf("cache dir should contain only %q (no temp leftovers), got %v", filepath.Base(cachePath), names)
	}

	// 新 Manager：上游不可用（500），仅靠磁盘缓存启动
	flip.set("", http.StatusInternalServerError)
	m2 := newTestManager(t, srv.URL)
	m2.cacheDir = m1.cacheDir
	m2.loadCache()

	sample := []string{idxIP(1), idxIP(700), idxIP(1499)}
	for _, ip := range sample {
		wantHit, wantMatched := m1.Lookup(ip)
		gotHit, gotMatched := m2.Lookup(ip)
		if gotHit != wantHit || gotMatched != wantMatched {
			t.Errorf("Lookup(%s) = (%v, %q), want (%v, %q)", ip, gotHit, gotMatched, wantHit, wantMatched)
		}
		if !gotHit {
			t.Errorf("Lookup(%s) should hit from cache", ip)
		}
	}
	stats := m2.GetStats()
	if !stats.LoadedFromCache {
		t.Error("LoadedFromCache should be true after loading from disk cache")
	}
	if stats.TotalEntries != 1500 {
		t.Errorf("TotalEntries = %d, want 1500", stats.TotalEntries)
	}
	// 缓存命中未命中均不应误报：缓存外的 IP miss
	if hit, _ := m2.Lookup("2.3.4.4"); hit {
		t.Error("Lookup(2.3.4.4) should miss")
	}
}

func TestCacheBelowMinimumIgnored(t *testing.T) {
	unreachable := "http://127.0.0.1:1/unreachable"
	m := newTestManager(t, unreachable)
	m.loadCache() // 无缓存文件：no-op

	if hit, _ := m.Lookup("1.0.0.1"); hit {
		t.Error("Lookup should miss with no cache")
	}

	// 手写一个过小的缓存文件（首行带当前 URL 标记）：低于 minEntries，忽略
	small := cacheURLHeader(unreachable) + strings.Join(genV4Lines(10), "\n") + "\n"
	if err := os.WriteFile(filepath.Join(m.cacheDir, cacheFileName("ustc")), []byte(small), 0644); err != nil {
		t.Fatalf("failed to write cache file: %v", err)
	}
	m.loadCache()

	if hit, _ := m.Lookup("1.0.0.1"); hit {
		t.Error("Lookup should miss: cache below minimum must be ignored")
	}
	if stats := m.GetStats(); stats.LoadedFromCache {
		t.Error("LoadedFromCache should be false when cache is ignored")
	}
}

func TestColdStartFailOpen(t *testing.T) {
	flip := &flipServer{body: "unavailable", status: http.StatusInternalServerError}
	srv := httptest.NewServer(flip)
	defer srv.Close()

	m := newTestManager(t, srv.URL)
	m.Start()
	defer m.Stop()

	// 等待首刷尝试完成（异步）
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if m.GetStats().LastAttemptAt != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if m.GetStats().LastAttemptAt == nil {
		t.Fatal("first refresh attempt did not happen within timeout")
	}

	// fail-open：空表运行，不 panic，Lookup 未命中
	if hit, matched := m.Lookup("1.2.3.4"); hit || matched != "" {
		t.Errorf("Lookup = (%v, %q), want (false, \"\") on cold-start failure", hit, matched)
	}
	stats := m.GetStats()
	if stats.TotalEntries != 0 || stats.LastSuccessAt != nil {
		t.Errorf("stats = (total %d, success %v), want (0, nil)", stats.TotalEntries, stats.LastSuccessAt)
	}
}

// TestColdStartFailOpenLogsError 冷启动（无缓存、无旧表）场景下，首刷失败与
// 防污染拒绝都必须记 Error 日志（PRD §5 决策 2 / §13 的 fail-open 可见性要求）
func TestColdStartFailOpenLogsError(t *testing.T) {
	flip := &flipServer{body: "unavailable", status: http.StatusInternalServerError}
	srv := httptest.NewServer(flip)
	defer srv.Close()

	rl := &recordLogger{}
	cfg := config.BlacklistConfig{
		Enabled: true,
		Sources: []config.BlacklistSourceConfig{{Name: "ustc", URL: srv.URL}},
	}
	m := NewManager(cfg, rl)
	m.cacheDir = t.TempDir()

	// 首刷失败 + 无旧表 → fail-open + Error
	m.refresh()
	if !rl.hasLevelContaining("error", "fail-open") {
		t.Errorf("expected an Error log mentioning fail-open on cold-start fetch failure, records: %+v", rl.snapshot())
	}

	// 首刷成功但条目 < minEntries 被防污染拒绝 + 无旧表 → 同样 fail-open + Error
	rl.reset()
	flip.set(strings.Join(genV4Lines(10), "\n"), http.StatusOK)
	m.refresh()
	if !rl.hasLevelContaining("error", "fail-open") {
		t.Errorf("expected an Error log mentioning fail-open when first fetch is rejected below minimum, records: %+v", rl.snapshot())
	}
	if hit, _ := m.Lookup(idxIP(1)); hit {
		t.Error("Lookup should miss: no store accepted on cold start")
	}
}

// TestRefreshFailureWithOldTableLogsWarnNotError 已有旧表时的刷新失败/防污染拒绝
// 只记 Warn（保留旧表属于正常降级），不得记 Error
func TestRefreshFailureWithOldTableLogsWarnNotError(t *testing.T) {
	flip := &flipServer{body: strings.Join(genV4Lines(3000), "\n"), status: http.StatusOK}
	srv := httptest.NewServer(flip)
	defer srv.Close()

	rl := &recordLogger{}
	cfg := config.BlacklistConfig{
		Enabled: true,
		Sources: []config.BlacklistSourceConfig{{Name: "ustc", URL: srv.URL}},
	}
	m := NewManager(cfg, rl)
	m.cacheDir = t.TempDir()

	m.refresh() // 成功建立旧表
	if c := rl.countLevel("error"); c != 0 {
		t.Errorf("successful refresh should log no Error, got %d: %+v", c, rl.snapshot())
	}

	// 拉取失败（有旧表）→ Warn 而非 Error
	rl.reset()
	flip.set("", http.StatusInternalServerError)
	m.refresh()
	if c := rl.countLevel("error"); c != 0 {
		t.Errorf("fetch failure with old table should log Warn, not Error, got %d Error: %+v", c, rl.snapshot())
	}
	if !rl.hasLevelContaining("warn", "keeping existing store") {
		t.Errorf("expected a Warn log about keeping existing store, records: %+v", rl.snapshot())
	}

	// 防污染 shrink 拒绝（有旧表）→ Warn 而非 Error
	flip.set(strings.Join(genV4Lines(3000), "\n"), http.StatusOK)
	m.refresh() // 恢复旧表 3000 条
	rl.reset()
	flip.set(strings.Join(genV4Lines(1200), "\n"), http.StatusOK) // 1200 >= minEntries 但 < 3000*0.5
	m.refresh()
	if c := rl.countLevel("error"); c != 0 {
		t.Errorf("shrink rejection with old table should log Warn, not Error, got %d Error: %+v", c, rl.snapshot())
	}
	if !rl.hasLevelContaining("warn", "shrank") {
		t.Errorf("expected a Warn log about shrink rejection, records: %+v", rl.snapshot())
	}
	if hit, _ := m.Lookup(idxIP(2000)); !hit {
		t.Error("Lookup should still hit with the old table")
	}
}

// TestStopLifecycle 覆盖 Start 前 Stop、双重 Stop、Stop 后 Start 的极端时序，
// 均不应 panic、阻塞或泄漏 goroutine（PRD §10 Stop 语义）
func TestStopLifecycle(t *testing.T) {
	m := newTestManager(t, "http://127.0.0.1:1/unreachable")

	// Start 前 Stop、双重 Stop
	m.Stop()
	m.Stop()

	// Stop 之后再 Start：runLoop 首刷立即失败后应随已关闭的 stopChan 退出
	m.Start()
	m.Stop()
	m.Stop()

	if hit, _ := m.Lookup("1.2.3.4"); hit {
		t.Error("Lookup should miss on empty store")
	}
}

func TestProxyFallback(t *testing.T) {
	// 目标服务器：直连不可达（已关闭的监听端口）
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	deadURL := dead.URL
	dead.Close()

	// 好内容服务器
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, strings.Join(genV4Lines(1200), "\n"))
	}))
	defer good.Close()

	// 简易正向代理：收到绝对 URL 请求后从好内容服务器取回数据。
	// 测试拓扑说明：deadURL 直连不可达；本机无法真实模拟"客户端不可达但代理可达"，
	// 故代理对任意代理式请求统一改从 good.URL 拉取，等价于代理侧网络可达上游。
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.RequestURI, "http://") {
			http.Error(w, "not a proxy request", http.StatusBadRequest)
			return
		}
		resp, err := http.Get(good.URL)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		w.WriteHeader(resp.StatusCode)
		if _, err := io.Copy(w, resp.Body); err != nil {
			t.Errorf("proxy copy body: %v", err)
		}
	}))
	defer proxy.Close()

	cfg := config.BlacklistConfig{
		Enabled: true,
		Sources: []config.BlacklistSourceConfig{{Name: "ustc", URL: deadURL}},
		Proxy: config.BlacklistProxyConfig{
			Enabled: true,
			URL:     proxy.URL,
		},
	}
	m := NewManager(cfg, &mockLogger{})
	m.cacheDir = t.TempDir()

	m.refresh()

	if hit, _ := m.Lookup("1.0.0.1"); !hit {
		t.Error("Lookup should hit: direct fetch failed but proxy fallback succeeded")
	}
	if stats := m.GetStats(); stats.TotalEntries != 1200 {
		t.Errorf("TotalEntries = %d, want 1200", stats.TotalEntries)
	}
}

func TestEnabledAndDisabledLookup(t *testing.T) {
	cfg := config.BlacklistConfig{Enabled: false}
	m := NewManager(cfg, &mockLogger{})
	if m.Enabled() {
		t.Error("Enabled() should be false")
	}
	// Store 为 nil 时 Lookup fail-open
	if hit, matched := m.Lookup("8.8.8.8"); hit || matched != "" {
		t.Errorf("Lookup on empty manager = (%v, %q), want (false, \"\")", hit, matched)
	}

	m.Start() // disabled: no-op，不启动循环
	m.Stop()

	if hit, _ := m.Lookup("8.8.8.8"); hit {
		t.Error("Lookup should still miss after Start/Stop on disabled manager")
	}
}

func TestRecordHitViaManager(t *testing.T) {
	m := newTestManager(t, "http://127.0.0.1:1/unreachable")

	m.RecordHit(config.BlacklistModeDetect, "5.6.7.8", "5.6.7.8", "a.example.com", "/x", "trace-9")
	m.RecordHit(config.BlacklistModeDetect, "5.6.7.8", "5.6.7.8", "a.example.com", "/y", "trace-10")

	stats := m.GetStats()
	if stats.HitTotalDetect != 2 || stats.HitTotalBlock != 0 {
		t.Errorf("hits = (block %d, detect %d), want (0, 2)", stats.HitTotalBlock, stats.HitTotalDetect)
	}
	if stats.RecentHits != 2 {
		t.Errorf("RecentHits = %d, want 2", stats.RecentHits)
	}

	events := m.GetEvents(10)
	if len(events) != 1 {
		t.Fatalf("events len = %d, want 1 (per-IP rate limit)", len(events))
	}
	if events[0].TraceID != "trace-9" {
		t.Errorf("event trace_id = %q, want trace-9 (first hit in the minute)", events[0].TraceID)
	}
}

func TestCacheFileName(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"ustc", "ustc.txt"},
		{"a b/c", "a_b_c.txt"},
		{"..", "...txt"},
		{"", "_.txt"},
	}
	for _, tt := range tests {
		if got := cacheFileName(tt.in); got != tt.want {
			t.Errorf("cacheFileName(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// TestRefreshRejectsMassiveDuplicates 防污染判定必须基于 Store 去重后条目数：
// 上游返回大量重复行（2000 行同一 IP）时行数口径 2000 >= minEntries 且不触发 shrink，
// 旧行为会静默清空黑名单；去重口径 distinct=1 必须被拒绝并保留旧表。
func TestRefreshRejectsMassiveDuplicates(t *testing.T) {
	flip := &flipServer{body: strings.Join(genV4Lines(1200), "\n"), status: http.StatusOK}
	srv := httptest.NewServer(flip)
	defer srv.Close()

	m := newTestManager(t, srv.URL)
	m.refresh()
	if stats := m.GetStats(); stats.TotalEntries != 1200 {
		t.Fatalf("initial TotalEntries = %d, want 1200", stats.TotalEntries)
	}

	flip.set(strings.Repeat("9.9.9.9\n", 2000), http.StatusOK)
	m.refresh()

	if hit, _ := m.Lookup(idxIP(5)); !hit {
		t.Error("Lookup should still hit: duplicate-heavy refresh must be rejected")
	}
	if hit, _ := m.Lookup("9.9.9.9"); hit {
		t.Error("Lookup(9.9.9.9) should miss: old table must be kept")
	}
	if stats := m.GetStats(); stats.TotalEntries != 1200 {
		t.Errorf("TotalEntries = %d, want 1200 (rejected refresh keeps old table)", stats.TotalEntries)
	}
	if stats := m.GetStats(); stats.LastAttemptAt == nil {
		t.Error("LastAttemptAt should be set even when refresh is rejected")
	}
}

// TestStopCancelsInflightFetch Stop 必须取消在途拉取：慢 source（不主动结束的 handler）
// 场景下，Stop 应在远小于 timeout 的时间内返回（未修复时需等满 20s 超时）。
func TestStopCancelsInflightFetch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done(): // 客户端请求被取消（stopCtx 生效）
		case <-time.After(30 * time.Second):
		}
	}))
	defer srv.Close()

	cfg := config.BlacklistConfig{
		Enabled: true,
		Timeout: 20 * time.Second,
		Sources: []config.BlacklistSourceConfig{{Name: "ustc", URL: srv.URL}},
	}
	m := NewManager(cfg, &mockLogger{})
	m.cacheDir = t.TempDir()

	m.Start()
	start := time.Now()
	m.Stop()
	elapsed := time.Since(start)

	if elapsed > 5*time.Second {
		t.Errorf("Stop took %v, want < 5s (in-flight fetch must be canceled, timeout is 20s)", elapsed)
	}
	if hit, _ := m.Lookup("1.2.3.4"); hit {
		t.Error("Lookup should miss on empty store")
	}
}

// TestCacheURLMismatchIgnored 缓存文件按 source name 键控，换 URL 后旧缓存必须作废：
// 缓存首行带 source_url 标记，加载时与当前配置 URL 不一致则忽略该文件。
func TestCacheURLMismatchIgnored(t *testing.T) {
	flip := &flipServer{body: strings.Join(genV4Lines(1500), "\n"), status: http.StatusOK}
	srv1 := httptest.NewServer(flip)
	defer srv1.Close()

	m1 := newTestManager(t, srv1.URL)
	m1.refresh()

	data, err := os.ReadFile(filepath.Join(m1.cacheDir, cacheFileName("ustc")))
	if err != nil {
		t.Fatalf("cache file should exist after refresh: %v", err)
	}
	if !bytes.HasPrefix(data, []byte(cacheURLHeader(srv1.URL))) {
		t.Errorf("cache file should start with URL header %q, got: %.80q", cacheURLHeader(srv1.URL), data)
	}

	// 同名 source 换 URL：旧缓存必须被忽略
	srv2 := httptest.NewServer(&flipServer{body: strings.Join(genV4Lines(1500), "\n"), status: http.StatusOK})
	defer srv2.Close()
	m2 := newTestManager(t, srv2.URL)
	m2.cacheDir = m1.cacheDir
	m2.loadCache()

	if hit, _ := m2.Lookup(idxIP(1)); hit {
		t.Error("Lookup should miss: cache written for a different URL must be ignored")
	}
	if stats := m2.GetStats(); stats.LoadedFromCache {
		t.Error("LoadedFromCache should be false when cache URL mismatches")
	}
}

// TestStaleTempFilesCleanedUp crash 遗留的 .tmp-* 残留临时文件应在
// loadCache/writeCache 时被顺带清理。
func TestStaleTempFilesCleanedUp(t *testing.T) {
	flip := &flipServer{body: strings.Join(genV4Lines(1100), "\n"), status: http.StatusOK}
	srv := httptest.NewServer(flip)
	defer srv.Close()

	m := newTestManager(t, srv.URL)

	stale1 := filepath.Join(m.cacheDir, ".tmp-crash-123")
	if err := os.WriteFile(stale1, []byte("leftover"), 0644); err != nil {
		t.Fatalf("failed to write stale temp file: %v", err)
	}
	m.loadCache()
	if _, err := os.Stat(stale1); !os.IsNotExist(err) {
		t.Errorf("stale temp file should be removed by loadCache, stat err = %v", err)
	}

	stale2 := filepath.Join(m.cacheDir, ".tmp-crash-456")
	if err := os.WriteFile(stale2, []byte("leftover"), 0644); err != nil {
		t.Fatalf("failed to write stale temp file: %v", err)
	}
	m.refresh() // 成功路径经 writeCache 再清一次
	if _, err := os.Stat(stale2); !os.IsNotExist(err) {
		t.Errorf("stale temp file should be removed by writeCache, stat err = %v", err)
	}
}

// TestRedirectConstraints 重定向约束：最多跟随 3 次；禁止 https→http 降级。
func TestRedirectConstraints(t *testing.T) {
	m := newTestManager(t, "http://placeholder.invalid")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := strconv.Atoi(r.URL.Query().Get("n"))
		if strings.HasPrefix(r.URL.Path, "/hop") && n < 3 {
			http.Redirect(w, r, fmt.Sprintf("/hop?n=%d", n+1), http.StatusFound)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/deep") && n < 6 {
			http.Redirect(w, r, fmt.Sprintf("/deep?n=%d", n+1), http.StatusFound)
			return
		}
		fmt.Fprint(w, strings.Join(genV4Lines(1100), "\n"))
	}))
	defer srv.Close()

	// 3 次重定向内允许
	data, err := m.doFetch(srv.URL+"/hop?n=0", m.httpClient)
	if err != nil {
		t.Errorf("redirect chain of 3 hops should be allowed: %v", err)
	} else if len(data) == 0 {
		t.Error("expected non-empty body after allowed redirects")
	}

	// 超过 3 次被拒
	if _, err := m.doFetch(srv.URL+"/deep?n=0", m.httpClient); err == nil {
		t.Error("redirect chain longer than 3 should be rejected")
	} else if !strings.Contains(err.Error(), "redirect") {
		t.Errorf("unexpected error for over-long chain: %v", err)
	}

	// https→http 降级被拒（测试 TLS 证书非 CA 签发，跳过校验以聚焦重定向策略本身）
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, strings.Join(genV4Lines(1100), "\n"))
	}))
	defer plain.Close()
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL, http.StatusFound)
	}))
	defer tlsSrv.Close()
	m.httpClient.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}

	if _, err := m.doFetch(tlsSrv.URL, m.httpClient); err == nil {
		t.Error("https→http downgrade redirect should be rejected")
	} else if !strings.Contains(err.Error(), "downgrade") {
		t.Errorf("unexpected error for https→http downgrade: %v", err)
	}
}

// TestMultiSourceAnyFailureKeepsWholeTable 多源场景：任一 source 拉取失败则本轮整体失败，
// 保留上一轮完整旧表（含其他 source 的条目），不产生部分替换。
func TestMultiSourceAnyFailureKeepsWholeTable(t *testing.T) {
	var bMu sync.Mutex
	bFail := false
	mux := http.NewServeMux()
	mux.HandleFunc("/a", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, strings.Join(genV4Lines(1200), "\n"))
	})
	mux.HandleFunc("/b", func(w http.ResponseWriter, r *http.Request) {
		bMu.Lock()
		fail := bFail
		bMu.Unlock()
		if fail {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		bLines := make([]string, 0, 1200)
		for i := 0; i < 1200; i++ {
			bLines = append(bLines, idxIP(5000+i))
		}
		fmt.Fprint(w, strings.Join(bLines, "\n"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cfg := config.BlacklistConfig{
		Enabled: true,
		Sources: []config.BlacklistSourceConfig{
			{Name: "a", URL: srv.URL + "/a"},
			{Name: "b", URL: srv.URL + "/b"},
		},
	}
	m := NewManager(cfg, &mockLogger{})
	m.cacheDir = t.TempDir()

	m.refresh()
	if stats := m.GetStats(); stats.TotalEntries != 2400 {
		t.Fatalf("initial TotalEntries = %d, want 2400", stats.TotalEntries)
	}
	if hit, _ := m.Lookup(idxIP(0)); !hit {
		t.Error("source a entries missing after initial refresh")
	}
	if hit, _ := m.Lookup(idxIP(5000)); !hit {
		t.Error("source b entries missing after initial refresh")
	}

	// source b 失败：整体保留旧表
	bMu.Lock()
	bFail = true
	bMu.Unlock()
	m.refresh()

	if stats := m.GetStats(); stats.TotalEntries != 2400 {
		t.Errorf("TotalEntries = %d, want 2400 (any-source failure keeps the whole old table)", stats.TotalEntries)
	}
	if hit, _ := m.Lookup(idxIP(5000)); !hit {
		t.Error("source b entries from old table must remain")
	}
	if hit, _ := m.Lookup(idxIP(0)); !hit {
		t.Error("source a entries from old table must remain")
	}
	if stats := m.GetStats(); stats.LastAttemptAt == nil {
		t.Error("LastAttemptAt should be set after failed round")
	}
}

// TestDownloadSizeBoundary maxDownloadSize 边界：恰好等于上限成功，超 1 字节失败。
func TestDownloadSizeBoundary(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		size := maxDownloadSize
		if r.URL.Query().Get("over") == "1" {
			size++
		}
		buf := bytes.Repeat([]byte("a"), 64*1024)
		for written := 0; written < size; {
			n := size - written
			if n > len(buf) {
				n = len(buf)
			}
			if _, err := w.Write(buf[:n]); err != nil {
				return
			}
			written += n
		}
	}))
	defer srv.Close()

	m := newTestManager(t, srv.URL)

	data, err := m.doFetch(srv.URL, m.httpClient)
	if err != nil {
		t.Fatalf("download of exactly maxDownloadSize should succeed: %v", err)
	}
	if len(data) != maxDownloadSize {
		t.Errorf("downloaded %d bytes, want %d", len(data), maxDownloadSize)
	}

	if _, err := m.doFetch(srv.URL+"?over=1", m.httpClient); err == nil {
		t.Fatal("download exceeding maxDownloadSize by 1 byte should fail")
	} else if !strings.Contains(err.Error(), "exceeds limit") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestConcurrentAccessWithRefreshSwap 并发压力：多 goroutine 并发 Lookup/RecordHit/
// GetStats/GetEvents 与两次 refresh 换表交织（-race 验证）；事件时间戳必须非降序
// （限速判定与事件写入同临界区 + 单调钳制）。
func TestConcurrentAccessWithRefreshSwap(t *testing.T) {
	flip := &flipServer{body: strings.Join(genV4Lines(1500), "\n"), status: http.StatusOK}
	srv := httptest.NewServer(flip)
	defer srv.Close()

	m := newTestManager(t, srv.URL)
	m.refresh()

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func(seed int) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(int64(seed)))
			for {
				select {
				case <-stop:
					return
				default:
				}
				m.Lookup(idxIP(rng.Intn(1500)))
				m.RecordHit(config.BlacklistModeBlock,
					fmt.Sprintf("10.%d.%d.%d", rng.Intn(255), rng.Intn(255), rng.Intn(255)),
					"m", "h", "/p", "")
				_ = m.GetStats()
				_ = m.GetEvents(10)
			}
		}(g)
	}

	// 并发读写下换表两次（1200/1500 唯一条目均过防污染检查）
	time.Sleep(20 * time.Millisecond)
	flip.set(strings.Join(genV4Lines(1200), "\n"), http.StatusOK)
	m.refresh()
	flip.set(strings.Join(genV4Lines(1500), "\n"), http.StatusOK)
	m.refresh()

	close(stop)
	wg.Wait()

	if stats := m.GetStats(); stats.TotalEntries != 1500 {
		t.Errorf("TotalEntries = %d, want 1500 after final swap", stats.TotalEntries)
	}

	// 事件时间戳必须非降序（admin 事件表不得乱序）
	events := m.GetEvents(0)
	for i := 1; i < len(events); i++ {
		if events[i].Time.Before(events[i-1].Time) {
			t.Fatalf("event %d (%v) is older than event %d (%v): events must be in non-decreasing time order",
				i, events[i].Time, i-1, events[i-1].Time)
		}
	}
}

// ── L6（内部PRD）：防追加式投毒的增长上限 ─────────────────────────────
// 新 feed 去重条目数 > max(2×上次成功条目数, MaxEntries) → 拒绝替换、保留旧表；
// 上次成功条目数随成功替换更新；首次加载（无旧表）不受增长上限约束但受 MaxEntries 硬上限。

// growthStep L6 增长上限场景的单步：feed 条目数 + 期望是否替换
type growthStep struct {
	feedCount     int
	expectReplace bool
}

// runGrowthSteps 驱动多步 feed 变化并逐步断言替换/保留行为与日志级别
func runGrowthSteps(t *testing.T, m *Manager, flip *flipServer, rl *recordLogger, steps []growthStep) {
	t.Helper()
	prevTotal := 0
	for i, step := range steps {
		flip.set(strings.Join(genV4Lines(step.feedCount), "\n"), http.StatusOK)
		rl.reset()
		m.refresh()

		wantTotal := step.feedCount
		if !step.expectReplace {
			wantTotal = prevTotal
		}
		if stats := m.GetStats(); stats.TotalEntries != wantTotal {
			t.Errorf("step %d (feed=%d): TotalEntries = %d, want %d (replaced=%v)",
				i, step.feedCount, stats.TotalEntries, wantTotal, step.expectReplace)
		}
		if step.expectReplace {
			// 新表条目可查（以本次 feed 首条 IP 为探针）
			if hit, _ := m.Lookup(idxIP(0)); !hit {
				t.Errorf("step %d: Lookup should hit the new feed after replacement", i)
			}
		} else if prevTotal > 0 {
			// 拒绝替换：旧表仍生效（以旧表末条 IP 为探针）
			if hit, _ := m.Lookup(idxIP(prevTotal - 1)); !hit {
				t.Errorf("step %d: Lookup should still hit the old table after rejection", i)
			}
			if !rl.hasLevelContaining("warn", "growth cap") {
				t.Errorf("step %d: expected Warn log about growth cap, records: %+v", i, rl.snapshot())
			}
		} else {
			// 冷启动被拒：无旧表，按包内约定记 Error（fail-open 可见性）
			if !rl.hasLevelContaining("error", "growth cap") {
				t.Errorf("step %d: expected Error log about growth cap on cold start, records: %+v", i, rl.snapshot())
			}
		}
		if step.expectReplace {
			prevTotal = step.feedCount
		}
	}
}

// TestRefreshGrowthCapAppendBeyondDoubleRejected 出口标准⑤前半：从 N 条追加到
// 3N 条（3N > 2N）→ 拒绝替换、保留旧表；= 2N（边界，严格大于才拒）→ 允许。
// MaxEntries=4000 使 2×prev 分支成为约束（2250×2=4500 > 4000）
func TestRefreshGrowthCapAppendBeyondDoubleRejected(t *testing.T) {
	flip := &flipServer{status: http.StatusOK}
	srv := httptest.NewServer(flip)
	defer srv.Close()

	rl := &recordLogger{}
	cfg := config.BlacklistConfig{
		Enabled:    true,
		MaxEntries: 4000,
		Sources:    []config.BlacklistSourceConfig{{Name: "ustc", URL: srv.URL}},
	}
	m := NewManager(cfg, rl)
	m.cacheDir = t.TempDir()

	runGrowthSteps(t, m, flip, rl, []growthStep{
		{2250, true},  // 首刷：2250 ≤ max(0×2, 4000) → 接受
		{4501, false}, // 4501 > max(2×2250, 4000)=4500 → 拒绝，保留 2250
		{4500, true},  // 4500 = 2×2250（不大于）→ 允许（严格不等号边界）
	})
}

// TestRefreshGrowthCapAcceptsModerateGrowth 出口标准⑤后半：从 N 到 1.5N
// （≤2N 且 ≤MaxEntries）→ 正常替换
func TestRefreshGrowthCapAcceptsModerateGrowth(t *testing.T) {
	flip := &flipServer{status: http.StatusOK}
	srv := httptest.NewServer(flip)
	defer srv.Close()

	rl := &recordLogger{}
	cfg := config.BlacklistConfig{
		Enabled:    true,
		MaxEntries: 4000,
		Sources:    []config.BlacklistSourceConfig{{Name: "ustc", URL: srv.URL}},
	}
	m := NewManager(cfg, rl)
	m.cacheDir = t.TempDir()

	runGrowthSteps(t, m, flip, rl, []growthStep{
		{2000, true}, // 首刷
		{3000, true}, // 1.5N = 3000 ≤ max(2×2000, 4000)=4000 → 正常替换
	})
}

// TestRefreshFirstLoadBoundByMaxEntries 首次加载（无旧表）不受 2× 增长约束，
// 但受 MaxEntries 硬上限；基线随成功替换更新
func TestRefreshFirstLoadBoundByMaxEntries(t *testing.T) {
	flip := &flipServer{status: http.StatusOK}
	srv := httptest.NewServer(flip)
	defer srv.Close()

	rl := &recordLogger{}
	cfg := config.BlacklistConfig{
		Enabled:    true,
		MaxEntries: 1200,
		Sources:    []config.BlacklistSourceConfig{{Name: "ustc", URL: srv.URL}},
	}
	m := NewManager(cfg, rl)
	m.cacheDir = t.TempDir()

	runGrowthSteps(t, m, flip, rl, []growthStep{
		{1500, false}, // 首刷 1500 > max(0×2, 1200)=1200 → MaxEntries 硬上限拒绝
		{1100, true},  // 1100 ≤ 1200 且 ≥ minEntries → 接受
		{2300, false}, // 基线已更新为 1100：2300 > max(2×1100, 1200)=2200 → 拒绝保留 1100
		{2200, true},  // 2200 = 2×1100（不大于）→ 允许（严格不等号边界）
	})
}

// TestRefreshDefaultMaxEntriesDoesNotBindNormalFeeds 缺省 MaxEntries（200000）
// 不约束常规规模的 feed 增长（回归保护）
func TestRefreshDefaultMaxEntriesDoesNotBindNormalFeeds(t *testing.T) {
	flip := &flipServer{status: http.StatusOK}
	srv := httptest.NewServer(flip)
	defer srv.Close()

	m := newTestManager(t, srv.URL) // MaxEntries 未配置 → 缺省 200000
	runGrowthSteps(t, m, flip, &recordLogger{}, []growthStep{
		{1500, true},
		{4500, true}, // ≤ max(2×1500, 200000) → 允许
	})
}
