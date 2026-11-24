package server

// IP 黑名单请求链接入的集成测试（内部PRD §17.2 六场景）。
// 测试方式：httptest 后端 + httptest 黑名单数据源 + NewServer（真实首刷走 HTTP 循环，
// 数据 ≥ minEntries=1000 过防污染阈值）+ 直接调用 handleRequestForPort，不启动监听端口。

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/lite-lake/infra-gate/internal/config"
	"github.com/lite-lake/infra-gate/internal/infrastructs/logger"
)

// blTestLogger 实现 logger.ILogger 的空实现（仿 blacklist/fetcher_test.go 的 mockLogger）
type blTestLogger struct{}

func (l *blTestLogger) Debug(msg string, fields ...logger.Field) {}
func (l *blTestLogger) Info(msg string, fields ...logger.Field)  {}
func (l *blTestLogger) Warn(msg string, fields ...logger.Field)  {}
func (l *blTestLogger) Error(msg string, fields ...logger.Field) {}
func (l *blTestLogger) Fatal(msg string, fields ...logger.Field) {}
func (l *blTestLogger) WithContext(ctx context.Context) logger.ILogger {
	return l
}
func (l *blTestLogger) WithField(key string, value interface{}) logger.ILogger { return l }
func (l *blTestLogger) WithFields(fields map[string]interface{}) logger.ILogger {
	return l
}
func (l *blTestLogger) WithTraceId(traceId string) logger.ILogger { return l }
func (l *blTestLogger) SetLevel(level logger.LogLevel)            {}
func (l *blTestLogger) GetLevel() logger.LogLevel                 { return logger.DebugLevel }
func (l *blTestLogger) Close() error                              { return nil }

// blLogRecord 一条被记录的日志（含字段，用于断言 Warn 中的条目内容）
type blLogRecord struct {
	level  string
	msg    string
	fields []logger.Field
}

// blRecordLogger 可捕获日志调用的测试 logger（仿 blacklist/fetcher_test.go 的
// recordLogger 模式，额外捕获 fields——用于断言 NewServer 预解析非法 whitelist
// 条目时的 Warn 带条目内容）
type blRecordLogger struct {
	mu      sync.Mutex
	records []blLogRecord
}

func (r *blRecordLogger) append(level, msg string, fields []logger.Field) {
	r.mu.Lock()
	r.records = append(r.records, blLogRecord{level: level, msg: msg, fields: fields})
	r.mu.Unlock()
}

func (r *blRecordLogger) Debug(msg string, fields ...logger.Field)       { r.append("debug", msg, fields) }
func (r *blRecordLogger) Info(msg string, fields ...logger.Field)        { r.append("info", msg, fields) }
func (r *blRecordLogger) Warn(msg string, fields ...logger.Field)        { r.append("warn", msg, fields) }
func (r *blRecordLogger) Error(msg string, fields ...logger.Field)       { r.append("error", msg, fields) }
func (r *blRecordLogger) Fatal(msg string, fields ...logger.Field)       { r.append("fatal", msg, fields) }
func (r *blRecordLogger) WithContext(ctx context.Context) logger.ILogger { return r }
func (r *blRecordLogger) WithField(key string, value interface{}) logger.ILogger {
	return r
}
func (r *blRecordLogger) WithFields(fields map[string]interface{}) logger.ILogger { return r }
func (r *blRecordLogger) WithTraceId(traceId string) logger.ILogger               { return r }
func (r *blRecordLogger) SetLevel(level logger.LogLevel)                          {}
func (r *blRecordLogger) GetLevel() logger.LogLevel                               { return logger.DebugLevel }
func (r *blRecordLogger) Close() error                                            { return nil }

// hasWarnWithField 判断是否存在携带指定 key/value 字段（fmt.Sprint 比较）的 Warn 日志
func (r *blRecordLogger) hasWarnWithField(key, value string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, rec := range r.records {
		if rec.level != "warn" {
			continue
		}
		for _, f := range rec.fields {
			if f.Key == key && fmt.Sprint(f.Value) == value {
				return true
			}
		}
	}
	return false
}

// 测试数据常量：1200 条 ≥ minEntries(1000) 防污染阈值；
// 目标 IP 混入生成的列表中，干净 IP 不在列表且不属于保留网段
const (
	blSourceName = "bltest"
	blEntries    = 1200
	blTargetIP   = "1.0.0.42" // blIP(42)：在黑名单列表内
	blCleanIP    = "2.3.4.4"  // 不在列表内、非保留网段
)

// blIP 返回 blGenLines 中第 i 条（0 起算）IP（1.x.y.z 段，避开保留网段）
func blIP(i int) string {
	return fmt.Sprintf("1.%d.%d.%d", (i>>16)&0xFF, (i>>8)&0xFF, i&0xFF)
}

// blGenLines 生成 n 条互不重复的公网 IPv4 单 IP 文本
func blGenLines(n int) string {
	lines := make([]string, 0, n)
	for i := 0; i < n; i++ {
		lines = append(lines, blIP(i))
	}
	return strings.Join(lines, "\n")
}

// chdirToRepoRoot 将工作目录切到仓库根目录：模板渲染器（blocked.html）与
// 黑名单磁盘缓存（./cache/blacklist）均按相对路径解析，测试须在仓库根下运行。
// 测试结束后恢复原目录（同包测试串行执行，无并发冲突）。
func chdirToRepoRoot(t *testing.T) {
	t.Helper()
	origWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir("../.."); err != nil {
		t.Fatalf("chdir to repo root: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(origWd); err != nil {
			t.Errorf("restore cwd: %v", err)
		}
	})
}

// newBLBackend 返回固定 200 "backend-ok" 的后端，以及命中计数（用于断言
// 被拦截的请求没有透传到后端）
func newBLBackend(t *testing.T) (*httptest.Server, *int64) {
	t.Helper()
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "backend-ok")
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// newBLSource 返回黑名单数据源（内容含 blTargetIP），以及拉取计数
// （用于断言 enabled=false 时一次拉取都不发生）
func newBLSource(t *testing.T) (*httptest.Server, *int64) {
	t.Helper()
	var hits int64
	body := blGenLines(blEntries)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
		fmt.Fprint(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func strPtr(s string) *string { return &s }
func boolPtr(b bool) *bool    { return &b }

// blHost 构建一个指向 backendURL 的虚拟主机（禁用健康检查，避免测试中启动
// 健康检查 goroutine）；bl 为 host 级黑名单覆盖，nil = 继承全局
func blHost(name, backendURL string, bl *config.HostBlacklistOverride) config.HostConfig {
	return config.HostConfig{
		Name:               name,
		Port:               8080,
		Backend:            []string{backendURL},
		HealthCheckEnabled: boolPtr(false),
		Blacklist:          bl,
	}
}

// newBLServer 构建 NewServer 产物：enabled=true 时等待异步首刷完成（真实 HTTP
// 循环拉取数据源）。cleanup 中走 shutdownAllServers 停止代理与黑名单管理器。
func newBLServer(t *testing.T, cfg *config.Config) *Server {
	return newBLServerWithLogger(t, cfg, &blTestLogger{})
}

// newBLServerWithLogger 同 newBLServer，但允许注入可捕获日志的 logger
// （用于断言 NewServer 阶段的 Warn，如非法 whitelist 条目）
func newBLServerWithLogger(t *testing.T, cfg *config.Config, log logger.ILogger) *Server {
	t.Helper()
	s, err := NewServer(cfg, log)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() {
		s.shutdownAllServers()
	})
	if s.blacklistManager != nil {
		waitBLRefreshReady(t, s)
	}
	return s
}

// waitBLRefreshReady 轮询等待黑名单首刷成功（LastSuccessAt 仅由真实 refresh 设置，
// 磁盘缓存加载不算），超时则失败并输出统计快照辅助定位
func waitBLRefreshReady(t *testing.T, s *Server) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if st := s.blacklistManager.GetStats(); st.LastSuccessAt != nil {
			if st.TotalEntries != blEntries {
				t.Fatalf("first refresh loaded %d entries, want %d", st.TotalEntries, blEntries)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("blacklist first refresh did not succeed within timeout, stats: %+v", s.blacklistManager.GetStats())
}

// blDoRequest 直接调用 handleRequestForPort 发起一次请求（不启动监听端口）。
// clientIP 通过 RemoteAddr 模拟（未配置可信代理时 ResolveClientIP 取直连地址）。
func blDoRequest(s *Server, hostName, clientIP, path, traceID string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "http://"+hostName+path, nil)
	req.RemoteAddr = clientIP + ":54321"
	if traceID != "" {
		req.Header.Set("X-Lite-Gate-Trace-Id", traceID)
	}
	return blDoRequestWithReq(s, req)
}

// blDoRequestWithReq 直接调用 handleRequestForPort 发起构造好的请求
// （不启动监听端口），供需要自定义请求头（如 WebSocket 升级）或 r.TLS 的场景使用。
func blDoRequestWithReq(s *Server, req *http.Request) *httptest.ResponseRecorder {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	s.handleRequestForPort(c, s.config.Hosts)
	return w
}

// 场景 1（§17.2）：detect 模式命中 → 放行（透传到后端，状态码不变），
// HitTotalDetect 增加，GetEvents 有对应事件记录
func TestBlacklistDetectModeHitPassesThroughAndRecords(t *testing.T) {
	chdirToRepoRoot(t)
	backend, backendHits := newBLBackend(t)
	src, _ := newBLSource(t)

	cfg := &config.Config{
		// trusted_proxies 含模拟客户端 IP：本用例验证事件记录请求 TraceID（采信语义），
		// 内部PRD 信任模型下不受信直连的入站 ID 会被重新生成
		Server: config.ServerConfig{Port: 8080, TrustedProxies: []string{blTargetIP}},
		Hosts:  []config.HostConfig{blHost("bl.example.com", backend.URL, nil)},
		Blacklist: config.BlacklistConfig{
			Enabled:     true,
			DefaultMode: config.BlacklistModeDetect,
			Sources:     []config.BlacklistSourceConfig{{Name: blSourceName, URL: src.URL}},
		},
	}
	s := newBLServer(t, cfg)

	w := blDoRequest(s, "bl.example.com", blTargetIP, "/wp-login.php", "bltrace1")
	if w.Code != http.StatusOK {
		t.Errorf("detect mode hit status = %d, want 200 (pass through)", w.Code)
	}
	if !strings.Contains(w.Body.String(), "backend-ok") {
		t.Errorf("detect mode hit body = %q, want backend response", w.Body.String())
	}
	if n := atomic.LoadInt64(backendHits); n != 1 {
		t.Errorf("backend hits = %d, want 1", n)
	}

	stats := s.GetBlacklistStats()
	if stats.HitTotalDetect != 1 || stats.HitTotalBlock != 0 {
		t.Errorf("hits = (block %d, detect %d), want (0, 1)", stats.HitTotalBlock, stats.HitTotalDetect)
	}

	events := s.GetBlacklistEvents(10)
	if len(events) != 1 {
		t.Fatalf("events len = %d, want 1", len(events))
	}
	ev := events[0]
	if ev.ClientIP != blTargetIP || ev.Matched != blTargetIP {
		t.Errorf("event = (ip %q, matched %q), want (%q, %q)", ev.ClientIP, ev.Matched, blTargetIP, blTargetIP)
	}
	if ev.Mode != config.BlacklistModeDetect || ev.Host != "bl.example.com" {
		t.Errorf("event = (mode %q, host %q), want (detect, bl.example.com)", ev.Mode, ev.Host)
	}
	if ev.Path != "/wp-login.php" || ev.TraceID != "bltrace1" {
		t.Errorf("event = (path %q, trace %q), want (/wp-login.php, bltrace1)", ev.Path, ev.TraceID)
	}
}

// 场景 2（§17.2）：block 模式命中 → 403 且响应体含 blocked 页面标识（含 TraceID）；
// 未命中 IP 正常代理到后端；被拦截的请求不透传后端
func TestBlacklistBlockModeReturns403AndCleanIPProxies(t *testing.T) {
	chdirToRepoRoot(t)
	backend, backendHits := newBLBackend(t)
	src, _ := newBLSource(t)

	cfg := &config.Config{
		// trusted_proxies 含模拟客户端 IP：本用例验证拦截页展示请求 TraceID（采信语义）
		Server: config.ServerConfig{Port: 8080, TrustedProxies: []string{blTargetIP}},
		Hosts:  []config.HostConfig{blHost("bl.example.com", backend.URL, nil)},
		Blacklist: config.BlacklistConfig{
			Enabled: true,
			Sources: []config.BlacklistSourceConfig{{Name: blSourceName, URL: src.URL}},
			// DefaultMode 留空 = 默认 block（GetEffectiveBlacklistMode 回退语义）
		},
	}
	s := newBLServer(t, cfg)

	// 命中：403 + blocked 页面标识
	w := blDoRequest(s, "bl.example.com", blTargetIP, "/admin", "bltrace2")
	if w.Code != http.StatusForbidden {
		t.Errorf("block mode hit status = %d, want 403", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "访问被拦截") {
		t.Errorf("block mode body should contain blocked page marker, got: %.200s", body)
	}
	if !strings.Contains(body, "bltrace2") {
		t.Errorf("block mode body should contain trace id for user reporting, got: %.200s", body)
	}
	if n := atomic.LoadInt64(backendHits); n != 0 {
		t.Errorf("backend hits after blocked request = %d, want 0", n)
	}

	stats := s.GetBlacklistStats()
	if stats.HitTotalBlock != 1 || stats.HitTotalDetect != 0 {
		t.Errorf("hits = (block %d, detect %d), want (1, 0)", stats.HitTotalBlock, stats.HitTotalDetect)
	}
	events := s.GetBlacklistEvents(10)
	if len(events) != 1 || events[0].Mode != config.BlacklistModeBlock {
		t.Errorf("events = %+v, want 1 block event", events)
	}

	// 未命中：正常代理到后端
	w = blDoRequest(s, "bl.example.com", blCleanIP, "/", "bltrace3")
	if w.Code != http.StatusOK {
		t.Errorf("clean ip status = %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), "backend-ok") {
		t.Errorf("clean ip body = %q, want backend response", w.Body.String())
	}
	if n := atomic.LoadInt64(backendHits); n != 1 {
		t.Errorf("backend hits = %d, want 1 (only the clean request)", n)
	}

	// 未命中不记统计
	if st := s.GetBlacklistStats(); st.HitTotalBlock != 1 {
		t.Errorf("HitTotalBlock = %d after clean request, want still 1", st.HitTotalBlock)
	}
}

// 场景 3（§17.2）：本地白名单优先 —— IP 在黑名单中但在 blacklist.whitelist 中
// → 放行且不记事件（HitTotal 不变）
func TestBlacklistWhitelistSkipsBlacklistCheck(t *testing.T) {
	chdirToRepoRoot(t)
	backend, backendHits := newBLBackend(t)
	src, _ := newBLSource(t)

	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Hosts:  []config.HostConfig{blHost("bl.example.com", backend.URL, nil)},
		Blacklist: config.BlacklistConfig{
			Enabled:     true,
			DefaultMode: config.BlacklistModeBlock,
			Sources:     []config.BlacklistSourceConfig{{Name: blSourceName, URL: src.URL}},
			Whitelist:   []string{blTargetIP}, // 目标 IP 同时在黑名单与本地白名单
		},
	}
	s := newBLServer(t, cfg)

	w := blDoRequest(s, "bl.example.com", blTargetIP, "/", "bltrace4")
	if w.Code != http.StatusOK {
		t.Errorf("whitelisted ip status = %d, want 200 (local whitelist wins)", w.Code)
	}
	if !strings.Contains(w.Body.String(), "backend-ok") {
		t.Errorf("whitelisted ip body = %q, want backend response", w.Body.String())
	}
	if n := atomic.LoadInt64(backendHits); n != 1 {
		t.Errorf("backend hits = %d, want 1", n)
	}

	stats := s.GetBlacklistStats()
	if stats.HitTotalBlock != 0 || stats.HitTotalDetect != 0 {
		t.Errorf("hits = (block %d, detect %d), want (0, 0): whitelist must not record", stats.HitTotalBlock, stats.HitTotalDetect)
	}
	if events := s.GetBlacklistEvents(10); len(events) != 0 {
		t.Errorf("events len = %d, want 0: whitelist must not record events", len(events))
	}
}

// 场景 4（§17.2）：host 覆盖 —— 全局 block + host 级 disabled → 该 host 放行；
// host 覆盖 detect → 放行但记 detect；未覆盖 host 继承全局 block
func TestBlacklistHostOverrideDisabledAndDetect(t *testing.T) {
	chdirToRepoRoot(t)
	backend, _ := newBLBackend(t)
	src, _ := newBLSource(t)

	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Hosts: []config.HostConfig{
			blHost("disabled.example.com", backend.URL, &config.HostBlacklistOverride{
				DefaultMode: strPtr(config.BlacklistModeDisabled),
			}),
			blHost("detect.example.com", backend.URL, &config.HostBlacklistOverride{
				DefaultMode: strPtr(config.BlacklistModeDetect),
			}),
			blHost("inherit.example.com", backend.URL, nil),
		},
		Blacklist: config.BlacklistConfig{
			Enabled:     true,
			DefaultMode: config.BlacklistModeBlock,
			Sources:     []config.BlacklistSourceConfig{{Name: blSourceName, URL: src.URL}},
		},
	}
	s := newBLServer(t, cfg)

	// host 级 disabled：黑名单 IP 放行，且不记任何统计/事件
	if w := blDoRequest(s, "disabled.example.com", blTargetIP, "/", "bltrace5"); w.Code != http.StatusOK {
		t.Errorf("host disabled status = %d, want 200", w.Code)
	}
	if st := s.GetBlacklistStats(); st.HitTotalBlock != 0 || st.HitTotalDetect != 0 {
		t.Errorf("host disabled hits = (block %d, detect %d), want (0, 0)", st.HitTotalBlock, st.HitTotalDetect)
	}
	if events := s.GetBlacklistEvents(10); len(events) != 0 {
		t.Errorf("host disabled events len = %d, want 0", len(events))
	}

	// host 级 detect：放行但记 detect
	if w := blDoRequest(s, "detect.example.com", blTargetIP, "/", "bltrace6"); w.Code != http.StatusOK {
		t.Errorf("host detect status = %d, want 200", w.Code)
	}
	if st := s.GetBlacklistStats(); st.HitTotalDetect != 1 || st.HitTotalBlock != 0 {
		t.Errorf("host detect hits = (block %d, detect %d), want (0, 1)", st.HitTotalBlock, st.HitTotalDetect)
	}

	// 未覆盖 host：继承全局 block → 403
	if w := blDoRequest(s, "inherit.example.com", blTargetIP, "/", "bltrace7"); w.Code != http.StatusForbidden {
		t.Errorf("inherit host status = %d, want 403 (global block)", w.Code)
	}
	if st := s.GetBlacklistStats(); st.HitTotalBlock != 1 || st.HitTotalDetect != 1 {
		t.Errorf("final hits = (block %d, detect %d), want (1, 1)", st.HitTotalBlock, st.HitTotalDetect)
	}
}

// 场景 5（§17.2）：enabled=false —— 完全不检查：即使数据源列表含该 IP 仍正常代理，
// manager 为 nil（零开销路径），且一次数据源拉取都不发生
func TestBlacklistEnabledFalseSkipsEntirely(t *testing.T) {
	chdirToRepoRoot(t)
	backend, backendHits := newBLBackend(t)
	src, srcHits := newBLSource(t)

	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Hosts:  []config.HostConfig{blHost("bl.example.com", backend.URL, nil)},
		Blacklist: config.BlacklistConfig{
			Enabled: false, // 数据源已配置但不启用
			Sources: []config.BlacklistSourceConfig{{Name: blSourceName, URL: src.URL}},
		},
	}
	s := newBLServer(t, cfg)

	if s.blacklistManager != nil {
		t.Error("blacklistManager should be nil when blacklist.enabled is false")
	}

	w := blDoRequest(s, "bl.example.com", blTargetIP, "/", "bltrace8")
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (blacklisted IP must proxy normally when disabled)", w.Code)
	}
	if !strings.Contains(w.Body.String(), "backend-ok") {
		t.Errorf("body = %q, want backend response", w.Body.String())
	}
	if n := atomic.LoadInt64(backendHits); n != 1 {
		t.Errorf("backend hits = %d, want 1", n)
	}
	if n := atomic.LoadInt64(srcHits); n != 0 {
		t.Errorf("source fetch count = %d, want 0 (no fetch when disabled)", n)
	}
}

// 场景 6：GetBlacklistStats / GetBlacklistEvents 在 manager 为 nil 时
// 返回零值快照 / 空切片，不得 panic（迭代 3 admin 注入的前置契约）
func TestBlacklistAccessorsWithNilManager(t *testing.T) {
	chdirToRepoRoot(t)
	backend, _ := newBLBackend(t)

	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Hosts:  []config.HostConfig{blHost("bl.example.com", backend.URL, nil)},
	}
	s := newBLServer(t, cfg)

	stats := s.GetBlacklistStats()
	if stats.Enabled || stats.DefaultMode != "" || stats.TotalEntries != 0 ||
		stats.HitTotalBlock != 0 || stats.HitTotalDetect != 0 || stats.RecentHits != 0 {
		t.Errorf("GetBlacklistStats with nil manager = %+v, want zero snapshot", stats)
	}

	events := s.GetBlacklistEvents(50)
	if events == nil {
		t.Error("GetBlacklistEvents with nil manager should return non-nil empty slice")
	}
	if len(events) != 0 {
		t.Errorf("GetBlacklistEvents len = %d, want 0", len(events))
	}
}

// 补充（§6.2 要点）：block 模式对 text 静态响应 host 同样生效 ——
// 黑名单 IP 得到 403 blocked 页而非放行到静态文本；干净 IP 得到静态文本
func TestBlacklistAppliesToTextHost(t *testing.T) {
	chdirToRepoRoot(t)
	src, _ := newBLSource(t)

	// 不用 blHost：text host 无 backend（blHost 的 backendURL 参数会成为单元素切片，
	// 使请求走代理而非 text 响应）
	textHost := config.HostConfig{
		Name:               "text.example.com",
		Port:               8080,
		Text:               "static-text-response",
		HealthCheckEnabled: boolPtr(false),
	}
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Hosts:  []config.HostConfig{textHost},
		Blacklist: config.BlacklistConfig{
			Enabled:     true,
			DefaultMode: config.BlacklistModeBlock,
			Sources:     []config.BlacklistSourceConfig{{Name: blSourceName, URL: src.URL}},
		},
	}
	s := newBLServer(t, cfg)

	// 黑名单 IP：403 + blocked 页面（不因 text host 放行到静态文本）
	w := blDoRequest(s, "text.example.com", blTargetIP, "/", "bltrace9")
	if w.Code != http.StatusForbidden {
		t.Errorf("text host blacklisted ip status = %d, want 403", w.Code)
	}
	if body := w.Body.String(); !strings.Contains(body, "访问被拦截") {
		t.Errorf("text host blacklisted ip body should be blocked page, got: %.200s", body)
	}

	// 干净 IP：正常返回静态文本
	w = blDoRequest(s, "text.example.com", blCleanIP, "/", "bltrace10")
	if w.Code != http.StatusOK {
		t.Errorf("text host clean ip status = %d, want 200", w.Code)
	}
	if body := w.Body.String(); !strings.Contains(body, "static-text-response") {
		t.Errorf("text host clean ip body = %q, want static text", body)
	}
}

// 补充（§6.2 检查点位置）：黑名单检查必须在 host 匹配之后、allowed_ips 之前。
//   - 未匹配 host：黑名单 IP 也得到 404（host 匹配在前）
//   - host 配置了不含客户端的 allowed_ips：黑名单命中返回 blocked 页而非
//     allowed_ips 的裸 "Forbidden"（黑名单在前），干净 IP 仍被 allowed_ips 拒绝
func TestBlacklistCheckOrderAfterHostMatchBeforeAllowedIPs(t *testing.T) {
	chdirToRepoRoot(t)
	backend, backendHits := newBLBackend(t)
	src, _ := newBLSource(t)

	restrictedHost := blHost("restricted.example.com", backend.URL, nil)
	restrictedHost.AllowedIPs = []string{"203.0.113.99"} // 不含 blTargetIP/blCleanIP
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Hosts: []config.HostConfig{
			restrictedHost,
			blHost("bl.example.com", backend.URL, nil),
		},
		Blacklist: config.BlacklistConfig{
			Enabled:     true,
			DefaultMode: config.BlacklistModeBlock,
			Sources:     []config.BlacklistSourceConfig{{Name: blSourceName, URL: src.URL}},
		},
	}
	s := newBLServer(t, cfg)

	// 未匹配 host：黑名单 IP 得到 404（host 匹配优先于黑名单检查）
	if w := blDoRequest(s, "nonexistent.example.com", blTargetIP, "/", "bltrace11"); w.Code != http.StatusNotFound {
		t.Errorf("unknown host with blacklisted ip status = %d, want 404 (host match runs first)", w.Code)
	}

	// 黑名单 IP + allowed_ips 不含该 IP：得到 blocked 页（黑名单先于 allowed_ips），
	// 而非 allowed_ips 拒绝时的裸 "Forbidden"
	w := blDoRequest(s, "restricted.example.com", blTargetIP, "/", "bltrace12")
	if w.Code != http.StatusForbidden {
		t.Errorf("blacklisted ip on restricted host status = %d, want 403", w.Code)
	}
	if body := w.Body.String(); !strings.Contains(body, "访问被拦截") {
		t.Errorf("blacklisted ip on restricted host should hit blacklist page before allowed_ips, got: %.200s", body)
	}
	if n := atomic.LoadInt64(backendHits); n != 0 {
		t.Errorf("backend hits = %d, want 0", n)
	}

	// 干净 IP 也不在 allowed_ips 内：由 allowed_ips 拒绝（裸 Forbidden），证明链路继续
	w = blDoRequest(s, "restricted.example.com", blCleanIP, "/", "bltrace13")
	if w.Code != http.StatusForbidden {
		t.Errorf("clean ip on restricted host status = %d, want 403 (allowed_ips)", w.Code)
	}
	if body := w.Body.String(); strings.Contains(body, "访问被拦截") {
		t.Errorf("clean ip on restricted host should be rejected by allowed_ips (plain Forbidden), got blocked page: %.200s", body)
	}
}

// 修复测试（P1，PRD §7.3）：whitelist 含非法条目时 NewServer 预解析记 Warn（带条目
// 内容）并跳过，不阻断启动；合法条目（单 IP 与 CIDR）仍生效——黑名单中被白名单
// 单 IP 豁免的来源放行，未被豁免的黑名单 IP 仍被拦截。
func TestBlacklistWhitelistInvalidEntryWarnsAndSkips(t *testing.T) {
	chdirToRepoRoot(t)
	backend, backendHits := newBLBackend(t)
	src, _ := newBLSource(t)

	rl := &blRecordLogger{}
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Hosts:  []config.HostConfig{blHost("bl.example.com", backend.URL, nil)},
		Blacklist: config.BlacklistConfig{
			Enabled:     true,
			DefaultMode: config.BlacklistModeBlock,
			Sources:     []config.BlacklistSourceConfig{{Name: blSourceName, URL: src.URL}},
			// 1 个非法条目 + 1 个合法单 IP + 1 个合法 CIDR
			Whitelist: []string{"not-an-ip", blTargetIP, "10.0.0.0/8"},
		},
	}
	s := newBLServerWithLogger(t, cfg, rl)

	// 启动时有 Warn 日志，且携带非法条目内容
	if !rl.hasWarnWithField("entry", "not-an-ip") {
		t.Error("NewServer should log a Warn containing the invalid whitelist entry")
	}
	// 非法条目被跳过：仅解析出 2 个有效网段
	if len(s.blacklistWhitelistNets) != 2 {
		t.Errorf("blacklistWhitelistNets len = %d, want 2 (invalid entry skipped)", len(s.blacklistWhitelistNets))
	}

	// 合法单 IP 条目仍生效：黑名单中的 blTargetIP 被白名单豁免 → 透传后端，不记事件
	if w := blDoRequest(s, "bl.example.com", blTargetIP, "/", "bltrace20"); w.Code != http.StatusOK {
		t.Errorf("whitelisted ip status = %d, want 200", w.Code)
	}
	if n := atomic.LoadInt64(backendHits); n != 1 {
		t.Errorf("backend hits = %d, want 1 (whitelisted request proxied)", n)
	}

	// 未被白名单覆盖的黑名单 IP（blIP(100) 不在 blTargetIP/32 与 10.0.0.0/8 内）仍被拦截
	if w := blDoRequest(s, "bl.example.com", blIP(100), "/", "bltrace21"); w.Code != http.StatusForbidden {
		t.Errorf("blacklisted non-whitelisted ip status = %d, want 403", w.Code)
	}
	if st := s.GetBlacklistStats(); st.HitTotalBlock != 1 || st.HitTotalDetect != 0 {
		t.Errorf("hits = (block %d, detect %d), want (1, 0)", st.HitTotalBlock, st.HitTotalDetect)
	}
	if n := atomic.LoadInt64(backendHits); n != 1 {
		t.Errorf("backend hits after blocked request = %d, want still 1", n)
	}
}

// 修复测试（§6.2 检查点覆盖）：黑名单 IP 的 WebSocket 升级请求
// （GET + Connection/Upgrade/Sec-WebSocket-Key/Sec-WebSocket-Version 规范头）
// 同样在黑名单检查点被 403 拦截（黑名单检查先于 WebSocket 判定与代理），不透传后端。
func TestBlacklistBlocksWebSocketUpgradeRequest(t *testing.T) {
	chdirToRepoRoot(t)
	backend, backendHits := newBLBackend(t)
	src, _ := newBLSource(t)

	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Hosts:  []config.HostConfig{blHost("bl.example.com", backend.URL, nil)},
		Blacklist: config.BlacklistConfig{
			Enabled:     true,
			DefaultMode: config.BlacklistModeBlock,
			Sources:     []config.BlacklistSourceConfig{{Name: blSourceName, URL: src.URL}},
		},
	}
	s := newBLServer(t, cfg)

	req := httptest.NewRequest(http.MethodGet, "http://bl.example.com/chat", nil)
	req.RemoteAddr = blTargetIP + ":54321"
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	req.Header.Set("Sec-WebSocket-Version", "13")

	w := blDoRequestWithReq(s, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("websocket upgrade from blacklisted ip status = %d, want 403", w.Code)
	}
	if body := w.Body.String(); !strings.Contains(body, "访问被拦截") {
		t.Errorf("websocket upgrade blocked body should be blocked page, got: %.200s", body)
	}
	if n := atomic.LoadInt64(backendHits); n != 0 {
		t.Errorf("backend hits = %d, want 0 (blocked before proxy)", n)
	}
	if st := s.GetBlacklistStats(); st.HitTotalBlock != 1 {
		t.Errorf("HitTotalBlock = %d, want 1", st.HitTotalBlock)
	}
}

// 修复测试（§6.2 链路完整性）：detect 命中仅记录不拦截，请求继续走 allowed_ips
// 并被其拒绝（403 裸 Forbidden，非黑名单 blocked 页），证明 detect 放行后链路完整；
// 阳性对照：allowed_ips 内的干净 IP 正常透传后端。
func TestBlacklistDetectHitContinuesToAllowedIPsRejection(t *testing.T) {
	chdirToRepoRoot(t)
	backend, backendHits := newBLBackend(t)
	src, _ := newBLSource(t)

	restrictedHost := blHost("restricted.example.com", backend.URL, nil)
	restrictedHost.AllowedIPs = []string{"203.0.113.99", blCleanIP} // 含 blCleanIP 用于阳性对照
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Hosts:  []config.HostConfig{restrictedHost},
		Blacklist: config.BlacklistConfig{
			Enabled:     true,
			DefaultMode: config.BlacklistModeDetect,
			Sources:     []config.BlacklistSourceConfig{{Name: blSourceName, URL: src.URL}},
		},
	}
	s := newBLServer(t, cfg)

	// 黑名单 IP：detect 记录后放行 → 被 allowed_ips 拒绝（裸 Forbidden）
	w := blDoRequest(s, "restricted.example.com", blTargetIP, "/", "bltrace22")
	if w.Code != http.StatusForbidden {
		t.Errorf("detect hit + disallowed ip status = %d, want 403 (allowed_ips rejection)", w.Code)
	}
	if body := w.Body.String(); strings.Contains(body, "访问被拦截") {
		t.Errorf("body should be plain allowed_ips Forbidden, got blocked page: %.200s", body)
	}
	if !strings.Contains(w.Body.String(), "Forbidden") {
		t.Errorf("body should contain plain Forbidden text, got: %.200s", w.Body.String())
	}
	if n := atomic.LoadInt64(backendHits); n != 0 {
		t.Errorf("backend hits = %d, want 0 (rejected by allowed_ips)", n)
	}

	// detect 事件已记录（证明黑名单检查点确实命中过且放行）
	if st := s.GetBlacklistStats(); st.HitTotalDetect != 1 || st.HitTotalBlock != 0 {
		t.Errorf("hits = (block %d, detect %d), want (0, 1)", st.HitTotalBlock, st.HitTotalDetect)
	}
	events := s.GetBlacklistEvents(10)
	if len(events) != 1 || events[0].Mode != config.BlacklistModeDetect {
		t.Errorf("events = %+v, want 1 detect event", events)
	}

	// 阳性对照：allowed_ips 内的干净 IP 正常透传后端（allowed_ips 链路可用）
	wClean := blDoRequest(s, "restricted.example.com", blCleanIP, "/", "bltrace23")
	if wClean.Code != http.StatusOK {
		t.Errorf("allowed clean ip status = %d, want 200", wClean.Code)
	}
	if !strings.Contains(wClean.Body.String(), "backend-ok") {
		t.Errorf("allowed clean ip body = %q, want backend response", wClean.Body.String())
	}
	if n := atomic.LoadInt64(backendHits); n != 1 {
		t.Errorf("backend hits = %d, want 1", n)
	}
}

// 修复测试（§5 拦截页 TraceID 上报 + 内部PRD 信任模型）：拦截响应带
// X-Lite-Gate-Trace-Id 响应头——受信直连携带请求 TraceID 时采信回显同值；
// 不受信直连（未配 trusted_proxies）无视入站值重新生成；未携带时自动生成（均非空）。
func TestBlacklistBlockResponseCarriesTraceIdHeader(t *testing.T) {
	chdirToRepoRoot(t)
	backend, _ := newBLBackend(t)
	src, _ := newBLSource(t)

	// 受信直连版：trusted_proxies 含模拟客户端 IP（blTargetIP），入站 ID 被采信
	cfgTrusted := &config.Config{
		Server: config.ServerConfig{Port: 8080, TrustedProxies: []string{blTargetIP}},
		Hosts:  []config.HostConfig{blHost("bl.example.com", backend.URL, nil)},
		Blacklist: config.BlacklistConfig{
			Enabled:     true,
			DefaultMode: config.BlacklistModeBlock,
			Sources:     []config.BlacklistSourceConfig{{Name: blSourceName, URL: src.URL}},
		},
	}
	sTrusted := newBLServer(t, cfgTrusted)
	w := blDoRequest(sTrusted, "bl.example.com", blTargetIP, "/", "bltrace24")
	if w.Code != http.StatusForbidden {
		t.Fatalf("trusted direct status = %d, want 403", w.Code)
	}
	if got := w.Header().Get("X-Lite-Gate-Trace-Id"); got != "bltrace24" {
		t.Errorf("trusted direct X-Lite-Gate-Trace-Id = %q, want bltrace24 (adopted)", got)
	}

	// 边缘语义版：未配置 trusted_proxies，入站 ID 无视、重新生成（非空且 ≠ 入站值）
	cfgEdge := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Hosts:  []config.HostConfig{blHost("bl.example.com", backend.URL, nil)},
		Blacklist: config.BlacklistConfig{
			Enabled:     true,
			DefaultMode: config.BlacklistModeBlock,
			Sources:     []config.BlacklistSourceConfig{{Name: blSourceName, URL: src.URL}},
		},
	}
	sEdge := newBLServer(t, cfgEdge)
	w = blDoRequest(sEdge, "bl.example.com", blTargetIP, "/", "bltrace24")
	if w.Code != http.StatusForbidden {
		t.Fatalf("edge direct status = %d, want 403", w.Code)
	}
	got := w.Header().Get("X-Lite-Gate-Trace-Id")
	if got == "" || got == "bltrace24" {
		t.Errorf("edge direct X-Lite-Gate-Trace-Id = %q, want regenerated (non-empty, ≠ inbound)", got)
	}

	// 请求未携带：自动生成新 TraceID 并回显（非空）
	w = blDoRequest(sEdge, "bl.example.com", blTargetIP, "/", "")
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
	if got := w.Header().Get("X-Lite-Gate-Trace-Id"); got == "" {
		t.Error("X-Lite-Gate-Trace-Id should be generated and echoed when request has none")
	}
}

// 修复测试（P3，与 §6.2 后置 HSTS 设置一致）：HTTPS（r.TLS 模拟）下黑名单拦截
// 响应含 Strict-Transport-Security 头（与 H8 同值）；纯 HTTP（r.TLS == nil）
// 拦截响应不含该头。
func TestBlacklistBlockResponseHSTSOnTLS(t *testing.T) {
	chdirToRepoRoot(t)
	backend, _ := newBLBackend(t)
	src, _ := newBLSource(t)

	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Hosts:  []config.HostConfig{blHost("bl.example.com", backend.URL, nil)},
		Blacklist: config.BlacklistConfig{
			Enabled:     true,
			DefaultMode: config.BlacklistModeBlock,
			Sources:     []config.BlacklistSourceConfig{{Name: blSourceName, URL: src.URL}},
		},
	}
	s := newBLServer(t, cfg)

	// L7（内部PRD）：默认 HSTS 值去 preload，断言随唯一事实源同步
	const wantHSTS = config.DefaultHSTSValue

	// HTTPS（r.TLS 非 nil 模拟网关 TLS 终止）：拦截响应含 HSTS
	req := httptest.NewRequest(http.MethodGet, "http://bl.example.com/", nil)
	req.RemoteAddr = blTargetIP + ":54321"
	req.TLS = &tls.ConnectionState{}
	w := blDoRequestWithReq(s, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("TLS block status = %d, want 403", w.Code)
	}
	if got := w.Header().Get("Strict-Transport-Security"); got != wantHSTS {
		t.Errorf("HSTS on TLS block response = %q, want %q", got, wantHSTS)
	}

	// 纯 HTTP（r.TLS == nil）：拦截响应不含 HSTS
	w = blDoRequest(s, "bl.example.com", blTargetIP, "/", "bltrace26")
	if w.Code != http.StatusForbidden {
		t.Fatalf("plain HTTP block status = %d, want 403", w.Code)
	}
	if got := w.Header().Get("Strict-Transport-Security"); got != "" {
		t.Errorf("HSTS on plain HTTP block response = %q, want empty", got)
	}
}
