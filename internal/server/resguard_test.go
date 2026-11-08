package server

// F1 资源治理集成测试（内部PRD §11 F1）：
//   - per-IP 速率限制：burst 耗尽后 429 + Retry-After，豁免网段不受限；
//   - 并发信号量：全局占满 503（经真实 gin 中间件链），释放后恢复；
//   - 逃生口：resource_governance.enabled=false 时三个治理器均为 nil（挂载点
//     零开销跳过），限速/并发不再生效；
//   - 配置：GetEffective 缺省回落与 per_ip_whitelist 校验 fail-fast。

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/lite-lake/infra-gate/internal/config"
)

// rgHost 复用 blHost 形态：backend host、禁用健康检查
func rgHost(name, backendURL string) config.HostConfig {
	return config.HostConfig{
		Name:               name,
		Port:               8080,
		Backend:            []string{backendURL},
		HealthCheckEnabled: boolPtr(false),
	}
}

// TestResourceGovernancePerIPRate429 F1b：per-IP 限速挂黑名单之后，burst 耗尽
// 后 429 + Retry-After: 1；per_ip_whitelist 网段豁免不受限。
func TestResourceGovernancePerIPRate429(t *testing.T) {
	chdirToRepoRoot(t)
	backend, backendHits := newBLBackend(t)

	cfg := &config.Config{
		Server: config.ServerConfig{
			Port: 8080,
			ResourceGovernance: config.ResourceGovernanceConfig{
				// burst 2：前两次放行，第三次立刻 429
				PerIPRate:  0.001, // 补充速率近似为零（测试窗口内不回补）
				PerIPBurst: 2,
				// 豁免网段：监控探针模拟
				PerIPWhitelist: []string{"10.71.0.0/24"},
			},
		},
		Hosts: []config.HostConfig{rgHost("rg.example.com", backend.URL)},
	}
	s := newBLServer(t, cfg)

	// 非豁免 IP：第 1、2 次放行，第 3 次 429 + Retry-After
	for i := 0; i < 2; i++ {
		w := blDoRequest(s, "rg.example.com", "203.0.113.7", "/", "")
		if w.Code != http.StatusOK {
			t.Fatalf("request #%d status = %d, want 200 (within burst)", i+1, w.Code)
		}
	}
	w := blDoRequest(s, "rg.example.com", "203.0.113.7", "/", "")
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("request #3 status = %d, want 429 (rate limited)", w.Code)
	}
	if ra := w.Header().Get("Retry-After"); ra != "1" {
		t.Errorf("Retry-After = %q, want 1", ra)
	}

	// 豁免 IP：连续多次全部放行（per-IP 维度豁免）
	for i := 0; i < 5; i++ {
		w := blDoRequest(s, "rg.example.com", "10.71.0.8", "/", "")
		if w.Code != http.StatusOK {
			t.Fatalf("exempt request #%d status = %d, want 200", i+1, w.Code)
		}
	}
	if n := atomic.LoadInt64(backendHits); n != 7 {
		t.Errorf("backend hits = %d, want 7 (2+5 passed requests)", n)
	}
}

// TestResourceGovernanceSemaphore503 F1a：并发信号量经中间件链生效——
// per-IP 占满立即 503 + Retry-After；全局占满为排队等待语义（等待槽位释放，
// 客户端断开由 ctx 放行），释放后按序放行。
func TestResourceGovernanceSemaphore503(t *testing.T) {
	chdirToRepoRoot(t)
	backend, _ := newBLBackend(t)

	cfg := &config.Config{
		Server: config.ServerConfig{
			Port: 8080,
			ResourceGovernance: config.ResourceGovernanceConfig{
				MaxConcurrentRequests:   10,
				PerIPConcurrentRequests: 1,
			},
		},
		Hosts: []config.HostConfig{rgHost("rg.example.com", backend.URL)},
	}
	s := newBLServer(t, cfg)
	if s.reqSemaphore == nil {
		t.Fatal("reqSemaphore should be non-nil when resource governance enabled")
	}

	// 复刻 startHTTPServer 的中间件链装配（ginLogger 之后）
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	_ = engine.SetTrustedProxies(nil)
	engine.Use(s.resguardMiddleware())
	release := make(chan struct{})
	engine.Use(func(c *gin.Context) {
		if c.Request.URL.Path == "/hold" {
			<-release // 持住该 IP 的唯一 per-IP 槽
		}
		c.String(http.StatusOK, "ok")
	})

	// 第一个请求持住 203.0.113.7 的 per-IP 槽
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		engine.ServeHTTP(httptest.NewRecorder(), holdRequest("203.0.113.7:1000", "/hold"))
	}()
	time.Sleep(100 * time.Millisecond)

	// 同 IP 第二个请求：per-IP 占满 → 立即 503 + Retry-After（不排队）
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, holdRequest("203.0.113.7:1001", "/pass"))
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("same-ip second request status = %d, want 503", w.Code)
	}
	if ra := w.Header().Get("Retry-After"); ra != "1" {
		t.Errorf("Retry-After = %q, want 1", ra)
	}

	// 不同 IP 不受影响 → 200
	w = httptest.NewRecorder()
	engine.ServeHTTP(w, holdRequest("198.51.100.9:1002", "/pass"))
	if w.Code != http.StatusOK {
		t.Errorf("different-ip request status = %d, want 200", w.Code)
	}

	// 释放后原 IP 恢复放行
	close(release)
	wg.Wait()
	w = httptest.NewRecorder()
	engine.ServeHTTP(w, holdRequest("203.0.113.7:1003", "/pass"))
	if w.Code != http.StatusOK {
		t.Errorf("same-ip request after release status = %d, want 200", w.Code)
	}
}

// TestResourceGovernanceGlobalFullWaitsThenServes 全局占满的排队语义：
// 等待者阻塞在 Acquire，槽位释放后按序完成（不拒绝）；ctx 取消则 503。
func TestResourceGovernanceGlobalFullWaitsThenServes(t *testing.T) {
	chdirToRepoRoot(t)
	backend, _ := newBLBackend(t)

	cfg := &config.Config{
		Server: config.ServerConfig{
			Port: 8080,
			ResourceGovernance: config.ResourceGovernanceConfig{
				MaxConcurrentRequests:   1,
				PerIPConcurrentRequests: 10,
			},
		},
		Hosts: []config.HostConfig{rgHost("rg.example.com", backend.URL)},
	}
	s := newBLServer(t, cfg)

	gin.SetMode(gin.TestMode)
	engine := gin.New()
	_ = engine.SetTrustedProxies(nil)
	engine.Use(s.resguardMiddleware())
	release := make(chan struct{})
	engine.Use(func(c *gin.Context) {
		if c.Request.URL.Path == "/hold" {
			<-release
		}
		c.String(http.StatusOK, "ok")
	})

	// 请求 A 持住唯一全局槽
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		engine.ServeHTTP(httptest.NewRecorder(), holdRequest("203.0.113.7:1000", "/hold"))
	}()
	time.Sleep(100 * time.Millisecond)

	// 请求 B（不同 IP）排队等待，而非立即拒绝
	wCh := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, holdRequest("198.51.100.9:1001", "/pass"))
		wCh <- w
	}()
	time.Sleep(100 * time.Millisecond)
	select {
	case <-wCh:
		t.Fatal("request B should be waiting for a global slot, not completed")
	default:
	}

	// 释放槽位 → B 按序完成 200
	close(release)
	wg.Wait()
	select {
	case w := <-wCh:
		if w.Code != http.StatusOK {
			t.Errorf("queued request status = %d, want 200 after slot release", w.Code)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("queued request did not complete after slot release")
	}
}

// holdRequest 构造指定 RemoteAddr 与路径的 GET 请求（/hold 路径会在 handler 中
// 阻塞直到 release 关闭，用于持住并发槽）
func holdRequest(remoteAddr, path string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.RemoteAddr = remoteAddr
	return req
}

// TestResourceGovernanceDisabledEscapeHatch 逃生口：enabled=false 时三个治理器
// 均为 nil，per-IP 限速与并发限制不再生效（超 burst 请求仍全部 200）。
func TestResourceGovernanceDisabledEscapeHatch(t *testing.T) {
	chdirToRepoRoot(t)
	backend, _ := newBLBackend(t)
	disabled := false

	cfg := &config.Config{
		Server: config.ServerConfig{
			Port: 8080,
			ResourceGovernance: config.ResourceGovernanceConfig{
				Enabled:    &disabled,
				PerIPRate:  0.001,
				PerIPBurst: 1,
			},
		},
		Hosts: []config.HostConfig{rgHost("rg.example.com", backend.URL)},
	}
	s := newBLServer(t, cfg)

	if s.reqSemaphore != nil || s.ipRateLimiter != nil || s.wsConnLimiter != nil {
		t.Fatal("governance components should be nil when enabled=false")
	}
	for i := 0; i < 5; i++ {
		w := blDoRequest(s, "rg.example.com", "203.0.113.7", "/", "")
		if w.Code != http.StatusOK {
			t.Fatalf("request #%d status = %d, want 200 (governance disabled)", i+1, w.Code)
		}
	}
}

// TestResourceGovernanceConfigDefaultsAndValidation 配置缺省回落与校验：
// 零值配置取 §5 缺省（4096/64/50/100/1024/256/16/32KB）；per_ip_whitelist
// 非法条目 Validate fail-fast。
func TestResourceGovernanceConfigDefaultsAndValidation(t *testing.T) {
	c := &config.Config{Server: config.ServerConfig{Port: 8080}}
	if err := c.Validate(); err != nil {
		t.Fatalf("zero-value config should validate: %v", err)
	}
	sc := &c.Server
	if got := sc.GetEffectiveMaxConcurrentRequests(); got != config.DefaultMaxConcurrentRequests {
		t.Errorf("MaxConcurrentRequests default = %d, want %d", got, config.DefaultMaxConcurrentRequests)
	}
	if got := sc.GetEffectivePerIPConcurrentRequests(); got != config.DefaultPerIPConcurrentRequests {
		t.Errorf("PerIPConcurrentRequests default = %d, want %d", got, config.DefaultPerIPConcurrentRequests)
	}
	if got := sc.GetEffectivePerIPRate(); got != config.DefaultPerIPRate {
		t.Errorf("PerIPRate default = %v, want %v", got, config.DefaultPerIPRate)
	}
	if got := sc.GetEffectivePerIPBurst(); got != config.DefaultPerIPBurst {
		t.Errorf("PerIPBurst default = %d, want %d", got, config.DefaultPerIPBurst)
	}
	if got := sc.GetEffectiveWSMaxGlobal(); got != config.DefaultWSMaxGlobal {
		t.Errorf("WSMaxGlobal default = %d, want %d", got, config.DefaultWSMaxGlobal)
	}
	if got := sc.GetEffectiveWSMaxPerHost(); got != config.DefaultWSMaxPerHost {
		t.Errorf("WSMaxPerHost default = %d, want %d", got, config.DefaultWSMaxPerHost)
	}
	if got := sc.GetEffectiveWSMaxPerIP(); got != config.DefaultWSMaxPerIP {
		t.Errorf("WSMaxPerIP default = %d, want %d", got, config.DefaultWSMaxPerIP)
	}
	if got := sc.GetEffectiveMaxHeaderBytes(); got != config.DefaultMaxHeaderBytes {
		t.Errorf("MaxHeaderBytes default = %d, want %d", got, config.DefaultMaxHeaderBytes)
	}
	if !sc.GetEffectiveResourceGovernanceEnabled() {
		t.Error("ResourceGovernanceEnabled default should be true")
	}

	// 非法 per_ip_whitelist 条目 fail-fast
	bad := &config.Config{Server: config.ServerConfig{
		Port:               8080,
		ResourceGovernance: config.ResourceGovernanceConfig{PerIPWhitelist: []string{"not-an-ip"}},
	}}
	if err := bad.Validate(); err == nil {
		t.Error("invalid per_ip_whitelist entry should fail validation")
	}
}
