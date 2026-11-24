package health

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/lite-lake/infra-gate/internal/infrastructs/logger"
	"github.com/lite-lake/infra-gate/internal/netutil"
	"github.com/lite-lake/infra-gate/internal/trace"
)

type HealthStatusCallback func(backend string, isHealthy bool)

type Checker struct {
	backends []string
	path     string
	interval time.Duration
	timeout  time.Duration
	callback HealthStatusCallback
	stopCh   chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
	logger   logger.ILogger
	client   *http.Client
}

// NewChecker 创建健康检查器
// H37: 接受 time.Duration 而非 int 秒数，避免亚秒级 Duration 被截断
func NewChecker(backends []string, path string, interval, timeout time.Duration, callback HealthStatusCallback, log logger.ILogger) *Checker {
	transport := &http.Transport{
		MaxIdleConns:        10,
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     90 * time.Second,
	}
	return &Checker{
		backends: backends,
		path:     path,
		interval: interval,
		timeout:  timeout,
		callback: callback,
		stopCh:   make(chan struct{}),
		logger:   log,
		client: &http.Client{
			Timeout:   timeout,
			Transport: transport,
			// L8（内部PRD）：不跟随重定向——CheckRedirect 返回
			// ErrUseLastResponse 直接取首个响应，3xx 即终态，不再对重定向目标
			// 二次请求（「重定向到任意 200 即视为健康」的绕过面被消除）
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (c *Checker) Start() {
	c.logger.Info("Starting health checker",
		logger.NewField("interval", c.interval),
		logger.NewField("timeout", c.timeout),
		logger.NewField("backends_count", len(c.backends)))
	c.wg.Add(1)
	go c.run()
}

func (c *Checker) Stop() {
	c.logger.Info("Stopping health checker")
	c.stopOnce.Do(func() {
		close(c.stopCh)
	})
	// H38: 等待检查完成，带超时防止永久阻塞
	done := make(chan struct{})
	go func() {
		c.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		c.logger.Warn("Timed out waiting for health check goroutines, proceeding with shutdown")
	}
	if c.client.Transport != nil {
		c.client.Transport.(*http.Transport).CloseIdleConnections()
	}
}

func (c *Checker) run() {
	defer c.wg.Done()

	// Initial health check
	c.logger.Debug("Running initial health check")
	c.checkAllBackends()

	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			c.checkAllBackends()
		}
	}
}

func (c *Checker) checkAllBackends() {
	var wg sync.WaitGroup
	for _, backend := range c.backends {
		wg.Add(1)
		go func(b string) {
			defer wg.Done()
			c.checkBackend(b)
		}(backend)
	}
	wg.Wait()
}

func (c *Checker) checkBackend(backend string) {
	// Generate TraceID for health check
	traceId := trace.GenerateTraceId()
	loggerWithTrace := c.logger.WithTraceId(traceId)

	parsedURL, err := url.Parse(backend)
	if err != nil {
		loggerWithTrace.Error("Failed to parse backend URL",
			logger.NewField("backend", netutil.RedactURL(backend)),
			logger.NewField("error", err))
		if c.callback != nil {
			c.callback(backend, false)
		}
		return
	}
	// H39: 使用 path.Join 会清除后端 URL 已有路径的尾随斜杠
	// 如果健康检查路径是绝对路径（以 / 开头），直接追加到后端路径
	if c.path != "" {
		if strings.HasPrefix(c.path, "/") {
			parsedURL.Path = strings.TrimRight(parsedURL.Path, "/") + c.path
		} else {
			parsedURL.Path = strings.TrimRight(parsedURL.Path, "/") + "/" + c.path
		}
	}

	// P2-54: 使用 context 感知 stopCh，使 Stop() 能取消正在进行的检查
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 监听 stopCh，收到停止信号时取消 context
	go func() {
		select {
		case <-c.stopCh:
			cancel()
		case <-ctx.Done():
		}
	}()

	// 设置超时
	timeoutCtx, timeoutCancel := context.WithTimeout(ctx, c.timeout)
	defer timeoutCancel()

	req, err := http.NewRequestWithContext(timeoutCtx, "GET", parsedURL.String(), nil)
	if err != nil {
		loggerWithTrace.Error("Failed to create health check request",
			logger.NewField("backend", netutil.RedactURL(backend)),
			logger.NewField("error", err))
		if c.callback != nil {
			c.callback(backend, false)
		}
		return
	}

	// Add TraceID to request header
	req.Header.Add("X-Lite-Gate-Trace-Id", traceId)

	resp, err := c.client.Do(req)
	// L8（内部PRD）：2xx 与 3xx 均判健康——探活路径返回重定向说明后端进程
	// 存活；ErrUseLastResponse 下 3xx 即首个响应（不跟随），不再产生二次请求
	isHealthy := err == nil && resp != nil && resp.StatusCode >= 200 && resp.StatusCode < 400

	if resp != nil {
		resp.Body.Close()
	}

	// Log health check result
	if isHealthy {
		loggerWithTrace.Debug("Health check passed",
			logger.NewField("backend", netutil.RedactURL(backend)),
			logger.NewField("url", netutil.RedactURL(parsedURL.String())))
	} else {
		loggerWithTrace.Debug("Health check failed",
			logger.NewField("backend", netutil.RedactURL(backend)),
			logger.NewField("url", netutil.RedactURL(parsedURL.String())),
			logger.NewField("error", err))
	}

	if c.callback != nil {
		c.callback(backend, isHealthy)
	}
}
