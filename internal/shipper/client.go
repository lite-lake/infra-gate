package shipper

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/lite-lake/infra-gate/internal/infrastructs/logger"
)

// 批量发送常量（内部PRD §4.4.1：失败有限次退避重试后丢弃本批并计数）
const (
	// sendAttempts 单批发送总尝试次数（1 次首发 + 2 次重试）
	sendAttempts = 3
	// baseBackoff 指数退避基值：重试间隔 100ms/200ms/400ms
	baseBackoff = 100 * time.Millisecond
	// sendTimeout 单次 HTTP 请求超时
	sendTimeout = 5 * time.Second
	// errSummaryLimit 错误摘要截断长度（防异常 URL/响应体刷屏）
	errSummaryLimit = 200
)

// ingest 密钥头与内容类型（契约见 内部PRD §6.1）
const (
	secretHeader    = "X-Lite-Gw-Secret"
	jsonContentType = "application/json"
)

// Client 批量外送 HTTP 客户端：POST endpoint（信封 JSON + 密钥头），
// 失败按指数退避重试 sendAttempts 次后丢弃本批并原子计数；
// 丢弃按 sampleRatio 采样打 warn（字段仅 node/批大小/错误摘要，绝不含 client_ip 原文）。
// 仅在 shipper flusher goroutine 上运行，阻塞不影响代理主链路。
type Client struct {
	endpoint    string
	secret      string
	sampleRatio float64
	httpClient  *http.Client
	log         logger.ILogger

	droppedBatches atomic.Uint64 // 丢弃批次数
	droppedRecords atomic.Uint64 // 丢弃记录数（批大小累加，对账观测点）
}

// NewClient 创建批量外送客户端（endpoint/secret 已由配置层校验非空）
func NewClient(endpoint, secret string, sampleRatio float64, log logger.ILogger) *Client {
	return &Client{
		endpoint:    endpoint,
		secret:      secret,
		sampleRatio: sampleRatio,
		httpClient:  &http.Client{Timeout: sendTimeout},
		log:         log,
	}
}

// Send 发送一批记录：成功返回 nil；失败重试耗尽后丢弃本批（计数 + 采样日志）并返回
// 最后一次错误。ctx 取消时立即中止并按丢弃处理。
func (c *Client) Send(ctx context.Context, env Envelope) error {
	body, err := json.Marshal(env)
	if err != nil {
		// 信封含非法字符串（理论上不应出现）也走统一丢弃计数，绝不 panic
		c.recordDrop(env, err)
		return fmt.Errorf("marshal envelope: %w", err)
	}

	var lastErr error
	for attempt := 0; attempt < sendAttempts; attempt++ {
		if attempt > 0 {
			backoff := baseBackoff << (attempt - 1) // 100ms → 200ms → 400ms
			select {
			case <-ctx.Done():
				c.recordDrop(env, ctx.Err())
				return ctx.Err()
			case <-time.After(backoff):
			}
		}
		if err := c.post(ctx, body); err != nil {
			lastErr = err
			continue
		}
		return nil
	}

	c.recordDrop(env, lastErr)
	return lastErr
}

// post 单次 POST：2xx 视为成功，其余状态码与传输错误均计为失败（交由上层重试）
func (c *Client) post(ctx context.Context, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set(secretHeader, c.secret)
	req.Header.Set("Content-Type", jsonContentType)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// 排干响应体（限长防异常大响应）以复用连接
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("ingest returned status %d", resp.StatusCode)
	}
	return nil
}

// recordDrop 丢弃本批：原子计数 + 按 sampleRatio 采样打 warn。
// 日志字段仅含 node/批大小/错误摘要——绝不含 client_ip 原文（PRD §10/§14 红线）。
func (c *Client) recordDrop(env Envelope, cause error) {
	batchSize := len(env.Requests)
	c.droppedBatches.Add(1)
	if batchSize > 0 {
		c.droppedRecords.Add(uint64(batchSize))
	}
	if c.sampleRatio > 0 && rand.Float64() < c.sampleRatio {
		c.log.Warn("Tracker shipper batch dropped after retries",
			logger.NewField("node", env.Node),
			logger.NewField("batch_size", batchSize),
			logger.NewField("error", truncateErrSummary(cause)))
	}
}

// DroppedBatches 返回累计丢弃批次数
func (c *Client) DroppedBatches() uint64 {
	return c.droppedBatches.Load()
}

// DroppedRecords 返回累计丢弃记录数
func (c *Client) DroppedRecords() uint64 {
	return c.droppedRecords.Load()
}

// truncateErrSummary 错误摘要截断（nil 安全）
func truncateErrSummary(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	if len(s) > errSummaryLimit {
		return s[:errSummaryLimit] + "...[truncated]"
	}
	return s
}
