package shipper

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/lite-lake/infra-gate/internal/infrastructs/logger"
)

// testLogger 静音测试日志（Error 级别 + 关闭控制台/文件输出）
func testLogger() logger.ILogger {
	return logger.NewLogger(logger.LoggerConfig{
		Level:         logger.ErrorLevel,
		EnableConsole: false,
		EnableFile:    false,
	})
}

func makeBatch(n int) Envelope {
	recs := make([]Record, n)
	for i := range recs {
		recs[i] = makeRecord(i)
	}
	return NewEnvelope("test-node", recs)
}

// TestClientSendSuccess 成功路径：端点/方法/密钥头/Content-Type/信封内容逐项断言
func TestClientSendSuccess(t *testing.T) {
	var gotPath, gotMethod, gotSecret, gotCT string
	var gotEnv Envelope

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotSecret = r.Header.Get("X-Lite-Gw-Secret")
		gotCT = r.Header.Get("Content-Type")
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &gotEnv)
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"accepted":2}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL+"/api/internal/gateway-ingest", "s3cret", 0, testLogger())
	env := makeBatch(2)
	if err := c.Send(context.Background(), env); err != nil {
		t.Fatalf("Send should succeed: %v", err)
	}

	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if gotPath != "/api/internal/gateway-ingest" {
		t.Errorf("path = %q, want /api/internal/gateway-ingest", gotPath)
	}
	if gotSecret != "s3cret" {
		t.Errorf("X-Lite-Gw-Secret = %q, want s3cret", gotSecret)
	}
	if gotCT != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", gotCT)
	}
	if gotEnv.Node != "test-node" || len(gotEnv.Requests) != 2 {
		t.Errorf("envelope = node:%q requests:%d, want test-node/2", gotEnv.Node, len(gotEnv.Requests))
	}
	if c.DroppedBatches() != 0 || c.DroppedRecords() != 0 {
		t.Errorf("success send should not count drops, got batches=%d records=%d",
			c.DroppedBatches(), c.DroppedRecords())
	}
}

// TestClientRetryThenSuccess 前两次 500、第三次 202：有限退避重试后成功，不计丢弃
func TestClientRetryThenSuccess(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "k", 0, testLogger())
	if err := c.Send(context.Background(), makeBatch(1)); err != nil {
		t.Fatalf("Send should succeed on 3rd attempt: %v", err)
	}
	if got := hits.Load(); got != 3 {
		t.Errorf("server hits = %d, want 3", got)
	}
	if c.DroppedBatches() != 0 {
		t.Errorf("DroppedBatches = %d, want 0", c.DroppedBatches())
	}
}

// TestClientRetryExhaustedDrop 持续 500：重试耗尽后丢弃本批 + 计数（PRD §4.4.1）
func TestClientRetryExhaustedDrop(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "k", 0, testLogger()) // ratio 0：不打采样日志
	if err := c.Send(context.Background(), makeBatch(3)); err == nil {
		t.Fatal("Send should fail after retries exhausted")
	}
	if got := hits.Load(); got != int32(sendAttempts) {
		t.Errorf("server hits = %d, want %d (sendAttempts)", got, sendAttempts)
	}
	if got := c.DroppedBatches(); got != 1 {
		t.Errorf("DroppedBatches = %d, want 1", got)
	}
	if got := c.DroppedRecords(); got != 3 {
		t.Errorf("DroppedRecords = %d, want 3", got)
	}
}

// TestClientSendContextCanceled ctx 取消按丢弃处理，不 panic 不悬挂
func TestClientSendContextCanceled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "k", 0, testLogger())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := c.Send(ctx, makeBatch(1)); err == nil {
		t.Fatal("Send with canceled ctx should fail")
	}
	if c.DroppedBatches() != 1 {
		t.Errorf("DroppedBatches = %d, want 1", c.DroppedBatches())
	}
}
