package health

// L8（内部PRD 迭代 1 出口标准⑤）：健康检查不跟随重定向——
// CheckRedirect 返回 http.ErrUseLastResponse，2xx 与 3xx 均判健康，
// 3xx 后端恰好 1 次请求（不再对重定向目标二次请求）。

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lite-lake/infra-gate/internal/infrastructs/logger"
)

// checkerTestLogger 实现 logger.ILogger 的空实现（对齐其他包测试基建模式）
type checkerTestLogger struct{}

func (l *checkerTestLogger) Debug(msg string, fields ...logger.Field) {}
func (l *checkerTestLogger) Info(msg string, fields ...logger.Field)  {}
func (l *checkerTestLogger) Warn(msg string, fields ...logger.Field)  {}
func (l *checkerTestLogger) Error(msg string, fields ...logger.Field) {}
func (l *checkerTestLogger) Fatal(msg string, fields ...logger.Field) {}
func (l *checkerTestLogger) WithContext(ctx context.Context) logger.ILogger {
	return l
}
func (l *checkerTestLogger) WithField(key string, value interface{}) logger.ILogger { return l }
func (l *checkerTestLogger) WithFields(fields map[string]interface{}) logger.ILogger {
	return l
}
func (l *checkerTestLogger) WithTraceId(traceId string) logger.ILogger { return l }
func (l *checkerTestLogger) SetLevel(level logger.LogLevel)            {}
func (l *checkerTestLogger) GetLevel() logger.LogLevel                 { return logger.DebugLevel }
func (l *checkerTestLogger) Close() error                              { return nil }

// newRedirectingBackend 返回健康端点 302 → /ok 200 的后端，记录全部命中数
func newRedirectingBackend(t *testing.T) (*httptest.Server, *int64) {
	t.Helper()
	var hits int64
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		http.Redirect(w, r, "/ok", http.StatusFound)
	})
	mux.HandleFunc("/ok", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		fmt.Fprint(w, "ok")
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &hits
}

// 出口标准⑤：302 后端 → 恰好 1 次请求即判健康，不再跟随重定向
func TestHealthCheckDoesNotFollowRedirect(t *testing.T) {
	backend, hits := newRedirectingBackend(t)

	var healthy bool
	c := NewChecker([]string{backend.URL}, "/healthz", time.Second, 2*time.Second,
		func(backend string, isHealthy bool) { healthy = isHealthy }, &checkerTestLogger{})

	c.checkBackend(backend.URL)

	if !healthy {
		t.Errorf("302 health endpoint should be judged healthy (ErrUseLastResponse, no follow)")
	}
	if n := atomic.LoadInt64(hits); n != 1 {
		t.Errorf("backend total requests = %d, want 1 (redirect must not be followed)", n)
	}
}

// 3xx 直接判健康的边界确认：301/307 同样健康（首个响应即终态）
func TestHealthCheckTreats3xxAsHealthy(t *testing.T) {
	tests := []struct {
		name string
		code int
		want bool
	}{
		{"301 moved", http.StatusMovedPermanently, true},
		{"302 found", http.StatusFound, true},
		{"307 temporary", http.StatusTemporaryRedirect, true},
		{"200 ok", http.StatusOK, true},
		{"404 not found", http.StatusNotFound, false},
		{"500 server error", http.StatusInternalServerError, false},
	}
	for _, tt := range tests {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(tt.code)
		}))
		var healthy bool
		c := NewChecker([]string{srv.URL}, "/healthz", time.Second, 2*time.Second,
			func(_ string, isHealthy bool) { healthy = isHealthy }, &checkerTestLogger{})
		c.checkBackend(srv.URL)
		srv.Close()
		if healthy != tt.want {
			t.Errorf("%s: status %d healthy = %v, want %v", tt.name, tt.code, healthy, tt.want)
		}
	}
}
