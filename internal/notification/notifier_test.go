package notification

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lite-lake/infra-gate/internal/infrastructs/endpoints"
	"github.com/lite-lake/infra-gate/internal/infrastructs/logger"
)

func TestNotifierMultiEndpointFailover(t *testing.T) {
	// Run multiple iterations to exercise both orderings (random picker)
	const iterations = 10
	for i := 0; i < iterations; i++ {
		var failHits int32
		var successHits int32

		// Server that always fails
		failServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&failHits, 1)
			w.WriteHeader(http.StatusInternalServerError)
		}))

		// Server that always succeeds
		successServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&successHits, 1)
			w.WriteHeader(http.StatusOK)
		}))

		cfg := NotificationConfig{
			Enabled: true,
			URL:     endpoints.New(failServer.URL, successServer.URL),
			Timeout: 5 * time.Second,
		}

		n := NewNotifier(cfg, logger.GetDefaultLogger(), "test-app")
		n.SendNotification("started", nil)
		n.Sync()

		// In every iteration, the success server must have been hit
		// (either directly if picked first, or via failover if fail server was picked first)
		if atomic.LoadInt32(&successHits) == 0 {
			t.Fatalf("iteration %d: expected success server to be hit (failover failed)", i)
		}

		failServer.Close()
		successServer.Close()
	}
}

func TestNotifierSingleEndpointBackwardCompat(t *testing.T) {
	var hits int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusOK)
		var payload map[string]interface{}
		json.NewDecoder(r.Body).Decode(&payload)
	}))
	defer server.Close()

	cfg := NotificationConfig{
		Enabled: true,
		URL:     endpoints.New(server.URL),
		Timeout: 5 * time.Second,
	}

	n := NewNotifier(cfg, logger.GetDefaultLogger(), "test-app")
	n.SendNotification("started", map[string]string{"key": "value"})
	n.Sync()

	if atomic.LoadInt32(&hits) != 1 {
		t.Errorf("expected exactly 1 hit, got %d", atomic.LoadInt32(&hits))
	}
}

func TestNotifierAllEndpointsFail(t *testing.T) {
	// Both servers return 500
	server1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server1.Close()

	server2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server2.Close()

	cfg := NotificationConfig{
		Enabled: true,
		URL:     endpoints.New(server1.URL, server2.URL),
		Timeout: 5 * time.Second,
	}

	n := NewNotifier(cfg, logger.GetDefaultLogger(), "test-app")

	// Should not panic or block
	n.SendNotification("started", nil)
	n.Sync()

	// Verify IsEnabled returns true
	if !n.IsEnabled() {
		t.Error("IsEnabled should be true")
	}
}

func TestNotifierDisabledEmptyURL(t *testing.T) {
	cfg := NotificationConfig{
		Enabled: true,
		URL:     endpoints.Config{}, // empty
	}

	n := NewNotifier(cfg, logger.GetDefaultLogger(), "test-app")

	if n.IsEnabled() {
		t.Error("IsEnabled should be false when URL is empty")
	}

	// SendNotification should be a no-op
	err := n.SendNotification("started", nil)
	if err != nil {
		t.Errorf("SendNotification on disabled notifier should return nil, got %v", err)
	}
}

// TestNotifierQueueFloodDropsNewKeepsOld F1e（内部PRD §4.1.7）：
// 通知洪峰下队列有界——worker 被慢 webhook 挂住时，超容量（64）的新事件被丢弃
// 且计数累计；SendNotification 本身永不阻塞。
func TestNotifierQueueFloodDropsNewKeepsOld(t *testing.T) {
	release := make(chan struct{})
	var hits int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		// 第一条挂住 worker，制造队列堆积
		<-release
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := NotificationConfig{
		Enabled: true,
		URL:     endpoints.New(server.URL),
		Timeout: 5 * time.Second,
	}
	n := NewNotifier(cfg, logger.GetDefaultLogger(), "test-app")

	// 洪峰：远超队列容量 64；1 条在 worker、64 条在队列、其余丢弃
	const flood = 200
	for i := 0; i < flood; i++ {
		_ = n.SendNotification("started", nil)
	}
	dropped := n.Dropped()
	if dropped == 0 {
		t.Error("dropped should be > 0 under flood")
	}
	if dropped > flood {
		t.Errorf("dropped = %d, want <= flood %d", dropped, flood)
	}

	// 放行 worker 后队列应排空（最多 64+1 条实际送达）
	close(release)
	n.Sync()
	if got := atomic.LoadInt32(&hits); got == 0 || got > notifyQueueCapacity+1 {
		t.Errorf("hits = %d, want in [1, %d]", got, notifyQueueCapacity+1)
	}
}
