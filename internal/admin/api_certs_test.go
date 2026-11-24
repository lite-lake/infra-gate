package admin

// /api/certs 响应形状测试（内部PRD §7.4 的兼容性落地）：
// data 必须保持 certInfo 数组（下游 app-ac-api gate_aggregator_service.go 按数组解析，
// 解析失败会把整个网关节点标记为不可达）；pending 平铺在响应顶层，空时输出 [] 而非 null。

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/lite-lake/infra-gate/internal/cert"
	"github.com/lite-lake/infra-gate/internal/infrastructs/endpoints"
)

func TestAPICertsDataStaysArrayAndPendingTopLevel(t *testing.T) {
	a := newAPIKeyTestServer(t, testReadOnlyAPIKey)

	// 场景 1：reconciler 未启动 —— data 数组 + pending 顶层空数组（非 null）
	w := doAPIKeyRequest(t, a, "/api/certs", testReadOnlyAPIKey)
	if w.Code != http.StatusOK {
		t.Fatalf("/api/certs status = %d, want 200", w.Code)
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	var data []map[string]interface{}
	if err := json.Unmarshal(body["data"], &data); err != nil {
		t.Errorf("data must remain a JSON array (app-ac-api gate_aggregator 兼容), got: %s", body["data"])
	}
	var pending []map[string]interface{}
	if err := json.Unmarshal(body["pending"], &pending); err != nil {
		t.Errorf("top-level pending must be a JSON array (空时输出 [] 而非 null), got: %s", body["pending"])
	}
	if len(pending) != 0 {
		t.Errorf("pending should be empty without reconciler, got %v", pending)
	}

	// 场景 2：reconciler 已启动（目标未就绪）—— pending 顶层可见收敛状态，
	// data 仍为数组。pending 在 newReconciler 同步创建，首个调度 tick 前即可断言。
	a.certManager.StartReconciler([]cert.CertTarget{{
		Domain: "pending.example.com",
		Config: &cert.CertConfig{Remote: &cert.RemoteCertConfig{
			Enabled:  true,
			Endpoint: endpoints.New("https://127.0.0.1:1"),
		}},
	}})
	defer a.certManager.StopReconciler()

	w = doAPIKeyRequest(t, a, "/api/certs", testReadOnlyAPIKey)
	if w.Code != http.StatusOK {
		t.Fatalf("/api/certs status = %d, want 200", w.Code)
	}
	body = nil
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if err := json.Unmarshal(body["data"], &data); err != nil {
		t.Errorf("data must remain a JSON array with pending targets, got: %s", body["data"])
	}
	pending = nil
	if err := json.Unmarshal(body["pending"], &pending); err != nil {
		t.Fatalf("decode pending: %v (%s)", err, body["pending"])
	}
	if len(pending) != 1 {
		t.Fatalf("pending len = %d, want 1", len(pending))
	}
	entry := pending[0]
	if entry["domain"] != "pending.example.com" {
		t.Errorf("pending domain = %v, want pending.example.com", entry["domain"])
	}
	if entry["status"] != "loading" {
		t.Errorf("pending status = %v, want loading", entry["status"])
	}
	if _, ok := entry["attempts"]; !ok {
		t.Error("pending entry should expose attempts")
	}
	// ConsecutiveFailures 为内部限频计数（json:"-"），不得出现在响应中
	if _, ok := entry["ConsecutiveFailures"]; ok {
		t.Error("internal consecutive_failures counter must not be serialized")
	}
}
