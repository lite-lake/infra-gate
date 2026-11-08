package shipper

import (
	"encoding/json"
	"testing"
)

// TestEnvelopeJSONShape 批量信封 JSON 形状与 ingest 契约逐字段一致
// （内部PRD §6.1：顶层 {"node","requests"}，记录 14 个 snake_case 字段）
func TestEnvelopeJSONShape(t *testing.T) {
	env := NewEnvelope("yo-prod-gateway-node4", []Record{{
		Method:      "GET",
		Host:        "kissfocus.vip",
		Path:        "/timer",
		Query:       "a=1",
		Status:      200,
		Bytes:       15234,
		LatencyMs:   42,
		RefHost:     "www.google.com",
		UserAgent:   "Mozilla/5.0",
		ContentType: "text/html; charset=utf-8",
		ClientIP:    "203.0.113.7",
		TraceId:     "abc123",
		ReqClass:    "doc",
		Ts:          1760000000000,
	}})

	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}

	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		t.Fatalf("unmarshal top-level: %v", err)
	}

	// 顶层键精确为 node + requests
	if len(top) != 2 {
		t.Errorf("top-level keys = %d, want 2, got keys of: %s", len(top), raw)
	}
	if _, ok := top["node"]; !ok {
		t.Errorf("missing top-level key \"node\" in: %s", raw)
	}
	if _, ok := top["requests"]; !ok {
		t.Errorf("missing top-level key \"requests\" in: %s", raw)
	}

	// node 值透传
	var node string
	if err := json.Unmarshal(top["node"], &node); err != nil {
		t.Fatalf("unmarshal node: %v", err)
	}
	if node != "yo-prod-gateway-node4" {
		t.Errorf("node = %q, want %q", node, "yo-prod-gateway-node4")
	}

	// 记录字段名逐个断言（snake_case，与 §6.1 契约一致）
	var reqs []map[string]json.RawMessage
	if err := json.Unmarshal(top["requests"], &reqs); err != nil {
		t.Fatalf("unmarshal requests: %v", err)
	}
	if len(reqs) != 1 {
		t.Fatalf("requests len = %d, want 1", len(reqs))
	}

	wantKeys := []string{
		"method", "host", "path", "query", "status", "bytes", "latency_ms",
		"ref_host", "user_agent", "content_type", "client_ip", "trace_id",
		"req_class", "ts",
	}
	got := reqs[0]
	if len(got) != len(wantKeys) {
		t.Errorf("record has %d fields, want %d: %s", len(got), len(wantKeys), raw)
	}
	for _, key := range wantKeys {
		if _, ok := got[key]; !ok {
			t.Errorf("missing record key %q in: %s", key, raw)
		}
	}

	// 关键字段值类型断言：ts 为数值（UnixMilli）、status/bytes 为数值
	var ts int64
	if err := json.Unmarshal(got["ts"], &ts); err != nil {
		t.Errorf("ts should be numeric, got: %s", got["ts"])
	}
	if ts != 1760000000000 {
		t.Errorf("ts = %d, want 1760000000000", ts)
	}
	var status int
	if err := json.Unmarshal(got["status"], &status); err != nil || status != 200 {
		t.Errorf("status should be numeric 200, got: %s", got["status"])
	}
	var latencyMs int64
	if err := json.Unmarshal(got["latency_ms"], &latencyMs); err != nil || latencyMs != 42 {
		t.Errorf("latency_ms should be numeric 42, got: %s", got["latency_ms"])
	}
	var reqClass string
	if err := json.Unmarshal(got["req_class"], &reqClass); err != nil || reqClass != "doc" {
		t.Errorf("req_class = %s, want \"doc\"", got["req_class"])
	}
}

// TestRecordJSONFieldNamesZeroValue 零值记录同样输出全部契约键（ingest 侧按名取值，
// 不依赖 omitempty 缺省行为）；Sec-Fetch 系透传字段（内部PRD）为 omitempty
// 可选字段，零值必须省略——旧版 tc 按旧契约解析不受影响
func TestRecordJSONFieldNamesZeroValue(t *testing.T) {
	raw, err := json.Marshal(Record{})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{
		"method", "host", "path", "query", "status", "bytes", "latency_ms",
		"ref_host", "user_agent", "content_type", "client_ip", "trace_id",
		"req_class", "ts",
	} {
		if _, ok := got[key]; !ok {
			t.Errorf("zero-value record missing key %q in: %s", key, raw)
		}
	}
	// 新增透传字段零值省略（空串缺省，内部PRD §2.1）
	for _, key := range []string{"sec_fetch_dest", "sec_fetch_mode", "sec_fetch_site", "sec_ch_ua"} {
		if _, ok := got[key]; ok {
			t.Errorf("zero-value record should omit optional key %q in: %s", key, raw)
		}
	}
}

// TestRecordJSONSecFetchPassthrough Sec-Fetch/CH-UA 头透传字段序列化（内部PRD）：
// 非零值按 snake_case 键输出、旧 14 字段零变动；空值字段省略
func TestRecordJSONSecFetchPassthrough(t *testing.T) {
	rec := Record{
		Method:       "GET",
		Host:         "kissfocus.vip",
		Path:         "/",
		Status:       200,
		UserAgent:    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
		ReqClass:     "doc",
		Ts:           1760000000000,
		SecFetchDest: "document",
		SecFetchMode: "navigate",
		SecFetchSite: "none",
		SecCHUA:      `"Chromium";v="132", "Google Chrome";v="132"`,
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	wantVals := map[string]string{
		"sec_fetch_dest": "document",
		"sec_fetch_mode": "navigate",
		"sec_fetch_site": "none",
		"sec_ch_ua":      `"Chromium";v="132", "Google Chrome";v="132"`,
	}
	for key, want := range wantVals {
		rawVal, ok := got[key]
		if !ok {
			t.Errorf("missing key %q in: %s", key, raw)
			continue
		}
		var gotVal string
		if err := json.Unmarshal(rawVal, &gotVal); err != nil || gotVal != want {
			t.Errorf("%s = %s, want %q", key, rawVal, want)
		}
	}

	// 旧 14 字段仍在（只增不改）
	for _, key := range []string{
		"method", "host", "path", "status", "user_agent", "req_class", "ts",
	} {
		if _, ok := got[key]; !ok {
			t.Errorf("old contract key %q missing after extension in: %s", key, raw)
		}
	}

	// 部分缺失场景：未带 Sec-Fetch 头的记录只省略对应键，其余字段不受影响
	rec2 := rec
	rec2.SecFetchSite = ""
	raw2, err := json.Marshal(rec2)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got2 map[string]json.RawMessage
	if err := json.Unmarshal(raw2, &got2); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := got2["sec_fetch_site"]; ok {
		t.Errorf("empty sec_fetch_site should be omitted in: %s", raw2)
	}
	if _, ok := got2["sec_fetch_mode"]; !ok {
		t.Errorf("non-empty sec_fetch_mode missing in: %s", raw2)
	}
}
