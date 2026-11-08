package waf

// F8 WAF 事件脱敏测试（内部PRD §4.8/§11 F8）：
// urlencoded/JSON 嵌套/数组键掩码；multipart 文件摘要；截断正则兜底；
// MatchedVars 掩码；事件 JSON 无 AuditLog 字段；body_hash 进程内一致。

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSanitizeURLEncodedBody(t *testing.T) {
	in := "username=admin&password=hunter2&csrf=xyz"
	got := SanitizeRequestBody(in, "application/x-www-form-urlencoded")
	if !strings.Contains(got, "password=%2A%2A%2A") && !strings.Contains(got, "password=***") {
		t.Errorf("urlencoded password not masked: %q", got)
	}
	if !strings.Contains(got, "username=admin") {
		t.Errorf("non-sensitive key should survive: %q", got)
	}
	// 嵌套表单键 user[password]
	got2 := SanitizeRequestBody("user[password]=secret&user[name]=bob", "application/x-www-form-urlencoded")
	if strings.Contains(got2, "secret") {
		t.Errorf("nested form key not masked: %q", got2)
	}
}

func TestSanitizeJSONBody(t *testing.T) {
	in := `{"user":"admin","password":"hunter2","nested":{"client_secret":"cs123","list":[{"token":"t1"},{"x":2}],"n":12345678901234567890}}`
	got := SanitizeRequestBody(in, "application/json")
	if strings.Contains(got, "hunter2") || strings.Contains(got, "cs123") || strings.Contains(got, "\"t1\"") {
		t.Errorf("json sensitive values not masked: %q", got)
	}
	if !strings.Contains(got, `"user":"admin"`) {
		t.Errorf("non-sensitive json key should survive: %q", got)
	}
	// UseNumber：大数不失真
	if !strings.Contains(got, "12345678901234567890") {
		t.Errorf("big number should survive exactly (UseNumber): %q", got)
	}
}

func TestSanitizeJSONParseFailureFallsBackToScrub(t *testing.T) {
	// >4KB 截断产生的半截 JSON：解析失败 → 正则兜底仍掩码
	in := `{"password":"truncated-secret","data":"` + strings.Repeat("x", 100)
	got := SanitizeRequestBody(in, "application/json")
	if strings.Contains(got, "truncated-secret") {
		t.Errorf("scrub fallback failed: %q", got)
	}
}

func TestSanitizeMultipartBody(t *testing.T) {
	body := "--BOUND\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nhunter2\r\n--BOUND\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"a.bin\"\r\nContent-Type: application/octet-stream\r\n\r\nBINARYDATA\r\n--BOUND--\r\n"
	ct := "multipart/form-data; boundary=BOUND"
	got := SanitizeRequestBody(body, ct)
	if strings.Contains(got, "hunter2") {
		t.Errorf("multipart password not masked: %q", got)
	}
	if strings.Contains(got, "BINARYDATA") {
		t.Errorf("multipart file content should be dropped (summary only): %q", got)
	}
	if !strings.Contains(got, "a.bin") {
		t.Errorf("file summary should keep filename: %q", got)
	}
}

func TestSanitizeOtherContentTypePassthrough(t *testing.T) {
	in := "raw-bytes-here"
	if got := SanitizeRequestBody(in, "application/octet-stream"); got != in {
		t.Errorf("other content types should pass through, got %q", got)
	}
}

func TestMaskMatchedVars(t *testing.T) {
	vars := []MatchedVar{
		{Variable: "ARGS", Key: "password", Value: "hunter2", Data: "hunter2"},
		{Variable: "ARGS", Key: "username", Value: "admin", Data: "admin"},
	}
	maskMatchedVars(vars)
	if vars[0].Value != maskedValue || vars[0].Data != maskedValue {
		t.Errorf("sensitive matched var not masked: %+v", vars[0])
	}
	if vars[1].Value != "admin" {
		t.Errorf("non-sensitive matched var should survive: %+v", vars[1])
	}
}

func TestRecordEventSanitizesAndHashes(t *testing.T) {
	st := newStatsTracker()
	ev := WAFEvent{
		Type:           EventTypeBlock,
		ReqBody:        "password=hunter2&ok=1",
		ReqContentType: "application/x-www-form-urlencoded",
		MatchedVars:    []MatchedVar{{Variable: "ARGS", Key: "password", Value: "hunter2"}},
	}
	st.recordEvent(ev)

	got := st.recentEvents(1)[0]
	if strings.Contains(got.ReqBody, "hunter2") {
		t.Errorf("stored event body not sanitized: %q", got.ReqBody)
	}
	if got.BodyLen != len("password=hunter2&ok=1") {
		t.Errorf("BodyLen = %d, want raw length", got.BodyLen)
	}
	if len(got.BodyHash) != 64 {
		t.Errorf("BodyHash = %q, want 64-char hex", got.BodyHash)
	}
	if got.MatchedVars[0].Value != maskedValue {
		t.Errorf("matched var not masked in stored event: %+v", got.MatchedVars[0])
	}

	// 事件 JSON 序列化不含 AuditLog 字段（D8）
	b, _ := json.Marshal(got)
	if strings.Contains(string(b), "audit_log") {
		t.Errorf("event JSON must not contain audit_log: %s", b)
	}
	// body_hash 进程内一致（同原文同摘要）
	if BodyHash("password=hunter2&ok=1") != got.BodyHash {
		t.Error("BodyHash should be deterministic within the process")
	}
}
