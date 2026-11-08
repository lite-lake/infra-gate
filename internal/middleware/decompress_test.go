package middleware

// F5 非 gzip 编码策略测试（内部PRD §4.5/§11 F5）：
// GZIP 大写、多编码链（顺带修的两个存量 bug）、deflate zlib/raw 双形态、
// br 默认 415、allowlist 透传、伪装 gzip 400、解压窗口超限 413。

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// gzipBytes 压缩为 gzip
func gzipBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(data); err != nil {
		t.Fatal(err)
	}
	zw.Close()
	return buf.Bytes()
}

// zlibBytes 压缩为 zlib 包装 deflate
func zlibBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	if _, err := zw.Write(data); err != nil {
		t.Fatal(err)
	}
	zw.Close()
	return buf.Bytes()
}

// rawDeflateBytes 压缩为 raw deflate（无 zlib 头）
func rawDeflateBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	fw, _ := flate.NewWriter(&buf, -1)
	if _, err := fw.Write(data); err != nil {
		t.Fatal(err)
	}
	fw.Close()
	return buf.Bytes()
}

// doDecompress 用给定策略跑一次解压中间件，返回下游看到的 body 与 Content-Encoding
func doDecompress(t *testing.T, policy DecompressPolicy, contentEncoding string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodPost, "/upload", bytes.NewReader(body))
	if contentEncoding != "" {
		req.Header.Set("Content-Encoding", contentEncoding)
	}
	w := httptest.NewRecorder()
	DecompressRequestHandler(h, policy).ServeHTTP(w, req)
	return w
}

// echoBodyHandler 下游回显收到的 body
func echoBodyHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_, _ = w.Write(b)
	})
}

func doDecompressEcho(t *testing.T, policy DecompressPolicy, contentEncoding string, body []byte) (int, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/upload", bytes.NewReader(body))
	if contentEncoding != "" {
		req.Header.Set("Content-Encoding", contentEncoding)
	}
	w := httptest.NewRecorder()
	DecompressRequestHandler(echoBodyHandler(), policy).ServeHTTP(w, req)
	return w.Code, w.Body.String()
}

func TestDecompressGzipVariantsAndChains(t *testing.T) {
	policy := DecompressPolicy{MaxDecompressedBytes: 1 << 20}
	payload := "hello-waf-plaintext"

	// 小写 gzip（存量行为回归）
	if code, body := doDecompressEcho(t, policy, "gzip", gzipBytes(t, []byte(payload))); code != 200 || body != payload {
		t.Errorf("gzip: code=%d body=%q", code, body)
	}
	// GZIP 大写（F5 修复的存量 bug：此前原样透传、WAF 全盲）
	if code, body := doDecompressEcho(t, policy, "GZIP", gzipBytes(t, []byte(payload))); code != 200 || body != payload {
		t.Errorf("GZIP uppercase: code=%d body=%q", code, body)
	}
	// 多编码链 gzip, gzip（F5 修复的存量 bug）
	once := gzipBytes(t, []byte(payload))
	if code, body := doDecompressEcho(t, policy, "gzip, gzip", gzipBytes(t, once)); code != 200 || body != payload {
		t.Errorf("gzip,gzip chain: code=%d body=%q", code, body)
	}
	// zlib 包装 deflate
	if code, body := doDecompressEcho(t, policy, "deflate", zlibBytes(t, []byte(payload))); code != 200 || body != payload {
		t.Errorf("deflate zlib: code=%d body=%q", code, body)
	}
	// raw deflate（zlib 解析失败回落）
	if code, body := doDecompressEcho(t, policy, "deflate", rawDeflateBytes(t, []byte(payload))); code != 200 || body != payload {
		t.Errorf("deflate raw: code=%d body=%q", code, body)
	}
	// DEFLATE 大小写
	if code, body := doDecompressEcho(t, policy, "DEFLATE", zlibBytes(t, []byte(payload))); code != 200 || body != payload {
		t.Errorf("DEFLATE: code=%d body=%q", code, body)
	}
	// 空声明（无编码头）直通
	if code, body := doDecompressEcho(t, policy, "", []byte(payload)); code != 200 || body != payload {
		t.Errorf("no encoding: code=%d body=%q", code, body)
	}
}

func TestDecompressUnsupportedEncoding415(t *testing.T) {
	policy := DecompressPolicy{MaxDecompressedBytes: 1 << 20}
	for _, enc := range []string{"br", "zstd", "compress", "x-br-custom"} {
		w := doDecompress(t, policy, enc, []byte("opaque-bytes"))
		if w.Code != http.StatusUnsupportedMediaType {
			t.Errorf("encoding %q: status = %d, want 415", enc, w.Code)
		}
		if !strings.Contains(w.Body.String(), enc) {
			t.Errorf("encoding %q: body should name the encoding, got %q", enc, w.Body.String())
		}
	}
}

func TestDecompressAllowlistPassthrough(t *testing.T) {
	policy := DecompressPolicy{
		MaxDecompressedBytes:    1 << 20,
		AllowedContentEncodings: []string{"br"},
	}
	// br 在放行清单 → 原样透传（下游看到原始字节与编码头）
	req := httptest.NewRequest(http.MethodPost, "/upload", bytes.NewReader([]byte("opaque-br-bytes")))
	req.Header.Set("Content-Encoding", "br")
	w := httptest.NewRecorder()
	var gotBody string
	var gotEnc string
	DecompressRequestHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody, gotEnc = string(b), r.Header.Get("Content-Encoding")
	}), policy).ServeHTTP(w, req)
	if w.Code != 200 || gotBody != "opaque-br-bytes" || gotEnc != "br" {
		t.Errorf("allowlist passthrough: code=%d body=%q enc=%q", w.Code, gotBody, gotEnc)
	}
	// zstd 不在清单 → 仍 415
	w = doDecompress(t, policy, "zstd", []byte("opaque"))
	if w.Code != http.StatusUnsupportedMediaType {
		t.Errorf("zstd not in allowlist: status = %d, want 415", w.Code)
	}
}

func TestDecompressDisguisedGzip400(t *testing.T) {
	policy := DecompressPolicy{MaxDecompressedBytes: 1 << 20}
	// 声明 gzip 但数据非 gzip → 400 fail-close（存量行为维持）
	if code, _ := doDecompressEcho(t, policy, "gzip", []byte("not-gzip-at-all")); code != http.StatusBadRequest {
		t.Errorf("disguised gzip: code = %d, want 400", code)
	}
}

func TestDecompressWindowLimit413(t *testing.T) {
	// F1.5：解压窗口（policy 注入，缺省 1MB 与 SecRequestBodyLimit 对齐）
	small := DecompressPolicy{MaxDecompressedBytes: 64}
	big := bytes.Repeat([]byte("a"), 1024)
	// gzip 超 64B 窗口 → 413
	if code, _ := doDecompressEcho(t, small, "gzip", gzipBytes(t, big)); code != http.StatusRequestEntityTooLarge {
		t.Errorf("over-window gzip: code = %d, want 413", code)
	}
	// deflate 超窗口 → 413
	if code, _ := doDecompressEcho(t, small, "deflate", zlibBytes(t, big)); code != http.StatusRequestEntityTooLarge {
		t.Errorf("over-window deflate: code = %d, want 413", code)
	}
	// 恰好等于窗口上限 → 放行（+1 语义不误杀边界）
	if code, body := doDecompressEcho(t, small, "gzip", gzipBytes(t, bytes.Repeat([]byte("a"), 64))); code != 200 || len(body) != 64 {
		t.Errorf("exact-window gzip: code=%d len=%d, want 200/64", code, len(body))
	}
}
