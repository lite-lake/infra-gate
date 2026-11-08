package middleware

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

func TestShouldCompress(t *testing.T) {
	tests := []struct {
		contentType string
		expected    bool
	}{
		// Compressible types
		{"text/html", true},
		{"text/html; charset=utf-8", true},
		{"text/css", true},
		{"text/javascript", true},
		{"text/plain", true},
		{"text/xml", true},
		{"application/json", true},
		{"application/json; charset=utf-8", true},
		{"application/xml", true},
		{"application/rss+xml", true},
		{"application/atom+xml", true},
		{"application/javascript", true},
		{"image/svg+xml", true},
		{"image/svg+xml; charset=utf-8", true},

		// Incompressible types
		{"image/jpeg", false},
		{"image/png", false},
		{"image/gif", false},
		{"image/webp", false},
		{"video/mp4", false},
		{"audio/mpeg", false},
		{"application/octet-stream", false},
		{"application/gzip", false},
		{"application/zip", false},
		{"application/pdf", false},
		{"application/x-tar", false},
		{"application/vnd.docker.distribution.manifest.v2+json", false},
		{"application/vnd.oci.image.manifest.v1+json", false},

		// Special types
		{"text/event-stream", false},
		{"application/grpc", false},
		{"application/grpc-web", false},

		// Edge cases
		{"", false},
		{"application/x-bzip2", false},
		{"application/x-xz", false},
		{"application/x-brotli", false},
		{"application/zstd", false},
	}

	for _, tt := range tests {
		result := shouldCompress(tt.contentType)
		if result != tt.expected {
			t.Errorf("shouldCompress(%q) = %v, want %v", tt.contentType, result, tt.expected)
		}
	}
}

func TestShouldNotCompressStatus(t *testing.T) {
	tests := []struct {
		statusCode int
		expected   bool
	}{
		{200, false},
		{301, false},
		{404, false},
		{500, false},
		{100, true},
		{101, true},
		{199, true},
		{204, true},
		{304, true},
	}

	for _, tt := range tests {
		result := shouldNotCompressStatus(tt.statusCode)
		if result != tt.expected {
			t.Errorf("shouldNotCompressStatus(%d) = %v, want %v", tt.statusCode, result, tt.expected)
		}
	}
}

func TestAcceptsGzip(t *testing.T) {
	tests := []struct {
		header   string
		expected bool
	}{
		{"gzip", true},
		{"gzip, deflate", true},
		{"deflate, gzip", true},
		{"gzip;q=1", true},
		{"gzip;q=0.5", true},
		{"*", true},
		{"*;q=0.5", true},
		{"", false},
		{"gzip;q=0", false},
		{"deflate, gzip;q=0", false},
		{"gzip;q=0, deflate", false},
		{"x-gzip", false},
		{"identity", false},
		{"br", false},
	}

	for _, tt := range tests {
		result := acceptsGzip(tt.header)
		if result != tt.expected {
			t.Errorf("acceptsGzip(%q) = %v, want %v", tt.header, result, tt.expected)
		}
	}
}

func TestGzipHandlerCompression(t *testing.T) {
	body := string(make([]byte, 2048)) // > 1KB to trigger compression
	backendHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, body)
	})

	handler := GzipHandler(backendHandler, gzip.BestSpeed, 0)

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	if resp.Header.Get("Content-Encoding") != "gzip" {
		t.Errorf("Content-Encoding = %q, want %q", resp.Header.Get("Content-Encoding"), "gzip")
	}

	if resp.Header.Get("Content-Length") != "" {
		t.Errorf("Content-Length should be removed when compressing, got %q", resp.Header.Get("Content-Length"))
	}

	if resp.Header.Get("Vary") == "" {
		t.Error("Vary header should be set")
	}

	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		t.Fatalf("gzip.NewReader failed: %v", err)
	}
	decompressed, err := io.ReadAll(gz)
	if err != nil {
		t.Fatalf("io.ReadAll failed: %v", err)
	}
	if string(decompressed) != body {
		t.Errorf("decompressed body length = %d, want %d", len(decompressed), len(body))
	}
}

func TestGzipHandlerPassthrough(t *testing.T) {
	body := "small"
	backendHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, body)
	})

	// minSize=1024 means small body won't be compressed
	handler := GzipHandler(backendHandler, gzip.BestSpeed, 1024)

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	if resp.Header.Get("Content-Encoding") == "gzip" {
		t.Error("should not compress small body when minSize=1024")
	}

	respBody, _ := io.ReadAll(resp.Body)
	if string(respBody) != body {
		t.Errorf("body = %q, want %q", string(respBody), body)
	}
}

func TestGzipHandlerNoAcceptEncoding(t *testing.T) {
	body := "hello world"
	backendHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, body)
	})

	handler := GzipHandler(backendHandler, gzip.BestSpeed, 0)

	req := httptest.NewRequest("GET", "/", nil)
	// No Accept-Encoding header
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	if resp.Header.Get("Content-Encoding") == "gzip" {
		t.Error("should not compress when client does not accept gzip")
	}
}

func TestGzipHandlerHeadRequest(t *testing.T) {
	backendHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
	})

	handler := GzipHandler(backendHandler, gzip.BestSpeed, 0)

	req := httptest.NewRequest("HEAD", "/", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	if resp.Header.Get("Content-Encoding") == "gzip" {
		t.Error("HEAD request should not be compressed")
	}
}

func TestGzipHandlerAlreadyCompressed(t *testing.T) {
	backendHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(http.StatusOK)
		// Write some fake gzip data
		w.Write([]byte{0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00})
	})

	handler := GzipHandler(backendHandler, gzip.BestSpeed, 0)

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	// Should not double-compress
	ce := resp.Header.Get("Content-Encoding")
	if ce != "gzip" {
		t.Errorf("Content-Encoding = %q, want %q (from backend, not double-compressed)", ce, "gzip")
	}
}

func TestGzipHandlerVaryHeaderNotOverwritten(t *testing.T) {
	backendHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Vary", "Cookie")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, string(make([]byte, 2048)))
	})

	handler := GzipHandler(backendHandler, gzip.BestSpeed, 0)

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	vary := resp.Header.Get("Vary")
	if vary == "" {
		t.Error("Vary header should be set")
	}
	// Should contain both Cookie and Accept-Encoding
	if !containsToken(vary, "cookie") {
		t.Errorf("Vary should contain 'Cookie', got %q", vary)
	}
	if !containsToken(vary, "accept-encoding") {
		t.Errorf("Vary should contain 'Accept-Encoding', got %q", vary)
	}
}

// --- DecompressRequestHandler tests ---

func TestDecompressRequestHandlerGzip(t *testing.T) {
	originalBody := `{"message":"hello world","data":"test"}`
	var compressedBody bytes.Buffer
	gz := gzip.NewWriter(&compressedBody)
	gz.Write([]byte(originalBody))
	gz.Close()

	var receivedBody string
	backendHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedBody = string(body)
		w.WriteHeader(http.StatusOK)
	})

	handler := DecompressRequestHandler(backendHandler, DecompressPolicy{})

	req := httptest.NewRequest("POST", "/", &compressedBody)
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("Content-Length", strconv.Itoa(compressedBody.Len()))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if receivedBody != originalBody {
		t.Errorf("decompressed body = %q, want %q", receivedBody, originalBody)
	}

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestDecompressRequestHandlerNoEncoding(t *testing.T) {
	originalBody := `{"message":"plain"}`
	var receivedBody string
	backendHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedBody = string(body)
		w.WriteHeader(http.StatusOK)
	})

	handler := DecompressRequestHandler(backendHandler, DecompressPolicy{})

	req := httptest.NewRequest("POST", "/", bytes.NewReader([]byte(originalBody)))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if receivedBody != originalBody {
		t.Errorf("body = %q, want %q", receivedBody, originalBody)
	}
}

func TestDecompressRequestHandlerMalformedGzip(t *testing.T) {
	backendHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := DecompressRequestHandler(backendHandler, DecompressPolicy{})

	req := httptest.NewRequest("POST", "/", bytes.NewReader([]byte("not gzip data")))
	req.Header.Set("Content-Encoding", "gzip")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d for malformed gzip", rec.Code, http.StatusBadRequest)
	}
}
