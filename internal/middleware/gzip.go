package middleware

import (
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

// gzipWriterPool 用于复用gzip.Writer对象，提高性能
// 使用 defaultLevel 作为池中预创建 writer 的压缩级别
// 实际使用时通过 Reset 指定目标 writer，压缩级别在 pool 创建时固定
const defaultGzipLevel = gzip.BestSpeed

var gzipWriterPool = sync.Pool{
	New: func() interface{} {
		w, err := gzip.NewWriterLevel(io.Discard, defaultGzipLevel)
		if err != nil {
			panic(fmt.Sprintf("failed to create gzip writer: %v", err))
		}
		return w
	},
} // shouldNotCompressStatus 判断该状态码是否不应该压缩
// 204 No Content、304 Not Modified 以及 1xx 响应不允许有 body，
// 压缩它们会注入 gzip 尾部字节，违反 HTTP 规范并可能导致客户端异常
func shouldNotCompressStatus(statusCode int) bool {
	if statusCode == http.StatusNoContent || statusCode == http.StatusNotModified {
		return true
	}
	return statusCode >= 100 && statusCode < 200
}

// appendVaryHeader 添加 Vary: Accept-Encoding 头
// 使用追加模式而非覆盖，保留后端已设置的 Vary 值（如 Cookie、Accept-Language）
func appendVaryHeader(h http.Header) {
	existing := h.Get("Vary")
	if existing == "" {
		h.Set("Vary", "Accept-Encoding")
	} else if !containsToken(existing, "accept-encoding") {
		h.Set("Vary", existing+", Accept-Encoding")
	}
}

// containsToken 检查 header 值中是否包含指定 token（不区分大小写）
func containsToken(value, token string) bool {
	for _, v := range strings.Split(value, ",") {
		if strings.EqualFold(strings.TrimSpace(v), token) {
			return true
		}
	}
	return false
}

// acceptsGzip 正确解析 Accept-Encoding 头，判断客户端是否接受 gzip
// 处理 q=0（明确拒绝）和子串误匹配（如 x-gzip）
func acceptsGzip(header string) bool {
	if header == "" {
		return false
	}
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		// 分离编码名和参数
		encoding := part
		q := 1.0
		if idx := strings.Index(part, ";"); idx != -1 {
			encoding = strings.TrimSpace(part[:idx])
			params := part[idx+1:]
			// 解析 q 值
			for _, p := range strings.Split(params, ";") {
				p = strings.TrimSpace(p)
				if strings.HasPrefix(strings.ToLower(p), "q=") {
					if val, err := strconv.ParseFloat(p[2:], 64); err == nil {
						q = val
					}
				}
			}
		}
		if strings.EqualFold(encoding, "gzip") || strings.EqualFold(encoding, "*") {
			return q > 0
		}
	}
	return false
}

// GzipHandler 返回一个包装http.Handler的函数，用于启用Gzip压缩
// level 和 minSize 分别控制压缩级别和最小压缩大小
// P2-23: level=0 表示"使用默认级别"，而非 gzip.NoCompression
// 这与配置文档中 "0 = default" 的语义一致
func GzipHandler(h http.Handler, level, minSize int) http.Handler {
	// level=0 表示使用默认级别
	if level == 0 {
		level = defaultGzipLevel
	}
	if level < gzip.BestSpeed || level > gzip.BestCompression {
		level = defaultGzipLevel
	}
	if minSize < 0 {
		minSize = 0
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// HEAD 请求的响应不允许有 body，跳过压缩以避免注入空 gzip stream
		if r.Method == http.MethodHead {
			h.ServeHTTP(w, r)
			return
		}
		// 正确解析 Accept-Encoding，处理 q=0 拒绝场景
		if !acceptsGzip(r.Header.Get("Accept-Encoding")) {
			h.ServeHTTP(w, r)
			return
		}

		// 创建一个智能的包装器，检测是否应该压缩并在确定后立即开始处理
		wrapped := &smartGzipWriter{
			ResponseWriter: w,
			r:              r,
			next:           h,
			level:          level,
			minSize:        minSize,
		}

		// 开始处理
		wrapped.handle()
	})
}

// smartGzipWriter 智能gzip包装器，支持流式传输
type smartGzipWriter struct {
	http.ResponseWriter
	r           *http.Request
	next        http.Handler
	gz          *gzip.Writer
	wroteHeader bool
	compressed  bool
	determined  bool
	buffer      []byte
	statusCode  int
	level       int // gzip 压缩级别
	minSize     int // 最小压缩大小（小于此值不压缩）
}

// determineCompression 判断是否应该压缩
func (w *smartGzipWriter) determineCompression() bool {
	// 检查响应是否已经被压缩
	if w.Header().Get("Content-Encoding") != "" {
		return false
	}
	// 无 body 或错误响应不压缩（避免注入空 gzip stream）
	if shouldNotCompressStatus(w.statusCode) {
		return false
	}
	// 检查最小压缩大小
	if w.minSize > 0 {
		// 如果已有 Content-Length，用它判断
		if cl := w.Header().Get("Content-Length"); cl != "" {
			if size, err := strconv.Atoi(cl); err == nil && size < w.minSize {
				return false
			}
		} else if len(w.buffer) < w.minSize {
			// 没有 Content-Length 且缓冲区不足 minSize，不压缩
			// 这确保小响应直接透传，避免 gzip 头部开销使响应变大
			return false
		}
	}
	// 检查Content-Type
	contentType := w.Header().Get("Content-Type")
	return shouldCompress(contentType)
}

// startCompression 开始压缩模式
func (w *smartGzipWriter) startCompression() error {
	// P2-24: 非默认级别时不要从 Pool 取出 writer（取出的会被泄漏）
	// 只有默认级别才使用 Pool 中的 writer
	var gz *gzip.Writer
	if w.level == defaultGzipLevel {
		gz = gzipWriterPool.Get().(*gzip.Writer)
		gz.Reset(w.ResponseWriter)
	} else {
		var err error
		gz, err = gzip.NewWriterLevel(w.ResponseWriter, w.level)
		if err != nil {
			return err
		}
	}
	w.gz = gz
	w.compressed = true
	w.determined = true
	// 压缩后响应体长度会改变，必须删除 Content-Length，否则客户端会按错误长度读取，导致 unexpected EOF
	// 注意：w.Header() 和 w.ResponseWriter.Header() 是同一个 map（嵌入式结构体），
	// 所以必须显式 Del，而不是靠循环跳过来"避免复制"
	w.Header().Del("Content-Length")
	// 设置响应头
	w.ResponseWriter.Header().Set("Content-Encoding", "gzip")
	// 使用追加模式设置 Vary，保留后端已设置的值（如 Cookie）
	appendVaryHeader(w.ResponseWriter.Header())
	// 写入状态码
	if w.statusCode > 0 {
		w.ResponseWriter.WriteHeader(w.statusCode)
	}
	w.wroteHeader = true
	// 写入已缓存的数据
	if len(w.buffer) > 0 {
		_, err := w.gz.Write(w.buffer)
		w.buffer = nil
		return err
	}
	return nil
}

// startPassthrough 开始透传模式
func (w *smartGzipWriter) startPassthrough() {
	w.compressed = false
	w.determined = true
	// 头部通过嵌入的 ResponseWriter 直接共享，无需复制
	// 追加 Vary: Accept-Encoding（即使不压缩，也告知缓存代理此响应对 Accept-Encoding 敏感）
	appendVaryHeader(w.ResponseWriter.Header())
	// 写入状态码
	if w.statusCode > 0 {
		w.ResponseWriter.WriteHeader(w.statusCode)
	}
	w.wroteHeader = true
	// 写入已缓存的数据
	if len(w.buffer) > 0 {
		w.ResponseWriter.Write(w.buffer)
		w.buffer = nil
	}
}

// Write 实现http.ResponseWriter接口
func (w *smartGzipWriter) Write(data []byte) (int, error) {
	if !w.determined {
		// 先缓存一些数据来判断是否应该压缩
		w.buffer = append(w.buffer, data...)
		// 检查是否有足够的信息来判断
		if w.Header().Get("Content-Type") != "" || len(w.buffer) > 1024 || w.statusCode > 0 {
			// 有Content-Type、数据量超过1KB，或者已经设置了状态码，现在判断
			if w.determineCompression() {
				if err := w.startCompression(); err != nil {
					return 0, err
				}
				return len(data), nil
			}
			w.startPassthrough()
			return len(data), nil
		}
		// 继续缓存
		return len(data), nil
	}
	if w.compressed {
		return w.gz.Write(data)
	}
	return w.ResponseWriter.Write(data)
}

// WriteHeader 实现http.ResponseWriter接口
func (w *smartGzipWriter) WriteHeader(code int) {
	if w.wroteHeader {
		return
	}
	w.statusCode = code
	// 检查是否已有足够信息判断是否压缩
	if w.Header().Get("Content-Type") != "" {
		if w.determineCompression() {
			if err := w.startCompression(); err != nil {
				return
			}
			return
		}
		w.startPassthrough()
		return
	}
	// 如果没有 Content-Type，但已经有状态码，我们也应该立即决定
	// 避免响应被阻塞
	if w.statusCode > 0 {
		w.startPassthrough()
		return
	}
	// 继续等待Content-Type
}

// Flush 实现http.Flusher接口
func (w *smartGzipWriter) Flush() {
	if !w.determined {
		// 如果还没决定，现在就决定（防止流式响应被阻塞）
		w.startPassthrough()
	}
	if w.compressed {
		_ = w.gz.Flush()
	}
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

// handle 处理请求
func (w *smartGzipWriter) handle() {
	defer func() {
		// 清理工作
		if w.gz != nil {
			closeErr := w.gz.Close()
			// P2-25: Close 失败的 Writer 不放回 Pool，避免污染 Pool
			// 只有默认级别且 Close 成功的 writer 才放回 pool
			if w.level == defaultGzipLevel && closeErr == nil {
				gzipWriterPool.Put(w.gz)
			}
		}
		// 确保响应被发送
		if !w.wroteHeader && (w.statusCode > 0 || len(w.buffer) > 0) {
			w.startPassthrough()
		}
	}()
	// 处理请求
	w.next.ServeHTTP(w, w.r)
	// 如果还没决定，现在决定
	if !w.determined {
		if len(w.buffer) > 0 || w.statusCode > 0 {
			if w.determineCompression() {
				_ = w.startCompression()
			} else {
				w.startPassthrough()
			}
		}
	}
}

// shouldCompress 判断是否应该压缩该类型的响应
// 使用精确的 MIME type 匹配，避免子串误匹配
func shouldCompress(contentType string) bool {
	if contentType == "" {
		return false
	}

	// 提取 MIME type（去除参数如 charset=utf-8）
	mimeType := strings.TrimSpace(strings.Split(contentType, ";")[0])
	mimeType = strings.ToLower(mimeType)

	// 不压缩流式响应类型（SSE, gRPC 等）
	switch mimeType {
	case "text/event-stream", "application/grpc", "application/grpc-web":
		return false
	}

	// 不压缩已压缩的二进制格式
	incompressibleTypes := map[string]bool{
		"application/octet-stream":     true,
		"application/gzip":             true,
		"application/x-gzip":           true,
		"application/x-bzip2":          true,
		"application/x-xz":             true,
		"application/x-compress":       true,
		"application/x-rar-compressed": true,
		"application/zip":              true,
		"application/x-7z-compressed":  true,
		"application/x-tar":            true,
		"application/pdf":              true,
		"application/x-brotli":         true,
		"application/zstd":             true,
		"image/jpeg":                   true,
		"image/png":                    true,
		"image/gif":                    true,
		"image/webp":                   true,
		"image/avif":                   true,
		"image/heic":                   true,
		"image/heif":                   true,
		"video/mp4":                    true,
		"video/webm":                   true,
		"video/quicktime":              true,
		"audio/mpeg":                   true,
		"audio/ogg":                    true,
		"audio/aac":                    true,
		"application/vnd.docker.distribution.manifest.v2+json":      true,
		"application/vnd.docker.distribution.manifest.list.v2+json": true,
		"application/vnd.docker.distribution.manifest.v1+json":      true,
		"application/vnd.docker.image.rootfs.diff.tar.gzip":         true,
		"application/vnd.oci.image.manifest.v1+json":                true,
		"application/vnd.oci.image.index.v1+json":                   true,
	}
	if incompressibleTypes[mimeType] {
		return false
	}

	// 压缩文本类格式（含 SVG）
	compressibleTypes := []string{
		"text/html",
		"text/css",
		"text/javascript",
		"text/xml",
		"text/plain",
		"application/javascript",
		"application/json",
		"application/xml",
		"application/rss+xml",
		"application/atom+xml",
		"image/svg+xml",
	}

	for _, t := range compressibleTypes {
		if strings.HasPrefix(mimeType, t) {
			return true
		}
	}

	return false
}
