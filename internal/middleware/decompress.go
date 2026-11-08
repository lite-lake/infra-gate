package middleware

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// DecompressRequestHandler 是一个中间件，在 WAF 检测之前解压压缩的请求体
// （gzip / deflate），使 WAF 检测明文内容。
//
// F5（内部PRD §4.5）改造：
//   - Content-Encoding 按 token 列表解析（逗号分割、EqualFold）——顺带修复
//     「GZIP 大写不识别」「gzip, br 多编码链不识别」两个存量 bug；
//   - 逐层解码：gzip 走既有逻辑；deflate 用标准库（zlib 失败回落 raw flate，
//     Caddy 同款兼容两种服务器形态）；
//   - br / zstd / 未知编码：命中 policy.AllowedContentEncodings → 原样透传 +
//     Debug 日志（不进 WAF 正文检测，放行清单显式声明）；未命中 → 415 fail-close
//     （body 写明不支持的编码名）。浏览器与常规 API 客户端几乎不发压缩请求体，
//     现网无压缩请求体业务（D5：br/zstd 解压依赖不引入）；
//   - gzip 伪装路径维持现状 fail-close（非 gzip 数据声明 gzip → 400）。
//
// F1.5（内部PRD §4.1.5）：解压窗口上限经 policy.MaxDecompressedBytes
// 注入（缺省 config.DefaultMaxDecompressedRequestBody = 1MB，与 WAF
// SecRequestBodyLimit 单一事实源对齐；per-host max_decompressed_request_body
// 可放宽，服务 body 扫描关闭的上传 host）；压缩侧 10MB 限幅不变。
func DecompressRequestHandler(h http.Handler, policy DecompressPolicy) http.Handler {
	if policy.MaxDecompressedBytes <= 0 {
		policy.MaxDecompressedBytes = 1 << 20
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		encodings := parseContentEncodings(r.Header.Get("Content-Encoding"))
		if len(encodings) == 0 {
			h.ServeHTTP(w, r)
			return
		}

		// 自外向内逐层判定：任一层是 br/zstd/未知编码 → 放行清单决定透传或 415
		for _, enc := range encodings {
			switch strings.ToLower(enc) {
			case "gzip", "deflate", "x-gzip":
				// 可解压编码，继续
			default:
				if containsFold(policy.AllowedContentEncodings, enc) {
					// F5.2：显式放行（原样透传，WAF 正文检测对该 host 明确豁免）
					h.ServeHTTP(w, r)
					return
				}
				w.Header().Set("Accept-Encoding", "gzip, deflate")
				http.Error(w, "Unsupported Content-Encoding: "+enc+" (only gzip/deflate are decoded; "+enc+" requires per-host allowed_content_encodings)", http.StatusUnsupportedMediaType)
				return
			}
		}

		// 全部为可解压编码（gzip/deflate 链）：移除头后逐层解压
		r.Header.Del("Content-Encoding")

		if r.Body == nil {
			h.ServeHTTP(w, r)
			return
		}

		// P2-26: 限制压缩前请求体大小（压缩侧 10MB 限幅不变），防止并发 OOM
		limitedCompressed := &io.LimitedReader{R: r.Body, N: maxCompressedBodySize + 1}

		// 逐层构建 reader：encodings[0] 为最外层（请求按声明顺序包裹）
		// Content-Encoding: gzip, gzip 表示先解第一层 gzip 再解第二层
		var reader io.Reader = limitedCompressed
		for _, enc := range encodings {
			switch strings.ToLower(enc) {
			case "gzip", "x-gzip":
				gr, err := gzip.NewReader(reader)
				if err != nil {
					http.Error(w, "malformed gzip request body", http.StatusBadRequest)
					return
				}
				defer gr.Close()
				reader = gr
			case "deflate":
				// deflate 有 zlib 包装与 raw flate 两种服务器形态。zlib.NewReader
				// 失败时已消费流头字节且不可回退，故不能先试 zlib 再回落——改用
				// bufio.Peek 判定 zlib 头（CMF/FLG 校验和整除 31 且低 4 位为 8，
				// nginx 同款判别）：有头走 zlib，无头走 raw flate
				br := bufio.NewReader(reader)
				if header, perr := br.Peek(2); perr == nil && len(header) == 2 &&
					(int(header[0])*256+int(header[1]))%31 == 0 && header[0]&0x0f == 8 {
					zr, zerr := zlib.NewReader(br)
					if zerr == nil {
						defer zr.Close()
						reader = zr
						break
					}
				}
				fr := flate.NewReader(br)
				defer fr.Close()
				reader = fr
			}
		}

		// LimitedReader 防 zip bomb：限制解压后总大小（F1.5 窗口）
		limitedReader := &io.LimitedReader{R: reader, N: int64(policy.MaxDecompressedBytes) + 1}
		decompressed, err := io.ReadAll(limitedReader)

		if err != nil && err != io.EOF {
			http.Error(w, "failed to decompress request body", http.StatusBadRequest)
			return
		}

		// 检查是否因解压超限被截断
		if limitedReader.N <= 0 && int64(len(decompressed)) >= int64(policy.MaxDecompressedBytes) {
			w.Header().Set("Accept-Encoding", "identity")
			http.Error(w, "request body too large after decompression", http.StatusRequestEntityTooLarge)
			return
		}

		// P2-26: 检查压缩数据是否超限
		if limitedCompressed.N <= 0 {
			http.Error(w, "compressed request body too large", http.StatusRequestEntityTooLarge)
			return
		}

		// 替换请求体为解压后的数据
		r.Body = io.NopCloser(bytes.NewReader(decompressed))
		// 更新 Content-Length 为解压后的实际长度
		r.Header.Set("Content-Length", strconv.Itoa(len(decompressed)))
		r.ContentLength = int64(len(decompressed))

		h.ServeHTTP(w, r)
	})
}

// DecompressPolicy F5 解压策略（由 server 按 host 合并后注入）
type DecompressPolicy struct {
	// MaxDecompressedBytes 解压后请求体上限（F1.5；<=0 取 1MB 缺省）
	MaxDecompressedBytes int
	// AllowedContentEncodings 放行透传的编码（取值 ∈ {br, zstd}，config 已校验）
	AllowedContentEncodings []string
}

// parseContentEncodings 解析 Content-Encoding 为 token 列表：
// 逗号分割、trim 空白、EqualFold 容忍大小写（修复 GZIP 大写与多编码链两个存量
// bug）；空 token 跳过；全空返回 nil
func parseContentEncodings(header string) []string {
	if strings.TrimSpace(header) == "" {
		return nil
	}
	parts := strings.Split(header, ",")
	tokens := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			tokens = append(tokens, p)
		}
	}
	return tokens
}

// containsFold 大小写不敏感的列表包含判断
func containsFold(list []string, s string) bool {
	for _, v := range list {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}

// maxCompressedBodySize 限制压缩前请求体的大小，防止 OOM（P2-26）
const maxCompressedBodySize = 10 * 1024 * 1024 // 10MB
