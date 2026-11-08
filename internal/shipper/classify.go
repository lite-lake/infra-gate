package shipper

import "strings"

// probePathPrefixes probe 排除路径前缀（内部PRD §4.4.1 表序 1；
// 与 ingest 侧 store.probe_paths 配置口径一致，网关侧固定内置）
var probePathPrefixes = []string{"/health", "/ready", "/healthz", "/metrics"}

// staticAssetPathFragments 静态资源目录片段（PRD §4.4.1 表序 4 path 兜底）
var staticAssetPathFragments = []string{"/_next/static/", "/static/", "/assets/"}

// staticAssetExts 静态资源后缀集（PRD §4.4.1 表序 4 path 兜底，"等"的落地清单：
// 图片/JS/CSS/字体/音视频常见后缀；比对用小写）
var staticAssetExts = map[string]bool{
	".js": true, ".mjs": true, ".css": true,
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".svg": true,
	".webp": true, ".ico": true, ".bmp": true, ".avif": true,
	".woff": true, ".woff2": true, ".ttf": true, ".eot": true, ".otf": true,
	".mp4": true, ".mp3": true, ".webm": true, ".ogg": true, ".wav": true, ".m4a": true,
}

// Classify 判定 req_class（内部PRD §4.4.1 打标表，顺序固定，纯函数便于单测）：
//
//  1. path 命中 probe 排除路径前缀 → probe
//  2. 响应 CT 前缀 text/html → doc
//  3. CT 含 json，或 path 以 /api/ 开头 → api
//  4. CT 属图片/JS/CSS/字体/媒体，或 path 后缀 ∈ 静态资源后缀集，
//     或 path 含 /_next/static/、/static/、/assets/ → asset
//  5. CT 属字节流（octet-stream/application/pdf/压缩包等）→ download
//  6. 其余（RSC、txt、未知 CT）→ other
//
// 判据实现必须保持纯内存、无 I/O；调整顺序需同步 PRD。
func Classify(path, contentType string) string {
	// 防御性裁剪 query/fragment：hook 契约只传 URL.Path（不含 query）；若调用方
	// 误传带 query/fragment 的路径，前缀与后缀判定不受影响
	if i := strings.IndexAny(path, "?#"); i >= 0 {
		path = path[:i]
	}

	ct := normalizeContentType(contentType)

	// 1) probe：排除路径前缀（前缀匹配，最高优先级）
	for _, prefix := range probePathPrefixes {
		if strings.HasPrefix(path, prefix) {
			return ReqClassProbe
		}
	}

	// 2) doc：响应 CT 前缀 text/html
	if strings.HasPrefix(ct, "text/html") {
		return ReqClassDoc
	}

	// 3) api：CT 含 json，或 path 以 /api/ 开头
	if strings.Contains(ct, "json") || strings.HasPrefix(path, "/api/") {
		return ReqClassAPI
	}

	// 4) asset：CT 属图片/JS/CSS/字体/媒体，或静态后缀 / 静态目录片段
	if isAssetContentType(ct) || isAssetPath(path) {
		return ReqClassAsset
	}

	// 5) download：CT 属字节流
	if isDownloadContentType(ct) {
		return ReqClassDownload
	}

	// 6) other
	return ReqClassOther
}

// normalizeContentType 归一化响应 CT：小写 + 去空白，供前缀/包含判定
func normalizeContentType(contentType string) string {
	return strings.ToLower(strings.TrimSpace(contentType))
}

// isAssetContentType 判定 CT 是否属图片/JS/CSS/字体/媒体类
func isAssetContentType(ct string) bool {
	switch {
	case strings.HasPrefix(ct, "image/"),
		strings.Contains(ct, "javascript"), // application/javascript、text/javascript、x-* 变体
		strings.Contains(ct, "css"),        // text/css、application/x-css 变体
		strings.Contains(ct, "font"),       // font/woff2、application/font-woff、x-font-ttf 变体
		strings.HasPrefix(ct, "audio/"),
		strings.HasPrefix(ct, "video/"):
		return true
	}
	return false
}

// isAssetPath 判定 path 是否命中静态资源后缀集或静态目录片段
func isAssetPath(path string) bool {
	lower := strings.ToLower(path)
	for _, fragment := range staticAssetPathFragments {
		if strings.Contains(lower, fragment) {
			return true
		}
	}
	dot := strings.LastIndexByte(lower, '.')
	if dot < 0 {
		return false
	}
	ext := lower[dot:]
	// 扩展名中不得含路径分隔符（如 "/v1.2/detail" 的 ".2/detail"），防目录误判
	if strings.ContainsAny(ext, "/\\") {
		return false
	}
	return staticAssetExts[ext]
}

// isDownloadContentType 判定 CT 是否属字节流（octet-stream/pdf/压缩包/二进制变体）
func isDownloadContentType(ct string) bool {
	switch {
	case strings.Contains(ct, "octet-stream"),
		strings.HasPrefix(ct, "application/pdf"),
		strings.Contains(ct, "zip"),      // application/zip、x-zip-compressed
		strings.Contains(ct, "x-tar"),    // application/x-tar
		strings.Contains(ct, "gzip"),     // application/gzip、x-gzip
		strings.Contains(ct, "compress"), // application/x-compress 等
		strings.Contains(ct, "7z"),
		strings.Contains(ct, "rar"),
		strings.Contains(ct, "x-msdownload"),
		strings.Contains(ct, "x-iso9660"):
		return true
	}
	return false
}
