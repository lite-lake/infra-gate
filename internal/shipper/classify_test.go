package shipper

import "testing"

// TestClassify 打标判据矩阵（内部PRD §4.4.1 表：6 类 × CT 主判据 × path 兜底，
// 判定顺序固定 1)probe → 2)doc → 3)api → 4)asset → 5)download → 6)other）
func TestClassify(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		contentType string
		want        string
	}{
		// --- 1) probe：排除路径前缀（前缀匹配，最高优先级，压过一切 CT/path 判据） ---
		{"probe /health with json CT", "/health", "application/json", ReqClassProbe},
		{"probe /health deeper path", "/health/detail", "text/plain", ReqClassProbe},
		{"probe /ready", "/ready", "", ReqClassProbe},
		{"probe /healthz beats html CT", "/healthz", "text/html; charset=utf-8", ReqClassProbe},
		{"probe /metrics", "/metrics", "text/plain", ReqClassProbe},
		{"probe prefix literal match /healthy-app", "/healthy-app", "application/json", ReqClassProbe}, // 前缀匹配语义（PRD 表序 1）
		{"not probe: other path", "/status", "text/plain", ReqClassOther},

		// --- 2) doc：响应 CT 前缀 text/html ---
		{"doc html with charset", "/", "text/html; charset=utf-8", ReqClassDoc},
		{"doc html case-insensitive", "/some/page", "TEXT/HTML", ReqClassDoc},
		{"doc beats /api/ path", "/api/list", "text/html", ReqClassDoc},

		// --- 3) api：CT 含 json，或 path 以 /api/ 开头 ---
		{"api application/json", "/x", "application/json", ReqClassAPI},
		{"api text/json", "/x", "text/json", ReqClassAPI},
		{"api ld+json variant", "/x", "application/ld+json; profile=xxx", ReqClassAPI},
		{"api path prefix no CT", "/api/users", "", ReqClassAPI},
		{"api path prefix with plain CT", "/api/users", "text/plain", ReqClassAPI},
		{"api path beats download CT", "/api/v1/items", "application/octet-stream", ReqClassAPI},
		{"not api: /api2 boundary", "/api2/x", "text/plain", ReqClassOther},

		// --- 4) asset：CT 图片/JS/CSS/字体/媒体，或静态后缀 / 静态目录片段 ---
		{"asset image CT", "/a.png", "image/png", ReqClassAsset},
		{"asset image variant", "/a", "image/webp", ReqClassAsset},
		{"asset javascript CT", "/app.js", "application/javascript", ReqClassAsset},
		{"asset css CT", "/style", "text/css", ReqClassAsset},
		{"asset font CT", "/f", "font/woff2", ReqClassAsset},
		{"asset font variant", "/f", "application/font-woff", ReqClassAsset},
		{"asset video CT", "/v", "video/mp4", ReqClassAsset},
		{"asset audio CT", "/a", "audio/mpeg", ReqClassAsset},
		{"asset path suffix no CT", "/app.js", "", ReqClassAsset},
		{"asset path suffix uppercase", "/APP.JS", "", ReqClassAsset},
		{"asset suffix beats download CT", "/a.js", "application/octet-stream", ReqClassAsset},
		{"asset /_next/static/ fragment", "/_next/static/chunk.abc.js", "text/plain", ReqClassAsset},
		{"asset /static/ fragment", "/static/logo.png", "", ReqClassAsset},
		{"asset /assets/ fragment", "/assets/img", "", ReqClassAsset},
		{"asset query does not break suffix", "/app.js?v=123", "", ReqClassAsset},

		// --- 5) download：CT 字节流（octet-stream/pdf/压缩包/二进制变体） ---
		{"download octet-stream", "/f.bin", "application/octet-stream", ReqClassDownload},
		{"download pdf", "/doc", "application/pdf", ReqClassDownload},
		{"download zip", "/f", "application/zip", ReqClassDownload},
		{"download zip variant", "/f", "application/x-zip-compressed", ReqClassDownload},
		{"download gzip", "/f", "application/gzip", ReqClassDownload},
		{"download tar", "/f", "application/x-tar", ReqClassDownload},
		{"download 7z", "/f", "application/x-7z-compressed", ReqClassDownload},
		{"download rar", "/f", "application/x-rar-compressed", ReqClassDownload},
		{"download msdownload", "/f", "application/x-msdownload", ReqClassDownload},

		// --- 6) other：RSC、txt、未知 CT 等 ---
		{"other text/plain", "/page", "text/plain", ReqClassOther},
		{"other RSC CT", "/rsc", "text/x-component", ReqClassOther},
		{"other empty CT", "/", "", ReqClassOther},
		{"other xml", "/weird", "application/xml", ReqClassOther},
		{"other txt suffix not static", "/file.TXT", "", ReqClassOther},
		{"other dot in dir not ext", "/v1.2/detail", "", ReqClassOther},
		{"other trailing slash no ext", "/dir/", "", ReqClassOther},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Classify(tt.path, tt.contentType); got != tt.want {
				t.Errorf("Classify(%q, %q) = %q, want %q", tt.path, tt.contentType, got, tt.want)
			}
		})
	}
}

// TestClassifyOrderPriority 固定顺序的判据优先级（高序判据压过低序）
func TestClassifyOrderPriority(t *testing.T) {
	// 1 probe > 3 api：json CT 不改变 probe 归类
	if got := Classify("/health", "application/json"); got != ReqClassProbe {
		t.Errorf("probe should beat api, got %q", got)
	}
	// 2 doc > 3 api：/api/ 路径不影响 doc 归类
	if got := Classify("/api/page", "text/html"); got != ReqClassDoc {
		t.Errorf("doc should beat api, got %q", got)
	}
	// 3 api > 4 asset：静态后缀不改变 /api/ 归类
	if got := Classify("/api/x.js", "image/png"); got != ReqClassAPI {
		t.Errorf("api should beat asset, got %q", got)
	}
	// 4 asset > 5 download：静态后缀 + 字节流 CT 归 asset
	if got := Classify("/x.js", "application/pdf"); got != ReqClassAsset {
		t.Errorf("asset should beat download, got %q", got)
	}
}
