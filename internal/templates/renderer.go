package templates

import (
	"bytes"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/lite-lake/infra-gate/internal/infrastructs/logger"
)

// Renderer 模板渲染器
type Renderer struct {
	templates    map[string]*template.Template
	fallbackTmpl *template.Template
	logger       logger.ILogger
}

// TemplateData 模板数据结构
type TemplateData struct {
	StatusCode     int
	TraceId        string
	Timestamp      string
	ClientIP       string
	RequestPath    string
	ServerInstance string
	Error          string
	Reason         string
	ErrorType      string
	ErrorLevel     string
	UpstreamHost   string
	RetryCount     int
	RetryAfter     int
	SupportEmail   string
	SupportPhone   string
}

// NewRenderer 创建新的模板渲染器
func NewRenderer(log logger.ILogger) *Renderer {
	r := &Renderer{
		templates: make(map[string]*template.Template),
		logger:    log,
	}

	// 预编译 fallback 模板，确保 HTML 转义
	// 品牌基线（内部PRD P3 / frontend-design.md §10.3）：墨阶令牌最小内联样式，
	// 中文单语，prefers-color-scheme 暗色跟随——模板渲染失败时也不裸奔
	r.fallbackTmpl = template.Must(template.New("fallback").Parse(`<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>服务暂时不可用</title>
<style>
:root{--bg:#FFFFFF;--ink:#1A1A1A;--ink-2:#717171}
@media (prefers-color-scheme:dark){:root{--bg:#141518;--ink:#F2F3F5;--ink-2:#A8ADB5}}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:var(--bg);color:var(--ink);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","Helvetica Neue","PingFang SC","Microsoft YaHei",sans-serif;font-size:16px;line-height:1.6;-webkit-font-smoothing:antialiased}
p{margin:0;padding:0 16px;text-align:center}
span{color:var(--ink-2)}
</style>
</head>
<body>
<p>服务暂时不可用，请稍后重试。<span>错误 {{.StatusCode}} · 追踪ID {{.TraceId}} · {{.Timestamp}}</span></p>
</body>
</html>`))

	// 加载所有模板
	r.loadTemplates()
	return r
}

// loadTemplates 加载所有模板文件
func (r *Renderer) loadTemplates() {
	// P2-51: 使用可执行文件目录解析模板路径，不依赖工作目录
	tmplBaseDir := getTemplatesDir()

	templateFiles := map[string]string{
		"blocked":        "blocked.html",
		"upstream_error": "upstream_error.html",
		"system_error":   "system_error.html",
	}

	for name, filename := range templateFiles {
		fullPath := filepath.Join(tmplBaseDir, filename)
		tmpl, err := template.ParseFiles(fullPath)
		if err != nil {
			// P2-50: 模板加载失败应 Fatal，因为错误页面渲染依赖模板
			r.logger.Fatal("Failed to load template, refusing to start without error pages",
				logger.NewField("template", name),
				logger.NewField("path", fullPath),
				logger.NewField("error", err))
		}
		r.templates[name] = tmpl
		r.logger.Info("Template loaded successfully",
			logger.NewField("template", name),
			logger.NewField("path", fullPath))
	}
}

// getTemplatesDir 返回模板文件的基准目录
// P2-51: 优先使用可执行文件所在目录，回退到工作目录
func getTemplatesDir() string {
	exePath, err := os.Executable()
	if err == nil {
		exeDir := filepath.Dir(exePath)
		// 检查可执行文件同目录下的 templates/
		if _, err := os.Stat(filepath.Join(exeDir, "templates")); err == nil {
			return filepath.Join(exeDir, "templates")
		}
		// 检查上一级目录（开发环境）
		parentDir := filepath.Dir(exeDir)
		if _, err := os.Stat(filepath.Join(parentDir, "templates")); err == nil {
			return filepath.Join(parentDir, "templates")
		}
	}
	// 回退到工作目录相对路径
	return "templates"
}

// Render 渲染模板并返回HTML内容
func (r *Renderer) Render(templateName string, data TemplateData) (string, error) {
	tmpl, exists := r.templates[templateName]
	if !exists {
		return "", fmt.Errorf("template not found: %s", templateName)
	}

	// 设置默认值
	if data.Timestamp == "" {
		data.Timestamp = time.Now().Format("2006-01-02 15:04:05")
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		r.logger.Error("Failed to render template",
			logger.NewField("template", templateName),
			logger.NewField("error", err))
		return "", fmt.Errorf("failed to render template %s: %w", templateName, err)
	}

	return buf.String(), nil
}

// setSecurityHeaders 设置安全响应头
// P2-52: 所有错误页面响应添加安全头
func setSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-XSS-Protection", "1; mode=block")
	w.Header().Set("Referrer-Policy", "no-referrer")
}

// RenderResponse 渲染模板并写入HTTP响应
func (r *Renderer) RenderResponse(w http.ResponseWriter, templateName string, statusCode int, data TemplateData) {
	// P2-52: 添加安全响应头
	setSecurityHeaders(w)

	// 设置状态码
	data.StatusCode = statusCode

	// 渲染模板
	html, err := r.Render(templateName, data)
	if err != nil {
		// 如果模板渲染失败，使用预编译的 fallback 模板（自动 HTML 转义）
		r.logger.Error("Template rendering failed, falling back to simple error",
			logger.NewField("template", templateName),
			logger.NewField("error", err))

		var buf bytes.Buffer
		if renderErr := r.fallbackTmpl.Execute(&buf, data); renderErr != nil {
			// 极端情况：fallback 模板也失败，返回纯文本（不含任何用户可控内容）
			r.logger.Error("Fallback template rendering also failed",
				logger.NewField("error", renderErr))
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(statusCode)
			w.Write([]byte("Internal Server Error"))
			return
		}
		fallbackHTML := buf.String()

		// 先设置头部，再调用 WriteHeader
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Length", strconv.Itoa(len(fallbackHTML)))
		w.WriteHeader(statusCode)
		w.Write([]byte(fallbackHTML))
		return
	}

	// 先设置响应头，再调用 WriteHeader，确保头部在响应中生效
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(html)))
	w.WriteHeader(statusCode)
	w.Write([]byte(html))
}

// RenderBlocked 渲染访问被拦截页面
// H40: 传入所有参数到 TemplateData
func (r *Renderer) RenderBlocked(w http.ResponseWriter, traceId, reason, clientIP string) {
	data := TemplateData{
		TraceId:  traceId,
		Reason:   reason,
		ClientIP: clientIP,
	}
	r.RenderResponse(w, "blocked", http.StatusForbidden, data)
}

// RenderUpstreamError 渲染上游服务器错误页面
// H40: 传入所有参数到 TemplateData
func (r *Renderer) RenderUpstreamError(w http.ResponseWriter, traceId, errorMsg, upstreamHost string, statusCode, retryCount, retryAfter int) {
	data := TemplateData{
		TraceId:      traceId,
		Error:        errorMsg,
		UpstreamHost: upstreamHost,
		RetryCount:   retryCount,
		RetryAfter:   retryAfter,
	}
	r.RenderResponse(w, "upstream_error", statusCode, data)
}

// RenderSystemError 渲染系统错误页面
// H40: 传入所有参数到 TemplateData
func (r *Renderer) RenderSystemError(w http.ResponseWriter, traceId, errorType, errorLevel, requestPath, serverInstance string) {
	data := TemplateData{
		TraceId:        traceId,
		ErrorType:      errorType,
		ErrorLevel:     errorLevel,
		RequestPath:    requestPath,
		ServerInstance: serverInstance,
	}
	r.RenderResponse(w, "system_error", http.StatusInternalServerError, data)
}

// ReplaceTemplateVars 替换模板中的变量占位符
func ReplaceTemplateVars(content string, data TemplateData) string {
	replacements := map[string]string{
		"{{StatusCode}}":     fmt.Sprintf("%d", data.StatusCode),
		"{{TraceId}}":        data.TraceId,
		"{{Timestamp}}":      data.Timestamp,
		"{{ClientIP}}":       data.ClientIP,
		"{{RequestPath}}":    data.RequestPath,
		"{{ServerInstance}}": data.ServerInstance,
		"{{Error}}":          data.Error,
		"{{Reason}}":         data.Reason,
		"{{ErrorType}}":      data.ErrorType,
		"{{ErrorLevel}}":     data.ErrorLevel,
		"{{UpstreamHost}}":   data.UpstreamHost,
		"{{RetryCount}}":     fmt.Sprintf("%d", data.RetryCount),
		"{{RetryAfter}}":     fmt.Sprintf("%d", data.RetryAfter),
		"{{SupportEmail}}":   data.SupportEmail,
		"{{SupportPhone}}":   data.SupportPhone,
	}

	result := content
	for placeholder, value := range replacements {
		result = strings.ReplaceAll(result, placeholder, value)
	}

	return result
}
