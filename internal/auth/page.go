package auth

// 内嵌登录页（内部PRD §4.3）：go:embed 编译进二进制，部署产物零附带文件。
// html/template 仅注入动态值（next/error/提交地址），静态部分保持内嵌字符串，
// 注入值自动转义防 XSS；页面无任何外部 CDN/字体/图片。

import (
	"embed"
	"html/template"
	"io"
)

//go:embed page.html
var loginPageFS embed.FS

// loginTmpl 启动时预解析一次；解析失败在包初始化阶段 panic（模板属于构建期资产）
var loginTmpl = template.Must(template.ParseFS(loginPageFS, "page.html"))

// loginPageData 登录页模板数据
type loginPageData struct {
	Action    string // form 提交地址（保留路径 login）
	Next      string // 登录成功后回跳路径（hidden input）
	Error     bool   // 是否为错误态（服务端渲染错误提示）
	ErrorText string // 错误提示文案
}

func renderLoginPage(w io.Writer, data loginPageData) error {
	return loginTmpl.Execute(w, data)
}
