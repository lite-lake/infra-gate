package auth

// 保留路径 handler 与拦截决策（内部PRD §6）。
// 302（拦截跳转，改 GET）与 303（登录后重定向，POST 后改 GET）语义区分（PRD §12）。

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/lite-lake/infra-gate/internal/infrastructs/logger"
	"github.com/lite-lake/infra-gate/internal/netutil"
)

const (
	// AuthPathRoot 保留路径根（无斜杠裸路径）：/_gate-auth 自身也是保留路径，
	// 由网关 404 处理，不转发后端（H1 补漏，内部PRD）
	AuthPathRoot = "/_gate-auth"
	// AuthPathPrefix 保留路径前缀（决策 D7）：启用 auth 的 host 上该前缀不再转发后端
	AuthPathPrefix = AuthPathRoot + "/"
	// AuthLoginPath 登录页（GET）+ 登录提交（POST）
	AuthLoginPath = "/_gate-auth/login"
	// AuthLogoutPath 登出（GET）
	AuthLogoutPath = "/_gate-auth/logout"
	// AuthCookieName 会话 cookie 名，独特前缀避免与业务应用 cookie 碰撞（决策 D7）
	AuthCookieName = "ltgate_auth"
)

// 登录页 error 参数取值（PRD §6.1）
const (
	errorParamWrongPassword = "1"    // 密码错误
	errorParamRateLimited   = "rate" // 尝试过于频繁
)

// serveReserved 分发保留路径；未知保留路径 404，一律不转发后端
func (m *Manager) serveReserved(w http.ResponseWriter, r *http.Request) {
	m.setGateHeaders(w, r)
	switch r.URL.Path {
	case AuthLoginPath:
		switch r.Method {
		case http.MethodGet, http.MethodHead:
			m.serveLoginPage(w, r)
		case http.MethodPost:
			m.handleLogin(w, r)
		default:
			w.Header().Set("Allow", "GET, POST")
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		}
	case AuthLogoutPath:
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET")
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		m.handleLogout(w, r)
	default:
		http.NotFound(w, r)
	}
}

// serveLoginPage 登录页（PRD §6.1）：无会话渲染内嵌页面；已持有效会话 303 回
// next，避免已登录者反复看到登录页。
func (m *Manager) serveLoginPage(w http.ResponseWriter, r *http.Request) {
	next := sanitizeNext(r.URL.Query().Get("next"))
	if m.validSession(r) {
		http.Redirect(w, r, next, http.StatusSeeOther)
		return
	}
	data := loginPageData{Action: AuthLoginPath, Next: next}
	switch r.URL.Query().Get("error") {
	case errorParamWrongPassword:
		data.Error = true
		data.ErrorText = "密码错误，请重试"
	case errorParamRateLimited:
		data.Error = true
		data.ErrorText = "尝试过于频繁，请稍后再试"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	// 显式写 200：gin 无路由链的 serveError 会预先把 status 置为 404，本页是
	// 网关自响应中唯一隐式写 body 的 200 路径，不显式声明会以 404 状态发出
	w.WriteHeader(http.StatusOK)
	if err := renderLoginPage(w, data); err != nil {
		// 模板写入失败（客户端断开等）：仅记日志，响应已部分写出无法补救
		m.log.Error("Auth login page render failed",
			logger.NewField("host", m.hostName),
			logger.NewField("error", err))
	}
}

// maxLoginBodyBytes 登录提交请求体上限（M1，内部PRD）：64KB，
// 远超正常 password+next 表单所需，防未认证端点被超大 body 打内存
const maxLoginBodyBytes = 64 * 1024

// loginBudgetKey 登录全局预算令牌桶的固定键（桶是 per-host 单例，键仅占位）
const loginBudgetKey = "login"

// handleLogin 登录提交（PRD §6.2）。检查顺序（M1，内部PRD）：
// F2.3 全局预算（最前，不读 body）→ 锁定检查（双维度，M1）→ MaxBytesReader
// 限幅 → ParseForm。
func (m *Manager) handleLogin(w http.ResponseWriter, r *http.Request) {
	// F2.3（内部PRD §4.2.3）：登录端点全局预算限速——per-host 令牌桶、
	// 所有来源共享，公网 IPv6 轮换绕过 per-IP 键时的统一兜底。最前（锁定检查
	// 之前、不读 body）；超预算 429 + Retry-After（区别于锁定的 303 跳转：
	// 预算是容量保护不是惩罚，客户端应显式退避）
	if m.loginBudget != nil && !m.loginBudget.Allow(loginBudgetKey, time.Now()) {
		w.Header().Set("Retry-After", "1")
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		return
	}

	// M1：锁定检查前移——锁定 IP 的请求体一律不读、不解析，未认证端点不为
	// 恶意大 body 付出内存（审计 M1：ParseForm 无上限且先于锁定检查 → 内存 DoS）
	// M3：键口径改解析后真实客户端 IP（见 clientIPForAuth）；锁定检查仍先于读 body
	// F2.2：双维度锁定——解析后 IP 维度（原语义）+ 直连对端维度（仅 resolved ≠
	// direct 即确实经 XFF 解析时生效，封堵伪 XFF 轮换）
	clientIP := m.clientIPForAuth(r)
	directIP := netutil.DirectRemoteIP(r)
	peerKey := ""
	if clientIP != directIP {
		peerKey = "peer:" + directIP
	}
	now := time.Now()
	if m.limiter.IsLocked(clientIP, now) || (peerKey != "" && m.peerLimiter.IsLocked(peerKey, now)) {
		// 锁定中：统一 rate 提示，不暴露"密码是否正确"（PRD §6.2）；
		// next 仅取 URL query（body 未读，POST form 不可用）
		next := sanitizeNext(r.URL.Query().Get("next"))
		http.Redirect(w, r, loginURL(next, errorParamRateLimited), http.StatusSeeOther)
		return
	}

	// M1：登录体上限 64KB，先包 MaxBytesReader 再 ParseForm，超限 413 快速失败
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodyBytes)
	if err := r.ParseForm(); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			http.Error(w, "Request Entity Too Large", http.StatusRequestEntityTooLarge)
			return
		}
		// 请求体非法：回登录页（不带错误参数，不算密码失败）
		http.Redirect(w, r, AuthLoginPath, http.StatusSeeOther)
		return
	}
	password := r.PostFormValue("password")
	next := sanitizeNext(r.FormValue("next"))

	// 常数时间比较防时序侧信道（PRD §8.1）
	if subtle.ConstantTimeCompare([]byte(password), []byte(m.password)) == 1 {
		m.limiter.Reset(clientIP)
		if peerKey != "" {
			m.peerLimiter.Reset(peerKey)
		}
		http.SetCookie(w, &http.Cookie{
			Name:     AuthCookieName,
			Value:    IssueToken(m.key, m.hostName, now, m.ttl),
			Path:     "/",
			MaxAge:   int(m.ttl / time.Second),
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			Secure:   r.TLS != nil, // HTTPS 带 Secure，HTTP 不带（决策 D3）
		})
		http.Redirect(w, r, next, http.StatusSeeOther)
		return
	}

	failures, locked := m.limiter.RecordFailure(clientIP, now)
	m.log.Warn("Auth login failed",
		logger.NewField("host", m.hostName),
		logger.NewField("client_ip", clientIP),
		logger.NewField("peer_key", peerKey),
		logger.NewField("failures", failures),
		logger.NewField("locked", locked))
	// M3（内部PRD §5）：IP 触发锁定阈值 → 全局告警一条（跳变沿去重见
	// notifyLockout 注释）；未触发跳变沿时 no-op
	if locked {
		m.notifyLockout(clientIP, failures)
	}
	// F2.2：直连对端维度同步计数与告警（resolved ≠ direct 时；阈值独立，
	// 缺省 max_failures×10）
	if peerKey != "" {
		peerFailures, peerLocked := m.peerLimiter.RecordFailure(peerKey, now)
		if peerLocked {
			m.notifyLockout(peerKey, peerFailures)
		}
	}
	http.Redirect(w, r, loginURL(next, errorParamWrongPassword), http.StatusSeeOther)
}

// handleLogout 登出（PRD §6.3）：清 cookie 回登录页
func (m *Manager) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     AuthCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1, // 输出 Max-Age=0，浏览器立即删除 cookie
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil,
	})
	http.Redirect(w, r, AuthLoginPath, http.StatusSeeOther)
}

// intercept 未认证拦截（PRD §6.4）：浏览器导航（Accept 含 text/html）302 登录页
// （带 next 原路径+query 回跳）；API/XHR/WS 升级 401 不升级。
func (m *Manager) intercept(w http.ResponseWriter, r *http.Request) {
	m.setGateHeaders(w, r)
	if isBrowserNavigation(r) {
		http.Redirect(w, r, loginURL(r.URL.RequestURI(), ""), http.StatusFound)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte("401 Unauthorized: password required (visit /_gate-auth/login)"))
}

// setGateHeaders 网关自响应安全头（对齐 processRequest 的 gateHeaders，PRD §8.1）。
// 登录页为单文件内联样式/脚本，CSP 相应允许 inline、拒绝一切外部资源与嵌入。
// HSTS 不在此设置：server.handleRequestForPort 已在 auth 检查点之前统一单点写入
// per-host 值（内部总体方案 W3-2），本函数与拦截页/登录页响应共用同一
// gin ResponseWriter 头表，自然继承。
func (m *Manager) setGateHeaders(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'self'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
}

// isBrowserNavigation 浏览器导航判定：Accept 头含 text/html（PRD §6.4）
func isBrowserNavigation(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

// sanitizeNext 校验回跳路径（PRD §8.1 Open redirect 对策）：仅接受以 / 开头且
// 非 //、/\ 开头的本站相对路径，否则回退 /。
// F4（内部PRD §4.4）：含任何 C0 控制字符（0x00-0x1F）或 0x7F 一律回退 /——
// `next=/\t/evil.com` 类控制字符可让部分客户端（curl/旧浏览器）的 URL 解析把
// 控制字符后的内容当 authority，绕过「以 / 开头」前缀检查实现开放重定向（已实测
// 复现）。零误杀论证：合法 next 是网关自身写入的已编码形态（RequestURI +
// QueryEscape），解码后不含控制字符；含真实控制字符的 next 只能是攻击者手工
// 单层编码注入。不做「剔除后重定向」（需永久追踪浏览器 WHATWG 预处理语义）。
func sanitizeNext(next string) string {
	if next == "" || !strings.HasPrefix(next, "/") ||
		strings.HasPrefix(next, "//") || strings.HasPrefix(next, "/\\") ||
		hasControlChar(next) {
		return "/"
	}
	return next
}

// hasControlChar 判断字符串是否含 ASCII 控制字符（\x00-\x1f、\x7f）。
// 与 server 包 server.go 同名函数同实现（server import auth，反向引用成环，
// 故复制；修改时两处同步）。
func hasControlChar(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] <= 0x1f || s[i] == 0x7f {
			return true
		}
	}
	return false
}

// loginURL 拼登录页地址：?next=<回跳>[&error=<错误码>]
func loginURL(next, errCode string) string {
	u := AuthLoginPath + "?next=" + url.QueryEscape(next)
	if errCode != "" {
		u += "&error=" + errCode
	}
	return u
}
