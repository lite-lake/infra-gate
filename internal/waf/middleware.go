package waf

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/corazawaf/coraza/v3"
	corazahttp "github.com/corazawaf/coraza/v3/http"
	"github.com/corazawaf/coraza/v3/types"

	"github.com/lite-lake/infra-gate/internal/config"
	"github.com/lite-lake/infra-gate/internal/crs"
	"github.com/lite-lake/infra-gate/internal/infrastructs/logger"
	"github.com/lite-lake/infra-gate/internal/netutil"
	"github.com/lite-lake/infra-gate/internal/templates"
	"github.com/lite-lake/infra-gate/internal/trace"
)

// 请求体捕获的最大字节数
const maxRequestBodyLen = 4096

// ErrWAFDegraded 降级哨兵错误：CRS 不可用且 failure_policy=degrade，本次 WAF 不构造，
// 对应 host 无 WAF 启动（流量无 WAF 防护，由 server 层跳过实例创建并发高优告警）。
// 调用方必须用 errors.Is 识别，与其他 WAF 构造失败（fail 语义）区分。
var ErrWAFDegraded = errors.New("waf degraded: CRS unavailable (failure_policy=degrade)")

// ruleMatchDetailKey 用于在 request context 中传递 per-request 的规则匹配状态
type ruleMatchDetailKey struct{}

// requestRuleMatch 存储单个请求的规则匹配状态
type requestRuleMatch struct {
	matched bool
	details []RuleMatchDetail // collects all matched rules; last one is the "primary" for backwards compat
}

// lastDetail returns the most recent matched rule detail, or empty if none
func (rm *requestRuleMatch) lastDetail() RuleMatchDetail {
	if len(rm.details) == 0 {
		return RuleMatchDetail{}
	}
	return rm.details[len(rm.details)-1]
}

// Middleware WAF中间件
type Middleware struct {
	waf            coraza.WAF
	logger         logger.ILogger
	whitelist      *Checker
	wafEnabled     bool
	mode           string
	renderer       *templates.Renderer
	trustedProxies []*net.IPNet
	stats          *statsTracker
}

// NewMiddleware 创建WAF中间件
func NewMiddleware(waf coraza.WAF, whitelist *Checker, wafEnabled bool, mode string, log logger.ILogger, renderer *templates.Renderer, trustedProxies []string, stats *statsTracker) *Middleware {
	if stats == nil {
		stats = newStatsTracker()
	}
	return &Middleware{
		waf:            waf,
		logger:         log,
		whitelist:      whitelist,
		wafEnabled:     wafEnabled,
		mode:           mode,
		renderer:       renderer,
		trustedProxies: netutil.ParseTrustedProxies(trustedProxies),
		stats:          stats,
	}
}

// GetStats 返回 WAF 拦截统计快照
func (m *Middleware) GetStats() StatsSnapshot {
	if m.stats == nil {
		return StatsSnapshot{}
	}
	return m.stats.snapshot()
}

// GetEvents 返回最近的 WAF 事件列表（阻断 + 检测）
func (m *Middleware) GetEvents(limit int) []WAFEvent {
	if m.stats == nil {
		return []WAFEvent{}
	}
	return m.stats.recentEvents(limit)
}

// FindEvent 按 ID 查找单个事件
func (m *Middleware) FindEvent(id int64) (WAFEvent, bool) {
	if m.stats == nil {
		return WAFEvent{}, false
	}
	return m.stats.findEvent(id)
}

// WrapHandler 将WAF包装到Gin处理器，hostName 用于统计区分虚拟主机
func (m *Middleware) WrapHandler(handler http.Handler, hostName string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 获取或生成TraceId
		traceId := trace.GetTraceIdFromRequest(r)
		if traceId == "" {
			traceId = trace.GenerateTraceId()
			// 将生成的TraceId添加到请求头中，以便后续处理使用
			r.Header.Set(trace.TraceIdHeader, traceId)
		}
		loggerWithTrace := m.logger
		if traceId != "" {
			loggerWithTrace = m.logger.WithTraceId(traceId)
		}

		// 如果WAF被禁用，直接转发请求
		if !m.wafEnabled {
			loggerWithTrace.Debug("WAF is disabled, bypassing all checks")
			handler.ServeHTTP(w, r)
			return
		}

		// 检查客户端IP是否在白名单中（F2.4，内部PRD §4.2.4 决策 D4：改**直连对端**口径
		// ——语义变为「边缘连接 ACL」（谁能连到网关），与 allowed_ips/admin 同口径；
		// trusted_proxies 内伪造 XFF 无法命中（解析后 IP 口径可被链内伪造就地绕过，
		// 现网 whitelist 全关是零迁移成本窗口）。统计/事件的 client_ip 仍为解析后口径
		//（下方 getClientIP）。命中日志 Info→Warn（跳过 WAF 是高权动作））
		whitelistIP := netutil.DirectRemoteIP(r)
		if m.whitelist != nil && m.whitelist.IsWhitelisted(whitelistIP) {
			loggerWithTrace.Warn("Request from whitelisted direct peer, bypassing WAF checks",
				logger.NewField("direct_peer_ip", whitelistIP),
				logger.NewField("path", r.URL.Path),
				logger.NewField("method", r.Method))
			handler.ServeHTTP(w, r)
			return
		}
		clientIP := m.getClientIP(r)

		// 记录经过 WAF 检查的请求数（白名单请求不计入）
		if m.stats != nil {
			m.stats.recordRequest(hostName)
		}

		// 捕获请求快照（仅用于事件记录，非命中时无额外开销）
		reqSnapshot := captureRequestSnapshot(r, traceId, hostName)

		// 创建 per-request 的规则匹配状态，通过 context 传递给 ErrorCallback
		reqMatch := &requestRuleMatch{}
		ctx := context.WithValue(r.Context(), ruleMatchDetailKey{}, reqMatch)
		r = r.WithContext(ctx)

		// 创建一个包装的ResponseWriter来捕获WAF拦截
		wrappedWriter := &intercept403Writer{
			ResponseWriter: w,
			traceId:        traceId,
			renderer:       m.renderer,
			logger:         loggerWithTrace,
			clientIP:       clientIP,
			path:           r.URL.Path,
			method:         r.Method,
			hostName:       hostName,
			mode:           m.mode,
			stats:          m.stats,
			reqSnapshot:    reqSnapshot,
			reqMatch:       reqMatch,
		}

		// Use Coraza's HTTP wrapper
		// Note: r.RemoteAddr is NOT rewritten to clientIP here. Rewriting it caused
		// downstream proxy's XFF chain logic to produce duplicate entries (e.g.
		// "X-Forwarded-For: 1.2.3.4, 1.2.3.4") because proxy saw the resolved real
		// client IP as the direct connection IP instead of the trusted proxy IP.
		// Coraza's REMOTE_ADDR will be the TCP connection IP (trusted proxy), which
		// is acceptable — application-layer whitelist already resolves the real IP
		// via getClientIP using the XFF chain.
		wafHandler := corazahttp.WrapHandler(m.waf, handler)
		wafHandler.ServeHTTP(wrappedWriter, r)

		// 在检测模式下，Coraza 不会阻断请求（不产生 403），但 ErrorCallback 仍会触发
		// 如果规则匹配了且请求未被阻断（非 403），则记录为检测事件
		if m.stats != nil {
			if reqMatch.matched && !wrappedWriter.wrote403 {
				m.stats.recordDetect(hostName, clientIP, r.Method, r.URL.Path)

				ev := m.buildEvent(EventTypeDetect, hostName, clientIP, r, reqMatch.lastDetail(), reqSnapshot, 0)
				m.stats.recordEvent(ev)
			}
		}
	})
}

// buildEvent 构建 WAFEvent，填充所有详情字段
func (m *Middleware) buildEvent(evType EventType, hostName, clientIP string, r *http.Request, detail RuleMatchDetail, snap RequestSnapshot, responseCode int) WAFEvent {
	ev := WAFEvent{
		ID:             m.stats.nextEventID(),
		Time:           time.Now(),
		Type:           evType,
		ClientIP:       clientIP,
		Method:         r.Method,
		Path:           r.URL.Path,
		HostName:       hostName,
		RuleID:         detail.RuleID,
		Message:        detail.Message,
		Severity:       detail.Severity,
		TraceID:        snap.TraceID,
		MatchedVars:    detail.MatchedVars,
		RuleTags:       detail.RuleTags,
		RuleOperator:   detail.RuleOperator,
		RuleFile:       detail.RuleFile,
		RuleLine:       detail.RuleLine,
		ReqHeaders:     snap.Headers,
		ReqBody:        snap.Body,
		ReqContentType: snap.ContentType,
		QueryString:    snap.QueryString,
		Protocol:       snap.Protocol,
		ResponseCode:   responseCode,
	}

	return ev
}

// sensitiveHeaderKeys 是可能包含敏感信息的请求头，记录事件时需要脱敏
var sensitiveHeaderKeys = map[string]bool{
	"authorization":       true,
	"cookie":              true,
	"set-cookie":          true,
	"x-api-key":           true,
	"x-auth-token":        true,
	"x-csrf-token":        true,
	"x-xsrf-token":        true,
	"proxy-authorization": true,
}

// sanitizeHeaderValue 脱敏敏感头值，只保留前几个字符
func sanitizeHeaderValue(key string, value string) string {
	if sensitiveHeaderKeys[strings.ToLower(key)] {
		if len(value) > 8 {
			return value[:4] + "****"
		}
		return "****"
	}
	return value
}

// captureRequestSnapshot 捕获请求快照用于事件记录
// 仅在 WAF 命中规则时写入事件，非命中请求的快照会被丢弃
// P2-27: 对敏感请求头和请求体进行脱敏，防止泄露密码/Token/PII
func captureRequestSnapshot(r *http.Request, traceId, hostName string) RequestSnapshot {
	headers := make(map[string]string)
	for k, v := range r.Header {
		if len(v) > 0 {
			headers[k] = truncateString(sanitizeHeaderValue(k, v[0]), maxValueLen)
		}
	}

	var body string
	if r.Body != nil {
		bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBodyLen))
		if err != nil {
			// P2-28: body 读取错误时恢复 r.Body，避免下游收到不完整 body
			// 将已读取的部分和原始 Body 串联，确保下游可以继续读取
			r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(bodyBytes), r.Body))
		} else if len(bodyBytes) > 0 {
			body = truncateString(string(bodyBytes), maxRequestBodyLen)
			// Restore body for downstream handlers: concatenate read and unread parts
			r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(bodyBytes), r.Body))
		}
	}

	return RequestSnapshot{
		Headers:     headers,
		Body:        body,
		ContentType: r.Header.Get("Content-Type"),
		QueryString: r.URL.RawQuery,
		Protocol:    r.Proto,
		Host:        hostName,
		TraceID:     traceId,
	}
}

// intercept403Writer 只拦截403响应的ResponseWriter
type intercept403Writer struct {
	http.ResponseWriter
	traceId     string
	renderer    *templates.Renderer
	logger      logger.ILogger
	clientIP    string
	path        string
	method      string
	hostName    string
	mode        string
	stats       *statsTracker
	wrote403    bool
	reqSnapshot RequestSnapshot
	reqMatch    *requestRuleMatch
}

func (w *intercept403Writer) WriteHeader(code int) {
	if code == http.StatusForbidden && !w.wrote403 {
		// Only treat as WAF block when:
		// 1. A WAF rule matched (reqMatch.matched == true), AND
		// 2. We are in block mode (detect mode never intercepts, even if rules matched)
		isWAFBlocked := w.mode != config.WAFModeDetect && w.reqMatch != nil && w.reqMatch.matched
		if !isWAFBlocked {
			// Backend's own 403 or detect mode — pass through, do not record as WAF event
			w.ResponseWriter.WriteHeader(code)
			return
		}

		w.wrote403 = true
		// Display custom WAF block page
		reason := "WAF规则拦截"
		w.logger.Warn("Request blocked by WAF",
			logger.NewField("client_ip", w.clientIP),
			logger.NewField("path", w.path),
			logger.NewField("method", w.method))

		// Record block statistics and event
		if w.stats != nil {
			blockDetail := w.reqMatch.lastDetail()
			// P2-31: 原子更新 block 统计和 last block 信息，避免快照不一致
			w.stats.recordBlockWithDetail(w.hostName, w.clientIP, w.method, w.path, blockDetail)

			detail := blockDetail
			ev := WAFEvent{
				ID:             w.stats.nextEventID(),
				Time:           time.Now(),
				Type:           EventTypeBlock,
				ClientIP:       w.clientIP,
				Method:         w.method,
				Path:           w.path,
				HostName:       w.hostName,
				RuleID:         detail.RuleID,
				Message:        detail.Message,
				Severity:       detail.Severity,
				TraceID:        w.reqSnapshot.TraceID,
				MatchedVars:    detail.MatchedVars,
				RuleTags:       detail.RuleTags,
				RuleOperator:   detail.RuleOperator,
				RuleFile:       detail.RuleFile,
				RuleLine:       detail.RuleLine,
				ReqHeaders:     w.reqSnapshot.Headers,
				ReqBody:        w.reqSnapshot.Body,
				ReqContentType: w.reqSnapshot.ContentType,
				QueryString:    w.reqSnapshot.QueryString,
				Protocol:       w.reqSnapshot.Protocol,
				ResponseCode:   http.StatusForbidden,
			}
			w.stats.recordEvent(ev)
		}

		// 确保TraceId被添加到响应头
		if w.traceId != "" {
			w.ResponseWriter.Header().Set("X-Lite-Gate-Trace-Id", w.traceId)
		}

		// 清除可能由 Coraza interceptor 设置的 Content-Length: 0
		// 否则 Go HTTP 服务器会截断写入的 body 为 0 字节，导致拦截页面丢失
		w.ResponseWriter.Header().Del("Content-Length")

		if w.renderer != nil {
			w.renderer.RenderBlocked(w.ResponseWriter, w.traceId, reason, w.clientIP)
		} else {
			w.ResponseWriter.WriteHeader(http.StatusForbidden)
			w.ResponseWriter.Write([]byte("Access Denied"))
		}
		return
	}
	// 对于其他状态码，直接传递
	w.ResponseWriter.WriteHeader(code)
}

// Hijack 实现http.Hijacker接口，将Hijack调用委托给底层ResponseWriter
// 这对于WebSocket升级请求是必需的，使Coraza的hijackerTracker能正确工作
func (w *intercept403Writer) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hijacker, ok := w.ResponseWriter.(http.Hijacker); ok {
		return hijacker.Hijack()
	}
	return nil, nil, errors.New("hijacking not supported")
}

// Flush 实现http.Flusher接口，将Flush调用委托给底层ResponseWriter
func (w *intercept403Writer) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

// LogError WAF错误日志回调
func (m *Middleware) LogError(matchedRule types.MatchedRule) {
	msg := matchedRule.ErrorLog()
	m.logger.Warn("WAF Rule Matched",
		logger.NewField("severity", matchedRule.Rule().Severity()),
		logger.NewField("rule_id", matchedRule.Rule().ID()),
		logger.NewField("message", msg))
}

// getClientIP 获取客户端真实IP地址
func (m *Middleware) getClientIP(r *http.Request) string {
	return netutil.ResolveClientIP(r, m.trustedProxies)
}

// CreateWAF 创建WAF实例，返回 WAF 实例和统计追踪器
func CreateWAF(wafConfig config.WAFConfig, log logger.ILogger) (coraza.WAF, *statsTracker, error) {
	stats := newStatsTracker()

	wafBuilder := coraza.NewWAFConfig().
		WithErrorCallback(func(matchedRule types.MatchedRule) {
			msg := matchedRule.ErrorLog()
			log.Warn("WAF Rule Matched",
				logger.NewField("severity", matchedRule.Rule().Severity()),
				logger.NewField("rule_id", matchedRule.Rule().ID()),
				logger.NewField("message", msg))

			// 提取完整的规则匹配详情
			var matchedVars []MatchedVar
			for _, md := range matchedRule.MatchedDatas() {
				matchedVars = append(matchedVars, MatchedVar{
					Variable: md.Variable().Name(),
					Key:      md.Key(),
					Value:    truncateString(md.Value(), maxValueLen),
					Message:  truncateString(md.Message(), maxValueLen),
					Data:     truncateString(md.Data(), maxValueLen),
				})
			}

			rule := matchedRule.Rule()
			detail := RuleMatchDetail{
				RuleID:       rule.ID(),
				Message:      msg,
				Severity:     rule.Severity().String(),
				AuditLog:     truncateString(matchedRule.AuditLog(), maxValueLen*4),
				MatchedVars:  matchedVars,
				RuleTags:     rule.Tags(),
				RuleOperator: rule.Operator(),
				RuleFile:     rule.File(),
				RuleLine:     rule.Line(),
			}

			// 写入 per-request 的标记（通过 MatchedRule 内部类型获取请求上下文）
			if ctxGetter, ok := matchedRule.(interface{ Context() context.Context }); ok {
				if ctx := ctxGetter.Context(); ctx != nil {
					if val := ctx.Value(ruleMatchDetailKey{}); val != nil {
						reqMatch := val.(*requestRuleMatch)
						reqMatch.matched = true
						reqMatch.details = append(reqMatch.details, detail)
					}
				}
			} else {
				// 类型断言失败时记录警告，避免静默降级到无防护状态
				log.Warn("WAF rule matched but failed to access request context, rule details may not be propagated",
					logger.NewField("rule_id", rule.ID()),
					logger.NewField("message", msg))
			}

			// Write to global stats tracker (for StatsSnapshot last block info)
			stats.recordRuleMatchDetail(detail)
		})

	// 显式启用请求体检查，避免仅在 CRS 文件中依赖 SecRequestBodyAccess On 时的静默失效
	// 当 crs.enabled=false 仅使用自定义规则时，phase 2 body 规则才能正常工作
	//
	// 可通过 waf.request_body_access=false（全局或 per-host）跳过请求体扫描：
	// CAJ/PDF 等二进制上传的随机字节会触发 CRS 大量正则匹配，扫描 ~1MB 可达数十秒，
	// 上传类流量应由应用层处理而非 WAF 扫描。跳过 body 扫描时仅检查头部与查询串。
	//
	// 请求体大小限制（防止文件上传等大 body 导致 WAF 内存爆炸）：
	// - SecRequestBodyLimit: 整个请求体的最大检测大小，超过则拒绝（413）
	// - SecRequestBodyNoFilesLimit: multipart 中非文件部分（文本字段）的大小上限
	// - SecRequestBodyInMemoryLimit: 请求体在内存中缓冲的上限，超出部分写磁盘临时文件
	if wafConfig.GetRequestBodyAccess() {
		wafBuilder = wafBuilder.WithDirectives(`
			SecRequestBodyAccess On
			SecRequestBodyLimit 1048576
			SecRequestBodyNoFilesLimit 1048576
			SecRequestBodyInMemoryLimit 1048576
		`)
		log.Info("WAF request body inspection enabled")
	} else {
		wafBuilder = wafBuilder.WithDirectives("SecRequestBodyAccess Off")
		log.Info("WAF request body inspection disabled (request_body_access=false)")
	}

	// 如果启用CRS，先加载CRS规则
	// EnsureCRS 返回富结果（内部PRD §5.1）：
	//   - degraded 哨兵（failure_policy=degrade 且无任何可用 CRS）→ 返回包装后的
	//     ErrWAFDegraded，不构造 WAF，由 server 层跳过该配置实例；
	//   - stale（旧缓存哈希不一致但保留可用）→ 正常用旧缓存规则构造，日志 WARN；
	//   - 其他错误（fail 语义）→ 维持原行为：返回错误使 NewServer 失败。
	if wafConfig.CRS.Enabled {
		crsManager := crs.NewManager("./cache", log, &wafConfig.CRS)
		res := crsManager.EnsureCRS(wafConfig.CRS.Version)
		if res.Err != nil {
			if errors.Is(res.Err, crs.ErrCRSDegraded) {
				log.Error("CRS unavailable, WAF not created for this config (degrade policy)",
					logger.NewField("version", wafConfig.CRS.Version),
					logger.NewField("error", res.Err.Error()))
				return nil, nil, fmt.Errorf("%w: %v", ErrWAFDegraded, res.Err)
			}
			return nil, nil, fmt.Errorf("failed to ensure CRS: %w", res.Err)
		}
		if res.State == crs.StateStale {
			log.Warn("Starting WAF with stale CRS cache, rules may be outdated",
				logger.NewField("version", wafConfig.CRS.Version),
				logger.NewField("path", res.Dir))
		}
		crsDir := res.Dir

		crsFiles, err := crsManager.GetCRSConfigFiles(crsDir)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get CRS config files: %w", err)
		}

		// 加载CRS配置文件
		for _, file := range crsFiles {
			wafBuilder = wafBuilder.WithDirectivesFromFile(file)
			log.Info("Loaded CRS config file", logger.NewField("file", file))
		}

		log.Info("OWASP CRS enabled",
			logger.NewField("version", wafConfig.CRS.Version),
			logger.NewField("source", res.Source),
			logger.NewField("rules_count", len(crsFiles)))
	}

	// 如果启用自定义规则，加载自定义规则文件
	if wafConfig.Custom.Enabled && wafConfig.Custom.RulesFile != "" {
		wafBuilder = wafBuilder.WithDirectivesFromFile(wafConfig.Custom.RulesFile)
		log.Info("Loaded custom rules file", logger.NewField("file", wafConfig.Custom.RulesFile))
	}

	// 根据运行模式设置 SecRuleEngine（必须在 CRS 和自定义规则加载之后，避免被 CRS 中的 SecRuleEngine On 覆盖）
	// block（默认）：SecRuleEngine On，命中规则时阻断请求（返回 403）
	// detect：SecRuleEngine DetectionOnly，命中规则时仅记录，不阻断
	// disabled：不应走到此处（server.go 在创建实例前已跳过 disabled 主机），此处做防御性兜底
	switch wafConfig.DefaultMode {
	case config.WAFModeDetect:
		wafBuilder = wafBuilder.WithDirectives("SecRuleEngine DetectionOnly")
		log.Info("WAF running in detection-only mode")
	case config.WAFModeDisabled:
		log.Warn("WAF mode is disabled but instance creation was not skipped, defaulting to block")
		wafBuilder = wafBuilder.WithDirectives("SecRuleEngine On")
	case config.WAFModeBlock, "":
		wafBuilder = wafBuilder.WithDirectives("SecRuleEngine On")
	default:
		wafBuilder = wafBuilder.WithDirectives("SecRuleEngine On")
	}

	// Debug 配置处理
	// 当配置了 debug.log_level > 0 时，通过 SecDebugLog 指令将 WAF 调试日志输出到指定文件
	// 这样管理员可以在排查 WAF 拦截问题时获取规则评估路径和变量快照
	if wafConfig.Debug.LogLevel > 0 {
		debugDirective := fmt.Sprintf("SecDebugLogLevel %d", wafConfig.Debug.LogLevel)
		if wafConfig.Debug.LogFile != "" {
			debugDirective = fmt.Sprintf("SecDebugLog %s\nSecDebugLogLevel %d", wafConfig.Debug.LogFile, wafConfig.Debug.LogLevel)
		}
		wafBuilder = wafBuilder.WithDirectives(debugDirective)
		log.Info("WAF debug logging enabled",
			logger.NewField("log_level", wafConfig.Debug.LogLevel),
			logger.NewField("log_file", wafConfig.Debug.LogFile))
	}

	waf, err := coraza.NewWAF(wafBuilder)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create WAF: %w", err)
	}

	return waf, stats, nil
}
