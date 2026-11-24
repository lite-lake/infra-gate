package netutil

// URL 日志脱敏（F7，内部PRD §4.7）：企业微信 webhook key 整串、
// backend URL 凭据等曾以原文进日志。策略：query 整体替换 ***（而非参数白名单——
// 本仓被日志记录的 URL 排障只需 scheme+host+path，白名单需枚举凭据参数名，
// 漏一个即失效）+ 剥 userinfo + 抹 fragment；解析失败走正则兜底。

import (
	"errors"
	"net/url"
	"regexp"
)

// redactedQueryMarker query 整体替换标记
const redactedQueryMarker = "***"

// sensitiveQueryKeyPattern 兜底正则：常见凭据参数名的值抹除（url.Parse 失败时）
var sensitiveQueryKeyPattern = regexp.MustCompile(`(?i)(key|token|secret|password|passwd|pwd|signature|sign|access_key|apikey|api_key|credential|auth)=([^&\s]+)`)

// RedactURL 返回脱敏后的 URL 字符串：
//   - url.Parse 成功：剥 userinfo（user:pass@host → host）、query 整体替换为 ***、
//     抹 fragment；scheme/host/path 保留（排障所需的最小信息）
//   - url.Parse 失败：正则兜底抹凭据参数值（不做其他改写）
//
// 幂等：对已脱敏 URL 再次调用返回原值（query 已是 ***）。
func RedactURL(raw string) string {
	if raw == "" {
		return raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return sensitiveQueryKeyPattern.ReplaceAllString(raw, "$1="+redactedQueryMarker)
	}
	if u.RawQuery != "" {
		u.RawQuery = redactedQueryMarker
	}
	u.Fragment = ""
	u.ForceQuery = false
	if u.User != nil {
		u.User = nil
	}
	return u.String()
}

// RedactURLError 对 *url.Error 的 URL 字段脱敏并重建（顶层 type 断言，http client
// 返回的错误绝大多数即该形态；Err 字段原样保留 → errors.Is/As 链不受影响）。
// 非 *url.Error 原样返回。
func RedactURLError(err error) error {
	if err == nil {
		return nil
	}
	var ue *url.Error
	if !errors.As(err, &ue) {
		return err
	}
	if ue.URL == "" {
		return err
	}
	return &url.Error{
		Op:  ue.Op,
		URL: RedactURL(ue.URL),
		Err: ue.Err,
	}
}
