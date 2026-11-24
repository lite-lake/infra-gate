package waf

// F8 WAF 事件请求体脱敏（内部PRD §4.8）：
// 拦截的明文密码等可经 admin API 读取事件原文——脱敏延迟到事件落库时
//（stats.recordEvent 单点漏斗），99.99% 未命中请求零新增开销。
//
// 策略（按 Content-Type 分派）：
//   - urlencoded / JSON：按 sensitiveBodyKeys 掩码为 ***（JSON 递归，深度上限
//     64、UseNumber 保大数；**不含裸 key**——误伤率过高）
//   - multipart：文件 part 只留 name/filename/size 摘要，值 part 同键掩码
//   - 解析失败（含 >4KB 截断导致的半截 JSON）：正则 scrub 回退
//   - 其他 Content-Type：维持原文（快照层已截断）

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// maskedValue 敏感值统一替换标记（与 sensitiveHeaderKeys 掩码形态一致）
const maskedValue = "***"

// sensitiveBodyKeys 敏感键名单（小写比较；不含裸 key，误伤率过高——D12 同款
// 硬编码不进配置，与 sensitiveHeaderKeys 同为代码常量）
var sensitiveBodyKeys = map[string]bool{
	"password": true, "passwd": true, "pwd": true, "pass": true,
	"secret": true, "client_secret": true,
	"token": true, "access_token": true, "refresh_token": true, "id_token": true,
	"api_key": true, "apikey": true, "access_key": true, "private_key": true,
	"authorization": true, "credentials": true,
}

// isSensitiveBodyKey 大小写不敏感判定（容忍 "user[password]" 类嵌套表单键）
func isSensitiveBodyKey(key string) bool {
	lower := strings.ToLower(key)
	if sensitiveBodyKeys[lower] {
		return true
	}
	// 嵌套表单键 user[password] / user[credentials][token]
	for k := range sensitiveBodyKeys {
		if strings.Contains(lower, "["+k+"]") {
			return true
		}
	}
	return false
}

// scrubPattern 正则兜底：JSON 形态 "key":"value" 与表单形态 key=value 的敏感值抹除
var scrubPattern = regexp.MustCompile(`(?i)("?(?:password|passwd|pwd|pass|secret|client_secret|token|access_token|refresh_token|id_token|api_key|apikey|access_key|private_key|authorization|credentials)"?\s*[:=]\s*)("[^"]*"|[^&"\s,}]+)`)

// scrubSensitiveBody 正则兜底脱敏（解析失败/未知形态时）
func scrubSensitiveBody(body string) string {
	return scrubPattern.ReplaceAllString(body, "$1"+maskedValue)
}

// SanitizeRequestBody 按 Content-Type 脱敏请求体原文（事件落库前调用）。
// 任何解析失败都回落 scrubSensitiveBody，绝不因脱敏失败外抛原文。
func SanitizeRequestBody(body, contentType string) string {
	if body == "" {
		return body
	}
	mediaType := strings.ToLower(strings.TrimSpace(contentType))
	// charset 等参数剥离
	if i := strings.IndexByte(mediaType, ';'); i >= 0 && !strings.Contains(mediaType[:i], "multipart/") {
		mediaType = strings.TrimSpace(mediaType[:i])
	}

	switch {
	case strings.Contains(mediaType, "application/x-www-form-urlencoded"):
		return maskURLEncodedBody(body)
	case strings.Contains(mediaType, "application/json"):
		return maskJSONBody(body)
	case strings.Contains(mediaType, "multipart/form-data"):
		return maskMultipartBody(body, contentType)
	default:
		// 其他 Content-Type 维持原文（快照层已截断；XML/SOAP 等结构里
		// 敏感键形态不可枚举，原文排障价值大于掩码收益）
		return body
	}
}

// maskURLEncodedBody urlencoded 表单键值掩码
func maskURLEncodedBody(body string) string {
	values, err := url.ParseQuery(body)
	if err != nil {
		return scrubSensitiveBody(body)
	}
	for key := range values {
		if isSensitiveBodyKey(key) {
			values[key] = []string{maskedValue}
		}
	}
	return values.Encode()
}

// maxJSONMaskDepth JSON 递归掩码深度上限（防恶意深嵌套构造 CPU 放大）
const maxJSONMaskDepth = 64

// maskJSONBody JSON 递归掩码（UseNumber 保大数不失真；深度超限回落 scrub）
func maskJSONBody(body string) string {
	dec := json.NewDecoder(strings.NewReader(body))
	dec.UseNumber()
	var root interface{}
	if err := dec.Decode(&root); err != nil {
		return scrubSensitiveBody(body)
	}
	masked, ok := maskJSONValue(root, 0)
	if !ok {
		return scrubSensitiveBody(body)
	}
	out, err := json.Marshal(masked)
	if err != nil {
		return scrubSensitiveBody(body)
	}
	return string(out)
}

// maskJSONValue 递归掩码 JSON 值；ok=false 表示深度超限
func maskJSONValue(v interface{}, depth int) (interface{}, bool) {
	if depth > maxJSONMaskDepth {
		return nil, false
	}
	switch t := v.(type) {
	case map[string]interface{}:
		for k, val := range t {
			if isSensitiveBodyKey(k) {
				t[k] = maskedValue
				continue
			}
			mv, ok := maskJSONValue(val, depth+1)
			if !ok {
				return nil, false
			}
			t[k] = mv
		}
		return t, true
	case []interface{}:
		for i, val := range t {
			mv, ok := maskJSONValue(val, depth+1)
			if !ok {
				return nil, false
			}
			t[i] = mv
		}
		return t, true
	default:
		return v, true
	}
}

// maskMultipartBody multipart 掩码：文件 part 只留 name/filename/size 摘要；
// 值 part 同键掩码。边界解析失败回落 scrub。
func maskMultipartBody(body, contentType string) string {
	_, params, err := mime.ParseMediaType(contentType)
	if err != nil || params["boundary"] == "" {
		return scrubSensitiveBody(body)
	}
	reader := multipart.NewReader(strings.NewReader(body), params["boundary"])
	form, err := reader.ReadForm(int64(maxRequestBodyLen))
	if err != nil {
		return scrubSensitiveBody(body)
	}
	var buf bytes.Buffer
	first := true
	writeField := func(k, v string) {
		if !first {
			buf.WriteString("&")
		}
		first = false
		buf.WriteString(url.QueryEscape(k))
		buf.WriteString("=")
		buf.WriteString(url.QueryEscape(v))
	}
	for key, vals := range form.Value {
		if isSensitiveBodyKey(key) {
			writeField(key, maskedValue)
			continue
		}
		for _, v := range vals {
			writeField(key, v)
		}
	}
	// 文件 part 摘要（name/filename/size——内容丢弃）
	for name, headers := range form.File {
		for _, h := range headers {
			writeField("__file_"+name, "filename="+h.Filename+",size="+strconv.FormatInt(h.Size, 10))
		}
	}
	return buf.String()
}

// ── body_hash（F8.4）：HMAC-SHA256 + 进程随机盐 ──
// 无盐 SHA256 对小 JSON 是离线口令验证 oracle（字典比对原始值）；加盐后仅
// 进程内可比对（比对同一请求跨事件的 body 一致性），离线字典失效。

var (
	bodyHashSaltOnce sync.Once
	bodyHashSalt     []byte
)

func getBodyHashSalt() []byte {
	bodyHashSaltOnce.Do(func() {
		bodyHashSalt = make([]byte, 16)
		if _, err := io.ReadFull(rand.Reader, bodyHashSalt); err != nil {
			// crypto/rand 失败极罕见：退化为全零盐（仍优于无盐，进程内可比对）
			for i := range bodyHashSalt {
				bodyHashSalt[i] = 0
			}
		}
	})
	return bodyHashSalt
}

// BodyHash 返回请求体原文的加盐 HMAC-SHA256 摘要（hex，进程内可比对）
func BodyHash(raw string) string {
	mac := hmac.New(sha256.New, getBodyHashSalt())
	mac.Write([]byte(raw))
	return hex.EncodeToString(mac.Sum(nil))
}

// maskMatchedVars F8.3：MatchedVars 按 Key 掩码 Value/Data（Coraza 命中值
// 如 ARGS:password 会原样内联明文）
func maskMatchedVars(vars []MatchedVar) {
	for i := range vars {
		if isSensitiveBodyKey(vars[i].Key) {
			vars[i].Value = maskedValue
			vars[i].Data = maskedValue
		}
	}
}
