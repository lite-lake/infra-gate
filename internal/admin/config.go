package admin

import (
	"crypto/subtle"
	"fmt"
	"github.com/lite-lake/infra-gate/internal/deployinfo"
	"net"
	"os"
	"strconv"
	"strings"
)

const (
	defaultHTTPPort  = 30080
	defaultHTTPSPort = 30443
	// allowedIPsEnvVar M4（内部PRD §7.2）：admin 允许名单环境变量
	allowedIPsEnvVar = "LITE_ADMIN_ALLOWED_IPS"
)

// AdminConfig 管理后台配置，从环境变量加载。
// 面板拆除（内部PRD 迭代 4b）后不再有登录账号密码环境变量（用户名/密码读取已移除），
// 唯一管理面为只读 API Key 通道。
type AdminConfig struct {
	Domain string
	HTTPS  bool
	Port   int
	// ReadOnlyAPIKeys 只读 API Key 数组（LITE_ADMIN_READONLY_API_KEYS，逗号分隔），
	// 供 AC（Admin Center）等内部系统以 X-API-Key 头轮询只读端点（/api/sites、/api/certs、/api/system、
	// WAF/黑名单统计与事件），面板拆除后为唯一认证通道，不含任何写操作；
	// 数组多把并存支持新旧 key 轮换。空 = 未配置 key（所有只读请求一律 401）
	ReadOnlyAPIKeys []string
	// AllowedIPs admin 允许名单（M4，内部PRD §5/§6/决策 D3）：IP/CIDR 条目，
	// 按直连对端评估（与 allowed_ips 边缘 ACL 同口径），不匹配 → 403（含免认证探针
	// 在内的全部端点）。未设置环境变量 → DefaultAdminAllowedIPs（私网+回环，覆盖
	// mesh 10.61/10.62）；显式设置空串 → 置空 + AllowedIPsUnlimited=true（逃生口）
	AllowedIPs []string
	// AllowedIPsUnlimited true = LITE_ADMIN_ALLOWED_IPS 显式设置为空串，不限制来源
	//（逃生口，启动 Warn）
	AllowedIPsUnlimited bool
}

// DefaultAdminAllowedIPs admin 允许名单缺省值（M4/决策 D3）：私网 + 回环——
// 127/8、::1/128、10/8、172.16/12、192.168/16，覆盖 EasyTier mesh 两段
// （dev 10.71.0.0/24 / prod 10.72.0.0/24）；mesh 内 Kuma 探活 / AC 轮询不受影响，
// 公网直连 admin 端口默认 403
func DefaultAdminAllowedIPs() []string {
	return []string{
		"127.0.0.0/8",
		"::1/128",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
	}
}

// LoadFromEnv 从环境变量加载管理后台配置
// 必填变量: LITE_ADMIN_DOMAIN（同时用于 admin 端点 Host 校验）
// 可选变量: LITE_ADMIN_HTTPS (默认 true), LITE_ADMIN_PORT (默认 30443/30080),
//
//	LITE_ADMIN_READONLY_API_KEYS (逗号分隔的只读 key，空则只读 API 全部拒绝),
//	LITE_ADMIN_ALLOWED_IPS (逗号分隔 IP/CIDR 允许名单，未设置 = 默认私网+回环，
//	显式空串 = 不限制；非法条目返回 error，启动 fail-fast)
//
// LITE_ADMIN_DOMAIN 为空则返回 nil，表示不启用管理后台；
// LITE_ADMIN_ALLOWED_IPS 含非法条目则返回错误（fail-fast，调用方拒绝启动）
func LoadFromEnv() (*AdminConfig, error) {
	domain := strings.TrimSpace(os.Getenv("LITE_ADMIN_DOMAIN"))

	if domain == "" {
		return nil, nil
	}

	https := true
	if v := strings.TrimSpace(os.Getenv("LITE_ADMIN_HTTPS")); v != "" {
		b, err := strconv.ParseBool(v)
		if err == nil {
			https = b
		}
	}

	port := 0
	if v := strings.TrimSpace(os.Getenv("LITE_ADMIN_PORT")); v != "" {
		p, err := strconv.Atoi(v)
		if err == nil && p > 0 && p <= 65535 {
			port = p
		}
	}
	if port == 0 {
		if https {
			port = defaultHTTPSPort
		} else {
			port = defaultHTTPPort
		}
	}

	// M4 允许名单（D3）：以 LookupEnv 区分「未设置」（默认私网+回环）与「显式
	// 空串」（不限制逃生口）；非空值逐条 fail-fast 校验
	allowed := DefaultAdminAllowedIPs()
	unlimited := false
	if raw, set := os.LookupEnv(allowedIPsEnvVar); set {
		if strings.TrimSpace(raw) == "" {
			unlimited = true
			allowed = nil
		} else {
			parsed, err := parseAllowedIPs(raw)
			if err != nil {
				return nil, err
			}
			allowed = parsed
		}
	}

	// F13.3：key 长度 fail-fast（错误上抛拒绝启动）
	readOnlyKeys, err := parseReadOnlyAPIKeys(os.Getenv("LITE_ADMIN_READONLY_API_KEYS"))
	if err != nil {
		return nil, err
	}

	// F13.5（内部PRD §4.13.5，D13）：逃生口分环境收紧——prod 下
	// LITE_ADMIN_HTTPS=false 或 LITE_ADMIN_ALLOWED_IPS 显式空串直接拒绝启动
	//（不引入二次确认变量：那会让「prod 关 TLS」重新合法化）；dev/local 保留 Warn
	if deployinfo.Get().DeployEnv == "prod" {
		if !https {
			return nil, fmt.Errorf("LITE_ADMIN_HTTPS=false is not allowed in prod (admin payloads would be plaintext); escape hatch is dev/local only (内部PRD F13/D13)")
		}
		if unlimited {
			return nil, fmt.Errorf("LITE_ADMIN_ALLOWED_IPS set to empty string (unlimited) is not allowed in prod; set explicit IP/CIDR entries (内部PRD F13/D13)")
		}
	}

	return &AdminConfig{
		Domain:              domain,
		HTTPS:               https,
		Port:                port,
		ReadOnlyAPIKeys:     readOnlyKeys,
		AllowedIPs:          allowed,
		AllowedIPsUnlimited: unlimited,
	}, nil
}

// parseAllowedIPs 解析逗号分隔的 IP/CIDR 允许名单（M4）：去空白、丢弃空项；
// 逐条校验格式，非法条目返回 error（启动 fail-fast——放行畸形条目等于在管理面
// ACL 上留洞）；显式配置却无任何有效条目同样报错
func parseAllowedIPs(raw string) ([]string, error) {
	entries := make([]string, 0)
	for _, part := range strings.Split(raw, ",") {
		e := strings.TrimSpace(part)
		if e == "" {
			continue
		}
		if strings.Contains(e, "/") {
			if _, _, err := net.ParseCIDR(e); err != nil {
				return nil, fmt.Errorf("%s entry %q is not a valid CIDR: %v", allowedIPsEnvVar, e, err)
			}
		} else if ip := net.ParseIP(e); ip == nil {
			return nil, fmt.Errorf("%s entry %q is not a valid IP or CIDR", allowedIPsEnvVar, e)
		}
		entries = append(entries, e)
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("%s is set but contains no valid entries (use an empty value to disable the allowlist)", allowedIPsEnvVar)
	}
	return entries, nil
}

// minReadOnlyAPIKeyLen F13.3（内部PRD §4.13.3）：只读 key 最小长度。
// 现网 key 全部 43 字符（base64 32 字节），32 位下限零影响；防手输弱 key
// 直接进无限速（现已有限速）的认证通道
const minReadOnlyAPIKeyLen = 32

// parseReadOnlyAPIKeys 解析逗号分隔的只读 API Key 列表（去空白、丢弃空项）。
// 空串返回 nil = 未启用 API Key 通道。
// F13.3：len < 32 的条目 fail-fast（返回错误，LoadFromEnv 上抛拒绝启动）
func parseReadOnlyAPIKeys(raw string) ([]string, error) {
	keys := make([]string, 0)
	for _, part := range strings.Split(raw, ",") {
		k := strings.TrimSpace(part)
		if k == "" {
			continue
		}
		if len(k) < minReadOnlyAPIKeyLen {
			return nil, fmt.Errorf("LITE_ADMIN_READONLY_API_KEYS entry too short: %d chars, minimum %d (内部PRD F13)", len(k), minReadOnlyAPIKeyLen)
		}
		keys = append(keys, k)
	}
	if len(keys) == 0 {
		return nil, nil
	}
	return keys, nil
}

// ValidReadOnlyAPIKey 校验候选 key 是否命中任一已配置的只读 API Key。
// 常数时间比较（crypto/subtle）且遍历全部 key 不短路——任一 key 命中即匹配，
// 但循环始终跑满，避免按配置顺序提前返回泄漏「命中了第几把 key」的时序信息（支持多把并存轮换）
func (c *AdminConfig) ValidReadOnlyAPIKey(candidate string) bool {
	if c == nil || len(c.ReadOnlyAPIKeys) == 0 {
		return false
	}
	var matched byte
	for _, key := range c.ReadOnlyAPIKeys {
		// subtle.ConstantTimeCompare：相等返回 1，否则 0（含长度不等）；按位或累积遍历结果
		matched |= byte(subtle.ConstantTimeCompare([]byte(key), []byte(candidate)) & 0x1)
	}
	return matched == 1
}

func (c *AdminConfig) String() string {
	scheme := "http"
	if c.HTTPS {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s:%d", scheme, c.Domain, c.Port)
}
