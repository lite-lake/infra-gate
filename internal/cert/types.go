package cert

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/lite-lake/infra-gate/internal/infrastructs/endpoints"
)

const (
	// DefaultExpiringSoonDays 默认证书即将过期阈值（天）
	DefaultExpiringSoonDays = 30
	// DefaultRemoteTimeout 远程证书请求默认超时
	DefaultRemoteTimeout = 6 * time.Minute
)

// CertConfig SSL证书配置
type CertConfig struct {
	Local  *LocalCertConfig  `yaml:"local"`
	Remote *RemoteCertConfig `yaml:"remote"`
}

// Validate H23: 校验 CertConfig 的完整性和合理性
// 确保 Local 和 Remote 不会同时启用，且至少有一个可用的配置。
// F6（内部PRD §4.6.2）：本方法由 config.Config.Validate 真正接线调用
// （此前是死代码）——endpoint https 强制与 timeout 越界在此 fail-fast
func (c *CertConfig) Validate() error {
	localEnabled := c.Local != nil && c.Local.Enabled
	remoteEnabled := c.Remote != nil && c.Remote.Enabled

	if localEnabled && remoteEnabled {
		return fmt.Errorf("local and remote certificate sources cannot be enabled simultaneously")
	}
	if !localEnabled && !remoteEnabled {
		return fmt.Errorf("at least one certificate source (local or remote) must be enabled")
	}
	if localEnabled && c.Local.CertDir == "" {
		return fmt.Errorf("local.cert_dir must be set when local is enabled")
	}
	if remoteEnabled {
		if c.Remote.Endpoint.IsEmpty() {
			return fmt.Errorf("remote.endpoint must be set when remote is enabled")
		}
		// F6.1：全部 endpoint 必须 https——明文 http 仅在 allow_insecure_http
		// 显式放行时允许（内网明文端点逃生口，对齐 CRS validateMirrorURLScheme）
		for _, raw := range c.Remote.Endpoint.All() {
			u, err := url.Parse(strings.TrimSpace(raw))
			if err != nil {
				continue // 解析失败的条目由运行期下载路径报错
			}
			if u.Scheme == "http" && !c.Remote.GetEffectiveAllowInsecureHTTP() {
				return fmt.Errorf("remote.endpoint %q uses plaintext http; set ssl.remote.allow_insecure_http: true to allow (内部PRD F6)", raw)
			}
		}
		// F6.2：timeout 越界拒绝（负值/零 = 异常配置；> 1h = 挂死）
		if c.Remote.Timeout != 0 && (c.Remote.Timeout < minRemoteTimeout || c.Remote.Timeout > maxRemoteTimeout) {
			return fmt.Errorf("remote.timeout %v out of bounds [%v, %v]", c.Remote.Timeout, minRemoteTimeout, maxRemoteTimeout)
		}
	}
	return nil
}

// LocalCertConfig 本地证书配置
type LocalCertConfig struct {
	Enabled bool   `yaml:"enabled"`
	CertDir string `yaml:"cert_dir"`
}

// RemoteCertConfig 远程证书配置
type RemoteCertConfig struct {
	Enabled           bool              `yaml:"enabled"`
	Endpoint          endpoints.Config  `yaml:"endpoint"`
	AutoUpdate        bool              `yaml:"auto_update"`
	UpdateCheckWindow string            `yaml:"update_check_window"` // 格式: "00:00-00:59"
	APIKey            string            `yaml:"api_key"`             // API Key 用于身份验证
	Proxy             RemoteProxyConfig `yaml:"proxy"`               // 代理配置
	Timeout           time.Duration     `yaml:"timeout"`             // 远程请求超时，默认 6 分钟
	// AllowInsecureHTTP F6.1（内部PRD §4.6.1）：明文 http 端点显式放行开关
	//（内网 docker 别名端点）。nil = false（仅 https，启动校验直接报错）；
	// 显式 true 时运行期首次下载 Warn 一条。对齐 CRS mirror_allow_insecure_http 先例
	AllowInsecureHTTP *bool `yaml:"allow_insecure_http,omitempty"`
	// VerifyChain F6.3：CA 链校验开关（默认开；roots 不可用时自动降级 Warn 跳过，
	// hostname/有效期窗口仍强制）。显式 false 为逃生口（如私有 CA 无系统根）
	VerifyChain *bool `yaml:"verify_chain,omitempty"`
}

// GetEffectiveAllowInsecureHTTP 返回是否放行明文 http 证书端点：nil = false（仅 https）
func (c *RemoteCertConfig) GetEffectiveAllowInsecureHTTP() bool {
	if c.AllowInsecureHTTP == nil {
		return false
	}
	return *c.AllowInsecureHTTP
}

// GetEffectiveVerifyChain 返回是否校验证书 CA 链：nil = true（默认开）
func (c *RemoteCertConfig) GetEffectiveVerifyChain() bool {
	if c.VerifyChain == nil {
		return true
	}
	return *c.VerifyChain
}

// remoteTimeoutBounds F6.2：远程请求超时合法区间（下限排除负值/零误配，
// 上限 1h——超时本身是异常场景的快速失败通道，过长等价于挂死）
const (
	minRemoteTimeout = time.Second
	maxRemoteTimeout = time.Hour
)

// RemoteProxyConfig 远程证书代理配置
type RemoteProxyConfig struct {
	Enabled  bool   `yaml:"enabled"`
	URL      string `yaml:"url"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

// CertMetadata 证书元数据
type CertMetadata struct {
	Domain      string    `json:"domain"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	UpdatedAt   time.Time `json:"updated_at"`
	Source      string    `json:"source"` // "local" 或 "remote"
	Endpoint    string    `json:"endpoint,omitempty"`
	Fingerprint string    `json:"fingerprint"`
}

// CertPair 证书对
type CertPair struct {
	Certificate *tls.Certificate
	Metadata    *CertMetadata
}

// RemoteCertResponse 远程证书API响应
type RemoteCertResponse struct {
	Domain      string `json:"domain"`
	FullChain   string `json:"fullchain"`
	PrivateKey  string `json:"privkey"`
	StartDate   string `json:"start_date"`
	ExpiredDate string `json:"expired_date"`
}

// IsExpired 检查证书是否过期
func (m *CertMetadata) IsExpired() bool {
	return time.Now().After(m.NotAfter)
}

// IsExpiringSoon 检查证书是否即将过期（使用默认阈值）
func (m *CertMetadata) IsExpiringSoon() bool {
	return m.IsExpiringSoonDays(DefaultExpiringSoonDays)
}

// IsExpiringSoonDays 检查证书是否在指定天数内过期
func (m *CertMetadata) IsExpiringSoonDays(days int) bool {
	return time.Now().Add(time.Duration(days) * 24 * time.Hour).After(m.NotAfter)
}

// GetEffectiveTimeout 获取有效的远程请求超时
func (c *RemoteCertConfig) GetEffectiveTimeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return DefaultRemoteTimeout
}

// SaveMetadata 保存证书元数据
func (m *CertMetadata) SaveMetadata(cacheDir string) error {
	if err := validateDomain(m.Domain); err != nil {
		return fmt.Errorf("invalid domain for metadata path: %w", err)
	}

	metadataPath := filepath.Join(cacheDir, m.Domain, "metadata.json")

	// 确保目录存在
	if err := os.MkdirAll(filepath.Dir(metadataPath), 0755); err != nil {
		return fmt.Errorf("failed to create metadata directory: %w", err)
	}

	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	return atomicWriteFile(metadataPath, data, 0644)
}

// LoadMetadata 加载证书元数据
func LoadMetadata(cacheDir, domain string) (*CertMetadata, error) {
	if err := validateDomain(domain); err != nil {
		return nil, fmt.Errorf("invalid domain for metadata path: %w", err)
	}

	metadataPath := filepath.Join(cacheDir, domain, "metadata.json")

	data, err := os.ReadFile(metadataPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read metadata: %w", err)
	}

	var metadata CertMetadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
	}

	return &metadata, nil
}
