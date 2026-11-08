package cert

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/lite-lake/infra-gate/internal/infrastructs/logger"
	"github.com/lite-lake/infra-gate/internal/netutil"
)

const (
	// maxResponseBodySize 最大响应体大小（1MB）
	maxResponseBodySize = 1 << 20
)

// Loader 证书加载器
type Loader struct {
	cacheDir string
	logger   logger.ILogger
	// httpWarnOnce F6.1：明文 http 端点放行时的首次 Warn 去重
	httpWarnOnce sync.Once
}

// NewLoader 创建证书加载器
func NewLoader(cacheDir string, log logger.ILogger) *Loader {
	return &Loader{
		cacheDir: cacheDir,
		logger:   log,
	}
}

// warnInsecureHTTPOnce F6.1：http+allow 端点首次下载 Warn 一条（进程内去重）
func (l *Loader) warnInsecureHTTPOnce(endpoint string) {
	l.httpWarnOnce.Do(func() {
		l.logger.Warn("SSL endpoint uses plaintext http with allow_insecure_http=true: certificate traffic is unencrypted on this hop",
			logger.NewField("endpoint", netutil.RedactURL(endpoint)))
	})
}

// LoadCertificate 加载证书（优先本地缓存）
func (l *Loader) LoadCertificate(domain string, config *CertConfig) (*CertPair, error) {
	if config == nil {
		return nil, fmt.Errorf("SSL certificate configuration is nil for domain %s", domain)
	}

	if certPair, err := l.loadFromCache(domain); err == nil {
		l.logger.Debug("Certificate loaded from cache", logger.NewField("domain", domain))
		return certPair, nil
	}

	if config.Local != nil && config.Local.Enabled {
		return l.loadLocalCertificate(domain, config.Local.CertDir)
	}

	if config.Remote != nil && config.Remote.Enabled {
		return l.loadRemoteCertificate(domain, config.Remote)
	}

	return nil, fmt.Errorf("no valid certificate configuration found for domain %s", domain)
}

// loadFromCache 从缓存加载证书
func (l *Loader) loadFromCache(domain string) (*CertPair, error) {
	if err := validateDomain(domain); err != nil {
		return nil, fmt.Errorf("invalid domain for cache path: %w", err)
	}

	metadata, err := LoadMetadata(l.cacheDir, domain)
	if err != nil {
		return nil, err
	}

	if metadata.IsExpired() {
		return nil, fmt.Errorf("cached certificate expired for domain %s", domain)
	}

	certPath := filepath.Join(l.cacheDir, domain, "fullchain.pem")
	keyPath := filepath.Join(l.cacheDir, domain, "privkey.pem")

	certData, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file: %w", err)
	}

	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %w", err)
	}

	cert, err := tls.X509KeyPair(certData, keyData)
	if err != nil {
		return nil, fmt.Errorf("failed to load X509 key pair: %w", err)
	}

	// 预解析证书并填充 Leaf，避免每次 TLS 握手时重复解析
	parsedCert, perr := ParseCertificate(certData)
	if perr == nil {
		cert.Leaf = parsedCert
		// F6.4（内部PRD §4.6.4）：缓存过期判定以证书本体 NotAfter 为准，
		// 不再信 metadata.json（防篡改延长表面有效期）；本体已过期即拒绝缓存
		if time.Now().After(parsedCert.NotAfter) {
			return nil, fmt.Errorf("cached certificate expired for domain %s (cert not_after=%s)", domain, parsedCert.NotAfter.Format(time.RFC3339))
		}
	}

	return &CertPair{
		Certificate: &cert,
		Metadata:    metadata,
	}, nil
}

// loadLocalCertificate 从本地文件加载证书
func (l *Loader) loadLocalCertificate(domain, certDir string) (*CertPair, error) {
	l.logger.Info("Loading certificate from local directory",
		logger.NewField("domain", domain),
		logger.NewField("cert_dir", certDir))

	certPath := filepath.Join(certDir, "fullchain.pem")
	keyPath := filepath.Join(certDir, "privkey.pem")

	if !l.fileExists(certPath) {
		return nil, fmt.Errorf("certificate file not found: %s", certPath)
	}

	if !l.fileExists(keyPath) {
		return nil, fmt.Errorf("private key file not found: %s", keyPath)
	}

	certData, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file: %w", err)
	}

	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %w", err)
	}

	cert, err := ParseCertificate(certData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	tlsCert, err := tls.X509KeyPair(certData, keyData)
	if err != nil {
		return nil, fmt.Errorf("failed to load X509 key pair: %w", err)
	}

	// 预解析证书并填充 Leaf，避免每次 TLS 握手时重复解析
	tlsCert.Leaf = cert

	metadata := &CertMetadata{
		Domain:      domain,
		NotBefore:   cert.NotBefore,
		NotAfter:    cert.NotAfter,
		UpdatedAt:   time.Now(),
		Source:      "local",
		Fingerprint: calculateFingerprint(certData),
	}

	if err := l.saveToCache(domain, certData, keyData, metadata); err != nil {
		l.logger.Warn("Failed to save certificate to cache",
			logger.NewField("domain", domain),
			logger.NewField("error", err.Error()))
	}

	return &CertPair{
		Certificate: &tlsCert,
		Metadata:    metadata,
	}, nil
}

// loadRemoteCertificate 从远程API加载证书
// 支持多端点故障转移：随机选择一个端点，失败后依次尝试其他端点
// 每个端点内部仍然保留 3 次重试（直连 + 代理）的现有逻辑
func (l *Loader) loadRemoteCertificate(domain string, remoteConfig *RemoteCertConfig) (*CertPair, error) {
	apiKey := remoteConfig.APIKey
	timeout := remoteConfig.GetEffectiveTimeout()

	l.logger.Info("Loading certificate from remote endpoint",
		logger.NewField("domain", domain),
		logger.NewField("endpoint_count", remoteConfig.Endpoint.Len()),
		logger.NewField("has_api_key", apiKey != ""))

	encodedDomain := url.QueryEscape(domain)
	picker := remoteConfig.Endpoint.NewPicker()

	var lastErr error
	for {
		endpoint, _, ok := picker.Next()
		if !ok {
			break
		}

		rawURL := fmt.Sprintf("%s?domain=%s", endpoint, encodedDomain)

		// F6.1（内部PRD §4.6.1）：运行期兜底——明文 http 端点仅在显式放行时
		// 允许（Validate 已 fail-fast，此处覆盖 Manager.UpdateCertificate 等绕过
		// LoadConfig 的路径）；放行时首次 Warn 一条
		if eu, uerr := url.Parse(endpoint); uerr == nil && eu.Scheme == "http" {
			if !remoteConfig.GetEffectiveAllowInsecureHTTP() {
				return nil, fmt.Errorf("remote endpoint %q uses plaintext http; set ssl.remote.allow_insecure_http: true to allow (内部PRD F6)", endpoint)
			}
			l.warnInsecureHTTPOnce(endpoint)
		}

		l.logger.Info("Trying remote endpoint",
			logger.NewField("domain", domain),
			logger.NewField("endpoint", netutil.RedactURL(endpoint)))

		var resp *http.Response
		var err error

		for attempt := 0; attempt < 3; attempt++ {
			if attempt > 0 {
				l.logger.Info("Retrying certificate download",
					logger.NewField("attempt", attempt+1),
					logger.NewField("domain", domain))
				time.Sleep(time.Duration(attempt*2) * time.Second)
			}

			// 直接下载
			l.logger.Info("Trying direct download", logger.NewField("attempt", attempt+1))
			resp, err = l.downloadWithTimeout(rawURL, false, apiKey, timeout, &remoteConfig.Proxy)
			if err == nil && resp != nil && resp.StatusCode == http.StatusOK {
				l.logger.Info("Direct download successful", logger.NewField("attempt", attempt+1))
				break
			}

			if resp != nil {
				if resp.StatusCode == http.StatusUnauthorized {
					l.logger.Error("API Key authentication failed",
						logger.NewField("domain", domain),
						logger.NewField("endpoint", netutil.RedactURL(endpoint)))
					resp.Body.Close()
					return nil, fmt.Errorf("API Key authentication failed: invalid API key for endpoint %s", endpoint)
				}
				// 4xx 客户端错误不重试
				if resp.StatusCode >= 400 && resp.StatusCode < 500 {
					resp.Body.Close()
					return nil, fmt.Errorf("remote API returned client error %d for domain %s", resp.StatusCode, domain)
				}
				resp.Body.Close()
				resp = nil
			}

			if err != nil {
				l.logger.Warn("Direct download failed",
					logger.NewField("attempt", attempt+1),
					logger.NewField("error", err.Error()))
			}

			// 代理下载
			l.logger.Info("Trying proxy download as fallback", logger.NewField("attempt", attempt+1))
			resp, err = l.downloadWithTimeout(rawURL, true, apiKey, timeout, &remoteConfig.Proxy)
			if err == nil && resp != nil && resp.StatusCode == http.StatusOK {
				l.logger.Info("Proxy download successful", logger.NewField("attempt", attempt+1))
				break
			}

			if resp != nil {
				if resp.StatusCode == http.StatusUnauthorized {
					l.logger.Error("API Key authentication failed (via proxy)",
						logger.NewField("domain", domain),
						logger.NewField("endpoint", netutil.RedactURL(endpoint)))
					resp.Body.Close()
					return nil, fmt.Errorf("API Key authentication failed: invalid API key for endpoint %s", endpoint)
				}
				if resp.StatusCode >= 400 && resp.StatusCode < 500 {
					resp.Body.Close()
					return nil, fmt.Errorf("remote API returned client error %d for domain %s", resp.StatusCode, domain)
				}
				resp.Body.Close()
				resp = nil
			}

			if err != nil {
				l.logger.Warn("Proxy download failed",
					logger.NewField("attempt", attempt+1),
					logger.NewField("error", err.Error()))
			}
		}

		if resp == nil {
			l.logger.Warn("All attempts failed for endpoint, trying next endpoint",
				logger.NewField("domain", domain),
				logger.NewField("endpoint", netutil.RedactURL(endpoint)))
			if err != nil {
				lastErr = err
			} else {
				lastErr = fmt.Errorf("failed to download certificate from %s after 3 attempts", endpoint)
			}
			continue
		}

		// 成功获取响应，解析证书
		certPair, parseErr := l.parseRemoteResponse(resp, domain, endpoint, remoteConfig)
		if parseErr != nil {
			l.logger.Warn("Failed to parse remote response, trying next endpoint",
				logger.NewField("domain", domain),
				logger.NewField("endpoint", netutil.RedactURL(endpoint)),
				logger.NewField("error", parseErr.Error()))
			lastErr = parseErr
			continue
		}

		return certPair, nil
	}

	if lastErr != nil {
		return nil, fmt.Errorf("failed to download certificate after trying all endpoints: %w", lastErr)
	}
	return nil, fmt.Errorf("no remote endpoints configured for domain %s", domain)
}

// parseRemoteResponse 解析远程证书 API 响应并构造 CertPair
func (l *Loader) parseRemoteResponse(resp *http.Response, domain, endpoint string, remoteConfig *RemoteCertConfig) (*CertPair, error) {
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("remote API returned status: %d", resp.StatusCode)
	}

	// 限制响应体大小
	limitedBody := io.LimitReader(resp.Body, maxResponseBodySize)

	// 一次性解析完整响应（{code, message, data}）
	var apiResponse struct {
		Code    int                `json:"code"`
		Message string             `json:"message"`
		Data    RemoteCertResponse `json:"data"`
	}
	if err := json.NewDecoder(limitedBody).Decode(&apiResponse); err != nil {
		return nil, fmt.Errorf("failed to decode remote response: %w", err)
	}

	if apiResponse.Code != 200 {
		return nil, fmt.Errorf("remote API error: code=%d, message=%s", apiResponse.Code, apiResponse.Message)
	}

	response := apiResponse.Data

	if response.Domain != domain && !isParentDomain(response.Domain, domain) {
		return nil, fmt.Errorf("domain mismatch: expected %s, got %s", domain, response.Domain)
	}

	if response.FullChain == "" || response.PrivateKey == "" {
		return nil, fmt.Errorf("invalid certificate data in remote response")
	}

	certData := []byte(response.FullChain)
	cert, err := ParseCertificate(certData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse remote certificate: %w", err)
	}

	tlsCert, err := tls.X509KeyPair(certData, []byte(response.PrivateKey))
	if err != nil {
		return nil, fmt.Errorf("failed to load X509 key pair from remote data: %w", err)
	}

	// 预解析证书并填充 Leaf，避免每次 TLS 握手时重复解析
	tlsCert.Leaf = cert

	// F6.3（内部PRD §4.6.3）：单点 choke point——SAN/有效期窗口/CA 链
	// 校验，失败即拒绝（不落盘、不进内存）。覆盖 Updater/Reconciler/手动更新
	if verr := validateRemoteCertificate(domain, cert, certData, remoteConfig.GetEffectiveVerifyChain(), l.logger); verr != nil {
		return nil, verr
	}

	// F6.4：metadata 的有效期直接取证书本体（响应 start_date/expired_date 与
	// 本体不一致时以本体为准——修「缓存过期判定信 metadata.json」）
	notBefore := cert.NotBefore
	notAfter := cert.NotAfter

	metadata := &CertMetadata{
		Domain:      domain,
		NotBefore:   notBefore,
		NotAfter:    notAfter,
		UpdatedAt:   time.Now(),
		Source:      "remote",
		Endpoint:    endpoint,
		Fingerprint: calculateFingerprint(certData),
	}

	keyData := []byte(response.PrivateKey)
	if err := l.saveToCache(domain, certData, keyData, metadata); err != nil {
		l.logger.Warn("Failed to save remote certificate to cache",
			logger.NewField("domain", domain),
			logger.NewField("error", err.Error()))
	}

	l.logger.Info("Certificate loaded successfully from remote",
		logger.NewField("domain", domain),
		logger.NewField("endpoint", netutil.RedactURL(endpoint)),
		logger.NewField("not_after", notAfter.Format(time.RFC3339)))

	return &CertPair{
		Certificate: &tlsCert,
		Metadata:    metadata,
	}, nil
}

// saveToCache 保存证书到缓存（原子写入）
func (l *Loader) saveToCache(domain string, certData, keyData []byte, metadata *CertMetadata) error {
	if err := validateDomain(domain); err != nil {
		return fmt.Errorf("invalid domain for cache path: %w", err)
	}

	domainCacheDir := filepath.Join(l.cacheDir, domain)

	if err := os.MkdirAll(domainCacheDir, 0700); err != nil {
		return fmt.Errorf("failed to create cache directory: %w", err)
	}

	certPath := filepath.Join(domainCacheDir, "fullchain.pem")
	if err := atomicWriteFile(certPath, certData, 0644); err != nil {
		return fmt.Errorf("failed to save certificate file: %w", err)
	}

	keyPath := filepath.Join(domainCacheDir, "privkey.pem")
	if err := atomicWriteFile(keyPath, keyData, 0600); err != nil {
		return fmt.Errorf("failed to save private key file: %w", err)
	}

	return metadata.SaveMetadata(l.cacheDir)
}

// fileExists 检查文件是否存在
func (l *Loader) fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// downloadWithTimeout 使用超时控制下载文件
func (l *Loader) downloadWithTimeout(rawURL string, useProxy bool, apiKey string, timeout time.Duration, proxyConfig *RemoteProxyConfig) (*http.Response, error) {
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return nil, err
	}

	if apiKey != "" {
		req.Header.Set("X-API-KEY", apiKey)
	}
	req.Header.Set("User-Agent", "infra-gate/1.0")

	var client *http.Client
	if useProxy && proxyConfig != nil && proxyConfig.Enabled && proxyConfig.URL != "" {
		client = l.createProxyClient(proxyConfig, timeout)
	} else {
		client = &http.Client{Timeout: timeout}
	}

	return client.Do(req)
}

// createProxyClient 创建使用代理的HTTP客户端
func (l *Loader) createProxyClient(proxyConfig *RemoteProxyConfig, timeout time.Duration) *http.Client {
	if proxyConfig == nil || !proxyConfig.Enabled || proxyConfig.URL == "" {
		return &http.Client{Timeout: timeout}
	}

	proxyURL, err := url.Parse(proxyConfig.URL)
	if err != nil {
		l.logger.Error("Invalid proxy URL",
			logger.NewField("url", netutil.RedactURL(proxyConfig.URL)),
			logger.NewField("error", err.Error()))
		return &http.Client{Timeout: timeout}
	}

	if proxyConfig.Username != "" && proxyConfig.Password != "" {
		proxyURL.User = url.UserPassword(proxyConfig.Username, proxyConfig.Password)
	}

	transport := &http.Transport{
		Proxy:                 http.ProxyURL(proxyURL),
		ResponseHeaderTimeout: timeout,
		ExpectContinueTimeout: 1 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}
}

// validateDomain 校验域名是否安全用于文件路径构造
// 拒绝包含路径穿越字符（..、/、\）和空字节的域名，防止 SNI 注入导致的路径穿越攻击
func validateDomain(domain string) error {
	if domain == "" {
		return fmt.Errorf("domain is empty")
	}
	if strings.Contains(domain, "\x00") {
		return fmt.Errorf("domain contains null byte: %s", domain)
	}
	if strings.Contains(domain, "..") || strings.ContainsAny(domain, "/\\") {
		return fmt.Errorf("domain contains path traversal characters: %s", domain)
	}
	return nil
}

// isParentDomain 检查parentDomain是否是domain的父域名
// H24: parentDomain 必须包含至少一个点号（不能是 TLD 如 "com"），防止过度匹配
func isParentDomain(parentDomain, domain string) bool {
	if parentDomain == domain {
		return true
	}
	if !strings.Contains(parentDomain, ".") {
		return false
	}
	if strings.HasSuffix(domain, "."+parentDomain) {
		return true
	}
	return false
}

// calculateFingerprint 计算证书指纹（完整 SHA-256）
func calculateFingerprint(certData []byte) string {
	return fmt.Sprintf("%x", sha256.Sum256(certData))
}

// ParseCertificate 解析证书并提取信息
func ParseCertificate(certData []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certData)
	if block == nil {
		return nil, fmt.Errorf("failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse X509 certificate: %w", err)
	}

	return cert, nil
}

// atomicWriteFile 原子写入文件（在同目录创建临时文件，写入 + Sync + rename）
// 使用 os.CreateTemp 在目标文件同目录创建随机命名临时文件，
// 避免 cross-device link error 和 .tmp 文件残留
func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)

	tmpFile, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath) // 清理未 rename 的临时文件（rename 成功后 Remove 为 no-op）

	if _, err := tmpFile.Write(data); err != nil {
		tmpFile.Close()
		return fmt.Errorf("failed to write temp file: %w", err)
	}

	if err := tmpFile.Chmod(perm); err != nil {
		tmpFile.Close()
		return fmt.Errorf("failed to chmod temp file: %w", err)
	}

	if err := tmpFile.Sync(); err != nil {
		tmpFile.Close()
		return fmt.Errorf("failed to sync temp file: %w", err)
	}

	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("failed to close temp file: %w", err)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("failed to rename temp file to target: %w", err)
	}

	return nil
}
