package cert

// F6.3（内部PRD §4.6.3）：远程证书本体校验单点 choke point。
// Updater / Reconciler / 手动更新全部经 parseRemoteResponse 汇入此处，
// 校验失败返回错误 → 不落盘（saveToCache 之前）。
//
// 校验项：
//  1. cert.VerifyHostname(domain)：SAN 必须匹配请求域名（含通配符形态；
//     父域 SAN 错配证书——响应 domain 字段通过但证书 SAN 实为其他域——正是要拦的目标）
//  2. 有效期窗口：NotAfter > now 且 NotBefore <= now+24h（ZeroSSL 等新签 NotBefore
//     可能在未来几分钟，24h 宽限不误杀；3 天后生效的属异常签发直接拒）
//  3. CA 链校验（默认开，verify_chain 逃生口）：x509.Verify + 系统 roots +
//    CurrentTime 钳制；roots 不可用（精简容器）时 Warn 降级跳过链校验，
//     hostname/窗口仍强制
//
// 不做指纹 pin（叶证书 90 天轮换，pin 运维成本高且收益与链校验重叠，D6）。

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/lite-lake/infra-gate/internal/infrastructs/logger"
)

// certNotBeforeGrace NotBefore 未来宽限（ZeroSSL 等新签证书 NotBefore 可晚于当前时刻几分钟）
const certNotBeforeGrace = 24 * time.Hour

// validateRemoteCertificate 校验远程下载的证书本体（单点 choke point）。
// fullChainPEM 为完整证书链 PEM（首块为叶证书，其余为中间证书）。
// 返回错误时调用方必须拒绝该证书（不写缓存、不进内存）。
func validateRemoteCertificate(domain string, cert *x509.Certificate, fullChainPEM []byte, verifyChain bool, log logger.ILogger) error {
	now := time.Now()

	// 1. SAN/hostname 匹配
	if err := cert.VerifyHostname(domain); err != nil {
		return fmt.Errorf("remote certificate SAN does not match domain %s: %w", domain, err)
	}

	// 2. 有效期窗口
	if !now.Before(cert.NotAfter) {
		return fmt.Errorf("remote certificate for %s is expired (not_after=%s)", domain, cert.NotAfter.Format(time.RFC3339))
	}
	if cert.NotBefore.After(now.Add(certNotBeforeGrace)) {
		return fmt.Errorf("remote certificate for %s has notBefore %s more than %v in the future (suspected misissuance)",
			domain, cert.NotBefore.Format(time.RFC3339), certNotBeforeGrace)
	}

	// 3. CA 链校验（可逃生）
	if verifyChain {
		if err := verifyCertificateChain(domain, cert, fullChainPEM, now, log); err != nil {
			return err
		}
	}
	return nil
}

// verifyCertificateChain 校验证书链：系统 roots + fullchain 其余证书为中间链。
// roots 不可用时 Warn 降级跳过（可用性优先；hostname/窗口校验仍在上游强制）
func verifyCertificateChain(domain string, leaf *x509.Certificate, fullChainPEM []byte, now time.Time, log logger.ILogger) error {
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		if log != nil {
			log.Warn("System cert pool unavailable, skipping CA chain verification (hostname/validity checks remain enforced)",
				logger.NewField("domain", domain),
				logger.NewField("error", fmt.Sprint(err)))
		}
		return nil
	}

	intermediates := x509.NewCertPool()
	rest := fullChainPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		if c.Equal(leaf) {
			continue
		}
		intermediates.AddCert(c)
	}

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
	}
	if _, err := leaf.Verify(opts); err != nil {
		// 私有 CA 场景配置 ssl.remote.verify_chain: false 逃生
		return fmt.Errorf("remote certificate for %s failed CA chain verification: %w (set ssl.remote.verify_chain: false if using a private CA)", domain, err)
	}
	return nil
}
