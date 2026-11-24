package waf

import (
	"net"
	"strings"

	"github.com/lite-lake/infra-gate/internal/config"
	"github.com/lite-lake/infra-gate/internal/infrastructs/logger"
)

// Checker IP白名单检查器
type Checker struct {
	ipNets []*net.IPNet
	logger logger.ILogger
}

// NewChecker 创建IP白名单检查器
func NewChecker(ipRanges []string, log logger.ILogger) *Checker {
	checker := &Checker{
		ipNets: make([]*net.IPNet, 0),
		logger: log,
	}

	for _, ipRange := range ipRanges {
		if strings.Contains(ipRange, "/") {
			// CIDR格式
			_, ipNet, err := net.ParseCIDR(ipRange)
			if err != nil {
				log.Warn("Invalid CIDR format in whitelist",
					logger.NewField("ip_range", ipRange),
					logger.NewField("error", err.Error()))
				continue
			}
			checker.ipNets = append(checker.ipNets, ipNet)
			log.Info("Added CIDR to whitelist",
				logger.NewField("ip_range", ipRange))
		} else {
			// 单个IP地址
			ip := net.ParseIP(ipRange)
			if ip == nil {
				log.Warn("Invalid IP address in whitelist",
					logger.NewField("ip_range", ipRange))
				continue
			}

			// 将单个IP转换为/32或/128的CIDR
			if ip.To4() != nil {
				// IPv4
				_, ipNet, _ := net.ParseCIDR(ipRange + "/32")
				checker.ipNets = append(checker.ipNets, ipNet)
			} else {
				// IPv6
				_, ipNet, _ := net.ParseCIDR(ipRange + "/128")
				checker.ipNets = append(checker.ipNets, ipNet)
			}
			log.Info("Added IP to whitelist",
				logger.NewField("ip_range", ipRange))
		}
	}

	log.Info("IP whitelist initialized",
		logger.NewField("total_ranges", len(checker.ipNets)))

	return checker
}

// IsWhitelisted 检查IP是否在白名单中
func (c *Checker) IsWhitelisted(clientIP string) bool {
	ip := net.ParseIP(clientIP)
	if ip == nil {
		c.logger.Warn("Invalid client IP format",
			logger.NewField("client_ip", clientIP))
		return false
	}

	for _, ipNet := range c.ipNets {
		if ipNet.Contains(ip) {
			c.logger.Debug("Client IP is whitelisted",
				logger.NewField("client_ip", clientIP),
				logger.NewField("matched_range", ipNet.String()))
			return true
		}
	}

	c.logger.Debug("Client IP is not whitelisted",
		logger.NewField("client_ip", clientIP))
	return false
}

// CreateFromConfig 从配置创建白名单检查器
func CreateFromConfig(wafConfig config.WAFConfig, log logger.ILogger) *Checker {
	if !wafConfig.Whitelist.Enabled {
		log.Info("IP whitelist is disabled")
		return &Checker{
			ipNets: make([]*net.IPNet, 0),
			logger: log,
		}
	}

	if len(wafConfig.Whitelist.IPRanges) == 0 {
		log.Warn("IP whitelist enabled but no IP ranges configured")
		return &Checker{
			ipNets: make([]*net.IPNet, 0),
			logger: log,
		}
	}

	return NewChecker(wafConfig.Whitelist.IPRanges, log)
}
