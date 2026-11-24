package notification

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lite-lake/infra-gate/internal/deployinfo"
	"github.com/lite-lake/infra-gate/internal/infrastructs/endpoints"
	"github.com/lite-lake/infra-gate/internal/infrastructs/logger"
	"github.com/lite-lake/infra-gate/internal/netutil"
)

// NotificationConfig 通知配置
type NotificationConfig struct {
	Enabled bool             `yaml:"enabled"`
	URL     endpoints.Config `yaml:"url"`
	Timeout time.Duration    `yaml:"timeout"`
}

// eventInfo 事件元信息
type eventInfo struct {
	Icon  string
	Label string
}

// 事件映射表
var eventMap = map[string]eventInfo{
	"starting":     {Icon: "\U0001f680", Label: "服务启动中"},
	"started":      {Icon: "\u2705", Label: "启动成功"},
	"start_failed": {Icon: "\u274c", Label: "启动失败"},
	"stopping":     {Icon: "\U0001f6d1", Label: "正在停止"},
	"stopped":      {Icon: "\U0001f4f4", Label: "已停止"},
	// 证书 Reconciler 事件（内部PRD §7.5）：cert_ready 仅远程拉取成功路径
	//（缓存命中静默）；cert_failed 首次失败 + 每连续失败 12 次重发
	"cert_ready":  {Icon: "\U0001f510", Label: "证书就绪"},
	"cert_failed": {Icon: "\u26a0\ufe0f", Label: "证书拉取失败"},
	// 监听器就绪与 WAF/CRS 降级事件（内部PRD §5.6）：
	// ready 由 server 在全端口实际绑定后触发；waf_crs_degraded 为高优语义
	//（WAF 未启用、流量无防护）；waf_crs_recovered 注明新规则下次重启生效
	"ready":                  {Icon: "\u2705", Label: "网关就绪"},
	"waf_crs_degraded":       {Icon: "\U0001f6a8", Label: "WAF 降级运行"},
	"waf_crs_stale_start":    {Icon: "\u26a0\ufe0f", Label: "WAF 规则过期启动"},
	"waf_crs_recovered":      {Icon: "\U0001f7e2", Label: "CRS 已恢复"},
	"waf_crs_refresh_failed": {Icon: "\u26a0\ufe0f", Label: "CRS 后台刷新失败"},
	// F6.5（内部PRD §4.6.5）：证书续期连续失败限频告警（updater 经
	// Manager.SetNotifier 级联上抛，首次 + 每 12 次）；cert_expired 为最高优
	//（已过期仍在服务，可用性优先降级状态的显式暴露）
	"cert_renewal_failed": {Icon: "⚠️", Label: "证书续期失败"},
	"cert_expired":        {Icon: "🚨", Label: "证书已过期"},
	// F13.2（内部PRD §4.13.2）：admin 只读 API 认证失败锁定告警
	// F10.3（内部PRD §4.10.3）：CRS 缓存疑似篡改（hash 在场不匹配/被删）
	// 高优告警——本地写权限者可换规则运行，须立即人工介入
	// F9.4（内部PRD §4.9.4）：黑名单表龄超阈（数据源长时间未成功刷新）
	"blacklist_stale":        {Icon: "⚠️", Label: "黑名单数据过期"},
	"waf_crs_cache_tampered": {Icon: "\U0001f6a8", Label: "CRS 缓存疑似篡改"},
	"admin_api_lockout":      {Icon: "🔒", Label: "Admin API 锁定"}, // 密码门登录失败锁定全局告警（M3，内部PRD §5）：IP 达到 host 配置的
	// 锁定阈值时由 auth Manager 触发，每个锁定会话至多一条（跳变沿去重，见
	// auth.Manager.notifyLockout）
	"auth_lockout": {Icon: "\U0001f512", Label: "登录失败锁定"},
}

// Notifier 生命周期事件通知器。
//
// F1e 队列化（内部PRD §4.1.7）：SendNotification 非阻塞入队（cap 64，
// 丢新保旧 + dropped 计数 + 采样 Warn），单 worker 顺序发送——修复「每次调用
// 一个 goroutine」的通知洪峰无界并发问题（告警风暴自身打爆网关）。
type Notifier struct {
	config   *NotificationConfig
	logger   logger.ILogger
	appName  string
	hostname string
	client   *http.Client

	// queue 待发通知队列（有界，丢新保旧）；job 在 worker 内构建正文
	queue chan *notifyJob
	// dropped 丢弃计数（队列满时丢新）
	dropped uint64
	// busy worker 正在发送的标志（Sync 判空用；非原子精度要求，仅观测排空）
	busy atomic.Bool
	// workerOnce worker 单次启动
	workerOnce sync.Once
	// syncMu 串行化 Sync 调用（防多次 Sync 并发等待）
	syncMu sync.Mutex
}

// notifyJob 队列条目：事件 + 详情（正文在 worker 内构建）
type notifyJob struct {
	event   string
	details map[string]string
}

// notifyQueueCapacity 队列容量（F1e：cap 64，shipper buffer 同款丢新保旧）
const notifyQueueCapacity = 64

// notifyDrainBudget Sync() 排空预算：最长等待时长（保留「进程退出前关键通知
// 不丢」的既有语义；超时后放弃剩余队列——queue 是尽力而为通道）
const notifyDrainBudget = 10 * time.Second

// notifyDropLogEvery 丢弃采样 Warn 间隔（每丢 N 条记一条，首条必记）
const notifyDropLogEvery = 16

// NewNotifier 创建通知器实例
func NewNotifier(cfg NotificationConfig, log logger.ILogger, appName string) *Notifier {
	hostname, _ := os.Hostname()

	var client *http.Client
	if cfg.Enabled && !cfg.URL.IsEmpty() {
		timeout := cfg.Timeout
		if timeout == 0 {
			timeout = 5 * time.Second
		}
		client = &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				DialContext: (&net.Dialer{
					Timeout:   3 * time.Second,
					KeepAlive: 30 * time.Second,
				}).DialContext,
				TLSHandshakeTimeout: 3 * time.Second,
			},
		}
	}

	n := &Notifier{
		config:   &cfg,
		logger:   log,
		appName:  appName,
		hostname: hostname,
		client:   client,
	}
	if client != nil {
		n.queue = make(chan *notifyJob, notifyQueueCapacity)
		n.startWorker()
	}
	return n
}

// startWorker 启动单发送 worker（NewNotifier 时一次；进程生命周期常驻）
func (n *Notifier) startWorker() {
	n.workerOnce.Do(func() {
		go func() {
			for job := range n.queue {
				n.busy.Store(true)
				content := n.buildTextContent(job.event, job.details)
				payload := n.buildWeComTextPayload(content)
				n.doSend(payload)
				n.busy.Store(false)
			}
		}()
	})
}

// IsEnabled 是否启用通知
func (n *Notifier) IsEnabled() bool {
	return n.config != nil && n.config.Enabled && !n.config.URL.IsEmpty()
}

// SendNotification 发送生命周期事件通知（F1e：非阻塞入队）。
// event: 事件类型 (starting, started, start_failed, stopping, stopped 等)
// details: 附加信息键值对
// 队列满时丢新保旧（旧事件保留，新事件丢弃 + 计数 + 采样 Warn），返回 nil
// （尽力而为通道，调用方无需处理投递错误——原 goroutine 模式同样不感知失败）。
func (n *Notifier) SendNotification(event string, details map[string]string) error {
	if !n.IsEnabled() {
		return nil
	}
	if n.client == nil || n.queue == nil {
		return fmt.Errorf("notification client not initialized")
	}

	job := &notifyJob{event: event, details: details}
	select {
	case n.queue <- job:
	default:
		// 丢新保旧：洪峰下保留最早事件（startup 失败类关键通知优先送出）
		dropped := atomic.AddUint64(&n.dropped, 1)
		if dropped == 1 || dropped%notifyDropLogEvery == 0 {
			n.logger.Warn("Notification queue full, dropping NEW event (keep-old)",
				logger.NewField("event", event),
				logger.NewField("dropped_total", dropped),
				logger.NewField("queue_capacity", notifyQueueCapacity))
		}
	}
	return nil
}

// Dropped 返回队列满丢弃的累计条数（观测/测试用）
func (n *Notifier) Dropped() uint64 {
	return atomic.LoadUint64(&n.dropped)
}

// Sync 等待队列排空（最长 notifyDrainBudget）。
// 在进程退出前调用，确保 stopped/start_failed 等关键通知尽量不丢失；
// 超预算后放弃剩余队列（尽力而为语义，与队列化前的 wg.Wait 无限等待相比
// 增加了上界，防 webhook 挂死拖住退出）。
func (n *Notifier) Sync() {
	n.syncMu.Lock()
	defer n.syncMu.Unlock()
	if n.queue == nil {
		return
	}
	deadline := time.Now().Add(notifyDrainBudget)
	for time.Now().Before(deadline) {
		if len(n.queue) == 0 && !n.busy.Load() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// buildTextContent 构建消息文本
func (n *Notifier) buildTextContent(event string, details map[string]string) string {
	info, ok := eventMap[event]
	if !ok {
		info = eventInfo{Icon: "\u2753", Label: event}
	}

	msg := fmt.Sprintf("[%s %s] %s", info.Icon, info.Label, n.appName)

	// 构建版本（LITE_BUILD_ID 环境变量，由 CI/CD 在镜像构建时注入）
	if buildID := os.Getenv("LITE_BUILD_ID"); buildID != "" {
		msg += fmt.Sprintf(" [%s]", buildID)
	}

	if n.hostname != "" {
		msg += fmt.Sprintf("\n主机: %s", n.hostname)
	}

	for key, value := range details {
		if value != "" {
			msg += fmt.Sprintf("\n%s: %s", key, value)
		}
	}

	// 追加部署环境信息（DEPLOY_ 环境变量）
	di := deployinfo.Get()
	if di.IsSet() {
		if di.DeployEnv != "" {
			msg += fmt.Sprintf("\n部署环境: %s", di.DeployEnv)
		}
		if di.DeployZone != "" {
			msg += fmt.Sprintf("\n部署网区: %s", di.DeployZone)
		}
		if di.DeployServer != "" {
			msg += fmt.Sprintf("\n部署主机: %s", di.DeployServer)
		}
		if di.DeployService != "" {
			msg += fmt.Sprintf("\n部署服务: %s", di.DeployService)
		}
	}

	msg += fmt.Sprintf("\n时间: %s", time.Now().Format("2006-01-02 15:04:05"))

	return msg
}

// buildWeComTextPayload 构建企业微信群机器人消息体
func (n *Notifier) buildWeComTextPayload(content string) map[string]interface{} {
	return map[string]interface{}{
		"msgtype": "text",
		"text": map[string]string{
			"content": content,
		},
	}
}

// doSend 异步发送 webhook 请求
// 支持多端点故障转移：随机选择一个 URL，失败后依次尝试其他 URL
func (n *Notifier) doSend(payload map[string]interface{}) {
	data, err := json.Marshal(payload)
	if err != nil {
		n.logger.Error("Failed to marshal notification payload",
			logger.NewField("error", err))
		return
	}

	picker := n.config.URL.NewPicker()

	var lastErr error
	for {
		url, _, ok := picker.Next()
		if !ok {
			break
		}

		resp, err := n.client.Post(url, "application/json", bytes.NewBuffer(data))
		if err != nil {
			n.logger.Warn("Failed to send notification, trying next URL",
				logger.NewField("url", netutil.RedactURL(url)),
				logger.NewField("error", err))
			lastErr = err
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			n.logger.Warn("Notification returned non-200 status, trying next URL",
				logger.NewField("url", netutil.RedactURL(url)),
				logger.NewField("status", resp.StatusCode))
			lastErr = fmt.Errorf("notification returned status %d", resp.StatusCode)
			resp.Body.Close()
			continue
		}

		n.logger.Debug("Notification sent successfully",
			logger.NewField("url", netutil.RedactURL(url)))
		return
	}

	if lastErr != nil {
		n.logger.Error("Failed to send notification after trying all URLs",
			logger.NewField("url_count", n.config.URL.Len()),
			logger.NewField("last_error", lastErr))
	}
}
