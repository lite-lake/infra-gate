package shipper

import (
	"context"
	"fmt"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lite-lake/infra-gate/internal/config"
	"github.com/lite-lake/infra-gate/internal/infrastructs/logger"
)

// flusher 生命周期常量
const (
	// stopDrainTimeout Stop 后清空缓冲的预算窗口（超时放弃剩余记录，PRD §4.4.1 优雅收尾）
	stopDrainTimeout = 2 * time.Second
	// stopWaitTimeout Stop 等待 flusher 退出的上限（最后一批可能仍在退避重试，超时放弃）
	stopWaitTimeout = 10 * time.Second
)

// classifyFn 打标函数注入点：Ship 在 recover 作用域内调用；单测可替换为 panic 实现，
// 验证打标异常不外抛、不影响调用方（PRD D7 recover 包裹硬约束）。
var classifyFn = Classify

// Shipper 访问日志旁路发射器（内部PRD §4.4.1）：
// 记录组装（server 侧 hook）→ req_class 打标 → 有界缓冲 → flusher 批量外送。
//
// 纯旁路组件（D7 硬约束）：
//   - Ship 非阻塞入队，recover 全包裹，任何 panic 等效于 shipper 不存在；
//   - flusher 独立 goroutine，发送失败退避重试后丢弃本批；
//   - 代理转发路径上零同步外呼（唯一交互是 channel 投递）。
type Shipper struct {
	nodeName      string
	batchSize     int
	flushInterval time.Duration
	sampleRatio   float64
	buffer        *Buffer
	client        *Client
	log           logger.ILogger

	stopCh   chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup

	sentRecords atomic.Uint64 // 已提交发送的记录数（对账不变式观测点，PRD §1.2 目标 3）
	// running flusher 存活信号（内部PRD §6.1 进程面哨兵）：Start 置 true，
	// flushLoop 退出时置 false。端口照常服务但 flusher 意外死亡时快照暴露 running=false。
	running atomic.Bool
	// normalizedDropped F12（内部PRD §4.12）：归一化折半兜底后仍超单条
	// 4KB 硬上限被丢弃的记录数（Snapshot 透出 normalized_dropped）
	normalizedDropped atomic.Uint64
	// lastSuccessSendAt 最近一次成功发送的 unix 毫秒时间戳（0 = 从未成功发送，
	// Snapshot 输出 null）。仅 Send 返回 nil 时写入，失败不写。
	lastSuccessSendAt atomic.Int64
}

// New 创建 Shipper（不启动后台任务；Start 前 Ship 安全——记录进缓冲等待消费）。
// 配置先经 WithDefaults 合并缺省值。
func New(cfg config.ShipperConfig, log logger.ILogger) *Shipper {
	eff := cfg.WithDefaults()
	return &Shipper{
		nodeName:      eff.NodeName,
		batchSize:     eff.BatchSize,
		flushInterval: eff.FlushInterval,
		sampleRatio:   eff.FailureSampleLogRatio,
		buffer:        NewBuffer(eff.BufferSize),
		client:        NewClient(eff.Endpoint, eff.SharedSecret, eff.FailureSampleLogRatio, log),
		log:           log,
		stopCh:        make(chan struct{}),
	}
}

// Start 启动 flusher goroutine（正常仅在启动路径调用一次）
func (s *Shipper) Start() {
	s.running.Store(true)
	s.wg.Add(1)
	go s.flushLoop()
}

// Ship 记录入缓冲入口（server 侧 hook 唯一调用点）：
// 打标在 recover 作用域内完成（打标 panic 只丢本条 + 采样日志，绝不外抛），
// 随后非阻塞入队（满则丢新保旧 + 计数）。任何路径绝不阻塞调用方（PRD D7）。
func (s *Shipper) Ship(rec Record) {
	defer func() {
		if r := recover(); r != nil {
			// D7：任何 panic 等效于 shipper 不存在；采样日志不含记录内容（含 client_ip）
			if s.sampled() {
				s.log.Warn("Tracker shipper panic suppressed",
					logger.NewField("node", s.nodeName),
					logger.NewField("panic", fmt.Sprint(r)))
			}
		}
	}()

	// F12（内部PRD §4.12.1/4.12.2）：classifyFn 之前单点归一化——字段
	// 上限截断 + 复制（防钉住 ~1MB 请求行分配）+ 4KB 投影硬保证（折半兜底）。
	// 分类只用前缀/后缀，截断不影响打标。折半后仍超限 → 丢弃计数（不毒杀整批）
	if !NormalizeRecord(&rec) {
		s.normalizedDropped.Add(1)
		if s.sampled() {
			s.log.Warn("Tracker shipper record dropped: exceeds 4KB contract after normalization",
				logger.NewField("node", s.nodeName))
		}
		return
	}
	rec.ReqClass = classifyFn(rec.Path, rec.ContentType)
	if rec.Ts == 0 {
		rec.Ts = nowUnixMilli()
	}
	s.buffer.Ship(rec)
}

// Stop 优雅收尾：通知 flusher 尽力清空缓冲发送（stopDrainTimeout 预算），
// 超时放弃剩余记录。幂等（sync.Once）。缓冲 channel 不关闭（close 后仍可能有
// 在途请求 Ship 入队，向已关闭 channel 发送会 panic），残留记录随进程退出放弃。
func (s *Shipper) Stop() {
	s.stopOnce.Do(func() {
		close(s.stopCh)
	})
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(stopWaitTimeout):
		s.log.Warn("Tracker shipper stop timed out, abandoning remaining buffer",
			logger.NewField("node", s.nodeName))
	}
}

// SentRecords 返回已提交发送的记录总数（对账观测点；成败都计，"已提交发送"语义）
func (s *Shipper) SentRecords() uint64 {
	return s.sentRecords.Load()
}

// DroppedRecords 返回缓冲满丢弃的记录总数（对账观测点）
func (s *Shipper) DroppedRecords() uint64 {
	return s.buffer.Dropped()
}

// PendingRecords 返回缓冲内待发送的记录条数（状态快照观测点）
func (s *Shipper) PendingRecords() int {
	return len(s.buffer.Chan())
}

// DroppedTotal 返回累计丢弃记录总数 = 缓冲满丢弃（丢新保旧）+ 发送失败丢弃
// （重试耗尽后弃批，Client 侧计数）。状态快照观测点，内部PRD §6.1。
func (s *Shipper) DroppedTotal() uint64 {
	return s.buffer.Dropped() + s.client.DroppedRecords()
}

// sampled 按采样比例判定是否记降级日志（hook panic 日志同样采样，防刷屏）
func (s *Shipper) sampled() bool {
	return s.sampleRatio > 0 && rand.Float64() < s.sampleRatio
}

// LogSampled 采样判定（供 server 侧 hook 的降级日志复用同一采样比例）
func (s *Shipper) LogSampled() bool {
	return s.sampled()
}

// flushLoop 消费循环：凑满 batch_size 或每 flush_interval 触发批量发送；
// Stop 后进入有预算的清空收尾。仅在 Start 的 goroutine 上运行。
func (s *Shipper) flushLoop() {
	defer s.wg.Done()
	// 进程面哨兵（内部PRD §6.1）：flusher 任何路径退出（含 Stop 收尾）
	// 都撤销 running，快照可见 flusher 不再消费
	defer s.running.Store(false)
	ticker := time.NewTicker(s.flushInterval)
	defer ticker.Stop()

	pending := make([]Record, 0, s.batchSize)
	// F12.4：批量投影字节预算（768KB 提前 flush）；F12.3：消费即扣减缓冲字节预算
	pendingBytes := 0
	consume := func(r Record) {
		pending = append(pending, r)
		pendingBytes += projectedRecordSize(&r)
		s.buffer.Release(r)
	}
	flush := func() {
		if len(pending) == 0 {
			return
		}
		// 发送失败由 Client 内部计数/采样日志，不影响循环继续消费；
		// 仅成功时更新 lastSuccessSendAt（失败不写，快照 null = 从未成功/长期失败）
		if err := s.client.Send(context.Background(), NewEnvelope(s.nodeName, pending)); err == nil {
			s.lastSuccessSendAt.Store(nowUnixMilli())
		}
		s.sentRecords.Add(uint64(len(pending)))
		pending = make([]Record, 0, s.batchSize)
		pendingBytes = 0
	}

	for {
		select {
		case <-s.stopCh:
			// 优雅收尾：预算窗口内尽力清空缓冲发送，超时放弃剩余（PRD §4.4.1）
			deadline := time.After(stopDrainTimeout)
			for {
				select {
				case r := <-s.buffer.Chan():
					consume(r)
					pending = s.appendAvailable(pending)
					if len(pending) >= s.batchSize {
						flush()
					}
				case <-deadline:
					flush()
					return
				default:
					// 缓冲已空：发送余量后退出。收尾语义为"尽力"——此刻仍可能在途
					// 请求随后入队的少量记录不等待，随进程退出放弃
					flush()
					return
				}
			}
		case r := <-s.buffer.Chan():
			consume(r)
			pending = s.appendAvailable(pending)
			// F12.4：条数或投影字节任一达阈即提前 flush（硬编码 768KB，防炸 1MB 批契约）
			if len(pending) >= s.batchSize || pendingBytes >= maxBatchProjectedBytes {
				flush()
				ticker.Reset(s.flushInterval)
			}
		case <-ticker.C:
			flush()
		}
	}
}

// appendAvailable 非阻塞补齐 pending 至 batch_size（通道空即返回，绝不等待）
func (s *Shipper) appendAvailable(pending []Record) []Record {
	for len(pending) < s.batchSize {
		select {
		case r := <-s.buffer.Chan():
			pending = append(pending, r)
			s.buffer.Release(r) // F12.3：消费扣减
		default:
			return pending
		}
	}
	return pending
}

// StatusSnapshot shipper 状态快照（admin 只读端点响应体，内部PRD §6.1）。
// C2 网关通道变暗哨兵：进程面自报真相，供 Uptime Kuma json-query 监控断言
// （enabled=false 的"组件消失"是有效状态而非错误——端点仍 200，由监控断言失败产生告警，
// 避免 404/500 混入基础设施故障噪音）。
type StatusSnapshot struct {
	Enabled      bool   `json:"enabled"`
	Running      bool   `json:"running"`
	NodeName     string `json:"node_name"`
	SentTotal    uint64 `json:"sent_total"`
	DroppedTotal uint64 `json:"dropped_total"`
	// NormalizedDropped F12：归一化后仍超 4KB 契约被丢弃的记录数
	//（对 Uptime Kuma json-query 向后兼容：additive 字段）
	NormalizedDropped uint64 `json:"normalized_dropped"`
	LastSuccessSendAt *int64 `json:"last_success_send_at"` // unix 毫秒；null=从未成功发送
	BufferPending     int    `json:"buffer_pending"`
}

// Snapshot 返回当前 shipper 状态快照（运行状态 + 发送/丢弃/缓冲计数）。
// LastSuccessSendAt 原子值为 0（从未成功发送）时输出 nil（JSON null）。
func (s *Shipper) Snapshot() StatusSnapshot {
	snap := StatusSnapshot{
		Enabled:           true,
		Running:           s.running.Load(),
		NodeName:          s.nodeName,
		SentTotal:         s.sentRecords.Load(),
		DroppedTotal:      s.DroppedTotal(),
		NormalizedDropped: s.normalizedDropped.Load(),
		BufferPending:     s.PendingRecords(),
	}
	if v := s.lastSuccessSendAt.Load(); v != 0 {
		snap.LastSuccessSendAt = &v
	}
	return snap
}

// DisabledStatusSnapshot 返回配置缺段/未启用（enabled=false）的全零快照：
// "组件消失"是有效状态不是错误，端点照常返回 200 + enabled:false，
// 由监控侧断言失败产生告警（内部PRD §6.1）。
func DisabledStatusSnapshot() StatusSnapshot {
	return StatusSnapshot{
		Enabled:           false,
		Running:           false,
		NodeName:          "",
		SentTotal:         0,
		DroppedTotal:      0,
		LastSuccessSendAt: nil,
		BufferPending:     0,
	}
}
