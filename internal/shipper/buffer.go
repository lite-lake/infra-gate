package shipper

import "sync/atomic"

// Buffer 有界记录缓冲（内部PRD D7）：容量固定，满则丢新保旧 + 原子计数，
// 入队路径零阻塞、零外呼——代理转发主链路上的唯一交互点（Buffer.Ship）必须恒定 O(1)。
//
// F12.3（内部PRD §4.12.3）：叠加字节预算（默认 32MB）——条数容量之外，
// 超长字段记录同样占用内存，字节维度超限同样丢新保旧（CAS 预检 + 满时回滚）；
// flusher 消费时经 Release 扣减（Ship/Release 用同一估算函数保证守恒）。
type Buffer struct {
	ch      chan Record
	dropped atomic.Uint64 // 缓冲满（条数或字节预算）被丢弃的记录数（丢新保旧计数）
	bytes   atomic.Int64  // 当前缓冲内记录的估算字节总量
}

// NewBuffer 创建容量为 size 的有界缓冲；size<=0 时按 1 兜底（调用方应在配置层
// WithDefaults 后传入，此处防御性处理保证永不 panic）
func NewBuffer(size int) *Buffer {
	if size <= 0 {
		size = 1
	}
	return &Buffer{ch: make(chan Record, size)}
}

// Ship 非阻塞入队：条数满或字节预算超限时丢弃本条（丢新保旧）并原子计数，
// 任何情况下不阻塞调用方。该函数运行在请求 goroutine 上，禁止引入任何可能
// 阻塞的实现（PRD D7 硬约束）。字节预算 CAS 预检失败即回滚（不占用预算）。
func (b *Buffer) Ship(r Record) {
	approx := int64(recordApproxBytes(r))
	// CAS 预检：预算已满直接丢新（不经 channel，条数容量留给小记录）
	for {
		cur := b.bytes.Load()
		if cur+approx > maxBufferBytes {
			b.dropped.Add(1)
			return
		}
		if b.bytes.CompareAndSwap(cur, cur+approx) {
			break
		}
	}
	select {
	case b.ch <- r:
	default:
		b.bytes.Add(-approx) // 回滚：条数容量满，本条未入队
		b.dropped.Add(1)
	}
}

// Release 消费端扣减一条记录的估算字节（flusher 三处读 channel 点调用；
// 与 Ship 用同一 recordApproxBytes 保证守恒）
func (b *Buffer) Release(r Record) {
	b.bytes.Add(-int64(recordApproxBytes(r)))
}

// Chan 返回只读通道（flusher 消费端）
func (b *Buffer) Chan() <-chan Record {
	return b.ch
}

// Dropped 返回累计丢弃记录数（对账不变式观测点，PRD §1.2 目标 3）
func (b *Buffer) Dropped() uint64 {
	return b.dropped.Load()
}

// ApproxBytes 返回当前缓冲内记录的估算字节总量（观测点）
func (b *Buffer) ApproxBytes() int64 {
	return b.bytes.Load()
}
