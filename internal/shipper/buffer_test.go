package shipper

import "testing"

func makeRecord(id int) Record {
	return Record{Method: "GET", Path: "/p", Ts: int64(id)}
}

// TestBufferShipAndReceive 未满容量时先进先出
func TestBufferShipAndReceive(t *testing.T) {
	b := NewBuffer(4)
	for i := 0; i < 4; i++ {
		b.Ship(makeRecord(i))
	}
	if b.Dropped() != 0 {
		t.Errorf("Dropped() = %d, want 0 (no overflow)", b.Dropped())
	}
	for i := 0; i < 4; i++ {
		r := <-b.Chan()
		if r.Ts != int64(i) {
			t.Errorf("record[%d].Ts = %d, want %d (FIFO)", i, r.Ts, i)
		}
	}
}

// TestBufferDropNewKeepOld 缓冲满丢新保旧 + 计数正确（PRD D7）
func TestBufferDropNewKeepOld(t *testing.T) {
	b := NewBuffer(4)
	for i := 0; i < 10; i++ {
		b.Ship(makeRecord(i))
	}
	if got := b.Dropped(); got != 6 {
		t.Errorf("Dropped() = %d, want 6 (10 shipped, capacity 4)", got)
	}
	// 保旧：收到的应是最先入队的 0..3
	for i := 0; i < 4; i++ {
		r := <-b.Chan()
		if r.Ts != int64(i) {
			t.Errorf("record Ts = %d, want %d (drop-new-keep-old)", r.Ts, i)
		}
	}
	// 再收应无残留
	select {
	case r := <-b.Chan():
		t.Errorf("unexpected residual record %+v", r)
	default:
	}
}

// TestBufferNeverBlocks 高频超量投递绝不阻塞（隐式断言：测试正常完成即为通过）
func TestBufferNeverBlocks(t *testing.T) {
	b := NewBuffer(1)
	const total = 1000
	for i := 0; i < total; i++ {
		b.Ship(makeRecord(i))
	}
	if got := b.Dropped(); got != total-1 {
		t.Errorf("Dropped() = %d, want %d (capacity 1)", got, total-1)
	}
}

// TestBufferDefensiveCapacity 非法容量防御性兜底不 panic
func TestBufferDefensiveCapacity(t *testing.T) {
	for _, size := range []int{0, -1} {
		b := NewBuffer(size)
		b.Ship(makeRecord(1))
		if r := <-b.Chan(); r.Ts != 1 {
			t.Errorf("NewBuffer(%d) should accept one record, got %+v", size, r)
		}
	}
}
