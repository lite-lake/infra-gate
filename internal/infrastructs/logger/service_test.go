package logger

// L4 单测（内部PRD §1.3，出口标准⑤）：msg 与字段值中的 C0 控制字符
//（\r \n \t 等）替换为空格——含 %0A 的用户可控字段（path/host）不得伪造日志行；
// 输出恒为单行。消毒收敛在 log() 单点（控制台与文件输出共享）。

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
)

// newBufferLogger 构造控制台输出进 buffer 的 logger（同包直构，注入可断言 writer）
func newBufferLogger(buf *bytes.Buffer) *loggerService {
	return &loggerService{
		config: LoggerConfig{
			Level:         InfoLevel,
			EnableConsole: true,
			EnableFile:    false,
			EnableColor:   false,
		},
		consoleWriter: buf,
		fileWriters:   make(map[LogLevel]*os.File),
		fileMu:        &sync.Mutex{},
		fields:        make(map[string]interface{}),
		ctx:           context.Background(),
	}
}

// sanitizeLogText 表驱动：\t \r \n、其余 C0、DEL → 空格；干净文本零改动（快速路径）
func TestSanitizeLogText(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"clean text untouched", "/api/data?id=1", "/api/data?id=1"},
		{"literal %0A stays", "/a%0AX-Injected: true", "/a%0AX-Injected: true"},
		{"newline becomes space", "line1\nline2", "line1 line2"},
		{"CR becomes space", "a\rb", "a b"},
		{"TAB becomes space", "a\tb", "a b"},
		{"mixed CRLF+TAB collapsed", "x\r\n\ty", "x   y"},
		{"other C0 controls become space", "a\x00b\x01c\x1fd", "a b c d"},
		{"DEL becomes space", "a\x7fb", "a b"},
		{"multi-byte text preserved", "路径/文件名?x=1", "路径/文件名?x=1"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := sanitizeLogText(tc.in); got != tc.want {
				t.Errorf("sanitizeLogText(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// 含 %0A（真实换字节）的字段值与 msg 写日志后输出单行：行数断言（出口标准⑤）
func TestLogControlCharsSingleLine(t *testing.T) {
	tests := []struct {
		name   string
		msg    string
		fields []Field
	}{
		{
			name:   "msg with raw newline",
			msg:    "request done\nX-Injected: forged log line",
			fields: nil,
		},
		{
			name:   "path field with %0A decoded newline",
			msg:    "request",
			fields: []Field{NewField("path", "/a%0AX-Injected\r\ntrue")},
		},
		{
			name:   "host field with CRLF+TAB",
			msg:    "request",
			fields: []Field{NewField("host", "evil.test\r\n\tBAD")},
		},
		{
			name:   "error value with newline",
			msg:    "upstream failed",
			fields: []Field{NewField("error", errors.New("dial failed\nat step 2"))},
		},
		{
			name:   "msg and fields both injected",
			msg:    "a\nb",
			fields: []Field{NewField("path", "/x\ny"), NewField("host", "h\ni")},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			l := newBufferLogger(&buf)
			l.Info(tc.msg, tc.fields...)

			out := buf.String()
			// Fprintln 恰好一个收尾换行：输出必须单行
			if n := strings.Count(out, "\n"); n != 1 {
				t.Errorf("log output has %d newlines, want exactly 1 (trailing): %q", n, out)
			}
			if strings.ContainsAny(out, "\r\t") {
				t.Errorf("log output contains raw CR/TAB: %q", out)
			}
			for i := 0; i < len(out)-1; i++ {
				if out[i] < 0x20 {
					t.Errorf("log output contains C0 control byte 0x%02X before trailing newline: %q", out[i], out)
					break
				}
			}
		})
	}
}

// 干净内容正常输出（回归对照）：消毒不丢内容、不改变普通日志形态
func TestLogCleanContentUnaffected(t *testing.T) {
	var buf bytes.Buffer
	l := newBufferLogger(&buf)
	l.Info("request handled",
		NewField("path", "/api/data?id=1"),
		NewField("host", "demo.example.com"))

	out := buf.String()
	if !strings.Contains(out, "request handled") ||
		!strings.Contains(out, "path=/api/data?id=1") ||
		!strings.Contains(out, "host=demo.example.com") {
		t.Errorf("clean log content altered: %q", out)
	}
	if strings.Count(out, "\n") != 1 {
		t.Errorf("clean log must stay single line, got %q", out)
	}
}

// WithField 全局字段同样消毒（收敛点在 log()，覆盖 With* 链路的存量字段）
func TestWithFieldStoredValueSanitized(t *testing.T) {
	var buf bytes.Buffer
	l := newBufferLogger(&buf).WithField("path", "/x\ninjected")
	l.Info("done")

	out := buf.String()
	if strings.Count(out, "\n") != 1 {
		t.Errorf("stored field injection must be sanitized, got %q", out)
	}
	if !strings.Contains(out, "path=/x injected") {
		t.Errorf("sanitized stored field should contain space replacement, got %q", out)
	}
}

// 快速路径零开销形态：不含控制字符的字符串返回原串（无分配）——直接断言等值即可
func TestSanitizeLogTextFastPath(t *testing.T) {
	s := strings.Repeat("/api/normal/path", 100)
	if got := sanitizeLogText(s); got != s {
		t.Errorf("fast path must return identical string")
	}
	// 慢路径长度守恒（1:1 替换）
	in := "a\nb\rc\td\x7fe\x01f"
	if got := sanitizeLogText(in); len(got) != len(in) {
		t.Errorf("sanitize must be length-preserving: in=%d out=%d", len(in), len(got))
	}
}
