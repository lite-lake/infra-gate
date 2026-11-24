package logger

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// loggerService 日志服务实现
type loggerService struct {
	config        LoggerConfig
	consoleWriter io.Writer
	fileWriters   map[LogLevel]*os.File
	mu            sync.RWMutex
	fileMu        *sync.Mutex // 保护 fileWriters，With* 方法共享此指针
	fields        map[string]interface{}
	ctx           context.Context
}

// NewLogger 创建日志服务实例
func NewLogger(config LoggerConfig) ILogger {
	return &loggerService{
		config:        config,
		consoleWriter: os.Stdout,
		fileWriters:   make(map[LogLevel]*os.File),
		fileMu:        &sync.Mutex{},
		fields:        make(map[string]interface{}),
		ctx:           context.Background(),
	}
}

// GetDefaultLogger 获取默认日志服务实例
func GetDefaultLogger() ILogger {
	config := LoggerConfig{
		Level:         InfoLevel,
		EnableConsole: true,
		EnableFile:    false,
		EnableColor:   true,
	}
	return NewLogger(config)
}

// Debug 记录调试信息
func (l *loggerService) Debug(msg string, fields ...Field) {
	l.log(DebugLevel, msg, fields...)
}

// Info 记录一般信息
func (l *loggerService) Info(msg string, fields ...Field) {
	l.log(InfoLevel, msg, fields...)
}

// Warn 记录警告信息
func (l *loggerService) Warn(msg string, fields ...Field) {
	l.log(WarnLevel, msg, fields...)
}

// Error 记录错误信息
func (l *loggerService) Error(msg string, fields ...Field) {
	l.log(ErrorLevel, msg, fields...)
}

// Fatal 记录致命错误信息并退出程序
func (l *loggerService) Fatal(msg string, fields ...Field) {
	l.log(FatalLevel, msg, fields...)
	os.Exit(1)
}

// WithContext 添加上下文信息
// F12.6（内部PRD §4.12.6）：With* 系列从不改写 l.fields/l.fileWriters
// （引用不可变：fileWriters map 本体仅 Close 在 fileMu 下改写，此处读引用），
// 写锁竞争在全部 With* 热路径调用点一次性消除
func (l *loggerService) WithContext(ctx context.Context) ILogger {
	l.mu.RLock()
	defer l.mu.RUnlock()

	// F12.6：fileWriters 为引用不可变（map 本体仅 Close 持 fileMu 改写），读引用无需加锁
	fileWriters := l.fileWriters

	newLogger := &loggerService{
		config:        l.config,
		consoleWriter: l.consoleWriter,
		fileWriters:   fileWriters,
		fileMu:        l.fileMu,
		fields:        make(map[string]interface{}),
		ctx:           ctx,
	}

	// 复制当前字段
	for k, v := range l.fields {
		newLogger.fields[k] = v
	}

	return newLogger
}

// WithField 添加字段
func (l *loggerService) WithField(key string, value interface{}) ILogger {
	l.mu.RLock()
	defer l.mu.RUnlock()

	// F12.6：fileWriters 为引用不可变（map 本体仅 Close 持 fileMu 改写），读引用无需加锁
	fileWriters := l.fileWriters

	newLogger := &loggerService{
		config:        l.config,
		consoleWriter: l.consoleWriter,
		fileWriters:   fileWriters,
		fileMu:        l.fileMu,
		fields:        make(map[string]interface{}),
		ctx:           l.ctx,
	}

	// 复制当前字段
	for k, v := range l.fields {
		newLogger.fields[k] = v
	}

	// 添加新字段
	newLogger.fields[key] = value

	return newLogger
}

// WithFields 添加多个字段
func (l *loggerService) WithFields(fields map[string]interface{}) ILogger {
	l.mu.RLock()
	defer l.mu.RUnlock()

	// F12.6：fileWriters 为引用不可变（map 本体仅 Close 持 fileMu 改写），读引用无需加锁
	fileWriters := l.fileWriters

	newLogger := &loggerService{
		config:        l.config,
		consoleWriter: l.consoleWriter,
		fileWriters:   fileWriters,
		fileMu:        l.fileMu,
		fields:        make(map[string]interface{}),
		ctx:           l.ctx,
	}

	// 复制当前字段
	for k, v := range l.fields {
		newLogger.fields[k] = v
	}

	// 添加新字段
	for k, v := range fields {
		newLogger.fields[k] = v
	}

	return newLogger
}

// WithTraceId 添加TraceId
func (l *loggerService) WithTraceId(traceId string) ILogger {
	l.mu.RLock()
	defer l.mu.RUnlock()

	// F12.6：fileWriters 为引用不可变（map 本体仅 Close 持 fileMu 改写），读引用无需加锁
	fileWriters := l.fileWriters

	newLogger := &loggerService{
		config:        l.config,
		consoleWriter: l.consoleWriter,
		fileWriters:   fileWriters,
		fileMu:        l.fileMu,
		fields:        make(map[string]interface{}),
		ctx:           l.ctx,
	}

	// 复制当前字段
	for k, v := range l.fields {
		newLogger.fields[k] = v
	}

	// 添加TraceId字段
	if traceId != "" {
		newLogger.fields["trace_id"] = traceId
	}

	return newLogger
}

// SetLevel 设置日志级别
func (l *loggerService) SetLevel(level LogLevel) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.config.Level = level
}

// GetLevel 获取当前日志级别
func (l *loggerService) GetLevel() LogLevel {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.config.Level
}

// Close 关闭日志服务，释放资源
func (l *loggerService) Close() error {
	l.fileMu.Lock()
	defer l.fileMu.Unlock()

	for level, writer := range l.fileWriters {
		if err := writer.Close(); err != nil {
			return fmt.Errorf("关闭 %s 日志文件失败: %w", level.String(), err)
		}
		delete(l.fileWriters, level)
	}

	return nil
}

// log 核心日志记录方法
func (l *loggerService) log(level LogLevel, msg string, fields ...Field) {
	// 持读锁保护对 config 和 fields 的并发读取
	// SetLevel/With* 等方法在写锁下修改这些字段
	l.mu.RLock()
	if level < l.config.Level {
		l.mu.RUnlock()
		return
	}

	// 获取调用者信息
	_, file, line, ok := runtime.Caller(2)
	caller := "unknown"
	if ok {
		caller = fmt.Sprintf("%s:%d", filepath.Base(file), line)
	}

	// 构建日志条目
	entry := LogEntry{
		Timestamp: time.Now().Format("2006-01-02 15:04:05.000"),
		Level:     level.String(),
		Message:   sanitizeLogText(msg),
		Caller:    caller,
		Fields:    make(map[string]interface{}),
	}

	// 添加全局字段（在 RLock 下安全读取）
	for k, v := range l.fields {
		entry.Fields[k] = sanitizeLogValue(v)
	}

	enableConsole := l.config.EnableConsole
	enableFile := l.config.EnableFile
	l.mu.RUnlock()

	// 添加临时字段（此时已释放锁，fields 是调用方传入的）
	for _, field := range fields {
		entry.Fields[field.Key] = sanitizeLogValue(field.Value)
	}

	// 输出到控制台
	if enableConsole {
		l.writeToConsole(entry)
	}

	// 输出到文件
	if enableFile {
		l.writeToFile(entry)
	}
}

// sanitizeLogValue 对字段值做控制字符消毒（L4）：string/error 两类载体转字符串后
// 替换控制字符，其余类型原样返回（数字/布尔无注入面）。error 转 Error() 字符串与
// 输出层 fmt %v 的呈现一致，不改变最终文本
func sanitizeLogValue(v interface{}) interface{} {
	switch tv := v.(type) {
	case string:
		return sanitizeLogText(tv)
	case error:
		return sanitizeLogText(tv.Error())
	default:
		return v
	}
}

// sanitizeLogText 将文本中的 C0 控制字符（\t \r \n 等 0x00-0x1F）与 DEL（0x7F）
// 替换为空格（L4，内部PRD §1.3）：用户可控的 path/host 等字段含 %0A 时
// 不得伪造日志行。单行输出是日志进入采集/告警管道后一切行级解析的前提。
// 快速路径：不含控制字符时零分配返回原串——高频访问日志的绝大多数行只付出一次
// 线性扫描（O(len) 纯比较，无内存操作）。
// maxLogValueLen F12.5（内部PRD §4.12.5）：单条日志字段值的全局字节兜底
// （8KB；WAF 既有 4096×4 预览不被二次截断——其截断在先且更小）
const maxLogValueLen = 8 << 10

func sanitizeLogText(s string) string {
	// F12.5：单条字段 8KB 全局兜底（超长 URL/UA 等不再整条进日志行）
	if len(s) > maxLogValueLen {
		end := maxLogValueLen
		for end > 0 && !utf8.RuneStart(s[end]) {
			end--
		}
		s = s[:end]
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7F {
			return sanitizeLogTextSlow(s)
		}
	}
	return s
}

// sanitizeLogTextSlow 含控制字符时的替换路径（已被快速路径确认至少命中一处）
func sanitizeLogTextSlow(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 || c == 0x7F {
			b.WriteByte(' ')
		} else {
			b.WriteByte(c)
		}
	}
	return b.String()
}

// writeToConsole 输出到控制台
func (l *loggerService) writeToConsole(entry LogEntry) {
	l.mu.RLock()
	enableColor := l.config.EnableColor
	l.mu.RUnlock()

	var colorCode string
	// 颜色开关关闭时不得输出任何转义序列（L4 同源纪律）：resetCode 此前无条件
	// 拼接，非色彩模式下每行日志都混入裸 ESC 控制字节，污染采集管道的行内容
	resetCode := ""
	if enableColor {
		resetCode = "\033[0m"
		switch entry.Level {
		case "DEBUG":
			colorCode = "\033[36m" // 青色
		case "INFO":
			colorCode = "\033[32m" // 绿色
		case "WARN":
			colorCode = "\033[33m" // 黄色
		case "ERROR":
			colorCode = "\033[31m" // 红色
		case "FATAL":
			colorCode = "\033[35m" // 紫色
		default:
			colorCode = "\033[0m"
		}
	}

	// 检查是否有TraceId
	var traceIdStr string
	if traceId, exists := entry.Fields["trace_id"]; exists {
		traceIdStr = fmt.Sprintf(" [TID=%v]", traceId)
	}

	// 构建控制台输出
	output := fmt.Sprintf("%s[%s] %s%s %s%s - %s",
		colorCode,
		entry.Timestamp,
		entry.Level,
		traceIdStr,
		resetCode,
		entry.Caller,
		entry.Message,
	)

	// 添加字段信息（跳过 trace_id，已在上方单独输出）
	if len(entry.Fields) > 0 {
		var fieldStrs []string
		for k, v := range entry.Fields {
			if k == "trace_id" {
				continue
			}
			fieldStrs = append(fieldStrs, fmt.Sprintf("%s=%v", k, v))
		}
		if len(fieldStrs) > 0 {
			output += fmt.Sprintf(" | %s", strings.Join(fieldStrs, ", "))
		}
	}

	fmt.Fprintln(l.consoleWriter, output)
}

// writeToFile 输出到文件
func (l *loggerService) writeToFile(entry LogEntry) {
	l.fileMu.Lock()
	defer l.fileMu.Unlock()

	// 确保日志目录存在
	if err := os.MkdirAll(l.config.LogDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "创建日志目录失败: %v\n", err)
		return
	}

	// 获取或创建文件写入器
	writer, err := l.getFileWriter(entry.Level)
	if err != nil {
		fmt.Fprintf(os.Stderr, "获取日志文件写入器失败: %v\n", err)
		return
	}

	// 检查是否有TraceId
	var traceIdStr string
	if traceId, exists := entry.Fields["trace_id"]; exists {
		traceIdStr = fmt.Sprintf(" [TID=%v]", traceId)
	}

	// 构建文件输出
	output := fmt.Sprintf("[%s] %s%s %s - %s",
		entry.Timestamp,
		entry.Level,
		traceIdStr,
		entry.Caller,
		entry.Message,
	)

	// 添加字段信息（跳过 trace_id，已在上方单独输出）
	if len(entry.Fields) > 0 {
		var fieldStrs []string
		for k, v := range entry.Fields {
			if k == "trace_id" {
				continue
			}
			fieldStrs = append(fieldStrs, fmt.Sprintf("%s=%v", k, v))
		}
		if len(fieldStrs) > 0 {
			output += fmt.Sprintf(" | %s", strings.Join(fieldStrs, ", "))
		}
	}

	// 写入文件
	if _, err := fmt.Fprintln(writer, output); err != nil {
		fmt.Fprintf(os.Stderr, "写入日志文件失败: %v\n", err)
	}
}

// maxLogFileSize 单个日志文件最大大小（100MB），超过后强制轮转
const maxLogFileSize int64 = 100 * 1024 * 1024

// getFileWriter 获取或创建文件写入器
func (l *loggerService) getFileWriter(level string) (*os.File, error) {
	// 使用日期作为文件名
	date := time.Now().Format("2006-01-02")
	filename := fmt.Sprintf("%s.log", strings.ToLower(level))
	logPath := filepath.Join(l.config.LogDir, filename)

	// 检查是否需要轮转文件
	if writer, exists := l.fileWriters[LogLevelFromString(level)]; exists {
		// 检查文件日期是否变化
		if info, err := os.Stat(logPath); err == nil {
			if info.ModTime().Format("2006-01-02") == date {
				// P2-48: 检查文件大小，超过限制时强制轮转
				if info.Size() >= maxLogFileSize {
					writer.Close()
					delete(l.fileWriters, LogLevelFromString(level))
					l.archiveFile(logPath, time.Now())
				} else {
					return writer, nil
				}
			} else {
				// 文件日期变化，关闭旧文件并归档
				writer.Close()
				delete(l.fileWriters, LogLevelFromString(level))
				l.archiveFile(logPath, info.ModTime())
			}
		}
	}

	// 创建新文件
	file, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}

	l.fileWriters[LogLevelFromString(level)] = file
	return file, nil
}

// archiveFile 归档文件
func (l *loggerService) archiveFile(filePath string, modTime time.Time) {
	// 确保归档目录存在
	if err := os.MkdirAll(l.config.ArchiveDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "创建归档目录失败: %v\n", err)
		return
	}

	// P2-45: 归档文件名包含日期和时间，避免同日多次轮转覆盖旧归档
	archiveName := fmt.Sprintf("%s_%s.zip",
		strings.TrimSuffix(filepath.Base(filePath), filepath.Ext(filePath)),
		modTime.Format("20060102_150405"))
	archivePath := filepath.Join(l.config.ArchiveDir, archiveName)

	// 创建ZIP文件
	archiveFile, err := os.Create(archivePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "创建归档文件失败: %v\n", err)
		return
	}

	zipWriter := zip.NewWriter(archiveFile)

	// 打开要归档的文件
	fileToArchive, err := os.Open(filePath)
	if err != nil {
		zipWriter.Close()
		archiveFile.Close()
		fmt.Fprintf(os.Stderr, "打开要归档的文件失败: %v\n", err)
		return
	}

	// 添加到ZIP
	writer, err := zipWriter.Create(filepath.Base(filePath))
	if err != nil {
		fileToArchive.Close()
		zipWriter.Close()
		archiveFile.Close()
		fmt.Fprintf(os.Stderr, "创建ZIP条目失败: %v\n", err)
		return
	}

	if _, err := io.Copy(writer, fileToArchive); err != nil {
		fileToArchive.Close()
		zipWriter.Close()
		archiveFile.Close()
		fmt.Fprintf(os.Stderr, "复制文件到ZIP失败: %v\n", err)
		return
	}

	fileToArchive.Close()

	// 先关闭 zipWriter 写入中央目录，再 sync 确保数据落盘
	if err := zipWriter.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "关闭ZIP写入器失败: %v\n", err)
		archiveFile.Close()
		return
	}

	if err := archiveFile.Sync(); err != nil {
		fmt.Fprintf(os.Stderr, "同步归档文件失败: %v\n", err)
		archiveFile.Close()
		return
	}

	archiveFile.Close()

	// ZIP 完整写入后才删除原文件
	if err := os.Remove(filePath); err != nil {
		fmt.Fprintf(os.Stderr, "删除原日志文件失败: %v\n", err)
	}

	// 清理旧归档文件
	l.cleanOldArchives()
}

// cleanOldArchives 清理旧归档文件
// P2-46: 使用文件名中的日期判断而非 ModTime，避免因文件复制/移动导致误删
func (l *loggerService) cleanOldArchives() {
	// P2-47: MaxRetentionDays=0 表示不限保留天数（永久保留），不执行清理
	if l.config.MaxRetentionDays == 0 {
		return
	}

	cutoff := time.Now().AddDate(0, 0, -l.config.MaxRetentionDays)

	err := filepath.Walk(l.config.ArchiveDir, func(walkPath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		// P2-46: 优先从文件名解析日期（格式：level_YYYYMMDD_HHMMSS.zip 或 level_YYYYMMDD.zip）
		filename := filepath.Base(walkPath)
		nameWithoutExt := strings.TrimSuffix(filename, filepath.Ext(filename))
		fileDate := parseArchiveDate(nameWithoutExt)

		if fileDate != nil {
			// 文件名中解析到日期，使用文件名日期判断
			if fileDate.Before(cutoff) {
				if err := os.Remove(walkPath); err != nil {
					fmt.Fprintf(os.Stderr, "删除旧归档文件失败: %v\n", err)
				}
			}
		} else {
			// 无法从文件名解析日期，回退到 ModTime
			if info.ModTime().Before(cutoff) {
				if err := os.Remove(walkPath); err != nil {
					fmt.Fprintf(os.Stderr, "删除旧归档文件失败: %v\n", err)
				}
			}
		}

		return nil
	})

	if err != nil {
		fmt.Fprintf(os.Stderr, "清理旧归档文件失败: %v\n", err)
	}
}

// parseArchiveDate 从归档文件名中解析日期
// 支持格式：level_YYYYMMDD_HHMMSS 和 level_YYYYMMDD
func parseArchiveDate(name string) *time.Time {
	// 尝试解析 level_YYYYMMDD_HHMMSS 格式
	parts := strings.Split(name, "_")
	if len(parts) >= 3 {
		dateStr := parts[len(parts)-2]
		timeStr := parts[len(parts)-1]
		if t, err := time.ParseInLocation("20060102_150405", dateStr+"_"+timeStr, time.Local); err == nil {
			return &t
		}
	}
	// 尝试解析 level_YYYYMMDD 格式
	if len(parts) >= 2 {
		dateStr := parts[len(parts)-1]
		if t, err := time.ParseInLocation("20060102", dateStr, time.Local); err == nil {
			return &t
		}
	}
	return nil
}

// LogLevelFromString 从字符串解析日志级别
func LogLevelFromString(level string) LogLevel {
	switch strings.ToUpper(level) {
	case "DEBUG":
		return DebugLevel
	case "INFO":
		return InfoLevel
	case "WARN":
		return WarnLevel
	case "ERROR":
		return ErrorLevel
	case "FATAL":
		return FatalLevel
	default:
		return InfoLevel
	}
}

// LogEntry 日志条目
type LogEntry struct {
	Timestamp string                 `json:"timestamp"`
	Level     string                 `json:"level"`
	Message   string                 `json:"message"`
	Caller    string                 `json:"caller"`
	Fields    map[string]interface{} `json:"fields,omitempty"`
}
