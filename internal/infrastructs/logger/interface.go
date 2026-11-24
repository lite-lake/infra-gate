package logger

import (
	"context"
)

// LogLevel 日志级别
type LogLevel int

const (
	DebugLevel LogLevel = iota
	InfoLevel
	WarnLevel
	ErrorLevel
	FatalLevel
)

// String 返回日志级别的字符串表示
func (l LogLevel) String() string {
	switch l {
	case DebugLevel:
		return "DEBUG"
	case InfoLevel:
		return "INFO"
	case WarnLevel:
		return "WARN"
	case ErrorLevel:
		return "ERROR"
	case FatalLevel:
		return "FATAL"
	default:
		return "UNKNOWN"
	}
}

// ILogger 日志服务接口
type ILogger interface {
	// Debug 记录调试信息
	Debug(msg string, fields ...Field)

	// Info 记录一般信息
	Info(msg string, fields ...Field)

	// Warn 记录警告信息
	Warn(msg string, fields ...Field)

	// Error 记录错误信息
	Error(msg string, fields ...Field)

	// Fatal 记录致命错误信息并退出程序
	Fatal(msg string, fields ...Field)

	// WithContext 添加上下文信息
	WithContext(ctx context.Context) ILogger

	// WithField 添加字段
	WithField(key string, value interface{}) ILogger

	// WithFields 添加多个字段
	WithFields(fields map[string]interface{}) ILogger

	// WithTraceId 添加TraceId
	WithTraceId(traceId string) ILogger

	// SetLevel 设置日志级别
	SetLevel(level LogLevel)

	// GetLevel 获取当前日志级别
	GetLevel() LogLevel

	// Close 关闭日志服务，释放资源
	Close() error
}

// Field 日志字段
type Field struct {
	Key   string
	Value interface{}
}

// NewField 创建日志字段
func NewField(key string, value interface{}) Field {
	return Field{
		Key:   key,
		Value: value,
	}
}

// LoggerConfig 日志配置
type LoggerConfig struct {
	// Level 日志级别
	Level LogLevel `yaml:"level"`

	// EnableConsole 是否启用控制台输出
	EnableConsole bool `yaml:"enable_console"`

	// EnableFile 是否启用文件输出
	EnableFile bool `yaml:"enable_file"`

	// LogDir 日志文件目录
	LogDir string `yaml:"log_dir"`

	// ArchiveDir 归档文件目录
	ArchiveDir string `yaml:"archive_dir"`

	// MaxRetentionDays 最大保留天数
	MaxRetentionDays int `yaml:"max_retention_days"`

	// EnableColor 是否启用控制台颜色
	EnableColor bool `yaml:"enable_color"`
}
