package logger

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"
)

// LogLevel represents the logging level
type LogLevel int

const (
	DEBUG LogLevel = iota
	INFO
	WARN
	ERROR
)

// String returns the string representation of the log level
func (l LogLevel) String() string {
	switch l {
	case DEBUG:
		return "DEBUG"
	case INFO:
		return "INFO"
	case WARN:
		return "WARN"
	case ERROR:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}

// ParseLogLevel parses a string into a LogLevel
func ParseLogLevel(level string) LogLevel {
	switch strings.ToUpper(level) {
	case "DEBUG":
		return DEBUG
	case "INFO":
		return INFO
	case "WARN", "WARNING":
		return WARN
	case "ERROR":
		return ERROR
	default:
		return INFO
	}
}

// Config represents logger configuration
type Config struct {
	Level      LogLevel
	Format     string // "text" or "json"
	Output     io.Writer
	Timestamp  bool
	Caller     bool
	Prefix     string
}

// DefaultConfig returns a default logger configuration
func DefaultConfig() *Config {
	return &Config{
		Level:     INFO,
		Format:    "text",
		Output:    os.Stdout,
		Timestamp: true,
		Caller:    true,
		Prefix:    "[TYPOSENTINEL]",
	}
}

// Logger provides a configurable logging interface
type Logger struct {
	config *Config
	logger *log.Logger
}

// New creates a new logger instance with default configuration
func New() *Logger {
	return NewWithConfig(DefaultConfig())
}

// NewWithConfig creates a new logger instance with custom configuration
func NewWithConfig(config *Config) *Logger {
	flags := 0
	if config.Timestamp {
		flags |= log.LstdFlags
	}
	if config.Caller {
		flags |= log.Lshortfile
	}

	return &Logger{
		config: config,
		logger: log.New(config.Output, config.Prefix+" ", flags),
	}
}

// SetLevel sets the logging level
func (l *Logger) SetLevel(level LogLevel) {
	l.config.Level = level
}

// SetFormat sets the logging format ("text" or "json")
func (l *Logger) SetFormat(format string) {
	l.config.Format = format
}

// logEntry represents a structured log entry
type logEntry struct {
	Timestamp string                 `json:"timestamp"`
	Level     string                 `json:"level"`
	Message   string                 `json:"message"`
	Caller    string                 `json:"caller,omitempty"`
	Fields    map[string]interface{} `json:"fields,omitempty"`
}

// log writes a log message if the level is enabled
func (l *Logger) log(level LogLevel, msg string, fields map[string]interface{}) {
	if level < l.config.Level {
		return
	}

	if l.config.Format == "json" {
		entry := logEntry{
			Timestamp: time.Now().Format(time.RFC3339),
			Level:     level.String(),
			Message:   msg,
			Fields:    fields,
		}

		if l.config.Caller {
			// Simple caller info - in production, you might want to use runtime.Caller
			entry.Caller = "caller_info"
		}

		jsonData, _ := json.Marshal(entry)
		l.logger.Print(string(jsonData))
	} else {
		// Text format
		prefix := fmt.Sprintf("[%s]", level.String())
		if len(fields) > 0 {
			fieldStr := ""
			for k, v := range fields {
				fieldStr += fmt.Sprintf(" %s=%v", k, v)
			}
			msg += fieldStr
		}
		l.logger.Print(prefix, " ", msg)
	}
}

// Info logs an info message
func (l *Logger) Info(msg string, fields ...map[string]interface{}) {
	var f map[string]interface{}
	if len(fields) > 0 {
		f = fields[0]
	}
	l.log(INFO, msg, f)
}

// Error logs an error message
func (l *Logger) Error(msg string, fields ...map[string]interface{}) {
	var f map[string]interface{}
	if len(fields) > 0 {
		f = fields[0]
	}
	l.log(ERROR, msg, f)
}

// Debug logs a debug message
func (l *Logger) Debug(msg string, fields ...map[string]interface{}) {
	var f map[string]interface{}
	if len(fields) > 0 {
		f = fields[0]
	}
	l.log(DEBUG, msg, f)
}

// Warn logs a warning message
func (l *Logger) Warn(msg string, fields ...map[string]interface{}) {
	var f map[string]interface{}
	if len(fields) > 0 {
		f = fields[0]
	}
	l.log(WARN, msg, f)
}

// Infof logs a formatted info message
func (l *Logger) Infof(format string, v ...interface{}) {
	msg := fmt.Sprintf(format, v...)
	l.log(INFO, msg, nil)
}

// Errorf logs a formatted error message
func (l *Logger) Errorf(format string, v ...interface{}) {
	msg := fmt.Sprintf(format, v...)
	l.log(ERROR, msg, nil)
}

// Debugf logs a formatted debug message
func (l *Logger) Debugf(format string, v ...interface{}) {
	msg := fmt.Sprintf(format, v...)
	l.log(DEBUG, msg, nil)
}

// Warnf logs a formatted warning message
func (l *Logger) Warnf(format string, v ...interface{}) {
	msg := fmt.Sprintf(format, v...)
	l.log(WARN, msg, nil)
}

// WithFields creates a logger with predefined fields
func (l *Logger) WithFields(fields map[string]interface{}) *FieldLogger {
	return &FieldLogger{
		logger: l,
		fields: fields,
	}
}

// FieldLogger wraps Logger with predefined fields
type FieldLogger struct {
	logger *Logger
	fields map[string]interface{}
}

// Info logs an info message with predefined fields
func (fl *FieldLogger) Info(msg string) {
	fl.logger.log(INFO, msg, fl.fields)
}

// Error logs an error message with predefined fields
func (fl *FieldLogger) Error(msg string) {
	fl.logger.log(ERROR, msg, fl.fields)
}

// Debug logs a debug message with predefined fields
func (fl *FieldLogger) Debug(msg string) {
	fl.logger.log(DEBUG, msg, fl.fields)
}

// Warn logs a warning message with predefined fields
func (fl *FieldLogger) Warn(msg string) {
	fl.logger.log(WARN, msg, fl.fields)
}

// Infof logs a formatted info message with predefined fields
func (fl *FieldLogger) Infof(format string, v ...interface{}) {
	msg := fmt.Sprintf(format, v...)
	fl.logger.log(INFO, msg, fl.fields)
}

// Errorf logs a formatted error message with predefined fields
func (fl *FieldLogger) Errorf(format string, v ...interface{}) {
	msg := fmt.Sprintf(format, v...)
	fl.logger.log(ERROR, msg, fl.fields)
}

// Debugf logs a formatted debug message with predefined fields
func (fl *FieldLogger) Debugf(format string, v ...interface{}) {
	msg := fmt.Sprintf(format, v...)
	fl.logger.log(DEBUG, msg, fl.fields)
}

// Warnf logs a formatted warning message with predefined fields
func (fl *FieldLogger) Warnf(format string, v ...interface{}) {
	msg := fmt.Sprintf(format, v...)
	fl.logger.log(WARN, msg, fl.fields)
}

// Global logger instance
var defaultLogger = New()

// Global logging functions
func Info(msg string, fields ...map[string]interface{}) {
	defaultLogger.Info(msg, fields...)
}

func Error(msg string, fields ...map[string]interface{}) {
	defaultLogger.Error(msg, fields...)
}

func Debug(msg string, fields ...map[string]interface{}) {
	defaultLogger.Debug(msg, fields...)
}

func Warn(msg string, fields ...map[string]interface{}) {
	defaultLogger.Warn(msg, fields...)
}

func Infof(format string, v ...interface{}) {
	defaultLogger.Infof(format, v...)
}

func Errorf(format string, v ...interface{}) {
	defaultLogger.Errorf(format, v...)
}

func Debugf(format string, v ...interface{}) {
	defaultLogger.Debugf(format, v...)
}

func Warnf(format string, v ...interface{}) {
	defaultLogger.Warnf(format, v...)
}

// SetGlobalLevel sets the log level for the global logger
func SetGlobalLevel(level LogLevel) {
	defaultLogger.SetLevel(level)
}

// SetGlobalFormat sets the format for the global logger
func SetGlobalFormat(format string) {
	defaultLogger.SetFormat(format)
}

// GetGlobalLogger returns the global logger instance
func GetGlobalLogger() *Logger {
	return defaultLogger
}