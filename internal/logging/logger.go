// Package logging provides structured logging for Typosentinel
// This package implements a comprehensive logging system with multiple outputs and formats
package logging

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/internal/errors"
	"github.com/Alivanroy/Typosentinel/internal/interfaces"
)

// Level represents log levels
type Level string

const (
	LevelDebug Level = "debug"
	LevelInfo  Level = "info"
	LevelWarn  Level = "warn"
	LevelError Level = "error"
)

// Format represents log output formats
type Format string

const (
	FormatJSON Format = "json"
	FormatText Format = "text"
)

// Output represents log output destinations
type Output string

const (
	OutputStdout Output = "stdout"
	OutputStderr Output = "stderr"
	OutputFile   Output = "file"
)

// Logger implements the interfaces.Logger interface
type Logger struct {
	logger    *logrus.Logger
	config    *config.LoggingConfig
	mu        sync.RWMutex
	fields    []interfaces.LogField
	writer    io.Writer
	file      *lumberjack.Logger
	ctxFields map[string]interface{}
}

// NewLogger creates a new logger instance
func NewLogger(cfg *config.LoggingConfig) (*Logger, error) {
	logger := &Logger{
		logger:    logrus.New(),
		config:    cfg,
		fields:    make([]interfaces.LogField, 0),
		ctxFields: make(map[string]interface{}),
	}

	// Configure the logger
	if err := logger.configure(); err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeConfig, "failed to configure logger")
	}

	return logger, nil
}

// configure sets up the logger based on configuration
func (l *Logger) configure() error {
	// Set log level
	level, err := logrus.ParseLevel(l.config.Level)
	if err != nil {
		return errors.Wrapf(err, errors.ErrCodeValidation, "invalid log level: %s", l.config.Level)
	}
	l.logger.SetLevel(level)

	// Set log format
	switch Format(l.config.Format) {
	case FormatJSON:
		l.logger.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: time.RFC3339Nano,
			FieldMap: logrus.FieldMap{
				logrus.FieldKeyTime:  "timestamp",
				logrus.FieldKeyLevel: "level",
				logrus.FieldKeyMsg:   "message",
				logrus.FieldKeyFunc:  "function",
				logrus.FieldKeyFile:  "file",
			},
		})
	case FormatText:
		l.logger.SetFormatter(&logrus.TextFormatter{
			TimestampFormat: time.RFC3339,
			FullTimestamp:   true,
			FieldMap: logrus.FieldMap{
				logrus.FieldKeyTime:  "time",
				logrus.FieldKeyLevel: "level",
				logrus.FieldKeyMsg:   "msg",
			},
		})
	default:
		return errors.NewValidationError(fmt.Sprintf("unsupported log format: %s", l.config.Format))
	}

	// Set output destination
	if err := l.setOutput(); err != nil {
		return err
	}

	// Enable caller reporting for better debugging
	l.logger.SetReportCaller(true)

	return nil
}

// setOutput configures the log output destination
func (l *Logger) setOutput() error {
	switch Output(l.config.Output) {
	case OutputStdout:
		l.writer = os.Stdout
	case OutputStderr:
		l.writer = os.Stderr
	case OutputFile:
		if l.config.File == "" {
			return errors.NewValidationError("log file path is required when output is set to file")
		}

		// Ensure log directory exists
		logDir := filepath.Dir(l.config.File)
		if err := os.MkdirAll(logDir, 0755); err != nil {
			return errors.Wrapf(err, errors.ErrCodeConfig, "failed to create log directory: %s", logDir)
		}

		// Configure log rotation
		l.file = &lumberjack.Logger{
			Filename:   l.config.File,
			MaxSize:    l.config.MaxSize,
			MaxBackups: l.config.MaxBackups,
			MaxAge:     l.config.MaxAge,
			Compress:   l.config.Compress,
		}
		l.writer = l.file
	default:
		return errors.NewValidationError(fmt.Sprintf("unsupported log output: %s", l.config.Output))
	}

	l.logger.SetOutput(l.writer)
	return nil
}

// Debug logs a debug message
func (l *Logger) Debug(message string, fields ...interfaces.LogField) {
	l.log(logrus.DebugLevel, message, fields...)
}

// Info logs an info message
func (l *Logger) Info(message string, fields ...interfaces.LogField) {
	l.log(logrus.InfoLevel, message, fields...)
}

// Warn logs a warning message
func (l *Logger) Warn(message string, fields ...interfaces.LogField) {
	l.log(logrus.WarnLevel, message, fields...)
}

// Error logs an error message
func (l *Logger) Error(message string, fields ...interfaces.LogField) {
	l.log(logrus.ErrorLevel, message, fields...)
}

// Fatal logs a fatal message and exits
func (l *Logger) Fatal(message string, fields ...interfaces.LogField) {
	l.log(logrus.FatalLevel, message, fields...)
	l.Close()
	os.Exit(1)
}

// ErrorWithErr logs an error message with error details
func (l *Logger) ErrorWithErr(message string, err error, fields ...interfaces.LogField) {
	logFields := l.mergeFields(fields...)
	if err != nil {
		logFields = append(logFields, interfaces.Error(err))
	}
	l.logWithFields(logrus.ErrorLevel, message, logFields)
}

// WithFields returns a logger with additional fields
func (l *Logger) WithFields(fields ...interfaces.LogField) interfaces.Logger {
	newLogger := &Logger{
		logger:    l.logger,
		config:    l.config,
		fields:    l.mergeFields(fields...),
		writer:    l.writer,
		file:      l.file,
		ctxFields: make(map[string]interface{}),
	}
	
	// Copy context fields
	for k, v := range l.ctxFields {
		newLogger.ctxFields[k] = v
	}
	
	return newLogger
}

// WithContext returns a logger with context information
func (l *Logger) WithContext(ctx context.Context) interfaces.Logger {
	newLogger := &Logger{
		logger:    l.logger,
		config:    l.config,
		fields:    make([]interfaces.LogField, 0),
		writer:    l.writer,
		file:      l.file,
		ctxFields: make(map[string]interface{}),
	}
	
	// Copy existing fields
	newLogger.fields = append(newLogger.fields, l.fields...)
	
	// Copy existing context fields
	for k, v := range l.ctxFields {
		newLogger.ctxFields[k] = v
	}
	
	// Extract context values
	if requestID := ctx.Value("request_id"); requestID != nil {
		newLogger.ctxFields["request_id"] = requestID
	}
	if userID := ctx.Value("user_id"); userID != nil {
		newLogger.ctxFields["user_id"] = userID
	}
	if traceID := ctx.Value("trace_id"); traceID != nil {
		newLogger.ctxFields["trace_id"] = traceID
	}
	if spanID := ctx.Value("span_id"); spanID != nil {
		newLogger.ctxFields["span_id"] = spanID
	}
	
	return newLogger
}

// SetLevel sets the log level
func (l *Logger) SetLevel(level string) error {
	logLevel, err := logrus.ParseLevel(level)
	if err != nil {
		return errors.Wrapf(err, errors.ErrCodeValidation, "invalid log level: %s", level)
	}
	
	l.mu.Lock()
	defer l.mu.Unlock()
	
	l.logger.SetLevel(logLevel)
	l.config.Level = level
	
	return nil
}

// GetLevel returns the current log level
func (l *Logger) GetLevel() string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.logger.GetLevel().String()
}

// Close closes the logger and any associated resources
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

// Rotate rotates the log file (if using file output)
func (l *Logger) Rotate() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	
	if l.file != nil {
		return l.file.Rotate()
	}
	return nil
}

// log is the internal logging method
func (l *Logger) log(level logrus.Level, message string, fields ...interfaces.LogField) {
	logFields := l.mergeFields(fields...)
	l.logWithFields(level, message, logFields)
}

// logWithFields logs with the provided fields
func (l *Logger) logWithFields(level logrus.Level, message string, fields []interfaces.LogField) {
	// Convert LogFields slice to logrus.Fields map
	logrusFields := make(logrus.Fields)
	for _, field := range fields {
		logrusFields[field.Key] = field.Value
	}
	
	entry := l.logger.WithFields(logrusFields)
	
	// Add context fields
	for k, v := range l.ctxFields {
		entry = entry.WithField(k, v)
	}
	
	// Add caller information
	if pc, file, line, ok := runtime.Caller(3); ok {
		funcName := runtime.FuncForPC(pc).Name()
		// Extract just the function name
		if idx := strings.LastIndex(funcName, "."); idx != -1 {
			funcName = funcName[idx+1:]
		}
		// Extract just the filename
		if idx := strings.LastIndex(file, "/"); idx != -1 {
			file = file[idx+1:]
		}
		entry = entry.WithFields(logrus.Fields{
			"caller_func": funcName,
			"caller_file": fmt.Sprintf("%s:%d", file, line),
		})
	}
	
	entry.Log(level, message)
}

// mergeFields merges multiple field slices with the logger's base fields
func (l *Logger) mergeFields(fields ...interfaces.LogField) []interfaces.LogField {
	var result []interfaces.LogField
	
	// Start with logger's base fields
	result = append(result, l.fields...)
	
	// Add provided fields
	result = append(result, fields...)
	
	return result
}

// StructuredLogger provides additional structured logging capabilities
type StructuredLogger struct {
	*Logger
	component string
	version   string
}

// NewStructuredLogger creates a new structured logger with component information
func NewStructuredLogger(cfg *config.LoggingConfig, component, version string) (*StructuredLogger, error) {
	baseLogger, err := NewLogger(cfg)
	if err != nil {
		return nil, err
	}
	
	return &StructuredLogger{
		Logger:    baseLogger,
		component: component,
		version:   version,
	}, nil
}

// LogRequest logs an HTTP request
func (sl *StructuredLogger) LogRequest(ctx context.Context, method, path string, statusCode int, duration time.Duration, fields ...interfaces.LogField) {
	logFields := sl.mergeFields(fields...)
	logFields = append(logFields, interfaces.String("component", sl.component))
	logFields = append(logFields, interfaces.String("http_method", method))
	logFields = append(logFields, interfaces.String("http_path", path))
	logFields = append(logFields, interfaces.Int("http_status", statusCode))
	logFields = append(logFields, interfaces.Int("duration_ms", int(duration.Milliseconds())))
	
	logger := sl.WithContext(ctx)
	
	if statusCode >= 500 {
		logger.Error("HTTP request failed", logFields...)
	} else if statusCode >= 400 {
		logger.Warn("HTTP request error", logFields...)
	} else {
		logger.Info("HTTP request completed", logFields...)
	}
}

// LogDatabaseOperation logs a database operation
func (sl *StructuredLogger) LogDatabaseOperation(ctx context.Context, operation, table string, duration time.Duration, err error, fields ...interfaces.LogField) {
	logFields := sl.mergeFields(fields...)
	logFields = append(logFields, interfaces.String("component", sl.component))
	logFields = append(logFields, interfaces.String("db_operation", operation))
	logFields = append(logFields, interfaces.String("db_table", table))
	logFields = append(logFields, interfaces.Int("duration_ms", int(duration.Milliseconds())))
	
	logger := sl.WithContext(ctx)
	
	if err != nil {
		errorFields := append(logFields, interfaces.String("error", err.Error()))
		logger.Error("Database operation failed", errorFields...)
	} else {
		logger.Debug("Database operation completed", logFields...)
	}
}

// LogCacheOperation logs a cache operation
func (sl *StructuredLogger) LogCacheOperation(ctx context.Context, operation, key string, hit bool, duration time.Duration, fields ...interfaces.LogField) {
	logFields := sl.mergeFields(fields...)
	logFields = append(logFields, interfaces.String("component", sl.component))
	logFields = append(logFields, interfaces.String("cache_operation", operation))
	logFields = append(logFields, interfaces.String("cache_key", key))
	logFields = append(logFields, interfaces.Bool("cache_hit", hit))
	logFields = append(logFields, interfaces.Int("duration_ms", int(duration.Milliseconds())))
	
	logger := sl.WithContext(ctx)
	logger.Debug("Cache operation completed", logFields...)
}

// LogScanOperation logs a package scan operation
func (sl *StructuredLogger) LogScanOperation(ctx context.Context, packageName, registry string, riskScore float64, duration time.Duration, err error, fields ...interfaces.LogField) {
	logFields := sl.mergeFields(fields...)
	logFields = append(logFields, interfaces.String("component", sl.component))
	logFields = append(logFields, interfaces.String("package_name", packageName))
	logFields = append(logFields, interfaces.String("registry", registry))
	logFields = append(logFields, interfaces.Float64("risk_score", riskScore))
	logFields = append(logFields, interfaces.Int("duration_ms", int(duration.Milliseconds())))
	
	logger := sl.WithContext(ctx)
	
	if err != nil {
		errorFields := append(logFields, interfaces.String("error", err.Error()))
		logger.Error("Package scan failed", errorFields...)
	} else {
		logger.Info("Package scan completed", logFields...)
	}
}

// LogMLOperation logs a machine learning operation
func (sl *StructuredLogger) LogMLOperation(ctx context.Context, operation string, inputSize int, confidence float64, duration time.Duration, err error, fields ...interfaces.LogField) {
	logFields := sl.mergeFields(fields...)
	logFields = append(logFields, interfaces.String("component", sl.component))
	logFields = append(logFields, interfaces.String("ml_operation", operation))
	logFields = append(logFields, interfaces.Int("input_size", inputSize))
	logFields = append(logFields, interfaces.Float64("confidence", confidence))
	logFields = append(logFields, interfaces.Int("duration_ms", int(duration.Milliseconds())))
	
	logger := sl.WithContext(ctx)
	
	if err != nil {
		errorFields := append(logFields, interfaces.String("error", err.Error()))
		logger.Error("ML operation failed", errorFields...)
	} else {
		logger.Debug("ML operation completed", logFields...)
	}
}

// LogSecurityEvent logs a security-related event
func (sl *StructuredLogger) LogSecurityEvent(ctx context.Context, eventType, description string, severity string, fields ...interfaces.LogField) {
	logFields := sl.mergeFields(fields...)
	logFields = append(logFields, interfaces.String("component", sl.component))
	logFields = append(logFields, interfaces.String("security_event_type", eventType))
	logFields = append(logFields, interfaces.String("security_severity", severity))
	logFields = append(logFields, interfaces.String("description", description))
	
	logger := sl.WithContext(ctx)
	
	switch severity {
	case "critical", "high":
		logger.Error("Security event detected", logFields...)
	case "medium":
		logger.Warn("Security event detected", logFields...)
	default:
		logger.Info("Security event detected", logFields...)
	}
}

// LogPerformanceMetric logs a performance metric
func (sl *StructuredLogger) LogPerformanceMetric(ctx context.Context, metricName string, value float64, unit string, fields ...interfaces.LogField) {
	logFields := sl.mergeFields(fields...)
	logFields = append(logFields, interfaces.String("component", sl.component))
	logFields = append(logFields, interfaces.String("metric_name", metricName))
	logFields = append(logFields, interfaces.Float64("metric_value", value))
	logFields = append(logFields, interfaces.String("metric_unit", unit))
	
	logger := sl.WithContext(ctx)
	logger.Debug("Performance metric recorded", logFields...)
}

// LogStartup logs application startup information
func (sl *StructuredLogger) LogStartup(ctx context.Context, fields ...interfaces.LogField) {
	logFields := sl.mergeFields(fields...)
	logFields = append(logFields, interfaces.String("component", sl.component))
	logFields = append(logFields, interfaces.String("version", sl.version))
	logFields = append(logFields, interfaces.String("event", "startup"))
	
	logger := sl.WithContext(ctx)
	logger.Info("Application starting", logFields...)
}

// LogShutdown logs application shutdown information
func (sl *StructuredLogger) LogShutdown(ctx context.Context, reason string, fields ...interfaces.LogField) {
	logFields := sl.mergeFields(fields...)
	logFields = append(logFields, interfaces.String("component", sl.component))
	logFields = append(logFields, interfaces.String("version", sl.version))
	logFields = append(logFields, interfaces.String("event", "shutdown"))
	logFields = append(logFields, interfaces.String("reason", reason))
	
	logger := sl.WithContext(ctx)
	logger.Info("Application shutting down", logFields...)
}

// HealthCheck performs a health check on the logger
func (l *Logger) HealthCheck() error {
	// Test if we can write to the output
	testEntry := l.logger.WithField("health_check", true)
	testEntry.Debug("Logger health check")
	
	// If using file output, check if file is writable
	if l.file != nil {
		if _, err := os.Stat(l.config.File); err != nil {
			return errors.Wrap(err, errors.ErrCodeInternal, "log file is not accessible")
		}
	}
	
	return nil
}

// GetStats returns logging statistics
func (l *Logger) GetStats() map[string]interface{} {
	stats := map[string]interface{}{
		"level":  l.GetLevel(),
		"format": l.config.Format,
		"output": l.config.Output,
	}
	
	if l.config.Output == "file" {
		stats["file"] = l.config.File
		stats["max_size"] = l.config.MaxSize
		stats["max_backups"] = l.config.MaxBackups
		stats["max_age"] = l.config.MaxAge
		stats["compress"] = l.config.Compress
	}
	
	return stats
}