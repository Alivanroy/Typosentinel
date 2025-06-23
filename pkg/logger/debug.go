package logger

import (
	"fmt"
	"runtime"
	"strings"
	"time"
)

// DebugMode represents different debug modes
type DebugMode int

const (
	DebugModeOff DebugMode = iota
	DebugModeBasic
	DebugModeVerbose
	DebugModeTrace
)

// String returns the string representation of debug mode
func (d DebugMode) String() string {
	switch d {
	case DebugModeOff:
		return "off"
	case DebugModeBasic:
		return "basic"
	case DebugModeVerbose:
		return "verbose"
	case DebugModeTrace:
		return "trace"
	default:
		return "unknown"
	}
}

// ParseDebugMode parses a string into a DebugMode
func ParseDebugMode(mode string) DebugMode {
	switch strings.ToLower(mode) {
	case "off", "false", "0":
		return DebugModeOff
	case "basic", "debug", "1":
		return DebugModeBasic
	case "verbose", "verb", "2":
		return DebugModeVerbose
	case "trace", "3":
		return DebugModeTrace
	default:
		return DebugModeOff
	}
}

// DebugConfig contains debug-specific configuration
type DebugConfig struct {
	Mode           DebugMode
	ShowCaller     bool
	ShowTimestamp  bool
	ShowGoroutine  bool
	ShowMemStats   bool
	IncludeStack   bool
	MaxStackDepth  int
}

// DefaultDebugConfig returns a default debug configuration
func DefaultDebugConfig() *DebugConfig {
	return &DebugConfig{
		Mode:          DebugModeOff,
		ShowCaller:    true,
		ShowTimestamp: true,
		ShowGoroutine: false,
		ShowMemStats:  false,
		IncludeStack:  false,
		MaxStackDepth: 10,
	}
}

// DebugLogger provides enhanced debugging capabilities
type DebugLogger struct {
	logger *Logger
	config *DebugConfig
}

// NewDebugLogger creates a new debug logger
func NewDebugLogger(logger *Logger, config *DebugConfig) *DebugLogger {
	if config == nil {
		config = DefaultDebugConfig()
	}
	return &DebugLogger{
		logger: logger,
		config: config,
	}
}

// SetDebugMode sets the debug mode
func (dl *DebugLogger) SetDebugMode(mode DebugMode) {
	dl.config.Mode = mode
	
	// Adjust logger level based on debug mode
	switch mode {
	case DebugModeOff:
		dl.logger.SetLevel(INFO)
	case DebugModeBasic:
		dl.logger.SetLevel(DEBUG)
	case DebugModeVerbose:
		dl.logger.SetLevel(VERBOSE)
	case DebugModeTrace:
		dl.logger.SetLevel(TRACE)
	}
}

// IsEnabled checks if debug logging is enabled for the given level
func (dl *DebugLogger) IsEnabled(level LogLevel) bool {
	switch dl.config.Mode {
	case DebugModeOff:
		return false
	case DebugModeBasic:
		return level >= DEBUG
	case DebugModeVerbose:
		return level >= VERBOSE
	case DebugModeTrace:
		return level >= TRACE
	default:
		return false
	}
}

// getCallerInfo returns caller information
func (dl *DebugLogger) getCallerInfo(skip int) map[string]interface{} {
	fields := make(map[string]interface{})
	
	if dl.config.ShowCaller {
		if pc, file, line, ok := runtime.Caller(skip + 2); ok {
			funcName := runtime.FuncForPC(pc).Name()
			// Extract just the function name
			if idx := strings.LastIndex(funcName, "."); idx != -1 {
				funcName = funcName[idx+1:]
			}
			// Extract just the filename
			if idx := strings.LastIndex(file, "/"); idx != -1 {
				file = file[idx+1:]
			} else if idx := strings.LastIndex(file, "\\"); idx != -1 {
				file = file[idx+1:]
			}
			fields["caller"] = fmt.Sprintf("%s:%d", file, line)
			fields["function"] = funcName
		}
	}
	
	if dl.config.ShowGoroutine {
		fields["goroutine"] = runtime.NumGoroutine()
	}
	
	if dl.config.ShowTimestamp {
		fields["timestamp"] = time.Now().Format(time.RFC3339Nano)
	}
	
	return fields
}

// getStackTrace returns stack trace information
func (dl *DebugLogger) getStackTrace() string {
	if !dl.config.IncludeStack {
		return ""
	}
	
	buf := make([]byte, 4096)
	n := runtime.Stack(buf, false)
	stack := string(buf[:n])
	
	// Limit stack depth if configured
	if dl.config.MaxStackDepth > 0 {
		lines := strings.Split(stack, "\n")
		if len(lines) > dl.config.MaxStackDepth*2 {
			lines = lines[:dl.config.MaxStackDepth*2]
			stack = strings.Join(lines, "\n") + "\n... (truncated)"
		}
	}
	
	return stack
}

// DebugWithContext logs a debug message with enhanced context
func (dl *DebugLogger) DebugWithContext(msg string, extraFields ...map[string]interface{}) {
	if !dl.IsEnabled(DEBUG) {
		return
	}
	
	fields := dl.getCallerInfo(1)
	if len(extraFields) > 0 {
		for k, v := range extraFields[0] {
			fields[k] = v
		}
	}
	
	if stack := dl.getStackTrace(); stack != "" {
		fields["stack"] = stack
	}
	
	dl.logger.Debug(msg, fields)
}

// VerboseWithContext logs a verbose message with enhanced context
func (dl *DebugLogger) VerboseWithContext(msg string, extraFields ...map[string]interface{}) {
	if !dl.IsEnabled(VERBOSE) {
		return
	}
	
	fields := dl.getCallerInfo(1)
	if len(extraFields) > 0 {
		for k, v := range extraFields[0] {
			fields[k] = v
		}
	}
	
	dl.logger.Verbose(msg, fields)
}

// TraceWithContext logs a trace message with enhanced context
func (dl *DebugLogger) TraceWithContext(msg string, extraFields ...map[string]interface{}) {
	if !dl.IsEnabled(TRACE) {
		return
	}
	
	fields := dl.getCallerInfo(1)
	if len(extraFields) > 0 {
		for k, v := range extraFields[0] {
			fields[k] = v
		}
	}
	
	if stack := dl.getStackTrace(); stack != "" {
		fields["stack"] = stack
	}
	
	dl.logger.Trace(msg, fields)
}

// TraceFunction logs function entry and exit
func (dl *DebugLogger) TraceFunction(funcName string) func() {
	if !dl.IsEnabled(TRACE) {
		return func() {}
	}
	
	start := time.Now()
	fields := dl.getCallerInfo(1)
	fields["function"] = funcName
	
	dl.logger.Trace(fmt.Sprintf("Entering function: %s", funcName), fields)
	
	return func() {
		fields["duration"] = time.Since(start).String()
		dl.logger.Trace(fmt.Sprintf("Exiting function: %s", funcName), fields)
	}
}

// Global debug logger instance
var globalDebugLogger *DebugLogger

// getOrCreateGlobalDebugLogger returns the global debug logger, creating it if necessary
func getOrCreateGlobalDebugLogger() *DebugLogger {
	if globalDebugLogger == nil {
		globalDebugLogger = NewDebugLogger(defaultLogger, DefaultDebugConfig())
	}
	return globalDebugLogger
}

// SetGlobalDebugMode sets the debug mode for the global debug logger
func SetGlobalDebugMode(mode DebugMode) {
	getOrCreateGlobalDebugLogger().SetDebugMode(mode)
}

// SetGlobalDebugModeFromString sets the debug mode from string
func SetGlobalDebugModeFromString(mode string) {
	SetGlobalDebugMode(ParseDebugMode(mode))
}

// GetGlobalDebugLogger returns the global debug logger
func GetGlobalDebugLogger() *DebugLogger {
	return getOrCreateGlobalDebugLogger()
}

// Global debug functions
func DebugWithContext(msg string, extraFields ...map[string]interface{}) {
	getOrCreateGlobalDebugLogger().DebugWithContext(msg, extraFields...)
}

func VerboseWithContext(msg string, extraFields ...map[string]interface{}) {
	getOrCreateGlobalDebugLogger().VerboseWithContext(msg, extraFields...)
}

func TraceWithContext(msg string, extraFields ...map[string]interface{}) {
	getOrCreateGlobalDebugLogger().TraceWithContext(msg, extraFields...)
}

func TraceFunction(funcName string) func() {
	return getOrCreateGlobalDebugLogger().TraceFunction(funcName)
}

// IsDebugEnabled checks if debug logging is enabled
func IsDebugEnabled() bool {
	return getOrCreateGlobalDebugLogger().IsEnabled(DEBUG)
}

// IsVerboseEnabled checks if verbose logging is enabled
func IsVerboseEnabled() bool {
	return getOrCreateGlobalDebugLogger().IsEnabled(VERBOSE)
}

// IsTraceEnabled checks if trace logging is enabled
func IsTraceEnabled() bool {
	return getOrCreateGlobalDebugLogger().IsEnabled(TRACE)
}