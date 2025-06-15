package logger

import (
	"log"
	"os"
)

// Logger provides a simple logging interface
type Logger struct {
	*log.Logger
}

// New creates a new logger instance
func New() *Logger {
	return &Logger{
		Logger: log.New(os.Stdout, "[TYPOSENTINEL] ", log.LstdFlags|log.Lshortfile),
	}
}

// Info logs an info message
func (l *Logger) Info(v ...interface{}) {
	l.Print("[INFO] ", v)
}

// Error logs an error message
func (l *Logger) Error(v ...interface{}) {
	l.Print("[ERROR] ", v)
}

// Debug logs a debug message
func (l *Logger) Debug(v ...interface{}) {
	l.Print("[DEBUG] ", v)
}

// Warn logs a warning message
func (l *Logger) Warn(v ...interface{}) {
	l.Print("[WARN] ", v)
}

// Infof logs a formatted info message
func (l *Logger) Infof(format string, v ...interface{}) {
	l.Printf("[INFO] "+format, v...)
}

// Errorf logs a formatted error message
func (l *Logger) Errorf(format string, v ...interface{}) {
	l.Printf("[ERROR] "+format, v...)
}

// Debugf logs a formatted debug message
func (l *Logger) Debugf(format string, v ...interface{}) {
	l.Printf("[DEBUG] "+format, v...)
}

// Warnf logs a formatted warning message
func (l *Logger) Warnf(format string, v ...interface{}) {
	l.Printf("[WARN] "+format, v...)
}