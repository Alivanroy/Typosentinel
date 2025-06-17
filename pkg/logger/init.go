package logger

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/natefinch/lumberjack.v2"
)

// InitFromConfig initializes the global logger from configuration
func InitFromConfig(config LoggerConfig) error {
	// Parse log level
	level := ParseLogLevel(config.Level)
	// No error handling needed as ParseLogLevel doesn't return an error

	// Determine output writer
	var output io.Writer
	switch strings.ToLower(config.Output) {
	case "stdout", "":
		output = os.Stdout
	case "stderr":
		output = os.Stderr
	default:
		// File output
		if config.Rotation.Enabled {
			// Use lumberjack for log rotation
			output = &lumberjack.Logger{
				Filename:   config.Output,
				MaxSize:    config.Rotation.MaxSize,
				MaxBackups: config.Rotation.MaxBackups,
				MaxAge:     config.Rotation.MaxAge,
				Compress:   config.Rotation.Compress,
			}
		} else {
			// Create directory if it doesn't exist
			dir := filepath.Dir(config.Output)
			if err := os.MkdirAll(dir, 0755); err != nil {
				return fmt.Errorf("failed to create log directory: %w", err)
			}

			// Open file for writing
			file, err := os.OpenFile(config.Output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
			if err != nil {
				return fmt.Errorf("failed to open log file: %w", err)
			}
			output = file
		}
	}

	// Create logger configuration
	loggerConfig := Config{
		Level:     level,
		Format:    config.Format,
		Output:    output,
		Timestamp: config.Timestamp,
		Caller:    config.Caller,
		Prefix:    config.Prefix,
	}

	// Create new logger and set as global
	newLogger := NewWithConfig(&loggerConfig)
	defaultLogger = newLogger

	return nil
}

// LoggerConfig represents the configuration structure for logger initialization
type LoggerConfig struct {
	Level     string
	Format    string
	Output    string
	Timestamp bool
	Caller    bool
	Prefix    string
	Rotation  RotationConfig
}

// RotationConfig represents log rotation configuration
type RotationConfig struct {
	Enabled    bool
	MaxSize    int
	MaxBackups int
	MaxAge     int
	Compress   bool
}

// InitDefault initializes the logger with default settings
func InitDefault() {
	defaultLogger = New()
}

// InitWithLevel initializes the logger with a specific log level
func InitWithLevel(level LogLevel) {
	config := DefaultConfig()
	config.Level = level
	defaultLogger = NewWithConfig(config)
}

// InitForTesting initializes a logger suitable for testing
func InitForTesting() {
	config := Config{
		Level:     DEBUG,
		Format:    "text",
		Output:    os.Stdout,
		Timestamp: false,
		Caller:    true,
		Prefix:    "[TEST]",
	}
	defaultLogger = NewWithConfig(&config)
}