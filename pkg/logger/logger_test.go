package logger

import (
	"testing"
)

func TestInitForTesting(t *testing.T) {
	// Test InitForTesting function
	InitForTesting()
	
	// Basic test to ensure no panic
	logger := GetGlobalLogger()
	if logger == nil {
		t.Error("Expected logger to be initialized, got nil")
	}
}

func TestGetGlobalLogger(t *testing.T) {
	// Test GetGlobalLogger function
	InitForTesting()
	
	logger1 := GetGlobalLogger()
	logger2 := GetGlobalLogger()
	
	// Should return the same instance (singleton pattern)
	if logger1 != logger2 {
		t.Error("Expected GetGlobalLogger to return the same instance")
	}
}

func TestLoggingLevels(t *testing.T) {
	// Test different logging levels
	InitForTesting()
	
	logger := GetGlobalLogger()
	
	// Test that logging functions don't panic
	logger.Debug("Debug message")
	logger.Info("Info message")
	logger.Warn("Warning message")
	logger.Error("Error message")
	
	// Test formatted logging
	logger.Debugf("Debug: %s", "formatted")
	logger.Infof("Info: %d", 42)
	logger.Warnf("Warning: %v", true)
	logger.Errorf("Error: %f", 3.14)
}

func TestLoggerConfiguration(t *testing.T) {
	// Test that logger can be configured
	config := LoggerConfig{
		Level:     "debug",
		Format:    "json",
		Output:    "stdout",
		Timestamp: true,
		Caller:    true,
		Prefix:    "[TEST]",
	}
	
	err := InitFromConfig(config)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	
	logger := GetGlobalLogger()
	if logger == nil {
		t.Error("Expected logger to be initialized")
	}
}

func TestSingletonPattern(t *testing.T) {
	// Test that logger follows singleton pattern
	InitForTesting()
	
	logger1 := GetGlobalLogger()
	logger2 := GetGlobalLogger()
	
	if logger1 != logger2 {
		t.Error("Logger should follow singleton pattern")
	}
}

func TestLoggingWithFields(t *testing.T) {
	// Test logging with fields
	InitForTesting()
	
	logger := GetGlobalLogger()
	
	// Test logging with fields
	fields := map[string]interface{}{
		"user_id": 123,
		"action":  "login",
	}
	
	// These should not panic
	logger.Info("User logged in", fields)
	logger.Error("Login failed", fields)
	logger.Debug("Debug info", fields)
	logger.Warn("Warning message", fields)
	
	// Test WithFields
	fieldLogger := logger.WithFields(fields)
	fieldLogger.Info("Message with predefined fields")
	fieldLogger.Error("Error with predefined fields")
}