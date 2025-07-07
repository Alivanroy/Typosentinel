package main

import (
	"errors"
	"time"

	"github.com/Alivanroy/Typosentinel/pkg/logger"
)

func main() {
	// Example 1: Basic logging with default configuration
	logger.Info("Application starting")
	logger.Debug("This debug message won't show with default INFO level")

	// Example 2: Logging with structured fields
	logger.Info("Processing package", map[string]interface{}{
		"package_name": "lodash",
		"version":      "4.17.21",
		"registry":     "npm",
		"scan_id":      "scan-123",
	})

	// Example 3: Error logging with context
	err := errors.New("package not found")
	logger.Error("Failed to fetch package", map[string]interface{}{
		"error":        err.Error(),
		"package_name": "nonexistent-package",
		"registry":     "pypi",
		"retry_count":  3,
	})

	// Example 4: Using formatted logging
	logger.Infof("Scan completed in %v with %d findings", 2*time.Second, 5)
	logger.Warnf("High risk score detected: %.2f", 8.5)

	// Example 5: Using logger with predefined fields
	scanLogger := logger.GetGlobalLogger().WithFields(map[string]interface{}{
		"scan_id":   "scan-456",
		"component": "static-analyzer",
	})

	scanLogger.Info("Starting static analysis")
	scanLogger.Debug("Analyzing file structure")
	scanLogger.Warn("Suspicious pattern detected")
	scanLogger.Error("Analysis failed")

	// Example 6: Changing log level dynamically
	logger.Info("Setting debug level")
	logger.SetGlobalLevel(logger.DEBUG)
	logger.Debug("This debug message will now show")

	// Example 7: JSON format logging
	logger.Info("Switching to JSON format")
	logger.SetGlobalFormat("json")
	logger.Info("This message will be in JSON format", map[string]interface{}{
		"timestamp": time.Now(),
		"user_id":   "user-123",
		"action":    "scan_package",
	})

	// Example 8: Performance logging
	start := time.Now()
	// Simulate some work
	time.Sleep(100 * time.Millisecond)
	duration := time.Since(start)

	logger.Info("Operation completed", map[string]interface{}{
		"operation": "package_analysis",
		"duration":  duration.String(),
		"success":   true,
	})

	logger.Info("Application shutting down")
}
