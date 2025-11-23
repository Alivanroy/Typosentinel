package security

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

// AuditLogger provides secure audit logging capabilities
type AuditLogger struct {
	logFile    *os.File
	logPath    string
	encryption *EncryptionService
	config     *AuditLogConfig
}

// AuditLogConfig holds audit logging configuration
type AuditLogConfig struct {
	LogPath         string `json:"log_path"`
	EncryptLogs     bool   `json:"encrypt_logs"`
	MaxFileSize     int64  `json:"max_file_size"`
	MaxFiles        int    `json:"max_files"`
	LogLevel        string `json:"log_level"`
	IncludeMetadata bool   `json:"include_metadata"`
}

// AuditEvent represents a generic audit event
type AuditEvent struct {
	EventType string                 `json:"event_type"`
	IPAddress string                 `json:"ip_address,omitempty"`
	UserAgent string                 `json:"user_agent,omitempty"`
	UserID    *string                `json:"user_id,omitempty"`
	Success   bool                   `json:"success"`
	EventData map[string]interface{} `json:"event_data,omitempty"`
}

// AuditLogEntry represents a single audit log entry
type AuditLogEntry struct {
	Timestamp   time.Time              `json:"timestamp"`
	Level       string                 `json:"level"`
	EventType   string                 `json:"event_type"`
	UserID      string                 `json:"user_id,omitempty"`
	IPAddress   string                 `json:"ip_address,omitempty"`
	UserAgent   string                 `json:"user_agent,omitempty"`
	Action      string                 `json:"action"`
	Resource    string                 `json:"resource,omitempty"`
	Result      string                 `json:"result"`
	Message     string                 `json:"message"`
	Details     map[string]interface{} `json:"details,omitempty"`
	RequestID   string                 `json:"request_id,omitempty"`
	SessionID   string                 `json:"session_id,omitempty"`
	Fingerprint string                 `json:"fingerprint"`
}

// NewAuditLogger creates a new audit logger
func NewAuditLogger(config *AuditLogConfig) (*AuditLogger, error) {
	if config == nil {
		config = &AuditLogConfig{
			LogPath:         "/var/log/typosentinel/audit.log",
			EncryptLogs:     true,
			MaxFileSize:     100 * 1024 * 1024, // 100MB
			MaxFiles:        10,
			LogLevel:        "INFO",
			IncludeMetadata: true,
		}
	}

	// Create log directory if it doesn't exist
	logDir := filepath.Dir(config.LogPath)
	if err := os.MkdirAll(logDir, 0750); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}

	// Open log file
	logFile, err := os.OpenFile(config.LogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %w", err)
	}

	logger := &AuditLogger{
		logFile: logFile,
		logPath: config.LogPath,
		config:  config,
	}

	// Initialize encryption if enabled
	if config.EncryptLogs {
		encryption, err := NewEncryptionService()
		if err != nil {
			log.Printf("Warning: Failed to initialize encryption for audit logs: %v", err)
		} else {
			logger.encryption = encryption
		}
	}

	return logger, nil
}

// LogAuthentication logs authentication events
func (al *AuditLogger) LogAuthentication(userID, ipAddress, userAgent string, success bool, details map[string]interface{}) {
	result := "SUCCESS"
	level := "INFO"
	if !success {
		result = "FAILURE"
		level = "WARN"
	}

	entry := AuditLogEntry{
		Timestamp: time.Now(),
		Level:     level,
		EventType: "AUTHENTICATION",
		UserID:    userID,
		IPAddress: ipAddress,
		UserAgent: userAgent,
		Action:    "LOGIN",
		Result:    result,
		Message:   fmt.Sprintf("User authentication %s", result),
		Details:   details,
	}

	al.writeLogEntry(entry)
}

// LogAuthorization logs authorization events
func (al *AuditLogger) LogAuthorization(userID, ipAddress, action, resource string, allowed bool, details map[string]interface{}) {
	result := "ALLOWED"
	level := "INFO"
	if !allowed {
		result = "DENIED"
		level = "WARN"
	}

	entry := AuditLogEntry{
		Timestamp: time.Now(),
		Level:     level,
		EventType: "AUTHORIZATION",
		UserID:    userID,
		IPAddress: ipAddress,
		Action:    action,
		Resource:  resource,
		Result:    result,
		Message:   fmt.Sprintf("Access %s for action %s on resource %s", result, action, resource),
		Details:   details,
	}

	al.writeLogEntry(entry)
}

// LogDataAccess logs data access events
func (al *AuditLogger) LogDataAccess(userID, ipAddress, action, resource string, details map[string]interface{}) {
	entry := AuditLogEntry{
		Timestamp: time.Now(),
		Level:     "INFO",
		EventType: "DATA_ACCESS",
		UserID:    userID,
		IPAddress: ipAddress,
		Action:    action,
		Resource:  resource,
		Result:    "SUCCESS",
		Message:   fmt.Sprintf("Data access: %s on %s", action, resource),
		Details:   details,
	}

	al.writeLogEntry(entry)
}

// LogSecurityViolation logs security violations
func (al *AuditLogger) LogSecurityViolation(userID, ipAddress, userAgent, violation string, severity string, details map[string]interface{}) {
	level := "ERROR"
	if severity == "CRITICAL" {
		level = "FATAL"
	}

	entry := AuditLogEntry{
		Timestamp: time.Now(),
		Level:     level,
		EventType: "SECURITY_VIOLATION",
		UserID:    userID,
		IPAddress: ipAddress,
		UserAgent: userAgent,
		Action:    "VIOLATION",
		Result:    "BLOCKED",
		Message:   fmt.Sprintf("Security violation: %s", violation),
		Details:   details,
	}

	al.writeLogEntry(entry)
}

// LogConfigChange logs configuration changes
func (al *AuditLogger) LogConfigChange(userID, ipAddress, configKey, oldValue, newValue string, details map[string]interface{}) {
	entry := AuditLogEntry{
		Timestamp: time.Now(),
		Level:     "INFO",
		EventType: "CONFIG_CHANGE",
		UserID:    userID,
		IPAddress: ipAddress,
		Action:    "UPDATE",
		Resource:  configKey,
		Result:    "SUCCESS",
		Message:   fmt.Sprintf("Configuration changed: %s", configKey),
		Details: map[string]interface{}{
			"old_value": oldValue,
			"new_value": newValue,
		},
	}

	if details != nil {
		for k, v := range details {
			entry.Details[k] = v
		}
	}

	al.writeLogEntry(entry)
}

// LogAPIAccess logs API access events
func (al *AuditLogger) LogAPIAccess(userID, ipAddress, userAgent, method, endpoint string, statusCode int, responseTime time.Duration, details map[string]interface{}) {
	level := "INFO"
	result := "SUCCESS"

	if statusCode >= 400 {
		level = "WARN"
		result = "ERROR"
	}

	if statusCode >= 500 {
		level = "ERROR"
	}

	entry := AuditLogEntry{
		Timestamp: time.Now(),
		Level:     level,
		EventType: "API_ACCESS",
		UserID:    userID,
		IPAddress: ipAddress,
		UserAgent: userAgent,
		Action:    method,
		Resource:  endpoint,
		Result:    result,
		Message:   fmt.Sprintf("API access: %s %s (%d)", method, endpoint, statusCode),
		Details: map[string]interface{}{
			"status_code":   statusCode,
			"response_time": responseTime.Milliseconds(),
		},
	}

	if details != nil {
		for k, v := range details {
			entry.Details[k] = v
		}
	}

	al.writeLogEntry(entry)
}

// LogSystemEvent logs system-level events
func (al *AuditLogger) LogSystemEvent(eventType, action, message string, details map[string]interface{}) {
	entry := AuditLogEntry{
		Timestamp: time.Now(),
		Level:     "INFO",
		EventType: eventType,
		Action:    action,
		Result:    "SUCCESS",
		Message:   message,
		Details:   details,
	}

	al.writeLogEntry(entry)
}

// LogEvent logs a generic audit event
func (al *AuditLogger) LogEvent(event AuditEvent) {
	entry := AuditLogEntry{
		Timestamp: time.Now(),
		Level:     "INFO",
		EventType: event.EventType,
		UserID:    "",
		IPAddress: event.IPAddress,
		UserAgent: event.UserAgent,
		Action:    "EVENT",
		Result:    "SUCCESS",
		Message:   "Generic audit event",
		Details:   event.EventData,
	}

	if event.UserID != nil {
		entry.UserID = *event.UserID
	}

	if !event.Success {
		entry.Result = "FAILURE"
		entry.Level = "WARN"
	}

	al.writeLogEntry(entry)
}

// writeLogEntry writes a log entry to the audit log
func (al *AuditLogger) writeLogEntry(entry AuditLogEntry) {
	// Generate fingerprint for deduplication
	entry.Fingerprint = al.generateFingerprint(entry)

	// Add metadata if enabled
	if al.config.IncludeMetadata {
		if entry.Details == nil {
			entry.Details = make(map[string]interface{})
		}
		entry.Details["hostname"], _ = os.Hostname()
		entry.Details["pid"] = os.Getpid()
	}

	// Serialize to JSON
	jsonData, err := json.Marshal(entry)
	if err != nil {
		log.Printf("Failed to marshal audit log entry: %v", err)
		return
	}

	// Encrypt if enabled
	var logData string
	if al.encryption != nil {
		encrypted, err := al.encryption.EncryptString(string(jsonData))
		if err != nil {
			log.Printf("Failed to encrypt audit log entry: %v", err)
			logData = string(jsonData) // Fall back to unencrypted
		} else {
			logData = "ENCRYPTED:" + encrypted
		}
	} else {
		logData = string(jsonData)
	}

	// Write to log file
	if _, err := al.logFile.WriteString(logData + "\n"); err != nil {
		log.Printf("Failed to write audit log entry: %v", err)
		return
	}

	// Flush to ensure data is written
	if err := al.logFile.Sync(); err != nil {
		log.Printf("Failed to sync audit log file: %v", err)
	}

	// Check file size and rotate if necessary
	al.checkAndRotateLog()
}

// generateFingerprint generates a fingerprint for log entry deduplication
func (al *AuditLogger) generateFingerprint(entry AuditLogEntry) string {
	data := fmt.Sprintf("%s:%s:%s:%s:%s:%s",
		entry.EventType,
		entry.UserID,
		entry.IPAddress,
		entry.Action,
		entry.Resource,
		entry.Message,
	)
	return fmt.Sprintf("%x", data)
}

// checkAndRotateLog checks if log rotation is needed
func (al *AuditLogger) checkAndRotateLog() {
	// Get current file size
	fileInfo, err := al.logFile.Stat()
	if err != nil {
		log.Printf("Failed to get log file stats: %v", err)
		return
	}

	// Check if rotation is needed
	if fileInfo.Size() >= al.config.MaxFileSize {
		al.rotateLog()
	}
}

// rotateLog rotates the audit log file
func (al *AuditLogger) rotateLog() {
	// Close current file
	if err := al.logFile.Close(); err != nil {
		log.Printf("Failed to close log file for rotation: %v", err)
	}

	// Rotate existing files
	for i := al.config.MaxFiles - 1; i > 0; i-- {
		oldPath := fmt.Sprintf("%s.%d", al.logPath, i)
		newPath := fmt.Sprintf("%s.%d", al.logPath, i+1)

		if _, err := os.Stat(oldPath); err == nil {
			if err := os.Rename(oldPath, newPath); err != nil {
				log.Printf("Failed to rotate log file %s to %s: %v", oldPath, newPath, err)
			}
		}
	}

	// Move current log to .1
	rotatedPath := al.logPath + ".1"
	if err := os.Rename(al.logPath, rotatedPath); err != nil {
		log.Printf("Failed to rotate current log file: %v", err)
	}

	// Create new log file
	logFile, err := os.OpenFile(al.logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
	if err != nil {
		log.Printf("Failed to create new log file after rotation: %v", err)
		return
	}

	al.logFile = logFile
}

// Close closes the audit logger
func (al *AuditLogger) Close() error {
	if al.logFile != nil {
		return al.logFile.Close()
	}
	return nil
}

// GetLogStats returns statistics about the audit log
func (al *AuditLogger) GetLogStats() (map[string]interface{}, error) {
	fileInfo, err := al.logFile.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to get log file stats: %w", err)
	}

	stats := map[string]interface{}{
		"log_path":      al.logPath,
		"file_size":     fileInfo.Size(),
		"max_size":      al.config.MaxFileSize,
		"encrypted":     al.config.EncryptLogs,
		"last_modified": fileInfo.ModTime(),
	}

	return stats, nil
}
