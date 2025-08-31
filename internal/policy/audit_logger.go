package policy

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/auth"
)

// DefaultAuditLogger provides a default implementation of AuditLogger
type DefaultAuditLogger struct {
	config *AuditConfig
	logger *log.Logger
	file   *os.File
}

// AuditConfig contains configuration for the audit logger
type AuditConfig struct {
	Enabled         bool   `json:"enabled"`
	LogFile         string `json:"log_file"`
	MaxFileSize     int64  `json:"max_file_size"`    // in bytes
	MaxBackups      int    `json:"max_backups"`      // number of backup files to keep
	MaxAge          int    `json:"max_age"`          // days to keep log files
	Compress        bool   `json:"compress"`         // compress backup files
	IncludeMetadata bool   `json:"include_metadata"` // include detailed metadata
	Format          string `json:"format"`           // "json" or "text"
}

// AuditEntry represents an audit log entry
type AuditEntry struct {
	Timestamp time.Time              `json:"timestamp"`
	EventType string                 `json:"event_type"`
	EventID   string                 `json:"event_id"`
	UserID    string                 `json:"user_id,omitempty"`
	Resource  string                 `json:"resource"`
	Action    string                 `json:"action"`
	Result    string                 `json:"result"`
	Severity  string                 `json:"severity"`
	Message   string                 `json:"message"`
	Details   map[string]interface{} `json:"details,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// NewDefaultAuditLogger creates a new default audit logger
func NewDefaultAuditLogger(config *AuditConfig) (*DefaultAuditLogger, error) {
	if !config.Enabled {
		return &DefaultAuditLogger{
			config: config,
			logger: log.Default(),
		}, nil
	}

	// Create log directory if it doesn't exist
	if config.LogFile != "" {
		dir := filepath.Dir(config.LogFile)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create log directory: %w", err)
		}

		// Open log file
		file, err := os.OpenFile(config.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return nil, fmt.Errorf("failed to open audit log file: %w", err)
		}

		logger := log.New(file, "", 0) // No prefix, we'll format ourselves
		return &DefaultAuditLogger{
			config: config,
			logger: logger,
			file:   file,
		}, nil
	}

	return &DefaultAuditLogger{
		config: config,
		logger: log.Default(),
	}, nil
}

// Close closes the audit logger and any open files
func (al *DefaultAuditLogger) Close() error {
	if al.file != nil {
		return al.file.Close()
	}
	return nil
}

// LogViolation logs a policy violation
func (al *DefaultAuditLogger) LogViolation(violation *auth.PolicyViolation) error {
	if !al.config.Enabled {
		return nil
	}

	entry := &AuditEntry{
		Timestamp: time.Now(),
		EventType: "policy_violation",
		EventID:   violation.ID,
		UserID:    "", // Not available in PolicyViolation struct
		Resource:  "", // Will extract from context if available
		Action:    "policy_check",
		Result:    "violation_detected",
		Severity:  violation.Severity,
		Message:   fmt.Sprintf("Policy violation detected: %s", violation.Description),
		Details: map[string]interface{}{
			"policy_id":   violation.PolicyID,
			"policy_name": violation.PolicyName,
			"created_at":  violation.CreatedAt,
			"status":      string(violation.Status),
		},
	}

	// Extract resource from context if available
	if violation.Context != nil && violation.Context.ScanResult != nil {
		entry.Resource = violation.Context.ScanResult.Target
	}

	if al.config.IncludeMetadata {
		entry.Metadata = map[string]interface{}{
			"approval_required": violation.ApprovalRequired,
			"auto_remediate":    violation.Remediation != nil,
		}
		if violation.Remediation != nil {
			entry.Metadata["remediation_type"] = violation.Remediation.Type
		}
		if violation.ResolvedAt != nil {
			entry.Metadata["resolved_at"] = violation.ResolvedAt
		}
	}

	return al.writeAuditEntry(entry)
}

// LogRemediation logs a remediation action
func (al *DefaultAuditLogger) LogRemediation(violation *auth.PolicyViolation, action *auth.RemediationAction) error {
	if !al.config.Enabled {
		return nil
	}

	entry := &AuditEntry{
		Timestamp: time.Now(),
		EventType: "remediation_action",
		EventID:   fmt.Sprintf("%s_remediation", violation.ID),
		UserID:    "", // Not available in PolicyViolation struct
		Resource:  "", // Will extract from context if available
		Action:    action.Type,
		Result:    "executed",
		Severity:  violation.Severity,
		Message:   fmt.Sprintf("Remediation action '%s' executed for violation %s", action.Type, violation.ID),
		Details: map[string]interface{}{
			"violation_id":     violation.ID,
			"policy_id":        violation.PolicyID,
			"remediation_type": action.Type,
			"executed_at":      time.Now(),
		},
	}

	// Extract resource from context if available
	if violation.Context != nil && violation.Context.ScanResult != nil {
		entry.Resource = violation.Context.ScanResult.Target
	}

	if al.config.IncludeMetadata {
		entry.Metadata = map[string]interface{}{
			"status":      action.Status,
			"description": action.Description,
			"assigned_to": action.AssignedTo,
		}
		if action.Metadata != nil {
			entry.Metadata["action_metadata"] = action.Metadata
		}
		if action.DueDate != nil {
			entry.Metadata["due_date"] = action.DueDate
		}
		if action.CompletedAt != nil {
			entry.Metadata["completed_at"] = action.CompletedAt
		}
	}

	return al.writeAuditEntry(entry)
}

// writeAuditEntry writes an audit entry to the log
func (al *DefaultAuditLogger) writeAuditEntry(entry *AuditEntry) error {
	var logLine string

	switch al.config.Format {
	case "json":
		jsonData, err := json.Marshal(entry)
		if err != nil {
			return fmt.Errorf("failed to marshal audit entry: %w", err)
		}
		logLine = string(jsonData)
	case "text":
		logLine = al.formatTextEntry(entry)
	default:
		// Default to JSON
		jsonData, err := json.Marshal(entry)
		if err != nil {
			return fmt.Errorf("failed to marshal audit entry: %w", err)
		}
		logLine = string(jsonData)
	}

	al.logger.Println(logLine)

	// Check if we need to rotate the log file
	if al.file != nil && al.config.MaxFileSize > 0 {
		if err := al.checkLogRotation(); err != nil {
			// Log rotation failed, but don't fail the audit log
			fmt.Printf("Log rotation failed: %v\n", err)
		}
	}

	return nil
}

// formatTextEntry formats an audit entry as human-readable text
func (al *DefaultAuditLogger) formatTextEntry(entry *AuditEntry) string {
	return fmt.Sprintf("[%s] %s %s %s %s - %s (Event: %s, Resource: %s)",
		entry.Timestamp.Format(time.RFC3339),
		entry.Severity,
		entry.EventType,
		entry.Action,
		entry.Result,
		entry.Message,
		entry.EventID,
		entry.Resource,
	)
}

// checkLogRotation checks if log rotation is needed and performs it
func (al *DefaultAuditLogger) checkLogRotation() error {
	if al.file == nil {
		return nil
	}

	// Get file info
	fileInfo, err := al.file.Stat()
	if err != nil {
		return fmt.Errorf("failed to get file info: %w", err)
	}

	// Check if rotation is needed
	if fileInfo.Size() >= al.config.MaxFileSize {
		return al.rotateLog()
	}

	return nil
}

// rotateLog rotates the current log file
func (al *DefaultAuditLogger) rotateLog() error {
	// Close current file
	if err := al.file.Close(); err != nil {
		return fmt.Errorf("failed to close current log file: %w", err)
	}

	// Rotate existing backup files
	for i := al.config.MaxBackups - 1; i >= 1; i-- {
		oldName := fmt.Sprintf("%s.%d", al.config.LogFile, i)
		newName := fmt.Sprintf("%s.%d", al.config.LogFile, i+1)

		if _, err := os.Stat(oldName); err == nil {
			if err := os.Rename(oldName, newName); err != nil {
				return fmt.Errorf("failed to rotate log file %s to %s: %w", oldName, newName, err)
			}
		}
	}

	// Move current log to .1
	backupName := fmt.Sprintf("%s.1", al.config.LogFile)
	if err := os.Rename(al.config.LogFile, backupName); err != nil {
		return fmt.Errorf("failed to move current log to backup: %w", err)
	}

	// Compress backup if configured
	if al.config.Compress {
		if err := al.compressBackupFile(backupName); err != nil {
			// Log compression failure but don't fail the rotation
			fmt.Printf("Failed to compress backup file %s: %v\n", backupName, err)
		}
	}

	// Create new log file
	file, err := os.OpenFile(al.config.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to create new log file: %w", err)
	}

	al.file = file
	al.logger = log.New(file, "", 0)

	// Clean up old backups
	al.cleanupOldBackups()

	return nil
}

// cleanupOldBackups removes old backup files based on MaxBackups and MaxAge
func (al *DefaultAuditLogger) cleanupOldBackups() {
	// Remove backups beyond MaxBackups
	for i := al.config.MaxBackups + 1; i <= al.config.MaxBackups+10; i++ {
		backupName := fmt.Sprintf("%s.%d", al.config.LogFile, i)
		if _, err := os.Stat(backupName); err == nil {
			os.Remove(backupName)
		}
	}

	// Remove backups older than MaxAge days
	if al.config.MaxAge > 0 {
		cutoff := time.Now().AddDate(0, 0, -al.config.MaxAge)

		for i := 1; i <= al.config.MaxBackups; i++ {
			backupName := fmt.Sprintf("%s.%d", al.config.LogFile, i)
			if fileInfo, err := os.Stat(backupName); err == nil {
				if fileInfo.ModTime().Before(cutoff) {
					os.Remove(backupName)
				}
			}
		}
	}
}

// compressBackupFile compresses a backup log file using gzip
func (al *DefaultAuditLogger) compressBackupFile(filename string) error {
	// Open the source file
	sourceFile, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("failed to open source file: %w", err)
	}
	defer sourceFile.Close()

	// Create the compressed file
	compressedFilename := filename + ".gz"
	compressedFile, err := os.Create(compressedFilename)
	if err != nil {
		return fmt.Errorf("failed to create compressed file: %w", err)
	}
	defer compressedFile.Close()

	// Create gzip writer
	gzipWriter := gzip.NewWriter(compressedFile)
	defer gzipWriter.Close()

	// Copy data from source to compressed file
	_, err = io.Copy(gzipWriter, sourceFile)
	if err != nil {
		return fmt.Errorf("failed to compress file: %w", err)
	}

	// Close gzip writer to flush data
	if err := gzipWriter.Close(); err != nil {
		return fmt.Errorf("failed to close gzip writer: %w", err)
	}

	// Remove the original uncompressed file
	if err := os.Remove(filename); err != nil {
		return fmt.Errorf("failed to remove original file: %w", err)
	}

	return nil
}
