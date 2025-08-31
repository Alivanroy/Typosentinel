package orchestrator

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/repository"
)

// DefaultAuditLogger implements the AuditLogger interface
type DefaultAuditLogger struct {
	config AuditLoggerConfig
	logger *log.Logger
	file   *os.File
	mu     sync.Mutex
}

// AuditLoggerConfig holds configuration for audit logging
type AuditLoggerConfig struct {
	Enabled    bool   `json:"enabled"`
	FilePath   string `json:"file_path"`
	MaxSize    int64  `json:"max_size"`    // Maximum file size in bytes
	MaxBackups int    `json:"max_backups"` // Maximum number of backup files
	Compress   bool   `json:"compress"`    // Whether to compress backup files
}

// NewDefaultAuditLogger creates a new audit logger
func NewDefaultAuditLogger(config AuditLoggerConfig, logger *log.Logger) (*DefaultAuditLogger, error) {
	if logger == nil {
		logger = log.New(log.Writer(), "[AuditLogger] ", log.LstdFlags)
	}

	auditLogger := &DefaultAuditLogger{
		config: config,
		logger: logger,
	}

	if config.Enabled && config.FilePath != "" {
		file, err := os.OpenFile(config.FilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return nil, fmt.Errorf("failed to open audit log file: %w", err)
		}
		auditLogger.file = file
	}

	return auditLogger, nil
}

// LogScanScheduled logs when a scan is scheduled
func (al *DefaultAuditLogger) LogScanScheduled(scan *ScheduledScan, user string) error {
	if !al.config.Enabled {
		return nil
	}

	event := AuditEvent{
		ID:        generateAuditID(),
		Timestamp: time.Now(),
		Event:     "scan_scheduled",
		User:      user,
		Resource:  fmt.Sprintf("scan:%s", scan.ID),
		Action:    "schedule",
		Result:    "success",
		Metadata: map[string]interface{}{
			"scan_name":    scan.Name,
			"schedule":     scan.Schedule,
			"enabled":      scan.Enabled,
			"target_count": len(scan.Targets),
		},
	}

	return al.writeAuditEvent(event)
}

// LogScanStarted logs when a scan starts
func (al *DefaultAuditLogger) LogScanStarted(scan *ScheduledScan) error {
	if !al.config.Enabled {
		return nil
	}

	event := AuditEvent{
		ID:        generateAuditID(),
		Timestamp: time.Now(),
		Event:     "scan_started",
		User:      "system",
		Resource:  fmt.Sprintf("scan:%s", scan.ID),
		Action:    "start",
		Result:    "success",
		Metadata: map[string]interface{}{
			"scan_name": scan.Name,
			"run_count": scan.RunCount,
		},
	}

	return al.writeAuditEvent(event)
}

// LogScanCompleted logs when a scan completes
func (al *DefaultAuditLogger) LogScanCompleted(scan *ScheduledScan, result *repository.ScanResult) error {
	if !al.config.Enabled {
		return nil
	}

	event := AuditEvent{
		ID:        generateAuditID(),
		Timestamp: time.Now(),
		Event:     "scan_completed",
		User:      "system",
		Resource:  fmt.Sprintf("scan:%s", scan.ID),
		Action:    "complete",
		Result:    "success",
		Metadata: map[string]interface{}{
			"scan_name":        scan.Name,
			"repository":       result.Repository.FullName,
			"scan_duration":    result.Duration.String(),
			"status":           result.Status,
			"dependency_files": len(result.DependencyFiles),
		},
	}

	return al.writeAuditEvent(event)
}

// LogPolicyViolation logs when a policy violation occurs
func (al *DefaultAuditLogger) LogPolicyViolation(repo *repository.Repository, policy *ScanPolicy, violation string) error {
	if !al.config.Enabled {
		return nil
	}

	event := AuditEvent{
		ID:        generateAuditID(),
		Timestamp: time.Now(),
		Event:     "policy_violation",
		User:      "system",
		Resource:  fmt.Sprintf("repository:%s", repo.FullName),
		Action:    "policy_check",
		Result:    "violation",
		Metadata: map[string]interface{}{
			"policy_id":   policy.ID,
			"policy_name": policy.Name,
			"violation":   violation,
			"repository":  repo.FullName,
			"platform":    repo.Platform,
		},
	}

	return al.writeAuditEvent(event)
}

// LogDiscoveryEvent logs repository discovery events
func (al *DefaultAuditLogger) LogDiscoveryEvent(platform string, repoCount int, duration time.Duration) error {
	if !al.config.Enabled {
		return nil
	}

	event := AuditEvent{
		ID:        generateAuditID(),
		Timestamp: time.Now(),
		Event:     "repository_discovery",
		User:      "system",
		Resource:  fmt.Sprintf("platform:%s", platform),
		Action:    "discover",
		Result:    "success",
		Metadata: map[string]interface{}{
			"platform":           platform,
			"repositories_found": repoCount,
			"duration":           duration.String(),
		},
	}

	return al.writeAuditEvent(event)
}

// writeAuditEvent writes an audit event to the log
func (al *DefaultAuditLogger) writeAuditEvent(event AuditEvent) error {
	al.mu.Lock()
	defer al.mu.Unlock()

	// Convert event to JSON
	eventJSON, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal audit event: %w", err)
	}

	// Write to file if configured
	if al.file != nil {
		if _, err := al.file.WriteString(string(eventJSON) + "\n"); err != nil {
			return fmt.Errorf("failed to write audit event to file: %w", err)
		}
		if err := al.file.Sync(); err != nil {
			return fmt.Errorf("failed to sync audit log file: %w", err)
		}
	}

	// Also log to standard logger
	al.logger.Printf("AUDIT: %s", string(eventJSON))

	return nil
}

// Close closes the audit logger
func (al *DefaultAuditLogger) Close() error {
	al.mu.Lock()
	defer al.mu.Unlock()

	if al.file != nil {
		return al.file.Close()
	}
	return nil
}

// generateAuditID generates a unique audit event ID
func generateAuditID() string {
	return fmt.Sprintf("audit_%d", time.Now().UnixNano())
}
