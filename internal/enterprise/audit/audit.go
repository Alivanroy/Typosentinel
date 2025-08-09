package audit

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/Alivanroy/Typosentinel/pkg/logger"
)

// AuditLogger provides enterprise audit logging capabilities
type AuditLogger struct {
	config    *AuditConfig
	logger    logger.Logger
	writers   []AuditWriter
	buffer    []*AuditEntry
	bufferMu  sync.Mutex
	stopChan  chan struct{}
	wg        sync.WaitGroup
}

// AuditConfig holds audit logging configuration
type AuditConfig struct {
	Enabled         bool                   `yaml:"enabled" json:"enabled"`
	BufferSize      int                    `yaml:"buffer_size" json:"buffer_size"`
	FlushInterval   time.Duration          `yaml:"flush_interval" json:"flush_interval"`
	RetentionPeriod time.Duration          `yaml:"retention_period" json:"retention_period"`
	Destinations    []AuditDestination     `yaml:"destinations" json:"destinations"`
	Filters         []AuditFilter          `yaml:"filters" json:"filters"`
	Encryption      *EncryptionConfig      `yaml:"encryption" json:"encryption"`
	Compression     bool                   `yaml:"compression" json:"compression"`
	Metadata        map[string]interface{} `yaml:"metadata" json:"metadata"`
}

// AuditDestination represents an audit log destination
type AuditDestination struct {
	Type     string                 `yaml:"type" json:"type"` // file, database, syslog, webhook, s3
	Enabled  bool                   `yaml:"enabled" json:"enabled"`
	Settings map[string]interface{} `yaml:"settings" json:"settings"`
}

// AuditFilter defines filtering rules for audit logs
type AuditFilter struct {
	Name      string   `yaml:"name" json:"name"`
	EventType string   `yaml:"event_type" json:"event_type"`
	Severity  string   `yaml:"severity" json:"severity"`
	Users     []string `yaml:"users" json:"users"`
	Actions   []string `yaml:"actions" json:"actions"`
	Enabled   bool     `yaml:"enabled" json:"enabled"`
}

// EncryptionConfig holds encryption settings for audit logs
type EncryptionConfig struct {
	Enabled   bool   `yaml:"enabled" json:"enabled"`
	Algorithm string `yaml:"algorithm" json:"algorithm"`
	KeyPath   string `yaml:"key_path" json:"key_path"`
}

// AuditEntry represents a single audit log entry
type AuditEntry struct {
	ID          string                 `json:"id"`
	Timestamp   time.Time              `json:"timestamp"`
	EventType   string                 `json:"event_type"`
	Action      string                 `json:"action"`
	Resource    string                 `json:"resource"`
	UserID      string                 `json:"user_id"`
	UserName    string                 `json:"user_name"`
	UserRole    string                 `json:"user_role"`
	SourceIP    string                 `json:"source_ip"`
	UserAgent   string                 `json:"user_agent"`
	SessionID   string                 `json:"session_id"`
	Severity    AuditSeverity          `json:"severity"`
	Status      string                 `json:"status"`
	Message     string                 `json:"message"`
	Details     map[string]interface{} `json:"details"`
	RiskScore   float64                `json:"risk_score"`
	Tags        []string               `json:"tags"`
	CorrelationID string               `json:"correlation_id"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// AuditSeverity represents audit event severity levels
type AuditSeverity string

const (
	AuditSeverityInfo     AuditSeverity = "info"
	AuditSeverityWarning  AuditSeverity = "warning"
	AuditSeverityError    AuditSeverity = "error"
	AuditSeverityCritical AuditSeverity = "critical"
)

// AuditWriter interface for different audit destinations
type AuditWriter interface {
	Write(entry *AuditEntry) error
	Flush() error
	Close() error
	Name() string
}

// NewAuditLogger creates a new audit logger
func NewAuditLogger(config *AuditConfig, logger logger.Logger) (*AuditLogger, error) {
	if config == nil {
		config = &AuditConfig{
			Enabled:       true,
			BufferSize:    1000,
			FlushInterval: 30 * time.Second,
			Destinations: []AuditDestination{
				{
					Type:    "file",
					Enabled: true,
					Settings: map[string]interface{}{
						"path": "./logs/audit.log",
					},
				},
			},
		}
	}

	auditLogger := &AuditLogger{
		config:   config,
		logger:   logger,
		buffer:   make([]*AuditEntry, 0, config.BufferSize),
		stopChan: make(chan struct{}),
	}

	// Initialize writers based on configuration
	for _, dest := range config.Destinations {
		if !dest.Enabled {
			continue
		}

		writer, err := createAuditWriter(dest)
		if err != nil {
			return nil, fmt.Errorf("failed to create audit writer for %s: %w", dest.Type, err)
		}

		auditLogger.writers = append(auditLogger.writers, writer)
	}

	return auditLogger, nil
}

// Start starts the audit logger
func (al *AuditLogger) Start(ctx context.Context) error {
	if !al.config.Enabled {
		al.logger.Info("Audit logging is disabled", nil)
		return nil
	}

	al.wg.Add(1)
	go al.flushWorker()

	// Start cleanup worker if retention period is configured
	if al.config.RetentionPeriod > 0 {
		al.wg.Add(1)
		go al.cleanupWorker()
	}

	al.logger.Info("Audit logger started", map[string]interface{}{
		"writers":         len(al.writers),
		"buffer_size":     al.config.BufferSize,
		"flush_interval":  al.config.FlushInterval,
		"retention_period": al.config.RetentionPeriod,
	})

	return nil
}

// Stop stops the audit logger
func (al *AuditLogger) Stop() error {
	close(al.stopChan)
	al.wg.Wait()

	// Flush remaining entries
	al.flush()

	// Close all writers
	for _, writer := range al.writers {
		if err := writer.Close(); err != nil {
			al.logger.Error("Failed to close audit writer", map[string]interface{}{
				"writer": writer.Name(),
				"error":  err,
			})
		}
	}

	al.logger.Info("Audit logger stopped", nil)
	return nil
}

// LogEvent logs an audit event
func (al *AuditLogger) LogEvent(ctx context.Context, eventType, action, resource string, details map[string]interface{}) {
	if !al.config.Enabled {
		return
	}

	entry := &AuditEntry{
		ID:        generateAuditID(),
		Timestamp: time.Now(),
		EventType: eventType,
		Action:    action,
		Resource:  resource,
		Severity:  AuditSeverityInfo,
		Status:    "success",
		Details:   details,
		Metadata:  make(map[string]interface{}),
	}

	// Extract user information from context
	if userID, ok := ctx.Value("user_id").(string); ok {
		entry.UserID = userID
	}
	if userName, ok := ctx.Value("user_name").(string); ok {
		entry.UserName = userName
	}
	if userRole, ok := ctx.Value("user_role").(string); ok {
		entry.UserRole = userRole
	}
	if sourceIP, ok := ctx.Value("source_ip").(string); ok {
		entry.SourceIP = sourceIP
	}
	if sessionID, ok := ctx.Value("session_id").(string); ok {
		entry.SessionID = sessionID
	}
	if correlationID, ok := ctx.Value("correlation_id").(string); ok {
		entry.CorrelationID = correlationID
	}

	al.addToBuffer(entry)
}

// LogSecurityEvent logs a security-related audit event
func (al *AuditLogger) LogSecurityEvent(ctx context.Context, action, resource, message string, severity AuditSeverity, details map[string]interface{}) {
	if !al.config.Enabled {
		return
	}

	entry := &AuditEntry{
		ID:        generateAuditID(),
		Timestamp: time.Now(),
		EventType: "security",
		Action:    action,
		Resource:  resource,
		Message:   message,
		Severity:  severity,
		Status:    "detected",
		Details:   details,
		Tags:      []string{"security", "threat"},
		RiskScore: calculateRiskScore(severity, action),
		Metadata:  make(map[string]interface{}),
	}

	// Extract context information
	if userID, ok := ctx.Value("user_id").(string); ok {
		entry.UserID = userID
	}
	if sourceIP, ok := ctx.Value("source_ip").(string); ok {
		entry.SourceIP = sourceIP
	}
	if correlationID, ok := ctx.Value("correlation_id").(string); ok {
		entry.CorrelationID = correlationID
	}

	al.addToBuffer(entry)
}

// LogComplianceEvent logs a compliance-related audit event
func (al *AuditLogger) LogComplianceEvent(ctx context.Context, action, resource, regulation string, compliant bool, details map[string]interface{}) {
	if !al.config.Enabled {
		return
	}

	status := "compliant"
	severity := AuditSeverityInfo
	if !compliant {
		status = "non_compliant"
		severity = AuditSeverityWarning
	}

	entry := &AuditEntry{
		ID:        generateAuditID(),
		Timestamp: time.Now(),
		EventType: "compliance",
		Action:    action,
		Resource:  resource,
		Severity:  severity,
		Status:    status,
		Details:   details,
		Tags:      []string{"compliance", regulation},
		Metadata: map[string]interface{}{
			"regulation": regulation,
			"compliant":  compliant,
		},
	}

	// Extract context information
	if userID, ok := ctx.Value("user_id").(string); ok {
		entry.UserID = userID
	}
	if correlationID, ok := ctx.Value("correlation_id").(string); ok {
		entry.CorrelationID = correlationID
	}

	al.addToBuffer(entry)
}

// addToBuffer adds an entry to the buffer
func (al *AuditLogger) addToBuffer(entry *AuditEntry) {
	// Apply filters
	if !al.shouldLog(entry) {
		return
	}

	al.bufferMu.Lock()
	defer al.bufferMu.Unlock()

	al.buffer = append(al.buffer, entry)

	// Flush if buffer is full
	if len(al.buffer) >= al.config.BufferSize {
		go al.flush()
	}
}

// shouldLog checks if an entry should be logged based on filters
func (al *AuditLogger) shouldLog(entry *AuditEntry) bool {
	for _, filter := range al.config.Filters {
		if !filter.Enabled {
			continue
		}

		// Check event type filter
		if filter.EventType != "" && filter.EventType != entry.EventType {
			continue
		}

		// Check severity filter
		if filter.Severity != "" && filter.Severity != string(entry.Severity) {
			continue
		}

		// Check user filter
		if len(filter.Users) > 0 {
			userMatch := false
			for _, user := range filter.Users {
				if user == entry.UserID || user == entry.UserName {
					userMatch = true
					break
				}
			}
			if !userMatch {
				continue
			}
		}

		// Check action filter
		if len(filter.Actions) > 0 {
			actionMatch := false
			for _, action := range filter.Actions {
				if action == entry.Action {
					actionMatch = true
					break
				}
			}
			if !actionMatch {
				continue
			}
		}

		// If we reach here, the filter matches - exclude the entry
		return false
	}

	// No filters matched, include the entry
	return true
}

// flushWorker periodically flushes the buffer
func (al *AuditLogger) flushWorker() {
	defer al.wg.Done()

	ticker := time.NewTicker(al.config.FlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			al.flush()
		case <-al.stopChan:
			return
		}
	}
}

// flush writes buffered entries to all writers
func (al *AuditLogger) flush() {
	al.bufferMu.Lock()
	if len(al.buffer) == 0 {
		al.bufferMu.Unlock()
		return
	}

	entries := make([]*AuditEntry, len(al.buffer))
	copy(entries, al.buffer)
	al.buffer = al.buffer[:0] // Clear buffer
	al.bufferMu.Unlock()

	// Write to all configured writers
	for _, writer := range al.writers {
		for _, entry := range entries {
			if err := writer.Write(entry); err != nil {
				al.logger.Error("Failed to write audit entry", map[string]interface{}{
					"writer": writer.Name(),
					"error":  err,
					"entry":  entry.ID,
				})
			}
		}

		if err := writer.Flush(); err != nil {
			al.logger.Error("Failed to flush audit writer", map[string]interface{}{
				"writer": writer.Name(),
				"error":  err,
			})
		}
	}
}

// GetAuditEntries retrieves audit entries based on criteria
func (al *AuditLogger) GetAuditEntries(ctx context.Context, criteria *AuditSearchCriteria) ([]*AuditEntry, error) {
	// This would typically query from persistent storage
	// For now, return empty slice as this requires database integration
	return []*AuditEntry{}, nil
}

// AuditSearchCriteria defines search criteria for audit entries
type AuditSearchCriteria struct {
	StartTime   *time.Time `json:"start_time"`
	EndTime     *time.Time `json:"end_time"`
	EventType   string     `json:"event_type"`
	Action      string     `json:"action"`
	UserID      string     `json:"user_id"`
	Resource    string     `json:"resource"`
	Severity    string     `json:"severity"`
	Limit       int        `json:"limit"`
	Offset      int        `json:"offset"`
}

// Helper functions

func generateAuditID() string {
	return fmt.Sprintf("audit_%d_%d", time.Now().UnixNano(), os.Getpid())
}

func calculateRiskScore(severity AuditSeverity, action string) float64 {
	baseScore := 0.0
	switch severity {
	case AuditSeverityInfo:
		baseScore = 1.0
	case AuditSeverityWarning:
		baseScore = 3.0
	case AuditSeverityError:
		baseScore = 7.0
	case AuditSeverityCritical:
		baseScore = 10.0
	}

	// Adjust based on action type
	switch action {
	case "login_failed", "unauthorized_access":
		baseScore *= 1.5
	case "privilege_escalation", "data_exfiltration":
		baseScore *= 2.0
	case "system_compromise", "malware_detected":
		baseScore *= 3.0
	}

	return baseScore
}

func createAuditWriter(dest AuditDestination) (AuditWriter, error) {
	switch dest.Type {
	case "file":
		return NewFileAuditWriter(dest.Settings)
	case "database":
		return NewDatabaseAuditWriter(dest.Settings)
	case "syslog":
		return NewSyslogAuditWriter(dest.Settings)
	case "webhook":
		return NewWebhookAuditWriter(dest.Settings)
	default:
		return nil, fmt.Errorf("unsupported audit writer type: %s", dest.Type)
	}
}

// cleanupWorker periodically cleans up expired audit logs
func (al *AuditLogger) cleanupWorker() {
	defer al.wg.Done()

	// Run cleanup every 24 hours
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	// Run initial cleanup after 1 hour
	initialTimer := time.NewTimer(1 * time.Hour)
	defer initialTimer.Stop()

	for {
		select {
		case <-initialTimer.C:
			al.cleanupExpiredLogs()
			initialTimer.Stop() // Prevent further triggers
		case <-ticker.C:
			al.cleanupExpiredLogs()
		case <-al.stopChan:
			return
		}
	}
}

// cleanupExpiredLogs removes audit logs older than the retention period
func (al *AuditLogger) cleanupExpiredLogs() {
	if al.config.RetentionPeriod <= 0 {
		return
	}

	for _, writer := range al.writers {
		if dbWriter, ok := writer.(*DatabaseAuditWriter); ok {
			if err := dbWriter.CleanupExpiredLogs(al.config.RetentionPeriod); err != nil {
				al.logger.Error("Failed to cleanup expired audit logs", map[string]interface{}{
					"writer":           writer.Name(),
					"error":            err,
					"retention_period": al.config.RetentionPeriod,
				})
			} else {
				al.logger.Info("Successfully cleaned up expired audit logs", map[string]interface{}{
					"writer":           writer.Name(),
					"retention_period": al.config.RetentionPeriod,
				})
			}
		}
	}
}