package audit

import (
	"encoding/json"
	"fmt"
	"log/syslog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"bytes"
	"database/sql"
	_ "github.com/lib/pq" // PostgreSQL driver
)

// FileAuditWriter writes audit logs to files
type FileAuditWriter struct {
	filePath string
	file     *os.File
	mu       sync.Mutex
}

// NewFileAuditWriter creates a new file audit writer
func NewFileAuditWriter(settings map[string]interface{}) (AuditWriter, error) {
	path, ok := settings["path"].(string)
	if !ok {
		return nil, fmt.Errorf("file path is required for file audit writer")
	}

	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create audit log directory: %w", err)
	}

	// Open file for appending
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open audit log file: %w", err)
	}

	return &FileAuditWriter{
		filePath: path,
		file:     file,
	}, nil
}

func (f *FileAuditWriter) Write(entry *AuditEntry) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("failed to marshal audit entry: %w", err)
	}

	_, err = f.file.WriteString(string(data) + "\n")
	return err
}

func (f *FileAuditWriter) Flush() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.file.Sync()
}

func (f *FileAuditWriter) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.file.Close()
}

func (f *FileAuditWriter) Name() string {
	return "file"
}

// DatabaseAuditWriter writes audit logs to a database
type DatabaseAuditWriter struct {
	connectionString string
	tableName        string
	db              *sql.DB
	buffer          []*AuditEntry
	bufferSize      int
	mu              sync.Mutex
}

// NewDatabaseAuditWriter creates a new database audit writer
func NewDatabaseAuditWriter(settings map[string]interface{}) (AuditWriter, error) {
	connStr, ok := settings["connection_string"].(string)
	if !ok {
		return nil, fmt.Errorf("connection_string is required for database audit writer")
	}

	tableName, ok := settings["table_name"].(string)
	if !ok {
		tableName = "audit_logs"
	}

	bufferSize := 100
	if size, ok := settings["buffer_size"].(int); ok {
		bufferSize = size
	}

	// Initialize database connection
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to open database connection: %w", err)
	}

	// Test connection
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return &DatabaseAuditWriter{
		connectionString: connStr,
		tableName:        tableName,
		db:              db,
		buffer:          make([]*AuditEntry, 0, bufferSize),
		bufferSize:      bufferSize,
	}, nil
}

func (d *DatabaseAuditWriter) Write(entry *AuditEntry) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.buffer = append(d.buffer, entry)

	// Flush if buffer is full
	if len(d.buffer) >= d.bufferSize {
		return d.flushBuffer()
	}

	return nil
}

func (d *DatabaseAuditWriter) Flush() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.flushBuffer()
}

func (d *DatabaseAuditWriter) flushBuffer() error {
	if len(d.buffer) == 0 {
		return nil
	}

	// Prepare batch insert query
	query := `
		INSERT INTO audit_logs (
			id, timestamp, user_id, action, resource, 
			source_ip, user_agent, severity, details, metadata
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`

	// Begin transaction for batch insert
	tx, err := d.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Prepare statement
	stmt, err := tx.Prepare(query)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	// Insert each audit entry
	for _, entry := range d.buffer {
		detailsJSON, _ := json.Marshal(entry.Details)
		metadataJSON, _ := json.Marshal(entry.Metadata)

		_, err := stmt.Exec(
			entry.ID,
			entry.Timestamp,
			entry.UserID,
			entry.Action,
			entry.Resource,
			entry.SourceIP,
			entry.UserAgent,
			string(entry.Severity),
			string(detailsJSON),
			string(metadataJSON),
		)
		if err != nil {
			return fmt.Errorf("failed to insert audit entry %s: %w", entry.ID, err)
		}
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	// Clear buffer after successful insertion
	d.buffer = d.buffer[:0]
	return nil
}

func (d *DatabaseAuditWriter) Close() error {
	return d.Flush()
}

func (d *DatabaseAuditWriter) Name() string {
	return "database"
}

// SyslogAuditWriter writes audit logs to syslog
type SyslogAuditWriter struct {
	writer   *syslog.Writer
	facility syslog.Priority
	tag      string
}

// NewSyslogAuditWriter creates a new syslog audit writer
func NewSyslogAuditWriter(settings map[string]interface{}) (AuditWriter, error) {
	facility := syslog.LOG_LOCAL0
	if f, ok := settings["facility"].(string); ok {
		switch strings.ToLower(f) {
		case "local0":
			facility = syslog.LOG_LOCAL0
		case "local1":
			facility = syslog.LOG_LOCAL1
		case "local2":
			facility = syslog.LOG_LOCAL2
		case "local3":
			facility = syslog.LOG_LOCAL3
		case "local4":
			facility = syslog.LOG_LOCAL4
		case "local5":
			facility = syslog.LOG_LOCAL5
		case "local6":
			facility = syslog.LOG_LOCAL6
		case "local7":
			facility = syslog.LOG_LOCAL7
		case "auth":
			facility = syslog.LOG_AUTH
		case "authpriv":
			facility = syslog.LOG_AUTHPRIV
		case "daemon":
			facility = syslog.LOG_DAEMON
		}
	}

	tag := "typosentinel-audit"
	if t, ok := settings["tag"].(string); ok {
		tag = t
	}

	writer, err := syslog.New(facility|syslog.LOG_INFO, tag)
	if err != nil {
		return nil, fmt.Errorf("failed to create syslog writer: %w", err)
	}

	return &SyslogAuditWriter{
		writer:   writer,
		facility: facility,
		tag:      tag,
	}, nil
}

func (s *SyslogAuditWriter) Write(entry *AuditEntry) error {
	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("failed to marshal audit entry: %w", err)
	}

	message := fmt.Sprintf("AUDIT: %s", string(data))

	switch entry.Severity {
	case AuditSeverityInfo:
		return s.writer.Info(message)
	case AuditSeverityWarning:
		return s.writer.Warning(message)
	case AuditSeverityError:
		return s.writer.Err(message)
	case AuditSeverityCritical:
		return s.writer.Crit(message)
	default:
		return s.writer.Info(message)
	}
}

func (s *SyslogAuditWriter) Flush() error {
	// Syslog doesn't need explicit flushing
	return nil
}

func (s *SyslogAuditWriter) Close() error {
	return s.writer.Close()
}

func (s *SyslogAuditWriter) Name() string {
	return "syslog"
}

// WebhookAuditWriter sends audit logs to a webhook endpoint
type WebhookAuditWriter struct {
	url        string
	client     *http.Client
	headers    map[string]string
	buffer     []*AuditEntry
	bufferSize int
	mu         sync.Mutex
}

// NewWebhookAuditWriter creates a new webhook audit writer
func NewWebhookAuditWriter(settings map[string]interface{}) (AuditWriter, error) {
	url, ok := settings["url"].(string)
	if !ok {
		return nil, fmt.Errorf("url is required for webhook audit writer")
	}

	timeout := 30 * time.Second
	if t, ok := settings["timeout"].(string); ok {
		if parsed, err := time.ParseDuration(t); err == nil {
			timeout = parsed
		}
	}

	headers := make(map[string]string)
	if h, ok := settings["headers"].(map[string]interface{}); ok {
		for k, v := range h {
			if str, ok := v.(string); ok {
				headers[k] = str
			}
		}
	}

	bufferSize := 10
	if size, ok := settings["buffer_size"].(int); ok {
		bufferSize = size
	}

	return &WebhookAuditWriter{
		url: url,
		client: &http.Client{
			Timeout: timeout,
		},
		headers:    headers,
		buffer:     make([]*AuditEntry, 0, bufferSize),
		bufferSize: bufferSize,
	}, nil
}

func (w *WebhookAuditWriter) Write(entry *AuditEntry) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.buffer = append(w.buffer, entry)

	// Flush if buffer is full
	if len(w.buffer) >= w.bufferSize {
		return w.flushBuffer()
	}

	return nil
}

func (w *WebhookAuditWriter) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.flushBuffer()
}

func (w *WebhookAuditWriter) flushBuffer() error {
	if len(w.buffer) == 0 {
		return nil
	}

	payload := map[string]interface{}{
		"timestamp": time.Now(),
		"source":    "typosentinel-audit",
		"entries":   w.buffer,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal webhook payload: %w", err)
	}

	req, err := http.NewRequest("POST", w.url, bytes.NewBuffer(data))
	if err != nil {
		return fmt.Errorf("failed to create webhook request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	for k, v := range w.headers {
		req.Header.Set(k, v)
	}

	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send webhook request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook request failed with status: %d", resp.StatusCode)
	}

	// Clear buffer on successful send
	w.buffer = w.buffer[:0]
	return nil
}

func (w *WebhookAuditWriter) Close() error {
	return w.Flush()
}

func (w *WebhookAuditWriter) Name() string {
	return "webhook"
}