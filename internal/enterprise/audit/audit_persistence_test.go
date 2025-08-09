package audit

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/Alivanroy/Typosentinel/pkg/logger"
	_ "github.com/lib/pq"
)

// setupTestDB creates a test database connection
func setupTestDB(t *testing.T) *sql.DB {
	// Use environment variable or default to test database
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://postgres:password@localhost:5432/typosentinel_test?sslmode=disable"
	}

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Skipf("Skipping database test: %v", err)
	}

	// Test connection
	if err := db.Ping(); err != nil {
		t.Skipf("Skipping database test - cannot connect: %v", err)
	}

	// Create audit_logs table if it doesn't exist
	createTableSQL := `
		CREATE TABLE IF NOT EXISTS audit_logs (
			id SERIAL PRIMARY KEY,
			audit_id VARCHAR(255) UNIQUE NOT NULL,
			timestamp TIMESTAMP NOT NULL,
			event_type VARCHAR(100) NOT NULL,
			action VARCHAR(100) NOT NULL,
			resource VARCHAR(255) NOT NULL,
			user_id VARCHAR(255),
			user_name VARCHAR(255),
			user_role VARCHAR(100),
			source_ip VARCHAR(45),
			user_agent TEXT,
			session_id VARCHAR(255),
			severity VARCHAR(20) NOT NULL,
			status VARCHAR(50),
			message TEXT,
			details JSONB,
			risk_score DECIMAL(5,2),
			tags TEXT[],
			correlation_id VARCHAR(255),
			metadata JSONB,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
	`

	if _, err := db.Exec(createTableSQL); err != nil {
		t.Fatalf("Failed to create audit_logs table: %v", err)
	}

	return db
}

// cleanupTestDB cleans up test data
func cleanupTestDB(t *testing.T, db *sql.DB) {
	if _, err := db.Exec("DELETE FROM audit_logs WHERE audit_id LIKE 'test-%'"); err != nil {
		t.Logf("Failed to cleanup test data: %v", err)
	}
	db.Close()
}

// TestDatabaseAuditPersistence tests basic audit log persistence to database
func TestDatabaseAuditPersistence(t *testing.T) {
	db := setupTestDB(t)
	defer cleanupTestDB(t, db)

	// Create logger
	testLogger := logger.New()

	// Create audit config with database destination
	config := &AuditConfig{
		Enabled:       true,
		BufferSize:    10,
		FlushInterval: 1 * time.Second,
		Destinations: []AuditDestination{
			{
				Type:    "database",
				Enabled: true,
				Settings: map[string]interface{}{
					"connection_string": "postgres://postgres:password@localhost:5432/typosentinel_test?sslmode=disable",
					"table_name":        "audit_logs",
				},
			},
		},
	}

	// Create audit logger
	auditLogger, err := NewAuditLogger(config, *testLogger)
	if err != nil {
		t.Fatalf("Failed to create audit logger: %v", err)
	}

	// Start audit logger
	ctx := context.Background()
	if err := auditLogger.Start(ctx); err != nil {
		t.Fatalf("Failed to start audit logger: %v", err)
	}
	defer auditLogger.Stop()

	// Log some audit events
	testEvents := []struct {
		eventType string
		action    string
		resource  string
		details   map[string]interface{}
	}{
		{
			eventType: "security",
			action:    "login",
			resource:  "user_account",
			details:   map[string]interface{}{"user_id": "test-user-1", "success": true},
		},
		{
			eventType: "data_access",
			action:    "read",
			resource:  "sensitive_data",
			details:   map[string]interface{}{"table": "users", "rows": 10},
		},
		{
			eventType: "configuration",
			action:    "update",
			resource:  "security_policy",
			details:   map[string]interface{}{"policy_id": "pol-123", "changes": []string{"timeout"}},
		},
	}

	for _, event := range testEvents {
		auditLogger.LogEvent(ctx, event.eventType, event.action, event.resource, event.details)
	}

	// Wait for flush
	time.Sleep(2 * time.Second)

	// Verify logs were persisted
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM audit_logs WHERE event_type IN ('security', 'data_access', 'configuration')").Scan(&count)
	if err != nil {
		t.Fatalf("Failed to query audit logs: %v", err)
	}

	if count < len(testEvents) {
		t.Errorf("Expected at least %d audit logs, got %d", len(testEvents), count)
	}

	// Verify specific log content
	var eventType, action, resource string
	err = db.QueryRow("SELECT event_type, action, resource FROM audit_logs WHERE action = 'login' LIMIT 1").Scan(&eventType, &action, &resource)
	if err != nil {
		t.Fatalf("Failed to query specific audit log: %v", err)
	}

	if eventType != "security" || action != "login" || resource != "user_account" {
		t.Errorf("Unexpected audit log content: %s/%s/%s", eventType, action, resource)
	}
}

// TestDatabaseAuditRetryLogic tests retry logic for database operations
func TestDatabaseAuditRetryLogic(t *testing.T) {
	db := setupTestDB(t)
	defer cleanupTestDB(t, db)

	// Create database writer with retry configuration
	writer, err := NewDatabaseAuditWriter(map[string]interface{}{
		"connection_string": "postgres://postgres:password@localhost:5432/typosentinel_test?sslmode=disable",
		"table_name":        "audit_logs",
		"buffer_size":       100,
		"max_retries":       3,
		"retry_delay":       "100ms",
	})
	if err != nil {
		t.Fatalf("Failed to create database writer: %v", err)
	}
	defer writer.Close()

	// Create test audit entry
	entry := &AuditEntry{
		ID:        "test-retry-001",
		Timestamp: time.Now(),
		EventType: "test",
		Action:    "retry_test",
		Resource:  "test_resource",
		Severity:  AuditSeverityInfo,
		Message:   "Test retry logic",
		Details:   map[string]interface{}{"test": true},
	}

	// Write entry
	if err := writer.Write(entry); err != nil {
		t.Fatalf("Failed to write audit entry: %v", err)
	}

	// Flush to database
	if err := writer.Flush(); err != nil {
		t.Fatalf("Failed to flush audit entries: %v", err)
	}

	// Verify entry was written
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM audit_logs WHERE audit_id = 'test-retry-001'").Scan(&count)
	if err != nil {
		t.Fatalf("Failed to query audit logs: %v", err)
	}

	if count != 1 {
		t.Errorf("Expected 1 audit log, got %d", count)
	}
}

// TestAuditLogCleanup tests audit log retention and cleanup
func TestAuditLogCleanup(t *testing.T) {
	db := setupTestDB(t)
	defer cleanupTestDB(t, db)

	// Insert old audit logs
	oldTimestamp := time.Now().Add(-48 * time.Hour)
	_, err := db.Exec(`
		INSERT INTO audit_logs (audit_id, timestamp, event_type, action, resource, severity, message)
		VALUES ($1, $2, 'test', 'cleanup_test', 'old_resource', 'info', 'Old test entry')
	`, "test-old-001", oldTimestamp)
	if err != nil {
		t.Fatalf("Failed to insert old audit log: %v", err)
	}

	// Create database writer
	writer, err := NewDatabaseAuditWriter(map[string]interface{}{
		"connection_string": "postgres://postgres:password@localhost:5432/typosentinel_test?sslmode=disable",
		"table_name":        "audit_logs",
		"buffer_size":       100,
		"max_retries":       3,
		"retry_delay":       "100ms",
	})
	if err != nil {
		t.Fatalf("Failed to create database writer: %v", err)
	}
	defer writer.Close()

	// Cast to DatabaseAuditWriter to access CleanupExpiredLogs method
	dbWriter, ok := writer.(*DatabaseAuditWriter)
	if !ok {
		t.Fatalf("Expected DatabaseAuditWriter, got %T", writer)
	}

	// Cleanup logs older than 24 hours
	retentionPeriod := 24 * time.Hour
	if err := dbWriter.CleanupExpiredLogs(retentionPeriod); err != nil {
		t.Fatalf("Failed to cleanup expired logs: %v", err)
	}

	// Verify old log was deleted
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM audit_logs WHERE audit_id = 'test-old-001'").Scan(&count)
	if err != nil {
		t.Fatalf("Failed to query audit logs: %v", err)
	}

	if count != 0 {
		t.Errorf("Expected old audit log to be deleted, but found %d entries", count)
	}
}

// TestConcurrentAuditLogging tests concurrent audit logging
func TestConcurrentAuditLogging(t *testing.T) {
	db := setupTestDB(t)
	defer cleanupTestDB(t, db)

	testLogger := logger.New()

	config := &AuditConfig{
		Enabled:       true,
		BufferSize:    50,
		FlushInterval: 500 * time.Millisecond,
		Destinations: []AuditDestination{
			{
				Type:    "database",
				Enabled: true,
				Settings: map[string]interface{}{
					"connection_string": db,
					"table_name":        "audit_logs",
				},
			},
		},
	}

	auditLogger, err := NewAuditLogger(config, *testLogger)
	if err != nil {
		t.Fatalf("Failed to create audit logger: %v", err)
	}

	ctx := context.Background()
	if err := auditLogger.Start(ctx); err != nil {
		t.Fatalf("Failed to start audit logger: %v", err)
	}
	defer auditLogger.Stop()

	// Simulate concurrent logging
	numGoroutines := 10
	eventsPerGoroutine := 5
	done := make(chan bool, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(goroutineID int) {
			for j := 0; j < eventsPerGoroutine; j++ {
				auditLogger.LogEvent(
					ctx,
					"concurrent_test",
					"test_action",
					fmt.Sprintf("resource_%d_%d", goroutineID, j),
					map[string]interface{}{
						"goroutine_id": goroutineID,
						"event_id":     j,
					},
				)
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < numGoroutines; i++ {
		<-done
	}

	// Wait for flush
	time.Sleep(2 * time.Second)

	// Verify all events were logged
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM audit_logs WHERE event_type = 'concurrent_test'").Scan(&count)
	if err != nil {
		t.Fatalf("Failed to query audit logs: %v", err)
	}

	expectedCount := numGoroutines * eventsPerGoroutine
	if count < expectedCount {
		t.Errorf("Expected at least %d audit logs, got %d", expectedCount, count)
	}
}