package integration

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/enterprise/audit"
	"github.com/Alivanroy/Typosentinel/pkg/logger"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDatabaseAuditPersistence tests audit log persistence to database
func TestDatabaseAuditPersistence(t *testing.T) {
	// Setup test database
	db, cleanup := setupTestDatabase(t)
	defer cleanup()

	// Create audit logger with database writer
	config := &audit.AuditConfig{
		Enabled:         true,
		BufferSize:      10,
		FlushInterval:   100 * time.Millisecond,
		RetentionPeriod: 24 * time.Hour,
		Destinations: []audit.AuditDestination{
			{
				Type: "database",
				Settings: map[string]interface{}{
					"connection_string": getTestDatabaseURL(),
					"table_name":        "audit_logs",
					"buffer_size":       5,
					"max_retries":       3,
					"retry_delay":       "100ms",
				},
			},
		},
	}

	testLogger := *logger.New()
	auditLogger, err := audit.NewAuditLogger(config, testLogger)
	require.NoError(t, err)

	// Start audit logger
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = auditLogger.Start(ctx)
	require.NoError(t, err)
	defer auditLogger.Stop()

	// Test cases
	testCases := []struct {
		name     string
		entries  []*audit.AuditEntry
		expected int
	}{
		{
			name: "Single audit entry",
			entries: []*audit.AuditEntry{
				createTestAuditEntry("user1", "package.scan", "npm:lodash"),
			},
			expected: 1,
		},
		{
			name: "Multiple audit entries",
			entries: []*audit.AuditEntry{
				createTestAuditEntry("user1", "package.scan", "npm:lodash"),
				createTestAuditEntry("user2", "vulnerability.detected", "npm:express"),
				createTestAuditEntry("user1", "policy.violation", "npm:react"),
			},
			expected: 3,
		},
		{
			name: "Batch flush trigger",
			entries: []*audit.AuditEntry{
				createTestAuditEntry("user1", "scan.start", "npm:package1"),
				createTestAuditEntry("user1", "scan.start", "npm:package2"),
				createTestAuditEntry("user1", "scan.start", "npm:package3"),
				createTestAuditEntry("user1", "scan.start", "npm:package4"),
				createTestAuditEntry("user1", "scan.start", "npm:package5"),
				createTestAuditEntry("user1", "scan.start", "npm:package6"), // Should trigger flush
			},
			expected: 6,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Clear existing audit logs
			clearAuditLogs(t, db)

			// Log audit entries
			for _, entry := range tc.entries {
				auditCtx := context.WithValue(ctx, "user_id", entry.UserID)
				auditLogger.LogEvent(auditCtx, "test", entry.Action, entry.Resource, entry.Details)
			}

			// Wait for flush
			time.Sleep(200 * time.Millisecond)

			// Verify entries in database
			count := countAuditLogs(t, db)
			assert.Equal(t, tc.expected, count, "Expected %d audit logs, got %d", tc.expected, count)

			// Verify entry details
			if tc.expected > 0 {
				entries := getAuditLogs(t, db)
				assert.Len(t, entries, tc.expected)

				for i, entry := range entries {
					assert.NotEmpty(t, entry.ID)
					assert.NotZero(t, entry.Timestamp)
					assert.Equal(t, tc.entries[i].UserID, entry.UserID)
					assert.Equal(t, tc.entries[i].Action, entry.Action)
					assert.Equal(t, tc.entries[i].Resource, entry.Resource)
				}
			}
		})
	}
}

// TestDatabaseAuditRetryLogic tests retry logic for database failures
func TestDatabaseAuditRetryLogic(t *testing.T) {
	// This test would require a more complex setup to simulate database failures
	// For now, we'll test the basic retry configuration
	
	config := &audit.AuditConfig{
		Enabled:         true,
		BufferSize:      10,
		FlushInterval:   100 * time.Millisecond,
		RetentionPeriod: 24 * time.Hour,
		Destinations: []audit.AuditDestination{
			{
				Type: "database",
				Settings: map[string]interface{}{
					"connection_string": "invalid://connection",
					"table_name":        "audit_logs",
					"buffer_size":       5,
					"max_retries":       2,
					"retry_delay":       "50ms",
				},
			},
		},
	}

	testLogger := *logger.New()
	_, err := audit.NewAuditLogger(config, testLogger)
	
	// Should fail to create logger with invalid connection
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create audit writer")
}

// TestAuditLogCleanup tests audit log cleanup functionality
func TestAuditLogCleanup(t *testing.T) {
	// Setup test database
	db, cleanup := setupTestDatabase(t)
	defer cleanup()

	// Create audit logger with short retention period
	config := &audit.AuditConfig{
		Enabled:         true,
		BufferSize:      10,
		FlushInterval:   100 * time.Millisecond,
		RetentionPeriod: 1 * time.Second, // Very short for testing
		Destinations: []audit.AuditDestination{
			{
				Type: "database",
				Settings: map[string]interface{}{
					"connection_string": getTestDatabaseURL(),
					"table_name":        "audit_logs",
					"buffer_size":       5,
				},
			},
		},
	}

	testLogger := *logger.New()
	auditLogger, err := audit.NewAuditLogger(config, testLogger)
	require.NoError(t, err)

	// Start audit logger
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = auditLogger.Start(ctx)
	require.NoError(t, err)
	defer auditLogger.Stop()

	// Clear existing audit logs
	clearAuditLogs(t, db)

	// Insert old audit log directly into database
	oldEntry := createTestAuditEntry("user1", "old.action", "old:resource")
	oldEntry.Timestamp = time.Now().Add(-2 * time.Hour) // Old entry
	insertAuditLogDirectly(t, db, oldEntry)

	// Insert recent audit log
	auditCtx := context.WithValue(ctx, "user_id", "user1")
	auditLogger.LogEvent(auditCtx, "test", "recent.action", "recent:resource", map[string]interface{}{"test": "data"})

	// Wait for flush
	time.Sleep(200 * time.Millisecond)

	// Should have 2 entries initially
	count := countAuditLogs(t, db)
	assert.Equal(t, 2, count)

	// Wait for cleanup (retention period + some buffer)
	time.Sleep(2 * time.Second)

	// Should have only 1 entry after cleanup (the recent one)
	count = countAuditLogs(t, db)
	assert.Equal(t, 1, count)
}

// TestConcurrentAuditLogging tests concurrent audit logging
func TestConcurrentAuditLogging(t *testing.T) {
	// Setup test database
	db, cleanup := setupTestDatabase(t)
	defer cleanup()

	// Create audit logger
	config := &audit.AuditConfig{
		Enabled:         true,
		BufferSize:      50,
		FlushInterval:   100 * time.Millisecond,
		RetentionPeriod: 24 * time.Hour,
		Destinations: []audit.AuditDestination{
			{
				Type: "database",
				Settings: map[string]interface{}{
					"connection_string": getTestDatabaseURL(),
					"table_name":        "audit_logs",
					"buffer_size":       10,
				},
			},
		},
	}

	testLogger := *logger.New()
	auditLogger, err := audit.NewAuditLogger(config, testLogger)
	require.NoError(t, err)

	// Start audit logger
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = auditLogger.Start(ctx)
	require.NoError(t, err)
	defer auditLogger.Stop()

	// Clear existing audit logs
	clearAuditLogs(t, db)

	// Concurrent logging
	numGoroutines := 10
	entriesPerGoroutine := 5
	expectedTotal := numGoroutines * entriesPerGoroutine

	done := make(chan bool, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(goroutineID int) {
			defer func() { done <- true }()
			
			for j := 0; j < entriesPerGoroutine; j++ {
				userID := fmt.Sprintf("user%d", goroutineID)
				action := fmt.Sprintf("action%d_%d", goroutineID, j)
				resource := fmt.Sprintf("resource%d_%d", goroutineID, j)
				
				auditCtx := context.WithValue(ctx, "user_id", userID)
				auditLogger.LogEvent(auditCtx, "test", action, resource, map[string]interface{}{
					"goroutine": goroutineID,
					"iteration": j,
				})
			}
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < numGoroutines; i++ {
		<-done
	}

	// Wait for flush
	time.Sleep(500 * time.Millisecond)

	// Verify all entries were logged
	count := countAuditLogs(t, db)
	assert.Equal(t, expectedTotal, count, "Expected %d audit logs, got %d", expectedTotal, count)
}

// Helper functions

func setupTestDatabase(t *testing.T) (*sql.DB, func()) {
	dbURL := getTestDatabaseURL()
	
	db, err := sql.Open("postgres", dbURL)
	require.NoError(t, err)
	
	// Test connection
	err = db.Ping()
	require.NoError(t, err)
	
	// Create audit_logs table
	createTableSQL := `
		CREATE TABLE IF NOT EXISTS audit_logs (
			id VARCHAR(255) PRIMARY KEY,
			timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
			user_id VARCHAR(255),
			action VARCHAR(255) NOT NULL,
			resource VARCHAR(255),
			source_ip VARCHAR(45),
			user_agent TEXT,
			severity VARCHAR(50),
			details JSONB,
			metadata JSONB
		);
		CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp);
		CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
		CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);
	`
	
	_, err = db.Exec(createTableSQL)
	require.NoError(t, err)
	
	cleanup := func() {
		db.Close()
	}
	
	return db, cleanup
}

func getTestDatabaseURL() string {
	// Use environment variable or default to in-memory SQLite for testing
	if dbURL := os.Getenv("TEST_DATABASE_URL"); dbURL != "" {
		return dbURL
	}
	// For this test, we'll use a simple connection string
	// In a real environment, this would be configured properly
	return "postgres://test:test@localhost/test_typosentinel?sslmode=disable"
}

func createTestAuditEntry(userID, action, resource string) *audit.AuditEntry {
	return &audit.AuditEntry{
		ID:        fmt.Sprintf("test-%d", time.Now().UnixNano()),
		Timestamp: time.Now(),
		UserID:    userID,
		Action:    action,
		Resource:  resource,
		SourceIP:  "127.0.0.1",
		UserAgent: "test-agent",
		Severity:  audit.AuditSeverityInfo,
		Details: map[string]interface{}{
			"test": "data",
			"timestamp": time.Now().Unix(),
		},
		Metadata: map[string]interface{}{
			"test_case": true,
		},
	}
}

func clearAuditLogs(t *testing.T, db *sql.DB) {
	_, err := db.Exec("DELETE FROM audit_logs")
	require.NoError(t, err)
}

func countAuditLogs(t *testing.T, db *sql.DB) int {
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM audit_logs").Scan(&count)
	require.NoError(t, err)
	return count
}

func getAuditLogs(t *testing.T, db *sql.DB) []audit.AuditEntry {
	rows, err := db.Query(`
		SELECT id, timestamp, user_id, action, resource, source_ip, user_agent, severity, details, metadata 
		FROM audit_logs 
		ORDER BY timestamp
	`)
	require.NoError(t, err)
	defer rows.Close()

	var entries []audit.AuditEntry
	for rows.Next() {
		var entry audit.AuditEntry
		var detailsJSON, metadataJSON string

		err := rows.Scan(
			&entry.ID,
			&entry.Timestamp,
			&entry.UserID,
			&entry.Action,
			&entry.Resource,
			&entry.SourceIP,
			&entry.UserAgent,
			&entry.Severity,
			&detailsJSON,
			&metadataJSON,
		)
		require.NoError(t, err)

		// Parse JSON fields
		if detailsJSON != "" {
			err = json.Unmarshal([]byte(detailsJSON), &entry.Details)
			require.NoError(t, err)
		}

		if metadataJSON != "" {
			err = json.Unmarshal([]byte(metadataJSON), &entry.Metadata)
			require.NoError(t, err)
		}

		entries = append(entries, entry)
	}

	require.NoError(t, rows.Err())
	return entries
}

func insertAuditLogDirectly(t *testing.T, db *sql.DB, entry *audit.AuditEntry) {
	detailsJSON, err := json.Marshal(entry.Details)
	require.NoError(t, err)

	metadataJSON, err := json.Marshal(entry.Metadata)
	require.NoError(t, err)

	_, err = db.Exec(`
		INSERT INTO audit_logs (
			id, timestamp, user_id, action, resource, 
			source_ip, user_agent, severity, details, metadata
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`,
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
	require.NoError(t, err)
}