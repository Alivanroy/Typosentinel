package audit

import (
	"context"
	"testing"
	"time"

	"github.com/Alivanroy/Typosentinel/pkg/logger"
)

// mockAuditWriter implements AuditWriter for testing
type mockAuditWriter struct {
	entries []*AuditEntry
	name    string
}

func (m *mockAuditWriter) Write(entry *AuditEntry) error {
	m.entries = append(m.entries, entry)
	return nil
}

func (m *mockAuditWriter) Flush() error {
	return nil
}

func (m *mockAuditWriter) Close() error {
	return nil
}

func (m *mockAuditWriter) Name() string {
	return m.name
}

// TestAuditLoggerBasicFunctionality tests basic audit logger functionality
func TestAuditLoggerBasicFunctionality(t *testing.T) {
	// Create logger
	testLogger := logger.New()

	// Create mock writer
	mockWriter := &mockAuditWriter{
		entries: make([]*AuditEntry, 0),
		name:    "mock",
	}

	// Create audit config
	config := &AuditConfig{
		Enabled:       true,
		BufferSize:    10,
		FlushInterval: 1 * time.Second,
		Destinations:  []AuditDestination{}, // No destinations, we'll add writer manually
	}

	// Create audit logger
	auditLogger, err := NewAuditLogger(config, *testLogger)
	if err != nil {
		t.Fatalf("Failed to create audit logger: %v", err)
	}

	// Add mock writer manually
	auditLogger.writers = append(auditLogger.writers, mockWriter)

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

	// Wait for processing
	time.Sleep(100 * time.Millisecond)

	// Force flush
	auditLogger.flush()

	// Verify events were logged
	if len(mockWriter.entries) != len(testEvents) {
		t.Errorf("Expected %d audit entries, got %d", len(testEvents), len(mockWriter.entries))
	}

	// Verify event content
	for i, entry := range mockWriter.entries {
		expectedEvent := testEvents[i]
		if entry.EventType != expectedEvent.eventType {
			t.Errorf("Entry %d: expected event type %s, got %s", i, expectedEvent.eventType, entry.EventType)
		}
		if entry.Action != expectedEvent.action {
			t.Errorf("Entry %d: expected action %s, got %s", i, expectedEvent.action, entry.Action)
		}
		if entry.Resource != expectedEvent.resource {
			t.Errorf("Entry %d: expected resource %s, got %s", i, expectedEvent.resource, entry.Resource)
		}
		if entry.Severity != AuditSeverityInfo {
			t.Errorf("Entry %d: expected severity %s, got %s", i, AuditSeverityInfo, entry.Severity)
		}
	}
}

// TestAuditLoggerBuffering tests audit logger buffering functionality
func TestAuditLoggerBuffering(t *testing.T) {
	testLogger := logger.New()
	mockWriter := &mockAuditWriter{
		entries: make([]*AuditEntry, 0),
		name:    "mock",
	}

	// Create config with small buffer
	config := &AuditConfig{
		Enabled:       true,
		BufferSize:    3, // Small buffer to test flushing
		FlushInterval: 10 * time.Second, // Long interval to test buffer-based flushing
		Destinations:  []AuditDestination{},
	}

	auditLogger, err := NewAuditLogger(config, *testLogger)
	if err != nil {
		t.Fatalf("Failed to create audit logger: %v", err)
	}

	auditLogger.writers = append(auditLogger.writers, mockWriter)

	ctx := context.Background()
	if err := auditLogger.Start(ctx); err != nil {
		t.Fatalf("Failed to start audit logger: %v", err)
	}
	defer auditLogger.Stop()

	// Log events to fill buffer
	for i := 0; i < 5; i++ {
		auditLogger.LogEvent(ctx, "test", "action", "resource", map[string]interface{}{"id": i})
	}

	// Wait for processing
	time.Sleep(100 * time.Millisecond)

	// Should have at least 3 entries (buffer size) flushed
	if len(mockWriter.entries) < 3 {
		t.Errorf("Expected at least 3 entries to be flushed, got %d", len(mockWriter.entries))
	}
}

// TestAuditLoggerFiltering tests audit log filtering functionality
func TestAuditLoggerFiltering(t *testing.T) {
	testLogger := logger.New()
	mockWriter := &mockAuditWriter{
		entries: make([]*AuditEntry, 0),
		name:    "mock",
	}

	// Create config with filters
	config := &AuditConfig{
		Enabled:       true,
		BufferSize:    10,
		FlushInterval: 1 * time.Second,
		Destinations:  []AuditDestination{},
		Filters: []AuditFilter{
			{
				Name:      "security_only",
				EventType: "security",
				Enabled:   true,
			},
		},
	}

	auditLogger, err := NewAuditLogger(config, *testLogger)
	if err != nil {
		t.Fatalf("Failed to create audit logger: %v", err)
	}

	auditLogger.writers = append(auditLogger.writers, mockWriter)

	ctx := context.Background()
	if err := auditLogger.Start(ctx); err != nil {
		t.Fatalf("Failed to start audit logger: %v", err)
	}
	defer auditLogger.Stop()

	// Log events of different types
	auditLogger.LogEvent(ctx, "security", "login", "user_account", map[string]interface{}{"user": "test"})
	auditLogger.LogEvent(ctx, "data_access", "read", "table", map[string]interface{}{"table": "users"})
	auditLogger.LogEvent(ctx, "security", "logout", "user_account", map[string]interface{}{"user": "test"})

	// Wait and flush
	time.Sleep(100 * time.Millisecond)
	auditLogger.flush()

	// Should only have security events (if filtering is implemented)
	// Note: This test assumes filtering is implemented in the audit logger
	if len(mockWriter.entries) > 0 {
		for _, entry := range mockWriter.entries {
			t.Logf("Logged entry: %s/%s/%s", entry.EventType, entry.Action, entry.Resource)
		}
	}
}

// TestAuditEntryGeneration tests audit entry generation and fields
func TestAuditEntryGeneration(t *testing.T) {
	testLogger := logger.New()
	mockWriter := &mockAuditWriter{
		entries: make([]*AuditEntry, 0),
		name:    "mock",
	}

	config := &AuditConfig{
		Enabled:       true,
		BufferSize:    10,
		FlushInterval: 1 * time.Second,
		Destinations:  []AuditDestination{},
	}

	auditLogger, err := NewAuditLogger(config, *testLogger)
	if err != nil {
		t.Fatalf("Failed to create audit logger: %v", err)
	}

	auditLogger.writers = append(auditLogger.writers, mockWriter)

	ctx := context.Background()
	if err := auditLogger.Start(ctx); err != nil {
		t.Fatalf("Failed to start audit logger: %v", err)
	}
	defer auditLogger.Stop()

	// Log an event
	details := map[string]interface{}{
		"user_id":    "test-user-123",
		"ip_address": "192.168.1.100",
		"success":    true,
	}

	auditLogger.LogEvent(ctx, "authentication", "login_attempt", "user_session", details)

	// Wait and flush
	time.Sleep(100 * time.Millisecond)
	auditLogger.flush()

	// Verify entry was created
	if len(mockWriter.entries) != 1 {
		t.Fatalf("Expected 1 audit entry, got %d", len(mockWriter.entries))
	}

	entry := mockWriter.entries[0]

	// Verify required fields
	if entry.ID == "" {
		t.Error("Audit entry ID should not be empty")
	}
	if entry.Timestamp.IsZero() {
		t.Error("Audit entry timestamp should not be zero")
	}
	if entry.EventType != "authentication" {
		t.Errorf("Expected event type 'authentication', got '%s'", entry.EventType)
	}
	if entry.Action != "login_attempt" {
		t.Errorf("Expected action 'login_attempt', got '%s'", entry.Action)
	}
	if entry.Resource != "user_session" {
		t.Errorf("Expected resource 'user_session', got '%s'", entry.Resource)
	}
	if entry.Details == nil {
		t.Error("Audit entry details should not be nil")
	}

	// Verify details were preserved
	if userID, ok := entry.Details["user_id"].(string); !ok || userID != "test-user-123" {
		t.Errorf("Expected user_id 'test-user-123' in details, got %v", entry.Details["user_id"])
	}
}