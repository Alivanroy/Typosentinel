package security

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/auth"
	"github.com/Alivanroy/Typosentinel/internal/storage"
	"github.com/Alivanroy/Typosentinel/pkg/logger"

	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
)

// TestViolationStoreOrderBySQLInjection verifies that dynamic ORDER BY is protected against SQL injection
func TestViolationStoreOrderBySQLInjection(t *testing.T) {
	// Use SQLite in-memory for testing
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open test database: %v", err)
	}
	defer db.Close()

	// Create policy_violations table (simplified schema for test)
	createTableSQL := `
		CREATE TABLE policy_violations (
			id TEXT PRIMARY KEY,
			policy_id TEXT NOT NULL,
			policy_name TEXT NOT NULL,
			severity TEXT NOT NULL,
			description TEXT NOT NULL,
			context TEXT,
			result TEXT,
			status TEXT NOT NULL DEFAULT 'open',
			approval_required BOOLEAN NOT NULL DEFAULT 0,
			approvals TEXT,
			remediation TEXT,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			resolved_at DATETIME,
			metadata TEXT
		)
	`
	if _, err := db.Exec(createTableSQL); err != nil {
		t.Fatalf("Failed to create test table: %v", err)
	}

	// Create test logger
	testLogger := logger.New()

	// Initialize violation store
	store := storage.NewViolationStore(db, testLogger)

	// Insert test violations
	testViolations := []*auth.PolicyViolation{
		{
			ID:          "violation-1",
			PolicyID:    "policy-1",
			PolicyName:  "Test Policy 1",
			Severity:    "high",
			Description: "Test violation 1",
			Status:      auth.ViolationStatusPending,
			CreatedAt:   time.Now().Add(-2 * time.Hour),
		},
		{
			ID:          "violation-2",
			PolicyID:    "policy-2",
			PolicyName:  "Test Policy 2",
			Severity:    "medium",
			Description: "Test violation 2",
			Status:      auth.ViolationStatusApproved,
			CreatedAt:   time.Now().Add(-1 * time.Hour),
		},
		{
			ID:          "violation-3",
			PolicyID:    "policy-3",
			PolicyName:  "Test Policy 3",
			Severity:    "low",
			Description: "Test violation 3",
			Status:      auth.ViolationStatusRejected,
			CreatedAt:   time.Now(),
		},
	}

	ctx := context.Background()
	for _, violation := range testViolations {
		if err := store.CreateViolation(ctx, violation); err != nil {
			t.Fatalf("Failed to create test violation: %v", err)
		}
	}

	// Test cases for SQL injection attempts in ORDER BY
	testCases := []struct {
		name      string
		sortBy    string
		sortOrder string
		expectErr bool
		comment   string
	}{
		{
			name:      "Valid column - created_at",
			sortBy:    "created_at",
			sortOrder: "desc",
			expectErr: false,
			comment:   "Should work with whitelisted column",
		},
		{
			name:      "Valid column - severity",
			sortBy:    "severity",
			sortOrder: "asc",
			expectErr: false,
			comment:   "Should work with whitelisted column",
		},
		{
			name:      "SQL Injection attempt - UNION",
			sortBy:    "created_at; DROP TABLE policy_violations; --",
			sortOrder: "desc",
			expectErr: false,
			comment:   "Should fallback to default column, not execute injection",
		},
		{
			name:      "SQL Injection attempt - Subquery",
			sortBy:    "created_at,(SELECT COUNT(*) FROM policy_violations)",
			sortOrder: "desc",
			expectErr: false,
			comment:   "Should fallback to default column, not execute subquery",
		},
		{
			name:      "SQL Injection attempt - CASE statement",
			sortBy:    "CASE WHEN 1=1 THEN created_at ELSE (SELECT password FROM users LIMIT 1) END",
			sortOrder: "desc",
			expectErr: false,
			comment:   "Should fallback to default column, not execute CASE",
		},
		{
			name:      "Invalid column name",
			sortBy:    "nonexistent_column",
			sortOrder: "desc",
			expectErr: false,
			comment:   "Should fallback to default column",
		},
		{
			name:      "Empty sort by",
			sortBy:    "",
			sortOrder: "desc",
			expectErr: false,
			comment:   "Should use default ordering",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			opts := storage.ListViolationsOptions{
				SortBy:    tc.sortBy,
				SortOrder: tc.sortOrder,
				Limit:     10,
				Offset:    0,
			}

			violations, total, err := store.ListViolations(ctx, opts)

			if tc.expectErr && err == nil {
				t.Errorf("Expected error for %s, but got none", tc.comment)
			}
			if !tc.expectErr && err != nil {
				t.Errorf("Unexpected error for %s: %v", tc.comment, err)
			}

			// Verify we still get results (injection should not succeed)
			if err == nil {
				if total != 3 {
					t.Errorf("Expected 3 total violations, got %d", total)
				}
				if len(violations) != 3 {
					t.Errorf("Expected 3 violations in result, got %d", len(violations))
				}
			}

			// Verify table still exists (DROP TABLE should not execute)
			var count int
			if err := db.QueryRow("SELECT COUNT(*) FROM policy_violations").Scan(&count); err != nil {
				t.Errorf("Table seems to have been dropped or corrupted: %v", err)
			}
		})
	}
}

// TestViolationStoreFilterSQLInjection verifies that WHERE clause filters are protected
func TestViolationStoreFilterSQLInjection(t *testing.T) {
	// Use SQLite in-memory for testing
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open test database: %v", err)
	}
	defer db.Close()

	// Create policy_violations table
	createTableSQL := `
		CREATE TABLE policy_violations (
			id TEXT PRIMARY KEY,
			policy_id TEXT NOT NULL,
			policy_name TEXT NOT NULL,
			severity TEXT NOT NULL,
			description TEXT NOT NULL,
			context TEXT,
			result TEXT,
			status TEXT NOT NULL DEFAULT 'open',
			approval_required BOOLEAN NOT NULL DEFAULT 0,
			approvals TEXT,
			remediation TEXT,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			resolved_at DATETIME,
			metadata TEXT
		)
	`
	if _, err := db.Exec(createTableSQL); err != nil {
		t.Fatalf("Failed to create test table: %v", err)
	}

	testLogger := logger.New()
	store := storage.NewViolationStore(db, testLogger)

	// Insert test violation
	testViolation := &auth.PolicyViolation{
		ID:          "violation-1",
		PolicyID:    "policy-1",
		PolicyName:  "Test Policy",
		Severity:    "high",
		Description: "Test violation",
		Status:      auth.ViolationStatusPending,
		CreatedAt:   time.Now(),
	}

	ctx := context.Background()
	if err := store.CreateViolation(ctx, testViolation); err != nil {
		t.Fatalf("Failed to create test violation: %v", err)
	}

	// Test SQL injection attempts in filter parameters
	testCases := []struct {
		name     string
		opts     storage.ListViolationsOptions
		comment  string
	}{
		{
			name: "SQL Injection in Status",
			opts: storage.ListViolationsOptions{
				Status: "pending'; DROP TABLE policy_violations; --",
				Limit:  10,
			},
			comment: "Should not execute DROP TABLE",
		},
		{
			name: "SQL Injection in PolicyID",
			opts: storage.ListViolationsOptions{
				PolicyID: "policy-1' OR '1'='1",
				Limit:    10,
			},
			comment: "Should not bypass WHERE condition",
		},
		{
			name: "SQL Injection in Severity",
			opts: storage.ListViolationsOptions{
				Severity: "high' UNION SELECT password FROM users --",
				Limit:    10,
			},
			comment: "Should not execute UNION query",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			violations, total, err := store.ListViolations(ctx, tc.opts)

			// Should not error (parameterized queries handle injection safely)
			if err != nil {
				t.Errorf("Unexpected error for %s: %v", tc.comment, err)
			}

			// Should return 0 results (injected values won't match real data)
			if total != 0 {
				t.Errorf("Expected 0 results for injection attempt, got %d", total)
			}
			if len(violations) != 0 {
				t.Errorf("Expected 0 violations for injection attempt, got %d", len(violations))
			}

			// Verify table still exists
			var count int
			if err := db.QueryRow("SELECT COUNT(*) FROM policy_violations").Scan(&count); err != nil {
				t.Errorf("Table seems to have been affected by injection: %v", err)
			}
		})
	}
}