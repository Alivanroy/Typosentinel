package database

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

func setupTestDB(t *testing.T) *ThreatDB {
	// Skip SQLite tests if CGO is not enabled
	if !cgoEnabled() {
		t.Skip("Skipping SQLite tests: CGO not enabled")
	}
	
	// Use in-memory SQLite database for testing
	db, err := NewThreatDB(":memory:")
	if err != nil {
		t.Fatalf("Failed to create threat database: %v", err)
	}
	return db
}

// cgoEnabled checks if CGO is enabled by trying to create a SQLite connection
func cgoEnabled() bool {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		return false
	}
	defer db.Close()
	return db.Ping() == nil
}

func TestNewThreatDB(t *testing.T) {
	// Create temporary database
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_threats.db")

	db, err := NewThreatDB(dbPath)
	if err != nil {
		t.Fatalf("Failed to create threat database: %v", err)
	}
	defer db.Close()

	// Verify database file exists
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Error("Database file was not created")
	}

	// Test database connection
	if err := db.db.Ping(); err != nil {
		t.Errorf("Database ping failed: %v", err)
	}
}

func TestAddAndGetThreat(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_threats.db")

	db, err := NewThreatDB(dbPath)
	if err != nil {
		t.Fatalf("Failed to create threat database: %v", err)
	}
	defer db.Close()

	// Add a threat
	threat := &ThreatRecord{
		PackageName: "malicious-package",
		Registry:    "npm",
		ThreatType:  "typosquatting",
		Severity:    "high",
		Confidence:  0.95,
		Description: "Known typosquatting package",
		Source:      "manual",
		Metadata:    `{"original":"popular-package"}`,
	}

	err = db.AddThreat(threat)
	if err != nil {
		t.Fatalf("Failed to add threat: %v", err)
	}

	// Retrieve the threat
	retrieved, err := db.GetThreat("malicious-package", "npm")
	if err != nil {
		t.Fatalf("Failed to get threat: %v", err)
	}

	if retrieved == nil {
		t.Fatal("Threat not found")
	}

	// Verify threat data
	if retrieved.PackageName != threat.PackageName {
		t.Errorf("Expected package name %s, got %s", threat.PackageName, retrieved.PackageName)
	}
	if retrieved.Registry != threat.Registry {
		t.Errorf("Expected registry %s, got %s", threat.Registry, retrieved.Registry)
	}
	if retrieved.ThreatType != threat.ThreatType {
		t.Errorf("Expected threat type %s, got %s", threat.ThreatType, retrieved.ThreatType)
	}
	if retrieved.Severity != threat.Severity {
		t.Errorf("Expected severity %s, got %s", threat.Severity, retrieved.Severity)
	}
	if retrieved.Confidence != threat.Confidence {
		t.Errorf("Expected confidence %f, got %f", threat.Confidence, retrieved.Confidence)
	}
}

func TestGetNonExistentThreat(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_threats.db")

	db, err := NewThreatDB(dbPath)
	if err != nil {
		t.Fatalf("Failed to create threat database: %v", err)
	}
	defer db.Close()

	// Try to get non-existent threat
	threat, err := db.GetThreat("non-existent", "npm")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if threat != nil {
		t.Error("Expected nil threat for non-existent package")
	}
}

func TestGetThreats(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_threats.db")

	db, err := NewThreatDB(dbPath)
	if err != nil {
		t.Fatalf("Failed to create threat database: %v", err)
	}
	defer db.Close()

	// Add multiple threats
	threats := []*ThreatRecord{
		{
			PackageName: "package1",
			Registry:    "npm",
			ThreatType:  "typosquatting",
			Severity:    "high",
			Confidence:  0.9,
			Description: "Test threat 1",
			Source:      "test",
		},
		{
			PackageName: "package2",
			Registry:    "pypi",
			ThreatType:  "malware",
			Severity:    "critical",
			Confidence:  0.95,
			Description: "Test threat 2",
			Source:      "test",
		},
		{
			PackageName: "package3",
			Registry:    "npm",
			ThreatType:  "suspicious",
			Severity:    "medium",
			Confidence:  0.7,
			Description: "Test threat 3",
			Source:      "test",
		},
	}

	for _, threat := range threats {
		if err := db.AddThreat(threat); err != nil {
			t.Fatalf("Failed to add threat: %v", err)
		}
	}

	// Test getting all threats
	allThreats, err := db.GetThreats("", "", 0)
	if err != nil {
		t.Fatalf("Failed to get threats: %v", err)
	}

	if len(allThreats) != 3 {
		t.Errorf("Expected 3 threats, got %d", len(allThreats))
	}

	// Test filtering by registry
	npmThreats, err := db.GetThreats("npm", "", 0)
	if err != nil {
		t.Fatalf("Failed to get npm threats: %v", err)
	}

	if len(npmThreats) != 2 {
		t.Errorf("Expected 2 npm threats, got %d", len(npmThreats))
	}

	// Test filtering by threat type
	typoThreats, err := db.GetThreats("", "typosquatting", 0)
	if err != nil {
		t.Fatalf("Failed to get typosquatting threats: %v", err)
	}

	if len(typoThreats) != 1 {
		t.Errorf("Expected 1 typosquatting threat, got %d", len(typoThreats))
	}

	// Test limit
	limitedThreats, err := db.GetThreats("", "", 2)
	if err != nil {
		t.Fatalf("Failed to get limited threats: %v", err)
	}

	if len(limitedThreats) != 2 {
		t.Errorf("Expected 2 limited threats, got %d", len(limitedThreats))
	}
}

func TestAddAndGetPattern(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_threats.db")

	db, err := NewThreatDB(dbPath)
	if err != nil {
		t.Fatalf("Failed to create threat database: %v", err)
	}
	defer db.Close()

	// Add a pattern
	pattern := &ThreatPattern{
		Name:        "common-typo-pattern",
		Pattern:     ".*-typo$",
		PatternType: "regex",
		ThreatType:  "typosquatting",
		Severity:    "medium",
		Enabled:     true,
	}

	err = db.AddPattern(pattern)
	if err != nil {
		t.Fatalf("Failed to add pattern: %v", err)
	}

	// Retrieve patterns
	patterns, err := db.GetPatterns("")
	if err != nil {
		t.Fatalf("Failed to get patterns: %v", err)
	}

	if len(patterns) != 1 {
		t.Errorf("Expected 1 pattern, got %d", len(patterns))
	}

	retrieved := patterns[0]
	if retrieved.Name != pattern.Name {
		t.Errorf("Expected pattern name %s, got %s", pattern.Name, retrieved.Name)
	}
	if retrieved.Pattern != pattern.Pattern {
		t.Errorf("Expected pattern %s, got %s", pattern.Pattern, retrieved.Pattern)
	}
	if retrieved.PatternType != pattern.PatternType {
		t.Errorf("Expected pattern type %s, got %s", pattern.PatternType, retrieved.PatternType)
	}
}

func TestDeleteThreat(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_threats.db")

	db, err := NewThreatDB(dbPath)
	if err != nil {
		t.Fatalf("Failed to create threat database: %v", err)
	}
	defer db.Close()

	// Add a threat
	threat := &ThreatRecord{
		PackageName: "to-delete",
		Registry:    "npm",
		ThreatType:  "test",
		Severity:    "low",
		Confidence:  0.5,
		Description: "Test threat for deletion",
		Source:      "test",
	}

	err = db.AddThreat(threat)
	if err != nil {
		t.Fatalf("Failed to add threat: %v", err)
	}

	// Verify threat exists
	retrieved, err := db.GetThreat("to-delete", "npm")
	if err != nil {
		t.Fatalf("Failed to get threat: %v", err)
	}
	if retrieved == nil {
		t.Fatal("Threat should exist before deletion")
	}

	// Delete the threat
	err = db.DeleteThreat("to-delete", "npm")
	if err != nil {
		t.Fatalf("Failed to delete threat: %v", err)
	}

	// Verify threat is deleted
	retrieved, err = db.GetThreat("to-delete", "npm")
	if err != nil {
		t.Fatalf("Failed to get threat after deletion: %v", err)
	}
	if retrieved != nil {
		t.Error("Threat should be deleted")
	}
}

func TestGetStats(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_threats.db")

	db, err := NewThreatDB(dbPath)
	if err != nil {
		t.Fatalf("Failed to create threat database: %v", err)
	}
	defer db.Close()

	// Add some threats and patterns
	threats := []*ThreatRecord{
		{
			PackageName: "threat1",
			Registry:    "npm",
			ThreatType:  "typosquatting",
			Severity:    "high",
			Confidence:  0.9,
			Description: "Test threat 1",
			Source:      "test",
		},
		{
			PackageName: "threat2",
			Registry:    "npm",
			ThreatType:  "malware",
			Severity:    "critical",
			Confidence:  0.95,
			Description: "Test threat 2",
			Source:      "test",
		},
	}

	for _, threat := range threats {
		if err := db.AddThreat(threat); err != nil {
			t.Fatalf("Failed to add threat: %v", err)
		}
	}

	pattern := &ThreatPattern{
		Name:        "test-pattern",
		Pattern:     "test.*",
		PatternType: "regex",
		ThreatType:  "test",
		Severity:    "low",
		Enabled:     true,
	}

	if err := db.AddPattern(pattern); err != nil {
		t.Fatalf("Failed to add pattern: %v", err)
	}

	// Get stats
	stats, err := db.GetStats()
	if err != nil {
		t.Fatalf("Failed to get stats: %v", err)
	}

	// Verify stats
	if stats["total_threats"] != 2 {
		t.Errorf("Expected 2 total threats, got %d", stats["total_threats"])
	}

	if stats["active_patterns"] != 1 {
		t.Errorf("Expected 1 active pattern, got %d", stats["active_patterns"])
	}

	if stats["high_threats"] != 1 {
		t.Errorf("Expected 1 high threat, got %d", stats["high_threats"])
	}

	if stats["critical_threats"] != 1 {
		t.Errorf("Expected 1 critical threat, got %d", stats["critical_threats"])
	}
}

func TestConvertToThreat(t *testing.T) {
	threatRecord := &ThreatRecord{
		ID:          1,
		PackageName: "test-package",
		Registry:    "npm",
		ThreatType:  "typosquatting",
		Severity:    "high",
		Confidence:  0.9,
		Description: "Test threat",
		Source:      "manual",
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	threat := threatRecord.ConvertToThreat()

	if threat.Package != threatRecord.PackageName {
		t.Errorf("Expected package %s, got %s", threatRecord.PackageName, threat.Package)
	}

	if string(threat.Type) != threatRecord.ThreatType {
		t.Errorf("Expected threat type %s, got %s", threatRecord.ThreatType, string(threat.Type))
	}

	if threat.Severity.String() != threatRecord.Severity {
		t.Errorf("Expected severity %s, got %s", threatRecord.Severity, threat.Severity.String())
	}

	if threat.Confidence != threatRecord.Confidence {
		t.Errorf("Expected confidence %f, got %f", threatRecord.Confidence, threat.Confidence)
	}

	if threat.Description != threatRecord.Description {
		t.Errorf("Expected description %s, got %s", threatRecord.Description, threat.Description)
	}
}

func TestThreatReplacement(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_threats.db")

	db, err := NewThreatDB(dbPath)
	if err != nil {
		t.Fatalf("Failed to create threat database: %v", err)
	}
	defer db.Close()

	// Add initial threat
	initialThreat := &ThreatRecord{
		PackageName: "test-package",
		Registry:    "npm",
		ThreatType:  "typosquatting",
		Severity:    "medium",
		Confidence:  0.7,
		Description: "Initial threat",
		Source:      "test",
	}

	err = db.AddThreat(initialThreat)
	if err != nil {
		t.Fatalf("Failed to add initial threat: %v", err)
	}

	// Add updated threat (should replace)
	updatedThreat := &ThreatRecord{
		PackageName: "test-package",
		Registry:    "npm",
		ThreatType:  "typosquatting",
		Severity:    "high",
		Confidence:  0.9,
		Description: "Updated threat",
		Source:      "test",
	}

	err = db.AddThreat(updatedThreat)
	if err != nil {
		t.Fatalf("Failed to add updated threat: %v", err)
	}

	// Retrieve and verify it was updated
	retrieved, err := db.GetThreat("test-package", "npm")
	if err != nil {
		t.Fatalf("Failed to get threat: %v", err)
	}

	if retrieved.Severity != "high" {
		t.Errorf("Expected severity high, got %s", retrieved.Severity)
	}

	if retrieved.Confidence != 0.9 {
		t.Errorf("Expected confidence 0.9, got %f", retrieved.Confidence)
	}

	if retrieved.Description != "Updated threat" {
		t.Errorf("Expected description 'Updated threat', got %s", retrieved.Description)
	}

	// Verify only one record exists
	allThreats, err := db.GetThreats("", "", 0)
	if err != nil {
		t.Fatalf("Failed to get all threats: %v", err)
	}

	if len(allThreats) != 1 {
		t.Errorf("Expected 1 threat after replacement, got %d", len(allThreats))
	}
}