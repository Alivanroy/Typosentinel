package database

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestNewThreatUpdater(t *testing.T) {
	// Skip if CGO not available
	if !cgoEnabled() {
		t.Skip("Skipping SQLite tests: CGO not enabled")
	}

	// Create test database
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_threats.db")

	db, err := NewThreatDB(dbPath)
	if err != nil {
		t.Fatalf("Failed to create threat database: %v", err)
	}
	defer db.Close()

	// Create test sources
	sources := []ThreatSource{
		{
			Name:    "test-source",
			URL:     "http://example.com/threats",
			Enabled: true,
		},
	}

	updater := NewThreatUpdater(db, sources)

	if updater == nil {
		t.Fatal("Expected non-nil updater")
	}

	if len(updater.sources) != 1 {
		t.Errorf("Expected 1 source, got %d", len(updater.sources))
	}

	if updater.sources[0].Name != "test-source" {
		t.Errorf("Expected source name 'test-source', got %s", updater.sources[0].Name)
	}
}

func TestThreatUpdater_FetchThreatsFromSource(t *testing.T) {
	// Skip if CGO not available
	if !cgoEnabled() {
		t.Skip("Skipping SQLite tests: CGO not enabled")
	}

	// Create mock server
	mockThreats := []ExternalThreat{
		{
			PackageName: "malicious-package",
			Registry:    "npm",
			ThreatType:  "typosquatting",
			Severity:    "high",
			Confidence:  0.9,
			Description: "Known typosquatting package",
			Source:      "test-intel",
			ReportedAt:  time.Now(),
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mockThreats)
	}))
	defer server.Close()

	// Create test database
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_threats.db")

	db, err := NewThreatDB(dbPath)
	if err != nil {
		t.Fatalf("Failed to create threat database: %v", err)
	}
	defer db.Close()

	updater := NewThreatUpdater(db, nil)

	source := ThreatSource{
		Name:    "test-source",
		URL:     server.URL,
		Enabled: true,
	}

	threats, err := updater.fetchThreatsFromSource(context.Background(), source)
	if err != nil {
		t.Fatalf("Failed to fetch threats: %v", err)
	}

	if len(threats) != 1 {
		t.Errorf("Expected 1 threat, got %d", len(threats))
	}

	if threats[0].PackageName != "malicious-package" {
		t.Errorf("Expected package name 'malicious-package', got %s", threats[0].PackageName)
	}
}

func TestThreatUpdater_ValidateThreat(t *testing.T) {
	updater := &ThreatUpdater{}

	// Valid threat
	validThreat := ExternalThreat{
		PackageName: "test-package",
		Registry:    "npm",
		ThreatType:  "typosquatting",
		Severity:    "high",
		Confidence:  0.8,
		Description: "Test threat",
	}

	if err := updater.validateThreat(validThreat); err != nil {
		t.Errorf("Expected valid threat to pass validation, got error: %v", err)
	}

	// Invalid threats
	invalidThreats := []ExternalThreat{
		{Registry: "npm", ThreatType: "typosquatting", Severity: "high", Confidence: 0.8}, // Missing package name
		{PackageName: "test", ThreatType: "typosquatting", Severity: "high", Confidence: 0.8}, // Missing registry
		{PackageName: "test", Registry: "npm", Severity: "high", Confidence: 0.8}, // Missing threat type
		{PackageName: "test", Registry: "npm", ThreatType: "typosquatting", Confidence: 0.8}, // Missing severity
		{PackageName: "test", Registry: "npm", ThreatType: "typosquatting", Severity: "high", Confidence: 1.5}, // Invalid confidence
	}

	for i, threat := range invalidThreats {
		if err := updater.validateThreat(threat); err == nil {
			t.Errorf("Expected invalid threat %d to fail validation", i)
		}
	}
}

func TestThreatUpdater_ConvertToThreatRecord(t *testing.T) {
	updater := &ThreatUpdater{}

	threat := ExternalThreat{
		PackageName: "test-package",
		Registry:    "npm",
		ThreatType:  "typosquatting",
		Severity:    "high",
		Confidence:  0.9,
		Description: "Test threat",
		Metadata:    map[string]interface{}{"key": "value"},
	}

	record := updater.convertToThreatRecord(threat, "test-source")

	if record.PackageName != threat.PackageName {
		t.Errorf("Expected package name %s, got %s", threat.PackageName, record.PackageName)
	}

	if record.Registry != threat.Registry {
		t.Errorf("Expected registry %s, got %s", threat.Registry, record.Registry)
	}

	if record.ThreatType != threat.ThreatType {
		t.Errorf("Expected threat type %s, got %s", threat.ThreatType, record.ThreatType)
	}

	if record.Severity != threat.Severity {
		t.Errorf("Expected severity %s, got %s", threat.Severity, record.Severity)
	}

	if record.Confidence != threat.Confidence {
		t.Errorf("Expected confidence %f, got %f", threat.Confidence, record.Confidence)
	}

	if record.Source != "test-source" {
		t.Errorf("Expected source 'test-source', got %s", record.Source)
	}

	// Check metadata JSON
	var metadata map[string]interface{}
	if err := json.Unmarshal([]byte(record.Metadata), &metadata); err != nil {
		t.Errorf("Failed to parse metadata JSON: %v", err)
	}

	if metadata["key"] != "value" {
		t.Errorf("Expected metadata key 'value', got %v", metadata["key"])
	}
}

func TestThreatUpdater_ShouldUpdateThreat(t *testing.T) {
	updater := &ThreatUpdater{}

	baseTime := time.Now()
	existing := &ThreatRecord{
		Confidence: 0.7,
		Severity:   "medium",
		UpdatedAt:  baseTime,
	}

	// Test higher confidence
	newThreat := &ThreatRecord{
		Confidence: 0.9,
		Severity:   "medium",
		UpdatedAt:  baseTime,
	}
	if !updater.shouldUpdateThreat(existing, newThreat) {
		t.Error("Expected to update threat with higher confidence")
	}

	// Test higher severity
	newThreat = &ThreatRecord{
		Confidence: 0.7,
		Severity:   "high",
		UpdatedAt:  baseTime,
	}
	if !updater.shouldUpdateThreat(existing, newThreat) {
		t.Error("Expected to update threat with higher severity")
	}

	// Test more recent data with same confidence
	newThreat = &ThreatRecord{
		Confidence: 0.7,
		Severity:   "medium",
		UpdatedAt:  baseTime.Add(time.Hour),
	}
	if !updater.shouldUpdateThreat(existing, newThreat) {
		t.Error("Expected to update threat with more recent data")
	}

	// Test lower confidence
	newThreat = &ThreatRecord{
		Confidence: 0.5,
		Severity:   "medium",
		UpdatedAt:  baseTime,
	}
	if updater.shouldUpdateThreat(existing, newThreat) {
		t.Error("Expected not to update threat with lower confidence")
	}
}

func TestThreatUpdater_SourceManagement(t *testing.T) {
	// Skip if CGO not available
	if !cgoEnabled() {
		t.Skip("Skipping SQLite tests: CGO not enabled")
	}

	// Create test database
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_threats.db")

	db, err := NewThreatDB(dbPath)
	if err != nil {
		t.Fatalf("Failed to create threat database: %v", err)
	}
	defer db.Close()

	updater := NewThreatUpdater(db, nil)

	// Test adding source
	source := ThreatSource{
		Name:    "new-source",
		URL:     "http://example.com",
		Enabled: true,
	}
	updater.AddSource(source)

	if len(updater.sources) != 1 {
		t.Errorf("Expected 1 source after adding, got %d", len(updater.sources))
	}

	// Test enabling/disabling source
	err = updater.EnableSource("new-source", false)
	if err != nil {
		t.Errorf("Failed to disable source: %v", err)
	}

	if updater.sources[0].Enabled {
		t.Error("Expected source to be disabled")
	}

	// Test removing source
	updater.RemoveSource("new-source")
	if len(updater.sources) != 0 {
		t.Errorf("Expected 0 sources after removal, got %d", len(updater.sources))
	}

	// Test enabling non-existent source
	err = updater.EnableSource("non-existent", true)
	if err == nil {
		t.Error("Expected error when enabling non-existent source")
	}
}

func TestThreatUpdater_UpdateThreats_Integration(t *testing.T) {
	// Skip if CGO not available
	if !cgoEnabled() {
		t.Skip("Skipping SQLite tests: CGO not enabled")
	}

	// Create mock server with threat data
	mockThreats := []ExternalThreat{
		{
			PackageName: "evil-package",
			Registry:    "npm",
			ThreatType:  "malicious",
			Severity:    "critical",
			Confidence:  0.95,
			Description: "Known malicious package",
			Source:      "security-feed",
			ReportedAt:  time.Now(),
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mockThreats)
	}))
	defer server.Close()

	// Create test database
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_threats.db")

	db, err := NewThreatDB(dbPath)
	if err != nil {
		t.Fatalf("Failed to create threat database: %v", err)
	}
	defer db.Close()

	// Create updater with mock source
	sources := []ThreatSource{
		{
			Name:    "mock-source",
			URL:     server.URL,
			Enabled: true,
		},
	}

	updater := NewThreatUpdater(db, sources)

	// Run update
	err = updater.UpdateThreats(context.Background())
	if err != nil {
		t.Fatalf("Failed to update threats: %v", err)
	}

	// Verify threat was added to database
	threat, err := db.GetThreat("evil-package", "npm")
	if err != nil {
		t.Fatalf("Failed to get threat from database: %v", err)
	}

	if threat == nil {
		t.Fatal("Expected threat to be found in database")
	}

	if threat.PackageName != "evil-package" {
		t.Errorf("Expected package name 'evil-package', got %s", threat.PackageName)
	}

	if threat.ThreatType != "malicious" {
		t.Errorf("Expected threat type 'malicious', got %s", threat.ThreatType)
	}

	if threat.Severity != "critical" {
		t.Errorf("Expected severity 'critical', got %s", threat.Severity)
	}
}