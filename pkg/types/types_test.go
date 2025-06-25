package types

import (
	"fmt"
	"testing"
	"time"
)

func TestSeverity(t *testing.T) {
	// Test Severity enum and string conversion
	testCases := []struct {
		severity Severity
		expected string
	}{
		{SeverityLow, "low"},
		{SeverityMedium, "medium"},
		{SeverityHigh, "high"},
		{SeverityCritical, "critical"},
		{SeverityUnknown, "unknown"},
		{Severity(999), "unknown"}, // Test default case
	}
	
	for _, tc := range testCases {
		if tc.severity.String() != tc.expected {
			t.Errorf("Expected severity %v to be '%s', got '%s'", tc.severity, tc.expected, tc.severity.String())
		}
	}
}

func TestRiskLevel(t *testing.T) {
	// Test RiskLevel enum and string conversion
	testCases := []struct {
		riskLevel RiskLevel
		expected  string
	}{
		{RiskLevelMinimal, "minimal"},
		{RiskLevelLow, "low"},
		{RiskLevelMedium, "medium"},
		{RiskLevelHigh, "high"},
		{RiskLevelCritical, "critical"},
		{RiskLevel(999), "unknown"}, // Test default case
	}
	
	for _, tc := range testCases {
		if tc.riskLevel.String() != tc.expected {
			t.Errorf("Expected risk level %v to be '%s', got '%s'", tc.riskLevel, tc.expected, tc.riskLevel.String())
		}
	}
}

func TestThreatType(t *testing.T) {
	// Test ThreatType constants
	testCases := []ThreatType{
		ThreatTypeTyposquatting,
		ThreatTypeDependencyConfusion,
		ThreatTypeMaliciousPackage,
		ThreatTypeHomoglyph,
		ThreatTypeReputationRisk,
	}
	
	for _, threatType := range testCases {
		if string(threatType) == "" {
			t.Errorf("ThreatType should not be empty: %v", threatType)
		}
	}
	
	// Test specific threat type
	if ThreatTypeTyposquatting != "typosquatting" {
		t.Errorf("Expected ThreatTypeTyposquatting to be 'typosquatting', got '%s'", ThreatTypeTyposquatting)
	}
}

func TestPackageMetadata(t *testing.T) {
	// Test PackageMetadata creation and properties
	now := time.Now()
	pkgMeta := &PackageMetadata{
		Name:        "lodash",
		Version:     "4.17.21",
		Registry:    "npm",
		Description: "A modern JavaScript utility library",
		Author:      "John Doe",
		License:     "MIT",
		Homepage:    "https://lodash.com",
		Repository:  "https://github.com/lodash/lodash",
		Downloads:   1000000,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	
	if pkgMeta.Name != "lodash" {
		t.Errorf("Expected Name 'lodash', got '%s'", pkgMeta.Name)
	}
	
	if pkgMeta.Downloads != 1000000 {
		t.Errorf("Expected Downloads 1000000, got %d", pkgMeta.Downloads)
	}
	
	if pkgMeta.License != "MIT" {
		t.Errorf("Expected License 'MIT', got '%s'", pkgMeta.License)
	}
}

func TestThreat(t *testing.T) {
	// Test Threat creation and properties
	threat := &Threat{
		ID:         "threat-001",
		Package:    "suspicious-package",
		Version:    "1.0.0",
		Registry:   "npm",
		Type:       ThreatTypeTyposquatting,
		Severity:   SeverityHigh,
		Confidence: 0.85,
	}
	
	if threat.ID != "threat-001" {
		t.Errorf("Expected ID 'threat-001', got '%s'", threat.ID)
	}
	
	if threat.Type != ThreatTypeTyposquatting {
		t.Errorf("Expected Type ThreatTypeTyposquatting, got '%s'", threat.Type)
	}
	
	if threat.Severity != SeverityHigh {
		t.Errorf("Expected Severity SeverityHigh, got %v", threat.Severity)
	}
	
	if threat.Confidence != 0.85 {
		t.Errorf("Expected Confidence 0.85, got %f", threat.Confidence)
	}
}

func TestDependency(t *testing.T) {
	// Test Dependency creation and properties
	dep := &Dependency{
		Name:        "lodash",
		Version:     "4.17.21",
		Registry:    "npm",
		Source:      "package.json",
		Direct:      true,
		Development: false,
		Constraints: "^4.17.0",
	}
	
	if dep.Name != "lodash" {
		t.Errorf("Expected Name 'lodash', got '%s'", dep.Name)
	}
	
	if dep.Version != "4.17.21" {
		t.Errorf("Expected Version '4.17.21', got '%s'", dep.Version)
	}
	
	if !dep.Direct {
		t.Error("Expected Direct to be true")
	}
	
	if dep.Development {
		t.Error("Expected Development to be false")
	}
}

func TestThreatWithMultipleTypes(t *testing.T) {
	// Test creating threats with different types
	threatTypes := []ThreatType{
		ThreatTypeTyposquatting,
		ThreatTypeMaliciousPackage,
		ThreatTypeReputationRisk,
	}
	
	for i, threatType := range threatTypes {
		threat := &Threat{
			ID:       fmt.Sprintf("threat-%d", i),
			Package:  "test-package",
			Type:     threatType,
			Severity: SeverityMedium,
		}
		
		if threat.Type != threatType {
			t.Errorf("Expected threat type %s, got %s", threatType, threat.Type)
		}
	}
}

func TestConfidenceValidation(t *testing.T) {
	// Test confidence score validation (should be between 0 and 1)
	testCases := []struct {
		confidence float64
		valid      bool
	}{
		{0.0, true},
		{0.5, true},
		{1.0, true},
		{-0.1, false},
		{1.1, false},
	}
	
	for _, tc := range testCases {
		threat := &Threat{
			Confidence: tc.confidence,
		}
		
		// Basic validation - confidence should be between 0 and 1
		isValid := threat.Confidence >= 0.0 && threat.Confidence <= 1.0
		
		if isValid != tc.valid {
			t.Errorf("Confidence %f: expected valid=%t, got valid=%t", tc.confidence, tc.valid, isValid)
		}
	}
}

func TestSeverityLevels(t *testing.T) {
	// Test different severity levels
	validSeverities := []Severity{SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}
	expectedStrings := []string{"low", "medium", "high", "critical"}
	
	for i, severity := range validSeverities {
		threat := &Threat{
			Severity: severity,
		}
		
		if threat.Severity != severity {
			t.Errorf("Expected severity %v, got %v", severity, threat.Severity)
		}
		
		if threat.Severity.String() != expectedStrings[i] {
			t.Errorf("Expected severity string '%s', got '%s'", expectedStrings[i], threat.Severity.String())
		}
	}
}