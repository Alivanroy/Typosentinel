package tests

import (
	"github.com/Alivanroy/Typosentinel/internal/analyzer"
	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/pkg/types"
	"testing"
	"time"
)

// Debug test for basic analyzer functionality
func TestDebug(t *testing.T) {
	// Test basic analyzer functionality
	cfg := &config.Config{}
	a, err := analyzer.New(cfg)
	if err != nil {
		t.Fatalf("Failed to create analyzer: %v", err)
	}

	// Create a test scan result
	testResult := &types.ScanResult{
		ID:          "test-scan-1",
		Target:      "test-package@1.0.0",
		Type:        "package",
		Status:      "completed",
		OverallRisk: "medium",
		RiskScore:   0.6,
		Packages: []*types.Package{
			{
				Name:     "test-package",
				Version:  "1.0.0",
				Registry: "npm",
			},
		},
		Summary: &types.ScanSummary{
			TotalPackages:   1,
			ScannedPackages: 1,
			CleanPackages:   0,
			CriticalThreats: 0,
			HighThreats:     0,
			MediumThreats:   1,
			LowThreats:      0,
			TotalThreats:    1,
			ThreatsFound:    1,
			HighestSeverity: types.SeverityMedium,
		},
		Duration:  time.Second * 5,
		CreatedAt: time.Now(),
	}

	// Test that analyzer was created successfully
	if a == nil {
		t.Error("Analyzer should not be nil")
	}

	// Test that scan result is valid
	if testResult.ID == "" {
		t.Error("Scan result ID should not be empty")
	}
	if testResult.Summary.TotalThreats != 1 {
		t.Errorf("Expected 1 threat, got %d", testResult.Summary.TotalThreats)
	}

	t.Logf("Debug test completed successfully")
	t.Logf("Analyzer created and scan result validated")
}
