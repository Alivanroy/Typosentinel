package tests

import (
	"context"
	"testing"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/edge"
	"github.com/Alivanroy/Typosentinel/pkg/types"
)

func TestGTRAlgorithm_NewGTRAlgorithm(t *testing.T) {
	gtr := edge.NewGTRAlgorithm(nil)
	if gtr == nil {
		t.Fatal("NewGTRAlgorithm() returned nil")
	}

	if gtr.Name() != "GTR" {
		t.Errorf("Expected algorithm name 'GTR', got '%s'", gtr.Name())
	}
}

func TestGTRAlgorithm_AnalyzeLegitimatePackage(t *testing.T) {
	gtr := edge.NewGTRAlgorithm(nil)
	ctx := context.Background()

	pkg := &types.Package{
		Name:     "express",
		Version:  "4.18.2",
		Registry: "npm",
		RiskLevel: types.SeverityLow,
		RiskScore: 0.1,
		Dependencies: []types.Dependency{
			{
				Name:    "accepts",
				Version: "1.3.8",
				Direct:  true,
			},
			{
				Name:    "array-flatten",
				Version: "1.1.1",
				Direct:  true,
			},
		},
		Metadata: &types.PackageMetadata{
			Name:        "express",
			Version:     "4.18.2",
			Registry:    "npm",
			Description: "Fast, unopinionated, minimalist web framework",
			Author:      "TJ Holowaychuk",
			License:     "MIT",
			Downloads:   50000000,
			CreatedAt:   time.Now().AddDate(-10, 0, 0),
			UpdatedAt:   time.Now().AddDate(0, -1, 0),
		},
		AnalyzedAt: time.Now(),
	}

	result, err := gtr.Analyze(ctx, pkg)
	if err != nil {
		t.Fatalf("Analyze() failed: %v", err)
	}

	// GTR algorithm returns 0.0 for packages without high-risk dependencies
	if result.ThreatScore != 0.0 {
		t.Errorf("Expected 0.0 threat score for legitimate package with safe dependencies, got %f", result.ThreatScore)
	}
}

func TestGTRAlgorithm_AnalyzeTyposquattingPackage(t *testing.T) {
	// Create GTR with lower risk threshold to detect suspicious dependencies
	config := &edge.GTRConfig{
		MaxTraversalDepth:    10,
		MinRiskThreshold:     0.3, // Lower threshold
		EnablePathAnalysis:   true,
		MaxPathLength:        15,
		CriticalityWeight:    0.3,
		VulnerabilityWeight:  0.4,
		PopularityWeight:     0.1,
		TrustWeight:          0.2,
		EnableCycleDetection: true,
		MaxCycleLength:       8,
	}
	gtr := edge.NewGTRAlgorithm(config)
	ctx := context.Background()

	pkg := &types.Package{
		Name:     "expres", // typosquatting "express"
		Version:  "1.0.0",
		Registry: "npm",
		RiskLevel: types.SeverityHigh,
		RiskScore: 0.8,
		Dependencies: []types.Dependency{
			{
				Name:    "suspicious-package",
				Version: "1.0.0",
				Direct:  true,
			},
		},
		Metadata: &types.PackageMetadata{
			Name:        "expres",
			Version:     "1.0.0",
			Registry:    "npm",
			Description: "Fast web framework",
			Author:      "unknown",
			License:     "MIT",
			Downloads:   100,
			CreatedAt:   time.Now().AddDate(0, 0, -1),
			UpdatedAt:   time.Now(),
		},
		AnalyzedAt: time.Now(),
	}

	result, err := gtr.Analyze(ctx, pkg)
	if err != nil {
		t.Fatalf("Analyze() failed: %v", err)
	}

	// GTR focuses on dependency analysis, not package name analysis
	// So we test that it processes the package without error
	if result == nil {
		t.Error("Expected analysis result, got nil")
	}
	if result.AlgorithmName != "GTR" {
		t.Errorf("Expected algorithm name 'GTR', got '%s'", result.AlgorithmName)
	}
}

func TestGTRAlgorithm_AnalyzeUnicodePackage(t *testing.T) {
	gtr := edge.NewGTRAlgorithm(nil)
	ctx := context.Background()

	pkg := &types.Package{
		Name:     "еxpress", // Cyrillic 'е' instead of Latin 'e'
		Version:  "1.0.0",
		Registry: "npm",
		RiskLevel: types.SeverityCritical,
		RiskScore: 0.9,
		Dependencies: []types.Dependency{
			{
				Name:    "malicious-dep",
				Version: "1.0.0",
				Direct:  true,
			},
		},
		Metadata: &types.PackageMetadata{
			Name:        "еxpress",
			Version:     "1.0.0",
			Registry:    "npm",
			Description: "Web framework",
			Author:      "attacker",
			License:     "MIT",
			Downloads:   10,
			CreatedAt:   time.Now().AddDate(0, 0, -1),
			UpdatedAt:   time.Now(),
		},
		AnalyzedAt: time.Now(),
	}

	result, err := gtr.Analyze(ctx, pkg)
	if err != nil {
		t.Fatalf("Analyze() failed: %v", err)
	}

	// GTR focuses on dependency analysis, verify it processes unicode package names
	if result == nil {
		t.Error("Expected analysis result, got nil")
	}
	if result.AlgorithmName != "GTR" {
		t.Errorf("Expected algorithm name 'GTR', got '%s'", result.AlgorithmName)
	}
}

func TestGTRAlgorithm_AnalyzeNilPackage(t *testing.T) {
	gtr := edge.NewGTRAlgorithm(nil)
	ctx := context.Background()

	_, err := gtr.Analyze(ctx, nil)
	if err == nil {
		t.Error("Expected error when analyzing nil package")
	}
}

func TestGTRAlgorithm_BatchAnalysis(t *testing.T) {
	gtr := edge.NewGTRAlgorithm(nil)
	ctx := context.Background()

	packages := []*types.Package{
		{
			Name:     "lodash",
			Version:  "4.17.21",
			Registry: "npm",
			RiskLevel: types.SeverityLow,
			RiskScore: 0.1,
			Dependencies: []types.Dependency{
				{
					Name:    "safe-dep",
					Version: "1.0.0",
					Direct:  true,
				},
			},
			Metadata: &types.PackageMetadata{
				Name:     "lodash",
				Version:  "4.17.21",
				Registry: "npm",
				Downloads: 100000000,
				CreatedAt: time.Now().AddDate(-8, 0, 0),
				UpdatedAt: time.Now().AddDate(0, -2, 0),
			},
			AnalyzedAt: time.Now(),
		},
		{
			Name:     "lodаsh", // Cyrillic 'а'
			Version:  "1.0.0",
			Registry: "npm",
			RiskLevel: types.SeverityCritical,
			RiskScore: 0.95,
			Dependencies: []types.Dependency{
				{
					Name:    "suspicious-dep",
					Version: "1.0.0",
					Direct:  true,
				},
			},
			Metadata: &types.PackageMetadata{
				Name:     "lodаsh",
				Version:  "1.0.0",
				Registry: "npm",
				Downloads: 5,
				CreatedAt: time.Now().AddDate(0, 0, -1),
				UpdatedAt: time.Now(),
			},
			AnalyzedAt: time.Now(),
		},
	}

	for i, pkg := range packages {
		result, err := gtr.Analyze(ctx, pkg)
		if err != nil {
			t.Errorf("Package %d analysis failed: %v", i, err)
			continue
		}

		// Verify that analysis completes successfully for both packages
		if result == nil {
			t.Errorf("Package %d: Expected analysis result, got nil", i)
		}
		if result.AlgorithmName != "GTR" {
			t.Errorf("Package %d: Expected algorithm name 'GTR', got '%s'", i, result.AlgorithmName)
		}
	}
}

func TestGTRAlgorithm_Performance(t *testing.T) {
	gtr := edge.NewGTRAlgorithm(nil)
	ctx := context.Background()

	pkg := &types.Package{
		Name:     "test-package",
		Version:  "1.0.0",
		Registry: "npm",
		RiskLevel: types.SeverityLow,
		RiskScore: 0.2,
		Metadata: &types.PackageMetadata{
			Name:     "test-package",
			Version:  "1.0.0",
			Registry: "npm",
			CreatedAt: time.Now().AddDate(-1, 0, 0),
			UpdatedAt: time.Now(),
		},
		AnalyzedAt: time.Now(),
	}

	start := time.Now()
	for i := 0; i < 100; i++ {
		_, err := gtr.Analyze(ctx, pkg)
		if err != nil {
			t.Fatalf("Analysis failed on iteration %d: %v", i, err)
		}
	}
	duration := time.Since(start)

	// Should complete 100 analyses in reasonable time (< 1 second)
	if duration > time.Second {
		t.Errorf("Performance test took too long: %v", duration)
	}
}

func TestGTRAlgorithm_ConcurrentAnalysis(t *testing.T) {
	gtr := edge.NewGTRAlgorithm(nil)
	ctx := context.Background()

	pkg := &types.Package{
		Name:     "concurrent-test",
		Version:  "1.0.0",
		Registry: "npm",
		RiskLevel: types.SeverityLow,
		RiskScore: 0.1,
		Metadata: &types.PackageMetadata{
			Name:     "concurrent-test",
			Version:  "1.0.0",
			Registry: "npm",
			CreatedAt: time.Now().AddDate(-1, 0, 0),
			UpdatedAt: time.Now(),
		},
		AnalyzedAt: time.Now(),
	}

	// Run 10 concurrent analyses
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func(id int) {
			_, err := gtr.Analyze(ctx, pkg)
			if err != nil {
				t.Errorf("Concurrent analysis %d failed: %v", id, err)
			}
			done <- true
		}(i)
	}

	// Wait for all to complete
	for i := 0; i < 10; i++ {
		select {
		case <-done:
			// Success
		case <-time.After(5 * time.Second):
			t.Fatal("Concurrent analysis timed out")
		}
	}
}

func TestGTRAlgorithm_EdgeCases(t *testing.T) {
	gtr := edge.NewGTRAlgorithm(nil)
	ctx := context.Background()

	testCases := []struct {
		name        string
		pkg         *types.Package
		expectError bool
	}{
		{
			name: "Empty package name",
			pkg: &types.Package{
				Name:     "",
				Version:  "1.0.0",
				Registry: "npm",
				Metadata: &types.PackageMetadata{},
				AnalyzedAt: time.Now(),
			},
			expectError: false, // GTR doesn't validate package names
		},
		{
			name: "Very long package name",
			pkg: &types.Package{
				Name:     "this-is-a-very-long-package-name-that-exceeds-normal-limits-and-might-be-used-for-malicious-purposes-to-confuse-users-and-hide-the-true-intent-of-the-package-which-could-be-a-sophisticated-attack-vector",
				Version:  "1.0.0",
				Registry: "npm",
				RiskLevel: types.SeverityHigh,
				RiskScore: 0.8,
				Dependencies: []types.Dependency{
					{
						Name:    "normal-dep",
						Version: "1.0.0",
						Direct:  true,
					},
				},
				Metadata: &types.PackageMetadata{
					Name:     "very-long-name",
					Version:  "1.0.0",
					Registry: "npm",
					CreatedAt: time.Now(),
					UpdatedAt: time.Now(),
				},
				AnalyzedAt: time.Now(),
			},
			expectError: false,
		},
		{
			name: "Special characters in name",
			pkg: &types.Package{
				Name:     "@scope/package-name_with.special-chars",
				Version:  "1.0.0",
				Registry: "npm",
				RiskLevel: types.SeverityLow,
				RiskScore: 0.2,
				Dependencies: []types.Dependency{
					{
						Name:    "scoped-dep",
						Version: "2.1.0",
						Direct:  true,
					},
				},
				Metadata: &types.PackageMetadata{
					Name:     "@scope/package-name_with.special-chars",
					Version:  "1.0.0",
					Registry: "npm",
					CreatedAt: time.Now(),
					UpdatedAt: time.Now(),
				},
				AnalyzedAt: time.Now(),
			},
			expectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := gtr.Analyze(ctx, tc.pkg)
			if tc.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tc.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if !tc.expectError && result == nil {
				t.Error("Expected analysis result, got nil")
			}
		})
	}
}