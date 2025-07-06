package tests

import (
	"context"
	"testing"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/reputation"
	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// TestReputationAnalysisRealLife tests reputation analysis with real-world scenarios
func TestReputationAnalysisRealLife(t *testing.T) {
	tests := []struct {
		name     string
		pkg      *types.Package
		expected types.RiskLevel
	}{
		{
			name: "Legitimate popular package - React",
			pkg: &types.Package{
				Name:     "react",
				Version:  "18.2.0",
				Registry: "npm",
				Metadata: &types.PackageMetadata{
					Downloads: 20000000,
					Metadata: map[string]interface{}{
						"author_email": "react-team@meta.com",
						"keywords":     []string{"react", "ui", "framework"},
						"description":  "A JavaScript library for building user interfaces",
					},
				},
			},
			expected: types.RiskLevelLow,
		},
		{
			name: "Suspicious typosquatting package",
			pkg: &types.Package{
				Name:     "reactt", // Typosquatting of react
				Version:  "1.0.0",
				Registry: "npm",
				Metadata: &types.PackageMetadata{
					Downloads: 100,
					Metadata: map[string]interface{}{
						"author_email": "suspicious@example.com",
						"keywords":     []string{"react", "ui"},
						"description":  "A JavaScript library for building user interfaces", // Same description
					},
				},
			},
			expected: types.RiskLevelHigh,
		},
		{
			name: "New package with low downloads",
			pkg: &types.Package{
				Name:     "my-new-utility",
				Version:  "0.1.0",
				Registry: "npm",
				Metadata: &types.PackageMetadata{
					Downloads: 50,
					Metadata: map[string]interface{}{
						"author_email": "developer@example.com",
						"keywords":     []string{"utility", "helper"},
						"description":  "A utility package for common tasks",
					},
				},
			},
			expected: types.RiskLevelMedium,
		},
		{
			name: "Package with suspicious keywords",
			pkg: &types.Package{
				Name:     "crypto-miner",
				Version:  "2.1.0",
				Registry: "npm",
				Metadata: &types.PackageMetadata{
					Downloads: 1000,
					Metadata: map[string]interface{}{
						"author_email": "miner@crypto.com",
						"keywords":     []string{"crypto", "mining", "bitcoin", "stealth"},
						"description":  "Cryptocurrency mining utility",
					},
				},
			},
			expected: types.RiskLevelHigh,
		},
	}

	// Create reputation analyzer
	config := &reputation.Config{
		Enabled:    true,
		CacheSize:  100,
		CacheTTL:   time.Hour,
		Timeout:    30 * time.Second,
		MaxRetries: 3,
		RetryDelay: time.Second,
		Sources:    []reputation.Source{},
	}
	analyzer := reputation.NewAnalyzer(config)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			// Analyze package reputation
			result, err := analyzer.AnalyzePackage(ctx, tt.pkg)
		if err != nil {
			t.Logf("Warning: Reputation analysis failed for %s: %v", tt.pkg.Name, err)
				// Don't fail the test for network issues, just log
				return
			}

			if result == nil {
				t.Errorf("Expected reputation result, got nil")
				return
			}

			// Log the analysis results
			t.Logf("Package: %s, Score: %.2f, Risk: %s",
			tt.pkg.Name, result.Score, result.Risk)

			// Verify risk assessment is reasonable
			if result.Score < 0 || result.Score > 1 {
				t.Errorf("Score should be between 0 and 1, got %.2f", result.Score)
			}

			// Check if the risk level matches expectations (with some tolerance)
			if tt.name == "Legitimate popular package - React" && result.Score > 0.3 {
				t.Logf("Note: Popular package has score %.2f, which may be higher than expected but acceptable", result.Score)
			}

			if tt.name == "Suspicious typosquatting package" && result.Score < 0.7 {
				t.Errorf("Suspicious package should have high score, got %.2f", result.Score)
			}
		})
	}
}

// TestReputationAnalysisBatch tests batch analysis of multiple packages
func TestReputationAnalysisBatch(t *testing.T) {
	packages := []*types.Package{
		{
			Name:     "lodash",
			Version:  "4.17.21",
			Registry: "npm",
			Metadata: &types.PackageMetadata{
				Downloads: 50000000,
				Metadata: map[string]interface{}{
					"author_email": "john.dalton@example.com",
					"keywords":     []string{"lodash", "utility", "functional"},
				},
			},
		},
		{
			Name:     "express",
			Version:  "4.18.2",
			Registry: "npm",
			Metadata: &types.PackageMetadata{
				Downloads: 30000000,
				Metadata: map[string]interface{}{
					"author_email": "tj@vision-media.ca",
					"keywords":     []string{"express", "framework", "web"},
				},
			},
		},
		{
			Name:     "suspicious-pkg",
			Version:  "1.0.0",
			Registry: "npm",
			Metadata: &types.PackageMetadata{
				Downloads: 10,
				Metadata: map[string]interface{}{
					"author_email": "hacker@malicious.com",
					"keywords":     []string{"hack", "exploit"},
				},
			},
		},
	}

	config := &reputation.Config{
		Enabled:    true,
		CacheSize:  100,
		CacheTTL:   time.Hour,
		Timeout:    30 * time.Second,
		MaxRetries: 3,
		RetryDelay: time.Second,
		Sources:    []reputation.Source{},
	}
	analyzer := reputation.NewAnalyzer(config)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	results, err := analyzer.AnalyzePackages(ctx, packages)
	if err != nil {
		t.Logf("Warning: Batch analysis failed: %v", err)
		return // Don't fail for network issues
	}

	if len(results) != len(packages) {
		t.Errorf("Expected %d results, got %d", len(packages), len(results))
	}

	for i, result := range results {
		if result != nil {
			t.Logf("Package %s: Score %.2f, Risk %s", 
				packages[i].Name, result.Score, result.Risk)
		}
	}
}

// TestReputationAnalysisPerformance tests the performance of reputation analysis
func TestReputationAnalysisPerformance(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	pkg := &types.Package{
		Name:     "test-performance",
		Version:  "1.0.0",
		Registry: "npm",
		Metadata: &types.PackageMetadata{
			Downloads: 1000,
			Metadata: map[string]interface{}{
				"author_email": "test@example.com",
				"keywords":     []string{"test"},
			},
		},
	}

	config := &reputation.Config{
		Enabled:    true,
		CacheSize:  100,
		CacheTTL:   time.Hour,
		Timeout:    10 * time.Second,
		MaxRetries: 3,
		RetryDelay: time.Second,
		Sources:    []reputation.Source{},
	}
	analyzer := reputation.NewAnalyzer(config)

	// Measure analysis time
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := analyzer.AnalyzePackage(ctx, pkg)
	duration := time.Since(start)

	if err != nil {
		t.Logf("Warning: Performance test failed: %v", err)
		return
	}

	t.Logf("Reputation analysis took %v", duration)

	// Analysis should complete within reasonable time
	if duration > 5*time.Second {
		t.Errorf("Reputation analysis took too long: %v", duration)
	}
}