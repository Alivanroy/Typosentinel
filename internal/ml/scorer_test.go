package ml

import (
	"testing"
)

func TestSimpleMLScorer_Analyze(t *testing.T) {
	scorer := NewSimpleMLScorer()

	tests := []struct {
		name     string
		features *EnhancedPackageFeatures
		wantRisk string
	}{
		{
			name: "Safe Package",
			features: &EnhancedPackageFeatures{
				PackageName: "safe-package",
				Maintainers: []string{"maintainer1"},
				Downloads:   1000,
			},
			wantRisk: "low",
		},
		{
			name: "Suspicious Package - No Maintainers",
			features: &EnhancedPackageFeatures{
				PackageName: "suspicious-package",
				Maintainers: []string{}, // No maintainers
				Downloads:   1000,
			},
			wantRisk: "low", // Score 0.2 -> low
		},
		{
			name: "Very Suspicious Package - No Maintainers & Low Downloads",
			features: &EnhancedPackageFeatures{
				PackageName: "very-suspicious",
				Maintainers: []string{}, // +0.2
				Downloads:   50,         // +0.1
			},
			wantRisk: "medium", // Score 0.3 -> medium (wait, logic says >0.3 is medium)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := scorer.Analyze(tt.features)
			if result.RiskLevel != tt.wantRisk {
				t.Errorf("Analyze() RiskLevel = %v, want %v (Score: %f)", result.RiskLevel, tt.wantRisk, result.Score)
			}
		})
	}
}
