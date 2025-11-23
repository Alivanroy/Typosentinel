package edge

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// TestAssetCriticalityMultipliers tests the asset criticality multiplier system
func TestAssetCriticalityMultipliers(t *testing.T) {
	tests := []struct {
		name              string
		criticality       AssetCriticality
		expectedMultiplier float64
	}{
		{
			name:              "Public assets have reduced risk multiplier",
			criticality:       CriticalityPublic,
			expectedMultiplier: 0.5,
		},
		{
			name:              "Internal assets have neutral risk multiplier",
			criticality:       CriticalityInternal,
			expectedMultiplier: 1.0,
		},
		{
			name:              "Critical assets have heightened risk multiplier",
			criticality:       CriticalityCritical,
			expectedMultiplier: 2.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test the internal getCriticalityMultiplier method
			config := DefaultDIRTConfig()
			dirt := NewDIRTAlgorithm(config)
			multiplier := dirt.getCriticalityMultiplier(tt.criticality)
			assert.Equal(t, tt.expectedMultiplier, multiplier)
		})
	}
}

// TestDIRTBusinessAwareAnalysis tests the DIRT algorithm with business-aware risk assessment
func TestDIRTBusinessAwareAnalysis(t *testing.T) {
	ctx := context.Background()
	config := DefaultDIRTConfig()
	dirt := NewDIRTAlgorithm(config)

	tests := []struct {
		name             string
		packageInfo      types.Package
		assetCriticality AssetCriticality
		expectedMinScore float64
		expectedAction   string
	}{
		{
			name: "Critical asset with vulnerabilities should have high business risk",
			packageInfo: types.Package{
				Name:    "vulnerable-core-package",
				Version: "1.0.0",
				Threats: []types.Threat{
					{
						ID:         "CVE-2023-1234",
						Package:    "vulnerable-core-package",
						Version:    "1.0.0",
						Type:       types.ThreatTypeVulnerable,
						Severity:   types.SeverityHigh,
						Confidence: 0.9,
						Description: "High severity vulnerability",
						DetectedAt: time.Now(),
					},
				},
				Metadata: &types.PackageMetadata{
					LastUpdated: &[]time.Time{time.Now().AddDate(0, -6, 0)}[0],
					Downloads:   1000,
					Maintainers: []string{"user1", "user2"},
				},
			},
			assetCriticality: CriticalityCritical,
			expectedMinScore: 0.3, // Should have moderate business risk due to critical multiplier
			expectedAction:   "BLOCK",
		},
		{
			name: "Public asset with no threats should have low business risk",
			packageInfo: types.Package{
				Name:     "public-utility",
				Version:  "3.0.0",
				Threats:  []types.Threat{},
				Metadata: &types.PackageMetadata{
					LastUpdated: &[]time.Time{time.Now().AddDate(0, -1, 0)}[0],
					Downloads:   100000,
					Maintainers: []string{"user1", "user2", "user3", "user4", "user5"},
				},
			},
			assetCriticality: CriticalityPublic,
			expectedMinScore: 0.0, // Low business risk with reduced multiplier
			expectedAction:   "ALLOW",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := dirt.AnalyzeWithCriticality(ctx, &tt.packageInfo, tt.assetCriticality)

			assert.NoError(t, err)
			assert.NotNil(t, result)
			assert.GreaterOrEqual(t, result.BusinessRisk, tt.expectedMinScore)
			assert.Equal(t, tt.assetCriticality, result.AssetCriticality)
			assert.Equal(t, dirt.getCriticalityMultiplier(tt.assetCriticality), result.ImpactMultiplier)
		})
	}
}