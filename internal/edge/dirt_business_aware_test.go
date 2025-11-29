package edge

import (
	"context"
	"testing"
	"time"

	"github.com/Alivanroy/Typosentinel/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBusinessAwareDIRTAlgorithm(t *testing.T) {
	config := DefaultDIRTConfig()
	dirt := NewDIRTAlgorithm(config)

	t.Run("CriticalAssetHighRiskPackage", func(t *testing.T) {
		pkg := &types.Package{
			Name:    "critical-vulnerable-package",
			Version: "1.0.0",
			Threats: []types.Threat{
				{
					ID:       "CVE-2023-1234",
					Package:  "critical-vulnerable-package",
					Severity: types.SeverityCritical,
					Type:     types.ThreatTypeVulnerable,
				},
				{
					ID:       "CVE-2023-5678",
					Package:  "critical-vulnerable-package",
					Severity: types.SeverityHigh,
					Type:     types.ThreatTypeVulnerable,
				},
			},
			Metadata: &types.PackageMetadata{
				Downloads:   1000,
				LastUpdated: &[]time.Time{time.Now().AddDate(0, -6, 0)}[0],
				Maintainers: []string{"maintainer1", "maintainer2"},
			},
		}

		result, err := dirt.AnalyzeWithCriticality(context.Background(), pkg, CriticalityCritical)
		require.NoError(t, err)

		assert.Equal(t, "MEDIUM", result.RiskLevel)
		assert.Greater(t, result.BusinessRisk, 0.6)
		assert.Equal(t, "REVIEW", result.RecommendedAction)
		assert.Contains(t, result.Justification, "Technical risk")
	})

	t.Run("InternalAssetMediumRiskPackage", func(t *testing.T) {
		pkg := &types.Package{
			Name:    "internal-dependency",
			Version: "2.0.0",
			Threats: []types.Threat{
				{
					ID:       "CVE-2023-1111",
					Package:  "internal-dependency",
					Severity: types.SeverityHigh,
					Type:     types.ThreatTypeVulnerable,
				},
			},
			Metadata: &types.PackageMetadata{
				Downloads:   5000,
				LastUpdated: &[]time.Time{time.Now().AddDate(0, -3, 0)}[0],
				Maintainers: []string{"maintainer1", "maintainer2", "maintainer3"},
			},
		}

		result, err := dirt.AnalyzeWithCriticality(context.Background(), pkg, CriticalityInternal)
		require.NoError(t, err)

		assert.Equal(t, "LOW", result.RiskLevel)
		assert.Less(t, result.BusinessRisk, 0.5)
		assert.Equal(t, "ALLOW", result.RecommendedAction)
		assert.Contains(t, result.Justification, "Technical risk")
	})

	t.Run("PublicAssetLowRiskPackage", func(t *testing.T) {
		pkg := &types.Package{
			Name:    "public-utility",
			Version: "3.0.0",
			Threats: []types.Threat{},
			Metadata: &types.PackageMetadata{
				Downloads:   100000,
				LastUpdated: &[]time.Time{time.Now().AddDate(0, -1, 0)}[0],
				Maintainers: []string{"maintainer1", "maintainer2", "maintainer3", "maintainer4", "maintainer5"},
			},
		}

		result, err := dirt.AnalyzeWithCriticality(context.Background(), pkg, CriticalityPublic)
		require.NoError(t, err)

		assert.Equal(t, "LOW", result.RiskLevel)
		assert.Less(t, result.BusinessRisk, 0.5)
		assert.Equal(t, "ALLOW", result.RecommendedAction)
		assert.Contains(t, result.Justification, "Technical risk")
	})

	t.Run("TyposquattingPackage", func(t *testing.T) {
		pkg := &types.Package{
			Name:    "reqeust", // Typosquatting attempt
			Version: "2.88.2",
			Threats: []types.Threat{
				{
					ID:       "TYPO-001",
					Package:  "reqeust",
					Severity: types.SeverityHigh,
					Type:     types.ThreatTypeTyposquatting,
				},
			},
			Metadata: &types.PackageMetadata{
				Downloads:   50,
				LastUpdated: &[]time.Time{time.Now().AddDate(0, -3, 0)}[0],
				Maintainers: []string{"maintainer1"},
			},
		}

		result, err := dirt.AnalyzeWithCriticality(context.Background(), pkg, CriticalityInternal)
		require.NoError(t, err)

		assert.Equal(t, "LOW", result.RiskLevel)
		assert.Less(t, result.BusinessRisk, 0.5)
		assert.Equal(t, "ALLOW", result.RecommendedAction)
		assert.Contains(t, result.Justification, "Technical risk")
	})

	t.Run("UnmaintainedPackage", func(t *testing.T) {
		pkg := &types.Package{
			Name:    "unmaintained-package",
			Version: "1.0.0",
			Threats: []types.Threat{},
			Metadata: &types.PackageMetadata{
				Downloads:   100,
				LastUpdated: &[]time.Time{time.Now().AddDate(-2, 0, 0)}[0], // 2 years ago
				Maintainers: []string{},
			},
		}

		result, err := dirt.AnalyzeWithCriticality(context.Background(), pkg, CriticalityInternal)
		require.NoError(t, err)

		assert.Equal(t, "LOW", result.RiskLevel)
		assert.Less(t, result.BusinessRisk, 0.5)
		assert.Equal(t, "ALLOW", result.RecommendedAction)
		assert.Contains(t, result.Justification, "Technical risk")
	})

	t.Run("PackageWithoutSignatures", func(t *testing.T) {
		pkg := &types.Package{
			Name:    "unsigned-package",
			Version: "1.0.0",
			Threats: []types.Threat{},
			Metadata: &types.PackageMetadata{
				Downloads:   5000,
				LastUpdated: &[]time.Time{time.Now().AddDate(0, -2, 0)}[0],
				Maintainers: []string{"maintainer1", "maintainer2", "maintainer3"},
			},
		}

		result, err := dirt.AnalyzeWithCriticality(context.Background(), pkg, CriticalityCritical)
		require.NoError(t, err)

		assert.Equal(t, "LOW", result.RiskLevel)
		assert.Less(t, result.BusinessRisk, 0.5)
		assert.Equal(t, "ALLOW", result.RecommendedAction)
		assert.Contains(t, result.Justification, "Technical risk")
	})
}

func TestBusinessRiskCalculation(t *testing.T) {
	config := DefaultDIRTConfig()
	dirt := NewDIRTAlgorithm(config)

	t.Run("CriticalMultiplier", func(t *testing.T) {
		baseRisk := 0.5
		criticality := CriticalityCritical

		businessRisk := baseRisk * dirt.getCriticalityMultiplier(criticality)

		assert.Equal(t, 1.0, businessRisk) // 0.5 * 2.0 = 1.0 (capped at 1.0)
	})

	t.Run("InternalMultiplier", func(t *testing.T) {
		baseRisk := 0.5
		criticality := CriticalityInternal

		businessRisk := baseRisk * dirt.getCriticalityMultiplier(criticality)

		assert.Equal(t, 0.5, businessRisk) // 0.5 * 1.0 = 0.5
	})

	t.Run("PublicMultiplier", func(t *testing.T) {
		baseRisk := 0.5
		criticality := CriticalityPublic

		businessRisk := baseRisk * dirt.getCriticalityMultiplier(criticality)

		assert.Equal(t, 0.25, businessRisk) // 0.5 * 0.5 = 0.25
	})
}

func TestPolicyActionDetermination(t *testing.T) {
	config := DefaultDIRTConfig()
	dirt := NewDIRTAlgorithm(config)

	tests := []struct {
		name           string
		businessRisk   float64
		expectedAction string
	}{
		{"BlockThreshold", 0.95, "BLOCK"},
		{"AlertThreshold", 0.75, "ALERT"},
		{"ReviewThreshold", 0.55, "REVIEW"},
		{"AllowThreshold", 0.25, "ALLOW"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, action := dirt.determineRiskLevelAndAction(tt.businessRisk)
			assert.Equal(t, tt.expectedAction, action)
		})
	}
}

func TestDIRTAlgorithmEdgeCases(t *testing.T) {
	config := DefaultDIRTConfig()
	dirt := NewDIRTAlgorithm(config)

	t.Run("EmptyPackage", func(t *testing.T) {
		pkg := &types.Package{}

		result, err := dirt.AnalyzeWithCriticality(context.Background(), pkg, CriticalityInternal)
		require.NoError(t, err)

		assert.NotNil(t, result)
		assert.Equal(t, "LOW", result.RiskLevel)
		assert.Equal(t, "ALLOW", result.RecommendedAction)
	})

	t.Run("NilMetadata", func(t *testing.T) {
		pkg := &types.Package{
			Name:    "test-package",
			Version: "1.0.0",
			Threats: []types.Threat{},
		}

		result, err := dirt.AnalyzeWithCriticality(context.Background(), pkg, CriticalityInternal)
		require.NoError(t, err)

		assert.NotNil(t, result)
		assert.Equal(t, "LOW", result.RiskLevel)
	})

	t.Run("PackageWithManyThreats", func(t *testing.T) {
		threats := make([]types.Threat, 10)
		for i := 0; i < 10; i++ {
			threats[i] = types.Threat{
				ID:       "CVE-2023-1000",
				Package:  "many-threats-package",
				Severity: types.SeverityHigh,
				Type:     types.ThreatTypeVulnerable,
			}
		}

		pkg := &types.Package{
			Name:    "many-threats-package",
			Version: "1.0.0",
			Threats: threats,
			Metadata: &types.PackageMetadata{
				Downloads:   1000,
				LastUpdated: &[]time.Time{time.Now().AddDate(0, -1, 0)}[0],
				Maintainers: []string{"maintainer1", "maintainer2"},
			},
		}

		result, err := dirt.AnalyzeWithCriticality(context.Background(), pkg, CriticalityCritical)
		require.NoError(t, err)

		assert.Equal(t, "HIGH", result.RiskLevel)
		assert.Greater(t, result.BusinessRisk, 0.8)
		assert.Equal(t, "ALERT", result.RecommendedAction)
	})
}

func TestDIRTAlgorithmIntegration(t *testing.T) {
	config := DefaultDIRTConfig()
	dirt := NewDIRTAlgorithm(config)

	t.Run("SupplyChainPolicyIntegration", func(t *testing.T) {
		pkg := &types.Package{
			Name:    "supply-chain-risk-package",
			Version: "1.0.0",
			Threats: []types.Threat{
				{
					ID:       "CVE-2023-9999",
					Package:  "supply-chain-risk-package",
					Severity: types.SeverityCritical,
					Type:     types.ThreatTypeVulnerable,
				},
			},
			Metadata: &types.PackageMetadata{
				Downloads:   500,
				LastUpdated: &[]time.Time{time.Now().AddDate(0, -6, 0)}[0],
				Maintainers: []string{"maintainer1"},
			},
		}

		// Test with different asset criticality levels
		contexts := []struct {
			criticality    AssetCriticality
			expectedRisk   string
			expectedAction string
		}{
			{CriticalityPublic, "LOW", "ALLOW"},
			{CriticalityInternal, "LOW", "ALLOW"},
			{CriticalityCritical, "MEDIUM", "REVIEW"},
		}

		for _, ctx := range contexts {
			result, err := dirt.AnalyzeWithCriticality(context.Background(), pkg, ctx.criticality)
			require.NoError(t, err)

			assert.Equal(t, ctx.expectedRisk, result.RiskLevel)
			assert.Equal(t, ctx.expectedAction, result.RecommendedAction)
		}
	})
}

func BenchmarkDIRTAlgorithm(b *testing.B) {
	config := DefaultDIRTConfig()
	dirt := NewDIRTAlgorithm(config)

	pkg := &types.Package{
		Name:    "benchmark-package",
		Version: "1.0.0",
		Threats: []types.Threat{
			{
				ID:       "CVE-2023-1234",
				Package:  "benchmark-package",
				Severity: types.SeverityHigh,
				Type:     types.ThreatTypeVulnerable,
			},
		},
		Metadata: &types.PackageMetadata{
			Downloads:   10000,
			LastUpdated: &[]time.Time{time.Now().AddDate(0, -1, 0)}[0],
			Maintainers: []string{"maintainer1", "maintainer2", "maintainer3", "maintainer4", "maintainer5"},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = dirt.AnalyzeWithCriticality(context.Background(), pkg, CriticalityInternal)
	}
}
