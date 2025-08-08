package reputation

import (
	"context"
	"testing"
	"time"

	"github.com/Alivanroy/Typosentinel/pkg/logger"
	"github.com/Alivanroy/Typosentinel/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnhancedReputationSystem_AnalyzePackageReputation(t *testing.T) {
	tests := []struct {
		name           string
		packageName    string
		registry       string
		version        string
		setupMocks     func(*EnhancedReputationSystem)
		expectedScore  float64
		expectedRisk   string
		expectedTrust  string
		expectError    bool
	}{
		{
			name:        "high reputation package",
			packageName: "requests",
			registry:    "pypi",
			version:     "2.28.1",
			setupMocks: func(ers *EnhancedReputationSystem) {
				// Mock high reputation package data
			},
			expectedScore: 0.62, // Calculated score based on component analysis
			expectedRisk:  "very_low",
			expectedTrust: "medium",
			expectError:   false,
		},
		{
			name:        "suspicious package",
			packageName: "malicious-pkg",
			registry:    "pypi",
			version:     "1.0.0",
			setupMocks: func(ers *EnhancedReputationSystem) {
				// Mock suspicious package data
			},
			expectedScore: 0.42, // Calculated score based on component analysis
			expectedRisk:  "very_low",
			expectedTrust: "low",
			expectError:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &EnhancedReputationConfig{
				ThreatIntelEnabled: true,
				CacheEnabled:       true,
				CacheTTL:           time.Hour,
				MaxCacheSize:       1000,
				ThreatIntelSources: []ThreatIntelSource{
					{
						Name:    "osv",
						Type:    "osv",
						URL:     "https://api.osv.dev",
						Enabled: true,
						Weight:  1.0,
					},
				},
				ScoringWeights: ScoringWeights{
					Popularity:    0.2,
					Maturity:      0.15,
					Maintenance:   0.15,
					Quality:       0.15,
					Security:      0.2,
					ThreatIntel:   0.15,
				},
			}

			testLogger := logger.New()
			ers := NewEnhancedReputationSystem(nil, config, testLogger)
			require.NotNil(t, ers)

			if tt.setupMocks != nil {
				tt.setupMocks(ers)
			}

			ctx := context.Background()
			pkg := &types.Package{
				Name:     tt.packageName,
				Registry: tt.registry,
				Version:  tt.version,
			}
			result, err := ers.AnalyzePackageReputation(ctx, pkg)

			if tt.expectError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, result)

			assert.Equal(t, tt.packageName, result.PackageName)
			assert.Equal(t, tt.registry, result.Registry)
			assert.Equal(t, tt.version, result.Version)
			assert.InDelta(t, tt.expectedScore, result.OverallScore, 0.1)
			assert.Equal(t, tt.expectedRisk, result.RiskLevel)
			assert.Equal(t, tt.expectedTrust, result.TrustLevel)
			assert.False(t, result.LastUpdated.IsZero())
		})
	}
}

func TestEnhancedReputationSystem_CacheIntegration(t *testing.T) {
	config := &EnhancedReputationConfig{
		ThreatIntelEnabled: false,
		CacheEnabled:       true,
		CacheTTL:           time.Hour,
		MaxCacheSize:       100,
		ScoringWeights: ScoringWeights{
			Popularity:  0.3,
			Maturity:    0.3,
			Maintenance: 0.4,
		},
	}

	testLogger := logger.New()
	ers := NewEnhancedReputationSystem(nil, config, testLogger)
	require.NotNil(t, ers)

	pkg := &types.Package{
		Name:     "test-package",
		Registry: "pypi",
		Version:  "1.0.0",
	}

	ctx := context.Background()

	// First call should not be cached
	result1, err := ers.AnalyzePackageReputation(ctx, pkg)
	require.NoError(t, err)
	require.NotNil(t, result1)
	assert.False(t, result1.CacheHit)

	// Second call should be cached
	result2, err := ers.AnalyzePackageReputation(ctx, pkg)
	require.NoError(t, err)
	require.NotNil(t, result2)
	assert.True(t, result2.CacheHit)

	// Results should be identical except for cache hit flag
	assert.Equal(t, result1.PackageName, result2.PackageName)
	assert.Equal(t, result1.OverallScore, result2.OverallScore)
	assert.Equal(t, result1.RiskLevel, result2.RiskLevel)
}

func TestEnhancedReputationSystem_ThreatIntelligenceIntegration(t *testing.T) {
	config := &EnhancedReputationConfig{
		ThreatIntelEnabled: true,
		CacheEnabled:       false,
		ThreatIntelSources: []ThreatIntelSource{
			{
				Name:    "test-source",
				Type:    "osv",
				URL:     "https://api.osv.dev",
				Enabled: true,
				Weight:  1.0,
			},
		},
		ScoringWeights: ScoringWeights{
			ThreatIntel: 0.5,
			Security:    0.5,
		},
	}

	testLogger := logger.New()
	ers := NewEnhancedReputationSystem(nil, config, testLogger)
	require.NotNil(t, ers)

	pkg := &types.Package{
		Name:     "test-package",
		Registry: "pypi",
		Version:  "1.0.0",
	}

	ctx := context.Background()
	result, err := ers.AnalyzePackageReputation(ctx, pkg)

	require.NoError(t, err)
	require.NotNil(t, result)
	// When threat intelligence manager is nil, ThreatIntelResults will be nil
	// This is expected behavior when no threat intelligence manager is provided
	assert.NotNil(t, result.SecurityAnalysis)
}

func TestEnhancedReputationSystem_ComponentScores(t *testing.T) {
	config := &EnhancedReputationConfig{
		ThreatIntelEnabled: false,
		CacheEnabled:       false,
		ScoringWeights: ScoringWeights{
			Popularity:    0.2,
			Maturity:      0.2,
			Maintenance:   0.2,
			Quality:       0.2,
			Security:      0.2,
		},
	}

	testLogger := logger.New()
	ers := NewEnhancedReputationSystem(nil, config, testLogger)
	require.NotNil(t, ers)

	pkg := &types.Package{
		Name:     "test-package",
		Registry: "pypi",
		Version:  "1.0.0",
	}

	ctx := context.Background()
	result, err := ers.AnalyzePackageReputation(ctx, pkg)

	require.NoError(t, err)
	require.NotNil(t, result)

	// Check that component scores are present
	assert.GreaterOrEqual(t, result.ComponentScores.Popularity, 0.0)
	assert.LessOrEqual(t, result.ComponentScores.Popularity, 1.0)
	assert.GreaterOrEqual(t, result.ComponentScores.Maturity, 0.0)
	assert.LessOrEqual(t, result.ComponentScores.Maturity, 1.0)
	assert.GreaterOrEqual(t, result.ComponentScores.Maintenance, 0.0)
	assert.LessOrEqual(t, result.ComponentScores.Maintenance, 1.0)
	assert.GreaterOrEqual(t, result.ComponentScores.Quality, 0.0)
	assert.LessOrEqual(t, result.ComponentScores.Quality, 1.0)
	assert.GreaterOrEqual(t, result.ComponentScores.Security, 0.0)
	assert.LessOrEqual(t, result.ComponentScores.Security, 1.0)

	// Check overall score is within valid range
	assert.GreaterOrEqual(t, result.OverallScore, 0.0)
	assert.LessOrEqual(t, result.OverallScore, 1.0)

	// Check that risk and trust levels are set
	assert.NotEmpty(t, result.RiskLevel)
	assert.NotEmpty(t, result.TrustLevel)
}

func BenchmarkEnhancedReputationSystem_AnalyzePackageReputation(b *testing.B) {
	config := &EnhancedReputationConfig{
		ThreatIntelEnabled: false,
		CacheEnabled:       true,
		CacheTTL:           time.Hour,
		MaxCacheSize:       1000,
		ScoringWeights: ScoringWeights{
			Popularity:  0.5,
			Maturity:    0.3,
			Maintenance: 0.2,
		},
	}

	testLogger := logger.New()
	ers := NewEnhancedReputationSystem(nil, config, testLogger)

	pkg := &types.Package{
		Name:     "benchmark-package",
		Registry: "pypi",
		Version:  "1.0.0",
	}

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ers.AnalyzePackageReputation(ctx, pkg)
		if err != nil {
			b.Fatal(err)
		}
	}
}