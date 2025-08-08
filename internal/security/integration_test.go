package security

import (
	"context"
	"testing"
	"time"

	"github.com/Alivanroy/Typosentinel/pkg/logger"
	"github.com/Alivanroy/Typosentinel/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSecurityIntegration tests the complete security system integration
func TestSecurityIntegration(t *testing.T) {
	// Create test logger
	testLogger := logger.NewTestLogger()

	// Create security coordinator with test configuration
	config := &SecurityCoordinatorConfig{
		EnableTemporalDetection:     true,
		EnableComplexityAnalysis:    true,
		EnableTrustValidation:       true,
		EnableMLHardening:           false, // Disabled for testing
		EnableMultiVectorDetection:  false, // Disabled for testing
		EnableBehavioralAnalysis:    false, // Disabled for testing
		EnableThreatIntelligence:    false, // Disabled for testing
		EnableResponseOrchestration: false, // Disabled for testing
		EnableSecurityMetrics:       true,
		EnableAlertManagement:       true,
		MaxConcurrentScans:          5,
		ScanTimeout:                 10 * time.Second,
		ThreatScoreThreshold:        0.7,
		CriticalThreatThreshold:     0.9,
		AutoResponseEnabled:         false,
		Enabled:                     true,
	}

	coordinator := NewSecurityCoordinator(config, *testLogger)
	require.NotNil(t, coordinator)

	// Create test package
	testPackage := &types.Package{
		Name:     "test-suspicious-package",
		Version:  "1.0.0",
		Registry: "npm",
		Metadata: &types.PackageMetadata{
			Name:        "test-suspicious-package",
			Version:     "1.0.0",
			Description: "A test package with suspicious patterns",
			Author:      "test-author",
			Homepage:    "https://example.com",
			Repository:  "https://github.com/test/repo",
			License:     "MIT",
			Keywords:    []string{"test", "suspicious"},
			Metadata: map[string]interface{}{
				"test_mode": true,
				"suspicious_patterns": []string{
					"setTimeout(maliciousCode, 86400000)", // 24 hour delay
					"new Date().getMonth() === 11",        // December trigger
					"process.env.NODE_ENV === 'production'", // Production trigger
				},
			},
		},
	}

	// Perform comprehensive security analysis
	ctx := context.Background()
	result, err := coordinator.PerformComprehensiveSecurityAnalysis(ctx, testPackage)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Validate basic result structure
	assert.Equal(t, testPackage.Name, result.PackageName)
	assert.NotZero(t, result.AnalysisTimestamp)
	assert.NotZero(t, result.AnalysisDuration)
	assert.NotEmpty(t, result.ThreatLevel)

	// Validate threat score calculation
	assert.GreaterOrEqual(t, result.OverallThreatScore, 0.0)
	assert.LessOrEqual(t, result.OverallThreatScore, 1.0)

	// Validate temporal analysis (if enabled and detected)
	if config.EnableTemporalDetection && result.TemporalAnalysis != nil {
		assert.Equal(t, testPackage.Name, result.TemporalAnalysis.PackageName)
		assert.NotEmpty(t, result.TemporalAnalysis.ThreatID)
	}

	// Validate complexity analysis (if enabled and detected)
	if config.EnableComplexityAnalysis && result.ComplexityAnalysis != nil {
		assert.Equal(t, testPackage.Name, result.ComplexityAnalysis.PackageName)
		assert.NotEmpty(t, result.ComplexityAnalysis.ThreatID)
	}

	// Validate trust validation (if enabled and detected)
	if config.EnableTrustValidation && result.TrustValidation != nil {
		assert.GreaterOrEqual(t, result.TrustValidation.OverallTrustScore, 0.0)
		assert.LessOrEqual(t, result.TrustValidation.OverallTrustScore, 1.0)
	}

	// Validate detected threats (if any)
	if result.DetectedThreats != nil {
		for _, threat := range result.DetectedThreats {
			assert.NotEmpty(t, threat.ThreatID)
			assert.NotEmpty(t, threat.ThreatType)
			assert.NotEmpty(t, threat.ThreatCategory)
			assert.NotEmpty(t, threat.Severity)
			assert.GreaterOrEqual(t, threat.Confidence, 0.0)
			assert.LessOrEqual(t, threat.Confidence, 1.0)
			assert.NotZero(t, threat.DetectionTimestamp)
		}
	}

	// Validate security recommendations (if any)
	if result.SecurityRecommendations != nil {
		for _, recommendation := range result.SecurityRecommendations {
			assert.NotEmpty(t, recommendation.RecommendationID)
			assert.NotEmpty(t, recommendation.RecommendationType)
			assert.NotEmpty(t, recommendation.Title)
			assert.NotEmpty(t, recommendation.Description)
		}
	}

	// Validate alerts (if any)
	if result.AlertsGenerated != nil {
		for _, alert := range result.AlertsGenerated {
			assert.NotEmpty(t, alert.AlertID)
			assert.NotEmpty(t, alert.AlertType)
			assert.NotEmpty(t, alert.Severity)
			assert.NotEmpty(t, alert.Title)
			assert.NotZero(t, alert.Timestamp)
		}
	}

	// Test threat level determination
	testThreatLevels := []struct {
		score    float64
		expected string
	}{
		{0.95, "CRITICAL"},
		{0.85, "HIGH"},
		{0.65, "MEDIUM"},
		{0.45, "LOW"},
		{0.25, "MINIMAL"},
	}

	for _, test := range testThreatLevels {
		level := coordinator.determineThreatLevel(test.score)
		assert.Equal(t, test.expected, level, "Score %.2f should result in %s threat level", test.score, test.expected)
	}
}

// TestTemporalDetectorIntegration tests temporal detector integration
func TestTemporalDetectorIntegration(t *testing.T) {
	testLogger := logger.NewTestLogger()
	
	config := DefaultTemporalDetectorConfig()
	config.MaxAnalysisWindow = 1 * time.Hour // Shorter for testing
	
	detector := NewTemporalDetector(config, *testLogger)
	require.NotNil(t, detector)

	testPackage := &types.Package{
		Name:    "temporal-test-package",
		Version: "1.0.0",
		Registry: "npm",
		Metadata: &types.PackageMetadata{
			Name:    "temporal-test-package",
			Version: "1.0.0",
			Metadata: map[string]interface{}{
				"code_content": "setTimeout(maliciousPayload, 31536000000)", // 1 year delay
			},
		},
	}

	ctx := context.Background()
	result, err := detector.AnalyzeTemporalThreats(ctx, testPackage)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, testPackage.Name, result.PackageName)
	assert.NotEmpty(t, result.ThreatID)
	assert.GreaterOrEqual(t, result.ConfidenceScore, 0.0)
	assert.LessOrEqual(t, result.ConfidenceScore, 1.0)
}

// TestComplexityAnalyzerIntegration tests complexity analyzer integration
func TestComplexityAnalyzerIntegration(t *testing.T) {
	testLogger := logger.NewTestLogger()
	
	config := DefaultComplexityAnalyzerConfig()
	config.MaxAnalysisTime = 5 * time.Second // Shorter for testing
	
	analyzer := NewComplexityAnalyzer(config, *testLogger)
	require.NotNil(t, analyzer)

	testPackage := &types.Package{
		Name:     "complexity-test-package",
		Version:  "1.0.0",
		Registry: "npm",
		Metadata: &types.PackageMetadata{
			Name:         "complexity-test-package",
			Version:      "1.0.0",
			Dependencies: []string{"dep1", "dep2", "dep3"},
		},
	}

	ctx := context.Background()
	result, err := analyzer.AnalyzeComplexity(ctx, testPackage)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, testPackage.Name, result.PackageName)
	assert.NotEmpty(t, result.ThreatID)
	assert.GreaterOrEqual(t, result.ComplexityScore, 0.0)
	assert.LessOrEqual(t, result.ComplexityScore, 1.0)
}

// TestTrustValidatorIntegration tests trust validator integration
func TestTrustValidatorIntegration(t *testing.T) {
	testLogger := logger.NewTestLogger()
	
	config := DefaultTrustValidatorConfig()
	
	validator := NewTrustValidator(config, *testLogger)
	require.NotNil(t, validator)

	testPackage := &types.Package{
		Name:     "trust-test-package",
		Version:  "1.0.0",
		Registry: "npm",
		Metadata: &types.PackageMetadata{
			Name:       "trust-test-package",
			Version:    "1.0.0",
			Author:     "test-author",
			Homepage:   "https://example.com",
			Repository: "https://github.com/test/repo",
		},
	}

	ctx := context.Background()
	result, err := validator.ValidateTrust(ctx, testPackage)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.GreaterOrEqual(t, result.OverallTrustScore, 0.0)
	assert.LessOrEqual(t, result.OverallTrustScore, 1.0)
	assert.NotNil(t, result.ValidationResults)
	assert.NotNil(t, result.TrustFactors)
	assert.NotEmpty(t, result.TrustLevel)
}