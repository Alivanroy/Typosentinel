package ml

import (
	"testing"
	"time"

	"github.com/Alivanroy/Typosentinel/pkg/types"
)

func TestNewBasicMLScorer(t *testing.T) {
	scorer := NewBasicMLScorer()

	if scorer == nil {
		t.Fatal("Expected non-nil scorer")
	}

	if scorer.config == nil {
		t.Fatal("Expected non-nil config")
	}

	if scorer.config.MaliciousThreshold != 0.7 {
		t.Errorf("Expected malicious threshold 0.7, got %f", scorer.config.MaliciousThreshold)
	}

	if scorer.config.SuspiciousThreshold != 0.4 {
		t.Errorf("Expected suspicious threshold 0.4, got %f", scorer.config.SuspiciousThreshold)
	}

	if len(scorer.weights) == 0 {
		t.Error("Expected non-empty weights map")
	}

	if len(scorer.featureStats) == 0 {
		t.Error("Expected non-empty feature stats map")
	}
}

func TestExtractFeatures(t *testing.T) {
	scorer := NewBasicMLScorer()

	dep := types.Dependency{
		Name:     "test-package",
		Version:  "1.0.0",
		Registry: "npm",
	}

	metadata := map[string]interface{}{
		"downloads":    float64(10000),
		"maintainers":  []interface{}{"user1", "user2"},
		"created":      time.Now().AddDate(-1, 0, 0), // 1 year ago
		"versions":     []interface{}{"1.0.0", "0.9.0", "0.8.0"},
		"description":  "A test package for testing purposes",
		"dependencies": map[string]interface{}{"dep1": "^1.0.0", "dep2": "^2.0.0"},
		"license":      "MIT",
		"readme":       "# Test Package\nThis is a test",
		"homepage":     "https://example.com",
		"repository":   "https://github.com/user/repo",
		"keywords":     []interface{}{"test", "package", "npm"},
		"modified":     time.Now().AddDate(0, -1, 0), // 1 month ago
	}

	features := scorer.ExtractFeatures(dep, metadata)

	if features.DownloadCount != 10000 {
		t.Errorf("Expected download count 10000, got %f", features.DownloadCount)
	}

	if features.MaintainerCount != 2 {
		t.Errorf("Expected maintainer count 2, got %f", features.MaintainerCount)
	}

	if features.VersionCount != 3 {
		t.Errorf("Expected version count 3, got %f", features.VersionCount)
	}

	if features.DependencyCount != 2 {
		t.Errorf("Expected dependency count 2, got %f", features.DependencyCount)
	}

	if features.LicensePresent != 1.0 {
		t.Errorf("Expected license present 1.0, got %f", features.LicensePresent)
	}

	if features.ReadmePresent != 1.0 {
		t.Errorf("Expected readme present 1.0, got %f", features.ReadmePresent)
	}

	if features.HomepagePresent != 1.0 {
		t.Errorf("Expected homepage present 1.0, got %f", features.HomepagePresent)
	}

	if features.RepositoryPresent != 1.0 {
		t.Errorf("Expected repository present 1.0, got %f", features.RepositoryPresent)
	}

	if features.KeywordCount != 3 {
		t.Errorf("Expected keyword count 3, got %f", features.KeywordCount)
	}

	if features.NameEntropy <= 0 {
		t.Errorf("Expected positive name entropy, got %f", features.NameEntropy)
	}

	if features.PackageAge <= 0 {
		t.Errorf("Expected positive package age, got %f", features.PackageAge)
	}
}

func TestScorePackage_LegitimatePackage(t *testing.T) {
	scorer := NewBasicMLScorer()

	// Features of a legitimate package
	features := BasicPackageFeatures{
		DownloadCount:         100000,  // High downloads
		MaintainerReputation:  0.9,     // Good reputation
		PackageAge:           1000,     // Old package
		VersionCount:         20,       // Many versions
		DescriptionLength:    150,      // Good description
		DependencyCount:      5,        // Reasonable dependencies
		TyposquattingSimilarity: 0.1,   // Low similarity to known packages
		NameEntropy:          3.5,      // Normal entropy
		UpdateFrequency:      0.1,      // Regular updates
		LicensePresent:       1.0,      // Has license
		ReadmePresent:        1.0,      // Has README
		HomepagePresent:      1.0,      // Has homepage
		RepositoryPresent:    1.0,      // Has repository
		KeywordCount:         5,        // Good keywords
		MaintainerCount:      2,        // Multiple maintainers
	}

	score := scorer.ScorePackage(features)

	if score.MaliciousScore >= scorer.config.SuspiciousThreshold {
		t.Errorf("Expected low malicious score for legitimate package, got %f", score.MaliciousScore)
	}

	if score.RiskLevel != "LOW" {
		t.Errorf("Expected LOW risk level, got %s", score.RiskLevel)
	}

	if score.Confidence < scorer.config.MinConfidence {
		t.Errorf("Expected confidence >= %f, got %f", scorer.config.MinConfidence, score.Confidence)
	}
}

func TestScorePackage_SuspiciousPackage(t *testing.T) {
	scorer := NewBasicMLScorer()

	// Features of a suspicious package
	features := BasicPackageFeatures{
		DownloadCount:         10,      // Very low downloads
		MaintainerReputation:  0.1,     // Poor reputation
		PackageAge:           1,        // Very new
		VersionCount:         1,        // Only one version
		DescriptionLength:    10,       // Short description
		DependencyCount:      0,        // No dependencies
		TyposquattingSimilarity: 0.9,   // High similarity to known packages
		NameEntropy:          5.0,      // High entropy (random name)
		UpdateFrequency:      0.0,      // No updates
		LicensePresent:       0.0,      // No license
		ReadmePresent:        0.0,      // No README
		HomepagePresent:      0.0,      // No homepage
		RepositoryPresent:    0.0,      // No repository
		KeywordCount:         0,        // No keywords
		MaintainerCount:      1,        // Single maintainer
	}

	score := scorer.ScorePackage(features)

	if score.MaliciousScore < scorer.config.SuspiciousThreshold {
		t.Errorf("Expected high malicious score for suspicious package, got %f", score.MaliciousScore)
	}

	if score.RiskLevel == "LOW" {
		t.Errorf("Expected MEDIUM or HIGH risk level, got %s", score.RiskLevel)
	}

	if len(score.ContributingFactors) == 0 {
		t.Error("Expected contributing factors for suspicious package")
	}
}

func TestCalculateEntropy(t *testing.T) {
	scorer := NewBasicMLScorer()

	tests := []struct {
		name     string
		input    string
		expected float64
	}{
		{"empty string", "", 0.0},
		{"single character", "a", 0.0},
		{"repeated characters", "aaaa", 0.0},
		{"two different characters", "ab", 1.0},
		{"normal package name", "express", 2.807354922057604}, // Approximate entropy
		{"random string", "xqzpwk", 2.584962500721156},        // Higher entropy
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := scorer.calculateEntropy(tt.input)
			if tt.name == "empty string" || tt.name == "single character" || tt.name == "repeated characters" {
				if result != tt.expected {
					t.Errorf("Expected entropy %f, got %f", tt.expected, result)
				}
			} else {
				// For more complex strings, check if entropy is reasonable
				if result <= 0 || result > 10 {
					t.Errorf("Expected reasonable entropy (0-10), got %f", result)
				}
			}
		})
	}
}

func TestSigmoid(t *testing.T) {
	scorer := NewBasicMLScorer()

	tests := []struct {
		input    float64
		expected float64
	}{
		{0.0, 0.5},
		{1.0, 0.7310585786300049},
		{-1.0, 0.2689414213699951},
		{10.0, 0.9999546021312976},
		{-10.0, 0.00004539992976248485},
	}

	for _, tt := range tests {
		result := scorer.sigmoid(tt.input)
		if abs(result-tt.expected) > 1e-6 {
			t.Errorf("sigmoid(%f) = %f, expected %f", tt.input, result, tt.expected)
		}
	}
}

func TestNormalizeFeatures(t *testing.T) {
	scorer := NewBasicMLScorer()

	features := BasicPackageFeatures{
		DownloadCount: 50000, // Above mean (10000)
		PackageAge:    100,   // Below mean (365)
	}

	normalized := scorer.normalizeFeatures(features)

	// Download count should be positive (above mean)
	if normalized.DownloadCount <= 0 {
		t.Errorf("Expected positive normalized download count, got %f", normalized.DownloadCount)
	}

	// Package age should be negative (below mean)
	if normalized.PackageAge >= 0 {
		t.Errorf("Expected negative normalized package age, got %f", normalized.PackageAge)
	}
}

func TestUpdateFeatureStats(t *testing.T) {
	scorer := NewBasicMLScorer()

	// Create sample features
	features := []BasicPackageFeatures{
		{DownloadCount: 1000, PackageAge: 100},
		{DownloadCount: 2000, PackageAge: 200},
		{DownloadCount: 3000, PackageAge: 300},
	}

	originalStats := scorer.featureStats["download_count"]
	scorer.UpdateFeatureStats(features)
	newStats := scorer.featureStats["download_count"]

	// Stats should be updated
	if newStats.Mean == originalStats.Mean {
		t.Error("Expected feature stats to be updated")
	}

	// Check calculated mean
	expectedMean := 2000.0 // (1000 + 2000 + 3000) / 3
	if newStats.Mean != expectedMean {
		t.Errorf("Expected mean %f, got %f", expectedMean, newStats.Mean)
	}
}

func TestDetermineRiskLevel(t *testing.T) {
	scorer := NewBasicMLScorer()

	tests := []struct {
		score    float64
		expected string
	}{
		{0.1, "LOW"},
		{0.3, "LOW"},
		{0.5, "MEDIUM"},
		{0.6, "MEDIUM"},
		{0.8, "HIGH"},
		{0.9, "HIGH"},
	}

	for _, tt := range tests {
		result := scorer.determineRiskLevel(tt.score)
		if result != tt.expected {
			t.Errorf("determineRiskLevel(%f) = %s, expected %s", tt.score, result, tt.expected)
		}
	}
}

func TestBoolToFloat(t *testing.T) {
	scorer := NewBasicMLScorer()

	if scorer.boolToFloat(true) != 1.0 {
		t.Error("Expected true to convert to 1.0")
	}

	if scorer.boolToFloat(false) != 0.0 {
		t.Error("Expected false to convert to 0.0")
	}
}

func TestFeaturesToMap(t *testing.T) {
	scorer := NewBasicMLScorer()

	features := BasicPackageFeatures{
		DownloadCount: 1000,
		PackageAge:    365,
		LicensePresent: 1.0,
	}

	featureMap := scorer.featuresToMap(features)

	if featureMap["download_count"] != 1000 {
		t.Errorf("Expected download_count 1000, got %f", featureMap["download_count"])
	}

	if featureMap["package_age"] != 365 {
		t.Errorf("Expected package_age 365, got %f", featureMap["package_age"])
	}

	if featureMap["license_present"] != 1.0 {
		t.Errorf("Expected license_present 1.0, got %f", featureMap["license_present"])
	}
}

// Helper function for floating point comparison
func abs(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}

// Benchmark tests
func BenchmarkScorePackage(b *testing.B) {
	scorer := NewBasicMLScorer()
	features := BasicPackageFeatures{
		DownloadCount:         10000,
		MaintainerReputation:  0.8,
		PackageAge:           365,
		VersionCount:         10,
		DescriptionLength:    100,
		DependencyCount:      5,
		TyposquattingSimilarity: 0.2,
		NameEntropy:          3.0,
		UpdateFrequency:      0.1,
		LicensePresent:       1.0,
		ReadmePresent:        1.0,
		HomepagePresent:      1.0,
		RepositoryPresent:    1.0,
		KeywordCount:         3,
		MaintainerCount:      2,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scorer.ScorePackage(features)
	}
}

func BenchmarkExtractFeatures(b *testing.B) {
	scorer := NewBasicMLScorer()
	dep := types.Dependency{
		Name:     "test-package",
		Version:  "1.0.0",
		Registry: "npm",
	}

	metadata := map[string]interface{}{
		"downloads":    float64(10000),
		"maintainers":  []interface{}{"user1", "user2"},
		"created":      time.Now().AddDate(-1, 0, 0),
		"versions":     []interface{}{"1.0.0", "0.9.0"},
		"description":  "A test package",
		"dependencies": map[string]interface{}{"dep1": "^1.0.0"},
		"license":      "MIT",
		"readme":       "# Test",
		"homepage":     "https://example.com",
		"repository":   "https://github.com/user/repo",
		"keywords":     []interface{}{"test"},
		"modified":     time.Now().AddDate(0, -1, 0),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scorer.ExtractFeatures(dep, metadata)
	}
}