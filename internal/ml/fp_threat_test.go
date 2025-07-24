package ml

import (
	"context"
	"math"
	"testing"

	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFalsePositiveDetection tests that legitimate packages are not flagged as threats
func TestFalsePositiveDetection(t *testing.T) {
	scorer := NewBasicMLScorer()

	legitimatePackages := []struct {
		name        string
		pkg         *types.Package
		description string
	}{
		{
			name: "react",
			pkg: &types.Package{
				Name:    "react",
				Version: "18.2.0",
				Metadata: &types.PackageMetadata{
					Description: "React is a JavaScript library for building user interfaces.",
					Author:      "Facebook",
					Downloads:   100000000, // Very high download count
					Homepage:    "https://reactjs.org",
					Repository:  "https://github.com/facebook/react",
					License:     "MIT",
					Keywords:    []string{"react", "javascript", "ui", "framework"},
				},
			},
			description: "Popular React framework",
		},
		{
			name: "lodash",
			pkg: &types.Package{
				Name:    "lodash",
				Version: "4.17.21",
				Metadata: &types.PackageMetadata{
					Description: "Lodash modular utilities.",
					Author:      "John-David Dalton",
					Downloads:   50000000,
					Homepage:    "https://lodash.com",
					Repository:  "https://github.com/lodash/lodash",
					License:     "MIT",
					Keywords:    []string{"lodash", "utility", "functional"},
				},
			},
			description: "Popular utility library",
		},
		{
			name: "webpack",
			pkg: &types.Package{
				Name:    "webpack",
				Version: "5.88.0",
				Metadata: &types.PackageMetadata{
					Description: "Packs CommonJs/AMD modules for the browser.",
					Author:      "Tobias Koppers",
					Downloads:   30000000,
					Homepage:    "https://webpack.js.org",
					Repository:  "https://github.com/webpack/webpack",
					License:     "MIT",
					Keywords:    []string{"webpack", "bundler", "build"},
				},
			},
			description: "Popular module bundler",
		},
		{
			name: "express",
			pkg: &types.Package{
				Name:    "express",
				Version: "4.18.2",
				Metadata: &types.PackageMetadata{
					Description: "Fast, unopinionated, minimalist web framework for node.",
					Author:      "TJ Holowaychuk",
					Downloads:   40000000,
					Homepage:    "http://expressjs.com/",
					Repository:  "https://github.com/expressjs/express",
					License:     "MIT",
					Keywords:    []string{"express", "framework", "web", "rest", "restful", "router", "app", "api"},
				},
			},
			description: "Popular web framework",
		},
	}

	ctx := context.Background()

	for _, tc := range legitimatePackages {
		t.Run(tc.name, func(t *testing.T) {
			features := map[string]interface{}{
				"typosquatting_similarity": 0.1, // Low similarity to known typosquatting
				"name_entropy":            calculateNameEntropy(tc.pkg.Name),
				"download_count":          float64(tc.pkg.Metadata.Downloads),
				"maintainer_reputation":   0.9, // High reputation
				"package_age":             365.0, // Old package
				"description_quality":     0.8,  // Good description
				"has_homepage":            1.0,  // Has homepage
				"has_repository":          1.0,  // Has repository
				"license_present":         1.0,  // Has license
				"keyword_count":           float64(len(tc.pkg.Metadata.Keywords)),
			}

			result, err := scorer.Score(ctx, tc.pkg, features)
			require.NoError(t, err, "Scoring should not fail for legitimate package %s", tc.name)

			// Legitimate packages should have low malicious scores
			assert.LessOrEqual(t, result.Score, 0.4, 
				"Legitimate package %s (%s) should have low malicious score, got %.3f", 
				tc.name, tc.description, result.Score)

			// Risk level should be low or none
			assert.Contains(t, []string{"LOW", "NONE"}, result.RiskLevel,
				"Legitimate package %s should have low risk level, got %s", tc.name, result.RiskLevel)

			t.Logf("✓ %s: Score=%.3f, Risk=%s, Confidence=%.3f", 
				tc.name, result.Score, result.RiskLevel, result.Confidence)
		})
	}
}

// TestRealThreatDetection tests that suspicious packages are correctly flagged
func TestRealThreatDetection(t *testing.T) {
	scorer := NewBasicMLScorer()

	suspiciousPackages := []struct {
		name        string
		pkg         *types.Package
		description string
		minScore    float64
	}{
		{
			name: "expres",
			pkg: &types.Package{
				Name:    "expres",
				Version: "1.0.0",
				Metadata: &types.PackageMetadata{
					Description: "Fast web framework", // Vague description
					Author:      "unknown",
					Downloads:   100, // Very low downloads
					Homepage:    "",  // No homepage
					Repository:  "",  // No repository
					License:     "",  // No license
					Keywords:    []string{},
				},
			},
			description: "Typosquatting express",
			minScore:    0.5,
		},
		{
			name: "lodas",
			pkg: &types.Package{
				Name:    "lodas",
				Version: "1.0.0",
				Metadata: &types.PackageMetadata{
					Description: "Utility functions",
					Author:      "anonymous",
					Downloads:   50,
					Homepage:    "",
					Repository:  "",
					License:     "",
					Keywords:    []string{},
				},
			},
			description: "Typosquatting lodash",
			minScore:    0.5,
		},
		{
			name: "recat",
			pkg: &types.Package{
				Name:    "recat",
				Version: "1.0.0",
				Metadata: &types.PackageMetadata{
					Description: "UI library",
					Author:      "unknown",
					Downloads:   25,
					Homepage:    "",
					Repository:  "",
					License:     "",
					Keywords:    []string{},
				},
			},
			description: "Typosquatting react",
			minScore:    0.5,
		},
		{
			name: "free-bitcoin-generator",
			pkg: &types.Package{
				Name:    "free-bitcoin-generator",
				Version: "1.0.0",
				Metadata: &types.PackageMetadata{
					Description: "Generate free bitcoins easily!",
					Author:      "crypto-master",
					Downloads:   10,
					Homepage:    "",
					Repository:  "",
					License:     "",
					Keywords:    []string{"bitcoin", "crypto", "free", "money"},
				},
			},
			description: "Suspicious cryptocurrency package",
			minScore:    0.7,
		},
	}

	ctx := context.Background()

	for _, tc := range suspiciousPackages {
		t.Run(tc.name, func(t *testing.T) {
			features := map[string]interface{}{
				"typosquatting_similarity": calculateTyposquattingSimilarity(tc.pkg.Name),
				"name_entropy":            calculateNameEntropy(tc.pkg.Name),
				"download_count":          float64(tc.pkg.Metadata.Downloads),
				"maintainer_reputation":   0.1, // Low reputation
				"package_age":             1.0, // New package
				"description_quality":     0.3, // Poor description
				"has_homepage":            0.0, // No homepage
				"has_repository":          0.0, // No repository
				"license_present":         0.0, // No license
				"keyword_count":           float64(len(tc.pkg.Metadata.Keywords)),
			}

			result, err := scorer.Score(ctx, tc.pkg, features)
			require.NoError(t, err, "Scoring should not fail for suspicious package %s", tc.name)

			// Suspicious packages should have high malicious scores
			assert.GreaterOrEqual(t, result.Score, tc.minScore,
				"Suspicious package %s (%s) should have high malicious score, got %.3f (expected >= %.3f)",
				tc.name, tc.description, result.Score, tc.minScore)

			// Risk level should be suspicious or malicious
			assert.Contains(t, []string{"MEDIUM", "HIGH", "CRITICAL"}, result.RiskLevel,
				"Suspicious package %s should have elevated risk level, got %s", tc.name, result.RiskLevel)

			t.Logf("✓ %s: Score=%.3f, Risk=%s, Confidence=%.3f",
				tc.name, result.Score, result.RiskLevel, result.Confidence)
		})
	}
}

// TestEdgeCases tests edge cases and boundary conditions
func TestEdgeCases(t *testing.T) {
	scorer := NewBasicMLScorer()

	edgeCases := []struct {
		name        string
		pkg         *types.Package
		description string
	}{
		{
			name: "q",
			pkg: &types.Package{
				Name:    "q",
				Version: "1.5.1",
				Metadata: &types.PackageMetadata{
					Description: "A promise library for JavaScript",
					Author:      "Kris Kowal",
					Downloads:   5000000,
					Homepage:    "https://github.com/kriskowal/q",
					Repository:  "https://github.com/kriskowal/q",
					License:     "MIT",
					Keywords:    []string{"promise", "async"},
				},
			},
			description: "Single letter legitimate package",
		},
		{
			name: "very-long-package-name-that-might-be-suspicious",
			pkg: &types.Package{
				Name:    "very-long-package-name-that-might-be-suspicious",
				Version: "1.0.0",
				Metadata: &types.PackageMetadata{
					Description: "A package with a very long name",
					Author:      "test-author",
					Downloads:   100,
					Homepage:    "",
					Repository:  "",
					License:     "",
					Keywords:    []string{},
				},
			},
			description: "Very long package name",
		},
		{
			name: "123456",
			pkg: &types.Package{
				Name:    "123456",
				Version: "1.0.0",
				Metadata: &types.PackageMetadata{
					Description: "Numeric package name",
					Author:      "numeric-author",
					Downloads:   10,
					Homepage:    "",
					Repository:  "",
					License:     "",
					Keywords:    []string{},
				},
			},
			description: "Numeric package name",
		},
	}

	ctx := context.Background()

	for _, tc := range edgeCases {
		t.Run(tc.name, func(t *testing.T) {
			features := map[string]interface{}{
				"typosquatting_similarity": calculateTyposquattingSimilarity(tc.pkg.Name),
				"name_entropy":            calculateNameEntropy(tc.pkg.Name),
				"download_count":          float64(tc.pkg.Metadata.Downloads),
				"maintainer_reputation":   0.5,
				"package_age":             30.0,
				"description_quality":     0.5,
				"has_homepage":            boolToFloat(tc.pkg.Metadata.Homepage != ""),
				"has_repository":          boolToFloat(tc.pkg.Metadata.Repository != ""),
				"license_present":         boolToFloat(tc.pkg.Metadata.License != ""),
				"keyword_count":           float64(len(tc.pkg.Metadata.Keywords)),
			}

			result, err := scorer.Score(ctx, tc.pkg, features)
			require.NoError(t, err, "Scoring should not fail for edge case %s", tc.name)

			// Edge cases should not crash the system
			assert.GreaterOrEqual(t, result.Score, 0.0, "Score should be non-negative")
			assert.LessOrEqual(t, result.Score, 1.0, "Score should not exceed 1.0")
			assert.GreaterOrEqual(t, result.Confidence, 0.0, "Confidence should be non-negative")
			assert.LessOrEqual(t, result.Confidence, 1.0, "Confidence should not exceed 1.0")

			t.Logf("✓ %s: Score=%.3f, Risk=%s, Confidence=%.3f",
				tc.name, result.Score, result.RiskLevel, result.Confidence)
		})
	}
}

// TestMLAnalyzerAccuracy tests the overall accuracy of the ML analyzer
func TestMLAnalyzerAccuracy(t *testing.T) {
	cfg := config.MLAnalysisConfig{
		Enabled:             true,
		SimilarityThreshold: 0.8,
		MaliciousThreshold:  0.7,
		ReputationThreshold: 0.5,
		ModelPath:           "test-model",
		BatchSize:           10,
		MaxFeatures:         1000,
		CacheEmbeddings:     true,
		ParallelProcessing:  false,
		GPUAcceleration:     false,
	}

	analyzer := NewMLAnalyzer(cfg)
	ctx := context.Background()

	// Test dataset with known results
	testCases := []struct {
		pkg      *types.Package
		expected string // "safe" or "threat"
	}{
		// Safe packages
		{
			pkg: &types.Package{
				Name:    "react",
				Version: "18.2.0",
				Metadata: &types.PackageMetadata{
					Description: "React is a JavaScript library for building user interfaces.",
					Author:      "Facebook",
					Downloads:   100000000,
					Homepage:    "https://reactjs.org",
					Repository:  "https://github.com/facebook/react",
					License:     "MIT",
				},
			},
			expected: "safe",
		},
		{
			pkg: &types.Package{
				Name:    "lodash",
				Version: "4.17.21",
				Metadata: &types.PackageMetadata{
					Description: "Lodash modular utilities.",
					Author:      "John-David Dalton",
					Downloads:   50000000,
					Homepage:    "https://lodash.com",
					Repository:  "https://github.com/lodash/lodash",
					License:     "MIT",
				},
			},
			expected: "safe",
		},
		// Threat packages
		{
			pkg: &types.Package{
				Name:    "expres",
				Version: "1.0.0",
				Metadata: &types.PackageMetadata{
					Description: "Fast web framework",
					Author:      "unknown",
					Downloads:   100,
					Homepage:    "",
					Repository:  "",
					License:     "",
				},
			},
			expected: "threat",
		},
		{
			pkg: &types.Package{
				Name:    "lodas",
				Version: "1.0.0",
				Metadata: &types.PackageMetadata{
					Description: "Utility functions",
					Author:      "anonymous",
					Downloads:   50,
					Homepage:    "",
					Repository:  "",
					License:     "",
				},
			},
			expected: "threat",
		},
	}

	correct := 0
	total := len(testCases)

	for _, tc := range testCases {
		result, err := analyzer.Analyze(ctx, tc.pkg)
		require.NoError(t, err, "Analysis should not fail for package %s", tc.pkg.Name)

		// Determine if prediction is correct
		predicted := "safe"
		if result.TyposquattingScore >= 0.6 || result.MaliciousScore >= 0.6 {
			predicted = "threat"
		}

		if predicted == tc.expected {
			correct++
			t.Logf("✓ %s: Correctly predicted as %s (Typo: %.3f, Malicious: %.3f)",
				tc.pkg.Name, predicted, result.TyposquattingScore, result.MaliciousScore)
		} else {
			t.Logf("✗ %s: Incorrectly predicted as %s, expected %s (Typo: %.3f, Malicious: %.3f)",
				tc.pkg.Name, predicted, tc.expected, result.TyposquattingScore, result.MaliciousScore)
		}
	}

	accuracy := float64(correct) / float64(total)
	t.Logf("Overall Accuracy: %.1f%% (%d/%d)", accuracy*100, correct, total)

	// Require at least 75% accuracy
	assert.GreaterOrEqual(t, accuracy, 0.75, "ML system should achieve at least 75%% accuracy")
}

// Helper functions
func calculateNameEntropy(name string) float64 {
	if len(name) == 0 {
		return 0
	}
	
	freq := make(map[rune]int)
	for _, char := range name {
		freq[char]++
	}
	
	entropy := 0.0
	length := float64(len(name))
	
	for _, count := range freq {
		p := float64(count) / length
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}
	
	return entropy
}

func calculateTyposquattingSimilarity(name string) float64 {
	popularPackages := []string{"react", "lodash", "express", "webpack", "angular", "vue", "bootstrap", "jquery"}
	
	maxSimilarity := 0.0
	for _, popular := range popularPackages {
		similarity := calculateLevenshteinSimilarity(name, popular)
		if similarity > maxSimilarity {
			maxSimilarity = similarity
		}
	}
	
	return maxSimilarity
}

func calculateLevenshteinSimilarity(s1, s2 string) float64 {
	distance := levenshteinDistance(s1, s2)
	maxLen := len(s1)
	if len(s2) > maxLen {
		maxLen = len(s2)
	}
	
	if maxLen == 0 {
		return 1.0
	}
	
	return 1.0 - float64(distance)/float64(maxLen)
}

func min(a, b, c int) int {
	if a < b && a < c {
		return a
	}
	if b < c {
		return b
	}
	return c
}