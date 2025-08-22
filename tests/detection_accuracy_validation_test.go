package tests

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/edge"
	"github.com/Alivanroy/Typosentinel/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// DetectionResult represents the outcome of a detection test
type DetectionResult struct {
	Algorithm     string
	TestCase      string
	ThreatScore   float64
	Confidence    float64
	Detected      bool
	Expected      bool
	Correct       bool
	ProcessingTime time.Duration
}

// ValidationSuite contains all test cases for comprehensive validation
type ValidationSuite struct {
	MaliciousPackages []types.Package
	BenignPackages    []types.Package
	TestCases         []TestCase
}

type TestCase struct {
	Name        string
	Package     types.Package
	Expected    bool // true if malicious, false if benign
	Category    string
	Difficulty  string // "easy", "medium", "hard", "extreme"
}

func TestDetectionAccuracyValidation(t *testing.T) {
	ctx := context.Background()

	// Initialize algorithms
	gtr := edge.NewGTRAlgorithm(nil)
	runt := edge.NewRUNTAlgorithm(nil)
	aicc := edge.NewAICCAlgorithm(nil)
	dirt := edge.NewDIRTAlgorithm(nil)

	algorithms := map[string]func() interface{}{
		"GTR":  func() interface{} { return gtr },
		"RUNT": func() interface{} { return runt },
		"AICC": func() interface{} { return aicc },
		"DIRT": func() interface{} { return dirt },
	}

	// Create comprehensive test suite
	suite := createValidationSuite()

	// Track results for each algorithm
	results := make(map[string][]DetectionResult)

	// Run validation tests
	for algorithmName, algoFactory := range algorithms {
		t.Run(fmt.Sprintf("Algorithm_%s", algorithmName), func(t *testing.T) {
			for _, testCase := range suite.TestCases {
				t.Run(testCase.Name, func(t *testing.T) {
					algo := algoFactory()
					
					start := time.Now()
					
					var result *edge.AnalysisResult
					var err error

					switch v := algo.(type) {
					case *edge.GTRAlgorithm:
						result, err = v.Analyze(ctx, &testCase.Package)
					case *edge.RUNTAlgorithm:
						result, err = v.Analyze(ctx, &testCase.Package)
					case *edge.AICCAlgorithm:
						result, err = v.Analyze(ctx, &testCase.Package)
					case *edge.DIRTAlgorithm:
						result, err = v.Analyze(ctx, &testCase.Package)
					default:
						t.Fatalf("Unknown algorithm type: %T", v)
					}
					
					processingTime := time.Since(start)

					require.NoError(t, err, "Analysis should not fail")
					require.NotNil(t, result, "Result should not be nil")

					// Determine if threat was detected (threshold: 0.5)
					detected := result.ThreatScore >= 0.5
					correct := detected == testCase.Expected

					detectionResult := DetectionResult{
						Algorithm:      algorithmName,
						TestCase:       testCase.Name,
						ThreatScore:    result.ThreatScore,
						Confidence:     result.Confidence,
						Detected:       detected,
						Expected:       testCase.Expected,
						Correct:        correct,
						ProcessingTime: processingTime,
					}

					results[algorithmName] = append(results[algorithmName], detectionResult)

					// Log detailed results
					t.Logf("[%s] %s: Score=%.3f, Confidence=%.3f, Detected=%v, Expected=%v, Correct=%v, Time=%v",
						algorithmName, testCase.Name, result.ThreatScore, result.Confidence,
						detected, testCase.Expected, correct, processingTime)

					// For critical test cases, ensure detection
					if testCase.Category == "critical" && testCase.Expected {
						assert.True(t, detected, "Critical malicious package should be detected")
					}
				})
			}
		})
	}

	// Generate comprehensive accuracy report
	t.Run("AccuracyReport", func(t *testing.T) {
		generateAccuracyReport(t, results, suite)
	})
}

func createValidationSuite() ValidationSuite {
	return ValidationSuite{
		MaliciousPackages: []types.Package{
			// Unicode homograph attacks
			{
				Metadata: types.PackageMetadata{
					Name:     "rеact", // Cyrillic 'е'
					Version:  "18.2.0",
					Registry: "npm",
				},
				Description: "A JavaScript library for building user interfaces",
				Author:      "Facebook",
				License:     "MIT",
				Downloads:   50000000,
				CreatedAt:   time.Now().AddDate(-2, 0, 0),
				UpdatedAt:   time.Now().AddDate(0, -1, 0),
			},
			// Typosquatting
			{
				Metadata: types.PackageMetadata{
					Name:     "reqeusts",
					Version:  "2.28.1",
					Registry: "pypi",
				},
				Description: "Python HTTP for Humans",
				Author:      "Kenneth Reitz",
				License:     "Apache 2.0",
				Downloads:   100000000,
				CreatedAt:   time.Now().AddDate(-5, 0, 0),
				UpdatedAt:   time.Now().AddDate(0, -2, 0),
			},
			// Subdomain confusion
			{
				Metadata: types.PackageMetadata{
					Name:     "lodаsh", // Cyrillic 'а'
					Version:  "4.17.21",
					Registry: "npm",
				},
				Description: "A modern JavaScript utility library",
				Author:      "John-David Dalton",
				License:     "MIT",
				Downloads:   80000000,
				CreatedAt:   time.Now().AddDate(-8, 0, 0),
				UpdatedAt:   time.Now().AddDate(0, -3, 0),
			},
		},
		BenignPackages: []types.Package{
			{
				Metadata: types.PackageMetadata{
					Name:     "react",
					Version:  "18.2.0",
					Registry: "npm",
				},
				Description: "A JavaScript library for building user interfaces",
				Author:      "Facebook",
				License:     "MIT",
				Downloads:   50000000,
				CreatedAt:   time.Now().AddDate(-2, 0, 0),
				UpdatedAt:   time.Now().AddDate(0, -1, 0),
			},
			{
				Metadata: types.PackageMetadata{
					Name:     "requests",
					Version:  "2.28.1",
					Registry: "pypi",
				},
				Description: "Python HTTP for Humans",
				Author:      "Kenneth Reitz",
				License:     "Apache 2.0",
				Downloads:   100000000,
				CreatedAt:   time.Now().AddDate(-5, 0, 0),
				UpdatedAt:   time.Now().AddDate(0, -2, 0),
			},
			{
				Metadata: types.PackageMetadata{
					Name:     "lodash",
					Version:  "4.17.21",
					Registry: "npm",
				},
				Description: "A modern JavaScript utility library",
				Author:      "John-David Dalton",
				License:     "MIT",
				Downloads:   80000000,
				CreatedAt:   time.Now().AddDate(-8, 0, 0),
				UpdatedAt:   time.Now().AddDate(0, -3, 0),
			},
		},
		TestCases: []TestCase{
			// Critical malicious packages (must be detected)
			{
				Name:     "Critical_Typosquatting_requests",
				Package:  createMaliciousPackage("reqeusts", "2.28.1", "pypi"),
				Expected: true,
				Category: "critical",
				Difficulty: "easy",
			},
			{
				Name:     "Critical_Typosquatting_numpy",
				Package:  createMaliciousPackage("nunpy", "1.21.0", "pypi"),
				Expected: true,
				Category: "critical",
				Difficulty: "easy",
			},
			{
				Name:     "Critical_Homograph_react",
				Package:  createMaliciousPackage("rеact", "18.2.0", "npm"), // Cyrillic 'е'
				Expected: true,
				Category: "critical",
				Difficulty: "medium",
			},

			// Advanced evasion techniques
			{
				Name:     "Advanced_Unicode_Steganography",
				Package:  createUnicodeStegPackage(),
				Expected: true,
				Category: "advanced",
				Difficulty: "extreme",
			},
			{
				Name:     "Advanced_Encoding_Layers",
				Package:  createEncodedPackage(),
				Expected: true,
				Category: "advanced",
				Difficulty: "hard",
			},
			{
				Name:     "Advanced_Polyglot_Attack",
				Package:  createPolyglotPackage(),
				Expected: true,
				Category: "advanced",
				Difficulty: "extreme",
			},

			// Legitimate packages (should not be flagged)
			{
				Name:     "Legitimate_requests",
				Package:  createLegitimatePackage("requests", "2.28.1", "pypi"),
				Expected: false,
				Category: "legitimate",
				Difficulty: "easy",
			},
			{
				Name:     "Legitimate_react",
				Package:  createLegitimatePackage("react", "18.2.0", "npm"),
				Expected: false,
				Category: "legitimate",
				Difficulty: "easy",
			},
			{
				Name:     "Legitimate_numpy",
				Package:  createLegitimatePackage("numpy", "1.21.0", "pypi"),
				Expected: false,
				Category: "legitimate",
				Difficulty: "easy",
			},

			// Edge cases
			{
				Name:     "Edge_Empty_Package",
				Package:  createEmptyPackage(),
				Expected: false,
				Category: "edge",
				Difficulty: "medium",
			},
			{
				Name:     "Edge_Very_Long_Name",
				Package:  createLongNamePackage(),
				Expected: true,
				Category: "edge",
				Difficulty: "medium",
			},
		},
	}
}

func createMaliciousPackage(name, version, registry string) types.Package {
	return types.Package{
		Metadata: &types.PackageMetadata{
			Name:        name,
			Version:     version,
			Registry:    registry,
			Description: "A malicious package designed to mimic legitimate software",
			Author:      "suspicious-author",
			License:     "MIT",
			Downloads:   1000,
			CreatedAt:   time.Now().AddDate(0, 0, -1),
			UpdatedAt:   time.Now(),
		},
	}
}

func createLegitimatePackage(name, version, registry string) types.Package {
	return types.Package{
		Metadata: &types.PackageMetadata{
			Name:        name,
			Version:     version,
			Registry:    registry,
			Description: "A legitimate, well-maintained package",
			Author:      "trusted-maintainer",
			License:     "MIT",
			Downloads:   1000000,
			CreatedAt:   time.Now().AddDate(-2, 0, 0),
			UpdatedAt:   time.Now().AddDate(0, -1, 0),
		},
	}
}

func createUnicodeStegPackage() types.Package {
	return types.Package{
		Metadata: &types.PackageMetadata{
			Name:        "req\u200buests", // Zero-width space
			Version:     "2.28.1",
			Registry:    "pypi",
			Description: "A package with hidden Unicode characters",
			Author:      "steganographer",
			License:     "MIT",
			Downloads:   500,
			CreatedAt:   time.Now().AddDate(0, 0, -1),
			UpdatedAt:   time.Now(),
		},
	}
}

func createEncodedPackage() types.Package {
	return types.Package{
		Metadata: &types.PackageMetadata{
			Name:        "cmVxdWVzdHM=", // Base64 encoded "requests"
			Version:     "2.28.1",
			Registry:    "pypi",
			Description: "A package with encoded name",
			Author:      "encoder",
			License:     "MIT",
			Downloads:   200,
			CreatedAt:   time.Now().AddDate(0, 0, -1),
			UpdatedAt:   time.Now(),
		},
	}
}

func createPolyglotPackage() types.Package {
	return types.Package{
		Metadata: &types.PackageMetadata{
			Name:        "legitimate-utils",
			Version:     "1.0.0",
			Registry:    "npm",
			Description: "Utilities for legitimate purposes",
			Author:      "polyglot-attacker",
			License:     "MIT",
			Downloads:   10000,
			CreatedAt:   time.Now().AddDate(0, -6, 0),
			UpdatedAt:   time.Now().AddDate(0, -1, 0),
		},
		Dependencies: []types.Dependency{
			{
				Name:     "rеact-dom", // Hidden Cyrillic character
				Version:  "18.2.0",
				Registry: "npm",
				Source:   "npm",
				Direct:   true,
			},
		},
	}
}

func createEmptyPackage() types.Package {
	return types.Package{
		Metadata: &types.PackageMetadata{
			Name:     "",
			Version:  "",
			Registry: "",
		},
	}
}

func createLongNamePackage() types.Package {
	longName := "this-is-a-very-long-package-name-that-might-be-used-to-confuse-users-and-hide-malicious-intent-by-making-it-difficult-to-read-and-verify-the-actual-package-name-which-could-be-a-typosquatting-attempt"
	return types.Package{
		Metadata: &types.PackageMetadata{
			Name:        longName,
			Version:     "1.0.0",
			Registry:    "npm",
			Description: "A package with an unusually long name",
			Author:      "long-name-attacker",
			License:     "MIT",
			Downloads:   50,
			CreatedAt:   time.Now().AddDate(0, 0, -1),
			UpdatedAt:   time.Now(),
		},
	}
}

func generateAccuracyReport(t *testing.T, results map[string][]DetectionResult, suite ValidationSuite) {
	t.Log("\n=== DETECTION ACCURACY VALIDATION REPORT ===")

	for algorithmName, algorithmResults := range results {
		t.Logf("\n--- %s Algorithm ---", algorithmName)

		// Calculate overall metrics
		totalTests := len(algorithmResults)
		correctDetections := 0
		truePositives := 0
		falsePositives := 0
		trueNegatives := 0
		falseNegatives := 0

		// Category-specific metrics
		categoryStats := make(map[string]map[string]int)
		difficultyStats := make(map[string]map[string]int)

		var totalProcessingTime time.Duration

		for _, result := range algorithmResults {
			totalProcessingTime += result.ProcessingTime

			if result.Correct {
				correctDetections++
			}

			if result.Expected && result.Detected {
				truePositives++
			} else if !result.Expected && result.Detected {
				falsePositives++
			} else if !result.Expected && !result.Detected {
				trueNegatives++
			} else if result.Expected && !result.Detected {
				falseNegatives++
			}

			// Find corresponding test case for category/difficulty
			for _, testCase := range suite.TestCases {
				if testCase.Name == result.TestCase {
					// Update category stats
					if categoryStats[testCase.Category] == nil {
						categoryStats[testCase.Category] = make(map[string]int)
					}
					categoryStats[testCase.Category]["total"]++
					if result.Correct {
						categoryStats[testCase.Category]["correct"]++
					}

					// Update difficulty stats
					if difficultyStats[testCase.Difficulty] == nil {
						difficultyStats[testCase.Difficulty] = make(map[string]int)
					}
					difficultyStats[testCase.Difficulty]["total"]++
					if result.Correct {
						difficultyStats[testCase.Difficulty]["correct"]++
					}
					break
				}
			}
		}

		// Calculate metrics
		accuracy := float64(correctDetections) / float64(totalTests) * 100
		precision := float64(truePositives) / float64(truePositives+falsePositives) * 100
		recall := float64(truePositives) / float64(truePositives+falseNegatives) * 100
		f1Score := 2 * (precision * recall) / (precision + recall)
		avgProcessingTime := totalProcessingTime / time.Duration(totalTests)

		// Log overall metrics
		t.Logf("Overall Accuracy: %.2f%% (%d/%d)", accuracy, correctDetections, totalTests)
		t.Logf("Precision: %.2f%%", precision)
		t.Logf("Recall: %.2f%%", recall)
		t.Logf("F1-Score: %.2f", f1Score)
		t.Logf("Average Processing Time: %v", avgProcessingTime)
		t.Logf("True Positives: %d, False Positives: %d", truePositives, falsePositives)
		t.Logf("True Negatives: %d, False Negatives: %d", trueNegatives, falseNegatives)

		// Log category performance
		t.Logf("\nCategory Performance:")
		for category, stats := range categoryStats {
			categoryAccuracy := float64(stats["correct"]) / float64(stats["total"]) * 100
			t.Logf("  %s: %.2f%% (%d/%d)", category, categoryAccuracy, stats["correct"], stats["total"])
		}

		// Log difficulty performance
		t.Logf("\nDifficulty Performance:")
		for difficulty, stats := range difficultyStats {
			difficultyAccuracy := float64(stats["correct"]) / float64(stats["total"]) * 100
			t.Logf("  %s: %.2f%% (%d/%d)", difficulty, difficultyAccuracy, stats["correct"], stats["total"])
		}

		// Performance thresholds
		t.Logf("\nPerformance Assessment:")
		if accuracy >= 90 {
			t.Logf("  ✅ EXCELLENT: Accuracy >= 90%%")
		} else if accuracy >= 80 {
			t.Logf("  ✅ GOOD: Accuracy >= 80%%")
		} else if accuracy >= 70 {
			t.Logf("  ⚠️  ACCEPTABLE: Accuracy >= 70%%")
		} else {
			t.Logf("  ❌ POOR: Accuracy < 70%%")
		}

		if recall >= 90 {
			t.Logf("  ✅ EXCELLENT: Recall >= 90%%")
		} else if recall >= 80 {
			t.Logf("  ✅ GOOD: Recall >= 80%%")
		} else if recall >= 70 {
			t.Logf("  ⚠️  ACCEPTABLE: Recall >= 70%%")
		} else {
			t.Logf("  ❌ POOR: Recall < 70%% (Missing critical threats)")
		}

		if precision >= 90 {
			t.Logf("  ✅ EXCELLENT: Precision >= 90%%")
		} else if precision >= 80 {
			t.Logf("  ✅ GOOD: Precision >= 80%%")
		} else if precision >= 70 {
			t.Logf("  ⚠️  ACCEPTABLE: Precision >= 70%%")
		} else {
			t.Logf("  ❌ POOR: Precision < 70%% (Too many false positives)")
		}
	}

	t.Log("\n=== END VALIDATION REPORT ===")
}