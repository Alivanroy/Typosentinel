package tests

import (
	"path/filepath"
	"testing"
	"time"

	"typosentinel/internal/config"
	"typosentinel/internal/ml"
)

// TestMLAnalysisValidation runs comprehensive validation tests against all datasets
func TestMLAnalysisValidation(t *testing.T) {
	// Initialize ML analyzer with default configuration
	analyzer := ml.NewMLAnalyzer(config.MLAnalysisConfig{
		Enabled:              true,
		SimilarityThreshold:  0.8,
		MaliciousThreshold:   0.7,
		ReputationThreshold:  0.6,
		ModelPath:           "./models/test_model.pkl",
		BatchSize:           32,
		MaxFeatures:         1000,
		CacheEmbeddings:     true,
		ParallelProcessing:  true,
		GPUAcceleration:     false,
	})

	// Get datasets directory
	datasetsDir := filepath.Join(".", "datasets")

	// Create dataset validator
	validator, err := NewDatasetValidator(analyzer, datasetsDir)
	if err != nil {
		t.Fatalf("Failed to create dataset validator: %v", err)
	}

	// Run validation on all datasets
	results, err := validator.ValidateAllDatasets()
	if err != nil {
		t.Fatalf("Failed to validate datasets: %v", err)
	}

	// Print results for debugging
	validator.PrintResults(results)

	// Save results to file
	outputPath := filepath.Join(".", "validation_results.json")
	if err := validator.SaveResults(results, outputPath); err != nil {
		t.Logf("Warning: Failed to save results to %s: %v", outputPath, err)
	}

	// Validate results meet minimum requirements
	for pm, result := range results {
		t.Run(pm, func(t *testing.T) {
			// Check that we have tests
			if result.TotalTests == 0 {
				t.Errorf("No tests found for %s", pm)
				return
			}

			// Check minimum accuracy (should be at least 70%)
			minAccuracy := 0.70
			if result.Accuracy < minAccuracy {
				t.Errorf("Accuracy too low for %s: %.3f < %.3f", pm, result.Accuracy, minAccuracy)
			}

			// Check that we have some true positives (detecting malicious packages)
			if result.TruePositives == 0 {
				t.Errorf("No true positives detected for %s - ML may not be detecting malicious packages", pm)
			}

			// Check that we have some true negatives (correctly identifying legitimate packages)
			if result.TrueNegatives == 0 {
				t.Errorf("No true negatives detected for %s - ML may be flagging all packages as malicious", pm)
			}

			// Check processing time is reasonable (should be under 1 second per package)
			maxTime := time.Second
			if result.MaxTime > maxTime {
				t.Errorf("Processing time too slow for %s: %v > %v", pm, result.MaxTime, maxTime)
			}

			// Log summary
			t.Logf("%s Results: %d/%d passed (%.1f%%), Precision: %.3f, Recall: %.3f, F1: %.3f",
				pm, result.PassedTests, result.TotalTests,
				result.Accuracy*100, result.Precision, result.Recall, result.F1Score)
		})
	}
}

// TestNPMDatasetValidation specifically tests NPM package validation
func TestNPMDatasetValidation(t *testing.T) {
	runPackageManagerTest(t, "npm")
}

// TestPyPIDatasetValidation specifically tests PyPI package validation
func TestPyPIDatasetValidation(t *testing.T) {
	runPackageManagerTest(t, "pypi")
}

// TestGoDatasetValidation specifically tests Go module validation
func TestGoDatasetValidation(t *testing.T) {
	runPackageManagerTest(t, "go")
}

// runPackageManagerTest runs validation for a specific package manager
func runPackageManagerTest(t *testing.T, packageManager string) {
	// Initialize ML analyzer
	analyzer := ml.NewMLAnalyzer(config.MLAnalysisConfig{
		Enabled:              true,
		SimilarityThreshold:  0.8,
		MaliciousThreshold:   0.7,
		ReputationThreshold:  0.6,
		ModelPath:           "./models/test_model.pkl",
		BatchSize:           32,
		MaxFeatures:         1000,
		CacheEmbeddings:     true,
		ParallelProcessing:  true,
		GPUAcceleration:     false,
	})

	// Create validator
	datasetsDir := filepath.Join(".", "datasets")
	validator, err := NewDatasetValidator(analyzer, datasetsDir)
	if err != nil {
		t.Fatalf("Failed to create dataset validator: %v", err)
	}

	// Run validation for specific package manager
	result, err := validator.ValidateDataset(packageManager)
	if err != nil {
		t.Fatalf("Failed to validate %s dataset: %v", packageManager, err)
	}

	// Print results
	results := map[string]*ValidationResults{packageManager: result}
	validator.PrintResults(results)

	// Validate specific requirements
	if result.TotalTests == 0 {
		t.Fatalf("No test packages found for %s", packageManager)
	}

	// Check that we can process packages without errors
	errorCount := 0
	for _, testResult := range result.Results {
		if testResult.Error != nil {
			errorCount++
			t.Logf("Error processing %s: %v", testResult.PackageName, testResult.Error)
		}
	}

	if errorCount > 0 {
		t.Errorf("%d/%d packages had processing errors", errorCount, result.TotalTests)
	}

	// Log detailed results for failed tests
	if result.FailedTests > 0 {
		t.Logf("Failed test details for %s:", packageManager)
		for _, testResult := range result.Results {
			if !testResult.Passed && testResult.Error == nil {
				t.Logf("  %s: Expected %s/%.2f, Got %s/%.2f (diff: %.2f)",
					testResult.PackageName,
					testResult.ExpectedRisk, testResult.ExpectedScore,
					testResult.ActualRisk, testResult.ActualScore,
					testResult.ActualScore-testResult.ExpectedScore)
			}
		}
	}
}

// TestPerformanceBenchmarks tests that the ML analysis meets performance requirements
func TestPerformanceBenchmarks(t *testing.T) {
	// Initialize ML analyzer
	analyzer := ml.NewMLAnalyzer(config.MLAnalysisConfig{
		Enabled:              true,
		SimilarityThreshold:  0.8,
		MaliciousThreshold:   0.7,
		ReputationThreshold:  0.6,
		ModelPath:           "./models/test_model.pkl",
		BatchSize:           32,
		MaxFeatures:         1000,
		CacheEmbeddings:     true,
		ParallelProcessing:  true,
		GPUAcceleration:     false,
	})

	// Create validator
	datasetsDir := filepath.Join(".", "datasets")
	validator, err := NewDatasetValidator(analyzer, datasetsDir)
	if err != nil {
		t.Fatalf("Failed to create dataset validator: %v", err)
	}

	// Test performance with all datasets
	results, err := validator.ValidateAllDatasets()
	if err != nil {
		t.Fatalf("Failed to validate datasets: %v", err)
	}

	// Check performance benchmarks
	benchmarks := validator.config.TestDatasets.PerformanceBenchmarks
	maxAnalysisTime := time.Duration(benchmarks.ProcessingTime.MaxAnalysisTimeMs) * time.Millisecond
	avgAnalysisTime := time.Duration(benchmarks.ProcessingTime.AverageAnalysisTimeMs) * time.Millisecond

	for pm, result := range results {
		t.Run(pm+"_performance", func(t *testing.T) {
			// Check maximum processing time
			if result.MaxTime > maxAnalysisTime {
				t.Errorf("Max processing time exceeded for %s: %v > %v", pm, result.MaxTime, maxAnalysisTime)
			}

			// Check average processing time
			if result.AverageTime > avgAnalysisTime {
				t.Errorf("Average processing time exceeded for %s: %v > %v", pm, result.AverageTime, avgAnalysisTime)
			}

			// Check accuracy targets
			accuracyTargets := benchmarks.AccuracyTargets
			if result.Precision < accuracyTargets.Precision {
				t.Errorf("Precision below target for %s: %.3f < %.3f", pm, result.Precision, accuracyTargets.Precision)
			}
			if result.Recall < accuracyTargets.Recall {
				t.Errorf("Recall below target for %s: %.3f < %.3f", pm, result.Recall, accuracyTargets.Recall)
			}
			if result.F1Score < accuracyTargets.F1Score {
				t.Errorf("F1 Score below target for %s: %.3f < %.3f", pm, result.F1Score, accuracyTargets.F1Score)
			}

			t.Logf("%s Performance: Avg=%v, Max=%v, Precision=%.3f, Recall=%.3f, F1=%.3f",
				pm, result.AverageTime, result.MaxTime, result.Precision, result.Recall, result.F1Score)
		})
	}
}

// TestSpecificRiskFactors tests detection of specific risk factors
func TestSpecificRiskFactors(t *testing.T) {
	// Initialize ML analyzer
	analyzer := ml.NewMLAnalyzer(config.MLAnalysisConfig{
		Enabled:              true,
		SimilarityThreshold:  0.8,
		MaliciousThreshold:   0.7,
		ReputationThreshold:  0.6,
		ModelPath:           "./models/test_model.pkl",
		BatchSize:           32,
		MaxFeatures:         1000,
		CacheEmbeddings:     true,
		ParallelProcessing:  true,
		GPUAcceleration:     false,
	})

	// Create validator
	datasetsDir := filepath.Join(".", "datasets")
	validator, err := NewDatasetValidator(analyzer, datasetsDir)
	if err != nil {
		t.Fatalf("Failed to create dataset validator: %v", err)
	}

	// Test each package manager's suspicious packages
	packageManagers := []string{"npm", "pypi", "go"}
	for _, pm := range packageManagers {
		t.Run(pm+"_risk_factors", func(t *testing.T) {
			// Load suspicious packages
			pmConfig := validator.config.TestDatasets.PackageManagers[pm]
			suspiciousPackages, err := validator.LoadTestPackages(pmConfig.SuspiciousPackages)
			if err != nil {
				t.Fatalf("Failed to load suspicious packages for %s: %v", pm, err)
			}

			// Test each suspicious package
			for _, pkg := range suspiciousPackages {
				t.Run(pkg.Name, func(t *testing.T) {
					result := validator.ValidatePackage(pkg)
					if result.Error != nil {
						t.Errorf("Error analyzing %s: %v", pkg.Name, result.Error)
						return
					}

					// Suspicious packages should have elevated risk scores
					if result.ActualScore < 0.3 {
						t.Errorf("Suspicious package %s has low risk score: %.3f", pkg.Name, result.ActualScore)
					}

					// Log risk factors for debugging
					if len(pkg.RiskFactors) > 0 {
						t.Logf("%s risk factors: %v, score: %.3f", pkg.Name, pkg.RiskFactors, result.ActualScore)
					}
				})
			}
		})
	}
}