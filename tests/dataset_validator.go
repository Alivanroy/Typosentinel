package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math"
	"path/filepath"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/ml"
	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// TestPackage represents a test package with expected results
type TestPackage struct {
	Name         string                 `json:"name"`
	Version      string                 `json:"version"`
	Description  string                 `json:"description"`
	Metadata     map[string]interface{} `json:"metadata"`
	ExpectedRisk string                 `json:"expected_risk"`
	ExpectedScore float64               `json:"expected_score"`
	RiskFactors  []string               `json:"risk_factors,omitempty"`
}

// TestConfig represents the test configuration
type TestConfig struct {
	TestDatasets struct {
		PackageManagers map[string]struct {
			LegitimatePackages string `json:"legitimate_packages"`
			SuspiciousPackages string `json:"suspicious_packages"`
			TotalPackages      int    `json:"total_packages"`
			LegitimateCount    int    `json:"legitimate_count"`
			SuspiciousCount    int    `json:"suspicious_count"`
		} `json:"package_managers"`
		PerformanceBenchmarks struct {
			AccuracyTargets struct {
				TruePositiveRate  float64 `json:"true_positive_rate"`
				FalsePositiveRate float64 `json:"false_positive_rate"`
				Precision         float64 `json:"precision"`
				Recall            float64 `json:"recall"`
				F1Score           float64 `json:"f1_score"`
			} `json:"accuracy_targets"`
			ProcessingTime struct {
				MaxAnalysisTimeMs     int `json:"max_analysis_time_ms"`
				AverageAnalysisTimeMs int `json:"average_analysis_time_ms"`
			} `json:"processing_time"`
		} `json:"performance_benchmarks"`
	} `json:"test_datasets"`
}

// TestResult represents the result of a single test
type TestResult struct {
	PackageName    string
	ExpectedRisk   string
	ExpectedScore  float64
	ActualRisk     string
	ActualScore    float64
	ProcessingTime time.Duration
	Passed         bool
	Error          error
}

// ValidationResults represents overall validation results
type ValidationResults struct {
	TotalTests       int
	PassedTests      int
	FailedTests      int
	TruePositives    int
	TrueNegatives    int
	FalsePositives   int
	FalseNegatives   int
	AverageTime      time.Duration
	MaxTime          time.Duration
	Accuracy         float64
	Precision        float64
	Recall           float64
	F1Score          float64
	Results          []TestResult
}

// DatasetValidator validates ML analysis against test datasets
type DatasetValidator struct {
	analyzer   *ml.MLAnalyzer
	config     *TestConfig
	datasetsDir string
}

// NewDatasetValidator creates a new dataset validator
func NewDatasetValidator(analyzer *ml.MLAnalyzer, datasetsDir string) (*DatasetValidator, error) {
	configPath := filepath.Join(datasetsDir, "test_config.json")
	configData, err := ioutil.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read test config: %w", err)
	}

	var config TestConfig
	if err := json.Unmarshal(configData, &config); err != nil {
		return nil, fmt.Errorf("failed to parse test config: %w", err)
	}

	return &DatasetValidator{
		analyzer:    analyzer,
		config:      &config,
		datasetsDir: datasetsDir,
	}, nil
}

// LoadTestPackages loads test packages from a JSON file
func (dv *DatasetValidator) LoadTestPackages(filePath string) ([]TestPackage, error) {
	fullPath := filepath.Join(dv.datasetsDir, filePath)
	data, err := ioutil.ReadFile(fullPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read test packages file %s: %w", fullPath, err)
	}

	var packages []TestPackage
	if err := json.Unmarshal(data, &packages); err != nil {
		return nil, fmt.Errorf("failed to parse test packages: %w", err)
	}

	return packages, nil
}

// ValidatePackage validates a single package against the ML analyzer
func (dv *DatasetValidator) ValidatePackage(pkg TestPackage) TestResult {
	start := time.Now()

	// Convert test package to types.Package
	testPkg := &types.Package{
		Name:     pkg.Name,
		Version:  pkg.Version,
		Metadata: &types.PackageMetadata{
			Name:        pkg.Name,
			Version:     pkg.Version,
			Description: pkg.Description,
		},
	}

	// Analyze the package
	ctx := context.Background()
	result, err := dv.analyzer.Analyze(ctx, testPkg)
	processingTime := time.Since(start)

	if err != nil {
		return TestResult{
			PackageName:    pkg.Name,
			ExpectedRisk:   pkg.ExpectedRisk,
			ExpectedScore:  pkg.ExpectedScore,
			ProcessingTime: processingTime,
			Passed:         false,
			Error:          err,
		}
	}

	// Check if results match expectations
	scoreTolerance := 0.15 // Allow 15% tolerance in score
	scoreMatch := math.Abs(result.RiskAssessment.RiskScore-pkg.ExpectedScore) <= scoreTolerance
	riskMatch := result.RiskAssessment.OverallRisk == pkg.ExpectedRisk

	return TestResult{
		PackageName:    pkg.Name,
		ExpectedRisk:   pkg.ExpectedRisk,
		ExpectedScore:  pkg.ExpectedScore,
		ActualRisk:     result.RiskAssessment.OverallRisk,
		ActualScore:    result.RiskAssessment.RiskScore,
		ProcessingTime: processingTime,
		Passed:         scoreMatch && riskMatch,
	}
}

// ValidateDataset validates all packages in a dataset
func (dv *DatasetValidator) ValidateDataset(packageManager string) (*ValidationResults, error) {
	pmConfig, exists := dv.config.TestDatasets.PackageManagers[packageManager]
	if !exists {
		return nil, fmt.Errorf("package manager %s not found in config", packageManager)
	}

	// Load legitimate packages
	legitPackages, err := dv.LoadTestPackages(pmConfig.LegitimatePackages)
	if err != nil {
		return nil, fmt.Errorf("failed to load legitimate packages: %w", err)
	}

	// Load suspicious packages
	suspiciousPackages, err := dv.LoadTestPackages(pmConfig.SuspiciousPackages)
	if err != nil {
		return nil, fmt.Errorf("failed to load suspicious packages: %w", err)
	}

	// Combine all packages
	allPackages := append(legitPackages, suspiciousPackages...)

	// Validate each package
	results := &ValidationResults{
		Results: make([]TestResult, 0, len(allPackages)),
	}

	var totalTime time.Duration
	for _, pkg := range allPackages {
		result := dv.ValidatePackage(pkg)
		results.Results = append(results.Results, result)
		results.TotalTests++

		if result.Passed {
			results.PassedTests++
		} else {
			results.FailedTests++
		}

		// Update confusion matrix
		if result.Error == nil {
			if pkg.ExpectedRisk == "HIGH" && result.ActualRisk == "HIGH" {
				results.TruePositives++
			} else if pkg.ExpectedRisk == "LOW" && result.ActualRisk == "LOW" {
				results.TrueNegatives++
			} else if pkg.ExpectedRisk == "LOW" && result.ActualRisk == "HIGH" {
				results.FalsePositives++
			} else if pkg.ExpectedRisk == "HIGH" && result.ActualRisk == "LOW" {
				results.FalseNegatives++
			}
		}

		totalTime += result.ProcessingTime
		if result.ProcessingTime > results.MaxTime {
			results.MaxTime = result.ProcessingTime
		}
	}

	// Calculate metrics
	if results.TotalTests > 0 {
		results.AverageTime = totalTime / time.Duration(results.TotalTests)
		results.Accuracy = float64(results.PassedTests) / float64(results.TotalTests)
	}

	if results.TruePositives+results.FalsePositives > 0 {
		results.Precision = float64(results.TruePositives) / float64(results.TruePositives+results.FalsePositives)
	}

	if results.TruePositives+results.FalseNegatives > 0 {
		results.Recall = float64(results.TruePositives) / float64(results.TruePositives+results.FalseNegatives)
	}

	if results.Precision+results.Recall > 0 {
		results.F1Score = 2 * (results.Precision * results.Recall) / (results.Precision + results.Recall)
	}

	return results, nil
}

// ValidateAllDatasets validates all package manager datasets
func (dv *DatasetValidator) ValidateAllDatasets() (map[string]*ValidationResults, error) {
	allResults := make(map[string]*ValidationResults)

	for pm := range dv.config.TestDatasets.PackageManagers {
		results, err := dv.ValidateDataset(pm)
		if err != nil {
			return nil, fmt.Errorf("failed to validate %s dataset: %w", pm, err)
		}
		allResults[pm] = results
	}

	return allResults, nil
}

// PrintResults prints validation results in a readable format
func (dv *DatasetValidator) PrintResults(results map[string]*ValidationResults) {
	fmt.Println("\n=== ML Analysis Validation Results ===")

	for pm, result := range results {
		fmt.Printf("\n--- %s Package Manager ---\n", pm)
		fmt.Printf("Total Tests: %d\n", result.TotalTests)
		fmt.Printf("Passed: %d (%.1f%%)\n", result.PassedTests, float64(result.PassedTests)/float64(result.TotalTests)*100)
		fmt.Printf("Failed: %d (%.1f%%)\n", result.FailedTests, float64(result.FailedTests)/float64(result.TotalTests)*100)
		fmt.Printf("\nConfusion Matrix:\n")
		fmt.Printf("  True Positives: %d\n", result.TruePositives)
		fmt.Printf("  True Negatives: %d\n", result.TrueNegatives)
		fmt.Printf("  False Positives: %d\n", result.FalsePositives)
		fmt.Printf("  False Negatives: %d\n", result.FalseNegatives)
		fmt.Printf("\nMetrics:\n")
		fmt.Printf("  Accuracy: %.3f\n", result.Accuracy)
		fmt.Printf("  Precision: %.3f\n", result.Precision)
		fmt.Printf("  Recall: %.3f\n", result.Recall)
		fmt.Printf("  F1 Score: %.3f\n", result.F1Score)
		fmt.Printf("\nPerformance:\n")
		fmt.Printf("  Average Time: %v\n", result.AverageTime)
		fmt.Printf("  Max Time: %v\n", result.MaxTime)

		// Print failed tests
		if result.FailedTests > 0 {
			fmt.Printf("\nFailed Tests:\n")
			for _, testResult := range result.Results {
				if !testResult.Passed {
					fmt.Printf("  %s: Expected %s/%.2f, Got %s/%.2f", 
						testResult.PackageName,
						testResult.ExpectedRisk, testResult.ExpectedScore,
						testResult.ActualRisk, testResult.ActualScore)
					if testResult.Error != nil {
						fmt.Printf(" (Error: %v)", testResult.Error)
					}
					fmt.Println()
				}
			}
		}
	}

	// Check against benchmarks
	fmt.Println("\n=== Benchmark Comparison ===")
	benchmarks := dv.config.TestDatasets.PerformanceBenchmarks.AccuracyTargets
	for pm, result := range results {
		fmt.Printf("\n%s:\n", pm)
		fmt.Printf("  Precision: %.3f (target: %.3f) %s\n", 
			result.Precision, benchmarks.Precision, 
			getStatus(result.Precision >= benchmarks.Precision))
		fmt.Printf("  Recall: %.3f (target: %.3f) %s\n", 
			result.Recall, benchmarks.Recall, 
			getStatus(result.Recall >= benchmarks.Recall))
		fmt.Printf("  F1 Score: %.3f (target: %.3f) %s\n", 
			result.F1Score, benchmarks.F1Score, 
			getStatus(result.F1Score >= benchmarks.F1Score))
	}
}

func getStatus(passed bool) string {
	if passed {
		return "✓ PASS"
	}
	return "✗ FAIL"
}

// SaveResults saves validation results to a JSON file
func (dv *DatasetValidator) SaveResults(results map[string]*ValidationResults, outputPath string) error {
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal results: %w", err)
	}

	return ioutil.WriteFile(outputPath, data, 0644)
}