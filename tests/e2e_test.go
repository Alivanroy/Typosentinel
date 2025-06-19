package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// E2ETestSuite contains end-to-end tests
type E2ETestSuite struct {
	binaryPath   string
	tempDir      string
	configPath   string
	outputDir    string
}

// E2ETestCase represents an end-to-end test case
type E2ETestCase struct {
	Name           string
	Args           []string
	ExpectedExit   int
	ExpectedOutput []string
	ExpectedFiles  []string
	Timeout        time.Duration
	SetupFunc      func(*E2ETestSuite) error
	CleanupFunc    func(*E2ETestSuite) error
}

// SetupE2ETestSuite initializes the end-to-end test suite
func SetupE2ETestSuite(t *testing.T) *E2ETestSuite {
	// Create temporary directory
	tempDir, err := ioutil.TempDir("", "typosentinel-e2e-test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}

	outputDir := filepath.Join(tempDir, "output")
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		t.Fatalf("Failed to create output directory: %v", err)
	}

	// Build the binary for testing
	binaryPath := filepath.Join(tempDir, "typosentinel.exe")
	if err := buildTestBinary(binaryPath); err != nil {
		t.Fatalf("Failed to build test binary: %v", err)
	}

	// Create test configuration
	configPath := filepath.Join(tempDir, "config.yaml")
	if err := createTestConfig(configPath, tempDir); err != nil {
		t.Fatalf("Failed to create test config: %v", err)
	}

	return &E2ETestSuite{
		binaryPath: binaryPath,
		tempDir:    tempDir,
		configPath: configPath,
		outputDir:  outputDir,
	}
}

// TeardownE2ETestSuite cleans up the test suite
func (suite *E2ETestSuite) TeardownE2ETestSuite() {
	if suite.tempDir != "" {
		os.RemoveAll(suite.tempDir)
	}
}

// buildTestBinary builds the TypoSentinel binary for testing
func buildTestBinary(outputPath string) error {
	cmd := exec.Command("go", "build", "-o", outputPath, "./cmd")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	return cmd.Run()
}

// createTestConfig creates a test configuration file
func createTestConfig(configPath, tempDir string) error {
	config := fmt.Sprintf(`
core:
  environment: test
  log_level: info
  data_dir: %s

static_analysis:
  enabled: true
  scan_scripts: true
  scan_manifests: true
  timeout: 30s

dynamic_analysis:
  enabled: false
  sandbox_type: docker
  timeout: 60s

ml_analysis:
  enabled: true
  scorer:
    enabled: true
    feature_weights:
      downloads: 0.15
      age: 0.10
      maintainers: 0.10
      dependencies: 0.15
      description: 0.10
      typosquatting: 0.25
      entropy: 0.15
    thresholds:
      high_risk: 0.7
      medium_risk: 0.4

provenance_analysis:
  enabled: false
`, strings.ReplaceAll(tempDir, "\\", "/"))

	return ioutil.WriteFile(configPath, []byte(config), 0644)
}

// TestE2ECommandLineInterface tests the command-line interface
func TestE2ECommandLineInterface(t *testing.T) {
	suite := SetupE2ETestSuite(t)
	defer suite.TeardownE2ETestSuite()

	testCases := []E2ETestCase{
		{
			Name:           "help_command",
			Args:           []string{"--help"},
			ExpectedExit:   0,
			ExpectedOutput: []string{"TypoSentinel", "Usage:", "scan"},
			Timeout:        10 * time.Second,
		},
		{
			Name:           "version_command",
			Args:           []string{"--version"},
			ExpectedExit:   0,
			ExpectedOutput: []string{"TypoSentinel"},
			Timeout:        10 * time.Second,
		},
		{
			Name:           "scan_help",
			Args:           []string{"scan", "--help"},
			ExpectedExit:   0,
			ExpectedOutput: []string{"Scan a package", "registry", "version"},
			Timeout:        10 * time.Second,
		},
		{
			Name:           "invalid_command",
			Args:           []string{"invalid-command"},
			ExpectedExit:   1,
			ExpectedOutput: []string{"Error:", "unknown command"},
			Timeout:        10 * time.Second,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Name, func(t *testing.T) {
			suite.runE2ETest(t, testCase)
		})
	}
}

// TestE2EPackageScanning tests end-to-end package scanning
func TestE2EPackageScanning(t *testing.T) {
	suite := SetupE2ETestSuite(t)
	defer suite.TeardownE2ETestSuite()

	testCases := []E2ETestCase{
		{
			Name: "scan_legitimate_npm_package",
			Args: []string{
				"scan",
				"--registry", "npm",
				"--package", "express",
				"--version", "4.18.2",
				"--config", suite.configPath,
				"--output", "json",
			},
			ExpectedExit:   0,
			ExpectedOutput: []string{"express", "4.18.2", "\"risk_score\":", "\"overall_risk\":"},
			Timeout:        60 * time.Second,
		},
		{
			Name: "scan_suspicious_npm_package",
			Args: []string{
				"scan",
				"--registry", "npm",
				"--package", "expresss", // Typosquatting
				"--version", "1.0.0",
				"--config", suite.configPath,
				"--output", "json",
			},
			ExpectedExit:   0,
			ExpectedOutput: []string{"expresss", "1.0.0", "\"risk_score\":", "high"},
			Timeout:        60 * time.Second,
		},
		{
			Name: "scan_with_report_output",
			Args: []string{
				"scan",
				"--registry", "pypi",
				"--package", "requests",
				"--version", "2.28.1",
				"--config", suite.configPath,
				"--output", "json",
				"--save-report", filepath.Join(suite.outputDir, "requests_report.json"),
			},
			ExpectedExit:   0,
			ExpectedOutput: []string{"requests", "2.28.1"},
			ExpectedFiles:  []string{"requests_report.json"},
			Timeout:        60 * time.Second,
		},
		{
			Name: "scan_with_verbose_output",
			Args: []string{
				"scan",
				"--registry", "npm",
				"--package", "lodash",
				"--version", "4.17.21",
				"--config", suite.configPath,
				"--verbose",
				"--output", "table",
			},
			ExpectedExit:   0,
			ExpectedOutput: []string{"lodash", "4.17.21", "Analysis Results"},
			Timeout:        60 * time.Second,
		},
		{
			Name: "scan_nonexistent_package",
			Args: []string{
				"scan",
				"--registry", "npm",
				"--package", "this-package-definitely-does-not-exist-12345",
				"--version", "1.0.0",
				"--config", suite.configPath,
			},
			ExpectedExit:   1,
			ExpectedOutput: []string{"Error:", "package not found"},
			Timeout:        30 * time.Second,
		},
		{
			Name: "scan_with_timeout",
			Args: []string{
				"scan",
				"--registry", "npm",
				"--package", "express",
				"--version", "4.18.2",
				"--config", suite.configPath,
				"--timeout", "1s", // Very short timeout
			},
			ExpectedExit:   1,
			ExpectedOutput: []string{"timeout", "context deadline exceeded"},
			Timeout:        10 * time.Second,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Name, func(t *testing.T) {
			suite.runE2ETest(t, testCase)
		})
	}
}

// TestE2EConfigurationHandling tests configuration file handling
func TestE2EConfigurationHandling(t *testing.T) {
	suite := SetupE2ETestSuite(t)
	defer suite.TeardownE2ETestSuite()

	testCases := []E2ETestCase{
		{
			Name: "scan_with_custom_config",
			Args: []string{
				"scan",
				"--registry", "npm",
				"--package", "express",
				"--version", "4.18.2",
				"--config", suite.configPath,
			},
			ExpectedExit:   0,
			ExpectedOutput: []string{"express", "4.18.2"},
			Timeout:        60 * time.Second,
		},
		{
			Name: "scan_with_invalid_config",
			Args: []string{
				"scan",
				"--registry", "npm",
				"--package", "express",
				"--version", "4.18.2",
				"--config", "/nonexistent/config.yaml",
			},
			ExpectedExit:   1,
			ExpectedOutput: []string{"Error:", "config"},
			Timeout:        30 * time.Second,
		},
		{
			Name: "scan_without_config",
			Args: []string{
				"scan",
				"--registry", "npm",
				"--package", "express",
				"--version", "4.18.2",
			},
			ExpectedExit:   0, // Should use default config
			ExpectedOutput: []string{"express", "4.18.2"},
			Timeout:        60 * time.Second,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Name, func(t *testing.T) {
			suite.runE2ETest(t, testCase)
		})
	}
}

// TestE2EOutputFormats tests different output formats
func TestE2EOutputFormats(t *testing.T) {
	suite := SetupE2ETestSuite(t)
	defer suite.TeardownE2ETestSuite()

	testCases := []E2ETestCase{
		{
			Name: "output_json_format",
			Args: []string{
				"scan",
				"--registry", "npm",
				"--package", "express",
				"--version", "4.18.2",
				"--config", suite.configPath,
				"--output", "json",
			},
			ExpectedExit:   0,
			ExpectedOutput: []string{"{", "\"package\":", "\"risk_score\":", "}"},
			Timeout:        60 * time.Second,
		},
		{
			Name: "output_table_format",
			Args: []string{
				"scan",
				"--registry", "npm",
				"--package", "express",
				"--version", "4.18.2",
				"--config", suite.configPath,
				"--output", "table",
			},
			ExpectedExit:   0,
			ExpectedOutput: []string{"Package", "Version", "Risk Score", "express"},
			Timeout:        60 * time.Second,
		},
		{
			Name: "output_yaml_format",
			Args: []string{
				"scan",
				"--registry", "npm",
				"--package", "express",
				"--version", "4.18.2",
				"--config", suite.configPath,
				"--output", "yaml",
			},
			ExpectedExit:   0,
			ExpectedOutput: []string{"package:", "risk_score:", "express"},
			Timeout:        60 * time.Second,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Name, func(t *testing.T) {
			suite.runE2ETest(t, testCase)
		})
	}
}

// TestE2EPerformance tests performance characteristics
func TestE2EPerformance(t *testing.T) {
	suite := SetupE2ETestSuite(t)
	defer suite.TeardownE2ETestSuite()

	// Test scanning multiple packages in sequence
	packages := []struct {
		registry string
		name     string
		version  string
	}{
		{"npm", "express", "4.18.2"},
		{"npm", "lodash", "4.17.21"},
		{"pypi", "requests", "2.28.1"},
		{"pypi", "numpy", "1.24.0"},
	}

	totalStartTime := time.Now()
	var totalProcessingTime time.Duration

	for i, pkg := range packages {
		t.Run(fmt.Sprintf("performance_scan_%d_%s_%s", i+1, pkg.registry, pkg.name), func(t *testing.T) {
			startTime := time.Now()
			
			testCase := E2ETestCase{
				Name: fmt.Sprintf("performance_scan_%s_%s", pkg.registry, pkg.name),
				Args: []string{
					"scan",
					"--registry", pkg.registry,
					"--package", pkg.name,
					"--version", pkg.version,
					"--config", suite.configPath,
					"--output", "json",
				},
				ExpectedExit:   0,
				ExpectedOutput: []string{pkg.name, pkg.version},
				Timeout:        120 * time.Second,
			}
			
			suite.runE2ETest(t, testCase)
			processingTime := time.Since(startTime)
			totalProcessingTime += processingTime
			
			t.Logf("Package %s@%s processed in %v", pkg.name, pkg.version, processingTime)
			
			// Performance assertion: each package should be processed within reasonable time
			if processingTime > 60*time.Second {
				t.Errorf("Package %s@%s took too long to process: %v", pkg.name, pkg.version, processingTime)
			}
		})
	}

	totalTime := time.Since(totalStartTime)
	averageTime := totalProcessingTime / time.Duration(len(packages))

	t.Logf("\n=== Performance Summary ===")
	t.Logf("Total packages scanned: %d", len(packages))
	t.Logf("Total processing time: %v", totalProcessingTime)
	t.Logf("Total wall time: %v", totalTime)
	t.Logf("Average processing time per package: %v", averageTime)

	// Performance assertions
	if averageTime > 30*time.Second {
		t.Errorf("Average processing time too slow: %v", averageTime)
	}
}

// runE2ETest runs a single end-to-end test case
func (suite *E2ETestSuite) runE2ETest(t *testing.T, testCase E2ETestCase) {
	// Setup if needed
	if testCase.SetupFunc != nil {
		if err := testCase.SetupFunc(suite); err != nil {
			t.Fatalf("Setup failed for test %s: %v", testCase.Name, err)
		}
	}

	// Cleanup if needed
	if testCase.CleanupFunc != nil {
		defer func() {
			if err := testCase.CleanupFunc(suite); err != nil {
				t.Logf("Cleanup failed for test %s: %v", testCase.Name, err)
			}
		}()
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), testCase.Timeout)
	defer cancel()

	// Execute command
	cmd := exec.CommandContext(ctx, suite.binaryPath, testCase.Args...)
	cmd.Dir = suite.tempDir

	output, err := cmd.CombinedOutput()
	outputStr := string(output)

	// Check exit code
	actualExit := 0
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			actualExit = exitError.ExitCode()
		} else {
			// Command failed to start or other error
			t.Fatalf("Command execution failed for test %s: %v", testCase.Name, err)
		}
	}

	if actualExit != testCase.ExpectedExit {
		t.Errorf("Test %s: Expected exit code %d, got %d\nOutput: %s",
			testCase.Name, testCase.ExpectedExit, actualExit, outputStr)
	}

	// Check expected output strings
	for _, expectedStr := range testCase.ExpectedOutput {
		if !strings.Contains(outputStr, expectedStr) {
			t.Errorf("Test %s: Expected output to contain '%s'\nActual output: %s",
				testCase.Name, expectedStr, outputStr)
		}
	}

	// Check expected files
	for _, expectedFile := range testCase.ExpectedFiles {
		filePath := filepath.Join(suite.outputDir, expectedFile)
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			t.Errorf("Test %s: Expected file %s was not created", testCase.Name, expectedFile)
		} else if err != nil {
			t.Errorf("Test %s: Error checking file %s: %v", testCase.Name, expectedFile, err)
		} else {
			// Validate file content if it's a JSON report
			if strings.HasSuffix(expectedFile, ".json") {
				if err := suite.validateJSONReport(filePath); err != nil {
					t.Errorf("Test %s: Invalid JSON report %s: %v", testCase.Name, expectedFile, err)
				}
			}
		}
	}

	t.Logf("Test %s completed successfully", testCase.Name)
}

// validateJSONReport validates that a JSON report file is well-formed
func (suite *E2ETestSuite) validateJSONReport(filePath string) error {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %v", err)
	}

	var report map[string]interface{}
	if err := json.Unmarshal(data, &report); err != nil {
		return fmt.Errorf("invalid JSON: %v", err)
	}

	// Check for required fields
	requiredFields := []string{"package", "version", "registry", "risk_score", "overall_risk"}
	for _, field := range requiredFields {
		if _, exists := report[field]; !exists {
			return fmt.Errorf("missing required field: %s", field)
		}
	}

	return nil
}

// TestE2EErrorRecovery tests error recovery scenarios
func TestE2EErrorRecovery(t *testing.T) {
	suite := SetupE2ETestSuite(t)
	defer suite.TeardownE2ETestSuite()

	testCases := []E2ETestCase{
		{
			Name: "recovery_from_network_error",
			Args: []string{
				"scan",
				"--registry", "npm",
				"--package", "express",
				"--version", "4.18.2",
				"--config", suite.configPath,
				"--retry", "3",
			},
			ExpectedExit:   0, // Should eventually succeed with retries
			ExpectedOutput: []string{"express"},
			Timeout:        120 * time.Second,
		},
		{
			Name: "graceful_degradation",
			Args: []string{
				"scan",
				"--registry", "npm",
				"--package", "express",
				"--version", "4.18.2",
				"--config", suite.configPath,
				"--fail-fast=false", // Continue even if some engines fail
			},
			ExpectedExit:   0,
			ExpectedOutput: []string{"express", "4.18.2"},
			Timeout:        60 * time.Second,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Name, func(t *testing.T) {
			suite.runE2ETest(t, testCase)
		})
	}
}

// TestE2EConcurrentScanning tests concurrent package scanning
func TestE2EConcurrentScanning(t *testing.T) {
	suite := SetupE2ETestSuite(t)
	defer suite.TeardownE2ETestSuite()

	// Test parallel scanning with different parallelism levels
	parallelismLevels := []int{1, 2, 4}
	packages := []string{"express", "lodash", "react", "vue"}

	for _, parallelism := range parallelismLevels {
		t.Run(fmt.Sprintf("concurrent_scan_parallelism_%d", parallelism), func(t *testing.T) {
			startTime := time.Now()
			
			testCase := E2ETestCase{
				Name: fmt.Sprintf("concurrent_scan_p%d", parallelism),
				Args: []string{
					"scan",
					"--registry", "npm",
					"--package", strings.Join(packages, ","),
					"--version", "latest",
					"--config", suite.configPath,
					"--parallelism", fmt.Sprintf("%d", parallelism),
					"--output", "json",
				},
				ExpectedExit:   0,
				ExpectedOutput: []string{"express", "lodash", "react", "vue"},
				Timeout:        180 * time.Second,
			}
			
			suite.runE2ETest(t, testCase)
			processingTime := time.Since(startTime)
			
			t.Logf("Concurrent scan with parallelism %d completed in %v", parallelism, processingTime)
		})
	}
}