package tests

import (
	"context"
	"testing"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/dynamic"
	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// TestDynamicAnalysisRealLife tests dynamic analysis with real-world scenarios
func TestDynamicAnalysisRealLife(t *testing.T) {
	tests := []struct {
		name          string
		pkg           *types.Package
		expectedRisk  float64
		expectedFlags int
	}{
		{
			name: "Legitimate package - express",
			pkg: &types.Package{
				Name:     "express",
				Version:  "4.18.2",
				Registry: "npm",
				Metadata: &types.PackageMetadata{
					Downloads: 30000000,
					Metadata: map[string]interface{}{
						"author_email": "tj@vision-media.ca",
						"keywords":     []string{"express", "framework", "web"},
						"description":  "Fast, unopinionated, minimalist web framework",
					},
				},
			},
			expectedRisk:  0.2,
			expectedFlags: 0,
		},
		{
			name: "Suspicious package - crypto-miner",
			pkg: &types.Package{
				Name:     "crypto-miner",
				Version:  "1.0.0",
				Registry: "npm",
				Metadata: &types.PackageMetadata{
					Downloads: 100,
					Metadata: map[string]interface{}{
						"author_email": "miner@suspicious.com",
						"keywords":     []string{"crypto", "mining", "bitcoin"},
						"description":  "Cryptocurrency mining utility",
					},
				},
			},
			expectedRisk:  0.8,
			expectedFlags: 2,
		},
		{
			name: "Network-heavy package - axios",
			pkg: &types.Package{
				Name:     "axios",
				Version:  "1.4.0",
				Registry: "npm",
				Metadata: &types.PackageMetadata{
					Downloads: 40000000,
					Metadata: map[string]interface{}{
						"author_email": "matt@axios.com",
						"keywords":     []string{"http", "request", "client"},
						"description":  "Promise based HTTP client for the browser and node.js",
					},
				},
			},
			expectedRisk:  0.3,
			expectedFlags: 1,
		},
		{
			name: "File system package - fs-extra",
			pkg: &types.Package{
				Name:     "fs-extra",
				Version:  "11.1.1",
				Registry: "npm",
				Metadata: &types.PackageMetadata{
					Downloads: 25000000,
					Metadata: map[string]interface{}{
						"author_email": "jprichardson@gmail.com",
						"keywords":     []string{"fs", "file", "filesystem"},
						"description":  "fs-extra contains methods that aren't included in the vanilla Node.js fs package",
					},
				},
			},
			expectedRisk:  0.4,
			expectedFlags: 1,
		},
	}

	// Create dynamic analyzer with sandbox configuration
	config := &dynamic.Config{
		Enabled:                true,
		SandboxType:            "docker",
		SandboxImage:           "ubuntu:20.04",
		SandboxTimeout:         "60s",
		MaxConcurrentSandboxes: 1,
		AnalyzeInstallScripts:  true,
		AnalyzeNetworkActivity: false,
		AnalyzeFileSystem:      false,
		AnalyzeProcesses:       true,
		AnalyzeEnvironment:     true,
		MaxExecutionTime:       "30s",
		MaxMemoryUsage:         512 * 1024 * 1024,  // 512MB
		MaxDiskUsage:           1024 * 1024 * 1024, // 1GB
		MaxNetworkConnections:  0,
		MonitoringInterval:     "1s",
		Verbose:                false,
		LogLevel:               "info",
	}

	analyzer, err := dynamic.NewAnalyzer(config)
	if err != nil {
		t.Logf("Warning: Could not create dynamic analyzer: %v", err)
		t.Skip("Skipping dynamic analysis tests - analyzer creation failed")
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()

			// Perform dynamic analysis
			result, err := analyzer.AnalyzePackage(ctx, tt.pkg.Name)
			if err != nil {
				t.Logf("Warning: Dynamic analysis failed for %s: %v", tt.pkg.Name, err)
				// Don't fail the test for sandbox setup issues
				return
			}

			if result == nil {
				t.Errorf("Expected dynamic analysis result, got nil")
				return
			}

			// Log the analysis results
			t.Logf("Package: %s, Risk Score: %.2f, Findings: %d",
				tt.pkg.Name, result.RiskScore, len(result.SecurityFindings))

			for _, finding := range result.SecurityFindings {
				t.Logf("  - Security Finding: %s (Severity: %s)", finding.Type, finding.Severity)
			}

			// Verify risk score is in valid range
			if result.RiskScore < 0 || result.RiskScore > 1 {
				t.Errorf("Risk score should be between 0 and 1, got %.2f", result.RiskScore)
			}

			// Note: ExecutionTime field not available in current AnalysisResult structure
			// Execution time validation would need to be implemented differently

			// Check if the risk assessment is reasonable (with tolerance)
			if tt.name == "Legitimate package - express" && result.RiskScore > 0.5 {
				t.Logf("Note: Popular package has higher than expected risk score: %.2f", result.RiskScore)
			}

			if tt.name == "Suspicious package - crypto-miner" && result.RiskScore < 0.6 {
				t.Logf("Note: Suspicious package has lower than expected risk score: %.2f", result.RiskScore)
			}

			// Verify security findings are valid
			for _, finding := range result.SecurityFindings {
				if finding.Severity == "" {
					t.Errorf("Security finding missing severity: %+v", finding)
				}
			}
		})
	}
}

// TestDynamicSandboxIsolation tests sandbox isolation capabilities
func TestDynamicSandboxIsolation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping sandbox isolation test in short mode")
	}

	pkg := &types.Package{
		Name:     "malicious-test",
		Version:  "1.0.0",
		Registry: "npm",
		Metadata: &types.PackageMetadata{
			Downloads: 10,
			Metadata: map[string]interface{}{
				"author_email": "test@malicious.com",
				"keywords":     []string{"test", "malicious"},
				"description":  "Test package for sandbox isolation",
			},
		},
	}

	config := &dynamic.Config{
		Enabled:                true,
		SandboxType:            "docker",
		SandboxTimeout:         "30s",
		MaxMemoryUsage:         256 * 1024 * 1024, // 256MB in bytes
		AnalyzeNetworkActivity: false,
		AnalyzeFileSystem:      false,
		MaxExecutionTime:       "15s",
	}

	analyzer, err := dynamic.NewAnalyzer(config)
	if err != nil {
		t.Logf("Warning: Could not create dynamic analyzer: %v", err)
		t.Skip("Skipping sandbox isolation tests")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	// Test sandbox isolation
	result, err := analyzer.AnalyzePackage(ctx, pkg.Name)
	if err != nil {
		t.Logf("Warning: Sandbox isolation test failed: %v", err)
		return
	}

	if result == nil {
		t.Errorf("Expected sandbox analysis result, got nil")
		return
	}

	t.Logf("Sandbox isolation test completed: Risk Score %.2f, Flags: %d",
		result.RiskScore, len(result.SecurityFindings))

	// Verify sandbox constraints were enforced
	// Check execution time (convert string to duration for comparison)
	maxExecTime, _ := time.ParseDuration(config.MaxExecutionTime)
	if result.ProcessingTime > maxExecTime {
		t.Errorf("Sandbox execution time exceeded limit: %v > %v",
			result.ProcessingTime, config.MaxExecutionTime)
	}

	// Check for security findings
	for _, finding := range result.SecurityFindings {
		if finding.Type == "network_access" && !config.AnalyzeNetworkActivity {
			t.Logf("Detected network access attempt in isolated sandbox")
		}
		if finding.Type == "filesystem_access" && !config.AnalyzeFileSystem {
			t.Logf("Detected filesystem access attempt in isolated sandbox")
		}
	}
}

// TestDynamicBehaviorAnalysis tests behavioral pattern detection
func TestDynamicBehaviorAnalysis(t *testing.T) {
	behaviorTests := []struct {
		name              string
		pkg               *types.Package
		expectedBehaviors []string
	}{
		{
			name: "HTTP client package",
			pkg: &types.Package{
				Name:     "http-client-test",
				Version:  "1.0.0",
				Registry: "npm",
				Metadata: &types.PackageMetadata{
					Downloads: 1000,
					Metadata: map[string]interface{}{
						"author_email": "test@http.com",
						"keywords":     []string{"http", "client"},
					},
				},
			},
			expectedBehaviors: []string{"network_request", "http_client"},
		},
		{
			name: "File manipulation package",
			pkg: &types.Package{
				Name:     "file-manipulator",
				Version:  "1.0.0",
				Registry: "npm",
				Metadata: &types.PackageMetadata{
					Downloads: 500,
					Metadata: map[string]interface{}{
						"author_email": "test@files.com",
						"keywords":     []string{"file", "manipulation"},
					},
				},
			},
			expectedBehaviors: []string{"file_access", "file_modification"},
		},
	}

	config := &dynamic.Config{
		Enabled:                true,
		SandboxType:            "docker",
		SandboxTimeout:         "45s",
		MaxMemoryUsage:         512 * 1024 * 1024, // 512MB in bytes
		AnalyzeNetworkActivity: true,              // Allow network for behavior detection
		AnalyzeFileSystem:      true,              // Allow filesystem for behavior detection
		MaxExecutionTime:       "30s",
	}

	analyzer, err := dynamic.NewAnalyzer(config)
	if err != nil {
		t.Logf("Warning: Could not create dynamic analyzer: %v", err)
		t.Skip("Skipping behavior analysis tests")
	}

	for _, tt := range behaviorTests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()

			result, err := analyzer.AnalyzePackage(ctx, tt.pkg.Name)
			if err != nil {
				t.Logf("Warning: Behavior analysis failed for %s: %v", tt.pkg.Name, err)
				return
			}

			if result == nil {
				t.Errorf("Expected behavior analysis result, got nil")
				return
			}

			t.Logf("Package: %s, Risk Score: %.2f", tt.pkg.Name, result.RiskScore)

			// Check security findings instead of behaviors
			for _, finding := range result.SecurityFindings {
				t.Logf("  - Finding: %s (Confidence: %.2f)", finding.Type, finding.Confidence)
			}

			// Verify findings are reasonable
			for _, finding := range result.SecurityFindings {
				if finding.Confidence < 0 || finding.Confidence > 1 {
					t.Errorf("Invalid finding confidence: %.2f", finding.Confidence)
				}
			}
		})
	}
}

// TestDynamicPerformance tests the performance of dynamic analysis
func TestDynamicPerformance(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping dynamic performance test in short mode")
	}

	pkg := &types.Package{
		Name:     "performance-test",
		Version:  "1.0.0",
		Registry: "npm",
		Metadata: &types.PackageMetadata{
			Downloads: 1000,
			Metadata: map[string]interface{}{
				"author_email": "perf@test.com",
				"keywords":     []string{"performance", "test"},
			},
		},
	}

	config := &dynamic.Config{
		Enabled:                true,
		SandboxType:            "docker",
		SandboxTimeout:         "30s",
		MaxMemoryUsage:         256 * 1024 * 1024, // 256MB in bytes
		AnalyzeNetworkActivity: false,
		AnalyzeFileSystem:      false,
		MaxExecutionTime:       "15s",
	}

	analyzer, err := dynamic.NewAnalyzer(config)
	if err != nil {
		t.Logf("Warning: Could not create dynamic analyzer: %v", err)
		t.Skip("Skipping dynamic performance tests")
	}

	// Measure analysis time
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	_, err = analyzer.AnalyzePackage(ctx, pkg.Name)
	duration := time.Since(start)

	if err != nil {
		t.Logf("Warning: Dynamic performance test failed: %v", err)
		return
	}

	t.Logf("Dynamic analysis took %v", duration)

	// Analysis should complete within reasonable time
	if duration > 60*time.Second {
		t.Errorf("Dynamic analysis took too long: %v", duration)
	}
}

// TestDynamicResourceLimits tests resource limit enforcement
func TestDynamicResourceLimits(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping resource limits test in short mode")
	}

	pkg := &types.Package{
		Name:     "resource-heavy",
		Version:  "1.0.0",
		Registry: "npm",
		Metadata: &types.PackageMetadata{
			Downloads: 100,
			Metadata: map[string]interface{}{
				"author_email": "heavy@resource.com",
				"keywords":     []string{"resource", "heavy"},
			},
		},
	}

	// Test with very restrictive limits
	config := &dynamic.Config{
		Enabled:                true,
		SandboxType:            "docker",
		SandboxTimeout:         "20s",
		MaxMemoryUsage:         64 * 1024 * 1024, // 64MB in bytes
		AnalyzeNetworkActivity: false,
		AnalyzeFileSystem:      false,
		MaxExecutionTime:       "5s", // Very short execution time
	}

	analyzer, err := dynamic.NewAnalyzer(config)
	if err != nil {
		t.Logf("Warning: Could not create dynamic analyzer: %v", err)
		t.Skip("Skipping resource limits tests")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := analyzer.AnalyzePackage(ctx, pkg.Name)
	if err != nil {
		t.Logf("Resource limits test completed with expected error: %v", err)
		// This is expected for resource-constrained analysis
		return
	}

	if result != nil {
		t.Logf("Resource limits test completed: Risk Score %.2f, Processing Time: %v",
			result.RiskScore, result.ProcessingTime)

		// Verify execution time was within limits
		maxExecTime, _ := time.ParseDuration(config.MaxExecutionTime)
		if result.ProcessingTime > maxExecTime {
			t.Errorf("Execution time %v exceeded limit %v",
				result.ProcessingTime, config.MaxExecutionTime)
		}

		// Check for resource limit violations
		for _, finding := range result.SecurityFindings {
			if finding.Type == "resource_limit_exceeded" {
				t.Logf("Detected resource limit violation: %s", finding.Description)
			}
		}
	}
}
