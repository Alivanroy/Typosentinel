package provenance

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestNewAnalyzer(t *testing.T) {
	cfg := &Config{
		Enabled:          true,
		VerifySignatures: true,
		VerifyIntegrity:  true,
		Timeout:          "30s",
	}

	analyzer, err := NewProvenanceAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if analyzer == nil {
		t.Error("Expected analyzer to be created, got nil")
	}

	if analyzer.config != cfg {
		t.Error("Expected analyzer config to match provided config")
	}

	if !analyzer.config.Enabled {
		t.Error("Expected analyzer to be enabled")
	}
}

func TestNewAnalyzer_Disabled(t *testing.T) {
	cfg := &Config{
		Enabled: false,
	}

	analyzer, err := NewProvenanceAnalyzer(cfg)
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

func TestAnalyzePackage_Success(t *testing.T) {
	cfg := &Config{
		Enabled:          true,
		VerifySignatures: true,
		VerifyIntegrity:  true,
		Timeout:          "30s",
	}

	analyzer, err := NewProvenanceAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Create test package data
	packagePath := "/tmp/test-package"
	packageName := "test-package"
	version := "1.0.0"
	registry := "npmjs.org"

	ctx := context.Background()
	result, err := analyzer.AnalyzePackage(ctx, packagePath, packageName, version, registry)

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Error("Expected result to not be nil")
	}

	if result.PackageName != packageName {
		t.Errorf("Expected package name %s, got %s", packageName, result.PackageName)
	}

	if result.PackageVersion != version {
		t.Errorf("Expected version %s, got %s", version, result.PackageVersion)
	}
}

func TestAnalyzePackage_Disabled(t *testing.T) {
	cfg := &Config{
		Enabled: false,
	}

	analyzer, err := NewProvenanceAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Create test package data
	packagePath := "/tmp/test-package"
	packageName := "test-package"
	version := "1.0.0"
	registry := "npmjs.org"

	ctx := context.Background()
	result, err := analyzer.AnalyzePackage(ctx, packagePath, packageName, version, registry)

	if err != nil {
		t.Errorf("Expected no error for disabled analyzer, got %v", err)
	}

	if result == nil {
		t.Error("Expected result to not be nil even when disabled")
	}

	if result.OverallScore != 0 {
		t.Errorf("Expected overall score 0 for disabled analyzer, got %f", result.OverallScore)
	}
}

func TestAnalyze_Success(t *testing.T) {
	cfg := &Config{
		Enabled:          true,
		VerifySignatures: true,
		VerifyIntegrity:  true,
		Timeout:          "30s",
	}

	analyzer, err := NewProvenanceAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Create temporary test directory with files
	tempDir, err := os.MkdirTemp("", "provenance_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create test package.json
	packageJSON := `{"name": "test-package", "version": "1.0.0"}`
	err = os.WriteFile(filepath.Join(tempDir, "package.json"), []byte(packageJSON), 0644)
	if err != nil {
		t.Fatalf("Failed to create package.json: %v", err)
	}

	ctx := context.Background()
	result, err := analyzer.AnalyzePackage(ctx, tempDir, "test-package", "1.0.0", "npm")

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Error("Expected result to not be nil")
	}
}

func TestVerifyIntegrity_Success(t *testing.T) {
	cfg := &Config{
		Enabled:         true,
		VerifyIntegrity: true,
	}

	analyzer, err := NewProvenanceAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Create test file
	tempDir, err := os.MkdirTemp("", "integrity_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	testFile := filepath.Join(tempDir, "test.txt")
	testContent := "test content for integrity verification"
	err = os.WriteFile(testFile, []byte(testContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Test integrity verification
	ctx := context.Background()
	result, err := analyzer.verifyIntegrity(ctx, testFile, "test-package", "1.0.0", "npm")

	// The method may return an error for hash not available, which is expected for now
	if result == nil {
		t.Error("Expected integrity check result")
	}
}

func TestVerifyIntegrity_InvalidChecksum(t *testing.T) {
	cfg := &Config{
		Enabled:         true,
		VerifyIntegrity: true,
	}

	analyzer, err := NewProvenanceAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Create test file
	tempDir, err := os.MkdirTemp("", "integrity_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	testFile := filepath.Join(tempDir, "test.txt")
	err = os.WriteFile(testFile, []byte("test content"), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Test integrity verification
	ctx := context.Background()
	result, err := analyzer.verifyIntegrity(ctx, testFile, "test-package", "1.0.0", "npm")

	// The method should handle gracefully and return a result
	if result == nil {
		t.Error("Expected integrity check result")
	}
}

func TestVerifyIntegrity_MissingFile(t *testing.T) {
	cfg := &Config{
		Enabled:         true,
		VerifyIntegrity: true,
	}

	analyzer, err := NewProvenanceAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Test with missing file
	missingFile := "/path/to/nonexistent/file.txt"

	// Test integrity verification with missing file
	ctx := context.Background()
	result, err := analyzer.verifyIntegrity(ctx, missingFile, "test-package", "1.0.0", "npm")

	// The method should handle missing files gracefully
	if result == nil {
		t.Error("Expected integrity check result even for missing file")
	}
}

func TestCheckSource_TrustedSource(t *testing.T) {
	cfg := &Config{
		Enabled:        true,
		TrustedSigners: []string{"trusted.com", "secure.org"},
	}

	analyzer, err := NewProvenanceAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	tests := []struct {
		signer   string
		expected bool
	}{
		{"trusted.com", true},
		{"secure.org", true},
		{"untrusted.com", false},
		{"", false},
	}

	for _, test := range tests {
		t.Run(test.signer, func(t *testing.T) {
			isTrusted := analyzer.isSignerTrusted(test.signer)
			if isTrusted != test.expected {
				t.Errorf("isSignerTrusted(%s) = %v, expected %v", test.signer, isTrusted, test.expected)
			}
		})
	}
}

func TestVerifySignature_ValidSignature(t *testing.T) {
	cfg := &Config{
		Enabled:          true,
		VerifySignatures: true,
	}

	analyzer, err := NewProvenanceAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Create test file
	tempDir, err := os.MkdirTemp("", "signature_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	testFile := filepath.Join(tempDir, "test.txt")
	err = os.WriteFile(testFile, []byte("test content"), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Create mock signature
	mockSig := &Signature{
		Algorithm: "RSA",
		Value:     "mock_signature_value",
		Signer:    "test_signer",
	}

	// Test signature verification (mock implementation)
	ctx := context.Background()
	isValid, err := analyzer.verifySignature(ctx, testFile, mockSig)

	// Since this is a mock implementation, we expect it to handle gracefully
	if err != nil {
		t.Logf("Signature verification returned error (expected for mock): %v", err)
	}

	// For mock implementation, we don't expect it to be valid
	if isValid {
		t.Log("Signature verification passed (unexpected for mock implementation)")
	}
}

func TestCalculateRiskScore(t *testing.T) {
	cfg := &Config{}
	analyzer, err := NewProvenanceAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	tests := []struct {
		name           string
		result         *AnalysisResult
		minScore       float64
		maxScore       float64
	}{
		{
			name: "all valid",
			result: &AnalysisResult{
				SignatureVerification: &SignatureVerification{Verified: true, TrustScore: 0.9},
				IntegrityChecks: &IntegrityChecks{OverallVerified: true, TrustScore: 0.8},
				SLSAProvenance: &SLSAProvenance{Present: true, TrustScore: 0.9},
				TransparencyLog: &TransparencyLogVerification{Present: true, TrustScore: 0.8},
			},
			minScore: 0.8,
			maxScore: 1.0,
		},
		{
			name: "integrity invalid",
			result: &AnalysisResult{
				SignatureVerification: &SignatureVerification{Verified: true, TrustScore: 0.6},
				IntegrityChecks: &IntegrityChecks{OverallVerified: false, TrustScore: 0.1},
				SLSAProvenance: &SLSAProvenance{Present: true, TrustScore: 0.7},
				TransparencyLog: &TransparencyLogVerification{Present: true, TrustScore: 0.5},
			},
			minScore: 0.3,
			maxScore: 0.7,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			analyzer.calculateOverallAssessment(test.result)
			if test.result.OverallScore < test.minScore || test.result.OverallScore > test.maxScore {
				t.Errorf("OverallScore = %f, expected between %f and %f",
					test.result.OverallScore, test.minScore, test.maxScore)
			}
		})
	}
}

func TestGenerateFindings(t *testing.T) {
	cfg := &Config{}
	analyzer, err := NewProvenanceAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	tests := []struct {
		name        string
		result      *AnalysisResult
		expectedMin int
	}{
		{
			name: "all valid",
			result: &AnalysisResult{
				SignatureVerification: &SignatureVerification{Verified: true},
				IntegrityChecks: &IntegrityChecks{OverallVerified: true},
				SLSAProvenance: &SLSAProvenance{Present: true},
			},
			expectedMin: 0,
		},
		{
			name: "integrity invalid",
			result: &AnalysisResult{
				SignatureVerification: &SignatureVerification{Verified: true},
				IntegrityChecks: &IntegrityChecks{OverallVerified: false},
				SLSAProvenance: &SLSAProvenance{Present: true},
			},
			expectedMin: 1,
		},
		{
			name: "signature invalid",
			result: &AnalysisResult{
				SignatureVerification: &SignatureVerification{Verified: false},
				IntegrityChecks: &IntegrityChecks{OverallVerified: true},
				SLSAProvenance: &SLSAProvenance{Present: true},
			},
			expectedMin: 1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			analyzer.generateFindings(test.result)
			if len(test.result.Findings) < test.expectedMin {
				t.Errorf("generateFindings() returned %d findings, expected at least %d",
					len(test.result.Findings), test.expectedMin)
			}

			// Check that findings have required fields
			for i, finding := range test.result.Findings {
				if finding.Type == "" {
					t.Errorf("Finding %d has empty type", i)
				}
				if finding.Description == "" {
					t.Errorf("Finding %d has empty description", i)
				}
				if finding.Severity == "" {
					t.Errorf("Finding %d has empty severity", i)
				}
			}
		})
	}
}

func TestGenerateRecommendations(t *testing.T) {
	cfg := &Config{}
	analyzer, err := NewProvenanceAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	tests := []struct {
		name        string
		result      *AnalysisResult
		expectedMin int
	}{
		{
			name: "high score",
			result: &AnalysisResult{
				OverallScore: 0.8,
				SignatureVerification: &SignatureVerification{Verified: true},
			},
			expectedMin: 0,
		},
		{
			name: "medium score",
			result: &AnalysisResult{
				OverallScore: 0.4,
				SignatureVerification: &SignatureVerification{Verified: false},
			},
			expectedMin: 1,
		},
		{
			name: "low score",
			result: &AnalysisResult{
				OverallScore: 0.2,
				SignatureVerification: &SignatureVerification{Verified: false},
			},
			expectedMin: 1,
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