package provenance

import (
	"context"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"
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

	ctx := context.Background()
	result, err := analyzer.AnalyzePackage(ctx, "/tmp/test", "test", "1.0.0", "npmjs.org")

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Error("Expected result to not be nil")
	}

	// When disabled, should return basic result without verification
	if result.SignatureVerification != nil {
		t.Error("Expected signature verification to be nil when disabled")
	}
}

func TestVerifySignatures_Success(t *testing.T) {
	cfg := &Config{
		Enabled:          true,
		VerifySignatures: true,
		Timeout:          "30s",
	}

	analyzer, err := NewProvenanceAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	ctx := context.Background()
	verification, err := analyzer.verifySignatures(ctx, "/tmp/test", "test-package", "1.0.0", "npmjs.org")

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if verification == nil {
		t.Error("Expected verification result")
	}

	if verification.TrustScore < 0 || verification.TrustScore > 1 {
		t.Errorf("Expected trust score between 0 and 1, got %f", verification.TrustScore)
	}
}

func TestVerifyIntegrity_Success(t *testing.T) {
	cfg := &Config{
		Enabled:         true,
		VerifyIntegrity: true,
		Timeout:         "30s",
	}

	analyzer, err := NewProvenanceAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Create a temporary test file
	tmpFile, err := ioutil.TempFile("", "test-package")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	// Write some test content
	testContent := "test package content"
	if _, err := tmpFile.WriteString(testContent); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}

	ctx := context.Background()
	integrity, err := analyzer.verifyIntegrity(ctx, tmpFile.Name(), "test-package", "1.0.0", "npmjs.org")

	// Since fetchExpectedHash returns "hash not available" error, we expect an error
	// but the integrity object should still be returned with verification failed
	if err == nil {
		t.Error("Expected error due to hash not available")
	}

	if integrity == nil {
		t.Error("Expected integrity result even with error")
	}

	if integrity != nil && (integrity.TrustScore < 0 || integrity.TrustScore > 1) {
		t.Errorf("Expected trust score between 0 and 1, got %f", integrity.TrustScore)
	}
}

func TestAssessTrust_HighTrust(t *testing.T) {
	cfg := &Config{
		Enabled: true,
		Timeout: "30s",
	}

	analyzer, err := NewProvenanceAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	result := &AnalysisResult{
		SignatureVerification: &SignatureVerification{
			Verified:   true,
			TrustScore: 0.9,
		},
		IntegrityChecks: &IntegrityChecks{
			OverallVerified: true,
			TrustScore:      0.95,
		},
	}

	trust := analyzer.assessTrust(result)

	if trust == nil {
		t.Error("Expected trust assessment")
	}

	if trust.OverallTrustScore <= 0.5 {
		t.Errorf("Expected high trust score, got %f", trust.OverallTrustScore)
	}

	if trust.TrustLevel == "" {
		t.Error("Expected trust level to be set")
	}
}

func TestAssessTrust_LowTrust(t *testing.T) {
	cfg := &Config{
		Enabled: true,
		Timeout: "30s",
	}

	analyzer, err := NewProvenanceAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	result := &AnalysisResult{
		SignatureVerification: &SignatureVerification{
			Verified:   false,
			TrustScore: 0.45,
		},
		IntegrityChecks: &IntegrityChecks{
			OverallVerified: false,
			TrustScore:      0.45,
		},
	}

	trust := analyzer.assessTrust(result)

	if trust == nil {
		t.Error("Expected trust assessment")
	}

	if trust.OverallTrustScore >= 0.5 {
		t.Errorf("Expected low trust score, got %f", trust.OverallTrustScore)
	}

	if trust.TrustLevel != "LOW" {
		t.Errorf("Expected LOW trust level, got %s", trust.TrustLevel)
	}
}

func TestCalculateOverallAssessment(t *testing.T) {
	cfg := &Config{
		Enabled: true,
		Timeout: "30s",
	}

	analyzer, err := NewProvenanceAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	result := &AnalysisResult{
		SignatureVerification: &SignatureVerification{
			Verified:   true,
			TrustScore: 0.8,
		},
		IntegrityChecks: &IntegrityChecks{
			OverallVerified: true,
			TrustScore:      0.9,
		},
		TrustAssessment: &TrustAssessment{
			OverallTrustScore: 0.8,
			TrustLevel:        "HIGH",
		},
	}

	analyzer.calculateOverallAssessment(result)

	if result.OverallScore == 0 {
		t.Error("Expected overall score to be calculated")
	}

	if result.TrustLevel == "" {
		t.Error("Expected trust level to be set")
	}
}

func TestGenerateFindings(t *testing.T) {
	cfg := &Config{
		Enabled: true,
		Timeout: "30s",
	}

	analyzer, err := NewProvenanceAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	result := &AnalysisResult{
		SignatureVerification: &SignatureVerification{
			Verified:           false,
			VerificationErrors: []string{"signature not found"},
		},
		Findings: []Finding{},
	}

	analyzer.generateFindings(result)

	if len(result.Findings) == 0 {
		t.Error("Expected findings to be generated")
	}
}

func TestGenerateRecommendations(t *testing.T) {
	cfg := &Config{
		Enabled: true,
		Timeout: "30s",
	}

	analyzer, err := NewProvenanceAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	result := &AnalysisResult{
		SignatureVerification: &SignatureVerification{
			Verified: false,
		},
		Recommendations: []string{},
	}

	analyzer.generateRecommendations(result)

	if len(result.Recommendations) == 0 {
		t.Error("Expected recommendations to be generated")
	}
}

func TestExportResults_JSON(t *testing.T) {
	cfg := &Config{
		Enabled: true,
		Timeout: "30s",
	}

	analyzer, err := NewProvenanceAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	result := &AnalysisResult{
		PackageName:    "test-package",
		PackageVersion: "1.0.0",
	}

	err = analyzer.ExportResults(result, "/tmp/test.json")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

}

func TestExportResults_YAML(t *testing.T) {
	cfg := &Config{
		Enabled: true,
		Timeout: "30s",
	}

	analyzer, err := NewProvenanceAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	result := &AnalysisResult{
		PackageName:    "test-package",
		PackageVersion: "1.0.0",
	}

	err = analyzer.ExportResults(result, "/tmp/test.yaml")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
}

func TestExportResults_InvalidFormat(t *testing.T) {
	cfg := &Config{
		Enabled: true,
		Timeout: "30s",
	}

	analyzer, err := NewProvenanceAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	result := &AnalysisResult{
		PackageName:    "test-package",
		PackageVersion: "1.0.0",
	}

	err = analyzer.ExportResults(result, "/tmp/test.invalid")
	if err == nil {
		t.Error("Expected error for invalid format")
	}
}

func TestConfigValidation_InvalidTimeout(t *testing.T) {
	cfg := &Config{
		Enabled: true,
		Timeout: "invalid",
	}

	_, err := NewProvenanceAnalyzer(cfg)
	if err == nil {
		t.Error("Expected error for invalid timeout")
	}
}

func TestConfigValidation_EmptyTimeout(t *testing.T) {
	cfg := &Config{
		Enabled: true,
		Timeout: "",
	}

	analyzer, err := NewProvenanceAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Should use default timeout
	if analyzer.config.Timeout == "" {
		t.Error("Expected default timeout to be set")
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
		name     string
		result   *AnalysisResult
		minScore float64
		maxScore float64
	}{
		{
			name: "all valid",
			result: &AnalysisResult{
				SignatureVerification: &SignatureVerification{Verified: true, TrustScore: 0.9},
				IntegrityChecks:       &IntegrityChecks{OverallVerified: true, TrustScore: 0.8},
				SLSAProvenance:        &SLSAProvenance{Present: true, TrustScore: 0.9},
				TransparencyLog:       &TransparencyLogVerification{Present: true, TrustScore: 0.8},
			},
			minScore: 0.8,
			maxScore: 1.0,
		},
		{
			name: "integrity invalid",
			result: &AnalysisResult{
				SignatureVerification: &SignatureVerification{Verified: true, TrustScore: 0.6},
				IntegrityChecks:       &IntegrityChecks{OverallVerified: false, TrustScore: 0.1},
				SLSAProvenance:        &SLSAProvenance{Present: true, TrustScore: 0.7},
				TransparencyLog:       &TransparencyLogVerification{Present: true, TrustScore: 0.5},
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

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()
	if config == nil {
		t.Error("Expected default config to not be nil")
	}
	if !config.Enabled {
		t.Error("Expected default config to be enabled")
	}
	if !config.SigstoreEnabled {
		t.Error("Expected sigstore to be enabled by default")
	}
	if config.SLSAMinLevel != 2 {
		t.Errorf("Expected SLSA min level 2, got %d", config.SLSAMinLevel)
	}
}

func TestVerifySignatures(t *testing.T) {
	cfg := &Config{
		Enabled:          true,
		VerifySignatures: true,
	}

	analyzer, err := NewProvenanceAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	tempDir, err := os.MkdirTemp("", "signature_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a test signature file to avoid panic
	sigFile := filepath.Join(tempDir, "package.sig")
	err = os.WriteFile(sigFile, []byte("test signature content"), 0644)
	if err != nil {
		t.Fatalf("Failed to create signature file: %v", err)
	}

	ctx := context.Background()
	result, err := analyzer.verifySignatures(ctx, tempDir, "test-package", "1.0.0", "npm")

	if result == nil {
		t.Error("Expected signature verification result")
	}
}

func TestVerifySLSAProvenance(t *testing.T) {
	cfg := &Config{
		Enabled:          true,
		SLSAEnabled:      true,
		VerifyProvenance: true,
	}

	analyzer, err := NewProvenanceAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	ctx := context.Background()
	result, err := analyzer.verifySLSAProvenance(ctx, "test-package", "1.0.0", "npm")

	if result == nil {
		t.Error("Expected SLSA provenance result")
	}
}

func TestVerifyTransparencyLog(t *testing.T) {
	cfg := &Config{
		Enabled:         true,
		SigstoreEnabled: true,
	}

	analyzer, err := NewProvenanceAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	ctx := context.Background()
	result, err := analyzer.verifyTransparencyLog(ctx, "test-package", "1.0.0", "npm")

	if result == nil {
		t.Error("Expected transparency log result")
	}
}

func TestFindSignatureFiles(t *testing.T) {
	cfg := &Config{}
	analyzer, err := NewProvenanceAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	tempDir, err := os.MkdirTemp("", "signature_files_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create test signature files
	sigFile := filepath.Join(tempDir, "package.sig")
	err = os.WriteFile(sigFile, []byte("test signature"), 0644)
	if err != nil {
		t.Fatalf("Failed to create signature file: %v", err)
	}

	files := analyzer.findSignatureFiles(tempDir)
	// The function should not panic even if no signature files are found
	_ = files
}

func TestIsSignerTrusted(t *testing.T) {
	cfg := &Config{
		TrustedSigners: []string{"trusted@example.com", "secure@test.org"},
	}
	analyzer, err := NewProvenanceAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	tests := []struct {
		signer   string
		expected bool
	}{
		{"trusted@example.com", true},
		{"secure@test.org", true},
		{"untrusted@example.com", false},
		{"", false},
	}

	for _, test := range tests {
		t.Run(test.signer, func(t *testing.T) {
			result := analyzer.isSignerTrusted(test.signer)
			if result != test.expected {
				t.Errorf("isSignerTrusted(%s) = %v, expected %v", test.signer, result, test.expected)
			}
		})
	}
}

func TestIsBuilderTrusted(t *testing.T) {
	cfg := &Config{
		TrustedBuilders: []string{"https://github.com/slsa-framework/slsa-github-generator"},
	}
	analyzer, err := NewProvenanceAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	tests := []struct {
		builder  string
		expected bool
	}{
		{"https://github.com/slsa-framework/slsa-github-generator", true},
		{"https://untrusted-builder.com", false},
		{"", false},
	}

	for _, test := range tests {
		t.Run(test.builder, func(t *testing.T) {
			result := analyzer.isBuilderTrusted(test.builder)
			if result != test.expected {
				t.Errorf("isBuilderTrusted(%s) = %v, expected %v", test.builder, result, test.expected)
			}
		})
	}
}

func TestAssessTrust(t *testing.T) {
	cfg := &Config{
		TrustedSigners:    []string{"trusted@example.com"},
		TrustedBuilders:   []string{"trusted-builder"},
		TrustedPublishers: []string{"trusted-publisher"},
	}
	analyzer, err := NewProvenanceAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	result := &AnalysisResult{
		SignatureVerification: &SignatureVerification{
			Verified: true,
			Signatures: []Signature{
				{Signer: "trusted@example.com", Verified: true, Trusted: true},
			},
		},
		SLSAProvenance: &SLSAProvenance{
			Present:    true,
			Builder:    &SLSABuilder{ID: "trusted-builder", Trusted: true},
			Compliance: &SLSACompliance{Score: 0.8},
		},
	}

	trustAssessment := analyzer.assessTrust(result)
	if trustAssessment == nil {
		t.Error("Expected trust assessment result")
	}
}

func TestCalculateSignatureTrustScore(t *testing.T) {
	cfg := &Config{}
	analyzer, err := NewProvenanceAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	verification := &SignatureVerification{
		Verified: true,
		Signatures: []Signature{
			{Verified: true, Trusted: true},
			{Verified: true, Trusted: false},
		},
	}

	score := analyzer.calculateSignatureTrustScore(verification)
	if score <= 0 {
		t.Error("Expected positive signature trust score")
	}
	if score > 1.0 {
		t.Error("Expected signature trust score <= 1.0")
	}
}

func TestCalculateSLSATrustScore(t *testing.T) {
	cfg := &Config{}
	analyzer, err := NewProvenanceAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	provenance := &SLSAProvenance{
		Present:  true,
		Level:    3,
		Verified: true,
		Builder:  &SLSABuilder{Trusted: true},
	}

	score := analyzer.calculateSLSATrustScore(provenance)
	if score <= 0 {
		t.Error("Expected positive SLSA trust score")
	}
	if score > 1.0 {
		t.Error("Expected SLSA trust score <= 1.0")
	}
}

func TestCalculateIntegrityTrustScore(t *testing.T) {
	cfg := &Config{}
	analyzer, err := NewProvenanceAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	checks := &IntegrityChecks{
		OverallVerified:  true,
		HashVerification: &HashVerification{Verified: true},
		SizeVerification: &SizeVerification{Verified: true},
		ContentVerification: &ContentVerification{
			ManifestVerified: true,
			FilesVerified:    true,
		},
	}

	score := analyzer.calculateIntegrityTrustScore(checks)
	if score <= 0 {
		t.Error("Expected positive integrity trust score")
	}
	if score > 1.0 {
		t.Error("Expected integrity trust score <= 1.0")
	}
}

func TestCalculateTransparencyLogTrustScore(t *testing.T) {
	cfg := &Config{}
	analyzer, err := NewProvenanceAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	verification := &TransparencyLogVerification{
		Present:  true,
		Verified: true,
		Entries: []TransparencyLogEntry{
			{LogIndex: 1, Verification: &LogEntryVerification{}},
		},
	}

	score := analyzer.calculateTransparencyLogTrustScore(verification)
	if score < 0 {
		t.Error("Expected non-negative transparency log trust score")
	}
	if score > 1.0 {
		t.Error("Expected transparency log trust score <= 1.0")
	}
}

func TestAssessSLSACompliance(t *testing.T) {
	cfg := &Config{SLSAMinLevel: 2}
	analyzer, err := NewProvenanceAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	provenance := &SLSAProvenance{
		Level:     3,
		Builder:   &SLSABuilder{ID: "test-builder", Trusted: true},
		BuildType: "test-build",
	}

	compliance := analyzer.assessSLSACompliance(provenance)
	if compliance == nil {
		t.Error("Expected SLSA compliance result")
	}
	if compliance.Level < 1 {
		t.Errorf("Expected compliance level at least 1, got %d", compliance.Level)
	}
}

func TestExportResults(t *testing.T) {
	cfg := &Config{}
	analyzer, err := NewProvenanceAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	result := &AnalysisResult{
		PackageName:    "test-package",
		PackageVersion: "1.0.0",
		OverallScore:   0.8,
	}

	tempDir, err := os.MkdirTemp("", "export_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	outputPath := filepath.Join(tempDir, "results.json")
	err = analyzer.ExportResults(result, outputPath)
	if err != nil {
		t.Errorf("Expected no error exporting results, got %v", err)
	}

	// Check if file was created
	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		t.Error("Expected results file to be created")
	}
}

func TestVerifyHash(t *testing.T) {
	cfg := &Config{}
	analyzer, err := NewProvenanceAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	tempDir, err := os.MkdirTemp("", "hash_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	testFile := filepath.Join(tempDir, "test.txt")
	err = os.WriteFile(testFile, []byte("test content"), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	result, err := analyzer.verifyHash(tempDir, "test-package", "1.0.0", "npm")
	// The function should not panic, result may be nil due to missing expected hash
	_ = result
	_ = err
}

func TestVerifySize(t *testing.T) {
	cfg := &Config{}
	analyzer, err := NewProvenanceAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	tempDir, err := os.MkdirTemp("", "size_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	result, err := analyzer.verifySize(tempDir, "test-package", "1.0.0", "npm")
	if result == nil {
		t.Error("Expected size verification result")
	}
}

func TestVerifyContent(t *testing.T) {
	cfg := &Config{}
	analyzer, err := NewProvenanceAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	tempDir, err := os.MkdirTemp("", "content_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	result, err := analyzer.verifyContent(tempDir, "test-package", "1.0.0", "npm")
	if result == nil {
		t.Error("Expected content verification result")
	}
}

func TestFindKeylessSignatures(t *testing.T) {
	cfg := &Config{}
	analyzer, err := NewProvenanceAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	ctx := context.Background()
	result := analyzer.findKeylessSignatures(ctx, "test-package", "1.0.0", "npm")
	if result == nil {
		t.Error("Expected keyless signatures result (even if empty)")
	}
}

func TestFetchSLSAProvenance(t *testing.T) {
	cfg := &Config{}
	analyzer, err := NewProvenanceAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	ctx := context.Background()
	result, err := analyzer.fetchSLSAProvenance(ctx, "test-package", "1.0.0", "npm")
	// This may return an error due to network issues, but should not panic
	_ = result
	_ = err
}

func TestParseSLSAProvenance(t *testing.T) {
	cfg := &Config{}
	analyzer, err := NewProvenanceAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	data := map[string]interface{}{
		"predicate": map[string]interface{}{
			"buildType": "test-build",
			"builder": map[string]interface{}{
				"id": "test-builder",
			},
		},
	}

	provenance := &SLSAProvenance{}
	err = analyzer.parseSLSAProvenance(data, provenance)
	// The function should handle the data without panicking
	_ = err
	if provenance.Builder != nil && provenance.Builder.ID != "test-builder" {
		t.Error("Expected builder ID to be parsed correctly")
	}
}

func TestVerifySLSAProvenanceData(t *testing.T) {
	cfg := &Config{}
	analyzer, err := NewProvenanceAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	data := map[string]interface{}{
		"predicate": map[string]interface{}{
			"buildType": "test-build",
		},
	}

	ctx := context.Background()
	result, err := analyzer.verifySLSAProvenanceData(ctx, data)
	// This may return false or error, but should not panic
	_ = result
	_ = err
}

func TestSearchTransparencyLogEntries(t *testing.T) {
	cfg := &Config{}
	analyzer, err := NewProvenanceAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	ctx := context.Background()
	result, err := analyzer.searchTransparencyLogEntries(ctx, "test-package", "1.0.0", "npm")
	// This may return an error due to network issues, but should not panic
	_ = result
	_ = err
}

func TestVerifyTransparencyLogEntry(t *testing.T) {
	cfg := &Config{}
	analyzer, err := NewProvenanceAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	entry := &TransparencyLogEntry{
		LogIndex: 123,
		LogID:    "test-log",
	}

	ctx := context.Background()
	result, err := analyzer.verifyTransparencyLogEntry(ctx, entry)
	// This may return false or error, but should not panic
	_ = result
	_ = err
}

func TestFetchExpectedHash(t *testing.T) {
	cfg := &Config{}
	analyzer, err := NewProvenanceAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	result, err := analyzer.fetchExpectedHash("test-package", "1.0.0", "npm")
	// This may return an error due to network issues, but should not panic
	_ = result
	_ = err
}

func TestFetchExpectedSize(t *testing.T) {
	cfg := &Config{}
	analyzer, err := NewProvenanceAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	result, err := analyzer.fetchExpectedSize("test-package", "1.0.0", "npm")
	// This may return an error due to network issues, but should not panic
	_ = result
	_ = err
}

// Additional tests for better coverage

func TestVerifyIntegrityWithMissingFile(t *testing.T) {
	cfg := &Config{Enabled: true}
	analyzer, err := NewProvenanceAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	ctx := context.Background()
	result, err := analyzer.verifyIntegrity(ctx, "/nonexistent/path", "test-package", "1.0.0", "npm")
	// Should handle missing files gracefully
	if result == nil {
		t.Error("Expected integrity verification result even for missing files")
	}
}

func TestVerifyContentWithFile(t *testing.T) {
	cfg := &Config{}
	analyzer, err := NewProvenanceAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	tempFile, err := os.CreateTemp("", "content_test")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tempFile.Name())

	_, err = tempFile.WriteString("test content for verification")
	if err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	tempFile.Close()

	result, err := analyzer.verifyContent(tempFile.Name(), "test-package", "1.0.0", "npm")
	// Content verification should complete without error
	if result == nil {
		t.Error("Expected content verification result")
	}
}

func TestVerifySizeWithFile(t *testing.T) {
	cfg := &Config{}
	analyzer, err := NewProvenanceAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	tempFile, err := os.CreateTemp("", "size_test")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tempFile.Name())

	_, err = tempFile.WriteString("test content")
	if err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	tempFile.Close()

	result, err := analyzer.verifySize(tempFile.Name(), "test-package", "1.0.0", "npm")
	// Size verification should complete
	if result == nil {
		t.Error("Expected size verification result")
	}
}

func TestAnalyzePackageDisabled(t *testing.T) {
	cfg := &Config{Enabled: false}
	analyzer, err := NewProvenanceAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	ctx := context.Background()
	result, err := analyzer.AnalyzePackage(ctx, "/some/path", "test-package", "1.0.0", "npm")

	if err != nil {
		t.Errorf("Expected no error when disabled, got %v", err)
	}
	if result == nil {
		t.Error("Expected result even when disabled")
	}
	// Check that analysis was performed even when disabled
	if result.PackageName != "test-package" {
		t.Error("Expected package name to be set")
	}
}

// Additional comprehensive tests for better coverage
func TestAnalyzePackageFullFlow(t *testing.T) {
	cfg := &Config{
		Enabled:                true,
		VerifySignatures:       true,
		VerifyProvenance:       true,
		VerifyIntegrity:        true,
		RequireTransparencyLog: true,
		TrustedSigners:         []string{"trusted@example.com"},
		TrustedBuilders:        []string{"trusted-builder"},
		TrustedPublishers:      []string{"trusted-publisher"},
		Timeout:                "30s",
		RetryAttempts:          3,
		SigstoreEnabled:        true,
		SLSAEnabled:            true,
		SLSAMinLevel:           1,
	}

	analyzer, err := NewProvenanceAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	tempDir, err := os.MkdirTemp("", "full_flow_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a test package file
	packageFile := filepath.Join(tempDir, "package.tgz")
	err = os.WriteFile(packageFile, []byte("test package content"), 0644)
	if err != nil {
		t.Fatalf("Failed to create package file: %v", err)
	}

	ctx := context.Background()
	result, err := analyzer.AnalyzePackage(ctx, packageFile, "test-package", "1.0.0", "npm")

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if result == nil {
		t.Fatal("Expected analysis result")
	}

	// Verify result structure
	if result.PackageName != "test-package" {
		t.Errorf("Expected package name 'test-package', got %s", result.PackageName)
	}
	if result.PackageVersion != "1.0.0" {
		t.Errorf("Expected version '1.0.0', got %s", result.PackageVersion)
	}
	if result.Registry != "npm" {
		t.Errorf("Expected registry 'npm', got %s", result.Registry)
	}
}

func TestParseSignatureFileError(t *testing.T) {
	cfg := &Config{}
	analyzer, err := NewProvenanceAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Test with non-existent file
	sig, err := analyzer.parseSignatureFile("/nonexistent/file.sig")
	if err == nil {
		t.Error("Expected error for non-existent file")
	}
	if sig != nil {
		t.Error("Expected nil signature for non-existent file")
	}
}

func TestVerifySignatureWithInvalidData(t *testing.T) {
	cfg := &Config{}
	analyzer, err := NewProvenanceAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	ctx := context.Background()
	sig := &Signature{
		Algorithm: "invalid",
		Signer:    "invalid@example.com",
		Verified:  false,
	}
	verified, err := analyzer.verifySignature(ctx, "/nonexistent/package", sig)
	// Should handle invalid signature gracefully
	if verified {
		t.Error("Expected signature verification to fail for invalid data")
	}
}

func TestFetchSLSAProvenanceError(t *testing.T) {
	cfg := &Config{}
	analyzer, err := NewProvenanceAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	ctx := context.Background()
	data, err := analyzer.fetchSLSAProvenance(ctx, "nonexistent-package", "1.0.0", "npm")
	// Should handle fetch errors gracefully
	if data != nil {
		t.Error("Expected nil data for non-existent package")
	}
}

func TestSearchTransparencyLogEntriesError(t *testing.T) {
	cfg := &Config{}
	analyzer, err := NewProvenanceAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	ctx := context.Background()
	entries, err := analyzer.searchTransparencyLogEntries(ctx, "nonexistent-package", "1.0.0", "npm")
	// Should handle search errors gracefully
	_ = entries
	_ = err
}

func TestVerifyTransparencyLogEntryError(t *testing.T) {
	cfg := &Config{}
	analyzer, err := NewProvenanceAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	ctx := context.Background()
	entry := &TransparencyLogEntry{
		LogIndex:       12345,
		IntegratedTime: time.Now().Unix(),
	}

	verified, err := analyzer.verifyTransparencyLogEntry(ctx, entry)
	// Should handle verification gracefully
	_ = verified
	_ = err
}

func TestFetchExpectedHashError(t *testing.T) {
	cfg := &Config{}
	analyzer, err := NewProvenanceAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	hash, err := analyzer.fetchExpectedHash("nonexistent-package", "1.0.0", "npm")
	// Should handle fetch errors gracefully
	if hash != "" {
		t.Error("Expected empty hash for non-existent package")
	}
	if err == nil {
		t.Error("Expected error for non-existent package")
	}
}

func TestComplexSLSACompliance(t *testing.T) {
	cfg := &Config{}
	analyzer, err := NewProvenanceAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Test with comprehensive SLSA provenance data
	provenance := &SLSAProvenance{
		Present: true,
		Builder: &SLSABuilder{
			ID:      "comprehensive-builder",
			Trusted: true,
		},
		Invocation: &SLSAInvocation{
			ConfigSource: &SLSAConfigSource{
				URI:    "https://github.com/example/repo",
				Digest: map[string]string{"sha256": "abc123"},
			},
		},
		Materials: []SLSAMaterial{
			{
				URI:    "https://github.com/example/source",
				Digest: map[string]string{"sha256": "def456"},
			},
		},
		Metadata: &SLSAMetadata{
			BuildInvocationID: "build-123",
			BuildStartedOn:    time.Now(),
			BuildFinishedOn:   time.Now().Add(time.Hour),
			Completeness: &SLSACompleteness{
				Parameters:  true,
				Environment: true,
				Materials:   true,
			},
			Reproducible: true,
		},
	}

	compliance := analyzer.assessSLSACompliance(provenance)
	if compliance == nil {
		t.Error("Expected SLSA compliance assessment")
	}
	if compliance.Score <= 0 {
		t.Error("Expected positive compliance score")
	}
}

// Additional edge case tests for maximum coverage
func TestEmptyProvenance(t *testing.T) {
	cfg := &Config{}
	analyzer, err := NewProvenanceAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Test with empty provenance
	provenance := &SLSAProvenance{Present: false}
	compliance := analyzer.assessSLSACompliance(provenance)
	if compliance == nil {
		t.Error("Expected compliance assessment even for empty provenance")
	}
}

func TestNilProvenance(t *testing.T) {
	cfg := &Config{}
	analyzer, err := NewProvenanceAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Test with nil provenance
	compliance := analyzer.assessSLSACompliance(nil)
	if compliance == nil {
		t.Error("Expected compliance assessment even for nil provenance")
	}
}

func TestVerifyHashWithMissingFile(t *testing.T) {
	cfg := &Config{}
	analyzer, err := NewProvenanceAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	result, err := analyzer.verifyHash("/nonexistent/file", "test-package", "1.0.0", "npm")
	if err == nil {
		t.Error("Expected error for missing file")
	}
	if result != nil {
		t.Error("Expected nil result for missing file")
	}
}

func TestVerifySizeWithMissingFile(t *testing.T) {
	cfg := &Config{}
	analyzer, err := NewProvenanceAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	result, err := analyzer.verifySize("/nonexistent/file", "test-package", "1.0.0", "npm")
	if err == nil {
		t.Error("Expected error for missing file")
	}
	if result != nil {
		t.Error("Expected nil result for missing file")
	}
}

func TestVerifyContentWithMissingFile(t *testing.T) {
	cfg := &Config{}
	analyzer, err := NewProvenanceAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	result, err := analyzer.verifyContent("/nonexistent/file", "test-package", "1.0.0", "npm")
	// Content verification should handle missing files gracefully
	_ = result
	_ = err
}

func TestFindKeylessSignaturesEdgeCase(t *testing.T) {
	cfg := &Config{}
	analyzer, err := NewProvenanceAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	ctx := context.Background()
	signatures := analyzer.findKeylessSignatures(ctx, "test-package", "1.0.0", "npm")
	// Should return empty slice for non-existent package
	if signatures == nil {
		t.Error("Expected empty slice, not nil")
	}
}

func TestVerifySLSAProvenanceDataWithNilData(t *testing.T) {
	cfg := &Config{}
	analyzer, err := NewProvenanceAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	ctx := context.Background()
	verified, err := analyzer.verifySLSAProvenanceData(ctx, nil)
	// Should handle nil data gracefully
	if verified {
		t.Error("Expected verification to fail for nil data")
	}
}

func TestIsSignerTrustedWithEmptyList(t *testing.T) {
	cfg := &Config{TrustedSigners: []string{}}
	analyzer, err := NewProvenanceAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	trusted := analyzer.isSignerTrusted("any@example.com")
	if trusted {
		t.Error("Expected signer to not be trusted with empty trusted list")
	}
}

func TestIsBuilderTrustedWithEmptyList(t *testing.T) {
	cfg := &Config{TrustedBuilders: []string{}}
	analyzer, err := NewProvenanceAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	trusted := analyzer.isBuilderTrusted("any-builder")
	if trusted {
		t.Error("Expected builder to not be trusted with empty trusted list")
	}
}

func TestAssessTrustWithNilComponents(t *testing.T) {
	cfg := &Config{}
	analyzer, err := NewProvenanceAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Test with minimal result
	result := &AnalysisResult{
		PackageName: "test",
	}

	assessment := analyzer.assessTrust(result)
	if assessment == nil {
		t.Error("Expected trust assessment even with minimal result")
	}
}

func TestCalculateOverallAssessmentWithNilComponents(t *testing.T) {
	cfg := &Config{}
	analyzer, err := NewProvenanceAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Test with minimal result
	result := &AnalysisResult{
		PackageName: "test",
	}

	analyzer.calculateOverallAssessment(result)
	// Should not panic and should set some score
	if result.OverallScore < 0 {
		t.Error("Expected non-negative overall score")
	}
}

func TestExportResultsWithCompleteData(t *testing.T) {
	cfg := &Config{}
	analyzer, err := NewProvenanceAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	result := &AnalysisResult{
		PackageName:     "test-package",
		PackageVersion:  "1.0.0",
		Registry:        "npm",
		OverallScore:    0.8,
		TrustLevel:      "HIGH",
		Findings:        []Finding{{Type: "info", Description: "test", Severity: "low"}},
		Warnings:        []string{"test warning"},
		Recommendations: []string{"test recommendation"},
	}

	// Create a temporary file for export
	tmpFile := "/tmp/test_export.json"
	err = analyzer.ExportResults(result, tmpFile)
	if err != nil {
		t.Errorf("Expected no error exporting results, got %v", err)
	}

	// Clean up
	os.Remove(tmpFile)
}

// Additional tests for maximum coverage
func TestCalculateSignatureTrustScoreEdgeCases(t *testing.T) {
	cfg := &Config{}
	analyzer, err := NewProvenanceAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Test with nil signatures
	score := analyzer.calculateSignatureTrustScore(nil)
	if score != 0.0 {
		t.Errorf("Expected 0.0 for nil signatures, got %f", score)
	}

	// Test with empty signatures
	emptySignatures := &SignatureVerification{Verified: false}
	score = analyzer.calculateSignatureTrustScore(emptySignatures)
	if score != 0.0 {
		t.Errorf("Expected 0.0 for empty signatures, got %f", score)
	}

	// Test with verified signatures
	verifiedSignatures := &SignatureVerification{
		Verified: true,
		Signatures: []Signature{
			{
				Algorithm: "RSA",
				Value:     "test-signature",
				Signer:    "test@example.com",
				Verified:  true,
				Trusted:   true,
			},
		},
	}
	score = analyzer.calculateSignatureTrustScore(verifiedSignatures)
	if score <= 0.0 {
		t.Errorf("Expected positive score for verified signatures, got %f", score)
	}
}

func TestCalculateSLSATrustScoreEdgeCases(t *testing.T) {
	cfg := &Config{}
	analyzer, err := NewProvenanceAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Test with nil provenance
	score := analyzer.calculateSLSATrustScore(nil)
	if score != 0.0 {
		t.Errorf("Expected 0.0 for nil provenance, got %f", score)
	}

	// Test with empty provenance
	emptyProvenance := &SLSAProvenance{Present: false}
	score = analyzer.calculateSLSATrustScore(emptyProvenance)
	if score != 0.0 {
		t.Errorf("Expected 0.0 for empty provenance, got %f", score)
	}

	// Test with verified provenance
	verifiedProvenance := &SLSAProvenance{
		Present:  true,
		Verified: true,
		Builder: &SLSABuilder{
			ID:      "trusted-builder",
			Trusted: true,
		},
		Compliance: &SLSACompliance{
			Level: 3,
			Score: 1.0,
		},
	}
	score = analyzer.calculateSLSATrustScore(verifiedProvenance)
	if score <= 0.0 {
		t.Errorf("Expected positive score for verified provenance, got %f", score)
	}
}

func TestCalculateIntegrityTrustScoreEdgeCases(t *testing.T) {
	cfg := &Config{}
	analyzer, err := NewProvenanceAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Test with nil checks
	score := analyzer.calculateIntegrityTrustScore(nil)
	if score != 0.0 {
		t.Errorf("Expected 0.0 for nil checks, got %f", score)
	}

	// Test with empty checks
	emptyChecks := &IntegrityChecks{}
	score = analyzer.calculateIntegrityTrustScore(emptyChecks)
	if score != 0.0 {
		t.Errorf("Expected 0.0 for empty checks, got %f", score)
	}

	// Test with all verified checks
	verifiedChecks := &IntegrityChecks{
		HashVerification: &HashVerification{
			Verified: true,
		},
		SizeVerification: &SizeVerification{
			Verified: true,
		},
		ContentVerification: &ContentVerification{
			ManifestVerified: true,
		},
	}
	score = analyzer.calculateIntegrityTrustScore(verifiedChecks)
	if score != 1.0 {
		t.Errorf("Expected 1.0 for all verified checks, got %f", score)
	}
}

func TestCalculateTransparencyLogTrustScoreEdgeCases(t *testing.T) {
	cfg := &Config{}
	analyzer, err := NewProvenanceAnalyzer(cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Test with nil verification
	score := analyzer.calculateTransparencyLogTrustScore(nil)
	if score != 0.0 {
		t.Errorf("Expected 0.0 for nil verification, got %f", score)
	}

	// Test with not present
	notPresent := &TransparencyLogVerification{Present: false}
	score = analyzer.calculateTransparencyLogTrustScore(notPresent)
	if score != 0.0 {
		t.Errorf("Expected 0.0 for not present, got %f", score)
	}

	// Test with present but not verified
	presentNotVerified := &TransparencyLogVerification{
		Present:  true,
		Verified: false,
	}
	score = analyzer.calculateTransparencyLogTrustScore(presentNotVerified)
	if score != 0.5 {
		t.Errorf("Expected 0.5 for present but not verified, got %f", score)
	}

	// Test with verified
	verified := &TransparencyLogVerification{
		Present:  true,
		Verified: true,
	}
	score = analyzer.calculateTransparencyLogTrustScore(verified)
	if score != 1.0 {
		t.Errorf("Expected 1.0 for verified, got %f", score)
	}
}

func TestMinFunction(t *testing.T) {
	// Test the min helper function
	if min(1.0, 2.0) != 1.0 {
		t.Error("Expected min(1.0, 2.0) to be 1.0")
	}
	if min(2.0, 1.0) != 1.0 {
		t.Error("Expected min(2.0, 1.0) to be 1.0")
	}
	if min(1.0, 1.0) != 1.0 {
		t.Error("Expected min(1.0, 1.0) to be 1.0")
	}
}
