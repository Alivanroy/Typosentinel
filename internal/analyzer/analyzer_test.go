package analyzer

import (
	"os"
	"path/filepath"
	"testing"

	"typosentinel/internal/config"
)

func TestNew(t *testing.T) {
	cfg := &config.Config{
		Detection: config.DetectionConfig{
			SimilarityThreshold: 0.8,
			HomoglyphDetection:  true,
			SemanticAnalysis:    true,
		},
	}

	analyzer := New(cfg)

	// Test that analyzer is properly initialized
	if analyzer == nil {
		t.Error("Expected analyzer to not be nil")
	}
	if analyzer.config == nil {
		t.Error("Expected analyzer.config to not be nil")
	}
	if analyzer.detector == nil {
		t.Error("Expected analyzer.detector to not be nil")
	}
}

func TestScan_Success(t *testing.T) {
	cfg := &config.Config{
		Detection: config.DetectionConfig{
			SimilarityThreshold: 0.8,
			HomoglyphDetection:  true,
			SemanticAnalysis:    true,
		},
	}

	analyzer := New(cfg)

	// Create a temporary test directory with a package.json
	testDir := t.TempDir()
	packageJSON := `{"name": "test-package", "version": "1.0.0", "dependencies": {"lodash": "^4.17.21"}}`
	err := os.WriteFile(filepath.Join(testDir, "package.json"), []byte(packageJSON), 0644)
	if err != nil {
		t.Fatalf("Failed to create test package.json: %v", err)
	}

	options := &ScanOptions{
		DeepAnalysis:        false,
		SimilarityThreshold: 0.8,
	}

	result, err := analyzer.Scan(testDir, options)

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if result == nil {
		t.Error("Expected result to not be nil")
	}
	if result.ScanID == "" {
		t.Error("Expected scan ID to be set")
	}
	if result.Path != testDir {
		t.Errorf("Expected path to be %s, got %s", testDir, result.Path)
	}
}

func TestScan_NoPackageFiles(t *testing.T) {
	cfg := &config.Config{
		Detection: config.DetectionConfig{
			SimilarityThreshold: 0.8,
		},
	}

	analyzer := New(cfg)

	// Create an empty test directory
	testDir := t.TempDir()

	options := &ScanOptions{
		SimilarityThreshold: 0.8,
	}

	_, err := analyzer.Scan(testDir, options)

	if err == nil {
		t.Error("Expected error for directory with no package files")
	}
}

func TestScan_SpecificFile(t *testing.T) {
	cfg := &config.Config{
		Detection: config.DetectionConfig{
			SimilarityThreshold: 0.8,
		},
	}

	analyzer := New(cfg)

	// Create a temporary test directory with a package.json
	testDir := t.TempDir()
	packageFile := filepath.Join(testDir, "package.json")
	packageJSON := `{"name": "test-package", "version": "1.0.0"}`
	err := os.WriteFile(packageFile, []byte(packageJSON), 0644)
	if err != nil {
		t.Fatalf("Failed to create test package.json: %v", err)
	}

	options := &ScanOptions{
		SpecificFile:        packageFile,
		SimilarityThreshold: 0.8,
	}

	result, err := analyzer.Scan(testDir, options)

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if result == nil {
		t.Error("Expected result to not be nil")
	}
}

func TestDetectFileType(t *testing.T) {
	cfg := &config.Config{}
	analyzer := New(cfg)

	tests := []struct {
		filePath     string
		expectedType string
		expectedReg  string
	}{
		{"package.json", "npm", "npm"},
		{"requirements.txt", "python", "pypi"},
		{"go.mod", "go", "go"},
		{"Cargo.toml", "rust", "cargo"},
		{"Gemfile", "ruby", "rubygems"},
		{"composer.json", "php", "packagist"},
		{"unknown.txt", "unknown", "unknown"},
	}

	for _, test := range tests {
		fileType, registryType := analyzer.detectFileType(test.filePath)
		if fileType != test.expectedType {
			t.Errorf("For %s, expected file type %s, got %s", test.filePath, test.expectedType, fileType)
		}
		if registryType != test.expectedReg {
			t.Errorf("For %s, expected registry type %s, got %s", test.filePath, test.expectedReg, registryType)
		}
	}
}

func TestFilterDependencies(t *testing.T) {
	cfg := &config.Config{}
	analyzer := New(cfg)

	// This test would require importing types.Dependency
	// For now, just test that the method exists and doesn't panic
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("filterDependencies panicked: %v", r)
		}
	}()

	// Test with empty dependencies and exclude list
	filtered := analyzer.filterDependencies(nil, nil)
	if filtered == nil {
		t.Error("Expected non-nil result from filterDependencies")
	}
}