package scanner

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Alivanroy/Typosentinel/internal/config"
)

func TestNew(t *testing.T) {
	cfg := &config.Config{
		TypoDetection: &config.TypoDetectionConfig{
			Enabled: true,
			Threshold: 0.8,
		},
		Scanner: &config.ScannerConfig{
			MaxConcurrency: 5,
			IncludeDevDeps: true,
		},
	}

	scanner, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}

	if scanner == nil {
		t.Error("Expected scanner to be created, got nil")
	}

	if scanner.config != cfg {
		t.Error("Expected scanner config to match provided config")
	}
}

func TestScanProject_Success(t *testing.T) {
	// Create temporary test directory
	tempDir, err := os.MkdirTemp("", "scanner_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create test package.json
	packageJSON := `{"name": "test-package", "version": "1.0.0", "dependencies": {"lodash": "^4.17.21"}}`
	err = os.WriteFile(filepath.Join(tempDir, "package.json"), []byte(packageJSON), 0644)
	if err != nil {
		t.Fatalf("Failed to create package.json: %v", err)
	}

	cfg := &config.Config{
		TypoDetection: &config.TypoDetectionConfig{
			Enabled: true,
			Threshold: 0.8,
		},
		Scanner: &config.ScannerConfig{
			IncludeDevDeps: true,
		},
	}

	scanner, err := New(cfg)
		if err != nil {
			t.Fatalf("Failed to create scanner: %v", err)
		}

	result, err := scanner.ScanProject(tempDir)
	if err != nil {
		t.Fatalf("Expected successful scan, got error: %v", err)
	}

	if result == nil {
		t.Error("Expected scan result, got nil")
	}

	if result.Target != tempDir {
		t.Errorf("Expected target %s, got %s", tempDir, result.Target)
	}
}

func TestScanProject_EmptyDirectory(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "scanner_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	cfg := &config.Config{
		TypoDetection: &config.TypoDetectionConfig{
			Enabled: true,
			Threshold: 0.8,
		},
	}

	scanner, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}

	result, err := scanner.ScanProject(tempDir)
	if err != nil {
		t.Fatalf("Expected successful scan of empty directory, got error: %v", err)
	}

	if result == nil {
		t.Error("Expected scan result, got nil")
	}

	if result.Target != tempDir {
		t.Errorf("Expected target %s, got %s", tempDir, result.Target)
	}
}

func TestScanProject_MultipleFiles(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "scanner_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create multiple dependency files
	packageJSON := `{"name": "test-package", "version": "1.0.0", "dependencies": {"express": "^4.18.0"}}`
	err = os.WriteFile(filepath.Join(tempDir, "package.json"), []byte(packageJSON), 0644)
	if err != nil {
		t.Fatalf("Failed to create package.json: %v", err)
	}

	requirementsTxt := `requests==2.28.1\nnumpy==1.24.0`
	err = os.WriteFile(filepath.Join(tempDir, "requirements.txt"), []byte(requirementsTxt), 0644)
	if err != nil {
		t.Fatalf("Failed to create requirements.txt: %v", err)
	}

	cfg := &config.Config{
		TypoDetection: &config.TypoDetectionConfig{
			Enabled: true,
			Threshold: 0.8,
		},
		Scanner: &config.ScannerConfig{
			IncludeDevDeps: true,
		},
	}

	scanner, err := New(cfg)
		if err != nil {
			t.Fatalf("Failed to create scanner: %v", err)
		}

		result, err := scanner.ScanProject(tempDir)
	if err != nil {
		t.Fatalf("Expected successful scan, got error: %v", err)
	}

	if result == nil {
		t.Error("Expected scan result, got nil")
	}

	if result.Target != tempDir {
		t.Errorf("Expected target %s, got %s", tempDir, result.Target)
	}
}

func TestScanProject_InvalidPath(t *testing.T) {
	cfg := &config.Config{
		TypoDetection: &config.TypoDetectionConfig{
			Enabled: true,
			Threshold: 0.8,
		},
	}

	scanner, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}

	_, err = scanner.ScanProject("/nonexistent/path")
	if err == nil {
		t.Error("Expected error for invalid path, got nil")
	}
}

func TestScanProject_NestedDirectories(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "scanner_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create nested directory structure
	nestedDir := filepath.Join(tempDir, "subproject")
	err = os.MkdirAll(nestedDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create nested dir: %v", err)
	}

	// Create package.json in nested directory
	packageJSON := `{"name": "nested-package", "version": "1.0.0"}`
	err = os.WriteFile(filepath.Join(nestedDir, "package.json"), []byte(packageJSON), 0644)
	if err != nil {
		t.Fatalf("Failed to create nested package.json: %v", err)
	}

	cfg := &config.Config{
		TypoDetection: &config.TypoDetectionConfig{
			Enabled: true,
			Threshold: 0.8,
		},
		Scanner: &config.ScannerConfig{},
	}

	scanner, err := New(cfg)
		if err != nil {
			t.Fatalf("Failed to create scanner: %v", err)
		}

		result, err := scanner.ScanProject(tempDir)
	if err != nil {
		t.Fatalf("Expected successful scan, got error: %v", err)
	}

	if result == nil {
		t.Error("Expected scan result, got nil")
	}
}

func TestScanProject_LargeProject(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "scanner_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a package.json with many dependencies
	packageJSON := `{
		"name": "large-project",
		"version": "1.0.0",
		"dependencies": {
			"express": "^4.18.0",
			"lodash": "^4.17.21",
			"axios": "^0.27.0",
			"moment": "^2.29.0",
			"uuid": "^9.0.0"
		},
		"devDependencies": {
			"jest": "^28.0.0",
			"eslint": "^8.0.0",
			"prettier": "^2.7.0"
		}
	}`
	err = os.WriteFile(filepath.Join(tempDir, "package.json"), []byte(packageJSON), 0644)
	if err != nil {
		t.Fatalf("Failed to create package.json: %v", err)
	}

	cfg := &config.Config{
		TypoDetection: &config.TypoDetectionConfig{
			Enabled: true,
			Threshold: 0.8,
		},
		Scanner: &config.ScannerConfig{
			IncludeDevDeps: true,
		},
	}

	scanner, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}

	result, err := scanner.ScanProject(tempDir)
	if err != nil {
		t.Fatalf("Expected successful scan, got error: %v", err)
	}

	if result == nil {
		t.Error("Expected scan result, got nil")
	}

	if result.Target != tempDir {
		t.Errorf("Expected target %s, got %s", tempDir, result.Target)
	}
}