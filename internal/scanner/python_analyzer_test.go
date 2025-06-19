package scanner

import (
	"os"
	"path/filepath"
	"testing"

	"typosentinel/internal/config"
	"typosentinel/pkg/types"
)

func TestPythonAnalyzer_ExtractPackages_RequirementsTxt(t *testing.T) {
	// Create temporary directory
	tempDir := t.TempDir()

	// Create requirements.txt
	requirementsContent := `# Production dependencies
requests==2.28.1
numpy>=1.21.0
pandas~=1.5.0
flask<=2.2.0
django>4.0.0
scipy<1.10.0
pytest

# Comments and empty lines should be ignored

# Development dependencies (should be parsed)
pytest-cov==4.0.0

# Skip editable installs
-e git+https://github.com/user/repo.git#egg=package

# Skip requirement files
-r dev-requirements.txt
--requirement test-requirements.txt
`

	requirementsPath := filepath.Join(tempDir, "requirements.txt")
	err := os.WriteFile(requirementsPath, []byte(requirementsContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create requirements.txt: %v", err)
	}

	// Create analyzer
	cfg := &config.Config{
		Scanner: config.ScannerConfig{
			IncludeDevDeps: true,
		},
	}
	analyzer := NewPythonAnalyzer(cfg)

	// Create project info
	projectInfo := &ProjectInfo{
		Type:         "python",
		Path:         tempDir,
		ManifestFile: "requirements.txt",
	}

	// Extract packages
	packages, err := analyzer.ExtractPackages(projectInfo)
	if err != nil {
		t.Fatalf("ExtractPackages failed: %v", err)
	}

	// Verify results
	expected := map[string]string{
		"requests":    "2.28.1",
		"numpy":      "1.21.0",
		"pandas":     "1.5.0",
		"flask":      "2.2.0",
		"django":     "4.0.0",
		"scipy":      "1.10.0",
		"pytest":     "*",
		"pytest-cov": "4.0.0",
	}

	if len(packages) != len(expected) {
		t.Errorf("Expected %d packages, got %d", len(expected), len(packages))
	}

	for _, pkg := range packages {
		expectedVersion, exists := expected[pkg.Name]
		if !exists {
			t.Errorf("Unexpected package: %s", pkg.Name)
			continue
		}

		if pkg.Version != expectedVersion {
			t.Errorf("Package %s: expected version %s, got %s", pkg.Name, expectedVersion, pkg.Version)
		}

		if pkg.Registry != "pypi" {
			t.Errorf("Package %s: expected registry 'pypi', got %s", pkg.Name, pkg.Registry)
		}

		if pkg.Type != "production" {
			t.Errorf("Package %s: expected type 'production', got %s", pkg.Name, pkg.Type)
		}
	}
}

func TestPythonAnalyzer_ExtractPackages_Pipfile(t *testing.T) {
	// Create temporary directory
	tempDir := t.TempDir()

	// Create Pipfile
	pipfileContent := `[[source]]
url = "https://pypi.org/simple"
verify_ssl = true
name = "pypi"

[packages]
requests = "*"
numpy = ">=1.21.0"
flask = {version = ">=2.0.0"}

[dev-packages]
pytest = "*"
pytest-cov = ">=4.0.0"

[requires]
python_version = "3.9"
`

	pipfilePath := filepath.Join(tempDir, "Pipfile")
	err := os.WriteFile(pipfilePath, []byte(pipfileContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create Pipfile: %v", err)
	}

	// Create analyzer
	cfg := &config.Config{
		Scanner: config.ScannerConfig{
			IncludeDevDeps: true,
		},
	}
	analyzer := NewPythonAnalyzer(cfg)

	// Create project info
	projectInfo := &ProjectInfo{
		Type:         "python",
		Path:         tempDir,
		ManifestFile: "Pipfile",
	}

	// Extract packages
	packages, err := analyzer.ExtractPackages(projectInfo)
	if err != nil {
		t.Fatalf("ExtractPackages failed: %v", err)
	}

	// Verify results
	expectedProd := map[string]string{
		"requests": "*",
		"numpy":    ">=1.21.0",
		"flask":    ">=2.0.0",
	}

	expectedDev := map[string]string{
		"pytest":     "*",
		"pytest-cov": ">=4.0.0",
	}

	prodCount := 0
	devCount := 0

	for _, pkg := range packages {
		if pkg.Type == "production" {
			prodCount++
			expectedVersion, exists := expectedProd[pkg.Name]
			if !exists {
				t.Errorf("Unexpected production package: %s", pkg.Name)
				continue
			}
			if pkg.Version != expectedVersion {
				t.Errorf("Production package %s: expected version %s, got %s", pkg.Name, expectedVersion, pkg.Version)
			}
		} else if pkg.Type == "development" {
			devCount++
			expectedVersion, exists := expectedDev[pkg.Name]
			if !exists {
				t.Errorf("Unexpected development package: %s", pkg.Name)
				continue
			}
			if pkg.Version != expectedVersion {
				t.Errorf("Development package %s: expected version %s, got %s", pkg.Name, expectedVersion, pkg.Version)
			}
		}

		if pkg.Registry != "pypi" {
			t.Errorf("Package %s: expected registry 'pypi', got %s", pkg.Name, pkg.Registry)
		}
	}

	if prodCount != len(expectedProd) {
		t.Errorf("Expected %d production packages, got %d", len(expectedProd), prodCount)
	}

	if devCount != len(expectedDev) {
		t.Errorf("Expected %d development packages, got %d", len(expectedDev), devCount)
	}
}

func TestPythonAnalyzer_ExtractPackages_PyprojectToml(t *testing.T) {
	// Create temporary directory
	tempDir := t.TempDir()

	// Create pyproject.toml
	pyprojectContent := `[tool.poetry]
name = "test-project"
version = "0.1.0"
description = "Test project"

[tool.poetry.dependencies]
python = "^3.9"
requests = "^2.28.0"
numpy = ">=1.21.0"
flask = {version = "^2.0.0", optional = true}

[tool.poetry.dev-dependencies]
pytest = "^7.0.0"
pytest-cov = "^4.0.0"

[tool.poetry.group.test.dependencies]
pytest-mock = "^3.10.0"

[build-system]
requires = ["poetry-core"]
build-backend = "poetry.core.masonry.api"
`

	pyprojectPath := filepath.Join(tempDir, "pyproject.toml")
	err := os.WriteFile(pyprojectPath, []byte(pyprojectContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create pyproject.toml: %v", err)
	}

	// Create analyzer
	cfg := &config.Config{
		Scanner: config.ScannerConfig{
			IncludeDevDeps: true,
		},
	}
	analyzer := NewPythonAnalyzer(cfg)

	// Create project info
	projectInfo := &ProjectInfo{
		Type:         "python",
		Path:         tempDir,
		ManifestFile: "pyproject.toml",
	}

	// Extract packages
	packages, err := analyzer.ExtractPackages(projectInfo)
	if err != nil {
		t.Fatalf("ExtractPackages failed: %v", err)
	}

	// Verify results
	expectedProd := map[string]string{
		"requests": "^2.28.0",
		"numpy":    ">=1.21.0",
		"flask":    "^2.0.0",
	}

	expectedDev := map[string]string{
		"pytest":     "^7.0.0",
		"pytest-cov": "^4.0.0",
	}

	expectedGroup := map[string]string{
		"pytest-mock": "^3.10.0",
	}

	prodCount := 0
	devCount := 0
	groupCount := 0

	for _, pkg := range packages {
		switch pkg.Type {
		case "production":
			prodCount++
			expectedVersion, exists := expectedProd[pkg.Name]
			if !exists {
				t.Errorf("Unexpected production package: %s", pkg.Name)
				continue
			}
			if pkg.Version != expectedVersion {
				t.Errorf("Production package %s: expected version %s, got %s", pkg.Name, expectedVersion, pkg.Version)
			}
		case "development":
			devCount++
			expectedVersion, exists := expectedDev[pkg.Name]
			if !exists {
				t.Errorf("Unexpected development package: %s", pkg.Name)
				continue
			}
			if pkg.Version != expectedVersion {
				t.Errorf("Development package %s: expected version %s, got %s", pkg.Name, expectedVersion, pkg.Version)
			}
		case "group-test":
			groupCount++
			expectedVersion, exists := expectedGroup[pkg.Name]
			if !exists {
				t.Errorf("Unexpected group package: %s", pkg.Name)
				continue
			}
			if pkg.Version != expectedVersion {
				t.Errorf("Group package %s: expected version %s, got %s", pkg.Name, expectedVersion, pkg.Version)
			}
		}

		if pkg.Registry != "pypi" {
			t.Errorf("Package %s: expected registry 'pypi', got %s", pkg.Name, pkg.Registry)
		}
	}

	if prodCount != len(expectedProd) {
		t.Errorf("Expected %d production packages, got %d", len(expectedProd), prodCount)
	}

	if devCount != len(expectedDev) {
		t.Errorf("Expected %d development packages, got %d", len(expectedDev), devCount)
	}

	if groupCount != len(expectedGroup) {
		t.Errorf("Expected %d group packages, got %d", len(expectedGroup), groupCount)
	}
}

func TestPythonAnalyzer_ExtractPackages_SetupPy(t *testing.T) {
	// Create temporary directory
	tempDir := t.TempDir()

	// Create setup.py
	setupContent := `from setuptools import setup, find_packages

setup(
    name="test-package",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "requests>=2.28.0",
        "numpy==1.21.0",
        "flask~=2.0.0",
        "django",
    ],
    extras_require={
        "dev": ["pytest>=7.0.0", "pytest-cov"],
    },
)
`

	setupPath := filepath.Join(tempDir, "setup.py")
	err := os.WriteFile(setupPath, []byte(setupContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create setup.py: %v", err)
	}

	// Create analyzer
	cfg := &config.Config{
		Scanner: config.ScannerConfig{
			IncludeDevDeps: false,
		},
	}
	analyzer := NewPythonAnalyzer(cfg)

	// Create project info
	projectInfo := &ProjectInfo{
		Type:         "python",
		Path:         tempDir,
		ManifestFile: "setup.py",
	}

	// Extract packages
	packages, err := analyzer.ExtractPackages(projectInfo)
	if err != nil {
		t.Fatalf("ExtractPackages failed: %v", err)
	}

	// Verify results
	expected := map[string]string{
		"requests": "2.28.0",
		"numpy":    "1.21.0",
		"flask":    "2.0.0",
		"django":   "*",
	}

	if len(packages) != len(expected) {
		t.Errorf("Expected %d packages, got %d", len(expected), len(packages))
	}

	for _, pkg := range packages {
		expectedVersion, exists := expected[pkg.Name]
		if !exists {
			t.Errorf("Unexpected package: %s", pkg.Name)
			continue
		}

		if pkg.Version != expectedVersion {
			t.Errorf("Package %s: expected version %s, got %s", pkg.Name, expectedVersion, pkg.Version)
		}

		if pkg.Registry != "pypi" {
			t.Errorf("Package %s: expected registry 'pypi', got %s", pkg.Name, pkg.Registry)
		}

		if pkg.Type != "production" {
			t.Errorf("Package %s: expected type 'production', got %s", pkg.Name, pkg.Type)
		}
	}
}

func TestPythonAnalyzer_AnalyzeDependencies(t *testing.T) {
	// Create temporary directory
	tempDir := t.TempDir()

	// Create requirements.txt
	requirementsContent := `requests==2.28.1
numpy>=1.21.0
flask<=2.2.0
`

	requirementsPath := filepath.Join(tempDir, "requirements.txt")
	err := os.WriteFile(requirementsPath, []byte(requirementsContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create requirements.txt: %v", err)
	}

	// Create analyzer
	cfg := &config.Config{
		Scanner: config.ScannerConfig{
			IncludeDevDeps: false,
		},
	}
	analyzer := NewPythonAnalyzer(cfg)

	// Create project info
	projectInfo := &ProjectInfo{
		Type:         "python",
		Path:         tempDir,
		ManifestFile: "requirements.txt",
	}

	// Analyze dependencies
	tree, err := analyzer.AnalyzeDependencies(projectInfo)
	if err != nil {
		t.Fatalf("AnalyzeDependencies failed: %v", err)
	}

	// Verify results
	if tree.Root == nil {
		t.Fatal("Expected root node, got nil")
	}

	if tree.Root.Name != "root" {
		t.Errorf("Expected root name 'root', got %s", tree.Root.Name)
	}

	if len(tree.Root.Dependencies) != 3 {
		t.Errorf("Expected 3 dependencies, got %d", len(tree.Root.Dependencies))
	}

	if len(tree.Packages) != 3 {
		t.Errorf("Expected 3 packages, got %d", len(tree.Packages))
	}

	// Verify package names
	expectedNames := map[string]bool{
		"requests": true,
		"numpy":    true,
		"flask":    true,
	}

	for _, dep := range tree.Root.Dependencies {
		if !expectedNames[dep.Name] {
			t.Errorf("Unexpected dependency: %s", dep.Name)
		}
	}
}

func TestPythonAnalyzer_UnsupportedManifest(t *testing.T) {
	// Create analyzer
	cfg := &config.Config{
		Scanner: config.ScannerConfig{
			IncludeDevDeps: false,
		},
	}
	analyzer := NewPythonAnalyzer(cfg)

	// Create project info with unsupported manifest
	projectInfo := &ProjectInfo{
		Type:         "python",
		Path:         "/tmp",
		ManifestFile: "unsupported.txt",
	}

	// Extract packages should fail
	_, err := analyzer.ExtractPackages(projectInfo)
	if err == nil {
		t.Fatal("Expected error for unsupported manifest file, got nil")
	}

	expectedError := "unsupported Python manifest file: unsupported.txt"
	if err.Error() != expectedError {
		t.Errorf("Expected error '%s', got '%s'", expectedError, err.Error())
	}
}