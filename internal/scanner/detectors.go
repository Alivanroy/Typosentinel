package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// NodeJSDetector detects Node.js projects
type NodeJSDetector struct{}

func (d *NodeJSDetector) Detect(projectPath string) (*ProjectInfo, error) {
	manifestPath := filepath.Join(projectPath, "package.json")
	if _, err := os.Stat(manifestPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("package.json not found")
	}

	// Check for lock files
	lockFile := ""
	if _, err := os.Stat(filepath.Join(projectPath, "package-lock.json")); err == nil {
		lockFile = "package-lock.json"
	} else if _, err := os.Stat(filepath.Join(projectPath, "yarn.lock")); err == nil {
		lockFile = "yarn.lock"
	}

	// Read package.json for metadata
	metadata := make(map[string]string)
	if data, err := os.ReadFile(manifestPath); err == nil {
		var pkg map[string]interface{}
		if json.Unmarshal(data, &pkg) == nil {
			if name, ok := pkg["name"].(string); ok {
				metadata["name"] = name
			}
			if version, ok := pkg["version"].(string); ok {
				metadata["version"] = version
			}
		}
	}

	return &ProjectInfo{
		Type:         "nodejs",
		Path:         projectPath,
		ManifestFile: "package.json",
		LockFile:     lockFile,
		Metadata:     metadata,
	}, nil
}

func (d *NodeJSDetector) GetManifestFiles() []string {
	return []string{"package.json"}
}

func (d *NodeJSDetector) GetProjectType() string {
	return "nodejs"
}

// PythonDetector detects Python projects
type PythonDetector struct{}

func (d *PythonDetector) Detect(projectPath string) (*ProjectInfo, error) {
	// Check for various Python manifest files
	manifestFiles := []string{"requirements.txt", "pyproject.toml", "Pipfile", "setup.py"}
	var foundManifest string
	var lockFile string

	for _, manifest := range manifestFiles {
		if _, err := os.Stat(filepath.Join(projectPath, manifest)); err == nil {
			foundManifest = manifest
			break
		}
	}

	if foundManifest == "" {
		return nil, fmt.Errorf("no Python manifest file found")
	}

	// Check for lock files
	if foundManifest == "Pipfile" {
		if _, err := os.Stat(filepath.Join(projectPath, "Pipfile.lock")); err == nil {
			lockFile = "Pipfile.lock"
		}
	} else if foundManifest == "pyproject.toml" {
		if _, err := os.Stat(filepath.Join(projectPath, "poetry.lock")); err == nil {
			lockFile = "poetry.lock"
		}
	}

	return &ProjectInfo{
		Type:         "python",
		Path:         projectPath,
		ManifestFile: foundManifest,
		LockFile:     lockFile,
		Metadata:     make(map[string]string),
	}, nil
}

func (d *PythonDetector) GetManifestFiles() []string {
	return []string{"requirements.txt", "pyproject.toml", "Pipfile", "setup.py"}
}

func (d *PythonDetector) GetProjectType() string {
	return "python"
}

// GoDetector detects Go projects
type GoDetector struct{}

func (d *GoDetector) Detect(projectPath string) (*ProjectInfo, error) {
	manifestPath := filepath.Join(projectPath, "go.mod")
	if _, err := os.Stat(manifestPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("go.mod not found")
	}

	lockFile := ""
	if _, err := os.Stat(filepath.Join(projectPath, "go.sum")); err == nil {
		lockFile = "go.sum"
	}

	// Read go.mod for metadata
	metadata := make(map[string]string)
	if data, err := os.ReadFile(manifestPath); err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "module ") {
				metadata["module"] = strings.TrimPrefix(line, "module ")
				break
			}
		}
	}

	return &ProjectInfo{
		Type:         "go",
		Path:         projectPath,
		ManifestFile: "go.mod",
		LockFile:     lockFile,
		Metadata:     metadata,
	}, nil
}

func (d *GoDetector) GetManifestFiles() []string {
	return []string{"go.mod"}
}

func (d *GoDetector) GetProjectType() string {
	return "go"
}

// RustDetector detects Rust projects
type RustDetector struct{}

func (d *RustDetector) Detect(projectPath string) (*ProjectInfo, error) {
	manifestPath := filepath.Join(projectPath, "Cargo.toml")
	if _, err := os.Stat(manifestPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("Cargo.toml not found")
	}

	lockFile := ""
	if _, err := os.Stat(filepath.Join(projectPath, "Cargo.lock")); err == nil {
		lockFile = "Cargo.lock"
	}

	return &ProjectInfo{
		Type:         "rust",
		Path:         projectPath,
		ManifestFile: "Cargo.toml",
		LockFile:     lockFile,
		Metadata:     make(map[string]string),
	}, nil
}

func (d *RustDetector) GetManifestFiles() []string {
	return []string{"Cargo.toml"}
}

func (d *RustDetector) GetProjectType() string {
	return "rust"
}

// RubyDetector detects Ruby projects
type RubyDetector struct{}

func (d *RubyDetector) Detect(projectPath string) (*ProjectInfo, error) {
	manifestPath := filepath.Join(projectPath, "Gemfile")
	if _, err := os.Stat(manifestPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("Gemfile not found")
	}

	lockFile := ""
	if _, err := os.Stat(filepath.Join(projectPath, "Gemfile.lock")); err == nil {
		lockFile = "Gemfile.lock"
	}

	return &ProjectInfo{
		Type:         "ruby",
		Path:         projectPath,
		ManifestFile: "Gemfile",
		LockFile:     lockFile,
		Metadata:     make(map[string]string),
	}, nil
}

func (d *RubyDetector) GetManifestFiles() []string {
	return []string{"Gemfile"}
}

func (d *RubyDetector) GetProjectType() string {
	return "ruby"
}

// PHPDetector detects PHP projects
type PHPDetector struct{}

func (d *PHPDetector) Detect(projectPath string) (*ProjectInfo, error) {
	manifestPath := filepath.Join(projectPath, "composer.json")
	if _, err := os.Stat(manifestPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("composer.json not found")
	}

	lockFile := ""
	if _, err := os.Stat(filepath.Join(projectPath, "composer.lock")); err == nil {
		lockFile = "composer.lock"
	}

	return &ProjectInfo{
		Type:         "php",
		Path:         projectPath,
		ManifestFile: "composer.json",
		LockFile:     lockFile,
		Metadata:     make(map[string]string),
	}, nil
}

func (d *PHPDetector) GetManifestFiles() []string {
	return []string{"composer.json"}
}

func (d *PHPDetector) GetProjectType() string {
	return "php"
}

// JavaDetector detects Java projects
type JavaDetector struct{}

func (d *JavaDetector) Detect(projectPath string) (*ProjectInfo, error) {
	// Check for Maven or Gradle
	if _, err := os.Stat(filepath.Join(projectPath, "pom.xml")); err == nil {
		return &ProjectInfo{
			Type:         "java",
			Path:         projectPath,
			ManifestFile: "pom.xml",
			Metadata:     map[string]string{"build_tool": "maven"},
		}, nil
	}

	gradleFiles := []string{"build.gradle", "build.gradle.kts"}
	for _, gradleFile := range gradleFiles {
		if _, err := os.Stat(filepath.Join(projectPath, gradleFile)); err == nil {
			return &ProjectInfo{
				Type:         "java",
				Path:         projectPath,
				ManifestFile: gradleFile,
				Metadata:     map[string]string{"build_tool": "gradle"},
			}, nil
		}
	}

	return nil, fmt.Errorf("no Java build file found")
}

func (d *JavaDetector) GetManifestFiles() []string {
	return []string{"pom.xml", "build.gradle", "build.gradle.kts"}
}

func (d *JavaDetector) GetProjectType() string {
	return "java"
}

// DotNetDetector detects .NET projects
type DotNetDetector struct{}

func (d *DotNetDetector) Detect(projectPath string) (*ProjectInfo, error) {
	// Look for .csproj files
	files, err := os.ReadDir(projectPath)
	if err != nil {
		return nil, err
	}

	for _, file := range files {
		if strings.HasSuffix(file.Name(), ".csproj") {
			return &ProjectInfo{
				Type:         "dotnet",
				Path:         projectPath,
				ManifestFile: file.Name(),
				Metadata:     make(map[string]string),
			}, nil
		}
	}

	// Check for packages.config
	if _, err := os.Stat(filepath.Join(projectPath, "packages.config")); err == nil {
		return &ProjectInfo{
			Type:         "dotnet",
			Path:         projectPath,
			ManifestFile: "packages.config",
			Metadata:     make(map[string]string),
		}, nil
	}

	return nil, fmt.Errorf("no .NET project file found")
}

func (d *DotNetDetector) GetManifestFiles() []string {
	return []string{"*.csproj", "packages.config"}
}

func (d *DotNetDetector) GetProjectType() string {
	return "dotnet"
}