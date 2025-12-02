package registry

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Alivanroy/Typosentinel/internal/scanner"
	"github.com/sirupsen/logrus"
)

// AutoDetector automatically detects project types and creates appropriate registry connectors
type AutoDetector struct {
	factory   *Factory
	detectors map[string]scanner.ProjectDetector
}

// NewAutoDetector creates a new auto detector
func NewAutoDetector() *AutoDetector {
	return &AutoDetector{
		factory: NewFactory(),
		detectors: map[string]scanner.ProjectDetector{
			"nodejs": &scanner.NodeJSDetector{},
			"python": &scanner.PythonDetector{},
			"go":     &scanner.GoDetector{},
			"rust":   &scanner.RustDetector{},
			"php":    &scanner.PHPDetector{},
			"java":   &scanner.JavaDetector{},
			"dotnet": &scanner.DotNetDetector{},
			"ruby":   &scanner.RubyDetector{},
		},
	}
}

// DetectProjectType detects the project type from a given directory
func (ad *AutoDetector) DetectProjectType(projectPath string) (*scanner.ProjectInfo, error) {
	// Try each detector to find the project type
	for projectType, detector := range ad.detectors {
		if projectInfo, err := detector.Detect(projectPath); err == nil {
			return projectInfo, nil
		} else {
			// Log the error for debugging but continue trying other detectors
			logrus.Debugf("%s detector failed for %s: %v", projectType, projectPath, err)
		}
	}

	return nil, fmt.Errorf("no supported project type detected in %s", projectPath)
}

// DetectAndCreateConnector detects project type and creates the appropriate registry connector
func (ad *AutoDetector) DetectAndCreateConnector(projectPath string) (Connector, error) {
	projectInfo, err := ad.DetectProjectType(projectPath)
	if err != nil {
		return nil, err
	}

	// Map project type to registry type
	registryType := ad.mapProjectTypeToRegistry(projectInfo.Type)
	if registryType == "" {
		return nil, fmt.Errorf("unsupported project type: %s", projectInfo.Type)
	}

	// Create connector using factory
	return ad.factory.CreateConnectorFromType(registryType)
}

// DetectAllProjectTypes scans a directory and detects all project types
func (ad *AutoDetector) DetectAllProjectTypes(rootPath string) ([]*scanner.ProjectInfo, error) {
	var projects []*scanner.ProjectInfo

	err := filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Continue walking despite errors
		}

		// Skip hidden directories and common non-project directories
		if info.IsDir() {
			dirName := filepath.Base(path)
			if strings.HasPrefix(dirName, ".") ||
				dirName == "node_modules" ||
				dirName == "vendor" ||
				dirName == "target" ||
				dirName == "build" ||
				dirName == "dist" ||
				dirName == "__pycache__" ||
				dirName == ".git" {
				return filepath.SkipDir
			}

			// Try to detect project in this directory
			if projectInfo, err := ad.DetectProjectType(path); err == nil {
				projects = append(projects, projectInfo)
				// Skip subdirectories of detected projects to avoid duplicates
				return filepath.SkipDir
			}
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to walk directory tree: %w", err)
	}

	if len(projects) == 0 {
		return nil, fmt.Errorf("no supported projects found in %s", rootPath)
	}

	return projects, nil
}

// CreateConnectorsForProjects creates registry connectors for multiple detected projects
func (ad *AutoDetector) CreateConnectorsForProjects(projects []*scanner.ProjectInfo) (map[string]Connector, error) {
	connectors := make(map[string]Connector)

	for _, project := range projects {
		registryType := ad.mapProjectTypeToRegistry(project.Type)
		if registryType == "" {
			continue // Skip unsupported project types
		}

		// Create connector if not already created
		if _, exists := connectors[registryType]; !exists {
			connector, err := ad.factory.CreateConnectorFromType(registryType)
			if err != nil {
				return nil, fmt.Errorf("failed to create %s connector: %w", registryType, err)
			}
			connectors[registryType] = connector
		}
	}

	return connectors, nil
}

// mapProjectTypeToRegistry maps project types to registry types
func (ad *AutoDetector) mapProjectTypeToRegistry(projectType string) string {
	switch strings.ToLower(projectType) {
	case "nodejs":
		return "npm"
	case "python":
		return "pypi"
	case "go":
		return "go" // Note: Go modules don't use a traditional registry like others
	case "rust":
		return "cargo"
	case "php":
		return "composer"
	case "java":
		return "maven"
	case "dotnet":
		return "nuget"
	case "ruby":
		return "rubygems"
	default:
		return ""
	}
}

// GetSupportedProjectTypes returns all supported project types
func (ad *AutoDetector) GetSupportedProjectTypes() []string {
	types := make([]string, 0, len(ad.detectors))
	for projectType := range ad.detectors {
		types = append(types, projectType)
	}
	return types
}

// GetRegistryForManifestFile determines registry type from manifest file name
func (ad *AutoDetector) GetRegistryForManifestFile(manifestFile string) string {
	filename := filepath.Base(manifestFile)

	switch filename {
	case "package.json", "package-lock.json", "yarn.lock":
		return "npm"
	case "requirements.txt", "pyproject.toml", "Pipfile", "Pipfile.lock", "setup.py":
		return "pypi"
	case "go.mod", "go.sum":
		return "go"
	case "Cargo.toml", "Cargo.lock":
		return "cargo"
	case "composer.json", "composer.lock":
		return "composer"
	case "pom.xml", "build.gradle", "build.gradle.kts":
		return "maven"
	case "Gemfile", "Gemfile.lock":
		return "rubygems"
	default:
		// Check for .csproj files
		if strings.HasSuffix(filename, ".csproj") || filename == "packages.config" {
			return "nuget"
		}
		return ""
	}
}

// ScanForManifestFiles scans a directory for manifest files and returns registry types
func (ad *AutoDetector) ScanForManifestFiles(rootPath string) (map[string][]string, error) {
	registryFiles := make(map[string][]string)

	err := filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Continue walking despite errors
		}

		// Skip directories and hidden files
		if info.IsDir() || strings.HasPrefix(info.Name(), ".") {
			return nil
		}

		// Check if this is a manifest file
		registryType := ad.GetRegistryForManifestFile(path)
		if registryType != "" {
			registryFiles[registryType] = append(registryFiles[registryType], path)
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to scan for manifest files: %w", err)
	}

	return registryFiles, nil
}
