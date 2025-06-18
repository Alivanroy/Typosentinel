package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"typosentinel/internal/config"
	"typosentinel/pkg/types"
)

// NodeJSAnalyzer analyzes Node.js projects
type NodeJSAnalyzer struct {
	config *config.Config
}

func (a *NodeJSAnalyzer) ExtractPackages(projectInfo *ProjectInfo) ([]*types.Package, error) {
	manifestPath := filepath.Join(projectInfo.Path, projectInfo.ManifestFile)
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, err
	}

	var packageJSON map[string]interface{}
	if err := json.Unmarshal(data, &packageJSON); err != nil {
		return nil, err
	}

	var packages []*types.Package

	// Extract dependencies
	if deps, ok := packageJSON["dependencies"].(map[string]interface{}); ok {
		for name, version := range deps {
			if versionStr, ok := version.(string); ok {
				pkg := &types.Package{
					Name:     name,
					Version:  versionStr,
					Registry: "npm",
					Type:     "production",
				}
				packages = append(packages, pkg)
			}
		}
	}

	// Extract dev dependencies if enabled
	if a.config.Scanner.IncludeDevDeps {
		if devDeps, ok := packageJSON["devDependencies"].(map[string]interface{}); ok {
			for name, version := range devDeps {
				if versionStr, ok := version.(string); ok {
					pkg := &types.Package{
						Name:     name,
						Version:  versionStr,
						Registry: "npm",
						Type:     "development",
					}
					packages = append(packages, pkg)
				}
			}
		}
	}

	return packages, nil
}

func (a *NodeJSAnalyzer) AnalyzeDependencies(projectInfo *ProjectInfo) (*types.DependencyTree, error) {
	// For now, return a simple tree structure
	// In a full implementation, this would parse lock files and build the actual dependency tree
	packages, err := a.ExtractPackages(projectInfo)
	if err != nil {
		return nil, err
	}

	root := &types.DependencyTree{
		Name:         projectInfo.Metadata["name"],
		Version:      projectInfo.Metadata["version"],
		Type:         "root",
		Dependencies: make([]types.DependencyTree, 0),
	}

	for _, pkg := range packages {
		dep := types.DependencyTree{
			Name:         pkg.Name,
			Version:      pkg.Version,
			Type:         pkg.Type,
			Threats:      pkg.Threats,
			Dependencies: make([]types.DependencyTree, 0),
		}
		root.Dependencies = append(root.Dependencies, dep)
	}

	return root, nil
}

// PythonAnalyzer analyzes Python projects
type PythonAnalyzer struct {
	config *config.Config
}

func (a *PythonAnalyzer) ExtractPackages(projectInfo *ProjectInfo) ([]*types.Package, error) {
	switch projectInfo.ManifestFile {
	case "requirements.txt":
		return a.parseRequirementsTxt(projectInfo)
	case "pyproject.toml":
		return a.parsePyprojectToml(projectInfo)
	case "Pipfile":
		return a.parsePipfile(projectInfo)
	default:
		return nil, fmt.Errorf("unsupported Python manifest file: %s", projectInfo.ManifestFile)
	}
}

func (a *PythonAnalyzer) parseRequirementsTxt(projectInfo *ProjectInfo) ([]*types.Package, error) {
	filePath := filepath.Join(projectInfo.Path, projectInfo.ManifestFile)
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var packages []*types.Package
	lines := strings.Split(string(data), "\n")

	// Regex to parse requirement lines
	reqRegex := regexp.MustCompile(`^([a-zA-Z0-9_-]+)([><=!~]+)?([0-9.]+.*)?$`)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		matches := reqRegex.FindStringSubmatch(line)
		if len(matches) >= 2 {
			name := matches[1]
			version := "*"
			if len(matches) >= 4 && matches[3] != "" {
				version = matches[2] + matches[3]
			}

			pkg := &types.Package{
				Name:     name,
				Version:  version,
				Registry: "pypi",
				Type:     "production",
			}
			packages = append(packages, pkg)
		}
	}

	return packages, nil
}

func (a *PythonAnalyzer) parsePyprojectToml(projectInfo *ProjectInfo) ([]*types.Package, error) {
	// TODO: Implement TOML parsing for pyproject.toml
	return nil, fmt.Errorf("pyproject.toml parsing not implemented yet")
}

func (a *PythonAnalyzer) parsePipfile(projectInfo *ProjectInfo) ([]*types.Package, error) {
	// TODO: Implement Pipfile parsing
	return nil, fmt.Errorf("Pipfile parsing not implemented yet")
}

func (a *PythonAnalyzer) AnalyzeDependencies(projectInfo *ProjectInfo) (*types.DependencyTree, error) {
	packages, err := a.ExtractPackages(projectInfo)
	if err != nil {
		return nil, err
	}

	root := &types.DependencyTree{
		Name:         "python-project",
		Version:      "1.0.0",
		Type:         "root",
		Dependencies: make([]types.DependencyTree, 0),
	}

	for _, pkg := range packages {
		dep := types.DependencyTree{
			Name:         pkg.Name,
			Version:      pkg.Version,
			Type:         pkg.Type,
			Threats:      pkg.Threats,
			Dependencies: make([]types.DependencyTree, 0),
		}
		root.Dependencies = append(root.Dependencies, dep)
	}

	return root, nil
}

// GoAnalyzer analyzes Go projects
type GoAnalyzer struct {
	config *config.Config
}

func (a *GoAnalyzer) ExtractPackages(projectInfo *ProjectInfo) ([]*types.Package, error) {
	modPath := filepath.Join(projectInfo.Path, "go.mod")
	data, err := os.ReadFile(modPath)
	if err != nil {
		return nil, err
	}

	var packages []*types.Package
	lines := strings.Split(string(data), "\n")
	inRequireBlock := false

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "require (") {
			inRequireBlock = true
			continue
		}

		if inRequireBlock && line == ")" {
			inRequireBlock = false
			continue
		}

		if inRequireBlock || strings.HasPrefix(line, "require ") {
			// Parse require line
			line = strings.TrimPrefix(line, "require ")
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				name := parts[0]
				version := parts[1]

				pkg := &types.Package{
					Name:     name,
					Version:  version,
					Registry: "go",
					Type:     "production",
				}
				packages = append(packages, pkg)
			}
		}
	}

	return packages, nil
}

func (a *GoAnalyzer) AnalyzeDependencies(projectInfo *ProjectInfo) (*types.DependencyTree, error) {
	packages, err := a.ExtractPackages(projectInfo)
	if err != nil {
		return nil, err
	}

	root := &types.DependencyTree{
		Name:         projectInfo.Metadata["module"],
		Version:      "1.0.0",
		Type:         "root",
		Dependencies: make([]types.DependencyTree, 0),
	}

	for _, pkg := range packages {
		dep := types.DependencyTree{
			Name:         pkg.Name,
			Version:      pkg.Version,
			Type:         pkg.Type,
			Threats:      pkg.Threats,
			Dependencies: make([]types.DependencyTree, 0),
		}
		root.Dependencies = append(root.Dependencies, dep)
	}

	return root, nil
}

// RustAnalyzer analyzes Rust projects
type RustAnalyzer struct {
	config *config.Config
	analyzer *RustPackageAnalyzer
}

func NewRustAnalyzer(cfg *config.Config) *RustAnalyzer {
	return &RustAnalyzer{
		config:   cfg,
		analyzer: NewRustPackageAnalyzer(cfg),
	}
}

func (a *RustAnalyzer) ExtractPackages(projectInfo *ProjectInfo) ([]*types.Package, error) {
	return a.analyzer.ExtractPackages(projectInfo)
}

func (a *RustAnalyzer) AnalyzeDependencies(projectInfo *ProjectInfo) (*types.DependencyTree, error) {
	return a.analyzer.AnalyzeDependencies(projectInfo)
}

// RubyAnalyzer analyzes Ruby projects
type RubyAnalyzer struct {
	config *config.Config
	analyzer *RubyPackageAnalyzer
}

func NewRubyAnalyzer(cfg *config.Config) *RubyAnalyzer {
	return &RubyAnalyzer{
		config:   cfg,
		analyzer: NewRubyPackageAnalyzer(cfg),
	}
}

func (a *RubyAnalyzer) ExtractPackages(projectInfo *ProjectInfo) ([]*types.Package, error) {
	return a.analyzer.ExtractPackages(projectInfo)
}

func (a *RubyAnalyzer) AnalyzeDependencies(projectInfo *ProjectInfo) (*types.DependencyTree, error) {
	return a.analyzer.AnalyzeDependencies(projectInfo)
}

// PHPAnalyzer analyzes PHP projects
type PHPAnalyzer struct {
	config *config.Config
	analyzer *PHPPackageAnalyzer
}

func NewPHPAnalyzer(cfg *config.Config) *PHPAnalyzer {
	return &PHPAnalyzer{
		config:   cfg,
		analyzer: NewPHPPackageAnalyzer(cfg),
	}
}

func (a *PHPAnalyzer) ExtractPackages(projectInfo *ProjectInfo) ([]*types.Package, error) {
	return a.analyzer.ExtractPackages(projectInfo)
}

func (a *PHPAnalyzer) AnalyzeDependencies(projectInfo *ProjectInfo) (*types.DependencyTree, error) {
	return a.analyzer.AnalyzeDependencies(projectInfo)
}

// JavaAnalyzer analyzes Java projects
type JavaAnalyzer struct {
	config *config.Config
	analyzer *JavaPackageAnalyzer
}

func NewJavaAnalyzer(cfg *config.Config) *JavaAnalyzer {
	return &JavaAnalyzer{
		config:   cfg,
		analyzer: NewJavaPackageAnalyzer(cfg),
	}
}

func (a *JavaAnalyzer) ExtractPackages(projectInfo *ProjectInfo) ([]*types.Package, error) {
	return a.analyzer.ExtractPackages(projectInfo)
}

func (a *JavaAnalyzer) AnalyzeDependencies(projectInfo *ProjectInfo) (*types.DependencyTree, error) {
	return a.analyzer.AnalyzeDependencies(projectInfo)
}

// DotNetAnalyzer analyzes .NET projects
type DotNetAnalyzer struct {
	config *config.Config
	analyzer *DotNetPackageAnalyzer
}

func NewDotNetAnalyzer(cfg *config.Config) *DotNetAnalyzer {
	return &DotNetAnalyzer{
		config:   cfg,
		analyzer: NewDotNetPackageAnalyzer(cfg),
	}
}

func (a *DotNetAnalyzer) ExtractPackages(projectInfo *ProjectInfo) ([]*types.Package, error) {
	return a.analyzer.ExtractPackages(projectInfo)
}

func (a *DotNetAnalyzer) AnalyzeDependencies(projectInfo *ProjectInfo) (*types.DependencyTree, error) {
	return a.analyzer.AnalyzeDependencies(projectInfo)
}