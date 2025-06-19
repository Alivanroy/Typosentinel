package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"typosentinel/internal/config"
	"typosentinel/pkg/types"
)

// NodeJSAnalyzer analyzes Node.js projects
type NodeJSAnalyzer struct {
	*BaseAnalyzer
	config *config.Config
}

// NewNodeJSAnalyzer creates a new Node.js analyzer
func NewNodeJSAnalyzer(cfg *config.Config) *NodeJSAnalyzer {
	metadata := &AnalyzerMetadata{
		Name:        "nodejs",
		Version:     "1.0.0",
		Description: "Analyzes Node.js projects using package.json, package-lock.json, and yarn.lock",
		Author:      "TypoSentinel",
		Languages:   []string{"javascript", "typescript", "nodejs"},
		Capabilities: []string{"dependency_extraction", "lock_file_parsing", "npm_registry", "yarn_support"},
		Requirements: []string{"package.json"},
	}
	
	baseAnalyzer := NewBaseAnalyzer(
		"nodejs",
		[]string{".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"},
		[]string{"package.json", "package-lock.json", "yarn.lock", "npm-shrinkwrap.json"},
		metadata,
		cfg,
	)
	
	return &NodeJSAnalyzer{
		BaseAnalyzer: baseAnalyzer,
		config:       cfg,
	}
}

func (a *NodeJSAnalyzer) ExtractPackages(projectInfo *ProjectInfo) ([]*types.Package, error) {
	var packages []*types.Package

	// Parse package.json for dependency information
	packageJSONPath := filepath.Join(projectInfo.Path, "package.json")
	if _, err := os.Stat(packageJSONPath); err == nil {
		jsonPackages, err := a.parsePackageJSON(packageJSONPath)
		if err != nil {
			return nil, fmt.Errorf("failed to parse package.json: %w", err)
		}
		packages = append(packages, jsonPackages...)
	}

	// Parse package-lock.json for exact versions and additional dependencies
	packageLockPath := filepath.Join(projectInfo.Path, "package-lock.json")
	if _, err := os.Stat(packageLockPath); err == nil {
		lockPackages, err := a.parsePackageLockJSON(packageLockPath)
		if err != nil {
			return nil, fmt.Errorf("failed to parse package-lock.json: %w", err)
		}
		// Merge with existing packages, preferring lock file versions
		packages = a.mergePackages(packages, lockPackages)
	}

	// Parse yarn.lock for Yarn projects
	yarnLockPath := filepath.Join(projectInfo.Path, "yarn.lock")
	if _, err := os.Stat(yarnLockPath); err == nil {
		yarnPackages, err := a.parseYarnLock(yarnLockPath)
		if err != nil {
			return nil, fmt.Errorf("failed to parse yarn.lock: %w", err)
		}
		// Merge with existing packages, preferring lock file versions
		packages = a.mergePackages(packages, yarnPackages)
	}

	// Parse pnpm-lock.yaml for pnpm projects
	pnpmLockPath := filepath.Join(projectInfo.Path, "pnpm-lock.yaml")
	if _, err := os.Stat(pnpmLockPath); err == nil {
		pnpmPackages, err := a.parsePnpmLock(pnpmLockPath)
		if err != nil {
			return nil, fmt.Errorf("failed to parse pnpm-lock.yaml: %w", err)
		}
		// Merge with existing packages, preferring lock file versions
		packages = a.mergePackages(packages, pnpmPackages)
	}

	return packages, nil
}

// parsePackageJSON parses package.json for dependency information
func (a *NodeJSAnalyzer) parsePackageJSON(filePath string) ([]*types.Package, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var packageJSON map[string]interface{}
	if err := json.Unmarshal(data, &packageJSON); err != nil {
		return nil, err
	}

	var packages []*types.Package

	// Extract production dependencies
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

	// Extract peer dependencies
	if peerDeps, ok := packageJSON["peerDependencies"].(map[string]interface{}); ok {
		for name, version := range peerDeps {
			if versionStr, ok := version.(string); ok {
				pkg := &types.Package{
					Name:     name,
					Version:  versionStr,
					Registry: "npm",
					Type:     "peer",
				}
				packages = append(packages, pkg)
			}
		}
	}

	// Extract optional dependencies
	if optDeps, ok := packageJSON["optionalDependencies"].(map[string]interface{}); ok {
		for name, version := range optDeps {
			if versionStr, ok := version.(string); ok {
				pkg := &types.Package{
					Name:     name,
					Version:  versionStr,
					Registry: "npm",
					Type:     "optional",
				}
				packages = append(packages, pkg)
			}
		}
	}

	return packages, nil
}

// parsePackageLockJSON parses package-lock.json for exact dependency versions
func (a *NodeJSAnalyzer) parsePackageLockJSON(filePath string) ([]*types.Package, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var lockData map[string]interface{}
	if err := json.Unmarshal(data, &lockData); err != nil {
		return nil, err
	}

	var packages []*types.Package

	// Handle lockfileVersion 2 and 3 format
	if packagesData, ok := lockData["packages"].(map[string]interface{}); ok {
		for path, pkgData := range packagesData {
			if path == "" {
				continue // Skip root package
			}
			if pkgInfo, ok := pkgData.(map[string]interface{}); ok {
				name := strings.TrimPrefix(path, "node_modules/")
				if version, ok := pkgInfo["version"].(string); ok {
					pkgType := "production"
					if dev, ok := pkgInfo["dev"].(bool); ok && dev {
						pkgType = "development"
					}
					if optional, ok := pkgInfo["optional"].(bool); ok && optional {
						pkgType = "optional"
					}

					pkg := &types.Package{
						Name:     name,
						Version:  version,
						Registry: "npm",
						Type:     pkgType,
					}
					packages = append(packages, pkg)
				}
			}
		}
	}

	// Handle lockfileVersion 1 format (legacy)
	if dependencies, ok := lockData["dependencies"].(map[string]interface{}); ok {
		for name, depData := range dependencies {
			if depInfo, ok := depData.(map[string]interface{}); ok {
				if version, ok := depInfo["version"].(string); ok {
					pkgType := "production"
					if dev, ok := depInfo["dev"].(bool); ok && dev {
						pkgType = "development"
					}

					pkg := &types.Package{
						Name:     name,
						Version:  version,
						Registry: "npm",
						Type:     pkgType,
					}
					packages = append(packages, pkg)
				}
			}
		}
	}

	return packages, nil
}

// parseYarnLock parses yarn.lock for dependency information
func (a *NodeJSAnalyzer) parseYarnLock(filePath string) ([]*types.Package, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var packages []*types.Package
	content := string(data)
	lines := strings.Split(content, "\n")

	// Simple yarn.lock parser - matches package@version patterns
	packageRegex := regexp.MustCompile(`^([^@\s]+)@(.+):$`)
	versionRegex := regexp.MustCompile(`^\s+version\s+"([^"]+)"$`)

	var currentPackage string
	for i, line := range lines {
		if matches := packageRegex.FindStringSubmatch(line); len(matches) == 3 {
			currentPackage = matches[1]
			// Look for version in next few lines
			for j := i + 1; j < len(lines) && j < i+10; j++ {
				if versionMatches := versionRegex.FindStringSubmatch(lines[j]); len(versionMatches) == 2 {
					pkg := &types.Package{
						Name:     currentPackage,
						Version:  versionMatches[1],
						Registry: "npm",
						Type:     "production", // yarn.lock doesn't distinguish dev deps
					}
					packages = append(packages, pkg)
					break
				}
			}
		}
	}

	return packages, nil
}

// parsePnpmLock parses pnpm-lock.yaml for dependency information
func (a *NodeJSAnalyzer) parsePnpmLock(filePath string) ([]*types.Package, error) {
	// TODO: Implement YAML parsing for pnpm-lock.yaml
	// This requires adding a YAML parser dependency like gopkg.in/yaml.v3
	return nil, fmt.Errorf("pnpm-lock.yaml parsing not implemented yet - requires YAML parser")
}

// mergePackages merges two package slices, preferring the second slice for conflicts
func (a *NodeJSAnalyzer) mergePackages(existing, new []*types.Package) []*types.Package {
	packageMap := make(map[string]*types.Package)

	// Add existing packages
	for _, pkg := range existing {
		key := pkg.Name + "@" + pkg.Registry
		packageMap[key] = pkg
	}

	// Add new packages, overwriting existing ones
	for _, pkg := range new {
		key := pkg.Name + "@" + pkg.Registry
		packageMap[key] = pkg
	}

	// Convert back to slice
	var result []*types.Package
	for _, pkg := range packageMap {
		result = append(result, pkg)
	}

	return result
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

// Python analyzer methods are implemented in python_analyzer.go

// GoAnalyzer analyzes Go projects with enhanced functionality
type GoAnalyzer struct {
	config   *config.Config
	enhanced *EnhancedGoAnalyzer
}

// NewGoAnalyzer creates a new Go analyzer with enhanced capabilities
func NewGoAnalyzer(config *config.Config) *GoAnalyzer {
	return &GoAnalyzer{
		config:   config,
		enhanced: NewEnhancedGoAnalyzer(config),
	}
}

func (a *GoAnalyzer) ExtractPackages(projectInfo *ProjectInfo) ([]*types.Package, error) {
	// Use enhanced analyzer if available, fallback to basic parsing
	if a.enhanced != nil {
		return a.enhanced.ExtractPackages(projectInfo)
	}

	// Fallback to basic go.mod parsing
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
	// Use enhanced analyzer if available
	if a.enhanced != nil {
		return a.enhanced.AnalyzeDependencies(projectInfo)
	}

	// Fallback to basic dependency analysis
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

// ValidateChecksums validates go.sum checksums using enhanced analyzer
func (a *GoAnalyzer) ValidateChecksums(projectPath string) ([]string, error) {
	if a.enhanced != nil {
		return a.enhanced.ValidateChecksums(projectPath)
	}
	return []string{}, nil
}

// DetectVulnerableVersions detects vulnerable Go package versions
func (a *GoAnalyzer) DetectVulnerableVersions(packages []*types.Package) ([]*types.Package, error) {
	if a.enhanced != nil {
		return a.enhanced.DetectVulnerableVersions(packages)
	}
	return packages, nil
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

// PythonPackageAnalyzer analyzes Python projects
type PythonPackageAnalyzer struct {
	config   *config.Config
	analyzer *PythonAnalyzer
}

func NewPythonPackageAnalyzer(cfg *config.Config) *PythonPackageAnalyzer {
	return &PythonPackageAnalyzer{
		config:   cfg,
		analyzer: NewPythonAnalyzer(cfg),
	}
}

func (a *PythonPackageAnalyzer) ExtractPackages(projectInfo *ProjectInfo) ([]*types.Package, error) {
	return a.analyzer.ExtractPackages(projectInfo)
}

func (a *PythonPackageAnalyzer) AnalyzeDependencies(projectInfo *ProjectInfo) (*types.DependencyTree, error) {
	return a.analyzer.AnalyzeDependencies(projectInfo)
}

// GenericAnalyzer handles projects without specific manifest files
type GenericAnalyzer struct {
	config *config.Config
}

func (a *GenericAnalyzer) ExtractPackages(projectInfo *ProjectInfo) ([]*types.Package, error) {
	// For generic projects without manifest files, return empty package list
	return []*types.Package{}, nil
}

func (a *GenericAnalyzer) AnalyzeDependencies(projectInfo *ProjectInfo) (*types.DependencyTree, error) {
	// For generic projects, return empty dependency tree
	return &types.DependencyTree{
		Name:         "root",
		Version:      "1.0.0",
		Type:         "generic",
		Threats:      []types.Threat{},
		Dependencies: []types.DependencyTree{},
		Depth:        0,
		TotalCount:   0,
		CreatedAt:    time.Now(),
	}, nil
}