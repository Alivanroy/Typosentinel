package scanner

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"typosentinel/internal/config"
	"typosentinel/pkg/types"
)

// RubyPackageAnalyzer analyzes Ruby projects
type RubyPackageAnalyzer struct {
	config *config.Config
}

// NewRubyPackageAnalyzer creates a new Ruby analyzer
func NewRubyPackageAnalyzer(cfg *config.Config) *RubyPackageAnalyzer {
	return &RubyPackageAnalyzer{
		config: cfg,
	}
}

// GemfileLock represents the structure of Gemfile.lock
type GemfileLock struct {
	Gems []GemLockEntry `json:"gems"`
}

type GemLockEntry struct {
	Name         string   `json:"name"`
	Version      string   `json:"version"`
	Dependencies []string `json:"dependencies"`
	Source       string   `json:"source"`
}

// GemSpec represents basic gem specification
type GemSpec struct {
	Name         string            `json:"name"`
	Version      string            `json:"version"`
	Description  string            `json:"description"`
	Authors      []string          `json:"authors"`
	Dependencies map[string]string `json:"dependencies"`
}

func (a *RubyPackageAnalyzer) ExtractPackages(projectInfo *ProjectInfo) ([]*types.Package, error) {
	var packages []*types.Package

	// Parse Gemfile for dependency information
	gemfilePath := filepath.Join(projectInfo.Path, "Gemfile")
	if _, err := os.Stat(gemfilePath); err == nil {
		gemfilePackages, err := a.parseGemfile(gemfilePath)
		if err != nil {
			return nil, fmt.Errorf("failed to parse Gemfile: %w", err)
		}
		packages = append(packages, gemfilePackages...)
	}

	// Parse Gemfile.lock for exact versions
	gemfileLockPath := filepath.Join(projectInfo.Path, "Gemfile.lock")
	if _, err := os.Stat(gemfileLockPath); err == nil {
		lockPackages, err := a.parseGemfileLock(gemfileLockPath)
		if err != nil {
			return nil, fmt.Errorf("failed to parse Gemfile.lock: %w", err)
		}
		// Merge lock file information with Gemfile packages
		packages = a.mergeLockInfo(packages, lockPackages)
	}

	// Parse .gemspec files if present
	gemspecFiles, err := filepath.Glob(filepath.Join(projectInfo.Path, "*.gemspec"))
	if err == nil && len(gemspecFiles) > 0 {
		for _, gemspecFile := range gemspecFiles {
			gemspecPackages, err := a.parseGemspec(gemspecFile)
			if err != nil {
				continue // Skip invalid gemspec files
			}
			packages = append(packages, gemspecPackages...)
		}
	}

	return packages, nil
}

func (a *RubyPackageAnalyzer) parseGemfile(filePath string) ([]*types.Package, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var packages []*types.Package
	scanner := bufio.NewScanner(file)
	currentGroup := "production"

	// Regex patterns for parsing Gemfile
	gemRegex := regexp.MustCompile(`^\s*gem\s+['"]([^'"]+)['"](?:\s*,\s*['"]([^'"]+)['"])?`)
	groupRegex := regexp.MustCompile(`^\s*group\s+:([a-zA-Z_]+)`)
	endRegex := regexp.MustCompile(`^\s*end\s*$`)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty lines
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}

		// Check for group declarations
		if matches := groupRegex.FindStringSubmatch(line); len(matches) >= 2 {
			currentGroup = matches[1]
			if currentGroup == "development" || currentGroup == "test" {
				currentGroup = "development"
			} else {
				currentGroup = "production"
			}
			continue
		}

		// Check for end of group
		if endRegex.MatchString(line) {
			currentGroup = "production"
			continue
		}

		// Parse gem declarations
		if matches := gemRegex.FindStringSubmatch(line); len(matches) >= 2 {
			name := matches[1]
			version := "*"
			if len(matches) >= 3 && matches[2] != "" {
				version = matches[2]
			}

			pkg := &types.Package{
				Name:     name,
				Version:  version,
				Registry: "rubygems.org",
				Type:     currentGroup,
				Metadata: &types.PackageMetadata{
					Name:     name,
					Version:  version,
					Registry: "rubygems.org",
					Metadata: map[string]interface{}{
						"ecosystem": "ruby",
						"source":    "Gemfile",
					},
				},
			}
			packages = append(packages, pkg)
		}
	}

	return packages, nil
}

func (a *RubyPackageAnalyzer) parseGemfileLock(filePath string) (map[string]*types.Package, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	packages := make(map[string]*types.Package)
	scanner := bufio.NewScanner(file)
	inSpecsSection := false

	// Regex for parsing gem entries in Gemfile.lock
	gemRegex := regexp.MustCompile(`^\s{4}([a-zA-Z0-9_-]+)\s+\(([^)]+)\)`)
	depRegex := regexp.MustCompile(`^\s{6}([a-zA-Z0-9_-]+)`)

	var currentGem *types.Package

	for scanner.Scan() {
		line := scanner.Text()

		// Check for specs section
		if strings.Contains(line, "specs:") {
			inSpecsSection = true
			continue
		}

		// Exit specs section
		if inSpecsSection && strings.HasPrefix(line, "PLATFORMS") {
			inSpecsSection = false
			continue
		}

		if !inSpecsSection {
			continue
		}

		// Parse gem entries
		if matches := gemRegex.FindStringSubmatch(line); len(matches) >= 3 {
			name := matches[1]
			version := matches[2]

			currentGem = &types.Package{
				Name:     name,
				Version:  version,
				Registry: "rubygems.org",
				Type:     "production",
				Metadata: &types.PackageMetadata{
					Name:     name,
					Version:  version,
					Registry: "rubygems.org",
					Metadata: map[string]interface{}{
						"ecosystem":    "ruby",
						"source":       "Gemfile.lock",
						"dependencies": []string{},
					},
				},
			}
			packages[name] = currentGem
			continue
		}

		// Parse dependencies
		if currentGem != nil {
			if matches := depRegex.FindStringSubmatch(line); len(matches) >= 2 {
				depName := matches[1]
				if deps, ok := currentGem.Metadata.Metadata["dependencies"].([]string); ok {
				currentGem.Metadata.Metadata["dependencies"] = append(deps, depName)
			}
			}
		}
	}

	return packages, nil
}

func (a *RubyPackageAnalyzer) parseGemspec(filePath string) ([]*types.Package, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	content := string(data)
	var packages []*types.Package

	// Parse add_dependency and add_development_dependency calls
	depRegex := regexp.MustCompile(`s\.add_(?:(development_|runtime_))?dependency\s+['"]([^'"]+)['"](?:\s*,\s*['"]([^'"]+)['"])?`)
	matches := depRegex.FindAllStringSubmatch(content, -1)

	for _, match := range matches {
		if len(match) >= 3 {
			depType := "production"
			if match[1] == "development_" {
				depType = "development"
			}

			name := match[2]
			version := "*"
			if len(match) >= 4 && match[3] != "" {
				version = match[3]
			}

			pkg := &types.Package{
				Name:     name,
				Version:  version,
				Registry: "rubygems.org",
				Type:     depType,
				Metadata: &types.PackageMetadata{
					Name:     name,
					Version:  version,
					Registry: "rubygems.org",
					Metadata: map[string]interface{}{
						"ecosystem": "ruby",
						"source":    "gemspec",
					},
				},
			}
			packages = append(packages, pkg)
		}
	}

	return packages, nil
}

func (a *RubyPackageAnalyzer) mergeLockInfo(gemfilePackages []*types.Package, lockPackages map[string]*types.Package) []*types.Package {
	// Update Gemfile packages with exact versions from lock file
	for _, pkg := range gemfilePackages {
		if lockPkg, exists := lockPackages[pkg.Name]; exists {
			pkg.Version = lockPkg.Version
			if pkg.Metadata == nil {
				pkg.Metadata = &types.PackageMetadata{
					Name:     pkg.Name,
					Version:  pkg.Version,
					Registry: pkg.Registry,
					Metadata: make(map[string]interface{}),
				}
			}
			pkg.Metadata.Metadata["exact_version"] = lockPkg.Version
			pkg.Metadata.Metadata["dependencies"] = lockPkg.Metadata.Metadata["dependencies"]
		}
	}

	// Add any packages from lock file that weren't in Gemfile (transitive dependencies)
	gemfilePackageNames := make(map[string]bool)
	for _, pkg := range gemfilePackages {
		gemfilePackageNames[pkg.Name] = true
	}

	for name, lockPkg := range lockPackages {
		if !gemfilePackageNames[name] {
			lockPkg.Type = "transitive"
			gemfilePackages = append(gemfilePackages, lockPkg)
		}
	}

	return gemfilePackages
}

func (a *RubyPackageAnalyzer) AnalyzeDependencies(projectInfo *ProjectInfo) (*types.DependencyTree, error) {
	packages, err := a.ExtractPackages(projectInfo)
	if err != nil {
		return nil, err
	}

	projectName := "ruby-project"
	projectVersion := "1.0.0"

	// Try to get project name and version from gemspec
	gemspecFiles, err := filepath.Glob(filepath.Join(projectInfo.Path, "*.gemspec"))
	if err == nil && len(gemspecFiles) > 0 {
		if name, version := a.extractProjectInfo(gemspecFiles[0]); name != "" {
			projectName = name
			if version != "" {
				projectVersion = version
			}
		}
	}

	root := &types.DependencyTree{
		Name:         projectName,
		Version:      projectVersion,
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

func (a *RubyPackageAnalyzer) extractProjectInfo(gemspecPath string) (string, string) {
	data, err := os.ReadFile(gemspecPath)
	if err != nil {
		return "", ""
	}

	content := string(data)

	// Extract name and version from gemspec
	nameRegex := regexp.MustCompile(`s\.name\s*=\s*['"]([^'"]+)['"]`)
	versionRegex := regexp.MustCompile(`s\.version\s*=\s*['"]([^'"]+)['"]`)

	var name, version string

	if matches := nameRegex.FindStringSubmatch(content); len(matches) >= 2 {
		name = matches[1]
	}

	if matches := versionRegex.FindStringSubmatch(content); len(matches) >= 2 {
		version = matches[1]
	}

	return name, version
}