package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// RustPackageAnalyzer analyzes Rust projects
type RustPackageAnalyzer struct {
	config *config.Config
}

// NewRustPackageAnalyzer creates a new Rust analyzer
func NewRustPackageAnalyzer(cfg *config.Config) *RustPackageAnalyzer {
	return &RustPackageAnalyzer{
		config: cfg,
	}
}

// CargoToml represents the structure of Cargo.toml
type CargoToml struct {
	Package           CargoPackage           `toml:"package"`
	Dependencies      map[string]interface{} `toml:"dependencies"`
	DevDependencies   map[string]interface{} `toml:"dev-dependencies"`
	BuildDependencies map[string]interface{} `toml:"build-dependencies"`
}

type CargoPackage struct {
	Name    string `toml:"name"`
	Version string `toml:"version"`
}

// CargoLock represents the structure of Cargo.lock
type CargoLock struct {
	Packages []CargoLockPackage `toml:"package"`
}

type CargoLockPackage struct {
	Name         string   `toml:"name"`
	Version      string   `toml:"version"`
	Source       string   `toml:"source"`
	Checksum     string   `toml:"checksum"`
	Dependencies []string `toml:"dependencies"`
}

func (a *RustPackageAnalyzer) ExtractPackages(projectInfo *ProjectInfo) ([]*types.Package, error) {
	var packages []*types.Package

	// Parse Cargo.toml for dependency information
	cargoTomlPath := filepath.Join(projectInfo.Path, "Cargo.toml")
	if _, err := os.Stat(cargoTomlPath); err == nil {
		tomlPackages, err := a.parseCargoToml(cargoTomlPath)
		if err != nil {
			return nil, fmt.Errorf("failed to parse Cargo.toml: %w", err)
		}
		packages = append(packages, tomlPackages...)
	}

	// Parse Cargo.lock for exact versions
	cargoLockPath := filepath.Join(projectInfo.Path, "Cargo.lock")
	if _, err := os.Stat(cargoLockPath); err == nil {
		lockPackages, err := a.parseCargoLock(cargoLockPath)
		if err != nil {
			return nil, fmt.Errorf("failed to parse Cargo.lock: %w", err)
		}
		// Merge lock file information with toml packages
		packages = a.mergeLockInfo(packages, lockPackages)
	}

	return packages, nil
}

func (a *RustPackageAnalyzer) parseCargoToml(filePath string) ([]*types.Package, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	// Simple TOML parsing for dependencies
	// In a production environment, you'd use a proper TOML parser like github.com/BurntSushi/toml
	var packages []*types.Package
	content := string(data)

	// Parse [dependencies] section
	if deps := a.extractDependenciesSection(content, "dependencies"); deps != nil {
		for name, version := range deps {
			pkg := &types.Package{
				Name:     name,
				Version:  version,
				Registry: "crates.io",
				Type:     "production",
				Metadata: &types.PackageMetadata{
					Name:     name,
					Version:  version,
					Registry: "crates.io",
					Metadata: map[string]interface{}{
						"ecosystem": "rust",
						"source":    "Cargo.toml",
						"section":   "dependencies",
					},
				},
			}
			packages = append(packages, pkg)
		}
	}

	// Parse [dev-dependencies] section
	if devDeps := a.extractDependenciesSection(content, "dev-dependencies"); devDeps != nil {
		for name, version := range devDeps {
			pkg := &types.Package{
				Name:     name,
				Version:  version,
				Registry: "crates.io",
				Type:     "development",
				Metadata: &types.PackageMetadata{
					Name:     name,
					Version:  version,
					Registry: "crates.io",
					Metadata: map[string]interface{}{
						"ecosystem": "rust",
						"source":    "Cargo.toml",
						"section":   "dev-dependencies",
					},
				},
			}
			packages = append(packages, pkg)
		}
	}

	// Parse [build-dependencies] section
	if buildDeps := a.extractDependenciesSection(content, "build-dependencies"); buildDeps != nil {
		for name, version := range buildDeps {
			pkg := &types.Package{
				Name:     name,
				Version:  version,
				Registry: "crates.io",
				Type:     "build",
				Metadata: &types.PackageMetadata{
					Name:     name,
					Version:  version,
					Registry: "crates.io",
					Metadata: map[string]interface{}{
						"ecosystem": "rust",
						"source":    "Cargo.toml",
						"section":   "build-dependencies",
					},
				},
			}
			packages = append(packages, pkg)
		}
	}

	return packages, nil
}

func (a *RustPackageAnalyzer) extractDependenciesSection(content, section string) map[string]string {
	// Simple regex-based TOML parsing for dependencies
	sectionRegex := regexp.MustCompile(fmt.Sprintf(`\[%s\]([\s\S]*?)(?:\[|$)`, regexp.QuoteMeta(section)))
	matches := sectionRegex.FindStringSubmatch(content)
	if len(matches) < 2 {
		return nil
	}

	depsSection := matches[1]
	deps := make(map[string]string)

	// Parse simple dependencies: name = "version"
	simpleDepRegex := regexp.MustCompile(`([a-zA-Z0-9_-]+)\s*=\s*"([^"]+)"`)
	simpleMatches := simpleDepRegex.FindAllStringSubmatch(depsSection, -1)
	for _, match := range simpleMatches {
		if len(match) >= 3 {
			deps[match[1]] = match[2]
		}
	}

	// Parse complex dependencies: name = { version = "x.y.z", ... }
	complexDepRegex := regexp.MustCompile(`([a-zA-Z0-9_-]+)\s*=\s*\{[^}]*version\s*=\s*"([^"]+)"[^}]*\}`)
	complexMatches := complexDepRegex.FindAllStringSubmatch(depsSection, -1)
	for _, match := range complexMatches {
		if len(match) >= 3 {
			deps[match[1]] = match[2]
		}
	}

	return deps
}

func (a *RustPackageAnalyzer) parseCargoLock(filePath string) (map[string]*types.Package, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	// Simple TOML parsing for Cargo.lock
	// In production, use a proper TOML parser
	content := string(data)
	packages := make(map[string]*types.Package)

	// Parse [[package]] entries
	packageRegex := regexp.MustCompile(`\[\[package\]\]([\s\S]*?)(?:\[\[|$)`)
	matches := packageRegex.FindAllStringSubmatch(content, -1)

	for _, match := range matches {
		if len(match) < 2 {
			continue
		}

		packageSection := match[1]
		name := a.extractTomlValue(packageSection, "name")
		version := a.extractTomlValue(packageSection, "version")
		source := a.extractTomlValue(packageSection, "source")
		checksum := a.extractTomlValue(packageSection, "checksum")

		if name != "" && version != "" {
			registry := "crates.io"
			if source != "" && !strings.Contains(source, "registry") {
				registry = "git"
			}

			pkg := &types.Package{
				Name:     name,
				Version:  version,
				Registry: registry,
				Type:     "transitive",
				Metadata: &types.PackageMetadata{
					Name:     name,
					Version:  version,
					Registry: registry,
					Metadata: map[string]interface{}{
						"ecosystem": "rust",
						"source":    "Cargo.lock",
						"checksum":  checksum,
					},
				},
			}
			packages[name] = pkg
		}
	}

	return packages, nil
}

func (a *RustPackageAnalyzer) extractTomlValue(content, key string) string {
	regex := regexp.MustCompile(fmt.Sprintf(`%s\s*=\s*"([^"]+)"`, regexp.QuoteMeta(key)))
	matches := regex.FindStringSubmatch(content)
	if len(matches) >= 2 {
		return matches[1]
	}
	return ""
}

func (a *RustPackageAnalyzer) mergeLockInfo(tomlPackages []*types.Package, lockPackages map[string]*types.Package) []*types.Package {
	// Update TOML packages with exact versions from lock file
	for _, pkg := range tomlPackages {
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
			pkg.Metadata.Metadata["checksum"] = lockPkg.Metadata.Metadata["checksum"]
		}
	}

	// Add any packages from lock file that weren't in TOML (transitive dependencies)
	tomlPackageNames := make(map[string]bool)
	for _, pkg := range tomlPackages {
		tomlPackageNames[pkg.Name] = true
	}

	for name, lockPkg := range lockPackages {
		if !tomlPackageNames[name] {
			lockPkg.Type = "transitive"
			tomlPackages = append(tomlPackages, lockPkg)
		}
	}

	return tomlPackages
}

func (a *RustPackageAnalyzer) AnalyzeDependencies(projectInfo *ProjectInfo) (*types.DependencyTree, error) {
	packages, err := a.ExtractPackages(projectInfo)
	if err != nil {
		return nil, err
	}

	projectName := "rust-project"
	projectVersion := "1.0.0"

	// Try to get project name and version from Cargo.toml
	cargoTomlPath := filepath.Join(projectInfo.Path, "Cargo.toml")
	if _, err := os.Stat(cargoTomlPath); err == nil {
		if name, version := a.extractProjectInfo(cargoTomlPath); name != "" {
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

func (a *RustPackageAnalyzer) extractProjectInfo(cargoTomlPath string) (string, string) {
	data, err := os.ReadFile(cargoTomlPath)
	if err != nil {
		return "", ""
	}

	content := string(data)

	// Extract project name and version from [package] section
	packageRegex := regexp.MustCompile(`\[package\]([\s\S]*?)(?:\[|$)`)
	matches := packageRegex.FindStringSubmatch(content)
	if len(matches) < 2 {
		return "", ""
	}

	packageSection := matches[1]
	name := a.extractTomlValue(packageSection, "name")
	version := a.extractTomlValue(packageSection, "version")

	return name, version
}
