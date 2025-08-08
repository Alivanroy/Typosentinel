package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/pkg/types"
	"github.com/pelletier/go-toml/v2"
	"gopkg.in/yaml.v3"
)

// NodeJSAnalyzer analyzes Node.js projects
type NodeJSAnalyzer struct {
	config *config.Config
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
	if a.config != nil && a.config.Scanner != nil && a.config.Scanner.IncludeDevDeps {
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
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read pnpm-lock.yaml: %w", err)
	}

	// Parse YAML structure for pnpm-lock.yaml
	var pnpmLock struct {
		LockfileVersion string `yaml:"lockfileVersion"`
		Dependencies    map[string]struct {
			Version  string `yaml:"version"`
			Resolved string `yaml:"resolved,omitempty"`
		} `yaml:"dependencies,omitempty"`
		DevDependencies map[string]struct {
			Version  string `yaml:"version"`
			Resolved string `yaml:"resolved,omitempty"`
		} `yaml:"devDependencies,omitempty"`
		Packages map[string]struct {
			Name         string            `yaml:"name,omitempty"`
			Version      string            `yaml:"version,omitempty"`
			Resolution   map[string]string `yaml:"resolution,omitempty"`
			Dependencies map[string]string `yaml:"dependencies,omitempty"`
			DevDeps      map[string]string `yaml:"devDependencies,omitempty"`
			Dev          bool              `yaml:"dev,omitempty"`
		} `yaml:"packages,omitempty"`
	}

	err = yaml.Unmarshal(data, &pnpmLock)
	if err != nil {
		return nil, fmt.Errorf("failed to parse pnpm-lock.yaml: %w", err)
	}

	var packages []*types.Package

	// Parse direct dependencies
	for name, dep := range pnpmLock.Dependencies {
		pkg := &types.Package{
			Name:     name,
			Version:  dep.Version,
			Registry: "npm",
			Type:     "production",
		}
		packages = append(packages, pkg)
	}

	// Parse dev dependencies
	for name, dep := range pnpmLock.DevDependencies {
		pkg := &types.Package{
			Name:     name,
			Version:  dep.Version,
			Registry: "npm",
			Type:     "development",
		}
		packages = append(packages, pkg)
	}

	// Parse packages section for more detailed information
	for pkgPath, pkgInfo := range pnpmLock.Packages {
		// Extract package name from path (e.g., "/package-name/1.0.0" -> "package-name")
		name := pkgInfo.Name
		if name == "" {
			// Extract from path if name is not provided
			parts := strings.Split(strings.Trim(pkgPath, "/"), "/")
			if len(parts) >= 1 {
				name = parts[0]
				// Handle scoped packages
				if strings.HasPrefix(name, "@") && len(parts) >= 2 {
					name = parts[0] + "/" + parts[1]
				}
			}
		}

		if name != "" {
			pkgType := "production"
			if pkgInfo.Dev {
				pkgType = "development"
			}

			pkg := &types.Package{
				Name:     name,
				Version:  pkgInfo.Version,
				Registry: "npm",
				Type:     pkgType,
			}
			packages = append(packages, pkg)
		}
	}

	// Remove duplicates
	packages = a.removeDuplicatePackages(packages)

	return packages, nil
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

// removeDuplicatePackages removes duplicate packages from a slice
func (a *NodeJSAnalyzer) removeDuplicatePackages(packages []*types.Package) []*types.Package {
	packageMap := make(map[string]*types.Package)

	// Use package name and registry as key to identify duplicates
	for _, pkg := range packages {
		key := pkg.Name + "@" + pkg.Registry
		if existing, exists := packageMap[key]; exists {
			// Keep the package with more specific version info
			if pkg.Version != "*" && (existing.Version == "*" || len(pkg.Version) > len(existing.Version)) {
				packageMap[key] = pkg
			}
		} else {
			packageMap[key] = pkg
		}
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

// PythonAnalyzer analyzes Python projects
type PythonAnalyzer struct {
	config *config.Config
}

// NewPythonAnalyzer creates a new Python analyzer
func NewPythonAnalyzer(cfg *config.Config) *PythonAnalyzer {
	return &PythonAnalyzer{
		config: cfg,
	}
}

func (a *PythonAnalyzer) ExtractPackages(projectInfo *ProjectInfo) ([]*types.Package, error) {
	switch projectInfo.ManifestFile {
	case "requirements.txt":
		return a.parseRequirementsTxt(projectInfo)
	case "pyproject.toml":
		return a.parsePyprojectToml(projectInfo)
	case "Pipfile":
		return a.parsePipfile(projectInfo)
	case "setup.py":
		return a.parseSetupPy(projectInfo)
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
	filePath := filepath.Join(projectInfo.Path, projectInfo.ManifestFile)
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read pyproject.toml: %w", err)
	}

	// Parse TOML structure for pyproject.toml
	var pyproject struct {
		Project struct {
			Name         string   `toml:"name"`
			Version      string   `toml:"version"`
			Dependencies []string `toml:"dependencies"`
		} `toml:"project"`
		BuildSystem struct {
			Requires []string `toml:"requires"`
		} `toml:"build-system"`
		Tool struct {
			Poetry struct {
				Dependencies    map[string]interface{} `toml:"dependencies"`
				DevDependencies map[string]interface{} `toml:"dev-dependencies"`
				Group           map[string]struct {
					Dependencies map[string]interface{} `toml:"dependencies"`
				} `toml:"group"`
			} `toml:"poetry"`
		} `toml:"tool"`
	}

	err = toml.Unmarshal(data, &pyproject)
	if err != nil {
		return nil, fmt.Errorf("failed to parse pyproject.toml: %w", err)
	}

	var packages []*types.Package

	// Parse PEP 621 dependencies
	for _, dep := range pyproject.Project.Dependencies {
		name, version := a.parseRequirementString(dep)
		if name != "" {
			pkg := &types.Package{
				Name:     name,
				Version:  version,
				Registry: "pypi",
				Type:     "production",
			}
			packages = append(packages, pkg)
		}
	}

	// Parse build system requirements
	for _, dep := range pyproject.BuildSystem.Requires {
		name, version := a.parseRequirementString(dep)
		if name != "" {
			pkg := &types.Package{
				Name:     name,
				Version:  version,
				Registry: "pypi",
				Type:     "build",
			}
			packages = append(packages, pkg)
		}
	}

	// Parse Poetry dependencies
	for name, versionSpec := range pyproject.Tool.Poetry.Dependencies {
		if name == "python" {
			continue // Skip Python version requirement
		}

		version := "*"
		switch v := versionSpec.(type) {
		case string:
			version = v
		case map[string]interface{}:
			if ver, ok := v["version"]; ok {
				if verStr, ok := ver.(string); ok {
					version = verStr
				}
			}
		}

		pkg := &types.Package{
			Name:     name,
			Version:  version,
			Registry: "pypi",
			Type:     "production",
		}
		packages = append(packages, pkg)
	}

	// Parse Poetry dev dependencies
	for name, versionSpec := range pyproject.Tool.Poetry.DevDependencies {
		version := "*"
		switch v := versionSpec.(type) {
		case string:
			version = v
		case map[string]interface{}:
			if ver, ok := v["version"]; ok {
				if verStr, ok := ver.(string); ok {
					version = verStr
				}
			}
		}

		pkg := &types.Package{
			Name:     name,
			Version:  version,
			Registry: "pypi",
			Type:     "development",
		}
		packages = append(packages, pkg)
	}

	// Parse Poetry group dependencies
	for groupName, group := range pyproject.Tool.Poetry.Group {
		for name, versionSpec := range group.Dependencies {
			version := "*"
			switch v := versionSpec.(type) {
			case string:
				version = v
			case map[string]interface{}:
				if ver, ok := v["version"]; ok {
					if verStr, ok := ver.(string); ok {
						version = verStr
					}
				}
			}

			pkg := &types.Package{
				Name:     name,
				Version:  version,
				Registry: "pypi",
				Type:     fmt.Sprintf("group-%s", groupName),
			}
			packages = append(packages, pkg)
		}
	}

	return packages, nil
}

func (a *PythonAnalyzer) parseSetupPy(projectInfo *ProjectInfo) ([]*types.Package, error) {
	filePath := filepath.Join(projectInfo.Path, projectInfo.ManifestFile)
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read setup.py: %w", err)
	}

	content := string(data)
	var packages []*types.Package

	// Extract install_requires using regex
	installRequiresRegex := regexp.MustCompile(`install_requires\s*=\s*\[([^\]]+)\]`)
	matches := installRequiresRegex.FindStringSubmatch(content)
	if len(matches) > 1 {
		// Parse the requirements list
		requirementsStr := matches[1]
		// Remove quotes and split by comma
		requirements := strings.Split(requirementsStr, ",")
		for _, req := range requirements {
			req = strings.TrimSpace(req)
			req = strings.Trim(req, `"'`)
			if req != "" {
				name, version := a.parseRequirementString(req)
				if name != "" {
					pkg := &types.Package{
						Name:     name,
						Version:  version,
						Registry: "pypi",
						Type:     "production",
					}
					packages = append(packages, pkg)
				}
			}
		}
	}

	// Extract extras_require for optional dependencies (only if IncludeDevDeps is true)
	if a.config.Scanner.IncludeDevDeps {
		extrasRequireRegex := regexp.MustCompile(`extras_require\s*=\s*\{([^}]+)\}`)
		extrasMatches := extrasRequireRegex.FindStringSubmatch(content)
		if len(extrasMatches) > 1 {
			extrasStr := extrasMatches[1]
			// Simple parsing of extras - this could be more sophisticated
			lines := strings.Split(extrasStr, "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if strings.Contains(line, ":") {
					parts := strings.Split(line, ":")
					if len(parts) >= 2 {
						requirementsStr := parts[1]
						requirementsStr = strings.Trim(requirementsStr, " \t[],")
						requirements := strings.Split(requirementsStr, ",")
						for _, req := range requirements {
							req = strings.TrimSpace(req)
							req = strings.Trim(req, `"'`)
							if req != "" {
								name, version := a.parseRequirementString(req)
								if name != "" {
									pkg := &types.Package{
										Name:     name,
										Version:  version,
										Registry: "pypi",
										Type:     "optional",
									}
									packages = append(packages, pkg)
								}
							}
						}
					}
				}
			}
		}
	}

	return packages, nil
}

func (a *PythonAnalyzer) parsePipfile(projectInfo *ProjectInfo) ([]*types.Package, error) {
	filePath := filepath.Join(projectInfo.Path, projectInfo.ManifestFile)
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read Pipfile: %w", err)
	}

	// Parse TOML structure for Pipfile
	var pipfile struct {
		Packages    map[string]interface{} `toml:"packages"`
		DevPackages map[string]interface{} `toml:"dev-packages"`
		Requires    struct {
			PythonVersion string `toml:"python_version"`
		} `toml:"requires"`
	}

	err = toml.Unmarshal(data, &pipfile)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Pipfile: %w", err)
	}

	var packages []*types.Package

	// Parse production packages
	for name, versionSpec := range pipfile.Packages {
		version := "*"
		switch v := versionSpec.(type) {
		case string:
			version = v
		case map[string]interface{}:
			if ver, ok := v["version"]; ok {
				if verStr, ok := ver.(string); ok {
					version = verStr
				}
			}
		}

		pkg := &types.Package{
			Name:     name,
			Version:  version,
			Registry: "pypi",
			Type:     "production",
		}
		packages = append(packages, pkg)
	}

	// Parse dev packages
	for name, versionSpec := range pipfile.DevPackages {
		version := "*"
		switch v := versionSpec.(type) {
		case string:
			version = v
		case map[string]interface{}:
			if ver, ok := v["version"]; ok {
				if verStr, ok := ver.(string); ok {
					version = verStr
				}
			}
		}

		pkg := &types.Package{
			Name:     name,
			Version:  version,
			Registry: "pypi",
			Type:     "development",
		}
		packages = append(packages, pkg)
	}

	return packages, nil
}

// parsePoetryProject parses pyproject.toml files for Poetry projects
func (a *PythonAnalyzer) parsePoetryProject(projectInfo *ProjectInfo) ([]*types.Package, error) {
	// For now, delegate to the existing pyproject.toml parser
	return a.parsePyprojectToml(projectInfo)
}

// parseRequirementString parses a requirement string and returns package name and version
func (a *PythonAnalyzer) parseRequirementString(requirement string) (string, string) {
	req := strings.TrimSpace(requirement)

	// Handle editable installs
	if strings.HasPrefix(req, "-e ") {
		req = strings.TrimPrefix(req, "-e ")
	}

	// Handle git URLs
	if strings.Contains(req, "git+") && strings.Contains(req, "#egg=") {
		parts := strings.Split(req, "#egg=")
		if len(parts) == 2 {
			return parts[1], "*"
		}
	}

	// Handle local paths
	if strings.HasPrefix(req, "./") || strings.HasPrefix(req, "/") {
		// Extract package name from path
		path := strings.TrimPrefix(req, "./")
		if strings.Contains(path, "/") {
			parts := strings.Split(path, "/")
			path = parts[len(parts)-1]
		}
		return path, "*"
	}

	// Handle environment markers (remove them from version)
	if strings.Contains(req, ";") {
		parts := strings.Split(req, ";")
		req = strings.TrimSpace(parts[0])
	}

	// Handle extras (remove them from package name)
	if strings.Contains(req, "[") && strings.Contains(req, "]") {
		start := strings.Index(req, "[")
		end := strings.Index(req, "]") + 1
		if start < end {
			req = req[:start] + req[end:]
		}
	}

	// Handle standard requirements
	reqRegex := regexp.MustCompile(`^([a-zA-Z0-9_-]+)([><=!~]+)?([0-9.]+.*)?$`)
	matches := reqRegex.FindStringSubmatch(req)
	if len(matches) >= 2 {
		name := matches[1]
		version := "*"
		if len(matches) >= 4 && matches[3] != "" {
			version = matches[3]
		}
		return name, version
	}
	return requirement, "*"
}

// parseRequirementStringPreserveSpec parses a requirement string preserving version specifications
func (a *PythonAnalyzer) parseRequirementStringPreserveSpec(requirement string) (string, string) {
	req := strings.TrimSpace(requirement)

	// Handle editable installs
	if strings.HasPrefix(req, "-e ") {
		req = strings.TrimPrefix(req, "-e ")
	}

	// Handle git URLs
	if strings.Contains(req, "git+") && strings.Contains(req, "#egg=") {
		parts := strings.Split(req, "#egg=")
		if len(parts) == 2 {
			return parts[1], "*"
		}
	}

	// Handle local paths
	if strings.HasPrefix(req, "./") || strings.HasPrefix(req, "/") {
		// Extract package name from path
		path := strings.TrimPrefix(req, "./")
		if strings.Contains(path, "/") {
			parts := strings.Split(path, "/")
			path = parts[len(parts)-1]
		}
		return path, "*"
	}

	// Handle environment markers (remove them from version)
	if strings.Contains(req, ";") {
		parts := strings.Split(req, ";")
		req = strings.TrimSpace(parts[0])
	}

	// Handle extras (remove them from package name)
	if strings.Contains(req, "[") && strings.Contains(req, "]") {
		start := strings.Index(req, "[")
		end := strings.Index(req, "]") + 1
		if start < end {
			req = req[:start] + req[end:]
		}
	}

	// Handle standard requirements
	reqRegex := regexp.MustCompile(`^([a-zA-Z0-9_-]+)([><=!~]+)?([0-9.]+.*)?$`)
	matches := reqRegex.FindStringSubmatch(req)
	if len(matches) >= 2 {
		name := matches[1]
		version := "*"
		if len(matches) >= 3 && matches[2] != "" {
			// Preserve the full version specification including operators
			version = matches[2]
			if len(matches) >= 4 && matches[3] != "" {
				version += matches[3]
			}
		}
		return name, version
	}
	return requirement, "*"
}

func (a *PythonAnalyzer) AnalyzeDependencies(projectInfo *ProjectInfo) (*types.DependencyTree, error) {
	packages, err := a.ExtractPackages(projectInfo)
	if err != nil {
		return nil, err
	}

	root := &types.DependencyTree{
		Name:         "root",
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
	config   *config.Config
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
	config   *config.Config
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
	config   *config.Config
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
	config   *config.Config
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
	config   *config.Config
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
