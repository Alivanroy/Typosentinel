package scanner

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"typosentinel/internal/config"
	"typosentinel/internal/registry"
	"typosentinel/pkg/logger"
	"typosentinel/pkg/types"
)

// PythonAnalyzer analyzes Python projects
type PythonAnalyzer struct {
	config    *config.Config
	pypiClient *registry.PyPIClient
}

// NewPythonAnalyzer creates a new Python analyzer
func NewPythonAnalyzer(cfg *config.Config) *PythonAnalyzer {
	return &PythonAnalyzer{
		config:     cfg,
		pypiClient: registry.NewPyPIClient(),
	}
}

// ExtractPackages extracts packages from Python project files
func (a *PythonAnalyzer) ExtractPackages(projectInfo *ProjectInfo) ([]*types.Package, error) {
	logger.TraceFunction("PythonAnalyzer.ExtractPackages")
	logger.VerboseWithContext("Starting Python package extraction", map[string]interface{}{
		"project_path":   projectInfo.Path,
		"manifest_file":  projectInfo.ManifestFile,
		"lock_file":      projectInfo.LockFile,
	})

	var packages []*types.Package
	var err error

	switch projectInfo.ManifestFile {
	case "requirements.txt":
		packages, err = a.parseRequirementsTxt(filepath.Join(projectInfo.Path, "requirements.txt"))
	case "Pipfile":
		packages, err = a.parsePipfile(projectInfo)
	case "pyproject.toml":
		packages, err = a.parsePoetryProject(projectInfo)
	case "setup.py":
		packages, err = a.parseSetupPy(filepath.Join(projectInfo.Path, "setup.py"))
	default:
		return nil, fmt.Errorf("unsupported Python manifest file: %s", projectInfo.ManifestFile)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", projectInfo.ManifestFile, err)
	}

	// Enrich packages with PyPI metadata if enabled
	if a.config.Scanner.EnrichMetadata {
		logger.VerboseWithContext("Enriching packages with PyPI metadata", map[string]interface{}{
			"package_count": len(packages),
		})

		for _, pkg := range packages {
			if err := a.pypiClient.EnrichPackage(pkg); err != nil {
				logger.DebugWithContext("Failed to enrich package", map[string]interface{}{
					"package": pkg.Name,
					"error":   err.Error(),
				})
				// Continue with other packages even if one fails
			}
		}
	}

	logger.VerboseWithContext("Python package extraction completed", map[string]interface{}{
		"package_count": len(packages),
		"manifest_file": projectInfo.ManifestFile,
	})

	return packages, nil
}

// AnalyzeDependencies builds a comprehensive dependency tree for Python projects
func (a *PythonAnalyzer) AnalyzeDependencies(projectInfo *ProjectInfo) (*types.DependencyTree, error) {
	logger.TraceFunction("PythonAnalyzer.AnalyzeDependencies")

	packages, err := a.ExtractPackages(projectInfo)
	if err != nil {
		return nil, err
	}

	// Build enhanced dependency tree with vulnerability analysis
	tree := &types.DependencyTree{
		Name:         "root",
		Version:      "1.0.0",
		Type:         "python",
		Dependencies: make([]types.DependencyTree, 0),
		Depth:        0,
		TotalCount:   len(packages),
		CreatedAt:    time.Now(),
	}

	// Add packages as direct dependencies with enhanced analysis
	for _, pkg := range packages {
		node := types.DependencyTree{
			Name:         pkg.Name,
			Version:      pkg.Version,
			Type:         "python",
			Dependencies: make([]types.DependencyTree, 0),
			Depth:        1,
			Threats:      pkg.Threats,
		}
		
		// Analyze transitive dependencies if enabled
		if a.config.Scanner.IncludeTransitive && a.config.Scanner.MaxDepth > 1 {
			transitiveDeps, err := a.analyzeTransitiveDependencies(pkg, 2, a.config.Scanner.MaxDepth)
			if err != nil {
				logger.DebugWithContext("Failed to analyze transitive dependencies", map[string]interface{}{
					"package": pkg.Name,
					"error":   err.Error(),
				})
			} else {
				node.Dependencies = transitiveDeps
			}
		}
		
		tree.Dependencies = append(tree.Dependencies, node)
	}

	return tree, nil
}

// parseRequirementsTxt parses requirements.txt file
func (a *PythonAnalyzer) parseRequirementsTxt(filePath string) ([]*types.Package, error) {
	logger.DebugWithContext("Parsing requirements.txt", map[string]interface{}{
		"file_path": filePath,
	})

	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var packages []*types.Package
	scanner := bufio.NewScanner(file)

	// Regex patterns for different requirement formats
	patterns := []*regexp.Regexp{
		// package==1.0.0
		regexp.MustCompile(`^([a-zA-Z0-9_-]+)\s*==\s*([^\s#]+)`),
		// package>=1.0.0
		regexp.MustCompile(`^([a-zA-Z0-9_-]+)\s*>=\s*([^\s#,]+)`),
		// package~=1.0.0
		regexp.MustCompile(`^([a-zA-Z0-9_-]+)\s*~=\s*([^\s#,]+)`),
		// package<=1.0.0
		regexp.MustCompile(`^([a-zA-Z0-9_-]+)\s*<=\s*([^\s#,]+)`),
		// package>1.0.0
		regexp.MustCompile(`^([a-zA-Z0-9_-]+)\s*>\s*([^\s#,]+)`),
		// package<1.0.0
		regexp.MustCompile(`^([a-zA-Z0-9_-]+)\s*<\s*([^\s#,]+)`),
		// package (no version)
		regexp.MustCompile(`^([a-zA-Z0-9_-]+)\s*$`),
	}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		
		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Skip -r or --requirement includes
		if strings.HasPrefix(line, "-r ") || strings.HasPrefix(line, "--requirement ") {
			continue
		}

		// Skip -e or --editable installs
		if strings.HasPrefix(line, "-e ") || strings.HasPrefix(line, "--editable ") {
			continue
		}

		// Try to match against patterns
		var name, version string
		matched := false

		for _, pattern := range patterns {
			matches := pattern.FindStringSubmatch(line)
			if len(matches) >= 2 {
				name = matches[1]
				if len(matches) >= 3 {
					version = matches[2]
				} else {
					version = "*"
				}
				matched = true
				break
			}
		}

		if matched {
			pkg := &types.Package{
				Name:     name,
				Version:  version,
				Registry: "pypi",
				Type:     "production",
			}
			packages = append(packages, pkg)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return packages, nil
}

// PipfileData represents the structure of a Pipfile
type PipfileData struct {
	Packages    map[string]interface{} `toml:"packages"`
	DevPackages map[string]interface{} `toml:"dev-packages"`
	Requires    map[string]interface{} `toml:"requires"`
	Source      []map[string]interface{} `toml:"source"`
}

// PipfileLockData represents the structure of a Pipfile.lock
type PipfileLockData struct {
	Default map[string]PipfileLockPackage `json:"default"`
	Develop map[string]PipfileLockPackage `json:"develop"`
}

type PipfileLockPackage struct {
	Version string   `json:"version"`
	Hashes  []string `json:"hashes"`
	Index   string   `json:"index"`
}

// parsePipfile parses Pipfile and Pipfile.lock
func (a *PythonAnalyzer) parsePipfile(projectInfo *ProjectInfo) ([]*types.Package, error) {
	logger.DebugWithContext("Parsing Pipfile", map[string]interface{}{
		"project_path": projectInfo.Path,
		"lock_file":    projectInfo.LockFile,
	})

	var packages []*types.Package

	// Parse Pipfile.lock if available (more precise)
	if projectInfo.LockFile == "Pipfile.lock" {
		lockPath := filepath.Join(projectInfo.Path, "Pipfile.lock")
		lockPackages, err := a.parsePipfileLock(lockPath)
		if err == nil {
			return lockPackages, nil
		}
		logger.Warn("Failed to parse Pipfile.lock, falling back to Pipfile")
	}

	// Parse Pipfile
	pipfilePath := filepath.Join(projectInfo.Path, "Pipfile")
	data, err := os.ReadFile(pipfilePath)
	if err != nil {
		return nil, err
	}

	var pipfile PipfileData
	if err := toml.Unmarshal(data, &pipfile); err != nil {
		return nil, err
	}

	// Parse production packages
	for name, versionSpec := range pipfile.Packages {
		version := a.parseVersionSpec(versionSpec)
		pkg := &types.Package{
			Name:     name,
			Version:  version,
			Registry: "pypi",
			Type:     "production",
		}
		packages = append(packages, pkg)
	}

	// Parse dev packages if enabled
	if a.config.Scanner.IncludeDevDeps {
		for name, versionSpec := range pipfile.DevPackages {
			version := a.parseVersionSpec(versionSpec)
			pkg := &types.Package{
				Name:     name,
				Version:  version,
				Registry: "pypi",
				Type:     "development",
			}
			packages = append(packages, pkg)
		}
	}

	return packages, nil
}

// parsePipfileLock parses Pipfile.lock for exact versions
func (a *PythonAnalyzer) parsePipfileLock(filePath string) ([]*types.Package, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var lockData PipfileLockData
	if err := json.Unmarshal(data, &lockData); err != nil {
		return nil, err
	}

	var packages []*types.Package

	// Parse production packages
	for name, lockPkg := range lockData.Default {
		version := strings.TrimPrefix(lockPkg.Version, "==")
		pkg := &types.Package{
			Name:     name,
			Version:  version,
			Registry: "pypi",
			Type:     "production",
		}
		packages = append(packages, pkg)
	}

	// Parse dev packages if enabled
	if a.config.Scanner.IncludeDevDeps {
		for name, lockPkg := range lockData.Develop {
			version := strings.TrimPrefix(lockPkg.Version, "==")
			pkg := &types.Package{
				Name:     name,
				Version:  version,
				Registry: "pypi",
				Type:     "development",
			}
			packages = append(packages, pkg)
		}
	}

	return packages, nil
}

// PyprojectTomlData represents the structure of pyproject.toml
type PyprojectTomlData struct {
	// PEP 621 standard project metadata
	Project struct {
		Name         string                 `toml:"name"`
		Version      string                 `toml:"version"`
		Description  string                 `toml:"description"`
		Authors      []map[string]string    `toml:"authors"`
		Maintainers  []map[string]string    `toml:"maintainers"`
		License      map[string]string      `toml:"license"`
		Keywords     []string               `toml:"keywords"`
		Classifiers  []string               `toml:"classifiers"`
		Dependencies []string               `toml:"dependencies"`
		OptionalDependencies map[string][]string `toml:"optional-dependencies"`
		URLs         map[string]string      `toml:"urls"`
		RequiresPython string               `toml:"requires-python"`
	} `toml:"project"`

	// Build system requirements
	BuildSystem struct {
		Requires     []string `toml:"requires"`
		BuildBackend string   `toml:"build-backend"`
	} `toml:"build-system"`

	// Tool-specific configurations
	Tool struct {
		// Poetry configuration
		Poetry struct {
			Name         string                 `toml:"name"`
			Version      string                 `toml:"version"`
			Description  string                 `toml:"description"`
			Authors      []string               `toml:"authors"`
			Maintainers  []string               `toml:"maintainers"`
			License      string                 `toml:"license"`
			Keywords     []string               `toml:"keywords"`
			Classifiers  []string               `toml:"classifiers"`
			Homepage     string                 `toml:"homepage"`
			Repository   string                 `toml:"repository"`
			Documentation string               `toml:"documentation"`
			Dependencies map[string]interface{} `toml:"dependencies"`
			DevDependencies map[string]interface{} `toml:"dev-dependencies"`
			Group        map[string]struct {
				Dependencies map[string]interface{} `toml:"dependencies"`
			} `toml:"group"`
		} `toml:"poetry"`

		// Setuptools configuration
		Setuptools struct {
			Packages map[string]interface{} `toml:"packages"`
		} `toml:"setuptools"`

		// PDM configuration
		PDM struct {
			DevDeps map[string][]string `toml:"dev-deps"`
		} `toml:"pdm"`

		// Hatch configuration
		Hatch struct {
			Envs map[string]struct {
				Dependencies []string `toml:"dependencies"`
			} `toml:"envs"`
		} `toml:"hatch"`
	} `toml:"tool"`
}

// PoetryLockData represents the structure of poetry.lock
type PoetryLockData struct {
	Packages []PoetryLockPackage `toml:"package"`
}

type PoetryLockPackage struct {
	Name     string `toml:"name"`
	Version  string `toml:"version"`
	Category string `toml:"category"`
}

// parsePoetryProject parses pyproject.toml and poetry.lock
func (a *PythonAnalyzer) parsePoetryProject(projectInfo *ProjectInfo) ([]*types.Package, error) {
	logger.DebugWithContext("Parsing Poetry project", map[string]interface{}{
		"project_path": projectInfo.Path,
		"lock_file":    projectInfo.LockFile,
	})

	var packages []*types.Package

	// Parse poetry.lock if available (more precise)
	if projectInfo.LockFile == "poetry.lock" {
		lockPath := filepath.Join(projectInfo.Path, "poetry.lock")
		lockPackages, err := a.parsePoetryLock(lockPath)
		if err == nil {
			return lockPackages, nil
		}
		logger.Warn("Failed to parse poetry.lock, falling back to pyproject.toml")
	}

	// Parse pyproject.toml
	pyprojectPath := filepath.Join(projectInfo.Path, "pyproject.toml")
	data, err := os.ReadFile(pyprojectPath)
	if err != nil {
		return nil, err
	}

	var pyproject PyprojectTomlData
	if err := toml.Unmarshal(data, &pyproject); err != nil {
		return nil, err
	}

	// Parse PEP 621 standard dependencies first
	if len(pyproject.Project.Dependencies) > 0 {
		for _, depStr := range pyproject.Project.Dependencies {
			name, version := a.parseRequirementStringPreserveSpec(depStr)
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

	// Parse PEP 621 optional dependencies
	for groupName, deps := range pyproject.Project.OptionalDependencies {
		for _, depStr := range deps {
			name, version := a.parseRequirementStringPreserveSpec(depStr)
			if name != "" {
				pkg := &types.Package{
					Name:     name,
					Version:  version,
					Registry: "pypi",
					Type:     fmt.Sprintf("optional-%s", groupName),
				}
				packages = append(packages, pkg)
			}
		}
	}

	// Parse build system requirements
	for _, depStr := range pyproject.BuildSystem.Requires {
		name, version := a.parseRequirementStringPreserveSpec(depStr)
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

	// Parse Poetry-specific dependencies (for backward compatibility)
	for name, versionSpec := range pyproject.Tool.Poetry.Dependencies {
		// Skip python version requirement
		if name == "python" {
			continue
		}
		version := a.parseVersionSpec(versionSpec)
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
		version := a.parseVersionSpec(versionSpec)
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
			version := a.parseVersionSpec(versionSpec)
			pkg := &types.Package{
				Name:     name,
				Version:  version,
				Registry: "pypi",
				Type:     fmt.Sprintf("group-%s", groupName),
			}
			packages = append(packages, pkg)
		}
	}

	// Parse PDM dev dependencies
	for groupName, deps := range pyproject.Tool.PDM.DevDeps {
		for _, depStr := range deps {
			name, version := a.parseRequirementStringPreserveSpec(depStr)
			if name != "" {
				pkg := &types.Package{
					Name:     name,
					Version:  version,
					Registry: "pypi",
					Type:     fmt.Sprintf("pdm-%s", groupName),
				}
				packages = append(packages, pkg)
			}
		}
	}

	// Parse Hatch environment dependencies
	for envName, env := range pyproject.Tool.Hatch.Envs {
		for _, depStr := range env.Dependencies {
			name, version := a.parseRequirementStringPreserveSpec(depStr)
			if name != "" {
				pkg := &types.Package{
					Name:     name,
					Version:  version,
					Registry: "pypi",
					Type:     fmt.Sprintf("hatch-%s", envName),
				}
				packages = append(packages, pkg)
			}
		}
	}

	return packages, nil
}

// parsePoetryLock parses poetry.lock for exact versions
func (a *PythonAnalyzer) parsePoetryLock(filePath string) ([]*types.Package, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var lockData PoetryLockData
	if err := toml.Unmarshal(data, &lockData); err != nil {
		return nil, err
	}

	var packages []*types.Package

	for _, lockPkg := range lockData.Packages {
		// Determine package type based on category
		pkgType := "production"
		if lockPkg.Category == "dev" {
			pkgType = "development"
			// Skip dev dependencies if not enabled
			if !a.config.Scanner.IncludeDevDeps {
				continue
			}
		}

		pkg := &types.Package{
			Name:     lockPkg.Name,
			Version:  lockPkg.Version,
			Registry: "pypi",
			Type:     pkgType,
		}
		packages = append(packages, pkg)
	}

	return packages, nil
}

// parseSetupPy parses setup.py for basic dependency information
func (a *PythonAnalyzer) parseSetupPy(filePath string) ([]*types.Package, error) {
	logger.DebugWithContext("Parsing setup.py", map[string]interface{}{
		"file_path": filePath,
	})

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	content := string(data)
	var packages []*types.Package

	// Look for install_requires pattern
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

			if req == "" {
				continue
			}

			// Parse package name and version
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

	return packages, nil
}

// parseVersionSpec parses various version specification formats
func (a *PythonAnalyzer) parseVersionSpec(versionSpec interface{}) string {
	switch v := versionSpec.(type) {
	case string:
		return v
	case map[string]interface{}:
		// Handle complex version specifications like {version = "^1.0.0"}
		if version, ok := v["version"].(string); ok {
			return version
		}
		return "*"
	default:
		return "*"
	}
}

// parseRequirementStringPreserveSpec parses a requirement string and preserves the full version specification
func (a *PythonAnalyzer) parseRequirementStringPreserveSpec(req string) (string, string) {
	// Clean up the requirement string
	req = strings.TrimSpace(req)
	
	// Handle editable installs
	if strings.HasPrefix(req, "-e ") {
		req = strings.TrimPrefix(req, "-e ")
		req = strings.TrimSpace(req)
	}
	
	// Handle Git URLs
	if strings.HasPrefix(req, "git+") {
		// Extract package name from #egg= parameter
		if eggIndex := strings.Index(req, "#egg="); eggIndex != -1 {
			eggPart := req[eggIndex+5:]
			// Remove any additional parameters after the egg name
			if ampIndex := strings.Index(eggPart, "&"); ampIndex != -1 {
				eggPart = eggPart[:ampIndex]
			}
			return eggPart, "*"
		}
		return "", ""
	}
	
	// Handle local paths
	if strings.HasPrefix(req, "./") || strings.HasPrefix(req, "/") {
		// Extract directory name as package name
		path := strings.TrimPrefix(req, "./")
		if lastSlash := strings.LastIndex(path, "/"); lastSlash != -1 {
			path = path[lastSlash+1:]
		}
		return path, "*"
	}
	
	// Remove environment markers (everything after semicolon)
	if semiIndex := strings.Index(req, ";"); semiIndex != -1 {
		req = req[:semiIndex]
		req = strings.TrimSpace(req)
	}
	
	// Remove extras (everything in square brackets)
	if bracketStart := strings.Index(req, "["); bracketStart != -1 {
		if bracketEnd := strings.Index(req, "]"); bracketEnd != -1 {
			req = req[:bracketStart] + req[bracketEnd+1:]
			req = strings.TrimSpace(req)
		}
	}
	
	// Parse version constraints - preserve full specification
	patterns := []*regexp.Regexp{
		// Complex version ranges like ">=2.25.0,<3.0.0"
		regexp.MustCompile(`^([a-zA-Z0-9_.-]+)\s*([><=~!^]+[^,\s]+(?:,[><=~!^]+[^,\s]+)*)`),
		// Simple version constraints
		regexp.MustCompile(`^([a-zA-Z0-9_.-]+)\s*(==|>=|<=|~=|!=|>|<|\^)\s*([^\s]+)`),
		// Package name only
		regexp.MustCompile(`^([a-zA-Z0-9_.-]+)\s*$`),
	}
	
	for _, pattern := range patterns {
		matches := pattern.FindStringSubmatch(req)
		if len(matches) >= 2 {
			name := matches[1]
			version := "*"
			if len(matches) >= 3 {
				if len(matches) == 4 {
					// Format: name operator version - preserve full specification
					version = matches[2] + matches[3]
				} else {
					// Format: name version_spec (complex) - preserve full specification
					version = matches[2]
				}
			}
			return name, version
		}
	}
	
	return "", ""
}

// analyzeTransitiveDependencies recursively analyzes package dependencies
func (a *PythonAnalyzer) analyzeTransitiveDependencies(pkg *types.Package, currentDepth, maxDepth int) ([]types.DependencyTree, error) {
	if currentDepth > maxDepth {
		return nil, nil
	}

	// Fetch package metadata from PyPI to get dependencies
	if pkg.Metadata == nil || pkg.Metadata.Dependencies == nil {
		return nil, nil
	}

	var dependencies []types.DependencyTree
	for _, depName := range pkg.Metadata.Dependencies {
		// Parse dependency specification
		name, version := a.parseRequirementStringPreserveSpec(depName)
		if name == "" {
			continue
		}

		depPkg := &types.Package{
			Name:     name,
			Version:  version,
			Registry: "pypi",
			Type:     "transitive",
		}

		// Enrich transitive dependency if enabled
		if a.config.Scanner.EnrichMetadata {
			if err := a.pypiClient.EnrichPackage(depPkg); err != nil {
				logger.DebugWithContext("Failed to enrich transitive dependency", map[string]interface{}{
					"package": depPkg.Name,
					"error":   err.Error(),
				})
			}
		}

		depNode := types.DependencyTree{
			Name:         depPkg.Name,
			Version:      depPkg.Version,
			Type:         "python",
			Dependencies: make([]types.DependencyTree, 0),
			Depth:        currentDepth,
			Threats:      depPkg.Threats,
		}

		// Recursively analyze deeper dependencies
		if currentDepth < maxDepth {
			subDeps, err := a.analyzeTransitiveDependencies(depPkg, currentDepth+1, maxDepth)
			if err == nil {
				depNode.Dependencies = subDeps
			}
		}

		dependencies = append(dependencies, depNode)
	}

	return dependencies, nil
}

// DetectVulnerabilities checks for known vulnerabilities in Python packages
func (a *PythonAnalyzer) DetectVulnerabilities(packages []*types.Package) error {
	logger.TraceFunction("PythonAnalyzer.DetectVulnerabilities")

	for _, pkg := range packages {
		// Check against known vulnerability patterns
		vulns := a.checkVulnerabilityPatterns(pkg)
		if len(vulns) > 0 {
			pkg.Threats = append(pkg.Threats, vulns...)
		}

		// Check for suspicious package characteristics
		suspiciousThreats := a.detectSuspiciousCharacteristics(pkg)
		if len(suspiciousThreats) > 0 {
			pkg.Threats = append(pkg.Threats, suspiciousThreats...)
		}
	}

	return nil
}

// checkVulnerabilityPatterns checks for known vulnerability patterns
func (a *PythonAnalyzer) checkVulnerabilityPatterns(pkg *types.Package) []types.Threat {
	var threats []types.Threat

	// Known malicious package patterns
	maliciousPatterns := []string{
		"urllib3", "requests", "numpy", "pandas", "tensorflow", // Common typosquatting targets
	}

	for _, pattern := range maliciousPatterns {
		if a.isTyposquattingCandidate(pkg.Name, pattern) {
			threats = append(threats, types.Threat{
				Type:        "typosquatting",
				Severity:    types.SeverityHigh,
				Description: fmt.Sprintf("Package name '%s' is similar to popular package '%s'", pkg.Name, pattern),
				DetectionMethod: "python_analyzer",
			})
		}
	}

	return threats
}

// detectSuspiciousCharacteristics identifies suspicious package characteristics
func (a *PythonAnalyzer) detectSuspiciousCharacteristics(pkg *types.Package) []types.Threat {
	var threats []types.Threat

	// Check for suspicious version patterns
	if a.isSuspiciousVersion(pkg.Version) {
		threats = append(threats, types.Threat{
			Type:        "suspicious_version",
			Severity:    types.SeverityMedium,
			Description: fmt.Sprintf("Package version '%s' follows suspicious pattern", pkg.Version),
			DetectionMethod: "python_analyzer",
		})
	}

	// Check metadata for suspicious indicators
	if pkg.Metadata != nil {
		if metadata, ok := pkg.Metadata.Metadata["description"].(string); ok {
			if a.isSuspiciousDescription(metadata) {
				threats = append(threats, types.Threat{
					Type:        "suspicious_description",
					Severity:    types.SeverityLow,
					Description: "Package description contains suspicious content",
					DetectionMethod: "python_analyzer",
				})
			}
		}
	}

	return threats
}

// isTyposquattingCandidate checks if a package name is a potential typosquatting attempt
func (a *PythonAnalyzer) isTyposquattingCandidate(packageName, targetName string) bool {
	// Simple Levenshtein distance check
	distance := a.levenshteinDistance(packageName, targetName)
	maxDistance := len(targetName) / 3 // Allow up to 1/3 character differences
	if maxDistance < 1 {
		maxDistance = 1
	}
	return distance > 0 && distance <= maxDistance && packageName != targetName
}

// levenshteinDistance calculates the Levenshtein distance between two strings
func (a *PythonAnalyzer) levenshteinDistance(s1, s2 string) int {
	if len(s1) == 0 {
		return len(s2)
	}
	if len(s2) == 0 {
		return len(s1)
	}

	matrix := make([][]int, len(s1)+1)
	for i := range matrix {
		matrix[i] = make([]int, len(s2)+1)
		matrix[i][0] = i
	}
	for j := range matrix[0] {
		matrix[0][j] = j
	}

	for i := 1; i <= len(s1); i++ {
		for j := 1; j <= len(s2); j++ {
			cost := 0
			if s1[i-1] != s2[j-1] {
				cost = 1
			}
			matrix[i][j] = min(
				matrix[i-1][j]+1,      // deletion
				matrix[i][j-1]+1,      // insertion
				matrix[i-1][j-1]+cost, // substitution
			)
		}
	}

	return matrix[len(s1)][len(s2)]
}

// min returns the minimum of three integers
func min(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}

// isSuspiciousVersion checks if a version string follows suspicious patterns
func (a *PythonAnalyzer) isSuspiciousVersion(version string) bool {
	// Check for very high version numbers (potential version spoofing)
	if strings.Contains(version, "999") || strings.Contains(version, "9999") {
		return true
	}

	// Check for suspicious pre-release patterns
	suspiciousPatterns := []string{
		"dev999", "alpha999", "beta999", "rc999",
	}
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(version, pattern) {
			return true
		}
	}

	return false
}

// isSuspiciousDescription checks if a package description contains suspicious content
func (a *PythonAnalyzer) isSuspiciousDescription(description string) bool {
	descLower := strings.ToLower(description)
	
	// Check for suspicious keywords
	suspiciousKeywords := []string{
		"bitcoin", "cryptocurrency", "wallet", "private key",
		"password", "credential", "token", "secret",
		"download", "install", "execute", "run",
	}

	for _, keyword := range suspiciousKeywords {
		if strings.Contains(descLower, keyword) {
			return true
		}
	}

	return false
}

// parseRequirementString parses a requirement string like "package>=1.0.0" and extracts clean version numbers
func (a *PythonAnalyzer) parseRequirementString(req string) (string, string) {
	// Clean up the requirement string
	req = strings.TrimSpace(req)
	
	// Handle editable installs
	if strings.HasPrefix(req, "-e ") {
		req = strings.TrimPrefix(req, "-e ")
		req = strings.TrimSpace(req)
	}
	
	// Handle Git URLs
	if strings.HasPrefix(req, "git+") {
		// Extract package name from #egg= parameter
		if eggIndex := strings.Index(req, "#egg="); eggIndex != -1 {
			eggPart := req[eggIndex+5:]
			// Remove any additional parameters after the egg name
			if ampIndex := strings.Index(eggPart, "&"); ampIndex != -1 {
				eggPart = eggPart[:ampIndex]
			}
			return eggPart, "*"
		}
		return "", ""
	}
	
	// Handle local paths
	if strings.HasPrefix(req, "./") || strings.HasPrefix(req, "/") {
		// Extract directory name as package name
		path := strings.TrimPrefix(req, "./")
		if lastSlash := strings.LastIndex(path, "/"); lastSlash != -1 {
			path = path[lastSlash+1:]
		}
		return path, "*"
	}
	
	// Remove environment markers (everything after semicolon)
	if semiIndex := strings.Index(req, ";"); semiIndex != -1 {
		req = req[:semiIndex]
		req = strings.TrimSpace(req)
	}
	
	// Remove extras (everything in square brackets)
	if bracketStart := strings.Index(req, "["); bracketStart != -1 {
		if bracketEnd := strings.Index(req, "]"); bracketEnd != -1 {
			req = req[:bracketStart] + req[bracketEnd+1:]
			req = strings.TrimSpace(req)
		}
	}
	
	// Parse version constraints - handle complex version ranges
	patterns := []*regexp.Regexp{
		// Complex version ranges like ">=2.25.0,<3.0.0"
		regexp.MustCompile(`^([a-zA-Z0-9_.-]+)\s*([><=~!]+[^,\s]+(?:,[><=~!]+[^,\s]+)*)`),
		// Simple version constraints
		regexp.MustCompile(`^([a-zA-Z0-9_.-]+)\s*(==|>=|<=|~=|!=|>|<)\s*([^\s]+)`),
		// Package name only
		regexp.MustCompile(`^([a-zA-Z0-9_.-]+)\s*$`),
	}
	
	for _, pattern := range patterns {
		matches := pattern.FindStringSubmatch(req)
		if len(matches) >= 2 {
			name := matches[1]
			version := "*"
			if len(matches) >= 3 {
				if len(matches) == 4 {
					// Format: name operator version - extract just the version number
					version = matches[3]
				} else {
					// Format: name version_spec (complex) - extract the first version number
					versionSpec := matches[2]
					// Extract version number from complex spec like ">=2.25.0,<3.0.0"
					versionRegex := regexp.MustCompile(`[><=~!]*([0-9]+(?:\.[0-9]+)*(?:\.[0-9]+)*)`)
					versionMatches := versionRegex.FindStringSubmatch(versionSpec)
					if len(versionMatches) >= 2 {
						version = versionMatches[1]
					} else {
						version = versionSpec
					}
				}
			}
			return name, version
		}
	}
	
	return "", ""
}