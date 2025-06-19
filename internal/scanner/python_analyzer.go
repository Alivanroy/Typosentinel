package scanner

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"
	"typosentinel/internal/config"
	"typosentinel/pkg/logger"
	"typosentinel/pkg/types"
)

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

	logger.VerboseWithContext("Python package extraction completed", map[string]interface{}{
		"package_count": len(packages),
		"manifest_file": projectInfo.ManifestFile,
	})

	return packages, nil
}

// AnalyzeDependencies builds a dependency tree for Python projects
func (a *PythonAnalyzer) AnalyzeDependencies(projectInfo *ProjectInfo) (*types.DependencyTree, error) {
	logger.TraceFunction("PythonAnalyzer.AnalyzeDependencies")

	packages, err := a.ExtractPackages(projectInfo)
	if err != nil {
		return nil, err
	}

	// Build dependency tree
	tree := &types.DependencyTree{
		Root: &types.DependencyNode{
			Name:         "root",
			Version:      "1.0.0",
			Dependencies: make([]*types.DependencyNode, 0),
		},
		Packages: packages,
	}

	// Add packages as direct dependencies of root
	for _, pkg := range packages {
		node := &types.DependencyNode{
			Name:         pkg.Name,
			Version:      pkg.Version,
			Dependencies: make([]*types.DependencyNode, 0),
		}
		tree.Root.Dependencies = append(tree.Root.Dependencies, node)
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
	Tool struct {
		Poetry struct {
			Name         string                 `toml:"name"`
			Version      string                 `toml:"version"`
			Dependencies map[string]interface{} `toml:"dependencies"`
			DevDependencies map[string]interface{} `toml:"dev-dependencies"`
			Group        map[string]struct {
				Dependencies map[string]interface{} `toml:"dependencies"`
			} `toml:"group"`
		} `toml:"poetry"`
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

	// Parse production dependencies
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

	// Parse dev dependencies if enabled
	if a.config.Scanner.IncludeDevDeps {
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

		// Parse group dependencies
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

// parseRequirementString parses a requirement string like "package>=1.0.0"
func (a *PythonAnalyzer) parseRequirementString(req string) (string, string) {
	// Regex to match package name and version
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`^([a-zA-Z0-9_-]+)\s*==\s*([^\s]+)`),
		regexp.MustCompile(`^([a-zA-Z0-9_-]+)\s*>=\s*([^\s]+)`),
		regexp.MustCompile(`^([a-zA-Z0-9_-]+)\s*~=\s*([^\s]+)`),
		regexp.MustCompile(`^([a-zA-Z0-9_-]+)\s*<=\s*([^\s]+)`),
		regexp.MustCompile(`^([a-zA-Z0-9_-]+)\s*>\s*([^\s]+)`),
		regexp.MustCompile(`^([a-zA-Z0-9_-]+)\s*<\s*([^\s]+)`),
		regexp.MustCompile(`^([a-zA-Z0-9_-]+)\s*$`),
	}

	for _, pattern := range patterns {
		matches := pattern.FindStringSubmatch(req)
		if len(matches) >= 2 {
			name := matches[1]
			version := "*"
			if len(matches) >= 3 {
				version = matches[2]
			}
			return name, version
		}
	}

	return "", ""
}