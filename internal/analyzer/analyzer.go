package analyzer

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/internal/detector"
	"github.com/Alivanroy/Typosentinel/internal/registry"
	"github.com/Alivanroy/Typosentinel/internal/scanner"
	"github.com/Alivanroy/Typosentinel/internal/vulnerability"
	"github.com/Alivanroy/Typosentinel/pkg/types"
	"github.com/pelletier/go-toml/v2"
	"github.com/sirupsen/logrus"
)

// Analyzer orchestrates the security scanning process
type Analyzer struct {
	config       *config.Config
	detector     *detector.Engine
	registries   map[string]registry.Connector
	resolver     *DependencyResolver
	autoDetector *registry.AutoDetector
	factory      *registry.Factory
	stubRepo     *StubRepo
}

// ScanOptions contains options for scanning
type ScanOptions struct {
	OutputFormat           string
	SpecificFile           string
	DeepAnalysis           bool
	IncludeDevDependencies bool
	SimilarityThreshold    float64
	ExcludePackages        []string
	AllowEmptyProjects     bool
	CheckVulnerabilities   bool
	VulnerabilityDBs       []string
	VulnConfigPath         string
	// Recursive scanning options
	Recursive         bool
	WorkspaceAware    bool
	ConsolidateReport bool
	PackageManagers   []string
	// Supply chain analysis options
	EnableSupplyChain bool
	AdvancedAnalysis  bool
}

// ScanResult contains the results of a security scan
type ScanResult struct {
	ScanID        string                 `json:"scan_id"`
	Timestamp     time.Time              `json:"timestamp"`
	Duration      time.Duration          `json:"duration"`
	Path          string                 `json:"path"`
	TotalPackages int                    `json:"total_packages"`
	Threats       []types.Threat         `json:"threats"`
	Warnings      []types.Warning        `json:"warnings"`
	Resolution    *ResolutionResult      `json:"resolution,omitempty"`
	Summary       ScanSummary            `json:"summary"`
	Metadata      map[string]interface{} `json:"metadata"`
}

// ScanSummary provides a high-level overview of scan results
type ScanSummary struct {
	CriticalThreats int `json:"critical_threats"`
	HighThreats     int `json:"high_threats"`
	MediumThreats   int `json:"medium_threats"`
	LowThreats      int `json:"low_threats"`
	TotalWarnings   int `json:"total_warnings"`
	CleanPackages   int `json:"clean_packages"`
	ConflictCount   int `json:"conflict_count"`
}

// New creates a new analyzer instance
func New(cfg *config.Config) (*Analyzer, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	// Initialize detector engine
	detectorEngine := detector.New(cfg)

	// Initialize dependency resolver
	resolver := NewDependencyResolver(cfg.Scanner)

	// Initialize registry factory and auto-detector
	factory := registry.NewFactory()
	autoDetector := registry.NewAutoDetector()

	return &Analyzer{
		config:       cfg,
		detector:     detectorEngine,
		resolver:     resolver,
		autoDetector: autoDetector,
		factory:      factory,
		registries:   make(map[string]registry.Connector),
	}, nil
}

// Scan performs a security scan of the specified path
func (a *Analyzer) Scan(path string, options *ScanOptions) (*ScanResult, error) {
	start := time.Now()
	scanID := generateScanID()

	logrus.Infof("Starting scan %s for path: %s", scanID, path)

	// Handle enhanced supply chain scanning
	if options.EnableSupplyChain {
		return a.scanWithSupplyChain(path, options)
	}

	// Initialize scan result
	result := &ScanResult{
		ScanID:    scanID,
		Timestamp: start,
		Path:      path,
		Metadata:  make(map[string]interface{}),
	}

	// Handle recursive scanning
	if options.Recursive {
		return a.scanRecursive(path, options, result)
	}

	// Use auto-detection if no specific package managers are specified
	if len(options.PackageManagers) == 0 {
		// Auto-detect project types and create registry connectors
		projects, err := a.autoDetector.DetectAllProjectTypes(path)
		if err != nil {
			logrus.Warnf("Auto-detection failed: %v", err)
		} else {
			logrus.Infof("Auto-detected %d projects", len(projects))
			// Create registry connectors for detected project types
			connectors, err := a.autoDetector.CreateConnectorsForProjects(projects)
			if err != nil {
				logrus.Warnf("Failed to create connectors: %v", err)
			} else {
				// Add connectors to the analyzer's registry map
				for registryType, connector := range connectors {
					a.registries[registryType] = connector
					logrus.Debugf("Created %s registry connector", registryType)
				}
			}
		}
	}

	// Discover dependency files
	depFiles, err := a.discoverDependencyFiles(path, options)
	if err != nil {
		return nil, fmt.Errorf("failed to discover dependency files: %w", err)
	}

	if len(depFiles) == 0 {
		if options.AllowEmptyProjects {
			// No dependency files found - return empty result instead of error
			logrus.Infof("No dependency files found in %s", path)
			result.TotalPackages = 0
			result.Threats = []types.Threat{}
			result.Warnings = []types.Warning{}
			result.Duration = time.Since(start)
			return result, nil
		} else {
			return nil, fmt.Errorf("no dependency files found in %s", path)
		}
	}

	logrus.Infof("Found %d dependency files", len(depFiles))

	// Parse dependencies from all files
	allDependencies := make([]types.Dependency, 0)
	for _, file := range depFiles {
		deps, err := a.parseDependencyFile(file, options)
		if err != nil {
			logrus.Warnf("Failed to parse %s: %v", file, err)
			continue
		}
		allDependencies = append(allDependencies, deps...)
	}

	result.TotalPackages = len(allDependencies)
	logrus.Infof("Analyzing %d dependencies", len(allDependencies))

	// Filter excluded packages
	filteredDeps := a.filterDependencies(allDependencies, options.ExcludePackages)

	// Resolve dependencies and detect conflicts
	var resolution *ResolutionResult
	if a.resolver != nil {
		resolution, err = a.resolver.ResolveDependencies(filteredDeps)
		if err != nil {
			logrus.Warnf("Dependency resolution failed: %v", err)
		} else {
			logrus.Debugf("Dependency resolution completed: %d conflicts, %d warnings",
				len(resolution.Conflicts), len(resolution.Warnings))

			// Use resolved dependencies for threat detection if available
			if len(resolution.Resolved) > 0 {
				filteredDeps = resolution.Resolved
			}
		}
	}

	// Perform threat detection
	ctx := context.Background()
	threats, warnings, err := a.detectThreats(ctx, filteredDeps, options)
	if err != nil {
		return nil, fmt.Errorf("threat detection failed: %w", err)
	}

	result.Threats = threats
	result.Warnings = warnings
	result.Resolution = resolution
	result.Duration = time.Since(start)
	result.Summary = a.calculateSummary(threats, warnings, len(filteredDeps))

	// Update summary with resolution data if available
	if resolution != nil {
		result.Summary.ConflictCount = len(resolution.Conflicts)
		result.Summary.TotalWarnings += len(resolution.Warnings)
	}

	// Add metadata
	result.Metadata["dependency_files"] = depFiles
	result.Metadata["scan_options"] = options
	result.Metadata["detector_version"] = a.detector.Version()

	logrus.Infof("Scan %s completed in %v. Found %d threats, %d warnings",
		scanID, result.Duration, len(threats), len(warnings))

	return result, nil
}

// ScanPackage performs a security scan on a single package (for integration tests)
func (a *Analyzer) ScanPackage(ctx context.Context, pkg *types.Package) (*types.ScanResult, error) {
	start := time.Now()
	scanID := generateScanID()

	logrus.Infof("Starting package scan %s for package: %s@%s", scanID, pkg.Name, pkg.Version)

	// Create dependency from package
	var metadata types.PackageMetadata
	if pkg.Metadata != nil {
		metadata = *pkg.Metadata
	} else {
		metadata = types.PackageMetadata{
			Name:     pkg.Name,
			Version:  pkg.Version,
			Registry: pkg.Registry,
		}
	}

	dep := types.Dependency{
		Name:     pkg.Name,
		Version:  pkg.Version,
		Registry: pkg.Registry,
		Direct:   true,
		Metadata: metadata,
	}

	// Perform threat detection on single package
	threats, warnings, err := a.detectThreats(ctx, []types.Dependency{dep}, &ScanOptions{
		DeepAnalysis:           true,
		IncludeDevDependencies: false,
		SimilarityThreshold:    0.8,
		CheckVulnerabilities:   true,
		VulnerabilityDBs:       []string{"osv"}, // Use OSV database for testing
	})
	if err != nil {
		return nil, fmt.Errorf("threat detection failed: %w", err)
	}

	// Calculate risk score
	riskScore := a.calculateRiskScore(threats, 1)
	overallRisk := a.determineOverallRisk(riskScore)

	// Create summary with engines used
	enginesUsed := []string{"typosquatting", "homoglyph", "semantic"}
	if len(threats) > 0 {
		enginesUsed = append(enginesUsed, "vulnerability")
	}

	summary := &types.ScanSummary{
		TotalPackages:   1,
		ScannedPackages: 1,
		CleanPackages:   0,
		TotalThreats:    len(threats),
		TotalWarnings:   len(warnings),
		ThreatsFound:    len(threats),
		EnginesUsed:     enginesUsed,
	}

	if len(threats) == 0 {
		summary.CleanPackages = 1
	}

	// Count threats by severity
	for _, threat := range threats {
		switch threat.Severity {
		case types.SeverityCritical:
			summary.CriticalThreats++
		case types.SeverityHigh:
			summary.HighThreats++
		case types.SeverityMedium:
			summary.MediumThreats++
		case types.SeverityLow:
			summary.LowThreats++
		}
	}

	// Generate recommendations based on threats
	recommendations := []string{}
	if len(threats) > 0 {
		recommendations = append(recommendations, "Consider using alternative packages with better security reputation")
		recommendations = append(recommendations, "Review package dependencies for potential security issues")
		if riskScore > 0.7 {
			recommendations = append(recommendations, "Avoid using this package in production environments")
		}
	}

	// Create scan result
	result := &types.ScanResult{
		ID:              scanID,
		Target:          pkg.Name,
		Type:            "package",
		Status:          "completed",
		OverallRisk:     overallRisk,
		RiskScore:       riskScore,
		Packages:        []*types.Package{pkg},
		Summary:         summary,
		Duration:        time.Since(start),
		Recommendations: recommendations,
		CreatedAt:       start,
	}

	logrus.Infof("Package scan %s completed in %v. Found %d threats, %d warnings",
		scanID, result.Duration, len(threats), len(warnings))

	return result, nil
}

// calculateRiskScore calculates a risk score based on threats
func (a *Analyzer) calculateRiskScore(threats []types.Threat, packageCount int) float64 {
	if len(threats) == 0 {
		return 0.0
	}

	totalScore := 0.0
	for _, threat := range threats {
		switch threat.Severity {
		case types.SeverityCritical:
			totalScore += 1.0
		case types.SeverityHigh:
			totalScore += 0.8
		case types.SeverityMedium:
			totalScore += 0.5
		case types.SeverityLow:
			totalScore += 0.2
		}
	}

	// Normalize by package count and cap at 1.0
	score := totalScore / float64(packageCount)
	if score > 1.0 {
		score = 1.0
	}

	return score
}

// determineOverallRisk determines overall risk level from score
func (a *Analyzer) determineOverallRisk(score float64) string {
	if score >= 0.8 {
		return "critical"
	} else if score >= 0.6 {
		return "high"
	} else if score >= 0.4 {
		return "medium"
	} else if score > 0.0 {
		return "low"
	}
	return "minimal"
}

// discoverDependencyFiles finds all dependency files in the given path
func (a *Analyzer) discoverDependencyFiles(path string, options *ScanOptions) ([]string, error) {
	if options.SpecificFile != "" {
		// Scan specific file
		if !filepath.IsAbs(options.SpecificFile) {
			options.SpecificFile = filepath.Join(path, options.SpecificFile)
		}
		return []string{options.SpecificFile}, nil
	}

	var depFiles []string

	// Known dependency file patterns
	patterns := []string{
		"package.json",
		"package-lock.json",
		"yarn.lock",
		"pnpm-lock.yaml",
		"requirements.txt",
		"requirements-dev.txt",
		"Pipfile",
		"Pipfile.lock",
		"pyproject.toml",
		"poetry.lock",
		"go.mod",
		"go.sum",
		"pom.xml",
		"Cargo.toml",
		"Cargo.lock",
		"Gemfile",
		"Gemfile.lock",
		"composer.json",
		"composer.lock",
	}

	err := filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			// Skip common directories that shouldn't contain dependency files
			dirName := info.Name()
			skipDirs := []string{
				"node_modules", ".git", "vendor", ".venv", "__pycache__",
				".tox", ".pytest_cache", "target", "dist", "build",
				".terraform", ".gradle",
			}
			for _, skip := range skipDirs {
				if dirName == skip {
					return filepath.SkipDir
				}
			}

			// Skip Windows problematic directories
			if strings.HasPrefix(dirName, "real-actions-") ||
				strings.HasPrefix(dirName, "docker-test-") ||
				strings.HasPrefix(dirName, "docker-realworld-") ||
				strings.HasPrefix(dirName, "docker-e2e-") ||
				dirName == "custom_test_workspace" {
				return filepath.SkipDir
			}
			return nil
		}

		fileName := info.Name()
		for _, pattern := range patterns {
			if fileName == pattern {
				depFiles = append(depFiles, filePath)
				break
			}
		}

		return nil
	})

	return depFiles, err
}

// parseDependencyFile parses dependencies from a specific file
func (a *Analyzer) parseDependencyFile(filePath string, options *ScanOptions) ([]types.Dependency, error) {
	logrus.Debugf("Parsing dependency file: %s", filePath)

	// Determine file type and registry
	fileType, registryType := a.detectFileType(filePath)
	logrus.Printf("DEBUG: Parsing file %s with type %s", filePath, fileType)
	if fileType == "" {
		return nil, fmt.Errorf("unsupported file type: %s", filePath)
	}

	// Parse dependencies based on file type
	switch fileType {
	case "npm":
		return a.parseNPMDependencies(filePath, options)
	case "python":
		return a.parsePythonDependencies(filePath, options)
	case "go":
		return a.parseGoDependencies(filePath)
	case "maven":
		return a.parseMavenDependencies(filePath)
	default:
		// Check if we have a registry connector for this type
		if connector, exists := a.registries[registryType]; exists {
			// Use the registry connector to parse dependencies
			logrus.Debugf("Using %s connector to parse %s", registryType, filePath)
			// For now, return empty dependencies as we need to implement
			// specific parsing logic for each registry type
			_ = connector // Use connector to avoid unused variable error
			return []types.Dependency{}, nil
		}
		// For unsupported file types, return empty
		return []types.Dependency{}, nil
	}
}

// parsePythonDependencies handles parsing of Python-related files
func (a *Analyzer) parsePythonDependencies(filePath string, options *ScanOptions) ([]types.Dependency, error) {
	fileName := filepath.Base(filePath)
	switch fileName {
	case "requirements.txt", "requirements-dev.txt":
		return a.parsePythonRequirements(filePath)
	case "pyproject.toml":
		return a.parsePyprojectToml(filePath)
	case "Pipfile":
		return a.parsePipfile(filePath)
	default:
		return []types.Dependency{}, nil
	}
}

func (a *Analyzer) parseGoDependencies(filePath string) ([]types.Dependency, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read go.mod: %w", err)
	}
	lines := strings.Split(string(data), "\n")
	var deps []types.Dependency
	inBlock := false
	for _, line := range lines {
		l := strings.TrimSpace(line)
		if l == "" || strings.HasPrefix(l, "//") {
			continue
		}
		if strings.HasPrefix(l, "require (") {
			inBlock = true
			continue
		}
		if inBlock && strings.HasPrefix(l, ")") {
			inBlock = false
			continue
		}
		if strings.HasPrefix(l, "require ") {
			parts := strings.Fields(l)
			if len(parts) >= 3 {
				deps = append(deps, types.Dependency{Name: parts[1], Version: parts[2], Registry: "go", Source: filePath, Direct: true})
			}
			continue
		}
		if inBlock {
			parts := strings.Fields(l)
			if len(parts) >= 2 {
				deps = append(deps, types.Dependency{Name: parts[0], Version: parts[1], Registry: "go", Source: filePath, Direct: true})
			}
		}
	}
	return deps, nil
}

func (a *Analyzer) parseMavenDependencies(filePath string) ([]types.Dependency, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read pom.xml: %w", err)
	}
	type dep struct{ GroupID, ArtifactID, Version string }
	type pom struct {
		Dependencies struct {
			Dependency []struct {
				GroupID    string `xml:"groupId"`
				ArtifactID string `xml:"artifactId"`
				Version    string `xml:"version"`
			} `xml:"dependency"`
		} `xml:"dependencies"`
	}
	var p pom
	if err := xml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("failed to parse pom.xml: %w", err)
	}
	var deps []types.Dependency
	for _, d := range p.Dependencies.Dependency {
		name := d.GroupID + ":" + d.ArtifactID
		ver := d.Version
		if name != ":" {
			deps = append(deps, types.Dependency{Name: name, Version: ver, Registry: "maven", Source: filePath, Direct: true})
		}
	}
	return deps, nil
}

func (a *Analyzer) parsePythonRequirements(filePath string) ([]types.Dependency, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read requirements.txt: %w", err)
	}
	lines := strings.Split(string(data), "\n")
	reqRegex := regexp.MustCompile(`^([a-zA-Z0-9_.\-]+)([><=!~]+)?([0-9A-Za-z_.\-]+.*)?$`)
	var dependencies []types.Dependency
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "-e ") {
			pkg := strings.TrimSpace(strings.TrimPrefix(line, "-e "))
			if pkg != "" {
				dependencies = append(dependencies, types.Dependency{
					Name:     pkg,
					Version:  "*",
					Registry: "pypi",
					Source:   filePath,
					Direct:   true,
				})
			}
			continue
		}
		if strings.Contains(line, ";") {
			parts := strings.Split(line, ";")
			line = strings.TrimSpace(parts[0])
		}
		if strings.Contains(line, "[") && strings.Contains(line, "]") {
			start := strings.Index(line, "[")
			end := strings.Index(line, "]") + 1
			if start >= 0 && end > start {
				line = line[:start] + line[end:]
			}
		}
		matches := reqRegex.FindStringSubmatch(line)
		if len(matches) >= 2 {
			name := matches[1]
			version := "*"
			if len(matches) >= 4 && matches[3] != "" {
				op := matches[2]
				spec := matches[3]
				version = strings.TrimSpace(op + spec)
			}
			dependencies = append(dependencies, types.Dependency{
				Name:     name,
				Version:  version,
				Registry: "pypi",
				Source:   filePath,
				Direct:   true,
			})
		}
	}
	return dependencies, nil
}

func (a *Analyzer) parsePyprojectToml(filePath string) ([]types.Dependency, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read pyproject.toml: %w", err)
	}
	var pyproject struct {
		Project struct {
			Dependencies []string `toml:"dependencies"`
		} `toml:"project"`
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
	if err := toml.Unmarshal(data, &pyproject); err != nil {
		return nil, fmt.Errorf("failed to parse pyproject.toml: %w", err)
	}
	var dependencies []types.Dependency
	addDep := func(name, version string, depType string) {
		if name == "" {
			return
		}
		dependencies = append(dependencies, types.Dependency{
			Name:     name,
			Version:  version,
			Registry: "pypi",
			Source:   filePath,
			Direct:   true,
			ExtraData: map[string]interface{}{
				"type": depType,
			},
		})
	}
	for _, dep := range pyproject.Project.Dependencies {
		n, v := a.parsePythonRequirementString(dep)
		addDep(n, v, "project")
	}
	for name, spec := range pyproject.Tool.Poetry.Dependencies {
		if name == "python" {
			continue
		}
		version := "*"
		switch s := spec.(type) {
		case string:
			version = s
		case map[string]interface{}:
			if ver, ok := s["version"].(string); ok {
				version = ver
			}
		}
		addDep(name, version, "poetry")
	}
	for name, spec := range pyproject.Tool.Poetry.DevDependencies {
		version := "*"
		switch s := spec.(type) {
		case string:
			version = s
		case map[string]interface{}:
			if ver, ok := s["version"].(string); ok {
				version = ver
			}
		}
		addDep(name, version, "poetry-dev")
	}
	for groupName, group := range pyproject.Tool.Poetry.Group {
		for name, spec := range group.Dependencies {
			version := "*"
			switch s := spec.(type) {
			case string:
				version = s
			case map[string]interface{}:
				if ver, ok := s["version"].(string); ok {
					version = ver
				}
			}
			addDep(name, version, "group-"+groupName)
		}
	}
	return dependencies, nil
}

func (a *Analyzer) parsePipfile(filePath string) ([]types.Dependency, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read Pipfile: %w", err)
	}
	var pipfile struct {
		Packages    map[string]interface{} `toml:"packages"`
		DevPackages map[string]interface{} `toml:"dev-packages"`
	}
	if err := toml.Unmarshal(data, &pipfile); err != nil {
		return nil, fmt.Errorf("failed to parse Pipfile: %w", err)
	}
	var dependencies []types.Dependency
	add := func(name, version string, depType string) {
		if name == "" {
			return
		}
		dependencies = append(dependencies, types.Dependency{
			Name:     name,
			Version:  version,
			Registry: "pypi",
			Source:   filePath,
			Direct:   true,
			ExtraData: map[string]interface{}{
				"type": depType,
			},
		})
	}
	for name, spec := range pipfile.Packages {
		version := "*"
		switch s := spec.(type) {
		case string:
			version = s
		case map[string]interface{}:
			if ver, ok := s["version"].(string); ok {
				version = ver
			}
		}
		add(name, version, "prod")
	}
	for name, spec := range pipfile.DevPackages {
		version := "*"
		switch s := spec.(type) {
		case string:
			version = s
		case map[string]interface{}:
			if ver, ok := s["version"].(string); ok {
				version = ver
			}
		}
		add(name, version, "dev")
	}
	return dependencies, nil
}

func (a *Analyzer) parsePythonRequirementString(req string) (string, string) {
	r := strings.TrimSpace(req)
	if strings.Contains(r, ";") {
		parts := strings.Split(r, ";")
		r = strings.TrimSpace(parts[0])
	}
	if strings.Contains(r, "[") && strings.Contains(r, "]") {
		start := strings.Index(r, "[")
		end := strings.Index(r, "]") + 1
		if start >= 0 && end > start {
			r = r[:start] + r[end:]
		}
	}
	re := regexp.MustCompile(`^([a-zA-Z0-9_.\-]+)([><=!~]+)?([0-9A-Za-z_.\-]+.*)?$`)
	m := re.FindStringSubmatch(r)
	if len(m) >= 2 {
		name := m[1]
		version := "*"
		if len(m) >= 4 && m[3] != "" {
			op := m[2]
			spec := m[3]
			version = strings.TrimSpace(op + spec)
		}
		return name, version
	}
	return r, "*"
}

// parseNPMDependencies handles parsing of NPM-related files
func (a *Analyzer) parseNPMDependencies(filePath string, options *ScanOptions) ([]types.Dependency, error) {
	fileName := filepath.Base(filePath)
	logrus.Printf("DEBUG: parseNPMDependencies called with fileName: %s", fileName)

	switch fileName {
	case "package.json":
		return a.parsePackageJSON(filePath, options)
	case "package-lock.json":
		return a.parsePackageLockJSON(filePath, options)
	case "yarn.lock":
		return a.parseYarnLock(filePath, options)
	default:
		return []types.Dependency{}, nil
	}
}

// parsePackageJSON parses dependencies from package.json with enhanced metadata extraction
func (a *Analyzer) parsePackageJSON(filePath string, options *ScanOptions) ([]types.Dependency, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read package.json: %w", err)
	}

	// Enhanced package.json structure with more metadata
	var packageData struct {
		Name                 string            `json:"name"`
		Version              string            `json:"version"`
		Description          string            `json:"description"`
		Author               interface{}       `json:"author"`
		License              string            `json:"license"`
		Repository           interface{}       `json:"repository"`
		Homepage             string            `json:"homepage"`
		Keywords             []string          `json:"keywords"`
		Dependencies         map[string]string `json:"dependencies"`
		DevDependencies      map[string]string `json:"devDependencies"`
		PeerDependencies     map[string]string `json:"peerDependencies"`
		OptionalDependencies map[string]string `json:"optionalDependencies"`
		BundledDependencies  []string          `json:"bundledDependencies"`
		Engines              map[string]string `json:"engines"`
		Scripts              map[string]string `json:"scripts"`
	}

	if err := json.Unmarshal(data, &packageData); err != nil {
		return nil, fmt.Errorf("failed to parse package.json: %w", err)
	}

	// Validate package.json structure
	if packageData.Name == "" {
		return nil, fmt.Errorf("package.json missing required 'name' field")
	}

	logrus.Debugf("Parsing package.json for %s@%s with %d dependencies and %d devDependencies",
		packageData.Name, packageData.Version, len(packageData.Dependencies), len(packageData.DevDependencies))

	var dependencies []types.Dependency

	// Parse regular dependencies with enhanced metadata
	for name, version := range packageData.Dependencies {
		if name == "" || version == "" {
			logrus.Warnf("Skipping invalid dependency: name='%s', version='%s'", name, version)
			continue
		}

		dep := types.Dependency{
			Name:        name,
			Version:     a.normalizeVersion(version),
			Registry:    "npm",
			Source:      filePath,
			Direct:      true,
			Development: false,
			ExtraData: map[string]interface{}{
				"constraint": version,
				"parent":     packageData.Name,
			},
		}
		dependencies = append(dependencies, dep)
	}

	// Parse dev dependencies if requested
	if options.IncludeDevDependencies {
		for name, version := range packageData.DevDependencies {
			if name == "" || version == "" {
				logrus.Warnf("Skipping invalid dev dependency: name='%s', version='%s'", name, version)
				continue
			}

			dep := types.Dependency{
				Name:        name,
				Version:     a.normalizeVersion(version),
				Registry:    "npm",
				Source:      filePath,
				Direct:      true,
				Development: true,
				ExtraData: map[string]interface{}{
					"constraint": version,
					"parent":     packageData.Name,
				},
			}
			dependencies = append(dependencies, dep)
		}
	}

	// Parse peer dependencies
	for name, version := range packageData.PeerDependencies {
		if name == "" || version == "" {
			logrus.Warnf("Skipping invalid peer dependency: name='%s', version='%s'", name, version)
			continue
		}

		dep := types.Dependency{
			Name:        name,
			Version:     a.normalizeVersion(version),
			Registry:    "npm",
			Source:      filePath,
			Direct:      true,
			Development: false,
			ExtraData: map[string]interface{}{
				"constraint": version,
				"parent":     packageData.Name,
				"type":       "peer",
			},
		}
		dependencies = append(dependencies, dep)
	}

	// Parse optional dependencies
	for name, version := range packageData.OptionalDependencies {
		if name == "" || version == "" {
			logrus.Warnf("Skipping invalid optional dependency: name='%s', version='%s'", name, version)
			continue
		}

		dep := types.Dependency{
			Name:        name,
			Version:     a.normalizeVersion(version),
			Registry:    "npm",
			Source:      filePath,
			Direct:      true,
			Development: false,
			ExtraData: map[string]interface{}{
				"constraint": version,
				"parent":     packageData.Name,
				"type":       "optional",
			},
		}
		dependencies = append(dependencies, dep)
	}

	logrus.Printf("DEBUG: Returning %d total dependencies", len(dependencies))
	return dependencies, nil
}

// normalizeVersion normalizes version constraints to extract actual version numbers
func (a *Analyzer) normalizeVersion(constraint string) string {
	if constraint == "" {
		return ""
	}

	// Remove common prefixes and operators
	constraint = strings.TrimSpace(constraint)
	constraint = strings.TrimPrefix(constraint, "^")
	constraint = strings.TrimPrefix(constraint, "~")
	constraint = strings.TrimPrefix(constraint, ">=")
	constraint = strings.TrimPrefix(constraint, "<=")
	constraint = strings.TrimPrefix(constraint, ">")
	constraint = strings.TrimPrefix(constraint, "<")
	constraint = strings.TrimPrefix(constraint, "=")

	// Handle version ranges (take the first version)
	if strings.Contains(constraint, " - ") {
		parts := strings.Split(constraint, " - ")
		if len(parts) > 0 {
			constraint = strings.TrimSpace(parts[0])
		}
	}

	// Handle OR conditions (take the first version)
	if strings.Contains(constraint, " || ") {
		parts := strings.Split(constraint, " || ")
		if len(parts) > 0 {
			constraint = strings.TrimSpace(parts[0])
			return a.normalizeVersion(constraint) // Recursive call to handle nested operators
		}
	}

	// Handle git URLs and file paths
	if strings.HasPrefix(constraint, "git+") || strings.HasPrefix(constraint, "file:") || strings.HasPrefix(constraint, "http") {
		return "latest" // Default for non-semver sources
	}

	// Handle npm tags
	if constraint == "latest" || constraint == "next" || constraint == "beta" || constraint == "alpha" {
		return constraint
	}

	return strings.TrimSpace(constraint)
}

// parsePackageLockJSON parses dependencies from package-lock.json with enhanced metadata
func (a *Analyzer) parsePackageLockJSON(filePath string, options *ScanOptions) ([]types.Dependency, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read package-lock.json: %w", err)
	}

	// Enhanced lock file structure
	var lockData struct {
		Name            string `json:"name"`
		Version         string `json:"version"`
		LockfileVersion int    `json:"lockfileVersion"`
		Packages        map[string]struct {
			Version      string            `json:"version"`
			Dev          bool              `json:"dev"`
			Optional     bool              `json:"optional"`
			Peer         bool              `json:"peer"`
			Resolved     string            `json:"resolved"`
			Integrity    string            `json:"integrity"`
			Dependencies map[string]string `json:"dependencies"`
			Engines      map[string]string `json:"engines"`
			License      string            `json:"license"`
		} `json:"packages"`
	}

	if err := json.Unmarshal(data, &lockData); err != nil {
		return nil, fmt.Errorf("failed to parse package-lock.json: %w", err)
	}

	// Validate lock file structure
	if lockData.LockfileVersion == 0 {
		logrus.Warnf("package-lock.json missing lockfileVersion, assuming version 1")
	}

	logrus.Debugf("Parsing package-lock.json v%d for %s@%s with %d packages",
		lockData.LockfileVersion, lockData.Name, lockData.Version, len(lockData.Packages))

	var dependencies []types.Dependency

	for packagePath, packageInfo := range lockData.Packages {
		// Skip the root package (empty path)
		if packagePath == "" {
			continue
		}

		// Skip dev dependencies if not requested
		if packageInfo.Dev && !options.IncludeDevDependencies {
			continue
		}

		// Extract package name from path (remove node_modules/ prefix)
		packageName := strings.TrimPrefix(packagePath, "node_modules/")

		// Handle scoped packages correctly
		if strings.Contains(packageName, "/node_modules/") {
			// This is a nested dependency, extract the actual package name
			parts := strings.Split(packageName, "/node_modules/")
			if len(parts) > 1 {
				packageName = parts[len(parts)-1]
			}
		}

		// Validate package info
		if packageName == "" || packageInfo.Version == "" {
			logrus.Warnf("Skipping invalid package: path='%s', version='%s'", packagePath, packageInfo.Version)
			continue
		}

		// Determine dependency type
		depType := "production"
		if packageInfo.Dev {
			depType = "development"
		} else if packageInfo.Peer {
			depType = "peer"
		} else if packageInfo.Optional {
			depType = "optional"
		}

		dep := types.Dependency{
			Name:        packageName,
			Version:     packageInfo.Version,
			Registry:    "npm",
			Source:      filePath,
			Direct:      !strings.Contains(packagePath, "/node_modules/"),
			Development: packageInfo.Dev,
			ExtraData: map[string]interface{}{
				"resolved":    packageInfo.Resolved,
				"integrity":   packageInfo.Integrity,
				"type":        depType,
				"path":        packagePath,
				"license":     packageInfo.License,
				"lockVersion": lockData.LockfileVersion,
			},
		}
		dependencies = append(dependencies, dep)
	}

	logrus.Debugf("Extracted %d dependencies from package-lock.json", len(dependencies))
	return dependencies, nil
}

// parseYarnLock parses dependencies from yarn.lock with enhanced parsing
func (a *Analyzer) parseYarnLock(filePath string, options *ScanOptions) ([]types.Dependency, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read yarn.lock: %w", err)
	}

	content := string(data)
	lines := strings.Split(content, "\n")

	logrus.Debugf("Parsing yarn.lock with %d lines", len(lines))

	var dependencies []types.Dependency
	packageMap := make(map[string]*types.Dependency)

	var currentPackages []string
	var currentDep *types.Dependency
	var inPackageBlock bool

	for _, line := range lines {
		originalLine := line
		line = strings.TrimSpace(line)

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Check for package declaration (starts without indentation and contains @)
		if !strings.HasPrefix(originalLine, " ") && !strings.HasPrefix(originalLine, "\t") {
			if strings.Contains(line, "@") && strings.HasSuffix(line, ":") {
				// Parse package declaration line
				packageDecl := strings.TrimSuffix(line, ":")
				currentPackages = a.parseYarnPackageDeclaration(packageDecl)
				inPackageBlock = len(currentPackages) > 0

				if inPackageBlock {
					currentDep = &types.Dependency{
						Registry:    "npm",
						Source:      filePath,
						Direct:      true,
						Development: false, // Yarn.lock doesn't distinguish dev deps
						ExtraData:   make(map[string]interface{}),
					}
				}
			} else {
				inPackageBlock = false
			}
			continue
		}

		// Parse properties within package block
		if inPackageBlock && currentDep != nil {
			if strings.HasPrefix(line, "version ") {
				version := a.extractYarnValue(line)
				currentDep.Version = version
				currentDep.ExtraData["version"] = version
			} else if strings.HasPrefix(line, "resolved ") {
				resolved := a.extractYarnValue(line)
				currentDep.ExtraData["resolved"] = resolved
			} else if strings.HasPrefix(line, "integrity ") {
				integrity := a.extractYarnValue(line)
				currentDep.ExtraData["integrity"] = integrity
			} else if strings.HasPrefix(line, "dependencies:") {
				// Start of dependencies block - we could parse these for transitive deps
				currentDep.ExtraData["hasDependencies"] = true
			}

			// Check if we've reached the end of the package block
			if currentDep.Version != "" && len(currentPackages) > 0 {
				// Create dependencies for all package names in the declaration
				for _, pkgName := range currentPackages {
					if pkgName == "" {
						continue
					}

					// Check if we already have this package with this version
					key := fmt.Sprintf("%s@%s", pkgName, currentDep.Version)
					if _, exists := packageMap[key]; !exists {
						dep := &types.Dependency{
							Name:        pkgName,
							Version:     currentDep.Version,
							Registry:    currentDep.Registry,
							Source:      currentDep.Source,
							Direct:      currentDep.Direct,
							Development: currentDep.Development,
							ExtraData:   make(map[string]interface{}),
						}

						// Copy metadata
						for k, v := range currentDep.ExtraData {
							dep.ExtraData[k] = v
						}
						dep.ExtraData["packageDeclaration"] = strings.Join(currentPackages, ", ")

						packageMap[key] = dep
						dependencies = append(dependencies, *dep)
					}
				}

				// Reset for next package
				currentPackages = nil
				currentDep = nil
				inPackageBlock = false
			}
		}
	}

	logrus.Debugf("Extracted %d unique dependencies from yarn.lock", len(dependencies))
	return dependencies, nil
}

// parseYarnPackageDeclaration parses a yarn package declaration line
func (a *Analyzer) parseYarnPackageDeclaration(decl string) []string {
	var packages []string

	// Handle multiple package declarations separated by commas
	parts := strings.Split(decl, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		part = strings.Trim(part, `"'`)

		// Extract package name (everything before the last @)
		if strings.Contains(part, "@") {
			// Handle scoped packages like @babel/core@^7.0.0
			lastAtIndex := strings.LastIndex(part, "@")
			if lastAtIndex > 0 {
				packageName := part[:lastAtIndex]
				if packageName != "" {
					packages = append(packages, packageName)
				}
			}
		}
	}

	return packages
}

// extractYarnValue extracts the value from a yarn.lock property line
func (a *Analyzer) extractYarnValue(line string) string {
	parts := strings.SplitN(line, " ", 2)
	if len(parts) < 2 {
		return ""
	}

	value := strings.TrimSpace(parts[1])
	value = strings.Trim(value, `"'`)
	return value
}

// detectFileType determines the file type and associated registry
func (a *Analyzer) detectFileType(filePath string) (fileType, registryType string) {
	fileName := filepath.Base(filePath)

	switch fileName {
	case "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json":
		return "npm", "npm"
	case "requirements.txt", "requirements-dev.txt", "Pipfile", "Pipfile.lock", "pyproject.toml", "poetry.lock":
		return "python", "pypi"
	case "go.mod", "go.sum":
		return "go", "go"
	case "pom.xml":
		return "maven", "maven"
	case "Cargo.toml", "Cargo.lock":
		return "rust", "cargo"
	case "Gemfile", "Gemfile.lock":
		return "ruby", "rubygems"
	case "composer.json", "composer.lock":
		return "php", "packagist"
	default:
		return "", ""
	}
}

// filterDependencies removes excluded packages from the dependency list
func (a *Analyzer) filterDependencies(deps []types.Dependency, excludePackages []string) []types.Dependency {
	if deps == nil {
		return []types.Dependency{}
	}
	if len(excludePackages) == 0 {
		return deps
	}

	excludeMap := make(map[string]bool)
	for _, pkg := range excludePackages {
		excludeMap[pkg] = true
	}

	filtered := make([]types.Dependency, 0, len(deps))
	for _, dep := range deps {
		if !excludeMap[dep.Name] {
			filtered = append(filtered, dep)
		}
	}

	return filtered
}

// detectThreats performs threat detection on the given dependencies
func (a *Analyzer) detectThreats(ctx context.Context, deps []types.Dependency, options *ScanOptions) ([]types.Threat, []types.Warning, error) {
	logrus.Infof("Starting threat analysis for %d dependencies", len(deps))
	start := time.Now()

	var allThreats []types.Threat
	var allWarnings []types.Warning

	// Initialize enhanced supply chain detector if enabled
	var enhancedDetector *detector.EnhancedSupplyChainDetector
	if options.EnableSupplyChain {
		logrus.Info("Enhanced supply chain detection enabled")
		enhancedDetector = detector.NewEnhancedSupplyChainDetector()
	}

	// Initialize vulnerability manager if vulnerability checking is enabled
	var vulnManager *vulnerability.Manager
	if options.CheckVulnerabilities {
		logrus.Info("Vulnerability checking enabled, initializing vulnerability manager")

		// Validate vulnerability database names
		validDBs := map[string]bool{
			"osv":    true,
			"github": true,
			"nvd":    true,
		}

		var validatedDBs []string
		for _, dbName := range options.VulnerabilityDBs {
			if validDBs[dbName] {
				validatedDBs = append(validatedDBs, dbName)
			} else {
				return nil, nil, fmt.Errorf("invalid vulnerability database: %s. Valid options are: osv, github, nvd", dbName)
			}
		}

		if len(validatedDBs) == 0 {
			return nil, nil, fmt.Errorf("no valid vulnerability databases specified")
		}

		// Create manager configuration
		managerConfig := &vulnerability.ManagerConfig{
			ParallelQueries: true,
			Timeout:         30 * time.Second,
			CacheEnabled:    true,
			CacheTTL:        1 * time.Hour,
			MergeResults:    true,
			DeduplicateByID: true,
			Priority:        validatedDBs,
		}

		// Create database configurations based on user selection
		for _, dbName := range validatedDBs {
			dbConfig := types.VulnerabilityDatabaseConfig{
				Type:    dbName,
				Enabled: true,
			}
			managerConfig.Databases = append(managerConfig.Databases, dbConfig)
		}

		vulnManager = vulnerability.NewManager(managerConfig)
		logrus.Infof("Vulnerability manager initialized with %d databases", len(validatedDBs))
	}

	// Analyze each dependency individually using CheckPackage for better threat detection
	for _, dep := range deps {
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		default:
		}

		// Use CheckPackage which compares against popular packages
		// Check if detector is initialized
		if a.detector == nil {
			logrus.Warnf("Detector not initialized, skipping threat detection for %s", dep.Name)
			continue
		}

		result, err := a.detector.CheckPackage(ctx, dep.Name, dep.Registry)
		if err != nil {
			logrus.Warnf("Failed to check package %s: %v", dep.Name, err)
			continue
		}

		// Add threats and warnings from the result
		allThreats = append(allThreats, result.Threats...)
		allWarnings = append(allWarnings, result.Warnings...)

		// Perform enhanced supply chain analysis if enabled
		if enhancedDetector != nil {
			// Convert dependency to package for enhanced analysis
			pkg := &types.Package{
				Name:     dep.Name,
				Version:  dep.Version,
				Registry: dep.Registry,
				Type:     dep.Registry,
			}

			// Perform enhanced threat detection
			enhancedResults, err := enhancedDetector.DetectThreats(ctx, []types.Package{*pkg})
			if err != nil {
				logrus.Warnf("Enhanced supply chain analysis failed for %s: %v", dep.Name, err)
			} else if len(enhancedResults) > 0 {
				enhancedResult := enhancedResults[0]

				// Convert enhanced result to standard threat if not filtered
				if !enhancedResult.IsFiltered && enhancedResult.ConfidenceScore > 0.5 {
					threat := types.Threat{
						Package:         enhancedResult.Package,
						Registry:        enhancedResult.Registry,
						Type:            types.ThreatType(enhancedResult.ThreatType),
						Severity:        a.convertStringSeverity(enhancedResult.Severity),
						Description:     fmt.Sprintf("Enhanced supply chain threat detected: %s", enhancedResult.ThreatType),
						Recommendation:  strings.Join(enhancedResult.Recommendations, "; "),
						Confidence:      enhancedResult.ConfidenceScore,
						DetectedAt:      time.Now(),
						DetectionMethod: "enhanced_supply_chain",
						Metadata: map[string]interface{}{
							"supply_chain_risk":   enhancedResult.SupplyChainRisk,
							"false_positive_risk": enhancedResult.FalsePositiveRisk,
							"filter_reasons":      enhancedResult.FilterReasons,
							"evidence":            enhancedResult.Evidence,
						},
					}
					allThreats = append(allThreats, threat)
					logrus.Infof("Enhanced supply chain threat detected for %s: %s (confidence: %.2f)",
						dep.Name, enhancedResult.ThreatType, enhancedResult.ConfidenceScore)
				} else if enhancedResult.IsFiltered {
					logrus.Debugf("Package %s filtered by enhanced supply chain analysis: %v",
						dep.Name, enhancedResult.FilterReasons)
				}
			}
		}

		// Check for vulnerabilities if enabled
		if vulnManager != nil {
			// Create package object for vulnerability checking
			pkg := &types.Package{
				Name:     dep.Name,
				Version:  dep.Version,
				Type:     dep.Registry, // Set the package type to the registry
				Registry: dep.Registry,
			}

			vulns, err := vulnManager.CheckVulnerabilities(pkg)
			if err != nil {
				logrus.Warnf("Failed to check vulnerabilities for %s@%s: %v", dep.Name, dep.Version, err)
				continue
			}

			// Convert vulnerabilities to threats
			for _, vuln := range vulns {
				// Extract affected versions from vulnerability data
				affectedVersions := ""
				fixedVersion := ""
				if len(vuln.AffectedPackages) > 0 {
					for _, affected := range vuln.AffectedPackages {
						if affected.Name == dep.Name {
							affectedVersions = affected.VersionRange
							break
						}
					}
				}

				// Generate proposed correction
				proposedCorrection := fmt.Sprintf("Update %s to a patched version that addresses %s", dep.Name, vuln.ID)
				if fixedVersion != "" {
					proposedCorrection = fmt.Sprintf("Update %s from version %s to %s or later", dep.Name, dep.Version, fixedVersion)
				}

				threat := types.Threat{
					Package:            dep.Name,
					Version:            dep.Version,
					Registry:           dep.Registry,
					Type:               types.ThreatTypeVulnerable,
					Severity:           vuln.Severity,
					Description:        vuln.Description,
					Recommendation:     fmt.Sprintf("Update to a version that fixes %s", vuln.ID),
					Confidence:         1.0, // High confidence for known vulnerabilities
					DetectedAt:         time.Now(),
					DetectionMethod:    "vulnerability_database",
					CVEs:               []string{vuln.CVE},
					References:         vuln.References,
					AffectedVersions:   affectedVersions,
					FixedVersion:       fixedVersion,
					ProposedCorrection: proposedCorrection,
					CVE:                vuln.CVE,
					Metadata: map[string]interface{}{
						"vulnerability_id": vuln.ID,
						"cvss_score":       vuln.CVSSScore,
						"published":        vuln.Published,
						"modified":         vuln.Modified,
						"source":           vuln.Source,
						"aliases":          vuln.Aliases,
					},
				}
				allThreats = append(allThreats, threat)
			}

			if len(vulns) > 0 {
				logrus.Infof("Found %d vulnerabilities for %s@%s", len(vulns), dep.Name, dep.Version)
			}
		}
	}

	duration := time.Since(start)
	logrus.Infof("Threat analysis completed in %v. Found %d threats, %d warnings", duration, len(allThreats), len(allWarnings))

	return allThreats, allWarnings, nil
}

// calculateSummary generates a summary of scan results
func (a *Analyzer) calculateSummary(threats []types.Threat, warnings []types.Warning, totalPackages int) ScanSummary {
	summary := ScanSummary{
		TotalWarnings: len(warnings),
		CleanPackages: totalPackages,
		ConflictCount: 0, // Will be updated by caller if resolution data is available
	}

	for _, threat := range threats {
		switch threat.Severity {
		case types.SeverityCritical:
			summary.CriticalThreats++
		case types.SeverityHigh:
			summary.HighThreats++
		case types.SeverityMedium:
			summary.MediumThreats++
		case types.SeverityLow:
			summary.LowThreats++
		}
		summary.CleanPackages--
	}

	return summary
}

// AnalyzeDependency analyzes a single dependency for threats
func (a *Analyzer) AnalyzeDependency(dep types.Dependency, popularPackages []string) ([]types.Threat, []types.Warning) {
	if a.detector == nil {
		return []types.Threat{}, []types.Warning{}
	}

	// Use detector engine to analyze the dependency
	options := &detector.Options{
		SimilarityThreshold: 0.8, // Default threshold
		DeepAnalysis:        true,
	}

	threats, warnings := a.detector.AnalyzeDependency(dep, popularPackages, options)
	if len(threats) == 0 && a.stubRepo != nil {
		st, sw := a.stubRepo.Generate(dep)
		threats = append(threats, st...)
		warnings = append(warnings, sw...)
	}
	return threats, warnings
}

// generateScanID generates a unique scan identifier
// scanRecursive performs recursive scanning of directories
func (a *Analyzer) scanRecursive(rootPath string, options *ScanOptions, result *ScanResult) (*ScanResult, error) {
	start := time.Now()
	logrus.Infof("Starting recursive scan for path: %s", rootPath)

	// Find all project directories
	projectDirs, err := a.findProjectDirectories(rootPath, options)
	if err != nil {
		return nil, fmt.Errorf("failed to find project directories: %w", err)
	}

	logrus.Infof("Found %d project directories for recursive scan", len(projectDirs))

	// Scan each project directory
	allDependencies := make([]types.Dependency, 0)
	allThreats := make([]types.Threat, 0)
	allWarnings := make([]types.Warning, 0)
	projectResults := make(map[string]*ScanResult)

	for _, projectDir := range projectDirs {
		logrus.Infof("Scanning project directory: %s", projectDir)

		// Create a copy of options without recursive flag to avoid infinite recursion
		projectOptions := *options
		projectOptions.Recursive = false

		// Scan individual project
		projectResult, err := a.Scan(projectDir, &projectOptions)
		if err != nil {
			logrus.Warnf("Failed to scan project %s: %v", projectDir, err)
			continue
		}

		// Store project result for consolidated reporting
		projectResults[projectDir] = projectResult

		// Aggregate results
		allThreats = append(allThreats, projectResult.Threats...)
		allWarnings = append(allWarnings, projectResult.Warnings...)

		// Parse dependencies from project
		depFiles, err := a.discoverDependencyFiles(projectDir, &projectOptions)
		if err != nil {
			logrus.Warnf("Failed to discover dependencies in %s: %v", projectDir, err)
			continue
		}

		for _, file := range depFiles {
			deps, err := a.parseDependencyFile(file, &projectOptions)
			if err != nil {
				logrus.Warnf("Failed to parse %s: %v", file, err)
				continue
			}
			allDependencies = append(allDependencies, deps...)
		}
	}

	// Update result with aggregated data
	result.TotalPackages = len(allDependencies)
	result.Threats = allThreats
	result.Warnings = allWarnings
	result.Duration = time.Since(start)
	result.Summary = a.calculateSummary(allThreats, allWarnings, len(allDependencies))

	// Add metadata for recursive scan
	result.Metadata["recursive_scan"] = true
	result.Metadata["projects_scanned"] = len(projectDirs)
	result.Metadata["project_directories"] = projectDirs

	// Add consolidated report if requested
	if options.ConsolidateReport {
		result.Metadata["project_results"] = projectResults
	}

	logrus.Infof("Recursive scan completed. Scanned %d projects, found %d threats", len(projectDirs), len(allThreats))
	return result, nil
}

// findProjectDirectories discovers all project directories in the given path
func (a *Analyzer) findProjectDirectories(rootPath string, options *ScanOptions) ([]string, error) {
	var projectDirs []string
	manifestFiles := []string{
		"package.json",     // npm
		"requirements.txt", // pip
		"Pipfile",          // pipenv
		"pyproject.toml",   // poetry
		"pom.xml",          // maven
		"build.gradle",     // gradle
		"*.csproj",         // nuget
		"packages.config",  // nuget
		"Gemfile",          // rubygems
		"go.mod",           // go modules
		"Cargo.toml",       // cargo
		"composer.json",    // composer
	}

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
				dirName == "dist" {
				return filepath.SkipDir
			}
			return nil
		}

		// Check if this is a manifest file
		fileName := filepath.Base(path)
		for _, manifestFile := range manifestFiles {
			if fileName == manifestFile {
				// Filter by package manager if specified
				if len(options.PackageManagers) > 0 {
					registry := a.getRegistryFromFile(fileName)
					if !a.isRegistryAllowed(registry, options.PackageManagers) {
						continue
					}
				}

				projectDir := filepath.Dir(path)
				// Avoid duplicate directories
				if !a.containsPath(projectDirs, projectDir) {
					projectDirs = append(projectDirs, projectDir)
				}
				break
			}
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to walk directory tree: %w", err)
	}

	return projectDirs, nil
}

// getRegistryFromFile maps file names to registry types
func (a *Analyzer) getRegistryFromFile(fileName string) string {
	switch fileName {
	case "package.json":
		return "npm"
	case "requirements.txt", "Pipfile", "pyproject.toml":
		return "pypi"
	case "pom.xml", "build.gradle":
		return "maven"
	case "packages.config":
		return "nuget"
	case "Gemfile":
		return "rubygems"
	case "go.mod":
		return "go"
	case "Cargo.toml":
		return "cargo"
	case "composer.json":
		return "composer"
	default:
		return "unknown"
	}
}

// isRegistryAllowed checks if a registry is in the allowed list
func (a *Analyzer) isRegistryAllowed(registry string, allowedRegistries []string) bool {
	for _, allowed := range allowedRegistries {
		if registry == allowed {
			return true
		}
	}
	return false
}

// containsPath checks if a path is already in the slice
func (a *Analyzer) containsPath(paths []string, path string) bool {
	for _, p := range paths {
		if p == path {
			return true
		}
	}
	return false
}

// convertStringSeverity converts string severity to types.Severity
func (a *Analyzer) convertStringSeverity(severity string) types.Severity {
	switch strings.ToLower(severity) {
	case "critical":
		return types.SeverityCritical
	case "high":
		return types.SeverityHigh
	case "medium":
		return types.SeverityMedium
	case "low":
		return types.SeverityLow
	default:
		return types.SeverityUnknown
	}
}

// scanWithSupplyChain performs enhanced supply chain scanning
func (a *Analyzer) scanWithSupplyChain(path string, options *ScanOptions) (*ScanResult, error) {
	logrus.Infof("Starting enhanced supply chain scan for path: %s", path)

	// Create a base scanner first
	baseScanner, err := scanner.New(a.config)
	if err != nil {
		return nil, fmt.Errorf("failed to create base scanner: %w", err)
	}

	// Create enhanced scanner with supply chain config
	enhancedScanner, err := scanner.NewEnhancedScanner(baseScanner, a.config.SupplyChain)
	if err != nil {
		return nil, fmt.Errorf("failed to create enhanced scanner: %w", err)
	}

	// Perform enhanced scan
	ctx := context.Background()
	enhancedResult, err := enhancedScanner.ScanWithSupplyChainAnalysis(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("enhanced supply chain scan failed: %w", err)
	}

	// Convert enhanced result to analyzer ScanResult format
	result := &ScanResult{
		ScanID:        enhancedResult.ScanMetadata.ScanID,
		Timestamp:     enhancedResult.ScanMetadata.Timestamp,
		Duration:      enhancedResult.ScanMetadata.ScanDuration,
		Path:          path,
		TotalPackages: 0, // Will be calculated from enhanced findings
		Threats:       []types.Threat{},
		Warnings:      []types.Warning{},
		Metadata:      make(map[string]interface{}),
	}

	// Extract threats and warnings from enhanced result packages
	if enhancedResult.ScanResult != nil && enhancedResult.ScanResult.Packages != nil {
		result.TotalPackages = len(enhancedResult.ScanResult.Packages)
		for _, pkg := range enhancedResult.ScanResult.Packages {
			if pkg.Threats != nil {
				result.Threats = append(result.Threats, pkg.Threats...)
			}
			if pkg.Warnings != nil {
				result.Warnings = append(result.Warnings, pkg.Warnings...)
			}
		}
	}

	// Add supply chain specific metadata
	result.Metadata["supply_chain_analysis"] = true
	result.Metadata["build_integrity_findings"] = len(enhancedResult.BuildIntegrityFindings)
	result.Metadata["zero_day_findings"] = len(enhancedResult.ZeroDayFindings)
	result.Metadata["threat_intel_findings"] = len(enhancedResult.ThreatIntelFindings)
	result.Metadata["honeypot_detections"] = len(enhancedResult.HoneypotDetections)
	result.Metadata["supply_chain_risk_score"] = enhancedResult.SupplyChainRisk.OverallScore
	result.Metadata["supply_chain_risk_level"] = enhancedResult.SupplyChainRisk.RiskLevel

	// Create summary with threat and warning counts
	result.Summary = ScanSummary{
		TotalWarnings: len(result.Warnings),
		CleanPackages: result.TotalPackages - len(result.Threats),
	}

	// Count threats by severity
	for _, threat := range result.Threats {
		switch threat.Severity {
		case types.SeverityCritical:
			result.Summary.CriticalThreats++
		case types.SeverityHigh:
			result.Summary.HighThreats++
		case types.SeverityMedium:
			result.Summary.MediumThreats++
		case types.SeverityLow:
			result.Summary.LowThreats++
		}
	}

	logrus.Infof("Enhanced supply chain scan completed with %d packages, %d threats and %d warnings", result.TotalPackages, len(result.Threats), len(result.Warnings))
	return result, nil
}

func generateScanID() string {
	return fmt.Sprintf("scan_%d", time.Now().Unix())
}

// OutputJSON outputs scan results in JSON format
func (r *ScanResult) OutputJSON(w io.Writer) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(r)
}

// OutputConsole outputs scan results in human-readable console format
func (r *ScanResult) OutputConsole(w io.Writer) error {
	fmt.Fprintf(w, "\n🔍 TypoSentinel Security Scan Results\n")
	fmt.Fprintf(w, "═══════════════════════════════════════\n\n")
	fmt.Fprintf(w, "📊 Scan Summary:\n")
	fmt.Fprintf(w, "   • Scan ID: %s\n", r.ScanID)
	fmt.Fprintf(w, "   • Duration: %v\n", r.Duration)
	fmt.Fprintf(w, "   • Packages Analyzed: %d\n", r.TotalPackages)
	fmt.Fprintf(w, "   • Clean Packages: %d\n", r.Summary.CleanPackages)

	if len(r.Threats) == 0 {
		fmt.Fprintf(w, "\n✅ No security threats detected!\n")
	} else {
		fmt.Fprintf(w, "\n⚠️  Security Threats Detected:\n")
		fmt.Fprintf(w, "   • Critical: %d\n", r.Summary.CriticalThreats)
		fmt.Fprintf(w, "   • High: %d\n", r.Summary.HighThreats)
		fmt.Fprintf(w, "   • Medium: %d\n", r.Summary.MediumThreats)
		fmt.Fprintf(w, "   • Low: %d\n", r.Summary.LowThreats)

		// Sort threats by severity
		sort.Slice(r.Threats, func(i, j int) bool {
			return r.Threats[i].Severity > r.Threats[j].Severity
		})

		fmt.Fprintf(w, "\n🚨 Threat Details:\n")
		for i, threat := range r.Threats {
			fmt.Fprintf(w, "\n%d. %s (%s)\n", i+1, threat.Package, threat.Severity)
			fmt.Fprintf(w, "   Type: %s\n", threat.Type)
			fmt.Fprintf(w, "   Description: %s\n", threat.Description)
			if threat.SimilarTo != "" {
				fmt.Fprintf(w, "   Similar to: %s (%.1f%% similarity)\n", threat.SimilarTo, threat.Confidence*100)
			}
			if threat.Recommendation != "" {
				fmt.Fprintf(w, "   💡 Recommendation: %s\n", threat.Recommendation)
			}
		}
	}

	if len(r.Warnings) > 0 {
		fmt.Fprintf(w, "\n⚠️  Warnings (%d):\n", len(r.Warnings))
		for i, warning := range r.Warnings {
			fmt.Fprintf(w, "%d. %s: %s\n", i+1, warning.Package, warning.Message)
		}
	}

	fmt.Fprintf(w, "\n")
	return nil
}

// OutputHTML outputs scan results in HTML format
func (r *ScanResult) OutputHTML(w io.Writer) error {
	html := `<!DOCTYPE html>
<html>
<head>
	<title>Typosentinel Scan Results</title>
	<style>
		body { font-family: Arial, sans-serif; margin: 20px; }
		.header { background: #f4f4f4; padding: 15px; border-radius: 5px; }
		.summary { margin: 20px 0; }
		.threat { background: #ffe6e6; padding: 10px; margin: 10px 0; border-left: 4px solid #ff4444; }
		.safe { background: #e6ffe6; padding: 10px; margin: 10px 0; border-left: 4px solid #44ff44; }
		.package { margin: 15px 0; padding: 10px; border: 1px solid #ddd; }
		.metadata { color: #666; font-size: 0.9em; }
	</style>
</head>
<body>
	<div class="header">
		<h1>Typosentinel Security Scan Report</h1>
		<p>Generated: %s</p>
		<p>Duration: %v</p>
	</div>
	
	<div class="summary">
		<h2>Summary</h2>
		<p>Packages Scanned: %d</p>
		<p>Threats Found: %d</p>
		<p>Risk Level: %s</p>
	</div>
	
	<div class="packages">
		<h2>Package Details</h2>
`

	// Write header with summary information
	_, err := fmt.Fprintf(w, html,
		time.Now().Format("2006-01-02 15:04:05"),
		r.Duration,
		r.TotalPackages,
		r.Summary.CriticalThreats+r.Summary.HighThreats+r.Summary.MediumThreats+r.Summary.LowThreats,
		"Medium")
	if err != nil {
		return err
	}

	// Write threat details
	for _, threat := range r.Threats {
		className := "threat"

		_, err := fmt.Fprintf(w, `		<div class="package %s">
			<h3>%s</h3>
			<div class="metadata">Severity: %s</div>
`,
			className, threat.Type, threat.Severity)
		if err != nil {
			return err
		}

		_, err = fmt.Fprintf(w, "\t\t\t<h4>Threat Details:</h4>\n\t\t\t<ul>\n")
		if err != nil {
			return err
		}

		_, err = fmt.Fprintf(w, "\t\t\t\t<li><strong>%s</strong> (%s): %s</li>\n",
			threat.Type, threat.Severity, threat.Description)
		if err != nil {
			return err
		}

		_, err = fmt.Fprintf(w, "\t\t\t</ul>\n")
		if err != nil {
			return err
		}

		_, err = fmt.Fprintf(w, "\t\t</div>\n")
		if err != nil {
			return err
		}
	}

	// Close HTML
	_, err = fmt.Fprintf(w, `	</div>
</body>
</html>`)
	return err
}
