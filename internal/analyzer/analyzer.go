package analyzer

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/internal/detector"
	"github.com/Alivanroy/Typosentinel/internal/registry"
	"github.com/Alivanroy/Typosentinel/internal/vulnerability"
	"github.com/Alivanroy/Typosentinel/pkg/types"
	"github.com/sirupsen/logrus"
)

// Analyzer orchestrates the security scanning process
type Analyzer struct {
	config     *config.Config
	detector   *detector.Engine
	registries map[string]registry.Connector
	resolver   *DependencyResolver
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

	return &Analyzer{
		config:   cfg,
		detector: detectorEngine,
		resolver: resolver,
	}, nil
}

// Scan performs a security scan of the specified path
func (a *Analyzer) Scan(path string, options *ScanOptions) (*ScanResult, error) {
	start := time.Now()
	scanID := generateScanID()

	logrus.Infof("Starting scan %s for path: %s", scanID, path)

	// Initialize scan result
	result := &ScanResult{
		ScanID:    scanID,
		Timestamp: start,
		Path:      path,
		Metadata:  make(map[string]interface{}),
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
			if dirName == "node_modules" || dirName == ".git" || dirName == "vendor" {
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
	fileType, _ := a.detectFileType(filePath)
	logrus.Printf("DEBUG: Parsing file %s with type %s", filePath, fileType)
	if fileType == "" {
		return nil, fmt.Errorf("unsupported file type: %s", filePath)
	}

	// Parse dependencies based on file type
	switch fileType {
	case "npm":
		return a.parseNPMDependencies(filePath, options)
	default:
		// For other file types, return empty for now
		return []types.Dependency{}, nil
	}
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
		result, err := a.detector.CheckPackage(ctx, dep.Name, dep.Registry)
		if err != nil {
			logrus.Warnf("Failed to check package %s: %v", dep.Name, err)
			continue
		}

		// Add threats and warnings from the result
		allThreats = append(allThreats, result.Threats...)
		allWarnings = append(allWarnings, result.Warnings...)

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
				threat := types.Threat{
					Package:         dep.Name,
					Version:         dep.Version,
					Registry:        dep.Registry,
					Type:            types.ThreatTypeVulnerable,
					Severity:        vuln.Severity,
					Description:     vuln.Description,
					Recommendation:  fmt.Sprintf("Update to a version that fixes %s", vuln.ID),
					Confidence:      1.0, // High confidence for known vulnerabilities
					DetectedAt:      time.Now(),
					DetectionMethod: "vulnerability_database",
					CVEs:            []string{vuln.CVE},
					References:      vuln.References,
					Metadata: map[string]interface{}{
						"vulnerability_id": vuln.ID,
						"cvss_score":      vuln.CVSSScore,
						"published":       vuln.Published,
						"modified":        vuln.Modified,
						"source":          vuln.Source,
						"aliases":         vuln.Aliases,
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

	return a.detector.AnalyzeDependency(dep, popularPackages, options)
}

// generateScanID generates a unique scan identifier
func generateScanID() string {
	return fmt.Sprintf("scan_%d", time.Now().UnixNano())
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
