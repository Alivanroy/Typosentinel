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

	"github.com/sirupsen/logrus"
	"typosentinel/internal/config"
	"typosentinel/internal/detector"
	"typosentinel/internal/registry"
	"typosentinel/pkg/types"
)

// Analyzer orchestrates the security scanning process
type Analyzer struct {
	config     *config.Config
	detector   *detector.Engine
	registries map[string]registry.Connector
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
}

// ScanResult contains the results of a security scan
type ScanResult struct {
	ScanID       string                `json:"scan_id"`
	Timestamp    time.Time             `json:"timestamp"`
	Duration     time.Duration         `json:"duration"`
	Path         string                `json:"path"`
	TotalPackages int                  `json:"total_packages"`
	Threats      []types.Threat        `json:"threats"`
	Warnings     []types.Warning       `json:"warnings"`
	Summary      ScanSummary           `json:"summary"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// ScanSummary provides a high-level overview of scan results
type ScanSummary struct {
	CriticalThreats int `json:"critical_threats"`
	HighThreats     int `json:"high_threats"`
	MediumThreats   int `json:"medium_threats"`
	LowThreats      int `json:"low_threats"`
	TotalWarnings   int `json:"total_warnings"`
	CleanPackages   int `json:"clean_packages"`
}

// New creates a new analyzer instance
func New(cfg *config.Config) *Analyzer {
	// Initialize detector engine
	detectorEngine := detector.New(cfg)

	// Initialize registry clients
	registryClients := make(map[string]registry.Connector)
	// TODO: Initialize registry connectors from config
	// For now, use the default manager
	manager := registry.NewManager()
	_ = cfg.Registries // avoid unused variable error
	_ = manager // avoid unused variable error

	return &Analyzer{
		config:     cfg,
		detector:   detectorEngine,
		registries: registryClients,
	}
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

	// Perform threat detection
	ctx := context.Background()
	threats, warnings, err := a.detectThreats(ctx, filteredDeps, options)
	if err != nil {
		return nil, fmt.Errorf("threat detection failed: %w", err)
	}

	result.Threats = threats
	result.Warnings = warnings
	result.Duration = time.Since(start)
	result.Summary = a.calculateSummary(threats, warnings, len(filteredDeps))

	// Add metadata
	result.Metadata["dependency_files"] = depFiles
	result.Metadata["scan_options"] = options
	result.Metadata["detector_version"] = a.detector.Version()

	logrus.Infof("Scan %s completed in %v. Found %d threats, %d warnings",
		scanID, result.Duration, len(threats), len(warnings))

	return result, nil
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

// parsePackageJSON parses dependencies from package.json
func (a *Analyzer) parsePackageJSON(filePath string, options *ScanOptions) ([]types.Dependency, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read package.json: %w", err)
	}

	var packageData struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}

	if err := json.Unmarshal(data, &packageData); err != nil {
		return nil, fmt.Errorf("failed to parse package.json: %w", err)
	}

	logrus.Printf("DEBUG: Found %d dependencies and %d devDependencies", len(packageData.Dependencies), len(packageData.DevDependencies))

	var dependencies []types.Dependency

	// Parse regular dependencies
	for name, version := range packageData.Dependencies {
		dep := types.Dependency{
			Name:        name,
			Version:     version,
			Registry:    "npm",
			Source:      filePath,
			Direct:      true,
			Development: false,
		}
		dependencies = append(dependencies, dep)
	}

	// Parse dev dependencies if requested
	if options.IncludeDevDependencies {
		for name, version := range packageData.DevDependencies {
			dep := types.Dependency{
				Name:        name,
				Version:     version,
				Registry:    "npm",
				Source:      filePath,
				Direct:      true,
				Development: true,
			}
			dependencies = append(dependencies, dep)
		}
	}

	logrus.Printf("DEBUG: Returning %d total dependencies", len(dependencies))
	return dependencies, nil
}

// parsePackageLockJSON parses dependencies from package-lock.json
func (a *Analyzer) parsePackageLockJSON(filePath string, options *ScanOptions) ([]types.Dependency, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read package-lock.json: %w", err)
	}

	var lockData struct {
		Packages map[string]struct {
			Version  string `json:"version"`
			Resolved string `json:"resolved"`
			Dev      bool   `json:"dev"`
		} `json:"packages"`
	}

	if err := json.Unmarshal(data, &lockData); err != nil {
		return nil, fmt.Errorf("failed to parse package-lock.json: %w", err)
	}

	var dependencies []types.Dependency

	// Parse packages (skip root package which has empty key)
	for packagePath, packageInfo := range lockData.Packages {
		if packagePath == "" {
			continue // Skip root package
		}

		// Extract package name from path (e.g., "node_modules/express" -> "express")
		name := filepath.Base(packagePath)
		
		// Skip dev dependencies if not requested
		if packageInfo.Dev && !options.IncludeDevDependencies {
			continue
		}

		dep := types.Dependency{
			Name:        name,
			Version:     packageInfo.Version,
			Registry:    "npm",
			Source:      filePath,
			Direct:      true,
			Development: packageInfo.Dev,
		}
		dependencies = append(dependencies, dep)
	}

	return dependencies, nil
}

// parseYarnLock parses dependencies from yarn.lock
func (a *Analyzer) parseYarnLock(filePath string, options *ScanOptions) ([]types.Dependency, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read yarn.lock: %w", err)
	}

	var dependencies []types.Dependency
	content := string(data)
	lines := strings.Split(content, "\n")

	var currentPackage string
	var currentVersion string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		
		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Package declaration line (e.g., "express@^4.18.0:")
		if strings.HasSuffix(line, ":") && !strings.HasPrefix(line, " ") {
			// Extract package name from the line
			packageSpec := strings.TrimSuffix(line, ":")
			// Handle multiple package specs separated by commas
			specs := strings.Split(packageSpec, ",")
			if len(specs) > 0 {
				// Take the first spec and extract package name
				firstSpec := strings.TrimSpace(specs[0])
				if atIndex := strings.Index(firstSpec, "@"); atIndex > 0 {
					currentPackage = firstSpec[:atIndex]
				} else {
					currentPackage = firstSpec
				}
			}
			continue
		}

		// Version line (e.g., '  version "4.18.2"')
		if strings.HasPrefix(line, "version ") && currentPackage != "" {
			versionPart := strings.TrimPrefix(line, "version ")
			versionPart = strings.Trim(versionPart, `"`)
			currentVersion = versionPart

			// Create dependency when we have both package and version
			if currentPackage != "" && currentVersion != "" {
				dep := types.Dependency{
					Name:        currentPackage,
					Version:     currentVersion,
					Registry:    "npm",
					Source:      filePath,
					Direct:      true,
					Development: false, // yarn.lock doesn't distinguish dev deps
				}
				dependencies = append(dependencies, dep)
				
				// Reset for next package
				currentPackage = ""
				currentVersion = ""
			}
		}
	}

	return dependencies, nil
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
	detectionOptions := &detector.Options{
		DeepAnalysis:        options.DeepAnalysis,
		SimilarityThreshold: options.SimilarityThreshold,
	}

	return a.detector.Analyze(ctx, deps, detectionOptions)
}

// calculateSummary generates a summary of scan results
func (a *Analyzer) calculateSummary(threats []types.Threat, warnings []types.Warning, totalPackages int) ScanSummary {
	summary := ScanSummary{
		TotalWarnings: len(warnings),
		CleanPackages: totalPackages,
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
	// TODO: Implement HTML output format
	return fmt.Errorf("HTML output format not yet implemented")
}