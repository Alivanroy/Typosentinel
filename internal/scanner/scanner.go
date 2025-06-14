package scanner

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/typosentinel/typosentinel/internal/config"
	"github.com/typosentinel/typosentinel/pkg/types"
)

// Scanner handles project scanning and dependency analysis
type Scanner struct {
	config    *config.Config
	detectors map[string]ProjectDetector
	analyzers map[string]DependencyAnalyzer
}

// ProjectDetector interface for detecting different project types
type ProjectDetector interface {
	Detect(projectPath string) (*ProjectInfo, error)
	GetManifestFiles() []string
	GetProjectType() string
}

// DependencyAnalyzer interface for analyzing dependencies
type DependencyAnalyzer interface {
	AnalyzeDependencies(projectInfo *ProjectInfo) (*types.DependencyTree, error)
	ExtractPackages(projectInfo *ProjectInfo) ([]*types.Package, error)
}

// ProjectInfo contains information about a detected project
type ProjectInfo struct {
	Type         string            `json:"type"`
	Path         string            `json:"path"`
	ManifestFile string            `json:"manifest_file"`
	LockFile     string            `json:"lock_file,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

// New creates a new scanner instance
func New(cfg *config.Config) *Scanner {
	s := &Scanner{
		config:    cfg,
		detectors: make(map[string]ProjectDetector),
		analyzers: make(map[string]DependencyAnalyzer),
	}

	// Register project detectors
	s.registerDetectors()
	s.registerAnalyzers()

	return s
}

// ScanProject scans a project for dependencies and security threats
func (s *Scanner) ScanProject(projectPath string) (*types.ScanResult, error) {
	start := time.Now()

	// Detect project type
	projectInfo, err := s.detectProject(projectPath)
	if err != nil {
		return nil, fmt.Errorf("failed to detect project: %w", err)
	}

	// Extract packages
	packages, err := s.extractPackages(projectInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to extract packages: %w", err)
	}

	// Analyze threats for each package
	for i, pkg := range packages {
		threats, err := s.analyzePackageThreats(pkg)
		if err != nil {
			// Log error but continue with other packages
			continue
		}
		// Convert []*types.Threat to []types.Threat
		var threatValues []types.Threat
		for _, threat := range threats {
			if threat != nil {
				threatValues = append(threatValues, *threat)
			}
		}
		packages[i].Threats = threatValues
		packages[i].RiskLevel = s.calculateRiskLevel(threats)
		packages[i].RiskScore = s.calculateRiskScore(threats)
	}

	// Build summary
	summary := s.buildSummary(packages)

	result := &types.ScanResult{
		ID:       generateScanID(),
		Target:   projectPath,
		Type:     projectInfo.Type,
		Status:   "completed",
		Packages: packages,
		Summary:  summary,
		Duration: time.Since(start),
		CreatedAt: time.Now(),
	}

	return result, nil
}

// BuildDependencyTree builds a dependency tree for the project
func (s *Scanner) BuildDependencyTree(projectPath string) (*types.DependencyTree, error) {
	projectInfo, err := s.detectProject(projectPath)
	if err != nil {
		return nil, fmt.Errorf("failed to detect project: %w", err)
	}

	analyzer, exists := s.analyzers[projectInfo.Type]
	if !exists {
		return nil, fmt.Errorf("no analyzer found for project type: %s", projectInfo.Type)
	}

	return analyzer.AnalyzeDependencies(projectInfo)
}

// WatchProject watches a project for changes and automatically scans
func (s *Scanner) WatchProject(projectPath string, interval time.Duration) error {
	if interval > 0 {
		return s.watchWithInterval(projectPath, interval)
	}
	return s.watchWithFileEvents(projectPath)
}

// detectProject detects the project type and returns project information
func (s *Scanner) detectProject(projectPath string) (*ProjectInfo, error) {
	absPath, err := filepath.Abs(projectPath)
	if err != nil {
		return nil, err
	}

	// Try each detector
	for _, detector := range s.detectors {
		projectInfo, err := detector.Detect(absPath)
		if err == nil && projectInfo != nil {
			return projectInfo, nil
		}
	}

	return nil, fmt.Errorf("no supported project type detected in %s", projectPath)
}

// extractPackages extracts packages from the project
func (s *Scanner) extractPackages(projectInfo *ProjectInfo) ([]*types.Package, error) {
	analyzer, exists := s.analyzers[projectInfo.Type]
	if !exists {
		return nil, fmt.Errorf("no analyzer found for project type: %s", projectInfo.Type)
	}

	return analyzer.ExtractPackages(projectInfo)
}

// analyzePackageThreats analyzes threats for a specific package
func (s *Scanner) analyzePackageThreats(pkg *types.Package) ([]*types.Threat, error) {
	// TODO: Implement threat analysis
	// This would typically involve:
	// 1. Checking against known vulnerability databases
	// 2. Analyzing package metadata for suspicious patterns
	// 3. Using ML models for typosquatting detection
	// 4. Checking package reputation and maintainer history

	var threats []*types.Threat

	// Example threat detection (placeholder)
	if strings.Contains(pkg.Name, "test") {
		threats = append(threats, &types.Threat{
			ID:          fmt.Sprintf("typo-%s-%d", pkg.Name, len(threats)),
			Package:     pkg.Name,
			Version:     pkg.Version,
			Registry:    pkg.Registry,
			Type:        types.ThreatTypeTyposquatting,
			Severity:    types.SeverityMedium,
			Description: "Package name contains suspicious patterns",
			Evidence: []types.Evidence{
				{
					Type:        "name_similarity",
					Description: "Similar to popular package",
					Score:       0.7,
				},
			},
		})
	}

	return threats, nil
}

// calculateRiskLevel calculates the risk level based on threats
func (s *Scanner) calculateRiskLevel(threats []*types.Threat) types.Severity {
	if len(threats) == 0 {
		return types.SeverityLow
	}

	highCount := 0
	mediumCount := 0

	for _, threat := range threats {
		switch threat.Severity {
		case types.SeverityHigh, types.SeverityCritical:
			highCount++
		case types.SeverityMedium:
			mediumCount++
		}
	}

	if highCount > 0 {
		return types.SeverityHigh
	}
	if mediumCount > 0 {
		return types.SeverityMedium
	}
	return types.SeverityLow
}

// calculateRiskScore calculates a numerical risk score
func (s *Scanner) calculateRiskScore(threats []*types.Threat) float64 {
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

	// Normalize to 0-1 range
	return totalScore / float64(len(threats))
}

// buildSummary builds a summary of the scan results
func (s *Scanner) buildSummary(packages []*types.Package) *types.ScanSummary {
	summary := &types.ScanSummary{
		TotalPackages:    len(packages),
		RiskDistribution: make(map[string]int),
	}

	for _, pkg := range packages {
		if len(pkg.Threats) > 0 {
			summary.ThreatsFound++
		}
		summary.RiskDistribution[string(pkg.RiskLevel)]++
	}

	return summary
}

// watchWithInterval watches the project with a fixed interval
func (s *Scanner) watchWithInterval(projectPath string, interval time.Duration) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	fmt.Printf("Starting interval-based watching (every %v)\n", interval)

	for {
		select {
		case <-ticker.C:
			result, err := s.ScanProject(projectPath)
			if err != nil {
				fmt.Printf("Scan error: %v\n", err)
				continue
			}
			fmt.Printf("Scan completed: %d packages, %d threats\n",
				result.Summary.TotalPackages, result.Summary.ThreatsFound)
		}
	}
}

// watchWithFileEvents watches the project using file system events
func (s *Scanner) watchWithFileEvents(projectPath string) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer watcher.Close()

	// Add project path to watcher
	err = watcher.Add(projectPath)
	if err != nil {
		return err
	}

	fmt.Println("Starting file system event watching")

	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return nil
			}

			// Check if it's a manifest file change
			if s.isManifestFile(event.Name) {
				fmt.Printf("Manifest file changed: %s\n", event.Name)
				result, err := s.ScanProject(projectPath)
				if err != nil {
					fmt.Printf("Scan error: %v\n", err)
					continue
				}
				fmt.Printf("Scan completed: %d packages, %d threats\n",
					result.Summary.TotalPackages, result.Summary.ThreatsFound)
			}

		case err, ok := <-watcher.Errors:
			if !ok {
				return nil
			}
			fmt.Printf("Watcher error: %v\n", err)
		}
	}
}

// isManifestFile checks if a file is a manifest file
func (s *Scanner) isManifestFile(filename string) bool {
	base := filepath.Base(filename)
	manifestFiles := []string{
		"package.json", "package-lock.json", "yarn.lock",
		"requirements.txt", "pyproject.toml", "poetry.lock", "Pipfile", "Pipfile.lock",
		"go.mod", "go.sum",
		"Cargo.toml", "Cargo.lock",
		"Gemfile", "Gemfile.lock",
		"composer.json", "composer.lock",
		"pom.xml", "build.gradle", "build.gradle.kts",
	}

	for _, manifest := range manifestFiles {
		if base == manifest {
			return true
		}
	}
	return false
}

// registerDetectors registers all project detectors
func (s *Scanner) registerDetectors() {
	s.detectors["nodejs"] = &NodeJSDetector{}
	s.detectors["python"] = &PythonDetector{}
	s.detectors["go"] = &GoDetector{}
	s.detectors["rust"] = &RustDetector{}
	s.detectors["ruby"] = &RubyDetector{}
	s.detectors["php"] = &PHPDetector{}
	s.detectors["java"] = &JavaDetector{}
	s.detectors["dotnet"] = &DotNetDetector{}
}

// registerAnalyzers registers all dependency analyzers
func (s *Scanner) registerAnalyzers() {
	s.analyzers["nodejs"] = &NodeJSAnalyzer{config: s.config}
	s.analyzers["python"] = &PythonAnalyzer{config: s.config}
	s.analyzers["go"] = &GoAnalyzer{config: s.config}
	s.analyzers["rust"] = &RustAnalyzer{config: s.config}
	s.analyzers["ruby"] = &RubyAnalyzer{config: s.config}
	s.analyzers["php"] = &PHPAnalyzer{config: s.config}
	s.analyzers["java"] = &JavaAnalyzer{config: s.config}
	s.analyzers["dotnet"] = &DotNetAnalyzer{config: s.config}
}

// generateScanID generates a unique scan ID
func generateScanID() string {
	return fmt.Sprintf("scan_%d", time.Now().UnixNano())
}