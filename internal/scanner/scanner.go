package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/Alivanroy/Typosentinel/internal/cache"
	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// Scanner handles project scanning and dependency analysis
type Scanner struct {
	config           *config.Config
	detectors        map[string]ProjectDetector
	analyzers        map[string]DependencyAnalyzer
	cache            *cache.CacheIntegration
	analyzerRegistry *AnalyzerRegistry
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

// ScanResults contains the results of a security scan
type ScanResults struct {
	Results []ScanResult `json:"results"`
}

// ScanResult represents a single package scan result
type ScanResult struct {
	Package *types.Package `json:"package"`
	Threats []Threat      `json:"threats"`
}

// Threat represents a security threat found in a package
type Threat struct {
	Type           string  `json:"type"`
	Severity       string  `json:"severity"`
	Score          float64 `json:"score"`
	Description    string  `json:"description"`
	Recommendation string  `json:"recommendation"`
	Evidence       string  `json:"evidence"`
	Source         string  `json:"source"`
	Confidence     float64 `json:"confidence"`
}

// New creates a new scanner instance
func New(cfg *config.Config) (*Scanner, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	s := &Scanner{
		config:           cfg,
		detectors:        make(map[string]ProjectDetector),
		analyzers:        make(map[string]DependencyAnalyzer),
		analyzerRegistry: NewAnalyzerRegistry(cfg),
	}

	// Initialize cache if enabled
	if cfg.Cache != nil && cfg.Cache.Enabled {
		cacheIntegration := cache.NewCacheIntegration(cfg.Cache.CacheDir, cfg.Cache.Enabled, cfg.Cache.TTL)
		s.cache = cacheIntegration
	}

	// Register project detectors
	s.registerDetectors()
	s.registerAnalyzers()

	// Initialize plugin system
	s.initializePlugins()

	return s, nil
}

// ScanProject scans a project for dependencies and security threats
func (s *Scanner) ScanProject(projectPath string) (*types.ScanResult, error) {
	start := time.Now()

	// Check cache first if enabled
	if s.cache != nil {
		cacheKey, err := s.generateCacheKey(projectPath)
		if err == nil {
			if cachedResult, found, err := s.cache.GetCachedAnalysisResult(cacheKey); err == nil && found {
				// Update scan duration to reflect cache hit
				cachedResult.Duration = time.Since(start)
				if cachedResult.Metadata == nil {
					cachedResult.Metadata = make(map[string]interface{})
				}
				cachedResult.Metadata["cache_hit"] = true
				return cachedResult, nil
			}
		}
	}

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
		ID:        generateScanID(),
		Target:    projectPath,
		Type:      projectInfo.Type,
		Status:    "completed",
		Packages:  packages,
		Summary:   summary,
		Duration:  time.Since(start),
		CreatedAt: time.Now(),
	}

	// Cache the result if caching is enabled
	if s.cache != nil {
		cacheKey, err := s.generateCacheKey(projectPath)
		if err == nil {
			metadata := map[string]interface{}{
				"project_type": projectInfo.Type,
				"package_count": len(packages),
				"threat_count": summary.ThreatsFound,
			}
			_ = s.cache.CacheAnalysisResult(cacheKey, result, metadata)
		}
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

	// Check if path exists
	if _, err := os.Stat(absPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("path does not exist: %s", projectPath)
	}

	// Try each detector
	for _, detector := range s.detectors {
		projectInfo, err := detector.Detect(absPath)
		if err == nil && projectInfo != nil {
			return projectInfo, nil
		}
	}

	// Check if directory is empty or has no recognizable package files
	entries, err := os.ReadDir(absPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory: %w", err)
	}

	// If directory is empty, return a generic project info
	if len(entries) == 0 {
		return &ProjectInfo{
			Type:         "generic",
			Path:         projectPath,
			ManifestFile: "",
			LockFile:     "",
			Metadata:     make(map[string]string),
		}, nil
	}

	// If no specific project type detected, return a generic project info
	return &ProjectInfo{
		Type:         "generic",
		Path:         projectPath,
		ManifestFile: "",
		LockFile:     "",
		Metadata:     make(map[string]string),
	}, nil
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
	var threats []*types.Threat

	// Typosquatting detection using similarity analysis
	popularPackages := []string{
		"numpy", "pandas", "requests", "flask", "django", "tensorflow",
		"react", "angular", "vue", "express", "lodash", "axios",
		"jquery", "bootstrap", "moment", "chalk", "commander",
	}

	for _, popular := range popularPackages {
		if similarity := s.calculateSimilarity(pkg.Name, popular); similarity > 0.7 && pkg.Name != popular {
			threats = append(threats, &types.Threat{
				ID:          fmt.Sprintf("typo-%s-%d", pkg.Name, len(threats)),
				Package:     pkg.Name,
				Version:     pkg.Version,
				Registry:    pkg.Registry,
				Type:        types.ThreatTypeTyposquatting,
				Severity:    types.SeverityHigh,
				Description: fmt.Sprintf("Potential typosquatting: %s is similar to popular package %s (similarity: %.3f)", pkg.Name, popular, similarity),
				Evidence: []types.Evidence{
					{
						Type:        "similarity",
						Description: "Levenshtein distance similarity score",
						Score:       similarity,
					},
				},
			})
		}
	}

	return threats, nil
}

// calculateSimilarity calculates similarity between two strings
func (s *Scanner) calculateSimilarity(s1, s2 string) float64 {
	if s1 == s2 {
		return 1.0
	}

	// Simple Levenshtein distance-based similarity
	dist := s.levenshteinDistance(s1, s2)
	maxLen := s.max(len(s1), len(s2))
	if maxLen == 0 {
		return 1.0
	}

	return 1.0 - float64(dist)/float64(maxLen)
}

// levenshteinDistance calculates the Levenshtein distance between two strings
func (s *Scanner) levenshteinDistance(s1, s2 string) int {
	if len(s1) == 0 {
		return len(s2)
	}
	if len(s2) == 0 {
		return len(s1)
	}

	matrix := make([][]int, len(s1)+1)
	for i := range matrix {
		matrix[i] = make([]int, len(s2)+1)
	}

	for i := 0; i <= len(s1); i++ {
		matrix[i][0] = i
	}
	for j := 0; j <= len(s2); j++ {
		matrix[0][j] = j
	}

	for i := 1; i <= len(s1); i++ {
		for j := 1; j <= len(s2); j++ {
			cost := 0
			if s1[i-1] != s2[j-1] {
				cost = 1
			}
			matrix[i][j] = s.min(
				matrix[i-1][j]+1,
				s.min(matrix[i][j-1]+1, matrix[i-1][j-1]+cost),
			)
		}
	}

	return matrix[len(s1)][len(s2)]
}

// min returns the minimum of two integers
func (s *Scanner) min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// max returns the maximum of two integers
func (s *Scanner) max(a, b int) int {
	if a > b {
		return a
	}
	return b
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
		summary.RiskDistribution[pkg.RiskLevel.String()]++
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
	s.analyzers["python"] = NewPythonPackageAnalyzer(s.config)
	s.analyzers["go"] = &GoAnalyzer{config: s.config}
	s.analyzers["rust"] = NewRustAnalyzer(s.config)
	s.analyzers["ruby"] = NewRubyAnalyzer(s.config)
	s.analyzers["php"] = NewPHPAnalyzer(s.config)
	s.analyzers["java"] = NewJavaAnalyzer(s.config)
	s.analyzers["dotnet"] = NewDotNetAnalyzer(s.config)
	s.analyzers["generic"] = &GenericAnalyzer{config: s.config}
}

// generateCacheKey generates a cache key for the scan
func (s *Scanner) generateCacheKey(projectPath string) (string, error) {
	if s.cache == nil {
		return "", fmt.Errorf("cache not initialized")
	}

	// Get enabled analyzers
	enabledAnalyzers := make([]string, 0, len(s.analyzers))
	for name := range s.analyzers {
		enabledAnalyzers = append(enabledAnalyzers, name)
	}

	// Create config map for cache key generation
	configMap := map[string]interface{}{
		"analyzers": enabledAnalyzers,
		"version":   "1.0.0", // Scanner version for cache invalidation
	}

	return s.cache.GenerateScanKey(projectPath, enabledAnalyzers, configMap)
}

// GetCacheStats returns cache statistics
func (s *Scanner) GetCacheStats() cache.CacheStats {
	if s.cache == nil {
		return cache.CacheStats{}
	}
	return s.cache.GetCacheStats()
}

// ClearCache clears all cached scan results
func (s *Scanner) ClearCache() error {
	if s.cache == nil {
		return nil
	}
	return s.cache.InvalidatePackageCache("")
}

// InvalidatePackageCache invalidates cache for a specific package
func (s *Scanner) InvalidatePackageCache(packagePath string) error {
	if s.cache == nil {
		return nil
	}
	return s.cache.InvalidatePackageCache(packagePath)
}

// SetCacheConfig updates the cache configuration
func (s *Scanner) SetCacheConfig(config *cache.CacheConfig) error {
	if s.cache == nil {
		return fmt.Errorf("cache not initialized")
	}
	return s.cache.SetCacheConfig(config)
}

// IsCacheEnabled returns whether caching is enabled
func (s *Scanner) IsCacheEnabled() bool {
	return s.cache != nil
}

// Close closes the scanner and its resources
func (s *Scanner) Close() error {
	if s.cache != nil {
		return s.cache.Close()
	}
	return nil
}

// initializePlugins initializes the plugin system
func (s *Scanner) initializePlugins() {
	if s.config.Plugins == nil || !s.config.Plugins.Enabled {
		return
	}

	// Auto-load plugins if enabled
	if s.config.Plugins.AutoLoad {
		s.loadPluginsFromDirectory()
	}

	// Load specific plugins from configuration
	for _, plugin := range s.config.Plugins.Plugins {
		if plugin.Enabled {
			if err := s.analyzerRegistry.LoadPlugin(plugin.Path); err != nil {
				// Log error but continue with other plugins
				continue
			}
		}
	}
}

// loadPluginsFromDirectory loads all plugins from the configured plugin directory
func (s *Scanner) loadPluginsFromDirectory() {
	if s.config.Plugins.PluginDirectory == "" {
		return
	}

	// Check if plugin directory exists
	if _, err := os.Stat(s.config.Plugins.PluginDirectory); os.IsNotExist(err) {
		return
	}

	// Walk through plugin directory
	filepath.Walk(s.config.Plugins.PluginDirectory, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		// Load .so files (Go plugins)
		if filepath.Ext(path) == ".so" {
			if err := s.analyzerRegistry.LoadPlugin(path); err != nil {
				// Log error but continue
			}
		}

		return nil
	})
}

// LoadPlugin loads a plugin at runtime
func (s *Scanner) LoadPlugin(pluginPath string) error {
	return s.analyzerRegistry.LoadPlugin(pluginPath)
}

// UnloadPlugin unloads a plugin at runtime
func (s *Scanner) UnloadPlugin(name string) error {
	return s.analyzerRegistry.UnloadPlugin(name)
}

// GetLoadedPlugins returns information about loaded plugins
func (s *Scanner) GetLoadedPlugins() map[string]*PluginAnalyzer {
	return s.analyzerRegistry.GetPluginAnalyzers()
}

// GetAnalyzerForProject gets the appropriate analyzer for a project
func (s *Scanner) GetAnalyzerForProject(projectInfo *ProjectInfo) (LanguageAnalyzer, error) {
	return s.analyzerRegistry.GetAnalyzerForProject(projectInfo)
}

// generateScanID generates a unique scan ID
func generateScanID() string {
	return fmt.Sprintf("scan_%d", time.Now().UnixNano())
}