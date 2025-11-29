// Package scanner handles project detection, dependency extraction, and threat analysis.
package scanner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/cache"
	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/internal/events"
	"github.com/Alivanroy/Typosentinel/internal/integrations/hub"
	pkgevents "github.com/Alivanroy/Typosentinel/pkg/events"
	"github.com/Alivanroy/Typosentinel/pkg/logger"
	"github.com/Alivanroy/Typosentinel/pkg/types"
	"github.com/fsnotify/fsnotify"
)

// Scanner handles project scanning and dependency analysis
type Scanner struct {
	config           *config.Config
	detectors        map[string]ProjectDetector
	analyzers        map[string]DependencyAnalyzer
	cache            *cache.CacheIntegration
	analyzerRegistry *AnalyzerRegistry
	// mlDetector removed to break circular dependency
	eventBus         *events.EventBus
	integrationHub   *hub.IntegrationHub
	metadataEnricher *MetadataEnricher
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
	Threats []Threat       `json:"threats"`
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
		metadataEnricher: NewMetadataEnricher(),
	}

	// Initialize logger
	loggerInstance := logger.New()

	// Initialize event bus
	s.eventBus = events.NewEventBus(*loggerInstance, 1000)

	// Initialize integration hub if integrations are configured
	if cfg.Integrations != nil {
		integrationHub := hub.NewIntegrationHub(s.eventBus, cfg.Integrations, *loggerInstance)
		s.integrationHub = integrationHub
	}

	// Initialize cache if enabled
	if cfg.Cache != nil && cfg.Cache.Enabled {
		// Convert config.CacheConfig to cache.CacheConfig
		cacheConfig := &cache.CacheConfig{
			Enabled:     cfg.Cache.Enabled,
			Type:        cfg.Cache.Provider,
			TTL:         cfg.Cache.TTL,
			MaxSize:     int64(cfg.Cache.MaxSize),
			CacheDir:    cfg.Cache.CacheDir,
			RedisURL:    "",    // Not available in config.CacheConfig
			Compression: false, // Default value
			Encryption:  false, // Default value
		}
		cacheIntegration, err := cache.NewCacheIntegration(cacheConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize cache: %w", err)
		}
		s.cache = cacheIntegration
	}

	// ML detector initialization commented out to break circular dependency
	// TODO: Implement ML integration through a different approach

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
			if cachedResult, found, err := s.cache.GetCachedScanResult(cacheKey); err == nil && found {
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

	// Enrich package metadata
	ctx := context.Background()
	for _, pkg := range packages {
		// Initialize metadata if nil
		if pkg.Metadata == nil {
			pkg.Metadata = &types.PackageMetadata{}
		}
		fmt.Printf("Enriching package %s (registry: %s, description: %s)\n", pkg.Name, pkg.Registry, pkg.Metadata.Description)
		if err := s.metadataEnricher.enrichPackage(ctx, pkg); err != nil {
			// Log error but continue with other packages
			fmt.Printf("Failed to enrich package %s: %v\n", pkg.Name, err)
		} else {
			fmt.Printf("Enriched package %s - new description: %s\n", pkg.Name, pkg.Metadata.Description)
		}
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
				// Emit security event for each threat detected
				s.emitSecurityEvent(pkg, threat, projectInfo)
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
			_ = s.cache.CacheScanResult(cacheKey, result, nil)
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

// analyzePackageThreats analyzes threats for a specific package using enhanced ML detection
func (s *Scanner) analyzePackageThreats(pkg *types.Package) ([]*types.Threat, error) {
	var threats []*types.Threat

	// Basic rule-based threat detection
	threats = append(threats, s.detectTyposquatting(pkg)...)
	threats = append(threats, s.detectSuspiciousPatterns(pkg)...)
	threats = append(threats, s.detectMaliciousIndicators(pkg)...)
	threats = append(threats, s.detectVersionAnomalies(pkg)...)

	return threats, nil
}

// convertToMLFeatures converts a package to enhanced ML features
// Commented out to break circular dependency with ml package
/*
func (s *Scanner) convertToMLFeatures(pkg *types.Package) *ml.EnhancedPackageFeatures {
	// Implementation commented out due to circular dependency
	return nil
}
*/

// convertMLResultsToThreats converts ML detection results to threat objects
// Commented out to break circular dependency with ml package
/*
func (s *Scanner) convertMLResultsToThreats(pkg *types.Package, result *ml.MLDetectionResult) []*types.Threat {
	// Implementation commented out due to circular dependency
	return nil
}
*/

// Helper methods for ML feature conversion

// convertRiskLevelToSeverity converts ML risk level to threat severity
func (s *Scanner) convertRiskLevelToSeverity(riskLevel string) types.Severity {
	switch riskLevel {
	case "critical":
		return types.SeverityCritical
	case "high":
		return types.SeverityHigh
	case "medium":
		return types.SeverityMedium
	case "low":
		return types.SeverityLow
	default:
		return types.SeverityLow
	}
}

// convertMaintainers converts package maintainers to ML format
func (s *Scanner) convertMaintainers(maintainers []string) []string {
	// ML package expects []string for maintainers, so return as-is
	return maintainers
}

// convertDependencies converts package dependencies to ML format
// Commented out to break circular dependency with ml package
/*
func (s *Scanner) convertDependencies(deps []types.Dependency) []ml.Dependency {
	// Implementation commented out due to circular dependency
	return nil
}
*/

// countFilesByExtension counts files with specific extension
func (s *Scanner) countFilesByExtension(files []string, ext string) int {
	count := 0
	for _, file := range files {
		if filepath.Ext(file) == ext {
			count++
		}
	}
	return count
}

// countBinaryFiles counts binary files
func (s *Scanner) countBinaryFiles(files []string) int {
	binaryExts := []string{".exe", ".dll", ".so", ".dylib", ".bin"}
	count := 0
	for _, file := range files {
		ext := filepath.Ext(file)
		for _, binExt := range binaryExts {
			if ext == binExt {
				count++
				break
			}
		}
	}
	return count
}

// countConfigFiles counts configuration files
func (s *Scanner) countConfigFiles(files []string) int {
	configFiles := []string{"config", ".env", ".ini", ".conf", ".cfg"}
	count := 0
	for _, file := range files {
		base := filepath.Base(file)
		for _, configFile := range configFiles {
			if base == configFile || filepath.Ext(base) == configFile {
				count++
				break
			}
		}
	}
	return count
}

// findSuspiciousFiles finds suspicious files
func (s *Scanner) findSuspiciousFiles(files []string) []string {
	suspiciousPatterns := []string{"install", "setup", "update", "download", "exec"}
	var suspicious []string
	for _, file := range files {
		base := filepath.Base(file)
		for _, pattern := range suspiciousPatterns {
			if len(base) >= len(pattern) {
				for i := 0; i <= len(base)-len(pattern); i++ {
					if base[i:i+len(pattern)] == pattern {
						suspicious = append(suspicious, file)
						break
					}
				}
			}
		}
	}
	return suspicious
}

// calculateLinesOfCode calculates total lines of code
func (s *Scanner) calculateLinesOfCode(files []string) int {
	// Simplified calculation - in real implementation, would read files
	return len(files) * 50 // Estimate 50 lines per file
}

// calculateComplexityScore calculates code complexity score
func (s *Scanner) calculateComplexityScore(files []string) float64 {
	// Simplified calculation - in real implementation, would analyze code
	return 0.5 // Default medium complexity
}

// calculateObfuscationScore calculates code obfuscation score
func (s *Scanner) calculateObfuscationScore(files []string) float64 {
	// Simplified calculation - in real implementation, would analyze code patterns
	return 0.1 // Default low obfuscation
}

// hasObfuscatedCode checks if package has obfuscated code
func (s *Scanner) hasObfuscatedCode(files []string) bool {
	// Simplified check - in real implementation, would analyze code patterns
	return false
}

// countNetworkCalls counts network-related calls in code
func (s *Scanner) countNetworkCalls(files []string) int {
	// Simplified calculation - in real implementation, would analyze code
	return 0
}

// countFileSystemAccess counts file system access calls
func (s *Scanner) countFileSystemAccess(files []string) int {
	// Simplified calculation - in real implementation, would analyze code
	return 0
}

// countProcessExecution counts process execution calls
func (s *Scanner) countProcessExecution(files []string) int {
	// Simplified calculation - in real implementation, would analyze code
	return 0
}

// hasInstallNetworkActivity checks for network activity during installation
func (s *Scanner) hasInstallNetworkActivity(pkg *types.Package) bool {
	// Simplified check - in real implementation, would analyze install scripts
	return false
}

// hasInstallFileModification checks for file modification during installation
func (s *Scanner) hasInstallFileModification(pkg *types.Package) bool {
	// Simplified check - in real implementation, would analyze install scripts
	return false
}

// hasAntiAnalysisTechniques checks for anti-analysis techniques
func (s *Scanner) hasAntiAnalysisTechniques(files []string) bool {
	// Simplified check - in real implementation, would analyze code patterns
	return false
}

// hasDataCollection checks for data collection behavior
func (s *Scanner) hasDataCollection(files []string) bool {
	// Simplified check - in real implementation, would analyze code patterns
	return false
}

// hasDataExfiltration checks for data exfiltration behavior
func (s *Scanner) hasDataExfiltration(files []string) bool {
	// Simplified check - in real implementation, would analyze code patterns
	return false
}

// hasSuspiciousConnections checks for suspicious network connections
func (s *Scanner) hasSuspiciousConnections(files []string) bool {
	// Simplified check - in real implementation, would analyze network patterns
	return false
}

// min returns the minimum of two integers
func (s *Scanner) min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// minThree returns the minimum of three integers
func (s *Scanner) minThree(a, b, c int) int {
	min := a
	if b < min {
		min = b
	}
	if c < min {
		min = c
	}
	return min
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
	var enabledAnalyzers []string
	for name := range s.analyzers {
		enabledAnalyzers = append(enabledAnalyzers, name)
	}

	// Create config map
	configMap := map[string]interface{}{
		"scan_config": s.config,
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

// emitSecurityEvent emits a security event when a threat is detected
func (s *Scanner) emitSecurityEvent(pkg *types.Package, threat *types.Threat, projectInfo *ProjectInfo) {
	if s.eventBus == nil {
		return
	}

	// Convert types.Threat to pkgevents.SecurityEvent
	event := &pkgevents.SecurityEvent{
		ID:        fmt.Sprintf("event_%d", time.Now().UnixNano()),
		Timestamp: time.Now(),
		Type:      s.convertThreatTypeToEventType(string(threat.Type)),
		Severity:  s.convertSeverityToEventSeverity(threat.Severity.String()),
		Package: pkgevents.PackageInfo{
			Name:     pkg.Name,
			Version:  pkg.Version,
			Registry: pkg.Registry,
		},
		Threat: pkgevents.ThreatInfo{
			Type:        string(threat.Type),
			Description: threat.Description,
			RiskScore:   threat.Confidence,
			Confidence:  threat.Confidence,
			Evidence:    s.convertEvidenceToMap(threat.Evidence),
			Mitigations: []string{threat.Recommendation},
		},
		Metadata: pkgevents.EventMetadata{
			DetectionMethod: threat.DetectionMethod,
			Tags:            []string{"scanner", "automated"},
			CustomFields: map[string]string{
				"project_path":    projectInfo.Path,
				"project_type":    projectInfo.Type,
				"scanner_version": "1.0.0",
			},
		},
	}

	// Publish the event
	ctx := context.Background()
	s.eventBus.Publish(ctx, event)
}

// convertThreatTypeToEventType converts types.ThreatType to pkgevents.EventType
func (s *Scanner) convertThreatTypeToEventType(threatType string) pkgevents.EventType {
	switch threatType {
	case string(types.ThreatTypeMalicious):
		return pkgevents.EventTypeThreatDetected
	case string(types.ThreatTypeTyposquatting):
		return pkgevents.EventTypeThreatDetected
	case string(types.ThreatTypeSuspicious):
		return pkgevents.EventTypeThreatDetected
	default:
		return pkgevents.EventTypeThreatDetected
	}
}

// convertSeverityToEventSeverity converts types.Severity to pkgevents.Severity
func (s *Scanner) convertSeverityToEventSeverity(severity string) pkgevents.Severity {
	switch severity {
	case types.SeverityCritical.String():
		return pkgevents.SeverityCritical
	case types.SeverityHigh.String():
		return pkgevents.SeverityHigh
	case types.SeverityMedium.String():
		return pkgevents.SeverityMedium
	case types.SeverityLow.String():
		return pkgevents.SeverityLow
	default:
		return pkgevents.SeverityLow
	}
}

// convertEvidenceToMap converts evidence slice to map format
func (s *Scanner) convertEvidenceToMap(evidence []types.Evidence) map[string]string {
	if len(evidence) == 0 {
		return make(map[string]string)
	}

	result := make(map[string]string)
	for i, ev := range evidence {
		key := fmt.Sprintf("evidence_%d", i)
		result[key] = fmt.Sprintf("%s: %s", ev.Type, ev.Description)
	}
	return result
}

// generateScanID generates a unique scan ID
func generateScanID() string {
	return fmt.Sprintf("scan_%d", time.Now().Unix())
}

// detectTyposquatting detects potential typosquatting threats
func (s *Scanner) detectTyposquatting(pkg *types.Package) []*types.Threat {
	var threats []*types.Threat

	// Popular package names to check against
	popularPackages := s.getPopularPackages(pkg.Registry)

	for _, popular := range popularPackages {
		if similarity := s.calculateSimilarity(pkg.Name, popular); similarity > 0.7 && similarity < 1.0 {
			threat := &types.Threat{
				ID:          fmt.Sprintf("typo_%d", time.Now().UnixNano()),
				Type:        "typosquatting",
				Severity:    s.getSeverityFromSimilarity(similarity),
				Confidence:  similarity,
				Description: fmt.Sprintf("Package name '%s' is similar to popular package '%s'", pkg.Name, popular),
				SimilarTo:   popular,
				Evidence:    []types.Evidence{{Type: "similarity", Value: fmt.Sprintf("%.2f", similarity)}},
			}
			threats = append(threats, threat)
		}
	}

	return threats
}

// detectSuspiciousPatterns detects suspicious naming patterns
func (s *Scanner) detectSuspiciousPatterns(pkg *types.Package) []*types.Threat {
	var threats []*types.Threat

	// Check for suspicious patterns
	suspiciousPatterns := []string{
		"test", "temp", "demo", "sample", "example",
		"hack", "crack", "exploit", "malware", "virus",
		"backdoor", "trojan", "keylog", "stealer",
	}

	for _, pattern := range suspiciousPatterns {
		if strings.Contains(strings.ToLower(pkg.Name), pattern) {
			threat := &types.Threat{
				ID:          fmt.Sprintf("pattern_%d", time.Now().UnixNano()),
				Type:        "suspicious_pattern",
				Severity:    types.SeverityMedium,
				Confidence:  0.6,
				Description: fmt.Sprintf("Package name contains suspicious pattern: %s", pattern),
				Evidence:    []types.Evidence{{Type: "pattern", Value: pattern}},
			}
			threats = append(threats, threat)
		}
	}

	return threats
}

// detectMaliciousIndicators detects known malicious indicators
func (s *Scanner) detectMaliciousIndicators(pkg *types.Package) []*types.Threat {
	var threats []*types.Threat

	// Check for suspicious metadata
	if pkg.Metadata.Author == "" || pkg.Metadata.Description == "" {
		threat := &types.Threat{
			ID:          fmt.Sprintf("meta_%d", time.Now().UnixNano()),
			Type:        "incomplete_metadata",
			Severity:    types.SeverityLow,
			Confidence:  0.4,
			Description: "Package has incomplete metadata (missing author or description)",
			Evidence:    []types.Evidence{{Type: "metadata", Value: "incomplete"}},
		}
		threats = append(threats, threat)
	}

	// Check for suspicious version patterns
	if strings.Contains(pkg.Version, "alpha") || strings.Contains(pkg.Version, "beta") {
		threat := &types.Threat{
			ID:          fmt.Sprintf("version_%d", time.Now().UnixNano()),
			Type:        "unstable_version",
			Severity:    types.SeverityLow,
			Confidence:  0.3,
			Description: "Package uses pre-release version which may be unstable",
			Evidence:    []types.Evidence{{Type: "version", Value: pkg.Version}},
		}
		threats = append(threats, threat)
	}

	return threats
}

// detectVersionAnomalies detects version-related anomalies
func (s *Scanner) detectVersionAnomalies(pkg *types.Package) []*types.Threat {
	var threats []*types.Threat

	// Check for suspicious version jumps (e.g., 1.0.0 to 999.0.0)
	if strings.HasPrefix(pkg.Version, "999") || strings.HasPrefix(pkg.Version, "9999") {
		threat := &types.Threat{
			ID:          fmt.Sprintf("anomaly_%d", time.Now().UnixNano()),
			Type:        "version_anomaly",
			Severity:    types.SeverityHigh,
			Confidence:  0.8,
			Description: "Package uses suspiciously high version number",
			Evidence:    []types.Evidence{{Type: "version", Value: pkg.Version}},
		}
		threats = append(threats, threat)
	}

	return threats
}

// getPopularPackages returns popular packages for the given registry
func (s *Scanner) getPopularPackages(registry string) []string {
	switch strings.ToLower(registry) {
	case "npm":
		return []string{"react", "lodash", "express", "axios", "webpack", "babel", "eslint", "typescript", "jquery", "moment"}
	case "pypi":
		return []string{"numpy", "pandas", "requests", "flask", "django", "tensorflow", "pytorch", "scikit-learn", "matplotlib", "pillow"}
	case "rubygems":
		return []string{"rails", "bundler", "rake", "rspec", "nokogiri"}
	case "maven":
		return []string{"junit", "spring-boot", "jackson-core", "slf4j-api", "commons-lang3"}
	default:
		return []string{}
	}
}

// calculateSimilarity calculates similarity between two strings using Levenshtein distance
func (s *Scanner) calculateSimilarity(s1, s2 string) float64 {
	if s1 == s2 {
		return 1.0
	}

	maxLen := len(s1)
	if len(s2) > maxLen {
		maxLen = len(s2)
	}

	if maxLen == 0 {
		return 1.0
	}

	distance := s.levenshteinDistance(s1, s2)
	return 1.0 - float64(distance)/float64(maxLen)
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

			matrix[i][j] = s.minThree(
				matrix[i-1][j]+1,      // deletion
				matrix[i][j-1]+1,      // insertion
				matrix[i-1][j-1]+cost, // substitution
			)
		}
	}

	return matrix[len(s1)][len(s2)]
}

// getSeverityFromSimilarity determines threat severity based on similarity score
func (s *Scanner) getSeverityFromSimilarity(similarity float64) types.Severity {
	if similarity >= 0.9 {
		return types.SeverityHigh
	} else if similarity >= 0.8 {
		return types.SeverityMedium
	}
	return types.SeverityLow
}
