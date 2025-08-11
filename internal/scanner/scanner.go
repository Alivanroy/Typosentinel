package scanner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/cache"
	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/internal/events"
	"github.com/Alivanroy/Typosentinel/internal/integrations/hub"
	"github.com/Alivanroy/Typosentinel/internal/ml"
	"github.com/Alivanroy/Typosentinel/pkg/logger"
	pkgevents "github.com/Alivanroy/Typosentinel/pkg/events"
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
	mlDetector       *ml.EnhancedMLDetector
	eventBus         *events.EventBus
	integrationHub   *hub.IntegrationHub
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
			RedisURL:    "", // Not available in config.CacheConfig
			Compression: false, // Default value
			Encryption:  false, // Default value
		}
		cacheIntegration, err := cache.NewCacheIntegration(cacheConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize cache: %w", err)
		}
		s.cache = cacheIntegration
	}

	// Initialize enhanced ML detector
	mlConfig := ml.DefaultEnhancedMLConfig()
	if cfg.MLAnalysis != nil {
		// Override with user configuration if available
		mlConfig.MalwareThreshold = cfg.MLAnalysis.MaliciousThreshold
		mlConfig.SimilarityThreshold = cfg.MLAnalysis.SimilarityThreshold
		mlConfig.ReputationThreshold = cfg.MLAnalysis.ReputationThreshold
	}
	mlDetector, err := ml.NewEnhancedMLDetector(mlConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize ML detector: %w", err)
	}
	s.mlDetector = mlDetector

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

	// Convert package to enhanced ML features
	features := s.convertToMLFeatures(pkg)

	// Run enhanced ML analysis
	ctx := context.Background()
	mlResult, err := s.mlDetector.AnalyzePackage(ctx, features)
	if err != nil {
		return nil, fmt.Errorf("ML analysis failed: %w", err)
	}

	// Convert ML results to threats
	threats = append(threats, s.convertMLResultsToThreats(pkg, mlResult)...)

	return threats, nil
}

// convertToMLFeatures converts a package to enhanced ML features
func (s *Scanner) convertToMLFeatures(pkg *types.Package) *ml.EnhancedPackageFeatures {

	var description, author, homepage, repository, license string
	var downloads int64
	var maintainers, keywords []string
	var creationDate, lastUpdated time.Time

	if pkg.Metadata != nil {
		description = pkg.Metadata.Description
		author = pkg.Metadata.Author
		homepage = pkg.Metadata.Homepage
		repository = pkg.Metadata.Repository
		license = pkg.Metadata.License
		downloads = pkg.Metadata.Downloads
		maintainers = pkg.Metadata.Maintainers
		keywords = pkg.Metadata.Keywords
		creationDate = pkg.Metadata.CreatedAt
		lastUpdated = pkg.Metadata.UpdatedAt
	}

	features := &ml.EnhancedPackageFeatures{
		Name:         pkg.Name,
		Version:      pkg.Version,
		Registry:     pkg.Registry,
		Description:  description,
		Author:       author,
		Homepage:     homepage,
		Repository:   repository,
		License:      license,
		Downloads:    downloads,
		CreationDate: creationDate,
		LastUpdated:  lastUpdated,
		Maintainers:  maintainers,
		Dependencies: s.convertDependencies(pkg.Dependencies),
		Keywords:     keywords,
		// Use empty/default values for file-based analysis since Package struct doesn't have Files field
		FileStructure: ml.FileStructure{
			TotalFiles:      0,
			JavaScriptFiles: 0,
			TypeScriptFiles: 0,
			BinaryFiles:     0,
			ConfigFiles:     0,
			SuspiciousFiles: []string{},
		},
		CodeMetrics: ml.CodeMetrics{
			LinesOfCode:          0,
			ObfuscationScore:     0.0,
			CyclomaticComplexity: 0.0,
		},
		SecurityMetrics: ml.SecurityMetrics{
			VulnerabilityCount: 0, // Package struct doesn't have Vulnerabilities field
			ObfuscatedCode:     false,
			NetworkCalls:       0,
			FileSystemAccess:   0,
			ProcessExecution:   0,
		},
		BehavioralMetrics: ml.BehavioralMetrics{
			InstallationBehavior: ml.EnhancedInstallBehavior{
				NetworkActivity:   false,
				FileModifications: 0,
			},
			RuntimeBehavior: ml.EnhancedRuntimeBehavior{
				AntiAnalysisTechniques: false,
			},
			NetworkBehavior: ml.EnhancedNetworkBehavior{
				DataExfiltration: false,
			},
		},
	}

	return features
}

// convertMLResultsToThreats converts ML detection results to threat objects
func (s *Scanner) convertMLResultsToThreats(pkg *types.Package, result *ml.MLDetectionResult) []*types.Threat {
	var threats []*types.Threat

	// Malware detection threat
	if result.IsMalicious {
		threats = append(threats, &types.Threat{
			ID:          fmt.Sprintf("malware-%s", pkg.Name),
			Package:     pkg.Name,
			Version:     pkg.Version,
			Registry:    pkg.Registry,
			Type:        types.ThreatTypeMalicious,
			Severity:    s.convertRiskLevelToSeverity(result.ThreatLevel),
			Description: fmt.Sprintf("Malware detected with confidence %.2f: %s", result.MalwareClassification.Confidence, result.MalwareClassification.ClassificationReason),
			Evidence: []types.Evidence{
				{
					Type:        "ml_classification",
					Description: "Enhanced ML malware classification",
					Score:       result.MalwareClassification.Confidence,
				},
			},
		})
	}

	// Typosquatting detection threat
	if result.IsTyposquatting {
		threats = append(threats, &types.Threat{
			ID:          fmt.Sprintf("typo-%s", pkg.Name),
			Package:     pkg.Name,
			Version:     pkg.Version,
			Registry:    pkg.Registry,
			Type:        types.ThreatTypeTyposquatting,
			Severity:    s.convertRiskLevelToSeverity(result.ThreatLevel),
			Description: fmt.Sprintf("Typosquatting detected targeting '%s' with confidence %.2f", result.TypoDetection.TargetPackage, result.TypoDetection.Confidence),
			Evidence: []types.Evidence{
				{
					Type:        "enhanced_similarity",
					Description: "Multi-algorithm similarity analysis",
					Score:       result.TypoDetection.Confidence,
				},
			},
		})
	}

	// Anomaly detection threat
	if result.IsAnomalous {
		threats = append(threats, &types.Threat{
			ID:          fmt.Sprintf("anomaly-%s", pkg.Name),
			Package:     pkg.Name,
			Version:     pkg.Version,
			Registry:    pkg.Registry,
			Type:        types.ThreatTypeSuspicious,
			Severity:    types.SeverityMedium,
			Description: fmt.Sprintf("Anomalous behavior detected with score %.2f", result.AnomalyDetection.AnomalyScore),
			Evidence: []types.Evidence{
				{
					Type:        "behavioral_anomaly",
					Description: "Enhanced behavioral anomaly detection",
					Score:       result.AnomalyDetection.AnomalyScore,
				},
			},
		})
	}

	// Reputation-based threat
	// Use a default threshold since GetConfig method is not available
	if result.ReputationAnalysis.ReputationScore < 0.5 {
		threats = append(threats, &types.Threat{
			ID:          fmt.Sprintf("reputation-%s", pkg.Name),
			Package:     pkg.Name,
			Version:     pkg.Version,
			Registry:    pkg.Registry,
			Type:        types.ThreatTypeSuspicious,
			Severity:    types.SeverityLow,
			Description: fmt.Sprintf("Low reputation score: %.2f", result.ReputationAnalysis.ReputationScore),
			Evidence: []types.Evidence{
				{
					Type:        "reputation_analysis",
					Description: "Enhanced reputation analysis",
					Score:       result.ReputationAnalysis.ReputationScore,
				},
			},
		})
	}

	return threats
}

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
func (s *Scanner) convertDependencies(deps []types.Dependency) []ml.Dependency {
	mlDeps := make([]ml.Dependency, len(deps))
	for i, dep := range deps {
		mlDeps[i] = ml.Dependency{
			Name:       dep.Name,
			Version:    dep.Version,
			Suspicious: false, // Default value since Suspicious field is not available
		}
	}
	return mlDeps
}

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
			Tags:           []string{"scanner", "automated"},
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
	return fmt.Sprintf("scan_%d", time.Now().UnixNano())
}
