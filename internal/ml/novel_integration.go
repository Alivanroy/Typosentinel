package ml

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/Alivanroy/Typosentinel/pkg/config"
	"github.com/Alivanroy/Typosentinel/pkg/logger"
	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// NovelMLIntegrator integrates novel algorithms with existing ML systems
type NovelMLIntegrator struct {
	mu                    sync.RWMutex
	novelSuite           *NovelAlgorithmSuite
	enhancedDetector     *EnhancedMLDetector
	featureExtractor     *AdvancedFeatureExtractor
	enhancedAlgorithms   *EnhancedMLAlgorithms
	config               *NovelIntegrationConfig
	logger               logger.Logger
	metrics              *IntegrationMetrics
	performanceTracker   *PerformanceTracker
	cacheManager         *CacheManager
}

// NovelIntegrationConfig contains configuration for novel ML integration
type NovelIntegrationConfig struct {
	NovelAlgorithmsEnabled    bool                     `yaml:"novel_algorithms_enabled"`
	HybridModeEnabled         bool                     `yaml:"hybrid_mode_enabled"`
	FallbackToClassic         bool                     `yaml:"fallback_to_classic"`
	NovelAlgorithmConfig      *NovelAlgorithmConfig    `yaml:"novel_algorithm_config"`
	IntegrationStrategy       string                   `yaml:"integration_strategy"`
	PerformanceThresholds     *PerformanceThresholds   `yaml:"performance_thresholds"`
	CachingConfig             *CachingConfig           `yaml:"caching_config"`
	MonitoringConfig          *MonitoringConfig        `yaml:"monitoring_config"`
}

// PerformanceThresholds defines performance criteria
type PerformanceThresholds struct {
	MaxLatencyMs          int     `yaml:"max_latency_ms"`
	MinAccuracy           float64 `yaml:"min_accuracy"`
	MaxMemoryUsageMB      int     `yaml:"max_memory_usage_mb"`
	MinThroughputPerSec   int     `yaml:"min_throughput_per_sec"`
	MaxErrorRate          float64 `yaml:"max_error_rate"`
}

// CachingConfig defines caching behavior
type CachingConfig struct {
	Enabled               bool          `yaml:"enabled"`
	TTL                   time.Duration `yaml:"ttl"`
	MaxSize               int           `yaml:"max_size"`
	EvictionPolicy        string        `yaml:"eviction_policy"`
	CompressionEnabled    bool          `yaml:"compression_enabled"`
}

// MonitoringConfig defines monitoring and alerting
type MonitoringConfig struct {
	MetricsEnabled        bool          `yaml:"metrics_enabled"`
	AlertsEnabled         bool          `yaml:"alerts_enabled"`
	ReportingInterval     time.Duration `yaml:"reporting_interval"`
	PerformanceLogging    bool          `yaml:"performance_logging"`
	DetailedTracing       bool          `yaml:"detailed_tracing"`
}

// IntegrationMetrics tracks integration performance
type IntegrationMetrics struct {
	mu                    sync.RWMutex
	TotalAnalyses         int64                    `json:"total_analyses"`
	NovelAnalyses         int64                    `json:"novel_analyses"`
	ClassicAnalyses       int64                    `json:"classic_analyses"`
	HybridAnalyses        int64                    `json:"hybrid_analyses"`
	AverageLatency        time.Duration            `json:"average_latency"`
	AccuracyMetrics       map[string]float64       `json:"accuracy_metrics"`
	ErrorRates            map[string]float64       `json:"error_rates"`
	Throughput            float64                  `json:"throughput"`
	MemoryUsage           int64                    `json:"memory_usage_mb"`
	CacheHitRate          float64                  `json:"cache_hit_rate"`
	AlgorithmPerformance  map[string]*AlgMetrics   `json:"algorithm_performance"`
}

// AlgMetrics tracks individual algorithm performance
type AlgMetrics struct {
	ExecutionCount        int64         `json:"execution_count"`
	AverageLatency        time.Duration `json:"average_latency"`
	SuccessRate           float64       `json:"success_rate"`
	Accuracy              float64       `json:"accuracy"`
	MemoryUsage           int64         `json:"memory_usage_mb"`
	LastExecution         time.Time     `json:"last_execution"`
}

// PerformanceTracker monitors system performance
type PerformanceTracker struct {
	mu                    sync.RWMutex
	startTime             time.Time
	executionTimes        []time.Duration
	memorySnapshots       []int64
	errorCounts           map[string]int64
	successCounts         map[string]int64
}

// CacheManager handles result caching
type CacheManager struct {
	mu                    sync.RWMutex
	cache                 map[string]*CacheEntry
	config                *CachingConfig
	lastCleanup           time.Time
	hitCount              int64
	missCount             int64
}

// CacheEntry represents a cached analysis result
type CacheEntry struct {
	Result                *IntegratedAnalysisResult
	Timestamp             time.Time
	AccessCount           int64
	LastAccess            time.Time
	Size                  int64
}

// IntegratedAnalysisResult combines novel and classic analysis results
type IntegratedAnalysisResult struct {
	PackageID             string                        `json:"package_id"`
	AnalysisTime          time.Time                     `json:"analysis_time"`
	Strategy              string                        `json:"strategy"`
	NovelResult           *NovelAnalysisResult          `json:"novel_result,omitempty"`
	ClassicResult         *types.MLAnalysisResult       `json:"classic_result,omitempty"`
	HybridScore           float64                       `json:"hybrid_score"`
	FinalThreatLevel      string                        `json:"final_threat_level"`
	Confidence            float64                       `json:"confidence"`
	Recommendations       []string                      `json:"recommendations"`
	PerformanceMetrics    *AnalysisPerformance          `json:"performance_metrics"`
	Explanation           *DetailedExplanation          `json:"explanation"`
	Metadata              map[string]interface{}        `json:"metadata"`
}

// AnalysisPerformance tracks performance of individual analysis
type AnalysisPerformance struct {
	TotalLatency          time.Duration                 `json:"total_latency"`
	NovelLatency          time.Duration                 `json:"novel_latency"`
	ClassicLatency        time.Duration                 `json:"classic_latency"`
	MemoryUsed            int64                         `json:"memory_used_mb"`
	AlgorithmsUsed        []string                      `json:"algorithms_used"`
	CacheHit              bool                          `json:"cache_hit"`
	ErrorsEncountered     []string                      `json:"errors_encountered"`
}

// DetailedExplanation provides comprehensive analysis explanation
type DetailedExplanation struct {
	Summary               string                        `json:"summary"`
	KeyFindings           []string                      `json:"key_findings"`
	AlgorithmContributions map[string]string            `json:"algorithm_contributions"`
	RiskFactors           []RiskFactor                  `json:"risk_factors"`
	MitigationStrategies  []string                      `json:"mitigation_strategies"`
	ConfidenceFactors     []string                      `json:"confidence_factors"`
}

// RiskFactor represents an identified risk
type RiskFactor struct {
	Type                  string                        `json:"type"`
	Severity              string                        `json:"severity"`
	Description           string                        `json:"description"`
	Evidence              []string                      `json:"evidence"`
	MitigationSuggestions []string                      `json:"mitigation_suggestions"`
}

// NewNovelMLIntegrator creates a new novel ML integrator
func NewNovelMLIntegrator(config *NovelIntegrationConfig, logger logger.Logger) (*NovelMLIntegrator, error) {
	integrator := &NovelMLIntegrator{
		config:             config,
		logger:             logger,
		metrics:            &IntegrationMetrics{
			AccuracyMetrics:      make(map[string]float64),
			ErrorRates:           make(map[string]float64),
			AlgorithmPerformance: make(map[string]*AlgMetrics),
		},
		performanceTracker: &PerformanceTracker{
			startTime:      time.Now(),
			errorCounts:    make(map[string]int64),
			successCounts:  make(map[string]int64),
		},
	}

	// Initialize cache manager
	if config.CachingConfig.Enabled {
		integrator.cacheManager = &CacheManager{
			cache:       make(map[string]*CacheEntry),
			config:      config.CachingConfig,
			lastCleanup: time.Now(),
		}
	}

	// Initialize novel algorithm suite
	if config.NovelAlgorithmsEnabled {
		integrator.novelSuite = NewNovelAlgorithmSuite(config.NovelAlgorithmConfig, logger)
	}

	// Initialize existing ML components
	integrator.enhancedDetector = &EnhancedMLDetector{} // Initialize with existing config
	integrator.featureExtractor = &AdvancedFeatureExtractor{} // Initialize with existing config
	integrator.enhancedAlgorithms = &EnhancedMLAlgorithms{} // Initialize with existing config

	logger.Info("Novel ML integrator initialized", "strategy", config.IntegrationStrategy)
	return integrator, nil
}

// AnalyzePackage performs integrated analysis using novel and classic algorithms
func (nmi *NovelMLIntegrator) AnalyzePackage(ctx context.Context, pkg *types.Package) (*IntegratedAnalysisResult, error) {
	startTime := time.Now()
	nmi.mu.RLock()
	defer nmi.mu.RUnlock()

	// Check cache first
	if nmi.cacheManager != nil {
		if cachedResult := nmi.getCachedResult(pkg.Name); cachedResult != nil {
			nmi.updateMetrics("cache_hit", time.Since(startTime), nil)
			return cachedResult, nil
		}
	}

	result := &IntegratedAnalysisResult{
		PackageID:    pkg.Name,
		AnalysisTime: startTime,
		Strategy:     nmi.config.IntegrationStrategy,
		PerformanceMetrics: &AnalysisPerformance{
			AlgorithmsUsed: make([]string, 0),
			ErrorsEncountered: make([]string, 0),
		},
		Metadata: make(map[string]interface{}),
	}

	var err error

	// Execute analysis based on strategy
	switch nmi.config.IntegrationStrategy {
	case "novel_only":
		err = nmi.executeNovelOnlyAnalysis(ctx, pkg, result)
	case "classic_only":
		err = nmi.executeClassicOnlyAnalysis(ctx, pkg, result)
	case "hybrid":
		err = nmi.executeHybridAnalysis(ctx, pkg, result)
	case "adaptive":
		err = nmi.executeAdaptiveAnalysis(ctx, pkg, result)
	default:
		err = nmi.executeHybridAnalysis(ctx, pkg, result) // Default to hybrid
	}

	if err != nil {
		nmi.updateMetrics("error", time.Since(startTime), err)
		return nil, fmt.Errorf("integrated analysis failed: %w", err)
	}

	// Finalize result
	nmi.finalizeResult(result)

	// Cache result if enabled
	if nmi.cacheManager != nil {
		nmi.cacheResult(pkg.Name, result)
	}

	// Update metrics
	nmi.updateMetrics("success", time.Since(startTime), nil)

	return result, nil
}

// executeNovelOnlyAnalysis runs only novel algorithms
func (nmi *NovelMLIntegrator) executeNovelOnlyAnalysis(ctx context.Context, pkg *types.Package, result *IntegratedAnalysisResult) error {
	if nmi.novelSuite == nil {
		return fmt.Errorf("novel algorithm suite not initialized")
	}

	novelStart := time.Now()
	novelResult, err := nmi.novelSuite.AnalyzePackageWithNovelAlgorithms(ctx, pkg)
	if err != nil {
		return fmt.Errorf("novel analysis failed: %w", err)
	}

	result.NovelResult = novelResult
	result.HybridScore = novelResult.EnsembleScore
	result.FinalThreatLevel = novelResult.ThreatLevel
	result.Confidence = novelResult.Confidence
	result.Recommendations = novelResult.Recommendations
	result.PerformanceMetrics.NovelLatency = time.Since(novelStart)
	result.PerformanceMetrics.AlgorithmsUsed = append(result.PerformanceMetrics.AlgorithmsUsed, "novel_suite")

	return nil
}

// executeClassicOnlyAnalysis runs only classic algorithms
func (nmi *NovelMLIntegrator) executeClassicOnlyAnalysis(ctx context.Context, pkg *types.Package, result *IntegratedAnalysisResult) error {
	classicStart := time.Now()
	
	// Extract features using existing feature extractor
	features, err := nmi.featureExtractor.ExtractFeatures(pkg)
	if err != nil {
		return fmt.Errorf("feature extraction failed: %w", err)
	}

	// Analyze using enhanced detector
	classicResult, err := nmi.enhancedDetector.AnalyzePackage(ctx, pkg, features)
	if err != nil {
		return fmt.Errorf("classic analysis failed: %w", err)
	}

	result.ClassicResult = classicResult
	result.HybridScore = classicResult.ThreatScore
	result.FinalThreatLevel = nmi.determineThreatLevel(classicResult.ThreatScore)
	result.Confidence = classicResult.Confidence
	result.PerformanceMetrics.ClassicLatency = time.Since(classicStart)
	result.PerformanceMetrics.AlgorithmsUsed = append(result.PerformanceMetrics.AlgorithmsUsed, "classic_suite")

	return nil
}

// executeHybridAnalysis runs both novel and classic algorithms
func (nmi *NovelMLIntegrator) executeHybridAnalysis(ctx context.Context, pkg *types.Package, result *IntegratedAnalysisResult) error {
	// Run novel analysis
	if nmi.novelSuite != nil {
		novelStart := time.Now()
		novelResult, err := nmi.novelSuite.AnalyzePackageWithNovelAlgorithms(ctx, pkg)
		if err != nil {
			nmi.logger.Warn("Novel analysis failed, continuing with classic", "error", err)
			result.PerformanceMetrics.ErrorsEncountered = append(result.PerformanceMetrics.ErrorsEncountered, "novel_analysis_failed")
		} else {
			result.NovelResult = novelResult
			result.PerformanceMetrics.NovelLatency = time.Since(novelStart)
			result.PerformanceMetrics.AlgorithmsUsed = append(result.PerformanceMetrics.AlgorithmsUsed, "novel_suite")
		}
	}

	// Run classic analysis
	classicStart := time.Now()
	features, err := nmi.featureExtractor.ExtractFeatures(pkg)
	if err != nil {
		return fmt.Errorf("feature extraction failed: %w", err)
	}

	classicResult, err := nmi.enhancedDetector.AnalyzePackage(ctx, pkg, features)
	if err != nil {
		return fmt.Errorf("classic analysis failed: %w", err)
	}

	result.ClassicResult = classicResult
	result.PerformanceMetrics.ClassicLatency = time.Since(classicStart)
	result.PerformanceMetrics.AlgorithmsUsed = append(result.PerformanceMetrics.AlgorithmsUsed, "classic_suite")

	// Combine results
	nmi.combineResults(result)

	return nil
}

// executeAdaptiveAnalysis dynamically chooses the best strategy
func (nmi *NovelMLIntegrator) executeAdaptiveAnalysis(ctx context.Context, pkg *types.Package, result *IntegratedAnalysisResult) error {
	// Analyze package characteristics to determine best strategy
	strategy := nmi.determineOptimalStrategy(pkg)
	result.Strategy = strategy

	switch strategy {
	case "novel_preferred":
		return nmi.executeNovelOnlyAnalysis(ctx, pkg, result)
	case "classic_preferred":
		return nmi.executeClassicOnlyAnalysis(ctx, pkg, result)
	default:
		return nmi.executeHybridAnalysis(ctx, pkg, result)
	}
}

// combineResults intelligently combines novel and classic results
func (nmi *NovelMLIntegrator) combineResults(result *IntegratedAnalysisResult) {
	novelWeight := 0.6
	classicWeight := 0.4

	// Adjust weights based on confidence
	if result.NovelResult != nil && result.ClassicResult != nil {
		novelConf := result.NovelResult.Confidence
		classicConf := result.ClassicResult.Confidence
		totalConf := novelConf + classicConf
		
		if totalConf > 0 {
			novelWeight = novelConf / totalConf
			classicWeight = classicConf / totalConf
		}

		// Compute hybrid score
		result.HybridScore = (result.NovelResult.EnsembleScore * novelWeight) + 
							(result.ClassicResult.ThreatScore * classicWeight)
		
		// Compute combined confidence
		result.Confidence = (novelConf * novelWeight) + (classicConf * classicWeight)
		
		// Combine recommendations
		result.Recommendations = nmi.combineRecommendations(
			result.NovelResult.Recommendations,
			result.ClassicResult.Recommendations,
		)
	} else if result.NovelResult != nil {
		result.HybridScore = result.NovelResult.EnsembleScore
		result.Confidence = result.NovelResult.Confidence
		result.Recommendations = result.NovelResult.Recommendations
	} else if result.ClassicResult != nil {
		result.HybridScore = result.ClassicResult.ThreatScore
		result.Confidence = result.ClassicResult.Confidence
		result.Recommendations = result.ClassicResult.Recommendations
	}

	result.FinalThreatLevel = nmi.determineThreatLevel(result.HybridScore)
}

// Helper methods
func (nmi *NovelMLIntegrator) determineThreatLevel(score float64) string {
	switch {
	case score >= 0.8:
		return "CRITICAL"
	case score >= 0.6:
		return "HIGH"
	case score >= 0.4:
		return "MEDIUM"
	case score >= 0.2:
		return "LOW"
	default:
		return "MINIMAL"
	}
}

func (nmi *NovelMLIntegrator) determineOptimalStrategy(pkg *types.Package) string {
	// Simple heuristic - can be enhanced with ML
	if len(pkg.Dependencies) > 50 {
		return "novel_preferred" // Complex packages benefit from novel algorithms
	}
	if len(pkg.Name) < 5 {
		return "classic_preferred" // Simple packages work well with classic
	}
	return "hybrid" // Default to hybrid
}

func (nmi *NovelMLIntegrator) combineRecommendations(novel, classic []string) []string {
	combined := make([]string, 0)
	seen := make(map[string]bool)

	// Add novel recommendations first
	for _, rec := range novel {
		if !seen[rec] {
			combined = append(combined, rec)
			seen[rec] = true
		}
	}

	// Add classic recommendations
	for _, rec := range classic {
		if !seen[rec] {
			combined = append(combined, rec)
			seen[rec] = true
		}
	}

	return combined
}

func (nmi *NovelMLIntegrator) finalizeResult(result *IntegratedAnalysisResult) {
	result.PerformanceMetrics.TotalLatency = time.Since(result.AnalysisTime)
	
	// Generate detailed explanation
	result.Explanation = nmi.generateDetailedExplanation(result)
	
	// Add metadata
	result.Metadata["integration_version"] = "1.0.0"
	result.Metadata["algorithms_count"] = len(result.PerformanceMetrics.AlgorithmsUsed)
	result.Metadata["has_errors"] = len(result.PerformanceMetrics.ErrorsEncountered) > 0
}

func (nmi *NovelMLIntegrator) generateDetailedExplanation(result *IntegratedAnalysisResult) *DetailedExplanation {
	explanation := &DetailedExplanation{
		Summary: fmt.Sprintf("Integrated analysis completed with %s threat level (score: %.2f, confidence: %.2f)",
			result.FinalThreatLevel, result.HybridScore, result.Confidence),
		KeyFindings:           make([]string, 0),
		AlgorithmContributions: make(map[string]string),
		RiskFactors:           make([]RiskFactor, 0),
		MitigationStrategies:  make([]string, 0),
		ConfidenceFactors:     make([]string, 0),
	}

	// Add algorithm contributions
	if result.NovelResult != nil {
		explanation.AlgorithmContributions["novel_suite"] = 
			fmt.Sprintf("Novel algorithms detected %s threat level with %.2f confidence",
				result.NovelResult.ThreatLevel, result.NovelResult.Confidence)
	}

	if result.ClassicResult != nil {
		explanation.AlgorithmContributions["classic_suite"] = 
			fmt.Sprintf("Classic algorithms detected threat score %.2f with %.2f confidence",
				result.ClassicResult.ThreatScore, result.ClassicResult.Confidence)
	}

	// Add key findings based on threat level
	if result.HybridScore >= 0.8 {
		explanation.KeyFindings = append(explanation.KeyFindings, "Critical threat detected requiring immediate action")
	} else if result.HybridScore >= 0.6 {
		explanation.KeyFindings = append(explanation.KeyFindings, "High risk package requiring careful review")
	}

	return explanation
}

// Cache management methods
func (nmi *NovelMLIntegrator) getCachedResult(packageID string) *IntegratedAnalysisResult {
	if nmi.cacheManager == nil {
		return nil
	}

	nmi.cacheManager.mu.RLock()
	defer nmi.cacheManager.mu.RUnlock()

	entry, exists := nmi.cacheManager.cache[packageID]
	if !exists {
		nmi.cacheManager.missCount++
		return nil
	}

	// Check TTL
	if time.Since(entry.Timestamp) > nmi.cacheManager.config.TTL {
		delete(nmi.cacheManager.cache, packageID)
		nmi.cacheManager.missCount++
		return nil
	}

	// Update access info
	entry.AccessCount++
	entry.LastAccess = time.Now()
	nmi.cacheManager.hitCount++

	return entry.Result
}

func (nmi *NovelMLIntegrator) cacheResult(packageID string, result *IntegratedAnalysisResult) {
	if nmi.cacheManager == nil {
		return
	}

	nmi.cacheManager.mu.Lock()
	defer nmi.cacheManager.mu.Unlock()

	// Create cache entry
	entry := &CacheEntry{
		Result:      result,
		Timestamp:   time.Now(),
		AccessCount: 1,
		LastAccess:  time.Now(),
		Size:        nmi.estimateResultSize(result),
	}

	nmi.cacheManager.cache[packageID] = entry

	// Cleanup if needed
	if len(nmi.cacheManager.cache) > nmi.cacheManager.config.MaxSize {
		nmi.cleanupCache()
	}
}

func (nmi *NovelMLIntegrator) estimateResultSize(result *IntegratedAnalysisResult) int64 {
	// Simple size estimation - can be enhanced
	baseSize := int64(1024) // Base size
	if result.NovelResult != nil {
		baseSize += int64(len(result.NovelResult.Algorithms) * 512)
	}
	if result.ClassicResult != nil {
		baseSize += int64(512)
	}
	return baseSize
}

func (nmi *NovelMLIntegrator) cleanupCache() {
	// Simple LRU cleanup
	oldestTime := time.Now()
	oldestKey := ""

	for key, entry := range nmi.cacheManager.cache {
		if entry.LastAccess.Before(oldestTime) {
			oldestTime = entry.LastAccess
			oldestKey = key
		}
	}

	if oldestKey != "" {
		delete(nmi.cacheManager.cache, oldestKey)
	}
}

// Metrics and monitoring methods
func (nmi *NovelMLIntegrator) updateMetrics(operation string, latency time.Duration, err error) {
	nmi.metrics.mu.Lock()
	defer nmi.metrics.mu.Unlock()

	nmi.metrics.TotalAnalyses++

	if err != nil {
		nmi.performanceTracker.errorCounts[operation]++
	} else {
		nmi.performanceTracker.successCounts[operation]++
	}

	// Update latency
	nmi.performanceTracker.executionTimes = append(nmi.performanceTracker.executionTimes, latency)
	if len(nmi.performanceTracker.executionTimes) > 1000 {
		// Keep only recent measurements
		nmi.performanceTracker.executionTimes = nmi.performanceTracker.executionTimes[500:]
	}

	// Calculate average latency
	totalLatency := time.Duration(0)
	for _, lat := range nmi.performanceTracker.executionTimes {
		totalLatency += lat
	}
	nmi.metrics.AverageLatency = totalLatency / time.Duration(len(nmi.performanceTracker.executionTimes))

	// Update cache hit rate
	if nmi.cacheManager != nil {
		totalRequests := nmi.cacheManager.hitCount + nmi.cacheManager.missCount
		if totalRequests > 0 {
			nmi.metrics.CacheHitRate = float64(nmi.cacheManager.hitCount) / float64(totalRequests)
		}
	}
}

// GetMetrics returns current integration metrics
func (nmi *NovelMLIntegrator) GetMetrics() *IntegrationMetrics {
	nmi.metrics.mu.RLock()
	defer nmi.metrics.mu.RUnlock()

	// Create a copy to avoid race conditions
	metricsCopy := *nmi.metrics
	return &metricsCopy
}

// Shutdown gracefully shuts down the integrator
func (nmi *NovelMLIntegrator) Shutdown(ctx context.Context) error {
	nmi.mu.Lock()
	defer nmi.mu.Unlock()

	nmi.logger.Info("Shutting down novel ML integrator")

	// Shutdown novel algorithm suite
	if nmi.novelSuite != nil {
		if err := nmi.novelSuite.Shutdown(ctx); err != nil {
			nmi.logger.Error("Failed to shutdown novel algorithm suite", "error", err)
		}
	}

	// Clear cache
	if nmi.cacheManager != nil {
		nmi.cacheManager.mu.Lock()
		nmi.cacheManager.cache = make(map[string]*CacheEntry)
		nmi.cacheManager.mu.Unlock()
	}

	nmi.logger.Info("Novel ML integrator shutdown complete")
	return nil
}