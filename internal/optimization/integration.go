package optimization

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/database"
	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// OptimizationManager provides a unified interface for all optimization features
type OptimizationManager struct {
	performanceOptimizer *PerformanceOptimizer
	config               *PerformanceConfig
	db                   *database.ThreatDB
	running              bool
	ctx                  context.Context
	cancel               context.CancelFunc
	mu                   sync.RWMutex
}

// OptimizationStats provides comprehensive optimization statistics
type OptimizationStats struct {
	Database    *DatabaseStats    `json:"database"`
	Cache       *CacheStats       `json:"cache"`
	Performance *PerformanceStats `json:"performance"`
	Resource    *ResourceStats    `json:"resource"`
	Overall     *OverallStats     `json:"overall"`
	Timestamp   time.Time         `json:"timestamp"`
}

// DatabaseStats contains database optimization statistics
type DatabaseStats struct {
	QueryCount       int64         `json:"query_count"`
	SlowQueries      int64         `json:"slow_queries"`
	CacheHitRatio    float64       `json:"cache_hit_ratio"`
	AvgQueryTime     time.Duration `json:"avg_query_time"`
	BatchEfficiency  float64       `json:"batch_efficiency"`
	OptimizedQueries int64         `json:"optimized_queries"`
}

// CacheStats contains cache performance statistics
type CacheStats struct {
	L1HitRatio    float64 `json:"l1_hit_ratio"`
	L2HitRatio    float64 `json:"l2_hit_ratio"`
	L3HitRatio    float64 `json:"l3_hit_ratio"`
	OverallHitRatio float64 `json:"overall_hit_ratio"`
	MemoryUsage   int64   `json:"memory_usage"`
	EntryCount    int64   `json:"entry_count"`
	Evictions     int64   `json:"evictions"`
}

// PerformanceStats contains performance optimization statistics
type PerformanceStats struct {
	Throughput       float64       `json:"throughput"`
	Latency          time.Duration `json:"latency"`
	ErrorRate        float64       `json:"error_rate"`
	ConcurrentTasks  int           `json:"concurrent_tasks"`
	CompletedTasks   int64         `json:"completed_tasks"`
	OptimizationScore float64      `json:"optimization_score"`
}

// ResourceStats contains resource usage statistics
type ResourceStats struct {
	CPUUsage       float64 `json:"cpu_usage"`
	MemoryUsage    int64   `json:"memory_usage"`
	GoroutineCount int     `json:"goroutine_count"`
	GCPauses       int64   `json:"gc_pauses"`
	HeapSize       uint64  `json:"heap_size"`
}

// OverallStats contains overall optimization statistics
type OverallStats struct {
	EfficiencyScore   float64 `json:"efficiency_score"`
	OptimizationLevel string  `json:"optimization_level"`
	Recommendations   int     `json:"recommendations"`
	ActiveAlerts      int     `json:"active_alerts"`
	Uptime            time.Duration `json:"uptime"`
}

// OptimizationReport provides detailed optimization analysis
type OptimizationReport struct {
	Stats           *OptimizationStats        `json:"stats"`
	Recommendations []*OptimizationRecommendation `json:"recommendations"`
	Alerts          []*OptimizationAlert      `json:"alerts"`
	Bottlenecks     []*PerformanceBottleneck  `json:"bottlenecks"`
	Improvements    []*OptimizationImprovement `json:"improvements"`
	GeneratedAt     time.Time                 `json:"generated_at"`
}

// OptimizationRecommendation provides specific optimization suggestions
type OptimizationRecommendation struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Priority    string    `json:"priority"`
	Impact      string    `json:"impact"`
	Complexity  string    `json:"complexity"`
	Action      string    `json:"action"`
	Created     time.Time `json:"created"`
}

// OptimizationAlert represents performance alerts
type OptimizationAlert struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"`
	Severity  string    `json:"severity"`
	Message   string    `json:"message"`
	Value     float64   `json:"value"`
	Threshold float64   `json:"threshold"`
	Triggered time.Time `json:"triggered"`
	Resolved  bool      `json:"resolved"`
}

// PerformanceBottleneck identifies performance bottlenecks
type PerformanceBottleneck struct {
	ID          string    `json:"id"`
	Component   string    `json:"component"`
	Description string    `json:"description"`
	Impact      string    `json:"impact"`
	Suggestion  string    `json:"suggestion"`
	Detected    time.Time `json:"detected"`
}

// OptimizationImprovement tracks applied optimizations
type OptimizationImprovement struct {
	ID               string        `json:"id"`
	Type             string        `json:"type"`
	Description      string        `json:"description"`
	Applied          time.Time     `json:"applied"`
	LatencyGain      time.Duration `json:"latency_gain"`
	ThroughputGain   float64       `json:"throughput_gain"`
	MemoryReduction  int64         `json:"memory_reduction"`
	EfficiencyGain   float64       `json:"efficiency_gain"`
}

// NewOptimizationManager creates a new optimization manager
func NewOptimizationManager(db *database.ThreatDB, environment string) (*OptimizationManager, error) {
	// Get configuration based on environment
	config := ConfigFromEnvironment(environment)

	// Validate configuration
	if err := ValidateConfig(config); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	// Optimize configuration for current system
	config = GetRecommendedConfig()

	// Create performance optimizer
	performanceOptimizer := NewPerformanceOptimizer(config, db)

	ctx, cancel := context.WithCancel(context.Background())

	manager := &OptimizationManager{
		performanceOptimizer: performanceOptimizer,
		config:               config,
		db:                   db,
		running:              false,
		ctx:                  ctx,
		cancel:               cancel,
	}

	return manager, nil
}

// Start begins the optimization processes
func (om *OptimizationManager) Start() error {
	om.mu.Lock()
	defer om.mu.Unlock()

	if om.running {
		return fmt.Errorf("optimization manager is already running")
	}

	om.running = true
	log.Println("Starting optimization manager...")

	// Start background monitoring and reporting
	go om.startReporting()

	log.Println("Optimization manager started successfully")
	return nil
}

// Stop gracefully stops the optimization processes
func (om *OptimizationManager) Stop() error {
	om.mu.Lock()
	defer om.mu.Unlock()

	if !om.running {
		return fmt.Errorf("optimization manager is not running")
	}

	log.Println("Stopping optimization manager...")

	// Cancel context to stop background processes
	om.cancel()

	// Shutdown performance optimizer
	if err := om.performanceOptimizer.Shutdown(); err != nil {
		log.Printf("Error shutting down performance optimizer: %v", err)
	}

	om.running = false
	log.Println("Optimization manager stopped successfully")
	return nil
}

// OptimizedThreatLookup performs an optimized threat lookup
func (om *OptimizationManager) OptimizedThreatLookup(packageName, registry string) (*database.ThreatRecord, error) {
	if !om.running {
		return nil, fmt.Errorf("optimization manager is not running")
	}

	return om.performanceOptimizer.OptimizedThreatLookup(packageName, registry)
}

// BatchOptimizedThreatLookup performs batch optimized threat lookups
func (om *OptimizationManager) BatchOptimizedThreatLookup(packages []types.Package) ([]*database.ThreatRecord, error) {
	if !om.running {
		return nil, fmt.Errorf("optimization manager is not running")
	}

	return om.performanceOptimizer.BatchThreatLookup(packages)
}

// GetOptimizationStats returns current optimization statistics
func (om *OptimizationManager) GetOptimizationStats() *OptimizationStats {
	if !om.running {
		return nil
	}

	// Gather metrics from all components
	performanceMetrics := om.performanceOptimizer.GetPerformanceMetrics()

	stats := &OptimizationStats{
		Database: &DatabaseStats{
			CacheHitRatio:    0.0, // Would need to get from database optimizer
			AvgQueryTime:     0,   // Would need to get from database optimizer
			BatchEfficiency:  0.0, // Would need to get from database optimizer
			OptimizedQueries: 0,   // Would need to get from database optimizer
		},
		Cache: &CacheStats{
			L1HitRatio:      func() float64 { if performanceMetrics.Cache != nil && performanceMetrics.Cache.L1Metrics != nil { return performanceMetrics.Cache.L1Metrics.HitRatio }; return 0.0 }(),
			L2HitRatio:      func() float64 { if performanceMetrics.Cache != nil && performanceMetrics.Cache.L2Metrics != nil { return performanceMetrics.Cache.L2Metrics.HitRatio }; return 0.0 }(),
			OverallHitRatio: func() float64 { if performanceMetrics.Cache != nil && performanceMetrics.Cache.Overall != nil { return performanceMetrics.Cache.Overall.OverallHitRatio }; return 0.0 }(),
			MemoryUsage:     0, // Would need to get from cache manager
			EntryCount:      0, // Would need to get from cache manager
			Evictions:       0, // Would need to get from cache manager
		},
		Performance: &PerformanceStats{
			Throughput:        performanceMetrics.Overall.Throughput,
			Latency:           performanceMetrics.Overall.Latency,
			ErrorRate:         performanceMetrics.Overall.ErrorRate,
			ConcurrentTasks:   performanceMetrics.Concurrency.ActiveWorkers,
			CompletedTasks:    performanceMetrics.Concurrency.CompletedTasks,
			OptimizationScore: performanceMetrics.Overall.OptimizationScore,
		},
		Resource: &ResourceStats{
			CPUUsage:       performanceMetrics.Resource.CPUUsage,
			MemoryUsage:    performanceMetrics.Resource.MemoryUsage,
			GoroutineCount: performanceMetrics.Resource.GoroutineCount,
			HeapSize:       uint64(performanceMetrics.Resource.MemoryUsage),
		},
		Overall: &OverallStats{
			EfficiencyScore:   performanceMetrics.Overall.Efficiency,
			OptimizationLevel: om.getOptimizationLevel(performanceMetrics.Overall.OptimizationScore),
			Recommendations:   len(om.performanceOptimizer.GetOptimizationSuggestions()),
			ActiveAlerts:      len(om.performanceOptimizer.GetResourceAlerts()),
		},
		Timestamp: time.Now(),
	}

	return stats
}

// GenerateOptimizationReport creates a comprehensive optimization report
func (om *OptimizationManager) GenerateOptimizationReport() *OptimizationReport {
	if !om.running {
		return nil
	}

	stats := om.GetOptimizationStats()
	recommendations := om.getRecommendations()
	alerts := om.getAlerts()
	bottlenecks := om.getBottlenecks()
	improvements := om.getImprovements()

	return &OptimizationReport{
		Stats:           stats,
		Recommendations: recommendations,
		Alerts:          alerts,
		Bottlenecks:     bottlenecks,
		Improvements:    improvements,
		GeneratedAt:     time.Now(),
	}
}

// ApplyOptimizationRecommendation applies a specific optimization recommendation
func (om *OptimizationManager) ApplyOptimizationRecommendation(recommendationID string) error {
	if !om.running {
		return fmt.Errorf("optimization manager is not running")
	}

	// Implementation would apply specific optimizations based on recommendation ID
	log.Printf("Applying optimization recommendation: %s", recommendationID)
	return nil
}

// GetConfiguration returns the current optimization configuration
func (om *OptimizationManager) GetConfiguration() *PerformanceConfig {
	om.mu.RLock()
	defer om.mu.RUnlock()
	return om.config
}

// UpdateConfiguration updates the optimization configuration
func (om *OptimizationManager) UpdateConfiguration(config *PerformanceConfig) error {
	if err := ValidateConfig(config); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	om.mu.Lock()
	om.config = config
	om.mu.Unlock()

	log.Println("Optimization configuration updated")
	return nil
}

// IsRunning returns whether the optimization manager is currently running
func (om *OptimizationManager) IsRunning() bool {
	om.mu.RLock()
	defer om.mu.RUnlock()
	return om.running
}

// Helper methods

func (om *OptimizationManager) startReporting() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			om.logOptimizationStatus()
		case <-om.ctx.Done():
			return
		}
	}
}

func (om *OptimizationManager) logOptimizationStatus() {
	stats := om.GetOptimizationStats()
	if stats == nil {
		return
	}

	log.Printf("Optimization Status - Cache Hit Ratio: %.2f%%, Avg Query Time: %v, Memory Usage: %d MB, Goroutines: %d",
		stats.Cache.OverallHitRatio*100,
		stats.Database.AvgQueryTime,
		stats.Resource.MemoryUsage/(1024*1024),
		stats.Resource.GoroutineCount)
}

func (om *OptimizationManager) getOptimizationLevel(score float64) string {
	switch {
	case score >= 0.9:
		return "Excellent"
	case score >= 0.8:
		return "Good"
	case score >= 0.7:
		return "Fair"
	case score >= 0.6:
		return "Poor"
	default:
		return "Critical"
	}
}

func (om *OptimizationManager) getRecommendations() []*OptimizationRecommendation {
	suggestions := om.performanceOptimizer.GetOptimizationSuggestions()
	recommendations := make([]*OptimizationRecommendation, len(suggestions))

	for i, suggestion := range suggestions {
		recommendations[i] = &OptimizationRecommendation{
			ID:          fmt.Sprintf("rec_%d", i),
			Type:        suggestion.Type,
			Title:       suggestion.Type,
			Description: suggestion.Description,
			Priority:    om.getPriorityString(suggestion.Priority),
			Impact:      suggestion.ExpectedGain,
			Complexity:  suggestion.Complexity,
			Action:      "Apply optimization",
			Created:     suggestion.Created,
		}
	}

	return recommendations
}

func (om *OptimizationManager) getAlerts() []*OptimizationAlert {
	resourceAlerts := om.performanceOptimizer.GetResourceAlerts()
	alerts := make([]*OptimizationAlert, len(resourceAlerts))

	for i, alert := range resourceAlerts {
		alerts[i] = &OptimizationAlert{
			ID:        fmt.Sprintf("alert_%d", i),
			Type:      alert.Type,
			Severity:  alert.Severity,
			Message:   alert.Message,
			Triggered: alert.Timestamp,
			Resolved:  alert.Resolved,
		}
	}

	return alerts
}

func (om *OptimizationManager) getBottlenecks() []*PerformanceBottleneck {
	bottlenecks := om.performanceOptimizer.GetBottlenecks()
	result := make([]*PerformanceBottleneck, len(bottlenecks))

	for i, bottleneck := range bottlenecks {
		result[i] = &PerformanceBottleneck{
			ID:          fmt.Sprintf("bottleneck_%d", i),
			Component:   bottleneck.Location,
			Description: bottleneck.Description,
			Impact:      bottleneck.Impact,
			Suggestion:  "Optimize this component",
			Detected:    bottleneck.Detected,
		}
	}

	return result
}

func (om *OptimizationManager) getImprovements() []*OptimizationImprovement {
	// This would track actual improvements made
	// For now, return empty slice
	return []*OptimizationImprovement{}
}

func (om *OptimizationManager) getPriorityString(priority int) string {
	switch {
	case priority >= 8:
		return "Critical"
	case priority >= 6:
		return "High"
	case priority >= 4:
		return "Medium"
	default:
		return "Low"
	}
}

// Convenience functions for easy integration

// QuickOptimizationSetup sets up optimization with sensible defaults
func QuickOptimizationSetup(db *database.ThreatDB) (*OptimizationManager, error) {
	return NewOptimizationManager(db, "production")
}

// DevelopmentOptimizationSetup sets up optimization for development
func DevelopmentOptimizationSetup(db *database.ThreatDB) (*OptimizationManager, error) {
	return NewOptimizationManager(db, "development")
}

// TestOptimizationSetup sets up optimization for testing
func TestOptimizationSetup(db *database.ThreatDB) (*OptimizationManager, error) {
	return NewOptimizationManager(db, "test")
}

// OptimizationHealthCheck performs a health check on optimization components
func (om *OptimizationManager) OptimizationHealthCheck() map[string]string {
	health := make(map[string]string)

	if !om.running {
		health["status"] = "stopped"
		return health
	}

	stats := om.GetOptimizationStats()
	if stats == nil {
		health["status"] = "unhealthy"
		health["reason"] = "unable to get stats"
		return health
	}

	health["status"] = "healthy"
	health["cache_hit_ratio"] = fmt.Sprintf("%.2f%%", stats.Cache.OverallHitRatio*100)
	health["memory_usage"] = fmt.Sprintf("%d MB", stats.Resource.MemoryUsage/(1024*1024))
	health["optimization_level"] = stats.Overall.OptimizationLevel
	health["active_alerts"] = fmt.Sprintf("%d", stats.Overall.ActiveAlerts)

	return health
}