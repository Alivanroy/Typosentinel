package orchestrator

import (
	"context"
	"fmt"
	"log"
	"runtime"
	"runtime/debug"
	"sync"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/repository"
)

// PerformanceOptimizer handles performance optimization for repository scanning
type PerformanceOptimizer struct {
	config  PerformanceConfig
	logger  *log.Logger
	metrics *PerformanceMetrics
	mu      sync.RWMutex
}

// PerformanceConfig holds performance optimization settings
type PerformanceConfig struct {
	MaxConcurrentScans int           `json:"max_concurrent_scans"`
	MaxConcurrentRepos int           `json:"max_concurrent_repos"`
	ScanTimeout        time.Duration `json:"scan_timeout"`
	MemoryLimit        int64         `json:"memory_limit"` // in bytes
	CPULimit           float64       `json:"cpu_limit"`    // percentage (0-100)
	CacheEnabled       bool          `json:"cache_enabled"`
	CacheTTL           time.Duration `json:"cache_ttl"`
	BatchSize          int           `json:"batch_size"`
	RetryAttempts      int           `json:"retry_attempts"`
	RetryDelay         time.Duration `json:"retry_delay"`
	AdaptiveScaling    bool          `json:"adaptive_scaling"`
	ResourceMonitoring bool          `json:"resource_monitoring"`
	GCOptimization     bool          `json:"gc_optimization"`
	ConnectionPoolSize int           `json:"connection_pool_size"`
	RequestQueueSize   int           `json:"request_queue_size"`
	CompressionEnabled bool          `json:"compression_enabled"`
	PrefetchEnabled    bool          `json:"prefetch_enabled"`
}

// PerformanceMetrics tracks performance statistics
type PerformanceMetrics struct {
	TotalScans          int64         `json:"total_scans"`
	SuccessfulScans     int64         `json:"successful_scans"`
	FailedScans         int64         `json:"failed_scans"`
	AverageScanDuration time.Duration `json:"average_scan_duration"`
	TotalScanDuration   time.Duration `json:"total_scan_duration"`
	PeakMemoryUsage     int64         `json:"peak_memory_usage"`
	AverageMemoryUsage  int64         `json:"average_memory_usage"`
	PeakCPUUsage        float64       `json:"peak_cpu_usage"`
	AverageCPUUsage     float64       `json:"average_cpu_usage"`
	CacheHitRate        float64       `json:"cache_hit_rate"`
	CacheMissRate       float64       `json:"cache_miss_rate"`
	ThroughputPerSecond float64       `json:"throughput_per_second"`
	ErrorRate           float64       `json:"error_rate"`
	RetryRate           float64       `json:"retry_rate"`
	QueueLength         int           `json:"queue_length"`
	ActiveConnections   int           `json:"active_connections"`
	LastUpdated         time.Time     `json:"last_updated"`
	mu                  sync.RWMutex
}

// ScanBatch represents a batch of repositories to scan
type ScanBatch struct {
	ID           string                   `json:"id"`
	Repositories []*repository.Repository `json:"repositories"`
	Priority     int                      `json:"priority"`
	CreatedAt    time.Time                `json:"created_at"`
	StartedAt    *time.Time               `json:"started_at,omitempty"`
	CompletedAt  *time.Time               `json:"completed_at,omitempty"`
	Status       string                   `json:"status"`
	Results      []*repository.ScanResult `json:"results"`
	Errors       []error                  `json:"errors"`
}

// ResourceMonitor tracks system resource usage
type ResourceMonitor struct {
	memStats   runtime.MemStats
	cpuUsage   float64
	goroutines int
	lastUpdate time.Time
	mu         sync.RWMutex
}

// NewPerformanceOptimizer creates a new performance optimizer
func NewPerformanceOptimizer(config PerformanceConfig, logger *log.Logger) *PerformanceOptimizer {
	if logger == nil {
		logger = log.New(log.Writer(), "[PerformanceOptimizer] ", log.LstdFlags)
	}

	optimizer := &PerformanceOptimizer{
		config:  config,
		logger:  logger,
		metrics: &PerformanceMetrics{LastUpdated: time.Now()},
	}

	// Start resource monitoring if enabled
	if config.ResourceMonitoring {
		go optimizer.startResourceMonitoring()
	}

	// Configure GC optimization if enabled
	if config.GCOptimization {
		optimizer.optimizeGC()
	}

	return optimizer
}

// OptimizeScanBatch optimizes a batch of repository scans
func (po *PerformanceOptimizer) OptimizeScanBatch(ctx context.Context, repos []*repository.Repository) ([]*ScanBatch, error) {
	po.mu.Lock()
	defer po.mu.Unlock()

	// Create batches based on configuration
	batches := po.createOptimalBatches(repos)

	// Sort batches by priority
	batches = po.prioritizeBatches(batches)

	// Apply resource-based optimization
	if po.config.AdaptiveScaling {
		batches = po.adaptBatchSizes(batches)
	}

	po.logger.Printf("Optimized %d repositories into %d batches", len(repos), len(batches))
	return batches, nil
}

// createOptimalBatches creates optimally sized batches
func (po *PerformanceOptimizer) createOptimalBatches(repos []*repository.Repository) []*ScanBatch {
	batchSize := po.config.BatchSize
	if batchSize <= 0 {
		batchSize = 10 // Default batch size
	}

	var batches []*ScanBatch
	for i := 0; i < len(repos); i += batchSize {
		end := i + batchSize
		if end > len(repos) {
			end = len(repos)
		}

		batch := &ScanBatch{
			ID:           fmt.Sprintf("batch_%d_%d", time.Now().Unix(), i/batchSize),
			Repositories: repos[i:end],
			Priority:     po.calculateBatchPriority(repos[i:end]),
			CreatedAt:    time.Now(),
			Status:       "pending",
			Results:      make([]*repository.ScanResult, 0),
			Errors:       make([]error, 0),
		}
		batches = append(batches, batch)
	}

	return batches
}

// calculateBatchPriority calculates priority for a batch based on repository characteristics
func (po *PerformanceOptimizer) calculateBatchPriority(repos []*repository.Repository) int {
	priority := 0
	for _, repo := range repos {
		// Higher priority for popular repositories
		priority += repo.StarCount / 100
		// Higher priority for recently updated repositories
		if time.Since(repo.UpdatedAt) < 24*time.Hour {
			priority += 10
		}
		// Higher priority for non-archived repositories
		if !repo.Archived {
			priority += 5
		}
	}
	return priority / len(repos) // Average priority
}

// prioritizeBatches sorts batches by priority
func (po *PerformanceOptimizer) prioritizeBatches(batches []*ScanBatch) []*ScanBatch {
	// Simple bubble sort by priority (descending)
	for i := 0; i < len(batches)-1; i++ {
		for j := 0; j < len(batches)-i-1; j++ {
			if batches[j].Priority < batches[j+1].Priority {
				batches[j], batches[j+1] = batches[j+1], batches[j]
			}
		}
	}
	return batches
}

// adaptBatchSizes adapts batch sizes based on current resource usage
func (po *PerformanceOptimizer) adaptBatchSizes(batches []*ScanBatch) []*ScanBatch {
	memUsage := po.getCurrentMemoryUsage()
	cpuUsage := po.getCurrentCPUUsage()

	// If resource usage is high, split large batches
	if memUsage > 80.0 || cpuUsage > 80.0 {
		return po.splitLargeBatches(batches)
	}

	// If resource usage is low, merge small batches
	if memUsage < 30.0 && cpuUsage < 30.0 {
		return po.mergeSmallBatches(batches)
	}

	return batches
}

// splitLargeBatches splits large batches when resources are constrained
func (po *PerformanceOptimizer) splitLargeBatches(batches []*ScanBatch) []*ScanBatch {
	var optimizedBatches []*ScanBatch
	maxBatchSize := po.config.BatchSize / 2
	if maxBatchSize < 1 {
		maxBatchSize = 1
	}

	for _, batch := range batches {
		if len(batch.Repositories) > maxBatchSize {
			// Split the batch
			for i := 0; i < len(batch.Repositories); i += maxBatchSize {
				end := i + maxBatchSize
				if end > len(batch.Repositories) {
					end = len(batch.Repositories)
				}

				newBatch := &ScanBatch{
					ID:           fmt.Sprintf("%s_split_%d", batch.ID, i/maxBatchSize),
					Repositories: batch.Repositories[i:end],
					Priority:     batch.Priority,
					CreatedAt:    batch.CreatedAt,
					Status:       batch.Status,
					Results:      make([]*repository.ScanResult, 0),
					Errors:       make([]error, 0),
				}
				optimizedBatches = append(optimizedBatches, newBatch)
			}
		} else {
			optimizedBatches = append(optimizedBatches, batch)
		}
	}

	return optimizedBatches
}

// mergeSmallBatches merges small batches when resources are available
func (po *PerformanceOptimizer) mergeSmallBatches(batches []*ScanBatch) []*ScanBatch {
	var optimizedBatches []*ScanBatch
	maxBatchSize := po.config.BatchSize * 2
	currentBatch := &ScanBatch{
		ID:           fmt.Sprintf("merged_%d", time.Now().Unix()),
		Repositories: make([]*repository.Repository, 0),
		CreatedAt:    time.Now(),
		Status:       "pending",
		Results:      make([]*repository.ScanResult, 0),
		Errors:       make([]error, 0),
	}

	for _, batch := range batches {
		if len(currentBatch.Repositories)+len(batch.Repositories) <= maxBatchSize {
			// Merge into current batch
			currentBatch.Repositories = append(currentBatch.Repositories, batch.Repositories...)
			if batch.Priority > currentBatch.Priority {
				currentBatch.Priority = batch.Priority
			}
		} else {
			// Start new batch
			if len(currentBatch.Repositories) > 0 {
				optimizedBatches = append(optimizedBatches, currentBatch)
			}
			currentBatch = &ScanBatch{
				ID:           fmt.Sprintf("merged_%d_%d", time.Now().Unix(), len(optimizedBatches)),
				Repositories: batch.Repositories,
				Priority:     batch.Priority,
				CreatedAt:    time.Now(),
				Status:       "pending",
				Results:      make([]*repository.ScanResult, 0),
				Errors:       make([]error, 0),
			}
		}
	}

	// Add the last batch if it has repositories
	if len(currentBatch.Repositories) > 0 {
		optimizedBatches = append(optimizedBatches, currentBatch)
	}

	return optimizedBatches
}

// RecordScanMetrics records metrics for a completed scan
func (po *PerformanceOptimizer) RecordScanMetrics(duration time.Duration, success bool, memoryUsed int64) {
	po.metrics.mu.Lock()
	defer po.metrics.mu.Unlock()

	po.metrics.TotalScans++
	if success {
		po.metrics.SuccessfulScans++
	} else {
		po.metrics.FailedScans++
	}

	// Update duration metrics
	po.metrics.TotalScanDuration += duration
	po.metrics.AverageScanDuration = po.metrics.TotalScanDuration / time.Duration(po.metrics.TotalScans)

	// Update memory metrics
	if memoryUsed > po.metrics.PeakMemoryUsage {
		po.metrics.PeakMemoryUsage = memoryUsed
	}
	po.metrics.AverageMemoryUsage = (po.metrics.AverageMemoryUsage + memoryUsed) / 2

	// Update error rate
	po.metrics.ErrorRate = float64(po.metrics.FailedScans) / float64(po.metrics.TotalScans) * 100

	// Update throughput
	elapsedTime := time.Since(po.metrics.LastUpdated)
	if elapsedTime > 0 {
		po.metrics.ThroughputPerSecond = float64(po.metrics.TotalScans) / elapsedTime.Seconds()
	}

	po.metrics.LastUpdated = time.Now()
}

// GetMetrics returns current performance metrics
func (po *PerformanceOptimizer) GetMetrics() *PerformanceMetrics {
	po.metrics.mu.RLock()
	defer po.metrics.mu.RUnlock()

	// Create a copy to avoid race conditions without copying the mutex
	metricsCopy := &PerformanceMetrics{
		TotalScans:          po.metrics.TotalScans,
		SuccessfulScans:     po.metrics.SuccessfulScans,
		FailedScans:         po.metrics.FailedScans,
		AverageScanDuration: po.metrics.AverageScanDuration,
		TotalScanDuration:   po.metrics.TotalScanDuration,
		PeakMemoryUsage:     po.metrics.PeakMemoryUsage,
		AverageMemoryUsage:  po.metrics.AverageMemoryUsage,
		PeakCPUUsage:        po.metrics.PeakCPUUsage,
		AverageCPUUsage:     po.metrics.AverageCPUUsage,
		CacheHitRate:        po.metrics.CacheHitRate,
		CacheMissRate:       po.metrics.CacheMissRate,
		ThroughputPerSecond: po.metrics.ThroughputPerSecond,
		ErrorRate:           po.metrics.ErrorRate,
		RetryRate:           po.metrics.RetryRate,
		QueueLength:         po.metrics.QueueLength,
		ActiveConnections:   po.metrics.ActiveConnections,
		LastUpdated:         po.metrics.LastUpdated,
	}
	return metricsCopy
}

// getCurrentMemoryUsage returns current memory usage percentage
func (po *PerformanceOptimizer) getCurrentMemoryUsage() float64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	if po.config.MemoryLimit > 0 {
		return float64(m.Alloc) / float64(po.config.MemoryLimit) * 100
	}
	return float64(m.Alloc) / float64(m.Sys) * 100
}

// getCurrentCPUUsage returns current CPU usage percentage
func (po *PerformanceOptimizer) getCurrentCPUUsage() float64 {
	// This is a simplified CPU usage calculation
	// In a real implementation, you would use more sophisticated CPU monitoring
	return float64(runtime.NumGoroutine()) / float64(runtime.NumCPU()) * 10
}

// startResourceMonitoring starts background resource monitoring
func (po *PerformanceOptimizer) startResourceMonitoring() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			po.updateResourceMetrics()
		}
	}
}

// updateResourceMetrics updates resource usage metrics
func (po *PerformanceOptimizer) updateResourceMetrics() {
	po.metrics.mu.Lock()
	defer po.metrics.mu.Unlock()

	memUsage := po.getCurrentMemoryUsage()
	cpuUsage := po.getCurrentCPUUsage()

	if int64(memUsage) > po.metrics.PeakMemoryUsage {
		po.metrics.PeakMemoryUsage = int64(memUsage)
	}
	po.metrics.AverageMemoryUsage = int64((float64(po.metrics.AverageMemoryUsage) + memUsage) / 2)

	if cpuUsage > po.metrics.PeakCPUUsage {
		po.metrics.PeakCPUUsage = cpuUsage
	}
	po.metrics.AverageCPUUsage = (po.metrics.AverageCPUUsage + cpuUsage) / 2

	po.metrics.LastUpdated = time.Now()
}

// optimizeGC configures garbage collection for better performance
func (po *PerformanceOptimizer) optimizeGC() {
	// Set GC target percentage based on memory limit
	if po.config.MemoryLimit > 0 {
		// More aggressive GC for limited memory
		debug.SetGCPercent(50)
		po.logger.Printf("GC optimization enabled with target percentage: 50")
	} else {
		// Less aggressive GC for unlimited memory
		debug.SetGCPercent(100)
		po.logger.Printf("GC optimization enabled with target percentage: 100")
	}
}

// ShouldThrottle determines if scanning should be throttled based on current resource usage
func (po *PerformanceOptimizer) ShouldThrottle() bool {
	memUsage := po.getCurrentMemoryUsage()
	cpuUsage := po.getCurrentCPUUsage()

	return memUsage > 90.0 || cpuUsage > 90.0
}

// GetOptimalConcurrency returns the optimal number of concurrent scans based on current resources
func (po *PerformanceOptimizer) GetOptimalConcurrency() int {
	memUsage := po.getCurrentMemoryUsage()
	cpuUsage := po.getCurrentCPUUsage()

	maxConcurrency := po.config.MaxConcurrentScans
	if maxConcurrency <= 0 {
		maxConcurrency = runtime.NumCPU()
	}

	// Reduce concurrency based on resource usage
	if memUsage > 80.0 || cpuUsage > 80.0 {
		return maxConcurrency / 2
	}
	if memUsage > 60.0 || cpuUsage > 60.0 {
		return maxConcurrency * 3 / 4
	}

	return maxConcurrency
}
