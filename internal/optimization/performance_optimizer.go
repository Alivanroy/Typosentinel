package optimization

import (
	"fmt"
	"log"
	"runtime"
	"sync"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/database"
	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// PerformanceOptimizer provides comprehensive performance optimization
type PerformanceOptimizer struct {
	dbOptimizer    *DatabaseOptimizer
	cacheManager   *CacheManager
	resourceMonitor *ResourceMonitor
	concurrencyManager *ConcurrencyManager
	performanceProfiler *PerformanceProfiler
	optimizationEngine *OptimizationEngine
	config         *PerformanceConfig
	metrics        *PerformanceMetrics
	mu             sync.RWMutex
}

// ResourceMonitor tracks system resource usage
type ResourceMonitor struct {
	cpuUsage      float64
	memoryUsage   int64
	goroutineCount int
	gcStats       *GCStats
	thresholds    *ResourceThresholds
	alerts        []*ResourceAlert
	mu            sync.RWMutex
}

// GCStats tracks garbage collection statistics
type GCStats struct {
	NumGC        uint32
	PauseTotal   time.Duration
	LastGC       time.Time
	HeapSize     uint64
	HeapInUse    uint64
	StackInUse   uint64
	NextGC       uint64
}

// ResourceThresholds defines resource usage thresholds
type ResourceThresholds struct {
	MaxCPUUsage      float64
	MaxMemoryUsage   int64
	MaxGoroutines    int
	MaxGCPause       time.Duration
	MaxHeapSize      uint64
}

// ResourceAlert represents a resource usage alert
type ResourceAlert struct {
	Type        string
	Message     string
	Severity    string
	Timestamp   time.Time
	Value       interface{}
	Threshold   interface{}
	Resolved    bool
}

// ConcurrencyManager optimizes concurrent operations
type ConcurrencyManager struct {
	maxWorkers     int
	workerPools    map[string]*WorkerPool
	requestLimiter *RequestLimiter
	batchProcessor *BatchProcessor
	loadBalancer   *LoadBalancer
	mu             sync.RWMutex
}

// WorkerPool manages a pool of workers for specific tasks
type WorkerPool struct {
	name        string
	workers     []*Worker
	maxWorkers  int
	taskQueue   chan Task
	resultQueue chan TaskResult
	active      bool
	metrics     *WorkerPoolMetrics
	mu          sync.RWMutex
}

// Worker represents a worker in the pool
type Worker struct {
	id       int
	pool     *WorkerPool
	active   bool
	taskChan chan Task
	quitChan chan bool
	metrics  *WorkerMetrics
}

// Task represents a task to be executed by workers
type Task struct {
	ID       string
	Type     string
	Data     interface{}
	Callback func(TaskResult)
	Priority int
	Timeout  time.Duration
	Created  time.Time
}

// TaskResult represents the result of a task execution
type TaskResult struct {
	TaskID    string
	Result    interface{}
	Error     error
	Duration  time.Duration
	WorkerID  int
	Completed time.Time
}

// RequestLimiter implements rate limiting and throttling
type RequestLimiter struct {
	limiters map[string]*RateLimiter
	global   *RateLimiter
	mu       sync.RWMutex
}

// RateLimiter implements token bucket rate limiting
type RateLimiter struct {
	tokens    int
	maxTokens int
	refillRate time.Duration
	lastRefill time.Time
	mu        sync.Mutex
}

// LoadBalancer distributes load across multiple resources
type LoadBalancer struct {
	resources []Resource
	strategy  LoadBalancingStrategy
	metrics   *LoadBalancerMetrics
	mu        sync.RWMutex
}

// Resource represents a resource that can handle requests
type Resource struct {
	ID       string
	Weight   int
	Active   bool
	Load     int
	Capacity int
	Latency  time.Duration
}

// LoadBalancingStrategy defines load balancing strategies
type LoadBalancingStrategy int

const (
	RoundRobin LoadBalancingStrategy = iota
	WeightedRoundRobin
	LeastConnections
	LeastLatency
	ResourceBased
)

// PerformanceProfiler profiles application performance
type PerformanceProfiler struct {
	profiles       map[string]*PerformanceProfile
	sampling       *SamplingConfig
	bottlenecks    []*Bottleneck
	optimizations  []*OptimizationSuggestion
	mu             sync.RWMutex
}

// PerformanceProfile contains performance data for a specific operation
type PerformanceProfile struct {
	Name           string
	ExecutionTimes []time.Duration
	MemoryUsage    []int64
	CPUUsage       []float64
	Throughput     float64
	Latency        PerformanceStatistics
	ErrorRate      float64
	LastUpdated    time.Time
}

// PerformanceStatistics contains statistical performance data
type PerformanceStatistics struct {
	Min    time.Duration
	Max    time.Duration
	Mean   time.Duration
	Median time.Duration
	P95    time.Duration
	P99    time.Duration
}

// PerformanceMetrics tracks overall performance metrics (removed duplicate definition)

// SamplingConfig configures performance sampling
type SamplingConfig struct {
	Enabled        bool
	SampleRate     float64
	MaxSamples     int
	RetentionPeriod time.Duration
}

// Bottleneck represents a performance bottleneck
type Bottleneck struct {
	Type        string
	Location    string
	Description string
	Impact      string
	Severity    int
	Detected    time.Time
	Resolved    bool
}

// OptimizationSuggestion provides performance optimization suggestions
type OptimizationSuggestion struct {
	Type         string
	Description  string
	ExpectedGain string
	Complexity   string
	Priority     int
	Created      time.Time
	Implemented  bool
}

// OptimizationEngine automatically applies performance optimizations
type OptimizationEngine struct {
	rules          []*OptimizationRule
	autoOptimize   bool
	optimizations  []*AppliedOptimization
	mu             sync.RWMutex
}

// OptimizationRule defines conditions and actions for optimization
type OptimizationRule struct {
	Name        string
	Condition   func(*PerformanceMetrics) bool
	Action      func(*PerformanceOptimizer) error
	Enabled     bool
	Priority    int
	Cooldown    time.Duration
	LastApplied time.Time
}

// AppliedOptimization tracks applied optimizations
type AppliedOptimization struct {
	Rule        string
	Applied     time.Time
	Impact      *OptimizationImpact
	Reverted    bool
	RevertTime  time.Time
}

// OptimizationImpact measures the impact of an optimization
type OptimizationImpact struct {
	LatencyImprovement   time.Duration
	ThroughputImprovement float64
	MemoryReduction      int64
	CPUReduction         float64
	ErrorRateReduction   float64
}

// PerformanceConfig contains performance optimization configuration
type PerformanceConfig struct {
	Database     *OptimizationConfig
	Cache        *CacheConfig
	Concurrency  *ConcurrencyConfig
	Profiling    *ProfilingConfig
	Optimization *OptimizationEngineConfig
	Monitoring   *MonitoringConfig
}

// ConcurrencyConfig configures concurrency optimization
type ConcurrencyConfig struct {
	MaxWorkers      int
	WorkerPoolSize  int
	QueueSize       int
	RateLimit       int
	BatchSize       int
	LoadBalancing   bool
	Adaptive        bool
}

// ProfilingConfig configures performance profiling
type ProfilingConfig struct {
	Enabled         bool
	SamplingRate    float64
	ProfileInterval time.Duration
	RetentionPeriod time.Duration
	BottleneckDetection bool
}

// OptimizationEngineConfig configures the optimization engine
type OptimizationEngineConfig struct {
	Enabled         bool
	AutoOptimize    bool
	OptimizationInterval time.Duration
	SafetyMode      bool
	RevertOnFailure bool
}

// MonitoringConfig configures performance monitoring
type MonitoringConfig struct {
	Enabled           bool
	MonitoringInterval time.Duration
	AlertThresholds   *ResourceThresholds
	MetricsRetention  time.Duration
}

// PerformanceMetrics tracks overall performance metrics
type PerformanceMetrics struct {
	Database     *OptimizationMetrics
	Cache        *CacheMetrics
	Resource     *ResourceMetrics
	Concurrency  *ConcurrencyMetrics
	Overall      *OverallPerformanceMetrics
	mu           sync.RWMutex
}

// ResourceMetrics tracks resource usage metrics
type ResourceMetrics struct {
	CPUUsage       float64
	MemoryUsage    int64
	GoroutineCount int
	GCMetrics      *GCStats
	LastUpdated    time.Time
}

// ConcurrencyMetrics tracks concurrency performance
type ConcurrencyMetrics struct {
	ActiveWorkers    int
	QueuedTasks      int
	CompletedTasks   int64
	FailedTasks      int64
	AvgTaskDuration  time.Duration
	Throughput       float64
	LastUpdated      time.Time
}

// OverallPerformanceMetrics tracks overall system performance
type OverallPerformanceMetrics struct {
	Latency         time.Duration
	Throughput      float64
	ErrorRate       float64
	Availability    float64
	Efficiency      float64
	OptimizationScore float64
	LastUpdated     time.Time
}

// WorkerPoolMetrics tracks worker pool performance
type WorkerPoolMetrics struct {
	ActiveWorkers   int
	IdleWorkers     int
	QueueLength     int
	TasksProcessed  int64
	TasksFailed     int64
	AvgProcessTime  time.Duration
	Throughput      float64
}

// WorkerMetrics tracks individual worker performance
type WorkerMetrics struct {
	TasksProcessed int64
	TasksFailed    int64
	AvgProcessTime time.Duration
	LastActive     time.Time
	Utilization    float64
}

// LoadBalancerMetrics tracks load balancer performance
type LoadBalancerMetrics struct {
	RequestsDistributed int64
	ActiveResources     int
	AvgLatency          time.Duration
	LoadDistribution    map[string]float64
}

// NewPerformanceOptimizer creates a new performance optimizer
func NewPerformanceOptimizer(config *PerformanceConfig, db *database.ThreatDB) *PerformanceOptimizer {
	// Initialize database optimizer
	dbOptimizer := NewDatabaseOptimizer(db, config.Database)

	// Initialize cache manager
	cacheManager := NewCacheManager(config.Cache, db)

	// Initialize resource monitor
	resourceMonitor := &ResourceMonitor{
		thresholds: config.Monitoring.AlertThresholds,
		alerts:     make([]*ResourceAlert, 0),
	}

	// Initialize concurrency manager
	concurrencyManager := &ConcurrencyManager{
		maxWorkers:  config.Concurrency.MaxWorkers,
		workerPools: make(map[string]*WorkerPool),
		requestLimiter: &RequestLimiter{
			limiters: make(map[string]*RateLimiter),
			global: &RateLimiter{
				maxTokens:  config.Concurrency.RateLimit,
				tokens:     config.Concurrency.RateLimit,
				refillRate: time.Second,
				lastRefill: time.Now(),
			},
		},
	}

	// Initialize performance profiler
	performanceProfiler := &PerformanceProfiler{
		profiles: make(map[string]*PerformanceProfile),
		sampling: &SamplingConfig{
			Enabled:         config.Profiling.Enabled,
			SampleRate:      config.Profiling.SamplingRate,
			MaxSamples:      10000,
			RetentionPeriod: config.Profiling.RetentionPeriod,
		},
		bottlenecks:   make([]*Bottleneck, 0),
		optimizations: make([]*OptimizationSuggestion, 0),
	}

	// Initialize optimization engine
	optimizationEngine := &OptimizationEngine{
		autoOptimize:  config.Optimization.AutoOptimize,
		optimizations: make([]*AppliedOptimization, 0),
	}

	optimizer := &PerformanceOptimizer{
		dbOptimizer:         dbOptimizer,
		cacheManager:        cacheManager,
		resourceMonitor:     resourceMonitor,
		concurrencyManager:  concurrencyManager,
		performanceProfiler: performanceProfiler,
		optimizationEngine:  optimizationEngine,
		config:             config,
		metrics: &PerformanceMetrics{
			Resource:    &ResourceMetrics{},
			Concurrency: &ConcurrencyMetrics{},
			Overall:     &OverallPerformanceMetrics{},
		},
	}

	// Initialize optimization rules
	optimizer.initializeOptimizationRules()

	// Start background processes
	go optimizer.startResourceMonitoring()
	go optimizer.startPerformanceProfiling()
	go optimizer.startOptimizationEngine()
	go optimizer.startMetricsCollection()

	return optimizer
}

// OptimizedThreatLookup performs optimized threat lookup with caching and batching
func (po *PerformanceOptimizer) OptimizedThreatLookup(packageName, registry string) (*database.ThreatRecord, error) {
	// Use cache manager for optimized lookup
	cacheKey := fmt.Sprintf("threat:%s:%s", packageName, registry)
	if cached, found := po.cacheManager.Get(cacheKey); found {
		if threat, ok := cached.(*database.ThreatRecord); ok {
			return threat, nil
		}
	}

	// Use database optimizer for efficient query
	threat, err := po.dbOptimizer.OptimizedGetThreat(packageName, registry)
	if err != nil {
		return nil, err
	}

	// Cache the result
	if threat != nil {
		po.cacheManager.Set(cacheKey, threat, 1*time.Hour, PriorityNormal)
	}

	return threat, nil
}

// BatchThreatLookup performs batch threat lookups with optimized concurrency
func (po *PerformanceOptimizer) BatchThreatLookup(packages []types.Package) ([]*database.ThreatRecord, error) {
	results := make([]*database.ThreatRecord, len(packages))
	errors := make([]error, len(packages))

	// Create worker pool for batch processing
	pool := po.concurrencyManager.getOrCreateWorkerPool("threat_lookup", 10)

	// Submit tasks
	var wg sync.WaitGroup
	for i, pkg := range packages {
		wg.Add(1)
		task := Task{
			ID:   fmt.Sprintf("lookup_%d", i),
			Type: "threat_lookup",
			Data: pkg,
			Callback: func(result TaskResult) {
				defer wg.Done()
				if result.Error != nil {
					errors[i] = result.Error
				} else if threat, ok := result.Result.(*database.ThreatRecord); ok {
					results[i] = threat
				}
			},
			Priority: 1,
			Timeout:  30 * time.Second,
			Created:  time.Now(),
		}
		pool.submitTask(task)
	}

	wg.Wait()

	// Check for errors
	for _, err := range errors {
		if err != nil {
			return nil, err
		}
	}

	return results, nil
}

// Worker pool methods
func (cm *ConcurrencyManager) getOrCreateWorkerPool(name string, maxWorkers int) *WorkerPool {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if pool, exists := cm.workerPools[name]; exists {
		return pool
	}

	pool := &WorkerPool{
		name:        name,
		maxWorkers:  maxWorkers,
		taskQueue:   make(chan Task, 1000),
		resultQueue: make(chan TaskResult, 1000),
		active:      true,
		metrics:     &WorkerPoolMetrics{},
	}

	// Start workers
	for i := 0; i < maxWorkers; i++ {
		worker := &Worker{
			id:       i,
			pool:     pool,
			active:   true,
			taskChan: make(chan Task),
			quitChan: make(chan bool),
			metrics:  &WorkerMetrics{},
		}
		pool.workers = append(pool.workers, worker)
		go worker.start()
	}

	cm.workerPools[name] = pool
	return pool
}

func (wp *WorkerPool) submitTask(task Task) {
	select {
	case wp.taskQueue <- task:
		// Task submitted successfully
	default:
		// Queue is full, handle overflow
		log.Printf("Worker pool %s queue is full, dropping task %s", wp.name, task.ID)
	}
}

func (w *Worker) start() {
	for {
		select {
		case task := <-w.pool.taskQueue:
			w.processTask(task)
		case <-w.quitChan:
			return
		}
	}
}

func (w *Worker) processTask(task Task) {
	start := time.Now()
	defer func() {
		duration := time.Since(start)
		w.metrics.TasksProcessed++
		w.metrics.AvgProcessTime = (w.metrics.AvgProcessTime + duration) / 2
		w.metrics.LastActive = time.Now()
	}()

	var result interface{}
	var err error

	// Process task based on type
	switch task.Type {
	case "threat_lookup":
		if pkg, ok := task.Data.(types.Package); ok {
			// This would call the actual threat lookup logic
			result, err = w.performThreatLookup(pkg)
		} else {
			err = fmt.Errorf("invalid task data for threat_lookup")
		}
	default:
		err = fmt.Errorf("unknown task type: %s", task.Type)
	}

	// Send result
	taskResult := TaskResult{
		TaskID:    task.ID,
		Result:    result,
		Error:     err,
		Duration:  time.Since(start),
		WorkerID:  w.id,
		Completed: time.Now(),
	}

	if task.Callback != nil {
		task.Callback(taskResult)
	}
}

func (w *Worker) performThreatLookup(pkg types.Package) (*database.ThreatRecord, error) {
	// This would integrate with the actual threat lookup logic
	// For now, return a placeholder
	return nil, fmt.Errorf("threat lookup not implemented in worker")
}

// Resource monitoring methods
func (po *PerformanceOptimizer) startResourceMonitoring() {
	ticker := time.NewTicker(po.config.Monitoring.MonitoringInterval)
	defer ticker.Stop()

	for range ticker.C {
		po.updateResourceMetrics()
		po.checkResourceThresholds()
	}
}

func (po *PerformanceOptimizer) updateResourceMetrics() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	po.resourceMonitor.mu.Lock()
	defer po.resourceMonitor.mu.Unlock()

	// Update CPU usage (simplified)
	po.resourceMonitor.cpuUsage = po.getCPUUsage()

	// Update memory usage
	po.resourceMonitor.memoryUsage = int64(m.Alloc)

	// Update goroutine count
	po.resourceMonitor.goroutineCount = runtime.NumGoroutine()

	// Update GC stats
	po.resourceMonitor.gcStats = &GCStats{
		NumGC:      m.NumGC,
		PauseTotal: time.Duration(m.PauseTotalNs),
		LastGC:     time.Unix(0, int64(m.LastGC)),
		HeapSize:   m.HeapSys,
		HeapInUse:  m.HeapInuse,
		StackInUse: m.StackInuse,
		NextGC:     m.NextGC,
	}

	// Update metrics
	po.mu.Lock()
	if po.metrics.Resource == nil {
		po.metrics.Resource = &ResourceMetrics{}
	}
	po.metrics.Resource.CPUUsage = po.resourceMonitor.cpuUsage
	po.metrics.Resource.MemoryUsage = po.resourceMonitor.memoryUsage
	po.metrics.Resource.GoroutineCount = po.resourceMonitor.goroutineCount
	po.metrics.Resource.GCMetrics = po.resourceMonitor.gcStats
	po.metrics.Resource.LastUpdated = time.Now()
	po.mu.Unlock()
}

func (po *PerformanceOptimizer) getCPUUsage() float64 {
	// Simplified CPU usage calculation
	// In a real implementation, this would use system calls or libraries
	return 0.0
}

func (po *PerformanceOptimizer) checkResourceThresholds() {
	thresholds := po.resourceMonitor.thresholds

	// Check CPU usage
	if po.resourceMonitor.cpuUsage > thresholds.MaxCPUUsage {
		po.createAlert("CPU", "High CPU usage detected", "Warning",
			po.resourceMonitor.cpuUsage, thresholds.MaxCPUUsage)
	}

	// Check memory usage
	if po.resourceMonitor.memoryUsage > thresholds.MaxMemoryUsage {
		po.createAlert("Memory", "High memory usage detected", "Warning",
			po.resourceMonitor.memoryUsage, thresholds.MaxMemoryUsage)
	}

	// Check goroutine count
	if po.resourceMonitor.goroutineCount > thresholds.MaxGoroutines {
		po.createAlert("Goroutines", "High goroutine count detected", "Warning",
			po.resourceMonitor.goroutineCount, thresholds.MaxGoroutines)
	}
}

func (po *PerformanceOptimizer) createAlert(alertType, message, severity string, value, threshold interface{}) {
	alert := &ResourceAlert{
		Type:      alertType,
		Message:   message,
		Severity:  severity,
		Timestamp: time.Now(),
		Value:     value,
		Threshold: threshold,
		Resolved:  false,
	}

	po.resourceMonitor.mu.Lock()
	po.resourceMonitor.alerts = append(po.resourceMonitor.alerts, alert)
	po.resourceMonitor.mu.Unlock()

	log.Printf("Resource alert: %s - %s", alertType, message)
}

// Performance profiling methods
func (po *PerformanceOptimizer) startPerformanceProfiling() {
	if !po.config.Profiling.Enabled {
		return
	}

	ticker := time.NewTicker(po.config.Profiling.ProfileInterval)
	defer ticker.Stop()

	for range ticker.C {
		po.collectPerformanceProfiles()
		po.analyzeBottlenecks()
	}
}

func (po *PerformanceOptimizer) collectPerformanceProfiles() {
	// Collect performance profiles for different operations
	// This would integrate with actual profiling data
}

func (po *PerformanceOptimizer) analyzeBottlenecks() {
	// Analyze performance data to identify bottlenecks
	// This would implement bottleneck detection algorithms
}

// Optimization engine methods
func (po *PerformanceOptimizer) initializeOptimizationRules() {
	rules := []*OptimizationRule{
		{
			Name: "HighMemoryUsage",
			Condition: func(metrics *PerformanceMetrics) bool {
				return metrics.Resource.MemoryUsage > 1024*1024*1024 // 1GB
			},
			Action: func(optimizer *PerformanceOptimizer) error {
				// Trigger garbage collection
				runtime.GC()
				// Clear caches if necessary
				optimizer.cacheManager.performMaintenance()
				return nil
			},
			Enabled:  true,
			Priority: 1,
			Cooldown: 5 * time.Minute,
		},
		{
			Name: "LowCacheHitRatio",
			Condition: func(metrics *PerformanceMetrics) bool {
				return metrics.Cache != nil && metrics.Cache.Overall.OverallHitRatio < 0.7
			},
			Action: func(optimizer *PerformanceOptimizer) error {
				// Trigger cache warming
				if optimizer.cacheManager.cacheWarmer != nil {
					optimizer.cacheManager.cacheWarmer.executeWarmingRules()
				}
				return nil
			},
			Enabled:  true,
			Priority: 2,
			Cooldown: 10 * time.Minute,
		},
	}

	po.optimizationEngine.rules = rules
}

func (po *PerformanceOptimizer) startOptimizationEngine() {
	if !po.config.Optimization.Enabled {
		return
	}

	ticker := time.NewTicker(po.config.Optimization.OptimizationInterval)
	defer ticker.Stop()

	for range ticker.C {
		po.runOptimizationRules()
	}
}

func (po *PerformanceOptimizer) runOptimizationRules() {
	for _, rule := range po.optimizationEngine.rules {
		if rule.Enabled && time.Since(rule.LastApplied) > rule.Cooldown {
			if rule.Condition(po.metrics) {
				if po.optimizationEngine.autoOptimize {
					err := rule.Action(po)
					if err != nil {
						log.Printf("Optimization rule %s failed: %v", rule.Name, err)
					} else {
						rule.LastApplied = time.Now()
						log.Printf("Applied optimization rule: %s", rule.Name)
					}
				} else {
					log.Printf("Optimization rule %s triggered (auto-optimize disabled)", rule.Name)
				}
			}
		}
	}
}

// Metrics collection
func (po *PerformanceOptimizer) startMetricsCollection() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		po.updateOverallMetrics()
	}
}

func (po *PerformanceOptimizer) updateOverallMetrics() {
	po.mu.Lock()
	defer po.mu.Unlock()

	// Update database metrics
	po.metrics.Database = po.dbOptimizer.GetOptimizationMetrics()

	// Update cache metrics
	po.metrics.Cache = po.cacheManager.GetMetrics()

	// Update overall performance metrics
	po.metrics.Overall.LastUpdated = time.Now()
	// Calculate overall efficiency, latency, etc.
	po.calculateOverallPerformance()
}

func (po *PerformanceOptimizer) calculateOverallPerformance() {
	// Calculate overall performance metrics based on individual components
	// This would implement complex performance calculations
}

// Public API methods
func (po *PerformanceOptimizer) GetPerformanceMetrics() *PerformanceMetrics {
	po.mu.RLock()
	defer po.mu.RUnlock()

	// Return a copy of metrics
	return &PerformanceMetrics{
		Database:    po.metrics.Database,
		Cache:       po.metrics.Cache,
		Resource:    po.metrics.Resource,
		Concurrency: po.metrics.Concurrency,
		Overall:     po.metrics.Overall,
	}
}

func (po *PerformanceOptimizer) GetResourceAlerts() []*ResourceAlert {
	po.resourceMonitor.mu.RLock()
	defer po.resourceMonitor.mu.RUnlock()

	alerts := make([]*ResourceAlert, len(po.resourceMonitor.alerts))
	copy(alerts, po.resourceMonitor.alerts)
	return alerts
}

func (po *PerformanceOptimizer) GetBottlenecks() []*Bottleneck {
	po.performanceProfiler.mu.RLock()
	defer po.performanceProfiler.mu.RUnlock()

	bottlenecks := make([]*Bottleneck, len(po.performanceProfiler.bottlenecks))
	copy(bottlenecks, po.performanceProfiler.bottlenecks)
	return bottlenecks
}

func (po *PerformanceOptimizer) GetOptimizationSuggestions() []*OptimizationSuggestion {
	po.performanceProfiler.mu.RLock()
	defer po.performanceProfiler.mu.RUnlock()

	suggestions := make([]*OptimizationSuggestion, len(po.performanceProfiler.optimizations))
	copy(suggestions, po.performanceProfiler.optimizations)
	return suggestions
}

// Shutdown gracefully shuts down the performance optimizer
func (po *PerformanceOptimizer) Shutdown() error {
	// Shutdown all components
	if err := po.dbOptimizer.Shutdown(); err != nil {
		return err
	}

	if err := po.cacheManager.Shutdown(); err != nil {
		return err
	}

	// Shutdown worker pools
	for _, pool := range po.concurrencyManager.workerPools {
		for _, worker := range pool.workers {
			worker.quitChan <- true
		}
	}

	return nil
}