package security

import (
	"context"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"
)

// GracefulDegradationManager manages system stability under high load
type GracefulDegradationManager struct {
	config               *GracefulDegradationConfig
	loadShedder          *LoadShedder
	backpressureManager  *BackpressureManager
	fallbackManager      *FallbackManager
	serviceHealthMonitor *ServiceHealthMonitor
	resourceMonitor      *GracefulResourceMonitor
	metrics              *DegradationMetrics
	logger               *log.Logger
	mu                   sync.RWMutex
	shutdownChan         chan struct{}
	active               int32
}

// GracefulDegradationConfig defines configuration for graceful degradation
type GracefulDegradationConfig struct {
	// Load shedding configuration
	EnableLoadShedding    bool    `yaml:"enable_load_shedding" default:"true"`
	LoadSheddingThreshold float64 `yaml:"load_shedding_threshold" default:"0.8"`
	CriticalThreshold     float64 `yaml:"critical_threshold" default:"0.95"`
	SheddingRate          float64 `yaml:"shedding_rate" default:"0.1"`
	MaxSheddingRate       float64 `yaml:"max_shedding_rate" default:"0.5"`

	// Backpressure configuration
	EnableBackpressure    bool          `yaml:"enable_backpressure" default:"true"`
	BackpressureThreshold float64       `yaml:"backpressure_threshold" default:"0.7"`
	MaxQueueSize          int           `yaml:"max_queue_size" default:"10000"`
	QueueTimeout          time.Duration `yaml:"queue_timeout" default:"30s"`

	// Fallback configuration
	EnableFallbacks   bool          `yaml:"enable_fallbacks" default:"true"`
	FallbackTimeout   time.Duration `yaml:"fallback_timeout" default:"5s"`
	CacheOnlyMode     bool          `yaml:"cache_only_mode" default:"false"`
	ReducedFeatureSet bool          `yaml:"reduced_feature_set" default:"true"`

	// Resource monitoring
	MonitoringInterval time.Duration `yaml:"monitoring_interval" default:"1s"`
	CPUThreshold       float64       `yaml:"cpu_threshold" default:"80.0"`
	MemoryThreshold    int64         `yaml:"memory_threshold" default:"1073741824"` // 1GB
	GoroutineThreshold int           `yaml:"goroutine_threshold" default:"10000"`

	// Service health
	HealthCheckInterval time.Duration `yaml:"health_check_interval" default:"5s"`
	UnhealthyThreshold  int           `yaml:"unhealthy_threshold" default:"3"`
	RecoveryThreshold   int           `yaml:"recovery_threshold" default:"5"`

	// Adaptive behavior
	AdaptiveMode       bool          `yaml:"adaptive_mode" default:"true"`
	AdaptationInterval time.Duration `yaml:"adaptation_interval" default:"10s"`
	LearningRate       float64       `yaml:"learning_rate" default:"0.1"`
}

// LoadShedder implements intelligent load shedding
type LoadShedder struct {
	config         *GracefulDegradationConfig
	currentLoad    float64
	sheddingRate   float64
	requestCounter int64
	droppedCounter int64
	prioritizer    *RequestPrioritizer
	mu             sync.RWMutex
}

// RequestPrioritizer prioritizes requests during load shedding
type RequestPrioritizer struct {
	priorities map[string]int
	mu         sync.RWMutex
}

// BackpressureManager manages backpressure mechanisms
type BackpressureManager struct {
	config       *GracefulDegradationConfig
	requestQueue chan *Request
	queueSize    int64
	maxQueueSize int64
	waitingTime  time.Duration
	mu           sync.RWMutex
}

// Request represents a request in the backpressure queue
type Request struct {
	ID        string
	Type      string
	Priority  int
	Payload   interface{}
	Callback  func(interface{}, error)
	Timeout   time.Duration
	CreatedAt time.Time
	Context   context.Context
}

// FallbackManager manages fallback mechanisms
type FallbackManager struct {
	config          *GracefulDegradationConfig
	fallbackModes   map[string]bool
	cacheOnlyMode   bool
	reducedFeatures bool
	fallbackCache   *FallbackCache
	mu              sync.RWMutex
}

// FallbackCache provides cached responses during degradation
type FallbackCache struct {
	cache      map[string]*FallbackCacheEntry
	ttl        time.Duration
	maxEntries int
	mu         sync.RWMutex
}

// FallbackCacheEntry represents a cached response
type FallbackCacheEntry struct {
	Value     interface{}
	CreatedAt time.Time
	TTL       time.Duration
}

// ServiceHealthMonitor monitors service health
type ServiceHealthMonitor struct {
	config         *GracefulDegradationConfig
	services       map[string]*ServiceHealth
	healthCheckers map[string]HealthChecker
	overallHealth  ServiceHealthStatus
	mu             sync.RWMutex
}

// ServiceHealth tracks health of individual services
type ServiceHealth struct {
	Name             string
	Status           ServiceHealthStatus
	LastCheck        time.Time
	ConsecutiveFails int
	ConsecutiveOKs   int
	Latency          time.Duration
	ErrorRate        float64
}

// ServiceHealthStatus represents service health status
type ServiceHealthStatus int

const (
	Healthy ServiceHealthStatus = iota
	Degraded
	Unhealthy
	Critical
)

// HealthChecker interface for service health checks
type HealthChecker interface {
	Check(ctx context.Context) error
	Name() string
}

// GracefulResourceMonitor monitors system resources for graceful degradation
type GracefulResourceMonitor struct {
	config         *GracefulDegradationConfig
	cpuUsage       float64
	memoryUsage    int64
	goroutineCount int
	loadAverage    float64
	lastUpdate     time.Time
	mu             sync.RWMutex
}

// DegradationMetrics tracks degradation metrics
type DegradationMetrics struct {
	TotalRequests       int64         `json:"total_requests"`
	DroppedRequests     int64         `json:"dropped_requests"`
	QueuedRequests      int64         `json:"queued_requests"`
	FallbackRequests    int64         `json:"fallback_requests"`
	LoadSheddingRate    float64       `json:"load_shedding_rate"`
	BackpressureRate    float64       `json:"backpressure_rate"`
	FallbackRate        float64       `json:"fallback_rate"`
	AverageResponseTime time.Duration `json:"average_response_time"`
	SystemLoad          float64       `json:"system_load"`
	HealthScore         float64       `json:"health_score"`
	DegradationLevel    int           `json:"degradation_level"`
	LastUpdated         time.Time     `json:"last_updated"`
	mu                  sync.RWMutex
}

// DegradationLevel represents the current degradation level
type DegradationLevel int

const (
	NormalOperation DegradationLevel = iota
	LightDegradation
	ModerateDegradation
	SevereDegradation
	CriticalDegradation
)

// NewGracefulDegradationManager creates a new graceful degradation manager
func NewGracefulDegradationManager(config *GracefulDegradationConfig, logger *log.Logger) *GracefulDegradationManager {
	if config == nil {
		config = DefaultGracefulDegradationConfig()
	}

	if logger == nil {
		logger = log.New(log.Writer(), "[GracefulDegradation] ", log.LstdFlags)
	}

	gdm := &GracefulDegradationManager{
		config:       config,
		logger:       logger,
		shutdownChan: make(chan struct{}),
		metrics:      &DegradationMetrics{LastUpdated: time.Now()},
	}

	// Initialize components
	gdm.loadShedder = NewLoadShedder(config)
	gdm.backpressureManager = NewBackpressureManager(config)
	gdm.fallbackManager = NewFallbackManager(config)
	gdm.serviceHealthMonitor = NewServiceHealthMonitor(config)
	gdm.resourceMonitor = NewGracefulResourceMonitor(config)

	return gdm
}

// Start starts the graceful degradation manager
func (gdm *GracefulDegradationManager) Start(ctx context.Context) error {
	if !atomic.CompareAndSwapInt32(&gdm.active, 0, 1) {
		return fmt.Errorf("graceful degradation manager already started")
	}

	gdm.logger.Println("Starting graceful degradation manager")

	// Start monitoring goroutines
	go gdm.monitorResources(ctx)
	go gdm.monitorServiceHealth(ctx)
	go gdm.updateMetrics(ctx)
	go gdm.adaptiveOptimization(ctx)

	return nil
}

// Stop stops the graceful degradation manager
func (gdm *GracefulDegradationManager) Stop() error {
	if !atomic.CompareAndSwapInt32(&gdm.active, 1, 0) {
		return fmt.Errorf("graceful degradation manager not started")
	}

	gdm.logger.Println("Stopping graceful degradation manager")
	close(gdm.shutdownChan)
	return nil
}

// ProcessRequest processes a request with graceful degradation
func (gdm *GracefulDegradationManager) ProcessRequest(ctx context.Context, req *Request) (interface{}, error) {
	atomic.AddInt64(&gdm.metrics.TotalRequests, 1)

	// Check if request should be shed
	if gdm.config.EnableLoadShedding && gdm.loadShedder.ShouldShedRequest(req) {
		atomic.AddInt64(&gdm.metrics.DroppedRequests, 1)
		return nil, fmt.Errorf("request dropped due to load shedding")
	}

	// Apply backpressure if needed
	if gdm.config.EnableBackpressure {
		if err := gdm.backpressureManager.ApplyBackpressure(ctx, req); err != nil {
			return nil, fmt.Errorf("backpressure applied: %w", err)
		}
	}

	// Try fallback if primary processing fails
	if gdm.config.EnableFallbacks {
		if result, err := gdm.fallbackManager.TryFallback(ctx, req); err == nil {
			atomic.AddInt64(&gdm.metrics.FallbackRequests, 1)
			return result, nil
		}
	}

	return gdm.processRequestNormally(ctx, req)
}

// processRequestNormally processes request through normal path
func (gdm *GracefulDegradationManager) processRequestNormally(ctx context.Context, req *Request) (interface{}, error) {
	// This would integrate with the actual request processing logic
	// For now, we'll simulate processing
	start := time.Now()
	defer func() {
		duration := time.Since(start)
		gdm.updateResponseTime(duration)
	}()

	// Simulate processing based on request type
	switch req.Type {
	case "threat_lookup":
		return gdm.processThreatLookup(ctx, req)
	case "package_scan":
		return gdm.processPackageScan(ctx, req)
	case "vulnerability_check":
		return gdm.processVulnerabilityCheck(ctx, req)
	default:
		return nil, fmt.Errorf("unknown request type: %s", req.Type)
	}
}

// processThreatLookup processes threat lookup requests
func (gdm *GracefulDegradationManager) processThreatLookup(ctx context.Context, req *Request) (interface{}, error) {
	// Simulate threat lookup processing
	time.Sleep(time.Millisecond * 10) // Simulate processing time
	return map[string]interface{}{
		"threat_level": "low",
		"confidence":   0.8,
		"processed_at": time.Now(),
	}, nil
}

// processPackageScan processes package scan requests
func (gdm *GracefulDegradationManager) processPackageScan(ctx context.Context, req *Request) (interface{}, error) {
	// Simulate package scan processing
	time.Sleep(time.Millisecond * 50) // Simulate processing time
	return map[string]interface{}{
		"scan_result":  "clean",
		"issues":       []string{},
		"processed_at": time.Now(),
	}, nil
}

// processVulnerabilityCheck processes vulnerability check requests
func (gdm *GracefulDegradationManager) processVulnerabilityCheck(ctx context.Context, req *Request) (interface{}, error) {
	// Simulate vulnerability check processing
	time.Sleep(time.Millisecond * 25) // Simulate processing time
	return map[string]interface{}{
		"vulnerabilities": []string{},
		"severity":        "none",
		"processed_at":    time.Now(),
	}, nil
}

// updateResponseTime updates average response time metrics
func (gdm *GracefulDegradationManager) updateResponseTime(duration time.Duration) {
	gdm.metrics.mu.Lock()
	defer gdm.metrics.mu.Unlock()

	// Simple moving average
	if gdm.metrics.AverageResponseTime == 0 {
		gdm.metrics.AverageResponseTime = duration
	} else {
		gdm.metrics.AverageResponseTime = (gdm.metrics.AverageResponseTime + duration) / 2
	}
}

// GetMetrics returns current degradation metrics
func (gdm *GracefulDegradationManager) GetMetrics() *DegradationMetrics {
	gdm.metrics.mu.RLock()
	defer gdm.metrics.mu.RUnlock()

	// Create a copy to avoid race conditions without copying the mutex
	metrics := &DegradationMetrics{
		TotalRequests:       gdm.metrics.TotalRequests,
		DroppedRequests:     gdm.metrics.DroppedRequests,
		QueuedRequests:      gdm.metrics.QueuedRequests,
		FallbackRequests:    gdm.metrics.FallbackRequests,
		LoadSheddingRate:    gdm.metrics.LoadSheddingRate,
		BackpressureRate:    gdm.metrics.BackpressureRate,
		FallbackRate:        gdm.metrics.FallbackRate,
		AverageResponseTime: gdm.metrics.AverageResponseTime,
		SystemLoad:          gdm.metrics.SystemLoad,
		HealthScore:         gdm.metrics.HealthScore,
		DegradationLevel:    gdm.metrics.DegradationLevel,
		LastUpdated:         gdm.metrics.LastUpdated,
	}
	return metrics
}

// GetDegradationLevel returns current degradation level
func (gdm *GracefulDegradationManager) GetDegradationLevel() DegradationLevel {
	gdm.mu.RLock()
	defer gdm.mu.RUnlock()

	load := gdm.resourceMonitor.loadAverage
	health := gdm.serviceHealthMonitor.overallHealth

	// Determine degradation level based on load and health
	if load > gdm.config.CriticalThreshold || health == Critical {
		return CriticalDegradation
	} else if load > gdm.config.LoadSheddingThreshold || health == Unhealthy {
		return SevereDegradation
	} else if load > gdm.config.BackpressureThreshold || health == Degraded {
		return ModerateDegradation
	} else if load > 0.5 {
		return LightDegradation
	}

	return NormalOperation
}

// DefaultGracefulDegradationConfig returns default configuration
func DefaultGracefulDegradationConfig() *GracefulDegradationConfig {
	return &GracefulDegradationConfig{
		EnableLoadShedding:    true,
		LoadSheddingThreshold: 0.8,
		CriticalThreshold:     0.95,
		SheddingRate:          0.1,
		MaxSheddingRate:       0.5,
		EnableBackpressure:    true,
		BackpressureThreshold: 0.7,
		MaxQueueSize:          10000,
		QueueTimeout:          30 * time.Second,
		EnableFallbacks:       true,
		FallbackTimeout:       5 * time.Second,
		CacheOnlyMode:         false,
		ReducedFeatureSet:     true,
		MonitoringInterval:    time.Second,
		CPUThreshold:          80.0,
		MemoryThreshold:       1024 * 1024 * 1024, // 1GB
		GoroutineThreshold:    10000,
		HealthCheckInterval:   5 * time.Second,
		UnhealthyThreshold:    3,
		RecoveryThreshold:     5,
		AdaptiveMode:          true,
		AdaptationInterval:    10 * time.Second,
		LearningRate:          0.1,
	}
}
