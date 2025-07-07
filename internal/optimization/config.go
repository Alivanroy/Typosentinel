package optimization

import (
	"fmt"
	"runtime"
	"time"
)

// DefaultOptimizationConfig returns a production-ready optimization configuration
func DefaultOptimizationConfig() *PerformanceConfig {
	return &PerformanceConfig{
		Database:     DefaultDatabaseOptimizationConfig(),
		Cache:        DefaultCacheConfig(),
		Concurrency:  DefaultConcurrencyConfig(),
		Profiling:    DefaultProfilingConfig(),
		Optimization: DefaultOptimizationEngineConfig(),
		Monitoring:   DefaultMonitoringConfig(),
	}
}

// DefaultDatabaseOptimizationConfig returns default database optimization settings
func DefaultDatabaseOptimizationConfig() *OptimizationConfig {
	return &OptimizationConfig{
		CacheTTL:           30 * time.Minute,
		CacheMaxSize:       10000,
		BatchSize:          100,
		FlushInterval:      5 * time.Second,
		SlowQueryThreshold: 100 * time.Millisecond,
		IndexOptimization:  true,
		ConnectionPoolSize: 25,
		QueryTimeout:       30 * time.Second,
	}
}

// DefaultCacheConfig returns default cache configuration
func DefaultCacheConfig() *CacheConfig {
	return &CacheConfig{
		L1Config: &L1Config{
			MaxSize:        5000,
			MaxMemory:      512 * 1024 * 1024, // 512MB
			DefaultTTL:     15 * time.Minute,
			EvictionPolicy: "LRU",
		},
		L2Config: &L2Config{
			CacheDir:    "/tmp/typosentinel_cache",
			MaxSize:     2 * 1024 * 1024 * 1024, // 2GB
			DefaultTTL:  1 * time.Hour,
			Compression: true,
			Encryption:  false,
		},
		L3Config: &L3Config{
			Enabled:    false, // Redis disabled by default
			RedisURL:   "redis://localhost:6379",
			DefaultTTL: 2 * time.Hour,
			MaxRetries: 3,
			RetryDelay: 1 * time.Second,
		},
		Warming: &WarmingConfig{
			Enabled:         true,
			WarmingInterval: 1 * time.Hour,
			MaxConcurrency:  5,
			PredictiveMode:  false,
		},
		Analysis: &AnalysisConfig{
			Enabled:          true,
			AnalysisInterval: 5 * time.Minute,
			RetentionPeriod:  24 * time.Hour,
			Recommendations:  true,
		},
	}
}

// DefaultConcurrencyConfig returns default concurrency settings
func DefaultConcurrencyConfig() *ConcurrencyConfig {
	return &ConcurrencyConfig{
		MaxWorkers:     20,
		WorkerPoolSize: 10,
		QueueSize:      1000,
		RateLimit:      100, // requests per second
		BatchSize:      50,
		LoadBalancing:  true,
		Adaptive:       true,
	}
}

// DefaultProfilingConfig returns default profiling settings
func DefaultProfilingConfig() *ProfilingConfig {
	return &ProfilingConfig{
		Enabled:             true,
		SamplingRate:        0.1, // 10% sampling
		ProfileInterval:     1 * time.Minute,
		RetentionPeriod:     24 * time.Hour,
		BottleneckDetection: true,
	}
}

// DefaultOptimizationEngineConfig returns default optimization engine settings
func DefaultOptimizationEngineConfig() *OptimizationEngineConfig {
	return &OptimizationEngineConfig{
		Enabled:              true,
		AutoOptimize:         true,
		OptimizationInterval: 5 * time.Minute,
		SafetyMode:           true,
		RevertOnFailure:      true,
	}
}

// DefaultMonitoringConfig returns default monitoring settings
func DefaultMonitoringConfig() *MonitoringConfig {
	return &MonitoringConfig{
		Enabled:            true,
		MonitoringInterval: 30 * time.Second,
		AlertThresholds:    DefaultResourceThresholds(),
		MetricsRetention:   7 * 24 * time.Hour, // 7 days
	}
}

// DefaultResourceThresholds returns default resource usage thresholds
func DefaultResourceThresholds() *ResourceThresholds {
	return &ResourceThresholds{
		MaxCPUUsage:    80.0,               // 80%
		MaxMemoryUsage: 1024 * 1024 * 1024, // 1GB
		MaxGoroutines:  1000,
		MaxGCPause:     100 * time.Millisecond,
		MaxHeapSize:    2 * 1024 * 1024 * 1024, // 2GB
	}
}

// ProductionOptimizationConfig returns optimized settings for production
func ProductionOptimizationConfig() *PerformanceConfig {
	config := DefaultOptimizationConfig()

	// Production database optimizations
	config.Database.CacheTTL = 1 * time.Hour
	config.Database.CacheMaxSize = 50000
	config.Database.BatchSize = 500
	config.Database.FlushInterval = 2 * time.Second
	config.Database.SlowQueryThreshold = 50 * time.Millisecond
	config.Database.ConnectionPoolSize = 50

	// Production cache optimizations
	config.Cache.L1Config.MaxSize = 20000
	config.Cache.L1Config.MaxMemory = 1024 * 1024 * 1024 // 1GB
	config.Cache.L1Config.DefaultTTL = 30 * time.Minute

	config.Cache.L2Config.MaxSize = 10 * 1024 * 1024 * 1024 // 10GB
	config.Cache.L2Config.DefaultTTL = 4 * time.Hour
	config.Cache.L2Config.Compression = true
	config.Cache.L2Config.Encryption = true

	// Enable Redis for production
	config.Cache.L3Config.Enabled = true
	config.Cache.L3Config.DefaultTTL = 8 * time.Hour

	// Production concurrency settings
	config.Concurrency.MaxWorkers = 50
	config.Concurrency.WorkerPoolSize = 20
	config.Concurrency.QueueSize = 5000
	config.Concurrency.RateLimit = 500
	config.Concurrency.BatchSize = 200

	// Production profiling (reduced sampling)
	config.Profiling.SamplingRate = 0.01 // 1% sampling
	config.Profiling.ProfileInterval = 5 * time.Minute

	// Production monitoring
	config.Monitoring.MonitoringInterval = 15 * time.Second
	config.Monitoring.AlertThresholds.MaxCPUUsage = 90.0
	config.Monitoring.AlertThresholds.MaxMemoryUsage = 4 * 1024 * 1024 * 1024 // 4GB
	config.Monitoring.AlertThresholds.MaxGoroutines = 2000

	return config
}

// DevelopmentOptimizationConfig returns settings optimized for development
func DevelopmentOptimizationConfig() *PerformanceConfig {
	config := DefaultOptimizationConfig()

	// Development-friendly settings
	config.Database.CacheTTL = 5 * time.Minute
	config.Database.CacheMaxSize = 1000
	config.Database.BatchSize = 10
	config.Database.SlowQueryThreshold = 500 * time.Millisecond

	// Smaller cache for development
	config.Cache.L1Config.MaxSize = 500
	config.Cache.L1Config.MaxMemory = 64 * 1024 * 1024 // 64MB
	config.Cache.L1Config.DefaultTTL = 5 * time.Minute

	config.Cache.L2Config.MaxSize = 100 * 1024 * 1024 // 100MB
	config.Cache.L2Config.DefaultTTL = 15 * time.Minute
	config.Cache.L2Config.Compression = false
	config.Cache.L2Config.Encryption = false

	// Disable Redis for development
	config.Cache.L3Config.Enabled = false

	// Lower concurrency for development
	config.Concurrency.MaxWorkers = 5
	config.Concurrency.WorkerPoolSize = 3
	config.Concurrency.QueueSize = 100
	config.Concurrency.RateLimit = 50

	// More aggressive profiling for development
	config.Profiling.SamplingRate = 0.5 // 50% sampling
	config.Profiling.ProfileInterval = 30 * time.Second

	// More frequent monitoring for development
	config.Monitoring.MonitoringInterval = 10 * time.Second
	config.Monitoring.AlertThresholds.MaxCPUUsage = 70.0
	config.Monitoring.AlertThresholds.MaxMemoryUsage = 512 * 1024 * 1024 // 512MB

	return config
}

// TestOptimizationConfig returns settings optimized for testing
func TestOptimizationConfig() *PerformanceConfig {
	config := DefaultOptimizationConfig()

	// Minimal settings for testing
	config.Database.CacheTTL = 1 * time.Minute
	config.Database.CacheMaxSize = 100
	config.Database.BatchSize = 5
	config.Database.FlushInterval = 100 * time.Millisecond

	// Minimal cache for testing
	config.Cache.L1Config.MaxSize = 50
	config.Cache.L1Config.MaxMemory = 10 * 1024 * 1024 // 10MB
	config.Cache.L1Config.DefaultTTL = 1 * time.Minute

	config.Cache.L2Config.MaxSize = 50 * 1024 * 1024 // 50MB
	config.Cache.L2Config.DefaultTTL = 2 * time.Minute
	config.Cache.L2Config.Compression = false
	config.Cache.L2Config.Encryption = false

	// Disable Redis for testing
	config.Cache.L3Config.Enabled = false

	// Disable cache warming for testing
	config.Cache.Warming.Enabled = false

	// Minimal concurrency for testing
	config.Concurrency.MaxWorkers = 2
	config.Concurrency.WorkerPoolSize = 1
	config.Concurrency.QueueSize = 10
	config.Concurrency.RateLimit = 10

	// Disable profiling for testing
	config.Profiling.Enabled = false

	// Disable auto-optimization for testing
	config.Optimization.AutoOptimize = false

	// Minimal monitoring for testing
	config.Monitoring.MonitoringInterval = 1 * time.Second
	config.Monitoring.AlertThresholds.MaxMemoryUsage = 100 * 1024 * 1024 // 100MB

	return config
}

// ConfigFromEnvironment creates configuration based on environment variables
func ConfigFromEnvironment(env string) *PerformanceConfig {
	switch env {
	case "production", "prod":
		return ProductionOptimizationConfig()
	case "development", "dev":
		return DevelopmentOptimizationConfig()
	case "test", "testing":
		return TestOptimizationConfig()
	default:
		return DefaultOptimizationConfig()
	}
}

// ValidateConfig validates the optimization configuration
func ValidateConfig(config *PerformanceConfig) error {
	if config == nil {
		return fmt.Errorf("configuration cannot be nil")
	}

	// Validate database config
	if config.Database != nil {
		if config.Database.CacheMaxSize <= 0 {
			return fmt.Errorf("database cache max size must be positive")
		}
		if config.Database.BatchSize <= 0 {
			return fmt.Errorf("database batch size must be positive")
		}
		if config.Database.ConnectionPoolSize <= 0 {
			return fmt.Errorf("database connection pool size must be positive")
		}
	}

	// Validate cache config
	if config.Cache != nil {
		if config.Cache.L1Config != nil {
			if config.Cache.L1Config.MaxSize <= 0 {
				return fmt.Errorf("L1 cache max size must be positive")
			}
			if config.Cache.L1Config.MaxMemory <= 0 {
				return fmt.Errorf("L1 cache max memory must be positive")
			}
		}
		if config.Cache.L2Config != nil {
			if config.Cache.L2Config.MaxSize <= 0 {
				return fmt.Errorf("L2 cache max size must be positive")
			}
			if config.Cache.L2Config.CacheDir == "" {
				return fmt.Errorf("L2 cache directory cannot be empty")
			}
		}
	}

	// Validate concurrency config
	if config.Concurrency != nil {
		if config.Concurrency.MaxWorkers <= 0 {
			return fmt.Errorf("max workers must be positive")
		}
		if config.Concurrency.QueueSize <= 0 {
			return fmt.Errorf("queue size must be positive")
		}
		if config.Concurrency.RateLimit <= 0 {
			return fmt.Errorf("rate limit must be positive")
		}
	}

	// Validate profiling config
	if config.Profiling != nil {
		if config.Profiling.SamplingRate < 0 || config.Profiling.SamplingRate > 1 {
			return fmt.Errorf("sampling rate must be between 0 and 1")
		}
	}

	return nil
}

// OptimizeConfigForWorkload adjusts configuration based on expected workload
func OptimizeConfigForWorkload(config *PerformanceConfig, workload WorkloadProfile) *PerformanceConfig {
	optimized := *config // Copy the config

	switch workload.Type {
	case "high_throughput":
		// Optimize for high throughput
		optimized.Concurrency.MaxWorkers *= 2
		optimized.Concurrency.QueueSize *= 3
		optimized.Database.BatchSize *= 2
		optimized.Cache.L1Config.MaxSize *= 2

	case "low_latency":
		// Optimize for low latency
		optimized.Database.SlowQueryThreshold /= 2
		optimized.Cache.L1Config.DefaultTTL *= 2
		optimized.Database.FlushInterval /= 2

	case "memory_constrained":
		// Optimize for memory constraints
		optimized.Cache.L1Config.MaxMemory /= 2
		optimized.Cache.L1Config.MaxSize /= 2
		optimized.Concurrency.MaxWorkers /= 2

	case "cpu_intensive":
		// Optimize for CPU-intensive workloads
		optimized.Concurrency.MaxWorkers = min(optimized.Concurrency.MaxWorkers, runtime.NumCPU())
		optimized.Profiling.SamplingRate /= 2 // Reduce profiling overhead

	case "io_intensive":
		// Optimize for I/O-intensive workloads
		optimized.Concurrency.MaxWorkers *= 3
		optimized.Database.ConnectionPoolSize *= 2
		optimized.Cache.L2Config.DefaultTTL *= 2
	}

	return &optimized
}

// WorkloadProfile describes the expected workload characteristics
type WorkloadProfile struct {
	Type                string // high_throughput, low_latency, memory_constrained, cpu_intensive, io_intensive
	ExpectedRPS         int    // Expected requests per second
	ExpectedConcurrency int    // Expected concurrent operations
	MemoryBudget        int64  // Available memory budget
	CPUCores            int    // Available CPU cores
	StorageType         string // SSD, HDD, Network
}

// Helper function for min
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// GetRecommendedConfig returns a recommended configuration based on system resources
func GetRecommendedConfig() *PerformanceConfig {
	config := DefaultOptimizationConfig()

	// Adjust based on available system resources
	numCPU := runtime.NumCPU()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	// Adjust concurrency based on CPU cores
	config.Concurrency.MaxWorkers = numCPU * 4
	config.Concurrency.WorkerPoolSize = numCPU * 2

	// Adjust cache size based on available memory
	availableMemory := int64(m.Sys)
	config.Cache.L1Config.MaxMemory = availableMemory / 8                       // Use 1/8 of system memory
	config.Cache.L1Config.MaxSize = int(config.Cache.L1Config.MaxMemory / 1024) // Rough estimate

	// Adjust database settings based on system capabilities
	config.Database.ConnectionPoolSize = numCPU * 5
	config.Database.BatchSize = numCPU * 20

	return config
}
