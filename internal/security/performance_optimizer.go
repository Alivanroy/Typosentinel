package security

import (
	"context"
	"errors"
	"sync"
	"time"
)

// PerformanceOptimizer optimizes security component performance
type PerformanceOptimizer struct {
	// Simple caching with maps
	policyCache     map[string]*CacheEntry
	validationCache map[string]*CacheEntry
	rateLimitCache  map[string]*CacheEntry
	
	// Connection pooling
	connectionPool sync.Pool
	
	// Metrics
	metrics *SecurityPerformanceMetrics
	
	// Configuration
	config *PerformanceConfig
	
	// Synchronization
	mu sync.RWMutex
}

// CacheEntry represents a cached item with expiration
type CacheEntry struct {
	Value     interface{}
	ExpiresAt time.Time
	CreatedAt time.Time
}

// PerformanceConfig holds performance optimization settings
type PerformanceConfig struct {
	// Cache settings
	PolicyCacheTTL      time.Duration `yaml:"policy_cache_ttl" default:"5m"`
	ValidationCacheTTL  time.Duration `yaml:"validation_cache_ttl" default:"1m"`
	RateLimitCacheTTL   time.Duration `yaml:"rate_limit_cache_ttl" default:"30s"`
	
	// Cache sizes
	PolicyCacheSize     int `yaml:"policy_cache_size" default:"1000"`
	ValidationCacheSize int `yaml:"validation_cache_size" default:"5000"`
	RateLimitCacheSize  int `yaml:"rate_limit_cache_size" default:"10000"`
	
	// Performance thresholds
	MaxProcessingTime   time.Duration `yaml:"max_processing_time" default:"100ms"`
	MaxMemoryUsage      int64         `yaml:"max_memory_usage" default:"104857600"` // 100MB
	
	// Optimization flags
	EnableCaching       bool `yaml:"enable_caching" default:"true"`
	EnablePooling       bool `yaml:"enable_pooling" default:"true"`
	EnableMetrics       bool `yaml:"enable_metrics" default:"true"`
	EnableCompression   bool `yaml:"enable_compression" default:"true"`
}

// SecurityPerformanceMetrics holds performance metrics for security components
type SecurityPerformanceMetrics struct {
	// Processing time metrics
	PolicyEvaluationCount    int64
	PolicyEvaluationTime     time.Duration
	ValidationCount          int64
	ValidationTime           time.Duration
	RateLimitCheckCount      int64
	RateLimitCheckTime       time.Duration
	EncryptionCount          int64
	EncryptionTime           time.Duration
	
	// Cache metrics
	PolicyCacheHits          int64
	PolicyCacheMisses        int64
	ValidationCacheHits      int64
	ValidationCacheMisses    int64
	
	// Performance metrics
	TotalProcessingTime      time.Duration
	MemoryUsed               int64
	ConcurrentRequests       int64
	
	// Error metrics
	SecurityErrors           int64
	TimeoutErrors            int64
	
	// Synchronization
	mu sync.RWMutex
}

// CacheKey represents a cache key with metadata
type CacheKey struct {
	Type      string
	Key       string
	Context   map[string]interface{}
	Timestamp time.Time
}

// PerformanceResult holds performance optimization results
type PerformanceResult struct {
	ProcessingTime time.Duration
	CacheHit       bool
	MemoryUsed     int64
	Optimized      bool
	Metrics        map[string]interface{}
}

// NewPerformanceOptimizer creates a new performance optimizer
func NewPerformanceOptimizer(config *PerformanceConfig) *PerformanceOptimizer {
	if config == nil {
		config = &PerformanceConfig{
			PolicyCacheTTL:      5 * time.Minute,
			ValidationCacheTTL:  1 * time.Minute,
			RateLimitCacheTTL:   30 * time.Second,
			PolicyCacheSize:     1000,
			ValidationCacheSize: 5000,
			RateLimitCacheSize:  10000,
			MaxProcessingTime:   100 * time.Millisecond,
			MaxMemoryUsage:      104857600, // 100MB
			EnableCaching:       true,
			EnablePooling:       true,
			EnableMetrics:       true,
			EnableCompression:   true,
		}
	}

	optimizer := &PerformanceOptimizer{
		config:  config,
		metrics: &SecurityPerformanceMetrics{},
	}

	// Initialize caches
	if config.EnableCaching {
		optimizer.policyCache = make(map[string]*CacheEntry)
		optimizer.validationCache = make(map[string]*CacheEntry)
		optimizer.rateLimitCache = make(map[string]*CacheEntry)
	}

	// Initialize connection pool
	if config.EnablePooling {
		optimizer.connectionPool = sync.Pool{
			New: func() interface{} {
				return &SecurityConnection{
					CreatedAt: time.Now(),
					LastUsed:  time.Now(),
				}
			},
		}
	}

	return optimizer
}

// SecurityConnection represents a pooled security connection
type SecurityConnection struct {
	CreatedAt time.Time
	LastUsed  time.Time
	InUse     bool
}

// OptimizePolicyEvaluation optimizes policy evaluation performance
func (po *PerformanceOptimizer) OptimizePolicyEvaluation(ctx context.Context, policyKey string, evaluationFunc func() (interface{}, error)) (interface{}, *PerformanceResult, error) {
	start := time.Now()
	result := &PerformanceResult{}

	// Check cache first
	if po.config.EnableCaching && po.policyCache != nil {
		po.mu.RLock()
		if entry, found := po.policyCache[policyKey]; found && entry.ExpiresAt.After(time.Now()) {
			po.mu.RUnlock()
			if po.metrics != nil {
				po.metrics.mu.Lock()
				po.metrics.PolicyCacheHits++
				po.metrics.mu.Unlock()
			}
			result.ProcessingTime = time.Since(start)
			result.CacheHit = true
			result.Optimized = true
			return entry.Value, result, nil
		}
		po.mu.RUnlock()
		
		if po.metrics != nil {
			po.metrics.mu.Lock()
			po.metrics.PolicyCacheMisses++
			po.metrics.mu.Unlock()
		}
	}

	// Execute with timeout
	resultChan := make(chan interface{}, 1)
	errorChan := make(chan error, 1)

	go func() {
		evalResult, err := evaluationFunc()
		if err != nil {
			errorChan <- err
			return
		}
		resultChan <- evalResult
	}()

	select {
	case evalResult := <-resultChan:
		// Cache the result
		if po.config.EnableCaching && po.policyCache != nil {
			po.mu.Lock()
			po.policyCache[policyKey] = &CacheEntry{
				Value:     evalResult,
				ExpiresAt: time.Now().Add(po.config.PolicyCacheTTL),
				CreatedAt: time.Now(),
			}
			po.mu.Unlock()
		}
		
		result.ProcessingTime = time.Since(start)
		result.CacheHit = false
		result.Optimized = true
		
		if po.metrics != nil {
			po.metrics.mu.Lock()
			po.metrics.PolicyEvaluationCount++
			po.metrics.PolicyEvaluationTime += result.ProcessingTime
			po.metrics.mu.Unlock()
		}
		
		return evalResult, result, nil
		
	case err := <-errorChan:
		if po.metrics != nil {
			po.metrics.mu.Lock()
			po.metrics.SecurityErrors++
			po.metrics.mu.Unlock()
		}
		return nil, result, err
		
	case <-time.After(po.config.MaxProcessingTime):
		if po.metrics != nil {
			po.metrics.mu.Lock()
			po.metrics.TimeoutErrors++
			po.metrics.mu.Unlock()
		}
		return nil, result, ErrProcessingTimeout
		
	case <-ctx.Done():
		return nil, result, ctx.Err()
	}
}

// OptimizeValidation optimizes input validation performance
func (po *PerformanceOptimizer) OptimizeValidation(ctx context.Context, validationKey string, validationFunc func() (bool, error)) (bool, *PerformanceResult, error) {
	start := time.Now()
	result := &PerformanceResult{}

	// Check cache first
	if po.config.EnableCaching && po.validationCache != nil {
		po.mu.RLock()
		if entry, found := po.validationCache[validationKey]; found && entry.ExpiresAt.After(time.Now()) {
			po.mu.RUnlock()
			if po.metrics != nil {
				po.metrics.mu.Lock()
				po.metrics.ValidationCacheHits++
				po.metrics.mu.Unlock()
			}
			result.ProcessingTime = time.Since(start)
			result.CacheHit = true
			result.Optimized = true
			return entry.Value.(bool), result, nil
		}
		po.mu.RUnlock()
		
		if po.metrics != nil {
			po.metrics.mu.Lock()
			po.metrics.ValidationCacheMisses++
			po.metrics.mu.Unlock()
		}
	}

	// Execute validation
	valid, err := validationFunc()
	if err != nil {
		if po.metrics != nil {
			po.metrics.mu.Lock()
			po.metrics.SecurityErrors++
			po.metrics.mu.Unlock()
		}
		return false, result, err
	}

	// Cache the result
	if po.config.EnableCaching && po.validationCache != nil {
		po.mu.Lock()
		po.validationCache[validationKey] = &CacheEntry{
			Value:     valid,
			ExpiresAt: time.Now().Add(po.config.ValidationCacheTTL),
			CreatedAt: time.Now(),
		}
		po.mu.Unlock()
	}

	result.ProcessingTime = time.Since(start)
	result.CacheHit = false
	result.Optimized = true

	if po.metrics != nil {
		po.metrics.mu.Lock()
		po.metrics.ValidationCount++
		po.metrics.ValidationTime += result.ProcessingTime
		po.metrics.mu.Unlock()
	}

	return valid, result, nil
}

// OptimizeRateLimit optimizes rate limiting performance
func (po *PerformanceOptimizer) OptimizeRateLimit(ctx context.Context, rateLimitKey string, checkFunc func() (bool, error)) (bool, *PerformanceResult, error) {
	start := time.Now()
	result := &PerformanceResult{}

	// Execute rate limit check
	allowed, err := checkFunc()
	if err != nil {
		if po.metrics != nil {
			po.metrics.mu.Lock()
			po.metrics.SecurityErrors++
			po.metrics.mu.Unlock()
		}
		return false, result, err
	}

	result.ProcessingTime = time.Since(start)
	result.Optimized = true

	if po.metrics != nil {
		po.metrics.mu.Lock()
		po.metrics.RateLimitCheckCount++
		po.metrics.RateLimitCheckTime += result.ProcessingTime
		po.metrics.mu.Unlock()
	}

	return allowed, result, nil
}

// GetConnection gets a connection from the pool
func (po *PerformanceOptimizer) GetConnection() *SecurityConnection {
	if !po.config.EnablePooling {
		return &SecurityConnection{
			CreatedAt: time.Now(),
			LastUsed:  time.Now(),
		}
	}

	conn := po.connectionPool.Get().(*SecurityConnection)
	conn.LastUsed = time.Now()
	conn.InUse = true
	return conn
}

// ReleaseConnection returns a connection to the pool
func (po *PerformanceOptimizer) ReleaseConnection(conn *SecurityConnection) {
	if !po.config.EnablePooling || conn == nil {
		return
	}

	conn.InUse = false
	conn.LastUsed = time.Now()
	po.connectionPool.Put(conn)
}

// GetMetrics returns current performance metrics
func (po *PerformanceOptimizer) GetMetrics() map[string]interface{} {
	po.mu.RLock()
	defer po.mu.RUnlock()

	metrics := make(map[string]interface{})
	
	if po.policyCache != nil {
		metrics["policy_cache_items"] = len(po.policyCache)
	}
	
	if po.validationCache != nil {
		metrics["validation_cache_items"] = len(po.validationCache)
	}
	
	if po.rateLimitCache != nil {
		metrics["rate_limit_cache_items"] = len(po.rateLimitCache)
	}

	if po.metrics != nil {
		po.metrics.mu.RLock()
		metrics["performance"] = map[string]interface{}{
			"policy_evaluation_count": po.metrics.PolicyEvaluationCount,
			"validation_count":        po.metrics.ValidationCount,
			"rate_limit_check_count":  po.metrics.RateLimitCheckCount,
			"policy_cache_hits":       po.metrics.PolicyCacheHits,
			"policy_cache_misses":     po.metrics.PolicyCacheMisses,
			"validation_cache_hits":   po.metrics.ValidationCacheHits,
			"validation_cache_misses": po.metrics.ValidationCacheMisses,
			"security_errors":         po.metrics.SecurityErrors,
			"timeout_errors":          po.metrics.TimeoutErrors,
		}
		po.metrics.mu.RUnlock()
	}

	metrics["config"] = po.config
	
	return metrics
}

// ClearCaches clears all caches
func (po *PerformanceOptimizer) ClearCaches() {
	po.mu.Lock()
	defer po.mu.Unlock()

	if po.policyCache != nil {
		po.policyCache = make(map[string]*CacheEntry)
	}
	
	if po.validationCache != nil {
		po.validationCache = make(map[string]*CacheEntry)
	}
	
	if po.rateLimitCache != nil {
		po.rateLimitCache = make(map[string]*CacheEntry)
	}
}

// CleanupExpiredEntries removes expired cache entries
func (po *PerformanceOptimizer) CleanupExpiredEntries() {
	po.mu.Lock()
	defer po.mu.Unlock()

	now := time.Now()

	// Clean policy cache
	if po.policyCache != nil {
		for key, entry := range po.policyCache {
			if entry.ExpiresAt.Before(now) {
				delete(po.policyCache, key)
			}
		}
	}

	// Clean validation cache
	if po.validationCache != nil {
		for key, entry := range po.validationCache {
			if entry.ExpiresAt.Before(now) {
				delete(po.validationCache, key)
			}
		}
	}

	// Clean rate limit cache
	if po.rateLimitCache != nil {
		for key, entry := range po.rateLimitCache {
			if entry.ExpiresAt.Before(now) {
				delete(po.rateLimitCache, key)
			}
		}
	}
}

// UpdateConfig updates the performance configuration
func (po *PerformanceOptimizer) UpdateConfig(config *PerformanceConfig) {
	po.mu.Lock()
	defer po.mu.Unlock()
	
	po.config = config
	
	// Reinitialize caches if needed
	if config.EnableCaching {
		if po.policyCache == nil {
			po.policyCache = make(map[string]*CacheEntry)
		}
		if po.validationCache == nil {
			po.validationCache = make(map[string]*CacheEntry)
		}
		if po.rateLimitCache == nil {
			po.rateLimitCache = make(map[string]*CacheEntry)
		}
	}
}

// Shutdown gracefully shuts down the performance optimizer
func (po *PerformanceOptimizer) Shutdown(ctx context.Context) error {
	po.mu.Lock()
	defer po.mu.Unlock()

	// Clear caches
	if po.policyCache != nil {
		po.policyCache = nil
	}
	if po.validationCache != nil {
		po.validationCache = nil
	}
	if po.rateLimitCache != nil {
		po.rateLimitCache = nil
	}

	return nil
}

// Performance optimization errors
var (
	ErrProcessingTimeout   = errors.New("security processing timeout")
	ErrMemoryLimitExceeded = errors.New("memory limit exceeded")
	ErrCacheNotAvailable   = errors.New("cache not available")
)