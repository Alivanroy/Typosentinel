package security

import (
	"context"
	"fmt"
	"runtime"
	"sync/atomic"
	"time"
)

// NewLoadShedder creates a new load shedder
func NewLoadShedder(config *GracefulDegradationConfig) *LoadShedder {
	return &LoadShedder{
		config:       config,
		sheddingRate: 0.0,
		prioritizer:  NewRequestPrioritizer(),
	}
}

// NewRequestPrioritizer creates a new request prioritizer
func NewRequestPrioritizer() *RequestPrioritizer {
	return &RequestPrioritizer{
		priorities: map[string]int{
			"threat_lookup":       1, // Highest priority
			"vulnerability_check": 2,
			"package_scan":        3, // Lowest priority
		},
	}
}

// ShouldShedRequest determines if a request should be shed
func (ls *LoadShedder) ShouldShedRequest(req *Request) bool {
	ls.mu.Lock()
	defer ls.mu.Unlock()

	atomic.AddInt64(&ls.requestCounter, 1)

	// Check if load shedding is needed
	if ls.currentLoad < ls.config.LoadSheddingThreshold {
		return false
	}

	// Calculate shedding probability based on priority
	priority := ls.prioritizer.GetPriority(req.Type)
	sheddingProbability := ls.sheddingRate * (1.0 + float64(priority-1)*0.2)

	// Simple probabilistic shedding
	if float64(time.Now().UnixNano()%100)/100.0 < sheddingProbability {
		atomic.AddInt64(&ls.droppedCounter, 1)
		return true
	}

	return false
}

// UpdateLoad updates the current load for the load shedder
func (ls *LoadShedder) UpdateLoad(load float64) {
	ls.mu.Lock()
	defer ls.mu.Unlock()

	ls.currentLoad = load

	// Adjust shedding rate based on load
	if load > ls.config.CriticalThreshold {
		ls.sheddingRate = ls.config.MaxSheddingRate
	} else if load > ls.config.LoadSheddingThreshold {
		ls.sheddingRate = ls.config.SheddingRate * (load - ls.config.LoadSheddingThreshold) / (ls.config.CriticalThreshold - ls.config.LoadSheddingThreshold)
	} else {
		ls.sheddingRate = 0.0
	}
}

// GetPriority returns the priority for a request type
func (rp *RequestPrioritizer) GetPriority(requestType string) int {
	rp.mu.RLock()
	defer rp.mu.RUnlock()

	if priority, exists := rp.priorities[requestType]; exists {
		return priority
	}
	return 5 // Default low priority
}

// NewBackpressureManager creates a new backpressure manager
func NewBackpressureManager(config *GracefulDegradationConfig) *BackpressureManager {
	return &BackpressureManager{
		config:       config,
		requestQueue: make(chan *Request, config.MaxQueueSize),
		maxQueueSize: int64(config.MaxQueueSize),
	}
}

// ApplyBackpressure applies backpressure to incoming requests
func (bm *BackpressureManager) ApplyBackpressure(ctx context.Context, req *Request) error {
	bm.mu.Lock()
	currentQueueSize := bm.queueSize
	bm.mu.Unlock()

	// Check if queue is full
	if currentQueueSize >= bm.maxQueueSize {
		return fmt.Errorf("request queue full, applying backpressure")
	}

	// Try to add request to queue with timeout
	select {
	case bm.requestQueue <- req:
		atomic.AddInt64(&bm.queueSize, 1)
		return nil
	case <-time.After(bm.config.QueueTimeout):
		return fmt.Errorf("queue timeout exceeded")
	case <-ctx.Done():
		return ctx.Err()
	}
}

// ProcessQueue processes requests from the backpressure queue
func (bm *BackpressureManager) ProcessQueue(ctx context.Context, processor func(*Request) (interface{}, error)) {
	for {
		select {
		case req := <-bm.requestQueue:
			atomic.AddInt64(&bm.queueSize, -1)
			result, err := processor(req)
			if req.Callback != nil {
				req.Callback(result, err)
			}
		case <-ctx.Done():
			return
		}
	}
}

// NewFallbackManager creates a new fallback manager
func NewFallbackManager(config *GracefulDegradationConfig) *FallbackManager {
	return &FallbackManager{
		config:        config,
		fallbackModes: make(map[string]bool),
		fallbackCache: NewFallbackCache(config.FallbackTimeout, 1000),
	}
}

// NewFallbackCache creates a new fallback cache
func NewFallbackCache(ttl time.Duration, maxEntries int) *FallbackCache {
	return &FallbackCache{
		cache:      make(map[string]*FallbackCacheEntry),
		ttl:        ttl,
		maxEntries: maxEntries,
	}
}

// TryFallback attempts to serve request from fallback mechanisms
func (fm *FallbackManager) TryFallback(ctx context.Context, req *Request) (interface{}, error) {
	fm.mu.RLock()
	cacheOnlyMode := fm.cacheOnlyMode
	reducedFeatures := fm.reducedFeatures
	fm.mu.RUnlock()

	// Try cache first
	if cached := fm.fallbackCache.Get(req.ID); cached != nil {
		return cached.Value, nil
	}

	// If in cache-only mode, return error if not in cache
	if cacheOnlyMode {
		return nil, fmt.Errorf("cache-only mode: no cached result available")
	}

	// If in reduced feature mode, return simplified response
	if reducedFeatures {
		return fm.getReducedResponse(req), nil
	}

	return nil, fmt.Errorf("no fallback available")
}

// getReducedResponse returns a simplified response for reduced feature mode
func (fm *FallbackManager) getReducedResponse(req *Request) interface{} {
	switch req.Type {
	case "threat_lookup":
		return map[string]interface{}{
			"threat_level": "unknown",
			"confidence":   0.5,
			"fallback":     true,
		}
	case "package_scan":
		return map[string]interface{}{
			"scan_result": "skipped",
			"fallback":    true,
		}
	case "vulnerability_check":
		return map[string]interface{}{
			"vulnerabilities": []string{},
			"severity":        "unknown",
			"fallback":        true,
		}
	default:
		return map[string]interface{}{
			"result":   "fallback",
			"fallback": true,
		}
	}
}

// Get retrieves a value from the fallback cache
func (fc *FallbackCache) Get(key string) *FallbackCacheEntry {
	fc.mu.RLock()
	defer fc.mu.RUnlock()

	entry, exists := fc.cache[key]
	if !exists {
		return nil
	}

	// Check if entry has expired
	if time.Since(entry.CreatedAt) > entry.TTL {
		delete(fc.cache, key)
		return nil
	}

	return entry
}

// Set stores a value in the fallback cache
func (fc *FallbackCache) Set(key string, value interface{}) {
	fc.mu.Lock()
	defer fc.mu.Unlock()

	// Remove oldest entries if cache is full
	if len(fc.cache) >= fc.maxEntries {
		fc.evictOldest()
	}

	fc.cache[key] = &FallbackCacheEntry{
		Value:     value,
		CreatedAt: time.Now(),
		TTL:       fc.ttl,
	}
}

// evictOldest removes the oldest entry from the cache
func (fc *FallbackCache) evictOldest() {
	var oldestKey string
	var oldestTime time.Time

	for key, entry := range fc.cache {
		if oldestKey == "" || entry.CreatedAt.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.CreatedAt
		}
	}

	if oldestKey != "" {
		delete(fc.cache, oldestKey)
	}
}

// NewServiceHealthMonitor creates a new service health monitor
func NewServiceHealthMonitor(config *GracefulDegradationConfig) *ServiceHealthMonitor {
	return &ServiceHealthMonitor{
		config:         config,
		services:       make(map[string]*ServiceHealth),
		healthCheckers: make(map[string]HealthChecker),
		overallHealth:  Healthy,
	}
}

// RegisterHealthChecker registers a health checker for a service
func (shm *ServiceHealthMonitor) RegisterHealthChecker(name string, checker HealthChecker) {
	shm.mu.Lock()
	defer shm.mu.Unlock()

	shm.healthCheckers[name] = checker
	shm.services[name] = &ServiceHealth{
		Name:   name,
		Status: Healthy,
	}
}

// CheckHealth performs health checks on all registered services
func (shm *ServiceHealthMonitor) CheckHealth(ctx context.Context) {
	shm.mu.Lock()
	defer shm.mu.Unlock()

	overallHealthy := true

	for name, checker := range shm.healthCheckers {
		service := shm.services[name]
		start := time.Now()

		err := checker.Check(ctx)
		latency := time.Since(start)

		service.LastCheck = time.Now()
		service.Latency = latency

		if err != nil {
			service.ConsecutiveFails++
			service.ConsecutiveOKs = 0

			if service.ConsecutiveFails >= shm.config.UnhealthyThreshold {
				service.Status = Unhealthy
				overallHealthy = false
			}
		} else {
			service.ConsecutiveOKs++
			service.ConsecutiveFails = 0

			if service.ConsecutiveOKs >= shm.config.RecoveryThreshold {
				service.Status = Healthy
			}
		}
	}

	// Update overall health
	if overallHealthy {
		shm.overallHealth = Healthy
	} else {
		shm.overallHealth = Unhealthy
	}
}

// GetServiceHealth returns health status for a specific service
func (shm *ServiceHealthMonitor) GetServiceHealth(name string) *ServiceHealth {
	shm.mu.RLock()
	defer shm.mu.RUnlock()

	if service, exists := shm.services[name]; exists {
		// Return a copy to avoid race conditions
		serviceCopy := *service
		return &serviceCopy
	}
	return nil
}

// NewGracefulResourceMonitor creates a new graceful resource monitor
func NewGracefulResourceMonitor(config *GracefulDegradationConfig) *GracefulResourceMonitor {
	return &GracefulResourceMonitor{
		config: config,
	}
}

// UpdateMetrics updates resource metrics
func (grm *GracefulResourceMonitor) UpdateMetrics() {
	grm.mu.Lock()
	defer grm.mu.Unlock()

	// Get current resource usage
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	grm.memoryUsage = int64(memStats.Alloc)
	grm.goroutineCount = runtime.NumGoroutine()
	grm.lastUpdate = time.Now()

	// Calculate load average (simplified)
	grm.loadAverage = float64(grm.goroutineCount) / 1000.0
	if grm.memoryUsage > grm.config.MemoryThreshold {
		grm.loadAverage += 0.3
	}
}

// GetLoadAverage returns the current load average
func (grm *GracefulResourceMonitor) GetLoadAverage() float64 {
	grm.mu.RLock()
	defer grm.mu.RUnlock()
	return grm.loadAverage
}
