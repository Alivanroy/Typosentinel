package optimization

import (
	"context"
	"encoding/json"
	"log"
	"sync"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/cache"
	"github.com/Alivanroy/Typosentinel/internal/database"
	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// CacheManager provides comprehensive caching strategies
type CacheManager struct {
	l1Cache       *L1Cache       // In-memory cache
	l2Cache       *L2Cache       // File-based cache
	l3Cache       *L3Cache       // Redis cache (optional)
	cacheWarmer   *CacheWarmer   // Proactive cache warming
	cacheAnalyzer *CacheAnalyzer // Cache performance analysis
	config        *CacheConfig
	metrics       *CacheMetrics
	cancel        context.CancelFunc // Context cancel function
	mu            sync.RWMutex
}

// L1Cache represents the fastest in-memory cache layer
type L1Cache struct {
	data          map[string]*CacheEntry
	ttl           time.Duration
	maxSize       int
	maxMemory     int64
	currentMemory int64
	hitCount      int64
	missCount     int64
	mu            sync.RWMutex
}

// L2Cache represents file-based persistent cache
type L2Cache struct {
	fileCache *cache.CacheIntegration
	ttl       time.Duration
	hitCount  int64
	missCount int64
	mu        sync.RWMutex
}

// L3Cache represents distributed Redis cache
type L3Cache struct {
	redisClient interface{} // Redis client interface
	ttl         time.Duration
	hitCount    int64
	missCount   int64
	mu          sync.RWMutex
}

// CacheEntry represents a cached item with metadata
type CacheEntry struct {
	Key         string
	Value       interface{}
	Timestamp   time.Time
	TTL         time.Duration
	AccessCount int64
	LastAccess  time.Time
	Size        int64
	Tags        []string
	Priority    CachePriority
}

// CachePriority defines cache entry priority levels
type CachePriority int

const (
	PriorityLow CachePriority = iota
	PriorityNormal
	PriorityHigh
	PriorityCritical
)

// CacheWarmer proactively warms cache with frequently accessed data
type CacheWarmer struct {
	manager      *CacheManager
	db           *database.ThreatDB
	warmingRules []*WarmingRule
	schedule     *WarmingSchedule
	ctx          context.Context
	cancel       context.CancelFunc
	mu           sync.RWMutex
}

// WarmingRule defines conditions for cache warming
type WarmingRule struct {
	Name       string
	Condition  func() bool
	DataLoader func() (interface{}, error)
	CacheKey   string
	Priority   CachePriority
	TTL        time.Duration
	Schedule   string // Cron-like schedule
	Enabled    bool
}

// WarmingSchedule manages cache warming schedules
type WarmingSchedule struct {
	rules   []*ScheduledRule
	ticker  *time.Ticker
	running bool
	mu      sync.RWMutex
}

// ScheduledRule represents a scheduled cache warming rule
type ScheduledRule struct {
	Rule     *WarmingRule
	NextRun  time.Time
	Interval time.Duration
	Enabled  bool
}

// CacheAnalyzer analyzes cache performance and provides insights
type CacheAnalyzer struct {
	metrics         *CacheMetrics
	performanceLog  []*CacheOperation
	analysisRules   []*AnalysisRule
	recommendations []*CacheRecommendation
	mu              sync.RWMutex
}

// CacheOperation represents a cache operation for analysis
type CacheOperation struct {
	Type      string // GET, SET, DELETE, EVICT
	Key       string
	Layer     string // L1, L2, L3
	Timestamp time.Time
	Duration  time.Duration
	Hit       bool
	Size      int64
}

// AnalysisRule defines rules for cache analysis
type AnalysisRule struct {
	Name      string
	Condition func(*CacheMetrics) bool
	Action    func(*CacheManager) error
	Enabled   bool
}

// CacheRecommendation provides optimization suggestions
type CacheRecommendation struct {
	Type        string
	Description string
	Impact      string
	Action      string
	Timestamp   time.Time
}

// CacheConfig contains cache configuration
type CacheConfig struct {
	L1Config *L1Config
	L2Config *L2Config
	L3Config *L3Config
	Warming  *WarmingConfig
	Analysis *AnalysisConfig
}

// L1Config configures in-memory cache
type L1Config struct {
	MaxSize        int
	MaxMemory      int64
	DefaultTTL     time.Duration
	EvictionPolicy string // LRU, LFU, FIFO
}

// L2Config configures file-based cache
type L2Config struct {
	CacheDir    string
	MaxSize     int64
	DefaultTTL  time.Duration
	Compression bool
	Encryption  bool
}

// L3Config configures Redis cache
type L3Config struct {
	Enabled    bool
	RedisURL   string
	DefaultTTL time.Duration
	MaxRetries int
	RetryDelay time.Duration
}

// WarmingConfig configures cache warming
type WarmingConfig struct {
	Enabled         bool
	WarmingInterval time.Duration
	MaxConcurrency  int
	PredictiveMode  bool
}

// AnalysisConfig configures cache analysis
type AnalysisConfig struct {
	Enabled          bool
	AnalysisInterval time.Duration
	RetentionPeriod  time.Duration
	Recommendations  bool
}

// CacheMetrics tracks cache performance
type CacheMetrics struct {
	L1Metrics *LayerMetrics
	L2Metrics *LayerMetrics
	L3Metrics *LayerMetrics
	Overall   *OverallMetrics
	mu        sync.RWMutex
}

// LayerMetrics tracks metrics for a specific cache layer
type LayerMetrics struct {
	Hits        int64
	Misses      int64
	Sets        int64
	Deletes     int64
	Evictions   int64
	HitRatio    float64
	AvgLatency  time.Duration
	MemoryUsage int64
	EntryCount  int64
	LastUpdated time.Time
}

// OverallMetrics tracks overall cache performance
type OverallMetrics struct {
	TotalHits       int64
	TotalMisses     int64
	OverallHitRatio float64
	AvgLatency      time.Duration
	TotalMemory     int64
	Efficiency      float64
	LastUpdated     time.Time
}

// NewCacheManager creates a new comprehensive cache manager
func NewCacheManager(config *CacheConfig, db *database.ThreatDB) *CacheManager {
	ctx, cancel := context.WithCancel(context.Background())

	// Initialize L1 cache
	l1 := &L1Cache{
		data:      make(map[string]*CacheEntry),
		ttl:       config.L1Config.DefaultTTL,
		maxSize:   config.L1Config.MaxSize,
		maxMemory: config.L1Config.MaxMemory,
	}

	// Initialize L2 cache
	cacheConfig := &cache.CacheConfig{
		Enabled:  true,
		CacheDir: config.L2Config.CacheDir,
		TTL:      config.L2Config.DefaultTTL,
	}
	fileCache, err := cache.NewCacheIntegration(cacheConfig)
	if err != nil {
		log.Printf("Failed to initialize L2 cache: %v", err)
		fileCache = nil
	}
	l2 := &L2Cache{
		fileCache: fileCache,
		ttl:       config.L2Config.DefaultTTL,
	}

	// Initialize L3 cache (Redis)
	var l3 *L3Cache
	if config.L3Config.Enabled {
		l3 = &L3Cache{
			// Redis client would be initialized here
			ttl: config.L3Config.DefaultTTL,
		}
	}

	// Initialize cache manager
	cm := &CacheManager{
		l1Cache: l1,
		l2Cache: l2,
		l3Cache: l3,
		config:  config,
		cancel:  cancel,
		metrics: &CacheMetrics{
			L1Metrics: &LayerMetrics{},
			L2Metrics: &LayerMetrics{},
			L3Metrics: &LayerMetrics{},
			Overall:   &OverallMetrics{},
		},
	}

	// Initialize cache warmer
	if config.Warming.Enabled {
		cm.cacheWarmer = &CacheWarmer{
			manager: cm,
			db:      db,
			ctx:     ctx,
			cancel:  cancel,
		}
		cm.initializeWarmingRules()
		go cm.cacheWarmer.start()
	}

	// Initialize cache analyzer
	if config.Analysis.Enabled {
		cm.cacheAnalyzer = &CacheAnalyzer{
			metrics:         cm.metrics,
			performanceLog:  make([]*CacheOperation, 0),
			recommendations: make([]*CacheRecommendation, 0),
		}
		cm.initializeAnalysisRules()
		go cm.startAnalysis()
	}

	// Start background processes
	go cm.startMetricsCollection()
	go cm.startEvictionProcess()

	return cm
}

// Get retrieves a value from the cache hierarchy
func (cm *CacheManager) Get(key string) (interface{}, bool) {
	start := time.Now()
	defer func() {
		duration := time.Since(start)
		cm.recordOperation("GET", key, "", duration, false, 0)
	}()

	// Try L1 cache first
	if value, found := cm.l1Cache.get(key); found {
		cm.recordOperation("GET", key, "L1", time.Since(start), true, 0)
		return value, true
	}

	// Try L2 cache
	if value, found := cm.l2Cache.get(key); found {
		// Promote to L1
		cm.l1Cache.set(key, value, cm.l1Cache.ttl, PriorityNormal)
		cm.recordOperation("GET", key, "L2", time.Since(start), true, 0)
		return value, true
	}

	// Try L3 cache if enabled
	if cm.l3Cache != nil {
		if value, found := cm.l3Cache.get(key); found {
			// Promote to L1 and L2
			cm.l1Cache.set(key, value, cm.l1Cache.ttl, PriorityNormal)
			cm.l2Cache.set(key, value, cm.l2Cache.ttl)
			cm.recordOperation("GET", key, "L3", time.Since(start), true, 0)
			return value, true
		}
	}

	return nil, false
}

// Set stores a value in the cache hierarchy
func (cm *CacheManager) Set(key string, value interface{}, ttl time.Duration, priority CachePriority) {
	start := time.Now()
	defer func() {
		duration := time.Since(start)
		cm.recordOperation("SET", key, "ALL", duration, false, 0)
	}()

	// Store in all cache layers based on priority
	cm.l1Cache.set(key, value, ttl, priority)

	if priority >= PriorityNormal {
		cm.l2Cache.set(key, value, ttl)
	}

	if cm.l3Cache != nil && priority >= PriorityHigh {
		cm.l3Cache.set(key, value, ttl)
	}
}

// Delete removes a value from all cache layers
func (cm *CacheManager) Delete(key string) {
	cm.l1Cache.delete(key)
	cm.l2Cache.delete(key)
	if cm.l3Cache != nil {
		cm.l3Cache.delete(key)
	}
	cm.recordOperation("DELETE", key, "ALL", 0, false, 0)
}

// InvalidateByTags removes all entries with specified tags
func (cm *CacheManager) InvalidateByTags(tags []string) {
	cm.l1Cache.invalidateByTags(tags)
	// L2 and L3 tag invalidation would be implemented here
}

// L1 Cache methods
func (l1 *L1Cache) get(key string) (interface{}, bool) {
	l1.mu.RLock()
	defer l1.mu.RUnlock()

	entry, exists := l1.data[key]
	if !exists {
		l1.missCount++
		return nil, false
	}

	// Check TTL
	if time.Since(entry.Timestamp) > entry.TTL {
		delete(l1.data, key)
		l1.missCount++
		return nil, false
	}

	// Update access statistics
	entry.AccessCount++
	entry.LastAccess = time.Now()
	l1.hitCount++

	return entry.Value, true
}

func (l1 *L1Cache) set(key string, value interface{}, ttl time.Duration, priority CachePriority) {
	l1.mu.Lock()
	defer l1.mu.Unlock()

	// Calculate entry size
	size := l1.calculateSize(value)

	// Check memory limits
	if l1.currentMemory+size > l1.maxMemory {
		l1.evictByMemory(size)
	}

	// Check size limits
	if len(l1.data) >= l1.maxSize {
		l1.evictLRU()
	}

	entry := &CacheEntry{
		Key:         key,
		Value:       value,
		Timestamp:   time.Now(),
		TTL:         ttl,
		AccessCount: 0,
		LastAccess:  time.Now(),
		Size:        size,
		Priority:    priority,
	}

	l1.data[key] = entry
	l1.currentMemory += size
}

func (l1 *L1Cache) delete(key string) {
	l1.mu.Lock()
	defer l1.mu.Unlock()

	if entry, exists := l1.data[key]; exists {
		l1.currentMemory -= entry.Size
		delete(l1.data, key)
	}
}

func (l1 *L1Cache) invalidateByTags(tags []string) {
	l1.mu.Lock()
	defer l1.mu.Unlock()

	for key, entry := range l1.data {
		for _, tag := range tags {
			for _, entryTag := range entry.Tags {
				if tag == entryTag {
					l1.currentMemory -= entry.Size
					delete(l1.data, key)
					break
				}
			}
		}
	}
}

func (l1 *L1Cache) calculateSize(value interface{}) int64 {
	// Estimate memory size of the value
	data, _ := json.Marshal(value)
	return int64(len(data))
}

func (l1 *L1Cache) evictLRU() {
	oldestKey := ""
	oldestTime := time.Now()

	for key, entry := range l1.data {
		if entry.LastAccess.Before(oldestTime) {
			oldestTime = entry.LastAccess
			oldestKey = key
		}
	}

	if oldestKey != "" {
		l1.currentMemory -= l1.data[oldestKey].Size
		delete(l1.data, oldestKey)
	}
}

func (l1 *L1Cache) evictByMemory(requiredSize int64) {
	// Evict entries until we have enough memory
	for l1.currentMemory+requiredSize > l1.maxMemory && len(l1.data) > 0 {
		l1.evictLRU()
	}
}

// L2 Cache methods
func (l2 *L2Cache) get(key string) (interface{}, bool) {
	l2.mu.RLock()
	defer l2.mu.RUnlock()

	// Use existing file cache implementation
	if result, found, err := l2.fileCache.GetCachedAnalysisResult(key); err == nil && found {
		l2.hitCount++
		return result, true
	}

	l2.missCount++
	return nil, false
}

func (l2 *L2Cache) set(key string, value interface{}, ttl time.Duration) {
	l2.mu.Lock()
	defer l2.mu.Unlock()

	// Type assert value to *types.DependencyTree for file cache
	if tree, ok := value.(*types.DependencyTree); ok {
		l2.fileCache.Set(key, tree, nil, nil)
	}
}

func (l2 *L2Cache) delete(key string) {
	// File cache deletion would be implemented here
	// Current cache implementation doesn't have delete method
}

// L3 Cache methods (Redis implementation would go here)
func (l3 *L3Cache) get(key string) (interface{}, bool) {
	// Redis GET implementation
	return nil, false
}

func (l3 *L3Cache) set(key string, value interface{}, ttl time.Duration) {
	// Redis SET implementation
}

func (l3 *L3Cache) delete(key string) {
	// Redis DELETE implementation
}

// Cache warming methods
func (cm *CacheManager) initializeWarmingRules() {
	rules := []*WarmingRule{
		{
			Name: "PopularThreats",
			Condition: func() bool {
				return time.Now().Hour() == 6 // Warm at 6 AM
			},
			DataLoader: func() (interface{}, error) {
				// Load most accessed threats
				return cm.cacheWarmer.db.GetThreats("", "", 100)
			},
			CacheKey: "popular_threats",
			Priority: PriorityHigh,
			TTL:      24 * time.Hour,
			Enabled:  true,
		},
		{
			Name: "CriticalPackages",
			Condition: func() bool {
				return true // Always warm critical packages
			},
			DataLoader: func() (interface{}, error) {
				// Load critical package threats
				return cm.cacheWarmer.db.GetThreats("", "critical", 50)
			},
			CacheKey: "critical_packages",
			Priority: PriorityCritical,
			TTL:      12 * time.Hour,
			Enabled:  true,
		},
	}

	cm.cacheWarmer.warmingRules = rules
}

func (cw *CacheWarmer) start() {
	ticker := time.NewTicker(cw.manager.config.Warming.WarmingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			cw.executeWarmingRules()
		case <-cw.ctx.Done():
			return
		}
	}
}

func (cw *CacheWarmer) executeWarmingRules() {
	for _, rule := range cw.warmingRules {
		if rule.Enabled && rule.Condition() {
			go cw.executeRule(rule)
		}
	}
}

func (cw *CacheWarmer) executeRule(rule *WarmingRule) {
	data, err := rule.DataLoader()
	if err != nil {
		log.Printf("Cache warming failed for rule %s: %v", rule.Name, err)
		return
	}

	cw.manager.Set(rule.CacheKey, data, rule.TTL, rule.Priority)
	log.Printf("Cache warmed for rule: %s", rule.Name)
}

// Cache analysis methods
func (cm *CacheManager) initializeAnalysisRules() {
	rules := []*AnalysisRule{
		{
			Name: "LowHitRatio",
			Condition: func(metrics *CacheMetrics) bool {
				return metrics.Overall.OverallHitRatio < 0.7
			},
			Action: func(manager *CacheManager) error {
				// Suggest cache warming or TTL adjustment
				recommendation := &CacheRecommendation{
					Type:        "HitRatio",
					Description: "Cache hit ratio is below 70%",
					Impact:      "High",
					Action:      "Consider implementing cache warming or adjusting TTL values",
					Timestamp:   time.Now(),
				}
				manager.cacheAnalyzer.addRecommendation(recommendation)
				return nil
			},
			Enabled: true,
		},
		{
			Name: "HighMemoryUsage",
			Condition: func(metrics *CacheMetrics) bool {
				return float64(metrics.L1Metrics.MemoryUsage)/float64(1024*1024*1024) > 0.8 // 80% of 1GB
			},
			Action: func(manager *CacheManager) error {
				// Trigger aggressive eviction
				manager.l1Cache.evictByMemory(0)
				recommendation := &CacheRecommendation{
					Type:        "Memory",
					Description: "L1 cache memory usage is above 80%",
					Impact:      "Medium",
					Action:      "Triggered aggressive eviction, consider increasing memory limit",
					Timestamp:   time.Now(),
				}
				manager.cacheAnalyzer.addRecommendation(recommendation)
				return nil
			},
			Enabled: true,
		},
	}

	cm.cacheAnalyzer.analysisRules = rules
}

func (ca *CacheAnalyzer) addRecommendation(rec *CacheRecommendation) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	ca.recommendations = append(ca.recommendations, rec)
}

func (cm *CacheManager) startAnalysis() {
	ticker := time.NewTicker(cm.config.Analysis.AnalysisInterval)
	defer ticker.Stop()

	for range ticker.C {
		cm.runAnalysis()
	}
}

func (cm *CacheManager) runAnalysis() {
	for _, rule := range cm.cacheAnalyzer.analysisRules {
		if rule.Enabled && rule.Condition(cm.metrics) {
			rule.Action(cm)
		}
	}
}

// Background processes
func (cm *CacheManager) startMetricsCollection() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		cm.updateMetrics()
	}
}

func (cm *CacheManager) updateMetrics() {
	cm.metrics.mu.Lock()
	defer cm.metrics.mu.Unlock()

	// Update L1 metrics
	cm.metrics.L1Metrics.Hits = cm.l1Cache.hitCount
	cm.metrics.L1Metrics.Misses = cm.l1Cache.missCount
	totalL1 := cm.l1Cache.hitCount + cm.l1Cache.missCount
	if totalL1 > 0 {
		cm.metrics.L1Metrics.HitRatio = float64(cm.l1Cache.hitCount) / float64(totalL1)
	}
	cm.metrics.L1Metrics.MemoryUsage = cm.l1Cache.currentMemory
	cm.metrics.L1Metrics.EntryCount = int64(len(cm.l1Cache.data))
	cm.metrics.L1Metrics.LastUpdated = time.Now()

	// Update L2 metrics
	cm.metrics.L2Metrics.Hits = cm.l2Cache.hitCount
	cm.metrics.L2Metrics.Misses = cm.l2Cache.missCount
	totalL2 := cm.l2Cache.hitCount + cm.l2Cache.missCount
	if totalL2 > 0 {
		cm.metrics.L2Metrics.HitRatio = float64(cm.l2Cache.hitCount) / float64(totalL2)
	}
	cm.metrics.L2Metrics.LastUpdated = time.Now()

	// Update overall metrics
	totalHits := cm.metrics.L1Metrics.Hits + cm.metrics.L2Metrics.Hits
	totalMisses := cm.metrics.L1Metrics.Misses + cm.metrics.L2Metrics.Misses
	totalRequests := totalHits + totalMisses
	if totalRequests > 0 {
		cm.metrics.Overall.OverallHitRatio = float64(totalHits) / float64(totalRequests)
	}
	cm.metrics.Overall.TotalHits = totalHits
	cm.metrics.Overall.TotalMisses = totalMisses
	cm.metrics.Overall.LastUpdated = time.Now()
}

func (cm *CacheManager) startEvictionProcess() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		cm.performMaintenance()
	}
}

func (cm *CacheManager) performMaintenance() {
	// Clean expired entries
	cm.cleanExpiredEntries()

	// Optimize cache based on access patterns
	cm.optimizeCache()
}

func (cm *CacheManager) cleanExpiredEntries() {
	cm.l1Cache.mu.Lock()
	defer cm.l1Cache.mu.Unlock()

	for key, entry := range cm.l1Cache.data {
		if time.Since(entry.Timestamp) > entry.TTL {
			cm.l1Cache.currentMemory -= entry.Size
			delete(cm.l1Cache.data, key)
		}
	}
}

func (cm *CacheManager) optimizeCache() {
	// Implement cache optimization based on access patterns
	// This could include promoting frequently accessed items,
	// adjusting TTLs, or reorganizing cache structure
}

func (cm *CacheManager) recordOperation(opType, key, layer string, duration time.Duration, hit bool, size int64) {
	if cm.cacheAnalyzer != nil {
		op := &CacheOperation{
			Type:      opType,
			Key:       key,
			Layer:     layer,
			Timestamp: time.Now(),
			Duration:  duration,
			Hit:       hit,
			Size:      size,
		}

		cm.cacheAnalyzer.mu.Lock()
		cm.cacheAnalyzer.performanceLog = append(cm.cacheAnalyzer.performanceLog, op)
		// Keep only recent operations
		if len(cm.cacheAnalyzer.performanceLog) > 10000 {
			cm.cacheAnalyzer.performanceLog = cm.cacheAnalyzer.performanceLog[1000:]
		}
		cm.cacheAnalyzer.mu.Unlock()
	}
}

// Public API methods
func (cm *CacheManager) GetMetrics() *CacheMetrics {
	cm.metrics.mu.RLock()
	defer cm.metrics.mu.RUnlock()

	// Return a copy of metrics
	return &CacheMetrics{
		L1Metrics: cm.metrics.L1Metrics,
		L2Metrics: cm.metrics.L2Metrics,
		L3Metrics: cm.metrics.L3Metrics,
		Overall:   cm.metrics.Overall,
	}
}

func (cm *CacheManager) GetRecommendations() []*CacheRecommendation {
	if cm.cacheAnalyzer == nil {
		return nil
	}

	cm.cacheAnalyzer.mu.RLock()
	defer cm.cacheAnalyzer.mu.RUnlock()

	recs := make([]*CacheRecommendation, len(cm.cacheAnalyzer.recommendations))
	copy(recs, cm.cacheAnalyzer.recommendations)
	return recs
}

func (cm *CacheManager) GetPerformanceLog() []*CacheOperation {
	if cm.cacheAnalyzer == nil {
		return nil
	}

	cm.cacheAnalyzer.mu.RLock()
	defer cm.cacheAnalyzer.mu.RUnlock()

	log := make([]*CacheOperation, len(cm.cacheAnalyzer.performanceLog))
	copy(log, cm.cacheAnalyzer.performanceLog)
	return log
}

// Shutdown gracefully shuts down the cache manager
func (cm *CacheManager) Shutdown() error {
	if cm.cancel != nil {
		cm.cancel()
	}
	if cm.cacheWarmer != nil {
		cm.cacheWarmer.cancel()
	}
	return nil
}
