package ml

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// FeatureStore manages cached package features for ML analysis
type FeatureStore struct {
	cache    map[string]*CachedFeatures
	config   *MLConfig
	mu       sync.RWMutex
	ttl      time.Duration
	cleanup  *time.Ticker
	stopChan chan bool
}

// CachedFeatures represents cached package features with metadata
type CachedFeatures struct {
	Features  *PackageFeatures `json:"features"`
	Timestamp time.Time        `json:"timestamp"`
	TTL       time.Duration    `json:"ttl"`
	HitCount  int              `json:"hit_count"`
	Version   string           `json:"version"`
}

// FeatureStoreStats represents feature store statistics
type FeatureStoreStats struct {
	TotalEntries    int           `json:"total_entries"`
	CacheHits       int64         `json:"cache_hits"`
	CacheMisses     int64         `json:"cache_misses"`
	HitRatio        float64       `json:"hit_ratio"`
	AverageAge      time.Duration `json:"average_age"`
	OldestEntry     time.Time     `json:"oldest_entry"`
	NewestEntry     time.Time     `json:"newest_entry"`
	MemoryUsage     int64         `json:"memory_usage_bytes"`
	CleanupCount    int64         `json:"cleanup_count"`
	LastCleanup     time.Time     `json:"last_cleanup"`
}

// NewFeatureStore creates a new feature store
func NewFeatureStore(config *MLConfig) *FeatureStore {
	ttl, _ := time.ParseDuration(config.FeatureStoreTTL)
	if ttl == 0 {
		ttl = 24 * time.Hour // Default TTL
	}
	
	fs := &FeatureStore{
		cache:    make(map[string]*CachedFeatures),
		config:   config,
		ttl:      ttl,
		stopChan: make(chan bool),
	}
	
	// Start cleanup routine
	fs.startCleanupRoutine()
	
	return fs
}

// GetFeatures retrieves cached features for a package
func (fs *FeatureStore) GetFeatures(packageName, registry string) *PackageFeatures {
	if !fs.config.FeatureStoreEnabled {
		return nil
	}
	
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	
	key := fs.generateKey(packageName, registry)
	cached, exists := fs.cache[key]
	
	if !exists {
		fs.incrementCacheMisses()
		return nil
	}
	
	// Check if entry has expired
	if time.Since(cached.Timestamp) > cached.TTL {
		fs.incrementCacheMisses()
		return nil
	}
	
	// Update hit count and return features
	cached.HitCount++
	fs.incrementCacheHits()
	
	return cached.Features
}

// StoreFeatures stores package features in the cache
func (fs *FeatureStore) StoreFeatures(features *PackageFeatures) {
	if !fs.config.FeatureStoreEnabled {
		return
	}
	
	fs.mu.Lock()
	defer fs.mu.Unlock()
	
	key := fs.generateKey(features.PackageName, features.Registry)
	
	cached := &CachedFeatures{
		Features:  features,
		Timestamp: time.Now(),
		TTL:       fs.ttl,
		HitCount:  0,
		Version:   features.FeatureVersion,
	}
	
	fs.cache[key] = cached
}

// InvalidateFeatures removes cached features for a package
func (fs *FeatureStore) InvalidateFeatures(packageName, registry string) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	
	key := fs.generateKey(packageName, registry)
	delete(fs.cache, key)
}

// InvalidateAll clears all cached features
func (fs *FeatureStore) InvalidateAll() {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	
	fs.cache = make(map[string]*CachedFeatures)
}

// GetStats returns feature store statistics
func (fs *FeatureStore) GetStats() *FeatureStoreStats {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	
	stats := &FeatureStoreStats{
		TotalEntries: len(fs.cache),
	}
	
	// Calculate statistics
	if len(fs.cache) > 0 {
		var totalAge time.Duration
		oldest := time.Now()
		newest := time.Time{}
		
		for _, cached := range fs.cache {
			age := time.Since(cached.Timestamp)
			totalAge += age
			
			if cached.Timestamp.Before(oldest) {
				oldest = cached.Timestamp
			}
			if cached.Timestamp.After(newest) {
				newest = cached.Timestamp
			}
		}
		
		stats.AverageAge = totalAge / time.Duration(len(fs.cache))
		stats.OldestEntry = oldest
		stats.NewestEntry = newest
	}
	
	// Calculate hit ratio
	totalRequests := fs.getCacheHits() + fs.getCacheMisses()
	if totalRequests > 0 {
		stats.HitRatio = float64(fs.getCacheHits()) / float64(totalRequests)
	}
	
	stats.CacheHits = fs.getCacheHits()
	stats.CacheMisses = fs.getCacheMisses()
	
	// Estimate memory usage
	stats.MemoryUsage = fs.estimateMemoryUsage()
	
	return stats
}

// ExportFeatures exports cached features to JSON
func (fs *FeatureStore) ExportFeatures() ([]byte, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	
	exportData := make(map[string]*CachedFeatures)
	for key, cached := range fs.cache {
		exportData[key] = cached
	}
	
	return json.MarshalIndent(exportData, "", "  ")
}

// ImportFeatures imports cached features from JSON
func (fs *FeatureStore) ImportFeatures(data []byte) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	
	var importData map[string]*CachedFeatures
	if err := json.Unmarshal(data, &importData); err != nil {
		return fmt.Errorf("failed to unmarshal feature data: %w", err)
	}
	
	// Validate and import features
	for key, cached := range importData {
		// Check if entry is still valid
		if time.Since(cached.Timestamp) <= cached.TTL {
			fs.cache[key] = cached
		}
	}
	
	return nil
}

// GetTopPackages returns most frequently accessed packages
func (fs *FeatureStore) GetTopPackages(limit int) []PackageAccessInfo {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	
	type packageHits struct {
		key      string
		hitCount int
		cached   *CachedFeatures
	}
	
	var packages []packageHits
	for key, cached := range fs.cache {
		packages = append(packages, packageHits{
			key:      key,
			hitCount: cached.HitCount,
			cached:   cached,
		})
	}
	
	// Sort by hit count
	for i := 0; i < len(packages)-1; i++ {
		for j := i + 1; j < len(packages); j++ {
			if packages[i].hitCount < packages[j].hitCount {
				packages[i], packages[j] = packages[j], packages[i]
			}
		}
	}
	
	// Convert to result format
	var result []PackageAccessInfo
	for i, pkg := range packages {
		if i >= limit {
			break
		}
		
		result = append(result, PackageAccessInfo{
			PackageName: pkg.cached.Features.PackageName,
			Registry:    pkg.cached.Features.Registry,
			HitCount:    pkg.hitCount,
			LastAccess:  pkg.cached.Timestamp,
			CacheAge:    time.Since(pkg.cached.Timestamp),
		})
	}
	
	return result
}

// PackageAccessInfo represents package access information
type PackageAccessInfo struct {
	PackageName string        `json:"package_name"`
	Registry    string        `json:"registry"`
	HitCount    int           `json:"hit_count"`
	LastAccess  time.Time     `json:"last_access"`
	CacheAge    time.Duration `json:"cache_age"`
}

// CleanupExpired removes expired entries from the cache
func (fs *FeatureStore) CleanupExpired() int {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	
	expiredCount := 0
	now := time.Now()
	
	for key, cached := range fs.cache {
		if now.Sub(cached.Timestamp) > cached.TTL {
			delete(fs.cache, key)
			expiredCount++
		}
	}
	
	fs.incrementCleanupCount()
	return expiredCount
}

// Close stops the feature store and cleanup routines
func (fs *FeatureStore) Close() {
	if fs.cleanup != nil {
		fs.cleanup.Stop()
	}
	close(fs.stopChan)
}

// Private methods

// generateKey generates a cache key for package and registry
func (fs *FeatureStore) generateKey(packageName, registry string) string {
	return fmt.Sprintf("%s:%s", registry, packageName)
}

// startCleanupRoutine starts the background cleanup routine
func (fs *FeatureStore) startCleanupRoutine() {
	// Run cleanup every hour
	fs.cleanup = time.NewTicker(time.Hour)
	
	go func() {
		for {
			select {
			case <-fs.cleanup.C:
				fs.CleanupExpired()
			case <-fs.stopChan:
				return
			}
		}
	}()
}

// estimateMemoryUsage estimates memory usage of the cache
func (fs *FeatureStore) estimateMemoryUsage() int64 {
	var totalSize int64
	
	for _, cached := range fs.cache {
		// Rough estimation of memory usage
		// This is a simplified calculation
		featureSize := int64(len(cached.Features.PackageName) + len(cached.Features.Registry))
		featureSize += int64(len(cached.Features.NameEmbedding) * 8) // 8 bytes per float64
		featureSize += 1000 // Rough estimate for other fields
		
		totalSize += featureSize
	}
	
	return totalSize
}

// Thread-safe counters for statistics
var (
	cacheHits    int64
	cacheMisses  int64
	cleanupCount int64
	counterMu    sync.RWMutex
)

func (fs *FeatureStore) incrementCacheHits() {
	counterMu.Lock()
	cacheHits++
	counterMu.Unlock()
}

func (fs *FeatureStore) incrementCacheMisses() {
	counterMu.Lock()
	cacheMisses++
	counterMu.Unlock()
}

func (fs *FeatureStore) incrementCleanupCount() {
	counterMu.Lock()
	cleanupCount++
	counterMu.Unlock()
}

func (fs *FeatureStore) getCacheHits() int64 {
	counterMu.RLock()
	defer counterMu.RUnlock()
	return cacheHits
}

func (fs *FeatureStore) getCacheMisses() int64 {
	counterMu.RLock()
	defer counterMu.RUnlock()
	return cacheMisses
}

// FeatureStoreManager manages multiple feature stores
type FeatureStoreManager struct {
	stores map[string]*FeatureStore
	mu     sync.RWMutex
}

// NewFeatureStoreManager creates a new feature store manager
func NewFeatureStoreManager() *FeatureStoreManager {
	return &FeatureStoreManager{
		stores: make(map[string]*FeatureStore),
	}
}

// GetStore returns a feature store for a specific registry
func (fsm *FeatureStoreManager) GetStore(registry string, config *MLConfig) *FeatureStore {
	fsm.mu.RLock()
	store, exists := fsm.stores[registry]
	fsm.mu.RUnlock()
	
	if exists {
		return store
	}
	
	fsm.mu.Lock()
	defer fsm.mu.Unlock()
	
	// Double-check after acquiring write lock
	if store, exists := fsm.stores[registry]; exists {
		return store
	}
	
	// Create new store
	store = NewFeatureStore(config)
	fsm.stores[registry] = store
	
	return store
}

// GetAllStores returns all feature stores
func (fsm *FeatureStoreManager) GetAllStores() map[string]*FeatureStore {
	fsm.mu.RLock()
	defer fsm.mu.RUnlock()
	
	stores := make(map[string]*FeatureStore)
	for registry, store := range fsm.stores {
		stores[registry] = store
	}
	
	return stores
}

// GetAggregatedStats returns aggregated statistics across all stores
func (fsm *FeatureStoreManager) GetAggregatedStats() *AggregatedFeatureStoreStats {
	fsm.mu.RLock()
	defer fsm.mu.RUnlock()
	
	stats := &AggregatedFeatureStoreStats{
		RegistryStats: make(map[string]*FeatureStoreStats),
	}
	
	for registry, store := range fsm.stores {
		registryStats := store.GetStats()
		stats.RegistryStats[registry] = registryStats
		
		// Aggregate totals
		stats.TotalEntries += registryStats.TotalEntries
		stats.TotalCacheHits += registryStats.CacheHits
		stats.TotalCacheMisses += registryStats.CacheMisses
		stats.TotalMemoryUsage += registryStats.MemoryUsage
	}
	
	// Calculate overall hit ratio
	totalRequests := stats.TotalCacheHits + stats.TotalCacheMisses
	if totalRequests > 0 {
		stats.OverallHitRatio = float64(stats.TotalCacheHits) / float64(totalRequests)
	}
	
	return stats
}

// AggregatedFeatureStoreStats represents aggregated statistics
type AggregatedFeatureStoreStats struct {
	TotalEntries      int                            `json:"total_entries"`
	TotalCacheHits    int64                          `json:"total_cache_hits"`
	TotalCacheMisses  int64                          `json:"total_cache_misses"`
	OverallHitRatio   float64                        `json:"overall_hit_ratio"`
	TotalMemoryUsage  int64                          `json:"total_memory_usage_bytes"`
	RegistryStats     map[string]*FeatureStoreStats  `json:"registry_stats"`
}

// CloseAll closes all feature stores
func (fsm *FeatureStoreManager) CloseAll() {
	fsm.mu.Lock()
	defer fsm.mu.Unlock()
	
	for _, store := range fsm.stores {
		store.Close()
	}
	
	fsm.stores = make(map[string]*FeatureStore)
}