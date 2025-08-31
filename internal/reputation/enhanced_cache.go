package reputation

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sync"
	"time"

	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// CacheEntry represents a cached reputation result
type CacheEntry struct {
	Key        string                    `json:"key"`
	Result     *EnhancedReputationResult `json:"result"`
	Timestamp  time.Time                 `json:"timestamp"`
	TTL        time.Duration             `json:"ttl"`
	AccessTime time.Time                 `json:"access_time"`
	HitCount   int                       `json:"hit_count"`
	Hits       int                       `json:"hits"` // For compatibility with ReputationCache
}

// InMemoryCache implements an in-memory cache for reputation results
type InMemoryCache struct {
	mu      sync.RWMutex
	entries map[string]*CacheEntry
	maxSize int
	stats   CacheStats
}

// CacheStats tracks cache performance metrics
type CacheStats struct {
	Hits        int64     `json:"hits"`
	Misses      int64     `json:"misses"`
	Evictions   int64     `json:"evictions"`
	Size        int       `json:"size"`
	LastCleanup time.Time `json:"last_cleanup"`
}

// NewInMemoryCache creates a new in-memory cache
func NewInMemoryCache(maxSize int) *InMemoryCache {
	cache := &InMemoryCache{
		entries: make(map[string]*CacheEntry),
		maxSize: maxSize,
		stats: CacheStats{
			LastCleanup: time.Now(),
		},
	}

	// Start cleanup goroutine
	go cache.cleanupLoop()

	return cache
}

// generateCacheKey generates a cache key for a package
func (ers *EnhancedReputationSystem) generateCacheKey(pkg *types.Package) string {
	data := fmt.Sprintf("%s:%s:%s", pkg.Name, pkg.Version, pkg.Registry)
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hash)
}

// Get retrieves a cached reputation result
func (cache *InMemoryCache) Get(key string) (*EnhancedReputationResult, bool) {
	cache.mu.RLock()
	defer cache.mu.RUnlock()

	entry, exists := cache.entries[key]
	if !exists {
		cache.stats.Misses++
		return nil, false
	}

	// Check if entry has expired
	if time.Since(entry.Timestamp) > entry.TTL {
		cache.mu.RUnlock()
		cache.mu.Lock()
		delete(cache.entries, key)
		cache.stats.Evictions++
		cache.stats.Size--
		cache.mu.Unlock()
		cache.mu.RLock()
		cache.stats.Misses++
		return nil, false
	}

	// Update access statistics
	entry.AccessTime = time.Now()
	entry.HitCount++
	cache.stats.Hits++

	return entry.Result, true
}

// Set stores a reputation result in the cache
func (cache *InMemoryCache) Set(key string, result *EnhancedReputationResult, ttl time.Duration) {
	cache.mu.Lock()
	defer cache.mu.Unlock()

	// Check if we need to evict entries
	if len(cache.entries) >= cache.maxSize {
		cache.evictLRU()
	}

	entry := &CacheEntry{
		Key:        key,
		Result:     result,
		Timestamp:  time.Now(),
		TTL:        ttl,
		AccessTime: time.Now(),
		HitCount:   0,
	}

	cache.entries[key] = entry
	cache.stats.Size = len(cache.entries)
}

// evictLRU evicts the least recently used entry
func (cache *InMemoryCache) evictLRU() {
	var oldestKey string
	var oldestTime time.Time

	for key, entry := range cache.entries {
		if oldestKey == "" || entry.AccessTime.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.AccessTime
		}
	}

	if oldestKey != "" {
		delete(cache.entries, oldestKey)
		cache.stats.Evictions++
	}
}

// Delete removes an entry from the cache
func (cache *InMemoryCache) Delete(key string) {
	cache.mu.Lock()
	defer cache.mu.Unlock()

	if _, exists := cache.entries[key]; exists {
		delete(cache.entries, key)
		cache.stats.Size = len(cache.entries)
	}
}

// Clear removes all entries from the cache
func (cache *InMemoryCache) Clear() {
	cache.mu.Lock()
	defer cache.mu.Unlock()

	cache.entries = make(map[string]*CacheEntry)
	cache.stats.Size = 0
	cache.stats.Evictions += int64(len(cache.entries))
}

// GetStats returns cache statistics
func (cache *InMemoryCache) GetStats() CacheStats {
	cache.mu.RLock()
	defer cache.mu.RUnlock()

	stats := cache.stats
	stats.Size = len(cache.entries)
	return stats
}

// cleanupLoop periodically removes expired entries
func (cache *InMemoryCache) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		cache.cleanup()
	}
}

// cleanup removes expired entries
func (cache *InMemoryCache) cleanup() {
	cache.mu.Lock()
	defer cache.mu.Unlock()

	now := time.Now()
	var expiredKeys []string

	for key, entry := range cache.entries {
		if now.Sub(entry.Timestamp) > entry.TTL {
			expiredKeys = append(expiredKeys, key)
		}
	}

	for _, key := range expiredKeys {
		delete(cache.entries, key)
		cache.stats.Evictions++
	}

	cache.stats.Size = len(cache.entries)
	cache.stats.LastCleanup = now
}

// getCachedResult retrieves a cached reputation result
func (ers *EnhancedReputationSystem) getCachedResult(ctx context.Context, pkg *types.Package) (*EnhancedReputationResult, bool) {
	if ers.cache == nil {
		return nil, false
	}

	result := ers.cache.Get(pkg.Name, pkg.Version, pkg.Registry)
	found := result != nil

	if found {
		ers.logger.Debug("Cache hit for package", map[string]interface{}{
			"package": pkg.Name,
			"version": pkg.Version,
		})
	} else {
		ers.logger.Debug("Cache miss for package", map[string]interface{}{
			"package": pkg.Name,
			"version": pkg.Version,
		})
	}

	return result, found
}

// setCachedResult stores a reputation result in the cache
func (ers *EnhancedReputationSystem) setCachedResult(ctx context.Context, pkg *types.Package, result *EnhancedReputationResult) {
	if ers.cache == nil {
		return
	}

	ers.cache.Set(pkg.Name, pkg.Version, pkg.Registry, result)

	ers.logger.Debug("Cached reputation result", map[string]interface{}{
		"package":    pkg.Name,
		"version":    pkg.Version,
		"risk_level": result.RiskLevel,
	})
}

// invalidateCache invalidates cache entries for a specific package
func (ers *EnhancedReputationSystem) invalidateCache(pkg *types.Package) {
	ers.logger.Debug("Cache invalidation not supported by ReputationCache", map[string]interface{}{
		"package": pkg.Name,
		"version": pkg.Version,
	})
}

// GetCacheStats returns cache statistics
func (ers *EnhancedReputationSystem) GetCacheStats() CacheStats {
	// ReputationCache doesn't support stats, return empty stats
	return CacheStats{}
}

// WarmupCache pre-loads cache with reputation data for common packages
func (ers *EnhancedReputationSystem) WarmupCache(ctx context.Context, packages []*types.Package) error {
	ers.logger.Info("Starting cache warmup", map[string]interface{}{
		"package_count": len(packages),
	})

	for i, pkg := range packages {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Check if already cached
		if _, found := ers.getCachedResult(ctx, pkg); found {
			continue
		}

		// Analyze package and cache result
		result, err := ers.AnalyzePackageReputation(ctx, pkg)
		if err != nil {
			ers.logger.Warn("Failed to analyze package during warmup", map[string]interface{}{
				"package": pkg.Name,
				"error":   err.Error(),
			})
			continue
		}

		ers.setCachedResult(ctx, pkg, result)

		// Log progress
		if (i+1)%100 == 0 {
			ers.logger.Info("Cache warmup progress", map[string]interface{}{
				"completed": i + 1,
				"total":     len(packages),
			})
		}
	}

	ers.logger.Info("Cache warmup completed", map[string]interface{}{
		"package_count": len(packages),
		"cache_stats":   ers.GetCacheStats(),
	})

	return nil
}

// PersistentCache interface for persistent cache implementations
type PersistentCache interface {
	Get(key string) (*EnhancedReputationResult, error)
	Set(key string, result *EnhancedReputationResult, ttl time.Duration) error
	Delete(key string) error
	Clear() error
	GetStats() (CacheStats, error)
}

// FilesystemCache implements a filesystem-based persistent cache
type FilesystemCache struct {
	basePath string
	mu       sync.RWMutex
	stats    CacheStats
}

// NewFilesystemCache creates a new filesystem-based cache
func NewFilesystemCache(basePath string) *FilesystemCache {
	return &FilesystemCache{
		basePath: basePath,
		stats: CacheStats{
			LastCleanup: time.Now(),
		},
	}
}

// Get retrieves a cached result from filesystem
func (fc *FilesystemCache) Get(key string) (*EnhancedReputationResult, error) {
	fc.mu.RLock()
	defer fc.mu.RUnlock()

	// Implementation would read from filesystem
	// This is a simplified version
	fc.stats.Misses++
	return nil, fmt.Errorf("not implemented")
}

// Set stores a result in filesystem cache
func (fc *FilesystemCache) Set(key string, result *EnhancedReputationResult, ttl time.Duration) error {
	fc.mu.Lock()
	defer fc.mu.Unlock()

	// Implementation would write to filesystem
	// This is a simplified version
	return fmt.Errorf("not implemented")
}

// Delete removes a cached result from filesystem
func (fc *FilesystemCache) Delete(key string) error {
	fc.mu.Lock()
	defer fc.mu.Unlock()

	// Implementation would delete from filesystem
	return fmt.Errorf("not implemented")
}

// Clear removes all cached results from filesystem
func (fc *FilesystemCache) Clear() error {
	fc.mu.Lock()
	defer fc.mu.Unlock()

	// Implementation would clear filesystem cache
	return fmt.Errorf("not implemented")
}

// GetStats returns filesystem cache statistics
func (fc *FilesystemCache) GetStats() (CacheStats, error) {
	fc.mu.RLock()
	defer fc.mu.RUnlock()

	return fc.stats, nil
}

// CacheMetrics provides detailed cache performance metrics
type CacheMetrics struct {
	HitRate        float64       `json:"hit_rate"`
	MissRate       float64       `json:"miss_rate"`
	EvictionRate   float64       `json:"eviction_rate"`
	AverageLatency time.Duration `json:"average_latency"`
	MemoryUsage    int64         `json:"memory_usage"`
	EntryCount     int           `json:"entry_count"`
}

// GetDetailedMetrics returns detailed cache performance metrics
func (cache *InMemoryCache) GetDetailedMetrics() CacheMetrics {
	cache.mu.RLock()
	defer cache.mu.RUnlock()

	stats := cache.stats
	totalRequests := stats.Hits + stats.Misses

	metrics := CacheMetrics{
		EntryCount: len(cache.entries),
	}

	if totalRequests > 0 {
		metrics.HitRate = float64(stats.Hits) / float64(totalRequests)
		metrics.MissRate = float64(stats.Misses) / float64(totalRequests)
	}

	if stats.Hits > 0 {
		metrics.EvictionRate = float64(stats.Evictions) / float64(stats.Hits)
	}

	// Estimate memory usage (simplified)
	metrics.MemoryUsage = int64(len(cache.entries) * 1024) // Rough estimate

	return metrics
}

// OptimizeCache performs cache optimization operations
func (ers *EnhancedReputationSystem) OptimizeCache() {
	if ers.cache == nil {
		return
	}

	ers.logger.Info("Cache optimization not supported by ReputationCache")
}
