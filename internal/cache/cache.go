package cache

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// Cache interface for caching functionality
type Cache interface {
	Get(key string) (interface{}, bool)
	Set(key string, value interface{}, ttl time.Duration)
	Delete(key string)
	Clear()
}

// CacheConfig configuration for cache
type CacheConfig struct {
	Enabled         bool
	Type            string
	MaxSize         int64
	TTL             time.Duration
	CacheDir        string
	RedisURL        string
	Compression     bool
	Encryption      bool
	CleanupInterval time.Duration
}

// ScanResult represents a cached scan result (alias to types.ScanResult)
type ScanResult = types.ScanResult

// CacheStats cache statistics
type CacheStats struct {
	Hits      int64
	Misses    int64
	Evictions int64
	Size      int
	MaxSize   int
}

// CacheIntegration cache integration for scanner
type CacheIntegration struct {
	cache  Cache
	config CacheConfig
	stats  CacheStats
	mu     sync.RWMutex
}

// MemoryCache in-memory cache implementation
type MemoryCache struct {
	data map[string]*cacheItem
	mu   sync.RWMutex
}

type cacheItem struct {
	value      interface{}
	expiration time.Time
}

// NewMemoryCache creates a new memory cache
func NewMemoryCache() *MemoryCache {
	return &MemoryCache{
		data: make(map[string]*cacheItem),
	}
}

// NewCacheIntegration creates a new cache integration
func NewCacheIntegration(config *CacheConfig) (*CacheIntegration, error) {
	if config == nil {
		return nil, fmt.Errorf("cache config cannot be nil")
	}

	return &CacheIntegration{
		cache:  NewMemoryCache(),
		config: *config,
	}, nil
}

// Get retrieves a value from cache
func (m *MemoryCache) Get(key string) (interface{}, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	item, exists := m.data[key]
	if !exists {
		return nil, false
	}

	if time.Now().After(item.expiration) {
		delete(m.data, key)
		return nil, false
	}

	return item.value, true
}

// Set stores a value in cache with TTL
func (m *MemoryCache) Set(key string, value interface{}, ttl time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.data[key] = &cacheItem{
		value:      value,
		expiration: time.Now().Add(ttl),
	}
}

// Delete removes a value from cache
func (m *MemoryCache) Delete(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.data, key)
}

// Clear removes all values from cache
func (m *MemoryCache) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.data = make(map[string]*cacheItem)
}

// GetCachedScanResult retrieves a cached scan result
func (ci *CacheIntegration) GetCachedScanResult(key string) (*types.ScanResult, bool, error) {
	ci.mu.RLock()
	defer ci.mu.RUnlock()

	if cached, found := ci.cache.Get(key); found {
		if result, ok := cached.(*types.ScanResult); ok {
			return result, true, nil
		}
	}
	return nil, false, nil
}

// CacheScanResult stores a scan result in cache
func (ci *CacheIntegration) CacheScanResult(key string, result *types.ScanResult, metadata map[string]interface{}) error {
	ci.mu.Lock()
	defer ci.mu.Unlock()

	if !ci.config.Enabled {
		return nil
	}

	ci.cache.Set(key, result, ci.config.TTL)
	return nil
}

// GenerateScanKey generates a cache key for scan results
func (ci *CacheIntegration) GenerateScanKey(projectPath string, analyzers []string, config map[string]interface{}) (string, error) {
	// Simple key generation - in a real implementation, this would be more sophisticated
	return fmt.Sprintf("scan:%s:%v:%v", projectPath, analyzers, config), nil
}

// GetCacheStats returns cache statistics
func (ci *CacheIntegration) GetCacheStats() CacheStats {
	ci.mu.RLock()
	defer ci.mu.RUnlock()
	return ci.stats
}

// InvalidatePackageCache invalidates cache for a specific package or all packages if empty
func (ci *CacheIntegration) InvalidatePackageCache(packagePath string) error {
	ci.mu.Lock()
	defer ci.mu.Unlock()

	if packagePath == "" {
		ci.cache.Clear()
	} else {
		ci.cache.Delete(packagePath)
	}

	return nil
}

// SetCacheConfig updates cache configuration
func (ci *CacheIntegration) SetCacheConfig(config *CacheConfig) error {
	ci.mu.Lock()
	defer ci.mu.Unlock()

	if config == nil {
		return fmt.Errorf("cache config cannot be nil")
	}

	ci.config = *config
	return nil
}

// Close closes the cache integration
func (ci *CacheIntegration) Close() error {
	ci.mu.Lock()
	defer ci.mu.Unlock()

	ci.cache.Clear()
	return nil
}

// StartCleanup starts the cleanup routine
func (ci *CacheIntegration) StartCleanup(ctx context.Context) {
	if !ci.config.Enabled {
		return
	}

	ticker := time.NewTicker(ci.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ci.cleanupExpired()
		}
	}
}

func (ci *CacheIntegration) cleanupExpired() {
	// Implementation for cleanup
}

// CleanupExpired removes expired items from cache
func (m *MemoryCache) CleanupExpired(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.mu.Lock()
			now := time.Now()
			for key, item := range m.data {
				if now.After(item.expiration) {
					delete(m.data, key)
				}
			}
			m.mu.Unlock()
		}
	}
}
