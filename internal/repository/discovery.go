package repository

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/config"
)

// DiscoveryService handles automatic repository discovery across platforms
type DiscoveryService struct {
	manager    RepositoryManager
	connectors map[string]Connector
	config     DiscoveryConfig
	repoConfig *config.RepositoryConfig
	cache      DiscoveryCache
	mu         sync.RWMutex
	running    bool
	stopCh     chan struct{}
	logger     *log.Logger
}

// DiscoveryConfig contains configuration for repository discovery
type DiscoveryConfig struct {
	// Platforms to discover repositories from
	Platforms []PlatformDiscoveryConfig `json:"platforms"`
	
	// Discovery interval
	Interval time.Duration `json:"interval"`
	
	// Maximum repositories to discover per platform per run
	MaxReposPerPlatform int `json:"max_repos_per_platform"`
	
	// Filter for repository discovery
	Filter *RepositoryFilter `json:"filter,omitempty"`
	
	// Whether to discover private repositories
	IncludePrivate bool `json:"include_private"`
	
	// Whether to discover forked repositories
	IncludeForks bool `json:"include_forks"`
	
	// Whether to discover archived repositories
	IncludeArchived bool `json:"include_archived"`
	
	// Concurrent discovery workers per platform
	Workers int `json:"workers"`
	
	// Timeout for discovery operations
	Timeout time.Duration `json:"timeout"`
	
	// Cache configuration
	Cache DiscoveryCacheConfig `json:"cache"`
}

// DiscoveryCacheConfig contains cache configuration for discovery
type DiscoveryCacheConfig struct {
	Enabled bool          `json:"enabled"`
	TTL     time.Duration `json:"ttl"`
}

// DiscoveryCache interface for caching discovery results
type DiscoveryCache interface {
	Get(key string) ([]*Repository, bool)
	Set(key string, repos []*Repository, ttl time.Duration)
	Delete(key string)
	Clear()
}

// MemoryDiscoveryCache implements DiscoveryCache using in-memory storage
type MemoryDiscoveryCache struct {
	data map[string]cacheEntry
	mu   sync.RWMutex
}

type cacheEntry struct {
	repos     []*Repository
	expiry    time.Time
	createdAt time.Time
}

// PlatformDiscoveryConfig contains platform-specific discovery configuration
type PlatformDiscoveryConfig struct {
	// Platform name (github, gitlab, bitbucket, azuredevops)
	Platform string `json:"platform"`
	
	// Platform configuration
	Config PlatformConfig `json:"config"`
	
	// Organizations/users to discover repositories from
	Organizations []string `json:"organizations,omitempty"`
	
	// Specific repositories to discover (owner/repo format)
	Repositories []string `json:"repositories,omitempty"`
	
	// Search queries for repository discovery
	SearchQueries []string `json:"search_queries,omitempty"`
	
	// Platform-specific filter
	Filter *RepositoryFilter `json:"filter,omitempty"`
	
	// Whether this platform is enabled for discovery
	Enabled bool `json:"enabled"`
}

// DiscoveryResult contains the result of a discovery operation
type DiscoveryResult struct {
	Platform     string                `json:"platform"`
	Repositories []*Repository         `json:"repositories"`
	Errors       []error               `json:"errors"`
	Duration     time.Duration         `json:"duration"`
	Timestamp    time.Time             `json:"timestamp"`
	Stats        DiscoveryStats        `json:"stats"`
}

// DiscoveryStats contains statistics about a discovery operation
type DiscoveryStats struct {
	TotalFound      int `json:"total_found"`
	NewRepositories int `json:"new_repositories"`
	Updated         int `json:"updated"`
	Skipped         int `json:"skipped"`
	Errors          int `json:"errors"`
}

// NewDiscoveryService creates a new repository discovery service
func NewDiscoveryService(manager RepositoryManager, config DiscoveryConfig) *DiscoveryService {
	cache := NewMemoryDiscoveryCache()
	return &DiscoveryService{
		manager:    manager,
		connectors: make(map[string]Connector),
		config:     config,
		cache:      cache,
		stopCh:     make(chan struct{}),
		logger:     log.New(log.Writer(), "[DiscoveryService] ", log.LstdFlags),
	}
}

// NewDiscoveryServiceWithRepoConfig creates a new discovery service with repository config
func NewDiscoveryServiceWithRepoConfig(manager RepositoryManager, config DiscoveryConfig, repoConfig *config.RepositoryConfig) *DiscoveryService {
	cache := NewMemoryDiscoveryCache()
	return &DiscoveryService{
		manager:    manager,
		connectors: make(map[string]Connector),
		config:     config,
		repoConfig: repoConfig,
		cache:      cache,
		stopCh:     make(chan struct{}),
		logger:     log.New(log.Writer(), "[DiscoveryService] ", log.LstdFlags),
	}
}

// Start begins the repository discovery process
func (ds *DiscoveryService) Start(ctx context.Context) error {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	
	if ds.running {
		return fmt.Errorf("discovery service is already running")
	}
	
	// Initialize connectors for each platform
	for _, platformConfig := range ds.config.Platforms {
		if !platformConfig.Enabled {
			continue
		}
		
		connector, err := ds.manager.GetConnector(platformConfig.Platform)
		if err != nil {
			ds.logger.Printf("Failed to get connector for platform %s: %v", platformConfig.Platform, err)
			continue
		}
		
		ds.connectors[platformConfig.Platform] = connector
	}
	
	ds.running = true
	ds.logger.Printf("Starting repository discovery service with %d platforms", len(ds.connectors))
	
	// Start discovery loop
	go ds.discoveryLoop(ctx)
	
	return nil
}

// Stop stops the repository discovery process
func (ds *DiscoveryService) Stop() error {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	
	if !ds.running {
		return fmt.Errorf("discovery service is not running")
	}
	
	ds.logger.Println("Stopping repository discovery service")
	close(ds.stopCh)
	ds.running = false
	
	return nil
}

// IsRunning returns whether the discovery service is currently running
func (ds *DiscoveryService) IsRunning() bool {
	ds.mu.RLock()
	defer ds.mu.RUnlock()
	return ds.running
}

// DiscoverOnce performs a single discovery operation across all configured platforms
func (ds *DiscoveryService) DiscoverOnce(ctx context.Context) ([]DiscoveryResult, error) {
	ds.mu.RLock()
	connectors := make(map[string]Connector)
	for platform, connector := range ds.connectors {
		connectors[platform] = connector
	}
	ds.mu.RUnlock()
	
	if len(connectors) == 0 {
		return nil, fmt.Errorf("no connectors available for discovery")
	}
	
	results := make([]DiscoveryResult, 0, len(connectors))
	resultsCh := make(chan DiscoveryResult, len(connectors))
	
	// Discover repositories from each platform concurrently
	var wg sync.WaitGroup
	for platform, connector := range connectors {
		wg.Add(1)
		go func(platform string, connector Connector) {
			defer wg.Done()
			result := ds.discoverFromPlatform(ctx, platform, connector)
			resultsCh <- result
		}(platform, connector)
	}
	
	// Wait for all discoveries to complete
	go func() {
		wg.Wait()
		close(resultsCh)
	}()
	
	// Collect results
	for result := range resultsCh {
		results = append(results, result)
	}
	
	return results, nil
}

// discoveryLoop runs the continuous discovery process
func (ds *DiscoveryService) discoveryLoop(ctx context.Context) {
	ticker := time.NewTicker(ds.config.Interval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			ds.logger.Println("Discovery loop stopped due to context cancellation")
			return
		case <-ds.stopCh:
			ds.logger.Println("Discovery loop stopped")
			return
		case <-ticker.C:
			ds.logger.Println("Starting scheduled repository discovery")
			results, err := ds.DiscoverOnce(ctx)
			if err != nil {
				ds.logger.Printf("Discovery failed: %v", err)
				continue
			}
			
			// Log discovery results
			for _, result := range results {
				ds.logger.Printf("Platform %s: discovered %d repositories in %v (new: %d, updated: %d, errors: %d)",
					result.Platform, result.Stats.TotalFound, result.Duration,
					result.Stats.NewRepositories, result.Stats.Updated, result.Stats.Errors)
			}
		}
	}
}

// discoverFromPlatform discovers repositories from a specific platform
func (ds *DiscoveryService) discoverFromPlatform(ctx context.Context, platform string, connector Connector) DiscoveryResult {
	start := time.Now()
	result := DiscoveryResult{
		Platform:  platform,
		Timestamp: start,
		Errors:    make([]error, 0),
	}
	
	// Get platform configuration
	var platformConfig *PlatformDiscoveryConfig
	for _, config := range ds.config.Platforms {
		if config.Platform == platform {
			platformConfig = &config
			break
		}
	}
	
	if platformConfig == nil {
		result.Errors = append(result.Errors, fmt.Errorf("no configuration found for platform %s", platform))
		result.Duration = time.Since(start)
		return result
	}
	
	repos := make([]*Repository, 0)
	
	// Discover from organizations
	for _, org := range platformConfig.Organizations {
		orgRepos, err := ds.discoverFromOrganization(ctx, connector, org, platformConfig.Filter)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Errorf("failed to discover from organization %s: %w", org, err))
			continue
		}
		repos = append(repos, orgRepos...)
	}
	
	// Discover specific repositories
	for _, repoName := range platformConfig.Repositories {
		repo, err := ds.discoverSpecificRepository(ctx, connector, repoName)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Errorf("failed to discover repository %s: %w", repoName, err))
			continue
		}
		if repo != nil {
			repos = append(repos, repo)
		}
	}
	
	// Discover from search queries
	for _, query := range platformConfig.SearchQueries {
		searchRepos, err := ds.discoverFromSearch(ctx, connector, query, platformConfig.Filter)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Errorf("failed to search repositories with query %s: %w", query, err))
			continue
		}
		repos = append(repos, searchRepos...)
	}
	
	// Apply global filter and limits
	repos = ds.applyFilters(repos)
	if ds.config.MaxReposPerPlatform > 0 && len(repos) > ds.config.MaxReposPerPlatform {
		repos = repos[:ds.config.MaxReposPerPlatform]
	}
	
	result.Repositories = repos
	result.Stats.TotalFound = len(repos)
	result.Stats.Errors = len(result.Errors)
	result.Duration = time.Since(start)
	
	return result
}

// discoverFromOrganization discovers repositories from an organization
func (ds *DiscoveryService) discoverFromOrganization(ctx context.Context, connector Connector, org string, filter *RepositoryFilter) ([]*Repository, error) {
	return connector.ListOrgRepositories(ctx, org, filter)
}

// discoverSpecificRepository discovers a specific repository
func (ds *DiscoveryService) discoverSpecificRepository(ctx context.Context, connector Connector, repoName string) (*Repository, error) {
	parts := splitRepositoryName(repoName)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid repository name format: %s (expected owner/repo)", repoName)
	}
	
	return connector.GetRepository(ctx, parts[0], parts[1])
}

// discoverFromSearch discovers repositories using search queries
func (ds *DiscoveryService) discoverFromSearch(ctx context.Context, connector Connector, query string, filter *RepositoryFilter) ([]*Repository, error) {
	return connector.SearchRepositories(ctx, query, filter)
}

// applyFilters applies global filters to discovered repositories
func (ds *DiscoveryService) applyFilters(repos []*Repository) []*Repository {
	filtered := make([]*Repository, 0, len(repos))
	
	for _, repo := range repos {
		// Apply global filters
		if !ds.config.IncludePrivate && repo.Private {
			continue
		}
		if !ds.config.IncludeForks && repo.Fork {
			continue
		}
		if !ds.config.IncludeArchived && repo.Archived {
			continue
		}
		
		// Apply discovery filter if configured
		if ds.config.Filter != nil && !ds.matchesFilter(repo, ds.config.Filter) {
			continue
		}
		
		filtered = append(filtered, repo)
	}
	
	return filtered
}

// matchesFilter checks if a repository matches the given filter
func (ds *DiscoveryService) matchesFilter(repo *Repository, filter *RepositoryFilter) bool {
	if filter == nil {
		return true
	}
	
	// Check languages
	if len(filter.Languages) > 0 {
		found := false
		for _, lang := range filter.Languages {
			if repo.Language == lang {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	
	// Check minimum stars
	if filter.MinStars > 0 && repo.StarCount < filter.MinStars {
		return false
	}
	
	// Check maximum size
	if filter.MaxSize > 0 && repo.Size > filter.MaxSize {
		return false
	}
	
	// Check updated after
	if filter.UpdatedAfter != nil && repo.UpdatedAt.Before(*filter.UpdatedAfter) {
		return false
	}
	
	// Check name pattern
	if filter.NamePattern != "" {
		if !matchesPattern(repo.Name, filter.NamePattern) {
			return false
		}
	}
	
	// Check exclude patterns
	for _, pattern := range filter.ExcludePatterns {
		if matchesPattern(repo.Name, pattern) {
			return false
		}
	}
	
	return true
}

// splitRepositoryName splits a repository name into owner and repo parts
func splitRepositoryName(name string) []string {
	parts := make([]string, 0, 2)
	if idx := findFirstSlash(name); idx != -1 {
		parts = append(parts, name[:idx], name[idx+1:])
	}
	return parts
}

// findFirstSlash finds the first slash in a string
func findFirstSlash(s string) int {
	for i, r := range s {
		if r == '/' {
			return i
		}
	}
	return -1
}

// matchesPattern checks if a string matches a simple pattern (supports * wildcard)
func matchesPattern(s, pattern string) bool {
	if pattern == "" {
		return true
	}
	if pattern == "*" {
		return true
	}
	
	// Simple pattern matching - just check if pattern is contained in string
	// For more complex patterns, we could use regexp or glob libraries
	pattern = strings.TrimPrefix(pattern, "*")
	pattern = strings.TrimSuffix(pattern, "*")
	
	return strings.Contains(strings.ToLower(s), strings.ToLower(pattern))
}

// NewMemoryDiscoveryCache creates a new in-memory discovery cache
func NewMemoryDiscoveryCache() *MemoryDiscoveryCache {
	cache := &MemoryDiscoveryCache{
		data: make(map[string]cacheEntry),
	}

	// Start cleanup goroutine
	go cache.cleanup()

	return cache
}

// Get retrieves repositories from cache
func (c *MemoryDiscoveryCache) Get(key string) ([]*Repository, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.data[key]
	if !exists || time.Now().After(entry.expiry) {
		return nil, false
	}

	return entry.repos, true
}

// Set stores repositories in cache
func (c *MemoryDiscoveryCache) Set(key string, repos []*Repository, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.data[key] = cacheEntry{
		repos:     repos,
		expiry:    time.Now().Add(ttl),
		createdAt: time.Now(),
	}
}

// Delete removes an entry from cache
func (c *MemoryDiscoveryCache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.data, key)
}

// Clear removes all entries from cache
func (c *MemoryDiscoveryCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.data = make(map[string]cacheEntry)
}

// cleanup removes expired entries from cache
func (c *MemoryDiscoveryCache) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		c.mu.Lock()
		now := time.Now()
		for key, entry := range c.data {
			if now.After(entry.expiry) {
				delete(c.data, key)
			}
		}
		c.mu.Unlock()
	}
}

// GetCachedRepositories retrieves cached repositories for a platform
func (ds *DiscoveryService) GetCachedRepositories(platform string) ([]*Repository, bool) {
	if ds.cache == nil || !ds.config.Cache.Enabled {
		return nil, false
	}
	cacheKey := fmt.Sprintf("discovery:%s", platform)
	return ds.cache.Get(cacheKey)
}

// ClearCache clears the discovery cache
func (ds *DiscoveryService) ClearCache() {
	if ds.cache != nil {
		ds.cache.Clear()
	}
}

// GetDiscoveryStats returns discovery service statistics
func (ds *DiscoveryService) GetDiscoveryStats() map[string]interface{} {
	ds.mu.RLock()
	defer ds.mu.RUnlock()

	stats := map[string]interface{}{
		"running":            ds.running,
		"enabled_platforms":  ds.getEnabledPlatforms(),
		"workers":            ds.config.Workers,
		"discovery_interval": ds.config.Interval,
		"cache_enabled":      ds.config.Cache.Enabled,
		"cache_ttl":          ds.config.Cache.TTL,
	}

	return stats
}

// getEnabledPlatforms returns list of enabled platforms
func (ds *DiscoveryService) getEnabledPlatforms() []string {
	var platforms []string
	for _, platformConfig := range ds.config.Platforms {
		if platformConfig.Enabled {
			platforms = append(platforms, platformConfig.Platform)
		}
	}
	return platforms
}