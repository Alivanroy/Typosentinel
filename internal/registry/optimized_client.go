package registry

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// OptimizedRegistryClient provides high-performance registry operations
type OptimizedRegistryClient struct {
	client     *http.Client
	cache      *sync.Map
	connPool   *ConnectionPool
	config     *ClientConfig
	mu         sync.RWMutex
}

// ClientConfig holds configuration for the registry client
type ClientConfig struct {
	Timeout           time.Duration
	MaxConnections    int
	MaxIdleConns      int
	IdleConnTimeout   time.Duration
	RetryAttempts     int
	RetryDelay        time.Duration
	UserAgent         string
	EnableCompression bool
	EnableKeepAlive   bool
}

// ConnectionPool manages HTTP connections
type ConnectionPool struct {
	transport *http.Transport
	client    *http.Client
}

// RegistryResponse represents a response from a package registry
type RegistryResponse struct {
	Package   *types.Package `json:"package"`
	Metadata  interface{}    `json:"metadata"`
	CacheHit  bool           `json:"cache_hit"`
	Timestamp time.Time      `json:"timestamp"`
}

// NewOptimizedRegistryClient creates a new optimized registry client
func NewOptimizedRegistryClient(config *ClientConfig) *OptimizedRegistryClient {
	if config == nil {
		config = &ClientConfig{
			Timeout:           10 * time.Second,
			MaxConnections:    100,
			MaxIdleConns:      10,
			IdleConnTimeout:   90 * time.Second,
			RetryAttempts:     3,
			RetryDelay:        1 * time.Second,
			UserAgent:         "Typosentinel/1.0",
			EnableCompression: true,
			EnableKeepAlive:   true,
		}
	}

	connPool := NewConnectionPool(config)

	return &OptimizedRegistryClient{
		client:   connPool.client,
		cache:    &sync.Map{},
		connPool: connPool,
		config:   config,
	}
}

// NewConnectionPool creates a new connection pool
func NewConnectionPool(config *ClientConfig) *ConnectionPool {
	transport := &http.Transport{
		MaxIdleConns:        config.MaxIdleConns,
		MaxIdleConnsPerHost: config.MaxIdleConns,
		IdleConnTimeout:     config.IdleConnTimeout,
		DisableCompression:  !config.EnableCompression,
		DisableKeepAlives:   !config.EnableKeepAlive,
		MaxConnsPerHost:     config.MaxConnections,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   config.Timeout,
	}

	return &ConnectionPool{
		transport: transport,
		client:    client,
	}
}

// GetPackageInfo retrieves package information with caching and optimization
func (c *OptimizedRegistryClient) GetPackageInfo(ctx context.Context, registry, name, version string) (*RegistryResponse, error) {
	cacheKey := fmt.Sprintf("%s:%s:%s", registry, name, version)

	// Check cache first
	if cached, ok := c.cache.Load(cacheKey); ok {
		if response, ok := cached.(*RegistryResponse); ok {
			// Check if cache entry is still valid (5 minutes)
			if time.Since(response.Timestamp) < 5*time.Minute {
				response.CacheHit = true
				return response, nil
			}
			// Remove expired entry
			c.cache.Delete(cacheKey)
		}
	}

	// Fetch from registry with retry logic
	var response *RegistryResponse
	var err error

	for attempt := 0; attempt < c.config.RetryAttempts; attempt++ {
		response, err = c.fetchPackageInfo(ctx, registry, name, version)
		if err == nil {
			break
		}

		if attempt < c.config.RetryAttempts-1 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(c.config.RetryDelay * time.Duration(attempt+1)):
				// Exponential backoff
			}
		}
	}

	if err != nil {
		return nil, fmt.Errorf("failed to fetch package info after %d attempts: %w", c.config.RetryAttempts, err)
	}

	// Cache the response
	response.Timestamp = time.Now()
	response.CacheHit = false
	c.cache.Store(cacheKey, response)

	return response, nil
}

// fetchPackageInfo performs the actual HTTP request to fetch package information
func (c *OptimizedRegistryClient) fetchPackageInfo(ctx context.Context, registry, name, version string) (*RegistryResponse, error) {
	var url string
	switch registry {
	case "npm":
		url = fmt.Sprintf("https://registry.npmjs.org/%s/%s", name, version)
	case "pypi":
		url = fmt.Sprintf("https://pypi.org/pypi/%s/%s/json", name, version)
	case "go":
		url = fmt.Sprintf("https://proxy.golang.org/%s/@v/%s.info", name, version)
	case "crates.io":
		url = fmt.Sprintf("https://crates.io/api/v1/crates/%s/%s", name, version)
	case "maven":
		// Maven coordinates are typically groupId:artifactId
		parts := splitMavenCoordinates(name)
		if len(parts) >= 2 {
			url = fmt.Sprintf("https://search.maven.org/solrsearch/select?q=g:%s+AND+a:%s+AND+v:%s&wt=json", parts[0], parts[1], version)
		} else {
			return nil, fmt.Errorf("invalid maven coordinates: %s", name)
		}
	default:
		return nil, fmt.Errorf("unsupported registry: %s", registry)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("User-Agent", c.config.UserAgent)
	req.Header.Set("Accept", "application/json")
	if c.config.EnableCompression {
		req.Header.Set("Accept-Encoding", "gzip, deflate")
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("registry returned status %d for %s:%s:%s", resp.StatusCode, registry, name, version)
	}

	// Parse response based on registry type
	pkg, metadata, err := c.parseRegistryResponse(resp, registry, name, version)
	if err != nil {
		return nil, fmt.Errorf("failed to parse registry response: %w", err)
	}

	return &RegistryResponse{
		Package:  pkg,
		Metadata: metadata,
	}, nil
}

// parseRegistryResponse parses the HTTP response based on registry type
func (c *OptimizedRegistryClient) parseRegistryResponse(resp *http.Response, registry, name, version string) (*types.Package, interface{}, error) {
	// This is a simplified implementation
	// In a real implementation, you would parse the actual JSON responses from each registry
	pkg := &types.Package{
		Name:       name,
		Version:    version,
		Registry:   registry,
		RiskLevel:  types.SeverityUnknown,
		RiskScore:  0.0,
		AnalyzedAt: time.Now(),
	}

	// Simulate metadata extraction
	metadata := map[string]interface{}{
		"registry":    registry,
		"fetched_at":  time.Now(),
		"status_code": resp.StatusCode,
	}

	return pkg, metadata, nil
}

// GetPackagesBatch retrieves multiple packages in parallel
func (c *OptimizedRegistryClient) GetPackagesBatch(ctx context.Context, requests []PackageRequest) ([]*RegistryResponse, error) {
	if len(requests) == 0 {
		return nil, nil
	}

	// Use worker pool for parallel processing
	workerCount := min(len(requests), 10) // Limit concurrent requests
	jobChan := make(chan PackageRequest, len(requests))
	resultChan := make(chan BatchResult, len(requests))

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for req := range jobChan {
				resp, err := c.GetPackageInfo(ctx, req.Registry, req.Name, req.Version)
				resultChan <- BatchResult{
					Request:  req,
					Response: resp,
					Error:    err,
				}
			}
		}()
	}

	// Send jobs
	go func() {
		defer close(jobChan)
		for _, req := range requests {
			select {
			case jobChan <- req:
			case <-ctx.Done():
				return
			}
		}
	}()

	// Collect results
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	var responses []*RegistryResponse
	var errors []error

	for result := range resultChan {
		if result.Error != nil {
			errors = append(errors, result.Error)
		} else {
			responses = append(responses, result.Response)
		}
	}

	if len(errors) > 0 {
		return responses, fmt.Errorf("batch request completed with %d errors", len(errors))
	}

	return responses, nil
}

// PackageRequest represents a request for package information
type PackageRequest struct {
	Registry string
	Name     string
	Version  string
}

// BatchResult represents the result of a batch request
type BatchResult struct {
	Request  PackageRequest
	Response *RegistryResponse
	Error    error
}

// ClearCache clears the internal cache
func (c *OptimizedRegistryClient) ClearCache() {
	c.cache = &sync.Map{}
}

// GetCacheStats returns cache statistics
func (c *OptimizedRegistryClient) GetCacheStats() map[string]interface{} {
	count := 0
	c.cache.Range(func(key, value interface{}) bool {
		count++
		return true
	})

	return map[string]interface{}{
		"cache_entries": count,
		"max_connections": c.config.MaxConnections,
		"timeout": c.config.Timeout.String(),
	}
}

// Close closes the client and cleans up resources
func (c *OptimizedRegistryClient) Close() error {
	c.ClearCache()
	c.connPool.transport.CloseIdleConnections()
	return nil
}

// Helper functions

func splitMavenCoordinates(coordinates string) []string {
	// Split Maven coordinates like "org.springframework:spring-core"
	parts := make([]string, 0)
	if coordinates != "" {
		parts = append(parts, coordinates) // Simplified for now
	}
	return parts
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}