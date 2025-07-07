package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// NPMClient handles interactions with the NPM registry API
type NPMClient struct {
	baseURL    string
	httpClient *http.Client
	cache      map[string]*CacheEntry
	cacheTTL   time.Duration
}

// CacheEntry represents a cached registry response
type CacheEntry struct {
	Data      interface{}
	Timestamp time.Time
}

// NPMPackageInfo represents package information from NPM registry
type NPMPackageInfo struct {
	Name                 string                 `json:"name"`
	Version              string                 `json:"version"`
	Description          string                 `json:"description"`
	Keywords             []string               `json:"keywords"`
	Homepage             string                 `json:"homepage"`
	Bugs                 map[string]interface{} `json:"bugs"`
	License              interface{}            `json:"license"`
	Author               interface{}            `json:"author"`
	Maintainers          []interface{}          `json:"maintainers"`
	Repository           map[string]interface{} `json:"repository"`
	Dependencies         map[string]string      `json:"dependencies"`
	DevDependencies      map[string]string      `json:"devDependencies"`
	PeerDependencies     map[string]string      `json:"peerDependencies"`
	OptionalDependencies map[string]string      `json:"optionalDependencies"`
	Engines              map[string]string      `json:"engines"`
	Scripts              map[string]string      `json:"scripts"`
	Dist                 NPMDistInfo            `json:"dist"`
	Time                 map[string]string      `json:"time"`
	Versions             map[string]interface{} `json:"versions"`
}

// NPMDistInfo represents distribution information
type NPMDistInfo struct {
	Shasum       string `json:"shasum"`
	Tarball      string `json:"tarball"`
	Integrity    string `json:"integrity"`
	FileCount    int    `json:"fileCount"`
	UnpackedSize int    `json:"unpackedSize"`
}

// NPMDownloadStats represents download statistics
type NPMDownloadStats struct {
	Downloads int    `json:"downloads"`
	Start     string `json:"start"`
	End       string `json:"end"`
	Package   string `json:"package"`
}

// NewNPMClient creates a new NPM registry client
func NewNPMClient() *NPMClient {
	return &NPMClient{
		baseURL: "https://registry.npmjs.org",
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		cache:    make(map[string]*CacheEntry),
		cacheTTL: 5 * time.Minute,
	}
}

// GetPackageInfo fetches package information from NPM registry
func (c *NPMClient) GetPackageInfo(ctx context.Context, packageName string) (*NPMPackageInfo, error) {
	if packageName == "" {
		return nil, fmt.Errorf("package name cannot be empty")
	}

	// Check cache first
	cacheKey := fmt.Sprintf("package:%s", packageName)
	if entry, exists := c.cache[cacheKey]; exists {
		if time.Since(entry.Timestamp) < c.cacheTTL {
			if info, ok := entry.Data.(*NPMPackageInfo); ok {
				logrus.Debugf("Cache hit for package: %s", packageName)
				return info, nil
			}
		}
		// Remove expired entry
		delete(c.cache, cacheKey)
	}

	// Encode package name for URL
	encodedName := url.PathEscape(packageName)
	url := fmt.Sprintf("%s/%s", c.baseURL, encodedName)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "TypoSentinel/1.0")

	logrus.Debugf("Fetching package info for: %s", packageName)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch package info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("package not found: %s", packageName)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var packageInfo NPMPackageInfo
	if err := json.NewDecoder(resp.Body).Decode(&packageInfo); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Cache the result
	c.cache[cacheKey] = &CacheEntry{
		Data:      &packageInfo,
		Timestamp: time.Now(),
	}

	logrus.Debugf("Successfully fetched package info for: %s", packageName)
	return &packageInfo, nil
}

// GetDownloadStats fetches download statistics for a package
func (c *NPMClient) GetDownloadStats(ctx context.Context, packageName string, period string) (*NPMDownloadStats, error) {
	if packageName == "" {
		return nil, fmt.Errorf("package name cannot be empty")
	}

	// Validate period
	validPeriods := []string{"last-day", "last-week", "last-month", "last-year"}
	if period == "" {
		period = "last-week"
	}

	validPeriod := false
	for _, p := range validPeriods {
		if period == p {
			validPeriod = true
			break
		}
	}
	if !validPeriod {
		return nil, fmt.Errorf("invalid period: %s. Valid periods: %s", period, strings.Join(validPeriods, ", "))
	}

	// Check cache first
	cacheKey := fmt.Sprintf("downloads:%s:%s", packageName, period)
	if entry, exists := c.cache[cacheKey]; exists {
		if time.Since(entry.Timestamp) < c.cacheTTL {
			if stats, ok := entry.Data.(*NPMDownloadStats); ok {
				logrus.Debugf("Cache hit for download stats: %s (%s)", packageName, period)
				return stats, nil
			}
		}
		// Remove expired entry
		delete(c.cache, cacheKey)
	}

	// Encode package name for URL
	encodedName := url.PathEscape(packageName)
	url := fmt.Sprintf("https://api.npmjs.org/downloads/point/%s/%s", period, encodedName)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "TypoSentinel/1.0")

	logrus.Debugf("Fetching download stats for: %s (%s)", packageName, period)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch download stats: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("download stats not found for package: %s", packageName)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var downloadStats NPMDownloadStats
	if err := json.NewDecoder(resp.Body).Decode(&downloadStats); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Cache the result
	c.cache[cacheKey] = &CacheEntry{
		Data:      &downloadStats,
		Timestamp: time.Now(),
	}

	logrus.Debugf("Successfully fetched download stats for: %s (%s): %d downloads", packageName, period, downloadStats.Downloads)
	return &downloadStats, nil
}

// GetPackageVersions fetches all available versions for a package
func (c *NPMClient) GetPackageVersions(ctx context.Context, packageName string) ([]string, error) {
	packageInfo, err := c.GetPackageInfo(ctx, packageName)
	if err != nil {
		return nil, err
	}

	versions := make([]string, 0, len(packageInfo.Versions))
	for version := range packageInfo.Versions {
		versions = append(versions, version)
	}

	return versions, nil
}

// ClearCache clears the internal cache
func (c *NPMClient) ClearCache() {
	c.cache = make(map[string]*CacheEntry)
	logrus.Debug("NPM client cache cleared")
}

// SetCacheTTL sets the cache time-to-live duration
func (c *NPMClient) SetCacheTTL(ttl time.Duration) {
	c.cacheTTL = ttl
	logrus.Debugf("NPM client cache TTL set to: %v", ttl)
}
