package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// CargoClient handles interactions with crates.io (Cargo registry)
type CargoClient struct {
	httpClient *http.Client
	baseURL    string
	cache      map[string]*types.PackageMetadata
	cacheTTL   time.Duration
}

// CargoSearchResponse represents the response from crates.io search API
type CargoSearchResponse struct {
	Crates []CargoCrateInfo `json:"crates"`
	Meta   CargoMeta        `json:"meta"`
}

// CargoCrateInfo represents crate information from crates.io
type CargoCrateInfo struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	Description     string    `json:"description"`
	Downloads       int64     `json:"downloads"`
	RecentDownloads int64     `json:"recent_downloads"`
	MaxVersion      string    `json:"max_version"`
	NewestVersion   string    `json:"newest_version"`
	UpdatedAt       time.Time `json:"updated_at"`
	CreatedAt       time.Time `json:"created_at"`
	Repository      string    `json:"repository"`
	Homepage        string    `json:"homepage"`
	Documentation   string    `json:"documentation"`
	Keywords        []string  `json:"keywords"`
	Categories      []string  `json:"categories"`
	ExactMatch      bool      `json:"exact_match"`
}

// CargoMeta represents metadata from search response
type CargoMeta struct {
	Total int `json:"total"`
}

// CargoCrateDetails represents detailed crate information
type CargoCrateDetails struct {
	Crate    CargoCrateMetadata `json:"crate"`
	Versions []CargoVersion     `json:"versions"`
	Keywords []CargoKeyword     `json:"keywords"`
}

// CargoCrateMetadata represents detailed crate metadata
type CargoCrateMetadata struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	Description     string    `json:"description"`
	Downloads       int64     `json:"downloads"`
	RecentDownloads int64     `json:"recent_downloads"`
	MaxVersion      string    `json:"max_version"`
	NewestVersion   string    `json:"newest_version"`
	UpdatedAt       time.Time `json:"updated_at"`
	CreatedAt       time.Time `json:"created_at"`
	Repository      string    `json:"repository"`
	Homepage        string    `json:"homepage"`
	Documentation   string    `json:"documentation"`
	Keywords        []string  `json:"keywords"`
	Categories      []string  `json:"categories"`
}

// CargoVersion represents version information
type CargoVersion struct {
	ID          int       `json:"id"`
	Crate       string    `json:"crate"`
	Num         string    `json:"num"`
	DL          int64     `json:"dl"`
	UpdatedAt   time.Time `json:"updated_at"`
	CreatedAt   time.Time `json:"created_at"`
	Yanked      bool      `json:"yanked"`
	License     string    `json:"license"`
	CrateSize   int64     `json:"crate_size"`
	PublishedBy CargoUser `json:"published_by"`
}

// CargoUser represents user information
type CargoUser struct {
	ID    int    `json:"id"`
	Login string `json:"login"`
	Name  string `json:"name"`
}

// CargoKeyword represents keyword information
type CargoKeyword struct {
	ID      string `json:"id"`
	Keyword string `json:"keyword"`
}

// NewCargoClient creates a new Cargo client
func NewCargoClient() *CargoClient {
	return &CargoClient{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		baseURL:  "https://crates.io/api/v1",
		cache:    make(map[string]*types.PackageMetadata),
		cacheTTL: 5 * time.Minute,
	}
}

// GetPackageInfo retrieves package information from crates.io
func (c *CargoClient) GetPackageInfo(ctx context.Context, name, version string) (*types.PackageMetadata, error) {
	cacheKey := fmt.Sprintf("%s@%s", name, version)
	if cached, exists := c.cache[cacheKey]; exists {
		return cached, nil
	}

	url := fmt.Sprintf("%s/crates/%s", c.baseURL, name)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("User-Agent", "TypoSentinel/1.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch crate info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API request failed with status %d", resp.StatusCode)
	}

	var details CargoCrateDetails
	if err := json.NewDecoder(resp.Body).Decode(&details); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	crate := details.Crate
	var targetVersion *CargoVersion
	var keywords []string

	// Extract keywords
	for _, kw := range details.Keywords {
		keywords = append(keywords, kw.Keyword)
	}

	// Find the requested version or latest
	if version != "" && version != "latest" {
		for _, v := range details.Versions {
			if v.Num == version {
				targetVersion = &v
				break
			}
		}
	}

	// If no specific version found or latest requested, use newest
	if targetVersion == nil && len(details.Versions) > 0 {
		targetVersion = &details.Versions[0] // Versions are sorted by newest first
	}

	var publishTime *time.Time
	var versionStr string
	var maintainers []string

	if targetVersion != nil {
		publishTime = &targetVersion.CreatedAt
		versionStr = targetVersion.Num
		if targetVersion.PublishedBy.Name != "" {
			maintainers = append(maintainers, targetVersion.PublishedBy.Name)
		} else if targetVersion.PublishedBy.Login != "" {
			maintainers = append(maintainers, targetVersion.PublishedBy.Login)
		}
	} else {
		versionStr = crate.MaxVersion
		publishTime = &crate.CreatedAt
	}

	metadata := &types.PackageMetadata{
		Name:        crate.Name,
		Version:     versionStr,
		Description: crate.Description,
		Maintainers: maintainers,
		Registry:    "cargo",
		Homepage:    crate.Homepage,
		Repository:  crate.Repository,
		Keywords:    keywords,
		Downloads:   crate.Downloads,
		CreatedAt:   crate.CreatedAt,
		UpdatedAt:   crate.UpdatedAt,
		LastUpdated: publishTime,
	}

	c.cache[cacheKey] = metadata
	return metadata, nil
}

// SearchPackages searches for packages in crates.io
func (c *CargoClient) SearchPackages(ctx context.Context, query string) ([]*types.PackageMetadata, error) {
	escapedQuery := url.QueryEscape(query)
	url := fmt.Sprintf("%s/crates?q=%s", c.baseURL, escapedQuery)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("User-Agent", "TypoSentinel/1.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to search crates: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API request failed with status %d", resp.StatusCode)
	}

	var searchResp CargoSearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&searchResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	var packages []*types.PackageMetadata
	for _, crate := range searchResp.Crates {
		metadata := &types.PackageMetadata{
			Name:        crate.Name,
			Version:     crate.MaxVersion,
			Description: crate.Description,
			Registry:    "cargo",
			Homepage:    crate.Homepage,
			Repository:  crate.Repository,
			Keywords:    crate.Keywords,
			Downloads:   crate.Downloads,
			CreatedAt:   crate.CreatedAt,
			UpdatedAt:   crate.UpdatedAt,
		}
		packages = append(packages, metadata)
	}

	return packages, nil
}

// GetPopularPackages retrieves popular packages from crates.io
func (c *CargoClient) GetPopularPackages(ctx context.Context, limit int) ([]*types.PackageMetadata, error) {
	url := fmt.Sprintf("%s/crates?sort=downloads&per_page=%d", c.baseURL, limit)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("User-Agent", "TypoSentinel/1.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch popular crates: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API request failed with status %d", resp.StatusCode)
	}

	var searchResp CargoSearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&searchResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	var packages []*types.PackageMetadata
	for _, crate := range searchResp.Crates {
		metadata := &types.PackageMetadata{
			Name:        crate.Name,
			Version:     crate.MaxVersion,
			Description: crate.Description,
			Registry:    "cargo",
			Homepage:    crate.Homepage,
			Repository:  crate.Repository,
			Keywords:    crate.Keywords,
			Downloads:   crate.Downloads,
			CreatedAt:   crate.CreatedAt,
			UpdatedAt:   crate.UpdatedAt,
		}
		packages = append(packages, metadata)
	}

	return packages, nil
}

// ClearCache clears the package cache
func (c *CargoClient) ClearCache() {
	c.cache = make(map[string]*types.PackageMetadata)
}

// SetCacheTTL sets the cache TTL
func (c *CargoClient) SetCacheTTL(ttl time.Duration) {
	c.cacheTTL = ttl
}