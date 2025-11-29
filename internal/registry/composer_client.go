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

// ComposerClient handles interactions with Packagist (Composer registry)
type ComposerClient struct {
	httpClient *http.Client
	baseURL    string
	cache      map[string]*types.PackageMetadata
	cacheTTL   time.Duration
}

// ComposerSearchResponse represents the response from Packagist search API
type ComposerSearchResponse struct {
	Results []ComposerPackageInfo `json:"results"`
	Total   int                   `json:"total"`
}

// ComposerPackageInfo represents package information from Packagist
type ComposerPackageInfo struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	URL         string `json:"url"`
	Repository  string `json:"repository"`
	Downloads   int    `json:"downloads"`
	Favers      int    `json:"favers"`
}

// ComposerPackageDetails represents detailed package information
type ComposerPackageDetails struct {
	Package ComposerPackageMetadata `json:"package"`
}

// ComposerPackageMetadata represents detailed package metadata
type ComposerPackageMetadata struct {
	Name        string                         `json:"name"`
	Description string                         `json:"description"`
	Time        string                         `json:"time"`
	Versions    map[string]ComposerVersionInfo `json:"versions"`
	Repository  ComposerRepository             `json:"repository"`
	Downloads   ComposerDownloads              `json:"downloads"`
}

// ComposerVersionInfo represents version-specific information
type ComposerVersionInfo struct {
	Name        string            `json:"name"`
	Version     string            `json:"version"`
	Description string            `json:"description"`
	Time        string            `json:"time"`
	Authors     []Author          `json:"authors"`
	Require     map[string]string `json:"require"`
}

// ComposerRepository represents repository information
type ComposerRepository struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// ComposerDownloads represents download statistics
type ComposerDownloads struct {
	Total   int `json:"total"`
	Monthly int `json:"monthly"`
	Daily   int `json:"daily"`
}

// Author represents package author information
type Author struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

// NewComposerClient creates a new Composer client
func NewComposerClient() *ComposerClient {
	return &ComposerClient{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		baseURL:  "https://packagist.org",
		cache:    make(map[string]*types.PackageMetadata),
		cacheTTL: 5 * time.Minute,
	}
}

// GetPackageInfo retrieves package information from Packagist
func (c *ComposerClient) GetPackageInfo(ctx context.Context, name, version string) (*types.PackageMetadata, error) {
	cacheKey := fmt.Sprintf("%s@%s", name, version)
	if cached, exists := c.cache[cacheKey]; exists {
		return cached, nil
	}

	url := fmt.Sprintf("%s/packages/%s.json", c.baseURL, name)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch package info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API request failed with status %d", resp.StatusCode)
	}

	var details ComposerPackageDetails
	if err := json.NewDecoder(resp.Body).Decode(&details); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	pkg := details.Package
	var authors []string
	var latestVersion string
	var publishTime *time.Time

	// Find the requested version or latest
	if version != "" && version != "latest" {
		if versionInfo, exists := pkg.Versions[version]; exists {
			latestVersion = versionInfo.Version
			for _, author := range versionInfo.Authors {
				authors = append(authors, author.Name)
			}
			if versionInfo.Time != "" {
				if t, err := time.Parse(time.RFC3339, versionInfo.Time); err == nil {
					publishTime = &t
				}
			}
		}
	} else {
		// Find latest version
		for v, versionInfo := range pkg.Versions {
			if latestVersion == "" || v > latestVersion {
				latestVersion = versionInfo.Version
				authors = nil
				for _, author := range versionInfo.Authors {
					authors = append(authors, author.Name)
				}
				if versionInfo.Time != "" {
					if t, err := time.Parse(time.RFC3339, versionInfo.Time); err == nil {
						publishTime = &t
					}
				}
			}
		}
	}

	metadata := &types.PackageMetadata{
		Name:        pkg.Name,
		Version:     latestVersion,
		Description: pkg.Description,
		Maintainers: authors,
		Registry:    "composer",
		Homepage:    pkg.Repository.URL,
		Downloads:   int64(pkg.Downloads.Total),
		LastUpdated: publishTime,
	}

	c.cache[cacheKey] = metadata
	return metadata, nil
}

// SearchPackages searches for packages in Packagist
func (c *ComposerClient) SearchPackages(ctx context.Context, query string) ([]*types.PackageMetadata, error) {
	escapedQuery := url.QueryEscape(query)
	url := fmt.Sprintf("%s/search.json?q=%s", c.baseURL, escapedQuery)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to search packages: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API request failed with status %d", resp.StatusCode)
	}

	var searchResp ComposerSearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&searchResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	var packages []*types.PackageMetadata
	for _, pkg := range searchResp.Results {
		metadata := &types.PackageMetadata{
			Name:        pkg.Name,
			Description: pkg.Description,
			Registry:    "composer",
			Homepage:    pkg.Repository,
			Downloads:   int64(pkg.Downloads),
		}
		packages = append(packages, metadata)
	}

	return packages, nil
}

// GetPopularPackages retrieves popular packages from Packagist
func (c *ComposerClient) GetPopularPackages(ctx context.Context, limit int) ([]*types.PackageMetadata, error) {
	url := fmt.Sprintf("%s/packages/list.json?type=package", c.baseURL)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch popular packages: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API request failed with status %d", resp.StatusCode)
	}

	var packageList map[string][]string
	if err := json.NewDecoder(resp.Body).Decode(&packageList); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	var packages []*types.PackageMetadata
	count := 0
	for _, pkgNames := range packageList {
		for _, name := range pkgNames {
			if count >= limit {
				break
			}
			metadata := &types.PackageMetadata{
				Name:     name,
				Registry: "composer",
			}
			packages = append(packages, metadata)
			count++
		}
		if count >= limit {
			break
		}
	}

	return packages, nil
}

// GetPopularNames tries Packagist popular endpoint, falls back to list
func (c *ComposerClient) GetPopularNames(ctx context.Context, limit int) ([]string, error) {
    // Attempt popular endpoint
    popURL := "https://packagist.org/explore/popular.json"
    req, err := http.NewRequestWithContext(ctx, "GET", popURL, nil)
    if err == nil {
        resp, err2 := c.httpClient.Do(req)
        if err2 == nil && resp.StatusCode == http.StatusOK {
            defer resp.Body.Close()
            var data struct{ Packages []struct{ Name string `json:"name"` } `json:"packages"` }
            if json.NewDecoder(resp.Body).Decode(&data) == nil {
                names := make([]string, 0, len(data.Packages))
                for _, p := range data.Packages { if p.Name != "" { names = append(names, p.Name) } }
                if limit > 0 && len(names) > limit { names = names[:limit] }
                if len(names) > 0 { return names, nil }
            }
        }
    }
    // Fallback to list
    pkgs, err := c.GetPopularPackages(ctx, limit)
    if err != nil { return nil, err }
    names := make([]string, 0, len(pkgs))
    for _, p := range pkgs { names = append(names, p.Name) }
    return names, nil
}

// ClearCache clears the package cache
func (c *ComposerClient) ClearCache() {
	c.cache = make(map[string]*types.PackageMetadata)
}

// SetCacheTTL sets the cache TTL
func (c *ComposerClient) SetCacheTTL(ttl time.Duration) {
	c.cacheTTL = ttl
}
