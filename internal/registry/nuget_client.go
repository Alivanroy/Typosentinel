package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// NuGetClient handles interactions with NuGet.org API
type NuGetClient struct {
	baseURL    string
	httpClient *http.Client
	cache      map[string]*CacheEntry
	cacheTTL   time.Duration
}

// NuGetSearchResponse represents NuGet search API response
type NuGetSearchResponse struct {
	TotalHits int `json:"totalHits"`
	Data      []struct {
		ID             string   `json:"id"`
		Version        string   `json:"version"`
		Description    string   `json:"description"`
		Summary        string   `json:"summary"`
		Title          string   `json:"title"`
		IconURL        string   `json:"iconUrl"`
		LicenseURL     string   `json:"licenseUrl"`
		ProjectURL     string   `json:"projectUrl"`
		Tags           []string `json:"tags"`
		Authors        []string `json:"authors"`
		Owners         []string `json:"owners"`
		TotalDownloads int64    `json:"totalDownloads"`
		Verified       bool     `json:"verified"`
		Versions       []struct {
			Version   string `json:"version"`
			Downloads int64  `json:"downloads"`
		} `json:"versions"`
	} `json:"data"`
}

// NuGetPackageInfo represents detailed package information
type NuGetPackageInfo struct {
	CatalogEntry struct {
		ID               string `json:"id"`
		Version          string `json:"version"`
		Description      string `json:"description"`
		Summary          string `json:"summary"`
		Title            string `json:"title"`
		IconURL          string `json:"iconUrl"`
		LicenseURL       string `json:"licenseUrl"`
		ProjectURL       string `json:"projectUrl"`
		Published        string `json:"published"`
		Authors          string `json:"authors"`
		Owners           string `json:"owners"`
		Tags             string `json:"tags"`
		DependencyGroups []struct {
			TargetFramework string `json:"targetFramework"`
			Dependencies    []struct {
				ID    string `json:"id"`
				Range string `json:"range"`
			} `json:"dependencies"`
		} `json:"dependencyGroups"`
	} `json:"catalogEntry"`
	PackageContent string `json:"packageContent"`
	Registration   string `json:"registration"`
}

// NewNuGetClient creates a new NuGet client
func NewNuGetClient() *NuGetClient {
	return &NuGetClient{
		baseURL: "https://api.nuget.org/v3-flatcontainer",
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		cache:    make(map[string]*CacheEntry),
		cacheTTL: 5 * time.Minute,
	}
}

// GetPackageInfo retrieves package information from NuGet.org
func (c *NuGetClient) GetPackageInfo(ctx context.Context, packageName, version string) (*types.PackageMetadata, error) {
	cacheKey := fmt.Sprintf("%s:%s", packageName, version)

	// Check cache first
	if entry, exists := c.cache[cacheKey]; exists {
		if time.Since(entry.Timestamp) < c.cacheTTL {
			if metadata, ok := entry.Data.(*types.PackageMetadata); ok {
				return metadata, nil
			}
		}
	}

	// Use NuGet API v3 registration endpoint
	registrationURL := fmt.Sprintf("https://api.nuget.org/v3/registration5-semver1/%s/%s.json",
		strings.ToLower(packageName), strings.ToLower(version))

	req, err := http.NewRequestWithContext(ctx, "GET", registrationURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch package info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("package not found: %s", resp.Status)
	}

	var packageInfo NuGetPackageInfo
	if err := json.NewDecoder(resp.Body).Decode(&packageInfo); err != nil {
		return nil, fmt.Errorf("failed to parse package info: %w", err)
	}

	// Parse published date
	var lastUpdated *time.Time
	if packageInfo.CatalogEntry.Published != "" {
		if parsed, err := time.Parse(time.RFC3339, packageInfo.CatalogEntry.Published); err == nil {
			lastUpdated = &parsed
		}
	}

	// Extract dependencies
	var dependencies []string
	for _, depGroup := range packageInfo.CatalogEntry.DependencyGroups {
		for _, dep := range depGroup.Dependencies {
			dependencies = append(dependencies, dep.ID)
		}
	}

	// Extract keywords from tags
	var keywords []string
	if packageInfo.CatalogEntry.Tags != "" {
		keywords = strings.Split(packageInfo.CatalogEntry.Tags, " ")
	}

	// Extract maintainers
	var maintainers []string
	if packageInfo.CatalogEntry.Owners != "" {
		maintainers = strings.Split(packageInfo.CatalogEntry.Owners, ",")
		for i, maintainer := range maintainers {
			maintainers[i] = strings.TrimSpace(maintainer)
		}
	}

	// Convert to PackageMetadata
	metadata := &types.PackageMetadata{
		Name:         packageName,
		Version:      version,
		Description:  packageInfo.CatalogEntry.Description,
		Homepage:     packageInfo.CatalogEntry.ProjectURL,
		Registry:     "nuget",
		Author:       packageInfo.CatalogEntry.Authors,
		License:      "", // License info would need separate API call
		Keywords:     keywords,
		Dependencies: dependencies,
		Maintainers:  maintainers,
		Downloads:    0, // Download stats would need separate API call
		LastUpdated:  lastUpdated,
	}

	// Use summary if description is empty
	if metadata.Description == "" {
		metadata.Description = packageInfo.CatalogEntry.Summary
	}

	// Cache the result
	c.cache[cacheKey] = &CacheEntry{
		Data:      metadata,
		Timestamp: time.Now(),
	}

	return metadata, nil
}

// SearchPackages searches for packages in NuGet.org
func (c *NuGetClient) SearchPackages(ctx context.Context, query string) ([]*types.PackageMetadata, error) {
	// Use NuGet search API v3
	searchURL := fmt.Sprintf("https://azuresearch-usnc.nuget.org/query?q=%s&take=20",
		url.QueryEscape(query))

	req, err := http.NewRequestWithContext(ctx, "GET", searchURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create search request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to search packages: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("search failed: %s", resp.Status)
	}

	var searchResp NuGetSearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&searchResp); err != nil {
		return nil, fmt.Errorf("failed to parse search response: %w", err)
	}

	var packages []*types.PackageMetadata
	for _, pkg := range searchResp.Data {
		// Extract maintainers
		var maintainers []string
		maintainers = append(maintainers, pkg.Authors...)
		maintainers = append(maintainers, pkg.Owners...)

		packageMetadata := &types.PackageMetadata{
			Name:         pkg.ID,
			Version:      pkg.Version,
			Description:  pkg.Description,
			Registry:     "nuget",
			Homepage:     pkg.ProjectURL,
			Author:       strings.Join(pkg.Authors, ", "),
			License:      "", // License info not available in search results
			Keywords:     pkg.Tags,
			Dependencies: []string{}, // Dependencies not available in search results
			Maintainers:  maintainers,
			Downloads:    pkg.TotalDownloads,
			LastUpdated:  nil, // Not available in search results
		}

		// Use summary if description is empty
		if packageMetadata.Description == "" {
			packageMetadata.Description = pkg.Summary
		}

		packages = append(packages, packageMetadata)
	}

	return packages, nil
}

// GetPopularPackages returns a list of popular NuGet packages
func (c *NuGetClient) GetPopularPackages(limit int) ([]string, error) {
	// Return a curated list of popular NuGet packages
	popularPackages := []string{
		"Newtonsoft.Json",
		"Microsoft.Extensions.DependencyInjection",
		"Microsoft.Extensions.Logging",
		"Microsoft.EntityFrameworkCore",
		"AutoMapper",
		"Serilog",
		"FluentValidation",
		"Microsoft.AspNetCore.Mvc",
		"System.Text.Json",
		"Microsoft.Extensions.Configuration",
		"NUnit",
		"xunit",
		"Moq",
		"Microsoft.Extensions.Hosting",
		"Swashbuckle.AspNetCore",
		"Microsoft.EntityFrameworkCore.SqlServer",
		"Microsoft.AspNetCore.Authentication.JwtBearer",
		"StackExchange.Redis",
		"Polly",
		"MediatR",
	}

	if limit > 0 && limit < len(popularPackages) {
		return popularPackages[:limit], nil
	}
	return popularPackages, nil
}

// ClearCache clears the client cache
func (c *NuGetClient) ClearCache() {
	c.cache = make(map[string]*CacheEntry)
}

// SetCacheTTL sets the cache TTL
func (c *NuGetClient) SetCacheTTL(ttl time.Duration) {
	c.cacheTTL = ttl
}
