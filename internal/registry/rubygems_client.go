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
    "github.com/spf13/viper"
)

// RubyGemsClient handles interactions with RubyGems.org API
type RubyGemsClient struct {
	baseURL    string
	httpClient *http.Client
	cache      map[string]*CacheEntry
	cacheTTL   time.Duration
}

// RubyGemsSearchResponse represents RubyGems search API response
type RubyGemsSearchResponse []struct {
	Name             string                 `json:"name"`
	Downloads        int64                  `json:"downloads"`
	Version          string                 `json:"version"`
	VersionDownloads int64                  `json:"version_downloads"`
	Platform         string                 `json:"platform"`
	Authors          string                 `json:"authors"`
	Info             string                 `json:"info"`
	Licenses         []string               `json:"licenses"`
	Metadata         map[string]interface{} `json:"metadata"`
	SHA              string                 `json:"sha"`
	ProjectURI       string                 `json:"project_uri"`
	GemURI           string                 `json:"gem_uri"`
	HomepageURI      string                 `json:"homepage_uri"`
	WikiURI          string                 `json:"wiki_uri"`
	DocumentationURI string                 `json:"documentation_uri"`
	MailingListURI   string                 `json:"mailing_list_uri"`
	SourceCodeURI    string                 `json:"source_code_uri"`
	BugTrackerURI    string                 `json:"bug_tracker_uri"`
	ChangelogURI     string                 `json:"changelog_uri"`
	FundingURI       string                 `json:"funding_uri"`
}

// RubyGemsGemInfo represents detailed gem information
type RubyGemsGemInfo struct {
	Name             string                 `json:"name"`
	Downloads        int64                  `json:"downloads"`
	Version          string                 `json:"version"`
	VersionDownloads int64                  `json:"version_downloads"`
	Platform         string                 `json:"platform"`
	Authors          string                 `json:"authors"`
	Info             string                 `json:"info"`
	Licenses         []string               `json:"licenses"`
	Metadata         map[string]interface{} `json:"metadata"`
	SHA              string                 `json:"sha"`
	ProjectURI       string                 `json:"project_uri"`
	GemURI           string                 `json:"gem_uri"`
	HomepageURI      string                 `json:"homepage_uri"`
	WikiURI          string                 `json:"wiki_uri"`
	DocumentationURI string                 `json:"documentation_uri"`
	MailingListURI   string                 `json:"mailing_list_uri"`
	SourceCodeURI    string                 `json:"source_code_uri"`
	BugTrackerURI    string                 `json:"bug_tracker_uri"`
	ChangelogURI     string                 `json:"changelog_uri"`
	FundingURI       string                 `json:"funding_uri"`
	Dependencies     struct {
		Development []struct {
			Name         string `json:"name"`
			Requirements string `json:"requirements"`
		} `json:"development"`
		Runtime []struct {
			Name         string `json:"name"`
			Requirements string `json:"requirements"`
		} `json:"runtime"`
	} `json:"dependencies"`
}

// RubyGemsVersions represents gem versions response
type RubyGemsVersions []struct {
	Number       string            `json:"number"`
	BuiltAt      time.Time         `json:"built_at"`
	Summary      string            `json:"summary"`
	Description  string            `json:"description"`
	Authors      string            `json:"authors"`
	Platform     string            `json:"platform"`
	RubyVersion  string            `json:"ruby_version"`
	Prerelease   bool              `json:"prerelease"`
	Licenses     []string          `json:"licenses"`
	Requirements map[string]string `json:"requirements"`
	SHA          string            `json:"sha"`
}

// NewRubyGemsClient creates a new RubyGems client
func NewRubyGemsClient() *RubyGemsClient {
	return &RubyGemsClient{
		baseURL: "https://rubygems.org/api/v1",
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		cache:    make(map[string]*CacheEntry),
		cacheTTL: 5 * time.Minute,
	}
}

// GetPackageInfo retrieves package information from RubyGems.org
func (c *RubyGemsClient) GetPackageInfo(ctx context.Context, gemName, version string) (*types.PackageMetadata, error) {
	cacheKey := fmt.Sprintf("%s:%s", gemName, version)

	// Check cache first
	if entry, exists := c.cache[cacheKey]; exists {
		if time.Since(entry.Timestamp) < c.cacheTTL {
			if metadata, ok := entry.Data.(*types.PackageMetadata); ok {
				return metadata, nil
			}
		}
	}

	// Get gem information
	gemURL := fmt.Sprintf("%s/gems/%s.json", c.baseURL, gemName)
	req, err := http.NewRequestWithContext(ctx, "GET", gemURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch gem info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gem not found: %s", resp.Status)
	}

	var gemInfo RubyGemsGemInfo
	if err := json.NewDecoder(resp.Body).Decode(&gemInfo); err != nil {
		return nil, fmt.Errorf("failed to parse gem info: %w", err)
	}

	// Get version-specific information if version is specified
	var versionInfo *RubyGemsVersions
	if version != "" && version != gemInfo.Version {
		versionsURL := fmt.Sprintf("%s/versions/%s.json", c.baseURL, gemName)
		versionReq, err := http.NewRequestWithContext(ctx, "GET", versionsURL, nil)
		if err == nil {
			versionResp, err := c.httpClient.Do(versionReq)
			if err == nil && versionResp.StatusCode == http.StatusOK {
				var versions RubyGemsVersions
				if json.NewDecoder(versionResp.Body).Decode(&versions) == nil {
					for _, v := range versions {
						if v.Number == version {
							versionInfo = &versions
							break
						}
					}
				}
				versionResp.Body.Close()
			}
		}
	}

	// Extract dependencies
	var dependencies []string
	for _, dep := range gemInfo.Dependencies.Runtime {
		dependencies = append(dependencies, dep.Name)
	}

	// Extract keywords from metadata
	var keywords []string
	if tags, ok := gemInfo.Metadata["tags"]; ok {
		if tagStr, ok := tags.(string); ok {
			keywords = strings.Split(tagStr, ",")
			for i, keyword := range keywords {
				keywords[i] = strings.TrimSpace(keyword)
			}
		}
	}

	// Extract maintainers from authors
	var maintainers []string
	if gemInfo.Authors != "" {
		// Authors can be comma-separated
		authorList := strings.Split(gemInfo.Authors, ",")
		for _, author := range authorList {
			maintainers = append(maintainers, strings.TrimSpace(author))
		}
	}

	// Determine the version to use
	useVersion := gemInfo.Version
	if version != "" {
		useVersion = version
	}

	// Get description from version info if available
	description := gemInfo.Info
	if versionInfo != nil {
		for _, v := range *versionInfo {
			if v.Number == useVersion && v.Description != "" {
				description = v.Description
				break
			}
		}
	}

	// Convert to PackageMetadata
	metadata := &types.PackageMetadata{
		Name:         gemName,
		Version:      useVersion,
		Description:  description,
		Homepage:     gemInfo.HomepageURI,
		Registry:     "rubygems",
		Author:       gemInfo.Authors,
		License:      strings.Join(gemInfo.Licenses, ", "),
		Keywords:     keywords,
		Dependencies: dependencies,
		Maintainers:  maintainers,
		Downloads:    gemInfo.Downloads,
		LastUpdated:  nil, // RubyGems API doesn't provide last updated easily
	}

	// Cache the result
	c.cache[cacheKey] = &CacheEntry{
		Data:      metadata,
		Timestamp: time.Now(),
	}

	return metadata, nil
}

// SearchPackages searches for packages in RubyGems.org
func (c *RubyGemsClient) SearchPackages(ctx context.Context, query string) ([]*types.PackageMetadata, error) {
	// Use RubyGems search API
	searchURL := fmt.Sprintf("%s/search.json?query=%s", c.baseURL, url.QueryEscape(query))

	req, err := http.NewRequestWithContext(ctx, "GET", searchURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create search request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to search gems: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("search failed: %s", resp.Status)
	}

	var searchResp RubyGemsSearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&searchResp); err != nil {
		return nil, fmt.Errorf("failed to parse search response: %w", err)
	}

	var packages []*types.PackageMetadata
	for _, gem := range searchResp {
		// Extract maintainers from authors
		var maintainers []string
		if gem.Authors != "" {
			authorList := strings.Split(gem.Authors, ",")
			for _, author := range authorList {
				maintainers = append(maintainers, strings.TrimSpace(author))
			}
		}

		packageMetadata := &types.PackageMetadata{
			Name:         gem.Name,
			Version:      gem.Version,
			Description:  gem.Info,
			Registry:     "rubygems",
			Homepage:     gem.HomepageURI,
			Author:       gem.Authors,
			License:      strings.Join(gem.Licenses, ", "),
			Keywords:     []string{}, // Search results don't include keywords
			Dependencies: []string{}, // Search results don't include dependencies
			Maintainers:  maintainers,
			Downloads:    gem.Downloads,
			LastUpdated:  nil, // Not available in search results
		}

		packages = append(packages, packageMetadata)
	}

	return packages, nil
}

// GetPopularPackages returns a list of popular Ruby gems
func (c *RubyGemsClient) GetPopularPackages(limit int) ([]string, error) {
	// Return a curated list of popular Ruby gems
	popularPackages := []string{
		"rails",
		"bundler",
		"rake",
		"rspec",
		"puma",
		"nokogiri",
		"devise",
		"activerecord",
		"activesupport",
		"thor",
		"json",
		"minitest",
		"rack",
		"sinatra",
		"capistrano",
		"sidekiq",
		"redis",
		"pg",
		"mysql2",
		"sqlite3",
		"faraday",
		"httparty",
		"factory_bot",
		"rubocop",
		"pry",
	}

	if limit > 0 && limit < len(popularPackages) {
		return popularPackages[:limit], nil
	}
	return popularPackages, nil
}

// GetPopularNames retrieves popular gems using a configurable endpoint (expects RubyGemsSearchResponse format)
func (c *RubyGemsClient) GetPopularNames(ctx context.Context, limit int) ([]string, error) {
    base := viper.GetString("detector.endpoints.rubygems_popular")
    if base == "" { base = fmt.Sprintf("%s/search.json?query=&sort=downloads", c.baseURL) }
    req, err := http.NewRequestWithContext(ctx, "GET", base, nil)
    if err != nil { return nil, fmt.Errorf("failed to create request: %w", err) }
    resp, err := c.httpClient.Do(req)
    if err != nil { return nil, fmt.Errorf("failed to fetch popular gems: %w", err) }
    defer resp.Body.Close()
    if resp.StatusCode != http.StatusOK { return nil, fmt.Errorf("rubygems popular status %d", resp.StatusCode) }
    var arr RubyGemsSearchResponse
    if err := json.NewDecoder(resp.Body).Decode(&arr); err != nil { return nil, fmt.Errorf("decode popular: %w", err) }
    names := make([]string, 0, len(arr))
    for _, g := range arr { if g.Name != "" { names = append(names, g.Name) } }
    if limit > 0 && len(names) > limit { names = names[:limit] }
    return names, nil
}

// ClearCache clears the client cache
func (c *RubyGemsClient) ClearCache() {
	c.cache = make(map[string]*CacheEntry)
}

// SetCacheTTL sets the cache TTL
func (c *RubyGemsClient) SetCacheTTL(ttl time.Duration) {
	c.cacheTTL = ttl
}
