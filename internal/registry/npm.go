package registry

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/typosentinel/typosentinel/pkg/types"
)

// NPMConnector implements the Connector interface for NPM registry
type NPMConnector struct {
	*BaseConnector
}

// NPMPackageInfo represents NPM package information
type NPMPackageInfo struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Version     string                 `json:"version"`
	Versions    map[string]interface{} `json:"versions"`
	Time        map[string]string      `json:"time"`
	Maintainers []NPMMaintainer        `json:"maintainers"`
	Author      NPMAuthor              `json:"author"`
	Repository  NPMRepository          `json:"repository"`
	Bugs        NPMBugs                `json:"bugs"`
	Homepage    string                 `json:"homepage"`
	Keywords    []string               `json:"keywords"`
	License     interface{}            `json:"license"`
	Readme      string                 `json:"readme"`
	DistTags    map[string]string      `json:"dist-tags"`
}

// NPMMaintainer represents an NPM package maintainer
type NPMMaintainer struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

// NPMAuthor represents an NPM package author
type NPMAuthor struct {
	Name  string `json:"name"`
	Email string `json:"email"`
	URL   string `json:"url"`
}

// NPMRepository represents repository information
type NPMRepository struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// NPMBugs represents bug tracking information
type NPMBugs struct {
	URL   string `json:"url"`
	Email string `json:"email"`
}

// NPMSearchResult represents NPM search results
type NPMSearchResult struct {
	Objects []NPMSearchObject `json:"objects"`
	Total   int               `json:"total"`
	Time    string            `json:"time"`
}

// NPMSearchObject represents a single search result
type NPMSearchObject struct {
	Package NPMSearchPackage `json:"package"`
	Score   NPMSearchScore   `json:"score"`
}

// NPMSearchPackage represents package info in search results
type NPMSearchPackage struct {
	Name        string            `json:"name"`
	Scope       string            `json:"scope"`
	Version     string            `json:"version"`
	Description string            `json:"description"`
	Keywords    []string          `json:"keywords"`
	Date        string            `json:"date"`
	Links       map[string]string `json:"links"`
	Author      NPMAuthor         `json:"author"`
	Publisher   NPMMaintainer     `json:"publisher"`
	Maintainers []NPMMaintainer   `json:"maintainers"`
}

// NPMSearchScore represents search scoring information
type NPMSearchScore struct {
	Final   float64 `json:"final"`
	Detail  NPMScoreDetail `json:"detail"`
}

// NPMScoreDetail represents detailed scoring
type NPMScoreDetail struct {
	Quality     float64 `json:"quality"`
	Popularity  float64 `json:"popularity"`
	Maintenance float64 `json:"maintenance"`
}

// NPMDownloads represents download statistics
type NPMDownloads struct {
	Downloads int    `json:"downloads"`
	Start     string `json:"start"`
	End       string `json:"end"`
	Package   string `json:"package"`
}

// NewNPMConnector creates a new NPM connector
func NewNPMConnector(client *http.Client) *NPMConnector {
	return &NPMConnector{
		BaseConnector: NewBaseConnector(client, "https://registry.npmjs.org", "npm"),
	}
}

// GetPackageInfo retrieves package information from NPM registry
func (nc *NPMConnector) GetPackageInfo(ctx context.Context, packageName string) (*types.PackageMetadata, error) {
	if err := validateNPMPackageName(packageName); err != nil {
		return nil, fmt.Errorf("invalid package name: %w", err)
	}

	// Encode package name for URL
	encodedName := nc.sanitizePackageName(packageName)
	url := nc.buildURL(encodedName)

	resp, err := nc.retryRequest(ctx, url, 3)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch package info: %w", err)
	}

	var npmInfo NPMPackageInfo
	if err := nc.parseJSONResponse(resp, &npmInfo); err != nil {
		return nil, fmt.Errorf("failed to parse NPM response: %w", err)
	}

	// Convert NPM info to standard package metadata
	metadata := nc.convertToPackageMetadata(&npmInfo)

	// Fetch additional statistics
	if err := nc.enrichWithDownloadStats(ctx, metadata); err != nil {
		// Log warning but don't fail
		fmt.Printf("Warning: failed to fetch download stats for %s: %v\n", packageName, err)
	}

	return metadata, nil
}

// SearchPackages searches for packages in NPM registry
func (nc *NPMConnector) SearchPackages(ctx context.Context, query string, limit int) ([]types.PackageMetadata, error) {
	if limit <= 0 {
		limit = 20
	}
	if limit > 250 {
		limit = 250 // NPM API limit
	}

	// Build search URL
	searchURL := fmt.Sprintf("https://registry.npmjs.org/-/v1/search?text=%s&size=%d",
		url.QueryEscape(query), limit)

	resp, err := nc.retryRequest(ctx, searchURL, 3)
	if err != nil {
		return nil, fmt.Errorf("failed to search packages: %w", err)
	}

	var searchResult NPMSearchResult
	if err := nc.parseJSONResponse(resp, &searchResult); err != nil {
		return nil, fmt.Errorf("failed to parse search response: %w", err)
	}

	// Convert search results to package metadata
	packages := make([]types.PackageMetadata, 0, len(searchResult.Objects))
	for _, obj := range searchResult.Objects {
		metadata := nc.convertSearchResultToPackageMetadata(&obj)
		packages = append(packages, *metadata)
	}

	return packages, nil
}

// GetPopularPackages retrieves popular packages from NPM
func (nc *NPMConnector) GetPopularPackages(ctx context.Context, limit int) ([]string, error) {
	if limit <= 0 {
		limit = 50
	}

	// Search for popular packages using a broad query
	_, err := nc.SearchPackages(ctx, "popular", limit)
	if err != nil {
		return nil, err
	}

	// TODO: Extract package names from search results
	// For now, return empty slice as PackageMetadata doesn't have Name field
	return []string{}, nil
}

// ValidatePackage validates if a package exists in NPM registry
func (nc *NPMConnector) ValidatePackage(ctx context.Context, packageName, version string) error {
	if err := validateNPMPackageName(packageName); err != nil {
		return fmt.Errorf("invalid package name: %w", err)
	}

	// If no version specified, just check if package exists
	if version == "" {
		_, err := nc.GetPackageInfo(ctx, packageName)
		return err
	}

	// Check specific version
	encodedName := nc.sanitizePackageName(packageName)
	normalizedVersion := normalizeVersion(version)
	url := nc.buildURL(fmt.Sprintf("%s/%s", encodedName, normalizedVersion))

	resp, err := nc.makeRequest(ctx, url)
	if err != nil {
		return fmt.Errorf("package version %s@%s not found: %w", packageName, version, err)
	}
	resp.Body.Close()

	return nil
}

// convertToPackageMetadata converts NPM package info to standard metadata
func (nc *NPMConnector) convertToPackageMetadata(npmInfo *NPMPackageInfo) *types.PackageMetadata {
	metadata := &types.PackageMetadata{
		Description:  npmInfo.Description,
		Keywords:     npmInfo.Keywords,
		Homepage:     npmInfo.Homepage,
		Maintainers:  make([]string, len(npmInfo.Maintainers)),
		Dependencies: make([]string, 0),
	}

	// Convert maintainers
	for i, maintainer := range npmInfo.Maintainers {
		metadata.Maintainers[i] = maintainer.Name
	}

	// Set author
	if npmInfo.Author.Name != "" {
		metadata.Author = npmInfo.Author.Name
	}

	// Set repository URL
	if npmInfo.Repository.URL != "" {
		metadata.Repository = npmInfo.Repository.URL
	}

	// Set license
	if npmInfo.License != nil {
		switch license := npmInfo.License.(type) {
		case string:
			metadata.License = license
		case map[string]interface{}:
			if licenseType, ok := license["type"].(string); ok {
				metadata.License = licenseType
			}
		}
	}

	// Parse creation and update times
	if createdTime, exists := npmInfo.Time["created"]; exists {
		if parsed, err := time.Parse(time.RFC3339, createdTime); err == nil {
			metadata.PublishedAt = &parsed
		}
	}

	if modifiedTime, exists := npmInfo.Time["modified"]; exists {
		if parsed, err := time.Parse(time.RFC3339, modifiedTime); err == nil {
			metadata.LastUpdated = &parsed
		}
	}

	// Note: Additional NPM-specific metadata could be stored in ExtraData field of Dependency
	// if needed for the specific use case

	return metadata
}

// convertSearchResultToPackageMetadata converts search result to package metadata
func (nc *NPMConnector) convertSearchResultToPackageMetadata(obj *NPMSearchObject) *types.PackageMetadata {
	pkg := &obj.Package
	metadata := &types.PackageMetadata{
		Description: pkg.Description,
		Keywords:    pkg.Keywords,
		Maintainers: make([]string, len(pkg.Maintainers)),
	}

	// Convert maintainers
	for i, maintainer := range pkg.Maintainers {
		metadata.Maintainers[i] = maintainer.Name
	}

	// Set author
	if pkg.Author.Name != "" {
		metadata.Author = pkg.Author.Name
	}

	// Parse date
	if pkg.Date != "" {
		if parsed, err := time.Parse(time.RFC3339, pkg.Date); err == nil {
			metadata.LastUpdated = &parsed
		}
	}

	// Note: Search-specific metadata could be stored in ExtraData field of Dependency
	// if needed for the specific use case

	return metadata
}

// enrichWithDownloadStats fetches and adds download statistics
// Note: This function is currently disabled as PackageMetadata doesn't have a Name field
// TODO: Pass package name as a separate parameter or use a different approach
func (nc *NPMConnector) enrichWithDownloadStats(ctx context.Context, metadata *types.PackageMetadata) error {
	// Temporarily disabled - would need package name as parameter
	return nil
}

// GetRegistryInfo returns NPM registry information
func (nc *NPMConnector) GetRegistryInfo() types.RegistryInfo {
	return types.RegistryInfo{
		Name:        "npm",
		URL:         "https://registry.npmjs.org",
		Supported:   true,
		Description: "Node Package Manager (npm) registry",
		Metadata: map[string]interface{}{
			"search_url":    "https://registry.npmjs.org/-/v1/search",
			"downloads_url": "https://api.npmjs.org/downloads",
			"website":       "https://www.npmjs.com",
			"package_count": "2M+",
		},
	}
}

// GetPackageVersions retrieves all versions of a package
func (nc *NPMConnector) GetPackageVersions(ctx context.Context, packageName string) ([]string, error) {
	// For now, return empty slice as we don't have access to all versions
	// In a full implementation, you'd need to fetch the package info and parse versions
	// TODO: Implement proper version fetching from NPM registry
	return []string{}, nil
}

// GetPackageDependencies retrieves package dependencies
func (nc *NPMConnector) GetPackageDependencies(ctx context.Context, packageName, version string) (map[string]string, error) {
	// Build URL for specific version
	encodedName := nc.sanitizePackageName(packageName)
	var url string
	if version != "" {
		normalizedVersion := normalizeVersion(version)
		url = nc.buildURL(fmt.Sprintf("%s/%s", encodedName, normalizedVersion))
	} else {
		url = nc.buildURL(encodedName)
	}

	resp, err := nc.retryRequest(ctx, url, 3)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch package dependencies: %w", err)
	}

	// For version-specific requests, the response structure is different
	if version != "" {
		var versionInfo map[string]interface{}
		if err := nc.parseJSONResponse(resp, &versionInfo); err != nil {
			return nil, fmt.Errorf("failed to parse version response: %w", err)
		}

		// Extract dependencies
		dependencies := make(map[string]string)
		if deps, exists := versionInfo["dependencies"]; exists {
			if depsMap, ok := deps.(map[string]interface{}); ok {
				for name, ver := range depsMap {
					if verStr, ok := ver.(string); ok {
						dependencies[name] = verStr
					}
				}
			}
		}

		return dependencies, nil
	}

	// For package info requests, parse the full response
	var npmInfo NPMPackageInfo
	if err := nc.parseJSONResponse(resp, &npmInfo); err != nil {
		return nil, fmt.Errorf("failed to parse NPM response: %w", err)
	}

	// Extract dependencies from the latest version
	if len(npmInfo.Versions) > 0 {
		// This would require parsing the versions map
		// For now, return empty dependencies
		return make(map[string]string), nil
	}

	return make(map[string]string), nil
}

// IsPackageDeprecated checks if a package is deprecated
func (nc *NPMConnector) IsPackageDeprecated(ctx context.Context, packageName string) (bool, string, error) {
	// TODO: Check deprecation status from NPM registry API
	// This would require parsing the package info response for deprecation warnings
	// For now, assume package is not deprecated

	return false, "", nil
}

// GetPackageSize retrieves package size information
func (nc *NPMConnector) GetPackageSize(ctx context.Context, packageName, version string) (int64, error) {
	// NPM doesn't provide direct size info in the registry API
	// This would typically require downloading the tarball or using bundlephobia API
	// For now, return 0 as placeholder
	return 0, fmt.Errorf("package size information not available from NPM registry API")
}

// Helper function to check if package name is scoped
func (nc *NPMConnector) isScopedPackage(packageName string) bool {
	return strings.HasPrefix(packageName, "@") && strings.Contains(packageName, "/")
}

// Helper function to extract scope from package name
func (nc *NPMConnector) extractScope(packageName string) string {
	if !nc.isScopedPackage(packageName) {
		return ""
	}

	parts := strings.Split(packageName, "/")
	if len(parts) > 0 {
		return strings.TrimPrefix(parts[0], "@")
	}

	return ""
}

// Helper function to extract package name without scope
func (nc *NPMConnector) extractPackageName(packageName string) string {
	if !nc.isScopedPackage(packageName) {
		return packageName
	}

	parts := strings.Split(packageName, "/")
	if len(parts) > 1 {
		return parts[1]
	}

	return packageName
}