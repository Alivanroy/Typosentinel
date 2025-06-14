package registry

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/typosentinel/typosentinel/pkg/types"
)

// PyPIConnector implements the Connector interface for PyPI registry
type PyPIConnector struct {
	*BaseConnector
}

// PyPIPackageInfo represents PyPI package information
type PyPIPackageInfo struct {
	Info     PyPIInfo                   `json:"info"`
	Releases map[string][]PyPIRelease  `json:"releases"`
	URLs     []PyPIURL                  `json:"urls"`
	Metadata map[string]interface{}     `json:"metadata"`
}

// PyPIInfo represents package info section
type PyPIInfo struct {
	Author          string   `json:"author"`
	AuthorEmail     string   `json:"author_email"`
	BugtrackURL     string   `json:"bugtrack_url"`
	Classifiers     []string `json:"classifiers"`
	Description     string   `json:"description"`
	DescriptionType string   `json:"description_content_type"`
	DownloadURL     string   `json:"download_url"`
	Downloads       PyPIDownloads `json:"downloads"`
	HomePage        string   `json:"home_page"`
	Keywords        string   `json:"keywords"`
	License         string   `json:"license"`
	Maintainer      string   `json:"maintainer"`
	MaintainerEmail string   `json:"maintainer_email"`
	Name            string   `json:"name"`
	PackageURL      string   `json:"package_url"`
	Platform        string   `json:"platform"`
	ProjectURL      string   `json:"project_url"`
	ProjectURLs     map[string]string `json:"project_urls"`
	ReleaseURL      string   `json:"release_url"`
	RequiresDist    []string `json:"requires_dist"`
	RequiresPython  string   `json:"requires_python"`
	Summary         string   `json:"summary"`
	Version         string   `json:"version"`
	Yanked          bool     `json:"yanked"`
	YankedReason    string   `json:"yanked_reason"`
}

// PyPIDownloads represents download statistics
type PyPIDownloads struct {
	LastDay   int `json:"last_day"`
	LastWeek  int `json:"last_week"`
	LastMonth int `json:"last_month"`
}

// PyPIRelease represents a package release
type PyPIRelease struct {
	Comment         string    `json:"comment_text"`
	Digests         PyPIDigests `json:"digests"`
	Downloads       int       `json:"downloads"`
	Filename        string    `json:"filename"`
	HasSignature    bool      `json:"has_sig"`
	MD5Digest       string    `json:"md5_digest"`
	PackageType     string    `json:"packagetype"`
	PythonVersion   string    `json:"python_version"`
	RequiresPython  string    `json:"requires_python"`
	Size            int       `json:"size"`
	UploadTime      string    `json:"upload_time"`
	UploadTimeISO   string    `json:"upload_time_iso_8601"`
	URL             string    `json:"url"`
	Yanked          bool      `json:"yanked"`
	YankedReason    string    `json:"yanked_reason"`
}

// PyPIDigests represents file digests
type PyPIDigests struct {
	MD5    string `json:"md5"`
	SHA256 string `json:"sha256"`
}

// PyPIURL represents a package URL
type PyPIURL struct {
	Comment         string      `json:"comment_text"`
	Digests         PyPIDigests `json:"digests"`
	Downloads       int         `json:"downloads"`
	Filename        string      `json:"filename"`
	HasSignature    bool        `json:"has_sig"`
	MD5Digest       string      `json:"md5_digest"`
	PackageType     string      `json:"packagetype"`
	PythonVersion   string      `json:"python_version"`
	RequiresPython  string      `json:"requires_python"`
	Size            int         `json:"size"`
	UploadTime      string      `json:"upload_time"`
	UploadTimeISO   string      `json:"upload_time_iso_8601"`
	URL             string      `json:"url"`
	Yanked          bool        `json:"yanked"`
	YankedReason    string      `json:"yanked_reason"`
}

// PyPISearchResult represents PyPI search results
type PyPISearchResult struct {
	Meta    PyPISearchMeta    `json:"meta"`
	Objects []PyPISearchObject `json:"objects"`
}

// PyPISearchMeta represents search metadata
type PyPISearchMeta struct {
	API     string `json:"_api"`
	Count   int    `json:"count"`
	Total   int    `json:"total"`
}

// PyPISearchObject represents a search result object
type PyPISearchObject struct {
	Name        string  `json:"name"`
	Version     string  `json:"version"`
	Description string  `json:"description"`
	Summary     string  `json:"summary"`
	Keywords    string  `json:"keywords"`
	Author      string  `json:"author"`
	AuthorEmail string  `json:"author_email"`
	Maintainer  string  `json:"maintainer"`
	HomePage    string  `json:"home_page"`
	License     string  `json:"license"`
	Score       float64 `json:"_score"`
}

// NewPyPIConnector creates a new PyPI connector
func NewPyPIConnector(client *http.Client) *PyPIConnector {
	return &PyPIConnector{
		BaseConnector: NewBaseConnector(client, "https://pypi.org/pypi", "pypi"),
	}
}

// GetPackageInfo retrieves package information from PyPI registry
func (pc *PyPIConnector) GetPackageInfo(ctx context.Context, packageName string) (*types.PackageMetadata, error) {
	if err := validatePyPIPackageName(packageName); err != nil {
		return nil, fmt.Errorf("invalid package name: %w", err)
	}

	// Normalize package name (PyPI is case-insensitive and treats - and _ as equivalent)
	normalizedName := pc.normalizePackageName(packageName)
	url := pc.buildURL(fmt.Sprintf("%s/json", normalizedName))

	resp, err := pc.retryRequest(ctx, url, 3)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch package info: %w", err)
	}

	var pypiInfo PyPIPackageInfo
	if err := pc.parseJSONResponse(resp, &pypiInfo); err != nil {
		return nil, fmt.Errorf("failed to parse PyPI response: %w", err)
	}

	// Convert PyPI info to standard package metadata
	metadata := pc.convertToPackageMetadata(&pypiInfo)

	return metadata, nil
}

// SearchPackages searches for packages in PyPI registry
func (pc *PyPIConnector) SearchPackages(ctx context.Context, query string, limit int) ([]types.PackageMetadata, error) {
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100 // Reasonable limit for PyPI search
	}

	// PyPI doesn't have a built-in search API anymore, so we'll use a simple approach
	// In a real implementation, you might use external search services or scraping
	// For now, we'll return an error indicating search is not available
	return nil, fmt.Errorf("PyPI search API is not available - use specific package names")
}

// GetPopularPackages retrieves popular packages from PyPI
func (pc *PyPIConnector) GetPopularPackages(ctx context.Context, limit int) ([]string, error) {
	if limit <= 0 {
		limit = 50
	}

	// PyPI doesn't provide a direct "popular packages" API
	// In a real implementation, you might use external services or maintain a curated list
	// For now, return a hardcoded list of well-known packages
	popularPackages := []string{
		"requests", "urllib3", "setuptools", "certifi", "pip",
		"python-dateutil", "six", "numpy", "charset-normalizer", "idna",
		"pyyaml", "click", "colorama", "packaging", "pytz",
		"jinja2", "markupsafe", "wheel", "cffi", "cryptography",
		"pycparser", "attrs", "jsonschema", "importlib-metadata", "zipp",
		"typing-extensions", "filelock", "platformdirs", "distlib", "virtualenv",
		"pillow", "scipy", "pandas", "matplotlib", "django",
		"flask", "sqlalchemy", "psycopg2", "redis", "celery",
		"gunicorn", "uwsgi", "pytest", "black", "flake8",
		"mypy", "isort", "pre-commit", "tox", "coverage",
	}

	if limit > len(popularPackages) {
		limit = len(popularPackages)
	}

	return popularPackages[:limit], nil
}

// ValidatePackage validates if a package exists in PyPI registry
func (pc *PyPIConnector) ValidatePackage(ctx context.Context, packageName, version string) error {
	if err := validatePyPIPackageName(packageName); err != nil {
		return fmt.Errorf("invalid package name: %w", err)
	}

	// Get package info to check if it exists
	_, err := pc.GetPackageInfo(ctx, packageName)
	if err != nil {
		return fmt.Errorf("package %s not found: %w", packageName, err)
	}

	// If no version specified, package exists
	if version == "" {
		return nil
	}

	// Check if specific version exists
	normalizedVersion := normalizeVersion(version)
	normalizedName := pc.normalizePackageName(packageName)
	url := pc.buildURL(fmt.Sprintf("%s/%s/json", normalizedName, normalizedVersion))

	resp, err := pc.makeRequest(ctx, url)
	if err != nil {
		return fmt.Errorf("package version %s@%s not found: %w", packageName, version, err)
	}
	resp.Body.Close()

	// TODO: Additional version validation could be implemented here

	return nil
}

// convertToPackageMetadata converts PyPI package info to standard metadata
func (pc *PyPIConnector) convertToPackageMetadata(pypiInfo *PyPIPackageInfo) *types.PackageMetadata {
	info := &pypiInfo.Info
	metadata := &types.PackageMetadata{
		Description:  info.Summary,
		Homepage:     info.HomePage,
		Author:       info.Author,
		License:      info.License,
		Downloads:    int64(info.Downloads.LastMonth),
		Dependencies: make([]string, 0),
	}

	// Parse keywords
	if info.Keywords != "" {
		metadata.Keywords = strings.Split(info.Keywords, ",")
		for i, keyword := range metadata.Keywords {
			metadata.Keywords[i] = strings.TrimSpace(keyword)
		}
	}

	// Set maintainers
	maintainers := []string{}
	if info.Author != "" {
		maintainers = append(maintainers, info.Author)
	}
	if info.Maintainer != "" && info.Maintainer != info.Author {
		maintainers = append(maintainers, info.Maintainer)
	}
	metadata.Maintainers = maintainers

	// Set repository URL from project URLs
	for key, url := range info.ProjectURLs {
		lowerKey := strings.ToLower(key)
		if strings.Contains(lowerKey, "repository") || strings.Contains(lowerKey, "source") || strings.Contains(lowerKey, "github") {
			metadata.Repository = url
			break
		}
	}

	// Parse dependencies from requires_dist
	for _, req := range info.RequiresDist {
		if dep := pc.parseRequirement(req); dep != nil {
			metadata.Dependencies = append(metadata.Dependencies, dep.Name)
		}
	}

	// Note: PyPI-specific metadata could be stored in ExtraData field of Dependency
	// if needed for the specific use case

	// Parse upload time from the latest release
	if len(pypiInfo.URLs) > 0 {
		latestURL := pypiInfo.URLs[0]
		if uploadTime, err := time.Parse("2006-01-02T15:04:05", latestURL.UploadTime); err == nil {
			metadata.LastUpdated = &uploadTime
		}
	}

	return metadata
}

// parseRequirement parses a Python requirement string
type PyPIRequirement struct {
	Name    string
	Version string
	Extras  []string
	Marker  string
}

func (pc *PyPIConnector) parseRequirement(reqStr string) *PyPIRequirement {
	// Simple requirement parsing - in a real implementation, use a proper parser
	reqStr = strings.TrimSpace(reqStr)
	if reqStr == "" {
		return nil
	}

	// Split on semicolon to separate markers
	parts := strings.Split(reqStr, ";")
	mainPart := strings.TrimSpace(parts[0])
	var marker string
	if len(parts) > 1 {
		marker = strings.TrimSpace(parts[1])
	}

	// Extract package name and version specifier
	var name, version string
	var extras []string

	// Handle extras (package[extra1,extra2])
	if strings.Contains(mainPart, "[") {
		extrasStart := strings.Index(mainPart, "[")
		extrasEnd := strings.Index(mainPart, "]")
		if extrasEnd > extrasStart {
			name = strings.TrimSpace(mainPart[:extrasStart])
			extrasStr := mainPart[extrasStart+1 : extrasEnd]
			extras = strings.Split(extrasStr, ",")
			for i, extra := range extras {
				extras[i] = strings.TrimSpace(extra)
			}
			mainPart = mainPart[extrasEnd+1:]
		}
	}

	// Extract version specifiers
	versionOperators := []string{"==", ">=", "<=", "!=", "~=", ">", "<", "==="}
	for _, op := range versionOperators {
		if strings.Contains(mainPart, op) {
			parts := strings.Split(mainPart, op)
			if len(parts) == 2 {
				if name == "" {
					name = strings.TrimSpace(parts[0])
				}
				version = op + strings.TrimSpace(parts[1])
				break
			}
		}
	}

	// If no version specifier found, the whole thing is the package name
	if name == "" {
		name = strings.TrimSpace(mainPart)
	}

	if name == "" {
		return nil
	}

	return &PyPIRequirement{
		Name:    name,
		Version: version,
		Extras:  extras,
		Marker:  marker,
	}
}

// normalizePackageName normalizes PyPI package names
func (pc *PyPIConnector) normalizePackageName(name string) string {
	// PyPI treats package names case-insensitively and treats - and _ as equivalent
	normalized := strings.ToLower(name)
	normalized = strings.ReplaceAll(normalized, "_", "-")
	return normalized
}

// GetRegistryInfo returns PyPI registry information
func (pc *PyPIConnector) GetRegistryInfo() types.RegistryInfo {
	return types.RegistryInfo{
		Name:        "pypi",
		URL:         "https://pypi.org",
		Supported:   true,
		Description: "Python Package Index (PyPI) registry",
		Metadata: map[string]interface{}{
			"api_url":       "https://pypi.org/pypi",
			"simple_url":    "https://pypi.org/simple",
			"website":       "https://pypi.org",
			"package_count": "400K+",
			"note":          "Search API is deprecated",
		},
	}
}

// GetPackageVersions retrieves all versions of a package
func (pc *PyPIConnector) GetPackageVersions(ctx context.Context, packageName string) ([]string, error) {
	_, err := pc.GetPackageInfo(ctx, packageName)
	if err != nil {
		return nil, err
	}

	// TODO: Extract versions from PyPI package info
	// For now, return empty slice as we don't have access to releases metadata
	return []string{}, nil
}

// GetPackageDependencies retrieves package dependencies
func (pc *PyPIConnector) GetPackageDependencies(ctx context.Context, packageName, version string) (map[string]string, error) {
	var url string
	normalizedName := pc.normalizePackageName(packageName)

	if version != "" {
		normalizedVersion := normalizeVersion(version)
		url = pc.buildURL(fmt.Sprintf("%s/%s/json", normalizedName, normalizedVersion))
	} else {
		url = pc.buildURL(fmt.Sprintf("%s/json", normalizedName))
	}

	resp, err := pc.retryRequest(ctx, url, 3)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch package dependencies: %w", err)
	}

	var pypiInfo PyPIPackageInfo
	if err := pc.parseJSONResponse(resp, &pypiInfo); err != nil {
		return nil, fmt.Errorf("failed to parse PyPI response: %w", err)
	}

	// Parse dependencies from requires_dist
	dependencies := make(map[string]string)
	for _, req := range pypiInfo.Info.RequiresDist {
		if dep := pc.parseRequirement(req); dep != nil {
			dependencies[dep.Name] = dep.Version
		}
	}

	return dependencies, nil
}

// IsPackageYanked checks if a package version is yanked
func (pc *PyPIConnector) IsPackageYanked(ctx context.Context, packageName, version string) (bool, string, error) {
	_, err := pc.GetPackageInfo(ctx, packageName)
	if err != nil {
		return false, "", err
	}

	// TODO: Check if package version is yanked from PyPI API
	// For now, assume package is not yanked

	return false, "", nil
}

// GetPackageSize retrieves package size information
func (pc *PyPIConnector) GetPackageSize(ctx context.Context, packageName, version string) (int64, error) {
	_, err := pc.GetPackageInfo(ctx, packageName)
	if err != nil {
		return 0, err
	}

	// TODO: Get package size from PyPI API
	// For now, return 0 as placeholder

	return 0, fmt.Errorf("package size information not available")
}

// GetPackageClassifiers retrieves PyPI classifiers for a package
func (pc *PyPIConnector) GetPackageClassifiers(ctx context.Context, packageName string) ([]string, error) {
	// TODO: Get classifiers from PyPI API
	// For now, return empty slice
	return []string{}, nil
}

// GetPythonRequirement retrieves Python version requirement
func (pc *PyPIConnector) GetPythonRequirement(ctx context.Context, packageName string) (string, error) {
	// TODO: Get Python requirement from PyPI API
	// For now, return empty string
	return "", nil
}