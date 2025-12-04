package registry

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/Alivanroy/Typosentinel/pkg/logger"
	"github.com/Alivanroy/Typosentinel/pkg/types"
	"github.com/spf13/viper"
)

// PyPIClient handles interactions with the PyPI registry
type PyPIClient struct {
	client  *http.Client
	baseURL string
}

// PyPIPackageInfo represents package information from PyPI API
type PyPIPackageInfo struct {
	Info struct {
		Name        string            `json:"name"`
		Version     string            `json:"version"`
		Summary     string            `json:"summary"`
		Description string            `json:"description"`
		Author      string            `json:"author"`
		AuthorEmail string            `json:"author_email"`
		Maintainer  string            `json:"maintainer"`
		HomePage    string            `json:"home_page"`
		License     string            `json:"license"`
		Keywords    string            `json:"keywords"`
		Classifiers []string          `json:"classifiers"`
		ProjectURLs map[string]string `json:"project_urls"`
	} `json:"info"`
	Releases map[string][]PyPIRelease `json:"releases"`
	URLs     []PyPIRelease            `json:"urls"`
}

// PyPIRelease represents a release file from PyPI
type PyPIRelease struct {
	Filename      string    `json:"filename"`
	PackageType   string    `json:"packagetype"`
	PythonVersion string    `json:"python_version"`
	Size          int64     `json:"size"`
	UploadTime    time.Time `json:"upload_time"`
	URL           string    `json:"url"`
	Digests       struct {
		MD5    string `json:"md5"`
		SHA256 string `json:"sha256"`
	} `json:"digests"`
}

// NewPyPIClient creates a new PyPI client
func NewPyPIClient() *PyPIClient {
	return &PyPIClient{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		baseURL: "https://pypi.org/pypi",
	}
}

// GetPackageInfo retrieves package information from PyPI
func (c *PyPIClient) GetPackageInfo(packageName string) (*PyPIPackageInfo, error) {
	logger.DebugWithContext("Fetching PyPI package info", map[string]interface{}{
		"package": packageName,
	})

	url := fmt.Sprintf("%s/%s/json", c.baseURL, packageName)
	resp, err := c.client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch package info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("package not found: %s", packageName)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("PyPI API returned status %d", resp.StatusCode)
	}

	var packageInfo PyPIPackageInfo
	if err := json.NewDecoder(resp.Body).Decode(&packageInfo); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &packageInfo, nil
}

// GetPackageVersion retrieves specific version information from PyPI
func (c *PyPIClient) GetPackageVersion(packageName, version string) (*PyPIPackageInfo, error) {
	logger.DebugWithContext("Fetching PyPI package version info", map[string]interface{}{
		"package": packageName,
		"version": version,
	})

	url := fmt.Sprintf("%s/%s/%s/json", c.baseURL, packageName, version)
	resp, err := c.client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch package version info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("package version not found: %s@%s", packageName, version)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("PyPI API returned status %d", resp.StatusCode)
	}

	var packageInfo PyPIPackageInfo
	if err := json.NewDecoder(resp.Body).Decode(&packageInfo); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &packageInfo, nil
}

// EnrichPackage enriches a package with metadata from PyPI
func (c *PyPIClient) EnrichPackage(pkg *types.Package) error {
	logger.DebugWithContext("Enriching package with PyPI metadata", map[string]interface{}{
		"package": pkg.Name,
		"version": pkg.Version,
	})

	var packageInfo *PyPIPackageInfo
	var err error

	// Try to get specific version info first, fall back to latest
	if pkg.Version != "*" && pkg.Version != "" {
		packageInfo, err = c.GetPackageVersion(pkg.Name, pkg.Version)
		if err != nil {
			logger.DebugWithContext("Failed to get specific version, trying latest", map[string]interface{}{
				"package": pkg.Name,
				"version": pkg.Version,
				"error":   err.Error(),
			})
			packageInfo, err = c.GetPackageInfo(pkg.Name)
		}
	} else {
		packageInfo, err = c.GetPackageInfo(pkg.Name)
	}

	if err != nil {
		return fmt.Errorf("failed to enrich package %s: %w", pkg.Name, err)
	}

	// Add metadata
	if pkg.Metadata == nil {
		pkg.Metadata = &types.PackageMetadata{}
	}
	if pkg.Metadata.Metadata == nil {
		pkg.Metadata.Metadata = make(map[string]interface{})
	}

	pkg.Metadata.Description = packageInfo.Info.Summary
	pkg.Metadata.Author = packageInfo.Info.Author
	pkg.Metadata.Homepage = packageInfo.Info.HomePage
	pkg.Metadata.License = packageInfo.Info.License

	// Add author email to metadata map
	pkg.Metadata.Metadata["author_email"] = packageInfo.Info.AuthorEmail
	pkg.Metadata.Metadata["maintainer"] = packageInfo.Info.Maintainer
	pkg.Metadata.Metadata["classifiers"] = packageInfo.Info.Classifiers
	pkg.Metadata.Metadata["project_urls"] = packageInfo.Info.ProjectURLs

	// Convert keywords string to slice and add to metadata map
	if packageInfo.Info.Keywords != "" {
		keywords := strings.Split(strings.TrimSpace(packageInfo.Info.Keywords), ",")
		for i, keyword := range keywords {
			keywords[i] = strings.TrimSpace(keyword)
		}
		pkg.Metadata.Keywords = keywords
		pkg.Metadata.Metadata["keywords"] = packageInfo.Info.Keywords
	}

	// Add release information
	if len(packageInfo.Releases) > 0 {
		var latestVersion string
		var latestTime time.Time

		for version, releases := range packageInfo.Releases {
			if len(releases) > 0 {
				uploadTime := releases[0].UploadTime
				if uploadTime.After(latestTime) {
					latestTime = uploadTime
					latestVersion = version
				}
			}
		}

		if latestVersion != "" {
			pkg.Metadata.LastUpdated = &latestTime
			pkg.Metadata.Metadata["latest_version"] = latestVersion
		}
	}

	// Add available versions count
	pkg.Metadata.Metadata["available_versions"] = len(packageInfo.Releases)

	logger.DebugWithContext("Package enriched successfully", map[string]interface{}{
		"package":     pkg.Name,
		"description": pkg.Metadata.Description,
		"author":      pkg.Metadata.Author,
	})

	return nil
}

// GetPopularPackages retrieves a list of popular packages from PyPI stats
func (c *PyPIClient) GetPopularPackages(limit int) ([]string, error) {
	logger.DebugWithContext("Fetching popular PyPI packages", map[string]interface{}{
		"limit": limit,
	})

	// Use PyPI's stats API to get popular packages
	// Note: PyPI doesn't have a direct "popular packages" endpoint, so we'll use a combination approach

	// First, try to get trending packages from PyPI's RSS feed
	trendingPackages, err := c.getTrendingPackages()
	if err != nil {
		logger.DebugWithContext("Failed to get trending packages, using fallback", map[string]interface{}{
			"error": err.Error(),
		})
		// Fallback to a curated list of well-known popular packages
		return c.getFallbackPopularPackages(limit), nil
	}

	// If we have trending packages, combine with known popular ones
	popular := c.combineWithKnownPopular(trendingPackages)

	if limit > 0 && limit < len(popular) {
		return popular[:limit], nil
	}
	return popular, nil
}

// getTrendingPackages fetches trending packages from PyPI's RSS feed
func (c *PyPIClient) getTrendingPackages() ([]string, error) {
	// PyPI RSS feed for new releases
	rssURL := "https://pypi.org/rss/updates.xml"

	resp, err := c.client.Get(rssURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch RSS feed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("RSS feed returned status %d", resp.StatusCode)
	}

	// Parse RSS feed to extract package names
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read RSS response: %w", err)
	}

	// Simple regex to extract package names from RSS titles
	// RSS titles are typically in format "package-name version"
	packageRegex := regexp.MustCompile(`<title>([a-zA-Z0-9\-_\.]+)\s+[\d\.]+`)
	matches := packageRegex.FindAllStringSubmatch(string(body), -1)

	var packages []string
	seen := make(map[string]bool)

	for _, match := range matches {
		if len(match) > 1 {
			packageName := match[1]
			if !seen[packageName] && isValidPackageName(packageName) {
				packages = append(packages, packageName)
				seen[packageName] = true
			}
		}
	}

	return packages, nil
}

// combineWithKnownPopular combines trending packages with known popular packages
func (c *PyPIClient) combineWithKnownPopular(trending []string) []string {
	// Known popular packages that should always be included
	knownPopular := []string{
		"requests", "numpy", "pandas", "django", "flask",
		"tensorflow", "pytorch", "scikit-learn", "matplotlib", "pillow",
		"beautifulsoup4", "selenium", "pytest", "black", "flake8",
		"click", "jinja2", "sqlalchemy", "fastapi", "pydantic",
		"boto3", "redis", "celery", "gunicorn", "uvicorn",
	}

	// Create a map to track unique packages
	seen := make(map[string]bool)
	var combined []string

	// Add known popular packages first
	for _, pkg := range knownPopular {
		if !seen[pkg] {
			combined = append(combined, pkg)
			seen[pkg] = true
		}
	}

	// Add trending packages that aren't already included
	for _, pkg := range trending {
		if !seen[pkg] && isValidPackageName(pkg) {
			combined = append(combined, pkg)
			seen[pkg] = true
		}
	}

	return combined
}

// getFallbackPopularPackages returns a curated list when API calls fail
func (c *PyPIClient) getFallbackPopularPackages(limit int) []string {
	popular := []string{
		"requests", "numpy", "pandas", "django", "flask",
		"tensorflow", "pytorch", "scikit-learn", "matplotlib", "pillow",
		"beautifulsoup4", "selenium", "pytest", "black", "flake8",
		"click", "jinja2", "sqlalchemy", "fastapi", "pydantic",
		"boto3", "redis", "celery", "gunicorn", "uvicorn",
		"httpx", "aiohttp", "asyncio", "typing-extensions", "setuptools",
		"wheel", "pip", "certifi", "urllib3", "charset-normalizer",
	}

	if limit > 0 && limit < len(popular) {
		return popular[:limit]
	}
	return popular
}

// GetPopularNames retrieves popular project names from a configured endpoint when provided
func (c *PyPIClient) GetPopularNames(limit int) ([]string, error) {
	base := viper.GetString("detector.endpoints.pypi_popular")
	if base == "" {
		return nil, fmt.Errorf("pypi popular endpoint not configured")
	}
	resp, err := c.client.Get(base)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch popular pypi: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("pypi popular status %d", resp.StatusCode)
	}
	// Try multiple decode formats
	// Format A: { projects: [ { name: "..." }, ... ] }
	var fmta struct {
		Projects []struct {
			Name string `json:"name"`
		} `json:"projects"`
	}
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&fmta); err == nil && len(fmta.Projects) > 0 {
		names := make([]string, 0, len(fmta.Projects))
		for _, p := range fmta.Projects {
			if p.Name != "" {
				names = append(names, p.Name)
			}
		}
		if limit > 0 && len(names) > limit {
			names = names[:limit]
		}
		return names, nil
	}
	// Reset body is not trivial; refetch for next format
	resp2, err2 := c.client.Get(base)
	if err2 == nil && resp2.StatusCode == http.StatusOK {
		defer resp2.Body.Close()
		// Format B: [ { name: "..." }, ... ]
		var fmtb []struct {
			Name string `json:"name"`
		}
		if json.NewDecoder(resp2.Body).Decode(&fmtb) == nil && len(fmtb) > 0 {
			names := make([]string, 0, len(fmtb))
			for _, p := range fmtb {
				if p.Name != "" {
					names = append(names, p.Name)
				}
			}
			if limit > 0 && len(names) > limit {
				names = names[:limit]
			}
			return names, nil
		}
	}
	// Refetch again for array of strings
	resp3, err3 := c.client.Get(base)
	if err3 == nil && resp3.StatusCode == http.StatusOK {
		defer resp3.Body.Close()
		var arr []string
		if json.NewDecoder(resp3.Body).Decode(&arr) == nil && len(arr) > 0 {
			names := make([]string, 0, len(arr))
			for _, n := range arr {
				if n != "" {
					names = append(names, n)
				}
			}
			if limit > 0 && len(names) > limit {
				names = names[:limit]
			}
			return names, nil
		}
	}
	return nil, fmt.Errorf("unsupported pypi popular response format")
}

// isValidPackageName checks if a package name is valid and not a common false positive
func isValidPackageName(name string) bool {
	// Filter out obviously invalid package names
	if len(name) < 2 || len(name) > 100 {
		return false
	}

	// Check for valid characters (letters, numbers, hyphens, underscores, dots)
	validName := regexp.MustCompile(`^[a-zA-Z0-9\-_\.]+$`)
	if !validName.MatchString(name) {
		return false
	}

	// Filter out common false positives
	invalidPatterns := []string{
		"^test", "^example", "^demo", "^sample",
		"^tmp", "^temp", "^debug", "^dev",
	}

	for _, pattern := range invalidPatterns {
		if matched, _ := regexp.MatchString(pattern, strings.ToLower(name)); matched {
			return false
		}
	}

	return true
}
