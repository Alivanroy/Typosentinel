package registry

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Alivanroy/Typosentinel/pkg/logger"
	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// PyPIClient handles interactions with the PyPI registry
type PyPIClient struct {
	client  *http.Client
	baseURL string
}

// PyPIPackageInfo represents package information from PyPI API
type PyPIPackageInfo struct {
	Info struct {
		Name        string `json:"name"`
		Version     string `json:"version"`
		Summary     string `json:"summary"`
		Description string `json:"description"`
		Author      string `json:"author"`
		AuthorEmail string `json:"author_email"`
		Maintainer  string `json:"maintainer"`
		HomePage    string `json:"home_page"`
		License     string `json:"license"`
		Keywords    string `json:"keywords"`
		Classifiers []string `json:"classifiers"`
		ProjectURLs map[string]string `json:"project_urls"`
	} `json:"info"`
	Releases map[string][]PyPIRelease `json:"releases"`
	URLs     []PyPIRelease `json:"urls"`
}

// PyPIRelease represents a release file from PyPI
type PyPIRelease struct {
	Filename     string    `json:"filename"`
	PackageType  string    `json:"packagetype"`
	PythonVersion string   `json:"python_version"`
	Size         int64     `json:"size"`
	UploadTime   time.Time `json:"upload_time"`
	URL          string    `json:"url"`
	Digests      struct {
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

// GetPopularPackages retrieves a list of popular packages (placeholder for future implementation)
func (c *PyPIClient) GetPopularPackages(limit int) ([]string, error) {
	// This would require a different API or scraping PyPI's trending page
	// For now, return a static list of well-known packages
	popular := []string{
		"requests", "numpy", "pandas", "django", "flask",
		"tensorflow", "pytorch", "scikit-learn", "matplotlib", "pillow",
		"beautifulsoup4", "selenium", "pytest", "black", "flake8",
	}

	if limit > 0 && limit < len(popular) {
		return popular[:limit], nil
	}
	return popular, nil
}