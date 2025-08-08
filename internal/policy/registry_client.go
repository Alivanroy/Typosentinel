package policy

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// DefaultRegistryClient implements the RegistryClient interface
type DefaultRegistryClient struct {
	client *http.Client
	config *RegistryClientConfig
}

// RegistryClientConfig configuration for registry client
type RegistryClientConfig struct {
	NPMRegistry     string        `json:"npm_registry"`
	PyPIRegistry    string        `json:"pypi_registry"`
	MavenRegistry   string        `json:"maven_registry"`
	NuGetRegistry   string        `json:"nuget_registry"`
	RubyGemsRegistry string       `json:"rubygems_registry"`
	CargoRegistry   string        `json:"cargo_registry"`
	Timeout         time.Duration `json:"timeout"`
	MaxRetries      int           `json:"max_retries"`
	RetryDelay      time.Duration `json:"retry_delay"`
	UserAgent       string        `json:"user_agent"`
}

// NPMPackageInfo represents NPM package information
type NPMPackageInfo struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Versions    map[string]NPMVersion  `json:"versions"`
	DistTags    map[string]string      `json:"dist-tags"`
	Time        map[string]string      `json:"time"`
}

// NPMVersion represents an NPM package version
type NPMVersion struct {
	Version     string            `json:"version"`
	Description string            `json:"description"`
	Main        string            `json:"main"`
	Scripts     map[string]string `json:"scripts"`
	Dependencies map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
	Dist        NPMDist           `json:"dist"`
}

// NPMDist represents NPM distribution info
type NPMDist struct {
	Tarball  string `json:"tarball"`
	Shasum   string `json:"shasum"`
	Integrity string `json:"integrity"`
}

// PyPIPackageInfo represents PyPI package information
type PyPIPackageInfo struct {
	Info     PyPIInfo              `json:"info"`
	Releases map[string][]PyPIFile `json:"releases"`
}

// PyPIInfo represents PyPI package info
type PyPIInfo struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Summary     string `json:"summary"`
	Description string `json:"description"`
	Author      string `json:"author"`
	License     string `json:"license"`
}

// PyPIFile represents a PyPI file
type PyPIFile struct {
	Filename string `json:"filename"`
	URL      string `json:"url"`
	Digests  map[string]string `json:"digests"`
}

// NewDefaultRegistryClient creates a new registry client
func NewDefaultRegistryClient(config *RegistryClientConfig) *DefaultRegistryClient {
	if config == nil {
		config = &RegistryClientConfig{
			NPMRegistry:      "https://registry.npmjs.org",
			PyPIRegistry:     "https://pypi.org/pypi",
			MavenRegistry:    "https://repo1.maven.org/maven2",
			NuGetRegistry:    "https://api.nuget.org/v3-flatcontainer",
			RubyGemsRegistry: "https://rubygems.org/api/v1",
			CargoRegistry:    "https://crates.io/api/v1",
			Timeout:          30 * time.Second,
			MaxRetries:       3,
			RetryDelay:       1 * time.Second,
			UserAgent:        "Typosentinel/1.0",
		}
	}

	return &DefaultRegistryClient{
		client: &http.Client{
			Timeout: config.Timeout,
		},
		config: config,
	}
}

// GetPackageVersions retrieves all available versions for a package
func (rc *DefaultRegistryClient) GetPackageVersions(pkg *types.Package) ([]string, error) {
	if pkg == nil {
		return nil, fmt.Errorf("package cannot be nil")
	}

	switch strings.ToLower(pkg.Registry) {
	case "npm":
		return rc.getNPMVersions(pkg.Name)
	case "pypi":
		return rc.getPyPIVersions(pkg.Name)
	case "maven":
		return rc.getMavenVersions(pkg.Name)
	case "nuget":
		return rc.getNuGetVersions(pkg.Name)
	case "gem", "rubygems":
		return rc.getRubyGemsVersions(pkg.Name)
	case "cargo":
		return rc.getCargoVersions(pkg.Name)
	default:
		return nil, fmt.Errorf("unsupported registry: %s", pkg.Registry)
	}
}

// GetPackageMetadata retrieves metadata for a specific package version
func (rc *DefaultRegistryClient) GetPackageMetadata(pkg *types.Package, version string) (*types.PackageMetadata, error) {
	if pkg == nil {
		return nil, fmt.Errorf("package cannot be nil")
	}

	switch strings.ToLower(pkg.Registry) {
	case "npm":
		return rc.getNPMMetadata(pkg.Name, version)
	case "pypi":
		return rc.getPyPIMetadata(pkg.Name, version)
	case "maven":
		return rc.getMavenMetadata(pkg.Name, version)
	case "nuget":
		return rc.getNuGetMetadata(pkg.Name, version)
	case "gem", "rubygems":
		return rc.getRubyGemsMetadata(pkg.Name, version)
	case "cargo":
		return rc.getCargoMetadata(pkg.Name, version)
	default:
		return nil, fmt.Errorf("unsupported registry: %s", pkg.Registry)
	}
}

// ValidateVersion checks if a version exists for a package
func (rc *DefaultRegistryClient) ValidateVersion(pkg *types.Package, version string) (bool, error) {
	if pkg == nil {
		return false, fmt.Errorf("package cannot be nil")
	}

	versions, err := rc.GetPackageVersions(pkg)
	if err != nil {
		return false, fmt.Errorf("failed to get package versions: %w", err)
	}

	for _, v := range versions {
		if v == version {
			return true, nil
		}
	}

	return false, nil
}

// NPM-specific methods

func (rc *DefaultRegistryClient) getNPMVersions(packageName string) ([]string, error) {
	url := fmt.Sprintf("%s/%s", rc.config.NPMRegistry, url.PathEscape(packageName))
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("User-Agent", rc.config.UserAgent)

	resp, err := rc.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch NPM package: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("package not found: %s", packageName)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("NPM registry returned status %d", resp.StatusCode)
	}

	var packageInfo NPMPackageInfo
	if err := json.NewDecoder(resp.Body).Decode(&packageInfo); err != nil {
		return nil, fmt.Errorf("failed to decode NPM response: %w", err)
	}

	versions := make([]string, 0, len(packageInfo.Versions))
	for version := range packageInfo.Versions {
		versions = append(versions, version)
	}

	// Sort versions (simplified - in production, use semantic versioning)
	sort.Strings(versions)
	return versions, nil
}

func (rc *DefaultRegistryClient) getNPMMetadata(packageName, version string) (*types.PackageMetadata, error) {
	url := fmt.Sprintf("%s/%s/%s", rc.config.NPMRegistry, url.PathEscape(packageName), version)
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("User-Agent", rc.config.UserAgent)

	resp, err := rc.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch NPM package metadata: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("package version not found: %s@%s", packageName, version)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("NPM registry returned status %d", resp.StatusCode)
	}

	var versionInfo NPMVersion
	if err := json.NewDecoder(resp.Body).Decode(&versionInfo); err != nil {
		return nil, fmt.Errorf("failed to decode NPM version response: %w", err)
	}

	dependencies := make([]string, 0, len(versionInfo.Dependencies))
	for dep := range versionInfo.Dependencies {
		dependencies = append(dependencies, dep)
	}

	now := time.Now()
	return &types.PackageMetadata{
		Name:        packageName,
		Version:     version,
		Description: versionInfo.Description,
		Registry:    "npm",
		PublishedAt: &now, // NPM doesn't provide this in version endpoint
		CreatedAt:   now,
	}, nil
}

// PyPI-specific methods

func (rc *DefaultRegistryClient) getPyPIVersions(packageName string) ([]string, error) {
	url := fmt.Sprintf("%s/%s/json", rc.config.PyPIRegistry, url.PathEscape(packageName))
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("User-Agent", rc.config.UserAgent)

	resp, err := rc.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch PyPI package: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("package not found: %s", packageName)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("PyPI registry returned status %d", resp.StatusCode)
	}

	var packageInfo PyPIPackageInfo
	if err := json.NewDecoder(resp.Body).Decode(&packageInfo); err != nil {
		return nil, fmt.Errorf("failed to decode PyPI response: %w", err)
	}

	versions := make([]string, 0, len(packageInfo.Releases))
	for version := range packageInfo.Releases {
		versions = append(versions, version)
	}

	// Sort versions (simplified - in production, use semantic versioning)
	sort.Strings(versions)
	return versions, nil
}

func (rc *DefaultRegistryClient) getPyPIMetadata(packageName, version string) (*types.PackageMetadata, error) {
	url := fmt.Sprintf("%s/%s/%s/json", rc.config.PyPIRegistry, url.PathEscape(packageName), version)
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("User-Agent", rc.config.UserAgent)

	resp, err := rc.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch PyPI package metadata: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("package version not found: %s@%s", packageName, version)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("PyPI registry returned status %d", resp.StatusCode)
	}

	var packageInfo PyPIPackageInfo
	if err := json.NewDecoder(resp.Body).Decode(&packageInfo); err != nil {
		return nil, fmt.Errorf("failed to decode PyPI response: %w", err)
	}

	now := time.Now()
	return &types.PackageMetadata{
		Name:        packageName,
		Version:     version,
		Description: packageInfo.Info.Description,
		Registry:    "pypi",
		Author:      packageInfo.Info.Author,
		License:     packageInfo.Info.License,
		PublishedAt: &now, // PyPI doesn't provide this in version endpoint
		CreatedAt:   now,
	}, nil
}

// Registry client implementations for Maven, NuGet, and RubyGems

func (rc *DefaultRegistryClient) getMavenVersions(packageName string) ([]string, error) {
	// Maven packages are in format groupId:artifactId
	parts := strings.Split(packageName, ":")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid Maven package format, expected groupId:artifactId")
	}
	
	artifactId := parts[1]
	
	url := fmt.Sprintf("https://search.maven.org/solrsearch/select?q=g:%s+AND+a:%s&core=gav&rows=100&wt=json", 
		url.QueryEscape(parts[0]), url.QueryEscape(artifactId))
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("User-Agent", rc.config.UserAgent)

	resp, err := rc.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch Maven package: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Maven Central returned status %d", resp.StatusCode)
	}

	var searchResult struct {
		Response struct {
			Docs []struct {
				V string `json:"v"` // version
			} `json:"docs"`
		} `json:"response"`
	}
	
	if err := json.NewDecoder(resp.Body).Decode(&searchResult); err != nil {
		return nil, fmt.Errorf("failed to decode Maven response: %w", err)
	}

	versions := make([]string, 0, len(searchResult.Response.Docs))
	for _, doc := range searchResult.Response.Docs {
		versions = append(versions, doc.V)
	}

	// Sort versions (simplified - in production, use semantic versioning)
	sort.Strings(versions)
	return versions, nil
}

func (rc *DefaultRegistryClient) getMavenMetadata(packageName, version string) (*types.PackageMetadata, error) {
	parts := strings.Split(packageName, ":")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid Maven package format, expected groupId:artifactId")
	}
	
	groupId := strings.ReplaceAll(parts[0], ".", "/")
	artifactId := parts[1]
	
	// Try to get POM file for metadata
	pomURL := fmt.Sprintf("https://repo1.maven.org/maven2/%s/%s/%s/%s-%s.pom", 
		groupId, artifactId, version, artifactId, version)
	
	req, err := http.NewRequest("GET", pomURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("User-Agent", rc.config.UserAgent)

	resp, err := rc.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch Maven POM: %w", err)
	}
	defer resp.Body.Close()

	now := time.Now()
	metadata := &types.PackageMetadata{
		Name:        packageName,
		Version:     version,
		Registry:    "maven",
		PublishedAt: &now,
		CreatedAt:   now,
	}

	if resp.StatusCode == http.StatusOK {
		// Parse basic info from POM if available
		body, err := io.ReadAll(resp.Body)
		if err == nil {
			pomContent := string(body)
			if desc := extractXMLTag(pomContent, "description"); desc != "" {
				metadata.Description = desc
			}
		}
	}

	return metadata, nil
}

// extractXMLTag extracts content from an XML tag
func extractXMLTag(content, tag string) string {
	re := regexp.MustCompile(fmt.Sprintf("<%s[^>]*>([^<]*)</%s>", tag, tag))
	matches := re.FindStringSubmatch(content)
	if len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}
	return ""
}

func (rc *DefaultRegistryClient) getNuGetVersions(packageName string) ([]string, error) {
	url := fmt.Sprintf("https://api.nuget.org/v3-flatcontainer/%s/index.json", 
		strings.ToLower(packageName))
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("User-Agent", rc.config.UserAgent)

	resp, err := rc.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch NuGet package: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("NuGet API returned status %d", resp.StatusCode)
	}

	var versionResponse struct {
		Versions []string `json:"versions"`
	}
	
	if err := json.NewDecoder(resp.Body).Decode(&versionResponse); err != nil {
		return nil, fmt.Errorf("failed to decode NuGet response: %w", err)
	}

	return versionResponse.Versions, nil
}

func (rc *DefaultRegistryClient) getNuGetMetadata(packageName, version string) (*types.PackageMetadata, error) {
	// Get package metadata from NuGet API
	url := fmt.Sprintf("https://api.nuget.org/v3/registration5-semver1/%s/%s.json", 
		strings.ToLower(packageName), strings.ToLower(version))
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("User-Agent", rc.config.UserAgent)

	resp, err := rc.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch NuGet metadata: %w", err)
	}
	defer resp.Body.Close()

	now := time.Now()
	metadata := &types.PackageMetadata{
		Name:        packageName,
		Version:     version,
		Registry:    "nuget",
		PublishedAt: &now,
		CreatedAt:   now,
	}

	if resp.StatusCode == http.StatusOK {
		var packageInfo struct {
			CatalogEntry struct {
				Description string    `json:"description"`
				Published   time.Time `json:"published"`
			} `json:"catalogEntry"`
		}
		
		if err := json.NewDecoder(resp.Body).Decode(&packageInfo); err == nil {
			metadata.Description = packageInfo.CatalogEntry.Description
			if !packageInfo.CatalogEntry.Published.IsZero() {
				metadata.PublishedAt = &packageInfo.CatalogEntry.Published
			}
		}
	}

	return metadata, nil
}

func (rc *DefaultRegistryClient) getRubyGemsVersions(packageName string) ([]string, error) {
	url := fmt.Sprintf("https://rubygems.org/api/v1/versions/%s.json", packageName)
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("User-Agent", rc.config.UserAgent)

	resp, err := rc.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch RubyGems package: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("RubyGems API returned status %d", resp.StatusCode)
	}

	var versions []struct {
		Number string `json:"number"`
	}
	
	if err := json.NewDecoder(resp.Body).Decode(&versions); err != nil {
		return nil, fmt.Errorf("failed to decode RubyGems response: %w", err)
	}

	versionNumbers := make([]string, 0, len(versions))
	for _, v := range versions {
		versionNumbers = append(versionNumbers, v.Number)
	}

	return versionNumbers, nil
}

func (rc *DefaultRegistryClient) getRubyGemsMetadata(packageName, version string) (*types.PackageMetadata, error) {
	url := fmt.Sprintf("https://rubygems.org/api/v1/gems/%s.json", packageName)
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("User-Agent", rc.config.UserAgent)

	resp, err := rc.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch RubyGems metadata: %w", err)
	}
	defer resp.Body.Close()

	now := time.Now()
	metadata := &types.PackageMetadata{
		Name:        packageName,
		Version:     version,
		Registry:    "rubygems",
		PublishedAt: &now,
		CreatedAt:   now,
	}

	if resp.StatusCode == http.StatusOK {
		var gemInfo struct {
			Info        string `json:"info"`
			Version     string `json:"version"`
			VersionCreatedAt string `json:"version_created_at"`
		}
		
		if err := json.NewDecoder(resp.Body).Decode(&gemInfo); err == nil {
			metadata.Description = gemInfo.Info
			if gemInfo.VersionCreatedAt != "" {
				if publishedAt, err := time.Parse(time.RFC3339, gemInfo.VersionCreatedAt); err == nil {
					metadata.PublishedAt = &publishedAt
				}
			}
		}
	}

	return metadata, nil
}

func (rc *DefaultRegistryClient) getCargoVersions(packageName string) ([]string, error) {
	url := fmt.Sprintf("https://crates.io/api/v1/crates/%s/versions", packageName)
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("User-Agent", rc.config.UserAgent)

	resp, err := rc.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch Cargo package: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crates.io API returned status %d", resp.StatusCode)
	}

	var versionResponse struct {
		Versions []struct {
			Num string `json:"num"`
		} `json:"versions"`
	}
	
	if err := json.NewDecoder(resp.Body).Decode(&versionResponse); err != nil {
		return nil, fmt.Errorf("failed to decode Cargo response: %w", err)
	}

	versions := make([]string, 0, len(versionResponse.Versions))
	for _, v := range versionResponse.Versions {
		versions = append(versions, v.Num)
	}

	return versions, nil
}

func (rc *DefaultRegistryClient) getCargoMetadata(packageName, version string) (*types.PackageMetadata, error) {
	url := fmt.Sprintf("https://crates.io/api/v1/crates/%s", packageName)
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("User-Agent", rc.config.UserAgent)

	resp, err := rc.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch Cargo metadata: %w", err)
	}
	defer resp.Body.Close()

	now := time.Now()
	metadata := &types.PackageMetadata{
		Name:        packageName,
		Version:     version,
		Registry:    "cargo",
		PublishedAt: &now,
		CreatedAt:   now,
	}

	if resp.StatusCode == http.StatusOK {
		var crateInfo struct {
			Crate struct {
				Description string    `json:"description"`
				CreatedAt   time.Time `json:"created_at"`
			} `json:"crate"`
		}
		
		if err := json.NewDecoder(resp.Body).Decode(&crateInfo); err == nil {
			metadata.Description = crateInfo.Crate.Description
			if !crateInfo.Crate.CreatedAt.IsZero() {
				metadata.PublishedAt = &crateInfo.Crate.CreatedAt
			}
		}
	}

	return metadata, nil
}