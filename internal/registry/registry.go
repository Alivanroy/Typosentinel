package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// Connector interface for connecting to package registries
type Connector interface {
	Connect(ctx context.Context) error
	GetPackageInfo(ctx context.Context, name, version string) (*types.PackageMetadata, error)
	SearchPackages(ctx context.Context, query string) ([]*types.PackageMetadata, error)
	GetRegistryType() string
	Close() error
}

// Registry represents a package registry
type Registry struct {
	Name    string
	URL     string
	Type    string
	Enabled bool
	APIKey  string
	Timeout int
}

// NPMConnector implements Connector for NPM registry
type NPMConnector struct {
	registry *Registry
	client   *NPMClient
}

// NewNPMConnector creates a new NPM connector
func NewNPMConnector(registry *Registry) *NPMConnector {
	return &NPMConnector{
		registry: registry,
		client:   NewNPMClient(),
	}
}

// Connect establishes connection to NPM registry
func (n *NPMConnector) Connect(ctx context.Context) error {
	// Implementation would go here
	return nil
}

// GetPackageInfo retrieves package information from NPM
func (n *NPMConnector) GetPackageInfo(ctx context.Context, name, version string) (*types.PackageMetadata, error) {
	packageInfo, err := n.client.GetPackageInfo(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("failed to get package info from NPM: %w", err)
	}

	// Get download stats
	downloadStats, err := n.client.GetDownloadStats(ctx, name, "last-week")
	if err != nil {
		// Log warning but don't fail the request
		fmt.Printf("Warning: failed to get download stats for %s: %v\n", name, err)
	}

	// Convert license to string if it's an object
	licenseStr := ""
	if packageInfo.License != nil {
		switch l := packageInfo.License.(type) {
		case string:
			licenseStr = l
		case map[string]interface{}:
			if licType, ok := l["type"].(string); ok {
				licenseStr = licType
			}
		}
	}

	// Convert author to string if it's an object
	authorStr := ""
	if packageInfo.Author != nil {
		switch a := packageInfo.Author.(type) {
		case string:
			authorStr = a
		case map[string]interface{}:
			if name, ok := a["name"].(string); ok {
				authorStr = name
			}
		}
	}

	// Extract repository URL
	repoURL := ""
	if packageInfo.Repository != nil {
		if url, ok := packageInfo.Repository["url"].(string); ok {
			repoURL = url
		}
	}

	// Convert dependencies map to slice of names
	dependencyNames := make([]string, 0, len(packageInfo.Dependencies))
	for depName := range packageInfo.Dependencies {
		dependencyNames = append(dependencyNames, depName)
	}

	metadata := &types.PackageMetadata{
		Name:         packageInfo.Name,
		Version:      version,
		Description:  packageInfo.Description,
		Author:       authorStr,
		License:      licenseStr,
		Homepage:     packageInfo.Homepage,
		Repository:   repoURL,
		Keywords:     packageInfo.Keywords,
		Registry:     "npm",
		Dependencies: dependencyNames,
	}

	// Add download count if available
	if downloadStats != nil {
		metadata.Downloads = int64(downloadStats.Downloads)
	}

	return metadata, nil
}

// SearchPackages searches for packages in NPM registry
func (n *NPMConnector) SearchPackages(ctx context.Context, query string) ([]*types.PackageMetadata, error) {
	// Implement NPM search using the NPM search API
	if query == "" {
		return []*types.PackageMetadata{}, nil
	}

	// Use NPM search API endpoint
	searchURL := fmt.Sprintf("https://registry.npmjs.org/-/v1/search?text=%s&size=20", url.QueryEscape(query))

	resp, err := http.Get(searchURL)
	if err != nil {
		return nil, fmt.Errorf("failed to search NPM registry: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("NPM search API returned status %d", resp.StatusCode)
	}

	var searchResult struct {
		Objects []struct {
			Package struct {
				Name        string `json:"name"`
				Version     string `json:"version"`
				Description string `json:"description"`
				Author      struct {
					Name string `json:"name"`
				} `json:"author"`
				Maintainers []struct {
					Name string `json:"name"`
				} `json:"maintainers"`
			} `json:"package"`
		} `json:"objects"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&searchResult); err != nil {
		return nil, fmt.Errorf("failed to decode search response: %w", err)
	}

	var packages []*types.PackageMetadata
	for _, obj := range searchResult.Objects {
		pkg := &types.PackageMetadata{
			Name:        obj.Package.Name,
			Version:     obj.Package.Version,
			Description: obj.Package.Description,
			Registry:    "npm",
		}

		if obj.Package.Author.Name != "" {
			pkg.Author = obj.Package.Author.Name
		}

		for _, maintainer := range obj.Package.Maintainers {
			pkg.Maintainers = append(pkg.Maintainers, maintainer.Name)
		}

		packages = append(packages, pkg)
	}

	return packages, nil
}

// GetRegistryType returns the registry type
func (n *NPMConnector) GetRegistryType() string {
	return "npm"
}

// Close closes the connection
func (n *NPMConnector) Close() error {
	return nil
}

// PyPIConnector implements Connector for PyPI registry
type PyPIConnector struct {
	registry *Registry
	client   *PyPIClient
}

// NewPyPIConnector creates a new PyPI connector
func NewPyPIConnector(registry *Registry) *PyPIConnector {
	return &PyPIConnector{
		registry: registry,
		client:   NewPyPIClient(),
	}
}

// Connect establishes connection to PyPI registry
func (p *PyPIConnector) Connect(ctx context.Context) error {
	// Test connection by making a simple API call
	_, err := p.client.GetPackageInfo("requests")
	if err != nil {
		return fmt.Errorf("failed to connect to PyPI: %w", err)
	}
	return nil
}

// GetPackageInfo retrieves package information from PyPI
func (p *PyPIConnector) GetPackageInfo(ctx context.Context, name, version string) (*types.PackageMetadata, error) {
	var packageInfo *PyPIPackageInfo
	var err error

	if version == "" {
		packageInfo, err = p.client.GetPackageInfo(name)
	} else {
		packageInfo, err = p.client.GetPackageVersion(name, version)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to get PyPI package info: %w", err)
	}

	return &types.PackageMetadata{
		Name:        packageInfo.Info.Name,
		Version:     packageInfo.Info.Version,
		Description: packageInfo.Info.Description,
		Registry:    "pypi",
		Author:      packageInfo.Info.Author,
		License:     packageInfo.Info.License,
		Homepage:    packageInfo.Info.HomePage,
		Keywords:    []string{packageInfo.Info.Keywords},
	}, nil
}

// SearchPackages searches for packages in PyPI registry
func (p *PyPIConnector) SearchPackages(ctx context.Context, query string) ([]*types.PackageMetadata, error) {
	// PyPI doesn't have a direct search API, so we'll use popular packages as fallback
	popularPackages, err := p.client.GetPopularPackages(50)
	if err != nil {
		return nil, fmt.Errorf("failed to get popular packages: %w", err)
	}

	var results []*types.PackageMetadata
	for _, pkgName := range popularPackages {
		if len(results) >= 20 { // Limit results
			break
		}

		// Simple string matching for search
		if query == "" || containsIgnoreCase(pkgName, query) {
			packageInfo, err := p.client.GetPackageInfo(pkgName)
			if err != nil {
				continue // Skip packages that fail to load
			}

			results = append(results, &types.PackageMetadata{
				Name:        packageInfo.Info.Name,
				Version:     packageInfo.Info.Version,
				Description: packageInfo.Info.Summary,
				Registry:    "pypi",
				Author:      packageInfo.Info.Author,
				License:     packageInfo.Info.License,
			})
		}
	}

	return results, nil
}

// GetRegistryType returns the registry type
func (p *PyPIConnector) GetRegistryType() string {
	return "pypi"
}

// Close closes the connection
func (p *PyPIConnector) Close() error {
	return nil
}

// PopularPackageNames returns popular package names for PyPI
func (p *PyPIConnector) PopularPackageNames(limit int) ([]string, error) {
	return p.client.GetPopularPackages(limit)
}

// MavenConnector implements Connector for Maven Central registry
type MavenConnector struct {
	registry *Registry
	client   *MavenClient
}

// NewMavenConnector creates a new Maven connector
func NewMavenConnector(registry *Registry) *MavenConnector {
	return &MavenConnector{
		registry: registry,
		client:   NewMavenClient(),
	}
}

// Connect establishes connection to Maven Central registry
func (m *MavenConnector) Connect(ctx context.Context) error {
	// Maven Central doesn't require authentication for public access
	return nil
}

// GetPackageInfo retrieves package information from Maven Central
func (m *MavenConnector) GetPackageInfo(ctx context.Context, name, version string) (*types.PackageMetadata, error) {
	// Parse Maven coordinate (groupId:artifactId)
	parts := strings.Split(name, ":")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid Maven coordinate format: %s (expected groupId:artifactId)", name)
	}

	groupID := parts[0]
	artifactID := parts[1]

	return m.client.GetPackageInfo(ctx, groupID, artifactID, version)
}

// SearchPackages searches for packages in Maven Central
func (m *MavenConnector) SearchPackages(ctx context.Context, query string) ([]*types.PackageMetadata, error) {
	return m.client.SearchPackages(ctx, query)
}

// GetRegistryType returns the registry type
func (m *MavenConnector) GetRegistryType() string {
	return "maven"
}

// Close closes the Maven connector
func (m *MavenConnector) Close() error {
	return nil
}

// PopularPackageNames returns popular Maven coordinates
func (m *MavenConnector) PopularPackageNames(limit int) ([]string, error) {
	return m.client.GetPopularPackages(limit)
}

// NuGetConnector implements Connector for NuGet registry
type NuGetConnector struct {
	registry *Registry
	client   *NuGetClient
}

// NewNuGetConnector creates a new NuGet connector
func NewNuGetConnector(registry *Registry) *NuGetConnector {
	return &NuGetConnector{
		registry: registry,
		client:   NewNuGetClient(),
	}
}

// Connect establishes connection to NuGet registry
func (n *NuGetConnector) Connect(ctx context.Context) error {
	// NuGet.org doesn't require authentication for public access
	return nil
}

// GetPackageInfo retrieves package information from NuGet.org
func (n *NuGetConnector) GetPackageInfo(ctx context.Context, name, version string) (*types.PackageMetadata, error) {
	return n.client.GetPackageInfo(ctx, name, version)
}

// SearchPackages searches for packages in NuGet.org
func (n *NuGetConnector) SearchPackages(ctx context.Context, query string) ([]*types.PackageMetadata, error) {
	return n.client.SearchPackages(ctx, query)
}

// GetRegistryType returns the registry type
func (n *NuGetConnector) GetRegistryType() string {
	return "nuget"
}

// Close closes the NuGet connector
func (n *NuGetConnector) Close() error {
	return nil
}

// PopularPackageNames returns popular NuGet package names
func (n *NuGetConnector) PopularPackageNames(limit int) ([]string, error) {
	return n.client.GetPopularPackages(limit)
}

// RubyGemsConnector implements Connector for RubyGems registry
type RubyGemsConnector struct {
	registry *Registry
	client   *RubyGemsClient
}

// NewRubyGemsConnector creates a new RubyGems connector
func NewRubyGemsConnector(registry *Registry) *RubyGemsConnector {
	return &RubyGemsConnector{
		registry: registry,
		client:   NewRubyGemsClient(),
	}
}

// Connect establishes connection to RubyGems registry
func (r *RubyGemsConnector) Connect(ctx context.Context) error {
	// RubyGems.org doesn't require authentication for public access
	return nil
}

// GetPackageInfo retrieves package information from RubyGems.org
func (r *RubyGemsConnector) GetPackageInfo(ctx context.Context, name, version string) (*types.PackageMetadata, error) {
	return r.client.GetPackageInfo(ctx, name, version)
}

// SearchPackages searches for packages in RubyGems.org
func (r *RubyGemsConnector) SearchPackages(ctx context.Context, query string) ([]*types.PackageMetadata, error) {
	return r.client.SearchPackages(ctx, query)
}

// GetRegistryType returns the registry type
func (r *RubyGemsConnector) GetRegistryType() string {
	return "rubygems"
}

// Close closes the RubyGems connector
func (r *RubyGemsConnector) Close() error {
	return nil
}

// Composer dynamic popular names
func (c *ComposerConnector) PopularPackageNames(limit int) ([]string, error) {
	return c.client.GetPopularNames(context.Background(), limit)
}

// Cargo dynamic popular names
func (c *CargoConnector) PopularPackageNames(limit int) ([]string, error) {
	pkgs, err := c.client.GetPopularPackages(context.Background(), limit)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(pkgs))
	for _, p := range pkgs {
		names = append(names, p.Name)
	}
	return names, nil
}

// NPM dynamic popular names (search API)
func (n *NPMConnector) PopularPackageNames(limit int) ([]string, error) {
	return n.client.GetPopularPackageNames(context.Background(), limit)
}

// PopularPackageNames returns popular RubyGems package names
func (r *RubyGemsConnector) PopularPackageNames(limit int) ([]string, error) {
	return r.client.GetPopularPackages(limit)
}

// ComposerConnector implements Connector for Composer registry
type ComposerConnector struct {
	registry *Registry
	client   *ComposerClient
}

// NewComposerConnector creates a new Composer connector
func NewComposerConnector(registry *Registry) *ComposerConnector {
	return &ComposerConnector{
		registry: registry,
		client:   NewComposerClient(),
	}
}

// Connect establishes connection to Packagist
func (c *ComposerConnector) Connect(ctx context.Context) error {
	// Packagist doesn't require authentication for public access
	return nil
}

// GetPackageInfo retrieves package information from Packagist
func (c *ComposerConnector) GetPackageInfo(ctx context.Context, name, version string) (*types.PackageMetadata, error) {
	return c.client.GetPackageInfo(ctx, name, version)
}

// SearchPackages searches for packages in Packagist
func (c *ComposerConnector) SearchPackages(ctx context.Context, query string) ([]*types.PackageMetadata, error) {
	return c.client.SearchPackages(ctx, query)
}

// GetRegistryType returns the registry type
func (c *ComposerConnector) GetRegistryType() string {
	return "composer"
}

// Close closes the Composer connector
func (c *ComposerConnector) Close() error {
	return nil
}

// CargoConnector implements Connector for Cargo registry
type CargoConnector struct {
	registry *Registry
	client   *CargoClient
}

// NewCargoConnector creates a new Cargo connector
func NewCargoConnector(registry *Registry) *CargoConnector {
	return &CargoConnector{
		registry: registry,
		client:   NewCargoClient(),
	}
}

// Connect establishes connection to crates.io
func (c *CargoConnector) Connect(ctx context.Context) error {
	// crates.io doesn't require authentication for public access
	return nil
}

// GetPackageInfo retrieves package information from crates.io
func (c *CargoConnector) GetPackageInfo(ctx context.Context, name, version string) (*types.PackageMetadata, error) {
	return c.client.GetPackageInfo(ctx, name, version)
}

// SearchPackages searches for packages in crates.io
func (c *CargoConnector) SearchPackages(ctx context.Context, query string) ([]*types.PackageMetadata, error) {
	return c.client.SearchPackages(ctx, query)
}

// GetRegistryType returns the registry type
func (c *CargoConnector) GetRegistryType() string {
	return "cargo"
}

// Close closes the Cargo connector
func (c *CargoConnector) Close() error {
	return nil
}

// containsIgnoreCase performs case-insensitive substring search
func containsIgnoreCase(s, substr string) bool {
	return len(s) >= len(substr) &&
		(s == substr ||
			len(s) > len(substr) &&
				(s[:len(substr)] == substr ||
					s[len(s)-len(substr):] == substr ||
					indexIgnoreCase(s, substr) >= 0))
}

// indexIgnoreCase finds the index of substr in s, case-insensitive
func indexIgnoreCase(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		match := true
		for j := 0; j < len(substr); j++ {
			if toLower(s[i+j]) != toLower(substr[j]) {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// toLower converts a byte to lowercase
func toLower(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

// Manager manages multiple registry connectors
type Manager struct {
	connectors map[string]Connector
}

// NewManager creates a new registry manager
func NewManager() *Manager {
	return &Manager{
		connectors: make(map[string]Connector),
	}
}

// AddConnector adds a connector to the manager
func (m *Manager) AddConnector(name string, connector Connector) {
	m.connectors[name] = connector
}

// GetConnector retrieves a connector by name
func (m *Manager) GetConnector(name string) (Connector, error) {
	connector, exists := m.connectors[name]
	if !exists {
		return nil, fmt.Errorf("connector %s not found", name)
	}
	return connector, nil
}

// GetAllConnectors returns all registered connectors
func (m *Manager) GetAllConnectors() map[string]Connector {
	return m.connectors
}

// Close closes all connectors
func (m *Manager) Close() error {
	for _, connector := range m.connectors {
		if err := connector.Close(); err != nil {
			return err
		}
	}
	return nil
}
