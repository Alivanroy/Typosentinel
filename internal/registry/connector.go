package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/typosentinel/typosentinel/pkg/types"
)

// Connector defines the interface for registry connectors
type Connector interface {
	GetPackageInfo(ctx context.Context, packageName string) (*types.PackageMetadata, error)
	SearchPackages(ctx context.Context, query string, limit int) ([]types.PackageMetadata, error)
	GetPopularPackages(ctx context.Context, limit int) ([]string, error)
	ValidatePackage(ctx context.Context, packageName, version string) error
	GetRegistryInfo() types.RegistryInfo
}

// Manager manages multiple registry connectors
type Manager struct {
	connectors map[string]Connector
	client     *http.Client
}

// NewManager creates a new registry manager
func NewManager() *Manager {
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	manager := &Manager{
		connectors: make(map[string]Connector),
		client:     client,
	}

	// Register default connectors
	manager.RegisterConnector("npm", NewNPMConnector(client))
	manager.RegisterConnector("pypi", NewPyPIConnector(client))
	// TODO: Implement additional connectors
	// manager.RegisterConnector("go", NewGoConnector(client))
	// manager.RegisterConnector("cargo", NewCargoConnector(client))
	// manager.RegisterConnector("rubygems", NewRubyGemsConnector(client))
	// manager.RegisterConnector("packagist", NewPackagistConnector(client))

	return manager
}

// RegisterConnector registers a new registry connector
func (m *Manager) RegisterConnector(registry string, connector Connector) {
	m.connectors[registry] = connector
}

// GetConnector returns a connector for the specified registry
func (m *Manager) GetConnector(registry string) (Connector, error) {
	connector, exists := m.connectors[registry]
	if !exists {
		return nil, fmt.Errorf("no connector found for registry: %s", registry)
	}
	return connector, nil
}

// GetAllRegistries returns a list of all supported registries
func (m *Manager) GetAllRegistries() []string {
	registries := make([]string, 0, len(m.connectors))
	for registry := range m.connectors {
		registries = append(registries, registry)
	}
	return registries
}

// GetPackageInfo retrieves package information from the specified registry
func (m *Manager) GetPackageInfo(ctx context.Context, registry, packageName string) (*types.PackageMetadata, error) {
	connector, err := m.GetConnector(registry)
	if err != nil {
		return nil, err
	}

	return connector.GetPackageInfo(ctx, packageName)
}

// SearchPackages searches for packages across the specified registry
func (m *Manager) SearchPackages(ctx context.Context, registry, query string, limit int) ([]types.PackageMetadata, error) {
	connector, err := m.GetConnector(registry)
	if err != nil {
		return nil, err
	}

	return connector.SearchPackages(ctx, query, limit)
}

// GetPopularPackages retrieves popular packages from the specified registry
func (m *Manager) GetPopularPackages(ctx context.Context, registry string, limit int) ([]string, error) {
	connector, err := m.GetConnector(registry)
	if err != nil {
		return nil, err
	}

	return connector.GetPopularPackages(ctx, limit)
}

// ValidatePackage validates if a package exists in the specified registry
func (m *Manager) ValidatePackage(ctx context.Context, registry, packageName, version string) error {
	connector, err := m.GetConnector(registry)
	if err != nil {
		return err
	}

	return connector.ValidatePackage(ctx, packageName, version)
}

// GetRegistryInfo returns information about the specified registry
func (m *Manager) GetRegistryInfo(registry string) (*types.RegistryInfo, error) {
	connector, err := m.GetConnector(registry)
	if err != nil {
		return nil, err
	}

	info := connector.GetRegistryInfo()
	return &info, nil
}

// BaseConnector provides common functionality for registry connectors
type BaseConnector struct {
	client      *http.Client
	baseURL     string
	registryName string
	rateLimit   time.Duration
	lastRequest time.Time
}

// NewBaseConnector creates a new base connector
func NewBaseConnector(client *http.Client, baseURL, registryName string) *BaseConnector {
	return &BaseConnector{
		client:       client,
		baseURL:      baseURL,
		registryName: registryName,
		rateLimit:    time.Second, // Default 1 request per second
	}
}

// makeRequest makes an HTTP request with rate limiting
func (bc *BaseConnector) makeRequest(ctx context.Context, url string) (*http.Response, error) {
	// Rate limiting
	if time.Since(bc.lastRequest) < bc.rateLimit {
		time.Sleep(bc.rateLimit - time.Since(bc.lastRequest))
	}
	bc.lastRequest = time.Now()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set common headers
	req.Header.Set("User-Agent", "TypoSentinel/1.0")
	req.Header.Set("Accept", "application/json")

	resp, err := bc.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}

	if resp.StatusCode >= 400 {
		resp.Body.Close()
		return nil, fmt.Errorf("HTTP error %d: %s", resp.StatusCode, resp.Status)
	}

	return resp, nil
}

// parseJSONResponse parses a JSON response into the provided interface
func (bc *BaseConnector) parseJSONResponse(resp *http.Response, v interface{}) error {
	defer resp.Body.Close()

	decoder := json.NewDecoder(resp.Body)
	if err := decoder.Decode(v); err != nil {
		return fmt.Errorf("failed to decode JSON response: %w", err)
	}

	return nil
}

// sanitizePackageName sanitizes package names for URL safety
func (bc *BaseConnector) sanitizePackageName(packageName string) string {
	// Basic URL encoding for package names
	// In a real implementation, you might want more sophisticated encoding
	return strings.ReplaceAll(packageName, "/", "%2F")
}

// buildURL builds a URL with the base URL and path
func (bc *BaseConnector) buildURL(path string) string {
	if strings.HasSuffix(bc.baseURL, "/") {
		return bc.baseURL + strings.TrimPrefix(path, "/")
	}
	return bc.baseURL + "/" + strings.TrimPrefix(path, "/")
}

// GetRegistryInfo returns basic registry information
func (bc *BaseConnector) GetRegistryInfo() types.RegistryInfo {
	return types.RegistryInfo{
		Name:        bc.registryName,
		URL:         bc.baseURL,
		Supported:   true,
		Description: fmt.Sprintf("%s package registry", bc.registryName),
	}
}

// Common error types
var (
	ErrPackageNotFound = fmt.Errorf("package not found")
	ErrInvalidPackage  = fmt.Errorf("invalid package")
	ErrRateLimited     = fmt.Errorf("rate limited")
	ErrRegistryDown    = fmt.Errorf("registry unavailable")
)

// isRetryableError checks if an error is retryable
func isRetryableError(err error) bool {
	if err == nil {
		return false
	}

	errorStr := err.Error()
	retryableErrors := []string{
		"timeout",
		"connection refused",
		"temporary failure",
		"rate limited",
		"503", // Service Unavailable
		"502", // Bad Gateway
		"504", // Gateway Timeout
	}

	for _, retryable := range retryableErrors {
		if strings.Contains(strings.ToLower(errorStr), retryable) {
			return true
		}
	}

	return false
}

// retryRequest retries a request with exponential backoff
func (bc *BaseConnector) retryRequest(ctx context.Context, url string, maxRetries int) (*http.Response, error) {
	var lastErr error

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			// Exponential backoff
			backoff := time.Duration(attempt*attempt) * time.Second
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
			}
		}

		resp, err := bc.makeRequest(ctx, url)
		if err == nil {
			return resp, nil
		}

		lastErr = err
		if !isRetryableError(err) {
			break
		}
	}

	return nil, fmt.Errorf("request failed after %d attempts: %w", maxRetries+1, lastErr)
}

// normalizeVersion normalizes version strings
func normalizeVersion(version string) string {
	// Remove common prefixes
	version = strings.TrimPrefix(version, "v")
	version = strings.TrimPrefix(version, "V")
	version = strings.TrimPrefix(version, "=")
	version = strings.TrimPrefix(version, "^")
	version = strings.TrimPrefix(version, "~")
	version = strings.TrimPrefix(version, ">=")
	version = strings.TrimPrefix(version, "<=")
	version = strings.TrimPrefix(version, ">")
	version = strings.TrimPrefix(version, "<")

	return strings.TrimSpace(version)
}

// parsePackageURL parses package URLs to extract registry and package name
func parsePackageURL(packageURL string) (registry, packageName string, err error) {
	// Handle different URL formats
	if strings.HasPrefix(packageURL, "npm:") {
		return "npm", strings.TrimPrefix(packageURL, "npm:"), nil
	}
	if strings.HasPrefix(packageURL, "pypi:") {
		return "pypi", strings.TrimPrefix(packageURL, "pypi:"), nil
	}
	if strings.HasPrefix(packageURL, "go:") {
		return "go", strings.TrimPrefix(packageURL, "go:"), nil
	}
	if strings.HasPrefix(packageURL, "cargo:") {
		return "cargo", strings.TrimPrefix(packageURL, "cargo:"), nil
	}
	if strings.HasPrefix(packageURL, "gem:") {
		return "rubygems", strings.TrimPrefix(packageURL, "gem:"), nil
	}
	if strings.HasPrefix(packageURL, "packagist:") {
		return "packagist", strings.TrimPrefix(packageURL, "packagist:"), nil
	}

	// Try to infer from URL structure
	if strings.Contains(packageURL, "npmjs.org") {
		return "npm", extractPackageFromNPMURL(packageURL), nil
	}
	if strings.Contains(packageURL, "pypi.org") {
		return "pypi", extractPackageFromPyPIURL(packageURL), nil
	}
	if strings.Contains(packageURL, "pkg.go.dev") {
		return "go", extractPackageFromGoURL(packageURL), nil
	}
	if strings.Contains(packageURL, "crates.io") {
		return "cargo", extractPackageFromCargoURL(packageURL), nil
	}
	if strings.Contains(packageURL, "rubygems.org") {
		return "rubygems", extractPackageFromRubyGemsURL(packageURL), nil
	}
	if strings.Contains(packageURL, "packagist.org") {
		return "packagist", extractPackageFromPackagistURL(packageURL), nil
	}

	return "", "", fmt.Errorf("unable to parse package URL: %s", packageURL)
}

// Helper functions to extract package names from URLs
func extractPackageFromNPMURL(url string) string {
	// Extract package name from NPM URLs
	// Example: https://www.npmjs.com/package/express -> express
	parts := strings.Split(url, "/")
	for i, part := range parts {
		if part == "package" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

func extractPackageFromPyPIURL(url string) string {
	// Extract package name from PyPI URLs
	// Example: https://pypi.org/project/requests/ -> requests
	parts := strings.Split(url, "/")
	for i, part := range parts {
		if part == "project" && i+1 < len(parts) {
			return strings.TrimSuffix(parts[i+1], "/")
		}
	}
	return ""
}

func extractPackageFromGoURL(url string) string {
	// Extract package name from Go URLs
	// Example: https://pkg.go.dev/github.com/gin-gonic/gin -> github.com/gin-gonic/gin
	if strings.Contains(url, "pkg.go.dev/") {
		parts := strings.Split(url, "pkg.go.dev/")
		if len(parts) > 1 {
			return strings.TrimSuffix(parts[1], "/")
		}
	}
	return ""
}

func extractPackageFromCargoURL(url string) string {
	// Extract package name from Cargo URLs
	// Example: https://crates.io/crates/serde -> serde
	parts := strings.Split(url, "/")
	for i, part := range parts {
		if part == "crates" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

func extractPackageFromRubyGemsURL(url string) string {
	// Extract package name from RubyGems URLs
	// Example: https://rubygems.org/gems/rails -> rails
	parts := strings.Split(url, "/")
	for i, part := range parts {
		if part == "gems" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

func extractPackageFromPackagistURL(url string) string {
	// Extract package name from Packagist URLs
	// Example: https://packagist.org/packages/symfony/console -> symfony/console
	parts := strings.Split(url, "/")
	for i, part := range parts {
		if part == "packages" && i+2 < len(parts) {
			return parts[i+1] + "/" + parts[i+2]
		}
	}
	return ""
}

// validatePackageName validates package names according to registry rules
func validatePackageName(registry, packageName string) error {
	if packageName == "" {
		return fmt.Errorf("package name cannot be empty")
	}

	switch registry {
	case "npm":
		return validateNPMPackageName(packageName)
	case "pypi":
		return validatePyPIPackageName(packageName)
	case "go":
		return validateGoPackageName(packageName)
	case "cargo":
		return validateCargoPackageName(packageName)
	case "rubygems":
		return validateRubyGemsPackageName(packageName)
	case "packagist":
		return validatePackagistPackageName(packageName)
	default:
		return nil // No validation for unknown registries
	}
}

func validateNPMPackageName(name string) error {
	// NPM package name validation rules
	if len(name) > 214 {
		return fmt.Errorf("npm package name too long (max 214 characters)")
	}
	if strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") {
		return fmt.Errorf("npm package name cannot start with . or _")
	}
	return nil
}

func validatePyPIPackageName(name string) error {
	// PyPI package name validation rules
	if len(name) == 0 {
		return fmt.Errorf("pypi package name cannot be empty")
	}
	// PyPI is quite permissive with names
	return nil
}

func validateGoPackageName(name string) error {
	// Go module name validation
	if !strings.Contains(name, "/") {
		return fmt.Errorf("go module name should contain a domain")
	}
	return nil
}

func validateCargoPackageName(name string) error {
	// Cargo package name validation
	if len(name) > 64 {
		return fmt.Errorf("cargo package name too long (max 64 characters)")
	}
	return nil
}

func validateRubyGemsPackageName(name string) error {
	// RubyGems package name validation
	if strings.Contains(name, " ") {
		return fmt.Errorf("rubygems package name cannot contain spaces")
	}
	return nil
}

func validatePackagistPackageName(name string) error {
	// Packagist package name validation (vendor/package format)
	parts := strings.Split(name, "/")
	if len(parts) != 2 {
		return fmt.Errorf("packagist package name must be in vendor/package format")
	}
	return nil
}