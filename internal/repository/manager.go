package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"

	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/internal/scanner"
)

// Manager implements the RepositoryManager interface
type Manager struct {
	connectors        map[string]Connector
	config           *ManagerConfig
	platformConfigs  map[string]PlatformConfig
	logger           *logrus.Logger
	mu               sync.RWMutex
}

// ManagerConfig contains configuration for the repository manager
type ManagerConfig struct {
	MaxConcurrentScans int           `json:"max_concurrent_scans"`
	ScanTimeout        time.Duration `json:"scan_timeout"`
	RetryAttempts      int           `json:"retry_attempts"`
	RetryDelay         time.Duration `json:"retry_delay"`
	EnableMetrics      bool          `json:"enable_metrics"`
	DefaultFilters     *RepositoryFilter `json:"default_filters"`
}

// DefaultManagerConfig returns default configuration
func DefaultManagerConfig() *ManagerConfig {
	return &ManagerConfig{
		MaxConcurrentScans: 10,
		ScanTimeout:        30 * time.Minute,
		RetryAttempts:      3,
		RetryDelay:         5 * time.Second,
		EnableMetrics:      true,
		DefaultFilters: &RepositoryFilter{
			IncludeArchived: false,
			IncludeForks:    false,
			MinStars:        0,
			Languages:       []string{},
			Topics:          []string{},
		},
	}
}

// NewManager creates a new repository manager
func NewManager(config *ManagerConfig) *Manager {
	if config == nil {
		config = DefaultManagerConfig()
	}
	
	return &Manager{
		connectors:       make(map[string]Connector),
		config:          config,
		platformConfigs: make(map[string]PlatformConfig),
		logger:          logrus.New(),
	}
}

// RegisterConnector registers a platform connector
func (m *Manager) RegisterConnector(platform string, connector Connector) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if connector == nil {
		return fmt.Errorf("connector cannot be nil")
	}
	
	m.connectors[platform] = connector
	m.logger.Infof("Registered connector for platform: %s", platform)
	return nil
}

// GetConnector retrieves a platform connector
func (m *Manager) GetConnector(platform string) (Connector, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	connector, exists := m.connectors[platform]
	if !exists {
		return nil, fmt.Errorf("connector not found for platform: %s", platform)
	}
	
	return connector, nil
}

// AddConnector adds a platform connector (alias for RegisterConnector)
func (m *Manager) AddConnector(name string, connector Connector) error {
	return m.RegisterConnector(name, connector)
}

// RemoveConnector removes a platform connector
func (m *Manager) RemoveConnector(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if _, exists := m.connectors[name]; !exists {
		return fmt.Errorf("connector not found for platform: %s", name)
	}
	
	delete(m.connectors, name)
	m.logger.Infof("Removed connector for platform: %s", name)
	return nil
}

// ListConnectors returns all registered connector names
func (m *Manager) ListConnectors() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	names := make([]string, 0, len(m.connectors))
	for name := range m.connectors {
		names = append(names, name)
	}
	
	return names
}

// ListConnectorsMap returns all registered connectors (for internal use)
func (m *Manager) ListConnectorsMap() map[string]Connector {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	connectors := make(map[string]Connector)
	for platform, connector := range m.connectors {
		connectors[platform] = connector
	}
	
	return connectors
}

// DiscoverRepositories discovers repositories across specified platforms
func (m *Manager) DiscoverRepositories(ctx context.Context, platforms []string, filter *RepositoryFilter) ([]*Repository, error) {
	if filter == nil {
		filter = m.config.DefaultFilters
	}
	
	var allRepos []*Repository
	var mu sync.Mutex
	var wg sync.WaitGroup
	errorChan := make(chan error, len(platforms))
	
	for _, platform := range platforms {
		wg.Add(1)
		go func(platformName string) {
			defer wg.Done()
			
			connector, err := m.GetConnector(platformName)
			if err != nil {
				errorChan <- fmt.Errorf("failed to get connector for %s: %w", platformName, err)
				return
			}
			
			// For now, just list repositories without specific configuration
			// This is a simplified implementation that can be enhanced later
			repos, err := connector.ListRepositories(ctx, "", filter)
			if err != nil {
				errorChan <- fmt.Errorf("failed to discover repositories for %s: %w", platformName, err)
				return
			}
			
			mu.Lock()
			allRepos = append(allRepos, repos...)
			mu.Unlock()
		}(platform)
	}
	
	wg.Wait()
	close(errorChan)
	
	// Collect any errors
	var errors []error
	for err := range errorChan {
		errors = append(errors, err)
	}
	
	if len(errors) > 0 {
		m.logger.Warnf("Encountered %d errors during repository discovery", len(errors))
		for _, err := range errors {
			m.logger.Warn(err)
		}
	}
	
	m.logger.Infof("Discovered %d repositories across %d platforms", len(allRepos), len(platforms))
	return allRepos, nil
}

// ScanRepositories scans multiple repositories concurrently
func (m *Manager) ScanRepositories(ctx context.Context, requests []*ScanRequest) ([]*ScanResult, error) {
	if len(requests) == 0 {
		return nil, fmt.Errorf("no scan requests provided")
	}
	
	// Create semaphore to limit concurrent scans
	semaphore := make(chan struct{}, m.config.MaxConcurrentScans)
	results := make([]*ScanResult, len(requests))
	var wg sync.WaitGroup
	errorChan := make(chan error, len(requests))
	
	for i, request := range requests {
		wg.Add(1)
		go func(index int, req *ScanRequest) {
			defer wg.Done()
			
			// Acquire semaphore
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			
			result, err := m.scanSingleRepository(ctx, req)
			if err != nil {
				errorChan <- fmt.Errorf("failed to scan repository %s: %w", req.Repository.FullName, err)
				results[index] = &ScanResult{
					Repository: req.Repository,
					Status:     "failed",
					Error:      err.Error(),
					StartTime:  time.Now(),
					EndTime:    time.Now(),
				}
				return
			}
			
			results[index] = result
		}(i, request)
	}
	
	wg.Wait()
	close(errorChan)
	
	// Collect errors
	var errors []error
	for err := range errorChan {
		errors = append(errors, err)
	}
	
	if len(errors) > 0 {
		m.logger.Warnf("Encountered %d errors during repository scanning", len(errors))
		for _, err := range errors {
			m.logger.Warn(err)
		}
	}
	
	m.logger.Infof("Completed scanning %d repositories", len(requests))
	return results, nil
}

// ScanRepository scans a single repository
func (m *Manager) ScanRepository(ctx context.Context, request *ScanRequest) error {
	_, err := m.scanSingleRepository(ctx, request)
	return err
}

// ScanRepositoryWithResult performs a repository scan and returns the full result
func (m *Manager) ScanRepositoryWithResult(ctx context.Context, request *ScanRequest) (*ScanResult, error) {
	return m.scanSingleRepository(ctx, request)
}

// GetRepositoryContent retrieves repository content
func (m *Manager) GetRepositoryContent(ctx context.Context, platform string, repo *Repository, path string, ref string) ([]byte, error) {
	connector, err := m.GetConnector(platform)
	if err != nil {
		return nil, err
	}
	
	return connector.GetRepositoryContent(ctx, repo, path, ref)
}

// Helper methods

func (m *Manager) discoverRepositoriesForPlatform(ctx context.Context, connector Connector, config *PlatformConfig, filter *RepositoryFilter) ([]*Repository, error) {
	var allRepos []*Repository
	
	// Get organizations if specified
	if len(config.Organizations) > 0 {
		for _, orgName := range config.Organizations {
			org, err := connector.GetOrganization(ctx, orgName)
			if err != nil {
				m.logger.Warnf("Failed to get organization %s: %v", orgName, err)
				continue
			}
			
			repos, err := connector.ListOrgRepositories(ctx, org.Login, filter)
			if err != nil {
				m.logger.Warnf("Failed to list repositories for organization %s: %v", orgName, err)
				continue
			}
			
			allRepos = append(allRepos, repos...)
		}
	}
	
	// Get specific repositories if specified
	if len(config.Repositories) > 0 {
		for _, repoName := range config.Repositories {
			// Parse owner/repo format
			parts := strings.Split(repoName, "/")
			if len(parts) != 2 {
				m.logger.Warnf("Invalid repository format %s, expected owner/repo", repoName)
				continue
			}
			repo, err := connector.GetRepository(ctx, parts[0], parts[1])
			if err != nil {
				m.logger.Warnf("Failed to get repository %s: %v", repoName, err)
				continue
			}
			
			// Apply filter
			if m.applyRepositoryFilter(repo, filter) {
				allRepos = append(allRepos, repo)
			}
		}
	}
	
	return allRepos, nil
}

func (m *Manager) scanSingleRepository(ctx context.Context, request *ScanRequest) (*ScanResult, error) {
	startTime := time.Now()
	
	// Create scan context with timeout
	scanCtx, cancel := context.WithTimeout(ctx, m.config.ScanTimeout)
	defer cancel()
	
	result := &ScanResult{
		Repository: request.Repository,
		ScanID:     request.ScanID,
		Status:     "running",
		StartTime:  startTime,
	}
	
	// Get connector for the repository platform
	connector, err := m.GetConnector(request.Repository.Platform)
	if err != nil {
		return nil, fmt.Errorf("failed to get connector: %w", err)
	}
	
	// Get dependency files from repository
	dependencyFiles, err := m.getDependencyFiles(scanCtx, connector, request.Repository)
	if err != nil {
		return nil, fmt.Errorf("failed to get dependency files: %w", err)
	}
	
	if len(dependencyFiles) == 0 {
		result.Status = "completed"
		result.EndTime = time.Now()
		result.Duration = result.EndTime.Sub(result.StartTime)
		result.Message = "No dependency files found"
		return result, nil
	}
	
	// Create temporary directory for analysis
	tempDir, err := m.createTempAnalysisDir(scanCtx, connector, request.Repository, dependencyFiles)
	if err != nil {
		return nil, fmt.Errorf("failed to create temp analysis directory: %w", err)
	}
	defer m.cleanupTempDir(tempDir)
	
	// Download dependency files to temp directory
	if err := m.downloadDependencyFiles(scanCtx, connector, request.Repository, dependencyFiles, tempDir); err != nil {
		return nil, fmt.Errorf("failed to download dependency files: %w", err)
	}
	
	// Initialize scanner with basic config
	scannerConfig := &config.Config{
		TypoDetection: &config.TypoDetectionConfig{
			Enabled:   true,
			Threshold: 0.8,
		},
		Scanner: &config.ScannerConfig{
			MaxConcurrency: 5,
			IncludeDevDeps: true,
		},
	}
	scanner, err := scanner.New(scannerConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize scanner: %w", err)
	}
	
	// Perform actual scanning
	scanResult, err := scanner.ScanProject(tempDir)
	if err != nil {
		return nil, fmt.Errorf("failed to scan project: %w", err)
	}
	
	// Convert scanner result to repository scan result
	analysisResult := map[string]interface{}{
		"dependency_files": dependencyFiles,
		"scan_options":     request.Options,
		"repository":       request.Repository.FullName,
		"status":           "completed",
		"packages":         len(scanResult.Packages),
		"findings":         len(scanResult.Findings),
		"risk_score":       scanResult.RiskScore,
		"overall_risk":     scanResult.OverallRisk,
	}
	
	// Complete the scan result
	result.Status = "completed"
	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)
	result.AnalysisResult = analysisResult
	result.DependencyFiles = dependencyFiles
	result.Metadata = map[string]interface{}{
		"scan_options": request.Options,
		"file_count":   len(dependencyFiles),
		"packages":     len(scanResult.Packages),
		"findings":     len(scanResult.Findings),
		"risk_score":   scanResult.RiskScore,
	}
	
	m.logger.Infof("Completed scan for repository %s in %v - found %d packages, %d findings", 
		request.Repository.FullName, result.Duration, len(scanResult.Packages), len(scanResult.Findings))
	return result, nil
}

func (m *Manager) getDependencyFiles(ctx context.Context, connector Connector, repo *Repository) ([]string, error) {
	// Common dependency file patterns
	dependencyPatterns := []string{
		"package.json",
		"package-lock.json",
		"yarn.lock",
		"requirements.txt",
		"Pipfile",
		"Pipfile.lock",
		"go.mod",
		"go.sum",
		"Cargo.toml",
		"Cargo.lock",
		"composer.json",
		"composer.lock",
		"Gemfile",
		"Gemfile.lock",
		"pom.xml",
		"build.gradle",
		"build.gradle.kts",
	}
	
	var foundFiles []string
	for _, pattern := range dependencyPatterns {
		_, err := connector.GetRepositoryContent(ctx, repo, pattern, repo.DefaultBranch)
		if err == nil {
			foundFiles = append(foundFiles, pattern)
		}
	}
	
	return foundFiles, nil
}

func (m *Manager) createTempAnalysisDir(ctx context.Context, connector Connector, repo *Repository, files []string) (string, error) {
	// This is a simplified implementation
	// In a real implementation, you would create a temporary directory
	// and download the dependency files to it
	return "/tmp/typosentinel-analysis", nil
}

func (m *Manager) downloadDependencyFiles(ctx context.Context, connector Connector, repo *Repository, files []string, tempDir string) error {
	for _, file := range files {
		// Get file content from repository
		content, err := connector.GetRepositoryContent(ctx, repo, file, repo.DefaultBranch)
		if err != nil {
			m.logger.Warnf("Failed to get content for file %s: %v", file, err)
			continue
		}
		
		// Create file path in temp directory
		filePath := filepath.Join(tempDir, filepath.Base(file))
		
		// Write file content
		if err := ioutil.WriteFile(filePath, content, 0644); err != nil {
			return fmt.Errorf("failed to write file %s: %w", filePath, err)
		}
		
		m.logger.Debugf("Downloaded dependency file: %s", file)
	}
	
	return nil
}

func (m *Manager) cleanupTempDir(dir string) {
	if err := os.RemoveAll(dir); err != nil {
		m.logger.Warnf("Failed to cleanup temp directory %s: %v", dir, err)
	}
}

func (m *Manager) applyRepositoryFilter(repo *Repository, filter *RepositoryFilter) bool {
	if filter == nil {
		return true
	}
	
	// Check archived status
	if !filter.IncludeArchived && repo.Archived {
		return false
	}
	
	// Check fork status
	if !filter.IncludeForks && repo.Fork {
		return false
	}
	
	// Check minimum stars
	if repo.StarCount < filter.MinStars {
		return false
	}
	
	// Check languages
	if len(filter.Languages) > 0 {
		langMatch := false
		for _, filterLang := range filter.Languages {
			for repoLang := range repo.Languages {
				if filterLang == repoLang {
					langMatch = true
					break
				}
			}
			if langMatch {
				break
			}
		}
		if !langMatch {
			return false
		}
	}
	
	// Check topics
	if len(filter.Topics) > 0 {
		topicMatch := false
		for _, filterTopic := range filter.Topics {
			for _, repoTopic := range repo.Topics {
				if filterTopic == repoTopic {
					topicMatch = true
					break
				}
			}
			if topicMatch {
				break
			}
		}
		if !topicMatch {
			return false
		}
	}
	
	// Check name pattern
	if filter.NamePattern != "" {
		if !m.matchesPattern(repo.Name, filter.NamePattern) {
			return false
		}
	}
	
	return true
}

func (m *Manager) matchesPattern(name, pattern string) bool {
	// Simple wildcard matching
	if pattern == "*" {
		return true
	}
	
	// For now, just check if the pattern is contained in the name
	// This could be enhanced with proper regex or glob matching
	return len(name) >= len(pattern) && name[:len(pattern)] == pattern
}

// BulkScan scans multiple repositories (alias for ScanRepositories)
func (m *Manager) BulkScan(ctx context.Context, requests []*ScanRequest) error {
	_, err := m.ScanRepositories(ctx, requests)
	return err
}

// ScanRepositoriesWithResults scans multiple repositories and returns the full results
func (m *Manager) ScanRepositoriesWithResults(ctx context.Context, requests []*ScanRequest) ([]*ScanResult, error) {
	return m.ScanRepositories(ctx, requests)
}

// LoadConfig loads configuration from a file
func (m *Manager) LoadConfig(configPath string) error {
	m.logger.Infof("Loading configuration from: %s", configPath)
	
	// Check if config file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return fmt.Errorf("configuration file not found: %s", configPath)
	}
	
	// Read configuration file
	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read configuration file: %w", err)
	}
	
	// Parse configuration based on file extension
	var platformConfigs map[string]PlatformConfig
	ext := filepath.Ext(configPath)
	
	switch ext {
	case ".json":
		if err := json.Unmarshal(data, &platformConfigs); err != nil {
			return fmt.Errorf("failed to parse JSON configuration: %w", err)
		}
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(data, &platformConfigs); err != nil {
			return fmt.Errorf("failed to parse YAML configuration: %w", err)
		}
	default:
		return fmt.Errorf("unsupported configuration file format: %s", ext)
	}
	
	// Store configuration
	m.mu.Lock()
	m.platformConfigs = platformConfigs
	m.mu.Unlock()
	
	m.logger.Infof("Successfully loaded configuration with %d platforms", len(platformConfigs))
	return nil
}

// ValidateConfiguration validates the current configuration
func (m *Manager) ValidateConfiguration() error {
	m.logger.Info("Validating configuration")
	
	m.mu.RLock()
	platformConfigs := m.platformConfigs
	m.mu.RUnlock()
	
	if len(platformConfigs) == 0 {
		return fmt.Errorf("no platform configurations found")
	}
	
	// Validate each platform configuration
	for platform, platformConfig := range platformConfigs {
		if err := m.validatePlatformConfig(platform, platformConfig); err != nil {
			return fmt.Errorf("invalid configuration for platform %s: %w", platform, err)
		}
	}
	
	// Validate connector availability
	for platform := range platformConfigs {
		if _, exists := m.connectors[platform]; !exists {
			m.logger.Warnf("No connector registered for configured platform: %s", platform)
		}
	}
	
	m.logger.Info("Configuration validation completed successfully")
	return nil
}

// validatePlatformConfig validates a single platform configuration
func (m *Manager) validatePlatformConfig(platform string, config PlatformConfig) error {
	// Check required fields
	if config.BaseURL == "" {
		return fmt.Errorf("base_url is required")
	}
	
	// Validate URL format
	if _, err := url.Parse(config.BaseURL); err != nil {
		return fmt.Errorf("invalid base_url format: %w", err)
	}
	
	// Check authentication configuration
	if config.Auth.Token == "" && config.Auth.Username == "" {
		return fmt.Errorf("either token or username must be provided for authentication")
	}
	
	// Validate rate limiting configuration
	if config.RateLimit.RequestsPerHour < 0 {
		return fmt.Errorf("requests_per_hour cannot be negative")
	}
	
	if config.RateLimit.BurstLimit < 0 {
		return fmt.Errorf("burst_limit cannot be negative")
	}
	
	// Validate timeout values
	if config.Timeout < 0 {
		return fmt.Errorf("timeout cannot be negative")
	}
	
	return nil
}

// GetConfiguration returns the current configuration
func (m *Manager) GetConfiguration() map[string]PlatformConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	// Return a copy to prevent external modification
	configCopy := make(map[string]PlatformConfig)
	for platform, config := range m.platformConfigs {
		// Create a copy of the config to avoid sharing references
		authCopy := AuthConfig{
			Type:         config.Auth.Type,
			Token:        "***", // Mask sensitive data
			Username:     config.Auth.Username,
			Password:     "***", // Mask sensitive data
			ClientID:     config.Auth.ClientID,
			ClientSecret: "***", // Mask sensitive data
			SSHKey:       "***", // Mask sensitive data
			SSHKeyPath:   config.Auth.SSHKeyPath,
			Metadata:     config.Auth.Metadata,
		}
		
		configCopy[platform] = PlatformConfig{
			Name:          config.Name,
			BaseURL:       config.BaseURL,
			APIVersion:    config.APIVersion,
			Auth:          authCopy,
			RateLimit:     config.RateLimit,
			Timeout:       config.Timeout,
			Retries:       config.Retries,
			Organizations: config.Organizations,
			Repositories:  config.Repositories,
			Metadata:      config.Metadata,
		}
	}
	
	return configCopy
}

// HealthCheck performs health checks on all connectors
func (m *Manager) HealthCheck(ctx context.Context) map[string]error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	results := make(map[string]error)
	for name, connector := range m.connectors {
		if err := connector.HealthCheck(ctx); err != nil {
			results[name] = err
		} else {
			results[name] = nil
		}
	}
	
	return results
}

// GetMetrics returns metrics for all connectors
func (m *Manager) GetMetrics(ctx context.Context) map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	metrics := make(map[string]interface{})
	metrics["total_connectors"] = len(m.connectors)
	metrics["connector_names"] = m.ListConnectors()
	
	// Add connector-specific metrics
	for name, connector := range m.connectors {
		rateLimit, err := connector.GetRateLimit(ctx)
		if err == nil {
			metrics[name+"_rate_limit"] = rateLimit
		}
	}
	
	return metrics
}

// InitializeDefaultConnectors initializes connectors for common platforms
// This method should be called after registering the actual connector implementations
func (m *Manager) InitializeDefaultConnectors() error {
	m.logger.Info("Default connectors should be registered externally to avoid import cycles")
	return nil
}