package repository

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/internal/scanner"
)

// Manager implements the RepositoryManager interface
type Manager struct {
	connectors map[string]Connector
	config     *ManagerConfig
	logger     *logrus.Logger
	mu         sync.RWMutex
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
		connectors: make(map[string]Connector),
		config:     config,
		logger:     logrus.New(),
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

// ListConnectors returns all registered connectors
func (m *Manager) ListConnectors() map[string]Connector {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	connectors := make(map[string]Connector)
	for platform, connector := range m.connectors {
		connectors[platform] = connector
	}
	
	return connectors
}

// DiscoverRepositories discovers repositories across all platforms
func (m *Manager) DiscoverRepositories(ctx context.Context, configs map[string]*PlatformConfig, filter *RepositoryFilter) ([]*Repository, error) {
	if filter == nil {
		filter = m.config.DefaultFilters
	}
	
	var allRepos []*Repository
	var mu sync.Mutex
	var wg sync.WaitGroup
	errorChan := make(chan error, len(configs))
	
	for platform, config := range configs {
		wg.Add(1)
		go func(platform string, config *PlatformConfig) {
			defer wg.Done()
			
			connector, err := m.GetConnector(platform)
			if err != nil {
				errorChan <- fmt.Errorf("failed to get connector for %s: %w", platform, err)
				return
			}
			
			repos, err := m.discoverRepositoriesForPlatform(ctx, connector, config, filter)
			if err != nil {
				errorChan <- fmt.Errorf("failed to discover repositories for %s: %w", platform, err)
				return
			}
			
			mu.Lock()
			allRepos = append(allRepos, repos...)
			mu.Unlock()
		}(platform, config)
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
	
	m.logger.Infof("Discovered %d repositories across %d platforms", len(allRepos), len(configs))
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
func (m *Manager) ScanRepository(ctx context.Context, request *ScanRequest) (*ScanResult, error) {
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

// InitializeDefaultConnectors initializes connectors for common platforms
// This method should be called after registering the actual connector implementations
func (m *Manager) InitializeDefaultConnectors() error {
	m.logger.Info("Default connectors should be registered externally to avoid import cycles")
	return nil
}