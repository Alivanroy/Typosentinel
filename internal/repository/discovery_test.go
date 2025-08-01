package repository

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// MockRepositoryManager implements RepositoryManager for testing
type MockRepositoryManager struct {
	connectors map[string]Connector
}

func NewMockRepositoryManager() *MockRepositoryManager {
	return &MockRepositoryManager{
		connectors: make(map[string]Connector),
	}
}

func (m *MockRepositoryManager) AddConnector(name string, connector Connector) error {
	m.connectors[name] = connector
	return nil
}

func (m *MockRepositoryManager) RemoveConnector(name string) error {
	delete(m.connectors, name)
	return nil
}

func (m *MockRepositoryManager) GetConnector(name string) (Connector, error) {
	connector, exists := m.connectors[name]
	if !exists {
		return nil, fmt.Errorf("connector not found: %s", name)
	}
	return connector, nil
}

func (m *MockRepositoryManager) ListConnectors() []string {
	names := make([]string, 0, len(m.connectors))
	for name := range m.connectors {
		names = append(names, name)
	}
	return names
}

func (m *MockRepositoryManager) DiscoverRepositories(ctx context.Context, platforms []string, filter *RepositoryFilter) ([]*Repository, error) {
	return nil, nil
}

func (m *MockRepositoryManager) ScanRepository(ctx context.Context, request *ScanRequest) error {
	return nil
}

func (m *MockRepositoryManager) BulkScan(ctx context.Context, requests []*ScanRequest) error {
	return nil
}

func (m *MockRepositoryManager) LoadConfig(configPath string) error {
	return nil
}

func (m *MockRepositoryManager) ValidateConfiguration() error {
	return nil
}

func (m *MockRepositoryManager) GetConfiguration() map[string]PlatformConfig {
	return make(map[string]PlatformConfig)
}

func (m *MockRepositoryManager) HealthCheck(ctx context.Context) map[string]error {
	return make(map[string]error)
}

func (m *MockRepositoryManager) GetMetrics(ctx context.Context) map[string]interface{} {
	return make(map[string]interface{})
}

// MockConnector implements Connector for testing
type MockConnector struct {
	platform     string
	repositories []*Repository
	organizations []*Organization
}

func NewMockConnector(platform string) *MockConnector {
	return &MockConnector{
		platform: platform,
		repositories: []*Repository{
			{
				ID:       "1",
				Name:     "test-repo",
				FullName: "test-org/test-repo",
				Language: "Go",
				Private:  false,
				StarCount: 10,
				Platform: platform,
			},
			{
				ID:       "2",
				Name:     "private-repo",
				FullName: "test-org/private-repo",
				Language: "Python",
				Private:  true,
				StarCount: 5,
				Platform: platform,
			},
		},
		organizations: []*Organization{
			{
				ID:       "org1",
				Login:    "test-org",
				Name:     "Test Organization",
				Platform: platform,
			},
		},
	}
}

func (m *MockConnector) GetPlatformName() string { return m.platform }
func (m *MockConnector) GetPlatformType() string { return "git" }
func (m *MockConnector) GetAPIVersion() string { return "v1" }

func (m *MockConnector) Authenticate(ctx context.Context, config AuthConfig) error { return nil }
func (m *MockConnector) ValidateAuth(ctx context.Context) error { return nil }
func (m *MockConnector) RefreshAuth(ctx context.Context) error { return nil }

func (m *MockConnector) ListOrganizations(ctx context.Context) ([]*Organization, error) {
	return m.organizations, nil
}

func (m *MockConnector) GetOrganization(ctx context.Context, name string) (*Organization, error) {
	for _, org := range m.organizations {
		if org.Login == name {
			return org, nil
		}
	}
	return nil, fmt.Errorf("organization not found: %s", name)
}

func (m *MockConnector) ListRepositories(ctx context.Context, owner string, filter *RepositoryFilter) ([]*Repository, error) {
	return m.filterRepositories(m.repositories, filter), nil
}

func (m *MockConnector) ListOrgRepositories(ctx context.Context, org string, filter *RepositoryFilter) ([]*Repository, error) {
	return m.filterRepositories(m.repositories, filter), nil
}

func (m *MockConnector) GetRepository(ctx context.Context, owner, name string) (*Repository, error) {
	for _, repo := range m.repositories {
		if repo.Name == name {
			return repo, nil
		}
	}
	return nil, fmt.Errorf("repository not found: %s/%s", owner, name)
}

func (m *MockConnector) SearchRepositories(ctx context.Context, query string, filter *RepositoryFilter) ([]*Repository, error) {
	return m.filterRepositories(m.repositories, filter), nil
}

func (m *MockConnector) filterRepositories(repos []*Repository, filter *RepositoryFilter) []*Repository {
	if filter == nil {
		return repos
	}
	
	filtered := make([]*Repository, 0)
	for _, repo := range repos {
		if !filter.IncludePrivate && repo.Private {
			continue
		}
		if filter.MinStars > 0 && repo.StarCount < filter.MinStars {
			continue
		}
		filtered = append(filtered, repo)
	}
	return filtered
}

func (m *MockConnector) GetRepositoryContent(ctx context.Context, repo *Repository, path string, ref string) ([]byte, error) {
	return []byte("mock content"), nil
}

func (m *MockConnector) ListRepositoryFiles(ctx context.Context, repo *Repository, path string, ref string) ([]string, error) {
	return []string{"file1.go", "file2.py"}, nil
}

func (m *MockConnector) GetPackageFiles(ctx context.Context, repo *Repository, ref string) (map[string][]byte, error) {
	return map[string][]byte{"go.mod": []byte("module test")}, nil
}

func (m *MockConnector) GetRepositoryLanguages(ctx context.Context, repo *Repository) (map[string]int, error) {
	return map[string]int{"Go": 100}, nil
}

func (m *MockConnector) GetRepositoryTopics(ctx context.Context, repo *Repository) ([]string, error) {
	return []string{"api", "testing"}, nil
}

func (m *MockConnector) GetRepositoryBranches(ctx context.Context, repo *Repository) ([]string, error) {
	return []string{"main", "develop"}, nil
}

func (m *MockConnector) GetRepositoryCommits(ctx context.Context, repo *Repository, branch string, limit int) ([]Commit, error) {
	return []Commit{
		{SHA: "abc123", Message: "Initial commit", Author: "test"},
	}, nil
}

func (m *MockConnector) CreateWebhook(ctx context.Context, repo *Repository, webhookURL string, events []string) error {
	return nil
}

func (m *MockConnector) DeleteWebhook(ctx context.Context, repo *Repository, webhookID string) error {
	return nil
}

func (m *MockConnector) ListWebhooks(ctx context.Context, repo *Repository) ([]Webhook, error) {
	return []Webhook{}, nil
}

func (m *MockConnector) GetRateLimit(ctx context.Context) (*RateLimit, error) {
	return &RateLimit{Limit: 5000, Remaining: 4999}, nil
}

func (m *MockConnector) HealthCheck(ctx context.Context) error {
	return nil
}

func (m *MockConnector) Close() error {
	return nil
}

func TestNewDiscoveryService(t *testing.T) {
	manager := NewMockRepositoryManager()
	config := DiscoveryConfig{
		Interval: 1 * time.Hour,
		MaxReposPerPlatform: 100,
		Workers: 2,
		Timeout: 30 * time.Second,
	}
	
	service := NewDiscoveryService(manager, config)
	if service == nil {
		t.Fatal("Discovery service should not be nil")
	}
	
	if service.IsRunning() {
		t.Error("Discovery service should not be running initially")
	}
}

func TestDiscoveryService_StartStop(t *testing.T) {
	manager := NewMockRepositoryManager()
	connector := NewMockConnector("github")
	manager.AddConnector("github", connector)
	
	config := DiscoveryConfig{
		Platforms: []PlatformDiscoveryConfig{
			{
				Platform: "github",
				Enabled:  true,
				Organizations: []string{"test-org"},
			},
		},
		Interval: 1 * time.Hour,
		MaxReposPerPlatform: 100,
		Workers: 2,
		Timeout: 30 * time.Second,
	}
	
	service := NewDiscoveryService(manager, config)
	ctx := context.Background()
	
	// Test start
	err := service.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start discovery service: %v", err)
	}
	
	if !service.IsRunning() {
		t.Error("Discovery service should be running after start")
	}
	
	// Test stop
	err = service.Stop()
	if err != nil {
		t.Fatalf("Failed to stop discovery service: %v", err)
	}
	
	if service.IsRunning() {
		t.Error("Discovery service should not be running after stop")
	}
}

func TestDiscoveryService_DiscoverOnce(t *testing.T) {
	manager := NewMockRepositoryManager()
	connector := NewMockConnector("github")
	manager.AddConnector("github", connector)
	
	config := DiscoveryConfig{
		Platforms: []PlatformDiscoveryConfig{
			{
				Platform: "github",
				Enabled:  true,
				Organizations: []string{"test-org"},
			},
		},
		Interval: 1 * time.Hour,
		MaxReposPerPlatform: 100,
		IncludePrivate: false,
		Workers: 2,
		Timeout: 30 * time.Second,
	}
	
	service := NewDiscoveryService(manager, config)
	ctx := context.Background()
	
	// Start the service
	err := service.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start discovery service: %v", err)
	}
	defer service.Stop()
	
	// Test discovery
	results, err := service.DiscoverOnce(ctx)
	if err != nil {
		t.Fatalf("Discovery failed: %v", err)
	}
	
	if len(results) != 1 {
		t.Errorf("Expected 1 discovery result, got %d", len(results))
	}
	
	result := results[0]
	if result.Platform != "github" {
		t.Errorf("Expected platform 'github', got '%s'", result.Platform)
	}
	
	// Should only include public repositories due to IncludePrivate: false
	if len(result.Repositories) != 1 {
		t.Errorf("Expected 1 repository (public only), got %d", len(result.Repositories))
	}
	
	if result.Repositories[0].Private {
		t.Error("Should not include private repositories")
	}
}

func TestDiscoveryService_ApplyFilters(t *testing.T) {
	manager := NewMockRepositoryManager()
	config := DiscoveryConfig{
		IncludePrivate: false,
		IncludeForks: false,
		IncludeArchived: false,
		Filter: &RepositoryFilter{
			MinStars: 8,
			Languages: []string{"Go"},
		},
	}
	
	service := NewDiscoveryService(manager, config)
	
	repos := []*Repository{
		{Name: "repo1", Private: false, Fork: false, Archived: false, StarCount: 10, Language: "Go"},
		{Name: "repo2", Private: true, Fork: false, Archived: false, StarCount: 15, Language: "Go"},
		{Name: "repo3", Private: false, Fork: true, Archived: false, StarCount: 12, Language: "Go"},
		{Name: "repo4", Private: false, Fork: false, Archived: true, StarCount: 20, Language: "Go"},
		{Name: "repo5", Private: false, Fork: false, Archived: false, StarCount: 5, Language: "Go"},
		{Name: "repo6", Private: false, Fork: false, Archived: false, StarCount: 25, Language: "Python"},
	}
	
	filtered := service.applyFilters(repos)
	
	// Should only include repo1 (public, not fork, not archived, >= 8 stars, Go language)
	if len(filtered) != 1 {
		t.Errorf("Expected 1 filtered repository, got %d", len(filtered))
	}
	
	if len(filtered) > 0 && filtered[0].Name != "repo1" {
		t.Errorf("Expected repo1, got %s", filtered[0].Name)
	}
}

func TestDiscoveryService_MatchesFilter(t *testing.T) {
	manager := NewMockRepositoryManager()
	config := DiscoveryConfig{}
	service := NewDiscoveryService(manager, config)
	
	repo := &Repository{
		Name:      "test-repo",
		Language:  "Go",
		StarCount: 10,
		Size:      1000,
		UpdatedAt: time.Now(),
	}
	
	tests := []struct {
		name     string
		filter   *RepositoryFilter
		expected bool
	}{
		{
			name:     "nil filter",
			filter:   nil,
			expected: true,
		},
		{
			name:     "matching language",
			filter:   &RepositoryFilter{Languages: []string{"Go", "Python"}},
			expected: true,
		},
		{
			name:     "non-matching language",
			filter:   &RepositoryFilter{Languages: []string{"Java", "Python"}},
			expected: false,
		},
		{
			name:     "minimum stars met",
			filter:   &RepositoryFilter{MinStars: 5},
			expected: true,
		},
		{
			name:     "minimum stars not met",
			filter:   &RepositoryFilter{MinStars: 15},
			expected: false,
		},
		{
			name:     "name pattern match",
			filter:   &RepositoryFilter{NamePattern: "test"},
			expected: true,
		},
		{
			name:     "name pattern no match",
			filter:   &RepositoryFilter{NamePattern: "production"},
			expected: false,
		},
		{
			name:     "exclude pattern match",
			filter:   &RepositoryFilter{ExcludePatterns: []string{"test"}},
			expected: false,
		},
		{
			name:     "exclude pattern no match",
			filter:   &RepositoryFilter{ExcludePatterns: []string{"production"}},
			expected: true,
		},
	}
	
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := service.matchesFilter(repo, test.filter)
			if result != test.expected {
				t.Errorf("Expected %v, got %v", test.expected, result)
			}
		})
	}
}

func TestSplitRepositoryName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "valid owner/repo",
			input:    "owner/repo",
			expected: []string{"owner", "repo"},
		},
		{
			name:     "no slash",
			input:    "repo",
			expected: []string{},
		},
		{
			name:     "multiple slashes",
			input:    "owner/repo/extra",
			expected: []string{"owner", "repo/extra"},
		},
		{
			name:     "empty string",
			input:    "",
			expected: []string{},
		},
	}
	
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := splitRepositoryName(test.input)
			if len(result) != len(test.expected) {
				t.Errorf("Expected length %d, got %d", len(test.expected), len(result))
				return
			}
			for i, expected := range test.expected {
				if result[i] != expected {
					t.Errorf("Expected %s at index %d, got %s", expected, i, result[i])
				}
			}
		})
	}
}

func TestMatchesPattern(t *testing.T) {
	tests := []struct {
		name     string
		string   string
		pattern  string
		expected bool
	}{
		{
			name:     "empty pattern",
			string:   "test",
			pattern:  "",
			expected: true,
		},
		{
			name:     "wildcard pattern",
			string:   "test",
			pattern:  "*",
			expected: true,
		},
		{
			name:     "exact match",
			string:   "test-repo",
			pattern:  "test",
			expected: true,
		},
		{
			name:     "no match",
			string:   "production-app",
			pattern:  "test",
			expected: false,
		},
		{
			name:     "case insensitive",
			string:   "TEST-REPO",
			pattern:  "test",
			expected: true,
		},
	}
	
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := matchesPattern(test.string, test.pattern)
			if result != test.expected {
				t.Errorf("Expected %v, got %v", test.expected, result)
			}
		})
	}
}