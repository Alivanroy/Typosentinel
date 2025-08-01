package tests

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/Alivanroy/Typosentinel/internal/auth"
	"github.com/Alivanroy/Typosentinel/internal/repository"
)

// EnterpriseIntegrationTestSuite tests enterprise features end-to-end
type EnterpriseIntegrationTestSuite struct {
	suite.Suite
	tempDir        string
	mockGitServer  *httptest.Server
	mockAuthServer *httptest.Server
	authManager    *auth.AuthManager
	repoManager    *repository.Manager
	ctx            context.Context
	cancel         context.CancelFunc
}

// SetupSuite initializes the test environment
func (suite *EnterpriseIntegrationTestSuite) SetupSuite() {
	// Create temporary directory
	var err error
	suite.tempDir, err = os.MkdirTemp("", "typosentinel-enterprise-test-*")
	require.NoError(suite.T(), err)

	// Setup context
	suite.ctx, suite.cancel = context.WithCancel(context.Background())

	// Setup mock servers
	suite.setupMockServers()

	// Initialize components
	suite.setupComponents()
}

// TearDownSuite cleans up the test environment
func (suite *EnterpriseIntegrationTestSuite) TearDownSuite() {
	suite.cancel()
	if suite.mockGitServer != nil {
		suite.mockGitServer.Close()
	}
	if suite.mockAuthServer != nil {
		suite.mockAuthServer.Close()
	}
	os.RemoveAll(suite.tempDir)
}

// setupMockServers creates mock external services
func (suite *EnterpriseIntegrationTestSuite) setupMockServers() {
	// Mock Git server (GitHub/GitLab/etc.)
	suite.mockGitServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/repos"):
			suite.handleRepoRequest(w, r)
		case strings.Contains(r.URL.Path, "/orgs"):
			suite.handleOrgRequest(w, r)
		case strings.Contains(r.URL.Path, "/user"):
			suite.handleUserRequest(w, r)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))

	// Mock authentication server (LDAP/SSO)
	suite.mockAuthServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/auth/login"):
			suite.handleAuthLogin(w, r)
		case strings.Contains(r.URL.Path, "/auth/validate"):
			suite.handleAuthValidate(w, r)
		case strings.Contains(r.URL.Path, "/auth/roles"):
			suite.handleAuthRoles(w, r)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

// setupComponents initializes Typosentinel components
func (suite *EnterpriseIntegrationTestSuite) setupComponents() {
	// Create test configuration
	config := suite.createTestConfig()

	// Initialize authentication manager
	suite.authManager = auth.NewAuthManager(config.Auth, nil)

	// Initialize repository manager
	suite.repoManager = repository.NewManager(repository.DefaultManagerConfig())
}

// TestE001_AuthenticationIntegration tests authentication features
func (suite *EnterpriseIntegrationTestSuite) TestE001_AuthenticationIntegration() {
	// Test user creation and authentication
	user := &auth.User{
		ID:          "test-user-123",
		Username:    "testuser",
		Email:       "test@company.com",
		DisplayName: "Test User",
		Roles:       []string{"security_analyst"},
		Groups:      []string{"security-team"},
		IsActive:    true,
		CreatedAt:   time.Now(),
	}

	// Test role checking
	assert.True(suite.T(), user.HasRole("security_analyst"))
	assert.False(suite.T(), user.HasRole("administrator"))

	// Test group membership
	assert.True(suite.T(), user.InGroup("security-team"))
	assert.False(suite.T(), user.InGroup("admin-team"))

	// Test multiple role checking
	assert.True(suite.T(), user.HasAnyRole("security_analyst", "developer"))
	assert.False(suite.T(), user.HasAnyRole("administrator", "manager"))
}

// TestE002_RepositoryManagement tests repository management features
func (suite *EnterpriseIntegrationTestSuite) TestE002_RepositoryManagement() {
	// Create test repositories
	repos := suite.createTestRepositories()

	// Test repository creation and management
	for _, repo := range repos {
		assert.NotEmpty(suite.T(), repo.Name)
		assert.NotEmpty(suite.T(), repo.URL)
		assert.NotEmpty(suite.T(), repo.Language)
		assert.NotEmpty(suite.T(), repo.Platform)
	}

	// Test repository filtering
	javascriptRepos := make([]*repository.Repository, 0)
	for _, repo := range repos {
		if repo.Language == "javascript" {
			javascriptRepos = append(javascriptRepos, repo)
		}
	}
	assert.NotEmpty(suite.T(), javascriptRepos)
}

// TestE003_RepositoryFilter tests repository filtering capabilities
func (suite *EnterpriseIntegrationTestSuite) TestE003_RepositoryFilter() {
	// Test repository filter creation
	filter := &repository.RepositoryFilter{
		Languages:       []string{"javascript", "python"},
		IncludePrivate:  false,
		IncludeArchived: false,
		IncludeForks:    false,
		MinStars:        10,
		MaxSize:         1000000, // 1MB
		NamePattern:     "test-*",
		ExcludePatterns: []string{"*-backup", "*-old"},
	}

	// Verify filter configuration
	assert.Contains(suite.T(), filter.Languages, "javascript")
	assert.Contains(suite.T(), filter.Languages, "python")
	assert.False(suite.T(), filter.IncludePrivate)
	assert.False(suite.T(), filter.IncludeArchived)
	assert.False(suite.T(), filter.IncludeForks)
	assert.Equal(suite.T(), 10, filter.MinStars)
	assert.Equal(suite.T(), int64(1000000), filter.MaxSize)
	assert.Equal(suite.T(), "test-*", filter.NamePattern)
	assert.Contains(suite.T(), filter.ExcludePatterns, "*-backup")
	assert.Contains(suite.T(), filter.ExcludePatterns, "*-old")
}

// TestE004_ScanOptions tests scan configuration options
func (suite *EnterpriseIntegrationTestSuite) TestE004_ScanOptions() {
	// Test scan options creation
	options := &repository.ScanOptions{
		DeepScan:               true,
		IncludeDev:             true,
		Timeout:                time.Minute * 10,
		MaxFileSize:            1024 * 1024, // 1MB
		ExcludePatterns:        []string{"*.test.js", "*.spec.js"},
		LanguageOverride:       "javascript",
		CustomRules:            []string{"custom-rule-1", "custom-rule-2"},
		OutputFormats:          []string{"json", "sarif"},
		SimilarityThreshold:    0.8,
		ExcludePackages:        []string{"test-package", "dev-package"},
		CheckVulnerabilities:   true,
	}

	// Verify scan options
	assert.True(suite.T(), options.DeepScan)
	assert.True(suite.T(), options.IncludeDev)
	assert.Equal(suite.T(), time.Minute*10, options.Timeout)
	assert.Equal(suite.T(), int64(1024*1024), options.MaxFileSize)
	assert.Contains(suite.T(), options.ExcludePatterns, "*.test.js")
	assert.Equal(suite.T(), "javascript", options.LanguageOverride)
	assert.Contains(suite.T(), options.CustomRules, "custom-rule-1")
	assert.Contains(suite.T(), options.OutputFormats, "json")
	assert.Contains(suite.T(), options.OutputFormats, "sarif")
	assert.Equal(suite.T(), 0.8, options.SimilarityThreshold)
	assert.Contains(suite.T(), options.ExcludePackages, "test-package")
	assert.True(suite.T(), options.CheckVulnerabilities)
}

// TestE005_ScanRequest tests scan request creation
func (suite *EnterpriseIntegrationTestSuite) TestE005_ScanRequest() {
	// Create test repository
	repo := &repository.Repository{
		ID:       "test-repo-123",
		Name:     "test-repo",
		FullName: "test-org/test-repo",
		URL:      "https://github.com/test-org/test-repo",
		Language: "javascript",
		Platform: "github",
	}

	// Create scan request
	request := &repository.ScanRequest{
		Repository:  repo,
		Branch:      "main",
		CommitSHA:   "abc123def456",
		ScanID:      "scan-123",
		RequestedBy: "test-user",
		Priority:    1,
		Options: repository.ScanOptions{
			DeepScan:    true,
			IncludeDev:  false,
			Timeout:     time.Minute * 5,
			MaxFileSize: 512 * 1024, // 512KB
		},
		CreatedAt: time.Now(),
	}

	// Verify scan request
	assert.Equal(suite.T(), repo, request.Repository)
	assert.Equal(suite.T(), "main", request.Branch)
	assert.Equal(suite.T(), "abc123def456", request.CommitSHA)
	assert.Equal(suite.T(), "scan-123", request.ScanID)
	assert.Equal(suite.T(), "test-user", request.RequestedBy)
	assert.Equal(suite.T(), 1, request.Priority)
	assert.True(suite.T(), request.Options.DeepScan)
	assert.False(suite.T(), request.Options.IncludeDev)
	assert.Equal(suite.T(), time.Minute*5, request.Options.Timeout)
	assert.Equal(suite.T(), int64(512*1024), request.Options.MaxFileSize)
	assert.False(suite.T(), request.CreatedAt.IsZero())
}

// TestE006_AuthConfig tests authentication configuration
func (suite *EnterpriseIntegrationTestSuite) TestE006_AuthConfig() {
	// Test token-based authentication
	tokenAuth := &repository.AuthConfig{
		Type:     "token",
		Token:    "ghp_test_token_123",
		Metadata: map[string]string{"scope": "repo"},
	}

	assert.Equal(suite.T(), "token", tokenAuth.Type)
	assert.Equal(suite.T(), "ghp_test_token_123", tokenAuth.Token)
	assert.Equal(suite.T(), "repo", tokenAuth.Metadata["scope"])

	// Test OAuth authentication
	oauthAuth := &repository.AuthConfig{
		Type:         "oauth",
		ClientID:     "client-123",
		ClientSecret: "secret-456",
		Metadata:     map[string]string{"redirect_uri": "http://localhost:8080/callback"},
	}

	assert.Equal(suite.T(), "oauth", oauthAuth.Type)
	assert.Equal(suite.T(), "client-123", oauthAuth.ClientID)
	assert.Equal(suite.T(), "secret-456", oauthAuth.ClientSecret)
	assert.Equal(suite.T(), "http://localhost:8080/callback", oauthAuth.Metadata["redirect_uri"])

	// Test SSH authentication
	sshAuth := &repository.AuthConfig{
		Type:       "ssh",
		SSHKeyPath: "/home/user/.ssh/id_rsa",
		Username:   "git",
		Metadata:   map[string]string{"host": "github.com"},
	}

	assert.Equal(suite.T(), "ssh", sshAuth.Type)
	assert.Equal(suite.T(), "/home/user/.ssh/id_rsa", sshAuth.SSHKeyPath)
	assert.Equal(suite.T(), "git", sshAuth.Username)
	assert.Equal(suite.T(), "github.com", sshAuth.Metadata["host"])
}

// TestE007_PlatformConfig tests platform configuration
func (suite *EnterpriseIntegrationTestSuite) TestE007_PlatformConfig() {
	// Test GitHub platform configuration
	githubConfig := &repository.PlatformConfig{
		Name:       "github",
		BaseURL:    "https://api.github.com",
		APIVersion: "v3",
		Auth: repository.AuthConfig{
			Type:  "token",
			Token: "ghp_test_token",
		},
		RateLimit: repository.RateLimitConfig{
			RequestsPerHour:   5000,
			RequestsPerMinute: 100,
			BurstLimit:        10,
			BackoffStrategy:   "exponential",
			MaxRetries:        3,
		},
		Timeout:       time.Second * 30,
		Retries:       3,
		Organizations: []string{"test-org", "another-org"},
		Repositories:  []string{"test-repo-1", "test-repo-2"},
	}

	assert.Equal(suite.T(), "github", githubConfig.Name)
	assert.Equal(suite.T(), "https://api.github.com", githubConfig.BaseURL)
	assert.Equal(suite.T(), "v3", githubConfig.APIVersion)
	assert.Equal(suite.T(), "token", githubConfig.Auth.Type)
	assert.Equal(suite.T(), "ghp_test_token", githubConfig.Auth.Token)
	assert.Equal(suite.T(), 5000, githubConfig.RateLimit.RequestsPerHour)
	assert.Equal(suite.T(), 100, githubConfig.RateLimit.RequestsPerMinute)
	assert.Equal(suite.T(), 10, githubConfig.RateLimit.BurstLimit)
	assert.Equal(suite.T(), "exponential", githubConfig.RateLimit.BackoffStrategy)
	assert.Equal(suite.T(), 3, githubConfig.RateLimit.MaxRetries)
	assert.Equal(suite.T(), time.Second*30, githubConfig.Timeout)
	assert.Equal(suite.T(), 3, githubConfig.Retries)
	assert.Contains(suite.T(), githubConfig.Organizations, "test-org")
	assert.Contains(suite.T(), githubConfig.Repositories, "test-repo-1")
}

// TestE008_RepositoryManagerConfiguration tests repository manager configuration
func (suite *EnterpriseIntegrationTestSuite) TestE008_RepositoryManagerConfiguration() {
	// Test default configuration
	defaultConfig := repository.DefaultManagerConfig()
	assert.Equal(suite.T(), 10, defaultConfig.MaxConcurrentScans)
	assert.Equal(suite.T(), 30*time.Minute, defaultConfig.ScanTimeout)
	assert.Equal(suite.T(), 3, defaultConfig.RetryAttempts)
	assert.Equal(suite.T(), 5*time.Second, defaultConfig.RetryDelay)
	assert.True(suite.T(), defaultConfig.EnableMetrics)
	assert.NotNil(suite.T(), defaultConfig.DefaultFilters)
	assert.False(suite.T(), defaultConfig.DefaultFilters.IncludeArchived)
	assert.False(suite.T(), defaultConfig.DefaultFilters.IncludeForks)
	assert.Equal(suite.T(), 0, defaultConfig.DefaultFilters.MinStars)

	// Test custom configuration
	customConfig := &repository.ManagerConfig{
		MaxConcurrentScans: 20,
		ScanTimeout:        time.Hour,
		RetryAttempts:      5,
		RetryDelay:         time.Second * 10,
		EnableMetrics:      false,
		DefaultFilters: &repository.RepositoryFilter{
			IncludeArchived: true,
			IncludeForks:    true,
			MinStars:        100,
			Languages:       []string{"go", "python"},
		},
	}

	assert.Equal(suite.T(), 20, customConfig.MaxConcurrentScans)
	assert.Equal(suite.T(), time.Hour, customConfig.ScanTimeout)
	assert.Equal(suite.T(), 5, customConfig.RetryAttempts)
	assert.Equal(suite.T(), time.Second*10, customConfig.RetryDelay)
	assert.False(suite.T(), customConfig.EnableMetrics)
	assert.True(suite.T(), customConfig.DefaultFilters.IncludeArchived)
	assert.True(suite.T(), customConfig.DefaultFilters.IncludeForks)
	assert.Equal(suite.T(), 100, customConfig.DefaultFilters.MinStars)
	assert.Contains(suite.T(), customConfig.DefaultFilters.Languages, "go")
	assert.Contains(suite.T(), customConfig.DefaultFilters.Languages, "python")
}

// Helper methods

func (suite *EnterpriseIntegrationTestSuite) createTestConfig() *TestConfig {
	return &TestConfig{
		Auth: auth.AuthConfig{
			DefaultProvider: "mock",
			Providers: map[string]auth.ProviderConfig{
				"mock": {
					Type:    "mock",
					Enabled: true,
					Settings: map[string]interface{}{
						"users": []map[string]interface{}{
							{
								"email":    "admin@company.com",
								"password": "password123",
								"roles":    []string{"administrator"},
							},
							{
								"email":    "analyst@company.com",
								"password": "password123",
								"roles":    []string{"security_analyst"},
							},
						},
					},
				},
			},
			Session: auth.SessionConfig{
				Timeout:        time.Hour,
				RefreshTimeout: time.Minute * 30,
			},
		},
	}
}

func (suite *EnterpriseIntegrationTestSuite) createTestRepositories() []*repository.Repository {
	return []*repository.Repository{
		{
			Name:     "test-repo-1",
			URL:      "https://github.com/test-org/test-repo-1",
			Language: "javascript",
			Platform: "github",
		},
		{
			Name:     "test-repo-2",
			URL:      "https://github.com/test-org/test-repo-2",
			Language: "python",
			Platform: "github",
		},
		{
			Name:     "test-repo-3",
			URL:      "https://gitlab.com/test-group/test-repo-3",
			Language: "go",
			Platform: "gitlab",
		},
	}
}

// Mock server handlers

func (suite *EnterpriseIntegrationTestSuite) handleRepoRequest(w http.ResponseWriter, r *http.Request) {
	repos := []map[string]interface{}{
		{
			"name":     "test-repo-1",
			"full_name": "test-org/test-repo-1",
			"html_url": "https://github.com/test-org/test-repo-1",
			"language": "JavaScript",
			"fork":     false,
		},
		{
			"name":     "test-repo-2",
			"full_name": "test-org/test-repo-2",
			"html_url": "https://github.com/test-org/test-repo-2",
			"language": "Python",
			"fork":     false,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(repos)
}

func (suite *EnterpriseIntegrationTestSuite) handleOrgRequest(w http.ResponseWriter, r *http.Request) {
	org := map[string]interface{}{
		"login": "test-org",
		"name":  "Test Organization",
		"type":  "Organization",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(org)
}

func (suite *EnterpriseIntegrationTestSuite) handleUserRequest(w http.ResponseWriter, r *http.Request) {
	user := map[string]interface{}{
		"login": "test-user",
		"name":  "Test User",
		"email": "test@company.com",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

func (suite *EnterpriseIntegrationTestSuite) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"token": "mock-jwt-token",
		"user": map[string]interface{}{
			"email": "admin@company.com",
			"roles": []string{"administrator"},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (suite *EnterpriseIntegrationTestSuite) handleAuthValidate(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"valid": true,
		"user": map[string]interface{}{
			"email": "admin@company.com",
			"roles": []string{"administrator"},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (suite *EnterpriseIntegrationTestSuite) handleAuthRoles(w http.ResponseWriter, r *http.Request) {
	roles := []map[string]interface{}{
		{
			"name":        "administrator",
			"permissions": []string{"*"},
		},
		{
			"name":        "security_analyst",
			"permissions": []string{"scan:execute", "report:view"},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(roles)
}

// TestConfig struct for test configuration
type TestConfig struct {
	Auth auth.AuthConfig
}

// TestEnterpriseIntegration runs the enterprise integration test suite
func TestEnterpriseIntegration(t *testing.T) {
	suite.Run(t, new(EnterpriseIntegrationTestSuite))
}