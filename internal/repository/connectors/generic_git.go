package connectors

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/repository"
)

// GenericGitConnector implements the Connector interface for generic Git repositories
type GenericGitConnector struct {
	client         *http.Client
	baseURL        string
	apiToken       string
	userAgent      string
	config         repository.PlatformConfig
	retryConfig    *GenericRetryConfig
	webhookManager *GenericWebhookManager
	workDir        string
}

// GenericRetryConfig defines retry behavior for generic Git operations
type GenericRetryConfig struct {
	MaxRetries    int
	InitialDelay  time.Duration
	MaxDelay      time.Duration
	BackoffFactor float64
}

// GenericWebhookManager manages webhooks for generic Git repositories
type GenericWebhookManager struct {
	connector *GenericGitConnector
	webhooks  map[string]*repository.Webhook
	mu        sync.RWMutex
}

// NewGenericGitConnector creates a new generic Git connector
func NewGenericGitConnector(config repository.PlatformConfig) (*GenericGitConnector, error) {
	baseURL := config.BaseURL
	if baseURL == "" {
		return nil, fmt.Errorf("base URL is required for generic Git connector")
	}

	// Create temporary work directory
	workDir, err := os.MkdirTemp("", "typosentinel-git-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create work directory: %w", err)
	}

	connector := &GenericGitConnector{
		client:    &http.Client{Timeout: config.Timeout},
		baseURL:   baseURL,
		apiToken:  config.Auth.Token,
		userAgent: "TypoSentinel/1.0",
		config:    config,
		workDir:   workDir,
		retryConfig: &GenericRetryConfig{
			MaxRetries:    3,
			InitialDelay:  time.Second,
			MaxDelay:      30 * time.Second,
			BackoffFactor: 2.0,
		},
		webhookManager: &GenericWebhookManager{
			webhooks: make(map[string]*repository.Webhook),
		},
	}

	// Set connector reference in webhook manager
	connector.webhookManager.connector = connector

	return connector, nil
}

// GetPlatformName returns the platform name
func (g *GenericGitConnector) GetPlatformName() string {
	return "Generic Git"
}

// GetPlatformType returns the platform type
func (g *GenericGitConnector) GetPlatformType() string {
	return "git"
}

// GetAPIVersion returns the API version
func (g *GenericGitConnector) GetAPIVersion() string {
	return "git"
}

// Authenticate validates the connection to the Git repository
func (g *GenericGitConnector) Authenticate(ctx context.Context, config repository.AuthConfig) error {
	// For generic Git, we'll try to clone or fetch from the repository
	return g.ValidateAuth(ctx)
}

// ValidateAuth validates the authentication
func (g *GenericGitConnector) ValidateAuth(ctx context.Context) error {
	// Try to perform a basic Git operation to validate access
	cmd := exec.CommandContext(ctx, "git", "ls-remote", "--heads", g.baseURL)
	if g.apiToken != "" {
		// Set up authentication for HTTPS URLs
		if strings.HasPrefix(g.baseURL, "https://") {
			authURL := strings.Replace(g.baseURL, "https://", fmt.Sprintf("https://%s@", g.apiToken), 1)
			cmd = exec.CommandContext(ctx, "git", "ls-remote", "--heads", authURL)
		}
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to validate Git repository access: %w, output: %s", err, string(output))
	}

	return nil
}

// RefreshAuth refreshes the authentication (no-op for generic Git)
func (g *GenericGitConnector) RefreshAuth(ctx context.Context) error {
	return nil
}

// ListOrganizations returns empty list (not applicable for generic Git)
func (g *GenericGitConnector) ListOrganizations(ctx context.Context) ([]*repository.Organization, error) {
	return []*repository.Organization{}, nil
}

// GetOrganization returns a mock organization
func (g *GenericGitConnector) GetOrganization(ctx context.Context, name string) (*repository.Organization, error) {
	return &repository.Organization{
		ID:          name,
		Login:       name,
		Name:        name,
		Description: "Generic Git Repository",
		Type:        "generic",
		Platform:    "git",
	}, nil
}

// ListRepositories lists repositories (returns single repository for generic Git)
func (g *GenericGitConnector) ListRepositories(ctx context.Context, owner string, filter *repository.RepositoryFilter) ([]*repository.Repository, error) {
	repo, err := g.getRepositoryInfo(ctx, owner, "")
	if err != nil {
		return nil, err
	}

	if filter != nil && !g.matchesFilter(repo, filter) {
		return []*repository.Repository{}, nil
	}

	return []*repository.Repository{repo}, nil
}

// ListOrgRepositories lists organization repositories
func (g *GenericGitConnector) ListOrgRepositories(ctx context.Context, org string, filter *repository.RepositoryFilter) ([]*repository.Repository, error) {
	return g.ListRepositories(ctx, org, filter)
}

// GetRepository gets a specific repository
func (g *GenericGitConnector) GetRepository(ctx context.Context, owner, name string) (*repository.Repository, error) {
	return g.getRepositoryInfo(ctx, owner, name)
}

// SearchRepositories searches repositories (returns single repository for generic Git)
func (g *GenericGitConnector) SearchRepositories(ctx context.Context, query string, filter *repository.RepositoryFilter) ([]*repository.Repository, error) {
	return g.ListRepositories(ctx, "", filter)
}

// getRepositoryInfo extracts repository information from Git
func (g *GenericGitConnector) getRepositoryInfo(ctx context.Context, owner, name string) (*repository.Repository, error) {
	// Clone repository to temporary directory
	repoDir := filepath.Join(g.workDir, "repo")
	cloneURL := g.baseURL

	// Add authentication if available
	if g.apiToken != "" && strings.HasPrefix(g.baseURL, "https://") {
		cloneURL = strings.Replace(g.baseURL, "https://", fmt.Sprintf("https://%s@", g.apiToken), 1)
	}

	// Clone repository
	cmd := exec.CommandContext(ctx, "git", "clone", "--depth", "1", cloneURL, repoDir)
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to clone repository: %w", err)
	}

	// Extract repository information
	repoName := name
	if repoName == "" {
		// Extract name from URL
		parts := strings.Split(strings.TrimSuffix(g.baseURL, ".git"), "/")
		if len(parts) > 0 {
			repoName = parts[len(parts)-1]
		}
	}

	fullName := fmt.Sprintf("%s/%s", owner, repoName)
	if owner == "" {
		fullName = repoName
	}

	// Get default branch
	defaultBranch := "main"
	cmd = exec.CommandContext(ctx, "git", "-C", repoDir, "symbolic-ref", "refs/remotes/origin/HEAD")
	if output, err := cmd.Output(); err == nil {
		branch := strings.TrimSpace(string(output))
		if parts := strings.Split(branch, "/"); len(parts) > 0 {
			defaultBranch = parts[len(parts)-1]
		}
	}

	// Get repository size (approximate)
	var size int64
	if info, err := os.Stat(repoDir); err == nil {
		size = info.Size()
	}

	return &repository.Repository{
		ID:            fmt.Sprintf("git-%s", repoName),
		Name:          repoName,
		FullName:      fullName,
		URL:           g.baseURL,
		CloneURL:      g.baseURL,
		SSHURL:        g.baseURL,
		DefaultBranch: defaultBranch,
		Language:      "",    // Would need language detection
		Private:       false, // Cannot determine without API
		Archived:      false,
		Fork:          false,
		Size:          size,
		StarCount:     0,
		ForkCount:     0,
		Topics:        []string{},
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
		PushedAt:      time.Now(),
		Platform:      "git",
		Owner: repository.Owner{
			ID:    owner,
			Login: owner,
			Name:  owner,
			Type:  "user",
		},
		Metadata: map[string]interface{}{
			"clone_url": g.baseURL,
			"work_dir":  repoDir,
		},
	}, nil
}

// GetRepositoryContent gets file content from repository
func (g *GenericGitConnector) GetRepositoryContent(ctx context.Context, repo *repository.Repository, path string, ref string) ([]byte, error) {
	repoDir, ok := repo.Metadata["work_dir"].(string)
	if !ok {
		return nil, fmt.Errorf("repository not cloned")
	}

	filePath := filepath.Join(repoDir, path)
	return os.ReadFile(filePath)
}

// ListRepositoryFiles lists files in repository
func (g *GenericGitConnector) ListRepositoryFiles(ctx context.Context, repo *repository.Repository, path string, ref string) ([]string, error) {
	repoDir, ok := repo.Metadata["work_dir"].(string)
	if !ok {
		return nil, fmt.Errorf("repository not cloned")
	}

	searchPath := filepath.Join(repoDir, path)
	var files []string

	err := filepath.Walk(searchPath, func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			relPath, _ := filepath.Rel(repoDir, filePath)
			files = append(files, relPath)
		}
		return nil
	})

	return files, err
}

// GetPackageFiles gets package files from repository
func (g *GenericGitConnector) GetPackageFiles(ctx context.Context, repo *repository.Repository, ref string) (map[string][]byte, error) {
	repoDir, ok := repo.Metadata["work_dir"].(string)
	if !ok {
		return nil, fmt.Errorf("repository not cloned")
	}

	packageFiles := make(map[string][]byte)
	packageFileNames := []string{
		"package.json", "package-lock.json", "yarn.lock",
		"requirements.txt", "Pipfile", "Pipfile.lock", "pyproject.toml",
		"go.mod", "go.sum",
		"Gemfile", "Gemfile.lock",
		"composer.json", "composer.lock",
		"pom.xml", "build.gradle", "build.gradle.kts",
		"Cargo.toml", "Cargo.lock",
	}

	for _, fileName := range packageFileNames {
		filePath := filepath.Join(repoDir, fileName)
		if content, err := os.ReadFile(filePath); err == nil {
			packageFiles[fileName] = content
		}
	}

	return packageFiles, nil
}

// GetRepositoryLanguages gets repository languages (basic detection)
func (g *GenericGitConnector) GetRepositoryLanguages(ctx context.Context, repo *repository.Repository) (map[string]int, error) {
	// Basic language detection based on file extensions
	languages := make(map[string]int)
	languageMap := map[string]string{
		".js":   "JavaScript",
		".ts":   "TypeScript",
		".py":   "Python",
		".go":   "Go",
		".java": "Java",
		".rb":   "Ruby",
		".php":  "PHP",
		".cpp":  "C++",
		".c":    "C",
		".cs":   "C#",
		".rs":   "Rust",
	}

	files, err := g.ListRepositoryFiles(ctx, repo, "", "")
	if err != nil {
		return languages, err
	}

	for _, file := range files {
		ext := filepath.Ext(file)
		if lang, ok := languageMap[ext]; ok {
			languages[lang]++
		}
	}

	return languages, nil
}

// GetRepositoryTopics returns empty topics (not available for generic Git)
func (g *GenericGitConnector) GetRepositoryTopics(ctx context.Context, repo *repository.Repository) ([]string, error) {
	return []string{}, nil
}

// GetRepositoryCommits gets repository commits
func (g *GenericGitConnector) GetRepositoryCommits(ctx context.Context, repo *repository.Repository, branch string, limit int) ([]repository.Commit, error) {
	repoDir, ok := repo.Metadata["work_dir"].(string)
	if !ok {
		return nil, fmt.Errorf("repository not cloned")
	}

	args := []string{"-C", repoDir, "log", "--oneline", fmt.Sprintf("-%d", limit)}
	if branch != "" {
		args = append(args, branch)
	}

	cmd := exec.CommandContext(ctx, "git", args...)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get commits: %w", err)
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	commits := make([]repository.Commit, 0, len(lines))

	for _, line := range lines {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, " ", 2)
		if len(parts) >= 2 {
			commits = append(commits, repository.Commit{
				SHA:     parts[0],
				Message: parts[1],
				Author:  "Unknown",
				Email:   "unknown@example.com",
				Date:    time.Now(),
				URL:     "",
			})
		}
	}

	return commits, nil
}

// GetRepositoryBranches gets repository branches
func (g *GenericGitConnector) GetRepositoryBranches(ctx context.Context, repo *repository.Repository) ([]string, error) {
	repoDir, ok := repo.Metadata["work_dir"].(string)
	if !ok {
		return nil, fmt.Errorf("repository not cloned")
	}

	cmd := exec.CommandContext(ctx, "git", "-C", repoDir, "branch", "-r")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get branches: %w", err)
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	var branches []string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.Contains(line, "HEAD") {
			continue
		}
		// Remove "origin/" prefix
		branchName := strings.TrimPrefix(line, "origin/")
		branches = append(branches, branchName)
	}

	return branches, nil
}

// CreateWebhook creates a webhook (not supported for generic Git)
func (g *GenericGitConnector) CreateWebhook(ctx context.Context, repo *repository.Repository, webhookURL string, events []string) error {
	return fmt.Errorf("webhooks not supported for generic Git repositories")
}

// DeleteWebhook deletes a webhook (not supported for generic Git)
func (g *GenericGitConnector) DeleteWebhook(ctx context.Context, repo *repository.Repository, webhookID string) error {
	return fmt.Errorf("webhooks not supported for generic Git repositories")
}

// ListWebhooks lists webhooks (not supported for generic Git)
func (g *GenericGitConnector) ListWebhooks(ctx context.Context, repo *repository.Repository) ([]repository.Webhook, error) {
	return []repository.Webhook{}, nil
}

// GetRateLimit returns rate limit information (not applicable for generic Git)
func (g *GenericGitConnector) GetRateLimit(ctx context.Context) (*repository.RateLimit, error) {
	return &repository.RateLimit{
		Limit:     1000,
		Remaining: 1000,
		ResetTime: time.Now().Add(time.Hour),
		Used:      0,
	}, nil
}

// HealthCheck performs a health check
func (g *GenericGitConnector) HealthCheck(ctx context.Context) error {
	return g.ValidateAuth(ctx)
}

// Close cleans up resources
func (g *GenericGitConnector) Close() error {
	if g.workDir != "" {
		return os.RemoveAll(g.workDir)
	}
	return nil
}

// matchesFilter checks if repository matches the filter
func (g *GenericGitConnector) matchesFilter(repo *repository.Repository, filter *repository.RepositoryFilter) bool {
	if filter == nil {
		return true
	}

	// Check private repositories
	if !filter.IncludePrivate && repo.Private {
		return false
	}

	// Check archived repositories
	if !filter.IncludeArchived && repo.Archived {
		return false
	}

	// Check forks
	if !filter.IncludeForks && repo.Fork {
		return false
	}

	// Check minimum stars
	if filter.MinStars > 0 && repo.StarCount < filter.MinStars {
		return false
	}

	// Check maximum size
	if filter.MaxSize > 0 && repo.Size > filter.MaxSize {
		return false
	}

	// Check languages
	if len(filter.Languages) > 0 && repo.Language != "" {
		found := false
		for _, lang := range filter.Languages {
			if strings.EqualFold(repo.Language, lang) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check updated after
	if filter.UpdatedAfter != nil && repo.UpdatedAt.Before(*filter.UpdatedAfter) {
		return false
	}

	// Check updated before
	if filter.UpdatedBefore != nil && repo.UpdatedAt.After(*filter.UpdatedBefore) {
		return false
	}

	// Check name pattern
	if filter.NamePattern != "" {
		if !strings.Contains(strings.ToLower(repo.Name), strings.ToLower(filter.NamePattern)) {
			return false
		}
	}

	// Check exclude patterns
	for _, pattern := range filter.ExcludePatterns {
		if strings.Contains(strings.ToLower(repo.Name), strings.ToLower(pattern)) {
			return false
		}
	}

	return true
}
