package connectors

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/repository"
)

// GitHubConnector implements the Connector interface for GitHub
type GitHubConnector struct {
	client    *http.Client
	baseURL   string
	apiToken  string
	userAgent string
	rateLimit *repository.RateLimit
	config    repository.PlatformConfig
}

// GitHub API response structures
type githubRepository struct {
	ID            int64       `json:"id"`
	Name          string      `json:"name"`
	FullName      string      `json:"full_name"`
	HTMLURL       string      `json:"html_url"`
	CloneURL      string      `json:"clone_url"`
	SSHURL        string      `json:"ssh_url"`
	GitURL        string      `json:"git_url"`
	SVNURL        string      `json:"svn_url"`
	Description   *string     `json:"description"`
	Homepage      *string     `json:"homepage"`
	Language      *string     `json:"language"`
	Private       bool        `json:"private"`
	Fork          bool        `json:"fork"`
	Archived      bool        `json:"archived"`
	Disabled      bool        `json:"disabled"`
	Size          int64       `json:"size"`
	Stargazers    int         `json:"stargazers_count"`
	Watchers      int         `json:"watchers_count"`
	Forks         int         `json:"forks_count"`
	OpenIssues    int         `json:"open_issues_count"`
	Topics        []string    `json:"topics"`
	CreatedAt     time.Time   `json:"created_at"`
	UpdatedAt     time.Time   `json:"updated_at"`
	PushedAt      time.Time   `json:"pushed_at"`
	Owner         githubOwner `json:"owner"`
	DefaultBranch string      `json:"default_branch"`
}

type githubOwner struct {
	ID        int64  `json:"id"`
	Login     string `json:"login"`
	Type      string `json:"type"`
	AvatarURL string `json:"avatar_url"`
	HTMLURL   string `json:"html_url"`
}

type githubOrganization struct {
	ID          int64     `json:"id"`
	Login       string    `json:"login"`
	Name        *string   `json:"name"`
	Description *string   `json:"description"`
	HTMLURL     string    `json:"html_url"`
	AvatarURL   string    `json:"avatar_url"`
	Type        string    `json:"type"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type githubContent struct {
	Name        string `json:"name"`
	Path        string `json:"path"`
	SHA         string `json:"sha"`
	Size        int64  `json:"size"`
	Type        string `json:"type"`
	Content     string `json:"content"`
	Encoding    string `json:"encoding"`
	DownloadURL string `json:"download_url"`
}

type githubCommit struct {
	SHA    string `json:"sha"`
	Commit struct {
		Message string `json:"message"`
		Author  struct {
			Name  string    `json:"name"`
			Email string    `json:"email"`
			Date  time.Time `json:"date"`
		} `json:"author"`
	} `json:"commit"`
	HTMLURL string `json:"html_url"`
}

type githubRateLimit struct {
	Resources struct {
		Core struct {
			Limit     int   `json:"limit"`
			Remaining int   `json:"remaining"`
			Reset     int64 `json:"reset"`
			Used      int   `json:"used"`
		} `json:"core"`
		Search struct {
			Limit     int   `json:"limit"`
			Remaining int   `json:"remaining"`
			Reset     int64 `json:"reset"`
			Used      int   `json:"used"`
		} `json:"search"`
	} `json:"resources"`
}

// NewGitHubConnector creates a new GitHub connector
func NewGitHubConnector(config repository.PlatformConfig) (*GitHubConnector, error) {
	if config.BaseURL == "" {
		config.BaseURL = "https://api.github.com"
	}

	client := &http.Client{
		Timeout: config.Timeout,
	}

	return &GitHubConnector{
		client:    client,
		baseURL:   config.BaseURL,
		apiToken:  config.Auth.Token,
		userAgent: "TypoSentinel/2.0",
		config:    config,
	}, nil
}

// GetPlatformName returns the platform name
func (g *GitHubConnector) GetPlatformName() string {
	return "github"
}

// GetPlatformType returns the platform type
func (g *GitHubConnector) GetPlatformType() string {
	return "git"
}

// GetAPIVersion returns the API version
func (g *GitHubConnector) GetAPIVersion() string {
	return "v3"
}

// Authenticate validates the authentication
func (g *GitHubConnector) Authenticate(ctx context.Context, config repository.AuthConfig) error {
	g.apiToken = config.Token
	return g.ValidateAuth(ctx)
}

// ValidateAuth validates the current authentication
func (g *GitHubConnector) ValidateAuth(ctx context.Context) error {
	req, err := g.createRequest(ctx, "GET", "/user", nil)
	if err != nil {
		return fmt.Errorf("failed to create auth validation request: %w", err)
	}

	resp, err := g.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to validate auth: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("authentication failed: %s", resp.Status)
	}

	return nil
}

// RefreshAuth refreshes the authentication (not applicable for token auth)
func (g *GitHubConnector) RefreshAuth(ctx context.Context) error {
	return nil // Token auth doesn't need refresh
}

// ListOrganizations lists all organizations for the authenticated user
func (g *GitHubConnector) ListOrganizations(ctx context.Context) ([]*repository.Organization, error) {
	var allOrgs []*repository.Organization
	page := 1
	perPage := 100

	for {
		url := fmt.Sprintf("/user/orgs?page=%d&per_page=%d", page, perPage)
		req, err := g.createRequest(ctx, "GET", url, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}

		resp, err := g.client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("failed to list organizations: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("failed to list organizations: %s", resp.Status)
		}

		var githubOrgs []githubOrganization
		if err := json.NewDecoder(resp.Body).Decode(&githubOrgs); err != nil {
			return nil, fmt.Errorf("failed to decode organizations: %w", err)
		}

		if len(githubOrgs) == 0 {
			break
		}

		for _, org := range githubOrgs {
			allOrgs = append(allOrgs, g.convertOrganization(&org))
		}

		if len(githubOrgs) < perPage {
			break
		}
		page++
	}

	return allOrgs, nil
}

// GetOrganization gets a specific organization
func (g *GitHubConnector) GetOrganization(ctx context.Context, name string) (*repository.Organization, error) {
	url := fmt.Sprintf("/orgs/%s", name)
	req, err := g.createRequest(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := g.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get organization: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get organization: %s", resp.Status)
	}

	var githubOrg githubOrganization
	if err := json.NewDecoder(resp.Body).Decode(&githubOrg); err != nil {
		return nil, fmt.Errorf("failed to decode organization: %w", err)
	}

	return g.convertOrganization(&githubOrg), nil
}

// ListRepositories lists repositories for a user
func (g *GitHubConnector) ListRepositories(ctx context.Context, owner string, filter *repository.RepositoryFilter) ([]*repository.Repository, error) {
	return g.listRepositoriesWithURL(ctx, fmt.Sprintf("/users/%s/repos", owner), filter)
}

// ListOrgRepositories lists repositories for an organization
func (g *GitHubConnector) ListOrgRepositories(ctx context.Context, org string, filter *repository.RepositoryFilter) ([]*repository.Repository, error) {
	return g.listRepositoriesWithURL(ctx, fmt.Sprintf("/orgs/%s/repos", org), filter)
}

// GetRepository gets a specific repository
func (g *GitHubConnector) GetRepository(ctx context.Context, owner, name string) (*repository.Repository, error) {
	url := fmt.Sprintf("/repos/%s/%s", owner, name)
	req, err := g.createRequest(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := g.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get repository: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get repository: %s", resp.Status)
	}

	var githubRepo githubRepository
	if err := json.NewDecoder(resp.Body).Decode(&githubRepo); err != nil {
		return nil, fmt.Errorf("failed to decode repository: %w", err)
	}

	return g.convertRepository(&githubRepo), nil
}

// SearchRepositories searches for repositories
func (g *GitHubConnector) SearchRepositories(ctx context.Context, query string, filter *repository.RepositoryFilter) ([]*repository.Repository, error) {
	searchQuery := g.buildSearchQuery(query, filter)
	url := fmt.Sprintf("/search/repositories?q=%s", url.QueryEscape(searchQuery))

	req, err := g.createRequest(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := g.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to search repositories: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to search repositories: %s", resp.Status)
	}

	var searchResult struct {
		Items []githubRepository `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&searchResult); err != nil {
		return nil, fmt.Errorf("failed to decode search results: %w", err)
	}

	var repos []*repository.Repository
	for _, item := range searchResult.Items {
		repos = append(repos, g.convertRepository(&item))
	}

	return repos, nil
}

// GetRepositoryContent gets file content from a repository
func (g *GitHubConnector) GetRepositoryContent(ctx context.Context, repo *repository.Repository, filePath string, ref string) ([]byte, error) {
	owner, name := g.parseFullName(repo.FullName)
	url := fmt.Sprintf("/repos/%s/%s/contents/%s", owner, name, filePath)
	if ref != "" {
		url += "?ref=" + ref
	}

	req, err := g.createRequest(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := g.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get repository content: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get repository content: %s", resp.Status)
	}

	var content githubContent
	if err := json.NewDecoder(resp.Body).Decode(&content); err != nil {
		return nil, fmt.Errorf("failed to decode content: %w", err)
	}

	if content.Encoding == "base64" {
		return g.decodeBase64Content(content.Content)
	}

	return []byte(content.Content), nil
}

// ListRepositoryFiles lists files in a repository directory
func (g *GitHubConnector) ListRepositoryFiles(ctx context.Context, repo *repository.Repository, dirPath string, ref string) ([]string, error) {
	owner, name := g.parseFullName(repo.FullName)
	url := fmt.Sprintf("/repos/%s/%s/contents/%s", owner, name, dirPath)
	if ref != "" {
		url += "?ref=" + ref
	}

	req, err := g.createRequest(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := g.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to list repository files: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to list repository files: %s", resp.Status)
	}

	var contents []githubContent
	if err := json.NewDecoder(resp.Body).Decode(&contents); err != nil {
		return nil, fmt.Errorf("failed to decode contents: %w", err)
	}

	var files []string
	for _, content := range contents {
		files = append(files, content.Path)
	}

	return files, nil
}

// GetPackageFiles gets package manager files from a repository
func (g *GitHubConnector) GetPackageFiles(ctx context.Context, repo *repository.Repository, ref string) (map[string][]byte, error) {
	packageFiles := map[string][]byte{}
	packageFileNames := []string{
		"package.json", "package-lock.json", "yarn.lock",
		"requirements.txt", "Pipfile", "Pipfile.lock", "pyproject.toml",
		"go.mod", "go.sum",
		"pom.xml", "build.gradle", "build.gradle.kts",
		"Gemfile", "Gemfile.lock",
		"composer.json", "composer.lock",
		"Cargo.toml", "Cargo.lock",
		"*.csproj", "packages.config", "project.json",
	}

	for _, fileName := range packageFileNames {
		content, err := g.GetRepositoryContent(ctx, repo, fileName, ref)
		if err == nil {
			packageFiles[fileName] = content
		}
	}

	return packageFiles, nil
}

// GetRepositoryLanguages gets repository languages
func (g *GitHubConnector) GetRepositoryLanguages(ctx context.Context, repo *repository.Repository) (map[string]int, error) {
	owner, name := g.parseFullName(repo.FullName)
	url := fmt.Sprintf("/repos/%s/%s/languages", owner, name)

	req, err := g.createRequest(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := g.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get repository languages: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get repository languages: %s", resp.Status)
	}

	var languages map[string]int
	if err := json.NewDecoder(resp.Body).Decode(&languages); err != nil {
		return nil, fmt.Errorf("failed to decode languages: %w", err)
	}

	return languages, nil
}

// GetRepositoryTopics gets repository topics
func (g *GitHubConnector) GetRepositoryTopics(ctx context.Context, repo *repository.Repository) ([]string, error) {
	owner, name := g.parseFullName(repo.FullName)
	url := fmt.Sprintf("/repos/%s/%s/topics", owner, name)

	req, err := g.createRequest(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/vnd.github.mercy-preview+json")

	resp, err := g.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get repository topics: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get repository topics: %s", resp.Status)
	}

	var topicsResponse struct {
		Names []string `json:"names"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&topicsResponse); err != nil {
		return nil, fmt.Errorf("failed to decode topics: %w", err)
	}

	return topicsResponse.Names, nil
}

// GetRepositoryBranches gets repository branches
func (g *GitHubConnector) GetRepositoryBranches(ctx context.Context, repo *repository.Repository) ([]string, error) {
	owner, name := g.parseFullName(repo.FullName)
	url := fmt.Sprintf("/repos/%s/%s/branches", owner, name)

	req, err := g.createRequest(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := g.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get repository branches: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get repository branches: %s", resp.Status)
	}

	var branches []struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&branches); err != nil {
		return nil, fmt.Errorf("failed to decode branches: %w", err)
	}

	var branchNames []string
	for _, branch := range branches {
		branchNames = append(branchNames, branch.Name)
	}

	return branchNames, nil
}

// GetRepositoryCommits gets repository commits
func (g *GitHubConnector) GetRepositoryCommits(ctx context.Context, repo *repository.Repository, branch string, limit int) ([]repository.Commit, error) {
	owner, name := g.parseFullName(repo.FullName)
	url := fmt.Sprintf("/repos/%s/%s/commits?per_page=%d", owner, name, limit)
	if branch != "" {
		url += "&sha=" + branch
	}

	req, err := g.createRequest(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := g.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get repository commits: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get repository commits: %s", resp.Status)
	}

	var githubCommits []githubCommit
	if err := json.NewDecoder(resp.Body).Decode(&githubCommits); err != nil {
		return nil, fmt.Errorf("failed to decode commits: %w", err)
	}

	var commits []repository.Commit
	for _, gc := range githubCommits {
		commits = append(commits, repository.Commit{
			SHA:     gc.SHA,
			Message: gc.Commit.Message,
			Author:  gc.Commit.Author.Name,
			Email:   gc.Commit.Author.Email,
			Date:    gc.Commit.Author.Date,
			URL:     gc.HTMLURL,
		})
	}

	return commits, nil
}

// CreateWebhook creates a webhook for the repository
func (g *GitHubConnector) CreateWebhook(ctx context.Context, repo *repository.Repository, webhookURL string, events []string) error {
	if repo == nil {
		return fmt.Errorf("repository cannot be nil")
	}
	if webhookURL == "" {
		return fmt.Errorf("webhook URL cannot be empty")
	}
	if len(events) == 0 {
		events = []string{"push", "pull_request", "release"}
	}

	owner, name := g.parseFullName(repo.FullName)
	if owner == "" || name == "" {
		return fmt.Errorf("invalid repository full name: %s", repo.FullName)
	}

	// Prepare webhook payload
	webhookConfig := map[string]interface{}{
		"url":          webhookURL,
		"content_type": "json",
		"insecure_ssl": "0",
	}

	payload := map[string]interface{}{
		"name":   "web",
		"active": true,
		"events": events,
		"config": webhookConfig,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal webhook payload: %w", err)
	}

	endpoint := fmt.Sprintf("/repos/%s/%s/hooks", owner, name)
	req, err := g.createRequest(ctx, "POST", endpoint, bytes.NewReader(payloadBytes))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := g.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to create webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("failed to create webhook: %s", resp.Status)
	}

	return nil
}

// DeleteWebhook deletes a webhook
func (g *GitHubConnector) DeleteWebhook(ctx context.Context, repo *repository.Repository, webhookID string) error {
	if repo == nil {
		return fmt.Errorf("repository cannot be nil")
	}
	if webhookID == "" {
		return fmt.Errorf("webhook ID cannot be empty")
	}

	owner, name := g.parseFullName(repo.FullName)
	if owner == "" || name == "" {
		return fmt.Errorf("invalid repository full name: %s", repo.FullName)
	}

	endpoint := fmt.Sprintf("/repos/%s/%s/hooks/%s", owner, name, webhookID)
	req, err := g.createRequest(ctx, "DELETE", endpoint, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := g.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to delete webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("failed to delete webhook: %s", resp.Status)
	}

	return nil
}

// ListWebhooks lists repository webhooks
func (g *GitHubConnector) ListWebhooks(ctx context.Context, repo *repository.Repository) ([]repository.Webhook, error) {
	if repo == nil {
		return nil, fmt.Errorf("repository cannot be nil")
	}

	owner, name := g.parseFullName(repo.FullName)
	if owner == "" || name == "" {
		return nil, fmt.Errorf("invalid repository full name: %s", repo.FullName)
	}

	endpoint := fmt.Sprintf("/repos/%s/%s/hooks", owner, name)
	req, err := g.createRequest(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := g.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to list webhooks: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to list webhooks: %s", resp.Status)
	}

	var githubHooks []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&githubHooks); err != nil {
		return nil, fmt.Errorf("failed to parse webhook response: %w", err)
	}

	webhooks := make([]repository.Webhook, 0, len(githubHooks))
	for _, hook := range githubHooks {
		webhook := repository.Webhook{
			ID:     fmt.Sprintf("%v", hook["id"]),
			Active: false,
		}

		// Extract URL from config
		if config, ok := hook["config"].(map[string]interface{}); ok {
			if url, ok := config["url"].(string); ok {
				webhook.URL = url
			}
		}

		// Extract events
		if events, ok := hook["events"].([]interface{}); ok {
			webhook.Events = make([]string, 0, len(events))
			for _, event := range events {
				if eventStr, ok := event.(string); ok {
					webhook.Events = append(webhook.Events, eventStr)
				}
			}
		}

		// Extract active status
		if active, ok := hook["active"].(bool); ok {
			webhook.Active = active
		}

		webhooks = append(webhooks, webhook)
	}

	return webhooks, nil
}

// GetRateLimit gets current rate limit status
func (g *GitHubConnector) GetRateLimit(ctx context.Context) (*repository.RateLimit, error) {
	req, err := g.createRequest(ctx, "GET", "/rate_limit", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := g.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get rate limit: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get rate limit: %s", resp.Status)
	}

	var githubRate githubRateLimit
	if err := json.NewDecoder(resp.Body).Decode(&githubRate); err != nil {
		return nil, fmt.Errorf("failed to decode rate limit: %w", err)
	}

	return &repository.RateLimit{
		Limit:     githubRate.Resources.Core.Limit,
		Remaining: githubRate.Resources.Core.Remaining,
		ResetTime: time.Unix(githubRate.Resources.Core.Reset, 0),
		Used:      githubRate.Resources.Core.Used,
	}, nil
}

// HealthCheck performs a health check
func (g *GitHubConnector) HealthCheck(ctx context.Context) error {
	return g.ValidateAuth(ctx)
}

// Close closes the connector
func (g *GitHubConnector) Close() error {
	return nil
}

// Helper methods

func (g *GitHubConnector) createRequest(ctx context.Context, method, endpoint string, body io.Reader) (*http.Request, error) {
	url := g.baseURL + endpoint
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "token "+g.apiToken)
	req.Header.Set("User-Agent", g.userAgent)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	return req, nil
}

func (g *GitHubConnector) listRepositoriesWithURL(ctx context.Context, baseURL string, filter *repository.RepositoryFilter) ([]*repository.Repository, error) {
	var allRepos []*repository.Repository
	page := 1
	perPage := 100

	for {
		url := fmt.Sprintf("%s?page=%d&per_page=%d&sort=updated&direction=desc", baseURL, page, perPage)
		req, err := g.createRequest(ctx, "GET", url, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}

		resp, err := g.client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("failed to list repositories: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("failed to list repositories: %s", resp.Status)
		}

		var githubRepos []githubRepository
		if err := json.NewDecoder(resp.Body).Decode(&githubRepos); err != nil {
			return nil, fmt.Errorf("failed to decode repositories: %w", err)
		}

		if len(githubRepos) == 0 {
			break
		}

		for _, repo := range githubRepos {
			convertedRepo := g.convertRepository(&repo)
			if g.matchesFilter(convertedRepo, filter) {
				allRepos = append(allRepos, convertedRepo)
			}
		}

		if len(githubRepos) < perPage {
			break
		}
		page++
	}

	return allRepos, nil
}

func (g *GitHubConnector) convertRepository(repo *githubRepository) *repository.Repository {
	language := ""
	if repo.Language != nil {
		language = *repo.Language
	}

	return &repository.Repository{
		ID:            strconv.FormatInt(repo.ID, 10),
		Name:          repo.Name,
		FullName:      repo.FullName,
		URL:           repo.HTMLURL,
		CloneURL:      repo.CloneURL,
		SSHURL:        repo.SSHURL,
		DefaultBranch: repo.DefaultBranch,
		Language:      language,
		Private:       repo.Private,
		Archived:      repo.Archived,
		Fork:          repo.Fork,
		Size:          repo.Size,
		StarCount:     repo.Stargazers,
		ForkCount:     repo.Forks,
		Topics:        repo.Topics,
		CreatedAt:     repo.CreatedAt,
		UpdatedAt:     repo.UpdatedAt,
		PushedAt:      repo.PushedAt,
		Platform:      "github",
		Owner: repository.Owner{
			ID:        strconv.FormatInt(repo.Owner.ID, 10),
			Login:     repo.Owner.Login,
			Type:      repo.Owner.Type,
			AvatarURL: repo.Owner.AvatarURL,
		},
		Metadata: map[string]interface{}{
			"watchers":    repo.Watchers,
			"open_issues": repo.OpenIssues,
			"disabled":    repo.Disabled,
			"git_url":     repo.GitURL,
			"svn_url":     repo.SVNURL,
		},
	}
}

func (g *GitHubConnector) convertOrganization(org *githubOrganization) *repository.Organization {
	name := ""
	if org.Name != nil {
		name = *org.Name
	}
	description := ""
	if org.Description != nil {
		description = *org.Description
	}

	return &repository.Organization{
		ID:          strconv.FormatInt(org.ID, 10),
		Login:       org.Login,
		Name:        name,
		Description: description,
		URL:         org.HTMLURL,
		AvatarURL:   org.AvatarURL,
		Type:        org.Type,
		Platform:    "github",
	}
}

func (g *GitHubConnector) matchesFilter(repo *repository.Repository, filter *repository.RepositoryFilter) bool {
	if filter == nil {
		return true
	}

	// Language filter
	if len(filter.Languages) > 0 {
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

	// Private filter
	if !filter.IncludePrivate && repo.Private {
		return false
	}

	// Archived filter
	if !filter.IncludeArchived && repo.Archived {
		return false
	}

	// Fork filter
	if !filter.IncludeForks && repo.Fork {
		return false
	}

	// Star count filter
	if filter.MinStars > 0 && repo.StarCount < filter.MinStars {
		return false
	}

	// Size filter
	if filter.MaxSize > 0 && repo.Size > filter.MaxSize {
		return false
	}

	// Date filters
	if filter.UpdatedAfter != nil && repo.UpdatedAt.Before(*filter.UpdatedAfter) {
		return false
	}
	if filter.UpdatedBefore != nil && repo.UpdatedAt.After(*filter.UpdatedBefore) {
		return false
	}

	// Name pattern filter
	if filter.NamePattern != "" {
		matched, _ := path.Match(filter.NamePattern, repo.Name)
		if !matched {
			return false
		}
	}

	// Topics filter
	if len(filter.Topics) > 0 {
		found := false
		for _, filterTopic := range filter.Topics {
			for _, repoTopic := range repo.Topics {
				if strings.EqualFold(repoTopic, filterTopic) {
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

func (g *GitHubConnector) buildSearchQuery(query string, filter *repository.RepositoryFilter) string {
	searchTerms := []string{query}

	if filter != nil {
		if len(filter.Languages) > 0 {
			for _, lang := range filter.Languages {
				searchTerms = append(searchTerms, "language:"+lang)
			}
		}

		if len(filter.Topics) > 0 {
			for _, topic := range filter.Topics {
				searchTerms = append(searchTerms, "topic:"+topic)
			}
		}

		if filter.MinStars > 0 {
			searchTerms = append(searchTerms, fmt.Sprintf("stars:>=%d", filter.MinStars))
		}

		if !filter.IncludeArchived {
			searchTerms = append(searchTerms, "archived:false")
		}

		if !filter.IncludeForks {
			searchTerms = append(searchTerms, "fork:false")
		}
	}

	return strings.Join(searchTerms, " ")
}

func (g *GitHubConnector) parseFullName(fullName string) (owner, name string) {
	parts := strings.Split(fullName, "/")
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return "", fullName
}

func (g *GitHubConnector) decodeBase64Content(content string) ([]byte, error) {
	// Remove whitespace and newlines
	content = strings.ReplaceAll(content, "\n", "")
	content = strings.ReplaceAll(content, " ", "")

	// Decode base64
	return base64.StdEncoding.DecodeString(content)
}
