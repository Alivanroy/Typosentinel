package connectors

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/repository"
)

// GitLabConnector implements the Connector interface for GitLab
type GitLabConnector struct {
	client    *http.Client
	baseURL   string
	apiToken  string
	userAgent string
	config    repository.PlatformConfig
}

// GitLab API response structures
type gitlabProject struct {
	ID                int64     `json:"id"`
	Name              string    `json:"name"`
	NameWithNamespace string    `json:"name_with_namespace"`
	Path              string    `json:"path"`
	PathWithNamespace string    `json:"path_with_namespace"`
	Description       *string   `json:"description"`
	WebURL            string    `json:"web_url"`
	HTTPURLToRepo     string    `json:"http_url_to_repo"`
	SSHURLToRepo      string    `json:"ssh_url_to_repo"`
	DefaultBranch     string    `json:"default_branch"`
	Visibility        string    `json:"visibility"`
	Archived          bool      `json:"archived"`
	StarCount         int       `json:"star_count"`
	ForksCount        int       `json:"forks_count"`
	CreatedAt         time.Time `json:"created_at"`
	LastActivityAt    time.Time `json:"last_activity_at"`
	TagList           []string  `json:"tag_list"`
	Topics            []string  `json:"topics"`
	Namespace         gitlabNamespace `json:"namespace"`
	Owner             *gitlabUser `json:"owner"`
	ForkedFromProject *gitlabProject `json:"forked_from_project"`
	Statistics        *gitlabProjectStatistics `json:"statistics"`
}

type gitlabNamespace struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	Path     string `json:"path"`
	Kind     string `json:"kind"`
	FullPath string `json:"full_path"`
	WebURL   string `json:"web_url"`
}

type gitlabUser struct {
	ID        int64  `json:"id"`
	Username  string `json:"username"`
	Name      string `json:"name"`
	State     string `json:"state"`
	AvatarURL string `json:"avatar_url"`
	WebURL    string `json:"web_url"`
}

type gitlabGroup struct {
	ID          int64   `json:"id"`
	Name        string  `json:"name"`
	Path        string  `json:"path"`
	Description *string `json:"description"`
	Visibility  string  `json:"visibility"`
	FullName    string  `json:"full_name"`
	FullPath    string  `json:"full_path"`
	WebURL      string  `json:"web_url"`
	AvatarURL   *string `json:"avatar_url"`
	ParentID    *int64  `json:"parent_id"`
}

type gitlabProjectStatistics struct {
	CommitCount           int64 `json:"commit_count"`
	StorageSize           int64 `json:"storage_size"`
	RepositorySize        int64 `json:"repository_size"`
	WikiSize              int64 `json:"wiki_size"`
	LfsObjectsSize        int64 `json:"lfs_objects_size"`
	JobArtifactsSize      int64 `json:"job_artifacts_size"`
	PackagesSize          int64 `json:"packages_size"`
	SnippetsSize          int64 `json:"snippets_size"`
	UploadsSize           int64 `json:"uploads_size"`
}

type gitlabFile struct {
	FileName     string `json:"file_name"`
	FilePath     string `json:"file_path"`
	Size         int64  `json:"size"`
	Encoding     string `json:"encoding"`
	Content      string `json:"content"`
	ContentSHA256 string `json:"content_sha256"`
	Ref          string `json:"ref"`
	BlobID       string `json:"blob_id"`
	CommitID     string `json:"commit_id"`
	LastCommitID string `json:"last_commit_id"`
}

type gitlabTreeItem struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
	Path string `json:"path"`
	Mode string `json:"mode"`
}

type gitlabCommit struct {
	ID             string    `json:"id"`
	ShortID        string    `json:"short_id"`
	Title          string    `json:"title"`
	Message        string    `json:"message"`
	AuthorName     string    `json:"author_name"`
	AuthorEmail    string    `json:"author_email"`
	AuthoredDate   time.Time `json:"authored_date"`
	CommitterName  string    `json:"committer_name"`
	CommitterEmail string    `json:"committer_email"`
	CommittedDate  time.Time `json:"committed_date"`
	WebURL         string    `json:"web_url"`
}

type gitlabBranch struct {
	Name               string        `json:"name"`
	Merged             bool          `json:"merged"`
	Protected          bool          `json:"protected"`
	DevelopersCanPush  bool          `json:"developers_can_push"`
	DevelopersCanMerge bool          `json:"developers_can_merge"`
	CanPush            bool          `json:"can_push"`
	Default            bool          `json:"default"`
	Commit             gitlabCommit  `json:"commit"`
}

// NewGitLabConnector creates a new GitLab connector
func NewGitLabConnector(config repository.PlatformConfig) (*GitLabConnector, error) {
	if config.BaseURL == "" {
		config.BaseURL = "https://gitlab.com/api/v4"
	}

	client := &http.Client{
		Timeout: config.Timeout,
	}

	return &GitLabConnector{
		client:    client,
		baseURL:   config.BaseURL,
		apiToken:  config.Auth.Token,
		userAgent: "TypoSentinel/2.0",
		config:    config,
	}, nil
}

// GetPlatformName returns the platform name
func (g *GitLabConnector) GetPlatformName() string {
	return "gitlab"
}

// GetPlatformType returns the platform type
func (g *GitLabConnector) GetPlatformType() string {
	return "git"
}

// GetAPIVersion returns the API version
func (g *GitLabConnector) GetAPIVersion() string {
	return "v4"
}

// Authenticate validates the authentication
func (g *GitLabConnector) Authenticate(ctx context.Context, config repository.AuthConfig) error {
	g.apiToken = config.Token
	return g.ValidateAuth(ctx)
}

// ValidateAuth validates the current authentication
func (g *GitLabConnector) ValidateAuth(ctx context.Context) error {
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
func (g *GitLabConnector) RefreshAuth(ctx context.Context) error {
	return nil // Token auth doesn't need refresh
}

// ListOrganizations lists all groups for the authenticated user
func (g *GitLabConnector) ListOrganizations(ctx context.Context) ([]*repository.Organization, error) {
	var allGroups []*repository.Organization
	page := 1
	perPage := 100

	for {
		endpoint := fmt.Sprintf("/groups?page=%d&per_page=%d&owned=true", page, perPage)
		req, err := g.createRequest(ctx, "GET", endpoint, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}

		resp, err := g.client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("failed to list groups: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("failed to list groups: %s", resp.Status)
		}

		var gitlabGroups []gitlabGroup
		if err := json.NewDecoder(resp.Body).Decode(&gitlabGroups); err != nil {
			return nil, fmt.Errorf("failed to decode groups: %w", err)
		}

		if len(gitlabGroups) == 0 {
			break
		}

		for _, group := range gitlabGroups {
			allGroups = append(allGroups, g.convertGroup(&group))
		}

		if len(gitlabGroups) < perPage {
			break
		}
		page++
	}

	return allGroups, nil
}

// GetOrganization gets a specific group
func (g *GitLabConnector) GetOrganization(ctx context.Context, name string) (*repository.Organization, error) {
	endpoint := fmt.Sprintf("/groups/%s", url.QueryEscape(name))
	req, err := g.createRequest(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := g.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get group: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get group: %s", resp.Status)
	}

	var gitlabGroup gitlabGroup
	if err := json.NewDecoder(resp.Body).Decode(&gitlabGroup); err != nil {
		return nil, fmt.Errorf("failed to decode group: %w", err)
	}

	return g.convertGroup(&gitlabGroup), nil
}

// ListRepositories lists repositories for a user
func (g *GitLabConnector) ListRepositories(ctx context.Context, owner string, filter *repository.RepositoryFilter) ([]*repository.Repository, error) {
	return g.listProjectsWithURL(ctx, fmt.Sprintf("/users/%s/projects", url.QueryEscape(owner)), filter)
}

// ListOrgRepositories lists repositories for a group
func (g *GitLabConnector) ListOrgRepositories(ctx context.Context, org string, filter *repository.RepositoryFilter) ([]*repository.Repository, error) {
	includeSubgroups := "true"
	if filter != nil && filter.CustomFilters != nil {
		if val, ok := filter.CustomFilters["include_subgroups"]; ok {
			if include, ok := val.(bool); ok && !include {
				includeSubgroups = "false"
			}
		}
	}

	endpoint := fmt.Sprintf("/groups/%s/projects?include_subgroups=%s", url.QueryEscape(org), includeSubgroups)
	return g.listProjectsWithURL(ctx, endpoint, filter)
}

// GetRepository gets a specific repository
func (g *GitLabConnector) GetRepository(ctx context.Context, owner, name string) (*repository.Repository, error) {
	projectPath := fmt.Sprintf("%s/%s", owner, name)
	endpoint := fmt.Sprintf("/projects/%s?statistics=true", url.QueryEscape(projectPath))
	req, err := g.createRequest(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := g.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get project: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get project: %s", resp.Status)
	}

	var gitlabProject gitlabProject
	if err := json.NewDecoder(resp.Body).Decode(&gitlabProject); err != nil {
		return nil, fmt.Errorf("failed to decode project: %w", err)
	}

	return g.convertProject(&gitlabProject), nil
}

// SearchRepositories searches for repositories
func (g *GitLabConnector) SearchRepositories(ctx context.Context, query string, filter *repository.RepositoryFilter) ([]*repository.Repository, error) {
	searchURL := fmt.Sprintf("/projects?search=%s&order_by=last_activity_at&sort=desc", url.QueryEscape(query))
	return g.listProjectsWithURL(ctx, searchURL, filter)
}

// GetRepositoryContent gets file content from a repository
func (g *GitLabConnector) GetRepositoryContent(ctx context.Context, repo *repository.Repository, filePath string, ref string) ([]byte, error) {
	projectID := repo.ID
	endpoint := fmt.Sprintf("/projects/%s/repository/files/%s", projectID, url.QueryEscape(filePath))
	if ref != "" {
		endpoint += "?ref=" + url.QueryEscape(ref)
	}

	req, err := g.createRequest(ctx, "GET", endpoint, nil)
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

	var file gitlabFile
	if err := json.NewDecoder(resp.Body).Decode(&file); err != nil {
		return nil, fmt.Errorf("failed to decode file content: %w", err)
	}

	if file.Encoding == "base64" {
		return g.decodeBase64Content(file.Content)
	}

	return []byte(file.Content), nil
}

// ListRepositoryFiles lists files in a repository directory
func (g *GitLabConnector) ListRepositoryFiles(ctx context.Context, repo *repository.Repository, dirPath string, ref string) ([]string, error) {
	projectID := repo.ID
	endpoint := fmt.Sprintf("/projects/%s/repository/tree", projectID)
	if dirPath != "" {
		endpoint += "?path=" + url.QueryEscape(dirPath)
	}
	if ref != "" {
		if strings.Contains(endpoint, "?") {
			endpoint += "&ref=" + url.QueryEscape(ref)
		} else {
			endpoint += "?ref=" + url.QueryEscape(ref)
		}
	}

	req, err := g.createRequest(ctx, "GET", endpoint, nil)
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

	var treeItems []gitlabTreeItem
	if err := json.NewDecoder(resp.Body).Decode(&treeItems); err != nil {
		return nil, fmt.Errorf("failed to decode tree items: %w", err)
	}

	var files []string
	for _, item := range treeItems {
		files = append(files, item.Path)
	}

	return files, nil
}

// GetPackageFiles gets package manager files from a repository
func (g *GitLabConnector) GetPackageFiles(ctx context.Context, repo *repository.Repository, ref string) (map[string][]byte, error) {
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
func (g *GitLabConnector) GetRepositoryLanguages(ctx context.Context, repo *repository.Repository) (map[string]int, error) {
	projectID := repo.ID
	endpoint := fmt.Sprintf("/projects/%s/languages", projectID)

	req, err := g.createRequest(ctx, "GET", endpoint, nil)
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

	var languages map[string]float64
	if err := json.NewDecoder(resp.Body).Decode(&languages); err != nil {
		return nil, fmt.Errorf("failed to decode languages: %w", err)
	}

	// Convert float64 percentages to int bytes (approximation)
	langBytes := make(map[string]int)
	for lang, percentage := range languages {
		langBytes[lang] = int(percentage * 1000) // Convert percentage to approximate bytes
	}

	return langBytes, nil
}

// GetRepositoryTopics gets repository topics
func (g *GitLabConnector) GetRepositoryTopics(ctx context.Context, repo *repository.Repository) ([]string, error) {
	// GitLab stores topics in the project data, so we need to fetch the project again
	projectID := repo.ID
	endpoint := fmt.Sprintf("/projects/%s", projectID)

	req, err := g.createRequest(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := g.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get repository topics: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get repository topics: %s", resp.Status)
	}

	var project gitlabProject
	if err := json.NewDecoder(resp.Body).Decode(&project); err != nil {
		return nil, fmt.Errorf("failed to decode project: %w", err)
	}

	// Return topics if available, otherwise return tag_list
	if len(project.Topics) > 0 {
		return project.Topics, nil
	}
	return project.TagList, nil
}

// GetRepositoryBranches gets repository branches
func (g *GitLabConnector) GetRepositoryBranches(ctx context.Context, repo *repository.Repository) ([]string, error) {
	projectID := repo.ID
	endpoint := fmt.Sprintf("/projects/%s/repository/branches", projectID)

	req, err := g.createRequest(ctx, "GET", endpoint, nil)
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

	var branches []gitlabBranch
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
func (g *GitLabConnector) GetRepositoryCommits(ctx context.Context, repo *repository.Repository, branch string, limit int) ([]repository.Commit, error) {
	projectID := repo.ID
	endpoint := fmt.Sprintf("/projects/%s/repository/commits?per_page=%d", projectID, limit)
	if branch != "" {
		endpoint += "&ref_name=" + url.QueryEscape(branch)
	}

	req, err := g.createRequest(ctx, "GET", endpoint, nil)
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

	var gitlabCommits []gitlabCommit
	if err := json.NewDecoder(resp.Body).Decode(&gitlabCommits); err != nil {
		return nil, fmt.Errorf("failed to decode commits: %w", err)
	}

	var commits []repository.Commit
	for _, gc := range gitlabCommits {
		commits = append(commits, repository.Commit{
			SHA:     gc.ID,
			Message: gc.Message,
			Author:  gc.AuthorName,
			Email:   gc.AuthorEmail,
			Date:    gc.AuthoredDate,
			URL:     gc.WebURL,
		})
	}

	return commits, nil
}

// CreateWebhook creates a webhook for the repository
func (g *GitLabConnector) CreateWebhook(ctx context.Context, repo *repository.Repository, webhookURL string, events []string) error {
	if repo == nil {
		return fmt.Errorf("repository cannot be nil")
	}
	if webhookURL == "" {
		return fmt.Errorf("webhook URL cannot be empty")
	}
	if len(events) == 0 {
		events = []string{"push_events", "merge_requests_events", "tag_push_events"}
	}

	// Convert events to GitLab format
	gitlabEvents := make(map[string]bool)
	for _, event := range events {
		switch event {
		case "push", "push_events":
			gitlabEvents["push_events"] = true
		case "pull_request", "merge_requests_events":
			gitlabEvents["merge_requests_events"] = true
		case "release", "tag_push_events":
			gitlabEvents["tag_push_events"] = true
		case "issues_events":
			gitlabEvents["issues_events"] = true
		case "wiki_page_events":
			gitlabEvents["wiki_page_events"] = true
		default:
			gitlabEvents[event] = true
		}
	}

	// Prepare webhook payload
	payload := map[string]interface{}{
		"url":                      webhookURL,
		"push_events":              gitlabEvents["push_events"],
		"merge_requests_events":    gitlabEvents["merge_requests_events"],
		"tag_push_events":          gitlabEvents["tag_push_events"],
		"issues_events":            gitlabEvents["issues_events"],
		"wiki_page_events":         gitlabEvents["wiki_page_events"],
		"enable_ssl_verification":  true,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal webhook payload: %w", err)
	}

	endpoint := fmt.Sprintf("/projects/%s/hooks", url.QueryEscape(repo.FullName))
	req, err := g.createRequest(ctx, "POST", endpoint, bytes.NewReader(payloadBytes))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

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
func (g *GitLabConnector) DeleteWebhook(ctx context.Context, repo *repository.Repository, webhookID string) error {
	if repo == nil {
		return fmt.Errorf("repository cannot be nil")
	}
	if webhookID == "" {
		return fmt.Errorf("webhook ID cannot be empty")
	}

	endpoint := fmt.Sprintf("/projects/%s/hooks/%s", url.QueryEscape(repo.FullName), webhookID)
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
func (g *GitLabConnector) ListWebhooks(ctx context.Context, repo *repository.Repository) ([]repository.Webhook, error) {
	if repo == nil {
		return nil, fmt.Errorf("repository cannot be nil")
	}

	endpoint := fmt.Sprintf("/projects/%s/hooks", url.QueryEscape(repo.FullName))
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

	var gitlabHooks []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&gitlabHooks); err != nil {
		return nil, fmt.Errorf("failed to parse webhook response: %w", err)
	}

	webhooks := make([]repository.Webhook, 0, len(gitlabHooks))
	for _, hook := range gitlabHooks {
		webhook := repository.Webhook{
			ID:     fmt.Sprintf("%v", hook["id"]),
			Active: true, // GitLab webhooks are active by default
		}

		// Extract URL
		if url, ok := hook["url"].(string); ok {
			webhook.URL = url
		}

		// Extract events
		var events []string
		if pushEvents, ok := hook["push_events"].(bool); ok && pushEvents {
			events = append(events, "push_events")
		}
		if mergeRequestEvents, ok := hook["merge_requests_events"].(bool); ok && mergeRequestEvents {
			events = append(events, "merge_requests_events")
		}
		if tagPushEvents, ok := hook["tag_push_events"].(bool); ok && tagPushEvents {
			events = append(events, "tag_push_events")
		}
		if issuesEvents, ok := hook["issues_events"].(bool); ok && issuesEvents {
			events = append(events, "issues_events")
		}
		if wikiPageEvents, ok := hook["wiki_page_events"].(bool); ok && wikiPageEvents {
			events = append(events, "wiki_page_events")
		}
		webhook.Events = events

		webhooks = append(webhooks, webhook)
	}

	return webhooks, nil
}

// GetRateLimit gets current rate limit status (GitLab doesn't have a specific endpoint)
func (g *GitLabConnector) GetRateLimit(ctx context.Context) (*repository.RateLimit, error) {
	// GitLab doesn't have a specific rate limit endpoint like GitHub
	// Return a default rate limit based on GitLab's documented limits
	return &repository.RateLimit{
		Limit:     2000, // GitLab.com default limit per hour
		Remaining: 2000, // We can't know the actual remaining without making a request
		ResetTime: time.Now().Add(time.Hour),
		Used:      0,
	}, nil
}

// HealthCheck performs a health check
func (g *GitLabConnector) HealthCheck(ctx context.Context) error {
	return g.ValidateAuth(ctx)
}

// Close closes the connector
func (g *GitLabConnector) Close() error {
	return nil
}

// Helper methods

func (g *GitLabConnector) createRequest(ctx context.Context, method, endpoint string, body io.Reader) (*http.Request, error) {
	url := g.baseURL + endpoint
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("PRIVATE-TOKEN", g.apiToken)
	req.Header.Set("User-Agent", g.userAgent)
	req.Header.Set("Content-Type", "application/json")

	return req, nil
}

func (g *GitLabConnector) listProjectsWithURL(ctx context.Context, baseURL string, filter *repository.RepositoryFilter) ([]*repository.Repository, error) {
	var allRepos []*repository.Repository
	page := 1
	perPage := 100

	for {
		endpoint := fmt.Sprintf("%s?page=%d&per_page=%d&order_by=last_activity_at&sort=desc&statistics=true", baseURL, page, perPage)
		req, err := g.createRequest(ctx, "GET", endpoint, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}

		resp, err := g.client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("failed to list projects: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("failed to list projects: %s", resp.Status)
		}

		var gitlabProjects []gitlabProject
		if err := json.NewDecoder(resp.Body).Decode(&gitlabProjects); err != nil {
			return nil, fmt.Errorf("failed to decode projects: %w", err)
		}

		if len(gitlabProjects) == 0 {
			break
		}

		for _, project := range gitlabProjects {
			convertedRepo := g.convertProject(&project)
			if g.matchesFilter(convertedRepo, filter) {
				allRepos = append(allRepos, convertedRepo)
			}
		}

		if len(gitlabProjects) < perPage {
			break
		}
		page++
	}

	return allRepos, nil
}

func (g *GitLabConnector) convertProject(project *gitlabProject) *repository.Repository {
	size := int64(0)
	if project.Statistics != nil {
		size = project.Statistics.RepositorySize
	}

	owner := repository.Owner{
		ID:    strconv.FormatInt(project.Namespace.ID, 10),
		Login: project.Namespace.Path,
		Name:  project.Namespace.Name,
		Type:  project.Namespace.Kind,
	}

	if project.Owner != nil {
		owner = repository.Owner{
			ID:        strconv.FormatInt(project.Owner.ID, 10),
			Login:     project.Owner.Username,
			Name:      project.Owner.Name,
			Type:      "user",
			AvatarURL: project.Owner.AvatarURL,
		}
	}

	topics := project.Topics
	if len(topics) == 0 {
		topics = project.TagList
	}

	return &repository.Repository{
		ID:            strconv.FormatInt(project.ID, 10),
		Name:          project.Name,
		FullName:      project.PathWithNamespace,
		URL:           project.WebURL,
		CloneURL:      project.HTTPURLToRepo,
		SSHURL:        project.SSHURLToRepo,
		DefaultBranch: project.DefaultBranch,
		Private:       project.Visibility == "private",
		Archived:      project.Archived,
		Fork:          project.ForkedFromProject != nil,
		Size:          size,
		StarCount:     project.StarCount,
		ForkCount:     project.ForksCount,
		Topics:        topics,
		CreatedAt:     project.CreatedAt,
		UpdatedAt:     project.LastActivityAt,
		PushedAt:      project.LastActivityAt,
		Platform:      "gitlab",
		Owner:         owner,
		Metadata: map[string]interface{}{
			"visibility":        project.Visibility,
			"name_with_namespace": project.NameWithNamespace,
			"path":             project.Path,
			"path_with_namespace": project.PathWithNamespace,
			"namespace":        project.Namespace,
		},
	}
}

func (g *GitLabConnector) convertGroup(group *gitlabGroup) *repository.Organization {
	description := ""
	if group.Description != nil {
		description = *group.Description
	}

	avatarURL := ""
	if group.AvatarURL != nil {
		avatarURL = *group.AvatarURL
	}

	return &repository.Organization{
		ID:          strconv.FormatInt(group.ID, 10),
		Login:       group.Path,
		Name:        group.Name,
		Description: description,
		URL:         group.WebURL,
		AvatarURL:   avatarURL,
		Type:        "group",
		Platform:    "gitlab",
		Metadata: map[string]interface{}{
			"full_name":  group.FullName,
			"full_path":  group.FullPath,
			"visibility": group.Visibility,
			"parent_id":  group.ParentID,
		},
	}
}

func (g *GitLabConnector) matchesFilter(repo *repository.Repository, filter *repository.RepositoryFilter) bool {
	if filter == nil {
		return true
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

func (g *GitLabConnector) decodeBase64Content(content string) ([]byte, error) {
	// Remove whitespace and newlines
	content = strings.ReplaceAll(content, "\n", "")
	content = strings.ReplaceAll(content, " ", "")
	
	// Decode base64
	return json.RawMessage(content), nil
}