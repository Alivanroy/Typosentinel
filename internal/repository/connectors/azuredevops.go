package connectors

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/repository"
)

// AzureDevOpsConnector implements the Connector interface for Azure DevOps
type AzureDevOpsConnector struct {
	client         *http.Client
	baseURL        string
	organization   string
	apiToken       string
	userAgent      string
	config         repository.PlatformConfig
	retryConfig    *AzureRetryConfig
	webhookManager *AzureWebhookManager
}

// AzureRetryConfig defines retry behavior for Azure DevOps API requests
type AzureRetryConfig struct {
	MaxRetries    int
	InitialDelay  time.Duration
	MaxDelay      time.Duration
	BackoffFactor float64
}

// AzureWebhookManager manages Azure DevOps service hooks
type AzureWebhookManager struct {
	connector *AzureDevOpsConnector
	webhooks  map[string]*repository.Webhook
	mu        sync.RWMutex
}

// Azure DevOps API response structures
type azureRepository struct {
	ID            string       `json:"id"`
	Name          string       `json:"name"`
	URL           string       `json:"url"`
	Project       azureProject `json:"project"`
	DefaultBranch string       `json:"defaultBranch"`
	Size          int64        `json:"size"`
	RemoteURL     string       `json:"remoteUrl"`
	SSHURL        string       `json:"sshUrl"`
	WebURL        string       `json:"webUrl"`
	IsDisabled    bool         `json:"isDisabled"`
	IsFork        bool         `json:"isFork"`
}

type azureProject struct {
	ID             string                 `json:"id"`
	Name           string                 `json:"name"`
	Description    string                 `json:"description"`
	URL            string                 `json:"url"`
	State          string                 `json:"state"`
	Revision       int64                  `json:"revision"`
	Visibility     string                 `json:"visibility"`
	LastUpdateTime time.Time              `json:"lastUpdateTime"`
	Capabilities   map[string]interface{} `json:"capabilities"`
}

type azureOrganization struct {
	AccountID   string                 `json:"accountId"`
	AccountName string                 `json:"accountName"`
	AccountURI  string                 `json:"accountUri"`
	Properties  map[string]interface{} `json:"properties"`
}

type azureCommit struct {
	CommitID     string           `json:"commitId"`
	Comment      string           `json:"comment"`
	Author       azureGitUserDate `json:"author"`
	Committer    azureGitUserDate `json:"committer"`
	ChangeCounts map[string]int   `json:"changeCounts"`
	URL          string           `json:"url"`
	RemoteURL    string           `json:"remoteUrl"`
}

type azureGitUserDate struct {
	Name  string    `json:"name"`
	Email string    `json:"email"`
	Date  time.Time `json:"date"`
}

type azureBranch struct {
	Name          string           `json:"name"`
	ObjectID      string           `json:"objectId"`
	Creator       azureIdentityRef `json:"creator"`
	URL           string           `json:"url"`
	IsBaseVersion bool             `json:"isBaseVersion"`
}

type azureIdentityRef struct {
	DisplayName string `json:"displayName"`
	URL         string `json:"url"`
	ID          string `json:"id"`
	UniqueName  string `json:"uniqueName"`
	ImageURL    string `json:"imageUrl"`
	Descriptor  string `json:"descriptor"`
}

type azureGitItem struct {
	ObjectID      string `json:"objectId"`
	GitObjectType string `json:"gitObjectType"`
	CommitID      string `json:"commitId"`
	Path          string `json:"path"`
	IsFolder      bool   `json:"isFolder"`
	URL           string `json:"url"`
}

type azureValueResponse struct {
	Value []json.RawMessage `json:"value"`
	Count int               `json:"count"`
}

// NewAzureDevOpsConnector creates a new Azure DevOps connector
func NewAzureDevOpsConnector(config repository.PlatformConfig) (*AzureDevOpsConnector, error) {
	baseURL := config.BaseURL
	if baseURL == "" {
		baseURL = "https://dev.azure.com"
	}

	// Extract organization from config or URL
	organization := ""
	if len(config.Organizations) > 0 {
		organization = config.Organizations[0]
	}

	connector := &AzureDevOpsConnector{
		client:       &http.Client{Timeout: config.Timeout},
		baseURL:      baseURL,
		organization: organization,
		apiToken:     config.Auth.Token,
		userAgent:    "TypoSentinel/1.0",
		config:       config,
		retryConfig: &AzureRetryConfig{
			MaxRetries:    3,
			InitialDelay:  time.Second,
			MaxDelay:      30 * time.Second,
			BackoffFactor: 2.0,
		},
		webhookManager: &AzureWebhookManager{
			webhooks: make(map[string]*repository.Webhook),
		},
	}

	// Set connector reference in webhook manager
	connector.webhookManager.connector = connector

	return connector, nil
}

// GetPlatformName returns the platform name
func (a *AzureDevOpsConnector) GetPlatformName() string {
	return "Azure DevOps"
}

// GetPlatformType returns the platform type
func (a *AzureDevOpsConnector) GetPlatformType() string {
	return "git"
}

// GetAPIVersion returns the API version
func (a *AzureDevOpsConnector) GetAPIVersion() string {
	return "7.0"
}

// Authenticate sets up authentication
func (a *AzureDevOpsConnector) Authenticate(ctx context.Context, config repository.AuthConfig) error {
	a.apiToken = config.Token
	return nil
}

// ValidateAuth validates the authentication
func (a *AzureDevOpsConnector) ValidateAuth(ctx context.Context) error {
	if a.organization == "" {
		return fmt.Errorf("organization not configured")
	}

	endpoint := fmt.Sprintf("/%s/_apis/projects", url.QueryEscape(a.organization))
	req, err := a.createRequest(ctx, "GET", endpoint, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := a.client.Do(req)
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
func (a *AzureDevOpsConnector) RefreshAuth(ctx context.Context) error {
	return nil
}

// ListOrganizations lists organizations (returns current organization)
func (a *AzureDevOpsConnector) ListOrganizations(ctx context.Context) ([]*repository.Organization, error) {
	if a.organization == "" {
		return nil, fmt.Errorf("organization not configured")
	}

	// Azure DevOps doesn't have a direct API to list organizations
	// Return the configured organization
	org := &repository.Organization{
		ID:       a.organization,
		Login:    a.organization,
		Name:     a.organization,
		URL:      fmt.Sprintf("%s/%s", a.baseURL, a.organization),
		Type:     "organization",
		Platform: "azuredevops",
	}

	return []*repository.Organization{org}, nil
}

// GetOrganization gets a specific organization
func (a *AzureDevOpsConnector) GetOrganization(ctx context.Context, name string) (*repository.Organization, error) {
	if name != a.organization {
		return nil, fmt.Errorf("organization %s not found", name)
	}

	org := &repository.Organization{
		ID:       a.organization,
		Login:    a.organization,
		Name:     a.organization,
		URL:      fmt.Sprintf("%s/%s", a.baseURL, a.organization),
		Type:     "organization",
		Platform: "azuredevops",
	}

	return org, nil
}

// ListRepositories lists repositories for a project
func (a *AzureDevOpsConnector) ListRepositories(ctx context.Context, project string, filter *repository.RepositoryFilter) ([]*repository.Repository, error) {
	return a.listRepositoriesForProject(ctx, project, filter)
}

// ListOrgRepositories lists all repositories in the organization
func (a *AzureDevOpsConnector) ListOrgRepositories(ctx context.Context, org string, filter *repository.RepositoryFilter) ([]*repository.Repository, error) {
	// First get all projects
	projects, err := a.listProjects(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list projects: %w", err)
	}

	var allRepositories []*repository.Repository
	for _, project := range projects {
		repos, err := a.listRepositoriesForProject(ctx, project.Name, filter)
		if err != nil {
			continue // Skip projects we can't access
		}
		allRepositories = append(allRepositories, repos...)
	}

	return allRepositories, nil
}

// GetRepository gets a specific repository
func (a *AzureDevOpsConnector) GetRepository(ctx context.Context, project, name string) (*repository.Repository, error) {
	endpoint := fmt.Sprintf("/%s/%s/_apis/git/repositories/%s",
		url.QueryEscape(a.organization), url.QueryEscape(project), url.QueryEscape(name))

	req, err := a.createRequest(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get repository: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get repository: %s", resp.Status)
	}

	var repo azureRepository
	if err := json.NewDecoder(resp.Body).Decode(&repo); err != nil {
		return nil, fmt.Errorf("failed to decode repository: %w", err)
	}

	return a.convertRepository(&repo), nil
}

// SearchRepositories searches for repositories
func (a *AzureDevOpsConnector) SearchRepositories(ctx context.Context, query string, filter *repository.RepositoryFilter) ([]*repository.Repository, error) {
	// Azure DevOps doesn't have a direct search API, so we'll list all and filter
	return a.ListOrgRepositories(ctx, a.organization, filter)
}

// GetRepositoryContent gets file content from repository
func (a *AzureDevOpsConnector) GetRepositoryContent(ctx context.Context, repo *repository.Repository, filePath string, ref string) ([]byte, error) {
	project, repoName := a.parseFullName(repo.FullName)
	if ref == "" {
		ref = repo.DefaultBranch
		if ref == "" {
			ref = "main"
		}
	}

	// Remove refs/heads/ prefix if present
	if strings.HasPrefix(ref, "refs/heads/") {
		ref = strings.TrimPrefix(ref, "refs/heads/")
	}

	endpoint := fmt.Sprintf("/%s/%s/_apis/git/repositories/%s/items",
		url.QueryEscape(a.organization), url.QueryEscape(project), url.QueryEscape(repoName))

	params := url.Values{}
	params.Set("path", filePath)
	params.Set("versionDescriptor.version", ref)
	params.Set("versionDescriptor.versionType", "branch")
	params.Set("includeContent", "true")
	params.Set("api-version", "7.0")

	req, err := a.createRequest(ctx, "GET", endpoint+"?"+params.Encode(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get file content: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get file content: %s", resp.Status)
	}

	return io.ReadAll(resp.Body)
}

// ListRepositoryFiles lists files in a repository directory
func (a *AzureDevOpsConnector) ListRepositoryFiles(ctx context.Context, repo *repository.Repository, dirPath string, ref string) ([]string, error) {
	project, repoName := a.parseFullName(repo.FullName)
	if ref == "" {
		ref = repo.DefaultBranch
		if ref == "" {
			ref = "main"
		}
	}

	// Remove refs/heads/ prefix if present
	if strings.HasPrefix(ref, "refs/heads/") {
		ref = strings.TrimPrefix(ref, "refs/heads/")
	}

	endpoint := fmt.Sprintf("/%s/%s/_apis/git/repositories/%s/items",
		url.QueryEscape(a.organization), url.QueryEscape(project), url.QueryEscape(repoName))

	params := url.Values{}
	params.Set("scopePath", dirPath)
	params.Set("versionDescriptor.version", ref)
	params.Set("versionDescriptor.versionType", "branch")
	params.Set("recursionLevel", "OneLevel")
	params.Set("api-version", "7.0")

	req, err := a.createRequest(ctx, "GET", endpoint+"?"+params.Encode(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to list files: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to list files: %s", resp.Status)
	}

	var response azureValueResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	var filePaths []string
	for _, itemData := range response.Value {
		var item azureGitItem
		if err := json.Unmarshal(itemData, &item); err != nil {
			continue
		}
		if !item.IsFolder {
			filePaths = append(filePaths, item.Path)
		}
	}

	return filePaths, nil
}

// GetPackageFiles gets package manager files
func (a *AzureDevOpsConnector) GetPackageFiles(ctx context.Context, repo *repository.Repository, ref string) (map[string][]byte, error) {
	packageFiles := map[string][]byte{}
	commonFiles := []string{"package.json", "requirements.txt", "Gemfile", "pom.xml", "build.gradle", "Cargo.toml", "go.mod"}

	for _, file := range commonFiles {
		content, err := a.GetRepositoryContent(ctx, repo, file, ref)
		if err == nil {
			packageFiles[file] = content
		}
	}

	return packageFiles, nil
}

// GetRepositoryLanguages gets repository languages (not directly supported)
func (a *AzureDevOpsConnector) GetRepositoryLanguages(ctx context.Context, repo *repository.Repository) (map[string]int, error) {
	// Azure DevOps doesn't provide language statistics
	return make(map[string]int), nil
}

// GetRepositoryTopics gets repository topics (not supported)
func (a *AzureDevOpsConnector) GetRepositoryTopics(ctx context.Context, repo *repository.Repository) ([]string, error) {
	return []string{}, nil
}

// GetRepositoryBranches gets repository branches
func (a *AzureDevOpsConnector) GetRepositoryBranches(ctx context.Context, repo *repository.Repository) ([]string, error) {
	project, repoName := a.parseFullName(repo.FullName)
	endpoint := fmt.Sprintf("/%s/%s/_apis/git/repositories/%s/refs",
		url.QueryEscape(a.organization), url.QueryEscape(project), url.QueryEscape(repoName))

	params := url.Values{}
	params.Set("filter", "heads/")
	params.Set("api-version", "7.0")

	req, err := a.createRequest(ctx, "GET", endpoint+"?"+params.Encode(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get branches: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get branches: %s", resp.Status)
	}

	var response azureValueResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	var branchNames []string
	for _, branchData := range response.Value {
		var branch azureBranch
		if err := json.Unmarshal(branchData, &branch); err != nil {
			continue
		}
		// Remove refs/heads/ prefix
		branchName := strings.TrimPrefix(branch.Name, "refs/heads/")
		branchNames = append(branchNames, branchName)
	}

	return branchNames, nil
}

// GetRepositoryCommits gets repository commits
func (a *AzureDevOpsConnector) GetRepositoryCommits(ctx context.Context, repo *repository.Repository, branch string, limit int) ([]repository.Commit, error) {
	project, repoName := a.parseFullName(repo.FullName)
	if branch == "" {
		branch = repo.DefaultBranch
		if branch == "" {
			branch = "main"
		}
	}

	endpoint := fmt.Sprintf("/%s/%s/_apis/git/repositories/%s/commits",
		url.QueryEscape(a.organization), url.QueryEscape(project), url.QueryEscape(repoName))

	params := url.Values{}
	params.Set("searchCriteria.itemVersion.version", branch)
	params.Set("searchCriteria.itemVersion.versionType", "branch")
	if limit > 0 {
		params.Set("$top", fmt.Sprintf("%d", limit))
	}
	params.Set("api-version", "7.0")

	req, err := a.createRequest(ctx, "GET", endpoint+"?"+params.Encode(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get commits: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get commits: %s", resp.Status)
	}

	var response azureValueResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	var commits []repository.Commit
	for _, commitData := range response.Value {
		var commit azureCommit
		if err := json.Unmarshal(commitData, &commit); err != nil {
			continue
		}
		commits = append(commits, a.convertCommit(&commit))
	}

	return commits, nil
}

// CreateWebhook creates a webhook
func (a *AzureDevOpsConnector) CreateWebhook(ctx context.Context, repo *repository.Repository, webhookURL string, events []string) error {
	return a.webhookManager.CreateWebhook(ctx, repo, webhookURL, events)
}

// DeleteWebhook deletes a webhook
func (a *AzureDevOpsConnector) DeleteWebhook(ctx context.Context, repo *repository.Repository, webhookID string) error {
	return a.webhookManager.DeleteWebhook(ctx, repo, webhookID)
}

// ListWebhooks lists webhooks
func (a *AzureDevOpsConnector) ListWebhooks(ctx context.Context, repo *repository.Repository) ([]repository.Webhook, error) {
	return a.webhookManager.ListWebhooks(ctx, repo)
}

// executeRequestWithRetry executes an HTTP request with retry logic
func (a *AzureDevOpsConnector) executeRequestWithRetry(ctx context.Context, req *http.Request) (*http.Response, error) {
	var lastErr error
	delay := a.retryConfig.InitialDelay

	for attempt := 0; attempt <= a.retryConfig.MaxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
				// Calculate next delay with exponential backoff
				delay = time.Duration(float64(delay) * a.retryConfig.BackoffFactor)
				if delay > a.retryConfig.MaxDelay {
					delay = a.retryConfig.MaxDelay
				}
			}
		}

		// Clone request for retry attempts
		reqClone := req.Clone(ctx)
		resp, err := a.client.Do(reqClone)
		if err != nil {
			lastErr = err
			continue
		}

		// Check if we should retry based on status code
		if !a.shouldRetry(resp.StatusCode) {
			return resp, nil
		}

		resp.Body.Close()
		lastErr = fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	return nil, fmt.Errorf("request failed after %d attempts: %w", a.retryConfig.MaxRetries+1, lastErr)
}

// shouldRetry determines if a request should be retried based on status code
func (a *AzureDevOpsConnector) shouldRetry(statusCode int) bool {
	return statusCode == 429 || // Rate limited
		statusCode == 502 || // Bad Gateway
		statusCode == 503 || // Service Unavailable
		statusCode == 504 // Gateway Timeout
}

// AzureWebhookManager methods

// CreateWebhook creates a new service hook for the repository
func (wm *AzureWebhookManager) CreateWebhook(ctx context.Context, repo *repository.Repository, webhookURL string, events []string) error {
	project, repoName := wm.connector.parseFullName(repo.FullName)
	endpoint := fmt.Sprintf("/%s/_apis/hooks/subscriptions", url.PathEscape(wm.connector.organization))

	// Azure DevOps service hook configuration
	serviceHookData := map[string]interface{}{
		"publisherId":      "tfs",
		"eventType":        "git.push", // Default to git push events
		"resourceVersion":  "1.0",
		"consumerId":       "webHooks",
		"consumerActionId": "httpRequest",
		"publisherInputs": map[string]interface{}{
			"projectId":  project,
			"repository": repoName,
		},
		"consumerInputs": map[string]interface{}{
			"url":               webhookURL,
			"httpHeaders":       "Content-Type:application/json",
			"basicAuthUsername": "",
			"basicAuthPassword": "",
		},
	}

	body, err := json.Marshal(serviceHookData)
	if err != nil {
		return fmt.Errorf("failed to marshal service hook data: %w", err)
	}

	req, err := wm.connector.createRequest(ctx, "POST", endpoint, strings.NewReader(string(body)))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := wm.connector.executeRequestWithRetry(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to create service hook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to create service hook: HTTP %d", resp.StatusCode)
	}

	// Parse response to get service hook ID
	var hookResp map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&hookResp); err != nil {
		return fmt.Errorf("failed to decode service hook response: %w", err)
	}

	hookID, ok := hookResp["id"].(string)
	if !ok {
		return fmt.Errorf("service hook ID not found in response")
	}

	// Store webhook in manager
	wm.mu.Lock()
	wm.webhooks[hookID] = &repository.Webhook{
		ID:     hookID,
		URL:    webhookURL,
		Events: events,
		Active: true,
	}
	wm.mu.Unlock()

	return nil
}

// DeleteWebhook deletes a service hook from the repository
func (wm *AzureWebhookManager) DeleteWebhook(ctx context.Context, repo *repository.Repository, webhookID string) error {
	endpoint := fmt.Sprintf("/%s/_apis/hooks/subscriptions/%s", url.PathEscape(wm.connector.organization), url.PathEscape(webhookID))

	req, err := wm.connector.createRequest(ctx, "DELETE", endpoint, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := wm.connector.executeRequestWithRetry(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to delete service hook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to delete service hook: HTTP %d", resp.StatusCode)
	}

	// Remove webhook from manager
	wm.mu.Lock()
	delete(wm.webhooks, webhookID)
	wm.mu.Unlock()

	return nil
}

// ListWebhooks lists all service hooks for the organization
func (wm *AzureWebhookManager) ListWebhooks(ctx context.Context, repo *repository.Repository) ([]repository.Webhook, error) {
	endpoint := fmt.Sprintf("/%s/_apis/hooks/subscriptions", url.PathEscape(wm.connector.organization))

	req, err := wm.connector.createRequest(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := wm.connector.executeRequestWithRetry(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to list service hooks: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to list service hooks: HTTP %d", resp.StatusCode)
	}

	var response azureValueResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	var hookList []map[string]interface{}
	for _, hookData := range response.Value {
		var hook map[string]interface{}
		if err := json.Unmarshal(hookData, &hook); err != nil {
			continue
		}
		hookList = append(hookList, hook)
	}

	webhooks := make([]repository.Webhook, 0, len(hookList))
	for _, hook := range hookList {
		webhook := repository.Webhook{
			ID:     fmt.Sprintf("%v", hook["id"]),
			Active: true, // Azure DevOps doesn't have explicit active status
		}

		// Extract URL from consumer inputs
		if consumerInputs, ok := hook["consumerInputs"].(map[string]interface{}); ok {
			if url, ok := consumerInputs["url"].(string); ok {
				webhook.URL = url
			}
		}

		// Extract event type
		if eventType, ok := hook["eventType"].(string); ok {
			webhook.Events = []string{eventType}
		}

		webhooks = append(webhooks, webhook)
	}

	return webhooks, nil
}

// GetRateLimit gets rate limit information (not available)
func (a *AzureDevOpsConnector) GetRateLimit(ctx context.Context) (*repository.RateLimit, error) {
	// Azure DevOps doesn't provide rate limit information
	return &repository.RateLimit{
		Limit:     1000, // Default assumption
		Remaining: 1000,
		ResetTime: time.Now().Add(time.Hour),
		Used:      0,
	}, nil
}

// HealthCheck performs a health check
func (a *AzureDevOpsConnector) HealthCheck(ctx context.Context) error {
	return a.ValidateAuth(ctx)
}

// Close closes the connector
func (a *AzureDevOpsConnector) Close() error {
	return nil
}

// Helper methods

func (a *AzureDevOpsConnector) createRequest(ctx context.Context, method, endpoint string, body io.Reader) (*http.Request, error) {
	url := a.baseURL + endpoint
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", a.userAgent)
	req.Header.Set("Accept", "application/json")
	if a.apiToken != "" {
		req.Header.Set("Authorization", "Basic "+a.apiToken) // Azure DevOps uses Basic auth with PAT
	}

	return req, nil
}

func (a *AzureDevOpsConnector) listProjects(ctx context.Context) ([]azureProject, error) {
	endpoint := fmt.Sprintf("/%s/_apis/projects", url.QueryEscape(a.organization))
	params := url.Values{}
	params.Set("api-version", "7.0")

	req, err := a.createRequest(ctx, "GET", endpoint+"?"+params.Encode(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to list projects: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to list projects: %s", resp.Status)
	}

	var response azureValueResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	var projects []azureProject
	for _, projectData := range response.Value {
		var project azureProject
		if err := json.Unmarshal(projectData, &project); err != nil {
			continue
		}
		projects = append(projects, project)
	}

	return projects, nil
}

func (a *AzureDevOpsConnector) listRepositoriesForProject(ctx context.Context, project string, filter *repository.RepositoryFilter) ([]*repository.Repository, error) {
	endpoint := fmt.Sprintf("/%s/%s/_apis/git/repositories",
		url.QueryEscape(a.organization), url.QueryEscape(project))

	params := url.Values{}
	params.Set("api-version", "7.0")

	req, err := a.createRequest(ctx, "GET", endpoint+"?"+params.Encode(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to list repositories: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to list repositories: %s", resp.Status)
	}

	var response azureValueResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	var repositories []*repository.Repository
	for _, repoData := range response.Value {
		var repo azureRepository
		if err := json.Unmarshal(repoData, &repo); err != nil {
			continue
		}
		convertedRepo := a.convertRepository(&repo)
		if filter == nil || a.matchesFilter(convertedRepo, filter) {
			repositories = append(repositories, convertedRepo)
		}
	}

	return repositories, nil
}

func (a *AzureDevOpsConnector) convertRepository(repo *azureRepository) *repository.Repository {
	defaultBranch := strings.TrimPrefix(repo.DefaultBranch, "refs/heads/")
	if defaultBranch == "" {
		defaultBranch = "main"
	}

	fullName := fmt.Sprintf("%s/%s", repo.Project.Name, repo.Name)

	return &repository.Repository{
		ID:            repo.ID,
		Name:          repo.Name,
		FullName:      fullName,
		URL:           repo.WebURL,
		CloneURL:      repo.RemoteURL,
		SSHURL:        repo.SSHURL,
		DefaultBranch: defaultBranch,
		Language:      "", // Not available in Azure DevOps API
		Private:       repo.Project.Visibility == "private",
		Archived:      repo.IsDisabled,
		Fork:          repo.IsFork,
		Size:          repo.Size,
		StarCount:     0,           // Not available in Azure DevOps
		ForkCount:     0,           // Not available in Azure DevOps
		Topics:        []string{},  // Not available in Azure DevOps
		CreatedAt:     time.Time{}, // Not available in basic API
		UpdatedAt:     repo.Project.LastUpdateTime,
		PushedAt:      repo.Project.LastUpdateTime,
		Platform:      "azuredevops",
		Owner: repository.Owner{
			ID:    repo.Project.ID,
			Login: repo.Project.Name,
			Name:  repo.Project.Name,
			Type:  "project",
		},
		Metadata: map[string]interface{}{
			"project_id":          repo.Project.ID,
			"project_description": repo.Project.Description,
			"project_state":       repo.Project.State,
			"project_visibility":  repo.Project.Visibility,
			"organization":        a.organization,
		},
	}
}

func (a *AzureDevOpsConnector) convertCommit(commit *azureCommit) repository.Commit {
	return repository.Commit{
		SHA:     commit.CommitID,
		Message: commit.Comment,
		Author:  commit.Author.Name,
		Email:   commit.Author.Email,
		Date:    commit.Author.Date,
		URL:     commit.RemoteURL,
	}
}

func (a *AzureDevOpsConnector) matchesFilter(repo *repository.Repository, filter *repository.RepositoryFilter) bool {
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

	// Check minimum stars (not applicable for Azure DevOps)
	if filter.MinStars > 0 && repo.StarCount < filter.MinStars {
		return false
	}

	// Check maximum size
	if filter.MaxSize > 0 && repo.Size > filter.MaxSize {
		return false
	}

	// Check languages (not available in Azure DevOps)
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

func (a *AzureDevOpsConnector) parseFullName(fullName string) (project, repo string) {
	parts := strings.Split(fullName, "/")
	if len(parts) >= 2 {
		return parts[0], parts[1]
	}
	return "", fullName
}
