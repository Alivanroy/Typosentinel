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

// BitbucketConnector implements the Connector interface for Bitbucket
type BitbucketConnector struct {
	client    *http.Client
	baseURL   string
	apiToken  string
	userAgent string
	config    repository.PlatformConfig
	retryConfig *RetryConfig
	webhookManager *WebhookManager
}

// RetryConfig defines retry behavior for API calls
type RetryConfig struct {
	MaxRetries    int           `json:"max_retries"`
	InitialDelay  time.Duration `json:"initial_delay"`
	MaxDelay      time.Duration `json:"max_delay"`
	BackoffFactor float64       `json:"backoff_factor"`
}

// WebhookManager handles webhook operations
type WebhookManager struct {
	connector *BitbucketConnector
	webhooks  map[string]*repository.Webhook
	mu        sync.RWMutex
}

// Bitbucket API response structures
type bitbucketRepository struct {
	UUID        string    `json:"uuid"`
	Name        string    `json:"name"`
	FullName    string    `json:"full_name"`
	Description *string   `json:"description"`
	Website     *string   `json:"website"`
	Language    *string   `json:"language"`
	IsPrivate   bool      `json:"is_private"`
	ForkPolicy  string    `json:"fork_policy"`
	HasIssues   bool      `json:"has_issues"`
	HasWiki     bool      `json:"has_wiki"`
	Size        int64     `json:"size"`
	CreatedOn   time.Time `json:"created_on"`
	UpdatedOn   time.Time `json:"updated_on"`
	MainBranch  *struct {
		Name string `json:"name"`
	} `json:"mainbranch"`
	Owner bitbucketOwner `json:"owner"`
	Parent *bitbucketRepository `json:"parent"`
	Links struct {
		Clone []struct {
			Name string `json:"name"`
			Href string `json:"href"`
		} `json:"clone"`
		HTML struct {
			Href string `json:"href"`
		} `json:"html"`
	} `json:"links"`
}

type bitbucketOwner struct {
	UUID        string `json:"uuid"`
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	Type        string `json:"type"`
	Links       struct {
		Avatar struct {
			Href string `json:"href"`
		} `json:"avatar"`
		HTML struct {
			Href string `json:"href"`
		} `json:"html"`
	} `json:"links"`
}

type bitbucketWorkspace struct {
	UUID        string `json:"uuid"`
	Name        string `json:"name"`
	Slug        string `json:"slug"`
	Type        string `json:"type"`
	IsPrivate   bool   `json:"is_private"`
	CreatedOn   time.Time `json:"created_on"`
	UpdatedOn   time.Time `json:"updated_on"`
	Links       struct {
		Avatar struct {
			Href string `json:"href"`
		} `json:"avatar"`
		HTML struct {
			Href string `json:"href"`
		} `json:"html"`
	} `json:"links"`
}

type bitbucketCommit struct {
	Hash    string `json:"hash"`
	Message string `json:"message"`
	Author  struct {
		Raw  string `json:"raw"`
		User *struct {
			DisplayName string `json:"display_name"`
			Username    string `json:"username"`
		} `json:"user"`
	} `json:"author"`
	Date  time.Time `json:"date"`
	Links struct {
		HTML struct {
			Href string `json:"href"`
		} `json:"html"`
	} `json:"links"`
}

type bitbucketBranch struct {
	Name   string          `json:"name"`
	Target bitbucketCommit `json:"target"`
	Type   string          `json:"type"`
	Links  struct {
		Commits struct {
			Href string `json:"href"`
		} `json:"commits"`
		HTML struct {
			Href string `json:"href"`
		} `json:"html"`
	} `json:"links"`
}

type bitbucketFile struct {
	Path     string `json:"path"`
	Type     string `json:"type"`
	Size     int64  `json:"size"`
	MimeType string `json:"mimetype"`
	Links    struct {
		Self struct {
			Href string `json:"href"`
		} `json:"self"`
	} `json:"links"`
}

type bitbucketPaginatedResponse struct {
	Values   json.RawMessage `json:"values"`
	Page     int             `json:"page"`
	Pagelen  int             `json:"pagelen"`
	Size     int             `json:"size"`
	Next     *string         `json:"next"`
	Previous *string         `json:"previous"`
}

// NewBitbucketConnector creates a new Bitbucket connector
func NewBitbucketConnector(config repository.PlatformConfig) (*BitbucketConnector, error) {
	baseURL := config.BaseURL
	if baseURL == "" {
		baseURL = "https://api.bitbucket.org/2.0"
	}

	connector := &BitbucketConnector{
		client:    &http.Client{Timeout: config.Timeout},
		baseURL:   baseURL,
		apiToken:  config.Auth.Token,
		userAgent: "TypoSentinel/1.0",
		config:    config,
		retryConfig: &RetryConfig{
			MaxRetries:    3,
			InitialDelay:  1 * time.Second,
			MaxDelay:      30 * time.Second,
			BackoffFactor: 2.0,
		},
	}
	
	connector.webhookManager = &WebhookManager{
		connector: connector,
		webhooks:  make(map[string]*repository.Webhook),
	}
	
	return connector, nil
}

// GetPlatformName returns the platform name
func (b *BitbucketConnector) GetPlatformName() string {
	return "Bitbucket"
}

// GetPlatformType returns the platform type
func (b *BitbucketConnector) GetPlatformType() string {
	return "git"
}

// GetAPIVersion returns the API version
func (b *BitbucketConnector) GetAPIVersion() string {
	return "2.0"
}

// Authenticate sets up authentication
func (b *BitbucketConnector) Authenticate(ctx context.Context, config repository.AuthConfig) error {
	b.apiToken = config.Token
	return nil
}

// ValidateAuth validates the authentication
func (b *BitbucketConnector) ValidateAuth(ctx context.Context) error {
	req, err := b.createRequest(ctx, "GET", "/user", nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := b.client.Do(req)
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
func (b *BitbucketConnector) RefreshAuth(ctx context.Context) error {
	return nil
}

// ListOrganizations lists workspaces (Bitbucket's equivalent of organizations)
func (b *BitbucketConnector) ListOrganizations(ctx context.Context) ([]*repository.Organization, error) {
	req, err := b.createRequest(ctx, "GET", "/workspaces", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := b.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to list workspaces: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to list workspaces: %s", resp.Status)
	}

	var paginatedResp bitbucketPaginatedResponse
	if err := json.NewDecoder(resp.Body).Decode(&paginatedResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	var workspaces []bitbucketWorkspace
	if err := json.Unmarshal(paginatedResp.Values, &workspaces); err != nil {
		return nil, fmt.Errorf("failed to unmarshal workspaces: %w", err)
	}

	var organizations []*repository.Organization
	for _, workspace := range workspaces {
		organizations = append(organizations, b.convertWorkspace(&workspace))
	}

	return organizations, nil
}

// GetOrganization gets a specific workspace
func (b *BitbucketConnector) GetOrganization(ctx context.Context, name string) (*repository.Organization, error) {
	endpoint := fmt.Sprintf("/workspaces/%s", url.QueryEscape(name))
	req, err := b.createRequest(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := b.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get workspace: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get workspace: %s", resp.Status)
	}

	var workspace bitbucketWorkspace
	if err := json.NewDecoder(resp.Body).Decode(&workspace); err != nil {
		return nil, fmt.Errorf("failed to decode workspace: %w", err)
	}

	return b.convertWorkspace(&workspace), nil
}

// ListRepositories lists repositories for a user
func (b *BitbucketConnector) ListRepositories(ctx context.Context, owner string, filter *repository.RepositoryFilter) ([]*repository.Repository, error) {
	return b.listRepositoriesWithURL(ctx, fmt.Sprintf("/repositories/%s", url.QueryEscape(owner)), filter)
}

// ListOrgRepositories lists repositories for a workspace
func (b *BitbucketConnector) ListOrgRepositories(ctx context.Context, org string, filter *repository.RepositoryFilter) ([]*repository.Repository, error) {
	return b.listRepositoriesWithURL(ctx, fmt.Sprintf("/repositories/%s", url.QueryEscape(org)), filter)
}

// GetRepository gets a specific repository
func (b *BitbucketConnector) GetRepository(ctx context.Context, owner, name string) (*repository.Repository, error) {
	endpoint := fmt.Sprintf("/repositories/%s/%s", url.QueryEscape(owner), url.QueryEscape(name))
	req, err := b.createRequest(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := b.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get repository: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get repository: %s", resp.Status)
	}

	var repo bitbucketRepository
	if err := json.NewDecoder(resp.Body).Decode(&repo); err != nil {
		return nil, fmt.Errorf("failed to decode repository: %w", err)
	}

	return b.convertRepository(&repo), nil
}

// SearchRepositories searches for repositories
func (b *BitbucketConnector) SearchRepositories(ctx context.Context, query string, filter *repository.RepositoryFilter) ([]*repository.Repository, error) {
	// Bitbucket search is limited, so we'll list all and filter
	return b.listRepositoriesWithURL(ctx, "/repositories", filter)
}

// GetRepositoryContent gets file content from repository
func (b *BitbucketConnector) GetRepositoryContent(ctx context.Context, repo *repository.Repository, filePath string, ref string) ([]byte, error) {
	owner, name := b.parseFullName(repo.FullName)
	if ref == "" {
		ref = repo.DefaultBranch
	}

	endpoint := fmt.Sprintf("/repositories/%s/%s/src/%s/%s", 
		url.QueryEscape(owner), url.QueryEscape(name), url.QueryEscape(ref), url.QueryEscape(filePath))

	req, err := b.createRequest(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := b.client.Do(req)
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
func (b *BitbucketConnector) ListRepositoryFiles(ctx context.Context, repo *repository.Repository, dirPath string, ref string) ([]string, error) {
	owner, name := b.parseFullName(repo.FullName)
	if ref == "" {
		ref = repo.DefaultBranch
	}

	endpoint := fmt.Sprintf("/repositories/%s/%s/src/%s/%s", 
		url.QueryEscape(owner), url.QueryEscape(name), url.QueryEscape(ref), url.QueryEscape(dirPath))

	req, err := b.createRequest(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := b.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to list files: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to list files: %s", resp.Status)
	}

	var paginatedResp bitbucketPaginatedResponse
	if err := json.NewDecoder(resp.Body).Decode(&paginatedResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	var files []bitbucketFile
	if err := json.Unmarshal(paginatedResp.Values, &files); err != nil {
		return nil, fmt.Errorf("failed to unmarshal files: %w", err)
	}

	var filePaths []string
	for _, file := range files {
		filePaths = append(filePaths, file.Path)
	}

	return filePaths, nil
}

// GetPackageFiles gets package manager files
func (b *BitbucketConnector) GetPackageFiles(ctx context.Context, repo *repository.Repository, ref string) (map[string][]byte, error) {
	packageFiles := map[string][]byte{}
	commonFiles := []string{"package.json", "requirements.txt", "Gemfile", "pom.xml", "build.gradle", "Cargo.toml", "go.mod"}

	for _, file := range commonFiles {
		content, err := b.GetRepositoryContent(ctx, repo, file, ref)
		if err == nil {
			packageFiles[file] = content
		}
	}

	return packageFiles, nil
}

// GetRepositoryLanguages gets repository languages (not directly supported by Bitbucket API)
func (b *BitbucketConnector) GetRepositoryLanguages(ctx context.Context, repo *repository.Repository) (map[string]int, error) {
	// Bitbucket doesn't provide language statistics like GitHub
	// Return the primary language if available
	languages := make(map[string]int)
	if repo.Language != "" {
		languages[repo.Language] = 100
	}
	return languages, nil
}

// GetRepositoryTopics gets repository topics (not directly supported by Bitbucket API)
func (b *BitbucketConnector) GetRepositoryTopics(ctx context.Context, repo *repository.Repository) ([]string, error) {
	return repo.Topics, nil
}

// GetRepositoryBranches gets repository branches
func (b *BitbucketConnector) GetRepositoryBranches(ctx context.Context, repo *repository.Repository) ([]string, error) {
	owner, name := b.parseFullName(repo.FullName)
	endpoint := fmt.Sprintf("/repositories/%s/%s/refs/branches", url.QueryEscape(owner), url.QueryEscape(name))

	req, err := b.createRequest(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := b.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get branches: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get branches: %s", resp.Status)
	}

	var paginatedResp bitbucketPaginatedResponse
	if err := json.NewDecoder(resp.Body).Decode(&paginatedResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	var branches []bitbucketBranch
	if err := json.Unmarshal(paginatedResp.Values, &branches); err != nil {
		return nil, fmt.Errorf("failed to unmarshal branches: %w", err)
	}

	var branchNames []string
	for _, branch := range branches {
		branchNames = append(branchNames, branch.Name)
	}

	return branchNames, nil
}

// GetRepositoryCommits gets repository commits
func (b *BitbucketConnector) GetRepositoryCommits(ctx context.Context, repo *repository.Repository, branch string, limit int) ([]repository.Commit, error) {
	owner, name := b.parseFullName(repo.FullName)
	if branch == "" {
		branch = repo.DefaultBranch
	}

	endpoint := fmt.Sprintf("/repositories/%s/%s/commits/%s", 
		url.QueryEscape(owner), url.QueryEscape(name), url.QueryEscape(branch))

	if limit > 0 {
		endpoint += fmt.Sprintf("?pagelen=%d", limit)
	}

	req, err := b.createRequest(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := b.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get commits: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get commits: %s", resp.Status)
	}

	var paginatedResp bitbucketPaginatedResponse
	if err := json.NewDecoder(resp.Body).Decode(&paginatedResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	var bitbucketCommits []bitbucketCommit
	if err := json.Unmarshal(paginatedResp.Values, &bitbucketCommits); err != nil {
		return nil, fmt.Errorf("failed to unmarshal commits: %w", err)
	}

	var commits []repository.Commit
	for _, commit := range bitbucketCommits {
		commits = append(commits, b.convertCommit(&commit))
	}

	return commits, nil
}

// CreateWebhook creates a webhook
func (b *BitbucketConnector) CreateWebhook(ctx context.Context, repo *repository.Repository, webhookURL string, events []string) error {
	return b.webhookManager.CreateWebhook(ctx, repo, webhookURL, events)
}

// DeleteWebhook deletes a webhook
func (b *BitbucketConnector) DeleteWebhook(ctx context.Context, repo *repository.Repository, webhookID string) error {
	return b.webhookManager.DeleteWebhook(ctx, repo, webhookID)
}

// ListWebhooks lists webhooks
func (b *BitbucketConnector) ListWebhooks(ctx context.Context, repo *repository.Repository) ([]repository.Webhook, error) {
	return b.webhookManager.ListWebhooks(ctx, repo)
}

// WebhookManager methods

// CreateWebhook creates a new webhook for the repository
func (wm *WebhookManager) CreateWebhook(ctx context.Context, repo *repository.Repository, webhookURL string, events []string) error {
	owner, name := wm.connector.parseFullName(repo.FullName)
	endpoint := fmt.Sprintf("/repositories/%s/%s/hooks", owner, name)
	
	webhookData := map[string]interface{}{
		"description": "TypoSentinel Security Webhook",
		"url":         webhookURL,
		"active":      true,
		"events":      events,
	}
	
	body, err := json.Marshal(webhookData)
	if err != nil {
		return fmt.Errorf("failed to marshal webhook data: %w", err)
	}
	
	req, err := wm.connector.createRequest(ctx, "POST", endpoint, strings.NewReader(string(body)))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	
	req.Header.Set("Content-Type", "application/json")
	
	resp, err := wm.connector.executeRequestWithRetry(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to create webhook: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("failed to create webhook: HTTP %d", resp.StatusCode)
	}
	
	// Parse response to get webhook ID
	var webhookResp map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&webhookResp); err != nil {
		return fmt.Errorf("failed to decode webhook response: %w", err)
	}
	
	webhookID, ok := webhookResp["uuid"].(string)
	if !ok {
		return fmt.Errorf("webhook ID not found in response")
	}
	
	// Store webhook in manager
	wm.mu.Lock()
	wm.webhooks[webhookID] = &repository.Webhook{
		ID:     webhookID,
		URL:    webhookURL,
		Events: events,
		Active: true,
	}
	wm.mu.Unlock()
	
	return nil
}

// DeleteWebhook deletes a webhook from the repository
func (wm *WebhookManager) DeleteWebhook(ctx context.Context, repo *repository.Repository, webhookID string) error {
	owner, name := wm.connector.parseFullName(repo.FullName)
	endpoint := fmt.Sprintf("/repositories/%s/%s/hooks/%s", owner, name, webhookID)
	
	req, err := wm.connector.createRequest(ctx, "DELETE", endpoint, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	
	resp, err := wm.connector.executeRequestWithRetry(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to delete webhook: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("failed to delete webhook: HTTP %d", resp.StatusCode)
	}
	
	// Remove webhook from manager
	wm.mu.Lock()
	delete(wm.webhooks, webhookID)
	wm.mu.Unlock()
	
	return nil
}

// ListWebhooks lists all webhooks for the repository
func (wm *WebhookManager) ListWebhooks(ctx context.Context, repo *repository.Repository) ([]repository.Webhook, error) {
	owner, name := wm.connector.parseFullName(repo.FullName)
	endpoint := fmt.Sprintf("/repositories/%s/%s/hooks", owner, name)
	
	req, err := wm.connector.createRequest(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	
	resp, err := wm.connector.executeRequestWithRetry(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to list webhooks: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to list webhooks: HTTP %d", resp.StatusCode)
	}
	
	var response bitbucketPaginatedResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	
	var webhookList []map[string]interface{}
	if err := json.Unmarshal(response.Values, &webhookList); err != nil {
		return nil, fmt.Errorf("failed to unmarshal webhooks: %w", err)
	}
	
	webhooks := make([]repository.Webhook, 0, len(webhookList))
	for _, wh := range webhookList {
		webhook := repository.Webhook{
			ID:     fmt.Sprintf("%v", wh["uuid"]),
			URL:    fmt.Sprintf("%v", wh["url"]),
			Active: wh["active"].(bool),
		}
		
		if events, ok := wh["events"].([]interface{}); ok {
			webhook.Events = make([]string, len(events))
			for i, event := range events {
				webhook.Events[i] = fmt.Sprintf("%v", event)
			}
		}
		
		webhooks = append(webhooks, webhook)
	}
	
	return webhooks, nil
}

// GetRateLimit gets rate limit information (not available in Bitbucket API)
func (b *BitbucketConnector) GetRateLimit(ctx context.Context) (*repository.RateLimit, error) {
	// Bitbucket doesn't provide rate limit information in headers like GitHub
	return &repository.RateLimit{
		Limit:     1000, // Default assumption
		Remaining: 1000,
		ResetTime: time.Now().Add(time.Hour),
		Used:      0,
	}, nil
}

// HealthCheck performs a health check
func (b *BitbucketConnector) HealthCheck(ctx context.Context) error {
	return b.ValidateAuth(ctx)
}

// Close closes the connector
func (b *BitbucketConnector) Close() error {
	return nil
}

// Helper methods

func (b *BitbucketConnector) createRequest(ctx context.Context, method, endpoint string, body io.Reader) (*http.Request, error) {
	url := b.baseURL + endpoint
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", b.userAgent)
	req.Header.Set("Accept", "application/json")
	if b.apiToken != "" {
		req.Header.Set("Authorization", "Bearer "+b.apiToken)
	}

	// Set content length for body requests
	if body != nil {
		if seeker, ok := body.(io.Seeker); ok {
			if size, err := seeker.Seek(0, io.SeekEnd); err == nil {
				req.ContentLength = size
				seeker.Seek(0, io.SeekStart)
			}
		}
	}

	return req, nil
}

// executeRequestWithRetry executes an HTTP request with retry logic
func (b *BitbucketConnector) executeRequestWithRetry(ctx context.Context, req *http.Request) (*http.Response, error) {
	var lastErr error
	delay := b.retryConfig.InitialDelay

	for attempt := 0; attempt <= b.retryConfig.MaxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
				// Continue with retry
			}
			
			// Exponential backoff with jitter
			delay = time.Duration(float64(delay) * b.retryConfig.BackoffFactor)
			if delay > b.retryConfig.MaxDelay {
				delay = b.retryConfig.MaxDelay
			}
		}

		// Clone request for retry attempts
		reqClone := req.Clone(ctx)
		resp, err := b.client.Do(reqClone)
		if err != nil {
			lastErr = err
			continue
		}

		// Check if we should retry based on status code
		if b.shouldRetry(resp.StatusCode) {
			resp.Body.Close()
			lastErr = fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
			continue
		}

		return resp, nil
	}

	return nil, fmt.Errorf("request failed after %d attempts: %w", b.retryConfig.MaxRetries+1, lastErr)
}

// shouldRetry determines if a request should be retried based on status code
func (b *BitbucketConnector) shouldRetry(statusCode int) bool {
	return statusCode == 429 || // Rate limited
		statusCode == 502 || // Bad Gateway
		statusCode == 503 || // Service Unavailable
		statusCode == 504    // Gateway Timeout
}

func (b *BitbucketConnector) listRepositoriesWithURL(ctx context.Context, baseURL string, filter *repository.RepositoryFilter) ([]*repository.Repository, error) {
	req, err := b.createRequest(ctx, "GET", baseURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := b.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to list repositories: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to list repositories: %s", resp.Status)
	}

	var paginatedResp bitbucketPaginatedResponse
	if err := json.NewDecoder(resp.Body).Decode(&paginatedResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	var repos []bitbucketRepository
	if err := json.Unmarshal(paginatedResp.Values, &repos); err != nil {
		return nil, fmt.Errorf("failed to unmarshal repositories: %w", err)
	}

	var repositories []*repository.Repository
	for _, repo := range repos {
		convertedRepo := b.convertRepository(&repo)
		if filter == nil || b.matchesFilter(convertedRepo, filter) {
			repositories = append(repositories, convertedRepo)
		}
	}

	return repositories, nil
}

func (b *BitbucketConnector) convertRepository(repo *bitbucketRepository) *repository.Repository {
	var cloneURL, sshURL string
	for _, link := range repo.Links.Clone {
		if link.Name == "https" {
			cloneURL = link.Href
		} else if link.Name == "ssh" {
			sshURL = link.Href
		}
	}

	defaultBranch := "main"
	if repo.MainBranch != nil {
		defaultBranch = repo.MainBranch.Name
	}

	language := ""
	if repo.Language != nil {
		language = *repo.Language
	}

	return &repository.Repository{
		ID:            repo.UUID,
		Name:          repo.Name,
		FullName:      repo.FullName,
		URL:           repo.Links.HTML.Href,
		CloneURL:      cloneURL,
		SSHURL:        sshURL,
		DefaultBranch: defaultBranch,
		Language:      language,
		Private:       repo.IsPrivate,
		Archived:      false, // Bitbucket doesn't have archived concept
		Fork:          repo.Parent != nil,
		Size:          repo.Size,
		StarCount:     0, // Not available in Bitbucket API
		ForkCount:     0, // Not available in basic API
		Topics:        []string{}, // Not available in basic API
		CreatedAt:     repo.CreatedOn,
		UpdatedAt:     repo.UpdatedOn,
		PushedAt:      repo.UpdatedOn,
		Platform:      "bitbucket",
		Owner: repository.Owner{
			ID:        repo.Owner.UUID,
			Login:     repo.Owner.Username,
			Name:      repo.Owner.DisplayName,
			Type:      repo.Owner.Type,
			AvatarURL: repo.Owner.Links.Avatar.Href,
		},
		Metadata: map[string]interface{}{
			"fork_policy": repo.ForkPolicy,
			"has_issues":  repo.HasIssues,
			"has_wiki":    repo.HasWiki,
		},
	}
}

func (b *BitbucketConnector) convertWorkspace(workspace *bitbucketWorkspace) *repository.Organization {
	return &repository.Organization{
		ID:          workspace.UUID,
		Login:       workspace.Slug,
		Name:        workspace.Name,
		Description: "",
		URL:         workspace.Links.HTML.Href,
		AvatarURL:   workspace.Links.Avatar.Href,
		Type:        workspace.Type,
		Platform:    "bitbucket",
		Metadata: map[string]interface{}{
			"is_private": workspace.IsPrivate,
			"created_on": workspace.CreatedOn,
			"updated_on": workspace.UpdatedOn,
		},
	}
}

func (b *BitbucketConnector) convertCommit(commit *bitbucketCommit) repository.Commit {
	author := commit.Author.Raw
	email := ""
	if commit.Author.User != nil {
		author = commit.Author.User.DisplayName
	}

	return repository.Commit{
		SHA:     commit.Hash,
		Message: commit.Message,
		Author:  author,
		Email:   email,
		Date:    commit.Date,
		URL:     commit.Links.HTML.Href,
	}
}

func (b *BitbucketConnector) matchesFilter(repo *repository.Repository, filter *repository.RepositoryFilter) bool {
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

	// Check topics
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

func (b *BitbucketConnector) parseFullName(fullName string) (owner, name string) {
	parts := strings.Split(fullName, "/")
	if len(parts) >= 2 {
		return url.QueryEscape(parts[0]), url.QueryEscape(parts[1])
	}
	return "", url.QueryEscape(fullName)
}