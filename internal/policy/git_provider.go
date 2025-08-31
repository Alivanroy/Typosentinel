package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// DefaultGitProvider implements the GitProvider interface
type DefaultGitProvider struct {
	client *http.Client
	config *GitProviderConfig
}

// GitProviderConfig configuration for Git provider
type GitProviderConfig struct {
	Provider   string            `json:"provider"` // github, gitlab, bitbucket
	BaseURL    string            `json:"base_url"`
	Token      string            `json:"token"`
	Username   string            `json:"username"`
	Timeout    time.Duration     `json:"timeout"`
	MaxRetries int               `json:"max_retries"`
	RetryDelay time.Duration     `json:"retry_delay"`
	UserAgent  string            `json:"user_agent"`
	Headers    map[string]string `json:"headers"`
}

// GitHubCreateBranchRequest represents a GitHub create branch request
type GitHubCreateBranchRequest struct {
	Ref string `json:"ref"`
	SHA string `json:"sha"`
}

// GitHubCommitRequest represents a GitHub commit request
type GitHubCommitRequest struct {
	Message   string             `json:"message"`
	Tree      string             `json:"tree"`
	Parents   []string           `json:"parents"`
	Author    GitHubCommitAuthor `json:"author"`
	Committer GitHubCommitAuthor `json:"committer"`
}

// GitHubCommitAuthor represents commit author information
type GitHubCommitAuthor struct {
	Name  string `json:"name"`
	Email string `json:"email"`
	Date  string `json:"date"`
}

// GitHubPullRequestRequest represents a GitHub PR request
type GitHubPullRequestRequest struct {
	Title               string `json:"title"`
	Head                string `json:"head"`
	Base                string `json:"base"`
	Body                string `json:"body"`
	MaintainerCanModify bool   `json:"maintainer_can_modify"`
	Draft               bool   `json:"draft"`
}

// GitHubPullRequestResponse represents a GitHub PR response
type GitHubPullRequestResponse struct {
	ID     int    `json:"id"`
	Number int    `json:"number"`
	URL    string `json:"html_url"`
	State  string `json:"state"`
}

// NewDefaultGitProvider creates a new Git provider
func NewDefaultGitProvider(config *GitProviderConfig) *DefaultGitProvider {
	if config == nil {
		config = &GitProviderConfig{
			Provider:   "github",
			BaseURL:    "https://api.github.com",
			Timeout:    30 * time.Second,
			MaxRetries: 3,
			RetryDelay: 1 * time.Second,
			UserAgent:  "Typosentinel/1.0",
			Headers:    make(map[string]string),
		}
	}

	return &DefaultGitProvider{
		client: &http.Client{
			Timeout: config.Timeout,
		},
		config: config,
	}
}

// CreateBranch creates a new branch in the repository
func (gp *DefaultGitProvider) CreateBranch(ctx context.Context, repo *Repository, branchName string, baseBranch string) error {
	if repo == nil {
		return fmt.Errorf("repository cannot be nil")
	}

	switch strings.ToLower(gp.config.Provider) {
	case "github":
		return gp.createGitHubBranch(ctx, repo, branchName, baseBranch)
	case "gitlab":
		return gp.createGitLabBranch(ctx, repo, branchName, baseBranch)
	case "bitbucket":
		return gp.createBitbucketBranch(ctx, repo, branchName, baseBranch)
	default:
		return fmt.Errorf("unsupported Git provider: %s", gp.config.Provider)
	}
}

// CommitFiles commits file changes to a branch
func (gp *DefaultGitProvider) CommitFiles(ctx context.Context, repo *Repository, branch string, changes []FileChange, message string) error {
	if repo == nil {
		return fmt.Errorf("repository cannot be nil")
	}

	switch strings.ToLower(gp.config.Provider) {
	case "github":
		return gp.commitGitHubFiles(ctx, repo, branch, changes, message)
	case "gitlab":
		return gp.commitGitLabFiles(ctx, repo, branch, changes, message)
	case "bitbucket":
		return gp.commitBitbucketFiles(ctx, repo, branch, changes, message)
	default:
		return fmt.Errorf("unsupported Git provider: %s", gp.config.Provider)
	}
}

// CreatePullRequest creates a pull request
func (gp *DefaultGitProvider) CreatePullRequest(ctx context.Context, repo *Repository, pr *PullRequestSpec) (*PRResult, error) {
	if repo == nil {
		return nil, fmt.Errorf("repository cannot be nil")
	}
	if pr == nil {
		return nil, fmt.Errorf("pull request spec cannot be nil")
	}

	switch strings.ToLower(gp.config.Provider) {
	case "github":
		return gp.createGitHubPullRequest(ctx, repo, pr)
	case "gitlab":
		return gp.createGitLabPullRequest(ctx, repo, pr)
	case "bitbucket":
		return gp.createBitbucketPullRequest(ctx, repo, pr)
	default:
		return nil, fmt.Errorf("unsupported Git provider: %s", gp.config.Provider)
	}
}

// GetRepository retrieves repository information
func (gp *DefaultGitProvider) GetRepository(ctx context.Context, repoURL string) (*Repository, error) {
	if repoURL == "" {
		return nil, fmt.Errorf("repository URL cannot be empty")
	}

	switch strings.ToLower(gp.config.Provider) {
	case "github":
		return gp.getGitHubRepository(ctx, repoURL)
	case "gitlab":
		return gp.getGitLabRepository(ctx, repoURL)
	case "bitbucket":
		return gp.getBitbucketRepository(ctx, repoURL)
	default:
		return nil, fmt.Errorf("unsupported Git provider: %s", gp.config.Provider)
	}
}

// GitHub-specific implementations

func (gp *DefaultGitProvider) createGitHubBranch(ctx context.Context, repo *Repository, branchName string, baseBranch string) error {
	// First, get the SHA of the base branch
	fullName := fmt.Sprintf("%s/%s", repo.Owner, repo.Name)
	url := fmt.Sprintf("%s/repos/%s/git/refs/heads/%s", gp.config.BaseURL, fullName, baseBranch)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	gp.setAuthHeaders(req)

	resp, err := gp.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to get base branch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to get base branch: %s", resp.Status)
	}

	var refResponse struct {
		Object struct {
			SHA string `json:"sha"`
		} `json:"object"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&refResponse); err != nil {
		return fmt.Errorf("failed to decode base branch response: %w", err)
	}

	// Create the new branch
	createBranchURL := fmt.Sprintf("%s/repos/%s/git/refs", gp.config.BaseURL, fullName)

	branchRequest := GitHubCreateBranchRequest{
		Ref: fmt.Sprintf("refs/heads/%s", branchName),
		SHA: refResponse.Object.SHA,
	}

	reqBody, err := json.Marshal(branchRequest)
	if err != nil {
		return fmt.Errorf("failed to marshal branch request: %w", err)
	}

	req, err = http.NewRequestWithContext(ctx, "POST", createBranchURL, strings.NewReader(string(reqBody)))
	if err != nil {
		return fmt.Errorf("failed to create branch request: %w", err)
	}

	gp.setAuthHeaders(req)
	req.Header.Set("Content-Type", "application/json")

	resp, err = gp.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to create branch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("failed to create branch: %s", resp.Status)
	}

	return nil
}

func (gp *DefaultGitProvider) commitGitHubFiles(ctx context.Context, repo *Repository, branch string, changes []FileChange, message string) error {
	// Simplified implementation - in production, this would handle file trees, blobs, etc.
	// For now, we'll just simulate the commit
	fullName := fmt.Sprintf("%s/%s", repo.Owner, repo.Name)
	fmt.Printf("Simulating GitHub commit to %s/%s: %s\n", fullName, branch, message)
	fmt.Printf("Files changed: %d\n", len(changes))
	return nil
}

func (gp *DefaultGitProvider) createGitHubPullRequest(ctx context.Context, repo *Repository, pr *PullRequestSpec) (*PRResult, error) {
	fullName := fmt.Sprintf("%s/%s", repo.Owner, repo.Name)
	url := fmt.Sprintf("%s/repos/%s/pulls", gp.config.BaseURL, fullName)

	prRequest := GitHubPullRequestRequest{
		Title:               pr.Title,
		Head:                pr.HeadBranch,
		Base:                pr.BaseBranch,
		Body:                pr.Description,
		MaintainerCanModify: true,
		Draft:               pr.Draft,
	}

	reqBody, err := json.Marshal(prRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal PR request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(string(reqBody)))
	if err != nil {
		return nil, fmt.Errorf("failed to create PR request: %w", err)
	}

	gp.setAuthHeaders(req)
	req.Header.Set("Content-Type", "application/json")

	resp, err := gp.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to create pull request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("failed to create pull request: %s", resp.Status)
	}

	var prResponse GitHubPullRequestResponse
	if err := json.NewDecoder(resp.Body).Decode(&prResponse); err != nil {
		return nil, fmt.Errorf("failed to decode PR response: %w", err)
	}

	return &PRResult{
		PRNumber:   prResponse.Number,
		PRURL:      prResponse.URL,
		BranchName: pr.HeadBranch,
		Success:    true,
	}, nil
}

func (gp *DefaultGitProvider) getGitHubRepository(ctx context.Context, repoURL string) (*Repository, error) {
	// Extract owner/repo from URL
	parts := strings.Split(strings.TrimSuffix(repoURL, ".git"), "/")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid repository URL: %s", repoURL)
	}

	owner := parts[len(parts)-2]
	name := parts[len(parts)-1]
	fullName := fmt.Sprintf("%s/%s", owner, name)

	url := fmt.Sprintf("%s/repos/%s", gp.config.BaseURL, fullName)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	gp.setAuthHeaders(req)

	resp, err := gp.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get repository: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get repository: %s", resp.Status)
	}

	var repoResponse struct {
		ID            int    `json:"id"`
		Name          string `json:"name"`
		FullName      string `json:"full_name"`
		DefaultBranch string `json:"default_branch"`
		CloneURL      string `json:"clone_url"`
		SSHURL        string `json:"ssh_url"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&repoResponse); err != nil {
		return nil, fmt.Errorf("failed to decode repository response: %w", err)
	}

	return &Repository{
		URL:           repoResponse.CloneURL,
		Owner:         owner,
		Name:          repoResponse.Name,
		DefaultBranch: repoResponse.DefaultBranch,
		ClonePath:     "",
	}, nil
}

// GitLab and Bitbucket provider implementations

func (gp *DefaultGitProvider) createGitLabBranch(ctx context.Context, repo *Repository, branchName string, baseBranch string) error {
	// GitLab uses project ID or namespace/project format
	projectPath := fmt.Sprintf("%s/%s", repo.Owner, repo.Name)
	url := fmt.Sprintf("%s/projects/%s/repository/branches", gp.config.BaseURL, strings.ReplaceAll(projectPath, "/", "%2F"))

	branchRequest := map[string]string{
		"branch": branchName,
		"ref":    baseBranch,
	}

	reqBody, err := json.Marshal(branchRequest)
	if err != nil {
		return fmt.Errorf("failed to marshal branch request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(string(reqBody)))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	gp.setAuthHeaders(req)
	req.Header.Set("Content-Type", "application/json")

	resp, err := gp.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to create GitLab branch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("failed to create GitLab branch: %s", resp.Status)
	}

	return nil
}

func (gp *DefaultGitProvider) commitGitLabFiles(ctx context.Context, repo *Repository, branch string, changes []FileChange, message string) error {
	projectPath := fmt.Sprintf("%s/%s", repo.Owner, repo.Name)
	url := fmt.Sprintf("%s/projects/%s/repository/commits", gp.config.BaseURL, strings.ReplaceAll(projectPath, "/", "%2F"))

	// Convert file changes to GitLab format
	actions := make([]map[string]interface{}, 0, len(changes))
	for _, change := range changes {
		action := map[string]interface{}{
			"action":    "update", // or "create", "delete"
			"file_path": change.Path,
			"content":   change.Content,
		}
		actions = append(actions, action)
	}

	commitRequest := map[string]interface{}{
		"branch":         branch,
		"commit_message": message,
		"actions":        actions,
	}

	reqBody, err := json.Marshal(commitRequest)
	if err != nil {
		return fmt.Errorf("failed to marshal commit request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(string(reqBody)))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	gp.setAuthHeaders(req)
	req.Header.Set("Content-Type", "application/json")

	resp, err := gp.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to commit GitLab files: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("failed to commit GitLab files: %s", resp.Status)
	}

	return nil
}

func (gp *DefaultGitProvider) createGitLabPullRequest(ctx context.Context, repo *Repository, pr *PullRequestSpec) (*PRResult, error) {
	projectPath := fmt.Sprintf("%s/%s", repo.Owner, repo.Name)
	url := fmt.Sprintf("%s/projects/%s/merge_requests", gp.config.BaseURL, strings.ReplaceAll(projectPath, "/", "%2F"))

	mrRequest := map[string]interface{}{
		"source_branch": pr.HeadBranch,
		"target_branch": pr.BaseBranch,
		"title":         pr.Title,
		"description":   pr.Description,
	}

	reqBody, err := json.Marshal(mrRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal MR request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(string(reqBody)))
	if err != nil {
		return nil, fmt.Errorf("failed to create MR request: %w", err)
	}

	gp.setAuthHeaders(req)
	req.Header.Set("Content-Type", "application/json")

	resp, err := gp.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to create GitLab merge request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("failed to create GitLab merge request: %s", resp.Status)
	}

	var mrResponse struct {
		IID    int    `json:"iid"`
		WebURL string `json:"web_url"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&mrResponse); err != nil {
		return nil, fmt.Errorf("failed to decode MR response: %w", err)
	}

	return &PRResult{
		PRNumber:   mrResponse.IID,
		PRURL:      mrResponse.WebURL,
		BranchName: pr.HeadBranch,
		Success:    true,
	}, nil
}

func (gp *DefaultGitProvider) getGitLabRepository(ctx context.Context, repoURL string) (*Repository, error) {
	// Extract owner/repo from URL
	parts := strings.Split(strings.TrimSuffix(repoURL, ".git"), "/")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid repository URL: %s", repoURL)
	}

	owner := parts[len(parts)-2]
	name := parts[len(parts)-1]
	projectPath := fmt.Sprintf("%s/%s", owner, name)

	url := fmt.Sprintf("%s/projects/%s", gp.config.BaseURL, strings.ReplaceAll(projectPath, "/", "%2F"))

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	gp.setAuthHeaders(req)

	resp, err := gp.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get GitLab repository: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get GitLab repository: %s", resp.Status)
	}

	var repoResponse struct {
		ID                int    `json:"id"`
		Name              string `json:"name"`
		PathWithNamespace string `json:"path_with_namespace"`
		DefaultBranch     string `json:"default_branch"`
		HTTPURLToRepo     string `json:"http_url_to_repo"`
		SSHURLToRepo      string `json:"ssh_url_to_repo"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&repoResponse); err != nil {
		return nil, fmt.Errorf("failed to decode GitLab repository response: %w", err)
	}

	return &Repository{
		URL:           repoResponse.HTTPURLToRepo,
		Owner:         owner,
		Name:          repoResponse.Name,
		DefaultBranch: repoResponse.DefaultBranch,
		ClonePath:     "",
	}, nil
}

func (gp *DefaultGitProvider) createBitbucketBranch(ctx context.Context, repo *Repository, branchName string, baseBranch string) error {
	// Bitbucket uses workspace/repo_slug format
	workspace := repo.Owner
	repoSlug := repo.Name
	url := fmt.Sprintf("%s/repositories/%s/%s/refs/branches", gp.config.BaseURL, workspace, repoSlug)

	branchRequest := map[string]interface{}{
		"name": branchName,
		"target": map[string]string{
			"hash": baseBranch, // In real implementation, you'd need to get the commit hash
		},
	}

	reqBody, err := json.Marshal(branchRequest)
	if err != nil {
		return fmt.Errorf("failed to marshal branch request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(string(reqBody)))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	gp.setAuthHeaders(req)
	req.Header.Set("Content-Type", "application/json")

	resp, err := gp.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to create Bitbucket branch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("failed to create Bitbucket branch: %s", resp.Status)
	}

	return nil
}

func (gp *DefaultGitProvider) commitBitbucketFiles(ctx context.Context, repo *Repository, branch string, changes []FileChange, message string) error {
	// Bitbucket doesn't have a direct commit API like GitLab
	// You would typically need to use the file API to update individual files
	// This is a simplified implementation

	for _, change := range changes {
		// In a real implementation, you'd use multipart form data to upload files
		// via the Bitbucket API: POST /repositories/{workspace}/{repo_slug}/src
		// For now, we'll just log the operation
		fmt.Printf("Bitbucket file update: %s on branch %s (message: %s)\n", change.Path, branch, message)
	}

	return nil
}

func (gp *DefaultGitProvider) createBitbucketPullRequest(ctx context.Context, repo *Repository, pr *PullRequestSpec) (*PRResult, error) {
	workspace := repo.Owner
	repoSlug := repo.Name
	url := fmt.Sprintf("%s/repositories/%s/%s/pullrequests", gp.config.BaseURL, workspace, repoSlug)

	prRequest := map[string]interface{}{
		"title":       pr.Title,
		"description": pr.Description,
		"source": map[string]interface{}{
			"branch": map[string]string{
				"name": pr.HeadBranch,
			},
		},
		"destination": map[string]interface{}{
			"branch": map[string]string{
				"name": pr.BaseBranch,
			},
		},
	}

	reqBody, err := json.Marshal(prRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal PR request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(string(reqBody)))
	if err != nil {
		return nil, fmt.Errorf("failed to create PR request: %w", err)
	}

	gp.setAuthHeaders(req)
	req.Header.Set("Content-Type", "application/json")

	resp, err := gp.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to create Bitbucket pull request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("failed to create Bitbucket pull request: %s", resp.Status)
	}

	var prResponse struct {
		ID    int `json:"id"`
		Links struct {
			HTML struct {
				Href string `json:"href"`
			} `json:"html"`
		} `json:"links"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&prResponse); err != nil {
		return nil, fmt.Errorf("failed to decode PR response: %w", err)
	}

	return &PRResult{
		PRNumber:   prResponse.ID,
		PRURL:      prResponse.Links.HTML.Href,
		BranchName: pr.HeadBranch,
		Success:    true,
	}, nil
}

func (gp *DefaultGitProvider) getBitbucketRepository(ctx context.Context, repoURL string) (*Repository, error) {
	// Extract workspace and repo slug from URL
	// Expected format: https://bitbucket.org/workspace/repo-slug
	parts := strings.Split(strings.TrimPrefix(repoURL, "https://bitbucket.org/"), "/")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid Bitbucket repository URL: %s", repoURL)
	}

	workspace := parts[0]
	repoSlug := parts[1]

	url := fmt.Sprintf("%s/repositories/%s/%s", gp.config.BaseURL, workspace, repoSlug)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	gp.setAuthHeaders(req)

	resp, err := gp.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get Bitbucket repository: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get Bitbucket repository: %s", resp.Status)
	}

	var repoResponse struct {
		Name       string `json:"name"`
		FullName   string `json:"full_name"`
		MainBranch struct {
			Name string `json:"name"`
		} `json:"mainbranch"`
		Owner struct {
			Username string `json:"username"`
		} `json:"owner"`
		Links struct {
			Clone []struct {
				Name string `json:"name"`
				Href string `json:"href"`
			} `json:"clone"`
		} `json:"links"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&repoResponse); err != nil {
		return nil, fmt.Errorf("failed to decode repository response: %w", err)
	}

	// Find HTTPS clone URL
	cloneURL := repoURL
	for _, link := range repoResponse.Links.Clone {
		if link.Name == "https" {
			cloneURL = link.Href
			break
		}
	}

	defaultBranch := "main"
	if repoResponse.MainBranch.Name != "" {
		defaultBranch = repoResponse.MainBranch.Name
	}

	return &Repository{
		URL:           cloneURL,
		Owner:         repoResponse.Owner.Username,
		Name:          repoResponse.Name,
		DefaultBranch: defaultBranch,
		ClonePath:     "",
	}, nil
}

// Helper methods

func (gp *DefaultGitProvider) setAuthHeaders(req *http.Request) {
	req.Header.Set("User-Agent", gp.config.UserAgent)

	if gp.config.Token != "" {
		switch strings.ToLower(gp.config.Provider) {
		case "github":
			req.Header.Set("Authorization", fmt.Sprintf("token %s", gp.config.Token))
		case "gitlab":
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", gp.config.Token))
		case "bitbucket":
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", gp.config.Token))
		}
	}

	// Set custom headers
	for key, value := range gp.config.Headers {
		req.Header.Set(key, value)
	}
}
