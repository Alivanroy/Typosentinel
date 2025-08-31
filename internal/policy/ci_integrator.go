package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// CIIntegratorImpl implements the CIIntegrator interface
type CIIntegratorImpl struct {
	config *CIIntegratorConfig
	client *http.Client
	logger Logger
}

// CIIntegratorConfig configuration for CI integrator
type CIIntegratorConfig struct {
	Enabled         bool                        `json:"enabled"`
	Providers       map[string]CIProviderConfig `json:"providers"`
	DefaultProvider string                      `json:"default_provider"`
	Timeout         time.Duration               `json:"timeout"`
	RetryAttempts   int                         `json:"retry_attempts"`
}

// CIProviderConfig configuration for a specific CI provider
type CIProviderConfig struct {
	Type    string            `json:"type"` // github, gitlab, jenkins, azure_devops, circleci
	BaseURL string            `json:"base_url"`
	Token   string            `json:"token"`
	Headers map[string]string `json:"headers"`
	Enabled bool              `json:"enabled"`
}

// PipelineStatus represents the status of a CI/CD pipeline
type PipelineStatus struct {
	ID        string     `json:"id"`
	Status    string     `json:"status"` // running, blocked, success, failed, cancelled
	Branch    string     `json:"branch"`
	Commit    string     `json:"commit"`
	BlockedAt *time.Time `json:"blocked_at,omitempty"`
	BlockedBy string     `json:"blocked_by,omitempty"`
	Reason    string     `json:"reason,omitempty"`
}

// NewCIIntegratorImpl creates a new CI integrator implementation
func NewCIIntegratorImpl(config *CIIntegratorConfig, logger Logger) *CIIntegratorImpl {
	if config == nil {
		config = &CIIntegratorConfig{
			Enabled:         false,
			Providers:       make(map[string]CIProviderConfig),
			DefaultProvider: "github",
			Timeout:         30 * time.Second,
			RetryAttempts:   3,
		}
	}

	client := &http.Client{
		Timeout: config.Timeout,
	}

	return &CIIntegratorImpl{
		config: config,
		client: client,
		logger: logger,
	}
}

// BlockPipeline blocks a CI/CD pipeline
func (ci *CIIntegratorImpl) BlockPipeline(ctx context.Context, repoURL, branch string) error {
	if !ci.config.Enabled {
		return fmt.Errorf("CI integration is disabled")
	}

	provider, err := ci.getProviderForRepo(repoURL)
	if err != nil {
		return fmt.Errorf("failed to determine CI provider: %w", err)
	}

	providerConfig, exists := ci.config.Providers[provider]
	if !exists || !providerConfig.Enabled {
		return fmt.Errorf("provider %s not configured or disabled", provider)
	}

	switch providerConfig.Type {
	case "github":
		return ci.blockGitHubPipeline(ctx, repoURL, branch, &providerConfig)
	case "gitlab":
		return ci.blockGitLabPipeline(ctx, repoURL, branch, &providerConfig)
	case "jenkins":
		return ci.blockJenkinsPipeline(ctx, repoURL, branch, &providerConfig)
	case "azure_devops":
		return ci.blockAzureDevOpsPipeline(ctx, repoURL, branch, &providerConfig)
	case "circleci":
		return ci.blockCircleCIPipeline(ctx, repoURL, branch, &providerConfig)
	default:
		return fmt.Errorf("unsupported CI provider type: %s", providerConfig.Type)
	}
}

// UnblockPipeline unblocks a CI/CD pipeline
func (ci *CIIntegratorImpl) UnblockPipeline(ctx context.Context, repoURL, branch string) error {
	if !ci.config.Enabled {
		return fmt.Errorf("CI integration is disabled")
	}

	provider, err := ci.getProviderForRepo(repoURL)
	if err != nil {
		return fmt.Errorf("failed to determine CI provider: %w", err)
	}

	providerConfig, exists := ci.config.Providers[provider]
	if !exists || !providerConfig.Enabled {
		return fmt.Errorf("provider %s not configured or disabled", provider)
	}

	switch providerConfig.Type {
	case "github":
		return ci.unblockGitHubPipeline(ctx, repoURL, branch, &providerConfig)
	case "gitlab":
		return ci.unblockGitLabPipeline(ctx, repoURL, branch, &providerConfig)
	case "jenkins":
		return ci.unblockJenkinsPipeline(ctx, repoURL, branch, &providerConfig)
	case "azure_devops":
		return ci.unblockAzureDevOpsPipeline(ctx, repoURL, branch, &providerConfig)
	case "circleci":
		return ci.unblockCircleCIPipeline(ctx, repoURL, branch, &providerConfig)
	default:
		return fmt.Errorf("unsupported CI provider type: %s", providerConfig.Type)
	}
}

// GetPipelineStatus gets the status of a CI/CD pipeline
func (ci *CIIntegratorImpl) GetPipelineStatus(ctx context.Context, repoURL, branch string) (string, error) {
	if !ci.config.Enabled {
		return "unknown", fmt.Errorf("CI integration is disabled")
	}

	provider, err := ci.getProviderForRepo(repoURL)
	if err != nil {
		return "unknown", fmt.Errorf("failed to determine CI provider: %w", err)
	}

	providerConfig, exists := ci.config.Providers[provider]
	if !exists || !providerConfig.Enabled {
		return "unknown", fmt.Errorf("provider %s not configured or disabled", provider)
	}

	switch providerConfig.Type {
	case "github":
		return ci.getGitHubPipelineStatus(ctx, repoURL, branch, &providerConfig)
	case "gitlab":
		return ci.getGitLabPipelineStatus(ctx, repoURL, branch, &providerConfig)
	case "jenkins":
		return ci.getJenkinsPipelineStatus(ctx, repoURL, branch, &providerConfig)
	case "azure_devops":
		return ci.getAzureDevOpsPipelineStatus(ctx, repoURL, branch, &providerConfig)
	case "circleci":
		return ci.getCircleCIPipelineStatus(ctx, repoURL, branch, &providerConfig)
	default:
		return "unknown", fmt.Errorf("unsupported CI provider type: %s", providerConfig.Type)
	}
}

// getProviderForRepo determines the CI provider based on repository URL
func (ci *CIIntegratorImpl) getProviderForRepo(repoURL string) (string, error) {
	repoURL = strings.ToLower(repoURL)

	if strings.Contains(repoURL, "github.com") {
		return "github", nil
	}
	if strings.Contains(repoURL, "gitlab.com") || strings.Contains(repoURL, "gitlab") {
		return "gitlab", nil
	}
	if strings.Contains(repoURL, "dev.azure.com") || strings.Contains(repoURL, "visualstudio.com") {
		return "azure_devops", nil
	}

	// Default to configured default provider
	if ci.config.DefaultProvider != "" {
		return ci.config.DefaultProvider, nil
	}

	return "", fmt.Errorf("unable to determine CI provider for repository: %s", repoURL)
}

// GitHub implementation
func (ci *CIIntegratorImpl) blockGitHubPipeline(ctx context.Context, repoURL, branch string, config *CIProviderConfig) error {
	// Extract owner and repo from URL
	owner, repo, err := ci.parseGitHubURL(repoURL)
	if err != nil {
		return err
	}

	// Create a deployment protection rule or update branch protection
	url := fmt.Sprintf("%s/repos/%s/%s/branches/%s/protection", config.BaseURL, owner, repo, branch)

	payload := map[string]interface{}{
		"required_status_checks": map[string]interface{}{
			"strict":   true,
			"contexts": []string{"typosentinel/security-check"},
		},
		"enforce_admins": true,
		"required_pull_request_reviews": map[string]interface{}{
			"required_approving_review_count": 1,
		},
		"restrictions": nil,
	}

	return ci.makeAPIRequest(ctx, "PUT", url, payload, config)
}

func (ci *CIIntegratorImpl) unblockGitHubPipeline(ctx context.Context, repoURL, branch string, config *CIProviderConfig) error {
	// Extract owner and repo from URL
	owner, repo, err := ci.parseGitHubURL(repoURL)
	if err != nil {
		return err
	}

	// Remove branch protection or update to allow deployments
	url := fmt.Sprintf("%s/repos/%s/%s/branches/%s/protection", config.BaseURL, owner, repo, branch)

	return ci.makeAPIRequest(ctx, "DELETE", url, nil, config)
}

func (ci *CIIntegratorImpl) getGitHubPipelineStatus(ctx context.Context, repoURL, branch string, config *CIProviderConfig) (string, error) {
	// Extract owner and repo from URL
	owner, repo, err := ci.parseGitHubURL(repoURL)
	if err != nil {
		return "unknown", err
	}

	// Get the latest commit status
	url := fmt.Sprintf("%s/repos/%s/%s/commits/%s/status", config.BaseURL, owner, repo, branch)

	resp, err := ci.makeAPIRequestWithResponse(ctx, "GET", url, nil, config)
	if err != nil {
		return "unknown", err
	}

	var status struct {
		State string `json:"state"`
	}

	if err := json.Unmarshal(resp, &status); err != nil {
		return "unknown", err
	}

	return status.State, nil
}

// GitLab implementation
func (ci *CIIntegratorImpl) blockGitLabPipeline(ctx context.Context, repoURL, branch string, config *CIProviderConfig) error {
	// Extract project ID from URL
	projectID, err := ci.parseGitLabURL(repoURL)
	if err != nil {
		return err
	}

	// Create or update branch protection rules
	url := fmt.Sprintf("%s/api/v4/projects/%s/protected_branches", config.BaseURL, projectID)

	payload := map[string]interface{}{
		"name":                         branch,
		"push_access_level":            40, // Maintainer level
		"merge_access_level":           40, // Maintainer level
		"code_owner_approval_required": true,
	}

	return ci.makeAPIRequest(ctx, "POST", url, payload, config)
}

func (ci *CIIntegratorImpl) unblockGitLabPipeline(ctx context.Context, repoURL, branch string, config *CIProviderConfig) error {
	// Extract project ID from URL
	projectID, err := ci.parseGitLabURL(repoURL)
	if err != nil {
		return err
	}

	// Remove branch protection
	url := fmt.Sprintf("%s/api/v4/projects/%s/protected_branches/%s", config.BaseURL, projectID, branch)

	return ci.makeAPIRequest(ctx, "DELETE", url, nil, config)
}

func (ci *CIIntegratorImpl) getGitLabPipelineStatus(ctx context.Context, repoURL, branch string, config *CIProviderConfig) (string, error) {
	// Extract project ID from URL
	projectID, err := ci.parseGitLabURL(repoURL)
	if err != nil {
		return "unknown", err
	}

	// Get the latest pipeline for the branch
	url := fmt.Sprintf("%s/api/v4/projects/%s/pipelines?ref=%s&per_page=1", config.BaseURL, projectID, branch)

	resp, err := ci.makeAPIRequestWithResponse(ctx, "GET", url, nil, config)
	if err != nil {
		return "unknown", err
	}

	var pipelines []struct {
		Status string `json:"status"`
	}

	if err := json.Unmarshal(resp, &pipelines); err != nil {
		return "unknown", err
	}

	if len(pipelines) == 0 {
		return "unknown", nil
	}

	return pipelines[0].Status, nil
}

// Jenkins implementation
func (ci *CIIntegratorImpl) blockJenkinsPipeline(ctx context.Context, repoURL, branch string, config *CIProviderConfig) error {
	// Extract job name from repo URL or use configured job name
	jobName := ci.extractJenkinsJobName(repoURL)

	// Disable the job
	url := fmt.Sprintf("%s/job/%s/disable", config.BaseURL, jobName)

	return ci.makeAPIRequest(ctx, "POST", url, nil, config)
}

func (ci *CIIntegratorImpl) unblockJenkinsPipeline(ctx context.Context, repoURL, branch string, config *CIProviderConfig) error {
	// Extract job name from repo URL or use configured job name
	jobName := ci.extractJenkinsJobName(repoURL)

	// Enable the job
	url := fmt.Sprintf("%s/job/%s/enable", config.BaseURL, jobName)

	return ci.makeAPIRequest(ctx, "POST", url, nil, config)
}

func (ci *CIIntegratorImpl) getJenkinsPipelineStatus(ctx context.Context, repoURL, branch string, config *CIProviderConfig) (string, error) {
	// Extract job name from repo URL or use configured job name
	jobName := ci.extractJenkinsJobName(repoURL)

	// Get job status
	url := fmt.Sprintf("%s/job/%s/api/json", config.BaseURL, jobName)

	resp, err := ci.makeAPIRequestWithResponse(ctx, "GET", url, nil, config)
	if err != nil {
		return "unknown", err
	}

	var jobInfo struct {
		Buildable bool   `json:"buildable"`
		Color     string `json:"color"`
	}

	if err := json.Unmarshal(resp, &jobInfo); err != nil {
		return "unknown", err
	}

	if !jobInfo.Buildable {
		return "blocked", nil
	}

	// Map Jenkins color to status
	switch jobInfo.Color {
	case "blue":
		return "success", nil
	case "red":
		return "failed", nil
	case "yellow":
		return "unstable", nil
	case "blue_anime", "red_anime", "yellow_anime":
		return "running", nil
	default:
		return "unknown", nil
	}
}

// Azure DevOps implementation
func (ci *CIIntegratorImpl) blockAzureDevOpsPipeline(ctx context.Context, repoURL, branch string, config *CIProviderConfig) error {
	org, project, repo, err := ci.parseAzureDevOpsURL(repoURL)
	if err != nil {
		return err
	}

	// Create branch policy to block builds
	url := fmt.Sprintf("%s/%s/%s/_apis/policy/configurations?api-version=6.0", config.BaseURL, org, project)

	payload := map[string]interface{}{
		"isEnabled":  true,
		"isBlocking": true,
		"type": map[string]interface{}{
			"id": "fa4e907d-c16b-4a4c-9dfa-4906e5d171dd", // Build policy type ID
		},
		"settings": map[string]interface{}{
			"buildDefinitionId":       0, // You might need to get this dynamically
			"queueOnSourceUpdateOnly": false,
			"manualQueueOnly":         true,
			"displayName":             "TypoSentinel Security Block",
			"scope": []map[string]interface{}{
				{
					"repositoryId": repo,
					"refName":      fmt.Sprintf("refs/heads/%s", branch),
					"matchKind":    "exact",
				},
			},
		},
	}

	return ci.makeAPIRequest(ctx, "POST", url, payload, config)
}

func (ci *CIIntegratorImpl) unblockAzureDevOpsPipeline(ctx context.Context, repoURL, branch string, config *CIProviderConfig) error {
	org, project, _, err := ci.parseAzureDevOpsURL(repoURL)
	if err != nil {
		return err
	}

	// List and delete relevant policies
	url := fmt.Sprintf("%s/%s/%s/_apis/policy/configurations?api-version=6.0", config.BaseURL, org, project)

	resp, err := ci.makeAPIRequestWithResponse(ctx, "GET", url, nil, config)
	if err != nil {
		return err
	}

	var policies struct {
		Value []struct {
			ID       int `json:"id"`
			Settings struct {
				DisplayName string `json:"displayName"`
			} `json:"settings"`
		} `json:"value"`
	}

	if err := json.Unmarshal(resp, &policies); err != nil {
		return err
	}

	// Delete TypoSentinel policies
	for _, policy := range policies.Value {
		if strings.Contains(policy.Settings.DisplayName, "TypoSentinel") {
			deleteURL := fmt.Sprintf("%s/%s/%s/_apis/policy/configurations/%d?api-version=6.0", config.BaseURL, org, project, policy.ID)
			ci.makeAPIRequest(ctx, "DELETE", deleteURL, nil, config)
		}
	}

	return nil
}

func (ci *CIIntegratorImpl) getAzureDevOpsPipelineStatus(ctx context.Context, repoURL, branch string, config *CIProviderConfig) (string, error) {
	org, project, _, err := ci.parseAzureDevOpsURL(repoURL)
	if err != nil {
		return "unknown", err
	}

	// Get recent builds for the branch
	url := fmt.Sprintf("%s/%s/%s/_apis/build/builds?branchName=refs/heads/%s&$top=1&api-version=6.0", config.BaseURL, org, project, branch)

	resp, err := ci.makeAPIRequestWithResponse(ctx, "GET", url, nil, config)
	if err != nil {
		return "unknown", err
	}

	var builds struct {
		Value []struct {
			Status string `json:"status"`
			Result string `json:"result"`
		} `json:"value"`
	}

	if err := json.Unmarshal(resp, &builds); err != nil {
		return "unknown", err
	}

	if len(builds.Value) == 0 {
		return "unknown", nil
	}

	build := builds.Value[0]
	if build.Status == "inProgress" {
		return "running", nil
	}

	switch build.Result {
	case "succeeded":
		return "success", nil
	case "failed":
		return "failed", nil
	case "canceled":
		return "cancelled", nil
	default:
		return "unknown", nil
	}
}

// CircleCI implementation
func (ci *CIIntegratorImpl) blockCircleCIPipeline(ctx context.Context, repoURL, branch string, config *CIProviderConfig) error {
	vcsType, org, repo, err := ci.parseCircleCIURL(repoURL)
	if err != nil {
		return err
	}

	// CircleCI doesn't have direct pipeline blocking, so we'll use project settings
	// to disable builds for the specific branch by updating project environment variables
	url := fmt.Sprintf("%s/api/v2/project/%s/%s/%s/envvar", config.BaseURL, vcsType, org, repo)

	payload := map[string]interface{}{
		"name":  fmt.Sprintf("TYPOSENTINEL_BLOCK_%s", strings.ToUpper(strings.ReplaceAll(branch, "-", "_"))),
		"value": "true",
	}

	return ci.makeAPIRequest(ctx, "POST", url, payload, config)
}

func (ci *CIIntegratorImpl) unblockCircleCIPipeline(ctx context.Context, repoURL, branch string, config *CIProviderConfig) error {
	vcsType, org, repo, err := ci.parseCircleCIURL(repoURL)
	if err != nil {
		return err
	}

	// Remove the blocking environment variable
	envVarName := fmt.Sprintf("TYPOSENTINEL_BLOCK_%s", strings.ToUpper(strings.ReplaceAll(branch, "-", "_")))
	url := fmt.Sprintf("%s/api/v2/project/%s/%s/%s/envvar/%s", config.BaseURL, vcsType, org, repo, envVarName)

	return ci.makeAPIRequest(ctx, "DELETE", url, nil, config)
}

func (ci *CIIntegratorImpl) getCircleCIPipelineStatus(ctx context.Context, repoURL, branch string, config *CIProviderConfig) (string, error) {
	vcsType, org, repo, err := ci.parseCircleCIURL(repoURL)
	if err != nil {
		return "unknown", err
	}

	// Get recent pipelines for the project
	url := fmt.Sprintf("%s/api/v2/project/%s/%s/%s/pipeline?branch=%s", config.BaseURL, vcsType, org, repo, branch)

	resp, err := ci.makeAPIRequestWithResponse(ctx, "GET", url, nil, config)
	if err != nil {
		return "unknown", err
	}

	var pipelines struct {
		Items []struct {
			State string `json:"state"`
		} `json:"items"`
	}

	if err := json.Unmarshal(resp, &pipelines); err != nil {
		return "unknown", err
	}

	if len(pipelines.Items) == 0 {
		return "unknown", nil
	}

	// Map CircleCI states to our standard states
	switch pipelines.Items[0].State {
	case "success":
		return "success", nil
	case "failed", "error":
		return "failed", nil
	case "running":
		return "running", nil
	case "canceled", "cancelled":
		return "cancelled", nil
	case "on_hold":
		return "blocked", nil
	default:
		return "unknown", nil
	}
}

// Helper functions
func (ci *CIIntegratorImpl) parseGitHubURL(repoURL string) (owner, repo string, err error) {
	// Parse GitHub URL to extract owner and repo
	// Example: https://github.com/owner/repo -> owner, repo
	parts := strings.Split(strings.TrimSuffix(repoURL, ".git"), "/")
	if len(parts) < 2 {
		return "", "", fmt.Errorf("invalid GitHub URL format: %s", repoURL)
	}

	// Get the last two parts (owner/repo)
	repo = parts[len(parts)-1]
	owner = parts[len(parts)-2]

	return owner, repo, nil
}

func (ci *CIIntegratorImpl) parseGitLabURL(repoURL string) (string, error) {
	// Parse URL like https://gitlab.com/group/project
	u, err := url.Parse(repoURL)
	if err != nil {
		return "", err
	}

	// For GitLab, we need to URL encode the project path
	projectPath := strings.Trim(u.Path, "/")
	if projectPath == "" {
		return "", fmt.Errorf("invalid GitLab URL format")
	}

	// URL encode the project path for API usage
	return url.QueryEscape(projectPath), nil
}

func (ci *CIIntegratorImpl) extractJenkinsJobName(repoURL string) string {
	// Extract job name from repository URL
	// This is a simple implementation - in practice, you might want to configure job mappings
	u, err := url.Parse(repoURL)
	if err != nil {
		// Fallback to a sanitized version of the URL
		return strings.ReplaceAll(strings.ReplaceAll(repoURL, "/", "-"), ":", "-")
	}

	// Use the repository name as job name
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) > 0 {
		jobName := parts[len(parts)-1]
		// Remove .git suffix if present
		jobName = strings.TrimSuffix(jobName, ".git")
		return jobName
	}

	return "default-job"
}

func (ci *CIIntegratorImpl) parseAzureDevOpsURL(repoURL string) (org, project, repo string, err error) {
	// Parse Azure DevOps URL like https://dev.azure.com/org/project/_git/repo
	u, err := url.Parse(repoURL)
	if err != nil {
		return "", "", "", err
	}

	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) < 4 {
		return "", "", "", fmt.Errorf("invalid Azure DevOps URL format: %s", repoURL)
	}

	// Expected format: /org/project/_git/repo
	org = parts[0]
	project = parts[1]
	if len(parts) >= 4 && parts[2] == "_git" {
		repo = parts[3]
	} else {
		repo = parts[len(parts)-1]
	}

	return org, project, repo, nil
}

func (ci *CIIntegratorImpl) parseCircleCIURL(repoURL string) (vcsType, org, repo string, err error) {
	// Parse repository URL to extract VCS type, organization, and repository
	// CircleCI supports GitHub and Bitbucket
	if strings.Contains(repoURL, "github.com") {
		vcsType = "github"
	} else if strings.Contains(repoURL, "bitbucket.org") {
		vcsType = "bitbucket"
	} else {
		vcsType = "github" // Default to GitHub
	}

	u, err := url.Parse(repoURL)
	if err != nil {
		return "", "", "", err
	}

	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) < 2 {
		return "", "", "", fmt.Errorf("invalid repository URL format: %s", repoURL)
	}

	org = parts[0]
	repo = strings.TrimSuffix(parts[1], ".git")

	return vcsType, org, repo, nil
}

func (ci *CIIntegratorImpl) makeAPIRequest(ctx context.Context, method, url string, payload interface{}, config *CIProviderConfig) error {
	_, err := ci.makeAPIRequestWithResponse(ctx, method, url, payload, config)
	return err
}

func (ci *CIIntegratorImpl) makeAPIRequestWithResponse(ctx context.Context, method, url string, payload interface{}, config *CIProviderConfig) ([]byte, error) {
	var body io.Reader
	if payload != nil {
		jsonData, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		body = bytes.NewBuffer(jsonData)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, err
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	if config.Token != "" {
		if strings.Contains(url, "github.com") {
			req.Header.Set("Authorization", "token "+config.Token)
		} else if strings.Contains(url, "gitlab") {
			req.Header.Set("Private-Token", config.Token)
		} else {
			req.Header.Set("Authorization", "Bearer "+config.Token)
		}
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}
