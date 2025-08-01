package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
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
	Enabled       bool                      `json:"enabled"`
	Providers     map[string]CIProviderConfig `json:"providers"`
	DefaultProvider string                   `json:"default_provider"`
	Timeout       time.Duration             `json:"timeout"`
	RetryAttempts int                       `json:"retry_attempts"`
}

// CIProviderConfig configuration for a specific CI provider
type CIProviderConfig struct {
	Type     string            `json:"type"` // github, gitlab, jenkins, azure_devops, circleci
	BaseURL  string            `json:"base_url"`
	Token    string            `json:"token"`
	Headers  map[string]string `json:"headers"`
	Enabled  bool              `json:"enabled"`
}

// PipelineStatus represents the status of a CI/CD pipeline
type PipelineStatus struct {
	ID       string    `json:"id"`
	Status   string    `json:"status"` // running, blocked, success, failed, cancelled
	Branch   string    `json:"branch"`
	Commit   string    `json:"commit"`
	BlockedAt *time.Time `json:"blocked_at,omitempty"`
	BlockedBy string    `json:"blocked_by,omitempty"`
	Reason   string    `json:"reason,omitempty"`
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
			"strict": true,
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

// GitLab implementation (placeholder)
func (ci *CIIntegratorImpl) blockGitLabPipeline(ctx context.Context, repoURL, branch string, config *CIProviderConfig) error {
	ci.logger.Info("GitLab pipeline blocking not yet implemented", "repo", repoURL, "branch", branch)
	return fmt.Errorf("GitLab integration not yet implemented")
}

func (ci *CIIntegratorImpl) unblockGitLabPipeline(ctx context.Context, repoURL, branch string, config *CIProviderConfig) error {
	ci.logger.Info("GitLab pipeline unblocking not yet implemented", "repo", repoURL, "branch", branch)
	return fmt.Errorf("GitLab integration not yet implemented")
}

func (ci *CIIntegratorImpl) getGitLabPipelineStatus(ctx context.Context, repoURL, branch string, config *CIProviderConfig) (string, error) {
	ci.logger.Info("GitLab pipeline status check not yet implemented", "repo", repoURL, "branch", branch)
	return "unknown", fmt.Errorf("GitLab integration not yet implemented")
}

// Jenkins implementation (placeholder)
func (ci *CIIntegratorImpl) blockJenkinsPipeline(ctx context.Context, repoURL, branch string, config *CIProviderConfig) error {
	ci.logger.Info("Jenkins pipeline blocking not yet implemented", "repo", repoURL, "branch", branch)
	return fmt.Errorf("Jenkins integration not yet implemented")
}

func (ci *CIIntegratorImpl) unblockJenkinsPipeline(ctx context.Context, repoURL, branch string, config *CIProviderConfig) error {
	ci.logger.Info("Jenkins pipeline unblocking not yet implemented", "repo", repoURL, "branch", branch)
	return fmt.Errorf("Jenkins integration not yet implemented")
}

func (ci *CIIntegratorImpl) getJenkinsPipelineStatus(ctx context.Context, repoURL, branch string, config *CIProviderConfig) (string, error) {
	ci.logger.Info("Jenkins pipeline status check not yet implemented", "repo", repoURL, "branch", branch)
	return "unknown", fmt.Errorf("Jenkins integration not yet implemented")
}

// Azure DevOps implementation (placeholder)
func (ci *CIIntegratorImpl) blockAzureDevOpsPipeline(ctx context.Context, repoURL, branch string, config *CIProviderConfig) error {
	ci.logger.Info("Azure DevOps pipeline blocking not yet implemented", "repo", repoURL, "branch", branch)
	return fmt.Errorf("Azure DevOps integration not yet implemented")
}

func (ci *CIIntegratorImpl) unblockAzureDevOpsPipeline(ctx context.Context, repoURL, branch string, config *CIProviderConfig) error {
	ci.logger.Info("Azure DevOps pipeline unblocking not yet implemented", "repo", repoURL, "branch", branch)
	return fmt.Errorf("Azure DevOps integration not yet implemented")
}

func (ci *CIIntegratorImpl) getAzureDevOpsPipelineStatus(ctx context.Context, repoURL, branch string, config *CIProviderConfig) (string, error) {
	ci.logger.Info("Azure DevOps pipeline status check not yet implemented", "repo", repoURL, "branch", branch)
	return "unknown", fmt.Errorf("Azure DevOps integration not yet implemented")
}

// CircleCI implementation (placeholder)
func (ci *CIIntegratorImpl) blockCircleCIPipeline(ctx context.Context, repoURL, branch string, config *CIProviderConfig) error {
	ci.logger.Info("CircleCI pipeline blocking not yet implemented", "repo", repoURL, "branch", branch)
	return fmt.Errorf("CircleCI integration not yet implemented")
}

func (ci *CIIntegratorImpl) unblockCircleCIPipeline(ctx context.Context, repoURL, branch string, config *CIProviderConfig) error {
	ci.logger.Info("CircleCI pipeline unblocking not yet implemented", "repo", repoURL, "branch", branch)
	return fmt.Errorf("CircleCI integration not yet implemented")
}

func (ci *CIIntegratorImpl) getCircleCIPipelineStatus(ctx context.Context, repoURL, branch string, config *CIProviderConfig) (string, error) {
	ci.logger.Info("CircleCI pipeline status check not yet implemented", "repo", repoURL, "branch", branch)
	return "unknown", fmt.Errorf("CircleCI integration not yet implemented")
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

func (ci *CIIntegratorImpl) makeAPIRequest(ctx context.Context, method, url string, payload interface{}, config *CIProviderConfig) error {
	_, err := ci.makeAPIRequestWithResponse(ctx, method, url, payload, config)
	return err
}

func (ci *CIIntegratorImpl) makeAPIRequestWithResponse(ctx context.Context, method, url string, payload interface{}, config *CIProviderConfig) ([]byte, error) {
	var req *http.Request
	var err error

	if payload != nil {
		payloadBytes, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal payload: %w", err)
		}
		req, err = http.NewRequestWithContext(ctx, method, url, strings.NewReader(string(payloadBytes)))
	} else {
		req, err = http.NewRequestWithContext(ctx, method, url, nil)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("token %s", config.Token))
	req.Header.Set("User-Agent", "TypoSentinel/1.0")

	// Add custom headers
	for key, value := range config.Headers {
		req.Header.Set(key, value)
	}

	resp, err := ci.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("API request failed with status %d", resp.StatusCode)
	}

	body := make([]byte, 0)
	if resp.ContentLength > 0 {
		body = make([]byte, resp.ContentLength)
		_, err = resp.Body.Read(body)
		if err != nil {
			return nil, fmt.Errorf("failed to read response body: %w", err)
		}
	}

	return body, nil
}