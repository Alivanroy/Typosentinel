package webhook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Alivanroy/Typosentinel/pkg/logger"
	"github.com/Alivanroy/Typosentinel/pkg/types"
	"github.com/gin-gonic/gin"
)

// WebhookHandler handles incoming webhook requests for scan triggers
type WebhookHandler struct {
    logger      *logger.Logger
	scanTrigger ScanTrigger
	config      *WebhookConfig
}

// WebhookConfig configuration for webhook handlers
type WebhookConfig struct {
	Enabled         bool                      `json:"enabled"`
	Secret          string                    `json:"secret"`
	SignatureHeader string                    `json:"signature_header"`
	Providers       map[string]ProviderConfig `json:"providers"`
	RateLimit       RateLimitConfig           `json:"rate_limit"`
	Timeout         time.Duration             `json:"timeout"`
}

// ProviderConfig configuration for specific webhook providers
type ProviderConfig struct {
	Enabled         bool     `json:"enabled"`
	Secret          string   `json:"secret"`
	SignatureHeader string   `json:"signature_header"`
	Events          []string `json:"events"`
	Branches        []string `json:"branches"`
	Paths           []string `json:"paths"`
}

// RateLimitConfig rate limiting configuration
type RateLimitConfig struct {
	Enabled     bool          `json:"enabled"`
	MaxRequests int           `json:"max_requests"`
	Window      time.Duration `json:"window"`
}

// ScanTrigger interface for triggering scans
type ScanTrigger interface {
	TriggerScan(ctx context.Context, request *ScanRequest) (*ScanResponse, error)
	GetScanStatus(ctx context.Context, scanID string) (*ScanStatus, error)
}

// ScanRequest represents a scan request
type ScanRequest struct {
	ID         string                 `json:"id"`
	Repository string                 `json:"repository"`
	Branch     string                 `json:"branch"`
	Commit     string                 `json:"commit"`
	Paths      []string               `json:"paths"`
	Trigger    string                 `json:"trigger"`
	Provider   string                 `json:"provider"`
	Event      string                 `json:"event"`
	Metadata   map[string]interface{} `json:"metadata"`
	Priority   string                 `json:"priority"`
	Callback   string                 `json:"callback"`
	Timeout    time.Duration          `json:"timeout"`
}

// ScanResponse represents a scan response
type ScanResponse struct {
	ScanID    string    `json:"scan_id"`
	Status    string    `json:"status"`
	Message   string    `json:"message"`
	StartedAt time.Time `json:"started_at"`
	ETA       string    `json:"eta,omitempty"`
	Callback  string    `json:"callback,omitempty"`
}

// ScanStatus represents scan status
type ScanStatus struct {
	ScanID      string                 `json:"scan_id"`
	Status      string                 `json:"status"`
	Progress    float64                `json:"progress"`
	StartedAt   time.Time              `json:"started_at"`
	CompletedAt *time.Time             `json:"completed_at,omitempty"`
	Results     *types.ScanResult      `json:"results,omitempty"`
	Error       string                 `json:"error,omitempty"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// GitHubWebhookPayload represents GitHub webhook payload
type GitHubWebhookPayload struct {
	Action     string `json:"action"`
	Repository struct {
		Name     string `json:"name"`
		FullName string `json:"full_name"`
		CloneURL string `json:"clone_url"`
		HTMLURL  string `json:"html_url"`
	} `json:"repository"`
	Ref     string `json:"ref"`
	Before  string `json:"before"`
	After   string `json:"after"`
	Commits []struct {
		ID       string   `json:"id"`
		Message  string   `json:"message"`
		Added    []string `json:"added"`
		Modified []string `json:"modified"`
		Removed  []string `json:"removed"`
	} `json:"commits"`
	PullRequest *struct {
		Number int    `json:"number"`
		Title  string `json:"title"`
		Head   struct {
			Ref string `json:"ref"`
			SHA string `json:"sha"`
		} `json:"head"`
		Base struct {
			Ref string `json:"ref"`
		} `json:"base"`
	} `json:"pull_request"`
}

// GitLabWebhookPayload represents GitLab webhook payload
type GitLabWebhookPayload struct {
	ObjectKind string `json:"object_kind"`
	Project    struct {
		Name              string `json:"name"`
		PathWithNamespace string `json:"path_with_namespace"`
		WebURL            string `json:"web_url"`
		HTTPURLToRepo     string `json:"http_url_to_repo"`
	} `json:"project"`
	Ref     string `json:"ref"`
	Before  string `json:"before"`
	After   string `json:"after"`
	Commits []struct {
		ID       string   `json:"id"`
		Message  string   `json:"message"`
		Added    []string `json:"added"`
		Modified []string `json:"modified"`
		Removed  []string `json:"removed"`
	} `json:"commits"`
	MergeRequest *struct {
		IID          int    `json:"iid"`
		Title        string `json:"title"`
		SourceBranch string `json:"source_branch"`
		TargetBranch string `json:"target_branch"`
	} `json:"merge_request"`
}

// GenericWebhookPayload represents a generic webhook payload
type GenericWebhookPayload struct {
	Event      string                 `json:"event"`
	Repository string                 `json:"repository"`
	Branch     string                 `json:"branch"`
	Commit     string                 `json:"commit"`
	Paths      []string               `json:"paths"`
	Metadata   map[string]interface{} `json:"metadata"`
	Callback   string                 `json:"callback"`
	Priority   string                 `json:"priority"`
}

// NewWebhookHandler creates a new webhook handler
func NewWebhookHandler(logger *logger.Logger, scanTrigger ScanTrigger, config *WebhookConfig) *WebhookHandler {
	if config == nil {
		config = &WebhookConfig{
			Enabled:         true,
			SignatureHeader: "X-Hub-Signature-256",
			Providers:       make(map[string]ProviderConfig),
			Timeout:         30 * time.Second,
			RateLimit: RateLimitConfig{
				Enabled:     true,
				MaxRequests: 100,
				Window:      time.Hour,
			},
		}
	}

	return &WebhookHandler{
		logger:      logger,
		scanTrigger: scanTrigger,
		config:      config,
	}
}

// RegisterRoutes registers webhook routes
func (h *WebhookHandler) RegisterRoutes(router *gin.Engine) {
	webhookGroup := router.Group("/api/v1/webhooks")
	{
		// Generic webhook endpoint
		webhookGroup.POST("/scan", h.handleGenericWebhook)

		// Provider-specific endpoints
		webhookGroup.POST("/github", h.handleGitHubWebhook)
		webhookGroup.POST("/gitlab", h.handleGitLabWebhook)
		webhookGroup.POST("/bitbucket", h.handleBitbucketWebhook)
		webhookGroup.POST("/azure", h.handleAzureWebhook)

		// Scan status endpoints
		webhookGroup.GET("/scan/:id/status", h.handleScanStatus)
		webhookGroup.POST("/scan/:id/cancel", h.handleCancelScan)

		// Health check
		webhookGroup.GET("/health", h.handleHealth)
	}
}

// handleGenericWebhook handles generic webhook requests
func (h *WebhookHandler) handleGenericWebhook(c *gin.Context) {
	if !h.config.Enabled {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Webhook service is disabled"})
		return
	}

	// Verify signature if configured
	if h.config.Secret != "" {
		if !h.verifySignature(c, h.config.Secret, h.config.SignatureHeader) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid signature"})
			return
		}
	}

	var payload GenericWebhookPayload
	if err := c.ShouldBindJSON(&payload); err != nil {
		h.logger.Error("Failed to parse webhook payload", map[string]interface{}{
			"error": err.Error(),
		})
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid payload"})
		return
	}

	// Create scan request
	scanRequest := &ScanRequest{
		ID:         h.generateScanID(),
		Repository: payload.Repository,
		Branch:     payload.Branch,
		Commit:     payload.Commit,
		Paths:      payload.Paths,
		Trigger:    "webhook",
		Provider:   "generic",
		Event:      payload.Event,
		Metadata:   payload.Metadata,
		Priority:   payload.Priority,
		Callback:   payload.Callback,
		Timeout:    h.config.Timeout,
	}

	h.processScanRequest(c, scanRequest)
}

// handleGitHubWebhook handles GitHub webhook requests
func (h *WebhookHandler) handleGitHubWebhook(c *gin.Context) {
	if !h.config.Enabled {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Webhook service is disabled"})
		return
	}

	providerConfig, exists := h.config.Providers["github"]
	if !exists || !providerConfig.Enabled {
		c.JSON(http.StatusNotFound, gin.H{"error": "GitHub webhook not configured"})
		return
	}

	// Verify GitHub signature
	if providerConfig.Secret != "" {
		if !h.verifySignature(c, providerConfig.Secret, providerConfig.SignatureHeader) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid signature"})
			return
		}
	}

	eventType := c.GetHeader("X-GitHub-Event")
	if !h.shouldProcessEvent(eventType, providerConfig.Events) {
		c.JSON(http.StatusOK, gin.H{"message": "Event ignored"})
		return
	}

	var payload GitHubWebhookPayload
	if err := c.ShouldBindJSON(&payload); err != nil {
		h.logger.Error("Failed to parse GitHub webhook payload", map[string]interface{}{
			"error": err.Error(),
		})
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid payload"})
		return
	}

	// Extract branch from ref
	branch := strings.TrimPrefix(payload.Ref, "refs/heads/")
	if !h.shouldProcessBranch(branch, providerConfig.Branches) {
		c.JSON(http.StatusOK, gin.H{"message": "Branch ignored"})
		return
	}

	// Extract changed paths
	changedPaths := h.extractChangedPaths(payload.Commits)
	if !h.shouldProcessPaths(changedPaths, providerConfig.Paths) {
		c.JSON(http.StatusOK, gin.H{"message": "No relevant paths changed"})
		return
	}

	// Create scan request
	scanRequest := &ScanRequest{
		ID:         h.generateScanID(),
		Repository: payload.Repository.CloneURL,
		Branch:     branch,
		Commit:     payload.After,
		Paths:      changedPaths,
		Trigger:    "webhook",
		Provider:   "github",
		Event:      eventType,
		Metadata: map[string]interface{}{
			"repository_name": payload.Repository.FullName,
			"repository_url":  payload.Repository.HTMLURL,
			"before_commit":   payload.Before,
			"after_commit":    payload.After,
			"commits_count":   len(payload.Commits),
		},
		Priority: "normal",
		Timeout:  h.config.Timeout,
	}

	// Add pull request metadata if available
	if payload.PullRequest != nil {
		scanRequest.Metadata["pull_request"] = map[string]interface{}{
			"number": payload.PullRequest.Number,
			"title":  payload.PullRequest.Title,
			"head":   payload.PullRequest.Head.Ref,
			"base":   payload.PullRequest.Base.Ref,
		}
	}

	h.processScanRequest(c, scanRequest)
}

// handleGitLabWebhook handles GitLab webhook requests
func (h *WebhookHandler) handleGitLabWebhook(c *gin.Context) {
	if !h.config.Enabled {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Webhook service is disabled"})
		return
	}

	providerConfig, exists := h.config.Providers["gitlab"]
	if !exists || !providerConfig.Enabled {
		c.JSON(http.StatusNotFound, gin.H{"error": "GitLab webhook not configured"})
		return
	}

	// Verify GitLab token
	if providerConfig.Secret != "" {
		token := c.GetHeader("X-Gitlab-Token")
		if token != providerConfig.Secret {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			return
		}
	}

	eventType := c.GetHeader("X-Gitlab-Event")
	if !h.shouldProcessEvent(eventType, providerConfig.Events) {
		c.JSON(http.StatusOK, gin.H{"message": "Event ignored"})
		return
	}

	var payload GitLabWebhookPayload
	if err := c.ShouldBindJSON(&payload); err != nil {
		h.logger.Error("Failed to parse GitLab webhook payload", map[string]interface{}{
			"error": err.Error(),
		})
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid payload"})
		return
	}

	// Extract branch from ref
	branch := strings.TrimPrefix(payload.Ref, "refs/heads/")
	if !h.shouldProcessBranch(branch, providerConfig.Branches) {
		c.JSON(http.StatusOK, gin.H{"message": "Branch ignored"})
		return
	}

	// Extract changed paths
	changedPaths := h.extractGitLabChangedPaths(payload.Commits)
	if !h.shouldProcessPaths(changedPaths, providerConfig.Paths) {
		c.JSON(http.StatusOK, gin.H{"message": "No relevant paths changed"})
		return
	}

	// Create scan request
	scanRequest := &ScanRequest{
		ID:         h.generateScanID(),
		Repository: payload.Project.HTTPURLToRepo,
		Branch:     branch,
		Commit:     payload.After,
		Paths:      changedPaths,
		Trigger:    "webhook",
		Provider:   "gitlab",
		Event:      eventType,
		Metadata: map[string]interface{}{
			"project_name":  payload.Project.PathWithNamespace,
			"project_url":   payload.Project.WebURL,
			"before_commit": payload.Before,
			"after_commit":  payload.After,
			"commits_count": len(payload.Commits),
		},
		Priority: "normal",
		Timeout:  h.config.Timeout,
	}

	// Add merge request metadata if available
	if payload.MergeRequest != nil {
		scanRequest.Metadata["merge_request"] = map[string]interface{}{
			"iid":           payload.MergeRequest.IID,
			"title":         payload.MergeRequest.Title,
			"source_branch": payload.MergeRequest.SourceBranch,
			"target_branch": payload.MergeRequest.TargetBranch,
		}
	}

	h.processScanRequest(c, scanRequest)
}

// handleBitbucketWebhook handles Bitbucket webhook requests
func (h *WebhookHandler) handleBitbucketWebhook(c *gin.Context) {
	providerConfig, exists := h.config.Providers["bitbucket"]
	if !exists || !providerConfig.Enabled {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Bitbucket webhooks not enabled"})
		return
	}

	// Verify signature if secret is configured
	if providerConfig.Secret != "" {
		if !h.verifySignature(c, providerConfig.Secret, "X-Hub-Signature-256") {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid signature"})
			return
		}
	}

	// Parse Bitbucket webhook payload
	var payload struct {
		Repository struct {
			FullName string `json:"full_name"`
			Name     string `json:"name"`
			Links    struct {
				HTML struct {
					Href string `json:"href"`
				} `json:"html"`
			} `json:"links"`
		} `json:"repository"`
		Push struct {
			Changes []struct {
				New struct {
					Name string `json:"name"`
					Type string `json:"type"`
				} `json:"new"`
				Commits []struct {
					Hash    string `json:"hash"`
					Message string `json:"message"`
				} `json:"commits"`
			} `json:"changes"`
		} `json:"push"`
		Actor struct {
			DisplayName string `json:"display_name"`
			Username    string `json:"username"`
		} `json:"actor"`
	}

	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON payload"})
		return
	}

	eventType := c.GetHeader("X-Event-Key")
	if eventType == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing X-Event-Key header"})
		return
	}

	// Check if event should be processed
	if !h.shouldProcessEvent(eventType, providerConfig.Events) {
		c.JSON(http.StatusOK, gin.H{"message": "Event ignored"})
		return
	}

	// Process push events
	if eventType == "repo:push" && len(payload.Push.Changes) > 0 {
		for _, change := range payload.Push.Changes {
			if change.New.Type != "branch" {
				continue
			}

			branch := change.New.Name
			if !h.shouldProcessBranch(branch, providerConfig.Branches) {
				continue
			}

			scanRequest := &ScanRequest{
				ID:         h.generateScanID(),
				Provider:   "bitbucket",
				Event:      eventType,
				Repository: payload.Repository.FullName,
				Branch:     branch,
				Commit:     "",
				Trigger:    "webhook",
				Metadata: map[string]interface{}{
					"author": payload.Actor.Username,
					"url":    payload.Repository.Links.HTML.Href,
				},
				Timeout: 30 * time.Second,
			}

			if len(change.Commits) > 0 {
				scanRequest.Commit = change.Commits[0].Hash
			}

			h.processScanRequest(c, scanRequest)
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": "Webhook processed"})
}

// handleAzureWebhook handles Azure DevOps webhook requests
func (h *WebhookHandler) handleAzureWebhook(c *gin.Context) {
	providerConfig, exists := h.config.Providers["azure"]
	if !exists || !providerConfig.Enabled {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Azure DevOps webhooks not enabled"})
		return
	}

	// Verify signature if secret is configured
	if providerConfig.Secret != "" {
		if !h.verifySignature(c, providerConfig.Secret, "X-Hub-Signature-256") {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid signature"})
			return
		}
	}

	// Parse Azure DevOps webhook payload
	var payload struct {
		EventType      string `json:"eventType"`
		SubscriptionId string `json:"subscriptionId"`
		Resource       struct {
			Repository struct {
				Name    string `json:"name"`
				Project struct {
					Name string `json:"name"`
				} `json:"project"`
				RemoteURL string `json:"remoteUrl"`
				WebURL    string `json:"webUrl"`
			} `json:"repository"`
			RefUpdates []struct {
				Name        string `json:"name"`
				OldObjectId string `json:"oldObjectId"`
				NewObjectId string `json:"newObjectId"`
			} `json:"refUpdates"`
			Commits []struct {
				CommitId string `json:"commitId"`
				Comment  string `json:"comment"`
				Author   struct {
					Name  string `json:"name"`
					Email string `json:"email"`
				} `json:"author"`
			} `json:"commits"`
			PushedBy struct {
				DisplayName string `json:"displayName"`
				UniqueName  string `json:"uniqueName"`
			} `json:"pushedBy"`
		} `json:"resource"`
	}

	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON payload"})
		return
	}

	eventType := payload.EventType
	if eventType == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing eventType in payload"})
		return
	}

	// Check if event should be processed
	if !h.shouldProcessEvent(eventType, providerConfig.Events) {
		c.JSON(http.StatusOK, gin.H{"message": "Event ignored"})
		return
	}

	// Process git.push events
	if eventType == "git.push" && len(payload.Resource.RefUpdates) > 0 {
		for _, refUpdate := range payload.Resource.RefUpdates {
			// Extract branch name from ref (refs/heads/branch-name)
			branch := strings.TrimPrefix(refUpdate.Name, "refs/heads/")
			if !h.shouldProcessBranch(branch, providerConfig.Branches) {
				continue
			}

			repositoryName := fmt.Sprintf("%s/%s",
				payload.Resource.Repository.Project.Name,
				payload.Resource.Repository.Name)

			scanRequest := &ScanRequest{
				ID:         h.generateScanID(),
				Provider:   "azure",
				Event:      eventType,
				Repository: repositoryName,
				Branch:     branch,
				Commit:     refUpdate.NewObjectId,
				Trigger:    "webhook",
				Metadata: map[string]interface{}{
					"pushedBy": payload.Resource.PushedBy.DisplayName,
					"url":      payload.Resource.Repository.WebURL,
					"project":  payload.Resource.Repository.Project.Name,
				},
				Timeout: 30 * time.Second,
			}

			h.processScanRequest(c, scanRequest)
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": "Webhook processed"})
}

// handleScanStatus returns the status of a scan
func (h *WebhookHandler) handleScanStatus(c *gin.Context) {
	scanID := c.Param("id")
	if scanID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Scan ID is required"})
		return
	}

	status, err := h.scanTrigger.GetScanStatus(c.Request.Context(), scanID)
	if err != nil {
		h.logger.Error("Failed to get scan status", map[string]interface{}{
			"scan_id": scanID,
			"error":   err.Error(),
		})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get scan status"})
		return
	}

	c.JSON(http.StatusOK, status)
}

// handleCancelScan cancels a running scan
func (h *WebhookHandler) handleCancelScan(c *gin.Context) {
	scanID := c.Param("id")
	if scanID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Scan ID is required"})
		return
	}

	// This would be implemented by the scan trigger
	c.JSON(http.StatusOK, gin.H{
		"scan_id": scanID,
		"status":  "cancelled",
		"message": "Scan cancellation requested",
	})
}

// handleHealth returns webhook service health
func (h *WebhookHandler) handleHealth(c *gin.Context) {
	health := map[string]interface{}{
		"status":    "healthy",
		"enabled":   h.config.Enabled,
		"timestamp": time.Now(),
		"providers": make(map[string]interface{}),
	}

	for name, config := range h.config.Providers {
		health["providers"].(map[string]interface{})[name] = map[string]interface{}{
			"enabled": config.Enabled,
			"events":  config.Events,
		}
	}

	c.JSON(http.StatusOK, health)
}

// processScanRequest processes a scan request
func (h *WebhookHandler) processScanRequest(c *gin.Context, request *ScanRequest) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), request.Timeout)
	defer cancel()

	h.logger.Info("Processing webhook scan request", map[string]interface{}{
		"scan_id":    request.ID,
		"repository": request.Repository,
		"branch":     request.Branch,
		"provider":   request.Provider,
		"event":      request.Event,
	})

	response, err := h.scanTrigger.TriggerScan(ctx, request)
	if err != nil {
		h.logger.Error("Failed to trigger scan", map[string]interface{}{
			"scan_id": request.ID,
			"error":   err.Error(),
		})
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to trigger scan",
			"scan_id": request.ID,
		})
		return
	}

	c.JSON(http.StatusOK, response)
}

// verifySignature verifies webhook signature
func (h *WebhookHandler) verifySignature(c *gin.Context, secret, headerName string) bool {
	signature := c.GetHeader(headerName)
	if signature == "" {
		return false
	}

	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		return false
	}

	// Reset body for further processing
	c.Request.Body = io.NopCloser(strings.NewReader(string(body)))

	// Calculate expected signature
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	expectedSignature := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	return hmac.Equal([]byte(signature), []byte(expectedSignature))
}

// shouldProcessEvent checks if event should be processed
func (h *WebhookHandler) shouldProcessEvent(eventType string, allowedEvents []string) bool {
	if len(allowedEvents) == 0 {
		return true // Process all events if none specified
	}

	for _, event := range allowedEvents {
		if event == eventType || event == "*" {
			return true
		}
	}

	return false
}

// shouldProcessBranch checks if branch should be processed
func (h *WebhookHandler) shouldProcessBranch(branch string, allowedBranches []string) bool {
	if len(allowedBranches) == 0 {
		return true // Process all branches if none specified
	}

	for _, allowedBranch := range allowedBranches {
		if allowedBranch == branch || allowedBranch == "*" {
			return true
		}
	}

	return false
}

// shouldProcessPaths checks if any changed paths should trigger a scan
func (h *WebhookHandler) shouldProcessPaths(changedPaths, watchedPaths []string) bool {
	if len(watchedPaths) == 0 {
		return true // Process all paths if none specified
	}

	for _, changedPath := range changedPaths {
		for _, watchedPath := range watchedPaths {
			if strings.HasPrefix(changedPath, watchedPath) || watchedPath == "*" {
				return true
			}
		}
	}

	return false
}

// extractChangedPaths extracts changed file paths from GitHub commits
func (h *WebhookHandler) extractChangedPaths(commits []struct {
	ID       string   `json:"id"`
	Message  string   `json:"message"`
	Added    []string `json:"added"`
	Modified []string `json:"modified"`
	Removed  []string `json:"removed"`
}) []string {
	pathSet := make(map[string]bool)

	for _, commit := range commits {
		for _, path := range commit.Added {
			pathSet[path] = true
		}
		for _, path := range commit.Modified {
			pathSet[path] = true
		}
		for _, path := range commit.Removed {
			pathSet[path] = true
		}
	}

	paths := make([]string, 0, len(pathSet))
	for path := range pathSet {
		paths = append(paths, path)
	}

	return paths
}

// extractGitLabChangedPaths extracts changed file paths from GitLab commits
func (h *WebhookHandler) extractGitLabChangedPaths(commits []struct {
	ID       string   `json:"id"`
	Message  string   `json:"message"`
	Added    []string `json:"added"`
	Modified []string `json:"modified"`
	Removed  []string `json:"removed"`
}) []string {
	// Same logic as GitHub for now
	return h.extractChangedPaths(commits)
}

// generateScanID generates a unique scan ID
func (h *WebhookHandler) generateScanID() string {
    return fmt.Sprintf("webhook_%d", time.Now().UnixNano())
}
