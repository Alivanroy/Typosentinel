package rest

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/orchestrator"
	"github.com/Alivanroy/Typosentinel/internal/output"
	"github.com/Alivanroy/Typosentinel/internal/repository"
	"github.com/Alivanroy/Typosentinel/internal/repository/connectors"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

// EnterpriseHandler handles enterprise repository scanning endpoints
type EnterpriseHandler struct {
	repoManager   *repository.Manager
	scheduler     *orchestrator.ScanScheduler
	logger        *logrus.Logger
}

// NewEnterpriseHandler creates a new enterprise handler
func NewEnterpriseHandler(repoManager *repository.Manager, scheduler *orchestrator.ScanScheduler) *EnterpriseHandler {
	return &EnterpriseHandler{
		repoManager: repoManager,
		scheduler:   scheduler,
		logger:      logrus.New(),
	}
}

// RegisterRoutes registers enterprise API routes
func (h *EnterpriseHandler) RegisterRoutes(router *gin.Engine) {
	v1 := router.Group("/api/v1/enterprise")
	{
		// Repository discovery and management
		v1.POST("/repositories/discover", h.DiscoverRepositories)
		v1.GET("/repositories", h.ListRepositories)
		v1.GET("/repositories/:platform/:owner/:repo", h.GetRepository)
		
		// Scanning operations
		v1.POST("/scan/single", h.ScanSingleRepository)
		v1.POST("/scan/bulk", h.ScanBulkRepositories)
		v1.POST("/scan/organization", h.ScanOrganization)
		v1.GET("/scan/:scanId/status", h.GetScanStatus)
		v1.GET("/scan/:scanId/results", h.GetScanResults)
		
		// Scheduled scanning
		v1.POST("/schedule", h.CreateSchedule)
		v1.GET("/schedule", h.ListSchedules)
		v1.PUT("/schedule/:scheduleId", h.UpdateSchedule)
		v1.DELETE("/schedule/:scheduleId", h.DeleteSchedule)
		v1.POST("/schedule/:scheduleId/trigger", h.TriggerSchedule)
		
		// Platform connectors
		v1.POST("/connectors/:platform/configure", h.ConfigureConnector)
		v1.GET("/connectors", h.ListConnectors)
		v1.GET("/connectors/:platform/health", h.CheckConnectorHealth)
		
		// Reports and exports
		v1.GET("/reports/dashboard", h.GetDashboard)
		v1.GET("/reports/export/:format", h.ExportResults)
		v1.GET("/reports/sarif/:scanId", h.GetSARIFReport)
	}
}

// DiscoverRepositoriesRequest represents a repository discovery request
type DiscoverRepositoriesRequest struct {
	Platforms map[string]*repository.PlatformConfig `json:"platforms"`
	Filter    *repository.RepositoryFilter          `json:"filter"`
}

// DiscoverRepositoriesResponse represents a repository discovery response
type DiscoverRepositoriesResponse struct {
	Repositories []*repository.Repository `json:"repositories"`
	Count        int                       `json:"count"`
	Platforms    []string                  `json:"platforms"`
	Duration     string                    `json:"duration"`
}

// DiscoverRepositories discovers repositories across platforms
func (h *EnterpriseHandler) DiscoverRepositories(c *gin.Context) {
	var req DiscoverRepositoriesRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format", "details": err.Error()})
		return
	}
	
	start := time.Now()
	ctx := c.Request.Context()
	
	repos, err := h.repoManager.DiscoverRepositories(ctx, req.Platforms, req.Filter)
	if err != nil {
		h.logger.Errorf("Failed to discover repositories: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to discover repositories", "details": err.Error()})
		return
	}
	
	platforms := make([]string, 0, len(req.Platforms))
	for platform := range req.Platforms {
		platforms = append(platforms, platform)
	}
	
	response := DiscoverRepositoriesResponse{
		Repositories: repos,
		Count:        len(repos),
		Platforms:    platforms,
		Duration:     time.Since(start).String(),
	}
	
	c.JSON(http.StatusOK, response)
}

// ScanSingleRepositoryRequest represents a single repository scan request
type ScanSingleRepositoryRequest struct {
	Platform   string                     `json:"platform"`
	Owner      string                     `json:"owner"`
	Repository string                     `json:"repository"`
	Branch     string                     `json:"branch,omitempty"`
	Options    repository.ScanOptions     `json:"options"`
}

// ScanSingleRepository scans a single repository
func (h *EnterpriseHandler) ScanSingleRepository(c *gin.Context) {
	var req ScanSingleRepositoryRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format", "details": err.Error()})
		return
	}
	
	ctx := c.Request.Context()
	
	// Get the repository
	connector, err := h.repoManager.GetConnector(req.Platform)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Unsupported platform", "platform": req.Platform})
		return
	}
	
	repo, err := connector.GetRepository(ctx, req.Owner, req.Repository)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Repository not found", "details": err.Error()})
		return
	}
	
	// Create scan request
	scanRequest := &repository.ScanRequest{
		Repository:  repo,
		Branch:      req.Branch,
		ScanID:      fmt.Sprintf("scan_%d", time.Now().Unix()),
		RequestedBy: "api",
		Priority:    1,
		Options:     req.Options,
		CreatedAt:   time.Now(),
	}
	
	// Perform scan
	result, err := h.repoManager.ScanRepository(ctx, scanRequest)
	if err != nil {
		h.logger.Errorf("Failed to scan repository: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Scan failed", "details": err.Error()})
		return
	}
	
	c.JSON(http.StatusOK, result)
}

// ScanBulkRepositoriesRequest represents a bulk repository scan request
type ScanBulkRepositoriesRequest struct {
	Repositories []ScanSingleRepositoryRequest `json:"repositories"`
	Options      repository.ScanOptions        `json:"default_options"`
}

// ScanBulkRepositories scans multiple repositories
func (h *EnterpriseHandler) ScanBulkRepositories(c *gin.Context) {
	var req ScanBulkRepositoriesRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format", "details": err.Error()})
		return
	}
	
	ctx := c.Request.Context()
	scanRequests := make([]*repository.ScanRequest, 0, len(req.Repositories))
	
	// Convert to scan requests
	for i, repoReq := range req.Repositories {
		connector, err := h.repoManager.GetConnector(repoReq.Platform)
		if err != nil {
			h.logger.Warnf("Skipping repository %s/%s: unsupported platform %s", repoReq.Owner, repoReq.Repository, repoReq.Platform)
			continue
		}
		
		repo, err := connector.GetRepository(ctx, repoReq.Owner, repoReq.Repository)
		if err != nil {
			h.logger.Warnf("Skipping repository %s/%s: %v", repoReq.Owner, repoReq.Repository, err)
			continue
		}
		
		options := req.Options
		if len(repoReq.Options.OutputFormats) > 0 {
			options = repoReq.Options
		}
		
		scanRequest := &repository.ScanRequest{
			Repository:  repo,
			Branch:      repoReq.Branch,
			ScanID:      fmt.Sprintf("bulk_scan_%d_%d", time.Now().Unix(), i),
			RequestedBy: "api",
			Priority:    1,
			Options:     options,
			CreatedAt:   time.Now(),
		}
		
		scanRequests = append(scanRequests, scanRequest)
	}
	
	if len(scanRequests) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No valid repositories to scan"})
		return
	}
	
	// Perform bulk scan
	results, err := h.repoManager.ScanRepositories(ctx, scanRequests)
	if err != nil {
		h.logger.Errorf("Failed to perform bulk scan: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Bulk scan failed", "details": err.Error()})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"results": results,
		"total":   len(results),
		"success": countSuccessfulScans(results),
		"failed":  len(results) - countSuccessfulScans(results),
	})
}

// ScanOrganizationRequest represents an organization scan request
type ScanOrganizationRequest struct {
	Platform     string                      `json:"platform"`
	Organization string                      `json:"organization"`
	Filter       *repository.RepositoryFilter `json:"filter"`
	Options      repository.ScanOptions       `json:"options"`
}

// ScanOrganization scans all repositories in an organization
func (h *EnterpriseHandler) ScanOrganization(c *gin.Context) {
	var req ScanOrganizationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format", "details": err.Error()})
		return
	}
	
	ctx := c.Request.Context()
	
	// Get connector
	connector, err := h.repoManager.GetConnector(req.Platform)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Unsupported platform", "platform": req.Platform})
		return
	}
	
	// Get organization
	org, err := connector.GetOrganization(ctx, req.Organization)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Organization not found", "details": err.Error()})
		return
	}
	
	// List repositories
	repos, err := connector.ListOrgRepositories(ctx, org.Login, req.Filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list repositories", "details": err.Error()})
		return
	}
	
	// Create scan requests
	scanRequests := make([]*repository.ScanRequest, 0, len(repos))
	for i, repo := range repos {
		scanRequest := &repository.ScanRequest{
			Repository:  repo,
			ScanID:      fmt.Sprintf("org_scan_%s_%d_%d", req.Organization, time.Now().Unix(), i),
			RequestedBy: "api",
			Priority:    1,
			Options:     req.Options,
			CreatedAt:   time.Now(),
		}
		scanRequests = append(scanRequests, scanRequest)
	}
	
	if len(scanRequests) == 0 {
		c.JSON(http.StatusOK, gin.H{"message": "No repositories found to scan", "organization": req.Organization})
		return
	}
	
	// Perform bulk scan
	results, err := h.repoManager.ScanRepositories(ctx, scanRequests)
	if err != nil {
		h.logger.Errorf("Failed to scan organization: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Organization scan failed", "details": err.Error()})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"organization": req.Organization,
		"results":      results,
		"total":        len(results),
		"success":      countSuccessfulScans(results),
		"failed":       len(results) - countSuccessfulScans(results),
	})
}

// ConfigureConnectorRequest represents a connector configuration request
type ConfigureConnectorRequest struct {
	Config repository.PlatformConfig `json:"config"`
}

// ConfigureConnector configures a platform connector
func (h *EnterpriseHandler) ConfigureConnector(c *gin.Context) {
	platform := c.Param("platform")
	
	var req ConfigureConnectorRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format", "details": err.Error()})
		return
	}
	
	ctx := c.Request.Context()
	
	// Create connector based on platform
	var connector repository.Connector
	var err error
	
	switch platform {
	case "github":
		connector, err = connectors.NewGitHubConnector(req.Config)
	case "gitlab":
		connector, err = connectors.NewGitLabConnector(req.Config)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "Unsupported platform", "platform": platform})
		return
	}
	
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create connector", "details": err.Error()})
		return
	}

	// Authenticate the connector
	if err := connector.Authenticate(ctx, req.Config.Auth); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication failed", "details": err.Error()})
		return
	}
	
	// Register connector
	if err := h.repoManager.RegisterConnector(platform, connector); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to register connector", "details": err.Error()})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"message":  "Connector configured successfully",
		"platform": platform,
		"status":   "active",
	})
}

// ListConnectors lists all configured connectors
func (h *EnterpriseHandler) ListConnectors(c *gin.Context) {
	connectors := h.repoManager.ListConnectors()
	
	result := make(map[string]interface{})
	for platform, connector := range connectors {
		result[platform] = gin.H{
			"platform": connector.GetPlatformName(),
			"type":     connector.GetPlatformType(),
			"version":  connector.GetAPIVersion(),
			"status":   "active",
		}
	}
	
	c.JSON(http.StatusOK, gin.H{
		"connectors": result,
		"count":      len(result),
	})
}

// CheckConnectorHealth checks the health of a platform connector
func (h *EnterpriseHandler) CheckConnectorHealth(c *gin.Context) {
	platform := c.Param("platform")
	
	connector, err := h.repoManager.GetConnector(platform)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Connector not found", "platform": platform})
		return
	}
	
	ctx := c.Request.Context()
	err = connector.HealthCheck(ctx)
	
	status := "healthy"
	if err != nil {
		status = "unhealthy"
	}
	
	c.JSON(http.StatusOK, gin.H{
		"platform": platform,
		"status":   status,
		"error":    err,
		"timestamp": time.Now(),
	})
}

// GetDashboard returns executive dashboard data
func (h *EnterpriseHandler) GetDashboard(c *gin.Context) {
	// This would typically aggregate data from multiple scans
	// For now, return a sample dashboard
	dashboard := gin.H{
		"summary": gin.H{
			"total_repositories": 0,
			"scanned_today":      0,
			"critical_threats":   0,
			"high_threats":       0,
			"medium_threats":     0,
			"low_threats":        0,
		},
		"platforms": gin.H{
			"github": gin.H{"repositories": 0, "last_scan": nil},
			"gitlab": gin.H{"repositories": 0, "last_scan": nil},
		},
		"trends": []gin.H{},
		"top_threats": []gin.H{},
		"recommendations": []gin.H{
			{"type": "info", "message": "Configure platform connectors to start scanning"},
		},
		"generated_at": time.Now(),
	}
	
	c.JSON(http.StatusOK, dashboard)
}

// ExportResults exports scan results in various formats
func (h *EnterpriseHandler) ExportResults(c *gin.Context) {
	format := c.Param("format")
	scanId := c.Query("scan_id")
	
	if scanId == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "scan_id parameter is required"})
		return
	}
	
	// This would typically retrieve scan results from storage
	// For now, return a sample response
	switch format {
	case "json":
		c.Header("Content-Type", "application/json")
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=scan_%s.json", scanId))
		c.JSON(http.StatusOK, gin.H{"scan_id": scanId, "format": "json", "data": "sample"})
	case "csv":
		c.Header("Content-Type", "text/csv")
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=scan_%s.csv", scanId))
		c.String(http.StatusOK, "scan_id,repository,threats,status\n%s,sample/repo,0,completed\n", scanId)
	case "pdf":
		c.Header("Content-Type", "application/pdf")
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=scan_%s.pdf", scanId))
		c.String(http.StatusOK, "PDF export not implemented yet")
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "Unsupported format", "supported": []string{"json", "csv", "pdf"}})
	}
}

// GetSARIFReport returns SARIF format report
func (h *EnterpriseHandler) GetSARIFReport(c *gin.Context) {
	scanId := c.Param("scanId")
	
	// This would typically retrieve scan results and convert to SARIF
	// For now, return a sample SARIF report
	sarif := output.SARIF{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs: []output.Run{
			{
				Tool: output.Tool{
					Driver: output.Driver{
						Name:    "TypoSentinel",
						Version: "1.0.0",
						Rules:   []output.Rule{},
					},
				},
				Results:   []output.Result{},
				Artifacts: []output.Artifact{},
			},
		},
	}
	
	c.Header("Content-Type", "application/json")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=sarif_%s.json", scanId))
	c.JSON(http.StatusOK, sarif)
}

// Schedule management endpoints

// CreateScheduleRequest represents a schedule creation request
type CreateScheduleRequest struct {
	Name        string                           `json:"name"`
	Description string                           `json:"description"`
	Schedule    string                           `json:"schedule"`
	Targets     []orchestrator.ScanTarget       `json:"targets"`
	Output      []orchestrator.OutputConfig     `json:"output"`
	Policies    []orchestrator.PolicyConfig     `json:"policies"`
	Enabled     bool                             `json:"enabled"`
}

// CreateSchedule creates a new scan schedule
func (h *EnterpriseHandler) CreateSchedule(c *gin.Context) {
	var req CreateScheduleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format", "details": err.Error()})
		return
	}
	
	schedule := &orchestrator.ScheduledScan{
		ID:          fmt.Sprintf("schedule_%d", time.Now().Unix()),
		Name:        req.Name,
		Description: req.Description,
		Schedule:    req.Schedule,
		Targets:     req.Targets,
		Output:      req.Output,
		Policies:    req.Policies,
		Enabled:     req.Enabled,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	
	if err := h.scheduler.AddSchedule(schedule); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create schedule", "details": err.Error()})
		return
	}
	
	c.JSON(http.StatusCreated, schedule)
}

// ListSchedules lists all scan schedules
func (h *EnterpriseHandler) ListSchedules(c *gin.Context) {
	schedules := h.scheduler.ListSchedules()
	
	c.JSON(http.StatusOK, gin.H{
		"schedules": schedules,
		"count":     len(schedules),
	})
}

// UpdateSchedule updates an existing schedule
func (h *EnterpriseHandler) UpdateSchedule(c *gin.Context) {
	scheduleId := c.Param("scheduleId")
	
	var req CreateScheduleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format", "details": err.Error()})
		return
	}
	
	schedule := &orchestrator.ScheduledScan{
		ID:          scheduleId,
		Name:        req.Name,
		Description: req.Description,
		Schedule:    req.Schedule,
		Targets:     req.Targets,
		Output:      req.Output,
		Policies:    req.Policies,
		Enabled:     req.Enabled,
		UpdatedAt:   time.Now(),
	}
	
	if err := h.scheduler.UpdateSchedule(schedule); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update schedule", "details": err.Error()})
		return
	}
	
	c.JSON(http.StatusOK, schedule)
}

// DeleteSchedule deletes a scan schedule
func (h *EnterpriseHandler) DeleteSchedule(c *gin.Context) {
	scheduleId := c.Param("scheduleId")
	
	if err := h.scheduler.RemoveSchedule(scheduleId); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete schedule", "details": err.Error()})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{"message": "Schedule deleted successfully", "schedule_id": scheduleId})
}

// TriggerSchedule manually triggers a scheduled scan
func (h *EnterpriseHandler) TriggerSchedule(c *gin.Context) {
	scheduleId := c.Param("scheduleId")
	
	if err := h.scheduler.TriggerSchedule(scheduleId); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to trigger schedule", "details": err.Error()})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{"message": "Schedule triggered successfully", "schedule_id": scheduleId})
}

// GetScanStatus returns the status of a scan
func (h *EnterpriseHandler) GetScanStatus(c *gin.Context) {
	scanId := c.Param("scanId")
	
	// This would typically query scan status from storage
	// For now, return a sample status
	status := gin.H{
		"scan_id":    scanId,
		"status":     "completed",
		"progress":   100,
		"started_at": time.Now().Add(-5 * time.Minute),
		"completed_at": time.Now(),
		"duration":   "5m0s",
		"repository": "example/repo",
		"platform":   "github",
	}
	
	c.JSON(http.StatusOK, status)
}

// GetScanResults returns the results of a scan
func (h *EnterpriseHandler) GetScanResults(c *gin.Context) {
	scanId := c.Param("scanId")
	format := c.DefaultQuery("format", "json")
	
	// This would typically retrieve scan results from storage
	// For now, return sample results
	results := gin.H{
		"scan_id":    scanId,
		"repository": "example/repo",
		"platform":   "github",
		"status":     "completed",
		"threats":    []gin.H{},
		"warnings":   []gin.H{},
		"summary": gin.H{
			"total_packages":      10,
			"vulnerable_packages": 0,
			"critical_threats":    0,
			"high_threats":        0,
			"medium_threats":      0,
			"low_threats":         0,
		},
		"metadata": gin.H{
			"scan_duration": "30s",
			"files_scanned": 3,
		},
	}
	
	switch format {
	case "json":
		c.JSON(http.StatusOK, results)
	case "sarif":
		// Redirect to SARIF endpoint
		h.GetSARIFReport(c)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "Unsupported format", "supported": []string{"json", "sarif"}})
	}
}

// GetRepository returns repository information
func (h *EnterpriseHandler) GetRepository(c *gin.Context) {
	platform := c.Param("platform")
	owner := c.Param("owner")
	repoName := c.Param("repo")
	
	connector, err := h.repoManager.GetConnector(platform)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Unsupported platform", "platform": platform})
		return
	}
	
	ctx := c.Request.Context()
	repo, err := connector.GetRepository(ctx, owner, repoName)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Repository not found", "details": err.Error()})
		return
	}
	
	c.JSON(http.StatusOK, repo)
}

// ListRepositories lists repositories with optional filtering
func (h *EnterpriseHandler) ListRepositories(c *gin.Context) {
	platform := c.Query("platform")
	owner := c.Query("owner")
	limitStr := c.DefaultQuery("limit", "50")
	
	limit, err := strconv.Atoi(limitStr)
	if err != nil {
		limit = 50
	}
	
	if platform == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "platform parameter is required"})
		return
	}
	
	connector, err := h.repoManager.GetConnector(platform)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Unsupported platform", "platform": platform})
		return
	}
	
	ctx := c.Request.Context()
	filter := &repository.RepositoryFilter{
		IncludePrivate:  true,
		IncludeArchived: false,
		IncludeForks:    false,
	}
	
	var repos []*repository.Repository
	if owner != "" {
		repos, err = connector.ListRepositories(ctx, owner, filter)
	} else {
		// List user's repositories or organizations
		orgs, err := connector.ListOrganizations(ctx)
		if err == nil && len(orgs) > 0 {
			repos, err = connector.ListOrgRepositories(ctx, orgs[0].Login, filter)
		}
	}
	
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list repositories", "details": err.Error()})
		return
	}
	
	// Apply limit
	if len(repos) > limit {
		repos = repos[:limit]
	}
	
	c.JSON(http.StatusOK, gin.H{
		"repositories": repos,
		"count":        len(repos),
		"platform":     platform,
		"owner":        owner,
	})
}

// Helper functions

func countSuccessfulScans(results []*repository.ScanResult) int {
	count := 0
	for _, result := range results {
		if result.Status == "completed" {
			count++
		}
	}
	return count
}