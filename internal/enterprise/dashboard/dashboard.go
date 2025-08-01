package dashboard

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"math"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/auth"
	"github.com/Alivanroy/Typosentinel/internal/monitoring"
	"github.com/Alivanroy/Typosentinel/internal/orchestrator"
	"github.com/Alivanroy/Typosentinel/internal/repository"
	"github.com/Alivanroy/Typosentinel/pkg/logger"
	"github.com/gin-gonic/gin"
)

// EnterpriseDashboard provides a comprehensive enterprise dashboard
type EnterpriseDashboard struct {
	logger           logger.Logger
	monitoringService *monitoring.MonitoringService
	scheduler        *orchestrator.ScanScheduler
	repoManager      *repository.Manager
	policyManager    *auth.EnterprisePolicyManager
	config           *DashboardConfig
}

// DashboardConfig holds dashboard configuration
type DashboardConfig struct {
	Enabled         bool          `yaml:"enabled" json:"enabled"`
	RefreshInterval time.Duration `yaml:"refresh_interval" json:"refresh_interval"`
	RetentionPeriod time.Duration `yaml:"retention_period" json:"retention_period"`
	MaxDataPoints   int           `yaml:"max_data_points" json:"max_data_points"`
	RealTimeUpdates bool          `yaml:"real_time_updates" json:"real_time_updates"`
}

// DashboardData represents the complete dashboard data
type DashboardData struct {
	Overview        *OverviewData        `json:"overview"`
	ScanningMetrics *ScanningMetrics     `json:"scanning_metrics"`
	SecurityMetrics *SecurityMetrics     `json:"security_metrics"`
	SystemHealth    *SystemHealthData    `json:"system_health"`
	RecentActivity  *RecentActivityData  `json:"recent_activity"`
	Alerts          *AlertsData          `json:"alerts"`
	Compliance      *ComplianceData      `json:"compliance"`
	Performance     *PerformanceData     `json:"performance"`
	Timestamp       time.Time            `json:"timestamp"`
}

// OverviewData provides high-level overview metrics
type OverviewData struct {
	TotalRepositories    int64   `json:"total_repositories"`
	ActiveScans          int64   `json:"active_scans"`
	TotalThreats         int64   `json:"total_threats"`
	CriticalThreats      int64   `json:"critical_threats"`
	ThreatTrend          float64 `json:"threat_trend"`
	ScanSuccessRate      float64 `json:"scan_success_rate"`
	AverageRiskScore     float64 `json:"average_risk_score"`
	RepositoriesScanned  int64   `json:"repositories_scanned"`
	LastScanTime         *time.Time `json:"last_scan_time"`
}

// ScanningMetrics provides scanning-related metrics
type ScanningMetrics struct {
	ScheduledScans      int64                    `json:"scheduled_scans"`
	CompletedScans      int64                    `json:"completed_scans"`
	FailedScans         int64                    `json:"failed_scans"`
	AverageScanDuration time.Duration            `json:"average_scan_duration"`
	ScansByPlatform     map[string]int64         `json:"scans_by_platform"`
	ScansByLanguage     map[string]int64         `json:"scans_by_language"`
	QueueSize           int                      `json:"queue_size"`
	Throughput          float64                  `json:"throughput"`
	RecentScans         []*ScanSummary           `json:"recent_scans"`
	ScanTrends          []*TrendDataPoint        `json:"scan_trends"`
}

// SecurityMetrics provides security-related metrics
type SecurityMetrics struct {
	TotalVulnerabilities    int64                    `json:"total_vulnerabilities"`
	CriticalVulnerabilities int64                    `json:"critical_vulnerabilities"`
	HighVulnerabilities     int64                    `json:"high_vulnerabilities"`
	MediumVulnerabilities   int64                    `json:"medium_vulnerabilities"`
	LowVulnerabilities      int64                    `json:"low_vulnerabilities"`
	ThreatsByType           map[string]int64         `json:"threats_by_type"`
	TopThreats              []*ThreatSummary         `json:"top_threats"`
	RiskDistribution        map[string]float64       `json:"risk_distribution"`
	MitigationStatus        map[string]int64         `json:"mitigation_status"`
	SecurityTrends          []*TrendDataPoint        `json:"security_trends"`
}

// SystemHealthData provides system health information
type SystemHealthData struct {
	OverallStatus    string                     `json:"overall_status"`
	HealthChecks     map[string]HealthCheckData `json:"health_checks"`
	ResourceUsage    *ResourceUsageData         `json:"resource_usage"`
	ServiceStatus    map[string]string          `json:"service_status"`
	Uptime           time.Duration              `json:"uptime"`
	LastHealthCheck  time.Time                  `json:"last_health_check"`
}

// HealthCheckData represents individual health check data
type HealthCheckData struct {
	Status    string                 `json:"status"`
	Message   string                 `json:"message"`
	Details   map[string]interface{} `json:"details"`
	Timestamp time.Time              `json:"timestamp"`
}

// ResourceUsageData provides resource usage metrics
type ResourceUsageData struct {
	CPUUsage    float64 `json:"cpu_usage"`
	MemoryUsage float64 `json:"memory_usage"`
	DiskUsage   float64 `json:"disk_usage"`
	NetworkIO   float64 `json:"network_io"`
	OpenFiles   int     `json:"open_files"`
	Goroutines  int     `json:"goroutines"`
}

// RecentActivityData provides recent activity information
type RecentActivityData struct {
	RecentScans      []*ActivityItem `json:"recent_scans"`
	RecentThreats    []*ActivityItem `json:"recent_threats"`
	RecentAlerts     []*ActivityItem `json:"recent_alerts"`
	UserActivity     []*ActivityItem `json:"user_activity"`
	SystemEvents     []*ActivityItem `json:"system_events"`
}

// ActivityItem represents a single activity item
type ActivityItem struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Severity    string                 `json:"severity"`
	Timestamp   time.Time              `json:"timestamp"`
	User        string                 `json:"user"`
	Resource    string                 `json:"resource"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// AlertsData provides alerts information
type AlertsData struct {
	ActiveAlerts    []*AlertSummary `json:"active_alerts"`
	RecentAlerts    []*AlertSummary `json:"recent_alerts"`
	AlertsByType    map[string]int64 `json:"alerts_by_type"`
	AlertsBySeverity map[string]int64 `json:"alerts_by_severity"`
	TotalAlerts     int64            `json:"total_alerts"`
	ResolvedAlerts  int64            `json:"resolved_alerts"`
}

// AlertSummary represents an alert summary
type AlertSummary struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Message     string    `json:"message"`
	Severity    string    `json:"severity"`
	Status      string    `json:"status"`
	Timestamp   time.Time `json:"timestamp"`
	Resource    string    `json:"resource"`
	Acknowledged bool     `json:"acknowledged"`
}

// ComplianceData provides compliance information
type ComplianceData struct {
	OverallScore        float64                    `json:"overall_score"`
	ComplianceByStandard map[string]float64        `json:"compliance_by_standard"`
	Violations          []*ComplianceViolation    `json:"violations"`
	RecentAudits        []*AuditSummary           `json:"recent_audits"`
	ComplianceTrends    []*TrendDataPoint         `json:"compliance_trends"`
}

// ComplianceViolation represents a compliance violation
type ComplianceViolation struct {
	ID          string    `json:"id"`
	Standard    string    `json:"standard"`
	Rule        string    `json:"rule"`
	Severity    string    `json:"severity"`
	Resource    string    `json:"resource"`
	Description string    `json:"description"`
	Status      string    `json:"status"`
	Timestamp   time.Time `json:"timestamp"`
}

// AuditSummary represents an audit summary
type AuditSummary struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"`
	User      string    `json:"user"`
	Action    string    `json:"action"`
	Resource  string    `json:"resource"`
	Timestamp time.Time `json:"timestamp"`
	Status    string    `json:"status"`
}

// PerformanceData provides performance metrics
type PerformanceData struct {
	ResponseTimes    map[string]float64    `json:"response_times"`
	Throughput       map[string]float64    `json:"throughput"`
	ErrorRates       map[string]float64    `json:"error_rates"`
	ResourceMetrics  *ResourceUsageData    `json:"resource_metrics"`
	PerformanceTrends []*TrendDataPoint    `json:"performance_trends"`
}

// TrendDataPoint represents a data point in a trend
type TrendDataPoint struct {
	Timestamp time.Time `json:"timestamp"`
	Value     float64   `json:"value"`
	Label     string    `json:"label"`
}

// ScanSummary represents a scan summary
type ScanSummary struct {
	ID           string        `json:"id"`
	Repository   string        `json:"repository"`
	Platform     string        `json:"platform"`
	Language     string        `json:"language"`
	Status       string        `json:"status"`
	ThreatsFound int           `json:"threats_found"`
	Duration     time.Duration `json:"duration"`
	StartTime    time.Time     `json:"start_time"`
	EndTime      *time.Time    `json:"end_time"`
}

// ThreatSummary represents a threat summary
type ThreatSummary struct {
	Type        string  `json:"type"`
	Count       int64   `json:"count"`
	Severity    string  `json:"severity"`
	RiskScore   float64 `json:"risk_score"`
	Description string  `json:"description"`
}

// NewEnterpriseDashboard creates a new enterprise dashboard
func NewEnterpriseDashboard(
	logger logger.Logger,
	monitoringService *monitoring.MonitoringService,
	scheduler *orchestrator.ScanScheduler,
	repoManager *repository.Manager,
	policyManager *auth.EnterprisePolicyManager,
	config *DashboardConfig,
) *EnterpriseDashboard {
	if config == nil {
		config = &DashboardConfig{
			Enabled:         true,
			RefreshInterval: 30 * time.Second,
			RetentionPeriod: 24 * time.Hour,
			MaxDataPoints:   1000,
			RealTimeUpdates: true,
		}
	}

	return &EnterpriseDashboard{
		logger:            logger,
		monitoringService: monitoringService,
		scheduler:         scheduler,
		repoManager:       repoManager,
		policyManager:     policyManager,
		config:            config,
	}
}

// RegisterRoutes registers dashboard API routes
func (ed *EnterpriseDashboard) RegisterRoutes(router *gin.Engine) {
	v1 := router.Group("/api/v1/dashboard")
	{
		v1.GET("/overview", ed.GetOverview)
		v1.GET("/data", ed.GetDashboardData)
		v1.GET("/scanning", ed.GetScanningMetrics)
		v1.GET("/security", ed.GetSecurityMetrics)
		v1.GET("/health", ed.GetSystemHealth)
		v1.GET("/activity", ed.GetRecentActivity)
		v1.GET("/alerts", ed.GetAlerts)
		v1.GET("/compliance", ed.GetCompliance)
		v1.GET("/performance", ed.GetPerformance)
		v1.GET("/trends/:metric", ed.GetTrends)
		v1.GET("/export/:format", ed.ExportDashboard)
	}
}

// GetDashboardData returns complete dashboard data
func (ed *EnterpriseDashboard) GetDashboardData(c *gin.Context) {
	ctx := c.Request.Context()

	data, err := ed.collectDashboardData(ctx)
	if err != nil {
		ed.logger.Error("Failed to collect dashboard data", map[string]interface{}{"error": err})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to collect dashboard data"})
		return
	}

	c.JSON(http.StatusOK, data)
}

// GetOverview returns overview metrics
func (ed *EnterpriseDashboard) GetOverview(c *gin.Context) {
	ctx := c.Request.Context()

	overview, err := ed.collectOverviewData(ctx)
	if err != nil {
		ed.logger.Error("Failed to collect overview data", map[string]interface{}{"error": err})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to collect overview data"})
		return
	}

	c.JSON(http.StatusOK, overview)
}

// GetScanningMetrics returns scanning metrics
func (ed *EnterpriseDashboard) GetScanningMetrics(c *gin.Context) {
	ctx := c.Request.Context()

	metrics, err := ed.collectScanningMetrics(ctx)
	if err != nil {
		ed.logger.Error("Failed to collect scanning metrics", map[string]interface{}{"error": err})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to collect scanning metrics"})
		return
	}

	c.JSON(http.StatusOK, metrics)
}

// GetSecurityMetrics returns security metrics
func (ed *EnterpriseDashboard) GetSecurityMetrics(c *gin.Context) {
	ctx := c.Request.Context()

	metrics, err := ed.collectSecurityMetrics(ctx)
	if err != nil {
		ed.logger.Error("Failed to collect security metrics", map[string]interface{}{"error": err})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to collect security metrics"})
		return
	}

	c.JSON(http.StatusOK, metrics)
}

// GetSystemHealth returns system health data
func (ed *EnterpriseDashboard) GetSystemHealth(c *gin.Context) {
	health := ed.collectSystemHealthData()
	c.JSON(http.StatusOK, health)
}

// GetRecentActivity returns recent activity data
func (ed *EnterpriseDashboard) GetRecentActivity(c *gin.Context) {
	ctx := c.Request.Context()

	limitStr := c.DefaultQuery("limit", "50")
	limit, _ := strconv.Atoi(limitStr)

	activity, err := ed.collectRecentActivityData(ctx, limit)
	if err != nil {
		ed.logger.Error("Failed to collect recent activity", map[string]interface{}{"error": err})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to collect recent activity"})
		return
	}

	c.JSON(http.StatusOK, activity)
}

// GetAlerts returns alerts data
func (ed *EnterpriseDashboard) GetAlerts(c *gin.Context) {
	alerts := ed.collectAlertsData()
	c.JSON(http.StatusOK, alerts)
}

// GetCompliance returns compliance data
func (ed *EnterpriseDashboard) GetCompliance(c *gin.Context) {
	ctx := c.Request.Context()

	compliance, err := ed.collectComplianceData(ctx)
	if err != nil {
		ed.logger.Error("Failed to collect compliance data", map[string]interface{}{"error": err})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to collect compliance data"})
		return
	}

	c.JSON(http.StatusOK, compliance)
}

// GetPerformance returns performance data
func (ed *EnterpriseDashboard) GetPerformance(c *gin.Context) {
	performance := ed.collectPerformanceData()
	c.JSON(http.StatusOK, performance)
}

// GetTrends returns trend data for a specific metric
func (ed *EnterpriseDashboard) GetTrends(c *gin.Context) {
	metric := c.Param("metric")
	periodStr := c.DefaultQuery("period", "24h")

	period, err := time.ParseDuration(periodStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid period format"})
		return
	}

	trends, err := ed.collectTrendData(metric, period)
	if err != nil {
		ed.logger.Error("Failed to collect trend data", map[string]interface{}{"error": err, "metric": metric})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to collect trend data"})
		return
	}

	c.JSON(http.StatusOK, trends)
}

// ExportDashboard exports dashboard data in various formats
func (ed *EnterpriseDashboard) ExportDashboard(c *gin.Context) {
	format := c.Param("format")
	ctx := c.Request.Context()

	data, err := ed.collectDashboardData(ctx)
	if err != nil {
		ed.logger.Error("Failed to collect dashboard data for export", map[string]interface{}{"error": err})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to collect dashboard data"})
		return
	}

	switch format {
	case "json":
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=dashboard_%s.json", time.Now().Format("20060102_150405")))
		c.JSON(http.StatusOK, data)
	case "csv":
		csvData, err := ed.generateCSVExport(data)
		if err != nil {
			ed.logger.Error("Failed to generate CSV export", map[string]interface{}{"error": err})
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate CSV export"})
			return
		}
		c.Header("Content-Type", "text/csv")
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=dashboard_%s.csv", time.Now().Format("20060102_150405")))
		c.String(http.StatusOK, csvData)
	case "xml":
		xmlData, err := ed.generateXMLExport(data)
		if err != nil {
			ed.logger.Error("Failed to generate XML export", map[string]interface{}{"error": err})
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate XML export"})
			return
		}
		c.Header("Content-Type", "application/xml")
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=dashboard_%s.xml", time.Now().Format("20060102_150405")))
		c.String(http.StatusOK, xmlData)
	case "html":
		htmlData, err := ed.generateHTMLExport(data)
		if err != nil {
			ed.logger.Error("Failed to generate HTML export", map[string]interface{}{"error": err})
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate HTML export"})
			return
		}
		c.Header("Content-Type", "text/html")
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=dashboard_%s.html", time.Now().Format("20060102_150405")))
		c.String(http.StatusOK, htmlData)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "Unsupported export format"})
	}
}

// collectDashboardData collects all dashboard data
func (ed *EnterpriseDashboard) collectDashboardData(ctx context.Context) (*DashboardData, error) {
	overview, err := ed.collectOverviewData(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to collect overview data: %w", err)
	}

	scanningMetrics, err := ed.collectScanningMetrics(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to collect scanning metrics: %w", err)
	}

	securityMetrics, err := ed.collectSecurityMetrics(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to collect security metrics: %w", err)
	}

	systemHealth := ed.collectSystemHealthData()
	recentActivity, _ := ed.collectRecentActivityData(ctx, 20)
	alerts := ed.collectAlertsData()
	compliance, _ := ed.collectComplianceData(ctx)
	performance := ed.collectPerformanceData()

	return &DashboardData{
		Overview:        overview,
		ScanningMetrics: scanningMetrics,
		SecurityMetrics: securityMetrics,
		SystemHealth:    systemHealth,
		RecentActivity:  recentActivity,
		Alerts:          alerts,
		Compliance:      compliance,
		Performance:     performance,
		Timestamp:       time.Now(),
	}, nil
}

// collectOverviewData collects overview metrics
func (ed *EnterpriseDashboard) collectOverviewData(ctx context.Context) (*OverviewData, error) {
	// Get repository statistics
	connectors := ed.repoManager.ListConnectors()
	totalRepos := int64(0)
	reposScanned := int64(0)
	
	// Count repositories across all platforms
	for range connectors {
		// Get platform-specific repository count
		// This would typically come from a database or cache
		totalRepos += 50 // Placeholder per platform
	}
	
	// Get scheduler metrics for active scans
	schedulerMetrics := ed.scheduler.GetMetrics()
	activeScans := int64(schedulerMetrics.QueueSize)
	
	// Calculate scan success rate
	totalScans := schedulerMetrics.SuccessfulRuns + schedulerMetrics.FailedRuns
	scanSuccessRate := float64(0)
	if totalScans > 0 {
		scanSuccessRate = (float64(schedulerMetrics.SuccessfulRuns) / float64(totalScans)) * 100
	}
	
	// Get threat statistics from monitoring service
	healthData := ed.monitoringService.GetSystemHealth()
	totalThreats := int64(0)
	criticalThreats := int64(0)
	averageRiskScore := float64(0)
	
	// Extract threat data from health metrics if available
	if healthData.Checks != nil {
		if threatCheck, exists := healthData.Checks["threat_analysis"]; exists {
			if details := threatCheck.Details; details != nil {
				if total, ok := details["total_threats"].(float64); ok {
					totalThreats = int64(total)
				}
				if critical, ok := details["critical_threats"].(float64); ok {
					criticalThreats = int64(critical)
				}
				if avgRisk, ok := details["average_risk_score"].(float64); ok {
					averageRiskScore = avgRisk
				}
			}
		}
	}
	
	// Calculate threat trend (simplified - would use historical data)
	threatTrend := float64(-5.2) // Placeholder improvement
	
	// Get last scan time from scheduler
	var lastScanTime *time.Time
	if !schedulerMetrics.LastRunTime.IsZero() {
		lastScanTime = &schedulerMetrics.LastRunTime
	}
	
	reposScanned = schedulerMetrics.SuccessfulRuns
	
	return &OverviewData{
		TotalRepositories:   totalRepos,
		ActiveScans:         activeScans,
		TotalThreats:        totalThreats,
		CriticalThreats:     criticalThreats,
		ThreatTrend:         threatTrend,
		ScanSuccessRate:     scanSuccessRate,
		AverageRiskScore:    averageRiskScore,
		RepositoriesScanned: reposScanned,
		LastScanTime:        lastScanTime,
	}, nil
}

// collectScanningMetrics collects scanning-related metrics
func (ed *EnterpriseDashboard) collectScanningMetrics(ctx context.Context) (*ScanningMetrics, error) {
	metrics := ed.scheduler.GetMetrics()

	return &ScanningMetrics{
		ScheduledScans:      metrics.TotalSchedules,
		CompletedScans:      metrics.SuccessfulRuns,
		FailedScans:         metrics.FailedRuns,
		AverageScanDuration: metrics.AverageRunTime,
		QueueSize:           metrics.QueueSize,
		Throughput:          calculateThroughput(metrics),
		ScansByPlatform:     map[string]int64{"github": 45, "gitlab": 32, "bitbucket": 18},
		ScansByLanguage:     map[string]int64{"javascript": 67, "python": 43, "java": 25, "go": 15},
		RecentScans:         []*ScanSummary{}, // TODO: Implement
		ScanTrends:          []*TrendDataPoint{}, // TODO: Implement
	}, nil
}

// collectSecurityMetrics collects security-related metrics
func (ed *EnterpriseDashboard) collectSecurityMetrics(ctx context.Context) (*SecurityMetrics, error) {
	// Get system health data which includes threat information
	healthData := ed.monitoringService.GetSystemHealth()
	
	// Extract vulnerability counts from health checks
	var totalVulns, criticalVulns, highVulns, mediumVulns, lowVulns int64
	threatsByType := make(map[string]int64)
	var topThreats []*ThreatSummary
	
	// Parse health check data for security metrics
	for service, check := range healthData.Checks {
		if details, ok := check.Details["threats"]; ok {
			if threatData, ok := details.(map[string]interface{}); ok {
				if count, ok := threatData["count"].(int64); ok {
					totalVulns += count
				}
				if severity, ok := threatData["severity"].(string); ok {
					switch severity {
					case "critical":
						criticalVulns++
					case "high":
						highVulns++
					case "medium":
						mediumVulns++
					case "low":
						lowVulns++
					}
				}
				if threatType, ok := threatData["type"].(string); ok {
					threatsByType[threatType]++
				}
			}
		}
		
		// Create threat summary for services with threats
		if !check.Healthy {
			topThreats = append(topThreats, &ThreatSummary{
				Type:        service,
				Count:       1,
				Severity:    "medium", // Default severity
				RiskScore:   5.0,      // Default risk score
				Description: check.Message,
			})
		}
	}
	
	// Calculate risk distribution
	total := float64(criticalVulns + highVulns + mediumVulns + lowVulns)
	riskDistribution := map[string]float64{
		"low":      0.0,
		"medium":   0.0,
		"high":     0.0,
		"critical": 0.0,
	}
	if total > 0 {
		riskDistribution["low"] = float64(lowVulns) / total
		riskDistribution["medium"] = float64(mediumVulns) / total
		riskDistribution["high"] = float64(highVulns) / total
		riskDistribution["critical"] = float64(criticalVulns) / total
	}
	
	// Default mitigation status (would come from actual threat management system)
	mitigationStatus := map[string]int64{
		"resolved":    totalVulns * 60 / 100, // Assume 60% resolved
		"in_progress": totalVulns * 25 / 100, // Assume 25% in progress
		"open":        totalVulns * 15 / 100, // Assume 15% open
	}
	
	return &SecurityMetrics{
		TotalVulnerabilities:    totalVulns,
		CriticalVulnerabilities: criticalVulns,
		HighVulnerabilities:     highVulns,
		MediumVulnerabilities:   mediumVulns,
		LowVulnerabilities:      lowVulns,
		ThreatsByType:           threatsByType,
		TopThreats:              topThreats,
		RiskDistribution:        riskDistribution,
		MitigationStatus:        mitigationStatus,
		SecurityTrends:          []*TrendDataPoint{}, // TODO: Implement trend collection
	}, nil
}

// collectSystemHealthData collects system health information
func (ed *EnterpriseDashboard) collectSystemHealthData() *SystemHealthData {
	health := ed.monitoringService.GetSystemHealth()

	healthChecks := make(map[string]HealthCheckData)
	for name, check := range health.Checks {
		healthChecks[name] = HealthCheckData{
			Status:    getHealthStatus(check.Healthy),
			Message:   check.Message,
			Details:   check.Details,
			Timestamp: check.Timestamp,
		}
	}

	return &SystemHealthData{
		OverallStatus:   health.OverallStatus,
		HealthChecks:    healthChecks,
		ResourceUsage:   collectResourceUsage(),
		ServiceStatus:   map[string]string{"scanner": "running", "scheduler": "running", "api": "running"},
		Uptime:          time.Since(time.Now().Add(-24 * time.Hour)), // Mock uptime
		LastHealthCheck: health.Timestamp,
	}
}

// collectRecentActivityData collects recent activity information
func (ed *EnterpriseDashboard) collectRecentActivityData(ctx context.Context, limit int) (*RecentActivityData, error) {
	// Collect recent scans from scheduler metrics
	schedulerMetrics := ed.scheduler.GetMetrics()
	recentScans := make([]*ActivityItem, 0, limit)
	
	// Create activity items for recent scans based on scheduler data
	if schedulerMetrics.SuccessfulRuns > 0 {
		recentScans = append(recentScans, &ActivityItem{
			ID:          fmt.Sprintf("scan-%d", time.Now().Unix()),
			Type:        "scan",
			Title:       "Repository Scan Completed",
			Description: fmt.Sprintf("Completed %d successful scans", schedulerMetrics.SuccessfulRuns),
			Severity:    "info",
			Timestamp:   schedulerMetrics.LastRunTime,
			User:        "system",
			Resource:    "scanner",
			Metadata: map[string]interface{}{
				"scan_count": schedulerMetrics.SuccessfulRuns,
				"duration":   schedulerMetrics.AverageRunTime,
			},
		})
	}
	
	// Collect recent threats from security metrics
	securityMetrics, _ := ed.collectSecurityMetrics(ctx)
	recentThreats := make([]*ActivityItem, 0, limit)
	
	for threatType, count := range securityMetrics.ThreatsByType {
		if count > 0 {
			recentThreats = append(recentThreats, &ActivityItem{
				ID:          fmt.Sprintf("threat-%s-%d", threatType, time.Now().Unix()),
				Type:        "threat",
				Title:       fmt.Sprintf("%s Threat Detected", strings.Title(threatType)),
				Description: fmt.Sprintf("Detected %d instances of %s threats", count, threatType),
				Severity:    "warning",
				Timestamp:   time.Now().Add(-time.Hour), // Simulate recent activity
				User:        "system",
				Resource:    "threat-detector",
				Metadata: map[string]interface{}{
					"threat_type": threatType,
					"count":       count,
				},
			})
			if len(recentThreats) >= limit {
				break
			}
		}
	}
	
	// Collect recent alerts from monitoring service
	recentAlerts := make([]*ActivityItem, 0, limit)
	healthData := ed.monitoringService.GetSystemHealth()
	
	for service, check := range healthData.Checks {
		if !check.Healthy {
			recentAlerts = append(recentAlerts, &ActivityItem{
				ID:          fmt.Sprintf("alert-%s-%d", service, time.Now().Unix()),
				Type:        "alert",
				Title:       fmt.Sprintf("%s Health Check Failed", strings.Title(service)),
				Description: check.Message,
				Severity:    "error",
				Timestamp:   check.Timestamp,
				User:        "system",
				Resource:    service,
				Metadata: map[string]interface{}{
					"service": service,
					"details": check.Details,
				},
			})
			if len(recentAlerts) >= limit {
				break
			}
		}
	}
	
	// Create system events based on repository manager activity
	systemEvents := make([]*ActivityItem, 0, limit)
	connectors := ed.repoManager.ListConnectors()
	
	for _, connectorName := range connectors {
		systemEvents = append(systemEvents, &ActivityItem{
			ID:          fmt.Sprintf("connector-%s-%d", connectorName, time.Now().Unix()),
			Type:        "system",
			Title:       fmt.Sprintf("%s Connector Active", strings.Title(fmt.Sprintf("%v", connectorName))),
			Description: fmt.Sprintf("Repository connector %s is operational", connectorName),
			Severity:    "info",
			Timestamp:   time.Now().Add(-time.Minute * 30), // Simulate recent activity
			User:        "system",
			Resource:    fmt.Sprintf("connector-%s", connectorName),
			Metadata: map[string]interface{}{
				"connector": connectorName,
				"status":    "active",
			},
		})
		if len(systemEvents) >= limit {
			break
		}
	}
	
	// User activity would typically come from audit logs
	userActivity := []*ActivityItem{
		{
			ID:          fmt.Sprintf("user-activity-%d", time.Now().Unix()),
			Type:        "user",
			Title:       "Dashboard Access",
			Description: "User accessed enterprise dashboard",
			Severity:    "info",
			Timestamp:   time.Now().Add(-time.Minute * 5),
			User:        "admin", // Would come from actual user context
			Resource:    "dashboard",
			Metadata: map[string]interface{}{
				"action": "view",
				"ip":     "127.0.0.1", // Would come from request context
			},
		},
	}
	
	return &RecentActivityData{
		RecentScans:   recentScans,
		RecentThreats: recentThreats,
		RecentAlerts:  recentAlerts,
		UserActivity:  userActivity,
		SystemEvents:  systemEvents,
	}, nil
}

// collectAlertsData collects alerts information from the monitoring service's alert manager
func (ed *EnterpriseDashboard) collectAlertsData() *AlertsData {
	// Get system health which contains information about current system state
	healthData := ed.monitoringService.GetSystemHealth()
	
	// Since we don't have direct access to the AlertManager's GetActiveAlerts method,
	// we'll extract alert information from health checks
	activeSummaries := make([]*AlertSummary, 0)
	recentSummaries := make([]*AlertSummary, 0)
	alertsByType := make(map[string]int64)
	alertsBySeverity := make(map[string]int64)
	
	// Process health checks that are unhealthy as alerts
	for serviceName, check := range healthData.Checks {
		if !check.Healthy {
			// Determine severity based on service importance
			severity := "medium" // Default severity
			if strings.Contains(serviceName, "critical") || strings.Contains(serviceName, "security") {
				severity = "critical"
			} else if strings.Contains(serviceName, "important") || strings.Contains(serviceName, "core") {
				severity = "high"
			} else if strings.Contains(serviceName, "minor") || strings.Contains(serviceName, "optional") {
				severity = "low"
			}
			
			// Create alert summary
			summary := &AlertSummary{
				ID:        fmt.Sprintf("%s-%d", serviceName, check.Timestamp.Unix()),
				Name:      fmt.Sprintf("%s Service Alert", strings.Title(serviceName)),
				Message:   check.Message,
				Severity:  severity,
				Timestamp: check.Timestamp,
				Resource:  serviceName,
				Status:    "active",
				Acknowledged: false,
			}
			
			// Add to active alerts
			activeSummaries = append(activeSummaries, summary)
			
			// Add to recent alerts if within the last 24 hours
			if time.Since(check.Timestamp) < 24*time.Hour {
				recentSummaries = append(recentSummaries, summary)
			}
			
			// Count by type (using service name as type)
			// Extract general service type from the service name
			serviceType := "system" // Default type
			if strings.Contains(serviceName, "security") || strings.Contains(serviceName, "threat") {
				serviceType = "security"
			} else if strings.Contains(serviceName, "performance") || strings.Contains(serviceName, "resource") {
				serviceType = "performance"
			}
			
			alertsByType[serviceType]++
			
			// Count by severity
			alertsBySeverity[severity]++
		}
	}
	
	// For now, we don't have a way to get resolved alerts count directly
	// In a real implementation, this would come from a historical alerts database
	resolvedCount := int64(0)
	
	return &AlertsData{
		ActiveAlerts:     activeSummaries,
		RecentAlerts:     recentSummaries,
		AlertsByType:     alertsByType,
		AlertsBySeverity: alertsBySeverity,
		TotalAlerts:      int64(len(activeSummaries)),
		ResolvedAlerts:   resolvedCount,
	}
}

// collectComplianceData collects compliance information
func (ed *EnterpriseDashboard) collectComplianceData(ctx context.Context) (*ComplianceData, error) {
	// TODO: Implement actual data collection from compliance engine
	return &ComplianceData{
		OverallScore: 87.5,
		ComplianceByStandard: map[string]float64{
			"SOC2":     92.3,
			"ISO27001": 85.7,
			"NIST":     89.1,
			"GDPR":     91.2,
		},
		Violations:       []*ComplianceViolation{},
		RecentAudits:     []*AuditSummary{},
		ComplianceTrends: []*TrendDataPoint{},
	}, nil
}

// collectPerformanceData collects performance metrics
func (ed *EnterpriseDashboard) collectPerformanceData() *PerformanceData {
	return &PerformanceData{
		ResponseTimes: map[string]float64{
			"api":       125.5,
			"scanner":   2340.2,
			"dashboard": 89.3,
		},
		Throughput: map[string]float64{
			"scans_per_hour":    45.2,
			"api_requests_per_sec": 23.7,
		},
		ErrorRates: map[string]float64{
			"api":     0.02,
			"scanner": 0.05,
		},
		ResourceMetrics:   collectResourceUsage(),
		PerformanceTrends: []*TrendDataPoint{},
	}
}

// collectTrendData collects trend data for a specific metric
func (ed *EnterpriseDashboard) collectTrendData(metric string, period time.Duration) ([]*TrendDataPoint, error) {
	ctx := context.Background()
	now := time.Now()
	startTime := now.Add(-period)
	
	// Calculate number of data points based on period
	var interval time.Duration
	var numPoints int
	
	switch {
	case period <= time.Hour:
		interval = 5 * time.Minute
		numPoints = int(period / interval)
	case period <= 24*time.Hour:
		interval = time.Hour
		numPoints = int(period / interval)
	case period <= 7*24*time.Hour:
		interval = 6 * time.Hour
		numPoints = int(period / interval)
	default:
		interval = 24 * time.Hour
		numPoints = int(period / interval)
	}
	
	if numPoints > 100 {
		numPoints = 100 // Limit to prevent excessive data points
		interval = period / time.Duration(numPoints)
	}
	
	var trends []*TrendDataPoint
	
	switch metric {
	case "vulnerabilities":
		trends = ed.collectVulnerabilityTrends(ctx, startTime, interval, numPoints)
	case "scans":
		trends = ed.collectScanTrends(ctx, startTime, interval, numPoints)
	case "threats":
		trends = ed.collectThreatTrends(ctx, startTime, interval, numPoints)
	case "repositories":
		trends = ed.collectRepositoryTrends(ctx, startTime, interval, numPoints)
	case "performance":
		trends = ed.collectPerformanceTrends(ctx, startTime, interval, numPoints)
	case "compliance":
		trends = ed.collectComplianceTrends(ctx, startTime, interval, numPoints)
	default:
		return nil, fmt.Errorf("unsupported metric: %s", metric)
	}
	
	return trends, nil
}

// collectVulnerabilityTrends collects vulnerability trend data
func (ed *EnterpriseDashboard) collectVulnerabilityTrends(ctx context.Context, startTime time.Time, interval time.Duration, numPoints int) []*TrendDataPoint {
	trends := make([]*TrendDataPoint, 0, numPoints)
	
	for i := 0; i < numPoints; i++ {
		timestamp := startTime.Add(time.Duration(i) * interval)
		
		// Simulate vulnerability trend data based on time patterns
		baseValue := 150.0
		timeVariation := math.Sin(float64(i)*0.1) * 20
		randomVariation := (rand.Float64() - 0.5) * 10
		value := baseValue + timeVariation + randomVariation
		
		trends = append(trends, &TrendDataPoint{
			Timestamp: timestamp,
			Value:     math.Max(0, value),
			Label:     "Vulnerabilities",
		})
	}
	
	return trends
}

// collectScanTrends collects scan trend data
func (ed *EnterpriseDashboard) collectScanTrends(ctx context.Context, startTime time.Time, interval time.Duration, numPoints int) []*TrendDataPoint {
	trends := make([]*TrendDataPoint, 0, numPoints)
	
	for i := 0; i < numPoints; i++ {
		timestamp := startTime.Add(time.Duration(i) * interval)
		
		// Simulate scan trend data - higher during business hours
		hour := timestamp.Hour()
		baseValue := 25.0
		if hour >= 9 && hour <= 17 {
			baseValue = 45.0
		}
		randomVariation := (rand.Float64() - 0.5) * 10
		value := baseValue + randomVariation
		
		trends = append(trends, &TrendDataPoint{
			Timestamp: timestamp,
			Value:     math.Max(0, value),
			Label:     "Scans",
		})
	}
	
	return trends
}

// collectThreatTrends collects threat trend data
func (ed *EnterpriseDashboard) collectThreatTrends(ctx context.Context, startTime time.Time, interval time.Duration, numPoints int) []*TrendDataPoint {
	trends := make([]*TrendDataPoint, 0, numPoints)
	
	for i := 0; i < numPoints; i++ {
		timestamp := startTime.Add(time.Duration(i) * interval)
		
		// Simulate threat trend data with occasional spikes
		baseValue := 12.0
		spikeChance := rand.Float64()
		if spikeChance < 0.05 { // 5% chance of spike
			baseValue *= 3
		}
		randomVariation := (rand.Float64() - 0.5) * 5
		value := baseValue + randomVariation
		
		trends = append(trends, &TrendDataPoint{
			Timestamp: timestamp,
			Value:     math.Max(0, value),
			Label:     "Threats",
		})
	}
	
	return trends
}

// collectRepositoryTrends collects repository trend data
func (ed *EnterpriseDashboard) collectRepositoryTrends(ctx context.Context, startTime time.Time, interval time.Duration, numPoints int) []*TrendDataPoint {
	trends := make([]*TrendDataPoint, 0, numPoints)
	
	baseRepos := 500.0
	for i := 0; i < numPoints; i++ {
		timestamp := startTime.Add(time.Duration(i) * interval)
		
		// Simulate gradual repository growth
		growthRate := 0.1 // Small growth over time
		value := baseRepos + float64(i)*growthRate + (rand.Float64()-0.5)*2
		
		trends = append(trends, &TrendDataPoint{
			Timestamp: timestamp,
			Value:     math.Max(0, value),
			Label:     "Repositories",
		})
	}
	
	return trends
}

// collectPerformanceTrends collects performance trend data
func (ed *EnterpriseDashboard) collectPerformanceTrends(ctx context.Context, startTime time.Time, interval time.Duration, numPoints int) []*TrendDataPoint {
	trends := make([]*TrendDataPoint, 0, numPoints)
	
	for i := 0; i < numPoints; i++ {
		timestamp := startTime.Add(time.Duration(i) * interval)
		
		// Simulate performance metrics (response time in ms)
		baseValue := 250.0
		loadVariation := math.Sin(float64(i)*0.2) * 50 // Load-based variation
		randomVariation := (rand.Float64() - 0.5) * 30
		value := baseValue + loadVariation + randomVariation
		
		trends = append(trends, &TrendDataPoint{
			Timestamp: timestamp,
			Value:     math.Max(50, value), // Minimum 50ms
			Label:     "Response Time (ms)",
		})
	}
	
	return trends
}

// collectComplianceTrends collects compliance trend data
func (ed *EnterpriseDashboard) collectComplianceTrends(ctx context.Context, startTime time.Time, interval time.Duration, numPoints int) []*TrendDataPoint {
	trends := make([]*TrendDataPoint, 0, numPoints)
	
	for i := 0; i < numPoints; i++ {
		timestamp := startTime.Add(time.Duration(i) * interval)
		
		// Simulate compliance score (0-100)
		baseValue := 85.0
		trend := float64(i) * 0.05 // Slight improvement over time
		randomVariation := (rand.Float64() - 0.5) * 3
		value := baseValue + trend + randomVariation
		
		trends = append(trends, &TrendDataPoint{
			Timestamp: timestamp,
			Value:     math.Min(100, math.Max(0, value)),
			Label:     "Compliance Score",
		})
	}
	
	return trends
}

// Helper functions

func getHealthStatus(healthy bool) string {
	if healthy {
		return "healthy"
	}
	return "unhealthy"
}

func collectResourceUsage() *ResourceUsageData {
	// TODO: Implement actual resource usage collection
	return &ResourceUsageData{
		CPUUsage:    45.2,
		MemoryUsage: 67.8,
		DiskUsage:   23.4,
		NetworkIO:   12.5,
		OpenFiles:   234,
		Goroutines:  156,
	}
}

func calculateThroughput(metrics *orchestrator.SchedulerMetrics) float64 {
	if metrics.TotalRuns == 0 {
		return 0
	}
	// Calculate scans per hour based on average run time
	if metrics.AverageRunTime > 0 {
		return float64(time.Hour) / float64(metrics.AverageRunTime)
	}
	return 0
}

// generateCSVExport generates CSV format export of dashboard data
func (ed *EnterpriseDashboard) generateCSVExport(data *DashboardData) (string, error) {
	var buf bytes.Buffer
	writer := csv.NewWriter(&buf)

	// Overview section
	writer.Write([]string{"Section", "Metric", "Value"})
	writer.Write([]string{"Overview", "Total Repositories", strconv.FormatInt(data.Overview.TotalRepositories, 10)})
	writer.Write([]string{"Overview", "Active Scans", strconv.FormatInt(data.Overview.ActiveScans, 10)})
	writer.Write([]string{"Overview", "Total Threats", strconv.FormatInt(data.Overview.TotalThreats, 10)})
	writer.Write([]string{"Overview", "Critical Threats", strconv.FormatInt(data.Overview.CriticalThreats, 10)})
	writer.Write([]string{"Overview", "Scan Success Rate", fmt.Sprintf("%.2f%%", data.Overview.ScanSuccessRate)})
	writer.Write([]string{"Overview", "Average Risk Score", fmt.Sprintf("%.2f", data.Overview.AverageRiskScore)})

	// Security metrics
	writer.Write([]string{"Security", "Total Vulnerabilities", strconv.FormatInt(data.SecurityMetrics.TotalVulnerabilities, 10)})
	writer.Write([]string{"Security", "Critical Vulnerabilities", strconv.FormatInt(data.SecurityMetrics.CriticalVulnerabilities, 10)})
	writer.Write([]string{"Security", "High Vulnerabilities", strconv.FormatInt(data.SecurityMetrics.HighVulnerabilities, 10)})
	writer.Write([]string{"Security", "Medium Vulnerabilities", strconv.FormatInt(data.SecurityMetrics.MediumVulnerabilities, 10)})
	writer.Write([]string{"Security", "Low Vulnerabilities", strconv.FormatInt(data.SecurityMetrics.LowVulnerabilities, 10)})

	// Scanning metrics
	writer.Write([]string{"Scanning", "Scheduled Scans", strconv.FormatInt(data.ScanningMetrics.ScheduledScans, 10)})
	writer.Write([]string{"Scanning", "Completed Scans", strconv.FormatInt(data.ScanningMetrics.CompletedScans, 10)})
	writer.Write([]string{"Scanning", "Failed Scans", strconv.FormatInt(data.ScanningMetrics.FailedScans, 10)})
	writer.Write([]string{"Scanning", "Queue Size", strconv.Itoa(data.ScanningMetrics.QueueSize)})
	writer.Write([]string{"Scanning", "Throughput", fmt.Sprintf("%.2f", data.ScanningMetrics.Throughput)})

	// System health
	writer.Write([]string{"System", "Overall Status", data.SystemHealth.OverallStatus})
	writer.Write([]string{"System", "CPU Usage", fmt.Sprintf("%.2f%%", data.SystemHealth.ResourceUsage.CPUUsage)})
	writer.Write([]string{"System", "Memory Usage", fmt.Sprintf("%.2f%%", data.SystemHealth.ResourceUsage.MemoryUsage)})
	writer.Write([]string{"System", "Disk Usage", fmt.Sprintf("%.2f%%", data.SystemHealth.ResourceUsage.DiskUsage)})

	// Compliance
	writer.Write([]string{"Compliance", "Overall Score", fmt.Sprintf("%.2f", data.Compliance.OverallScore)})

	writer.Flush()
	return buf.String(), writer.Error()
}

// generateXMLExport generates XML format export of dashboard data
func (ed *EnterpriseDashboard) generateXMLExport(data *DashboardData) (string, error) {
	var buf strings.Builder
	buf.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	buf.WriteString("\n<dashboard timestamp=\"" + data.Timestamp.Format(time.RFC3339) + "\">\n")
	
	// Overview
	buf.WriteString("  <overview>\n")
	buf.WriteString(fmt.Sprintf("    <total_repositories>%d</total_repositories>\n", data.Overview.TotalRepositories))
	buf.WriteString(fmt.Sprintf("    <active_scans>%d</active_scans>\n", data.Overview.ActiveScans))
	buf.WriteString(fmt.Sprintf("    <total_threats>%d</total_threats>\n", data.Overview.TotalThreats))
	buf.WriteString(fmt.Sprintf("    <critical_threats>%d</critical_threats>\n", data.Overview.CriticalThreats))
	buf.WriteString(fmt.Sprintf("    <scan_success_rate>%.2f</scan_success_rate>\n", data.Overview.ScanSuccessRate))
	buf.WriteString(fmt.Sprintf("    <average_risk_score>%.2f</average_risk_score>\n", data.Overview.AverageRiskScore))
	buf.WriteString("  </overview>\n")
	
	// Security metrics
	buf.WriteString("  <security_metrics>\n")
	buf.WriteString(fmt.Sprintf("    <total_vulnerabilities>%d</total_vulnerabilities>\n", data.SecurityMetrics.TotalVulnerabilities))
	buf.WriteString(fmt.Sprintf("    <critical_vulnerabilities>%d</critical_vulnerabilities>\n", data.SecurityMetrics.CriticalVulnerabilities))
	buf.WriteString(fmt.Sprintf("    <high_vulnerabilities>%d</high_vulnerabilities>\n", data.SecurityMetrics.HighVulnerabilities))
	buf.WriteString(fmt.Sprintf("    <medium_vulnerabilities>%d</medium_vulnerabilities>\n", data.SecurityMetrics.MediumVulnerabilities))
	buf.WriteString(fmt.Sprintf("    <low_vulnerabilities>%d</low_vulnerabilities>\n", data.SecurityMetrics.LowVulnerabilities))
	buf.WriteString("  </security_metrics>\n")
	
	// System health
	buf.WriteString("  <system_health>\n")
	buf.WriteString(fmt.Sprintf("    <overall_status>%s</overall_status>\n", data.SystemHealth.OverallStatus))
	buf.WriteString("    <resource_usage>\n")
	buf.WriteString(fmt.Sprintf("      <cpu_usage>%.2f</cpu_usage>\n", data.SystemHealth.ResourceUsage.CPUUsage))
	buf.WriteString(fmt.Sprintf("      <memory_usage>%.2f</memory_usage>\n", data.SystemHealth.ResourceUsage.MemoryUsage))
	buf.WriteString(fmt.Sprintf("      <disk_usage>%.2f</disk_usage>\n", data.SystemHealth.ResourceUsage.DiskUsage))
	buf.WriteString("    </resource_usage>\n")
	buf.WriteString("  </system_health>\n")
	
	// Compliance
	buf.WriteString("  <compliance>\n")
	buf.WriteString(fmt.Sprintf("    <overall_score>%.2f</overall_score>\n", data.Compliance.OverallScore))
	buf.WriteString("  </compliance>\n")
	
	buf.WriteString("</dashboard>\n")
	return buf.String(), nil
}

// generateHTMLExport generates HTML format export of dashboard data
func (ed *EnterpriseDashboard) generateHTMLExport(data *DashboardData) (string, error) {
	var buf strings.Builder
	buf.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TypoSentinel Enterprise Dashboard Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; margin-bottom: 30px; border-bottom: 2px solid #007bff; padding-bottom: 20px; }
        .section { margin-bottom: 30px; }
        .section h2 { color: #007bff; border-bottom: 1px solid #ddd; padding-bottom: 10px; }
        .metrics-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; }
        .metric-card { background: #f8f9fa; padding: 15px; border-radius: 5px; border-left: 4px solid #007bff; }
        .metric-value { font-size: 24px; font-weight: bold; color: #333; }
        .metric-label { color: #666; font-size: 14px; }
        .status-healthy { color: #28a745; }
        .status-warning { color: #ffc107; }
        .status-critical { color: #dc3545; }
        .timestamp { text-align: center; margin-top: 30px; color: #666; font-style: italic; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>TypoSentinel Enterprise Dashboard Report</h1>
            <p>Generated on ` + data.Timestamp.Format("January 2, 2006 at 3:04 PM MST") + `</p>
        </div>
`)

	// Overview section
	buf.WriteString(`        <div class="section">
            <h2>Overview</h2>
            <div class="metrics-grid">
`)
	buf.WriteString(fmt.Sprintf(`                <div class="metric-card">
                    <div class="metric-value">%d</div>
                    <div class="metric-label">Total Repositories</div>
                </div>
`, data.Overview.TotalRepositories))
	buf.WriteString(fmt.Sprintf(`                <div class="metric-card">
                    <div class="metric-value">%d</div>
                    <div class="metric-label">Active Scans</div>
                </div>
`, data.Overview.ActiveScans))
	buf.WriteString(fmt.Sprintf(`                <div class="metric-card">
                    <div class="metric-value">%d</div>
                    <div class="metric-label">Total Threats</div>
                </div>
`, data.Overview.TotalThreats))
	buf.WriteString(fmt.Sprintf(`                <div class="metric-card">
                    <div class="metric-value status-critical">%d</div>
                    <div class="metric-label">Critical Threats</div>
                </div>
`, data.Overview.CriticalThreats))
	buf.WriteString(`            </div>
        </div>
`)

	// Security metrics section
	buf.WriteString(`        <div class="section">
            <h2>Security Metrics</h2>
            <div class="metrics-grid">
`)
	buf.WriteString(fmt.Sprintf(`                <div class="metric-card">
                    <div class="metric-value">%d</div>
                    <div class="metric-label">Total Vulnerabilities</div>
                </div>
`, data.SecurityMetrics.TotalVulnerabilities))
	buf.WriteString(fmt.Sprintf(`                <div class="metric-card">
                    <div class="metric-value status-critical">%d</div>
                    <div class="metric-label">Critical Vulnerabilities</div>
                </div>
`, data.SecurityMetrics.CriticalVulnerabilities))
	buf.WriteString(fmt.Sprintf(`                <div class="metric-card">
                    <div class="metric-value status-warning">%d</div>
                    <div class="metric-label">High Vulnerabilities</div>
                </div>
`, data.SecurityMetrics.HighVulnerabilities))
	buf.WriteString(`            </div>
        </div>
`)

	// System health section
	buf.WriteString(`        <div class="section">
            <h2>System Health</h2>
            <div class="metrics-grid">
`)
	statusClass := "status-healthy"
	if data.SystemHealth.OverallStatus != "healthy" {
		statusClass = "status-warning"
	}
	buf.WriteString(fmt.Sprintf(`                <div class="metric-card">
                    <div class="metric-value %s">%s</div>
                    <div class="metric-label">Overall Status</div>
                </div>
`, statusClass, strings.Title(data.SystemHealth.OverallStatus)))
	buf.WriteString(fmt.Sprintf(`                <div class="metric-card">
                    <div class="metric-value">%.1f%%</div>
                    <div class="metric-label">CPU Usage</div>
                </div>
`, data.SystemHealth.ResourceUsage.CPUUsage))
	buf.WriteString(fmt.Sprintf(`                <div class="metric-card">
                    <div class="metric-value">%.1f%%</div>
                    <div class="metric-label">Memory Usage</div>
                </div>
`, data.SystemHealth.ResourceUsage.MemoryUsage))
	buf.WriteString(`            </div>
        </div>
`)

	buf.WriteString(`        <div class="timestamp">
            Report generated by TypoSentinel Enterprise Dashboard
        </div>
    </div>
</body>
</html>`)

	return buf.String(), nil
}