package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/repository"
)

// Dashboard provides a web interface for monitoring and managing the orchestrator
type Dashboard struct {
	config      *DashboardConfig
	coordinator *ScanCoordinator
	metrics     *DashboardMetrics
	server      *http.Server
}

// DashboardConfig defines dashboard configuration
type DashboardConfig struct {
	Enabled     bool   `json:"enabled"`
	Port        int    `json:"port"`
	Host        string `json:"host"`
	BasePath    string `json:"base_path"`
	AuthEnabled bool   `json:"auth_enabled"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	TLSEnabled  bool   `json:"tls_enabled"`
	CertFile    string `json:"cert_file"`
	KeyFile     string `json:"key_file"`
	RefreshRate int    `json:"refresh_rate"` // seconds
	MaxHistory  int    `json:"max_history"`  // number of historical records to keep
}

// DashboardMetrics holds dashboard-specific metrics
type DashboardMetrics struct {
	ActiveScans       int                `json:"active_scans"`
	CompletedScans    int                `json:"completed_scans"`
	FailedScans       int                `json:"failed_scans"`
	TotalRepositories int                `json:"total_repositories"`
	TotalThreats      int                `json:"total_threats"`
	AverageRiskScore  float64            `json:"average_risk_score"`
	SystemHealth      string             `json:"system_health"`
	Uptime            time.Duration      `json:"uptime"`
	LastUpdated       time.Time          `json:"last_updated"`
	ScanHistory       []ScanHistoryEntry `json:"scan_history"`
	ThreatTrends      []ThreatTrendEntry `json:"threat_trends"`
	PerformanceStats  PerformanceStats   `json:"performance_stats"`
	IntegrationStatus map[string]string  `json:"integration_status"`
}

// ScanHistoryEntry represents a historical scan record
type ScanHistoryEntry struct {
	Timestamp   time.Time `json:"timestamp"`
	ScanID      string    `json:"scan_id"`
	Repository  string    `json:"repository"`
	Status      string    `json:"status"`
	Duration    int64     `json:"duration_ms"`
	ThreatCount int       `json:"threat_count"`
	RiskScore   float64   `json:"risk_score"`
}

// ThreatTrendEntry represents threat trend data
type ThreatTrendEntry struct {
	Timestamp   time.Time `json:"timestamp"`
	ThreatCount int       `json:"threat_count"`
	RiskScore   float64   `json:"risk_score"`
}

// PerformanceStats holds performance statistics
type PerformanceStats struct {
	AverageScanTime  float64 `json:"average_scan_time_ms"`
	ScansPerHour     float64 `json:"scans_per_hour"`
	MemoryUsage      int64   `json:"memory_usage_mb"`
	CPUUsage         float64 `json:"cpu_usage_percent"`
	DiskUsage        int64   `json:"disk_usage_mb"`
	NetworkBandwidth int64   `json:"network_bandwidth_mbps"`
}

// ScanningMetrics represents current scanning metrics
type ScanningMetrics struct {
	ActiveScans    int                    `json:"active_scans"`
	QueuedScans    int                    `json:"queued_scans"`
	CompletedToday int                    `json:"completed_today"`
	FailedToday    int                    `json:"failed_today"`
	AverageTime    time.Duration          `json:"average_time"`
	Throughput     float64                `json:"throughput"`
	ErrorRate      float64                `json:"error_rate"`
	Details        map[string]interface{} `json:"details"`
}

// NewDashboard creates a new dashboard instance
func NewDashboard(config *DashboardConfig, coordinator *ScanCoordinator) *Dashboard {
	if config.Port == 0 {
		config.Port = 8080
	}
	if config.Host == "" {
		config.Host = "localhost"
	}
	if config.RefreshRate == 0 {
		config.RefreshRate = 30
	}
	if config.MaxHistory == 0 {
		config.MaxHistory = 1000
	}

	return &Dashboard{
		config:      config,
		coordinator: coordinator,
		metrics: &DashboardMetrics{
			ScanHistory:       make([]ScanHistoryEntry, 0),
			ThreatTrends:      make([]ThreatTrendEntry, 0),
			IntegrationStatus: make(map[string]string),
			LastUpdated:       time.Now(),
		},
	}
}

// Start starts the dashboard web server
func (d *Dashboard) Start(ctx context.Context) error {
	if !d.config.Enabled {
		return nil
	}

	mux := http.NewServeMux()
	d.setupRoutes(mux)

	addr := fmt.Sprintf("%s:%d", d.config.Host, d.config.Port)
	d.server = &http.Server{
		Addr:    addr,
		Handler: d.authMiddleware(mux),
	}

	// Start metrics collection
	go d.collectMetrics(ctx)

	if d.config.TLSEnabled {
		return d.server.ListenAndServeTLS(d.config.CertFile, d.config.KeyFile)
	}

	return d.server.ListenAndServe()
}

// Stop stops the dashboard web server
func (d *Dashboard) Stop(ctx context.Context) error {
	if d.server != nil {
		return d.server.Shutdown(ctx)
	}
	return nil
}

// setupRoutes configures HTTP routes
func (d *Dashboard) setupRoutes(mux *http.ServeMux) {
	basePath := d.config.BasePath
	if basePath == "" {
		basePath = "/"
	}

	// Static dashboard page
	mux.HandleFunc(basePath, d.handleDashboard)

	// API endpoints
	mux.HandleFunc(basePath+"api/metrics", d.handleMetrics)
	mux.HandleFunc(basePath+"api/scans", d.handleScans)
	mux.HandleFunc(basePath+"api/repositories", d.handleRepositories)
	mux.HandleFunc(basePath+"api/threats", d.handleThreats)
	mux.HandleFunc(basePath+"api/health", d.handleHealth)
	mux.HandleFunc(basePath+"api/config", d.handleConfig)
	mux.HandleFunc(basePath+"api/integrations", d.handleIntegrations)
	mux.HandleFunc(basePath+"api/performance", d.handlePerformance)

	// Control endpoints
	mux.HandleFunc(basePath+"api/scan/start", d.handleStartScan)
	mux.HandleFunc(basePath+"api/scan/stop", d.handleStopScan)
	mux.HandleFunc(basePath+"api/discovery/start", d.handleStartDiscovery)
}

// authMiddleware provides basic authentication if enabled
func (d *Dashboard) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if d.config.AuthEnabled {
			username, password, ok := r.BasicAuth()
			if !ok || username != d.config.Username || password != d.config.Password {
				w.Header().Set("WWW-Authenticate", `Basic realm="Dashboard"`)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// collectMetrics periodically collects system metrics
func (d *Dashboard) collectMetrics(ctx context.Context) {
	ticker := time.NewTicker(time.Duration(d.config.RefreshRate) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.updateMetrics()
		}
	}
}

// updateMetrics updates dashboard metrics
func (d *Dashboard) updateMetrics() {
	// Update basic metrics
	d.metrics.LastUpdated = time.Now()

	// Get metrics from coordinator
	if d.coordinator != nil {
		coordinatorMetrics := d.coordinator.GetMetrics()
		if coordinatorMetrics != nil {
			d.metrics.ActiveScans = coordinatorMetrics.ActiveScans
			d.metrics.CompletedScans = int(coordinatorMetrics.CompletedScans)
			d.metrics.FailedScans = int(coordinatorMetrics.FailedScans)
			d.metrics.TotalRepositories = int(coordinatorMetrics.TotalRepositories)
			d.metrics.TotalThreats = int(coordinatorMetrics.TotalThreats)
		}

		// Get active scans
		activeScans := d.coordinator.ListScans()
		for _, scan := range activeScans {
			if scan.Status == "running" {
				d.metrics.ActiveScans++
			}
		}
	}

	// Update system health
	d.updateSystemHealth()
}

// updateSystemHealth determines overall system health
func (d *Dashboard) updateSystemHealth() {
	health := "healthy"

	// Check error rates
	if d.metrics.FailedScans > 0 {
		errorRate := float64(d.metrics.FailedScans) / float64(d.metrics.CompletedScans+d.metrics.FailedScans)
		if errorRate > 0.1 { // 10% error rate
			health = "degraded"
		}
		if errorRate > 0.25 { // 25% error rate
			health = "unhealthy"
		}
	}

	// Check integration health
	for _, status := range d.metrics.IntegrationStatus {
		if status == "error" && health == "healthy" {
			health = "degraded"
		}
	}

	d.metrics.SystemHealth = health
}

// HTTP Handlers

// handleDashboard serves the main dashboard HTML page
func (d *Dashboard) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(d.getDashboardHTML()))
}

// handleMetrics returns current metrics as JSON
func (d *Dashboard) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(d.metrics)
}

// handleScans returns scan information
func (d *Dashboard) handleScans(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get scan history with optional filtering
	limit := 100
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil {
			limit = l
		}
	}

	history := d.metrics.ScanHistory
	if len(history) > limit {
		history = history[len(history)-limit:]
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"scans":  history,
		"total":  len(d.metrics.ScanHistory),
		"active": d.metrics.ActiveScans,
	})
}

// handleRepositories returns repository information
func (d *Dashboard) handleRepositories(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// This would typically fetch from the orchestrator
	repos := map[string]interface{}{
		"total":        d.metrics.TotalRepositories,
		"scanned":      d.metrics.CompletedScans,
		"with_threats": d.metrics.TotalThreats,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(repos)
}

// handleThreats returns threat information
func (d *Dashboard) handleThreats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	threats := map[string]interface{}{
		"total":        d.metrics.TotalThreats,
		"average_risk": d.metrics.AverageRiskScore,
		"trends":       d.metrics.ThreatTrends,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(threats)
}

// handleHealth returns system health status
func (d *Dashboard) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	health := map[string]interface{}{
		"status":       d.metrics.SystemHealth,
		"uptime":       d.metrics.Uptime.String(),
		"last_updated": d.metrics.LastUpdated,
		"integrations": d.metrics.IntegrationStatus,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(health)
}

// handleConfig returns dashboard configuration
func (d *Dashboard) handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Return safe config (without sensitive data)
	config := map[string]interface{}{
		"refresh_rate": d.config.RefreshRate,
		"max_history":  d.config.MaxHistory,
		"auth_enabled": d.config.AuthEnabled,
		"tls_enabled":  d.config.TLSEnabled,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config)
}

// handleIntegrations returns integration status
func (d *Dashboard) handleIntegrations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(d.metrics.IntegrationStatus)
}

// handlePerformance returns performance statistics
func (d *Dashboard) handlePerformance(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(d.metrics.PerformanceStats)
}

// Control Handlers

// handleStartScan starts a new scan
func (d *Dashboard) handleStartScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var request struct {
		Repository string `json:"repository"`
		Branch     string `json:"branch"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// This would trigger a scan via the orchestrator
	response := map[string]interface{}{
		"status":  "started",
		"scan_id": fmt.Sprintf("scan_%d", time.Now().Unix()),
		"message": fmt.Sprintf("Scan started for %s", request.Repository),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleStopScan stops a running scan
func (d *Dashboard) handleStopScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var request struct {
		ScanID string `json:"scan_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// This would stop a scan via the orchestrator
	response := map[string]interface{}{
		"status":  "stopped",
		"scan_id": request.ScanID,
		"message": "Scan stopped successfully",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleStartDiscovery starts repository discovery
func (d *Dashboard) handleStartDiscovery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var request struct {
		Platforms []string `json:"platforms"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// This would trigger discovery via the orchestrator
	response := map[string]interface{}{
		"status":    "started",
		"platforms": request.Platforms,
		"message":   "Repository discovery started",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// AddScanResult adds a scan result to the dashboard metrics
func (d *Dashboard) AddScanResult(result *repository.ScanResult) {
	entry := ScanHistoryEntry{
		Timestamp:   time.Now(),
		ScanID:      result.ScanID,
		Repository:  result.Repository.FullName,
		Status:      result.Status,
		Duration:    result.Duration.Milliseconds(),
		ThreatCount: 0,
		RiskScore:   0.0,
	}

	// Extract threat information if available
	if result.AnalysisResult != nil {
		if analysisMap, ok := result.AnalysisResult.(map[string]interface{}); ok {
			if threats, ok := analysisMap["threats"]; ok {
				if threatList, ok := threats.([]interface{}); ok {
					entry.ThreatCount = len(threatList)
				}
			}
			if riskScore, ok := analysisMap["risk_score"]; ok {
				if score, ok := riskScore.(float64); ok {
					entry.RiskScore = score
				}
			}
		}
	}

	// Add to history
	d.metrics.ScanHistory = append(d.metrics.ScanHistory, entry)

	// Trim history if too long
	if len(d.metrics.ScanHistory) > d.config.MaxHistory {
		d.metrics.ScanHistory = d.metrics.ScanHistory[1:]
	}

	// Update threat trends
	trendEntry := ThreatTrendEntry{
		Timestamp:   time.Now(),
		ThreatCount: entry.ThreatCount,
		RiskScore:   entry.RiskScore,
	}
	d.metrics.ThreatTrends = append(d.metrics.ThreatTrends, trendEntry)

	// Trim trends if too long
	if len(d.metrics.ThreatTrends) > d.config.MaxHistory {
		d.metrics.ThreatTrends = d.metrics.ThreatTrends[1:]
	}

	// Update aggregated metrics
	if result.Status == "completed" {
		d.metrics.CompletedScans++
	} else if result.Status == "failed" {
		d.metrics.FailedScans++
	}

	d.metrics.TotalThreats += entry.ThreatCount

	// Recalculate average risk score
	if len(d.metrics.ScanHistory) > 0 {
		totalRisk := 0.0
		count := 0
		for _, scan := range d.metrics.ScanHistory {
			if scan.RiskScore > 0 {
				totalRisk += scan.RiskScore
				count++
			}
		}
		if count > 0 {
			d.metrics.AverageRiskScore = totalRisk / float64(count)
		}
	}
}

// GetMetrics returns current dashboard metrics
func (d *Dashboard) GetMetrics() *DashboardMetrics {
	return d.metrics
}

// GetRecentScans returns recent scan results
func (d *Dashboard) GetRecentScans(limit int) []ScanHistoryEntry {
	history := d.metrics.ScanHistory
	if len(history) > limit {
		return history[len(history)-limit:]
	}
	return history
}

// GetThreatTrends returns threat trend data
func (d *Dashboard) GetThreatTrends(hours int) []ThreatTrendEntry {
	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour)
	var trends []ThreatTrendEntry

	for _, trend := range d.metrics.ThreatTrends {
		if trend.Timestamp.After(cutoff) {
			trends = append(trends, trend)
		}
	}

	return trends
}

// GetTopThreats returns repositories with the highest threat counts
func (d *Dashboard) GetTopThreats(limit int) []ScanHistoryEntry {
	// Create a copy and sort by threat count
	scans := make([]ScanHistoryEntry, len(d.metrics.ScanHistory))
	copy(scans, d.metrics.ScanHistory)

	sort.Slice(scans, func(i, j int) bool {
		return scans[i].ThreatCount > scans[j].ThreatCount
	})

	if len(scans) > limit {
		return scans[:limit]
	}
	return scans
}

// getDashboardHTML returns the HTML for the dashboard page
func (d *Dashboard) getDashboardHTML() string {
	return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TypoSentinel Dashboard</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background-color: #f5f5f5; color: #333; margin: 0; padding: 0; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 1rem 2rem; }
        .header h1 { font-size: 2rem; font-weight: 300; margin: 0; }
        .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
        .metrics-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 1.5rem; margin-bottom: 2rem; }
        .metric-card { background: white; padding: 1.5rem; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); border-left: 4px solid #667eea; }
        .metric-card h3 { color: #666; font-size: 0.9rem; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 0.5rem; }
        .metric-value { font-size: 2rem; font-weight: bold; color: #333; }
        .status-healthy { color: #28a745; }
        .status-degraded { color: #ffc107; }
        .status-unhealthy { color: #dc3545; }
        .recent-scans { background: white; padding: 1.5rem; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .scan-item { display: flex; justify-content: space-between; align-items: center; padding: 0.75rem 0; border-bottom: 1px solid #eee; }
        .scan-item:last-child { border-bottom: none; }
        .scan-status { padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.8rem; font-weight: bold; }
        .status-completed { background: #d4edda; color: #155724; }
        .status-failed { background: #f8d7da; color: #721c24; }
        .status-running { background: #d1ecf1; color: #0c5460; }
        .refresh-indicator { position: fixed; top: 1rem; right: 1rem; background: rgba(255,255,255,0.9); padding: 0.5rem 1rem; border-radius: 4px; font-size: 0.8rem; color: #666; }
    </style>
</head>
<body>
    <div class="header">
        <h1>TypoSentinel Dashboard</h1>
    </div>
    <div class="refresh-indicator" id="refreshIndicator">
        Last updated: <span id="lastUpdate">Loading...</span>
    </div>
    <div class="container">
        <div class="metrics-grid">
            <div class="metric-card">
                <h3>Active Scans</h3>
                <div class="metric-value" id="activeScans">-</div>
            </div>
            <div class="metric-card">
                <h3>Completed Scans</h3>
                <div class="metric-value" id="completedScans">-</div>
            </div>
            <div class="metric-card">
                <h3>Total Threats</h3>
                <div class="metric-value" id="totalThreats">-</div>
            </div>
            <div class="metric-card">
                <h3>System Health</h3>
                <div class="metric-value" id="systemHealth">-</div>
            </div>
            <div class="metric-card">
                <h3>Repositories</h3>
                <div class="metric-value" id="totalRepositories">-</div>
            </div>
            <div class="metric-card">
                <h3>Average Risk</h3>
                <div class="metric-value" id="averageRisk">-</div>
            </div>
        </div>
        <div class="recent-scans">
            <h3>Recent Scans</h3>
            <div id="recentScans">Loading...</div>
        </div>
    </div>
    <script>
        let refreshRate = 30000;
        function updateDashboard() {
            fetch('/api/metrics')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('activeScans').textContent = data.active_scans || 0;
                    document.getElementById('completedScans').textContent = data.completed_scans || 0;
                    document.getElementById('totalThreats').textContent = data.total_threats || 0;
                    document.getElementById('totalRepositories').textContent = data.total_repositories || 0;
                    document.getElementById('averageRisk').textContent = (data.average_risk_score || 0).toFixed(1);
                    const healthElement = document.getElementById('systemHealth');
                    healthElement.textContent = data.system_health || 'Unknown';
                    healthElement.className = 'metric-value status-' + (data.system_health || 'unknown');
                    document.getElementById('lastUpdate').textContent = new Date().toLocaleTimeString();
                })
                .catch(error => console.error('Error updating metrics:', error));
            fetch('/api/scans?limit=10')
                .then(response => response.json())
                .then(data => {
                    const scansContainer = document.getElementById('recentScans');
                    if (data.scans && data.scans.length > 0) {
                        scansContainer.innerHTML = data.scans.map(scan => 
                            '<div class="scan-item"><div><strong>' + scan.repository + '</strong><br><small>' + new Date(scan.timestamp).toLocaleString() + '</small></div><div><span class="scan-status status-' + scan.status + '">' + scan.status + '</span>' + (scan.threat_count > 0 ? '<br><small>' + scan.threat_count + ' threats</small>' : '') + '</div></div>'
                        ).join('');
                    } else {
                        scansContainer.innerHTML = '<p>No recent scans</p>';
                    }
                })
                .catch(error => console.error('Error updating scans:', error));
        }
        updateDashboard();
        setInterval(updateDashboard, refreshRate);
        fetch('/api/config')
            .then(response => response.json())
            .then(config => {
                if (config.refresh_rate) {
                    refreshRate = config.refresh_rate * 1000;
                }
            })
            .catch(error => console.error('Error loading config:', error));
    </script>
</body>
</html>`
}
