package security

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"time"
)

// SecurityDashboard provides a web interface for security monitoring
type SecurityDashboard struct {
	auditLogger   *AuditLogger
	policyEngine  *PolicyEngine
	rateLimiter   *RateLimiter
	inputValidator *InputValidator
	encryptionSvc *EncryptionService
}

// DashboardMetrics represents security metrics for the dashboard
type DashboardMetrics struct {
	TotalRequests       int64                    `json:"total_requests"`
	BlockedRequests     int64                    `json:"blocked_requests"`
	SecurityViolations  int64                    `json:"security_violations"`
	ActivePolicies      int                      `json:"active_policies"`
	RateLimitViolations int64                    `json:"rate_limit_violations"`
	InputValidationFails int64                   `json:"input_validation_fails"`
	TopThreats          []ThreatSummary          `json:"top_threats"`
	RecentEvents        []SecurityEventSummary   `json:"recent_events"`
	PolicyStats         map[string]PolicyStats   `json:"policy_stats"`
	SystemHealth        SystemHealthStatus       `json:"system_health"`
	Timestamp           time.Time                `json:"timestamp"`
}

// ThreatSummary represents a threat summary
type ThreatSummary struct {
	Type        string    `json:"type"`
	Count       int64     `json:"count"`
	LastSeen    time.Time `json:"last_seen"`
	Severity    string    `json:"severity"`
	Description string    `json:"description"`
}

// SecurityEventSummary represents a security event summary
type SecurityEventSummary struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Severity    string                 `json:"severity"`
	Message     string                 `json:"message"`
	UserID      string                 `json:"user_id"`
	IPAddress   string                 `json:"ip_address"`
	Timestamp   time.Time              `json:"timestamp"`
	Details     map[string]interface{} `json:"details"`
}

// PolicyStats represents policy statistics
type PolicyStats struct {
	PolicyID      string    `json:"policy_id"`
	PolicyName    string    `json:"policy_name"`
	Evaluations   int64     `json:"evaluations"`
	Violations    int64     `json:"violations"`
	LastTriggered time.Time `json:"last_triggered"`
	Enabled       bool      `json:"enabled"`
}

// SystemHealthStatus represents system health
type SystemHealthStatus struct {
	Status           string             `json:"status"`
	SecurityScore    int                `json:"security_score"`
	LastHealthCheck  time.Time          `json:"last_health_check"`
	Components       map[string]string  `json:"components"`
	Recommendations  []string           `json:"recommendations"`
}

// NewSecurityDashboard creates a new security dashboard
func NewSecurityDashboard(auditLogger *AuditLogger, policyEngine *PolicyEngine, 
	rateLimiter *RateLimiter, inputValidator *InputValidator, 
	encryptionSvc *EncryptionService) *SecurityDashboard {
	return &SecurityDashboard{
		auditLogger:    auditLogger,
		policyEngine:   policyEngine,
		rateLimiter:    rateLimiter,
		inputValidator: inputValidator,
		encryptionSvc:  encryptionSvc,
	}
}

// RegisterRoutes registers dashboard HTTP routes
func (sd *SecurityDashboard) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/security/dashboard", sd.handleDashboard)
	mux.HandleFunc("/security/metrics", sd.handleMetrics)
	mux.HandleFunc("/security/events", sd.handleEvents)
	mux.HandleFunc("/security/policies", sd.handlePolicies)
	mux.HandleFunc("/security/health", sd.handleHealth)
	mux.HandleFunc("/security/threats", sd.handleThreats)
	mux.HandleFunc("/security/config", sd.handleConfig)
}

// handleDashboard serves the main dashboard page
func (sd *SecurityDashboard) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Serve dashboard HTML
	dashboardHTML := sd.generateDashboardHTML()
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(dashboardHTML))
}

// handleMetrics serves security metrics
func (sd *SecurityDashboard) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	metrics := sd.collectMetrics()
	
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(metrics)
}

// handleEvents serves recent security events
func (sd *SecurityDashboard) handleEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get query parameters
	limitStr := r.URL.Query().Get("limit")
	limit := 50 // default
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	events := sd.getRecentEvents(limit)
	
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(events)
}

// handlePolicies serves policy information
func (sd *SecurityDashboard) handlePolicies(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		policies := sd.policyEngine.GetPolicies()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(policies)
	case http.MethodPost:
		// Add new policy
		var policy SecurityPolicy
		if err := json.NewDecoder(r.Body).Decode(&policy); err != nil {
			http.Error(w, "Invalid policy data", http.StatusBadRequest)
			return
		}
		
		if err := sd.policyEngine.AddPolicy(&policy); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"status": "created"})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleHealth serves system health information
func (sd *SecurityDashboard) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	health := sd.checkSystemHealth()
	
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(health)
}

// handleThreats serves threat analysis
func (sd *SecurityDashboard) handleThreats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	threats := sd.analyzeThreats()
	
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(threats)
}

// handleConfig serves security configuration
func (sd *SecurityDashboard) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		config := sd.getSecurityConfig()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(config)
	case http.MethodPost:
		// Update configuration
		var config map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
			http.Error(w, "Invalid configuration data", http.StatusBadRequest)
			return
		}
		
		if err := sd.updateSecurityConfig(config); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "updated"})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// collectMetrics collects security metrics
func (sd *SecurityDashboard) collectMetrics() *DashboardMetrics {
	metrics := &DashboardMetrics{
		Timestamp:    time.Now(),
		PolicyStats:  make(map[string]PolicyStats),
	}

	// Collect basic metrics (would be implemented with actual data sources)
	metrics.TotalRequests = sd.getTotalRequests()
	metrics.BlockedRequests = sd.getBlockedRequests()
	metrics.SecurityViolations = sd.getSecurityViolations()
	metrics.RateLimitViolations = sd.getRateLimitViolations()
	metrics.InputValidationFails = sd.getInputValidationFails()

	// Collect policy metrics
	policies := sd.policyEngine.GetPolicies()
	metrics.ActivePolicies = len(policies)
	
	for id, policy := range policies {
		metrics.PolicyStats[id] = PolicyStats{
			PolicyID:    id,
			PolicyName:  policy.Name,
			Enabled:     policy.Enabled,
			// These would be collected from actual metrics storage
			Evaluations:   sd.getPolicyEvaluations(id),
			Violations:    sd.getPolicyViolations(id),
			LastTriggered: sd.getPolicyLastTriggered(id),
		}
	}

	// Collect top threats
	metrics.TopThreats = sd.getTopThreats()

	// Collect recent events
	metrics.RecentEvents = sd.getRecentEvents(10)

	// Collect system health
	metrics.SystemHealth = sd.checkSystemHealth()

	return metrics
}

// getRecentEvents gets recent security events
func (sd *SecurityDashboard) getRecentEvents(limit int) []SecurityEventSummary {
	// This would be implemented with actual event storage
	// For now, return mock data
	events := []SecurityEventSummary{
		{
			ID:        "evt_001",
			Type:      "AUTHENTICATION_FAILURE",
			Severity:  "MEDIUM",
			Message:   "Failed login attempt",
			UserID:    "user123",
			IPAddress: "192.168.1.100",
			Timestamp: time.Now().Add(-5 * time.Minute),
			Details:   map[string]interface{}{"attempts": 3},
		},
		{
			ID:        "evt_002",
			Type:      "RATE_LIMIT_EXCEEDED",
			Severity:  "LOW",
			Message:   "Rate limit exceeded",
			UserID:    "user456",
			IPAddress: "192.168.1.101",
			Timestamp: time.Now().Add(-10 * time.Minute),
			Details:   map[string]interface{}{"endpoint": "/api/data"},
		},
	}

	if len(events) > limit {
		events = events[:limit]
	}

	return events
}

// checkSystemHealth checks system health
func (sd *SecurityDashboard) checkSystemHealth() SystemHealthStatus {
	health := SystemHealthStatus{
		Status:          "HEALTHY",
		SecurityScore:   85,
		LastHealthCheck: time.Now(),
		Components:      make(map[string]string),
		Recommendations: []string{},
	}

	// Check components
	health.Components["audit_logger"] = sd.checkAuditLoggerHealth()
	health.Components["policy_engine"] = sd.checkPolicyEngineHealth()
	health.Components["rate_limiter"] = sd.checkRateLimiterHealth()
	health.Components["input_validator"] = sd.checkInputValidatorHealth()
	health.Components["encryption_service"] = sd.checkEncryptionServiceHealth()

	// Calculate overall status
	unhealthyComponents := 0
	for _, status := range health.Components {
		if status != "HEALTHY" {
			unhealthyComponents++
		}
	}

	if unhealthyComponents > 0 {
		health.Status = "DEGRADED"
		health.SecurityScore -= unhealthyComponents * 10
	}

	// Add recommendations
	if unhealthyComponents > 0 {
		health.Recommendations = append(health.Recommendations, 
			"Check unhealthy security components")
	}

	if health.SecurityScore < 80 {
		health.Recommendations = append(health.Recommendations, 
			"Review and update security policies")
	}

	return health
}

// analyzeThreats analyzes security threats
func (sd *SecurityDashboard) analyzeThreats() []ThreatSummary {
	threats := []ThreatSummary{
		{
			Type:        "SQL_INJECTION",
			Count:       5,
			LastSeen:    time.Now().Add(-2 * time.Hour),
			Severity:    "HIGH",
			Description: "SQL injection attempts detected",
		},
		{
			Type:        "XSS_ATTEMPT",
			Count:       3,
			LastSeen:    time.Now().Add(-1 * time.Hour),
			Severity:    "MEDIUM",
			Description: "Cross-site scripting attempts",
		},
		{
			Type:        "BRUTE_FORCE",
			Count:       12,
			LastSeen:    time.Now().Add(-30 * time.Minute),
			Severity:    "HIGH",
			Description: "Brute force login attempts",
		},
	}

	// Sort by count (descending)
	sort.Slice(threats, func(i, j int) bool {
		return threats[i].Count > threats[j].Count
	})

	return threats
}

// Helper methods for metrics collection (would be implemented with actual data sources)
func (sd *SecurityDashboard) getTotalRequests() int64 { return 10000 }
func (sd *SecurityDashboard) getBlockedRequests() int64 { return 150 }
func (sd *SecurityDashboard) getSecurityViolations() int64 { return 75 }
func (sd *SecurityDashboard) getRateLimitViolations() int64 { return 25 }
func (sd *SecurityDashboard) getInputValidationFails() int64 { return 50 }
func (sd *SecurityDashboard) getPolicyEvaluations(policyID string) int64 { return 1000 }
func (sd *SecurityDashboard) getPolicyViolations(policyID string) int64 { return 10 }
func (sd *SecurityDashboard) getPolicyLastTriggered(policyID string) time.Time { 
	return time.Now().Add(-1 * time.Hour) 
}

func (sd *SecurityDashboard) getTopThreats() []ThreatSummary {
	return sd.analyzeThreats()[:3] // Top 3 threats
}

// Component health check methods
func (sd *SecurityDashboard) checkAuditLoggerHealth() string {
	if sd.auditLogger != nil {
		return "HEALTHY"
	}
	return "UNHEALTHY"
}

func (sd *SecurityDashboard) checkPolicyEngineHealth() string {
	if sd.policyEngine != nil {
		return "HEALTHY"
	}
	return "UNHEALTHY"
}

func (sd *SecurityDashboard) checkRateLimiterHealth() string {
	if sd.rateLimiter != nil {
		return "HEALTHY"
	}
	return "UNHEALTHY"
}

func (sd *SecurityDashboard) checkInputValidatorHealth() string {
	if sd.inputValidator != nil {
		return "HEALTHY"
	}
	return "UNHEALTHY"
}

func (sd *SecurityDashboard) checkEncryptionServiceHealth() string {
	if sd.encryptionSvc != nil {
		return "HEALTHY"
	}
	return "UNHEALTHY"
}

// getSecurityConfig gets current security configuration
func (sd *SecurityDashboard) getSecurityConfig() map[string]interface{} {
	config := map[string]interface{}{
		"audit_logging_enabled":    true,
		"rate_limiting_enabled":    true,
		"input_validation_enabled": true,
		"encryption_enabled":       true,
		"policy_engine_enabled":    true,
		"security_headers_enabled": true,
		"csrf_protection_enabled":  true,
	}
	return config
}

// updateSecurityConfig updates security configuration
func (sd *SecurityDashboard) updateSecurityConfig(config map[string]interface{}) error {
	// This would update actual configuration
	// For now, just validate the config
	requiredKeys := []string{
		"audit_logging_enabled",
		"rate_limiting_enabled", 
		"input_validation_enabled",
		"encryption_enabled",
	}

	for _, key := range requiredKeys {
		if _, exists := config[key]; !exists {
			return fmt.Errorf("missing required configuration key: %s", key)
		}
	}

	// Log configuration change
	if sd.auditLogger != nil {
		sd.auditLogger.LogConfigChange("system", "127.0.0.1", "SECURITY_CONFIG", 
			"previous_config", "updated_config", config)
	}

	return nil
}

// generateDashboardHTML generates the dashboard HTML page
func (sd *SecurityDashboard) generateDashboardHTML() string {
	return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TypoSentinel Security Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .metrics-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 20px; }
        .metric-card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .metric-value { font-size: 2em; font-weight: bold; color: #3498db; }
        .metric-label { color: #7f8c8d; margin-top: 5px; }
        .status-healthy { color: #27ae60; }
        .status-warning { color: #f39c12; }
        .status-error { color: #e74c3c; }
        .events-table { width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; }
        .events-table th, .events-table td { padding: 12px; text-align: left; border-bottom: 1px solid #ecf0f1; }
        .events-table th { background: #34495e; color: white; }
        .severity-high { color: #e74c3c; font-weight: bold; }
        .severity-medium { color: #f39c12; font-weight: bold; }
        .severity-low { color: #27ae60; font-weight: bold; }
        .refresh-btn { background: #3498db; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; }
        .refresh-btn:hover { background: #2980b9; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>TypoSentinel Security Dashboard</h1>
            <p>Real-time security monitoring and management</p>
            <button class="refresh-btn" onclick="refreshDashboard()">Refresh</button>
        </div>

        <div class="metrics-grid" id="metrics-grid">
            <!-- Metrics will be loaded here -->
        </div>

        <div class="metric-card">
            <h3>Recent Security Events</h3>
            <table class="events-table" id="events-table">
                <thead>
                    <tr>
                        <th>Time</th>
                        <th>Type</th>
                        <th>Severity</th>
                        <th>Message</th>
                        <th>User/IP</th>
                    </tr>
                </thead>
                <tbody id="events-tbody">
                    <!-- Events will be loaded here -->
                </tbody>
            </table>
        </div>
    </div>

    <script>
        function refreshDashboard() {
            loadMetrics();
            loadEvents();
        }

        function loadMetrics() {
            fetch('/security/metrics')
                .then(response => response.json())
                .then(data => {
                    const grid = document.getElementById('metrics-grid');
                    grid.innerHTML = ` + "`" + `
                        <div class="metric-card">
                            <div class="metric-value">${data.total_requests.toLocaleString()}</div>
                            <div class="metric-label">Total Requests</div>
                        </div>
                        <div class="metric-card">
                            <div class="metric-value status-error">${data.blocked_requests.toLocaleString()}</div>
                            <div class="metric-label">Blocked Requests</div>
                        </div>
                        <div class="metric-card">
                            <div class="metric-value status-warning">${data.security_violations.toLocaleString()}</div>
                            <div class="metric-label">Security Violations</div>
                        </div>
                        <div class="metric-card">
                            <div class="metric-value status-healthy">${data.active_policies}</div>
                            <div class="metric-label">Active Policies</div>
                        </div>
                        <div class="metric-card">
                            <div class="metric-value ${data.system_health.status === 'HEALTHY' ? 'status-healthy' : 'status-warning'}">${data.system_health.security_score}%</div>
                            <div class="metric-label">Security Score</div>
                        </div>
                        <div class="metric-card">
                            <div class="metric-value ${data.system_health.status === 'HEALTHY' ? 'status-healthy' : 'status-warning'}">${data.system_health.status}</div>
                            <div class="metric-label">System Status</div>
                        </div>
                    ` + "`" + `;
                })
                .catch(error => console.error('Error loading metrics:', error));
        }

        function loadEvents() {
            fetch('/security/events?limit=10')
                .then(response => response.json())
                .then(data => {
                    const tbody = document.getElementById('events-tbody');
                    tbody.innerHTML = data.map(event => ` + "`" + `
                        <tr>
                            <td>${new Date(event.timestamp).toLocaleString()}</td>
                            <td>${event.type}</td>
                            <td><span class="severity-${event.severity.toLowerCase()}">${event.severity}</span></td>
                            <td>${event.message}</td>
                            <td>${event.user_id || 'N/A'} / ${event.ip_address}</td>
                        </tr>
                    ` + "`" + `).join('');
                })
                .catch(error => console.error('Error loading events:', error));
        }

        // Load data on page load
        document.addEventListener('DOMContentLoaded', function() {
            refreshDashboard();
            // Auto-refresh every 30 seconds
            setInterval(refreshDashboard, 30000);
        });
    </script>
</body>
</html>`
}