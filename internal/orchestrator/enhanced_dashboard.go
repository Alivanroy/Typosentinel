package orchestrator

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// EnhancedDashboard provides advanced web interface features
type EnhancedDashboard struct {
	*Dashboard
	sessions     map[string]*UserSession
	preferences  map[string]*UserPreferences
	configHistory []ConfigHistoryEntry
}

// UserSession represents an authenticated user session
type UserSession struct {
	ID        string    `json:"id"`
	Username  string    `json:"username"`
	CreatedAt time.Time `json:"created_at"`
	LastSeen  time.Time `json:"last_seen"`
	IPAddress string    `json:"ip_address"`
	UserAgent string    `json:"user_agent"`
}

// UserPreferences stores user-specific dashboard preferences
type UserPreferences struct {
	Username        string            `json:"username"`
	Theme           string            `json:"theme"`           // "light", "dark", "auto"
	RefreshRate     int               `json:"refresh_rate"`    // seconds
	DefaultView     string            `json:"default_view"`    // "dashboard", "scans", "config"
	ChartType       string            `json:"chart_type"`      // "line", "bar", "area"
	Notifications   NotificationPrefs `json:"notifications"`
	DashboardLayout DashboardLayout   `json:"dashboard_layout"`
	Filters         FilterPrefs       `json:"filters"`
	UpdatedAt       time.Time         `json:"updated_at"`
}

// NotificationPrefs defines notification preferences
type NotificationPrefs struct {
	Email         bool `json:"email"`
	Browser       bool `json:"browser"`
	Slack         bool `json:"slack"`
	OnHighThreats bool `json:"on_high_threats"`
	OnScanComplete bool `json:"on_scan_complete"`
	OnSystemError bool `json:"on_system_error"`
}

// DashboardLayout defines dashboard widget layout
type DashboardLayout struct {
	Widgets []WidgetConfig `json:"widgets"`
}

// WidgetConfig defines individual widget configuration
type WidgetConfig struct {
	ID       string `json:"id"`
	Type     string `json:"type"`     // "metrics", "chart", "table", "status"
	Position int    `json:"position"`
	Size     string `json:"size"`     // "small", "medium", "large"
	Visible  bool   `json:"visible"`
}

// FilterPrefs defines default filter preferences
type FilterPrefs struct {
	DefaultSeverity []string `json:"default_severity"`
	DefaultStatus   []string `json:"default_status"`
	DefaultTimeRange string  `json:"default_time_range"`
	AutoRefresh     bool     `json:"auto_refresh"`
}

// ConfigHistoryEntry represents a configuration change
type ConfigHistoryEntry struct {
	ID          string                 `json:"id"`
	Timestamp   time.Time              `json:"timestamp"`
	Username    string                 `json:"username"`
	Action      string                 `json:"action"`      // "create", "update", "delete", "export"
	ConfigType  string                 `json:"config_type"` // "scan", "detector", "output", "global"
	ConfigData  map[string]interface{} `json:"config_data"`
	Description string                 `json:"description"`
	IPAddress   string                 `json:"ip_address"`
}

// NewEnhancedDashboard creates a new enhanced dashboard instance
func NewEnhancedDashboard(config *DashboardConfig, coordinator *ScanCoordinator) *EnhancedDashboard {
	baseDashboard := NewDashboard(config, coordinator)
	
	return &EnhancedDashboard{
		Dashboard:     baseDashboard,
		sessions:      make(map[string]*UserSession),
		preferences:   make(map[string]*UserPreferences),
		configHistory: make([]ConfigHistoryEntry, 0),
	}
}

// Start starts the enhanced dashboard with additional features
func (ed *EnhancedDashboard) Start(ctx context.Context) error {
	if !ed.config.Enabled {
		return nil
	}

	mux := http.NewServeMux()
	ed.setupEnhancedRoutes(mux)

	addr := fmt.Sprintf("%s:%d", ed.config.Host, ed.config.Port)
	ed.server = &http.Server{
		Addr:    addr,
		Handler: ed.enhancedAuthMiddleware(mux),
	}

	// Start background tasks
	go ed.collectMetrics(ctx)
	go ed.cleanupSessions(ctx)

	if ed.config.TLSEnabled {
		return ed.server.ListenAndServeTLS(ed.config.CertFile, ed.config.KeyFile)
	}

	return ed.server.ListenAndServe()
}

// setupEnhancedRoutes configures enhanced HTTP routes
func (ed *EnhancedDashboard) setupEnhancedRoutes(mux *http.ServeMux) {
	basePath := ed.config.BasePath
	if basePath == "" {
		basePath = "/"
	}

	// Authentication routes
	mux.HandleFunc(basePath+"auth/login", ed.handleLogin)
	mux.HandleFunc(basePath+"auth/logout", ed.handleLogout)
	mux.HandleFunc(basePath+"auth/session", ed.handleSession)

	// User preferences routes
	mux.HandleFunc(basePath+"api/preferences", ed.handlePreferences)
	mux.HandleFunc(basePath+"api/preferences/theme", ed.handleThemePreference)
	mux.HandleFunc(basePath+"api/preferences/layout", ed.handleLayoutPreference)

	// Configuration management routes
	mux.HandleFunc(basePath+"api/config/history", ed.handleConfigHistory)
	mux.HandleFunc(basePath+"api/config/export", ed.handleConfigExport)
	mux.HandleFunc(basePath+"api/config/import", ed.handleConfigImport)
	mux.HandleFunc(basePath+"api/config/validate", ed.handleConfigValidate)
	mux.HandleFunc(basePath+"api/config/templates", ed.handleConfigTemplates)

	// Enhanced dashboard routes
	mux.HandleFunc(basePath+"dashboard/enhanced", ed.handleEnhancedDashboard)
	mux.HandleFunc(basePath+"api/widgets", ed.handleWidgets)
	mux.HandleFunc(basePath+"api/notifications", ed.handleNotifications)

	// Include base routes
	ed.setupRoutes(mux)
}

// enhancedAuthMiddleware provides session-based authentication
func (ed *EnhancedDashboard) enhancedAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip auth for login endpoint
		if r.URL.Path == ed.config.BasePath+"auth/login" {
			next.ServeHTTP(w, r)
			return
		}

		if ed.config.AuthEnabled {
			sessionID := ed.getSessionFromRequest(r)
			if sessionID == "" {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			session, exists := ed.sessions[sessionID]
			if !exists || ed.isSessionExpired(session) {
				delete(ed.sessions, sessionID)
				http.Error(w, "Session expired", http.StatusUnauthorized)
				return
			}

			// Update last seen
			session.LastSeen = time.Now()
			
			// Add user context to request
			ctx := context.WithValue(r.Context(), "user", session.Username)
			r = r.WithContext(ctx)
		}

		next.ServeHTTP(w, r)
	})
}

// handleLogin handles user authentication
func (ed *EnhancedDashboard) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var loginReq struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&loginReq); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Validate credentials
	if loginReq.Username != ed.config.Username || loginReq.Password != ed.config.Password {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Create session
	sessionID := ed.generateSessionID()
	session := &UserSession{
		ID:        sessionID,
		Username:  loginReq.Username,
		CreatedAt: time.Now(),
		LastSeen:  time.Now(),
		IPAddress: r.RemoteAddr,
		UserAgent: r.UserAgent(),
	}

	ed.sessions[sessionID] = session

	// Set session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   ed.config.TLSEnabled,
		MaxAge:   86400, // 24 hours
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":    true,
		"session_id": sessionID,
		"username":   loginReq.Username,
	})
}

// handleLogout handles user logout
func (ed *EnhancedDashboard) handleLogout(w http.ResponseWriter, r *http.Request) {
	sessionID := ed.getSessionFromRequest(r)
	if sessionID != "" {
		delete(ed.sessions, sessionID)
	}

	// Clear session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

// handlePreferences handles user preferences management
func (ed *EnhancedDashboard) handlePreferences(w http.ResponseWriter, r *http.Request) {
	username := r.Context().Value("user").(string)

	switch r.Method {
	case http.MethodGet:
		prefs, exists := ed.preferences[username]
		if !exists {
			prefs = ed.getDefaultPreferences(username)
			ed.preferences[username] = prefs
		}
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(prefs)

	case http.MethodPost:
		var prefs UserPreferences
		if err := json.NewDecoder(r.Body).Decode(&prefs); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		prefs.Username = username
		prefs.UpdatedAt = time.Now()
		ed.preferences[username] = &prefs

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"success": true})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleConfigHistory handles configuration change history
func (ed *EnhancedDashboard) handleConfigHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get query parameters for filtering
	limit := 50
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := fmt.Sscanf(limitStr, "%d", &limit); err == nil && l > 0 {
			if limit > 1000 {
				limit = 1000
			}
		}
	}

	// Return recent history
	history := ed.configHistory
	if len(history) > limit {
		history = history[len(history)-limit:]
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"history": history,
		"total":   len(ed.configHistory),
	})
}

// handleEnhancedDashboard serves the enhanced dashboard HTML
func (ed *EnhancedDashboard) handleEnhancedDashboard(w http.ResponseWriter, r *http.Request) {
	username := r.Context().Value("user").(string)
	prefs, exists := ed.preferences[username]
	if !exists {
		prefs = ed.getDefaultPreferences(username)
	}

	html := ed.getEnhancedDashboardHTML(prefs)
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

// Helper functions

func (ed *EnhancedDashboard) generateSessionID() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return base64.URLEncoding.EncodeToString(bytes)
}

func (ed *EnhancedDashboard) getSessionFromRequest(r *http.Request) string {
	if cookie, err := r.Cookie("session_id"); err == nil {
		return cookie.Value
	}
	return r.Header.Get("X-Session-ID")
}

func (ed *EnhancedDashboard) isSessionExpired(session *UserSession) bool {
	return time.Since(session.LastSeen) > 24*time.Hour
}

func (ed *EnhancedDashboard) cleanupSessions(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for id, session := range ed.sessions {
				if ed.isSessionExpired(session) {
					delete(ed.sessions, id)
				}
			}
		}
	}
}

func (ed *EnhancedDashboard) getDefaultPreferences(username string) *UserPreferences {
	return &UserPreferences{
		Username:    username,
		Theme:       "auto",
		RefreshRate: 30,
		DefaultView: "dashboard",
		ChartType:   "line",
		Notifications: NotificationPrefs{
			Browser:       true,
			OnHighThreats: true,
			OnSystemError: true,
		},
		DashboardLayout: DashboardLayout{
			Widgets: []WidgetConfig{
				{ID: "metrics", Type: "metrics", Position: 1, Size: "large", Visible: true},
				{ID: "scans", Type: "table", Position: 2, Size: "medium", Visible: true},
				{ID: "threats", Type: "chart", Position: 3, Size: "medium", Visible: true},
				{ID: "status", Type: "status", Position: 4, Size: "small", Visible: true},
			},
		},
		Filters: FilterPrefs{
			DefaultSeverity:  []string{"medium", "high", "critical"},
			DefaultStatus:    []string{"completed", "failed"},
			DefaultTimeRange: "24h",
			AutoRefresh:      true,
		},
		UpdatedAt: time.Now(),
	}
}

func (ed *EnhancedDashboard) addConfigHistoryEntry(username, action, configType, description string, configData map[string]interface{}, ipAddress string) {
	entry := ConfigHistoryEntry{
		ID:          ed.generateSessionID(),
		Timestamp:   time.Now(),
		Username:    username,
		Action:      action,
		ConfigType:  configType,
		ConfigData:  configData,
		Description: description,
		IPAddress:   ipAddress,
	}

	ed.configHistory = append(ed.configHistory, entry)

	// Keep only last 1000 entries
	if len(ed.configHistory) > 1000 {
		ed.configHistory = ed.configHistory[1:]
	}
}

// handleSession handles session information requests
func (ed *EnhancedDashboard) handleSession(w http.ResponseWriter, r *http.Request) {
	sessionID := ed.getSessionFromRequest(r)
	if sessionID == "" {
		http.Error(w, "No session", http.StatusUnauthorized)
		return
	}

	session, exists := ed.sessions[sessionID]
	if !exists {
		http.Error(w, "Invalid session", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(session)
}

// handleThemePreference handles theme preference updates
func (ed *EnhancedDashboard) handleThemePreference(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username := r.Context().Value("user").(string)
	var req struct {
		Theme string `json:"theme"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	prefs, exists := ed.preferences[username]
	if !exists {
		prefs = ed.getDefaultPreferences(username)
	}

	prefs.Theme = req.Theme
	prefs.UpdatedAt = time.Now()
	ed.preferences[username] = prefs

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

// handleLayoutPreference handles dashboard layout preference updates
func (ed *EnhancedDashboard) handleLayoutPreference(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username := r.Context().Value("user").(string)
	var req struct {
		Layout DashboardLayout `json:"layout"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	prefs, exists := ed.preferences[username]
	if !exists {
		prefs = ed.getDefaultPreferences(username)
	}

	prefs.DashboardLayout = req.Layout
	prefs.UpdatedAt = time.Now()
	ed.preferences[username] = prefs

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

// handleConfigExport handles configuration export
func (ed *EnhancedDashboard) handleConfigExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username := r.Context().Value("user").(string)
	configType := r.URL.Query().Get("type")
	if configType == "" {
		configType = "all"
	}

	// Create export data
	exportData := map[string]interface{}{
		"exported_at": time.Now(),
		"exported_by": username,
		"config_type": configType,
		"version":     "1.0",
	}

	// Add user preferences if requested
	if configType == "all" || configType == "preferences" {
		if prefs, exists := ed.preferences[username]; exists {
			exportData["preferences"] = prefs
		}
	}

	// Log export action
	ed.addConfigHistoryEntry(username, "export", configType, "Configuration exported", exportData, r.RemoteAddr)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=typosentinel-config-%s.json", time.Now().Format("2006-01-02")))
	json.NewEncoder(w).Encode(exportData)
}

// handleConfigImport handles configuration import
func (ed *EnhancedDashboard) handleConfigImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username := r.Context().Value("user").(string)
	var importData map[string]interface{}

	if err := json.NewDecoder(r.Body).Decode(&importData); err != nil {
		http.Error(w, "Invalid import data", http.StatusBadRequest)
		return
	}

	// Validate import data
	if version, ok := importData["version"].(string); !ok || version != "1.0" {
		http.Error(w, "Unsupported configuration version", http.StatusBadRequest)
		return
	}

	// Import preferences if present
	if prefsData, ok := importData["preferences"]; ok {
		prefsJSON, _ := json.Marshal(prefsData)
		var prefs UserPreferences
		if err := json.Unmarshal(prefsJSON, &prefs); err == nil {
			prefs.Username = username
			prefs.UpdatedAt = time.Now()
			ed.preferences[username] = &prefs
		}
	}

	// Log import action
	ed.addConfigHistoryEntry(username, "import", "configuration", "Configuration imported", importData, r.RemoteAddr)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

// handleConfigValidate handles configuration validation
func (ed *EnhancedDashboard) handleConfigValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var configData map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&configData); err != nil {
		http.Error(w, "Invalid configuration data", http.StatusBadRequest)
		return
	}

	// Perform validation
	errors := []string{}
	warnings := []string{}

	// Basic validation logic
	if scanConfig, ok := configData["scanner"].(map[string]interface{}); ok {
		if timeout, ok := scanConfig["timeout"].(float64); ok && timeout < 1 {
			errors = append(errors, "Scanner timeout must be at least 1 second")
		}
		if concurrency, ok := scanConfig["concurrency"].(float64); ok && (concurrency < 1 || concurrency > 100) {
			warnings = append(warnings, "Scanner concurrency should be between 1 and 100")
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"valid":    len(errors) == 0,
		"errors":   errors,
		"warnings": warnings,
	})
}

// handleConfigTemplates handles configuration template requests
func (ed *EnhancedDashboard) handleConfigTemplates(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	templates := []map[string]interface{}{
		{
			"id":          "basic",
			"name":        "Basic Security Scan",
			"description": "Standard configuration for basic security scanning",
			"config": map[string]interface{}{
				"scanner": map[string]interface{}{
					"timeout":     30,
					"concurrency": 5,
					"scan_depth":  3,
				},
				"detector": map[string]interface{}{
					"threshold": 0.7,
					"algorithms": []string{"levenshtein", "jaro_winkler"},
				},
			},
		},
		{
			"id":          "enterprise",
			"name":        "Enterprise Security",
			"description": "High-security configuration for enterprise environments",
			"config": map[string]interface{}{
				"scanner": map[string]interface{}{
					"timeout":     60,
					"concurrency": 10,
					"scan_depth":  5,
				},
				"detector": map[string]interface{}{
					"threshold": 0.8,
					"algorithms": []string{"levenshtein", "jaro_winkler", "soundex"},
				},
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"templates": templates,
	})
}

// handleWidgets handles widget management
func (ed *EnhancedDashboard) handleWidgets(w http.ResponseWriter, r *http.Request) {
	username := r.Context().Value("user").(string)

	switch r.Method {
	case http.MethodGet:
		prefs, exists := ed.preferences[username]
		if !exists {
			prefs = ed.getDefaultPreferences(username)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"widgets": prefs.DashboardLayout.Widgets,
		})

	case http.MethodPost:
		var req struct {
			Widgets []WidgetConfig `json:"widgets"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		prefs, exists := ed.preferences[username]
		if !exists {
			prefs = ed.getDefaultPreferences(username)
		}

		prefs.DashboardLayout.Widgets = req.Widgets
		prefs.UpdatedAt = time.Now()
		ed.preferences[username] = prefs

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"success": true})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleNotifications handles notification management
func (ed *EnhancedDashboard) handleNotifications(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		// Return recent notifications
		notifications := []map[string]interface{}{
			{
				"id":        "1",
				"type":      "info",
				"message":   "Dashboard loaded successfully",
				"timestamp": time.Now(),
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"notifications": notifications,
		})

	case http.MethodPost:
		var req struct {
			Type    string `json:"type"`
			Message string `json:"message"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		// Process notification (could send to external systems)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"success": true})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (ed *EnhancedDashboard) getEnhancedDashboardHTML(prefs *UserPreferences) string {
	return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TypoSentinel Enhanced Dashboard</title>
    <style>
        :root {
            --primary-color: #667eea;
            --secondary-color: #764ba2;
            --success-color: #28a745;
            --warning-color: #ffc107;
            --danger-color: #dc3545;
            --info-color: #17a2b8;
            --light-color: #f8f9fa;
            --dark-color: #343a40;
        }
        
        [data-theme="dark"] {
            --bg-color: #1a1a1a;
            --text-color: #ffffff;
            --card-bg: #2d2d2d;
            --border-color: #404040;
        }
        
        [data-theme="light"] {
            --bg-color: #ffffff;
            --text-color: #333333;
            --card-bg: #ffffff;
            --border-color: #e0e0e0;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background-color: var(--bg-color, #f5f5f5);
            color: var(--text-color, #333);
            margin: 0;
            padding: 0;
            transition: all 0.3s ease;
        }
        
        .header {
            background: linear-gradient(135deg, var(--primary-color) 0%, var(--secondary-color) 100%);
            color: white;
            padding: 1rem 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .header h1 {
            font-size: 2rem;
            font-weight: 300;
            margin: 0;
        }
        
        .user-menu {
            display: flex;
            align-items: center;
            gap: 1rem;
        }
        
        .theme-toggle {
            background: rgba(255,255,255,0.2);
            border: none;
            color: white;
            padding: 0.5rem 1rem;
            border-radius: 4px;
            cursor: pointer;
            transition: background 0.3s ease;
        }
        
        .theme-toggle:hover {
            background: rgba(255,255,255,0.3);
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 2rem;
        }
        
        .dashboard-controls {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 2rem;
            padding: 1rem;
            background: var(--card-bg, white);
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .widget-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }
        
        .widget {
            background: var(--card-bg, white);
            padding: 1.5rem;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            border-left: 4px solid var(--primary-color);
            transition: transform 0.2s ease, box-shadow 0.2s ease;
        }
        
        .widget:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0,0,0,0.15);
        }
        
        .widget.dragging {
            opacity: 0.5;
            transform: rotate(5deg);
        }
        
        .widget-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1rem;
        }
        
        .widget-title {
            font-size: 1.1rem;
            font-weight: 600;
            color: var(--text-color, #333);
        }
        
        .widget-menu {
            position: relative;
        }
        
        .notification-center {
            position: fixed;
            top: 1rem;
            right: 1rem;
            z-index: 1000;
        }
        
        .notification {
            background: var(--card-bg, white);
            border-left: 4px solid var(--info-color);
            padding: 1rem;
            margin-bottom: 0.5rem;
            border-radius: 4px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.15);
            max-width: 300px;
            animation: slideIn 0.3s ease;
        }
        
        .notification.success { border-left-color: var(--success-color); }
        .notification.warning { border-left-color: var(--warning-color); }
        .notification.error { border-left-color: var(--danger-color); }
        
        @keyframes slideIn {
            from { transform: translateX(100%); opacity: 0; }
            to { transform: translateX(0); opacity: 1; }
        }
        
        .config-history {
            background: var(--card-bg, white);
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        
        .config-history-header {
            background: var(--primary-color);
            color: white;
            padding: 1rem;
            font-weight: 600;
        }
        
        .config-history-item {
            padding: 1rem;
            border-bottom: 1px solid var(--border-color, #eee);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .config-history-item:last-child {
            border-bottom: none;
        }
        
        .preferences-panel {
            position: fixed;
            top: 0;
            right: -400px;
            width: 400px;
            height: 100vh;
            background: var(--card-bg, white);
            box-shadow: -2px 0 8px rgba(0,0,0,0.15);
            transition: right 0.3s ease;
            z-index: 1001;
            overflow-y: auto;
        }
        
        .preferences-panel.open {
            right: 0;
        }
        
        .preferences-header {
            background: var(--primary-color);
            color: white;
            padding: 1rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .preferences-content {
            padding: 1rem;
        }
        
        .form-group {
            margin-bottom: 1rem;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 0.5rem;
            font-weight: 500;
        }
        
        .form-group select,
        .form-group input {
            width: 100%;
            padding: 0.5rem;
            border: 1px solid var(--border-color, #ddd);
            border-radius: 4px;
            background: var(--card-bg, white);
            color: var(--text-color, #333);
        }
        
        .btn {
            padding: 0.5rem 1rem;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-weight: 500;
            transition: all 0.2s ease;
        }
        
        .btn-primary {
            background: var(--primary-color);
            color: white;
        }
        
        .btn-primary:hover {
            background: var(--secondary-color);
        }
        
        .btn-secondary {
            background: var(--light-color);
            color: var(--dark-color);
        }
        
        .btn-secondary:hover {
            background: #e2e6ea;
        }
    </style>
</head>
<body data-theme="` + prefs.Theme + `">
    <div class="header">
        <h1>TypoSentinel Enhanced Dashboard</h1>
        <div class="user-menu">
            <button class="theme-toggle" onclick="toggleTheme()">🌓</button>
            <button class="btn btn-secondary" onclick="openPreferences()">⚙️ Preferences</button>
            <button class="btn btn-secondary" onclick="logout()">Logout</button>
        </div>
    </div>
    
    <div class="notification-center" id="notificationCenter"></div>
    
    <div class="container">
        <div class="dashboard-controls">
            <div>
                <button class="btn btn-primary" onclick="refreshDashboard()">🔄 Refresh</button>
                <button class="btn btn-secondary" onclick="exportConfig()">📥 Export Config</button>
                <button class="btn btn-secondary" onclick="showConfigHistory()">📋 History</button>
            </div>
            <div>
                <span>Auto-refresh: <span id="refreshRate">` + fmt.Sprintf("%d", prefs.RefreshRate) + `s</span></span>
                <span>Last updated: <span id="lastUpdate">Loading...</span></span>
            </div>
        </div>
        
        <div class="widget-grid" id="widgetGrid">
            <!-- Widgets will be dynamically loaded based on user preferences -->
        </div>
        
        <div class="config-history" id="configHistory" style="display: none;">
            <div class="config-history-header">
                Configuration History
                <button class="btn btn-secondary" onclick="hideConfigHistory()">✕</button>
            </div>
            <div id="configHistoryContent">
                Loading...
            </div>
        </div>
    </div>
    
    <div class="preferences-panel" id="preferencesPanel">
        <div class="preferences-header">
            <h3>Dashboard Preferences</h3>
            <button class="btn btn-secondary" onclick="closePreferences()">✕</button>
        </div>
        <div class="preferences-content">
            <div class="form-group">
                <label for="themeSelect">Theme</label>
                <select id="themeSelect" onchange="updateTheme()">
                    <option value="auto">Auto</option>
                    <option value="light">Light</option>
                    <option value="dark">Dark</option>
                </select>
            </div>
            
            <div class="form-group">
                <label for="refreshRateInput">Refresh Rate (seconds)</label>
                <input type="number" id="refreshRateInput" min="5" max="300" value="` + fmt.Sprintf("%d", prefs.RefreshRate) + `">
            </div>
            
            <div class="form-group">
                <label for="defaultViewSelect">Default View</label>
                <select id="defaultViewSelect">
                    <option value="dashboard">Dashboard</option>
                    <option value="scans">Scans</option>
                    <option value="config">Configuration</option>
                </select>
            </div>
            
            <div class="form-group">
                <label>Notifications</label>
                <label><input type="checkbox" id="browserNotifications" checked> Browser Notifications</label>
                <label><input type="checkbox" id="highThreatNotifications" checked> High Threat Alerts</label>
                <label><input type="checkbox" id="systemErrorNotifications" checked> System Error Alerts</label>
            </div>
            
            <button class="btn btn-primary" onclick="savePreferences()">Save Preferences</button>
        </div>
    </div>
    
    <script>
        let currentTheme = '` + prefs.Theme + `';
        let refreshRate = ` + fmt.Sprintf("%d", prefs.RefreshRate) + ` * 1000;
        let refreshInterval;
        
        // Initialize dashboard
        document.addEventListener('DOMContentLoaded', function() {
            loadUserPreferences();
            initializeWidgets();
            startAutoRefresh();
            requestNotificationPermission();
        });
        
        function toggleTheme() {
            const themes = ['auto', 'light', 'dark'];
            const currentIndex = themes.indexOf(currentTheme);
            currentTheme = themes[(currentIndex + 1) % themes.length];
            document.body.setAttribute('data-theme', currentTheme);
            document.getElementById('themeSelect').value = currentTheme;
        }
        
        function updateTheme() {
            currentTheme = document.getElementById('themeSelect').value;
            document.body.setAttribute('data-theme', currentTheme);
        }
        
        function openPreferences() {
            document.getElementById('preferencesPanel').classList.add('open');
        }
        
        function closePreferences() {
            document.getElementById('preferencesPanel').classList.remove('open');
        }
        
        function savePreferences() {
            const preferences = {
                theme: document.getElementById('themeSelect').value,
                refresh_rate: parseInt(document.getElementById('refreshRateInput').value),
                default_view: document.getElementById('defaultViewSelect').value,
                notifications: {
                    browser: document.getElementById('browserNotifications').checked,
                    on_high_threats: document.getElementById('highThreatNotifications').checked,
                    on_system_error: document.getElementById('systemErrorNotifications').checked
                }
            };
            
            fetch('/api/preferences', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(preferences)
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showNotification('Preferences saved successfully', 'success');
                    refreshRate = preferences.refresh_rate * 1000;
                    restartAutoRefresh();
                }
            })
            .catch(error => {
                showNotification('Failed to save preferences', 'error');
            });
            
            closePreferences();
        }
        
        function showNotification(message, type = 'info') {
            const notification = document.createElement('div');
            notification.className = 'notification ' + type;
            notification.innerHTML = message + '<button onclick="this.parentElement.remove()" style="float: right; background: none; border: none; cursor: pointer;">✕</button>';
            
            document.getElementById('notificationCenter').appendChild(notification);
            
            setTimeout(() => {
                notification.remove();
            }, 5000);
        }
        
        function refreshDashboard() {
            updateDashboard();
            showNotification('Dashboard refreshed', 'success');
        }
        
        function updateDashboard() {
            // Update metrics and widgets
            fetch('/api/metrics')
                .then(response => response.json())
                .then(data => {
                    updateWidgets(data);
                    document.getElementById('lastUpdate').textContent = new Date().toLocaleTimeString();
                })
                .catch(error => {
                    showNotification('Failed to update dashboard', 'error');
                });
        }
        
        function startAutoRefresh() {
            refreshInterval = setInterval(updateDashboard, refreshRate);
        }
        
        function restartAutoRefresh() {
            clearInterval(refreshInterval);
            startAutoRefresh();
        }
        
        function logout() {
            fetch('/auth/logout', { method: 'POST' })
                .then(() => {
                    window.location.href = '/auth/login';
                });
        }
        
        // Additional functions for widget management, config history, etc.
        // ... (implementation continues)
    </script>
</body>
</html>`
}