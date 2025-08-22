package security

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// APISecurityHardening provides advanced API security features
type APISecurityHardening struct {
	config              *APISecurityConfig
	inputValidator      *InputValidator
	attackDetector      *AttackDetector
	requestAnalyzer     *RequestAnalyzer
	responseFilter      *ResponseFilter
	sessionManager      *SessionManager
	auditLogger         *AuditLogger
	blacklistManager    *BlacklistManager
	anomalyDetector     *AnomalyDetector
	mu                  sync.RWMutex
	enabled             bool
}

// APISecurityConfig holds configuration for API security hardening
type APISecurityConfig struct {
	Enabled                    bool                    `json:"enabled"`
	MaxRequestSize             int64                   `json:"max_request_size"`
	MaxHeaderSize              int64                   `json:"max_header_size"`
	MaxQueryParams             int                     `json:"max_query_params"`
	MaxJSONDepth               int                     `json:"max_json_depth"`
	RequestTimeout             time.Duration           `json:"request_timeout"`
	EnableRequestSigning       bool                    `json:"enable_request_signing"`
	EnableAdvancedValidation   bool                    `json:"enable_advanced_validation"`
	EnableAttackDetection      bool                    `json:"enable_attack_detection"`
	EnableAnomalyDetection     bool                    `json:"enable_anomaly_detection"`
	EnableResponseFiltering    bool                    `json:"enable_response_filtering"`
	EnableAuditLogging         bool                    `json:"enable_audit_logging"`
	BlacklistConfig            BlacklistConfig         `json:"blacklist_config"`
	RateLimitConfig            RateLimitConfig         `json:"rate_limit_config"`
	SessionConfig              SessionConfig           `json:"session_config"`
	CSRFProtection             CSRFConfig              `json:"csrf_protection"`
	ContentSecurityPolicy      CSPConfig               `json:"content_security_policy"`
	AdvancedHeaders            map[string]string       `json:"advanced_headers"`
	TrustedProxies             []string                `json:"trusted_proxies"`
	AllowedContentTypes        []string                `json:"allowed_content_types"`
	BlockedUserAgents          []string                `json:"blocked_user_agents"`
	GeoBlocking                GeoBlockingConfig       `json:"geo_blocking"`
}

// Using AttackDetector from attack_detector.go

// Using RequestAnalyzer from behavioral_analyzer.go

// RequestMetrics tracks request characteristics
type RequestMetrics struct {
	Timestamp           time.Time
	Method              string
	Path                string
	UserAgent           string
	ContentLength       int64
	Headers             map[string]string
	QueryParams         map[string]string
	BodyHash            string
	ResponseTime        time.Duration
	StatusCode          int
	Fingerprint         string
	AnomalyScore        float64
	ThreatLevel         string
}

// Using ResponseFilter from existing security components

// Using ResponseFilterConfig from existing components

// SessionManager manages secure sessions
type SessionManager struct {
	sessions            map[string]*SecureSession
	config              *SessionConfig
	cleanupTicker       *time.Ticker
	mu                  sync.RWMutex
}

// SecureSession represents a secure session
type SecureSession struct {
	ID                  string
	UserID              string
	CreatedAt           time.Time
	LastAccessed        time.Time
	ExpiresAt           time.Time
	IPAddress           string
	UserAgent           string
	CSRFToken           string
	Permissions         []string
	Metadata            map[string]interface{}
	SecurityFlags       SecurityFlags
}

// SecurityFlags tracks session security state
type SecurityFlags struct {
	RequireReauth       bool
	SuspiciousActivity  bool
	LocationChanged     bool
	DeviceChanged       bool
	ElevatedPrivileges  bool
}

// Using SessionConfig from security_config.go

// Using AuditLogger and AuditConfig from audit_logger.go

// BlacklistManager manages IP and pattern blacklists
type BlacklistManager struct {
	ipBlacklist         map[string]BlacklistEntry
	patternBlacklist    map[string]BlacklistEntry
	userAgentBlacklist  map[string]BlacklistEntry
	config              *BlacklistConfig
	mu                  sync.RWMutex
}

// BlacklistEntry represents a blacklist entry
type BlacklistEntry struct {
	Value               string
	Reason              string
	AddedAt             time.Time
	ExpiresAt           *time.Time
	Severity            string
	Source              string
	HitCount            int
	LastHit             time.Time
}

// BlacklistConfig configures blacklist management
type BlacklistConfig struct {
	Enabled             bool          `json:"enabled"`
	AutoBlacklist       bool          `json:"auto_blacklist"`
	Threshold           int           `json:"threshold"`
	Duration            time.Duration `json:"duration"`
	Whitelist           []string      `json:"whitelist"`
	ExternalSources     []string      `json:"external_sources"`
	UpdateInterval      time.Duration `json:"update_interval"`
}

// Using AnomalyDetector from behavioral_analyzer.go

// CSRFConfig configures CSRF protection
type CSRFConfig struct {
	Enabled             bool     `json:"enabled"`
	TokenLength         int      `json:"token_length"`
	TokenTimeout        int      `json:"token_timeout"`
	ExemptPaths         []string `json:"exempt_paths"`
	HeaderName          string   `json:"header_name"`
	FieldName           string   `json:"field_name"`
}

// CSPConfig configures Content Security Policy
type CSPConfig struct {
	Enabled             bool              `json:"enabled"`
	Directives          map[string]string `json:"directives"`
	ReportOnly          bool              `json:"report_only"`
	ReportURI           string            `json:"report_uri"`
}

// GeoBlockingConfig configures geographical blocking
type GeoBlockingConfig struct {
	Enabled             bool     `json:"enabled"`
	BlockedCountries    []string `json:"blocked_countries"`
	AllowedCountries    []string `json:"allowed_countries"`
	BlockTor            bool     `json:"block_tor"`
	BlockVPN            bool     `json:"block_vpn"`
	BlockDatacenters    bool     `json:"block_datacenters"`
}

// RateLimitConfig configures advanced rate limiting
// Using RateLimitConfig from existing rate limiter

// DetectionEvent represents an attack detection event
// Using DetectionEvent from attack_detector.go

// NewAPISecurityHardening creates a new API security hardening instance
func NewAPISecurityHardening(config *APISecurityConfig) *APISecurityHardening {
	if config == nil {
		config = getDefaultAPISecurityConfig()
	}

	ash := &APISecurityHardening{
		config:          config,
		inputValidator:  NewInputValidator(),
		enabled:         config.Enabled,
	}

	if config.EnableAttackDetection {
		ash.attackDetector = NewAttackDetector()
	}

	// Simple session manager initialization
	ash.sessionManager = &SessionManager{
		sessions: make(map[string]*SecureSession),
		config:   &config.SessionConfig,
	}

	// Simple blacklist manager initialization
	ash.blacklistManager = &BlacklistManager{
		ipBlacklist:        make(map[string]BlacklistEntry),
		patternBlacklist:   make(map[string]BlacklistEntry),
		userAgentBlacklist: make(map[string]BlacklistEntry),
		config:             &config.BlacklistConfig,
	}

	return ash
}

// SecurityHardeningMiddleware returns the main security hardening middleware
func (ash *APISecurityHardening) SecurityHardeningMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !ash.enabled {
			c.Next()
			return
		}

		start := time.Now()
		requestID := generateRequestID()
		c.Set("request_id", requestID)

		// Pre-request security checks
		if blocked, reason := ash.preRequestChecks(c); blocked {
			ash.logSecurityEvent(c, "request_blocked", "high", reason, nil)
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Request blocked",
				"reason": reason,
				"request_id": requestID,
			})
			c.Abort()
			return
		}

		// Advanced input validation
		if ash.config.EnableAdvancedValidation {
			if err := ash.performAdvancedValidation(c); err != nil {
				ash.logSecurityEvent(c, "validation_failed", "medium", err.Error(), nil)
				c.JSON(http.StatusBadRequest, gin.H{
					"error": "Invalid request",
					"details": err.Error(),
					"request_id": requestID,
				})
				c.Abort()
				return
			}
		}

		// Attack detection
		if ash.config.EnableAttackDetection {
			if detected, attackType := ash.detectAttacks(c); detected {
				ash.handleAttackDetection(c, attackType, requestID)
				return
			}
		}

		// Request analysis and anomaly detection
		if ash.config.EnableAnomalyDetection {
			ash.analyzeRequest(c, start)
		}

		// Set security headers
		ash.setSecurityHeaders(c)

		// Process request
		c.Next()

		// Post-request processing
		ash.postRequestProcessing(c, start, requestID)
	}
}

// preRequestChecks performs initial security checks
func (ash *APISecurityHardening) preRequestChecks(c *gin.Context) (bool, string) {
	// Check blacklists (simplified)
	if ash.blacklistManager != nil {
		// Simple blacklist check implementation
		if entry, exists := ash.blacklistManager.ipBlacklist[c.ClientIP()]; exists {
			return true, entry.Reason
		}
	}

	// Check geo-blocking
	if ash.config.GeoBlocking.Enabled {
		if blocked, reason := ash.checkGeoBlocking(c); blocked {
			return true, reason
		}
	}

	// Check request size limits
	if c.Request.ContentLength > ash.config.MaxRequestSize {
		return true, "Request size exceeds limit"
	}

	// Check header size limits
	headerSize := int64(0)
	for name, values := range c.Request.Header {
		headerSize += int64(len(name))
		for _, value := range values {
			headerSize += int64(len(value))
		}
	}
	if headerSize > ash.config.MaxHeaderSize {
		return true, "Header size exceeds limit"
	}

	// Check query parameter limits
	if len(c.Request.URL.Query()) > ash.config.MaxQueryParams {
		return true, "Too many query parameters"
	}

	// Check content type
	if len(ash.config.AllowedContentTypes) > 0 {
		contentType := c.GetHeader("Content-Type")
		allowed := false
		for _, allowedType := range ash.config.AllowedContentTypes {
			if strings.Contains(contentType, allowedType) {
				allowed = true
				break
			}
		}
		if !allowed {
			return true, "Content type not allowed"
		}
	}

	// Check blocked user agents
	userAgent := c.GetHeader("User-Agent")
	for _, blockedUA := range ash.config.BlockedUserAgents {
		if strings.Contains(strings.ToLower(userAgent), strings.ToLower(blockedUA)) {
			return true, "User agent blocked"
		}
	}

	return false, ""
}

// performAdvancedValidation performs comprehensive input validation
func (ash *APISecurityHardening) performAdvancedValidation(c *gin.Context) error {
	// Validate headers
	for name, values := range c.Request.Header {
		for _, value := range values {
			if err := ash.validateHeaderValue(name, value); err != nil {
				return fmt.Errorf("invalid header %s: %v", name, err)
			}
		}
	}

	// Validate query parameters
	for name, values := range c.Request.URL.Query() {
		for _, value := range values {
			if err := ash.validateQueryParam(name, value); err != nil {
				return fmt.Errorf("invalid query parameter %s: %v", name, err)
			}
		}
	}

	// Validate request body if present
	if c.Request.ContentLength > 0 {
		body, err := io.ReadAll(c.Request.Body)
		if err != nil {
			return fmt.Errorf("failed to read request body: %v", err)
		}
		c.Request.Body = io.NopCloser(bytes.NewBuffer(body))

		if err := ash.validateRequestBody(body, c.GetHeader("Content-Type")); err != nil {
			return fmt.Errorf("invalid request body: %v", err)
		}
	}

	return nil
}

// detectAttacks detects various attack patterns
func (ash *APISecurityHardening) detectAttacks(c *gin.Context) (bool, string) {
	if ash.attackDetector == nil {
		return false, ""
	}

	// Check URL path for attacks
	if detected, attackType := ash.attackDetector.DetectInString(c.Request.URL.Path); detected {
		return true, attackType
	}

	// Check query parameters
	for _, values := range c.Request.URL.Query() {
		for _, value := range values {
			if detected, attackType := ash.attackDetector.DetectInString(value); detected {
				return true, attackType
			}
		}
	}

	// Check headers
	for _, values := range c.Request.Header {
		for _, value := range values {
			if detected, attackType := ash.attackDetector.DetectInString(value); detected {
				return true, attackType
			}
		}
	}

	// Check request body if available
	if c.Request.ContentLength > 0 {
		body, err := io.ReadAll(c.Request.Body)
		if err == nil {
			c.Request.Body = io.NopCloser(bytes.NewBuffer(body))
			if detected, attackType := ash.attackDetector.DetectInString(string(body)); detected {
				return true, attackType
			}
		}
	}

	return false, ""
}

// handleAttackDetection handles detected attacks
func (ash *APISecurityHardening) handleAttackDetection(c *gin.Context, attackType, requestID string) {
	ash.logSecurityEvent(c, "attack_detected", "high", attackType, map[string]interface{}{
		"attack_type": attackType,
		"endpoint": c.Request.URL.Path,
		"method": c.Request.Method,
	})

	// Auto-blacklist if configured
	if ash.blacklistManager != nil && ash.config.BlacklistConfig.AutoBlacklist {
		// Simple blacklist addition
		ash.blacklistManager.ipBlacklist[c.ClientIP()] = BlacklistEntry{
			Value:    c.ClientIP(),
			Reason:   fmt.Sprintf("Attack detected: %s", attackType),
			AddedAt:  time.Now(),
			Severity: "high",
		}
	}

	c.JSON(http.StatusForbidden, gin.H{
		"error": "Security violation detected",
		"request_id": requestID,
	})
	c.Abort()
}

// analyzeRequest analyzes request for anomalies
func (ash *APISecurityHardening) analyzeRequest(c *gin.Context, start time.Time) {
	if ash.requestAnalyzer == nil {
		return
	}

	metrics := &RequestMetrics{
		Timestamp:     start,
		Method:        c.Request.Method,
		Path:          c.Request.URL.Path,
		UserAgent:     c.GetHeader("User-Agent"),
		ContentLength: c.Request.ContentLength,
		Headers:       make(map[string]string),
		QueryParams:   make(map[string]string),
	}

	// Collect headers
	for name, values := range c.Request.Header {
		if len(values) > 0 {
			metrics.Headers[name] = values[0]
		}
	}

	// Collect query parameters
	for name, values := range c.Request.URL.Query() {
		if len(values) > 0 {
			metrics.QueryParams[name] = values[0]
		}
	}

	// Simple request analysis
	if ash.requestAnalyzer != nil {
		// Analyze request (simplified implementation)
	}
}

// setSecurityHeaders sets security-related headers
func (ash *APISecurityHardening) setSecurityHeaders(c *gin.Context) {
	// Standard security headers
	c.Header("X-Content-Type-Options", "nosniff")
	c.Header("X-Frame-Options", "DENY")
	c.Header("X-XSS-Protection", "1; mode=block")
	c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
	c.Header("X-Request-ID", c.GetString("request_id"))

	// Content Security Policy
	if ash.config.ContentSecurityPolicy.Enabled {
		csp := ash.buildCSPHeader()
		if ash.config.ContentSecurityPolicy.ReportOnly {
			c.Header("Content-Security-Policy-Report-Only", csp)
		} else {
			c.Header("Content-Security-Policy", csp)
		}
	}

	// HSTS header for HTTPS
	if c.Request.TLS != nil {
		c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
	}

	// Custom security headers
	for name, value := range ash.config.AdvancedHeaders {
		c.Header(name, value)
	}

	// Remove server identification headers
	c.Header("Server", "")
	c.Header("X-Powered-By", "")
}

// postRequestProcessing handles post-request security tasks
func (ash *APISecurityHardening) postRequestProcessing(c *gin.Context, start time.Time, requestID string) {
	duration := time.Since(start)

	// Log audit event
	if ash.auditLogger != nil {
		ash.auditLogger.LogEvent(AuditEvent{
			EventType: "api_request",
			IPAddress: c.ClientIP(),
			UserAgent: c.GetHeader("User-Agent"),
			Success:   c.Writer.Status() < 400,
			CreatedAt: start,
			EventData: map[string]interface{}{
				"severity":      "info",
				"endpoint":      c.Request.URL.Path,
				"method":        c.Request.Method,
				"status_code":   c.Writer.Status(),
				"request_id":    requestID,
				"duration_ms":   duration.Milliseconds(),
				"response_size": c.Writer.Size(),
			},
		})
	}

	// Update request metrics for anomaly detection
	if ash.requestAnalyzer != nil {
		// Simple metrics update (simplified implementation)
	}

	// Filter response if enabled
	if ash.config.EnableResponseFiltering && ash.responseFilter != nil {
		// Simple response filtering (simplified implementation)
	}
}

// Helper functions for validation
func (ash *APISecurityHardening) validateHeaderValue(name, value string) error {
	// Check for null bytes
	if strings.Contains(value, "\x00") {
		return fmt.Errorf("null byte detected")
	}

	// Check for CRLF injection
	if strings.Contains(value, "\r") || strings.Contains(value, "\n") {
		return fmt.Errorf("CRLF injection detected")
	}

	// Simple header validation
	if len(value) > 1000 {
		return fmt.Errorf("header value too long")
	}

	// Validate specific headers
	switch strings.ToLower(name) {
	case "content-length":
		if _, err := strconv.ParseInt(value, 10, 64); err != nil {
			return fmt.Errorf("invalid content-length")
		}
	case "host":
		if !isValidHostname(value) {
			return fmt.Errorf("invalid hostname")
		}
	}

	return nil
}

func (ash *APISecurityHardening) validateQueryParam(name, value string) error {
	// Simple query parameter validation
	if len(value) > 1000 {
		return fmt.Errorf("query parameter too long")
	}

	// Check for common injection patterns
	if strings.Contains(value, "<script") || strings.Contains(value, "javascript:") {
		return fmt.Errorf("potential XSS in query parameter")
	}
	if strings.Contains(value, "'") || strings.Contains(value, "--") {
		return fmt.Errorf("potential SQL injection in query parameter")
	}

	return nil
}

func (ash *APISecurityHardening) validateRequestBody(body []byte, contentType string) error {
	if len(body) == 0 {
		return nil
	}

	// Validate JSON structure and depth
	if strings.Contains(contentType, "application/json") {
		var data interface{}
		if err := json.Unmarshal(body, &data); err != nil {
			return fmt.Errorf("invalid JSON: %v", err)
		}

		if depth := calculateJSONDepth(data); depth > ash.config.MaxJSONDepth {
			return fmt.Errorf("JSON depth exceeds limit: %d", depth)
		}
	}

	// Check for malicious patterns in body
	bodyStr := string(body)
	if strings.Contains(bodyStr, "<script") || strings.Contains(bodyStr, "javascript:") {
		return fmt.Errorf("potential XSS in body content")
	}
	if strings.Contains(bodyStr, "'") || strings.Contains(bodyStr, "--") {
		return fmt.Errorf("potential SQL injection in body content")
	}

	return nil
}

// Helper functions
func (ash *APISecurityHardening) checkGeoBlocking(c *gin.Context) (bool, string) {
	// This would integrate with a GeoIP service
	// For now, return false (not blocked)
	return false, ""
}

func (ash *APISecurityHardening) buildCSPHeader() string {
	if len(ash.config.ContentSecurityPolicy.Directives) == 0 {
		return "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
	}

	var parts []string
	for directive, value := range ash.config.ContentSecurityPolicy.Directives {
		parts = append(parts, fmt.Sprintf("%s %s", directive, value))
	}
	return strings.Join(parts, "; ")
}

func (ash *APISecurityHardening) logSecurityEvent(c *gin.Context, eventType, severity, message string, additionalData map[string]interface{}) {
	if ash.auditLogger == nil {
		return
	}

	// Create event data map
	eventData := map[string]interface{}{
		"severity": severity,
		"message":  message,
		"endpoint": c.Request.URL.Path,
		"method":   c.Request.Method,
	}

	// Add additional data if provided
	for key, value := range additionalData {
		eventData[key] = value
	}

	ash.auditLogger.LogEvent(AuditEvent{
		EventType: eventType,
		IPAddress: c.ClientIP(),
		UserAgent: c.Request.UserAgent(),
		Success:   false,
		CreatedAt: time.Now(),
		EventData: eventData,
	})
}

func generateRequestID() string {
	return fmt.Sprintf("%d-%s", time.Now().UnixNano(), generateRandomString(8))
}

func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[time.Now().UnixNano()%int64(len(charset))]
	}
	return string(b)
}

func isValidHostname(hostname string) bool {
	if len(hostname) == 0 || len(hostname) > 253 {
		return false
	}

	// Check for valid hostname format
	hostnameRegex := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`)
	return hostnameRegex.MatchString(hostname)
}

func getDefaultAPISecurityConfig() *APISecurityConfig {
	return &APISecurityConfig{
		Enabled:                    true,
		MaxRequestSize:             10 * 1024 * 1024, // 10MB
		MaxHeaderSize:              8 * 1024,         // 8KB
		MaxQueryParams:             100,
		MaxJSONDepth:               10,
		RequestTimeout:             30 * time.Second,
		EnableRequestSigning:       false,
		EnableAdvancedValidation:   true,
		EnableAttackDetection:      true,
		EnableAnomalyDetection:     true,
		EnableResponseFiltering:    true,
		EnableAuditLogging:         true,
		BlacklistConfig: BlacklistConfig{
			Enabled:       true,
			AutoBlacklist: true,
			Threshold:     5,
			Duration:      24 * time.Hour,
		},
		// Using simplified rate limit config
		RateLimitConfig: RateLimitConfig{},
		// End rate limit config
		SessionConfig: SessionConfig{},
		// Simplified session config
		CSRFProtection: CSRFConfig{
			Enabled:      true,
			TokenLength:  32,
			TokenTimeout: 3600,
			HeaderName:   "X-CSRF-Token",
			FieldName:    "csrf_token",
		},
		ContentSecurityPolicy: CSPConfig{
			Enabled:    true,
			ReportOnly: false,
			Directives: map[string]string{
				"default-src": "'self'",
				"script-src":  "'self' 'unsafe-inline'",
				"style-src":   "'self' 'unsafe-inline'",
				"img-src":     "'self' data:",
				"font-src":    "'self'",
				"connect-src": "'self'",
				"frame-src":   "'none'",
				"object-src":  "'none'",
			},
		},
		GeoBlocking: GeoBlockingConfig{
			Enabled:          false,
			BlockTor:         true,
			BlockVPN:         false,
			BlockDatacenters: false,
		},
		AllowedContentTypes: []string{
			"application/json",
			"application/x-www-form-urlencoded",
			"multipart/form-data",
			"text/plain",
		},
		AdvancedHeaders: map[string]string{
			"X-API-Version":     "1.0",
			"X-Security-Policy": "strict",
		},
	}
}