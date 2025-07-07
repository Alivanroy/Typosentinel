package plugins

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// WebhookPlugin implements Plugin interface for generic webhook integration
type WebhookPlugin struct {
	info     PluginInfo
	settings WebhookSettings
	logger   Logger
	client   *http.Client
	status   PluginStatus
}

// WebhookSettings contains webhook specific configuration
type WebhookSettings struct {
	URL             string                 `json:"url"`
	Method          string                 `json:"method"`
	Headers         map[string]string      `json:"headers"`
	Secret          string                 `json:"secret"`
	SignatureHeader string                 `json:"signature_header"`
	ContentType     string                 `json:"content_type"`
	Timeout         int                    `json:"timeout_seconds"`
	RetryAttempts   int                    `json:"retry_attempts"`
	RetryDelay      int                    `json:"retry_delay_seconds"`
	FailOnCritical  bool                   `json:"fail_on_critical"`
	FailOnHigh      bool                   `json:"fail_on_high"`
	FilterSeverity  []string               `json:"filter_severity"`
	CustomPayload   map[string]interface{} `json:"custom_payload"`
	AuthType        string                 `json:"auth_type"`
	AuthToken       string                 `json:"auth_token"`
	Username        string                 `json:"username"`
	Password        string                 `json:"password"`
}

// WebhookOutput represents the output structure for webhook
type WebhookOutput struct {
	RequestID       string                 `json:"request_id"`
	URL             string                 `json:"url"`
	Method          string                 `json:"method"`
	StatusCode      int                    `json:"status_code"`
	ResponseTime    int64                  `json:"response_time_ms"`
	RequestHeaders  map[string]string      `json:"request_headers"`
	ResponseHeaders map[string]string      `json:"response_headers"`
	RequestBody     interface{}            `json:"request_body"`
	ResponseBody    string                 `json:"response_body"`
	Success         bool                   `json:"success"`
	Error           string                 `json:"error,omitempty"`
	RetryAttempts   int                    `json:"retry_attempts"`
	Metrics         map[string]interface{} `json:"metrics"`
}

// WebhookPayload represents the standard webhook payload
type WebhookPayload struct {
	Event           string                 `json:"event"`
	Timestamp       time.Time              `json:"timestamp"`
	Source          string                 `json:"source"`
	Version         string                 `json:"version"`
	PackageName     string                 `json:"package_name"`
	PackageVersion  string                 `json:"package_version"`
	RiskScore       float64                `json:"risk_score"`
	OverallRisk     string                 `json:"overall_risk"`
	Threats         []WebhookThreat        `json:"threats"`
	Recommendations []string               `json:"recommendations"`
	Metadata        map[string]interface{} `json:"metadata"`
	CustomData      map[string]interface{} `json:"custom_data,omitempty"`
}

// WebhookThreat represents a threat in the webhook payload
type WebhookThreat struct {
	Type        string  `json:"type"`
	Severity    string  `json:"severity"`
	Description string  `json:"description"`
	Score       float64 `json:"score"`
	Confidence  float64 `json:"confidence"`
}

// WebhookResponse represents the response from webhook endpoint
type WebhookResponse struct {
	Success   bool                   `json:"success"`
	Message   string                 `json:"message"`
	RequestID string                 `json:"request_id,omitempty"`
	Actions   []string               `json:"actions,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// NewWebhookPlugin creates a new webhook plugin instance
func NewWebhookPlugin(logger Logger) *WebhookPlugin {
	return &WebhookPlugin{
		info: PluginInfo{
			Name:        "webhook",
			Version:     "1.0.0",
			Description: "Generic webhook integration for Typosentinel",
			Author:      "Typosentinel Team",
			Platform:    "webhook",
			Capabilities: []string{
				"http_notifications",
				"custom_payloads",
				"authentication",
				"retry_logic",
				"signature_verification",
				"severity_filtering",
				"custom_headers",
				"response_handling",
			},
		},
		logger: logger,
	}
}

// GetInfo returns plugin information
func (p *WebhookPlugin) GetInfo() PluginInfo {
	return p.info
}

// Initialize sets up the webhook plugin
func (p *WebhookPlugin) Initialize(ctx context.Context, config map[string]interface{}) error {
	// Convert config to settings
	configBytes, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := json.Unmarshal(configBytes, &p.settings); err != nil {
		return fmt.Errorf("failed to unmarshal settings: %w", err)
	}

	// Set defaults
	if p.settings.Method == "" {
		p.settings.Method = "POST"
	}
	if p.settings.ContentType == "" {
		p.settings.ContentType = "application/json"
	}
	if p.settings.Timeout == 0 {
		p.settings.Timeout = 30
	}
	if p.settings.RetryAttempts == 0 {
		p.settings.RetryAttempts = 3
	}
	if p.settings.RetryDelay == 0 {
		p.settings.RetryDelay = 5
	}
	if p.settings.SignatureHeader == "" {
		p.settings.SignatureHeader = "X-Typosentinel-Signature"
	}

	// Initialize HTTP client
	p.client = &http.Client{
		Timeout: time.Duration(p.settings.Timeout) * time.Second,
	}

	// Initialize headers if not provided
	if p.settings.Headers == nil {
		p.settings.Headers = make(map[string]string)
	}

	// Set default headers
	p.settings.Headers["Content-Type"] = p.settings.ContentType
	p.settings.Headers["User-Agent"] = "Typosentinel-Webhook/1.0.0"

	p.logger.Info("Webhook plugin initialized", map[string]interface{}{
		"url":            p.settings.URL,
		"method":         p.settings.Method,
		"content_type":   p.settings.ContentType,
		"timeout":        p.settings.Timeout,
		"retry_attempts": p.settings.RetryAttempts,
		"auth_type":      p.settings.AuthType,
	})

	return nil
}

// Execute runs the webhook integration
func (p *WebhookPlugin) Execute(ctx context.Context, result *types.ScanResult) (*PluginResult, error) {
	start := time.Now()

	// Derive package information from first package or fallback to target
	packageName := result.Target
	packageVersion := "unknown"
	if len(result.Packages) > 0 {
		packageName = result.Packages[0].Name
		packageVersion = result.Packages[0].Version
	}

	// Collect all threats from all packages
	allThreats := []types.Threat{}
	for _, pkg := range result.Packages {
		allThreats = append(allThreats, pkg.Threats...)
	}

	p.logger.Info("Executing webhook plugin", map[string]interface{}{
		"package": packageName,
		"risk":    "unknown", // Risk calculation moved to individual packages
		"url":     p.settings.URL,
	})

	// Filter threats by severity if configured
	filteredThreats := p.filterThreatsBySeverity(allThreats)

	// Skip webhook if no threats match filter
	if len(p.settings.FilterSeverity) > 0 && len(filteredThreats) == 0 {
		p.logger.Info("No threats match severity filter, skipping webhook")
		skippedData := map[string]interface{}{
			"skipped": true,
			"reason":  "no_matching_threats",
		}
		return &PluginResult{
			Success: true,
			Message: "No threats match severity filter",
			Data:    skippedData,
		}, nil
	}

	// Create webhook payload
	payload := p.createPayload(result, filteredThreats)

	// Send webhook with retry logic
	output, err := p.sendWebhookWithRetry(ctx, payload)
	if err != nil {
		return nil, fmt.Errorf("failed to send webhook: %w", err)
	}

	// Handle severity-based actions
	actions := p.handleSeverityActions(result)

	// Update metrics
	output.Metrics = map[string]interface{}{
		"execution_duration_ms": time.Since(start).Milliseconds(),
		"threats_sent":          len(filteredThreats),
		"total_threats":         len(allThreats),
		"risk_score":            0.0,       // Risk calculation moved to individual packages
		"overall_risk":          "unknown", // Risk calculation moved to individual packages
		"package_name":          packageName,
		"package_version":       packageVersion,
	}

	return &PluginResult{
		Success: output.Success,
		Message: p.generateSummaryMessage(result, output),
		Data: map[string]interface{}{
			"webhook_output": output,
		},
		Actions: actions,
		Metadata: map[string]interface{}{
			"platform":       "webhook",
			"url":            p.settings.URL,
			"method":         p.settings.Method,
			"status_code":    output.StatusCode,
			"response_time":  output.ResponseTime,
			"retry_attempts": output.RetryAttempts,
		},
	}, nil
}

// filterThreatsBySeverity filters threats based on severity settings
func (p *WebhookPlugin) filterThreatsBySeverity(threats []types.Threat) []types.Threat {
	if len(p.settings.FilterSeverity) == 0 {
		return threats
	}

	filtered := []types.Threat{}
	for _, threat := range threats {
		for _, severity := range p.settings.FilterSeverity {
			if threat.Severity.String() == severity {
				filtered = append(filtered, threat)
				break
			}
		}
	}

	return filtered
}

// createPayload creates the webhook payload
func (p *WebhookPlugin) createPayload(result *types.ScanResult, threats []types.Threat) *WebhookPayload {
	// Derive package information from first package or fallback to target
	packageName := result.Target
	packageVersion := "unknown"
	if len(result.Packages) > 0 {
		packageName = result.Packages[0].Name
		packageVersion = result.Packages[0].Version
	}

	// Calculate total threats across all packages
	totalThreats := 0
	for _, pkg := range result.Packages {
		totalThreats += len(pkg.Threats)
	}

	webhookThreats := make([]WebhookThreat, len(threats))
	for i, threat := range threats {
		webhookThreats[i] = WebhookThreat{
			Type:        string(threat.Type),
			Severity:    threat.Severity.String(),
			Description: threat.Description,
			Score:       0.0, // Default score, can be enhanced
			Confidence:  1.0, // Default confidence
		}
	}

	payload := &WebhookPayload{
		Event:           "security_scan_completed",
		Timestamp:       time.Now(),
		Source:          "typosentinel",
		Version:         "1.0.0",
		PackageName:     packageName,
		PackageVersion:  packageVersion,
		RiskScore:       0.0,       // Risk calculation moved to individual packages
		OverallRisk:     "unknown", // Risk calculation moved to individual packages
		Threats:         webhookThreats,
		Recommendations: []string{}, // Recommendations not available in new structure
		Metadata: map[string]interface{}{
			"scan_timestamp":   time.Now().Unix(),
			"total_threats":    totalThreats,
			"filtered_threats": len(threats),
		},
	}

	// Add custom payload data if configured
	if len(p.settings.CustomPayload) > 0 {
		payload.CustomData = p.settings.CustomPayload
	}

	return payload
}

// sendWebhookWithRetry sends webhook with retry logic
func (p *WebhookPlugin) sendWebhookWithRetry(ctx context.Context, payload *WebhookPayload) (*WebhookOutput, error) {
	requestID := p.generateRequestID()
	output := &WebhookOutput{
		RequestID:      requestID,
		URL:            p.settings.URL,
		Method:         p.settings.Method,
		RequestHeaders: make(map[string]string),
		RetryAttempts:  0,
	}

	var lastErr error
	for attempt := 0; attempt <= p.settings.RetryAttempts; attempt++ {
		if attempt > 0 {
			p.logger.Info("Retrying webhook request", map[string]interface{}{
				"attempt": attempt,
				"url":     p.settings.URL,
			})
			time.Sleep(time.Duration(p.settings.RetryDelay) * time.Second)
		}

		output.RetryAttempts = attempt
		err := p.sendWebhook(ctx, payload, output)
		if err == nil && output.Success {
			return output, nil
		}

		lastErr = err
		if err != nil {
			p.logger.Warn("Webhook request failed", map[string]interface{}{
				"attempt": attempt,
				"error":   err.Error(),
				"url":     p.settings.URL,
			})
		}
	}

	if lastErr != nil {
		output.Error = lastErr.Error()
	}

	return output, lastErr
}

// sendWebhook sends a single webhook request
func (p *WebhookPlugin) sendWebhook(ctx context.Context, payload *WebhookPayload, output *WebhookOutput) error {
	start := time.Now()

	// Marshal payload to JSON
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	output.RequestBody = payload

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, p.settings.Method, p.settings.URL, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	for key, value := range p.settings.Headers {
		req.Header.Set(key, value)
		output.RequestHeaders[key] = value
	}

	// Add authentication
	p.addAuthentication(req)

	// Add signature if secret is configured
	if p.settings.Secret != "" {
		signature := p.generateSignature(payloadBytes)
		req.Header.Set(p.settings.SignatureHeader, signature)
		output.RequestHeaders[p.settings.SignatureHeader] = signature
	}

	// Send request
	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	output.StatusCode = resp.StatusCode
	output.ResponseTime = time.Since(start).Milliseconds()

	// Copy response headers
	output.ResponseHeaders = make(map[string]string)
	for key, values := range resp.Header {
		if len(values) > 0 {
			output.ResponseHeaders[key] = values[0]
		}
	}

	// Read response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	output.ResponseBody = string(respBody)

	// Check if request was successful
	output.Success = resp.StatusCode >= 200 && resp.StatusCode < 300

	if !output.Success {
		return fmt.Errorf("webhook returned status %d: %s", resp.StatusCode, string(respBody))
	}

	p.logger.Info("Webhook sent successfully", map[string]interface{}{
		"url":           p.settings.URL,
		"status_code":   resp.StatusCode,
		"response_time": output.ResponseTime,
	})

	return nil
}

// addAuthentication adds authentication to the request
func (p *WebhookPlugin) addAuthentication(req *http.Request) {
	switch p.settings.AuthType {
	case "bearer":
		if p.settings.AuthToken != "" {
			req.Header.Set("Authorization", "Bearer "+p.settings.AuthToken)
		}
	case "basic":
		if p.settings.Username != "" && p.settings.Password != "" {
			req.SetBasicAuth(p.settings.Username, p.settings.Password)
		}
	case "token":
		if p.settings.AuthToken != "" {
			req.Header.Set("Authorization", "Token "+p.settings.AuthToken)
		}
	case "api-key":
		if p.settings.AuthToken != "" {
			req.Header.Set("X-API-Key", p.settings.AuthToken)
		}
	}
}

// generateSignature generates HMAC signature for the payload
func (p *WebhookPlugin) generateSignature(payload []byte) string {
	h := hmac.New(sha256.New, []byte(p.settings.Secret))
	h.Write(payload)
	return "sha256=" + hex.EncodeToString(h.Sum(nil))
}

// generateRequestID generates a unique request ID
func (p *WebhookPlugin) generateRequestID() string {
	return fmt.Sprintf("typosentinel-%d", time.Now().UnixNano())
}

// handleSeverityActions handles actions based on threat severity
func (p *WebhookPlugin) handleSeverityActions(result *types.ScanResult) []PluginAction {
	actions := []PluginAction{}

	hasCritical := false
	hasHigh := false

	for _, pkg := range result.Packages {
		for _, threat := range pkg.Threats {
			if threat.Severity == types.SeverityCritical {
				hasCritical = true
			}
			if threat.Severity == types.SeverityHigh {
				hasHigh = true
			}
		}
	}

	if hasCritical && p.settings.FailOnCritical {
		actions = append(actions, PluginAction{
			Type: "fail_build",
			Data: map[string]interface{}{
				"reason": "Critical security threats detected",
			},
		})
	}

	if hasHigh && p.settings.FailOnHigh {
		actions = append(actions, PluginAction{
			Type: "fail_build",
			Data: map[string]interface{}{
				"reason": "High severity security threats detected",
			},
		})
	}

	return actions
}

// generateSummaryMessage generates a summary message
func (p *WebhookPlugin) generateSummaryMessage(result *types.ScanResult, output *WebhookOutput) string {
	// Derive package information from first package or fallback to target
	packageName := result.Target
	packageVersion := "unknown"
	if len(result.Packages) > 0 {
		packageName = result.Packages[0].Name
		packageVersion = result.Packages[0].Version
	}

	// Calculate total threats across all packages
	totalThreats := 0
	for _, pkg := range result.Packages {
		totalThreats += len(pkg.Threats)
	}

	if output.Success {
		if totalThreats == 0 {
			return fmt.Sprintf("✅ Webhook sent successfully - No threats detected in %s@%s", packageName, packageVersion)
		}
		return fmt.Sprintf("✅ Webhook sent successfully - %d threats detected in %s@%s (Status: %d)",
			totalThreats, packageName, packageVersion, output.StatusCode)
	}

	return fmt.Sprintf("❌ Webhook failed - %s@%s (Status: %d, Attempts: %d)",
		packageName, packageVersion, output.StatusCode, output.RetryAttempts+1)
}

// Validate checks if the plugin configuration is valid
func (p *WebhookPlugin) Validate(ctx context.Context) error {
	if p.settings.URL == "" {
		return fmt.Errorf("url is required for webhook integration")
	}

	if !strings.HasPrefix(p.settings.URL, "http://") && !strings.HasPrefix(p.settings.URL, "https://") {
		return fmt.Errorf("url must start with http:// or https://")
	}

	validMethods := []string{"GET", "POST", "PUT", "PATCH"}
	validMethod := false
	for _, method := range validMethods {
		if p.settings.Method == method {
			validMethod = true
			break
		}
	}
	if !validMethod {
		return fmt.Errorf("method must be one of: %s", strings.Join(validMethods, ", "))
	}

	if p.settings.Timeout < 1 || p.settings.Timeout > 300 {
		return fmt.Errorf("timeout must be between 1 and 300 seconds")
	}

	if p.settings.RetryAttempts < 0 || p.settings.RetryAttempts > 10 {
		return fmt.Errorf("retry_attempts must be between 0 and 10")
	}

	if p.settings.AuthType != "" {
		validAuthTypes := []string{"bearer", "basic", "token", "api-key"}
		validAuth := false
		for _, authType := range validAuthTypes {
			if p.settings.AuthType == authType {
				validAuth = true
				break
			}
		}
		if !validAuth {
			return fmt.Errorf("auth_type must be one of: %s", strings.Join(validAuthTypes, ", "))
		}
	}

	return nil
}

// GetStatus returns the current plugin status
func (p *WebhookPlugin) GetStatus() PluginStatus {
	return p.status
}

// Cleanup performs any necessary cleanup
func (p *WebhookPlugin) Cleanup(ctx context.Context) error {
	if p.client != nil {
		p.client.CloseIdleConnections()
	}
	p.logger.Info("Webhook plugin cleanup completed")
	return nil
}
