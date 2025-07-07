package threat_intelligence

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/smtp"
	"strings"
	"sync"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/pkg/logger"
)

// AlertingSystem manages threat intelligence alerts
type AlertingSystem struct {
	config    AlertConfig
	logger    *logger.Logger
	mu        sync.RWMutex
	throttler *AlertThrottler
	channels  map[string]AlertChannelHandler
	stats     AlertingStats
}

// AlertChannelHandler represents an alert channel handler
type AlertChannelHandler interface {
	// Initialize sets up the channel
	Initialize(ctx context.Context, settings map[string]interface{}) error
	
	// SendAlert sends an alert through the channel
	SendAlert(ctx context.Context, alert *ThreatAlert) error
	
	// GetStatus returns the channel status
	GetStatus() ChannelStatus
	
	// Close closes the channel
	Close() error
}

// ThreatAlert represents a threat alert
type ThreatAlert struct {
	ID              string                 `json:"id"`
	Timestamp       time.Time              `json:"timestamp"`
	Severity        string                 `json:"severity"`
	Title           string                 `json:"title"`
	Description     string                 `json:"description"`
	ThreatID        string                 `json:"threat_id"`
	PackageName     string                 `json:"package_name"`
	Ecosystem       string                 `json:"ecosystem"`
	ThreatType      string                 `json:"threat_type"`
	Source          string                 `json:"source"`
	ConfidenceLevel float64                `json:"confidence_level"`
	Recommendations []string               `json:"recommendations"`
	References      []string               `json:"references"`
	Metadata        map[string]interface{} `json:"metadata"`
	Tags            []string               `json:"tags"`
}

// ChannelStatus represents the status of an alert channel
type ChannelStatus struct {
	Name         string    `json:"name"`
	Type         string    `json:"type"`
	Enabled      bool      `json:"enabled"`
	Healthy      bool      `json:"healthy"`
	LastAlert    time.Time `json:"last_alert"`
	LastError    string    `json:"last_error,omitempty"`
	AlertsSent   int64     `json:"alerts_sent"`
	ErrorCount   int64     `json:"error_count"`
}

// AlertingStats represents alerting system statistics
type AlertingStats struct {
	TotalAlerts     int64                    `json:"total_alerts"`
	AlertsBySeverity map[string]int64        `json:"alerts_by_severity"`
	AlertsByChannel map[string]int64         `json:"alerts_by_channel"`
	ThrottledAlerts int64                    `json:"throttled_alerts"`
	FailedAlerts    int64                    `json:"failed_alerts"`
	LastAlert       time.Time                `json:"last_alert"`
	ChannelStats    map[string]ChannelStatus `json:"channel_stats"`
}

// AlertThrottler manages alert throttling
type AlertThrottler struct {
	config      config.ThrottlingConfig
	alertCounts map[string][]time.Time
	mu          sync.RWMutex
}

// NewAlertingSystem creates a new alerting system
func NewAlertingSystem(config AlertConfig, logger *logger.Logger) *AlertingSystem {
	return &AlertingSystem{
		config:    config,
		logger:    logger,
		throttler: NewAlertThrottler(config.Throttling),
		channels:  make(map[string]AlertChannelHandler),
		stats: AlertingStats{
			AlertsBySeverity: make(map[string]int64),
			AlertsByChannel:  make(map[string]int64),
			ChannelStats:     make(map[string]ChannelStatus),
		},
	}
}

// Initialize sets up the alerting system
func (as *AlertingSystem) Initialize(ctx context.Context) error {
	as.mu.Lock()
	defer as.mu.Unlock()

	if !as.config.Enabled {
		as.logger.Info("Alerting system is disabled")
		return nil
	}

	as.logger.Info("Initializing alerting system")

	// Initialize alert channels
	for _, channelConfig := range as.config.Channels {
		// Check if channel is enabled via config map
		if enabled, ok := channelConfig.Config["enabled"]; ok && enabled != "true" {
			continue
		}

		handler, err := as.createChannelHandler(channelConfig.Type)
		if err != nil {
			as.logger.Warn("Failed to create channel handler", map[string]interface{}{
				"type":  channelConfig.Type,
				"error": err,
			})
			continue
		}

		// Convert config map to interface{} map for initialization
		settings := make(map[string]interface{})
		for k, v := range channelConfig.Config {
			settings[k] = v
		}

		if err := handler.Initialize(ctx, settings); err != nil {
			as.logger.Warn("Failed to initialize channel", map[string]interface{}{
				"type":  channelConfig.Type,
				"error": err,
			})
			continue
		}

		as.channels[channelConfig.Type] = handler
		as.logger.Info("Alert channel initialized", map[string]interface{}{
			"type": channelConfig.Type,
		})
	}

	as.logger.Info("Alerting system initialized", map[string]interface{}{
		"channels": len(as.channels),
	})
	return nil
}

// SendThreatAlert sends a threat alert through all configured channels
func (as *AlertingSystem) SendThreatAlert(ctx context.Context, threat *ThreatIntelligence) error {
	if !as.config.Enabled {
		return nil
	}

	// Check if severity is in configured levels
	if !as.shouldAlert(threat.Severity) {
		return nil
	}

	// Create alert
	alert := as.createThreatAlert(threat)

	// Apply filters
	if !as.passesFilters(alert) {
		as.logger.Debug("Alert filtered out", map[string]interface{}{
			"threat_id": threat.ID,
		})
		return nil
	}

	// Check throttling
	if as.throttler.ShouldThrottle(alert) {
		as.updateStats("throttled", "")
		as.logger.Debug("Alert throttled", map[string]interface{}{
			"threat_id": threat.ID,
		})
		return nil
	}

	// Send alert through all channels
	return as.sendAlert(ctx, alert)
}

// SendCustomAlert sends a custom alert
func (as *AlertingSystem) SendCustomAlert(ctx context.Context, alert *ThreatAlert) error {
	if !as.config.Enabled {
		return nil
	}

	// Apply filters
	if !as.passesFilters(alert) {
		as.logger.Debug("Custom alert filtered out", map[string]interface{}{
			"alert_id": alert.ID,
		})
		return nil
	}

	// Check throttling
	if as.throttler.ShouldThrottle(alert) {
		as.updateStats("throttled", "")
		as.logger.Debug("Custom alert throttled", map[string]interface{}{
			"alert_id": alert.ID,
		})
		return nil
	}

	// Send alert through all channels
	return as.sendAlert(ctx, alert)
}

// GetStatistics returns alerting statistics
func (as *AlertingSystem) GetStatistics() AlertingStats {
	as.mu.RLock()
	defer as.mu.RUnlock()

	// Update channel stats
	for name, handler := range as.channels {
		as.stats.ChannelStats[name] = handler.GetStatus()
	}

	return as.stats
}

// UpdateConfiguration updates the alerting configuration
func (as *AlertingSystem) UpdateConfiguration(config AlertConfig) error {
	as.mu.Lock()
	defer as.mu.Unlock()

	as.config = config
	as.throttler.UpdateConfig(config.Throttling)

	as.logger.Info("Alerting configuration updated")
	return nil
}

// Shutdown gracefully shuts down the alerting system
func (as *AlertingSystem) Shutdown(ctx context.Context) error {
	as.mu.Lock()
	defer as.mu.Unlock()

	as.logger.Info("Shutting down alerting system")

	// Close all channels
	for name, handler := range as.channels {
		if err := handler.Close(); err != nil {
			as.logger.Warn("Failed to close alert channel", map[string]interface{}{
				"channel": name,
				"error":   err,
			})
		}
	}

	as.logger.Info("Alerting system shutdown completed")
	return nil
}

// Helper methods

func (as *AlertingSystem) createChannelHandler(channelType string) (AlertChannelHandler, error) {
	switch channelType {
	case "email":
		return NewEmailChannel(as.logger), nil
	case "slack":
		return NewSlackChannel(as.logger), nil
	case "webhook":
		return NewWebhookChannel(as.logger), nil
	case "github":
		return NewGitHubChannel(as.logger), nil
	default:
		return nil, fmt.Errorf("unsupported channel type: %s", channelType)
	}
}

func (as *AlertingSystem) shouldAlert(severity string) bool {
	for _, level := range as.config.SeverityLevels {
		if level == severity {
			return true
		}
	}
	return false
}

func (as *AlertingSystem) createThreatAlert(threat *ThreatIntelligence) *ThreatAlert {
	return &ThreatAlert{
		ID:              fmt.Sprintf("alert-%s-%d", threat.ID, time.Now().Unix()),
		Timestamp:       time.Now(),
		Severity:        threat.Severity,
		Title:           fmt.Sprintf("Threat Detected: %s", threat.PackageName),
		Description:     threat.Description,
		ThreatID:        threat.ID,
		PackageName:     threat.PackageName,
		Ecosystem:       threat.Ecosystem,
		ThreatType:      threat.Type,
		Source:          threat.Source,
		ConfidenceLevel: threat.ConfidenceLevel,
		Recommendations: as.generateRecommendations(threat),
		References:      threat.References,
		Metadata:        threat.Metadata,
		Tags:            threat.Tags,
	}
}

func (as *AlertingSystem) generateRecommendations(threat *ThreatIntelligence) []string {
	var recommendations []string

	switch threat.Severity {
	case "critical":
		recommendations = append(recommendations, "Immediate action required")
		recommendations = append(recommendations, "Remove package from all systems")
		recommendations = append(recommendations, "Scan for potential compromise")
	case "high":
		recommendations = append(recommendations, "Avoid using this package")
		recommendations = append(recommendations, "Find alternative packages")
	case "medium":
		recommendations = append(recommendations, "Use with caution")
		recommendations = append(recommendations, "Monitor for updates")
	case "low":
		recommendations = append(recommendations, "Monitor for changes")
	}

	switch threat.Type {
	case "typosquatting":
		recommendations = append(recommendations, "Verify package name spelling")
	case "malware":
		recommendations = append(recommendations, "Run security scan")
	case "supply_chain":
		recommendations = append(recommendations, "Verify package integrity")
	}

	return recommendations
}

func (as *AlertingSystem) passesFilters(alert *ThreatAlert) bool {
	for _, filter := range as.config.Filters {
		if !as.applyFilter(alert, filter) {
			return false
		}
	}
	return true
}

func (as *AlertingSystem) applyFilter(alert *ThreatAlert, filter AlertFilter) bool {
	var fieldValue interface{}

	switch filter.Field {
	case "severity":
		fieldValue = alert.Severity
	case "threat_type":
		fieldValue = alert.ThreatType
	case "package_name":
		fieldValue = alert.PackageName
	case "ecosystem":
		fieldValue = alert.Ecosystem
	case "confidence_level":
		fieldValue = alert.ConfidenceLevel
	default:
		return true // Unknown field, pass through
	}

	matches := as.evaluateFilterCondition(fieldValue, filter.Operator, filter.Value)

	if filter.Action == "include" {
		return matches
	} else if filter.Action == "exclude" {
		return !matches
	}

	return true
}

func (as *AlertingSystem) evaluateFilterCondition(fieldValue interface{}, operator string, filterValue interface{}) bool {
	switch operator {
	case "equals":
		return fieldValue == filterValue
	case "contains":
		if str, ok := fieldValue.(string); ok {
			if filterStr, ok := filterValue.(string); ok {
				return strings.Contains(str, filterStr)
			}
		}
	case "gt":
		if num, ok := fieldValue.(float64); ok {
			if filterNum, ok := filterValue.(float64); ok {
				return num > filterNum
			}
		}
	case "lt":
		if num, ok := fieldValue.(float64); ok {
			if filterNum, ok := filterValue.(float64); ok {
				return num < filterNum
			}
		}
	}
	return false
}

func (as *AlertingSystem) sendAlert(ctx context.Context, alert *ThreatAlert) error {
	as.logger.Info("Sending threat alert", map[string]interface{}{
		"alert_id":    alert.ID,
		"severity":    alert.Severity,
		"package":     alert.PackageName,
		"threat_type": alert.ThreatType,
	})

	var errors []string
	successCount := 0

	for name, handler := range as.channels {
		if err := handler.SendAlert(ctx, alert); err != nil {
			as.logger.Warn("Failed to send alert through channel", map[string]interface{}{
				"channel": name,
				"error":   err,
			})
			errors = append(errors, fmt.Sprintf("%s: %v", name, err))
			as.updateStats("failed", name)
		} else {
			as.logger.Debug("Alert sent successfully", map[string]interface{}{
				"channel": name,
			})
			successCount++
			as.updateStats("sent", name)
		}
	}

	// Update overall stats
	as.updateStats("total", "")
	as.updateStats(alert.Severity, "")

	if successCount == 0 && len(errors) > 0 {
		return fmt.Errorf("failed to send alert through any channel: %s", strings.Join(errors, "; "))
	}

	return nil
}

func (as *AlertingSystem) updateStats(statType, channel string) {
	as.mu.Lock()
	defer as.mu.Unlock()

	switch statType {
	case "total":
		as.stats.TotalAlerts++
		as.stats.LastAlert = time.Now()
	case "throttled":
		as.stats.ThrottledAlerts++
	case "failed":
		as.stats.FailedAlerts++
	case "sent":
		if channel != "" {
			as.stats.AlertsByChannel[channel]++
		}
	case "critical", "high", "medium", "low", "info":
		as.stats.AlertsBySeverity[statType]++
	}
}

// Alert Throttler

// NewAlertThrottler creates a new alert throttler
func NewAlertThrottler(config config.ThrottlingConfig) *AlertThrottler {
	return &AlertThrottler{
		config:      config,
		alertCounts: make(map[string][]time.Time),
	}
}

// ShouldThrottle determines if an alert should be throttled
func (at *AlertThrottler) ShouldThrottle(alert *ThreatAlert) bool {
	if !at.config.Enabled {
		return false
	}

	at.mu.Lock()
	defer at.mu.Unlock()

	// Create throttle key based on alert characteristics
	key := fmt.Sprintf("%s:%s:%s", alert.Severity, alert.ThreatType, alert.PackageName)

	now := time.Now()
	windowStart := now.Add(-time.Minute)

	// Clean old entries
	var recentAlerts []time.Time
	for _, timestamp := range at.alertCounts[key] {
		if timestamp.After(windowStart) {
			recentAlerts = append(recentAlerts, timestamp)
		}
	}

	at.alertCounts[key] = recentAlerts

	// Check if we've exceeded the limit
	if len(recentAlerts) >= at.config.MaxPerMinute {
		return true
	}

	// Add current alert to count
	at.alertCounts[key] = append(at.alertCounts[key], now)

	return false
}

// UpdateConfig updates the throttling configuration
func (at *AlertThrottler) UpdateConfig(config config.ThrottlingConfig) {
	at.mu.Lock()
	defer at.mu.Unlock()

	at.config = config
	// Clear existing counts when config changes
	at.alertCounts = make(map[string][]time.Time)
}

// Email Channel Implementation

type EmailChannel struct {
	logger   *logger.Logger
	settings EmailSettings
	status   ChannelStatus
}

type EmailSettings struct {
	SMTPHost     string   `json:"smtp_host"`
	SMTPPort     int      `json:"smtp_port"`
	Username     string   `json:"username"`
	Password     string   `json:"password"`
	FromAddress  string   `json:"from_address"`
	ToAddresses  []string `json:"to_addresses"`
	SubjectPrefix string  `json:"subject_prefix"`
}

func NewEmailChannel(logger *logger.Logger) *EmailChannel {
	return &EmailChannel{
		logger: logger,
		status: ChannelStatus{
			Name:    "email",
			Type:    "email",
			Enabled: true,
			Healthy: true,
		},
	}
}

func (ec *EmailChannel) Initialize(ctx context.Context, settings map[string]interface{}) error {
	// Parse settings
	settingsJSON, err := json.Marshal(settings)
	if err != nil {
		return fmt.Errorf("failed to marshal email settings: %w", err)
	}

	if err := json.Unmarshal(settingsJSON, &ec.settings); err != nil {
		return fmt.Errorf("failed to unmarshal email settings: %w", err)
	}

	// Validate settings
	if ec.settings.SMTPHost == "" || ec.settings.FromAddress == "" || len(ec.settings.ToAddresses) == 0 {
		return fmt.Errorf("missing required email settings")
	}

	ec.logger.Info("Email channel initialized", map[string]interface{}{
		"smtp_host": ec.settings.SMTPHost,
	})
	return nil
}

func (ec *EmailChannel) SendAlert(ctx context.Context, alert *ThreatAlert) error {
	subject := fmt.Sprintf("%s[%s] %s", ec.settings.SubjectPrefix, strings.ToUpper(alert.Severity), alert.Title)
	body := ec.formatEmailBody(alert)

	// Create message
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s",
		ec.settings.FromAddress,
		strings.Join(ec.settings.ToAddresses, ", "),
		subject,
		body)

	// Send email
	auth := smtp.PlainAuth("", ec.settings.Username, ec.settings.Password, ec.settings.SMTPHost)
	addr := fmt.Sprintf("%s:%d", ec.settings.SMTPHost, ec.settings.SMTPPort)

	err := smtp.SendMail(addr, auth, ec.settings.FromAddress, ec.settings.ToAddresses, []byte(msg))
	if err != nil {
		ec.status.ErrorCount++
		ec.status.LastError = err.Error()
		ec.status.Healthy = false
		return fmt.Errorf("failed to send email: %w", err)
	}

	ec.status.AlertsSent++
	ec.status.LastAlert = time.Now()
	ec.status.Healthy = true
	ec.status.LastError = ""

	return nil
}

func (ec *EmailChannel) formatEmailBody(alert *ThreatAlert) string {
	var body strings.Builder

	body.WriteString(fmt.Sprintf("Threat Alert: %s\n", alert.Title))
	body.WriteString(fmt.Sprintf("Severity: %s\n", strings.ToUpper(alert.Severity)))
	body.WriteString(fmt.Sprintf("Package: %s (%s)\n", alert.PackageName, alert.Ecosystem))
	body.WriteString(fmt.Sprintf("Threat Type: %s\n", alert.ThreatType))
	body.WriteString(fmt.Sprintf("Source: %s\n", alert.Source))
	body.WriteString(fmt.Sprintf("Confidence: %.2f\n", alert.ConfidenceLevel))
	body.WriteString(fmt.Sprintf("Timestamp: %s\n\n", alert.Timestamp.Format(time.RFC3339)))

	body.WriteString("Description:\n")
	body.WriteString(alert.Description)
	body.WriteString("\n\n")

	if len(alert.Recommendations) > 0 {
		body.WriteString("Recommendations:\n")
		for _, rec := range alert.Recommendations {
			body.WriteString(fmt.Sprintf("- %s\n", rec))
		}
		body.WriteString("\n")
	}

	if len(alert.References) > 0 {
		body.WriteString("References:\n")
		for _, ref := range alert.References {
			body.WriteString(fmt.Sprintf("- %s\n", ref))
		}
	}

	return body.String()
}

func (ec *EmailChannel) GetStatus() ChannelStatus {
	return ec.status
}

func (ec *EmailChannel) Close() error {
	return nil
}

// Webhook Channel Implementation

type WebhookChannel struct {
	logger   *logger.Logger
	settings WebhookSettings
	status   ChannelStatus
	client   *http.Client
}

type WebhookSettings struct {
	URL     string            `json:"url"`
	Method  string            `json:"method"`
	Headers map[string]string `json:"headers"`
	Timeout int               `json:"timeout"`
}

func NewWebhookChannel(logger *logger.Logger) *WebhookChannel {
	return &WebhookChannel{
		logger: logger,
		status: ChannelStatus{
			Name:    "webhook",
			Type:    "webhook",
			Enabled: true,
			Healthy: true,
		},
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

func (wc *WebhookChannel) Initialize(ctx context.Context, settings map[string]interface{}) error {
	settingsJSON, err := json.Marshal(settings)
	if err != nil {
		return fmt.Errorf("failed to marshal webhook settings: %w", err)
	}

	if err := json.Unmarshal(settingsJSON, &wc.settings); err != nil {
		return fmt.Errorf("failed to unmarshal webhook settings: %w", err)
	}

	if wc.settings.URL == "" {
		return fmt.Errorf("webhook URL is required")
	}

	if wc.settings.Method == "" {
		wc.settings.Method = "POST"
	}

	if wc.settings.Timeout > 0 {
		wc.client.Timeout = time.Duration(wc.settings.Timeout) * time.Second
	}

	wc.logger.Info("Webhook channel initialized", map[string]interface{}{
		"url": wc.settings.URL,
	})
	return nil
}

func (wc *WebhookChannel) SendAlert(ctx context.Context, alert *ThreatAlert) error {
	payload, err := json.Marshal(alert)
	if err != nil {
		return fmt.Errorf("failed to marshal alert: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, wc.settings.Method, wc.settings.URL, bytes.NewBuffer(payload))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	for key, value := range wc.settings.Headers {
		req.Header.Set(key, value)
	}

	resp, err := wc.client.Do(req)
	if err != nil {
		wc.status.ErrorCount++
		wc.status.LastError = err.Error()
		wc.status.Healthy = false
		return fmt.Errorf("failed to send webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		wc.status.ErrorCount++
		wc.status.LastError = fmt.Sprintf("HTTP %d", resp.StatusCode)
		wc.status.Healthy = false
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}

	wc.status.AlertsSent++
	wc.status.LastAlert = time.Now()
	wc.status.Healthy = true
	wc.status.LastError = ""

	return nil
}

func (wc *WebhookChannel) GetStatus() ChannelStatus {
	return wc.status
}

func (wc *WebhookChannel) Close() error {
	return nil
}

// Placeholder implementations for Slack and GitHub channels
// These would be implemented similarly to Email and Webhook channels

type SlackChannel struct {
	logger *logger.Logger
	status ChannelStatus
}

func NewSlackChannel(logger *logger.Logger) *SlackChannel {
	return &SlackChannel{
		logger: logger,
		status: ChannelStatus{Name: "slack", Type: "slack", Enabled: true, Healthy: true},
	}
}

func (sc *SlackChannel) Initialize(ctx context.Context, settings map[string]interface{}) error {
	// TODO: Implement Slack channel initialization
	return nil
}

func (sc *SlackChannel) SendAlert(ctx context.Context, alert *ThreatAlert) error {
	// TODO: Implement Slack alert sending
	return nil
}

func (sc *SlackChannel) GetStatus() ChannelStatus {
	return sc.status
}

func (sc *SlackChannel) Close() error {
	return nil
}

type GitHubChannel struct {
	logger *logger.Logger
	status ChannelStatus
}

func NewGitHubChannel(logger *logger.Logger) *GitHubChannel {
	return &GitHubChannel{
		logger: logger,
		status: ChannelStatus{Name: "github", Type: "github", Enabled: true, Healthy: true},
	}
}

func (gc *GitHubChannel) Initialize(ctx context.Context, settings map[string]interface{}) error {
	// TODO: Implement GitHub channel initialization
	return nil
}

func (gc *GitHubChannel) SendAlert(ctx context.Context, alert *ThreatAlert) error {
	// TODO: Implement GitHub alert sending (issues, security advisories)
	return nil
}

func (gc *GitHubChannel) GetStatus() ChannelStatus {
	return gc.status
}

func (gc *GitHubChannel) Close() error {
	return nil
}