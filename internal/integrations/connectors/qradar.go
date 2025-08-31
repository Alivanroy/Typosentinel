package connectors

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Alivanroy/Typosentinel/pkg/events"
	"github.com/Alivanroy/Typosentinel/pkg/integrations"
	"github.com/Alivanroy/Typosentinel/pkg/logger"
)

// QRadarConnector sends events to IBM QRadar SIEM
type QRadarConnector struct {
	name   string
	config QRadarConfig
	client *http.Client
	logger logger.Logger
	health integrations.HealthStatus
}

// QRadarConfig defines QRadar connection settings
type QRadarConfig struct {
	URL         string `json:"url"`
	APIToken    string `json:"api_token"`
	Timeout     int    `json:"timeout"`
	VerifySSL   bool   `json:"verify_ssl"`
	EventSource string `json:"event_source"`
	LogSource   string `json:"log_source"`
}

// QRadarEvent represents an event to be sent to QRadar
type QRadarEvent struct {
	EventTime  int64                  `json:"event_time"`
	EventType  string                 `json:"event_type"`
	Severity   int                    `json:"severity"`
	Message    string                 `json:"message"`
	SourceIP   string                 `json:"source_ip,omitempty"`
	DestIP     string                 `json:"dest_ip,omitempty"`
	UserName   string                 `json:"username,omitempty"`
	EventID    string                 `json:"event_id"`
	Category   string                 `json:"category"`
	Properties map[string]interface{} `json:"properties"`
	LogSource  string                 `json:"log_source"`
}

// NewQRadarConnector creates a new QRadar connector
func NewQRadarConnector(name string, settings map[string]interface{}, logger logger.Logger) (*QRadarConnector, error) {
	config, err := parseQRadarConfig(settings)
	if err != nil {
		return nil, fmt.Errorf("invalid QRadar configuration: %w", err)
	}

	timeout := 30 * time.Second
	if config.Timeout > 0 {
		timeout = time.Duration(config.Timeout) * time.Second
	}

	client := &http.Client{
		Timeout: timeout,
	}

	return &QRadarConnector{
		name:   name,
		config: config,
		client: client,
		logger: logger,
		health: integrations.HealthStatus{
			Healthy:   false,
			LastCheck: time.Now(),
		},
	}, nil
}

// parseQRadarConfig parses QRadar configuration from settings
func parseQRadarConfig(settings map[string]interface{}) (QRadarConfig, error) {
	var config QRadarConfig

	// Required fields
	url, ok := settings["url"].(string)
	if !ok || url == "" {
		return config, fmt.Errorf("url is required")
	}
	config.URL = strings.TrimSuffix(url, "/")

	apiToken, ok := settings["api_token"].(string)
	if !ok || apiToken == "" {
		return config, fmt.Errorf("api_token is required")
	}
	config.APIToken = apiToken

	// Optional fields with defaults
	if eventSource, ok := settings["event_source"].(string); ok && eventSource != "" {
		config.EventSource = eventSource
	} else {
		config.EventSource = "TypoSentinel"
	}

	if logSource, ok := settings["log_source"].(string); ok && logSource != "" {
		config.LogSource = logSource
	} else {
		config.LogSource = "TypoSentinel Security Scanner"
	}

	if timeout, ok := settings["timeout"].(float64); ok && timeout > 0 {
		config.Timeout = int(timeout)
	}

	if verifySSL, ok := settings["verify_ssl"].(bool); ok {
		config.VerifySSL = verifySSL
	} else {
		config.VerifySSL = true // Default to true for security
	}

	return config, nil
}

// Connect establishes connection to QRadar
func (q *QRadarConnector) Connect(ctx context.Context) error {
	// Test connection by checking system information
	systemURL := fmt.Sprintf("%s/api/system/information", q.config.URL)
	req, err := http.NewRequestWithContext(ctx, "GET", systemURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create system info request: %w", err)
	}

	req.Header.Set("SEC", q.config.APIToken)
	req.Header.Set("Version", "12.0")
	req.Header.Set("Accept", "application/json")

	resp, err := q.client.Do(req)
	if err != nil {
		return fmt.Errorf("system info check failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("QRadar system info check returned status %d", resp.StatusCode)
	}

	q.updateHealth(true, nil, 0)
	q.logger.Info("QRadar connector connected successfully", map[string]interface{}{
		"connector": q.name,
		"url":       q.config.URL,
	})

	return nil
}

// Send sends a security event to QRadar
func (q *QRadarConnector) Send(ctx context.Context, event *events.SecurityEvent) error {
	start := time.Now()

	qradarEvent := q.transformEvent(event)

	if err := q.sendToQRadar(ctx, qradarEvent); err != nil {
		q.updateHealth(false, err, time.Since(start))
		return err
	}

	q.updateHealth(true, nil, time.Since(start))
	q.logger.Debug("Event sent to QRadar", map[string]interface{}{
		"event_id":   event.ID,
		"latency_ms": time.Since(start).Milliseconds(),
	})

	return nil
}

// sendToQRadar sends an event to QRadar using the SIEM API
func (q *QRadarConnector) sendToQRadar(ctx context.Context, event *QRadarEvent) error {
	payload, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %w", err)
	}

	// Use the SIEM events API endpoint
	eventsURL := fmt.Sprintf("%s/api/siem/events", q.config.URL)
	req, err := http.NewRequestWithContext(ctx, "POST", eventsURL, bytes.NewBuffer(payload))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("SEC", q.config.APIToken)
	req.Header.Set("Version", "12.0")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := q.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send to QRadar: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("QRadar returned status %d", resp.StatusCode)
	}

	return nil
}

// transformEvent converts a SecurityEvent to a QRadarEvent
func (q *QRadarConnector) transformEvent(event *events.SecurityEvent) *QRadarEvent {
	// Map severity to QRadar severity levels (1-10)
	severity := q.mapSeverity(string(event.Severity))

	// Create detailed message
	message := fmt.Sprintf("TypoSentinel detected %s threat in package %s@%s: %s",
		event.Threat.Type, event.Package.Name, event.Package.Version, event.Threat.Description)

	// Convert context from map[string]string to map[string]interface{}
	properties := make(map[string]interface{})
	for k, v := range event.Context {
		properties[k] = v
	}

	// Add additional properties
	properties["package_name"] = event.Package.Name
	properties["package_version"] = event.Package.Version
	properties["package_registry"] = event.Package.Registry
	properties["package_hash"] = event.Package.Hash
	properties["package_path"] = event.Package.Path
	properties["threat_type"] = event.Threat.Type
	properties["threat_confidence"] = event.Threat.Confidence
	properties["risk_score"] = event.Threat.RiskScore
	properties["detection_method"] = event.Metadata.DetectionMethod
	properties["correlation_id"] = event.Metadata.CorrelationID
	properties["tags"] = strings.Join(event.Metadata.Tags, ",")

	// Add evidence if available
	if len(event.Threat.Evidence) > 0 {
		evidenceList := make([]string, 0, len(event.Threat.Evidence))
		for key, value := range event.Threat.Evidence {
			evidenceList = append(evidenceList, fmt.Sprintf("%s: %s", key, value))
		}
		properties["evidence"] = strings.Join(evidenceList, "; ")
	}

	// Add mitigations if available
	if len(event.Threat.Mitigations) > 0 {
		properties["mitigations"] = strings.Join(event.Threat.Mitigations, "; ")
	}

	return &QRadarEvent{
		EventTime:  event.Timestamp.Unix() * 1000, // QRadar expects milliseconds
		EventType:  string(event.Type),
		Severity:   severity,
		Message:    message,
		EventID:    event.ID,
		Category:   "Security",
		Properties: properties,
		LogSource:  q.config.LogSource,
	}
}

// mapSeverity maps TypoSentinel severity to QRadar severity (1-10)
func (q *QRadarConnector) mapSeverity(severity string) int {
	switch strings.ToLower(severity) {
	case "critical":
		return 10
	case "high":
		return 8
	case "medium":
		return 5
	case "low":
		return 3
	case "info":
		return 1
	default:
		return 5 // Default to medium
	}
}

// updateHealth updates the connector's health status
func (q *QRadarConnector) updateHealth(healthy bool, err error, latency time.Duration) {
	q.health.Healthy = healthy
	q.health.LastCheck = time.Now()
	q.health.Latency = latency

	if healthy {
		q.health.EventsSent++
		q.health.LastError = ""
	} else {
		q.health.ErrorCount++
		if err != nil {
			q.health.LastError = err.Error()
		}
	}
}

// Health returns the current health status
func (q *QRadarConnector) Health() integrations.HealthStatus {
	return q.health
}

// Close closes the connector
func (q *QRadarConnector) Close() error {
	q.logger.Info("QRadar connector closed", map[string]interface{}{
		"connector": q.name,
	})
	return nil
}

// GetName returns the connector's name
func (q *QRadarConnector) GetName() string {
	return q.name
}

// GetType returns the connector's type
func (q *QRadarConnector) GetType() string {
	return "qradar"
}
