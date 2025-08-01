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

// ElasticsearchConnector sends events to Elasticsearch
type ElasticsearchConnector struct {
	name     string
	config   ElasticsearchConfig
	client   *http.Client
	logger   logger.Logger
	health   integrations.HealthStatus
}

// ElasticsearchConfig defines Elasticsearch connection settings
type ElasticsearchConfig struct {
	URL      string `json:"url"`
	Username string `json:"username"`
	Password string `json:"password"`
	APIKey   string `json:"api_key"`
	Index    string `json:"index"`
	Timeout  int    `json:"timeout"`
	VerifySSL bool  `json:"verify_ssl"`
}

// ElasticsearchEvent represents an event to be sent to Elasticsearch
type ElasticsearchEvent struct {
	Timestamp   time.Time              `json:"@timestamp"`
	EventType   string                 `json:"event_type"`
	Severity    string                 `json:"severity"`
	Source      string                 `json:"source"`
	Package     map[string]interface{} `json:"package"`
	Threat      map[string]interface{} `json:"threat"`
	Metadata    map[string]interface{} `json:"metadata"`
	Context     map[string]interface{} `json:"context,omitempty"`
	EventID     string                 `json:"event_id"`
	RiskScore   float64                `json:"risk_score"`
	Description string                 `json:"description"`
}

// NewElasticsearchConnector creates a new Elasticsearch connector
func NewElasticsearchConnector(name string, settings map[string]interface{}, logger logger.Logger) (*ElasticsearchConnector, error) {
	config, err := parseElasticsearchConfig(settings)
	if err != nil {
		return nil, fmt.Errorf("invalid Elasticsearch configuration: %w", err)
	}

	timeout := 30 * time.Second
	if config.Timeout > 0 {
		timeout = time.Duration(config.Timeout) * time.Second
	}

	client := &http.Client{
		Timeout: timeout,
	}

	return &ElasticsearchConnector{
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

// parseElasticsearchConfig parses Elasticsearch configuration from settings
func parseElasticsearchConfig(settings map[string]interface{}) (ElasticsearchConfig, error) {
	var config ElasticsearchConfig

	// Required fields
	url, ok := settings["url"].(string)
	if !ok || url == "" {
		return config, fmt.Errorf("url is required")
	}
	config.URL = strings.TrimSuffix(url, "/")

	index, ok := settings["index"].(string)
	if !ok || index == "" {
		return config, fmt.Errorf("index is required")
	}
	config.Index = index

	// Authentication - either username/password or API key
	if apiKey, ok := settings["api_key"].(string); ok && apiKey != "" {
		config.APIKey = apiKey
	} else {
		username, hasUsername := settings["username"].(string)
		password, hasPassword := settings["password"].(string)
		if hasUsername && hasPassword {
			config.Username = username
			config.Password = password
		} else {
			return config, fmt.Errorf("either api_key or username/password is required")
		}
	}

	// Optional fields
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

// Connect establishes connection to Elasticsearch
func (e *ElasticsearchConnector) Connect(ctx context.Context) error {
	// Test connection by checking cluster health
	healthURL := fmt.Sprintf("%s/_cluster/health", e.config.URL)
	req, err := http.NewRequestWithContext(ctx, "GET", healthURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create health check request: %w", err)
	}

	e.setAuthHeaders(req)

	resp, err := e.client.Do(req)
	if err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("Elasticsearch health check returned status %d", resp.StatusCode)
	}

	e.updateHealth(true, nil, 0)
	e.logger.Info("Elasticsearch connector connected successfully", map[string]interface{}{
		"connector": e.name,
		"url":       e.config.URL,
		"index":     e.config.Index,
	})

	return nil
}

// Send sends a security event to Elasticsearch
func (e *ElasticsearchConnector) Send(ctx context.Context, event *events.SecurityEvent) error {
	start := time.Now()

	elasticEvent := e.transformEvent(event)

	if err := e.sendToElasticsearch(ctx, elasticEvent); err != nil {
		e.updateHealth(false, err, time.Since(start))
		return err
	}

	e.updateHealth(true, nil, time.Since(start))
	e.logger.Debug("Event sent to Elasticsearch", map[string]interface{}{
		"event_id":   event.ID,
		"latency_ms": time.Since(start).Milliseconds(),
	})

	return nil
}

// sendToElasticsearch sends an event to Elasticsearch
func (e *ElasticsearchConnector) sendToElasticsearch(ctx context.Context, event *ElasticsearchEvent) error {
	payload, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %w", err)
	}

	// Use index API with auto-generated ID
	indexURL := fmt.Sprintf("%s/%s/_doc", e.config.URL, e.config.Index)
	req, err := http.NewRequestWithContext(ctx, "POST", indexURL, bytes.NewBuffer(payload))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	e.setAuthHeaders(req)

	resp, err := e.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send to Elasticsearch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("Elasticsearch returned status %d", resp.StatusCode)
	}

	return nil
}

// setAuthHeaders sets authentication headers based on configuration
func (e *ElasticsearchConnector) setAuthHeaders(req *http.Request) {
	if e.config.APIKey != "" {
		req.Header.Set("Authorization", "ApiKey "+e.config.APIKey)
	} else if e.config.Username != "" && e.config.Password != "" {
		req.SetBasicAuth(e.config.Username, e.config.Password)
	}
}

// transformEvent converts a SecurityEvent to an ElasticsearchEvent
func (e *ElasticsearchConnector) transformEvent(event *events.SecurityEvent) *ElasticsearchEvent {
	// Convert context from map[string]string to map[string]interface{}
	context := make(map[string]interface{})
	for k, v := range event.Context {
		context[k] = v
	}

	return &ElasticsearchEvent{
		Timestamp: event.Timestamp,
		EventType: string(event.Type),
		Severity:  string(event.Severity),
		Source:    event.Source,
		EventID:   event.ID,
		RiskScore: event.Threat.RiskScore,
		Description: event.Threat.Description,
		Package: map[string]interface{}{
			"name":     event.Package.Name,
			"version":  event.Package.Version,
			"registry": event.Package.Registry,
			"hash":     event.Package.Hash,
			"path":     event.Package.Path,
		},
		Threat: map[string]interface{}{
			"type":         event.Threat.Type,
			"confidence":   event.Threat.Confidence,
			"risk_score":   event.Threat.RiskScore,
			"description":  event.Threat.Description,
			"evidence":     event.Threat.Evidence,
			"mitigations": event.Threat.Mitigations,
		},
		Metadata: map[string]interface{}{
			"detection_method": event.Metadata.DetectionMethod,
			"tags":            event.Metadata.Tags,
			"custom_fields":   event.Metadata.CustomFields,
			"correlation_id":  event.Metadata.CorrelationID,
		},
		Context: context,
	}
}

// updateHealth updates the connector's health status
func (e *ElasticsearchConnector) updateHealth(healthy bool, err error, latency time.Duration) {
	e.health.Healthy = healthy
	e.health.LastCheck = time.Now()
	e.health.Latency = latency

	if healthy {
		e.health.EventsSent++
		e.health.LastError = ""
	} else {
		e.health.ErrorCount++
		if err != nil {
			e.health.LastError = err.Error()
		}
	}
}

// Health returns the current health status
func (e *ElasticsearchConnector) Health() integrations.HealthStatus {
	return e.health
}

// Close closes the connector
func (e *ElasticsearchConnector) Close() error {
	e.logger.Info("Elasticsearch connector closed", map[string]interface{}{
		"connector": e.name,
	})
	return nil
}

// GetName returns the connector's name
func (e *ElasticsearchConnector) GetName() string {
	return e.name
}

// GetType returns the connector's type
func (e *ElasticsearchConnector) GetType() string {
	return "elasticsearch"
}