package connectors

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/Alivanroy/Typosentinel/pkg/events"
	"github.com/Alivanroy/Typosentinel/pkg/integrations"
	"github.com/Alivanroy/Typosentinel/pkg/logger"
)

// SplunkConnector sends events to Splunk via HTTP Event Collector
type SplunkConnector struct {
	name   string
	config SplunkConfig
	client *http.Client
	logger logger.Logger
	health integrations.HealthStatus
}

// SplunkConfig holds Splunk-specific configuration
type SplunkConfig struct {
	HECURL     string `json:"hec_url"`
	Token      string `json:"token"`
	Index      string `json:"index"`
	Source     string `json:"source"`
	SourceType string `json:"sourcetype"`
	Host       string `json:"host"`
	Timeout    int    `json:"timeout"`
}

// SplunkEvent represents a Splunk HEC event
type SplunkEvent struct {
	Time       int64       `json:"time"`
	Host       string      `json:"host,omitempty"`
	Source     string      `json:"source,omitempty"`
	SourceType string      `json:"sourcetype,omitempty"`
	Index      string      `json:"index,omitempty"`
	Event      interface{} `json:"event"`
}

// NewSplunkConnector creates a new Splunk connector
func NewSplunkConnector(name string, settings map[string]interface{}, logger logger.Logger) (*SplunkConnector, error) {
	config, err := parseSplunkConfig(settings)
	if err != nil {
		return nil, fmt.Errorf("invalid Splunk configuration: %w", err)
	}

	timeout := 30 * time.Second
	if config.Timeout > 0 {
		timeout = time.Duration(config.Timeout) * time.Second
	}

	client := &http.Client{
		Timeout: timeout,
	}

	return &SplunkConnector{
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

// parseSplunkConfig parses and validates Splunk configuration
func parseSplunkConfig(settings map[string]interface{}) (SplunkConfig, error) {
	config := SplunkConfig{
		Source:     "typosentinel",
		SourceType: "json",
		Host:       "typosentinel",
		Timeout:    30,
	}

	// Required fields
	hecURL, ok := settings["hec_url"].(string)
	if !ok || hecURL == "" {
		return config, integrations.ValidationError{
			Field:   "hec_url",
			Message: "hec_url is required and must be a non-empty string",
		}
	}
	config.HECURL = hecURL

	token, ok := settings["token"].(string)
	if !ok || token == "" {
		return config, integrations.ValidationError{
			Field:   "token",
			Message: "token is required and must be a non-empty string",
		}
	}
	config.Token = token

	// Optional fields
	if index, ok := settings["index"].(string); ok && index != "" {
		config.Index = index
	}

	if source, ok := settings["source"].(string); ok && source != "" {
		config.Source = source
	}

	if sourcetype, ok := settings["sourcetype"].(string); ok && sourcetype != "" {
		config.SourceType = sourcetype
	}

	if host, ok := settings["host"].(string); ok && host != "" {
		config.Host = host
	}

	if timeout, ok := settings["timeout"].(float64); ok && timeout > 0 {
		config.Timeout = int(timeout)
	}

	return config, nil
}

// Connect establishes connection to Splunk HEC
func (s *SplunkConnector) Connect(ctx context.Context) error {
	// Test connection by sending a test event
	testEvent := &SplunkEvent{
		Time:       time.Now().Unix(),
		Host:       s.config.Host,
		Source:     s.config.Source,
		SourceType: s.config.SourceType,
		Index:      s.config.Index,
		Event: map[string]interface{}{
			"message":    "TypoSentinel Splunk connector test",
			"event_type": "connection_test",
			"timestamp":  time.Now().Format(time.RFC3339),
		},
	}

	if err := s.sendToSplunk(ctx, testEvent); err != nil {
		return fmt.Errorf("connection test failed: %w", err)
	}

	s.updateHealth(true, nil, 0)
	s.logger.Info("Splunk connector connected successfully", map[string]interface{}{
		"connector": s.name,
		"hec_url":   s.config.HECURL,
		"index":     s.config.Index,
	})

	return nil
}

// Send sends a security event to Splunk
func (s *SplunkConnector) Send(ctx context.Context, event *events.SecurityEvent) error {
	start := time.Now()

	splunkEvent := s.transformEvent(event)

	if err := s.sendToSplunk(ctx, splunkEvent); err != nil {
		s.updateHealth(false, err, time.Since(start))
		return err
	}

	s.updateHealth(true, nil, time.Since(start))
	s.logger.Debug("Event sent to Splunk", map[string]interface{}{
		"event_id":   event.ID,
		"latency_ms": time.Since(start).Milliseconds(),
	})

	return nil
}

// sendToSplunk sends an event to Splunk HEC
func (s *SplunkConnector) sendToSplunk(ctx context.Context, event *SplunkEvent) error {
	payload, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", s.config.HECURL, bytes.NewBuffer(payload))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Splunk "+s.config.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send to Splunk: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("Splunk returned status %d", resp.StatusCode)
	}

	return nil
}

// transformEvent converts a SecurityEvent to a SplunkEvent
func (s *SplunkConnector) transformEvent(event *events.SecurityEvent) *SplunkEvent {
	// Create enriched event data
	eventData := map[string]interface{}{
		"id":         event.ID,
		"timestamp":  event.Timestamp.Format(time.RFC3339),
		"event_type": string(event.Type),
		"severity":   string(event.Severity),
		"source":     event.Source,
		"package": map[string]interface{}{
			"name":     event.Package.Name,
			"version":  event.Package.Version,
			"registry": event.Package.Registry,
			"hash":     event.Package.Hash,
			"path":     event.Package.Path,
		},
		"threat": map[string]interface{}{
			"type":        event.Threat.Type,
			"confidence":  event.Threat.Confidence,
			"risk_score":  event.Threat.RiskScore,
			"description": event.Threat.Description,
			"evidence":    event.Threat.Evidence,
			"mitigations": event.Threat.Mitigations,
		},
		"metadata": map[string]interface{}{
			"detection_method": event.Metadata.DetectionMethod,
			"tags":             event.Metadata.Tags,
			"custom_fields":    event.Metadata.CustomFields,
			"correlation_id":   event.Metadata.CorrelationID,
		},
	}

	// Add context if present
	if len(event.Context) > 0 {
		eventData["context"] = event.Context
	}

	return &SplunkEvent{
		Time:       event.Timestamp.Unix(),
		Host:       s.config.Host,
		Source:     s.config.Source,
		SourceType: s.config.SourceType,
		Index:      s.config.Index,
		Event:      eventData,
	}
}

// updateHealth updates the connector's health status
func (s *SplunkConnector) updateHealth(healthy bool, err error, latency time.Duration) {
	s.health.Healthy = healthy
	s.health.LastCheck = time.Now()
	s.health.Latency = latency

	if healthy {
		s.health.EventsSent++
		s.health.LastError = ""
	} else {
		s.health.ErrorCount++
		if err != nil {
			s.health.LastError = err.Error()
		}
	}
}

// Health returns the current health status
func (s *SplunkConnector) Health() integrations.HealthStatus {
	return s.health
}

// Close closes the connector
func (s *SplunkConnector) Close() error {
	s.logger.Info("Splunk connector closed", map[string]interface{}{
		"connector": s.name,
	})
	return nil
}

// GetName returns the connector's name
func (s *SplunkConnector) GetName() string {
	return s.name
}

// GetType returns the connector's type
func (s *SplunkConnector) GetType() string {
	return "splunk"
}
