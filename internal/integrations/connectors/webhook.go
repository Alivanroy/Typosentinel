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

// WebhookConnector sends events to generic HTTP endpoints
type WebhookConnector struct {
	name   string
	config WebhookConfig
	client *http.Client
	logger logger.Logger
	health integrations.HealthStatus
}

// WebhookConfig holds webhook-specific configuration
type WebhookConfig struct {
	URL         string            `json:"url"`
	Method      string            `json:"method"`
	Headers     map[string]string `json:"headers"`
	AuthHeader  string            `json:"auth_header"`
	AuthToken   string            `json:"auth_token"`
	Timeout     int               `json:"timeout"`
	RetryCount  int               `json:"retry_count"`
	ContentType string            `json:"content_type"`
}

// WebhookPayload represents the payload sent to webhook endpoints
type WebhookPayload struct {
	Source    string                 `json:"source"`
	Timestamp string                 `json:"timestamp"`
	Event     *events.SecurityEvent  `json:"event"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// NewWebhookConnector creates a new webhook connector
func NewWebhookConnector(name string, settings map[string]interface{}, logger logger.Logger) (*WebhookConnector, error) {
	config, err := parseWebhookConfig(settings)
	if err != nil {
		return nil, fmt.Errorf("invalid webhook configuration: %w", err)
	}

	timeout := 30 * time.Second
	if config.Timeout > 0 {
		timeout = time.Duration(config.Timeout) * time.Second
	}

	client := &http.Client{
		Timeout: timeout,
	}

	return &WebhookConnector{
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

// parseWebhookConfig parses and validates webhook configuration
func parseWebhookConfig(settings map[string]interface{}) (WebhookConfig, error) {
	config := WebhookConfig{
		Method:      "POST",
		Headers:     make(map[string]string),
		Timeout:     30,
		RetryCount:  3,
		ContentType: "application/json",
	}

	// Required fields
	url, ok := settings["url"].(string)
	if !ok || url == "" {
		return config, integrations.ValidationError{
			Field:   "url",
			Message: "url is required and must be a non-empty string",
		}
	}
	config.URL = url

	// Optional fields
	if method, ok := settings["method"].(string); ok && method != "" {
		config.Method = method
	}

	if headers, ok := settings["headers"].(map[string]interface{}); ok {
		for key, value := range headers {
			if strValue, ok := value.(string); ok {
				config.Headers[key] = strValue
			}
		}
	}

	if authHeader, ok := settings["auth_header"].(string); ok && authHeader != "" {
		config.AuthHeader = authHeader
	}

	if authToken, ok := settings["auth_token"].(string); ok && authToken != "" {
		config.AuthToken = authToken
	}

	if timeout, ok := settings["timeout"].(float64); ok && timeout > 0 {
		config.Timeout = int(timeout)
	}

	if retryCount, ok := settings["retry_count"].(float64); ok && retryCount >= 0 {
		config.RetryCount = int(retryCount)
	}

	if contentType, ok := settings["content_type"].(string); ok && contentType != "" {
		config.ContentType = contentType
	}

	return config, nil
}

// Connect establishes connection to the webhook endpoint
func (w *WebhookConnector) Connect(ctx context.Context) error {
	// Test connection by sending a test payload
	testPayload := &WebhookPayload{
		Source:    "typosentinel",
		Timestamp: time.Now().Format(time.RFC3339),
		Event: &events.SecurityEvent{
			ID:        "test-connection",
			Timestamp: time.Now(),
			Type:      events.EventTypeSystemAlert,
			Severity:  events.SeverityInfo,
			Source:    "typosentinel",
			Package: events.PackageInfo{
				Name:     "test-package",
				Version:  "1.0.0",
				Registry: "test",
			},
			Threat: events.ThreatInfo{
				Type:        "connection_test",
				Description: "TypoSentinel webhook connector test",
			},
		},
		Metadata: map[string]interface{}{
			"test": true,
		},
	}

	if err := w.sendWebhook(ctx, testPayload); err != nil {
		return fmt.Errorf("connection test failed: %w", err)
	}

	w.updateHealth(true, nil, 0)
	w.logger.Info("Webhook connector connected successfully", map[string]interface{}{
		"connector": w.name,
		"url":       w.config.URL,
		"method":    w.config.Method,
	})

	return nil
}

// Send sends a security event to the webhook endpoint
func (w *WebhookConnector) Send(ctx context.Context, event *events.SecurityEvent) error {
	start := time.Now()

	payload := &WebhookPayload{
		Source:    "typosentinel",
		Timestamp: event.Timestamp.Format(time.RFC3339),
		Event:     event,
		Metadata: map[string]interface{}{
			"connector_name": w.name,
			"sent_at":        time.Now().Format(time.RFC3339),
		},
	}

	var lastErr error
	for attempt := 0; attempt <= w.config.RetryCount; attempt++ {
		if attempt > 0 {
			// Exponential backoff
			backoff := time.Duration(attempt*attempt) * time.Second
			w.logger.Debug("Retrying webhook request", map[string]interface{}{
				"attempt": attempt,
				"backoff": backoff,
			})
			time.Sleep(backoff)
		}

		if err := w.sendWebhook(ctx, payload); err != nil {
			lastErr = err
			continue
		}

		// Success
		w.updateHealth(true, nil, time.Since(start))
		w.logger.Debug("Event sent to webhook", map[string]interface{}{
			"event_id":   event.ID,
			"attempt":    attempt + 1,
			"latency_ms": time.Since(start).Milliseconds(),
		})
		return nil
	}

	// All attempts failed
	w.updateHealth(false, lastErr, time.Since(start))
	return fmt.Errorf("webhook failed after %d attempts: %w", w.config.RetryCount+1, lastErr)
}

// sendWebhook sends a payload to the webhook endpoint
func (w *WebhookConnector) sendWebhook(ctx context.Context, payload *WebhookPayload) error {
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, w.config.Method, w.config.URL, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set content type
	req.Header.Set("Content-Type", w.config.ContentType)

	// Set custom headers
	for key, value := range w.config.Headers {
		req.Header.Set(key, value)
	}

	// Set authentication header if configured
	if w.config.AuthHeader != "" && w.config.AuthToken != "" {
		req.Header.Set(w.config.AuthHeader, w.config.AuthToken)
	}

	// Set user agent
	req.Header.Set("User-Agent", "TypoSentinel-Webhook/1.0")

	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}

	return nil
}

// updateHealth updates the connector's health status
func (w *WebhookConnector) updateHealth(healthy bool, err error, latency time.Duration) {
	w.health.Healthy = healthy
	w.health.LastCheck = time.Now()
	w.health.Latency = latency

	if healthy {
		w.health.EventsSent++
		w.health.LastError = ""
	} else {
		w.health.ErrorCount++
		if err != nil {
			w.health.LastError = err.Error()
		}
	}
}

// Health returns the current health status
func (w *WebhookConnector) Health() integrations.HealthStatus {
	return w.health
}

// Close closes the connector
func (w *WebhookConnector) Close() error {
	w.logger.Info("Webhook connector closed", map[string]interface{}{
		"connector": w.name,
	})
	return nil
}

// GetName returns the connector's name
func (w *WebhookConnector) GetName() string {
	return w.name
}

// GetType returns the connector's type
func (w *WebhookConnector) GetType() string {
	return "webhook"
}
