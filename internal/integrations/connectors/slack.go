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

// SlackConnector sends events to Slack via webhooks
type SlackConnector struct {
	name   string
	config SlackConfig
	client *http.Client
	logger logger.Logger
	health integrations.HealthStatus
}

// SlackConfig holds Slack-specific configuration
type SlackConfig struct {
	WebhookURL string `json:"webhook_url"`
	Channel    string `json:"channel"`
	Username   string `json:"username"`
	IconEmoji  string `json:"icon_emoji"`
	Timeout    int    `json:"timeout"`
}

// SlackMessage represents a Slack message
type SlackMessage struct {
	Channel     string            `json:"channel,omitempty"`
	Username    string            `json:"username,omitempty"`
	IconEmoji   string            `json:"icon_emoji,omitempty"`
	Text        string            `json:"text"`
	Attachments []SlackAttachment `json:"attachments,omitempty"`
}

// SlackAttachment represents a Slack message attachment
type SlackAttachment struct {
	Color     string       `json:"color,omitempty"`
	Title     string       `json:"title,omitempty"`
	Text      string       `json:"text,omitempty"`
	Fields    []SlackField `json:"fields,omitempty"`
	Timestamp int64        `json:"ts,omitempty"`
}

// SlackField represents a field in a Slack attachment
type SlackField struct {
	Title string `json:"title"`
	Value string `json:"value"`
	Short bool   `json:"short"`
}

// NewSlackConnector creates a new Slack connector
func NewSlackConnector(name string, settings map[string]interface{}, logger logger.Logger) (*SlackConnector, error) {
	config, err := parseSlackConfig(settings)
	if err != nil {
		return nil, fmt.Errorf("invalid Slack configuration: %w", err)
	}

	timeout := 30 * time.Second
	if config.Timeout > 0 {
		timeout = time.Duration(config.Timeout) * time.Second
	}

	client := &http.Client{
		Timeout: timeout,
	}

	return &SlackConnector{
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

// parseSlackConfig parses and validates Slack configuration
func parseSlackConfig(settings map[string]interface{}) (SlackConfig, error) {
	config := SlackConfig{
		Username:  "TypoSentinel",
		IconEmoji: ":shield:",
		Timeout:   30,
	}

	// Required fields
	webhookURL, ok := settings["webhook_url"].(string)
	if !ok || webhookURL == "" {
		return config, integrations.ValidationError{
			Field:   "webhook_url",
			Message: "webhook_url is required and must be a non-empty string",
		}
	}
	config.WebhookURL = webhookURL

	// Optional fields
	if channel, ok := settings["channel"].(string); ok && channel != "" {
		config.Channel = channel
	}

	if username, ok := settings["username"].(string); ok && username != "" {
		config.Username = username
	}

	if iconEmoji, ok := settings["icon_emoji"].(string); ok && iconEmoji != "" {
		config.IconEmoji = iconEmoji
	}

	if timeout, ok := settings["timeout"].(float64); ok && timeout > 0 {
		config.Timeout = int(timeout)
	}

	return config, nil
}

// Connect establishes connection to Slack
func (s *SlackConnector) Connect(ctx context.Context) error {
	// Test connection by sending a test message
	testMessage := &SlackMessage{
		Channel:   s.config.Channel,
		Username:  s.config.Username,
		IconEmoji: s.config.IconEmoji,
		Text:      "🔗 TypoSentinel connected successfully",
	}

	if err := s.sendMessage(ctx, testMessage); err != nil {
		return fmt.Errorf("connection test failed: %w", err)
	}

	s.updateHealth(true, nil, 0)
	s.logger.Info("Slack connector connected successfully", map[string]interface{}{
		"connector": s.name,
		"channel":   s.config.Channel,
	})

	return nil
}

// Send sends a security event to Slack
func (s *SlackConnector) Send(ctx context.Context, event *events.SecurityEvent) error {
	start := time.Now()

	message := s.transformEvent(event)

	if err := s.sendMessage(ctx, message); err != nil {
		s.updateHealth(false, err, time.Since(start))
		return err
	}

	s.updateHealth(true, nil, time.Since(start))
	s.logger.Debug("Event sent to Slack", map[string]interface{}{
		"event_id":   event.ID,
		"latency_ms": time.Since(start).Milliseconds(),
	})

	return nil
}

// sendMessage sends a message to Slack
func (s *SlackConnector) sendMessage(ctx context.Context, message *SlackMessage) error {
	payload, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", s.config.WebhookURL, bytes.NewBuffer(payload))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send to Slack: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("Slack returned status %d", resp.StatusCode)
	}

	return nil
}

// transformEvent converts a SecurityEvent to a SlackMessage
func (s *SlackConnector) transformEvent(event *events.SecurityEvent) *SlackMessage {
	color := s.getSeverityColor(event.Severity)
	emoji := s.getSeverityEmoji(event.Severity)

	title := fmt.Sprintf("%s Security Alert: %s", emoji, event.Threat.Type)
	text := fmt.Sprintf("Package threat detected in %s", event.Package.Name)

	attachment := SlackAttachment{
		Color:     color,
		Title:     title,
		Text:      event.Threat.Description,
		Timestamp: event.Timestamp.Unix(),
		Fields: []SlackField{
			{Title: "Package", Value: fmt.Sprintf("%s@%s", event.Package.Name, event.Package.Version), Short: true},
			{Title: "Registry", Value: event.Package.Registry, Short: true},
			{Title: "Threat Type", Value: event.Threat.Type, Short: true},
			{Title: "Risk Score", Value: fmt.Sprintf("%.2f", event.Threat.RiskScore), Short: true},
			{Title: "Confidence", Value: fmt.Sprintf("%.1f%%", event.Threat.Confidence*100), Short: true},
			{Title: "Severity", Value: string(event.Severity), Short: true},
		},
	}

	// Add detection method if available
	if event.Metadata.DetectionMethod != "" {
		attachment.Fields = append(attachment.Fields, SlackField{
			Title: "Detection Method",
			Value: event.Metadata.DetectionMethod,
			Short: true,
		})
	}

	// Add evidence if available
	if len(event.Threat.Evidence) > 0 {
		evidenceText := ""
		for key, value := range event.Threat.Evidence {
			evidenceText += fmt.Sprintf("• %s: %s\n", key, value)
		}
		attachment.Fields = append(attachment.Fields, SlackField{
			Title: "Evidence",
			Value: evidenceText,
			Short: false,
		})
	}

	// Add mitigations if available
	if len(event.Threat.Mitigations) > 0 {
		mitigationText := ""
		for _, mitigation := range event.Threat.Mitigations {
			mitigationText += fmt.Sprintf("• %s\n", mitigation)
		}
		attachment.Fields = append(attachment.Fields, SlackField{
			Title: "Recommended Actions",
			Value: mitigationText,
			Short: false,
		})
	}

	return &SlackMessage{
		Channel:     s.config.Channel,
		Username:    s.config.Username,
		IconEmoji:   s.config.IconEmoji,
		Text:        text,
		Attachments: []SlackAttachment{attachment},
	}
}

// getSeverityColor returns the appropriate color for a severity level
func (s *SlackConnector) getSeverityColor(severity events.Severity) string {
	switch severity {
	case events.SeverityCritical:
		return "danger"
	case events.SeverityHigh:
		return "warning"
	case events.SeverityMedium:
		return "#FFA500" // Orange
	case events.SeverityLow:
		return "good"
	default:
		return "#36a64f" // Green
	}
}

// getSeverityEmoji returns the appropriate emoji for a severity level
func (s *SlackConnector) getSeverityEmoji(severity events.Severity) string {
	switch severity {
	case events.SeverityCritical:
		return "🚨"
	case events.SeverityHigh:
		return "⚠️"
	case events.SeverityMedium:
		return "🟡"
	case events.SeverityLow:
		return "🔵"
	default:
		return "ℹ️"
	}
}

// updateHealth updates the connector's health status
func (s *SlackConnector) updateHealth(healthy bool, err error, latency time.Duration) {
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
func (s *SlackConnector) Health() integrations.HealthStatus {
	return s.health
}

// Close closes the connector
func (s *SlackConnector) Close() error {
	s.logger.Info("Slack connector closed", map[string]interface{}{
		"connector": s.name,
	})
	return nil
}

// GetName returns the connector's name
func (s *SlackConnector) GetName() string {
	return s.name
}

// GetType returns the connector's type
func (s *SlackConnector) GetType() string {
	return "slack"
}