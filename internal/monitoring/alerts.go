package monitoring

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/smtp"
	"time"

	"github.com/Alivanroy/Typosentinel/pkg/logger"
)

// NewAlertManager creates a new alert manager
func NewAlertManager(config *MonitoringConfig, logger logger.Logger) *AlertManager {
	return &AlertManager{
		config:       config,
		logger:       logger,
		activeAlerts: make(map[string]*Alert),
		notifiers:    []AlertNotifier{},
	}
}

// Start starts the alert manager
func (am *AlertManager) Start(ctx context.Context) {
	// Initialize notifiers based on configuration
	if am.config.SlackConfig != nil {
		am.notifiers = append(am.notifiers, NewSlackNotifier(am.config.SlackConfig))
	}

	if am.config.EmailConfig != nil {
		am.notifiers = append(am.notifiers, NewEmailNotifier(am.config.EmailConfig))
	}

	if am.config.WebhookURL != "" {
		am.notifiers = append(am.notifiers, NewWebhookNotifier(am.config.WebhookURL))
	}

	am.logger.Info("Alert manager started with notifiers", map[string]interface{}{"count": len(am.notifiers)})
}

// TriggerAlert triggers a new alert
func (am *AlertManager) TriggerAlert(alert *Alert) {
	am.mu.Lock()
	defer am.mu.Unlock()

	// Check if alert already exists
	if existingAlert, exists := am.activeAlerts[alert.ID]; exists {
		if !existingAlert.Resolved {
			// Alert already active, skip
			return
		}
	}

	// Store the alert
	am.activeAlerts[alert.ID] = alert

	// Send notifications
	for _, notifier := range am.notifiers {
		go func(n AlertNotifier) {
			if err := n.SendAlert(alert); err != nil {
				am.logger.Error("Failed to send alert notification", map[string]interface{}{"notifier": n.Name(), "error": err})
			}
		}(notifier)
	}

	am.logger.Warn("Alert triggered", map[string]interface{}{"id": alert.ID, "severity": alert.Severity, "message": alert.Message})
}

// ResolveAlert resolves an active alert
func (am *AlertManager) ResolveAlert(alertID string) {
	am.mu.Lock()
	defer am.mu.Unlock()

	if alert, exists := am.activeAlerts[alertID]; exists {
		now := time.Now()
		alert.Resolved = true
		alert.ResolvedAt = &now
		am.logger.Info("Alert resolved", map[string]interface{}{"id": alertID})
	}
}

// GetActiveAlerts returns all active alerts
func (am *AlertManager) GetActiveAlerts() []*Alert {
	am.mu.RLock()
	defer am.mu.RUnlock()

	var alerts []*Alert
	for _, alert := range am.activeAlerts {
		if !alert.Resolved {
			alerts = append(alerts, alert)
		}
	}

	return alerts
}

// SlackNotifier sends alerts to Slack
type SlackNotifier struct {
	config *SlackConfig
}

// NewSlackNotifier creates a new Slack notifier
func NewSlackNotifier(config *SlackConfig) *SlackNotifier {
	return &SlackNotifier{config: config}
}

func (sn *SlackNotifier) Name() string {
	return "slack"
}

func (sn *SlackNotifier) SendAlert(alert *Alert) error {
	payload := map[string]interface{}{
		"channel":  sn.config.Channel,
		"username": sn.config.Username,
		"text":     fmt.Sprintf("🚨 *%s*\n%s", alert.Name, alert.Message),
		"attachments": []map[string]interface{}{
			{
				"color": sn.getSeverityColor(alert.Severity),
				"fields": []map[string]interface{}{
					{
						"title": "Severity",
						"value": string(alert.Severity),
						"short": true,
					},
					{
						"title": "Metric",
						"value": alert.Metric,
						"short": true,
					},
					{
						"title": "Value",
						"value": fmt.Sprintf("%.2f", alert.Value),
						"short": true,
					},
					{
						"title": "Threshold",
						"value": fmt.Sprintf("%.2f", alert.Threshold),
						"short": true,
					},
				},
				"ts": alert.Timestamp.Unix(),
			},
		},
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal Slack payload: %w", err)
	}

	resp, err := http.Post(sn.config.WebhookURL, "application/json", bytes.NewBuffer(jsonPayload))
	if err != nil {
		return fmt.Errorf("failed to send Slack notification: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Slack API returned status %d", resp.StatusCode)
	}

	return nil
}

func (sn *SlackNotifier) getSeverityColor(severity AlertSeverity) string {
	switch severity {
	case AlertSeverityCritical:
		return "danger"
	case AlertSeverityError:
		return "warning"
	case AlertSeverityWarning:
		return "#ffcc00"
	default:
		return "good"
	}
}

// EmailNotifier sends alerts via email
type EmailNotifier struct {
	config *EmailConfig
}

// NewEmailNotifier creates a new email notifier
func NewEmailNotifier(config *EmailConfig) *EmailNotifier {
	return &EmailNotifier{config: config}
}

func (en *EmailNotifier) Name() string {
	return "email"
}

func (en *EmailNotifier) SendAlert(alert *Alert) error {
	subject := fmt.Sprintf("[%s] %s", alert.Severity, alert.Name)
	body := fmt.Sprintf(`
Alert Details:

Name: %s
Severity: %s
Message: %s
Metric: %s
Value: %.2f
Threshold: %.2f
Timestamp: %s

Alert ID: %s
`,
		alert.Name,
		alert.Severity,
		alert.Message,
		alert.Metric,
		alert.Value,
		alert.Threshold,
		alert.Timestamp.Format(time.RFC3339),
		alert.ID,
	)

	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s",
		en.config.FromAddress,
		en.config.ToAddresses[0], // Send to first recipient for simplicity
		subject,
		body,
	)

	auth := smtp.PlainAuth("", en.config.Username, en.config.Password, en.config.SMTPHost)
	addr := fmt.Sprintf("%s:%d", en.config.SMTPHost, en.config.SMTPPort)

	err := smtp.SendMail(addr, auth, en.config.FromAddress, en.config.ToAddresses, []byte(msg))
	if err != nil {
		return fmt.Errorf("failed to send email notification: %w", err)
	}

	return nil
}

// WebhookNotifier sends alerts to a webhook URL
type WebhookNotifier struct {
	webhookURL string
}

// NewWebhookNotifier creates a new webhook notifier
func NewWebhookNotifier(webhookURL string) *WebhookNotifier {
	return &WebhookNotifier{webhookURL: webhookURL}
}

func (wn *WebhookNotifier) Name() string {
	return "webhook"
}

func (wn *WebhookNotifier) SendAlert(alert *Alert) error {
	jsonPayload, err := json.Marshal(alert)
	if err != nil {
		return fmt.Errorf("failed to marshal alert payload: %w", err)
	}

	resp, err := http.Post(wn.webhookURL, "application/json", bytes.NewBuffer(jsonPayload))
	if err != nil {
		return fmt.Errorf("failed to send webhook notification: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}

	return nil
}
