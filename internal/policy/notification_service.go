package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/auth"
)

// DefaultNotificationService provides a default implementation of NotificationService
type DefaultNotificationService struct {
	config *NotificationConfig
	logger *log.Logger
}



// NotificationPayload represents the payload sent in notifications
type NotificationPayload struct {
	Type        string                 `json:"type"`
	Timestamp   time.Time              `json:"timestamp"`
	Severity    string                 `json:"severity"`
	Title       string                 `json:"title"`
	Message     string                 `json:"message"`
	Violation   *auth.PolicyViolation  `json:"violation,omitempty"`
	Remediation *auth.RemediationAction `json:"remediation,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}



// NewDefaultNotificationService creates a new default notification service
func NewDefaultNotificationService(config *NotificationConfig, logger *log.Logger) *DefaultNotificationService {
	if logger == nil {
		logger = log.Default()
	}
	
	return &DefaultNotificationService{
		config: config,
		logger: logger,
	}
}

// SendViolationAlert sends an alert for a policy violation
func (ns *DefaultNotificationService) SendViolationAlert(violation *auth.PolicyViolation) error {
	if !ns.config.Enabled {
		return nil
	}

	payload := &NotificationPayload{
		Type:      "violation_alert",
		Timestamp: time.Now(),
		Severity:  violation.Severity,
		Title:     fmt.Sprintf("Policy Violation Detected: %s", violation.PolicyName),
		Message:   fmt.Sprintf("Policy violation detected: %s", violation.Description),
		Violation: violation,
		Metadata: map[string]interface{}{
			"violation_id": violation.ID,
			"policy_id":    violation.PolicyID,
			"policy_name":  violation.PolicyName,
			"created_at":   violation.CreatedAt,
		},
	}

	return ns.sendNotification(payload)
}

// SendRemediationUpdate sends an update about a remediation action
func (ns *DefaultNotificationService) SendRemediationUpdate(violation *auth.PolicyViolation, action *auth.RemediationAction) error {
	if !ns.config.Enabled {
		return nil
	}

	payload := &NotificationPayload{
		Type:        "remediation_update",
		Timestamp:   time.Now(),
		Severity:    violation.Severity,
		Title:       fmt.Sprintf("Remediation Action Executed: %s", action.Type),
		Message:     fmt.Sprintf("Remediation action '%s' executed for violation %s", action.Type, violation.ID),
		Violation:   violation,
		Remediation: action,
		Metadata: map[string]interface{}{
			"violation_id":     violation.ID,
			"remediation_type": action.Type,
			"executed_at":      time.Now(),
		},
	}

	return ns.sendNotification(payload)
}

// sendNotification sends a notification through configured channels
func (ns *DefaultNotificationService) sendNotification(payload *NotificationPayload) error {
	var lastErr error

	for _, channel := range ns.config.Channels {
		var err error
		
		switch channel {
		case "console":
			err = ns.sendConsoleNotification(payload)
		case "slack":
			err = ns.sendSlackNotification(payload)
		case "email":
			err = ns.sendEmailNotification(payload)
		case "webhook":
			err = ns.sendWebhookNotification(payload)
		default:
			ns.logger.Printf("Unknown notification channel: %s", channel)
			continue
		}

		if err != nil {
			ns.logger.Printf("Failed to send notification via %s: %v", channel, err)
			lastErr = err
		} else {
			ns.logger.Printf("Successfully sent notification via %s", channel)
		}
	}

	return lastErr
}

// sendConsoleNotification sends a notification to the console
func (ns *DefaultNotificationService) sendConsoleNotification(payload *NotificationPayload) error {
	jsonData, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal notification payload: %w", err)
	}

	ns.logger.Printf("NOTIFICATION [%s]: %s", payload.Type, string(jsonData))
	return nil
}

// sendSlackNotification sends a notification to Slack
func (ns *DefaultNotificationService) sendSlackNotification(payload *NotificationPayload) error {
	if ns.config.SlackURL == "" {
		return fmt.Errorf("slack webhook URL not configured")
	}

	// Create Slack message payload
	slackPayload := map[string]interface{}{
		"text": payload.Title,
		"attachments": []map[string]interface{}{
			{
				"color": getSeverityColor(payload.Severity),
				"fields": []map[string]interface{}{
					{
						"title": "Message",
						"value": payload.Message,
						"short": false,
					},
					{
						"title": "Severity",
						"value": payload.Severity,
						"short": true,
					},
					{
						"title": "Timestamp",
						"value": payload.Timestamp.Format(time.RFC3339),
						"short": true,
					},
				},
			},
		},
	}

	jsonData, err := json.Marshal(slackPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal Slack payload: %w", err)
	}

	resp, err := http.Post(ns.config.SlackURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to send Slack notification: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Slack webhook returned status %d", resp.StatusCode)
	}

	return nil
}

// getSeverityColor returns a color for Slack attachments based on severity
func getSeverityColor(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "danger"
	case "high":
		return "warning"
	case "medium":
		return "#ffcc00"
	case "low":
		return "good"
	default:
		return "#808080"
	}
}

// sendEmailNotification sends a notification via email
func (ns *DefaultNotificationService) sendEmailNotification(payload *NotificationPayload) error {
	if len(ns.config.EmailTo) == 0 {
		return fmt.Errorf("email recipients not configured")
	}

	// For now, log the email since we don't have SMTP configuration in NotificationConfig
	// In a real implementation, you would add SMTP settings to NotificationConfig
	subject := fmt.Sprintf("Security Alert: %s", payload.Title)
	body := fmt.Sprintf(`Security Alert Notification

Title: %s
Message: %s
Severity: %s
Timestamp: %s

%s

This is an automated notification from Typosentinel.
`, payload.Title, payload.Message, payload.Severity, 
		payload.Timestamp.Format(time.RFC3339),
		formatPayloadDetails(payload))

	// Log the email content (in production, you'd send via SMTP)
	ns.logger.Printf("EMAIL NOTIFICATION to %v:\nSubject: %s\nBody:\n%s", 
		ns.config.EmailTo, subject, body)

	// Example of how real SMTP sending would work (commented out since we don't have SMTP config):
	/*
	smtpHost := "smtp.gmail.com"
	smtpPort := "587"
	from := "alerts@typosentinel.com"
	password := "your-app-password"

	auth := smtp.PlainAuth("", from, password, smtpHost)
	
	for _, to := range ns.config.EmailTo {
		msg := []byte(fmt.Sprintf("To: %s\r\nSubject: %s\r\n\r\n%s", to, subject, body))
		err := smtp.SendMail(smtpHost+":"+smtpPort, auth, from, []string{to}, msg)
		if err != nil {
			return fmt.Errorf("failed to send email to %s: %w", to, err)
		}
	}
	*/

	return nil
}

// formatPayloadDetails formats additional payload details for email
func formatPayloadDetails(payload *NotificationPayload) string {
	var details strings.Builder
	
	if payload.Violation != nil {
		details.WriteString(fmt.Sprintf("Violation Details:\n"))
		details.WriteString(fmt.Sprintf("  ID: %s\n", payload.Violation.ID))
		details.WriteString(fmt.Sprintf("  Policy: %s\n", payload.Violation.PolicyName))
		details.WriteString(fmt.Sprintf("  Description: %s\n", payload.Violation.Description))
		details.WriteString(fmt.Sprintf("  Status: %s\n", payload.Violation.Status))
	}
	
	if payload.Remediation != nil {
		details.WriteString(fmt.Sprintf("\nRemediation Action:\n"))
		details.WriteString(fmt.Sprintf("  Type: %s\n", payload.Remediation.Type))
		details.WriteString(fmt.Sprintf("  Status: %s\n", payload.Remediation.Status))
	}
	
	return details.String()
}

// sendWebhookNotification sends a notification to webhooks
func (ns *DefaultNotificationService) sendWebhookNotification(payload *NotificationPayload) error {
	if len(ns.config.Webhooks) == 0 {
		return fmt.Errorf("webhook URLs not configured")
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal webhook payload: %w", err)
	}

	var lastErr error
	for _, webhookURL := range ns.config.Webhooks {
		req, err := http.NewRequest("POST", webhookURL, bytes.NewBuffer(jsonData))
		if err != nil {
			ns.logger.Printf("Failed to create webhook request for %s: %v", webhookURL, err)
			lastErr = err
			continue
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "Typosentinel-Webhook/1.0")

		client := &http.Client{
			Timeout: 30 * time.Second,
		}

		resp, err := client.Do(req)
		if err != nil {
			ns.logger.Printf("Failed to send webhook to %s: %v", webhookURL, err)
			lastErr = err
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			ns.logger.Printf("Webhook %s returned status %d", webhookURL, resp.StatusCode)
			lastErr = fmt.Errorf("webhook returned status %d", resp.StatusCode)
			continue
		}

		ns.logger.Printf("Successfully sent webhook notification to %s", webhookURL)
	}

	return lastErr
}