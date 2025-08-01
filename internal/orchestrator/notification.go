package orchestrator

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/smtp"
	"strings"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/repository"
)

// DefaultNotificationManager implements the NotificationManager interface
type DefaultNotificationManager struct {
	config NotificationManagerConfig
	logger *log.Logger
}

// NotificationManagerConfig holds configuration for notifications
type NotificationManagerConfig struct {
	EmailConfig   EmailConfig   `json:"email_config"`
	SlackConfig   SlackConfig   `json:"slack_config"`
	WebhookConfig WebhookConfig `json:"webhook_config"`
	Enabled       bool          `json:"enabled"`
}

// EmailConfig holds email notification configuration
type EmailConfig struct {
	SMTPHost     string `json:"smtp_host"`
	SMTPPort     int    `json:"smtp_port"`
	Username     string `json:"username"`
	Password     string `json:"password"`
	FromAddress  string `json:"from_address"`
	Enabled      bool   `json:"enabled"`
}

// SlackConfig holds Slack notification configuration
type SlackConfig struct {
	WebhookURL string `json:"webhook_url"`
	Channel    string `json:"channel"`
	Username   string `json:"username"`
	Enabled    bool   `json:"enabled"`
}

// WebhookConfig holds webhook notification configuration
type WebhookConfig struct {
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Enabled bool              `json:"enabled"`
}

// NewDefaultNotificationManager creates a new notification manager
func NewDefaultNotificationManager(config NotificationManagerConfig, logger *log.Logger) *DefaultNotificationManager {
	if logger == nil {
		logger = log.New(log.Writer(), "[NotificationManager] ", log.LstdFlags)
	}
	return &DefaultNotificationManager{
		config: config,
		logger: logger,
	}
}

// SendScanStarted sends notification when a scan starts
func (nm *DefaultNotificationManager) SendScanStarted(scan *ScheduledScan) error {
	if !nm.config.Enabled {
		return nil
	}

	message := fmt.Sprintf("Scan started for schedule: %s\nScan ID: %s\nStarted at: %s",
		scan.Name, scan.ID, time.Now().Format(time.RFC3339))

	return nm.sendNotification("Scan Started", message, scan)
}

// SendScanCompleted sends notification when a scan completes
func (nm *DefaultNotificationManager) SendScanCompleted(scan *ScheduledScan, result *repository.ScanResult) error {
	if !nm.config.Enabled {
		return nil
	}

	message := fmt.Sprintf("Scan completed for schedule: %s\nScan ID: %s\nCompleted at: %s\nRepository: %s\nStatus: %s",
		scan.Name, scan.ID, time.Now().Format(time.RFC3339), result.Repository.FullName, result.Status)

	return nm.sendNotification("Scan Completed", message, scan)
}

// SendScanFailed sends notification when a scan fails
func (nm *DefaultNotificationManager) SendScanFailed(scan *ScheduledScan, err error) error {
	if !nm.config.Enabled {
		return nil
	}

	message := fmt.Sprintf("Scan failed for schedule: %s\nScan ID: %s\nError: %s\nFailed at: %s",
		scan.Name, scan.ID, err.Error(), time.Now().Format(time.RFC3339))

	return nm.sendNotification("Scan Failed", message, scan)
}

// SendDiscoveryCompleted sends notification when discovery completes
func (nm *DefaultNotificationManager) SendDiscoveryCompleted(results []repository.DiscoveryResult) error {
	if !nm.config.Enabled {
		return nil
	}

	totalRepos := 0
	for _, result := range results {
		totalRepos += len(result.Repositories)
	}

	message := fmt.Sprintf("Repository discovery completed\nTotal repositories discovered: %d\nPlatforms scanned: %d\nCompleted at: %s",
		totalRepos, len(results), time.Now().Format(time.RFC3339))

	return nm.sendNotification("Discovery Completed", message, nil)
}

// sendNotification sends notification through all configured channels
func (nm *DefaultNotificationManager) sendNotification(subject, message string, scan *ScheduledScan) error {
	var errors []string

	// Send email notification
	if nm.config.EmailConfig.Enabled {
		if err := nm.sendEmailNotification(subject, message); err != nil {
			errors = append(errors, fmt.Sprintf("email: %v", err))
		}
	}

	// Send Slack notification
	if nm.config.SlackConfig.Enabled {
		if err := nm.sendSlackNotification(subject, message); err != nil {
			errors = append(errors, fmt.Sprintf("slack: %v", err))
		}
	}

	// Send webhook notification
	if nm.config.WebhookConfig.Enabled {
		if err := nm.sendWebhookNotification(subject, message, scan); err != nil {
			errors = append(errors, fmt.Sprintf("webhook: %v", err))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("notification errors: %s", strings.Join(errors, ", "))
	}

	return nil
}

// sendEmailNotification sends email notification
func (nm *DefaultNotificationManager) sendEmailNotification(subject, message string) error {
	config := nm.config.EmailConfig
	auth := smtp.PlainAuth("", config.Username, config.Password, config.SMTPHost)

	body := fmt.Sprintf("Subject: %s\r\n\r\n%s", subject, message)
	addr := fmt.Sprintf("%s:%d", config.SMTPHost, config.SMTPPort)

	return smtp.SendMail(addr, auth, config.FromAddress, []string{config.FromAddress}, []byte(body))
}

// sendSlackNotification sends Slack notification
func (nm *DefaultNotificationManager) sendSlackNotification(subject, message string) error {
	payload := map[string]interface{}{
		"text":     fmt.Sprintf("*%s*\n%s", subject, message),
		"channel":  nm.config.SlackConfig.Channel,
		"username": nm.config.SlackConfig.Username,
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	resp, err := http.Post(nm.config.SlackConfig.WebhookURL, "application/json", bytes.NewBuffer(jsonPayload))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("slack webhook returned status %d", resp.StatusCode)
	}

	return nil
}

// sendWebhookNotification sends webhook notification
func (nm *DefaultNotificationManager) sendWebhookNotification(subject, message string, scan *ScheduledScan) error {
	payload := map[string]interface{}{
		"subject":   subject,
		"message":   message,
		"timestamp": time.Now().Unix(),
	}

	if scan != nil {
			payload["scan_id"] = scan.ID
			payload["scan_name"] = scan.Name
			payload["schedule"] = scan.Schedule
		}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", nm.config.WebhookConfig.URL, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	for key, value := range nm.config.WebhookConfig.Headers {
		req.Header.Set(key, value)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}

	return nil
}