package connectors

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/smtp"
	"strings"
	"time"

	"github.com/Alivanroy/Typosentinel/pkg/events"
	"github.com/Alivanroy/Typosentinel/pkg/integrations"
	"github.com/Alivanroy/Typosentinel/pkg/logger"
)

// EmailConnector sends events via email
type EmailConnector struct {
	name   string
	config EmailConfig
	logger logger.Logger
	health integrations.HealthStatus
}

// EmailConfig holds email-specific configuration
type EmailConfig struct {
	SMTPHost      string   `json:"smtp_host"`
	SMTPPort      int      `json:"smtp_port"`
	Username      string   `json:"username"`
	Password      string   `json:"password"`
	FromEmail     string   `json:"from_email"`
	FromName      string   `json:"from_name"`
	ToEmails      []string `json:"to_emails"`
	CCEmails      []string `json:"cc_emails"`
	SubjectPrefix string   `json:"subject_prefix"`
	UseTLS        bool     `json:"use_tls"`
	Timeout       int      `json:"timeout"`
}

// EmailMessage represents an email message
type EmailMessage struct {
	To      []string
	CC      []string
	Subject string
	Body    string
	IsHTML  bool
}

// NewEmailConnector creates a new email connector
func NewEmailConnector(name string, settings map[string]interface{}, logger logger.Logger) (*EmailConnector, error) {
	config, err := parseEmailConfig(settings)
	if err != nil {
		return nil, fmt.Errorf("invalid email configuration: %w", err)
	}

	return &EmailConnector{
		name:   name,
		config: config,
		logger: logger,
		health: integrations.HealthStatus{
			Healthy:   false,
			LastCheck: time.Now(),
		},
	}, nil
}

// parseEmailConfig parses and validates email configuration
func parseEmailConfig(settings map[string]interface{}) (EmailConfig, error) {
	config := EmailConfig{
		SMTPPort:      587,
		FromName:      "TypoSentinel",
		SubjectPrefix: "[TypoSentinel]",
		UseTLS:        true,
		Timeout:       30,
	}

	// Required fields
	smtpHost, ok := settings["smtp_host"].(string)
	if !ok || smtpHost == "" {
		return config, integrations.ValidationError{
			Field:   "smtp_host",
			Message: "smtp_host is required and must be a non-empty string",
		}
	}
	config.SMTPHost = smtpHost

	username, ok := settings["username"].(string)
	if !ok || username == "" {
		return config, integrations.ValidationError{
			Field:   "username",
			Message: "username is required and must be a non-empty string",
		}
	}
	config.Username = username

	password, ok := settings["password"].(string)
	if !ok || password == "" {
		return config, integrations.ValidationError{
			Field:   "password",
			Message: "password is required and must be a non-empty string",
		}
	}
	config.Password = password

	fromEmail, ok := settings["from_email"].(string)
	if !ok || fromEmail == "" {
		return config, integrations.ValidationError{
			Field:   "from_email",
			Message: "from_email is required and must be a non-empty string",
		}
	}
	config.FromEmail = fromEmail

	toEmailsInterface, ok := settings["to_emails"].([]interface{})
	if !ok || len(toEmailsInterface) == 0 {
		return config, integrations.ValidationError{
			Field:   "to_emails",
			Message: "to_emails is required and must be a non-empty array",
		}
	}

	for _, email := range toEmailsInterface {
		if emailStr, ok := email.(string); ok && emailStr != "" {
			config.ToEmails = append(config.ToEmails, emailStr)
		}
	}

	if len(config.ToEmails) == 0 {
		return config, integrations.ValidationError{
			Field:   "to_emails",
			Message: "to_emails must contain at least one valid email address",
		}
	}

	// Optional fields
	if smtpPort, ok := settings["smtp_port"].(float64); ok && smtpPort > 0 {
		config.SMTPPort = int(smtpPort)
	}

	if fromName, ok := settings["from_name"].(string); ok && fromName != "" {
		config.FromName = fromName
	}

	if ccEmailsInterface, ok := settings["cc_emails"].([]interface{}); ok {
		for _, email := range ccEmailsInterface {
			if emailStr, ok := email.(string); ok && emailStr != "" {
				config.CCEmails = append(config.CCEmails, emailStr)
			}
		}
	}

	if subjectPrefix, ok := settings["subject_prefix"].(string); ok {
		config.SubjectPrefix = subjectPrefix
	}

	if useTLS, ok := settings["use_tls"].(bool); ok {
		config.UseTLS = useTLS
	}

	if timeout, ok := settings["timeout"].(float64); ok && timeout > 0 {
		config.Timeout = int(timeout)
	}

	return config, nil
}

// Connect establishes connection to the SMTP server
func (e *EmailConnector) Connect(ctx context.Context) error {
	// Test connection by attempting to connect to SMTP server
	addr := fmt.Sprintf("%s:%d", e.config.SMTPHost, e.config.SMTPPort)

	var auth smtp.Auth
	if e.config.Username != "" && e.config.Password != "" {
		auth = smtp.PlainAuth("", e.config.Username, e.config.Password, e.config.SMTPHost)
	}

	// Test connection
	if e.config.UseTLS {
		// For TLS connections, we need to use a different approach
		tlsConfig := &tls.Config{
			ServerName: e.config.SMTPHost,
		}

		conn, err := tls.Dial("tcp", addr, tlsConfig)
		if err != nil {
			return fmt.Errorf("failed to connect to SMTP server with TLS: %w", err)
		}
		defer conn.Close()

		client, err := smtp.NewClient(conn, e.config.SMTPHost)
		if err != nil {
			return fmt.Errorf("failed to create SMTP client: %w", err)
		}
		defer client.Quit()

		if auth != nil {
			if err := client.Auth(auth); err != nil {
				return fmt.Errorf("SMTP authentication failed: %w", err)
			}
		}
	} else {
		// For non-TLS connections
		client, err := smtp.Dial(addr)
		if err != nil {
			return fmt.Errorf("failed to connect to SMTP server: %w", err)
		}
		defer client.Quit()

		if auth != nil {
			if err := client.Auth(auth); err != nil {
				return fmt.Errorf("SMTP authentication failed: %w", err)
			}
		}
	}

	e.updateHealth(true, nil, 0)
	e.logger.Info("Email connector connected successfully", map[string]interface{}{
		"connector":  e.name,
		"smtp_host":  e.config.SMTPHost,
		"smtp_port":  e.config.SMTPPort,
		"from_email": e.config.FromEmail,
	})

	return nil
}

// Send sends a security event via email
func (e *EmailConnector) Send(ctx context.Context, event *events.SecurityEvent) error {
	start := time.Now()

	message := e.transformEvent(event)

	if err := e.sendEmail(message); err != nil {
		e.updateHealth(false, err, time.Since(start))
		return err
	}

	e.updateHealth(true, nil, time.Since(start))
	e.logger.Debug("Event sent via email", map[string]interface{}{
		"event_id":   event.ID,
		"recipients": len(message.To),
		"latency_ms": time.Since(start).Milliseconds(),
	})

	return nil
}

// sendEmail sends an email message
func (e *EmailConnector) sendEmail(message *EmailMessage) error {
	addr := fmt.Sprintf("%s:%d", e.config.SMTPHost, e.config.SMTPPort)

	var auth smtp.Auth
	if e.config.Username != "" && e.config.Password != "" {
		auth = smtp.PlainAuth("", e.config.Username, e.config.Password, e.config.SMTPHost)
	}

	// Build email content
	headers := make(map[string]string)
	headers["From"] = fmt.Sprintf("%s <%s>", e.config.FromName, e.config.FromEmail)
	headers["To"] = strings.Join(message.To, ", ")
	if len(message.CC) > 0 {
		headers["CC"] = strings.Join(message.CC, ", ")
	}
	headers["Subject"] = message.Subject
	headers["MIME-Version"] = "1.0"

	if message.IsHTML {
		headers["Content-Type"] = "text/html; charset=UTF-8"
	} else {
		headers["Content-Type"] = "text/plain; charset=UTF-8"
	}

	// Build message
	var emailContent strings.Builder
	for key, value := range headers {
		emailContent.WriteString(fmt.Sprintf("%s: %s\r\n", key, value))
	}
	emailContent.WriteString("\r\n")
	emailContent.WriteString(message.Body)

	// Combine To and CC for recipients
	recipients := append(message.To, message.CC...)

	// Send email
	if e.config.UseTLS {
		return e.sendEmailTLS(addr, auth, e.config.FromEmail, recipients, emailContent.String())
	}

	return smtp.SendMail(addr, auth, e.config.FromEmail, recipients, []byte(emailContent.String()))
}

// sendEmailTLS sends email using TLS
func (e *EmailConnector) sendEmailTLS(addr string, auth smtp.Auth, from string, to []string, msg string) error {
	tlsConfig := &tls.Config{
		ServerName: e.config.SMTPHost,
	}

	conn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to connect with TLS: %w", err)
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, e.config.SMTPHost)
	if err != nil {
		return fmt.Errorf("failed to create SMTP client: %w", err)
	}
	defer client.Quit()

	if auth != nil {
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("authentication failed: %w", err)
		}
	}

	if err := client.Mail(from); err != nil {
		return fmt.Errorf("failed to set sender: %w", err)
	}

	for _, recipient := range to {
		if err := client.Rcpt(recipient); err != nil {
			return fmt.Errorf("failed to set recipient %s: %w", recipient, err)
		}
	}

	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("failed to get data writer: %w", err)
	}
	defer w.Close()

	if _, err := w.Write([]byte(msg)); err != nil {
		return fmt.Errorf("failed to write message: %w", err)
	}

	return nil
}

// transformEvent converts a SecurityEvent to an EmailMessage
func (e *EmailConnector) transformEvent(event *events.SecurityEvent) *EmailMessage {
	subject := fmt.Sprintf("%s %s Alert: %s in %s",
		e.config.SubjectPrefix,
		strings.Title(string(event.Severity)),
		event.Threat.Type,
		event.Package.Name)

	body := e.buildEmailBody(event)

	return &EmailMessage{
		To:      e.config.ToEmails,
		CC:      e.config.CCEmails,
		Subject: subject,
		Body:    body,
		IsHTML:  true,
	}
}

// buildEmailBody builds the HTML email body
func (e *EmailConnector) buildEmailBody(event *events.SecurityEvent) string {
	var body strings.Builder

	body.WriteString(`<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>TypoSentinel Security Alert</title>
</head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
`)

	// Header
	body.WriteString(`<div style="background-color: #f8f9fa; padding: 20px; border-left: 5px solid `)
	switch event.Severity {
	case events.SeverityCritical:
		body.WriteString(`#dc3545`)
	case events.SeverityHigh:
		body.WriteString(`#fd7e14`)
	case events.SeverityMedium:
		body.WriteString(`#ffc107`)
	default:
		body.WriteString(`#28a745`)
	}
	body.WriteString(`;">
`)
	body.WriteString(fmt.Sprintf(`<h2 style="margin: 0; color: #495057;">🛡️ TypoSentinel Security Alert</h2>
`))
	body.WriteString(fmt.Sprintf(`<p style="margin: 5px 0 0 0; font-size: 14px; color: #6c757d;">%s</p>
`, event.Timestamp.Format("January 2, 2006 at 3:04 PM MST")))
	body.WriteString(`</div>
`)

	// Alert summary
	body.WriteString(`<div style="padding: 20px;">
`)
	body.WriteString(fmt.Sprintf(`<h3 style="color: #495057; margin-top: 0;">%s Threat Detected</h3>
`, strings.Title(string(event.Severity))))
	body.WriteString(fmt.Sprintf(`<p><strong>%s</strong></p>
`, event.Threat.Description))

	// Package details
	body.WriteString(`<h4 style="color: #495057; margin-bottom: 10px;">📦 Package Information</h4>
`)
	body.WriteString(`<table style="border-collapse: collapse; width: 100%; margin-bottom: 20px;">
`)
	body.WriteString(fmt.Sprintf(`<tr><td style="padding: 8px; border: 1px solid #dee2e6; background-color: #f8f9fa; font-weight: bold;">Name:</td><td style="padding: 8px; border: 1px solid #dee2e6;">%s</td></tr>
`, event.Package.Name))
	body.WriteString(fmt.Sprintf(`<tr><td style="padding: 8px; border: 1px solid #dee2e6; background-color: #f8f9fa; font-weight: bold;">Version:</td><td style="padding: 8px; border: 1px solid #dee2e6;">%s</td></tr>
`, event.Package.Version))
	body.WriteString(fmt.Sprintf(`<tr><td style="padding: 8px; border: 1px solid #dee2e6; background-color: #f8f9fa; font-weight: bold;">Registry:</td><td style="padding: 8px; border: 1px solid #dee2e6;">%s</td></tr>
`, event.Package.Registry))
	body.WriteString(`</table>
`)

	// Threat details
	body.WriteString(`<h4 style="color: #495057; margin-bottom: 10px;">⚠️ Threat Details</h4>
`)
	body.WriteString(`<table style="border-collapse: collapse; width: 100%; margin-bottom: 20px;">
`)
	body.WriteString(fmt.Sprintf(`<tr><td style="padding: 8px; border: 1px solid #dee2e6; background-color: #f8f9fa; font-weight: bold;">Type:</td><td style="padding: 8px; border: 1px solid #dee2e6;">%s</td></tr>
`, event.Threat.Type))
	body.WriteString(fmt.Sprintf(`<tr><td style="padding: 8px; border: 1px solid #dee2e6; background-color: #f8f9fa; font-weight: bold;">Risk Score:</td><td style="padding: 8px; border: 1px solid #dee2e6;">%.2f</td></tr>
`, event.Threat.RiskScore))
	body.WriteString(fmt.Sprintf(`<tr><td style="padding: 8px; border: 1px solid #dee2e6; background-color: #f8f9fa; font-weight: bold;">Confidence:</td><td style="padding: 8px; border: 1px solid #dee2e6;">%.1f%%</td></tr>
`, event.Threat.Confidence*100))
	body.WriteString(fmt.Sprintf(`<tr><td style="padding: 8px; border: 1px solid #dee2e6; background-color: #f8f9fa; font-weight: bold;">Detection Method:</td><td style="padding: 8px; border: 1px solid #dee2e6;">%s</td></tr>
`, event.Metadata.DetectionMethod))
	body.WriteString(`</table>
`)

	// Evidence
	if len(event.Threat.Evidence) > 0 {
		body.WriteString(`<h4 style="color: #495057; margin-bottom: 10px;">🔍 Evidence</h4>
`)
		body.WriteString(`<ul style="margin-bottom: 20px;">
`)
		for key, value := range event.Threat.Evidence {
			body.WriteString(fmt.Sprintf(`<li><strong>%s:</strong> %s</li>
`, key, value))
		}
		body.WriteString(`</ul>
`)
	}

	// Mitigations
	if len(event.Threat.Mitigations) > 0 {
		body.WriteString(`<h4 style="color: #495057; margin-bottom: 10px;">🛠️ Recommended Actions</h4>
`)
		body.WriteString(`<ul style="margin-bottom: 20px;">
`)
		for _, mitigation := range event.Threat.Mitigations {
			body.WriteString(fmt.Sprintf(`<li>%s</li>
`, mitigation))
		}
		body.WriteString(`</ul>
`)
	}

	body.WriteString(`</div>
`)

	// Footer
	body.WriteString(`<div style="background-color: #f8f9fa; padding: 15px; border-top: 1px solid #dee2e6; font-size: 12px; color: #6c757d;">
`)
	body.WriteString(`<p style="margin: 0;">This alert was generated by TypoSentinel. Event ID: ` + event.ID + `</p>
`)
	body.WriteString(`</div>
`)

	body.WriteString(`</body>
</html>`)

	return body.String()
}

// updateHealth updates the connector's health status
func (e *EmailConnector) updateHealth(healthy bool, err error, latency time.Duration) {
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
func (e *EmailConnector) Health() integrations.HealthStatus {
	return e.health
}

// Close closes the connector
func (e *EmailConnector) Close() error {
	e.logger.Info("Email connector closed", map[string]interface{}{
		"connector": e.name,
	})
	return nil
}

// GetName returns the connector's name
func (e *EmailConnector) GetName() string {
	return e.name
}

// GetType returns the connector's type
func (e *EmailConnector) GetType() string {
	return "email"
}
