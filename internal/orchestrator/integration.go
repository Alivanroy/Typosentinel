package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/repository"
)

// IntegrationManager handles external system integrations
type IntegrationManager struct {
	config  *IntegrationConfig
	clients map[string]IntegrationClient
}

// IntegrationConfig defines configuration for external integrations
type IntegrationConfig struct {
	SIEM      *SIEMConfig             `json:"siem,omitempty"`
	Ticketing *TicketingConfig        `json:"ticketing,omitempty"`
	CICD      *CICDConfig             `json:"cicd,omitempty"`
	Slack     *ExtendedSlackConfig    `json:"slack,omitempty"`
	Webhooks  []ExtendedWebhookConfig `json:"webhooks,omitempty"`
}

// SIEMConfig defines SIEM integration settings
type SIEMConfig struct {
	Enabled         bool                   `json:"enabled"`
	Type            string                 `json:"type"` // splunk, elastic, qradar
	Endpoint        string                 `json:"endpoint"`
	APIKey          string                 `json:"api_key"`
	Index           string                 `json:"index,omitempty"`
	BatchSize       int                    `json:"batch_size,omitempty"`
	StreamingMode   bool                   `json:"streaming_mode,omitempty"`
	CustomFormat    map[string]interface{} `json:"custom_format,omitempty"`
	RetryConfig     *SIEMRetryConfig       `json:"retry_config,omitempty"`
	Timeout         time.Duration          `json:"timeout,omitempty"`
	VerifySSL       bool                   `json:"verify_ssl,omitempty"`
	CompressionType string                 `json:"compression_type,omitempty"` // gzip, none
}

// SIEMRetryConfig defines retry behavior for SIEM operations
type SIEMRetryConfig struct {
	MaxRetries    int           `json:"max_retries"`
	InitialDelay  time.Duration `json:"initial_delay"`
	MaxDelay      time.Duration `json:"max_delay"`
	BackoffFactor float64       `json:"backoff_factor"`
	RetryOnStatus []int         `json:"retry_on_status,omitempty"`
}

// TicketingConfig defines ticketing system integration
type TicketingConfig struct {
	Enabled    bool   `json:"enabled"`
	Type       string `json:"type"` // jira, servicenow, github
	Endpoint   string `json:"endpoint"`
	Username   string `json:"username"`
	APIKey     string `json:"api_key"`
	Project    string `json:"project"`
	IssueType  string `json:"issue_type,omitempty"`
	Priority   string `json:"priority,omitempty"`
	AutoCreate bool   `json:"auto_create,omitempty"`
	Threshold  string `json:"threshold,omitempty"` // high, critical
}

// CICDConfig defines CI/CD integration settings
type CICDConfig struct {
	Enabled    bool   `json:"enabled"`
	Type       string `json:"type"` // jenkins, gitlab, github-actions
	Endpoint   string `json:"endpoint"`
	Token      string `json:"token"`
	Project    string `json:"project,omitempty"`
	Pipeline   string `json:"pipeline,omitempty"`
	FailOnHigh bool   `json:"fail_on_high,omitempty"`
}

// ExtendedSlackConfig extends SlackConfig with additional fields for integration
type ExtendedSlackConfig struct {
	SlackConfig
	IconEmoji string `json:"icon_emoji,omitempty"`
}

// ExtendedWebhookConfig extends WebhookConfig with additional fields for integration
type ExtendedWebhookConfig struct {
	WebhookConfig
	Name    string        `json:"name"`
	Method  string        `json:"method,omitempty"`
	Events  []string      `json:"events"`
	Retries int           `json:"retries,omitempty"`
	Timeout time.Duration `json:"timeout,omitempty"`
}

// IntegrationClient interface for external system clients
type IntegrationClient interface {
	SendEvent(ctx context.Context, event *IntegrationEvent) error
	HealthCheck(ctx context.Context) error
	GetName() string
}

// IntegrationEvent represents an event to send to external systems
type IntegrationEvent struct {
	Type        string                 `json:"type"`
	Timestamp   time.Time              `json:"timestamp"`
	Severity    string                 `json:"severity"`
	Source      string                 `json:"source"`
	Repository  string                 `json:"repository,omitempty"`
	ScanID      string                 `json:"scan_id,omitempty"`
	Message     string                 `json:"message"`
	Details     map[string]interface{} `json:"details,omitempty"`
	ThreatCount int                    `json:"threat_count,omitempty"`
	RiskScore   float64                `json:"risk_score,omitempty"`
}

// NewIntegrationManager creates a new integration manager
func NewIntegrationManager(config *IntegrationConfig) *IntegrationManager {
	im := &IntegrationManager{
		config:  config,
		clients: make(map[string]IntegrationClient),
	}

	// Initialize clients based on configuration
	if config.SIEM != nil && config.SIEM.Enabled {
		im.clients["siem"] = NewSIEMClient(config.SIEM)
	}

	if config.Ticketing != nil && config.Ticketing.Enabled {
		im.clients["ticketing"] = NewTicketingClient(config.Ticketing)
	}

	if config.CICD != nil && config.CICD.Enabled {
		im.clients["cicd"] = NewCICDClient(config.CICD)
	}

	if config.Slack != nil && config.Slack.Enabled {
		im.clients["slack"] = NewSlackClient(config.Slack)
	}

	for _, webhook := range config.Webhooks {
		if webhook.Enabled {
			im.clients["webhook_"+webhook.Name] = NewWebhookClient(&webhook)
		}
	}

	return im
}

// SendScanResult sends scan results to configured integrations
func (im *IntegrationManager) SendScanResult(ctx context.Context, result *repository.ScanResult) error {
	event := &IntegrationEvent{
		Type:       "scan_completed",
		Timestamp:  time.Now(),
		Severity:   im.determineSeverity(result),
		Source:     "typosentinel",
		Repository: result.Repository.FullName,
		ScanID:     result.ScanID,
		Message:    fmt.Sprintf("Scan completed for %s", result.Repository.FullName),
		Details: map[string]interface{}{
			"status":     result.Status,
			"duration":   result.Duration,
			"start_time": result.StartTime,
			"end_time":   result.EndTime,
		},
	}

	// Add threat information if available
	if result.AnalysisResult != nil {
		if analysisMap, ok := result.AnalysisResult.(map[string]interface{}); ok {
			if threats, ok := analysisMap["threats"]; ok {
				if threatList, ok := threats.([]interface{}); ok {
					event.ThreatCount = len(threatList)
				}
			}
			if riskScore, ok := analysisMap["risk_score"]; ok {
				if score, ok := riskScore.(float64); ok {
					event.RiskScore = score
				}
			}
		}
	}

	return im.sendToAllClients(ctx, event)
}

// SendThreatAlert sends threat alerts to configured integrations
func (im *IntegrationManager) SendThreatAlert(ctx context.Context, repository string, threats []interface{}) error {
	event := &IntegrationEvent{
		Type:        "threat_detected",
		Timestamp:   time.Now(),
		Severity:    "high",
		Source:      "typosentinel",
		Repository:  repository,
		Message:     fmt.Sprintf("Threats detected in %s", repository),
		ThreatCount: len(threats),
		Details: map[string]interface{}{
			"threats": threats,
		},
	}

	return im.sendToAllClients(ctx, event)
}

// SendPolicyViolation sends policy violation alerts
func (im *IntegrationManager) SendPolicyViolation(ctx context.Context, repository, policy, violation string) error {
	event := &IntegrationEvent{
		Type:       "policy_violation",
		Timestamp:  time.Now(),
		Severity:   "medium",
		Source:     "typosentinel",
		Repository: repository,
		Message:    fmt.Sprintf("Policy violation in %s: %s", repository, violation),
		Details: map[string]interface{}{
			"policy":    policy,
			"violation": violation,
		},
	}

	return im.sendToAllClients(ctx, event)
}

// sendToAllClients sends event to all configured clients
func (im *IntegrationManager) sendToAllClients(ctx context.Context, event *IntegrationEvent) error {
	var errors []string

	for name, client := range im.clients {
		if err := client.SendEvent(ctx, event); err != nil {
			errors = append(errors, fmt.Sprintf("%s: %v", name, err))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("integration errors: %s", strings.Join(errors, "; "))
	}

	return nil
}

// determineSeverity determines event severity based on scan result
func (im *IntegrationManager) determineSeverity(result *repository.ScanResult) string {
	if result.Status == "failed" {
		return "high"
	}

	if result.AnalysisResult != nil {
		if analysisMap, ok := result.AnalysisResult.(map[string]interface{}); ok {
			if threats, ok := analysisMap["threats"]; ok {
				if threatList, ok := threats.([]interface{}); ok {
					if len(threatList) > 10 {
						return "critical"
					} else if len(threatList) > 5 {
						return "high"
					} else if len(threatList) > 0 {
						return "medium"
					}
				}
			}
		}
	}

	return "low"
}

// HealthCheck checks the health of all integration clients
func (im *IntegrationManager) HealthCheck(ctx context.Context) map[string]error {
	results := make(map[string]error)

	for name, client := range im.clients {
		results[name] = client.HealthCheck(ctx)
	}

	return results
}

// GetActiveIntegrations returns list of active integration names
func (im *IntegrationManager) GetActiveIntegrations() []string {
	var active []string
	for name := range im.clients {
		active = append(active, name)
	}
	return active
}

// SIEM Client Implementation
type SIEMClient struct {
	config      *SIEMConfig
	client      *http.Client
	eventQueue  chan *IntegrationEvent
	batchBuffer []*IntegrationEvent
	mu          sync.RWMutex
	running     bool
	ctx         context.Context
	cancel      context.CancelFunc
	metrics     *SIEMMetrics
}

// SIEMMetrics tracks SIEM client performance
type SIEMMetrics struct {
	EventsSent    int64     `json:"events_sent"`
	EventsDropped int64     `json:"events_dropped"`
	RetryAttempts int64     `json:"retry_attempts"`
	LastEventTime time.Time `json:"last_event_time"`
	LastError     string    `json:"last_error,omitempty"`
	mu            sync.RWMutex
}

func NewSIEMClient(config *SIEMConfig) *SIEMClient {
	// Set default values
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}
	if config.BatchSize == 0 {
		config.BatchSize = 100
	}
	if config.RetryConfig == nil {
		config.RetryConfig = &SIEMRetryConfig{
			MaxRetries:    3,
			InitialDelay:  time.Second,
			MaxDelay:      30 * time.Second,
			BackoffFactor: 2.0,
			RetryOnStatus: []int{429, 500, 502, 503, 504},
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	client := &SIEMClient{
		config:      config,
		client:      &http.Client{Timeout: config.Timeout},
		eventQueue:  make(chan *IntegrationEvent, config.BatchSize*2),
		batchBuffer: make([]*IntegrationEvent, 0, config.BatchSize),
		ctx:         ctx,
		cancel:      cancel,
		metrics:     &SIEMMetrics{},
	}

	// Start background processing if streaming mode is enabled
	if config.StreamingMode {
		go client.startEventProcessor()
	}

	return client
}

func (s *SIEMClient) SendEvent(ctx context.Context, event *IntegrationEvent) error {
	if s.config.StreamingMode {
		// Non-blocking send to queue for streaming mode
		select {
		case s.eventQueue <- event:
			return nil
		default:
			// Queue is full, drop event and increment metric
			s.metrics.mu.Lock()
			s.metrics.EventsDropped++
			s.metrics.mu.Unlock()
			return fmt.Errorf("event queue full, event dropped")
		}
	}

	// Synchronous send for non-streaming mode
	return s.sendEventWithRetry(ctx, event)
}

// sendEventWithRetry sends an event with retry logic
func (s *SIEMClient) sendEventWithRetry(ctx context.Context, event *IntegrationEvent) error {
	var lastErr error
	delay := s.config.RetryConfig.InitialDelay

	for attempt := 0; attempt <= s.config.RetryConfig.MaxRetries; attempt++ {
		if attempt > 0 {
			// Wait before retry
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
				// Exponential backoff
				delay = time.Duration(float64(delay) * s.config.RetryConfig.BackoffFactor)
				if delay > s.config.RetryConfig.MaxDelay {
					delay = s.config.RetryConfig.MaxDelay
				}
			}

			s.metrics.mu.Lock()
			s.metrics.RetryAttempts++
			s.metrics.mu.Unlock()
		}

		err := s.sendSingleEvent(ctx, event)
		if err == nil {
			s.metrics.mu.Lock()
			s.metrics.EventsSent++
			s.metrics.LastEventTime = time.Now()
			s.metrics.mu.Unlock()
			return nil
		}

		lastErr = err

		// Check if we should retry based on error type
		if !s.shouldRetry(err) {
			break
		}
	}

	s.metrics.mu.Lock()
	s.metrics.LastError = lastErr.Error()
	s.metrics.mu.Unlock()

	return fmt.Errorf("failed to send event after %d attempts: %w", s.config.RetryConfig.MaxRetries+1, lastErr)
}

// sendSingleEvent sends a single event to the SIEM system
func (s *SIEMClient) sendSingleEvent(ctx context.Context, event *IntegrationEvent) error {
	// Apply custom formatting if configured
	formattedEvent := s.formatEvent(event)

	data, err := json.Marshal(formattedEvent)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %w", err)
	}

	// Create request based on SIEM type
	req, err := s.createRequest(ctx, data)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return &SIEMError{
			StatusCode: resp.StatusCode,
			Message:    string(body),
			Retryable:  s.isRetryableStatus(resp.StatusCode),
		}
	}

	return nil
}

// createRequest creates an HTTP request based on SIEM type
func (s *SIEMClient) createRequest(ctx context.Context, data []byte) (*http.Request, error) {
	var req *http.Request
	var err error

	switch strings.ToLower(s.config.Type) {
	case "splunk":
		req, err = s.createSplunkRequest(ctx, data)
	case "elastic", "elasticsearch":
		req, err = s.createElasticRequest(ctx, data)
	case "qradar":
		req, err = s.createQRadarRequest(ctx, data)
	default:
		// Generic SIEM request
		req, err = http.NewRequestWithContext(ctx, "POST", s.config.Endpoint, bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+s.config.APIKey)
	}

	return req, err
}

// createSplunkRequest creates a Splunk HEC request
func (s *SIEMClient) createSplunkRequest(ctx context.Context, data []byte) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", s.config.Endpoint, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Splunk "+s.config.APIKey)
	if s.config.Index != "" {
		req.Header.Set("X-Splunk-Request-Channel", s.config.Index)
	}

	return req, nil
}

// createElasticRequest creates an Elasticsearch request
func (s *SIEMClient) createElasticRequest(ctx context.Context, data []byte) (*http.Request, error) {
	endpoint := s.config.Endpoint
	if s.config.Index != "" {
		endpoint = fmt.Sprintf("%s/%s/_doc", strings.TrimSuffix(endpoint, "/"), s.config.Index)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+s.config.APIKey)

	return req, nil
}

// createQRadarRequest creates a QRadar request
func (s *SIEMClient) createQRadarRequest(ctx context.Context, data []byte) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", s.config.Endpoint, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("SEC", s.config.APIKey)
	req.Header.Set("Version", "12.0")

	return req, nil
}

// formatEvent applies custom formatting to the event
func (s *SIEMClient) formatEvent(event *IntegrationEvent) interface{} {
	if s.config.CustomFormat == nil {
		return event
	}

	// Apply custom formatting based on SIEM type
	switch strings.ToLower(s.config.Type) {
	case "splunk":
		return s.formatSplunkEvent(event)
	case "elastic", "elasticsearch":
		return s.formatElasticEvent(event)
	case "qradar":
		return s.formatQRadarEvent(event)
	default:
		return s.applyCustomFormat(event)
	}
}

// formatSplunkEvent formats event for Splunk HEC
func (s *SIEMClient) formatSplunkEvent(event *IntegrationEvent) map[string]interface{} {
	splunkEvent := map[string]interface{}{
		"time":       event.Timestamp.Unix(),
		"host":       "typosentinel",
		"source":     event.Source,
		"sourcetype": "typosentinel:security",
		"event":      event,
	}

	if s.config.Index != "" {
		splunkEvent["index"] = s.config.Index
	}

	return splunkEvent
}

// formatElasticEvent formats event for Elasticsearch
func (s *SIEMClient) formatElasticEvent(event *IntegrationEvent) map[string]interface{} {
	elasticEvent := map[string]interface{}{
		"@timestamp": event.Timestamp.Format(time.RFC3339),
		"event_type": event.Type,
		"severity":   event.Severity,
		"source":     event.Source,
		"message":    event.Message,
		"fields":     event.Details,
	}

	if event.Repository != "" {
		elasticEvent["repository"] = event.Repository
	}
	if event.ScanID != "" {
		elasticEvent["scan_id"] = event.ScanID
	}

	return elasticEvent
}

// formatQRadarEvent formats event for QRadar
func (s *SIEMClient) formatQRadarEvent(event *IntegrationEvent) map[string]interface{} {
	qradarEvent := map[string]interface{}{
		"StartTime":     event.Timestamp.Unix() * 1000, // QRadar expects milliseconds
		"EventName":     event.Type,
		"Severity":      s.mapSeverityToQRadar(event.Severity),
		"SourceIP":      "127.0.0.1", // Default source IP
		"EventCategory": "Security",
		"Description":   event.Message,
		"Properties":    event.Details,
	}

	return qradarEvent
}

// applyCustomFormat applies user-defined custom formatting
func (s *SIEMClient) applyCustomFormat(event *IntegrationEvent) map[string]interface{} {
	result := make(map[string]interface{})

	// Start with the original event
	eventMap := map[string]interface{}{
		"type":         event.Type,
		"timestamp":    event.Timestamp,
		"severity":     event.Severity,
		"source":       event.Source,
		"repository":   event.Repository,
		"scan_id":      event.ScanID,
		"message":      event.Message,
		"details":      event.Details,
		"threat_count": event.ThreatCount,
		"risk_score":   event.RiskScore,
	}

	// Apply custom field mappings
	for customField, mapping := range s.config.CustomFormat {
		if mappingStr, ok := mapping.(string); ok {
			if value, exists := eventMap[mappingStr]; exists {
				result[customField] = value
			}
		} else {
			result[customField] = mapping
		}
	}

	return result
}

// mapSeverityToQRadar maps severity levels to QRadar severity values
func (s *SIEMClient) mapSeverityToQRadar(severity string) int {
	switch strings.ToLower(severity) {
	case "critical":
		return 10
	case "high":
		return 8
	case "medium":
		return 5
	case "low":
		return 3
	default:
		return 1
	}
}

// shouldRetry determines if an error should trigger a retry
func (s *SIEMClient) shouldRetry(err error) bool {
	if siemErr, ok := err.(*SIEMError); ok {
		return siemErr.Retryable
	}

	// Retry on network errors
	return true
}

// isRetryableStatus checks if an HTTP status code is retryable
func (s *SIEMClient) isRetryableStatus(statusCode int) bool {
	for _, code := range s.config.RetryConfig.RetryOnStatus {
		if statusCode == code {
			return true
		}
	}
	return false
}

// startEventProcessor starts the background event processor for streaming mode
func (s *SIEMClient) startEventProcessor() {
	s.running = true
	ticker := time.NewTicker(5 * time.Second) // Process batch every 5 seconds
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			// Flush remaining events before shutdown
			s.flushBatch()
			s.running = false
			return

		case event := <-s.eventQueue:
			s.mu.Lock()
			s.batchBuffer = append(s.batchBuffer, event)
			if len(s.batchBuffer) >= s.config.BatchSize {
				s.flushBatch()
			}
			s.mu.Unlock()

		case <-ticker.C:
			// Periodic flush
			s.mu.Lock()
			if len(s.batchBuffer) > 0 {
				s.flushBatch()
			}
			s.mu.Unlock()
		}
	}
}

// flushBatch sends all events in the current batch
func (s *SIEMClient) flushBatch() {
	if len(s.batchBuffer) == 0 {
		return
	}

	// Send batch based on SIEM type
	switch strings.ToLower(s.config.Type) {
	case "splunk":
		s.sendSplunkBatch()
	case "elastic", "elasticsearch":
		s.sendElasticBatch()
	default:
		// Send events individually for other SIEM types
		for _, event := range s.batchBuffer {
			ctx, cancel := context.WithTimeout(context.Background(), s.config.Timeout)
			s.sendEventWithRetry(ctx, event)
			cancel()
		}
	}

	// Clear the batch
	s.batchBuffer = s.batchBuffer[:0]
}

// sendSplunkBatch sends a batch of events to Splunk
func (s *SIEMClient) sendSplunkBatch() {
	var batchData []byte
	for _, event := range s.batchBuffer {
		formattedEvent := s.formatSplunkEvent(event)
		eventData, err := json.Marshal(formattedEvent)
		if err != nil {
			continue
		}
		batchData = append(batchData, eventData...)
		batchData = append(batchData, '\n')
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.config.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", s.config.Endpoint, bytes.NewReader(batchData))
	if err != nil {
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Splunk "+s.config.APIKey)

	resp, err := s.client.Do(req)
	if err == nil {
		resp.Body.Close()
		s.metrics.mu.Lock()
		s.metrics.EventsSent += int64(len(s.batchBuffer))
		s.metrics.LastEventTime = time.Now()
		s.metrics.mu.Unlock()
	}
}

// sendElasticBatch sends a batch of events to Elasticsearch using bulk API
func (s *SIEMClient) sendElasticBatch() {
	var batchData []byte
	for _, event := range s.batchBuffer {
		// Bulk API header
		header := map[string]interface{}{
			"index": map[string]interface{}{},
		}
		if s.config.Index != "" {
			header["index"].(map[string]interface{})["_index"] = s.config.Index
		}

		headerData, _ := json.Marshal(header)
		batchData = append(batchData, headerData...)
		batchData = append(batchData, '\n')

		// Event data
		formattedEvent := s.formatElasticEvent(event)
		eventData, err := json.Marshal(formattedEvent)
		if err != nil {
			continue
		}
		batchData = append(batchData, eventData...)
		batchData = append(batchData, '\n')
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.config.Timeout)
	defer cancel()

	endpoint := fmt.Sprintf("%s/_bulk", strings.TrimSuffix(s.config.Endpoint, "/"))
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(batchData))
	if err != nil {
		return
	}

	req.Header.Set("Content-Type", "application/x-ndjson")
	req.Header.Set("Authorization", "Bearer "+s.config.APIKey)

	resp, err := s.client.Do(req)
	if err == nil {
		resp.Body.Close()
		s.metrics.mu.Lock()
		s.metrics.EventsSent += int64(len(s.batchBuffer))
		s.metrics.LastEventTime = time.Now()
		s.metrics.mu.Unlock()
	}
}

// GetMetrics returns current SIEM client metrics
func (s *SIEMClient) GetMetrics() *SIEMMetrics {
	s.metrics.mu.RLock()
	defer s.metrics.mu.RUnlock()

	return &SIEMMetrics{
		EventsSent:    s.metrics.EventsSent,
		EventsDropped: s.metrics.EventsDropped,
		RetryAttempts: s.metrics.RetryAttempts,
		LastEventTime: s.metrics.LastEventTime,
		LastError:     s.metrics.LastError,
	}
}

// Close gracefully shuts down the SIEM client
func (s *SIEMClient) Close() error {
	if s.cancel != nil {
		s.cancel()
	}

	// Wait for background processor to finish
	for s.running {
		time.Sleep(100 * time.Millisecond)
	}

	return nil
}

// SIEMError represents a SIEM-specific error
type SIEMError struct {
	StatusCode int
	Message    string
	Retryable  bool
}

func (e *SIEMError) Error() string {
	return fmt.Sprintf("SIEM API error %d: %s", e.StatusCode, e.Message)
}

func (s *SIEMClient) HealthCheck(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", s.config.Endpoint+"/health", nil)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+s.config.APIKey)

	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

func (s *SIEMClient) GetName() string {
	return "siem"
}

// Ticketing Client Implementation
type TicketingClient struct {
	config *TicketingConfig
	client *http.Client
}

func NewTicketingClient(config *TicketingConfig) *TicketingClient {
	return &TicketingClient{
		config: config,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

func (t *TicketingClient) SendEvent(ctx context.Context, event *IntegrationEvent) error {
	// Only create tickets for high severity events if auto-create is enabled
	if !t.config.AutoCreate {
		return nil
	}

	if event.Severity != "high" && event.Severity != "critical" {
		return nil
	}

	// Create ticket payload (simplified)
	ticket := map[string]interface{}{
		"summary":     event.Message,
		"description": fmt.Sprintf("Event: %s\nRepository: %s\nSeverity: %s\nTimestamp: %s", event.Type, event.Repository, event.Severity, event.Timestamp),
		"project":     t.config.Project,
		"issuetype":   t.config.IssueType,
		"priority":    t.config.Priority,
	}

	data, err := json.Marshal(ticket)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", t.config.Endpoint+"/rest/api/2/issue", strings.NewReader(string(data)))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(t.config.Username, t.config.APIKey)

	resp, err := t.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("ticketing API error: %d", resp.StatusCode)
	}

	return nil
}

func (t *TicketingClient) HealthCheck(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", t.config.Endpoint+"/rest/api/2/serverInfo", nil)
	if err != nil {
		return err
	}

	req.SetBasicAuth(t.config.Username, t.config.APIKey)

	resp, err := t.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

func (t *TicketingClient) GetName() string {
	return "ticketing"
}

// CI/CD Client Implementation
type CICDClient struct {
	config *CICDConfig
	client *http.Client
}

func NewCICDClient(config *CICDConfig) *CICDClient {
	return &CICDClient{
		config: config,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *CICDClient) SendEvent(ctx context.Context, event *IntegrationEvent) error {
	// Trigger pipeline or update build status based on scan results
	if event.Type == "scan_completed" && c.config.FailOnHigh {
		if event.Severity == "high" || event.Severity == "critical" {
			// Fail the build/pipeline
			return c.failBuild(ctx, event)
		}
	}

	return nil
}

func (c *CICDClient) failBuild(ctx context.Context, event *IntegrationEvent) error {
	// Implementation would depend on CI/CD system
	// This is a placeholder
	return nil
}

func (c *CICDClient) HealthCheck(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", c.config.Endpoint+"/api/health", nil)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+c.config.Token)

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

func (c *CICDClient) GetName() string {
	return "cicd"
}

// Slack Client Implementation
type SlackClient struct {
	config *ExtendedSlackConfig
	client *http.Client
}

func NewSlackClient(config *ExtendedSlackConfig) *SlackClient {
	return &SlackClient{
		config: config,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

func (s *SlackClient) SendEvent(ctx context.Context, event *IntegrationEvent) error {
	color := s.getColorForSeverity(event.Severity)
	text := fmt.Sprintf("*%s*\n%s", event.Type, event.Message)

	if event.Repository != "" {
		text += fmt.Sprintf("\n*Repository:* %s", event.Repository)
	}

	if event.ThreatCount > 0 {
		text += fmt.Sprintf("\n*Threats:* %d", event.ThreatCount)
	}

	payload := map[string]interface{}{
		"text": text,
		"attachments": []map[string]interface{}{
			{
				"color": color,
				"fields": []map[string]interface{}{
					{
						"title": "Severity",
						"value": event.Severity,
						"short": true,
					},
					{
						"title": "Timestamp",
						"value": event.Timestamp.Format(time.RFC3339),
						"short": true,
					},
				},
			},
		},
	}

	if s.config.Channel != "" {
		payload["channel"] = s.config.Channel
	}

	if s.config.Username != "" {
		payload["username"] = s.config.Username
	}

	if s.config.IconEmoji != "" {
		payload["icon_emoji"] = s.config.IconEmoji
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", s.config.WebhookURL, strings.NewReader(string(data)))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("slack webhook error: %d", resp.StatusCode)
	}

	return nil
}

func (s *SlackClient) getColorForSeverity(severity string) string {
	switch severity {
	case "critical":
		return "danger"
	case "high":
		return "warning"
	case "medium":
		return "#ffcc00"
	case "low":
		return "good"
	default:
		return "#cccccc"
	}
}

func (s *SlackClient) HealthCheck(ctx context.Context) error {
	// Slack webhooks don't have a health endpoint, so we'll just validate the URL
	if s.config.WebhookURL == "" {
		return fmt.Errorf("webhook URL not configured")
	}
	return nil
}

func (s *SlackClient) GetName() string {
	return "slack"
}

// Webhook Client Implementation
type WebhookClient struct {
	config *ExtendedWebhookConfig
	client *http.Client
}

func NewWebhookClient(config *ExtendedWebhookConfig) *WebhookClient {
	timeout := 30 * time.Second
	if config.Timeout > 0 {
		timeout = config.Timeout
	}

	return &WebhookClient{
		config: config,
		client: &http.Client{Timeout: timeout},
	}
}

func (w *WebhookClient) SendEvent(ctx context.Context, event *IntegrationEvent) error {
	// Check if this event type is configured for this webhook
	if !w.shouldSendEvent(event.Type) {
		return nil
	}

	data, err := json.Marshal(event)
	if err != nil {
		return err
	}

	method := "POST"
	if w.config.Method != "" {
		method = w.config.Method
	}

	req, err := http.NewRequestWithContext(ctx, method, w.config.URL, strings.NewReader(string(data)))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "TypoSentinel/1.0")

	// Add custom headers
	for key, value := range w.config.Headers {
		req.Header.Set(key, value)
	}

	retries := 3
	if w.config.Retries > 0 {
		retries = w.config.Retries
	}

	var lastErr error
	for i := 0; i < retries; i++ {
		resp, err := w.client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		resp.Body.Close()

		if resp.StatusCode < 400 {
			return nil
		}

		lastErr = fmt.Errorf("webhook error: %d", resp.StatusCode)
		if i < retries-1 {
			time.Sleep(time.Duration(i+1) * time.Second)
		}
	}

	return lastErr
}

func (w *WebhookClient) shouldSendEvent(eventType string) bool {
	if len(w.config.Events) == 0 {
		return true // Send all events if none specified
	}

	for _, event := range w.config.Events {
		if event == eventType || event == "*" {
			return true
		}
	}

	return false
}

func (w *WebhookClient) HealthCheck(ctx context.Context) error {
	// Simple GET request to check if webhook endpoint is reachable
	req, err := http.NewRequestWithContext(ctx, "HEAD", w.config.URL, nil)
	if err != nil {
		return err
	}

	resp, err := w.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

func (w *WebhookClient) GetName() string {
	return w.config.Name
}
