# TypoSentinel Integration Implementation Plan

## 📁 Project Structure Extensions

Add these directories and files to your existing TypoSentinel project:

```
internal/
├── integrations/           # NEW - Integration framework
│   ├── hub/               # Central integration hub
│   ├── connectors/        # Individual platform connectors
│   ├── events/           # Event processing
│   └── config/           # Integration configurations
├── events/               # NEW - Event system
├── notifications/        # NEW - Alert routing
└── policies/            # NEW - Response policies

pkg/
├── integrations/         # NEW - Public integration APIs
├── events/              # NEW - Event types and interfaces
└── connectors/          # NEW - Connector interfaces

config/
└── integrations/        # NEW - Integration configs

cmd/
└── typosentinel/
    └── integrations.go  # NEW - Integration CLI commands
```

## 🎯 Phase 1: Core Integration Framework (Week 1-2)

### Step 1: Add Event System Foundation

**File: `pkg/events/types.go`**
```go
package events

import (
    "time"
    "encoding/json"
)

// SecurityEvent represents a threat detection event
type SecurityEvent struct {
    ID          string                 `json:"id"`
    Timestamp   time.Time              `json:"timestamp"`
    Type        EventType              `json:"type"`
    Severity    Severity               `json:"severity"`
    Source      string                 `json:"source"`
    Package     PackageInfo            `json:"package"`
    Threat      ThreatInfo             `json:"threat"`
    Context     map[string]interface{} `json:"context"`
    Metadata    EventMetadata          `json:"metadata"`
}

type EventType string

const (
    EventTypeThreatDetected     EventType = "threat_detected"
    EventTypePackageBlocked     EventType = "package_blocked"
    EventTypePolicyViolation    EventType = "policy_violation"
    EventTypeVulnerabilityFound EventType = "vulnerability_found"
)

type Severity string

const (
    SeverityCritical Severity = "critical"
    SeverityHigh     Severity = "high"
    SeverityMedium   Severity = "medium"
    SeverityLow      Severity = "low"
)

type PackageInfo struct {
    Name     string `json:"name"`
    Version  string `json:"version"`
    Registry string `json:"registry"`
    Hash     string `json:"hash,omitempty"`
}

type ThreatInfo struct {
    Type        string  `json:"type"`
    Confidence  float64 `json:"confidence"`
    RiskScore   float64 `json:"risk_score"`
    Description string  `json:"description"`
    Evidence    []string `json:"evidence"`
}

type EventMetadata struct {
    DetectionMethod string            `json:"detection_method"`
    AnalysisDuration time.Duration    `json:"analysis_duration"`
    Correlation     map[string]string `json:"correlation"`
    Tags           []string           `json:"tags"`
}
```

**File: `internal/events/bus.go`**
```go
package events

import (
    "context"
    "fmt"
    "sync"
    "time"

    "github.com/Alivanroy/Typosentinel/pkg/events"
    "github.com/Alivanroy/Typosentinel/pkg/logger"
)

// EventBus handles event routing and processing
type EventBus struct {
    subscribers map[events.EventType][]Subscriber
    buffer      chan *events.SecurityEvent
    logger      *logger.Logger
    mu          sync.RWMutex
    running     bool
}

type Subscriber interface {
    Handle(ctx context.Context, event *events.SecurityEvent) error
    GetID() string
}

// NewEventBus creates a new event bus
func NewEventBus(logger *logger.Logger, bufferSize int) *EventBus {
    return &EventBus{
        subscribers: make(map[events.EventType][]Subscriber),
        buffer:      make(chan *events.SecurityEvent, bufferSize),
        logger:      logger,
    }
}

// Subscribe registers a subscriber for specific event types
func (eb *EventBus) Subscribe(eventType events.EventType, subscriber Subscriber) {
    eb.mu.Lock()
    defer eb.mu.Unlock()
    
    eb.subscribers[eventType] = append(eb.subscribers[eventType], subscriber)
    eb.logger.Info("Subscriber registered", map[string]interface{}{
        "subscriber_id": subscriber.GetID(),
        "event_type":    eventType,
    })
}

// Publish sends an event to all subscribers
func (eb *EventBus) Publish(ctx context.Context, event *events.SecurityEvent) error {
    select {
    case eb.buffer <- event:
        return nil
    case <-ctx.Done():
        return ctx.Err()
    default:
        return fmt.Errorf("event buffer full")
    }
}

// Start begins event processing
func (eb *EventBus) Start(ctx context.Context) {
    eb.running = true
    eb.logger.Info("Event bus started")
    
    for {
        select {
        case event := <-eb.buffer:
            eb.processEvent(ctx, event)
        case <-ctx.Done():
            eb.running = false
            eb.logger.Info("Event bus stopped")
            return
        }
    }
}

func (eb *EventBus) processEvent(ctx context.Context, event *events.SecurityEvent) {
    eb.mu.RLock()
    subscribers := eb.subscribers[event.Type]
    eb.mu.RUnlock()
    
    for _, subscriber := range subscribers {
        go func(sub Subscriber) {
            if err := sub.Handle(ctx, event); err != nil {
                eb.logger.Error("Subscriber error", map[string]interface{}{
                    "subscriber_id": sub.GetID(),
                    "event_id":      event.ID,
                    "error":         err,
                })
            }
        }(subscriber)
    }
}
```

### Step 2: Create Integration Hub

**File: `internal/integrations/hub/hub.go`**
```go
package hub

import (
    "context"
    "fmt"
    "sync"

    "github.com/Alivanroy/Typosentinel/internal/events"
    "github.com/Alivanroy/Typosentinel/pkg/events"
    "github.com/Alivanroy/Typosentinel/pkg/integrations"
    "github.com/Alivanroy/Typosentinel/pkg/logger"
)

// IntegrationHub manages all security tool integrations
type IntegrationHub struct {
    eventBus     *events.EventBus
    connectors   map[string]integrations.Connector
    config       *Config
    logger       *logger.Logger
    mu           sync.RWMutex
}

type Config struct {
    Enabled      bool                          `yaml:"enabled"`
    Connectors   map[string]ConnectorConfig    `yaml:"connectors"`
    EventRouting map[string][]string           `yaml:"event_routing"`
    Filters      map[string]FilterConfig       `yaml:"filters"`
}

type ConnectorConfig struct {
    Type     string                 `yaml:"type"`
    Enabled  bool                   `yaml:"enabled"`
    Settings map[string]interface{} `yaml:"settings"`
}

type FilterConfig struct {
    MinSeverity string   `yaml:"min_severity"`
    EventTypes  []string `yaml:"event_types"`
    Conditions  []string `yaml:"conditions"`
}

// NewIntegrationHub creates a new integration hub
func NewIntegrationHub(eventBus *events.EventBus, config *Config, logger *logger.Logger) *IntegrationHub {
    return &IntegrationHub{
        eventBus:   eventBus,
        connectors: make(map[string]integrations.Connector),
        config:     config,
        logger:     logger,
    }
}

// Initialize sets up all configured integrations
func (ih *IntegrationHub) Initialize(ctx context.Context) error {
    if !ih.config.Enabled {
        ih.logger.Info("Integration hub disabled")
        return nil
    }

    // Initialize connectors
    for name, config := range ih.config.Connectors {
        if !config.Enabled {
            continue
        }

        connector, err := ih.createConnector(name, config)
        if err != nil {
            return fmt.Errorf("failed to create connector %s: %w", name, err)
        }

        if err := connector.Connect(ctx); err != nil {
            return fmt.Errorf("failed to connect %s: %w", name, err)
        }

        ih.connectors[name] = connector
        ih.logger.Info("Connector initialized", map[string]interface{}{
            "connector": name,
            "type":      config.Type,
        })
    }

    // Subscribe to events
    ih.eventBus.Subscribe(events.EventTypeThreatDetected, ih)
    ih.eventBus.Subscribe(events.EventTypePackageBlocked, ih)
    ih.eventBus.Subscribe(events.EventTypePolicyViolation, ih)

    return nil
}

// Handle implements the Subscriber interface
func (ih *IntegrationHub) Handle(ctx context.Context, event *events.SecurityEvent) error {
    routedConnectors := ih.getRoutedConnectors(event)
    
    for _, connectorName := range routedConnectors {
        connector, exists := ih.connectors[connectorName]
        if !exists {
            continue
        }

        go func(conn integrations.Connector, evt *events.SecurityEvent) {
            if err := conn.Send(ctx, evt); err != nil {
                ih.logger.Error("Failed to send event", map[string]interface{}{
                    "connector": connectorName,
                    "event_id":  evt.ID,
                    "error":     err,
                })
            }
        }(connector, event)
    }

    return nil
}

func (ih *IntegrationHub) GetID() string {
    return "integration_hub"
}

func (ih *IntegrationHub) getRoutedConnectors(event *events.SecurityEvent) []string {
    routing, exists := ih.config.EventRouting[string(event.Type)]
    if !exists {
        // Default routing - send to all enabled connectors
        var connectors []string
        for name := range ih.connectors {
            connectors = append(connectors, name)
        }
        return connectors
    }
    return routing
}

func (ih *IntegrationHub) createConnector(name string, config ConnectorConfig) (integrations.Connector, error) {
    // Factory pattern for creating connectors
    switch config.Type {
    case "splunk":
        return newSplunkConnector(name, config.Settings, ih.logger)
    case "slack":
        return newSlackConnector(name, config.Settings, ih.logger)
    case "webhook":
        return newWebhookConnector(name, config.Settings, ih.logger)
    default:
        return nil, fmt.Errorf("unknown connector type: %s", config.Type)
    }
}
```

### Step 3: Define Connector Interface

**File: `pkg/integrations/connector.go`**
```go
package integrations

import (
    "context"
    "time"

    "github.com/Alivanroy/Typosentinel/pkg/events"
)

// Connector interface for security tool integrations
type Connector interface {
    // Connect establishes connection to the external system
    Connect(ctx context.Context) error
    
    // Send transmits a security event to the external system
    Send(ctx context.Context, event *events.SecurityEvent) error
    
    // Health returns the current health status
    Health() HealthStatus
    
    // Close terminates the connection
    Close() error
    
    // GetName returns the connector name
    GetName() string
    
    // GetType returns the connector type
    GetType() string
}

type HealthStatus struct {
    Healthy     bool      `json:"healthy"`
    LastCheck   time.Time `json:"last_check"`
    LastError   string    `json:"last_error,omitempty"`
    Latency     time.Duration `json:"latency"`
    EventsSent  int64     `json:"events_sent"`
    ErrorCount  int64     `json:"error_count"`
}

// ConnectorFactory creates connectors
type ConnectorFactory interface {
    Create(name string, config map[string]interface{}) (Connector, error)
    GetType() string
}
```

## 🔌 Phase 2: Basic Connectors (Week 3-4)

### Step 1: Splunk Connector

**File: `internal/integrations/connectors/splunk.go`**
```go
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

type SplunkConnector struct {
    name     string
    config   SplunkConfig
    client   *http.Client
    logger   *logger.Logger
    health   integrations.HealthStatus
}

type SplunkConfig struct {
    HECURL   string `yaml:"hec_url"`
    Token    string `yaml:"token"`
    Index    string `yaml:"index"`
    Source   string `yaml:"source"`
    Timeout  time.Duration `yaml:"timeout"`
}

type SplunkEvent struct {
    Time       int64                  `json:"time"`
    Host       string                 `json:"host"`
    Source     string                 `json:"source"`
    Sourcetype string                 `json:"sourcetype"`
    Index      string                 `json:"index"`
    Event      map[string]interface{} `json:"event"`
}

func NewSplunkConnector(name string, settings map[string]interface{}, logger *logger.Logger) (*SplunkConnector, error) {
    config := SplunkConfig{
        Timeout: 30 * time.Second,
        Source:  "typosentinel",
        Index:   "security",
    }

    // Parse settings into config
    if url, ok := settings["hec_url"].(string); ok {
        config.HECURL = url
    }
    if token, ok := settings["token"].(string); ok {
        config.Token = token
    }
    if index, ok := settings["index"].(string); ok {
        config.Index = index
    }

    if config.HECURL == "" || config.Token == "" {
        return nil, fmt.Errorf("missing required Splunk configuration")
    }

    return &SplunkConnector{
        name:   name,
        config: config,
        client: &http.Client{Timeout: config.Timeout},
        logger: logger,
        health: integrations.HealthStatus{
            Healthy:   true,
            LastCheck: time.Now(),
        },
    }, nil
}

func (s *SplunkConnector) Connect(ctx context.Context) error {
    // Test connection by sending a test event
    testEvent := &events.SecurityEvent{
        ID:        "test-connection",
        Timestamp: time.Now(),
        Type:      "test",
        Severity:  "low",
        Source:    "typosentinel",
        Package:   events.PackageInfo{Name: "test", Version: "1.0.0", Registry: "test"},
        Threat:    events.ThreatInfo{Type: "test", Confidence: 0.1, RiskScore: 0.1, Description: "Connection test"},
    }

    if err := s.Send(ctx, testEvent); err != nil {
        return fmt.Errorf("connection test failed: %w", err)
    }

    s.logger.Info("Splunk connector connected successfully", map[string]interface{}{
        "connector": s.name,
        "hec_url":   s.config.HECURL,
    })
    return nil
}

func (s *SplunkConnector) Send(ctx context.Context, event *events.SecurityEvent) error {
    start := time.Now()

    splunkEvent := s.transformEvent(event)
    
    payload, err := json.Marshal(splunkEvent)
    if err != nil {
        s.updateHealth(false, err, time.Since(start))
        return fmt.Errorf("failed to marshal event: %w", err)
    }

    req, err := http.NewRequestWithContext(ctx, "POST", s.config.HECURL, bytes.NewBuffer(payload))
    if err != nil {
        s.updateHealth(false, err, time.Since(start))
        return fmt.Errorf("failed to create request: %w", err)
    }

    req.Header.Set("Authorization", "Splunk "+s.config.Token)
    req.Header.Set("Content-Type", "application/json")

    resp, err := s.client.Do(req)
    if err != nil {
        s.updateHealth(false, err, time.Since(start))
        return fmt.Errorf("failed to send to Splunk: %w", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode >= 400 {
        err := fmt.Errorf("Splunk returned status %d", resp.StatusCode)
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

func (s *SplunkConnector) transformEvent(event *events.SecurityEvent) *SplunkEvent {
    return &SplunkEvent{
        Time:       event.Timestamp.Unix(),
        Host:       "typosentinel",
        Source:     s.config.Source,
        Sourcetype: "package_threat",
        Index:      s.config.Index,
        Event: map[string]interface{}{
            "id":            event.ID,
            "type":          event.Type,
            "severity":      event.Severity,
            "package_name":  event.Package.Name,
            "package_version": event.Package.Version,
            "registry":      event.Package.Registry,
            "threat_type":   event.Threat.Type,
            "confidence":    event.Threat.Confidence,
            "risk_score":    event.Threat.RiskScore,
            "description":   event.Threat.Description,
            "evidence":      event.Threat.Evidence,
            "detection_method": event.Metadata.DetectionMethod,
            "analysis_duration_ms": event.Metadata.AnalysisDuration.Milliseconds(),
            "tags":          event.Metadata.Tags,
        },
    }
}

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

func (s *SplunkConnector) Health() integrations.HealthStatus {
    return s.health
}

func (s *SplunkConnector) Close() error {
    return nil
}

func (s *SplunkConnector) GetName() string {
    return s.name
}

func (s *SplunkConnector) GetType() string {
    return "splunk"
}
```

### Step 2: Slack Connector

**File: `internal/integrations/connectors/slack.go`**
```go
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

type SlackConnector struct {
    name       string
    config     SlackConfig
    client     *http.Client
    logger     *logger.Logger
    health     integrations.HealthStatus
}

type SlackConfig struct {
    WebhookURL string        `yaml:"webhook_url"`
    Channel    string        `yaml:"channel"`
    Username   string        `yaml:"username"`
    Timeout    time.Duration `yaml:"timeout"`
}

type SlackMessage struct {
    Channel     string            `json:"channel,omitempty"`
    Username    string            `json:"username,omitempty"`
    Text        string            `json:"text"`
    Attachments []SlackAttachment `json:"attachments,omitempty"`
}

type SlackAttachment struct {
    Color     string       `json:"color"`
    Title     string       `json:"title"`
    Text      string       `json:"text"`
    Fields    []SlackField `json:"fields"`
    Timestamp int64        `json:"ts"`
}

type SlackField struct {
    Title string `json:"title"`
    Value string `json:"value"`
    Short bool   `json:"short"`
}

func NewSlackConnector(name string, settings map[string]interface{}, logger *logger.Logger) (*SlackConnector, error) {
    config := SlackConfig{
        Timeout:  30 * time.Second,
        Username: "TypoSentinel",
        Channel:  "#security",
    }

    if url, ok := settings["webhook_url"].(string); ok {
        config.WebhookURL = url
    }
    if channel, ok := settings["channel"].(string); ok {
        config.Channel = channel
    }
    if username, ok := settings["username"].(string); ok {
        config.Username = username
    }

    if config.WebhookURL == "" {
        return nil, fmt.Errorf("missing required Slack webhook URL")
    }

    return &SlackConnector{
        name:   name,
        config: config,
        client: &http.Client{Timeout: config.Timeout},
        logger: logger,
        health: integrations.HealthStatus{
            Healthy:   true,
            LastCheck: time.Now(),
        },
    }, nil
}

func (s *SlackConnector) Connect(ctx context.Context) error {
    // Test connection with a simple message
    testMessage := &SlackMessage{
        Channel:  s.config.Channel,
        Username: s.config.Username,
        Text:     "🔗 TypoSentinel connected successfully",
    }

    if err := s.sendMessage(ctx, testMessage); err != nil {
        return fmt.Errorf("connection test failed: %w", err)
    }

    s.logger.Info("Slack connector connected successfully", map[string]interface{}{
        "connector": s.name,
        "channel":   s.config.Channel,
    })
    return nil
}

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

    return &SlackMessage{
        Channel:     s.config.Channel,
        Username:    s.config.Username,
        Text:        text,
        Attachments: []SlackAttachment{attachment},
    }
}

func (s *SlackConnector) getSeverityColor(severity events.Severity) string {
    switch severity {
    case events.SeverityCritical:
        return "danger"
    case events.SeverityHigh:
        return "warning"
    case events.SeverityMedium:
        return "#FFA500"
    default:
        return "good"
    }
}

func (s *SlackConnector) getSeverityEmoji(severity events.Severity) string {
    switch severity {
    case events.SeverityCritical:
        return "🚨"
    case events.SeverityHigh:
        return "⚠️"
    case events.SeverityMedium:
        return "🟡"
    default:
        return "ℹ️"
    }
}

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

func (s *SlackConnector) Health() integrations.HealthStatus {
    return s.health
}

func (s *SlackConnector) Close() error {
    return nil
}

func (s *SlackConnector) GetName() string {
    return s.name
}

func (s *SlackConnector) GetType() string {
    return "slack"
}
```

## ⚙️ Phase 3: Integration into Scanner (Week 5)

### Step 1: Modify Scanner to Emit Events

**File: `internal/scanner/scanner.go` (modifications)**

Add to the Scanner struct:
```go
type Scanner struct {
    // ... existing fields
    eventBus        *events.EventBus  // ADD THIS
    integrationHub  *hub.IntegrationHub // ADD THIS
}
```

Add to the constructor:
```go
func New(cfg *config.Config) (*Scanner, error) {
    // ... existing code

    // Initialize event system
    eventBus := events.NewEventBus(logger, 1000)
    
    // Initialize integration hub
    integrationHub := hub.NewIntegrationHub(eventBus, cfg.Integrations, logger)
    
    s := &Scanner{
        // ... existing fields
        eventBus:       eventBus,
        integrationHub: integrationHub,
    }

    // Initialize integrations
    if err := s.integrationHub.Initialize(context.Background()); err != nil {
        return nil, fmt.Errorf("failed to initialize integrations: %w", err)
    }

    // Start event processing
    go s.eventBus.Start(context.Background())

    return s, nil
}
```

Add event emission to threat detection:
```go
func (s *Scanner) analyzePackageThreats(pkg *types.Package) ([]*types.Threat, error) {
    // ... existing threat analysis code

    // If threats found, emit security event
    if len(threats) > 0 {
        for _, threat := range threats {
            securityEvent := &events.SecurityEvent{
                ID:        generateEventID(),
                Timestamp: time.Now(),
                Type:      events.EventTypeThreatDetected,
                Severity:  mapThreatSeverity(threat.Severity),
                Source:    "typosentinel",
                Package: events.PackageInfo{
                    Name:     pkg.Name,
                    Version:  pkg.Version,
                    Registry: pkg.Registry,
                    Hash:     pkg.Hash,
                },
                Threat: events.ThreatInfo{
                    Type:        string(threat.Type),
                    Confidence:  threat.Confidence,
                    RiskScore:   threat.RiskScore,
                    Description: threat.Description,
                    Evidence:    threat.Evidence,
                },
                Metadata: events.EventMetadata{
                    DetectionMethod: threat.DetectionMethod,
                    Tags:           []string{"automated", "scanner"},
                },
            }

            // Emit event asynchronously
            go func(event *events.SecurityEvent) {
                ctx := context.Background()
                if err := s.eventBus.Publish(ctx, event); err != nil {
                    s.logger.Error("Failed to publish security event", map[string]interface{}{
                        "event_id": event.ID,
                        "error":    err,
                    })
                }
            }(securityEvent)
        }
    }

    return threats, nil
}

func generateEventID() string {
    return fmt.Sprintf("evt_%d_%s", time.Now().UnixNano(), randomString(8))
}

func mapThreatSeverity(severity types.Severity) events.Severity {
    switch severity {
    case types.SeverityCritical:
        return events.SeverityCritical
    case types.SeverityHigh:
        return events.SeverityHigh
    case types.SeverityMedium:
        return events.SeverityMedium
    default:
        return events.SeverityLow
    }
}
```

### Step 2: Update Configuration

**File: `internal/config/structs.go` (add to Config struct)**
```go
type Config struct {
    // ... existing fields
    Integrations *IntegrationsConfig `mapstructure:"integrations"`
}

type IntegrationsConfig struct {
    Enabled      bool                          `mapstructure:"enabled"`
    Connectors   map[string]ConnectorConfig    `mapstructure:"connectors"`
    EventRouting map[string][]string           `mapstructure:"event_routing"`
    Filters      map[string]FilterConfig       `mapstructure:"filters"`
}

type ConnectorConfig struct {
    Type     string                 `mapstructure:"type"`
    Enabled  bool                   `mapstructure:"enabled"`
    Settings map[string]interface{} `mapstructure:"settings"`
}

type FilterConfig struct {
    MinSeverity string   `mapstructure:"min_severity"`
    EventTypes  []string `mapstructure:"event_types"`
    Conditions  []string `mapstructure:"conditions"`
}
```

### Step 3: Create Configuration Example

**File: `config/integrations.example.yaml`**
```yaml
integrations:
  enabled: true
  
  connectors:
    splunk_security:
      type: "splunk"
      enabled: true
      settings:
        hec_url: "https://splunk.company.com:8088/services/collector"
        token: "${SPLUNK_HEC_TOKEN}"
        index: "security"
        source: "typosentinel"
        
    slack_alerts:
      type: "slack"  
      enabled: true
      settings:
        webhook_url: "${SLACK_WEBHOOK_URL}"
        channel: "#security-alerts"
        username: "TypoSentinel"
        
    security_webhook:
      type: "webhook"
      enabled: false
      settings:
        url: "https://security.company.com/api/alerts"
        auth_header: "Authorization"
        auth_token: "${SECURITY_API_TOKEN}"
  
  event_routing:
    threat_detected: ["splunk_security", "slack_alerts"]
    package_blocked: ["splunk_security"]
    policy_violation: ["splunk_security", "security_webhook"]
    
  filters:
    slack_alerts:
      min_severity: "high"
      event_types: ["threat_detected", "package_blocked"]
    splunk_security:
      min_severity: "low"
      event_types: ["threat_detected", "package_blocked", "policy_violation"]
```

## 🚀 Phase 4: CLI Integration Commands (Week 6)

### Step 1: Add Integration CLI Commands

**File: `cmd/typosentinel/integrations.go`**
```go
package main

import (
    "encoding/json"
    "fmt"
    "os"

    "github.com/spf13/cobra"
    "github.com/Alivanroy/Typosentinel/internal/integrations/hub"
)

func init() {
    rootCmd.AddCommand(integrationsCmd)
    integrationsCmd.AddCommand(integrationsListCmd)
    integrationsCmd.AddCommand(integrationsTestCmd)
    integrationsCmd.AddCommand(integrationsStatusCmd)
}

var integrationsCmd = &cobra.Command{
    Use:   "integrations",
    Short: "Manage security tool integrations",
    Long:  "Commands for managing and monitoring security tool integrations",
}

var integrationsListCmd = &cobra.Command{
    Use:   "list",
    Short: "List configured integrations",
    RunE: func(cmd *cobra.Command, args []string) error {
        config, err := loadConfig()
        if err != nil {
            return err
        }

        if config.Integrations == nil || !config.Integrations.Enabled {
            fmt.Println("Integrations are disabled")
            return nil
        }

        fmt.Printf("%-20s %-10s %-10s %-30s\n", "NAME", "TYPE", "STATUS", "DESCRIPTION")
        fmt.Printf("%-20s %-10s %-10s %-30s\n", "----", "----", "------", "-----------")

        for name, connector := range config.Integrations.Connectors {
            status := "disabled"
            if connector.Enabled {
                status = "enabled"
            }
            
            description := fmt.Sprintf("%s integration", connector.Type)
            fmt.Printf("%-20s %-10s %-10s %-30s\n", name, connector.Type, status, description)
        }

        return nil
    },
}

var integrationsTestCmd = &cobra.Command{
    Use:   "test [integration-name]",
    Short: "Test integration connectivity",
    Args:  cobra.ExactArgs(1),
    RunE: func(cmd *cobra.Command, args []string) error {
        integrationName := args[0]
        
        config, err := loadConfig()
        if err != nil {
            return err
        }

        if config.Integrations == nil {
            return fmt.Errorf("no integrations configured")
        }

        connectorConfig, exists := config.Integrations.Connectors[integrationName]
        if !exists {
            return fmt.Errorf("integration '%s' not found", integrationName)
        }

        fmt.Printf("Testing integration: %s (%s)\n", integrationName, connectorConfig.Type)
        
        // Create and test connector
        connector, err := createTestConnector(integrationName, connectorConfig)
        if err != nil {
            return fmt.Errorf("failed to create connector: %w", err)
        }

        ctx := cmd.Context()
        if err := connector.Connect(ctx); err != nil {
            fmt.Printf("❌ Connection failed: %v\n", err)
            return err
        }

        fmt.Printf("✅ Connection successful\n")
        
        // Test health
        health := connector.Health()
        fmt.Printf("Health Status: %s\n", formatHealth(health))
        
        return connector.Close()
    },
}

var integrationsStatusCmd = &cobra.Command{
    Use:   "status",
    Short: "Show integration health status",
    RunE: func(cmd *cobra.Command, args []string) error {
        config, err := loadConfig()
        if err != nil {
            return err
        }

        if config.Integrations == nil || !config.Integrations.Enabled {
            fmt.Println("Integrations are disabled")
            return nil
        }

        // This would connect to running TypoSentinel instance via API
        // For now, show configuration status
        fmt.Printf("Integration Status:\n\n")
        
        for name, connector := range config.Integrations.Connectors {
            status := "🔴 Disabled"
            if connector.Enabled {
                status = "🟡 Configured"
            }
            
            fmt.Printf("%-20s %s\n", name+":", status)
        }

        return nil
    },
}

func formatHealth(health integrations.HealthStatus) string {
    status := "🔴 Unhealthy"
    if health.Healthy {
        status = "🟢 Healthy"
    }
    
    return fmt.Sprintf("%s (Events: %d, Errors: %d, Latency: %v)", 
        status, health.EventsSent, health.ErrorCount, health.Latency)
}
```

## 📝 Phase 5: Testing & Documentation (Week 7)

### Step 1: Integration Tests

**File: `tests/integration/integrations_test.go`**
```go
package integration

import (
    "context"
    "testing"
    "time"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
    
    "github.com/Alivanroy/Typosentinel/internal/events"
    "github.com/Alivanroy/Typosentinel/internal/integrations/connectors"
    "github.com/Alivanroy/Typosentinel/pkg/events"
)

func TestSlackConnector(t *testing.T) {
    if testing.Short() {
        t.Skip("Skipping integration test in short mode")
    }

    webhookURL := os.Getenv("SLACK_WEBHOOK_URL")
    if webhookURL == "" {
        t.Skip("SLACK_WEBHOOK_URL not set")
    }

    settings := map[string]interface{}{
        "webhook_url": webhookURL,
        "channel":     "#test",
        "username":    "test-bot",
    }

    connector, err := connectors.NewSlackConnector("test", settings, logger)
    require.NoError(t, err)

    ctx := context.Background()
    err = connector.Connect(ctx)
    require.NoError(t, err)

    // Test sending an event
    testEvent := &events.SecurityEvent{
        ID:        "test-123",
        Timestamp: time.Now(),
        Type:      events.EventTypeThreatDetected,
        Severity:  events.SeverityHigh,
        Source:    "test",
        Package: events.PackageInfo{
            Name:     "test-package",
            Version:  "1.0.0",
            Registry: "npm",
        },
        Threat: events.ThreatInfo{
            Type:        "typosquatting",
            Confidence:  0.95,
            RiskScore:   0.85,
            Description: "Test threat detection",
        },
    }

    err = connector.Send(ctx, testEvent)
    assert.NoError(t, err)

    // Check health
    health := connector.Health()
    assert.True(t, health.Healthy)
    assert.Equal(t, int64(1), health.EventsSent)

    err = connector.Close()
    assert.NoError(t, err)
}

func TestEventBusIntegration(t *testing.T) {
    logger := logger.NewLogger(logger.Config{Level: "debug"})
    eventBus := events.NewEventBus(logger, 10)

    // Mock subscriber
    subscriber := &mockSubscriber{events: make(chan *events.SecurityEvent, 10)}
    eventBus.Subscribe(events.EventTypeThreatDetected, subscriber)

    // Start event bus
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()
    go eventBus.Start(ctx)

    // Publish test event
    testEvent := &events.SecurityEvent{
        ID:        "test-456",
        Timestamp: time.Now(),
        Type:      events.EventTypeThreatDetected,
        Severity:  events.SeverityCritical,
    }

    err := eventBus.Publish(ctx, testEvent)
    require.NoError(t, err)

    // Wait for event
    select {
    case receivedEvent := <-subscriber.events:
        assert.Equal(t, testEvent.ID, receivedEvent.ID)
        assert.Equal(t, testEvent.Type, receivedEvent.Type)
    case <-time.After(5 * time.Second):
        t.Fatal("Event not received within timeout")
    }
}

type mockSubscriber struct {
    events chan *events.SecurityEvent
}

func (m *mockSubscriber) Handle(ctx context.Context, event *events.SecurityEvent) error {
    m.events <- event
    return nil
}

func (m *mockSubscriber) GetID() string {
    return "mock-subscriber"
}
```

### Step 2: Documentation

**File: `docs/INTEGRATIONS.md`**
```markdown
# TypoSentinel Security Integrations

This document explains how to configure and use TypoSentinel's security tool integrations.

## Quick Start

1. Enable integrations in your configuration:
```yaml
integrations:
  enabled: true
```

2. Configure your security tools:
```yaml
integrations:
  connectors:
    splunk:
      type: "splunk"
      enabled: true
      settings:
        hec_url: "https://your-splunk.com:8088/services/collector"
        token: "your-hec-token"
```

3. Test the integration:
```bash
typosentinel integrations test splunk
```

## Supported Integrations

### SIEM Platforms
- **Splunk** - Send events via HTTP Event Collector (HEC)
- **Elastic Stack** - Send events to Elasticsearch
- **QRadar** - Send events via REST API

### Communication Tools  
- **Slack** - Send alerts to Slack channels
- **Microsoft Teams** - Send alerts to Teams channels
- **Email** - Send email notifications

### Generic
- **Webhook** - Send events to any HTTP endpoint

## Configuration

### Environment Variables

Set these environment variables for sensitive configuration:

```bash
export SPLUNK_HEC_TOKEN="your-splunk-token"
export SLACK_WEBHOOK_URL="your-slack-webhook"
export SECURITY_API_TOKEN="your-api-token"
```

### Configuration File

Create `config/integrations.yaml`:

```yaml
integrations:
  enabled: true
  
  connectors:
    splunk_security:
      type: "splunk"
      enabled: true
      settings:
        hec_url: "${SPLUNK_HEC_URL}"
        token: "${SPLUNK_HEC_TOKEN}"
        index: "security"
        
  event_routing:
    threat_detected: ["splunk_security", "slack_alerts"]
    
  filters:
    slack_alerts:
      min_severity: "high"
```

## Testing

Test individual integrations:
```bash
# Test specific integration
typosentinel integrations test splunk

# List all integrations
typosentinel integrations list

# Check status
typosentinel integrations status
```

## Troubleshooting

Common issues and solutions:

1. **Connection Failed**: Check network connectivity and credentials
2. **Events Not Received**: Verify event routing configuration
3. **High Latency**: Check system resources and network performance

Enable debug logging:
```yaml
logging:
  level: "debug"
```
```

## 🎯 Implementation Checklist

### Week 1-2: Foundation
- [ ] Create event system (`pkg/events/`, `internal/events/`)
- [ ] Implement integration hub (`internal/integrations/hub/`)
- [ ] Define connector interfaces (`pkg/integrations/`)
- [ ] Add configuration structures

### Week 3-4: Basic Connectors  
- [ ] Implement Splunk connector
- [ ] Implement Slack connector
- [ ] Implement generic webhook connector
- [ ] Add connector factory pattern

### Week 5: Scanner Integration
- [ ] Modify scanner to emit events
- [ ] Update configuration loading
- [ ] Test event emission during scans
- [ ] Add error handling

### Week 6: CLI Commands
- [ ] Add `integrations` command group
- [ ] Implement `list`, `test`, `status` subcommands
- [ ] Add configuration validation
- [ ] Create help documentation

### Week 7: Testing & Docs
- [ ] Write integration tests
- [ ] Add unit tests for connectors
- [ ] Create user documentation
- [ ] Write troubleshooting guide

## 🚀 Quick Commands to Get Started

1. **Add the new files** to your project following the structure above

2. **Update your go.mod** dependencies:
```bash
go mod tidy
```

3. **Test the basic structure**:
```bash
go build ./cmd/typosentinel
```

4. **Create a test configuration**:
```bash
cp config/integrations.example.yaml config/integrations.yaml
# Edit with your actual credentials
```

5. **Test an integration**:
```bash
./typosentinel integrations test slack
```

This plan gives you a working integration system that you can extend with additional connectors (SOAR, vulnerability management, etc.) using the same patterns.