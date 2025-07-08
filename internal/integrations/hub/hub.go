package hub

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/internal/events"
	"github.com/Alivanroy/Typosentinel/pkg/events"
	"github.com/Alivanroy/Typosentinel/pkg/integrations"
	"github.com/Alivanroy/Typosentinel/pkg/logger"
)

// IntegrationHub manages all security tool integrations
type IntegrationHub struct {
	eventBus    *events.EventBus
	config      *config.IntegrationsConfig
	logger      logger.Logger
	connectors  map[string]integrations.Connector
	factory     integrations.ConnectorFactory
	routing     map[events.EventType][]string
	mu          sync.RWMutex
	running     bool
	metrics     *HubMetrics
}

// HubMetrics tracks integration hub performance
type HubMetrics struct {
	TotalEvents     int64
	RoutedEvents    int64
	FailedEvents    int64
	ActiveConnectors int
	mu              sync.RWMutex
}

// NewIntegrationHub creates a new integration hub
func NewIntegrationHub(eventBus *events.EventBus, config *config.IntegrationsConfig, logger logger.Logger) *IntegrationHub {
	return &IntegrationHub{
		eventBus:   eventBus,
		config:     config,
		logger:     logger,
		connectors: make(map[string]integrations.Connector),
		factory:    NewConnectorFactory(logger),
		routing:    make(map[events.EventType][]string),
		metrics:    &HubMetrics{},
	}
}

// Initialize initializes all configured connectors
func (ih *IntegrationHub) Initialize(ctx context.Context) error {
	if ih.config == nil || !ih.config.Enabled {
		ih.logger.Info("Integrations are disabled", nil)
		return nil
	}

	ih.logger.Info("Initializing integration hub", map[string]interface{}{
		"connector_count": len(ih.config.Connectors),
	})

	// Initialize connectors
	for name, connectorConfig := range ih.config.Connectors {
		if !connectorConfig.Enabled {
			ih.logger.Debug("Skipping disabled connector", map[string]interface{}{
				"connector": name,
			})
			continue
		}

		if err := ih.initializeConnector(ctx, name, connectorConfig); err != nil {
			ih.logger.Error("Failed to initialize connector", map[string]interface{}{
				"connector": name,
				"error":     err,
			})
			// Continue with other connectors
			continue
		}
	}

	// Setup event routing
	ih.setupEventRouting()

	// Subscribe to events
	ih.subscribeToEvents()

	ih.mu.Lock()
	ih.running = true
	ih.mu.Unlock()

	ih.logger.Info("Integration hub initialized", map[string]interface{}{
		"active_connectors": len(ih.connectors),
	})

	return nil
}

// initializeConnector initializes a single connector
func (ih *IntegrationHub) initializeConnector(ctx context.Context, name string, config integrations.ConnectorConfig) error {
	connector, err := ih.factory.CreateConnector(config.Type, name, config.Settings)
	if err != nil {
		return fmt.Errorf("failed to create connector: %w", err)
	}

	// Connect to the external system
	connectCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	if err := connector.Connect(connectCtx); err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}

	ih.mu.Lock()
	ih.connectors[name] = connector
	ih.mu.Unlock()

	ih.logger.Info("Connector initialized", map[string]interface{}{
		"connector": name,
		"type":      config.Type,
	})

	return nil
}

// setupEventRouting configures event routing based on configuration
func (ih *IntegrationHub) setupEventRouting() {
	if ih.config.EventRouting == nil {
		return
	}

	for eventTypeStr, connectorNames := range ih.config.EventRouting {
		eventType := events.EventType(eventTypeStr)
		ih.routing[eventType] = connectorNames

		ih.logger.Debug("Event routing configured", map[string]interface{}{
			"event_type":  eventTypeStr,
			"connectors": connectorNames,
		})
	}
}

// subscribeToEvents subscribes the hub to relevant events
func (ih *IntegrationHub) subscribeToEvents() {
	// Subscribe to all event types that have routing configured
	for eventType := range ih.routing {
		ih.eventBus.Subscribe(eventType, ih)
	}

	// If no specific routing, subscribe to all threat detection events
	if len(ih.routing) == 0 {
		ih.eventBus.Subscribe(events.EventTypeThreatDetected, ih)
		ih.eventBus.Subscribe(events.EventTypePackageBlocked, ih)
		ih.eventBus.Subscribe(events.EventTypePolicyViolation, ih)
	}
}

// Handle implements the EventSubscriber interface
func (ih *IntegrationHub) Handle(ctx context.Context, event *events.SecurityEvent) error {
	start := time.Now()

	ih.updateMetrics(func(m *HubMetrics) {
		m.TotalEvents++
	})

	// Get connectors for this event type
	connectorNames := ih.getConnectorsForEvent(event)
	if len(connectorNames) == 0 {
		ih.logger.Debug("No connectors configured for event", map[string]interface{}{
			"event_type": string(event.Type),
			"event_id":   event.ID,
		})
		return nil
	}

	// Route event to connectors concurrently
	var wg sync.WaitGroup
	errorChan := make(chan error, len(connectorNames))

	for _, connectorName := range connectorNames {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			if err := ih.routeToConnector(ctx, event, name); err != nil {
				errorChan <- err
			}
		}(connectorName)
	}

	wg.Wait()
	close(errorChan)

	// Collect any errors
	var errors []error
	for err := range errorChan {
		errors = append(errors, err)
	}

	if len(errors) > 0 {
		ih.updateMetrics(func(m *HubMetrics) {
			m.FailedEvents++
		})

		ih.logger.Error("Failed to route event to some connectors", map[string]interface{}{
			"event_id":    event.ID,
			"error_count": len(errors),
			"latency_ms":  time.Since(start).Milliseconds(),
		})

		// Return first error
		return errors[0]
	}

	ih.updateMetrics(func(m *HubMetrics) {
		m.RoutedEvents++
	})

	ih.logger.Debug("Event routed successfully", map[string]interface{}{
		"event_id":       event.ID,
		"connector_count": len(connectorNames),
		"latency_ms":      time.Since(start).Milliseconds(),
	})

	return nil
}

// getConnectorsForEvent returns the list of connectors that should receive this event
func (ih *IntegrationHub) getConnectorsForEvent(event *events.SecurityEvent) []string {
	// Check specific routing for this event type
	if connectors, exists := ih.routing[event.Type]; exists {
		return ih.filterActiveConnectors(connectors)
	}

	// Default: route to all active connectors
	ih.mu.RLock()
	defer ih.mu.RUnlock()

	var connectorNames []string
	for name := range ih.connectors {
		connectorNames = append(connectorNames, name)
	}

	return connectorNames
}

// filterActiveConnectors filters out inactive connectors
func (ih *IntegrationHub) filterActiveConnectors(connectorNames []string) []string {
	ih.mu.RLock()
	defer ih.mu.RUnlock()

	var activeConnectors []string
	for _, name := range connectorNames {
		if _, exists := ih.connectors[name]; exists {
			activeConnectors = append(activeConnectors, name)
		}
	}

	return activeConnectors
}

// routeToConnector routes an event to a specific connector
func (ih *IntegrationHub) routeToConnector(ctx context.Context, event *events.SecurityEvent, connectorName string) error {
	ih.mu.RLock()
	connector, exists := ih.connectors[connectorName]
	ih.mu.RUnlock()

	if !exists {
		return fmt.Errorf("connector %s not found", connectorName)
	}

	// Apply connector-specific filters if configured
	if ih.config.Filters != nil {
		if filter, exists := ih.config.Filters[connectorName]; exists {
			if !event.MatchesFilter(&filter) {
				ih.logger.Debug("Event filtered out for connector", map[string]interface{}{
					"connector": connectorName,
					"event_id":  event.ID,
				})
				return nil
			}
		}
	}

	// Send event with timeout
	sendCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	if err := connector.Send(sendCtx, event); err != nil {
		return fmt.Errorf("failed to send event to %s: %w", connectorName, err)
	}

	return nil
}

// GetID implements the EventSubscriber interface
func (ih *IntegrationHub) GetID() string {
	return "integration-hub"
}

// GetConnectorStatus returns the status of all connectors
func (ih *IntegrationHub) GetConnectorStatus() map[string]integrations.HealthStatus {
	ih.mu.RLock()
	defer ih.mu.RUnlock()

	status := make(map[string]integrations.HealthStatus)
	for name, connector := range ih.connectors {
		status[name] = connector.Health()
	}

	return status
}

// GetMetrics returns hub metrics
func (ih *IntegrationHub) GetMetrics() HubMetrics {
	ih.metrics.mu.RLock()
	defer ih.metrics.mu.RUnlock()

	metrics := *ih.metrics
	metrics.ActiveConnectors = len(ih.connectors)
	return metrics
}

// updateMetrics safely updates hub metrics
func (ih *IntegrationHub) updateMetrics(updateFn func(*HubMetrics)) {
	ih.metrics.mu.Lock()
	defer ih.metrics.mu.Unlock()
	updateFn(ih.metrics)
}

// Stop gracefully stops the integration hub
func (ih *IntegrationHub) Stop(ctx context.Context) error {
	ih.mu.Lock()
	defer ih.mu.Unlock()

	if !ih.running {
		return nil
	}

	ih.logger.Info("Stopping integration hub", nil)

	// Close all connectors
	for name, connector := range ih.connectors {
		if err := connector.Close(); err != nil {
			ih.logger.Error("Failed to close connector", map[string]interface{}{
				"connector": name,
				"error":     err,
			})
		}
	}

	ih.running = false
	ih.logger.Info("Integration hub stopped", nil)

	return nil
}

// IsRunning returns whether the hub is running
func (ih *IntegrationHub) IsRunning() bool {
	ih.mu.RLock()
	defer ih.mu.RUnlock()
	return ih.running
}