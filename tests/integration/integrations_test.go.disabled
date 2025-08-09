package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/internal/events"
	"github.com/Alivanroy/Typosentinel/internal/integrations/connectors"
	"github.com/Alivanroy/Typosentinel/internal/integrations/hub"
	pkgevents "github.com/Alivanroy/Typosentinel/pkg/events"
	"github.com/Alivanroy/Typosentinel/pkg/integrations"
)

func TestSlackConnectorIntegration(t *testing.T) {
	tests := []struct {
		name           string
		event          *pkgevents.SecurityEvent
		expectedFields []string
		expectedColor  string
	}{
		{
			name: "high_severity_malware_detection",
			event: &pkgevents.SecurityEvent{
				ID:        "test-001",
				Type:      pkgevents.EventTypeThreatDetected,
				Severity:  pkgevents.SeverityHigh,
				Timestamp: time.Now(),
				Package: pkgevents.PackageInfo{
					Name:     "malicious-package",
					Version:  "1.0.0",
					Registry: "npm",
					Path:     "/project/package.json",
				},
				Threat: pkgevents.ThreatInfo{
					Type:        "malicious",
					Description: "Package contains malicious code",
					RiskScore:   0.95,
					Confidence:  0.9,
					Evidence:    map[string]interface{}{"suspicious_files": []string{"backdoor.js"}},
				},
				Metadata: pkgevents.EventMetadata{
					DetectionMethod: "ml_analysis",
					ProjectPath:     "/test/project",
					ScanID:          "scan-001",
				},
			},
			expectedFields: []string{"Package", "Threat Type", "Risk Score", "Detection Method"},
			expectedColor:  "warning",
		},
		{
			name: "medium_severity_typosquatting",
			event: &pkgevents.SecurityEvent{
				ID:        "test-002",
				Type:      pkgevents.EventTypeThreatDetected,
				Severity:  pkgevents.SeverityMedium,
				Timestamp: time.Now(),
				Package: pkgevents.PackageInfo{
					Name:     "expres", // typosquatting of "express"
					Version:  "4.18.0",
					Registry: "npm",
					Path:     "/project/package.json",
				},
				Threat: pkgevents.ThreatInfo{
					Type:        "typosquatting",
					Description: "Potential typosquatting of popular package 'express'",
					RiskScore:   0.7,
					Confidence:  0.8,
					Evidence:    map[string]interface{}{"similar_package": "express", "edit_distance": 1},
				},
				Metadata: pkgevents.EventMetadata{
					DetectionMethod: "name_similarity",
					ProjectPath:     "/test/project",
					ScanID:          "scan-002",
				},
			},
			expectedFields: []string{"Package", "Threat Type", "Risk Score", "Detection Method"},
			expectedColor:  "good",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock Slack server
			var receivedPayload map[string]interface{}
			var mu sync.Mutex

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()

				assert.Equal(t, "POST", r.Method)
				assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

				var payload map[string]interface{}
				err := json.NewDecoder(r.Body).Decode(&payload)
				require.NoError(t, err)

				receivedPayload = payload
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("ok"))
			}))
			defer server.Close()

			// Create Slack connector
			config := map[string]interface{}{
				"webhook_url": server.URL,
				"channel":     "#security-alerts",
				"username":    "TypoSentinel",
				"icon_emoji":  ":shield:",
				"color_mapping": map[string]interface{}{
					"critical": "danger",
					"high":     "warning",
					"medium":   "good",
					"low":      "#439FE0",
				},
			}

			connector, err := connectors.NewSlackConnector(config)
			require.NoError(t, err)

			// Connect and send event
			err = connector.Connect()
			require.NoError(t, err)

			err = connector.SendEvent(tt.event)
			require.NoError(t, err)

			// Wait for request to be processed
			time.Sleep(100 * time.Millisecond)

			// Verify payload
			mu.Lock()
			defer mu.Unlock()

			require.NotNil(t, receivedPayload)
			assert.Equal(t, "#security-alerts", receivedPayload["channel"])
			assert.Equal(t, "TypoSentinel", receivedPayload["username"])
			assert.Equal(t, ":shield:", receivedPayload["icon_emoji"])

			// Check attachments
			attachments, ok := receivedPayload["attachments"].([]interface{})
			require.True(t, ok)
			require.Len(t, attachments, 1)

			attachment := attachments[0].(map[string]interface{})
			assert.Equal(t, tt.expectedColor, attachment["color"])
			assert.Contains(t, attachment["title"], "Security Threat Detected")

			// Check fields
			fields, ok := attachment["fields"].([]interface{})
			require.True(t, ok)

			fieldTitles := make([]string, len(fields))
			for i, field := range fields {
				fieldMap := field.(map[string]interface{})
				fieldTitles[i] = fieldMap["title"].(string)
			}

			for _, expectedField := range tt.expectedFields {
				assert.Contains(t, fieldTitles, expectedField)
			}

			// Test health check
			status := connector.HealthCheck()
			assert.Equal(t, integrations.HealthStatusHealthy, status.Status)

			// Clean up
			connector.Close()
		})
	}
}

func TestEventBusIntegration(t *testing.T) {
	// Create event bus
	eventBus := events.NewEventBus()
	require.NotNil(t, eventBus)

	// Start the bus
	err := eventBus.Start()
	require.NoError(t, err)
	defer eventBus.Stop()

	// Test event subscription and publishing
	t.Run("event_subscription_and_publishing", func(t *testing.T) {
		var receivedEvents []*pkgevents.SecurityEvent
		var mu sync.Mutex

		// Create subscriber
		subscriber := &testEventSubscriber{
			onEvent: func(event *pkgevents.SecurityEvent) {
				mu.Lock()
				defer mu.Unlock()
				receivedEvents = append(receivedEvents, event)
			},
		}

		// Subscribe to events
		subscriptionID := eventBus.Subscribe(subscriber)
		require.NotEmpty(t, subscriptionID)

		// Create test events
		events := []*pkgevents.SecurityEvent{
			{
				ID:        "event-1",
				Type:      pkgevents.EventTypeThreatDetected,
				Severity:  pkgevents.SeverityHigh,
				Timestamp: time.Now(),
				Package: pkgevents.PackageInfo{
					Name:     "test-package-1",
					Version:  "1.0.0",
					Registry: "npm",
				},
				Threat: pkgevents.ThreatInfo{
					Type:        "malicious",
					Description: "Test threat 1",
					RiskScore:   0.9,
					Confidence:  0.8,
				},
			},
			{
				ID:        "event-2",
				Type:      pkgevents.EventTypeScanCompleted,
				Severity:  pkgevents.SeverityLow,
				Timestamp: time.Now(),
				Package: pkgevents.PackageInfo{
					Name:     "test-package-2",
					Version:  "2.0.0",
					Registry: "pypi",
				},
			},
		}

		// Publish events
		for _, event := range events {
			err := eventBus.Publish(event)
			require.NoError(t, err)
		}

		// Wait for events to be processed
		time.Sleep(200 * time.Millisecond)

		// Verify received events
		mu.Lock()
		defer mu.Unlock()

		assert.Len(t, receivedEvents, 2)
		assert.Equal(t, "event-1", receivedEvents[0].ID)
		assert.Equal(t, "event-2", receivedEvents[1].ID)

		// Unsubscribe
		eventBus.Unsubscribe(subscriptionID)

		// Publish another event (should not be received)
		err = eventBus.Publish(&pkgevents.SecurityEvent{
			ID:   "event-3",
			Type: pkgevents.EventTypeThreatDetected,
		})
		require.NoError(t, err)

		time.Sleep(100 * time.Millisecond)

		// Should still have only 2 events
		mu.Lock()
		assert.Len(t, receivedEvents, 2)
		mu.Unlock()
	})

	// Test event filtering
	t.Run("event_filtering", func(t *testing.T) {
		var receivedEvents []*pkgevents.SecurityEvent
		var mu sync.Mutex

		// Create subscriber with filter
		subscriber := &testEventSubscriber{
			onEvent: func(event *pkgevents.SecurityEvent) {
				mu.Lock()
				defer mu.Unlock()
				receivedEvents = append(receivedEvents, event)
			},
		}

		// Subscribe with high severity filter
		filter := &pkgevents.EventFilter{
			Severities: []pkgevents.Severity{pkgevents.SeverityHigh, pkgevents.SeverityCritical},
		}

		subscriptionID := eventBus.Subscribe(subscriber)
		eventBus.SetFilter(subscriptionID, filter)

		// Publish events with different severities
		testEvents := []*pkgevents.SecurityEvent{
			{ID: "high-event", Severity: pkgevents.SeverityHigh, Type: pkgevents.EventTypeThreatDetected},
			{ID: "low-event", Severity: pkgevents.SeverityLow, Type: pkgevents.EventTypeThreatDetected},
			{ID: "critical-event", Severity: pkgevents.SeverityCritical, Type: pkgevents.EventTypeThreatDetected},
			{ID: "medium-event", Severity: pkgevents.SeverityMedium, Type: pkgevents.EventTypeThreatDetected},
		}

		for _, event := range testEvents {
			err := eventBus.Publish(event)
			require.NoError(t, err)
		}

		time.Sleep(200 * time.Millisecond)

		// Should only receive high and critical severity events
		mu.Lock()
		defer mu.Unlock()

		assert.Len(t, receivedEvents, 2)
		receivedIDs := []string{receivedEvents[0].ID, receivedEvents[1].ID}
		assert.Contains(t, receivedIDs, "high-event")
		assert.Contains(t, receivedIDs, "critical-event")

		eventBus.Unsubscribe(subscriptionID)
	})
}

func TestIntegrationHubIntegration(t *testing.T) {
	// Create mock webhook server
	var receivedEvents []*pkgevents.SecurityEvent
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()

		var event pkgevents.SecurityEvent
		err := json.NewDecoder(r.Body).Decode(&event)
		if err == nil {
			receivedEvents = append(receivedEvents, &event)
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer server.Close()

	// Create integration configuration
	integrationsConfig := &config.IntegrationsConfig{
		Enabled: true,
		Connectors: map[string]config.ConnectorConfig{
			"test-webhook": {
				Type:    "webhook",
				Enabled: true,
				Settings: map[string]interface{}{
					"url":    server.URL,
					"method": "POST",
					"headers": map[string]interface{}{
						"Content-Type": "application/json",
					},
					"timeout": 10,
				},
				Retry: config.RetryConfig{
					Enabled:       true,
					MaxAttempts:   3,
					InitialDelay:  time.Second,
					MaxDelay:      time.Minute,
					BackoffFactor: 2.0,
				},
			},
		},
	}

	// Create event bus and integration hub
	eventBus := events.NewEventBus()
	integrationHub := hub.NewIntegrationHub(eventBus, integrationsConfig)

	// Start components
	err := eventBus.Start()
	require.NoError(t, err)
	defer eventBus.Stop()

	err = integrationHub.Initialize()
	require.NoError(t, err)
	defer integrationHub.Stop()

	// Wait for initialization
	time.Sleep(100 * time.Millisecond)

	// Publish test event
	testEvent := &pkgevents.SecurityEvent{
		ID:        "integration-test-event",
		Type:      pkgevents.EventTypeThreatDetected,
		Severity:  pkgevents.SeverityHigh,
		Timestamp: time.Now(),
		Package: pkgevents.PackageInfo{
			Name:     "malicious-package",
			Version:  "1.0.0",
			Registry: "npm",
		},
		Threat: pkgevents.ThreatInfo{
			Type:        "malicious",
			Description: "Integration test threat",
			RiskScore:   0.9,
			Confidence:  0.8,
		},
		Metadata: pkgevents.EventMetadata{
			DetectionMethod: "integration_test",
			ProjectPath:     "/test/project",
			ScanID:          "integration-scan-001",
		},
	}

	err = eventBus.Publish(testEvent)
	require.NoError(t, err)

	// Wait for event to be processed
	time.Sleep(500 * time.Millisecond)

	// Verify event was received by webhook
	mu.Lock()
	defer mu.Unlock()

	assert.Len(t, receivedEvents, 1)
	assert.Equal(t, "integration-test-event", receivedEvents[0].ID)
	assert.Equal(t, "malicious-package", receivedEvents[0].Package.Name)

	// Test connector health
	status := integrationHub.GetConnectorHealth("test-webhook")
	assert.Equal(t, integrations.HealthStatusHealthy, status.Status)

	// Test metrics
	metrics := integrationHub.GetMetrics()
	assert.Equal(t, int64(1), metrics.EventsProcessed)
	assert.Equal(t, int64(1), metrics.ActiveConnectors)
}

// testEventSubscriber implements the EventSubscriber interface for testing
type testEventSubscriber struct {
	onEvent func(*pkgevents.SecurityEvent)
}

func (s *testEventSubscriber) OnEvent(ctx context.Context, event *pkgevents.SecurityEvent) error {
	if s.onEvent != nil {
		s.onEvent(event)
	}
	return nil
}

func (s *testEventSubscriber) ID() string {
	return "test-subscriber"
}