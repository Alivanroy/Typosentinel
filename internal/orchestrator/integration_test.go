package orchestrator

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSIEMClient_NewSIEMClient(t *testing.T) {
	tests := []struct {
		name   string
		config *SIEMConfig
		want   *SIEMClient
	}{
		{
			name: "default configuration",
			config: &SIEMConfig{
				Enabled:  true,
				Type:     "splunk",
				Endpoint: "http://localhost:8088",
				APIKey:   "test-key",
			},
		},
		{
			name: "custom configuration",
			config: &SIEMConfig{
				Enabled:       true,
				Type:          "elastic",
				Endpoint:      "http://localhost:9200",
				APIKey:        "test-key",
				BatchSize:     50,
				StreamingMode: true,
				Timeout:       10 * time.Second,
				RetryConfig: &SIEMRetryConfig{
					MaxRetries:    5,
					InitialDelay:  2 * time.Second,
					MaxDelay:      60 * time.Second,
					BackoffFactor: 1.5,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := NewSIEMClient(tt.config)
			require.NotNil(t, client)
			assert.Equal(t, tt.config.Type, client.config.Type)
			assert.Equal(t, tt.config.Endpoint, client.config.Endpoint)
			assert.Equal(t, tt.config.APIKey, client.config.APIKey)

			// Check default values
			if tt.config.Timeout == 0 {
				assert.Equal(t, 30*time.Second, client.config.Timeout)
			}
			if tt.config.BatchSize == 0 {
				assert.Equal(t, 100, client.config.BatchSize)
			}
			if tt.config.RetryConfig == nil {
				require.NotNil(t, client.config.RetryConfig)
				assert.Equal(t, 3, client.config.RetryConfig.MaxRetries)
			}

			// Cleanup
			client.Close()
		})
	}
}

func TestSIEMClient_SendEvent_Synchronous(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		assert.Equal(t, "Splunk test-key", r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := &SIEMConfig{
		Enabled:       true,
		Type:          "splunk",
		Endpoint:      server.URL,
		APIKey:        "test-key",
		StreamingMode: false, // Synchronous mode
	}

	client := NewSIEMClient(config)
	defer client.Close()

	event := &IntegrationEvent{
		Type:        "vulnerability_detected",
		Timestamp:   time.Now(),
		Severity:    "high",
		Source:      "typosentinel",
		Repository:  "test-repo",
		ScanID:      "scan-123",
		Message:     "Test vulnerability detected",
		ThreatCount: 5,
		RiskScore:   8.5,
	}

	err := client.SendEvent(context.Background(), event)
	assert.NoError(t, err)

	// Check metrics
	metrics := client.GetMetrics()
	assert.Equal(t, int64(1), metrics.EventsSent)
	assert.Equal(t, int64(0), metrics.EventsDropped)
}

func TestSIEMClient_SendEvent_Streaming(t *testing.T) {
	eventReceived := make(chan bool, 1)

	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		w.WriteHeader(http.StatusOK)
		eventReceived <- true
	}))
	defer server.Close()

	config := &SIEMConfig{
		Enabled:       true,
		Type:          "splunk",
		Endpoint:      server.URL,
		APIKey:        "test-key",
		BatchSize:     1, // Small batch for immediate processing
		StreamingMode: true,
	}

	client := NewSIEMClient(config)
	defer client.Close()

	event := &IntegrationEvent{
		Type:        "vulnerability_detected",
		Timestamp:   time.Now(),
		Severity:    "high",
		Source:      "typosentinel",
		Repository:  "test-repo",
		Message:     "Test vulnerability detected",
		ThreatCount: 3,
		RiskScore:   7.2,
	}

	err := client.SendEvent(context.Background(), event)
	assert.NoError(t, err)

	// Wait for event to be processed
	select {
	case <-eventReceived:
		// Success
	case <-time.After(5 * time.Second):
		t.Fatal("Event was not processed within timeout")
	}
}

func TestSIEMClient_RetryLogic(t *testing.T) {
	attempts := 0

	// Create a test server that fails initially
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := &SIEMConfig{
		Enabled:       true,
		Type:          "splunk",
		Endpoint:      server.URL,
		APIKey:        "test-key",
		StreamingMode: false,
		RetryConfig: &SIEMRetryConfig{
			MaxRetries:    3,
			InitialDelay:  100 * time.Millisecond,
			MaxDelay:      1 * time.Second,
			BackoffFactor: 2.0,
			RetryOnStatus: []int{500, 502, 503, 504},
		},
	}

	client := NewSIEMClient(config)
	defer client.Close()

	event := &IntegrationEvent{
		Type:      "test_event",
		Timestamp: time.Now(),
		Severity:  "medium",
		Source:    "typosentinel",
		Message:   "Test retry logic",
	}

	err := client.SendEvent(context.Background(), event)
	assert.NoError(t, err)
	assert.Equal(t, 3, attempts)

	// Check retry metrics
	metrics := client.GetMetrics()
	assert.Equal(t, int64(1), metrics.EventsSent)
	assert.Equal(t, int64(2), metrics.RetryAttempts) // 2 retries before success
}

func TestSIEMClient_CustomFormatting(t *testing.T) {
	tests := []struct {
		name         string
		siemType     string
		customFormat map[string]interface{}
		expectedKeys []string
	}{
		{
			name:     "splunk formatting",
			siemType: "splunk",
			expectedKeys: []string{"time", "host", "source", "sourcetype", "event"},
		},
		{
			name:     "elasticsearch formatting",
			siemType: "elasticsearch",
			expectedKeys: []string{"@timestamp", "event_type", "severity", "source", "message"},
		},
		{
			name:     "qradar formatting",
			siemType: "qradar",
			expectedKeys: []string{"StartTime", "EventName", "Severity", "SourceIP", "EventCategory"},
		},
		{
			name:     "custom formatting",
			siemType: "custom",
			customFormat: map[string]interface{}{
				"custom_type":      "type",
				"custom_timestamp": "timestamp",
				"custom_severity":  "severity",
				"static_field":     "static_value",
			},
			expectedKeys: []string{"custom_type", "custom_timestamp", "custom_severity", "static_field"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &SIEMConfig{
				Enabled:      true,
				Type:         tt.siemType,
				Endpoint:     "http://localhost:8088",
				APIKey:       "test-key",
				CustomFormat: tt.customFormat,
			}

			client := NewSIEMClient(config)
			defer client.Close()

			event := &IntegrationEvent{
				Type:        "test_event",
				Timestamp:   time.Now(),
				Severity:    "high",
				Source:      "typosentinel",
				Repository:  "test-repo",
				Message:     "Test formatting",
				ThreatCount: 2,
				RiskScore:   6.5,
			}

			formattedEvent := client.formatEvent(event)
			require.NotNil(t, formattedEvent)

			// Convert to map for easier testing
			var eventMap map[string]interface{}
			eventData, err := json.Marshal(formattedEvent)
			require.NoError(t, err)
			err = json.Unmarshal(eventData, &eventMap)
			require.NoError(t, err)

			// Check expected keys exist
			for _, key := range tt.expectedKeys {
				assert.Contains(t, eventMap, key, "Expected key %s not found in formatted event", key)
			}
		})
	}
}

func TestSIEMClient_ErrorHandling(t *testing.T) {
	tests := []struct {
		name           string
		statusCode     int
		expectRetry    bool
		expectError    bool
	}{
		{
			name:        "success",
			statusCode:  200,
			expectRetry: false,
			expectError: false,
		},
		{
			name:        "client error - no retry",
			statusCode:  400,
			expectRetry: false,
			expectError: true,
		},
		{
			name:        "rate limit - retry",
			statusCode:  429,
			expectRetry: true,
			expectError: true,
		},
		{
			name:        "server error - retry",
			statusCode:  500,
			expectRetry: true,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test server that returns the specified status code
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				w.Write([]byte("test error message"))
			}))
			defer server.Close()

			config := &SIEMConfig{
				Enabled:       true,
				Type:          "splunk",
				Endpoint:      server.URL,
				APIKey:        "test-key",
				StreamingMode: false,
				RetryConfig: &SIEMRetryConfig{
					MaxRetries:    1, // Limit retries for faster testing
					InitialDelay:  10 * time.Millisecond,
					MaxDelay:      100 * time.Millisecond,
					BackoffFactor: 2.0,
					RetryOnStatus: []int{429, 500, 502, 503, 504},
				},
			}

			client := NewSIEMClient(config)
			defer client.Close()

			event := &IntegrationEvent{
				Type:      "test_event",
				Timestamp: time.Now(),
				Severity:  "medium",
				Source:    "typosentinel",
				Message:   "Test error handling",
			}

			err := client.SendEvent(context.Background(), event)

			if tt.expectError {
				assert.Error(t, err)
				if siemErr, ok := err.(*SIEMError); ok {
					assert.Equal(t, tt.statusCode, siemErr.StatusCode)
					assert.Equal(t, tt.expectRetry, siemErr.Retryable)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestSIEMClient_BatchProcessing(t *testing.T) {
	batchReceived := make(chan []byte, 1)

	// Create a test server that captures batch data
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, r.ContentLength)
		r.Body.Read(body)
		batchReceived <- body
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := &SIEMConfig{
		Enabled:       true,
		Type:          "splunk",
		Endpoint:      server.URL,
		APIKey:        "test-key",
		BatchSize:     2,
		StreamingMode: true,
	}

	client := NewSIEMClient(config)
	defer client.Close()

	// Send multiple events
	for i := 0; i < 2; i++ {
		event := &IntegrationEvent{
			Type:      "test_event",
			Timestamp: time.Now(),
			Severity:  "low",
			Source:    "typosentinel",
			Message:   "Batch test event",
		}
		err := client.SendEvent(context.Background(), event)
		assert.NoError(t, err)
	}

	// Wait for batch to be processed
	select {
	case batchData := <-batchReceived:
		// Verify batch contains multiple events
		batchStr := string(batchData)
		assert.True(t, strings.Contains(batchStr, "test_event"))
		// Should contain newline separators for Splunk batch format
		assert.True(t, strings.Contains(batchStr, "\n"))
	case <-time.After(5 * time.Second):
		t.Fatal("Batch was not processed within timeout")
	}
}

func TestSIEMClient_Metrics(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := &SIEMConfig{
		Enabled:       true,
		Type:          "splunk",
		Endpoint:      server.URL,
		APIKey:        "test-key",
		StreamingMode: false,
	}

	client := NewSIEMClient(config)
	defer client.Close()

	// Initial metrics should be zero
	metrics := client.GetMetrics()
	assert.Equal(t, int64(0), metrics.EventsSent)
	assert.Equal(t, int64(0), metrics.EventsDropped)
	assert.Equal(t, int64(0), metrics.RetryAttempts)

	// Send an event
	event := &IntegrationEvent{
		Type:      "test_event",
		Timestamp: time.Now(),
		Severity:  "medium",
		Source:    "typosentinel",
		Message:   "Metrics test",
	}

	err := client.SendEvent(context.Background(), event)
	assert.NoError(t, err)

	// Check updated metrics
	metrics = client.GetMetrics()
	assert.Equal(t, int64(1), metrics.EventsSent)
	assert.True(t, !metrics.LastEventTime.IsZero())
}

func TestSIEMClient_QueueOverflow(t *testing.T) {
	// Create a slow server to cause queue backup
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := &SIEMConfig{
		Enabled:       true,
		Type:          "splunk",
		Endpoint:      server.URL,
		APIKey:        "test-key",
		BatchSize:     2, // Small batch size
		StreamingMode: true,
	}

	client := NewSIEMClient(config)
	defer client.Close()

	// Fill up the queue beyond capacity
	queueCapacity := config.BatchSize * 2
	for i := 0; i < queueCapacity+5; i++ {
		event := &IntegrationEvent{
			Type:      "test_event",
			Timestamp: time.Now(),
			Severity:  "low",
			Source:    "typosentinel",
			Message:   "Queue overflow test",
		}
		client.SendEvent(context.Background(), event)
	}

	// Wait a bit for processing
	time.Sleep(200 * time.Millisecond)

	// Check that some events were dropped
	metrics := client.GetMetrics()
	assert.True(t, metrics.EventsDropped > 0, "Expected some events to be dropped due to queue overflow")
}