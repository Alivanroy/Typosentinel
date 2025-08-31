package integrations

import (
	"context"
	"time"

	"github.com/Alivanroy/Typosentinel/pkg/events"
)

// Connector defines the interface for security tool integrations
type Connector interface {
	// Connect establishes connection to the external system
	Connect(ctx context.Context) error

	// Send sends a security event to the external system
	Send(ctx context.Context, event *events.SecurityEvent) error

	// Health returns the current health status of the connector
	Health() HealthStatus

	// Close closes the connection and cleans up resources
	Close() error

	// GetName returns the connector's name
	GetName() string

	// GetType returns the connector's type
	GetType() string
}

// HealthStatus represents the health status of a connector
type HealthStatus struct {
	Healthy     bool          `json:"healthy"`
	LastCheck   time.Time     `json:"last_check"`
	Latency     time.Duration `json:"latency"`
	EventsSent  int64         `json:"events_sent"`
	ErrorCount  int64         `json:"error_count"`
	LastError   string        `json:"last_error,omitempty"`
	ConnectedAt time.Time     `json:"connected_at,omitempty"`
}

// ConnectorFactory creates connectors based on type and configuration
type ConnectorFactory interface {
	CreateConnector(connectorType, name string, settings map[string]interface{}) (Connector, error)
	GetSupportedTypes() []string
}

// ConnectorConfig represents the configuration for a connector
type ConnectorConfig struct {
	Type     string                 `mapstructure:"type" json:"type"`
	Enabled  bool                   `mapstructure:"enabled" json:"enabled"`
	Settings map[string]interface{} `mapstructure:"settings" json:"settings"`
	Filters  *events.EventFilter    `mapstructure:"filters" json:"filters,omitempty"`
	Retry    *RetryConfig           `mapstructure:"retry" json:"retry,omitempty"`
}

// RetryConfig defines retry behavior for failed deliveries
type RetryConfig struct {
	MaxAttempts   int           `mapstructure:"max_attempts" json:"max_attempts"`
	InitialDelay  time.Duration `mapstructure:"initial_delay" json:"initial_delay"`
	MaxDelay      time.Duration `mapstructure:"max_delay" json:"max_delay"`
	BackoffFactor float64       `mapstructure:"backoff_factor" json:"backoff_factor"`
}

// DefaultRetryConfig returns a default retry configuration
func DefaultRetryConfig() *RetryConfig {
	return &RetryConfig{
		MaxAttempts:   3,
		InitialDelay:  1 * time.Second,
		MaxDelay:      30 * time.Second,
		BackoffFactor: 2.0,
	}
}

// ConnectorMetrics tracks performance metrics for a connector
type ConnectorMetrics struct {
	EventsSent       int64         `json:"events_sent"`
	EventsSucceeded  int64         `json:"events_succeeded"`
	EventsFailed     int64         `json:"events_failed"`
	AverageLatency   time.Duration `json:"average_latency"`
	LastEventTime    time.Time     `json:"last_event_time"`
	ConnectionUptime time.Duration `json:"connection_uptime"`
}

// ValidationError represents a configuration validation error
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

func (e ValidationError) Error() string {
	return e.Message
}

// ConnectorError represents an error from a connector operation
type ConnectorError struct {
	ConnectorName string `json:"connector_name"`
	Operation     string `json:"operation"`
	Message       string `json:"message"`
	Retryable     bool   `json:"retryable"`
}

func (e ConnectorError) Error() string {
	return e.Message
}

// NewConnectorError creates a new connector error
func NewConnectorError(connectorName, operation, message string, retryable bool) *ConnectorError {
	return &ConnectorError{
		ConnectorName: connectorName,
		Operation:     operation,
		Message:       message,
		Retryable:     retryable,
	}
}
