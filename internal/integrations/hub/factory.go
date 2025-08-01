package hub

import (
	"fmt"

	"github.com/Alivanroy/Typosentinel/internal/integrations/connectors"
	"github.com/Alivanroy/Typosentinel/pkg/integrations"
	"github.com/Alivanroy/Typosentinel/pkg/logger"
)

// ConnectorFactory implements the integrations.ConnectorFactory interface
type ConnectorFactory struct {
	logger logger.Logger
}

// NewConnectorFactory creates a new connector factory
func NewConnectorFactory(logger logger.Logger) *ConnectorFactory {
	return &ConnectorFactory{
		logger: logger,
	}
}

// CreateConnector creates a connector based on type and configuration
func (cf *ConnectorFactory) CreateConnector(connectorType, name string, settings map[string]interface{}) (integrations.Connector, error) {
	switch connectorType {
	case "splunk":
		return connectors.NewSplunkConnector(name, settings, cf.logger)

	case "elasticsearch":
		return connectors.NewElasticsearchConnector(name, settings, cf.logger)

	case "qradar":
		return connectors.NewQRadarConnector(name, settings, cf.logger)

	case "slack":
		return connectors.NewSlackConnector(name, settings, cf.logger)

	case "webhook":
		return connectors.NewWebhookConnector(name, settings, cf.logger)

	case "email":
		return connectors.NewEmailConnector(name, settings, cf.logger)

	default:
		return nil, fmt.Errorf("unsupported connector type: %s", connectorType)
	}
}

// GetSupportedTypes returns the list of supported connector types
func (cf *ConnectorFactory) GetSupportedTypes() []string {
	return []string{
		"splunk",
		"elasticsearch",
		"qradar",
		"slack",
		"webhook",
		"email",
	}
}