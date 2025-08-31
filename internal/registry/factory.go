package registry

import (
	"fmt"
	"strings"
)

// Factory creates registry connectors based on registry type
type Factory struct {
	supportedRegistries map[string]func(*Registry) Connector
}

// NewFactory creates a new registry factory
func NewFactory() *Factory {
	return &Factory{
		supportedRegistries: map[string]func(*Registry) Connector{
			"npm":      func(r *Registry) Connector { return NewNPMConnector(r) },
			"pypi":     func(r *Registry) Connector { return NewPyPIConnector(r) },
			"maven":    func(r *Registry) Connector { return NewMavenConnector(r) },
			"nuget":    func(r *Registry) Connector { return NewNuGetConnector(r) },
			"rubygems": func(r *Registry) Connector { return NewRubyGemsConnector(r) },
			"composer": func(r *Registry) Connector { return NewComposerConnector(r) },
			"cargo":    func(r *Registry) Connector { return NewCargoConnector(r) },
		},
	}
}

// CreateConnector creates a connector for the specified registry type
func (f *Factory) CreateConnector(registryType string, registry *Registry) (Connector, error) {
	registryType = strings.ToLower(registryType)

	createFunc, exists := f.supportedRegistries[registryType]
	if !exists {
		return nil, fmt.Errorf("unsupported registry type: %s", registryType)
	}

	return createFunc(registry), nil
}

// GetSupportedRegistries returns the list of supported registry types
func (f *Factory) GetSupportedRegistries() []string {
	return []string{
		"npm",
		"pypi",
		"maven",
		"nuget",
		"rubygems",
		"composer",
		"cargo",
	}
}

// RegisterRegistry allows registering custom registry connectors
func (f *Factory) RegisterRegistry(registryType string, createFunc func(*Registry) Connector) {
	f.supportedRegistries[strings.ToLower(registryType)] = createFunc
}

// UnregisterRegistry removes a registry type from the factory
func (f *Factory) UnregisterRegistry(registryType string) {
	delete(f.supportedRegistries, strings.ToLower(registryType))
}

// ValidateRegistryType checks if a registry type is supported
func (f *Factory) ValidateRegistryType(registryType string) bool {
	_, exists := f.supportedRegistries[strings.ToLower(registryType)]
	return exists
}

// CreateConnectorFromType creates a connector with default registry configuration
func (f *Factory) CreateConnectorFromType(registryType string) (Connector, error) {
	registryType = strings.ToLower(registryType)

	// Create default registry configuration based on type
	registry := &Registry{
		Name:    registryType,
		Type:    registryType,
		Enabled: true,
		Timeout: 30,
	}

	// Set default URLs for each registry type
	switch registryType {
	case "npm":
		registry.URL = "https://registry.npmjs.org"
	case "pypi":
		registry.URL = "https://pypi.org"
	case "maven":
		registry.URL = "https://repo1.maven.org/maven2"
	case "nuget":
		registry.URL = "https://api.nuget.org/v3/index.json"
	case "rubygems":
		registry.URL = "https://rubygems.org"
	case "composer":
		registry.URL = "https://packagist.org"
	case "cargo":
		registry.URL = "https://crates.io"
	default:
		return nil, fmt.Errorf("unsupported registry type: %s", registryType)
	}

	return f.CreateConnector(registryType, registry)
}
