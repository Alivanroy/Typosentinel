package registry

import (
	"context"
	"fmt"
	"typosentinel/pkg/types"
)

// Connector interface for connecting to package registries
type Connector interface {
	Connect(ctx context.Context) error
	GetPackageInfo(ctx context.Context, name, version string) (*types.PackageMetadata, error)
	SearchPackages(ctx context.Context, query string) ([]*types.PackageMetadata, error)
	GetRegistryType() string
	Close() error
}

// Registry represents a package registry
type Registry struct {
	Name     string
	URL      string
	Type     string
	Enabled  bool
	APIKey   string
	Timeout  int
}

// NPMConnector implements Connector for NPM registry
type NPMConnector struct {
	registry *Registry
}

// NewNPMConnector creates a new NPM connector
func NewNPMConnector(registry *Registry) *NPMConnector {
	return &NPMConnector{
		registry: registry,
	}
}

// Connect establishes connection to NPM registry
func (n *NPMConnector) Connect(ctx context.Context) error {
	// Implementation would go here
	return nil
}

// GetPackageInfo retrieves package information from NPM
func (n *NPMConnector) GetPackageInfo(ctx context.Context, name, version string) (*types.PackageMetadata, error) {
	// Implementation would go here
	return &types.PackageMetadata{
		Name:     name,
		Version:  version,
		Registry: "npm",
	}, nil
}

// SearchPackages searches for packages in NPM registry
func (n *NPMConnector) SearchPackages(ctx context.Context, query string) ([]*types.PackageMetadata, error) {
	// Implementation would go here
	return []*types.PackageMetadata{}, nil
}

// GetRegistryType returns the registry type
func (n *NPMConnector) GetRegistryType() string {
	return "npm"
}

// Close closes the connection
func (n *NPMConnector) Close() error {
	return nil
}

// PyPIConnector implements Connector for PyPI registry
type PyPIConnector struct {
	registry *Registry
}

// NewPyPIConnector creates a new PyPI connector
func NewPyPIConnector(registry *Registry) *PyPIConnector {
	return &PyPIConnector{
		registry: registry,
	}
}

// Connect establishes connection to PyPI registry
func (p *PyPIConnector) Connect(ctx context.Context) error {
	return nil
}

// GetPackageInfo retrieves package information from PyPI
func (p *PyPIConnector) GetPackageInfo(ctx context.Context, name, version string) (*types.PackageMetadata, error) {
	return &types.PackageMetadata{
		Name:     name,
		Version:  version,
		Registry: "pypi",
	}, nil
}

// SearchPackages searches for packages in PyPI registry
func (p *PyPIConnector) SearchPackages(ctx context.Context, query string) ([]*types.PackageMetadata, error) {
	return []*types.PackageMetadata{}, nil
}

// GetRegistryType returns the registry type
func (p *PyPIConnector) GetRegistryType() string {
	return "pypi"
}

// Close closes the connection
func (p *PyPIConnector) Close() error {
	return nil
}

// Manager manages multiple registry connectors
type Manager struct {
	connectors map[string]Connector
}

// NewManager creates a new registry manager
func NewManager() *Manager {
	return &Manager{
		connectors: make(map[string]Connector),
	}
}

// AddConnector adds a connector to the manager
func (m *Manager) AddConnector(name string, connector Connector) {
	m.connectors[name] = connector
}

// GetConnector retrieves a connector by name
func (m *Manager) GetConnector(name string) (Connector, error) {
	connector, exists := m.connectors[name]
	if !exists {
		return nil, fmt.Errorf("connector %s not found", name)
	}
	return connector, nil
}

// GetAllConnectors returns all registered connectors
func (m *Manager) GetAllConnectors() map[string]Connector {
	return m.connectors
}

// Close closes all connectors
func (m *Manager) Close() error {
	for _, connector := range m.connectors {
		if err := connector.Close(); err != nil {
			return err
		}
	}
	return nil
}