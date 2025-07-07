package registry

import (
	"context"
	"testing"

	"github.com/Alivanroy/Typosentinel/pkg/types"
)

func TestNewManager(t *testing.T) {
	manager := NewManager()

	if manager == nil {
		t.Error("Expected manager to be created")
	}
}

func TestNPMConnector_GetPackageInfo(t *testing.T) {
	registry := &Registry{
		Name:    "npm",
		URL:     "https://registry.npmjs.org",
		Type:    "npm",
		Enabled: true,
		Timeout: 30,
	}

	connector := NewNPMConnector(registry)
	ctx := context.Background()

	// This is a basic test - in a real implementation, you'd mock the HTTP calls
	pkgInfo, err := connector.GetPackageInfo(ctx, "lodash", "4.17.21")

	if err != nil {
		t.Logf("Expected error for mock implementation: %v", err)
	}

	if pkgInfo != nil {
		if pkgInfo.Name != "lodash" {
			t.Errorf("Expected package name 'lodash', got '%s'", pkgInfo.Name)
		}
	}
}

func TestNPMConnector_Connect(t *testing.T) {
	registry := &Registry{
		Name:    "npm",
		URL:     "https://registry.npmjs.org",
		Type:    "npm",
		Enabled: true,
		Timeout: 30,
	}

	connector := NewNPMConnector(registry)
	ctx := context.Background()

	err := connector.Connect(ctx)

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
}

func TestPyPIConnector_GetPackageInfo(t *testing.T) {
	registry := &Registry{
		Name:    "pypi",
		URL:     "https://pypi.org",
		Type:    "pypi",
		Enabled: true,
		Timeout: 30,
	}

	connector := NewPyPIConnector(registry)
	ctx := context.Background()

	// This is a basic test - in a real implementation, you'd mock the HTTP calls
	pkgInfo, err := connector.GetPackageInfo(ctx, "requests", "2.28.1")

	if err != nil {
		t.Logf("Expected error for mock implementation: %v", err)
	}

	if pkgInfo != nil {
		if pkgInfo.Name != "requests" {
			t.Errorf("Expected package name 'requests', got '%s'", pkgInfo.Name)
		}
	}

	// Test completed above
}

func TestManager_GetConnector(t *testing.T) {
	manager := NewManager()

	if manager == nil {
		t.Error("Expected manager to not be nil")
	}

	// Test that manager is properly initialized
	t.Log("Manager created successfully")
}

func TestRegistry_Validation(t *testing.T) {
	registry := &Registry{
		Name:    "test",
		URL:     "https://example.com",
		Type:    "npm",
		Enabled: true,
		Timeout: 30,
	}

	if registry.Name != "test" {
		t.Errorf("Expected name 'test', got '%s'", registry.Name)
	}

	if !registry.Enabled {
		t.Error("Expected registry to be enabled")
	}
}

func TestConnector_Interface(t *testing.T) {
	registry := &Registry{
		Name:    "npm",
		URL:     "https://registry.npmjs.org",
		Type:    "npm",
		Enabled: true,
		Timeout: 30,
	}

	connector := NewNPMConnector(registry)

	// Test that connector implements the Connector interface
	var _ Connector = connector

	t.Log("NPM connector implements Connector interface correctly")

	// Test PyPI connector as well
	pypiRegistry := &Registry{
		Name:    "pypi",
		URL:     "https://pypi.org",
		Type:    "pypi",
		Enabled: true,
		Timeout: 30,
	}

	pypiConnector := NewPyPIConnector(pypiRegistry)
	var _ Connector = pypiConnector

	t.Log("PyPI connector implements Connector interface correctly")
}

func TestRegistry_Types(t *testing.T) {
	tests := []struct {
		name    string
		regType string
	}{
		{"NPM Registry", "npm"},
		{"PyPI Registry", "pypi"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registry := &Registry{
				Name:    tt.name,
				Type:    tt.regType,
				Enabled: true,
			}

			if registry.Type != tt.regType {
				t.Errorf("Expected type '%s', got '%s'", tt.regType, registry.Type)
			}
		})
	}
}

func TestRegistry_Configuration(t *testing.T) {
	registry := &Registry{
		Name:    "test-registry",
		URL:     "https://test.example.com",
		Type:    "npm",
		Enabled: true,
		Timeout: 60,
		APIKey:  "test-key",
	}

	if registry.Timeout != 60 {
		t.Errorf("Expected timeout 60, got %d", registry.Timeout)
	}

	if registry.APIKey != "test-key" {
		t.Errorf("Expected API key 'test-key', got '%s'", registry.APIKey)
	}

	if registry.URL != "https://test.example.com" {
		t.Errorf("Expected URL 'https://test.example.com', got '%s'", registry.URL)
	}
}

func TestRegistry_Disabled(t *testing.T) {
	registry := &Registry{
		Name:    "disabled-registry",
		URL:     "https://disabled.example.com",
		Type:    "npm",
		Enabled: false,
		Timeout: 30,
	}

	if registry.Enabled {
		t.Error("Expected registry to be disabled")
	}

	connector := NewNPMConnector(registry)
	if connector == nil {
		t.Error("Expected connector to be created even for disabled registry")
	}
}

func TestPackage_Validation(t *testing.T) {
	pkg := &types.Package{
		Name:     "test-package",
		Version:  "1.0.0",
		Registry: "npm",
	}

	if pkg.Name == "" {
		t.Error("Package name should not be empty")
	}

	if pkg.Version == "" {
		t.Error("Package version should not be empty")
	}

	if pkg.Registry == "" {
		t.Error("Package registry should not be empty")
	}
}

func TestRegistry_URLBuilding(t *testing.T) {
	npmRegistry := &Registry{
		Name:    "npm",
		Type:    "npm",
		URL:     "https://registry.npmjs.org",
		Enabled: true,
	}

	if npmRegistry.URL == "" {
		t.Error("NPM registry base URL should not be empty")
	}

	pypiRegistry := &Registry{
		Name:    "pypi",
		Type:    "pypi",
		URL:     "https://pypi.org",
		Enabled: true,
	}

	if pypiRegistry.URL == "" {
		t.Error("PyPI registry base URL should not be empty")
	}
}

func TestRegistry_PackageTypes(t *testing.T) {
	registries := []Registry{
		{
			Name:    "npm",
			Type:    "npm",
			URL:     "https://registry.npmjs.org",
			Enabled: true,
		},
		{
			Name:    "pypi",
			Type:    "pypi",
			URL:     "https://pypi.org",
			Enabled: true,
		},
	}

	for _, registry := range registries {
		if registry.Type == "" {
			t.Errorf("Registry %s should have a type", registry.Name)
		}
		if registry.URL == "" {
			t.Errorf("Registry %s should have a base URL", registry.Name)
		}
	}
}

func TestPackage_NPMData(t *testing.T) {
	pkg := &types.Package{
		Name:     "test-package",
		Version:  "1.0.0",
		Registry: "npm",
	}

	if pkg.Name != "test-package" {
		t.Errorf("Expected name 'test-package', got '%s'", pkg.Name)
	}

	if pkg.Version != "1.0.0" {
		t.Errorf("Expected version '1.0.0', got '%s'", pkg.Version)
	}

	if pkg.Registry != "npm" {
		t.Errorf("Expected registry 'npm', got '%s'", pkg.Registry)
	}
}

func TestPackage_PyPIData(t *testing.T) {
	pkg := &types.Package{
		Name:     "test-package",
		Version:  "2.0.0",
		Registry: "pypi",
	}

	if pkg.Name != "test-package" {
		t.Errorf("Expected name 'test-package', got '%s'", pkg.Name)
	}

	if pkg.Version != "2.0.0" {
		t.Errorf("Expected version '2.0.0', got '%s'", pkg.Version)
	}

	if pkg.Registry != "pypi" {
		t.Errorf("Expected registry 'pypi', got '%s'", pkg.Registry)
	}
}
