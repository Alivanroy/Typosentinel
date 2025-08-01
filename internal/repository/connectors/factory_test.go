package connectors

import (
	"testing"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/repository"
)

func TestNewConnectorFactory(t *testing.T) {
	factory := NewFactory()
	if factory == nil {
		t.Fatal("Factory should not be nil")
	}

	// Check that all expected platforms are supported
	expectedPlatforms := []string{"github", "gitlab", "bitbucket", "azuredevops"}
	supportedPlatforms := factory.GetSupportedPlatforms()

	if len(supportedPlatforms) != len(expectedPlatforms) {
		t.Errorf("Expected %d supported platforms, got %d", len(expectedPlatforms), len(supportedPlatforms))
	}

	for _, platform := range expectedPlatforms {
		found := false
		for _, supported := range supportedPlatforms {
			if supported == platform {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Platform '%s' should be supported", platform)
		}
	}
}

func TestConnectorFactory_CreateConnector(t *testing.T) {
	factory := NewFactory()

	tests := []struct {
		platform string
		baseURL  string
	}{
		{"github", "https://api.github.com"},
		{"gitlab", "https://gitlab.com/api/v4"},
		{"bitbucket", "https://api.bitbucket.org/2.0"},
		{"azuredevops", "https://dev.azure.com"},
	}

	for _, test := range tests {
		t.Run(test.platform, func(t *testing.T) {
			config := repository.PlatformConfig{
				BaseURL: test.baseURL,
				Auth: repository.AuthConfig{
					Token: "test-token",
				},
				Timeout: 30 * time.Second,
			}

			connector, err := factory.CreateConnector(test.platform, config)
			if err != nil {
				t.Fatalf("Failed to create %s connector: %v", test.platform, err)
			}

			if connector == nil {
				t.Fatal("Connector should not be nil")
			}

			// Test that the connector can be closed
			err = connector.Close()
			if err != nil {
				t.Errorf("Failed to close %s connector: %v", test.platform, err)
			}
		})
	}
}

func TestConnectorFactory_CreateConnector_UnsupportedPlatform(t *testing.T) {
	factory := NewFactory()

	config := repository.PlatformConfig{
		BaseURL: "https://example.com",
		Auth: repository.AuthConfig{
			Token: "test-token",
		},
		Timeout: 30 * time.Second,
	}

	_, err := factory.CreateConnector("unsupported", config)
	if err == nil {
		t.Error("Expected error for unsupported platform, but got none")
	}
}

func TestConnectorFactory_ValidateConfig(t *testing.T) {
	factory := NewFactory()

	tests := []struct {
		name     string
		platform string
		config   repository.PlatformConfig
		expectError bool
	}{
		{
			name:     "valid github config",
			platform: "github",
			config: repository.PlatformConfig{
				BaseURL: "https://api.github.com",
				Auth: repository.AuthConfig{
					Token: "test-token",
				},
				Timeout: 30 * time.Second,
			},
			expectError: false,
		},
		{
			name:     "missing token",
			platform: "github",
			config: repository.PlatformConfig{
				BaseURL: "https://api.github.com",
				Timeout: 30 * time.Second,
			},
			expectError: true,
		},
		{
			name:     "missing base URL",
			platform: "github",
			config: repository.PlatformConfig{
				Auth: repository.AuthConfig{
					Token: "test-token",
				},
				Timeout: 30 * time.Second,
			},
			expectError: true,
		},
		{
			name:     "unsupported platform",
			platform: "unsupported",
			config: repository.PlatformConfig{
				BaseURL: "https://example.com",
				Auth: repository.AuthConfig{
					Token: "test-token",
				},
				Timeout: 30 * time.Second,
			},
			expectError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := factory.ValidateConfig(test.platform, test.config)
			if test.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !test.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
		})
	}
}

func TestConnectorFactory_GetDefaultConfig(t *testing.T) {
	factory := NewFactory()

	tests := []struct {
		platform    string
		expectedURL string
	}{
		{"github", "https://api.github.com"},
		{"gitlab", "https://gitlab.com/api/v4"},
		{"bitbucket", "https://api.bitbucket.org/2.0"},
		{"azuredevops", "https://dev.azure.com"},
	}

	for _, test := range tests {
		t.Run(test.platform, func(t *testing.T) {
			config := factory.GetPlatformDefaults(test.platform)
			if config.BaseURL != test.expectedURL {
				t.Errorf("Expected base URL '%s', got '%s'", test.expectedURL, config.BaseURL)
			}
			if config.Timeout != 30*time.Second {
				t.Errorf("Expected timeout 30s, got %v", config.Timeout)
			}
		})
	}

	// Test unsupported platform
	config := factory.GetPlatformDefaults("unsupported")
	if config.BaseURL != "" {
		t.Error("Expected empty base URL for unsupported platform")
	}
}

func TestConnectorFactory_RegisterUnregister(t *testing.T) {
	factory := NewFactory()

	// Test registering a custom platform
	customCreator := func(config repository.PlatformConfig) (repository.Connector, error) {
		return NewGitHubConnector(config) // Use GitHub connector as a mock
	}

	factory.RegisterPlatform("custom", customCreator)

	// Check that the platform is now supported
	supportedPlatforms := factory.GetSupportedPlatforms()
	found := false
	for _, platform := range supportedPlatforms {
		if platform == "custom" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Custom platform should be supported after registration")
	}

	// Test creating a connector with the custom platform
	config := repository.PlatformConfig{
		BaseURL: "https://api.github.com",
		Auth: repository.AuthConfig{
			Token: "test-token",
		},
		Timeout: 30 * time.Second,
	}

	connector, err := factory.CreateConnector("custom", config)
	if err != nil {
		t.Fatalf("Failed to create custom connector: %v", err)
	}
	if connector == nil {
		t.Fatal("Custom connector should not be nil")
	}
	connector.Close()

	// Test unregistering the platform
	factory.UnregisterPlatform("custom")

	// Check that the platform is no longer supported
	supportedPlatforms = factory.GetSupportedPlatforms()
	for _, platform := range supportedPlatforms {
		if platform == "custom" {
			t.Error("Custom platform should not be supported after unregistration")
		}
	}

	// Test that creating a connector with the unregistered platform fails
	_, err = factory.CreateConnector("custom", config)
	if err == nil {
		t.Error("Expected error for unregistered platform, but got none")
	}
}

func TestConnectorFactory_RegisterExistingPlatform(t *testing.T) {
	factory := NewFactory()

	// Try to register an existing platform
	customCreator := func(config repository.PlatformConfig) (repository.Connector, error) {
		return NewGitHubConnector(config)
	}

	// RegisterPlatform doesn't return an error, it just overwrites
	factory.RegisterPlatform("github", customCreator)
	// This should succeed as it just overwrites the existing platform
}

func TestConnectorFactory_UnregisterNonExistentPlatform(t *testing.T) {
	factory := NewFactory()

	// Try to unregister a non-existent platform
	// UnregisterPlatform doesn't return an error, it just does nothing if platform doesn't exist
	factory.UnregisterPlatform("nonexistent")
	// This should succeed (no-op for non-existent platforms)
}