package connectors

import (
	"fmt"
	"strings"

	"github.com/Alivanroy/Typosentinel/internal/repository"
)

// Factory implements the ConnectorFactory interface
type Factory struct {
	supportedPlatforms map[string]func(repository.PlatformConfig) (repository.Connector, error)
}

// NewFactory creates a new connector factory
func NewFactory() *Factory {
	return &Factory{
		supportedPlatforms: map[string]func(repository.PlatformConfig) (repository.Connector, error){
			"github":      createGitHubConnector,
			"gitlab":      createGitLabConnector,
			"bitbucket":   createBitbucketConnector,
			"azuredevops": createAzureDevOpsConnector,
		},
	}
}

// CreateConnector creates a connector for the specified platform
func (f *Factory) CreateConnector(platform string, config repository.PlatformConfig) (repository.Connector, error) {
	platform = strings.ToLower(platform)
	
	createFunc, exists := f.supportedPlatforms[platform]
	if !exists {
		return nil, fmt.Errorf("unsupported platform: %s", platform)
	}
	
	return createFunc(config)
}

// GetSupportedPlatforms returns a list of supported platforms
func (f *Factory) GetSupportedPlatforms() []string {
	platforms := make([]string, 0, len(f.supportedPlatforms))
	for platform := range f.supportedPlatforms {
		platforms = append(platforms, platform)
	}
	return platforms
}

// ValidateConfig validates the configuration for a specific platform
func (f *Factory) ValidateConfig(platform string, config repository.PlatformConfig) error {
	platform = strings.ToLower(platform)
	
	if _, exists := f.supportedPlatforms[platform]; !exists {
		return fmt.Errorf("unsupported platform: %s", platform)
	}
	
	// Basic validation
	if config.BaseURL == "" {
		return fmt.Errorf("base URL is required for platform %s", platform)
	}
	
	if config.Auth.Token == "" && config.Auth.Username == "" {
		return fmt.Errorf("authentication credentials are required for platform %s", platform)
	}
	
	// Platform-specific validation
	switch platform {
	case "github":
		return f.validateGitHubConfig(config)
	case "gitlab":
		return f.validateGitLabConfig(config)
	case "bitbucket":
		return f.validateBitbucketConfig(config)
	case "azuredevops":
		return f.validateAzureDevOpsConfig(config)
	default:
		return nil
	}
}

// Platform-specific creator functions

func createGitHubConnector(config repository.PlatformConfig) (repository.Connector, error) {
	return NewGitHubConnector(config)
}

func createGitLabConnector(config repository.PlatformConfig) (repository.Connector, error) {
	return NewGitLabConnector(config)
}

func createBitbucketConnector(config repository.PlatformConfig) (repository.Connector, error) {
	return NewBitbucketConnector(config)
}

func createAzureDevOpsConnector(config repository.PlatformConfig) (repository.Connector, error) {
	return NewAzureDevOpsConnector(config)
}

// Platform-specific validation functions

func (f *Factory) validateGitHubConfig(config repository.PlatformConfig) error {
	if config.BaseURL == "" {
		config.BaseURL = "https://api.github.com"
	}
	
	if config.Auth.Type == "" {
		config.Auth.Type = "token"
	}
	
	if config.Auth.Type == "token" && config.Auth.Token == "" {
		return fmt.Errorf("GitHub token is required for token authentication")
	}
	
	if config.Auth.Type == "oauth" {
		if config.Auth.ClientID == "" || config.Auth.ClientSecret == "" {
			return fmt.Errorf("GitHub OAuth requires client ID and client secret")
		}
	}
	
	return nil
}

func (f *Factory) validateGitLabConfig(config repository.PlatformConfig) error {
	if config.BaseURL == "" {
		config.BaseURL = "https://gitlab.com/api/v4"
	}
	
	if config.Auth.Type == "" {
		config.Auth.Type = "token"
	}
	
	if config.Auth.Type == "token" && config.Auth.Token == "" {
		return fmt.Errorf("GitLab token is required for token authentication")
	}
	
	return nil
}

func (f *Factory) validateBitbucketConfig(config repository.PlatformConfig) error {
	if config.BaseURL == "" {
		config.BaseURL = "https://api.bitbucket.org/2.0"
	}
	
	if config.Auth.Type == "" {
		config.Auth.Type = "token"
	}
	
	if config.Auth.Type == "token" && config.Auth.Token == "" {
		return fmt.Errorf("Bitbucket token is required for token authentication")
	}
	
	return nil
}

func (f *Factory) validateAzureDevOpsConfig(config repository.PlatformConfig) error {
	if config.BaseURL == "" {
		config.BaseURL = "https://dev.azure.com"
	}
	
	if config.Auth.Type == "" {
		config.Auth.Type = "token"
	}
	
	if config.Auth.Type == "token" && config.Auth.Token == "" {
		return fmt.Errorf("Azure DevOps Personal Access Token is required")
	}
	
	if len(config.Organizations) == 0 {
		return fmt.Errorf("Azure DevOps organization is required")
	}
	
	return nil
}

// RegisterPlatform allows registering custom platform connectors
func (f *Factory) RegisterPlatform(platform string, createFunc func(repository.PlatformConfig) (repository.Connector, error)) {
	f.supportedPlatforms[strings.ToLower(platform)] = createFunc
}

// UnregisterPlatform removes a platform from the factory
func (f *Factory) UnregisterPlatform(platform string) {
	delete(f.supportedPlatforms, strings.ToLower(platform))
}

// IsPlatformSupported checks if a platform is supported
func (f *Factory) IsPlatformSupported(platform string) bool {
	_, exists := f.supportedPlatforms[strings.ToLower(platform)]
	return exists
}

// GetPlatformDefaults returns default configuration for a platform
func (f *Factory) GetPlatformDefaults(platform string) repository.PlatformConfig {
	platform = strings.ToLower(platform)
	
	switch platform {
	case "github":
		return repository.PlatformConfig{
			Name:       "GitHub",
			BaseURL:    "https://api.github.com",
			APIVersion: "v3",
			Auth: repository.AuthConfig{
				Type: "token",
			},
			RateLimit: repository.RateLimitConfig{
				RequestsPerHour:   5000,
				RequestsPerMinute: 60,
				BurstLimit:        100,
				BackoffStrategy:   "exponential",
				MaxRetries:        3,
			},
			Timeout: 30000000000, // 30 seconds in nanoseconds
			Retries: 3,
		}
	case "gitlab":
		return repository.PlatformConfig{
			Name:       "GitLab",
			BaseURL:    "https://gitlab.com/api/v4",
			APIVersion: "v4",
			Auth: repository.AuthConfig{
				Type: "token",
			},
			RateLimit: repository.RateLimitConfig{
				RequestsPerHour:   2000,
				RequestsPerMinute: 300,
				BurstLimit:        50,
				BackoffStrategy:   "exponential",
				MaxRetries:        3,
			},
			Timeout: 30000000000, // 30 seconds in nanoseconds
			Retries: 3,
		}
	case "bitbucket":
		return repository.PlatformConfig{
			Name:       "Bitbucket",
			BaseURL:    "https://api.bitbucket.org/2.0",
			APIVersion: "2.0",
			Auth: repository.AuthConfig{
				Type: "token",
			},
			RateLimit: repository.RateLimitConfig{
				RequestsPerHour:   1000,
				RequestsPerMinute: 60,
				BurstLimit:        20,
				BackoffStrategy:   "exponential",
				MaxRetries:        3,
			},
			Timeout: 30000000000, // 30 seconds in nanoseconds
			Retries: 3,
		}
	case "azuredevops":
		return repository.PlatformConfig{
			Name:       "Azure DevOps",
			BaseURL:    "https://dev.azure.com",
			APIVersion: "7.0",
			Auth: repository.AuthConfig{
				Type: "token",
			},
			RateLimit: repository.RateLimitConfig{
				RequestsPerHour:   1000,
				RequestsPerMinute: 60,
				BurstLimit:        30,
				BackoffStrategy:   "exponential",
				MaxRetries:        3,
			},
			Timeout: 30000000000, // 30 seconds in nanoseconds
			Retries: 3,
		}
	default:
		return repository.PlatformConfig{}
	}
}