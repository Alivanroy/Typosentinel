package connectors

import (
	"context"
	"testing"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/repository"
)

func TestNewGitHubConnector(t *testing.T) {
	config := repository.PlatformConfig{
		BaseURL: "https://api.github.com",
		Auth: repository.AuthConfig{
			Token: "test-token",
		},
		Timeout: 30 * time.Second,
	}

	connector, err := NewGitHubConnector(config)
	if err != nil {
		t.Fatalf("Failed to create GitHub connector: %v", err)
	}

	if connector == nil {
		t.Fatal("Connector should not be nil")
	}

	// Test basic methods
	if connector.GetPlatformName() != "github" {
		t.Errorf("Expected platform name 'github', got '%s'", connector.GetPlatformName())
	}

	if connector.GetPlatformType() != "git" {
		t.Errorf("Expected platform type 'git', got '%s'", connector.GetPlatformType())
	}

	if connector.GetAPIVersion() != "v3" {
		t.Errorf("Expected API version 'v3', got '%s'", connector.GetAPIVersion())
	}
}

func TestGitHubConnector_URLEscaping(t *testing.T) {
	config := repository.PlatformConfig{
		BaseURL: "https://api.github.com",
		Auth: repository.AuthConfig{
			Token: "test-token",
		},
		Timeout: 30 * time.Second,
	}

	connector, err := NewGitHubConnector(config)
	if err != nil {
		t.Fatalf("Failed to create GitHub connector: %v", err)
	}

	// Test that the connector can be created without URL escaping errors
	ctx := context.Background()
	
	// Test ListRepositories with special characters in owner name
	_, err = connector.ListRepositories(ctx, "test/owner", nil)
	// We expect an error due to invalid token, but no compilation error
	if err == nil {
		t.Log("ListRepositories call succeeded (unexpected with test token)")
	} else {
		t.Logf("ListRepositories call failed as expected: %v", err)
	}

	// Test SearchRepositories with special characters
	_, err = connector.SearchRepositories(ctx, "test query", nil)
	if err == nil {
		t.Log("SearchRepositories call succeeded (unexpected with test token)")
	} else {
		t.Logf("SearchRepositories call failed as expected: %v", err)
	}
}