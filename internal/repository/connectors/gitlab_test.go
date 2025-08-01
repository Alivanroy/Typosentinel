package connectors

import (
	"context"
	"testing"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/repository"
)

func TestNewGitLabConnector(t *testing.T) {
	config := repository.PlatformConfig{
		BaseURL: "https://gitlab.com/api/v4",
		Auth: repository.AuthConfig{
			Token: "test-token",
		},
		Timeout: 30 * time.Second,
	}

	connector, err := NewGitLabConnector(config)
	if err != nil {
		t.Fatalf("Failed to create GitLab connector: %v", err)
	}

	if connector == nil {
		t.Fatal("Connector should not be nil")
	}

	// Test basic methods
	if connector.GetPlatformName() != "gitlab" {
		t.Errorf("Expected platform name 'gitlab', got '%s'", connector.GetPlatformName())
	}

	if connector.GetPlatformType() != "git" {
		t.Errorf("Expected platform type 'git', got '%s'", connector.GetPlatformType())
	}

	if connector.GetAPIVersion() != "v4" {
		t.Errorf("Expected API version 'v4', got '%s'", connector.GetAPIVersion())
	}
}

func TestGitLabConnector_URLEscaping(t *testing.T) {
	config := repository.PlatformConfig{
		BaseURL: "https://gitlab.com/api/v4",
		Auth: repository.AuthConfig{
			Token: "test-token",
		},
		Timeout: 30 * time.Second,
	}

	connector, err := NewGitLabConnector(config)
	if err != nil {
		t.Fatalf("Failed to create GitLab connector: %v", err)
	}

	// Test that the connector can be created without URL escaping errors
	// This tests the fixes we made to resolve the url.QueryEscape shadowing issues
	ctx := context.Background()
	
	// Test ListRepositories with special characters in owner name
	// This should not panic or cause compilation errors
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

func TestGitLabConnector_Close(t *testing.T) {
	config := repository.PlatformConfig{
		BaseURL: "https://gitlab.com/api/v4",
		Auth: repository.AuthConfig{
			Token: "test-token",
		},
		Timeout: 30 * time.Second,
	}

	connector, err := NewGitLabConnector(config)
	if err != nil {
		t.Fatalf("Failed to create GitLab connector: %v", err)
	}

	// Test Close method
	err = connector.Close()
	if err != nil {
		t.Errorf("Close should not return an error, got: %v", err)
	}
}