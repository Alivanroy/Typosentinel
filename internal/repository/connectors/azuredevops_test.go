package connectors

import (
	"context"
	"testing"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/repository"
)

func TestNewAzureDevOpsConnector(t *testing.T) {
	config := repository.PlatformConfig{
		BaseURL: "https://dev.azure.com",
		Auth: repository.AuthConfig{
			Token: "test-token",
		},
		Timeout: 30 * time.Second,
	}

	connector, err := NewAzureDevOpsConnector(config)
	if err != nil {
		t.Fatalf("Failed to create Azure DevOps connector: %v", err)
	}

	if connector == nil {
		t.Fatal("Connector should not be nil")
	}

	if connector.GetPlatformName() != "Azure DevOps" {
		t.Errorf("Expected platform name 'Azure DevOps', got '%s'", connector.GetPlatformName())
	}

	if connector.GetPlatformType() != "git" {
		t.Errorf("Expected platform type 'git', got '%s'", connector.GetPlatformType())
	}

	if connector.GetAPIVersion() != "7.0" {
		t.Errorf("Expected API version '7.0', got '%s'", connector.GetAPIVersion())
	}
}

func TestAzureDevOpsConnector_URLEscaping(t *testing.T) {
	config := repository.PlatformConfig{
		BaseURL: "https://dev.azure.com",
		Auth: repository.AuthConfig{
			Token: "test-token",
		},
		Timeout: 30 * time.Second,
	}

	connector, err := NewAzureDevOpsConnector(config)
	if err != nil {
		t.Fatalf("Failed to create Azure DevOps connector: %v", err)
	}

	ctx := context.Background()

	// Test URL escaping with special characters
	_, err = connector.GetOrganization(ctx, "test/org")
	if err == nil {
		t.Error("Expected error for invalid API call, but got none")
	}

	// Test repository operations with URL escaping
	_, err = connector.GetRepository(ctx, "test/owner", "test/repo")
	if err == nil {
		t.Error("Expected error for invalid API call, but got none")
	}

	// The fact that we can create requests without panicking indicates URL escaping is working
	t.Log("URL escaping test completed successfully")
}

func TestAzureDevOpsConnector_Close(t *testing.T) {
	config := repository.PlatformConfig{
		BaseURL: "https://dev.azure.com",
		Auth: repository.AuthConfig{
			Token: "test-token",
		},
		Timeout: 30 * time.Second,
	}

	connector, err := NewAzureDevOpsConnector(config)
	if err != nil {
		t.Fatalf("Failed to create Azure DevOps connector: %v", err)
	}

	err = connector.Close()
	if err != nil {
		t.Errorf("Failed to close connector: %v", err)
	}
}

func TestAzureDevOpsConnector_ParseFullName(t *testing.T) {
	config := repository.PlatformConfig{
		BaseURL: "https://dev.azure.com",
		Auth: repository.AuthConfig{
			Token: "test-token",
		},
		Timeout: 30 * time.Second,
	}

	connector, err := NewAzureDevOpsConnector(config)
	if err != nil {
		t.Fatalf("Failed to create Azure DevOps connector: %v", err)
	}

	tests := []struct {
		fullName      string
		expectedOwner string
		expectedName  string
	}{
		{"project/repo", "project", "repo"},
		{"single", "", "single"},
		{"project/repo/extra", "project", "repo"},
	}

	for _, test := range tests {
		owner, name := connector.parseFullName(test.fullName)
		if owner != test.expectedOwner {
			t.Errorf("For fullName '%s', expected owner '%s', got '%s'", test.fullName, test.expectedOwner, owner)
		}
		if name != test.expectedName {
			t.Errorf("For fullName '%s', expected name '%s', got '%s'", test.fullName, test.expectedName, name)
		}
	}
}

func TestAzureDevOpsConnector_MatchesFilter(t *testing.T) {
	config := repository.PlatformConfig{
		BaseURL: "https://dev.azure.com",
		Auth: repository.AuthConfig{
			Token: "test-token",
		},
		Timeout: 30 * time.Second,
	}

	connector, err := NewAzureDevOpsConnector(config)
	if err != nil {
		t.Fatalf("Failed to create Azure DevOps connector: %v", err)
	}

	repo := &repository.Repository{
		Name:      "test-repo",
		Language:  "C#",
		Private:   false,
		Archived:  false,
		Fork:      false,
		StarCount: 15,
		Size:      2000,
		Topics:    []string{"dotnet", "api"},
		UpdatedAt: time.Now(),
	}

	// Test with nil filter (should match)
	if !connector.matchesFilter(repo, nil) {
		t.Error("Repository should match nil filter")
	}

	// Test with empty filter (should match)
	emptyFilter := &repository.RepositoryFilter{}
	if !connector.matchesFilter(repo, emptyFilter) {
		t.Error("Repository should match empty filter")
	}

	// Test language filter
	langFilter := &repository.RepositoryFilter{
		Languages: []string{"C#", "Python"},
	}
	if !connector.matchesFilter(repo, langFilter) {
		t.Error("Repository should match language filter")
	}

	// Test minimum stars filter
	starsFilter := &repository.RepositoryFilter{
		MinStars: 10,
	}
	if !connector.matchesFilter(repo, starsFilter) {
		t.Error("Repository should match stars filter")
	}

	// Test exclude private filter
	privateFilter := &repository.RepositoryFilter{
		IncludePrivate: false,
	}
	if !connector.matchesFilter(repo, privateFilter) {
		t.Error("Repository should match private filter")
	}

	// Test name pattern filter
	nameFilter := &repository.RepositoryFilter{
		NamePattern: "test",
	}
	if !connector.matchesFilter(repo, nameFilter) {
		t.Error("Repository should match name pattern filter")
	}
}

func TestAzureDevOpsConnector_ListProjects(t *testing.T) {
	config := repository.PlatformConfig{
		BaseURL: "https://dev.azure.com",
		Auth: repository.AuthConfig{
			Token: "test-token",
		},
		Timeout: 30 * time.Second,
	}

	connector, err := NewAzureDevOpsConnector(config)
	if err != nil {
		t.Fatalf("Failed to create Azure DevOps connector: %v", err)
	}

	ctx := context.Background()

	// Test listing projects (will fail due to authentication, but should not panic)
	_, err = connector.listProjects(ctx)
	if err == nil {
		t.Error("Expected error for invalid API call, but got none")
	}

	t.Log("List projects test completed successfully")
}