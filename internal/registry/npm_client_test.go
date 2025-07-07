package registry

import (
	"context"
	"testing"
	"time"
)

func TestNPMClient_GetPackageInfo(t *testing.T) {
	client := NewNPMClient()
	ctx := context.Background()

	// Test with a well-known package
	packageInfo, err := client.GetPackageInfo(ctx, "lodash")
	if err != nil {
		t.Fatalf("Failed to get package info: %v", err)
	}

	if packageInfo.Name != "lodash" {
		t.Errorf("Expected package name 'lodash', got '%s'", packageInfo.Name)
	}

	if packageInfo.Description == "" {
		t.Error("Expected non-empty description")
	}

	t.Logf("Package info: %+v", packageInfo)
}

func TestNPMClient_GetDownloadStats(t *testing.T) {
	client := NewNPMClient()
	ctx := context.Background()

	// Test with a well-known package
	stats, err := client.GetDownloadStats(ctx, "lodash", "last-week")
	if err != nil {
		t.Fatalf("Failed to get download stats: %v", err)
	}

	if stats.Package != "lodash" {
		t.Errorf("Expected package name 'lodash', got '%s'", stats.Package)
	}

	if stats.Downloads <= 0 {
		t.Error("Expected positive download count")
	}

	t.Logf("Download stats: %+v", stats)
}

func TestNPMClient_GetPackageVersions(t *testing.T) {
	client := NewNPMClient()
	ctx := context.Background()

	// Test with a well-known package
	versions, err := client.GetPackageVersions(ctx, "lodash")
	if err != nil {
		t.Fatalf("Failed to get package versions: %v", err)
	}

	if len(versions) == 0 {
		t.Error("Expected at least one version")
	}

	t.Logf("Found %d versions for lodash", len(versions))
}

func TestNPMClient_Cache(t *testing.T) {
	client := NewNPMClient()
	client.SetCacheTTL(1 * time.Second)
	ctx := context.Background()

	// First request
	start := time.Now()
	_, err := client.GetPackageInfo(ctx, "lodash")
	if err != nil {
		t.Fatalf("Failed to get package info: %v", err)
	}
	firstDuration := time.Since(start)

	// Second request (should be cached)
	start = time.Now()
	_, err = client.GetPackageInfo(ctx, "lodash")
	if err != nil {
		t.Fatalf("Failed to get package info: %v", err)
	}
	secondDuration := time.Since(start)

	// Cache should make second request faster
	if secondDuration >= firstDuration {
		t.Logf("Warning: Second request (%v) was not faster than first (%v), cache might not be working", secondDuration, firstDuration)
	}

	// Wait for cache to expire
	time.Sleep(2 * time.Second)

	// Third request (cache expired)
	start = time.Now()
	_, err = client.GetPackageInfo(ctx, "lodash")
	if err != nil {
		t.Fatalf("Failed to get package info: %v", err)
	}
	thirdDuration := time.Since(start)

	t.Logf("Request durations - First: %v, Second (cached): %v, Third (expired): %v", firstDuration, secondDuration, thirdDuration)
}

func TestNPMClient_InvalidPackage(t *testing.T) {
	client := NewNPMClient()
	ctx := context.Background()

	// Test with non-existent package
	_, err := client.GetPackageInfo(ctx, "this-package-definitely-does-not-exist-12345")
	if err == nil {
		t.Error("Expected error for non-existent package")
	}

	t.Logf("Expected error: %v", err)
}

func TestNPMClient_EmptyPackageName(t *testing.T) {
	client := NewNPMClient()
	ctx := context.Background()

	// Test with empty package name
	_, err := client.GetPackageInfo(ctx, "")
	if err == nil {
		t.Error("Expected error for empty package name")
	}

	_, err = client.GetDownloadStats(ctx, "", "last-week")
	if err == nil {
		t.Error("Expected error for empty package name in download stats")
	}
}

func TestNPMClient_InvalidPeriod(t *testing.T) {
	client := NewNPMClient()
	ctx := context.Background()

	// Test with invalid period
	_, err := client.GetDownloadStats(ctx, "lodash", "invalid-period")
	if err == nil {
		t.Error("Expected error for invalid period")
	}

	t.Logf("Expected error: %v", err)
}
