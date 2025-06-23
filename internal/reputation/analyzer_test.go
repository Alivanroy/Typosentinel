package reputation

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Alivanroy/Typosentinel/pkg/types"
)

func TestNewAnalyzer(t *testing.T) {
	cfg := &Config{
		Enabled:     true,
		CacheSize:   1000,
		CacheTTL:    time.Hour,
		Timeout:     30 * time.Second,
		MaxRetries:  3,
		RetryDelay:  time.Second,
		Sources: []Source{
			{
				Name:     "test-source",
				Endpoint: "http://localhost:8002",
				APIKey:   "test-key",
				Weight:   1.0,
				Enabled:  true,
			},
		},
	}

	analyzer := NewAnalyzer(cfg)

	if analyzer == nil {
		t.Error("Expected analyzer to be created, got nil")
	}

	if analyzer.config != cfg {
		t.Error("Expected analyzer config to match provided config")
	}

	if analyzer.client == nil {
		t.Error("Expected HTTP client to be initialized")
	}

	if analyzer.cache == nil {
		t.Error("Expected cache to be initialized")
	}

	if len(analyzer.sources) != 1 {
		t.Errorf("Expected 1 reputation source, got %d", len(analyzer.sources))
	}
}

func TestAnalyzePackage_Success(t *testing.T) {
	// Create mock HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("Expected GET request, got %s", r.Method)
		}

		if r.Header.Get("Authorization") != "Bearer test-key" {
			t.Errorf("Expected Authorization header, got %s", r.Header.Get("Authorization"))
		}

		response := ReputationResponse{
			PackageName: "test-package",
			Registry:    "npm",
			Score:       0.85,
			Risk:        "low",
			Metrics: ReputationMetrics{
				DownloadCount:    1000000,
				AgeInDays:        365,
				MaintainerCount:  3,
				IssueCount:       5,
				StarCount:        500,
				ForkCount:        50,
				LastUpdateDays:   7,
				VulnerabilityCount: 0,
				LicenseScore:     0.9,
				CommunityScore:   0.8,
			},
			Flags: []ReputationFlag{
				{
					Type:        "verified_publisher",
					Severity:    "info",
					Description: "Package from verified publisher",
				},
			},
			Sources: []SourceResult{
				{
					Name:   "test-source",
					Score:  0.85,
					Weight: 1.0,
					Status: "success",
				},
			},
			Metadata: map[string]interface{}{
				"analysis_time": "50ms",
				"cache_hit":     false,
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	cfg := &Config{
		Enabled:     true,
		CacheSize:   1000,
		CacheTTL:    time.Hour,
		Timeout:     30 * time.Second,
		MaxRetries:  3,
		RetryDelay:  time.Second,
		Sources: []Source{
			{
				Name:     "test-source",
				Endpoint: server.URL,
				APIKey:   "test-key",
				Weight:   1.0,
				Enabled:  true,
			},
		},
	}

	analyzer := NewAnalyzer(cfg)

	pkg := &types.Package{
		Name:     "test-package",
		Version:  "1.0.0",
		Registry: "npm",
	}

	ctx := context.Background()
	result, err := analyzer.AnalyzePackage(ctx, pkg)

	if err != nil {
		t.Fatalf("Expected successful analysis, got error: %v", err)
	}

	if result == nil {
		t.Error("Expected analysis result, got nil")
	}

	if result.PackageName != "test-package" {
		t.Errorf("Expected package name test-package, got %s", result.PackageName)
	}

	if result.Registry != "npm" {
		t.Errorf("Expected registry npm, got %s", result.Registry)
	}

	if result.Score != 0.85 {
		t.Errorf("Expected score 0.85, got %f", result.Score)
	}

	if result.Risk != "low" {
		t.Errorf("Expected risk low, got %s", result.Risk)
	}

	if result.Metrics.DownloadCount != 1000000 {
		t.Errorf("Expected download count 1000000, got %d", result.Metrics.DownloadCount)
	}

	if len(result.Flags) != 1 {
		t.Errorf("Expected 1 flag, got %d", len(result.Flags))
	}

	if result.Flags[0].Type != "verified_publisher" {
		t.Errorf("Expected flag type verified_publisher, got %s", result.Flags[0].Type)
	}

	if len(result.Sources) != 1 {
		t.Errorf("Expected 1 source result, got %d", len(result.Sources))
	}
}

func TestAnalyzePackage_ServerError(t *testing.T) {
	// Create mock HTTP server that returns error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Internal Server Error"))
	}))
	defer server.Close()

	cfg := &Config{
		Enabled:     true,
		CacheSize:   1000,
		CacheTTL:    time.Hour,
		Timeout:     30 * time.Second,
		MaxRetries:  1, // Reduce retries for faster test
		RetryDelay:  10 * time.Millisecond,
		Sources: []Source{
			{
				Name:     "test-source",
				Endpoint: server.URL,
				APIKey:   "test-key",
				Weight:   1.0,
				Enabled:  true,
			},
		},
	}

	analyzer := NewAnalyzer(cfg)

	pkg := &types.Package{
		Name:     "test-package",
		Version:  "1.0.0",
		Registry: "npm",
	}

	ctx := context.Background()
	_, err := analyzer.AnalyzePackage(ctx, pkg)

	if err == nil {
		t.Error("Expected error from server error response")
	}
}

func TestAnalyzePackage_ContextCancellation(t *testing.T) {
	// Create mock HTTP server with delay
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ReputationResponse{})
	}))
	defer server.Close()

	cfg := &Config{
		Enabled:     true,
		CacheSize:   1000,
		CacheTTL:    time.Hour,
		Timeout:     30 * time.Second,
		MaxRetries:  3,
		RetryDelay:  time.Second,
		Sources: []Source{
			{
				Name:     "test-source",
				Endpoint: server.URL,
				APIKey:   "test-key",
				Weight:   1.0,
				Enabled:  true,
			},
		},
	}

	analyzer := NewAnalyzer(cfg)

	pkg := &types.Package{
		Name:     "test-package",
		Version:  "1.0.0",
		Registry: "npm",
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := analyzer.AnalyzePackage(ctx, pkg)
	if err == nil {
		t.Error("Expected error due to context cancellation")
	}
}

func TestAnalyzePackage_Timeout(t *testing.T) {
	// Create mock HTTP server with long delay
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ReputationResponse{})
	}))
	defer server.Close()

	cfg := &Config{
		Enabled:     true,
		CacheSize:   1000,
		CacheTTL:    time.Hour,
		Timeout:     50 * time.Millisecond, // Short timeout
		MaxRetries:  1,
		RetryDelay:  10 * time.Millisecond,
		Sources: []Source{
			{
				Name:     "test-source",
				Endpoint: server.URL,
				APIKey:   "test-key",
				Weight:   1.0,
				Enabled:  true,
			},
		},
	}

	analyzer := NewAnalyzer(cfg)

	pkg := &types.Package{
		Name:     "test-package",
		Version:  "1.0.0",
		Registry: "npm",
	}

	ctx := context.Background()
	_, err := analyzer.AnalyzePackage(ctx, pkg)

	if err == nil {
		t.Error("Expected error due to timeout")
	}
}

func TestAnalyzePackages_Batch(t *testing.T) {
	// Create mock HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract package name from URL path
		packageName := r.URL.Query().Get("package")
		if packageName == "" {
			packageName = "unknown"
		}

		response := ReputationResponse{
			PackageName: packageName,
			Registry:    "npm",
			Score:       0.7,
			Risk:        "medium",
			Metrics: ReputationMetrics{
				DownloadCount: 10000,
				AgeInDays:     100,
			},
			Flags:   []ReputationFlag{},
			Sources: []SourceResult{},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	cfg := &Config{
		Enabled:     true,
		CacheSize:   1000,
		CacheTTL:    time.Hour,
		Timeout:     30 * time.Second,
		MaxRetries:  3,
		RetryDelay:  time.Second,
		Sources: []Source{
			{
				Name:     "test-source",
				Endpoint: server.URL,
				APIKey:   "test-key",
				Weight:   1.0,
				Enabled:  true,
			},
		},
	}

	analyzer := NewAnalyzer(cfg)

	packages := []*types.Package{
		{
			Name:     "package1",
			Version:  "1.0.0",
			Registry: "npm",
		},
		{
			Name:     "package2",
			Version:  "2.0.0",
			Registry: "pypi",
		},
		{
			Name:     "package3",
			Version:  "3.0.0",
			Registry: "rubygems",
		},
	}

	ctx := context.Background()
	results, err := analyzer.AnalyzePackages(ctx, packages)

	if err != nil {
		t.Fatalf("Expected successful batch analysis, got error: %v", err)
	}

	if len(results) != len(packages) {
		t.Errorf("Expected %d results, got %d", len(packages), len(results))
	}

	for i, result := range results {
		if result.Score != 0.7 {
			t.Errorf("Result %d score mismatch: expected 0.7, got %f", i, result.Score)
		}
		if result.Risk != "medium" {
			t.Errorf("Result %d risk mismatch: expected medium, got %s", i, result.Risk)
		}
	}
}

func TestCacheHit(t *testing.T) {
	requestCount := 0
	// Create mock HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		response := ReputationResponse{
			PackageName: "test-package",
			Registry:    "npm",
			Score:       0.8,
			Risk:        "low",
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	cfg := &Config{
		Enabled:     true,
		CacheSize:   1000,
		CacheTTL:    time.Hour,
		Timeout:     30 * time.Second,
		MaxRetries:  3,
		RetryDelay:  time.Second,
		Sources: []Source{
			{
				Name:     "test-source",
				Endpoint: server.URL,
				APIKey:   "test-key",
				Weight:   1.0,
				Enabled:  true,
			},
		},
	}

	analyzer := NewAnalyzer(cfg)

	pkg := &types.Package{
		Name:     "test-package",
		Version:  "1.0.0",
		Registry: "npm",
	}

	ctx := context.Background()

	// First request - should hit the server
	result1, err := analyzer.AnalyzePackage(ctx, pkg)
	if err != nil {
		t.Fatalf("First request failed: %v", err)
	}

	// Second request - should hit the cache
	result2, err := analyzer.AnalyzePackage(ctx, pkg)
	if err != nil {
		t.Fatalf("Second request failed: %v", err)
	}

	if requestCount != 1 {
		t.Errorf("Expected 1 server request (cache hit on second), got %d", requestCount)
	}

	if result1.Score != result2.Score {
		t.Errorf("Cache results don't match: %f vs %f", result1.Score, result2.Score)
	}
}

func TestMultipleSources(t *testing.T) {
	// Create two mock HTTP servers
	server1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := ReputationResponse{
			PackageName: "test-package",
			Registry:    "npm",
			Score:       0.9,
			Risk:        "low",
			Sources: []SourceResult{
				{
					Name:   "source1",
					Score:  0.9,
					Weight: 0.6,
					Status: "success",
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer server1.Close()

	server2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := ReputationResponse{
			PackageName: "test-package",
			Registry:    "npm",
			Score:       0.7,
			Risk:        "medium",
			Sources: []SourceResult{
				{
					Name:   "source2",
					Score:  0.7,
					Weight: 0.4,
					Status: "success",
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer server2.Close()

	cfg := &Config{
		Enabled:     true,
		CacheSize:   1000,
		CacheTTL:    time.Hour,
		Timeout:     30 * time.Second,
		MaxRetries:  3,
		RetryDelay:  time.Second,
		Sources: []Source{
			{
				Name:     "source1",
				Endpoint: server1.URL,
				APIKey:   "key1",
				Weight:   0.6,
				Enabled:  true,
			},
			{
				Name:     "source2",
				Endpoint: server2.URL,
				APIKey:   "key2",
				Weight:   0.4,
				Enabled:  true,
			},
		},
	}

	analyzer := NewAnalyzer(cfg)

	pkg := &types.Package{
		Name:     "test-package",
		Version:  "1.0.0",
		Registry: "npm",
	}

	ctx := context.Background()
	result, err := analyzer.AnalyzePackage(ctx, pkg)

	if err != nil {
		t.Fatalf("Expected successful analysis, got error: %v", err)
	}

	// Weighted average: (0.9 * 0.6) + (0.7 * 0.4) = 0.54 + 0.28 = 0.82
	expectedScore := 0.82
	if result.Score != expectedScore {
		t.Errorf("Expected weighted score %f, got %f", expectedScore, result.Score)
	}

	if len(result.Sources) != 2 {
		t.Errorf("Expected 2 source results, got %d", len(result.Sources))
	}
}

func TestReputationMetrics(t *testing.T) {
	metrics := ReputationMetrics{
		DownloadCount:      5000000,
		AgeInDays:          730,
		MaintainerCount:    5,
		IssueCount:         12,
		StarCount:          1500,
		ForkCount:          200,
		LastUpdateDays:     3,
		VulnerabilityCount: 1,
		LicenseScore:       0.95,
		CommunityScore:     0.88,
		DocumentationScore: 0.92,
		TestCoverage:       85.5,
	}

	if metrics.DownloadCount != 5000000 {
		t.Errorf("Expected download count 5000000, got %d", metrics.DownloadCount)
	}

	if metrics.AgeInDays != 730 {
		t.Errorf("Expected age 730 days, got %d", metrics.AgeInDays)
	}

	if metrics.VulnerabilityCount != 1 {
		t.Errorf("Expected vulnerability count 1, got %d", metrics.VulnerabilityCount)
	}

	if metrics.TestCoverage != 85.5 {
		t.Errorf("Expected test coverage 85.5, got %f", metrics.TestCoverage)
	}
}

func TestReputationFlag(t *testing.T) {
	flag := ReputationFlag{
		Type:        "suspicious_activity",
		Severity:    "high",
		Description: "Unusual download patterns detected",
		Evidence:    []string{"spike in downloads", "new maintainer", "version mismatch"},
		Source:      "security-scanner",
		Timestamp:   time.Now(),
	}

	if flag.Type != "suspicious_activity" {
		t.Errorf("Expected type suspicious_activity, got %s", flag.Type)
	}

	if flag.Severity != "high" {
		t.Errorf("Expected severity high, got %s", flag.Severity)
	}

	if len(flag.Evidence) != 3 {
		t.Errorf("Expected 3 evidence items, got %d", len(flag.Evidence))
	}

	if flag.Source != "security-scanner" {
		t.Errorf("Expected source security-scanner, got %s", flag.Source)
	}
}

func TestSourceResult(t *testing.T) {
	source := SourceResult{
		Name:      "virustotal",
		Score:     0.75,
		Weight:    0.3,
		Status:    "success",
		Latency:   120 * time.Millisecond,
		Error:     "",
		Metadata: map[string]interface{}{
			"detections": 2,
			"scanners":   45,
			"scan_date":  "2024-01-15",
		},
	}

	if source.Name != "virustotal" {
		t.Errorf("Expected name virustotal, got %s", source.Name)
	}

	if source.Score != 0.75 {
		t.Errorf("Expected score 0.75, got %f", source.Score)
	}

	if source.Weight != 0.3 {
		t.Errorf("Expected weight 0.3, got %f", source.Weight)
	}

	if source.Status != "success" {
		t.Errorf("Expected status success, got %s", source.Status)
	}

	if source.Metadata["detections"] != 2 {
		t.Errorf("Expected detections 2, got %v", source.Metadata["detections"])
	}
}

func TestAnalyzerWithDisabledReputation(t *testing.T) {
	cfg := &Config{
		Enabled: false, // Disabled
	}

	analyzer := NewAnalyzer(cfg)

	pkg := &types.Package{
		Name:     "test-package",
		Version:  "1.0.0",
		Registry: "npm",
	}

	ctx := context.Background()
	_, err := analyzer.AnalyzePackage(ctx, pkg)

	if err == nil {
		t.Error("Expected error when reputation service is disabled")
	}
}

func TestConcurrentReputationAnalysis(t *testing.T) {
	// Create mock HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		packageName := r.URL.Query().Get("package")
		if packageName == "" {
			packageName = "unknown"
		}

		response := ReputationResponse{
			PackageName: packageName,
			Registry:    "npm",
			Score:       0.6,
			Risk:        "medium",
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	cfg := &Config{
		Enabled:     true,
		CacheSize:   1000,
		CacheTTL:    time.Hour,
		Timeout:     30 * time.Second,
		MaxRetries:  3,
		RetryDelay:  time.Second,
		Sources: []Source{
			{
				Name:     "test-source",
				Endpoint: server.URL,
				APIKey:   "test-key",
				Weight:   1.0,
				Enabled:  true,
			},
		},
	}

	analyzer := NewAnalyzer(cfg)

	packages := make([]*types.Package, 5)
	for i := 0; i < 5; i++ {
		packages[i] = &types.Package{
			Name:     fmt.Sprintf("package-%d", i),
			Version:  "1.0.0",
			Registry: "npm",
		}
	}

	ctx := context.Background()

	// Run concurrent analyses
	done := make(chan *ReputationResponse, len(packages))
	for _, pkg := range packages {
		go func(p *types.Package) {
			result, err := analyzer.AnalyzePackage(ctx, p)
			if err != nil {
				t.Errorf("Error analyzing package %s: %v", p.Name, err)
				return
			}
			done <- result
		}(pkg)
	}

	// Collect results
	results := make([]*ReputationResponse, 0, len(packages))
	for i := 0; i < len(packages); i++ {
		result := <-done
		results = append(results, result)
	}

	if len(results) != len(packages) {
		t.Errorf("Expected %d results, got %d", len(packages), len(results))
	}
}