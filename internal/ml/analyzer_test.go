package ml

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"typosentinel/internal/config"
	"typosentinel/pkg/types"
)

type MockMLService struct{}

func (m *MockMLService) AnalyzePackage(ctx context.Context, pkg *types.Package) (*AnalysisResult, error) {
	return &AnalysisResult{
		SimilarityScore: 0.8,
		MaliciousScore:  0.2,
		ReputationScore: 0.9,
	}, nil
}

func TestNewAnalyzer(t *testing.T) {
	cfg := config.MLAnalysisConfig{
		Enabled:             true,
		SimilarityThreshold: 0.8,
		MaliciousThreshold:  0.7,
		ReputationThreshold: 0.6,
		ModelPath:           "test-model",
	}

	analyzer := NewMLAnalyzer(cfg)

	if analyzer == nil {
		t.Error("Expected analyzer to be created, got nil")
	}

	if analyzer.config != cfg {
		t.Error("Expected analyzer config to match provided config")
	}

	if analyzer.client == nil {
		t.Error("Expected HTTP client to be initialized")
	}

	if analyzer.endpoint != cfg.MLService.Endpoint {
		t.Errorf("Expected endpoint %s, got %s", cfg.MLService.Endpoint, analyzer.endpoint)
	}

	if analyzer.apiKey != cfg.MLService.APIKey {
		t.Errorf("Expected API key %s, got %s", cfg.MLService.APIKey, analyzer.apiKey)
	}
}

func TestAnalyzePackage_Success(t *testing.T) {
	cfg := config.MLAnalysisConfig{
		Enabled:             true,
		SimilarityThreshold: 0.8,
		MaliciousThreshold:  0.7,
		ReputationThreshold: 0.6,
		ModelPath:           "test-model",
	}

	analyzer := NewMLAnalyzer(cfg)
	analyzer.service = &MockMLService{}

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

	if result.RiskScore != 0.75 {
		t.Errorf("Expected risk score 0.75, got %f", result.RiskScore)
	}

	if result.Confidence != 0.9 {
		t.Errorf("Expected confidence 0.9, got %f", result.Confidence)
	}

	if len(result.Threats) != 1 {
		t.Errorf("Expected 1 threat, got %d", len(result.Threats))
	}

	if result.Threats[0].Type != "typosquatting" {
		t.Errorf("Expected threat type typosquatting, got %s", result.Threats[0].Type)
	}

	if result.Features.LexicalSimilarity != 0.8 {
		t.Errorf("Expected lexical similarity 0.8, got %f", result.Features.LexicalSimilarity)
	}
}

func TestAnalyzePackage_ServerError(t *testing.T) {
	// Create mock HTTP server that returns error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Internal Server Error"))
	}))
	defer server.Close()

	cfg := &config.Config{
		MLService: config.MLServiceConfig{
			Enabled:  true,
			Endpoint: server.URL,
			APIKey:   "test-api-key",
			Timeout:  30 * time.Second,
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

func TestAnalyzePackage_InvalidJSON(t *testing.T) {
	// Create mock HTTP server that returns invalid JSON
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("invalid json response"))
	}))
	defer server.Close()

	cfg := &config.Config{
		MLService: config.MLServiceConfig{
			Enabled:  true,
			Endpoint: server.URL,
			APIKey:   "test-api-key",
			Timeout:  30 * time.Second,
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
		t.Error("Expected error from invalid JSON response")
	}
}

func TestAnalyzePackage_ContextCancellation(t *testing.T) {
	// Create mock HTTP server with delay
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(MLResponse{})
	}))
	defer server.Close()

	cfg := &config.Config{
		MLService: config.MLServiceConfig{
			Enabled:  true,
			Endpoint: server.URL,
			APIKey:   "test-api-key",
			Timeout:  30 * time.Second,
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
	cfg := config.MLAnalysisConfig{
		Enabled:             true,
		SimilarityThreshold: 0.8,
		MaliciousThreshold:  0.7,
		ReputationThreshold: 0.6,
		ModelPath:           "test-model",
	}

	analyzer := NewMLAnalyzer(cfg)
	analyzer.service = &MockMLService{}

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
		var request MLRequest
		json.NewDecoder(r.Body).Decode(&request)

		response := MLResponse{
			PackageName: request.PackageName,
			Registry:    request.Registry,
			RiskScore:   0.5,
			Confidence:  0.8,
			Threats:     []MLThreat{},
			Features: MLFeatures{
				LexicalSimilarity: 0.6,
				HomoglyphScore:    0.2,
				ReputationScore:   0.9,
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	cfg := &config.Config{
		MLService: config.MLServiceConfig{
			Enabled:  true,
			Endpoint: server.URL,
			APIKey:   "test-api-key",
			Timeout:  30 * time.Second,
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
		if result.PackageName != packages[i].Name {
			t.Errorf("Result %d package name mismatch: expected %s, got %s", i, packages[i].Name, result.PackageName)
		}
		if result.Registry != packages[i].Registry {
			t.Errorf("Result %d registry mismatch: expected %s, got %s", i, packages[i].Registry, result.Registry)
		}
	}
}

func TestMLRequest(t *testing.T) {
	request := MLRequest{
		PackageName: "test-package",
		Version:     "1.0.0",
		Registry:    "npm",
		Metadata: map[string]interface{}{
			"description": "A test package",
			"author":      "Test Author",
		},
	}

	if request.PackageName != "test-package" {
		t.Errorf("Expected package name test-package, got %s", request.PackageName)
	}

	if request.Version != "1.0.0" {
		t.Errorf("Expected version 1.0.0, got %s", request.Version)
	}

	if request.Registry != "npm" {
		t.Errorf("Expected registry npm, got %s", request.Registry)
	}

	if request.Metadata["description"] != "A test package" {
		t.Errorf("Expected description 'A test package', got %v", request.Metadata["description"])
	}
}

func TestMLResponse(t *testing.T) {
	response := MLResponse{
		PackageName: "test-package",
		Registry:    "npm",
		RiskScore:   0.85,
		Confidence:  0.92,
		Threats: []MLThreat{
			{
				Type:        "typosquatting",
				Severity:    "high",
				Confidence:  0.9,
				Description: "Potential typosquatting detected",
				Evidence:    []string{"similar name to popular package", "low download count"},
			},
			{
				Type:        "reputation",
				Severity:    "medium",
				Confidence:  0.7,
				Description: "Low reputation score",
				Evidence:    []string{"new package", "unknown author"},
			},
		},
		Features: MLFeatures{
			LexicalSimilarity: 0.88,
			HomoglyphScore:    0.45,
			ReputationScore:   0.3,
			DownloadCount:     150,
			AgeInDays:         30,
			AuthorReputation:  0.2,
		},
		Metadata: map[string]interface{}{
			"model_version":  "1.3.0",
			"analysis_time":  "200ms",
			"feature_count":  15,
			"algorithms":     []string{"neural_network", "decision_tree"},
		},
	}

	if response.PackageName != "test-package" {
		t.Errorf("Expected package name test-package, got %s", response.PackageName)
	}

	if response.RiskScore != 0.85 {
		t.Errorf("Expected risk score 0.85, got %f", response.RiskScore)
	}

	if len(response.Threats) != 2 {
		t.Errorf("Expected 2 threats, got %d", len(response.Threats))
	}

	if response.Threats[0].Type != "typosquatting" {
		t.Errorf("Expected first threat type typosquatting, got %s", response.Threats[0].Type)
	}

	if response.Features.LexicalSimilarity != 0.88 {
		t.Errorf("Expected lexical similarity 0.88, got %f", response.Features.LexicalSimilarity)
	}

	if response.Features.DownloadCount != 150 {
		t.Errorf("Expected download count 150, got %d", response.Features.DownloadCount)
	}
}

func TestMLThreat(t *testing.T) {
	threat := MLThreat{
		Type:        "dependency_confusion",
		Severity:    "critical",
		Confidence:  0.95,
		Description: "Potential dependency confusion attack",
		Evidence:    []string{"internal package name", "external registry", "higher version"},
		Mitigation:  "Use scoped packages or private registry",
	}

	if threat.Type != "dependency_confusion" {
		t.Errorf("Expected type dependency_confusion, got %s", threat.Type)
	}

	if threat.Severity != "critical" {
		t.Errorf("Expected severity critical, got %s", threat.Severity)
	}

	if threat.Confidence != 0.95 {
		t.Errorf("Expected confidence 0.95, got %f", threat.Confidence)
	}

	if len(threat.Evidence) != 3 {
		t.Errorf("Expected 3 evidence items, got %d", len(threat.Evidence))
	}

	if threat.Mitigation != "Use scoped packages or private registry" {
		t.Errorf("Expected specific mitigation, got %s", threat.Mitigation)
	}
}

func TestMLFeatures(t *testing.T) {
	features := MLFeatures{
		LexicalSimilarity: 0.75,
		HomoglyphScore:    0.3,
		ReputationScore:   0.8,
		DownloadCount:     50000,
		AgeInDays:         365,
		AuthorReputation:  0.9,
		DependencyCount:   15,
		LicenseScore:      0.95,
		SecurityScore:     0.85,
	}

	if features.LexicalSimilarity != 0.75 {
		t.Errorf("Expected lexical similarity 0.75, got %f", features.LexicalSimilarity)
	}

	if features.DownloadCount != 50000 {
		t.Errorf("Expected download count 50000, got %d", features.DownloadCount)
	}

	if features.AgeInDays != 365 {
		t.Errorf("Expected age 365 days, got %d", features.AgeInDays)
	}

	if features.DependencyCount != 15 {
		t.Errorf("Expected dependency count 15, got %d", features.DependencyCount)
	}

	if features.LicenseScore != 0.95 {
		t.Errorf("Expected license score 0.95, got %f", features.LicenseScore)
	}
}

func TestAnalyzerWithDisabledMLService(t *testing.T) {
	cfg := config.MLAnalysisConfig{
		Enabled: false, // Disabled
	}

	analyzer := NewMLAnalyzer(cfg)

	pkg := &types.Package{
		Name:     "test-package",
		Version:  "1.0.0",
		Registry: "npm",
	}

	ctx := context.Background()
	_, err := analyzer.AnalyzePackage(ctx, pkg)

	if err == nil {
		t.Error("Expected error when ML service is disabled")
	}
}

func TestAnalyzePackage_Error(t *testing.T) {
	cfg := config.MLAnalysisConfig{
		Enabled:             true,
		SimilarityThreshold: 0.8,
		MaliciousThreshold:  0.7,
		ReputationThreshold: 0.6,
		ModelPath:           "test-model",
	}

	analyzer := NewMLAnalyzer(cfg)

	pkg := &types.Package{
		Name:     "test-package",
		Version:  "1.0.0",
		Registry: "npm",
	}

	ctx := context.Background()
	_, err := analyzer.AnalyzePackage(ctx, pkg)

	if err == nil {
		t.Error("Expected error from service error")
	}
}

func TestConcurrentMLAnalysis(t *testing.T) {
	// Create mock HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request MLRequest
		json.NewDecoder(r.Body).Decode(&request)

		response := MLResponse{
			PackageName: request.PackageName,
			Registry:    request.Registry,
			RiskScore:   0.5,
			Confidence:  0.8,
			Threats:     []MLThreat{},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	cfg := &config.Config{
		MLService: config.MLServiceConfig{
			Enabled:  true,
			Endpoint: server.URL,
			APIKey:   "test-api-key",
			Timeout:  30 * time.Second,
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
	done := make(chan *MLResponse, len(packages))
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
	results := make([]*MLResponse, 0, len(packages))
	for i := 0; i < len(packages); i++ {
		result := <-done
		results = append(results, result)
	}

	if len(results) != len(packages) {
		t.Errorf("Expected %d results, got %d", len(packages), len(results))
	}
}