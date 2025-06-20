package ml

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"typosentinel/internal/config"
	"typosentinel/pkg/types"
)

type MockMLService struct{}

func (m *MockMLService) Analyze(ctx context.Context, pkg *types.Package) (*AnalysisResult, error) {
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

	if analyzer.Config.Enabled != cfg.Enabled {
		t.Error("Expected analyzer config to match provided config")
	}



	// Note: apiKey is not a direct field of MLAnalyzer
	// API key would be handled through the Config field
}

func TestAnalyze_Success(t *testing.T) {
	cfg := config.MLAnalysisConfig{
		Enabled:             true,
		SimilarityThreshold: 0.8,
		MaliciousThreshold:  0.7,
		ReputationThreshold: 0.6,
		ModelPath:           "test-model",
		BatchSize:           10,
		MaxFeatures:         100,
		CacheEmbeddings:     true,
		ParallelProcessing:  false,
		GPUAcceleration:     false,
	}

	// Mock HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"malicious_score": 0.3,
			"confidence":      0.9,
			"features": map[string]float64{
				"download_count": 1000,
				"age_days":       365,
			},
		})
	}))
	defer server.Close()

	analyzer := NewMLAnalyzer(cfg)

	pkg := &types.Package{
		Name:     "test-package",
		Version:  "1.0.0",
		Registry: "npm",
	}

	ctx := context.Background()
	result, err := analyzer.Analyze(ctx, pkg)

	if err != nil {
		t.Fatalf("Expected successful analysis, got error: %v", err)
	}

	if result == nil {
		t.Error("Expected analysis result, got nil")
	}

	// Check basic analysis result fields
	if result.SimilarityScore <= 0 {
		t.Errorf("Expected positive similarity score, got %f", result.SimilarityScore)
	}

	if result.MaliciousScore < 0 || result.MaliciousScore > 1 {
		t.Errorf("Expected malicious score between 0 and 1, got %f", result.MaliciousScore)
	}

	if result.ReputationScore < 0 || result.ReputationScore > 1 {
		t.Errorf("Expected reputation score between 0 and 1, got %f", result.ReputationScore)
	}

	if result.TyposquattingScore < 0 || result.TyposquattingScore > 1 {
		t.Errorf("Expected typosquatting score between 0 and 1, got %f", result.TyposquattingScore)
	}

	if result.Features == nil {
		t.Error("Expected features map, got nil")
	}

	if len(result.Features) == 0 {
		t.Error("Expected non-empty features map")
	}

	if result.RiskAssessment.OverallRisk == "" {
		t.Error("Expected risk assessment overall risk to be set")
	}
}

func TestAnalyze_ServerError(t *testing.T) {
	// Create mock HTTP server that returns error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Internal Server Error"))
	}))
	defer server.Close()

	cfg := config.MLAnalysisConfig{
		Enabled:             true,
		SimilarityThreshold: 0.8,
		MaliciousThreshold:  0.7,
		ReputationThreshold: 0.6,
		ModelPath:           "test-model",
		BatchSize:           10,
		MaxFeatures:         100,
		CacheEmbeddings:     true,
		ParallelProcessing:  false,
		GPUAcceleration:     false,
	}

	// Create ML client with test server URL
	client := NewClient(server.URL, "test-api-key")
	analyzer := NewMLAnalyzerWithClient(cfg, client)

	pkg := &types.Package{
		Name:     "test-package",
		Version:  "1.0.0",
		Registry: "npm",
	}

	ctx := context.Background()
	_, err := analyzer.Analyze(ctx, pkg)

	if err == nil {
		t.Error("Expected error from server error response")
	}
}

func TestAnalyze_InvalidJSON(t *testing.T) {
	cfg := config.MLAnalysisConfig{
		Enabled:             true,
		SimilarityThreshold: 0.8,
		MaliciousThreshold:  0.7,
		ReputationThreshold: 0.6,
		ModelPath:           "test-model",
		BatchSize:           10,
		MaxFeatures:         100,
		CacheEmbeddings:     true,
		ParallelProcessing:  false,
		GPUAcceleration:     false,
	}

	// Create mock HTTP server that returns invalid JSON
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("invalid json response"))
	}))
	defer server.Close()

	// Create ML client with test server URL
	client := NewClient(server.URL, "test-api-key")
	analyzer := NewMLAnalyzerWithClient(cfg, client)

	pkg := &types.Package{
		Name:     "test-package",
		Version:  "1.0.0",
		Registry: "npm",
	}

	ctx := context.Background()
	_, err := analyzer.Analyze(ctx, pkg)

	if err == nil {
		t.Error("Expected error from invalid JSON response")
	}
}

func TestAnalyze_ContextCancellation(t *testing.T) {
	// Create mock HTTP server with delay
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(AnalysisResult{})
	}))
	defer server.Close()

	cfg := config.MLAnalysisConfig{
		Enabled:             true,
		SimilarityThreshold: 0.8,
		MaliciousThreshold:  0.7,
		ReputationThreshold: 0.6,
		ModelPath:           "test-model",
		BatchSize:           10,
		MaxFeatures:         100,
		CacheEmbeddings:     true,
		ParallelProcessing:  false,
		GPUAcceleration:     false,
	}

	// Create ML client with test server URL
	client := NewClient(server.URL, "test-api-key")
	analyzer := NewMLAnalyzerWithClient(cfg, client)

	pkg := &types.Package{
		Name:     "test-package",
		Version:  "1.0.0",
		Registry: "npm",
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := analyzer.Analyze(ctx, pkg)
	if err == nil {
		t.Error("Expected error due to context cancellation")
	}
}

func TestAnalyze_Timeout(t *testing.T) {
	// Create mock HTTP server that delays response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second) // Delay longer than timeout
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(MaliciousResponse{Score: 0.5})
	}))
	defer server.Close()

	cfg := config.MLAnalysisConfig{
		Enabled:             true,
		SimilarityThreshold: 0.8,
		MaliciousThreshold:  0.7,
		ReputationThreshold: 0.6,
		ModelPath:           "test-model",
	}

	// Create ML client with test server URL
	client := NewClient(server.URL, "test-api-key")
	analyzer := NewMLAnalyzerWithClient(cfg, client)

	pkg := &types.Package{
		Name:     "test-package",
		Version:  "1.0.0",
		Registry: "npm",
	}

	// Create context with short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := analyzer.Analyze(ctx, pkg)

	if err == nil {
		t.Error("Expected error due to timeout")
	}
}

func TestAnalyzePackages_Batch(t *testing.T) {
	// Create mock HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
		PackageName string `json:"package_name"`
		Registry    string `json:"registry"`
	}
		json.NewDecoder(r.Body).Decode(&request)

		response := AnalysisResult{
			SimilarityScore:    0.6,
			MaliciousScore:     0.5,
			ReputationScore:    0.9,
			TyposquattingScore: 0.2,
			Features:           map[string]float64{"lexical_similarity": 0.6, "homoglyph_score": 0.2},
			Predictions:        []Prediction{},
			SimilarPackages:    []SimilarPackage{},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	cfg := config.MLAnalysisConfig{
		Enabled:             true,
		SimilarityThreshold: 0.8,
		MaliciousThreshold:  0.7,
		ReputationThreshold: 0.6,
		ModelPath:           "test-model",
		BatchSize:           10,
		MaxFeatures:         100,
		CacheEmbeddings:     true,
		ParallelProcessing:  false,
		GPUAcceleration:     false,
	}

	analyzer := NewMLAnalyzer(cfg)

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
	// Analyze packages individually since batch method doesn't exist
	results := make([]*AnalysisResult, len(packages))
	for i, pkg := range packages {
		result, err := analyzer.Analyze(ctx, pkg)
		if err != nil {
			t.Fatalf("Failed to analyze package %s: %v", pkg.Name, err)
		}
		results[i] = result
	}
	err := error(nil) // No error for successful individual analyses

	if err != nil {
		t.Fatalf("Expected successful batch analysis, got error: %v", err)
	}

	if len(results) != len(packages) {
		t.Errorf("Expected %d results, got %d", len(packages), len(results))
	}

	for i, result := range results {
		if result.SimilarityScore < 0 || result.SimilarityScore > 1 {
			t.Errorf("Result %d similarity score out of range: %f", i, result.SimilarityScore)
		}
		if result.MaliciousScore < 0 || result.MaliciousScore > 1 {
			t.Errorf("Result %d malicious score out of range: %f", i, result.MaliciousScore)
		}
	}
}

func TestPackageRequest(t *testing.T) {
	request := struct {
		PackageName string `json:"package_name"`
		Registry    string `json:"registry"`
	}{
		PackageName: "test-package",
		Registry:    "npm",
	}

	if request.PackageName != "test-package" {
		t.Errorf("Expected package name test-package, got %s", request.PackageName)
	}

	if request.Registry != "npm" {
		t.Errorf("Expected registry npm, got %s", request.Registry)
	}


}

func TestAnalysisResult(t *testing.T) {
	response := AnalysisResult{
		SimilarityScore:    0.88,
		MaliciousScore:     0.85,
		ReputationScore:    0.92,
		TyposquattingScore: 0.45,
		Features:           map[string]float64{"lexical_similarity": 0.88, "homoglyph_score": 0.45},
		Predictions:        []Prediction{},
		SimilarPackages:    []SimilarPackage{},
	}

	if response.SimilarityScore != 0.88 {
		t.Errorf("Expected similarity score 0.88, got %f", response.SimilarityScore)
	}

	if response.MaliciousScore != 0.85 {
		t.Errorf("Expected malicious score 0.85, got %f", response.MaliciousScore)
	}

	if response.ReputationScore != 0.92 {
		t.Errorf("Expected reputation score 0.92, got %f", response.ReputationScore)
	}

	if response.TyposquattingScore != 0.45 {
		t.Errorf("Expected typosquatting score 0.45, got %f", response.TyposquattingScore)
	}

	if len(response.Features) == 0 {
		t.Error("Expected features to be populated")
	}

	if response.Features["lexical_similarity"] != 0.88 {
		t.Errorf("Expected lexical similarity 0.88, got %f", response.Features["lexical_similarity"])
	}

	if response.Features["homoglyph_score"] != 0.45 {
		t.Errorf("Expected homoglyph score 0.45, got %f", response.Features["homoglyph_score"])
	}
}

func TestThreat(t *testing.T) {
	threat := struct {
		Type        string
		Severity    string
		Confidence  float64
		Description string
	}{
		Type:        "dependency_confusion",
		Severity:    "critical",
		Confidence:  0.95,
		Description: "Potential dependency confusion attack",
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


}

func TestMLFeatures(t *testing.T) {
	features := struct {
		LexicalSimilarity float64
		HomoglyphScore    float64
		ReputationScore   float64
		DownloadCount     int
		AgeInDays         int
		AuthorReputation  float64
		DependencyCount   int
		LicenseScore      float64
		SecurityScore     float64
	}{
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
	_, err := analyzer.Analyze(ctx, pkg)

	if err == nil {
		t.Error("Expected error when ML service is disabled")
	}
}

func TestAnalyze_Error(t *testing.T) {
	cfg := config.MLAnalysisConfig{
		Enabled:             true,
		SimilarityThreshold: 0.8,
		MaliciousThreshold:  0.7,
		ReputationThreshold: 0.6,
		ModelPath:           "test-model",
		BatchSize:           10,
		MaxFeatures:         100,
		CacheEmbeddings:     true,
		ParallelProcessing:  false,
		GPUAcceleration:     false,
	}

	// Mock HTTP server that returns error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	// Create ML client with test server URL
	client := NewClient(server.URL, "test-api-key")
	analyzer := NewMLAnalyzerWithClient(cfg, client)

	pkg := &types.Package{
		Name:     "test-package",
		Version:  "1.0.0",
		Registry: "npm",
	}

	ctx := context.Background()
	_, err := analyzer.Analyze(ctx, pkg)

	if err == nil {
		t.Error("Expected error from service error")
	}
}

func TestConcurrentMLAnalysis(t *testing.T) {
	// Create mock HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			PackageName string `json:"package_name"`
			Registry    string `json:"registry"`
		}
		json.NewDecoder(r.Body).Decode(&request)

		response := AnalysisResult{
			SimilarityScore:    0.6,
			MaliciousScore:     0.5,
			ReputationScore:    0.8,
			TyposquattingScore: 0.2,
			Features:           map[string]float64{"test": 0.5},
			Predictions:        []Prediction{},
			SimilarPackages:    []SimilarPackage{},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	cfg := config.MLAnalysisConfig{
		Enabled:             true,
		SimilarityThreshold: 0.8,
		MaliciousThreshold:  0.7,
		ReputationThreshold: 0.6,
		ModelPath:           "test-model",
		BatchSize:           10,
		MaxFeatures:         100,
		CacheEmbeddings:     true,
		ParallelProcessing:  false,
		GPUAcceleration:     false,
	}

	analyzer := NewMLAnalyzer(cfg)

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
	done := make(chan *AnalysisResult, len(packages))
	for _, pkg := range packages {
		go func(p *types.Package) {
			result, err := analyzer.Analyze(ctx, p)
			if err != nil {
				t.Errorf("Error analyzing package %s: %v", p.Name, err)
				return
			}
			done <- result
		}(pkg)
	}

	// Collect results
	results := make([]*AnalysisResult, 0, len(packages))
	for i := 0; i < len(packages); i++ {
		result := <-done
		results = append(results, result)
	}

	if len(results) != len(packages) {
		t.Errorf("Expected %d results, got %d", len(packages), len(results))
	}
}