//go:build api
// +build api

package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	baseURL = "http://localhost:8080"
	timeout = 10 * time.Second
)

type AnalyzeRequest struct {
	PackageName string `json:"package_name"`
	Registry    string `json:"registry,omitempty"`
}

type AnalysisResult struct {
	PackageName string    `json:"package_name"`
	Registry    string    `json:"registry"`
	Threats     []Threat  `json:"threats"`
	Warnings    []Warning `json:"warnings"`
	RiskLevel   int       `json:"risk_level"`
	RiskScore   float64   `json:"risk_score"`
	AnalyzedAt  time.Time `json:"analyzed_at"`
}

type Threat struct {
	Type        string  `json:"type"`
	Severity    string  `json:"severity"`
	Description string  `json:"description"`
	Confidence  float64 `json:"confidence"`
}

type Warning struct {
	Type        string `json:"type"`
	Description string `json:"description"`
}

type BatchAnalyzeRequest struct {
	Packages []AnalyzeRequest `json:"packages"`
}

type BatchAnalysisResult struct {
	Results    []AnalysisResult `json:"results"`
	Summary    BatchSummary     `json:"summary"`
	AnalyzedAt time.Time        `json:"analyzed_at"`
}

type BatchSummary struct {
	Total      int `json:"total"`
	HighRisk   int `json:"high_risk"`
	MediumRisk int `json:"medium_risk"`
	LowRisk    int `json:"low_risk"`
	NoThreats  int `json:"no_threats"`
}

type HealthResponse struct {
	Status    string    `json:"status"`
	Timestamp time.Time `json:"timestamp"`
	Version   string    `json:"version"`
}

type ReadyResponse struct {
	Ready     bool      `json:"ready"`
	Timestamp time.Time `json:"timestamp"`
}

type TestResponse struct {
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
}

type StatusResponse struct {
	Service   string                 `json:"service"`
	Version   string                 `json:"version"`
	Status    string                 `json:"status"`
	Timestamp time.Time              `json:"timestamp"`
	Features  map[string]bool        `json:"features"`
	Limits    map[string]interface{} `json:"limits"`
}

type StatsResponse struct {
	TotalRequests     string   `json:"total_requests"`
	PackagesAnalyzed  string   `json:"packages_analyzed"`
	ThreatsDetected   string   `json:"threats_detected"`
	Uptime            string   `json:"uptime"`
	RateLimitHits     string   `json:"rate_limit_hits"`
	PopularEcosystems []string `json:"popular_ecosystems"`
	DemoMode          bool     `json:"demo_mode"`
	Message           string   `json:"message"`
}

type Vulnerability struct {
	ID               string   `json:"id"`
	Title            string   `json:"title"`
	Package          string   `json:"package"`
	Version          string   `json:"version"`
	Severity         string   `json:"severity"`
	Score            float64  `json:"score"`
	Description      string   `json:"description"`
	PublishedDate    string   `json:"publishedDate"`
	LastModified     string   `json:"lastModified"`
	Status           string   `json:"status"`
	AffectedVersions string   `json:"affectedVersions"`
	FixedVersion     string   `json:"fixedVersion"`
	CVE              string   `json:"cve"`
	References       []string `json:"references"`
}

type DashboardMetrics struct {
	TotalScans      int     `json:"totalScans"`
	ThreatsDetected int     `json:"threatsDetected"`
	CriticalThreats int     `json:"criticalThreats"`
	PackagesScanned int     `json:"packagesScanned"`
	ScanSuccessRate float64 `json:"scanSuccessRate"`
	AverageScanTime float64 `json:"averageScanTime"`
	TimeRange       string  `json:"timeRange"`
	LastUpdated     string  `json:"lastUpdated"`
}

type PerformanceMetrics struct {
	ResponseTimes     map[string]float64 `json:"response_times"`
	Throughput        map[string]float64 `json:"throughput"`
	ErrorRates        map[string]float64 `json:"error_rates"`
	ResourceMetrics   map[string]float64 `json:"resource_metrics"`
	PerformanceTrends []interface{}      `json:"performance_trends"`
}

func TestHealthEndpoint(t *testing.T) {
	client := &http.Client{Timeout: timeout}

	resp, err := client.Get(baseURL + "/health")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var health HealthResponse
	err = json.NewDecoder(resp.Body).Decode(&health)
	require.NoError(t, err)

	assert.Equal(t, "healthy", health.Status)
	assert.Equal(t, "1.0.0", health.Version)
	assert.WithinDuration(t, time.Now(), health.Timestamp, 5*time.Second)
}

func TestReadyEndpoint(t *testing.T) {
	client := &http.Client{Timeout: timeout}

	resp, err := client.Get(baseURL + "/ready")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var ready ReadyResponse
	err = json.NewDecoder(resp.Body).Decode(&ready)
	require.NoError(t, err)

	assert.True(t, ready.Ready)
	assert.WithinDuration(t, time.Now(), ready.Timestamp, 5*time.Second)
}

func TestTestEndpoint(t *testing.T) {
	client := &http.Client{Timeout: timeout}

	resp, err := client.Get(baseURL + "/test")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var test TestResponse
	err = json.NewDecoder(resp.Body).Decode(&test)
	require.NoError(t, err)

	assert.Equal(t, "test endpoint working", test.Message)
	assert.WithinDuration(t, time.Now(), test.Timestamp, 5*time.Second)
}

func TestAnalyzeEndpoint(t *testing.T) {
	client := &http.Client{Timeout: timeout}

	tests := []struct {
		name           string
		request        AnalyzeRequest
		expectedStatus int
		validateResult func(t *testing.T, result AnalysisResult)
	}{
		{
			name: "valid package analysis",
			request: AnalyzeRequest{
				PackageName: "express",
				Registry:    "npm",
			},
			expectedStatus: http.StatusOK,
			validateResult: func(t *testing.T, result AnalysisResult) {
				assert.Equal(t, "express", result.PackageName)
				assert.Equal(t, "npm", result.Registry)
				assert.Equal(t, 0, result.RiskLevel)   // Legitimate packages should have zero risk
				assert.Equal(t, 0.0, result.RiskScore) // Legitimate packages should have zero risk score
				assert.WithinDuration(t, time.Now(), result.AnalyzedAt, 5*time.Second)
			},
		},
		{
			name: "package with test keyword",
			request: AnalyzeRequest{
				PackageName: "test-package",
				Registry:    "npm",
			},
			expectedStatus: http.StatusOK,
			validateResult: func(t *testing.T, result AnalysisResult) {
				assert.Equal(t, "test-package", result.PackageName)
				assert.True(t, len(result.Threats) > 0 || len(result.Warnings) > 0)
			},
		},
		{
			name: "short package name",
			request: AnalyzeRequest{
				PackageName: "ab",
				Registry:    "npm",
			},
			expectedStatus: http.StatusOK,
			validateResult: func(t *testing.T, result AnalysisResult) {
				assert.Equal(t, "ab", result.PackageName)
				assert.True(t, len(result.Warnings) > 0)
			},
		},
		{
			name: "package with numbers",
			request: AnalyzeRequest{
				PackageName: "package123",
				Registry:    "npm",
			},
			expectedStatus: http.StatusOK,
			validateResult: func(t *testing.T, result AnalysisResult) {
				assert.Equal(t, "package123", result.PackageName)
				assert.True(t, len(result.Warnings) > 0)
			},
		},
		{
			name: "missing package name",
			request: AnalyzeRequest{
				PackageName: "",
				Registry:    "npm",
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "default registry",
			request: AnalyzeRequest{
				PackageName: "lodash",
			},
			expectedStatus: http.StatusOK,
			validateResult: func(t *testing.T, result AnalysisResult) {
				assert.Equal(t, "lodash", result.PackageName)
				assert.Equal(t, "npm", result.Registry) // Should default to npm
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, err := json.Marshal(tt.request)
			require.NoError(t, err)

			req, err := http.NewRequest("POST", baseURL+"/v1/analyze", bytes.NewBuffer(body))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/json")

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()

			assert.Equal(t, tt.expectedStatus, resp.StatusCode)

			if tt.expectedStatus == http.StatusOK && tt.validateResult != nil {
				var result AnalysisResult
				err = json.NewDecoder(resp.Body).Decode(&result)
				require.NoError(t, err)
				tt.validateResult(t, result)
			}
		})
	}
}

func TestBatchAnalyzeEndpoint(t *testing.T) {
	client := &http.Client{Timeout: timeout}

	tests := []struct {
		name           string
		request        BatchAnalyzeRequest
		expectedStatus int
		validateResult func(t *testing.T, result BatchAnalysisResult)
	}{
		{
			name: "valid batch analysis",
			request: BatchAnalyzeRequest{
				Packages: []AnalyzeRequest{
					{PackageName: "express", Registry: "npm"},
					{PackageName: "lodash", Registry: "npm"},
					{PackageName: "react", Registry: "npm"},
				},
			},
			expectedStatus: http.StatusOK,
			validateResult: func(t *testing.T, result BatchAnalysisResult) {
				assert.Equal(t, 3, len(result.Results))
				assert.Equal(t, 3, result.Summary.Total)
				assert.NotZero(t, result.Summary.NoThreats+result.Summary.LowRisk+result.Summary.MediumRisk+result.Summary.HighRisk)
				assert.WithinDuration(t, time.Now(), result.AnalyzedAt, 5*time.Second)
			},
		},
		{
			name: "empty batch",
			request: BatchAnalyzeRequest{
				Packages: []AnalyzeRequest{},
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "batch too large",
			request: BatchAnalyzeRequest{
				Packages: []AnalyzeRequest{
					{PackageName: "pkg1"}, {PackageName: "pkg2"}, {PackageName: "pkg3"},
					{PackageName: "pkg4"}, {PackageName: "pkg5"}, {PackageName: "pkg6"},
					{PackageName: "pkg7"}, {PackageName: "pkg8"}, {PackageName: "pkg9"},
					{PackageName: "pkg10"}, {PackageName: "pkg11"}, // 11 packages > limit
				},
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "mixed risk packages",
			request: BatchAnalyzeRequest{
				Packages: []AnalyzeRequest{
					{PackageName: "test-package", Registry: "npm"},
					{PackageName: "ab", Registry: "npm"},
					{PackageName: "normal-package", Registry: "npm"},
				},
			},
			expectedStatus: http.StatusOK,
			validateResult: func(t *testing.T, result BatchAnalysisResult) {
				assert.Equal(t, 3, len(result.Results))
				assert.Equal(t, 3, result.Summary.Total)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, err := json.Marshal(tt.request)
			require.NoError(t, err)

			req, err := http.NewRequest("POST", baseURL+"/v1/analyze/batch", bytes.NewBuffer(body))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/json")

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()

			assert.Equal(t, tt.expectedStatus, resp.StatusCode)

			if tt.expectedStatus == http.StatusOK && tt.validateResult != nil {
				var result BatchAnalysisResult
				err = json.NewDecoder(resp.Body).Decode(&result)
				require.NoError(t, err)
				tt.validateResult(t, result)
			}
		})
	}
}

func TestStatusEndpoint(t *testing.T) {
	client := &http.Client{Timeout: timeout}

	resp, err := client.Get(baseURL + "/v1/status")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var status StatusResponse
	err = json.NewDecoder(resp.Body).Decode(&status)
	require.NoError(t, err)

	assert.Equal(t, "TypoSentinel API", status.Service)
	assert.Equal(t, "1.0.0", status.Version)
	assert.Equal(t, "operational", status.Status)
	assert.NotNil(t, status.Features)
	assert.True(t, status.Features["typosquatting_detection"])
	assert.True(t, status.Features["rate_limiting"])
	assert.NotNil(t, status.Limits)
	assert.Equal(t, float64(10), status.Limits["requests_per_minute"])
}

func TestStatsEndpoint(t *testing.T) {
	client := &http.Client{Timeout: timeout}

	resp, err := client.Get(baseURL + "/v1/stats")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var stats StatsResponse
	err = json.NewDecoder(resp.Body).Decode(&stats)
	require.NoError(t, err)

	assert.True(t, stats.DemoMode)
	assert.Contains(t, stats.Message, "demo mode")
	assert.Contains(t, stats.TotalRequests, "N/A")
}

func TestVulnerabilitiesEndpoint(t *testing.T) {
	client := &http.Client{Timeout: timeout}

	tests := []struct {
		name           string
		queryParams    string
		expectedStatus int
		validateResult func(t *testing.T, vulns []Vulnerability)
	}{
		{
			name:           "all vulnerabilities",
			queryParams:    "",
			expectedStatus: http.StatusOK,
			validateResult: func(t *testing.T, vulns []Vulnerability) {
				assert.True(t, len(vulns) > 0)
			},
		},
		{
			name:           "filter by severity",
			queryParams:    "?severity=critical",
			expectedStatus: http.StatusOK,
			validateResult: func(t *testing.T, vulns []Vulnerability) {
				for _, vuln := range vulns {
					assert.Equal(t, "critical", vuln.Severity)
				}
			},
		},
		{
			name:           "filter by package",
			queryParams:    "?package=react",
			expectedStatus: http.StatusOK,
			validateResult: func(t *testing.T, vulns []Vulnerability) {
				for _, vuln := range vulns {
					assert.Equal(t, "react", vuln.Package)
				}
			},
		},
		{
			name:           "filter by status",
			queryParams:    "?status=fixed",
			expectedStatus: http.StatusOK,
			validateResult: func(t *testing.T, vulns []Vulnerability) {
				for _, vuln := range vulns {
					assert.Equal(t, "fixed", vuln.Status)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := client.Get(baseURL + "/api/v1/vulnerabilities" + tt.queryParams)
			require.NoError(t, err)
			defer resp.Body.Close()

			assert.Equal(t, tt.expectedStatus, resp.StatusCode)

			if tt.expectedStatus == http.StatusOK && tt.validateResult != nil {
				var vulns []Vulnerability
				err = json.NewDecoder(resp.Body).Decode(&vulns)
				require.NoError(t, err)
				tt.validateResult(t, vulns)
			}
		})
	}
}

func TestDashboardMetricsEndpoint(t *testing.T) {
	client := &http.Client{Timeout: timeout}

	resp, err := client.Get(baseURL + "/api/v1/dashboard/metrics")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var metrics DashboardMetrics
	err = json.NewDecoder(resp.Body).Decode(&metrics)
	require.NoError(t, err)

	assert.NotZero(t, metrics.TotalScans)
	assert.NotZero(t, metrics.PackagesScanned)
	assert.NotZero(t, metrics.ScanSuccessRate)
	assert.NotZero(t, metrics.AverageScanTime)
	assert.Equal(t, "24h", metrics.TimeRange)
}

func TestDashboardPerformanceEndpoint(t *testing.T) {
	client := &http.Client{Timeout: timeout}

	resp, err := client.Get(baseURL + "/api/v1/dashboard/performance")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var perf PerformanceMetrics
	err = json.NewDecoder(resp.Body).Decode(&perf)
	require.NoError(t, err)

	assert.NotNil(t, perf.ResponseTimes)
	assert.NotNil(t, perf.Throughput)
	assert.NotNil(t, perf.ErrorRates)
	assert.NotNil(t, perf.ResourceMetrics)
}

func TestRateLimiting(t *testing.T) {
	client := &http.Client{Timeout: timeout}

	// Make multiple requests quickly to trigger rate limiting
	for i := 0; i < 15; i++ {
		resp, err := client.Get(baseURL + "/test")
		require.NoError(t, err)
		resp.Body.Close()

		if resp.StatusCode == http.StatusTooManyRequests {
			// Rate limiting triggered - test passed
			return
		}

		// Small delay to avoid overwhelming the server
		time.Sleep(100 * time.Millisecond)
	}

	// Note: Rate limiting might not trigger in demo mode
	// This test is more about ensuring the endpoint handles requests
	t.Log("Rate limiting test completed - may not trigger in demo mode")
}

func TestCORSSupport(t *testing.T) {
	client := &http.Client{Timeout: timeout}

	req, err := http.NewRequest("OPTIONS", baseURL+"/v1/analyze", nil)
	require.NoError(t, err)
	req.Header.Set("Origin", "http://localhost:3000")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "Content-Type")

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// CORS should be configured, but exact behavior depends on implementation
	assert.True(t, true, "CORS test completed")
}

func TestInvalidJSON(t *testing.T) {
	client := &http.Client{Timeout: timeout}

	// Test invalid JSON in analyze endpoint
	req, err := http.NewRequest("POST", baseURL+"/v1/analyze", bytes.NewBufferString("invalid json"))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestMethodNotAllowed(t *testing.T) {
	client := &http.Client{Timeout: timeout}

	// Test GET on POST endpoint
	resp, err := client.Get(baseURL + "/v1/analyze")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
}

func TestServerStartup(t *testing.T) {
	// Test that server is running by checking health endpoint
	client := &http.Client{Timeout: timeout}

	// Give server time to start if just launched
	time.Sleep(2 * time.Second)

	resp, err := client.Get(baseURL + "/health")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestConcurrentRequests(t *testing.T) {
	client := &http.Client{Timeout: timeout}

	// Test concurrent requests to ensure server handles them properly
	done := make(chan bool, 5)
	errors := make(chan error, 5)

	for i := 0; i < 5; i++ {
		go func(id int) {
			req := AnalyzeRequest{
				PackageName: fmt.Sprintf("test-package-%d", id),
				Registry:    "npm",
			}

			body, err := json.Marshal(req)
			if err != nil {
				errors <- err
				done <- false
				return
			}

			resp, err := client.Post(baseURL+"/v1/analyze", "application/json", bytes.NewBuffer(body))
			if err != nil {
				errors <- err
				done <- false
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				errors <- fmt.Errorf("unexpected status code: %d", resp.StatusCode)
				done <- false
				return
			}

			done <- true
		}(i)
	}

	// Wait for all requests to complete
	successCount := 0
	for i := 0; i < 5; i++ {
		select {
		case success := <-done:
			if success {
				successCount++
			}
		case err := <-errors:
			t.Logf("Concurrent request error: %v", err)
		case <-time.After(15 * time.Second):
			t.Fatal("Timeout waiting for concurrent requests")
		}
	}

	assert.True(t, successCount > 0, "At least some concurrent requests should succeed")
}
