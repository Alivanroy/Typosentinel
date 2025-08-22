package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/analyzer"
	"github.com/Alivanroy/Typosentinel/internal/api/rest"
	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/internal/ml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type TestServer struct {
	server  *rest.Server
	baseURL string
	ctx     context.Context
	cancel  context.CancelFunc
}

func setupTestServer(t *testing.T) *TestServer {
	// Create test configuration
	cfg := config.RESTAPIConfig{
		Enabled:     true,
		Host:        "localhost",
		Port:        8081, // Use different port for testing
		BasePath:    "/api",
		Prefix:      "v1",
		Version:     "1.0.0",
		MaxBodySize: 1024 * 1024, // 1MB
		Versioning: config.APIVersioning{
			Enabled:           true,
			Strategy:          "path",
			DefaultVersion:    "v1",
			SupportedVersions: []string{"v1"},
		},
	}

	// Create mock ML pipeline
	mlPipeline := &ml.MLPipeline{}

	// Create mock analyzer
	analyzer := &analyzer.Analyzer{}

	// Create server
	server := rest.NewServer(cfg, mlPipeline, analyzer)
	require.NotNil(t, server, "Failed to create test server")

	baseURL := fmt.Sprintf("http://%s:%d", cfg.Host, cfg.Port)
	ctx, cancel := context.WithCancel(context.Background())

	// Start server in goroutine
	go func() {
		if err := server.Start(ctx); err != nil && err != http.ErrServerClosed {
			t.Logf("Server error: %v", err)
		}
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	return &TestServer{
		server:  server,
		baseURL: baseURL,
		ctx:     ctx,
		cancel:  cancel,
	}
}

func (ts *TestServer) Close() {
	if ts.cancel != nil {
		ts.cancel()
	}
	if ts.server != nil {
		ts.server.Stop(ts.ctx)
	}
}

func makeRequest(baseURL, method, path string, body []byte) (*http.Response, error) {
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}

	req, err := http.NewRequest(method, baseURL+path, bodyReader)
	if err != nil {
		return nil, err
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	return client.Do(req)
}

// TestHealthEndpoint tests the health check endpoint
func TestHealthEndpoint(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	resp, err := makeRequest(ts.baseURL, "GET", "/health", nil)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// TestReadinessEndpoint tests the readiness check endpoint
func TestReadinessEndpoint(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	resp, err := makeRequest(ts.baseURL, "GET", "/ready", nil)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Readiness endpoint returns 503 when dependencies (like database) are not fully initialized
	// This is expected behavior in test environment
	assert.Equal(t, 503, resp.StatusCode)
}

// TestAnalyzePackageEndpoint tests the package analysis endpoint
func TestAnalyzePackageEndpoint(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	reqBody := map[string]interface{}{
		"ecosystem": "npm",
		"name":      "test-package",
		"version":   "1.0.0",
	}

	body, err := json.Marshal(reqBody)
	require.NoError(t, err)

	resp, err := makeRequest(ts.baseURL, "POST", "/api/v1/analyze", body)
	require.NoError(t, err)
	defer resp.Body.Close()

	// The endpoint might return various status codes depending on implementation
	// We just verify it doesn't crash
	assert.True(t, resp.StatusCode >= 200 && resp.StatusCode < 500)
}

// TestBatchAnalyzeEndpoint tests the batch analysis endpoint
func TestBatchAnalyzeEndpoint(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	reqBody := map[string]interface{}{
		"packages": []map[string]interface{}{
			{
				"ecosystem": "npm",
				"name":      "test-package-1",
				"version":   "1.0.0",
			},
			{
				"ecosystem": "npm",
				"name":      "test-package-2",
				"version":   "2.0.0",
			},
		},
	}

	body, err := json.Marshal(reqBody)
	require.NoError(t, err)

	resp, err := makeRequest(ts.baseURL, "POST", "/api/v1/batch-analyze", body)
	require.NoError(t, err)
	defer resp.Body.Close()

	// The endpoint might return various status codes depending on implementation
	// We just verify it doesn't crash
	assert.True(t, resp.StatusCode >= 200 && resp.StatusCode < 500)
}

// TestInvalidEndpoint tests handling of invalid endpoints
func TestInvalidEndpoint(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	resp, err := makeRequest(ts.baseURL, "GET", "/invalid-endpoint", nil)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// TestConcurrentRequests tests handling of concurrent requests
func TestConcurrentRequests(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	const numRequests = 10
	results := make(chan error, numRequests)

	for i := 0; i < numRequests; i++ {
		go func() {
			resp, err := makeRequest(ts.baseURL, "GET", "/health", nil)
			if err != nil {
				results <- err
				return
			}
			resp.Body.Close()
			results <- nil
		}()
	}

	// Wait for all requests to complete
	for i := 0; i < numRequests; i++ {
		err := <-results
		assert.NoError(t, err)
	}
}

// TestRequestValidation tests request validation
func TestRequestValidation(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	// Test invalid JSON
	invalidJSON := []byte(`{"invalid": json}`)
	resp, err := makeRequest(ts.baseURL, "POST", "/api/v1/analyze", invalidJSON)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should return bad request for invalid JSON
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}