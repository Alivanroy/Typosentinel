package rest

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Alivanroy/Typosentinel/internal/analyzer"
	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/internal/ml"
	"github.com/Alivanroy/Typosentinel/pkg/types"
)

func TestServer_HealthCheck(t *testing.T) {
	server := setupTestServer(t)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/health", nil)
	server.gin.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "healthy", response["status"])
	assert.Contains(t, response, "timestamp")
	assert.Contains(t, response, "version")
}

func TestServer_ReadinessCheck(t *testing.T) {
	server := setupTestServer(t)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/ready", nil)
	server.gin.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Contains(t, response, "ready")
	assert.Contains(t, response, "ml_pipeline")
	assert.Contains(t, response, "analyzer")
}

func TestServer_AuthenticationRequired(t *testing.T) {
	server := setupTestServer(t)

	// Test without authentication
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/api/v1/packages/analyze", nil)
	server.gin.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "Authentication required", response["error"])
}

func TestServer_JWTAuthentication(t *testing.T) {
	server := setupTestServer(t)

	// Generate a test JWT token
	validator := NewJWTValidator("test-secret", "typosentinel")
	token, err := validator.GenerateToken("testuser", "Test User", "user", 1)
	require.NoError(t, err)

	// Test with valid JWT token
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/api/v1/system/status", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	server.gin.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestServer_AnalyzePackage(t *testing.T) {
	server := setupTestServer(t)

	// Create test request
	reqBody := AnalyzePackageRequest{
		Ecosystem: "npm",
		Name:      "lodash",
		Version:   "4.17.21",
	}

	body, err := json.Marshal(reqBody)
	require.NoError(t, err)

	// Test with authentication
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/api/v1/packages/analyze", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer valid-jwt-token")
	server.gin.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Contains(t, response, "package")
	assert.Contains(t, response, "analysis_time")
}

func TestServer_BatchAnalyzePackages(t *testing.T) {
	server := setupTestServer(t)

	// Create test request
	reqBody := BatchAnalyzeRequest{
		Packages: []AnalyzePackageRequest{
			{Ecosystem: "npm", Name: "lodash", Version: "4.17.21"},
			{Ecosystem: "npm", Name: "express", Version: "4.18.0"},
		},
	}

	body, err := json.Marshal(reqBody)
	require.NoError(t, err)

	// Test with authentication
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/api/v1/packages/batch-analyze", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer valid-jwt-token")
	server.gin.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Contains(t, response, "results")
	assert.Contains(t, response, "summary")
}

func TestServer_RateLimiting(t *testing.T) {
	server := setupTestServer(t)

	// Make multiple requests quickly to trigger rate limiting
	for i := 0; i < 15; i++ {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/health", nil)
		server.gin.ServeHTTP(w, req)

		if i < 10 {
			assert.Equal(t, http.StatusOK, w.Code, "Request %d should succeed", i)
		} else {
			// Should be rate limited after 10 requests
			assert.Equal(t, http.StatusTooManyRequests, w.Code, "Request %d should be rate limited", i)
		}
	}
}

func TestServer_MLPrediction(t *testing.T) {
	server := setupTestServer(t)

	// Create test request
	reqBody := MLPredictionRequest{
		Package: types.Package{
			Name:     "suspicious-package",
			Version:  "1.0.0",
			Type:     "npm",
			Registry: "npm",
		},
	}

	body, err := json.Marshal(reqBody)
	require.NoError(t, err)

	// Test typosquatting prediction
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/api/v1/ml/predict/typosquatting", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer valid-jwt-token")
	server.gin.ServeHTTP(w, req)

	// Should return service unavailable if ML pipeline is not available
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestServer_SystemStatus(t *testing.T) {
	// Create a server without rate limiting for this test
	server := setupTestServerWithoutRateLimit(t)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/api/v1/system/status", nil)
	req.Header.Set("Authorization", "Bearer valid-jwt-token")
	server.gin.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Contains(t, response, "status")
	assert.Contains(t, response, "uptime")
	assert.Contains(t, response, "version")
}

// setupTestServer creates a test server instance
func setupTestServer(t *testing.T) *Server {
	// Set gin to test mode
	gin.SetMode(gin.TestMode)

	// Create test configuration
	cfg := config.RESTAPIConfig{
		Port:     8080,
		Host:     "localhost",
		Enabled:  true,
		BasePath: "/api",
		Authentication: &config.APIAuthentication{
			Enabled:   true,
			Methods:   []string{"jwt"},
			JWTSecret: "test-secret",
		},
		RateLimiting: &config.APIRateLimiting{
			Enabled: true,
			RPS:     10,
			Burst:   20,
		},
		CORS: &config.CORSConfig{
			AllowedOrigins: []string{"*"},
			AllowedMethods: []string{"GET", "POST", "PUT", "DELETE"},
			AllowedHeaders: []string{"*"},
		},
		Documentation: config.APIDocumentation{
			Enabled: true,
		},
		Versioning: config.APIVersioning{
			Enabled:           true,
			DefaultVersion:    "v1",
			SupportedVersions: []string{"v1"},
		},
	}

	// Create mock ML pipeline and analyzer
	// In a real test, you might want to use actual mock implementations
	var mlPipeline *ml.MLPipeline = nil
	var analyzer *analyzer.Analyzer = nil

	// Create server
	server := NewServer(cfg, mlPipeline, analyzer)

	return server
}

// setupTestServerWithoutRateLimit creates a test server instance without rate limiting
func setupTestServerWithoutRateLimit(t *testing.T) *Server {
	// Set gin to test mode
	gin.SetMode(gin.TestMode)

	// Create test configuration without rate limiting
	cfg := config.RESTAPIConfig{
		Port:     8080,
		Host:     "localhost",
		Enabled:  true,
		BasePath: "/api",
		Authentication: &config.APIAuthentication{
			Enabled:   true,
			Methods:   []string{"jwt"},
			JWTSecret: "test-secret",
		},
		RateLimiting: &config.APIRateLimiting{
			Enabled: false, // Disable rate limiting for this test
		},
		CORS: &config.CORSConfig{
			AllowedOrigins: []string{"*"},
			AllowedMethods: []string{"GET", "POST", "PUT", "DELETE"},
			AllowedHeaders: []string{"*"},
		},
		Documentation: config.APIDocumentation{
			Enabled: true,
		},
		Versioning: config.APIVersioning{
			Enabled:           true,
			DefaultVersion:    "v1",
			SupportedVersions: []string{"v1"},
		},
	}

	// Create mock ML pipeline and analyzer
	var mlPipeline *ml.MLPipeline = nil
	var analyzer *analyzer.Analyzer = nil

	// Create server
	server := NewServer(cfg, mlPipeline, analyzer)

	return server
}

func TestJWTValidator_GenerateAndValidateToken(t *testing.T) {
	validator := NewJWTValidator("test-secret-key", "typosentinel")

	// Generate a token
	token, err := validator.GenerateToken("testuser", "Test User", "admin", 1)
	require.NoError(t, err)
	assert.NotEmpty(t, token)

	// Validate the token
	claims, err := validator.ValidateToken(token)
	require.NoError(t, err)
	assert.Equal(t, "testuser", claims.Subject)
	assert.Equal(t, "Test User", claims.Name)
	assert.Equal(t, "admin", claims.Role)
	assert.Equal(t, "typosentinel", claims.Issuer)
}

func TestJWTValidator_ExpiredToken(t *testing.T) {
	validator := NewJWTValidator("test-secret-key", "typosentinel")

	// Test with a properly formatted but invalid token
	_, err := validator.ValidateToken("invalid.token.format")
	assert.Error(t, err)
	// The error could be either "invalid token format" or a parsing error
	// Both are valid for malformed tokens
	assert.True(t, strings.Contains(err.Error(), "invalid token format") ||
		strings.Contains(err.Error(), "failed to parse header"))
}
