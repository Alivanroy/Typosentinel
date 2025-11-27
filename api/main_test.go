package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthHandler(t *testing.T) {
	// Initialize rate limiter for tests
	rateLimiter = NewRateLimiter()

	req, err := http.NewRequest("GET", "/health", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(healthHandler)

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	var response HealthResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Errorf("Failed to unmarshal response: %v", err)
	}

	if response.Status != "healthy" {
		t.Errorf("Expected status 'healthy', got %v", response.Status)
	}

	if response.Version != "1.0.0" {
		t.Errorf("Expected version '1.0.0', got %v", response.Version)
	}

	if response.Timestamp.IsZero() {
		t.Error("Timestamp should not be zero")
	}
}

func TestReadyHandler(t *testing.T) {
	// Initialize rate limiter for tests
	rateLimiter = NewRateLimiter()

	req, err := http.NewRequest("GET", "/ready", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(readyHandler)

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	var response ReadyResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Errorf("Failed to unmarshal response: %v", err)
	}

	if !response.Ready {
		t.Error("Expected ready to be true")
	}

	if response.Timestamp.IsZero() {
		t.Error("Timestamp should not be zero")
	}
}

func TestTestHandler(t *testing.T) {
	// Initialize rate limiter for tests
	rateLimiter = NewRateLimiter()

	req, err := http.NewRequest("GET", "/test", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(testHandler)

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	var response TestResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Errorf("Failed to unmarshal response: %v", err)
	}

	if response.Message != "test endpoint working" {
		t.Errorf("Expected message 'test endpoint working', got %v", response.Message)
	}

	if response.Timestamp.IsZero() {
		t.Error("Timestamp should not be zero")
	}
}

func TestAnalyzeHandler_ValidRequest(t *testing.T) {
	// Initialize rate limiter for tests
	rateLimiter = NewRateLimiter()

	request := AnalyzeRequest{
		PackageName: "test-package",
		Registry:    "npm",
	}

	body, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest("POST", "/v1/analyze", bytes.NewBuffer(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler := rateLimitMiddleware(http.HandlerFunc(analyzeHandler))

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	var response AnalysisResult
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Errorf("Failed to unmarshal response: %v", err)
	}

	if response.PackageName != "test-package" {
		t.Errorf("Expected package name 'test-package', got %v", response.PackageName)
	}

	if response.Registry != "npm" {
		t.Errorf("Expected registry 'npm', got %v", response.Registry)
	}

	if response.AnalyzedAt.IsZero() {
		t.Error("AnalyzedAt should not be zero")
	}
}

func TestAnalyzeHandler_MissingPackageName(t *testing.T) {
	// Initialize rate limiter for tests
	rateLimiter = NewRateLimiter()

	request := AnalyzeRequest{
		Registry: "npm",
	}

	body, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest("POST", "/v1/analyze", bytes.NewBuffer(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler := rateLimitMiddleware(http.HandlerFunc(analyzeHandler))

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusBadRequest)
	}

	if rr.Body.String() != "Package name is required\n" {
		t.Errorf("Expected error message 'Package name is required', got %v", rr.Body.String())
	}
}

func TestAnalyzeHandler_InvalidJSON(t *testing.T) {
	// Initialize rate limiter for tests
	rateLimiter = NewRateLimiter()

	req, err := http.NewRequest("POST", "/v1/analyze", bytes.NewBufferString("invalid json"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler := rateLimitMiddleware(http.HandlerFunc(analyzeHandler))

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusBadRequest)
	}
}

func TestBatchAnalyzeHandler_ValidRequest(t *testing.T) {
	// Initialize rate limiter for tests
	rateLimiter = NewRateLimiter()

	request := BatchAnalyzeRequest{
		Packages: []AnalyzeRequest{
			{PackageName: "package1", Registry: "npm"},
			{PackageName: "package2", Registry: "pypi"},
		},
	}

	body, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest("POST", "/v1/analyze/batch", bytes.NewBuffer(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler := rateLimitMiddleware(http.HandlerFunc(batchAnalyzeHandler))

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	var response BatchAnalysisResult
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Errorf("Failed to unmarshal response: %v", err)
	}

	if len(response.Results) != 2 {
		t.Errorf("Expected 2 results, got %v", len(response.Results))
	}

	if response.Summary.Total != 2 {
		t.Errorf("Expected total 2, got %v", response.Summary.Total)
	}

	if response.AnalyzedAt.IsZero() {
		t.Error("AnalyzedAt should not be zero")
	}
}

func TestBatchAnalyzeHandler_EmptyPackages(t *testing.T) {
	// Initialize rate limiter for tests
	rateLimiter = NewRateLimiter()

	request := BatchAnalyzeRequest{
		Packages: []AnalyzeRequest{},
	}

	body, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest("POST", "/v1/analyze/batch", bytes.NewBuffer(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler := rateLimitMiddleware(http.HandlerFunc(batchAnalyzeHandler))

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusBadRequest)
	}

	if rr.Body.String() != "At least one package is required\n" {
		t.Errorf("Expected error message 'At least one package is required', got %v", rr.Body.String())
	}
}

func TestBatchAnalyzeHandler_TooManyPackages(t *testing.T) {
	// Initialize rate limiter for tests
	rateLimiter = NewRateLimiter()

	// Create 11 packages (limit is 10)
	packages := make([]AnalyzeRequest, 11)
	for i := 0; i < 11; i++ {
		packages[i] = AnalyzeRequest{PackageName: "package" + string(rune(i)), Registry: "npm"}
	}

	request := BatchAnalyzeRequest{
		Packages: packages,
	}

	body, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest("POST", "/v1/analyze/batch", bytes.NewBuffer(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler := rateLimitMiddleware(http.HandlerFunc(batchAnalyzeHandler))

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusBadRequest)
	}

	if rr.Body.String() != "Maximum 10 packages allowed per batch\n" {
		t.Errorf("Expected error message 'Maximum 10 packages allowed per batch', got %v", rr.Body.String())
	}
}

func TestStatusHandler(t *testing.T) {
	// Initialize rate limiter for tests
	rateLimiter = NewRateLimiter()

	req, err := http.NewRequest("GET", "/v1/status", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(statusHandler)

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	var response map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Errorf("Failed to unmarshal response: %v", err)
	}

	if response["service"] != "TypoSentinel API" {
		t.Errorf("Expected service 'TypoSentinel API', got %v", response["service"])
	}

	if response["version"] != "1.0.0" {
		t.Errorf("Expected version '1.0.0', got %v", response["version"])
	}

	if response["status"] != "operational" {
		t.Errorf("Expected status 'operational', got %v", response["status"])
	}

	features, ok := response["features"].(map[string]interface{})
	if !ok {
		t.Error("Features should be a map")
	}

	if features["typosquatting_detection"] != true {
		t.Error("Typosquatting detection should be enabled")
	}

	if features["rate_limiting"] != true {
		t.Error("Rate limiting should be enabled")
	}
}

func TestStatsHandler(t *testing.T) {
	// Initialize rate limiter for tests
	rateLimiter = NewRateLimiter()

	req, err := http.NewRequest("GET", "/v1/stats", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(statsHandler)

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	var response map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Errorf("Failed to unmarshal response: %v", err)
	}

	if response["demo_mode"] != true {
		t.Error("Demo mode should be true")
	}

	if response["total_requests"] != "N/A (demo mode)" {
		t.Error("Total requests should show demo mode message")
	}

	popularEcosystems, ok := response["popular_ecosystems"].([]interface{})
	if !ok {
		t.Error("Popular ecosystems should be an array")
	}

	if len(popularEcosystems) == 0 {
		t.Error("Should have popular ecosystems listed")
	}
}

func TestVulnerabilitiesHandler(t *testing.T) {
	// Initialize rate limiter for tests
	rateLimiter = NewRateLimiter()

	req, err := http.NewRequest("GET", "/api/v1/vulnerabilities", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(vulnerabilitiesHandler)

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	var response []map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Errorf("Failed to unmarshal response: %v", err)
	}

	if len(response) == 0 {
		t.Error("Should return vulnerability data")
	}

	// Check first vulnerability
	vuln := response[0]
	if vuln["id"] == "" {
		t.Error("Vulnerability should have an ID")
	}

	if vuln["title"] == "" {
		t.Error("Vulnerability should have a title")
	}

	if vuln["severity"] == "" {
		t.Error("Vulnerability should have a severity")
	}
}

func TestVulnerabilitiesHandler_WithFilters(t *testing.T) {
	// Initialize rate limiter for tests
	rateLimiter = NewRateLimiter()

	// Test with severity filter
	req, err := http.NewRequest("GET", "/api/v1/vulnerabilities?severity=critical", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(vulnerabilitiesHandler)

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	var response []map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Errorf("Failed to unmarshal response: %v", err)
	}

	// All returned vulnerabilities should have critical severity
	for _, vuln := range response {
		if vuln["severity"] != "critical" {
			t.Errorf("Expected severity 'critical', got %v", vuln["severity"])
		}
	}
}

func TestDashboardMetricsHandler(t *testing.T) {
	// Initialize rate limiter for tests
	rateLimiter = NewRateLimiter()

	req, err := http.NewRequest("GET", "/api/v1/dashboard/metrics", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(dashboardMetricsHandler)

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	var response map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Errorf("Failed to unmarshal response: %v", err)
	}

	if response["totalScans"] == nil {
		t.Error("Should have totalScans metric")
	}

	if response["threatsDetected"] == nil {
		t.Error("Should have threatsDetected metric")
	}

	if response["timeRange"] != "24h" {
		t.Errorf("Expected timeRange '24h', got %v", response["timeRange"])
	}
}

func TestDashboardPerformanceHandler(t *testing.T) {
	// Initialize rate limiter for tests
	rateLimiter = NewRateLimiter()

	req, err := http.NewRequest("GET", "/api/v1/dashboard/performance", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(dashboardPerformanceHandler)

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	var response map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Errorf("Failed to unmarshal response: %v", err)
	}

	responseTimes, ok := response["response_times"].(map[string]interface{})
	if !ok {
		t.Error("Should have response_times data")
	}

	if responseTimes["api"] == nil {
		t.Error("Should have API response time")
	}

	throughput, ok := response["throughput"].(map[string]interface{})
	if !ok {
		t.Error("Should have throughput data")
	}

	if throughput["api_requests_per_sec"] == nil {
		t.Error("Should have API requests per second")
	}
}

func TestPerformThreatAnalysis(t *testing.T) {
	// Test package with suspicious keywords
	threats, warnings := performThreatAnalysis("test-package", "npm")

	if len(threats) == 0 {
		t.Error("Should detect threats for package with 'test' keyword")
	}

	foundTyposquatting := false
	for _, threat := range threats {
		if threat.Type == "typosquatting" {
			foundTyposquatting = true
			if threat.Severity != "medium" {
				t.Errorf("Expected severity 'medium', got %v", threat.Severity)
			}
			if threat.Confidence != 0.7 {
				t.Errorf("Expected confidence 0.7, got %v", threat.Confidence)
			}
		}
	}

	if !foundTyposquatting {
		t.Error("Should detect typosquatting threat")
	}

	// Test short package name
	_, warnings = performThreatAnalysis("ab", "npm")

	foundShortNameWarning := false
	for _, warning := range warnings {
		if warning.Type == "short_name" {
			foundShortNameWarning = true
		}
	}

	if !foundShortNameWarning {
		t.Error("Should warn about short package name")
	}

	// Test package with numbers
	_, warnings = performThreatAnalysis("package123", "npm")

	foundNumericWarning := false
	for _, warning := range warnings {
		if warning.Type == "numeric_chars" {
			foundNumericWarning = true
		}
	}

	if !foundNumericWarning {
		t.Error("Should warn about numeric characters")
	}
}

func TestCalculateRiskLevel(t *testing.T) {
	// Test with no threats
	riskLevel, riskScore := calculateRiskLevel([]Threat{})
	if riskLevel != 0 {
		t.Errorf("Expected risk level 0 for no threats, got %v", riskLevel)
	}
	if riskScore != 0.0 {
		t.Errorf("Expected risk score 0.0 for no threats, got %v", riskScore)
	}

	// Test with high confidence threat
	threats := []Threat{
		{Confidence: 0.9},
	}
	riskLevel, riskScore = calculateRiskLevel(threats)
	if riskLevel != 3 {
		t.Errorf("Expected risk level 3 for high confidence threat, got %v", riskLevel)
	}
	if riskScore != 0.9 {
		t.Errorf("Expected risk score 0.9, got %v", riskScore)
	}

	// Test with medium confidence threat
	threats = []Threat{
		{Confidence: 0.6},
	}
	riskLevel, riskScore = calculateRiskLevel(threats)
	if riskLevel != 2 {
		t.Errorf("Expected risk level 2 for medium confidence threat, got %v", riskLevel)
	}
	if riskScore != 0.6 {
		t.Errorf("Expected risk score 0.6, got %v", riskScore)
	}

	// Test with low confidence threat
	threats = []Threat{
		{Confidence: 0.3},
	}
	riskLevel, riskScore = calculateRiskLevel(threats)
	if riskLevel != 1 {
		t.Errorf("Expected risk level 1 for low confidence threat, got %v", riskLevel)
	}
	if riskScore != 0.3 {
		t.Errorf("Expected risk score 0.3, got %v", riskScore)
	}
}

func TestRateLimiter(t *testing.T) {
	rl := NewRateLimiter()

	// Test that limiter is created for new IP
	limiter := rl.getLimiter("192.168.1.1")
	if limiter == nil {
		t.Error("Limiter should not be nil")
	}

	// Test that same limiter is returned for same IP
	limiter2 := rl.getLimiter("192.168.1.1")
	if limiter != limiter2 {
		t.Error("Should return same limiter for same IP")
	}

	// Test Allow method
	if !rl.Allow("192.168.1.1") {
		t.Error("Should allow first request")
	}
}

func TestGetClientIP(t *testing.T) {
	// Test with X-Forwarded-For header
	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-For", "10.0.0.1")
	ip := getClientIP(req)
	if ip != "10.0.0.1" {
		t.Errorf("Expected IP 10.0.0.1, got %v", ip)
	}

	// Test with X-Real-IP header
	req, _ = http.NewRequest("GET", "/", nil)
	req.Header.Set("X-Real-IP", "10.0.0.2")
	ip = getClientIP(req)
	if ip != "10.0.0.2" {
		t.Errorf("Expected IP 10.0.0.2, got %v", ip)
	}

	// Test with RemoteAddr fallback
	req, _ = http.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.3:12345"
	ip = getClientIP(req)
	if ip != "10.0.0.3:12345" {
		t.Errorf("Expected IP 10.0.0.3:12345, got %v", ip)
	}
}

func TestRateLimitMiddleware(t *testing.T) {
	// Initialize rate limiter for tests
	rateLimiter = NewRateLimiter()

	// Create a simple handler that always returns 200
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Wrap with rate limiting
	limitedHandler := rateLimitMiddleware(testHandler)

	// Test that first request is allowed
	req, _ := http.NewRequest("POST", "/v1/analyze", bytes.NewBufferString("{}"))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "192.168.1.1:12345"

	rr := httptest.NewRecorder()
	limitedHandler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("First request should be allowed, got status %v", status)
	}
}

func TestPerformThreatAnalysis_DemoPackage(t *testing.T) {
	// Test with demo package name
	threats, _ := performThreatAnalysis("demo-package", "npm")

	if len(threats) == 0 {
		t.Error("Should detect threats for package with 'demo' keyword")
	}

	foundTyposquatting := false
	for _, threat := range threats {
		if threat.Type == "typosquatting" {
			foundTyposquatting = true
			if threat.Description != "Package name contains suspicious keywords" {
				t.Errorf("Expected description 'Package name contains suspicious keywords', got %v", threat.Description)
			}
		}
	}

	if !foundTyposquatting {
		t.Error("Should detect typosquatting threat for demo package")
	}
}
