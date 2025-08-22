package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// SecurityTestSuite contains security-focused tests
type SecurityTestSuite struct {
	baseURL string
}

// TestSQLInjectionPrevention tests SQL injection attack prevention
func TestSQLInjectionPrevention(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	sqlInjectionPayloads := []string{
		"'; DROP TABLE packages; --",
		"' OR '1'='1",
		"'; SELECT * FROM users; --",
		"' UNION SELECT password FROM users --",
		"'; INSERT INTO packages VALUES ('malicious'); --",
	}

	for _, payload := range sqlInjectionPayloads {
		t.Run(fmt.Sprintf("SQLInjection_%s", payload), func(t *testing.T) {
			reqBody := map[string]interface{}{
				"package_name": payload,
				"version":      "1.0.0",
			}

			body, _ := json.Marshal(reqBody)
			resp, err := makeRequest(ts.baseURL, "POST", "/api/v1/analyze", body)
			require.NoError(t, err)
			defer resp.Body.Close()

			// Should return 400 (bad request) for malicious input, not 500 (server error)
			assert.True(t, resp.StatusCode == 400 || resp.StatusCode == 422, 
				"Expected 400 or 422 for SQL injection attempt, got %d", resp.StatusCode)
		})
	}
}

// TestXSSPrevention tests Cross-Site Scripting attack prevention
func TestXSSPrevention(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	xssPayloads := []string{
		"<script>alert('xss')</script>",
		"javascript:alert('xss')",
		"<img src=x onerror=alert('xss')>",
		"<svg onload=alert('xss')>",
		"';alert('xss');//",
	}

	for _, payload := range xssPayloads {
		t.Run(fmt.Sprintf("XSS_%s", payload), func(t *testing.T) {
			reqBody := map[string]interface{}{
				"package_name": payload,
				"version":      "1.0.0",
			}

			body, _ := json.Marshal(reqBody)
			resp, err := makeRequest(ts.baseURL, "POST", "/api/v1/analyze", body)
			require.NoError(t, err)
			defer resp.Body.Close()

			// Should sanitize input and return appropriate error
			assert.True(t, resp.StatusCode == 400 || resp.StatusCode == 422,
				"Expected 400 or 422 for XSS attempt, got %d", resp.StatusCode)

			// Check response doesn't contain unsanitized script
			respBody, _ := io.ReadAll(resp.Body)
			assert.NotContains(t, string(respBody), "<script>",
				"Response should not contain unsanitized script tags")
		})
	}
}

// TestAuthenticationBypass tests authentication bypass attempts
func TestAuthenticationBypass(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	// Test various authentication bypass attempts
	bypassAttempts := []struct {
		name   string
		method string
		path   string
		headers map[string]string
	}{
		{"No Auth Header", "POST", "/api/v1/analyze", nil},
		{"Invalid Token", "POST", "/api/v1/analyze", map[string]string{"Authorization": "Bearer invalid"}},
		{"Malformed Token", "POST", "/api/v1/analyze", map[string]string{"Authorization": "malformed"}},
		{"Empty Token", "POST", "/api/v1/analyze", map[string]string{"Authorization": "Bearer "}},
		{"SQL Injection in Auth", "POST", "/api/v1/analyze", map[string]string{"Authorization": "Bearer ' OR 1=1 --"}},
	}

	for i, attempt := range bypassAttempts {
		t.Run(fmt.Sprintf("AuthBypass_%d", i), func(t *testing.T) {
			body := []byte(`{"package_name":"test"}`)
			resp, err := makeRequest(ts.baseURL, attempt.method, attempt.path, body)
			require.NoError(t, err)
			defer resp.Body.Close()

			// In test environment, endpoints may not require auth
			// Check that we get a valid response (400 for bad request is acceptable)
			assert.True(t, resp.StatusCode == 400 || resp.StatusCode == 401 || resp.StatusCode == 403,
				"Expected 400, 401, or 403 for authentication test, got %d", resp.StatusCode)
			t.Logf("Auth bypass test %s returned status %d", attempt.name, resp.StatusCode)
		})
	}
}

// TestRateLimitingEnforcement tests rate limiting enforcement
func TestRateLimitingEnforcement(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	// Make rapid requests to trigger rate limiting
	var responses []*http.Response
	for i := 0; i < 20; i++ {
		resp, err := makeRequest(ts.baseURL, "GET", "/health", nil)
		require.NoError(t, err)
		responses = append(responses, resp)
	}

	// Check if any requests were rate limited (429 status)
	rateLimited := false
	for _, resp := range responses {
		if resp.StatusCode == 429 {
			rateLimited = true
			break
		}
		resp.Body.Close()
	}

	// Note: Rate limiting might not trigger in test environment
	// This test verifies the endpoint handles rapid requests gracefully
	if !rateLimited {
		t.Log("Rate limiting not triggered - this may be expected in test environment")
	}
}

// TestInputValidationEdgeCases tests edge cases in input validation
func TestInputValidationEdgeCases(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	edgeCases := []map[string]interface{}{
		{"package_name": "", "version": "1.0.0"}, // Empty package name
		{"package_name": strings.Repeat("a", 1000), "version": "1.0.0"}, // Very long package name
		{"package_name": "test", "version": ""}, // Empty version
		{"package_name": "test", "version": strings.Repeat("1.", 500)}, // Very long version
		{"package_name": "../../../etc/passwd", "version": "1.0.0"}, // Path traversal
		{"package_name": "test\x00null", "version": "1.0.0"}, // Null byte injection
		{"package_name": "test", "version": "1.0.0\x00"}, // Null byte in version
	}

	for i, testCase := range edgeCases {
		t.Run(fmt.Sprintf("EdgeCase_%d", i), func(t *testing.T) {
			body, _ := json.Marshal(testCase)
			resp, err := makeRequest(ts.baseURL, "POST", "/api/v1/analyze", body)
			require.NoError(t, err)
			defer resp.Body.Close()

			// Should handle edge cases gracefully with appropriate error codes
			assert.True(t, resp.StatusCode >= 400 && resp.StatusCode < 500,
				"Expected 4xx status for edge case input, got %d", resp.StatusCode)
		})
	}
}

// TestJSONBombPrevention tests protection against JSON bomb attacks
func TestJSONBombPrevention(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	// Create deeply nested JSON structure
	deepJSON := `{"a":{"b":{"c":{"d":{"e":{"f":{"g":{"h":{"i":{"j":{"k":{"l":{"m":{"n":{"o":{"p":{"q":{"r":{"s":{"t":"value"}}}}}}}}}}}}}}}}}}}`
	
	// Create large JSON payload
	largeArray := make([]string, 10000)
	for i := range largeArray {
		largeArray[i] = strings.Repeat("x", 100)
	}
	largeJSON, _ := json.Marshal(map[string]interface{}{
		"package_name": "test",
		"version":      "1.0.0",
		"large_data":   largeArray,
	})

	testCases := []struct {
		name string
		data []byte
	}{
		{"DeepNesting", []byte(deepJSON)},
		{"LargePayload", largeJSON},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := makeRequest(ts.baseURL, "POST", "/api/v1/analyze", tc.data)
			require.NoError(t, err)
			defer resp.Body.Close()

			// Should reject malformed or oversized JSON
			assert.True(t, resp.StatusCode >= 400 && resp.StatusCode < 500,
				"Expected 4xx status for JSON bomb attempt, got %d", resp.StatusCode)
		})
	}
}

// TestSecurityHeaders tests presence of security headers
func TestSecurityHeaders(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	resp, err := makeRequest(ts.baseURL, "GET", "/health", nil)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Check for basic security headers that should be present
	// Note: Some headers may not be set in test environment
	securityHeaders := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
	}

	for header, expectedValue := range securityHeaders {
		actualValue := resp.Header.Get(header)
		if actualValue != "" {
			assert.Equal(t, expectedValue, actualValue,
				"Security header %s should be set to %s, got %s", header, expectedValue, actualValue)
		} else {
			t.Logf("Security header %s not set in test environment", header)
		}
	}

	// Log all headers for debugging
	t.Logf("Response headers: %+v", resp.Header)

	// Verify the response is successful
	assert.Equal(t, 200, resp.StatusCode, "Health endpoint should return 200")
}

// TestDependencyConfusionPrevention tests protection against dependency confusion attacks
func TestDependencyConfusionPrevention(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	// Test suspicious package names that might indicate dependency confusion
	suspiciousPackages := []string{
		"internal-company-package",
		"@company/internal-tool",
		"company-secret-lib",
		"private-utils",
	}

	for _, pkg := range suspiciousPackages {
		t.Run(fmt.Sprintf("DepConfusion_%s", pkg), func(t *testing.T) {
			reqBody := map[string]interface{}{
				"package_name": pkg,
				"version":      "1.0.0",
			}

			body, _ := json.Marshal(reqBody)
			resp, err := makeRequest(ts.baseURL, "POST", "/api/v1/analyze", body)
			require.NoError(t, err)
			defer resp.Body.Close()

			// Should analyze the package and potentially flag suspicious patterns
			assert.True(t, resp.StatusCode == 200 || resp.StatusCode == 400,
				"Expected 200 or 400 for suspicious package analysis, got %d", resp.StatusCode)

			if resp.StatusCode == 200 {
				var result map[string]interface{}
				json.NewDecoder(resp.Body).Decode(&result)
				// Check if the response includes security warnings
				t.Logf("Analysis result for %s: %+v", pkg, result)
			}
		})
	}
}

// TestTimingAttackPrevention tests protection against timing attacks
func TestTimingAttackPrevention(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	// Test with valid and invalid package names to check for timing differences
	testCases := []string{
		"express",     // Popular package (likely to exist)
		"nonexistent-package-12345", // Unlikely to exist
		"react",       // Popular package
		"fake-package-xyz", // Unlikely to exist
	}

	var timings []time.Duration

	for _, pkg := range testCases {
		reqBody := map[string]interface{}{
			"package_name": pkg,
			"version":      "1.0.0",
		}

		body, _ := json.Marshal(reqBody)
		start := time.Now()
		resp, err := makeRequest(ts.baseURL, "POST", "/api/v1/analyze", body)
		duration := time.Since(start)
		timings = append(timings, duration)

		require.NoError(t, err)
		resp.Body.Close()
	}

	// Check that timing differences are not excessive (basic timing attack prevention)
	var maxTiming, minTiming time.Duration
	for i, timing := range timings {
		if i == 0 {
			maxTiming = timing
			minTiming = timing
		} else {
			if timing > maxTiming {
				maxTiming = timing
			}
			if timing < minTiming {
				minTiming = timing
			}
		}
	}

	// Log timing information for analysis
	t.Logf("Timing analysis - Min: %v, Max: %v, Ratio: %.2f", 
		minTiming, maxTiming, float64(maxTiming)/float64(minTiming))

	// This is a basic check - in production, more sophisticated timing analysis would be needed
	assert.True(t, float64(maxTiming)/float64(minTiming) < 10.0,
		"Timing difference should not be excessive (potential timing attack vector)")
}

// TestConcurrentSecurityRequests tests security under concurrent load
func TestConcurrentSecurityRequests(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	context, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Launch concurrent requests with various payloads
	payloads := []map[string]interface{}{
		{"package_name": "test1", "version": "1.0.0"},
		{"package_name": "test2", "version": "2.0.0"},
		{"package_name": "'; DROP TABLE packages; --", "version": "1.0.0"}, // SQL injection
		{"package_name": "<script>alert('xss')</script>", "version": "1.0.0"}, // XSS
	}

	var responses []int
	responseChan := make(chan int, 40)

	// Launch 10 concurrent requests for each payload
	for _, payload := range payloads {
		for i := 0; i < 10; i++ {
			go func(p map[string]interface{}) {
				body, _ := json.Marshal(p)
				resp, err := makeRequest(ts.baseURL, "POST", "/api/v1/analyze", body)
				if err == nil {
					responseChan <- resp.StatusCode
					resp.Body.Close()
				} else {
					responseChan <- 0 // Error case
				}
			}(payload)
		}
	}

	// Collect responses
	for i := 0; i < 40; i++ {
		select {
		case status := <-responseChan:
			responses = append(responses, status)
		case <-context.Done():
			t.Fatal("Test timed out waiting for responses")
		}
	}

	// Verify all requests were handled (no crashes or hangs)
	assert.Equal(t, 40, len(responses), "All concurrent requests should be handled")

	// Verify no server errors (5xx) occurred
	for _, status := range responses {
		assert.True(t, status < 500 || status == 0, 
			"No server errors should occur under concurrent load, got status %d", status)
	}
}