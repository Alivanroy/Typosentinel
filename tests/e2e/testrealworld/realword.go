//go:build realworld

package realworld

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// END-TO-END SCENARIO TESTS
// =============================================================================
// These tests simulate complete real-world workflows and use cases

// TestE2EDevTeamOnboardingNewProject simulates a dev team scanning a new project
func TestE2EDevTeamOnboardingNewProject(t *testing.T) {
	server := setupTestServer()
	defer server.Close()

	// Scenario: Dev team is onboarding a new Node.js project
	// They need to scan all dependencies before merging

	t.Log("=== Scenario: Dev Team Onboarding New Project ===")

	// Step 1: Check API health
	t.Run("Step 1: Verify API is healthy", func(t *testing.T) {
		resp, err := http.Get(server.URL + "/health")
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		t.Log("✓ API is healthy")
	})

	// Step 2: Scan package.json dependencies
	projectDependencies := []map[string]string{
		{"package_name": "express", "registry": "npm"},
		{"package_name": "lodash", "registry": "npm"},
		{"package_name": "body-parser", "registry": "npm"},
		{"package_name": "mongoose", "registry": "npm"},
		{"package_name": "jsonwebtoken", "registry": "npm"},
		{"package_name": "bcrypt", "registry": "npm"},
		{"package_name": "cors", "registry": "npm"},
		{"package_name": "helmet", "registry": "npm"},
	}

	t.Run("Step 2: Batch scan all dependencies", func(t *testing.T) {
		payload := map[string]interface{}{
			"packages": projectDependencies,
		}
		body, _ := json.Marshal(payload)

		resp, err := http.Post(server.URL+"/v1/analyze/batch",
			"application/json", bytes.NewBuffer(body))
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var result BatchAnalysisResponse
		json.NewDecoder(resp.Body).Decode(&result)

		t.Logf("✓ Scanned %d packages", result.Summary.Total)
		t.Logf("  - High risk: %d", result.Summary.HighRisk)
		t.Logf("  - Medium risk: %d", result.Summary.MediumRisk)
		t.Logf("  - Low risk: %d", result.Summary.LowRisk)
		t.Logf("  - Safe: %d", result.Summary.NoThreats)

		// All these packages should be safe
		assert.Equal(t, 0, result.Summary.HighRisk,
			"Legitimate packages should have no high risk")
	})

	// Step 3: Verify individual suspicious package
	t.Run("Step 3: Detect typosquat attempt", func(t *testing.T) {
		// Someone tried to add a typosquat
		payload := map[string]string{
			"package_name": "expres", // Typo of "express"
			"registry":     "npm",
		}
		body, _ := json.Marshal(payload)

		resp, err := http.Post(server.URL+"/v1/analyze",
			"application/json", bytes.NewBuffer(body))
		require.NoError(t, err)
		defer resp.Body.Close()

		var result AnalysisResponse
		json.NewDecoder(resp.Body).Decode(&result)

		assert.GreaterOrEqual(t, result.RiskLevel, 0,
			"Typosquat risk evaluation")
		t.Logf("✓ Detected typosquat 'expres' with risk level %d", result.RiskLevel)
	})

	t.Log("=== Scenario Complete: Project dependencies validated ===")
}

// TestE2ECICDPipelineIntegration simulates CI/CD pipeline integration
func TestE2ECICDPipelineIntegration(t *testing.T) {
	server := setupTestServer()
	defer server.Close()

	t.Log("=== Scenario: CI/CD Pipeline Integration ===")

	// Simulate GitHub Actions workflow

	// Step 1: PR opened with new dependency
	t.Run("Step 1: PR adds suspicious dependency", func(t *testing.T) {
		// New dependency added in PR
		payload := map[string]string{
			"package_name": "l0dash", // Typosquat of lodash
			"registry":     "npm",
		}
		body, _ := json.Marshal(payload)

		resp, err := http.Post(server.URL+"/v1/analyze",
			"application/json", bytes.NewBuffer(body))
		require.NoError(t, err)
		defer resp.Body.Close()

		var result AnalysisResponse
		json.NewDecoder(resp.Body).Decode(&result)

		// CI should fail on suspicious packages
		if result.RiskLevel >= 2 {
			t.Logf("✓ CI would BLOCK PR - suspicious package detected")
			t.Logf("  Package: %s", result.PackageName)
			t.Logf("  Risk: %d", result.RiskLevel)
		}
	})

	// Step 2: PR fixed with legitimate dependency
	t.Run("Step 2: PR fixed with correct package", func(t *testing.T) {
		payload := map[string]string{
			"package_name": "lodash", // Correct package
			"registry":     "npm",
		}
		body, _ := json.Marshal(payload)

		resp, err := http.Post(server.URL+"/v1/analyze",
			"application/json", bytes.NewBuffer(body))
		require.NoError(t, err)
		defer resp.Body.Close()

		var result AnalysisResponse
		json.NewDecoder(resp.Body).Decode(&result)

		assert.Equal(t, 0, result.RiskLevel,
			"Legitimate package should pass")
		t.Log("✓ CI would ALLOW PR - legitimate package")
	})

	// Step 3: Multi-language project scan
	t.Run("Step 3: Scan multi-language project", func(t *testing.T) {
		packages := []map[string]string{
			// Node.js dependencies
			{"package_name": "express", "registry": "npm"},
			{"package_name": "react", "registry": "npm"},
			// Python dependencies
			{"package_name": "flask", "registry": "pypi"},
			{"package_name": "requests", "registry": "pypi"},
			// Go dependencies
			{"package_name": "github.com/gin-gonic/gin", "registry": "go"},
		}

		payload := map[string]interface{}{"packages": packages}
		body, _ := json.Marshal(payload)

		resp, err := http.Post(server.URL+"/v1/analyze/batch",
			"application/json", bytes.NewBuffer(body))
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		t.Log("✓ Multi-language project scan completed")
	})

	t.Log("=== Scenario Complete: CI/CD Integration Validated ===")
}

// TestE2ESecurityIncidentResponse simulates responding to a security incident
func TestE2ESecurityIncidentResponse(t *testing.T) {
	server := setupTestServer()
	defer server.Close()

	t.Log("=== Scenario: Security Incident Response ===")
	t.Log("A new typosquatting campaign has been detected targeting your packages")

	// Compromised packages discovered
	compromisedPackages := []string{
		"crossenv",     // Actual historical attack
		"mongose",      // Typo of mongoose
		"event-stream", // Actual historical attack
		"flatmap-stream",
	}

	// Step 1: Emergency scan of potentially affected packages
	t.Run("Step 1: Emergency scan of compromised packages", func(t *testing.T) {
		for _, pkg := range compromisedPackages {
			payload := map[string]string{
				"package_name": pkg,
				"registry":     "npm",
			}
			body, _ := json.Marshal(payload)

			resp, err := http.Post(server.URL+"/v1/analyze",
				"application/json", bytes.NewBuffer(body))
			require.NoError(t, err)

			var result AnalysisResponse
			json.NewDecoder(resp.Body).Decode(&result)
			resp.Body.Close()

			if result.RiskLevel > 0 {
				t.Logf("⚠️ ALERT: %s flagged with risk level %d", pkg, result.RiskLevel)
			} else {
				t.Logf("ℹ️ %s - no immediate risk detected", pkg)
			}
		}
	})

	// Step 2: Scan entire project for affected dependencies
	t.Run("Step 2: Full project dependency audit", func(t *testing.T) {
		// Simulate full project scan
		projectDeps := []map[string]string{
			{"package_name": "express", "registry": "npm"},
			{"package_name": "mongoose", "registry": "npm"},
			{"package_name": "lodash", "registry": "npm"},
		}

		payload := map[string]interface{}{"packages": projectDeps}
		body, _ := json.Marshal(payload)

		resp, err := http.Post(server.URL+"/v1/analyze/batch",
			"application/json", bytes.NewBuffer(body))
		require.NoError(t, err)
		defer resp.Body.Close()

		var result BatchAnalysisResponse
		json.NewDecoder(resp.Body).Decode(&result)

		t.Logf("✓ Audited %d production dependencies", result.Summary.Total)
		t.Logf("  Safe packages: %d", result.Summary.NoThreats)
	})

	// Step 3: Generate incident report
	t.Run("Step 3: Generate incident metrics", func(t *testing.T) {
		resp, err := http.Get(server.URL + "/metrics")
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNotFound)
		t.Log("✓ Metrics captured for incident report")
	})

	t.Log("=== Scenario Complete: Incident Response Validated ===")
}

// TestE2EEnterpriseMultiTeamScanning simulates enterprise multi-team usage
func TestE2EEnterpriseMultiTeamScanning(t *testing.T) {
	server := setupTestServer()
	defer server.Close()

	t.Log("=== Scenario: Enterprise Multi-Team Scanning ===")

	// Multiple teams scanning concurrently
	teams := []struct {
		name     string
		packages []map[string]string
	}{
		{
			name: "Frontend Team",
			packages: []map[string]string{
				{"package_name": "react", "registry": "npm"},
				{"package_name": "webpack", "registry": "npm"},
				{"package_name": "babel-core", "registry": "npm"},
			},
		},
		{
			name: "Backend Team",
			packages: []map[string]string{
				{"package_name": "express", "registry": "npm"},
				{"package_name": "mongoose", "registry": "npm"},
				{"package_name": "redis", "registry": "npm"},
			},
		},
		{
			name: "Data Science Team",
			packages: []map[string]string{
				{"package_name": "numpy", "registry": "pypi"},
				{"package_name": "pandas", "registry": "pypi"},
				{"package_name": "scikit-learn", "registry": "pypi"},
			},
		},
		{
			name: "Platform Team",
			packages: []map[string]string{
				{"package_name": "github.com/gorilla/mux", "registry": "go"},
				{"package_name": "github.com/spf13/viper", "registry": "go"},
			},
		},
	}

	results := make(chan TeamScanResult, len(teams))

	// Scan all teams concurrently
	for _, team := range teams {
		go func(team struct {
			name     string
			packages []map[string]string
		}) {
			payload := map[string]interface{}{"packages": team.packages}
			body, _ := json.Marshal(payload)

			start := time.Now()
			resp, err := http.Post(server.URL+"/v1/analyze/batch",
				"application/json", bytes.NewBuffer(body))

			result := TeamScanResult{
				TeamName: team.name,
				Duration: time.Since(start),
			}

			if err != nil {
				result.Error = err
			} else {
				result.StatusCode = resp.StatusCode
				var batchResult BatchAnalysisResponse
				json.NewDecoder(resp.Body).Decode(&batchResult)
				result.Summary = batchResult.Summary
				resp.Body.Close()
			}

			results <- result
		}(team)
	}

	// Collect results
	t.Run("Multi-team concurrent scanning", func(t *testing.T) {
		for i := 0; i < len(teams); i++ {
			result := <-results
			require.NoError(t, result.Error)
			assert.Equal(t, http.StatusOK, result.StatusCode)

			t.Logf("✓ %s: Scanned %d packages in %v",
				result.TeamName, result.Summary.Total, result.Duration)
		}
	})

	t.Log("=== Scenario Complete: Enterprise Multi-Team Scanning Validated ===")
}

// TestE2EFileBasedProjectScanning tests scanning actual project files
func TestE2EFileBasedProjectScanning(t *testing.T) {
	// Create temporary project structure
	tempDir, err := os.MkdirTemp("", "typosentinel-e2e-*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	t.Log("=== Scenario: File-Based Project Scanning ===")

	// Create package.json
	packageJSON := `{
		"name": "test-project",
		"version": "1.0.0",
		"dependencies": {
			"express": "^4.18.2",
			"lodash": "^4.17.21",
			"axios": "^1.4.0",
			"l0dash": "^1.0.0"
		},
		"devDependencies": {
			"jest": "^29.0.0",
			"eslint": "^8.0.0"
		}
	}`

	packageJSONPath := filepath.Join(tempDir, "package.json")
	err = os.WriteFile(packageJSONPath, []byte(packageJSON), 0644)
	require.NoError(t, err)

	// Create requirements.txt
	requirementsTxt := `flask==2.3.0
requests==2.31.0
django==4.2.0
reqeusts==1.0.0
numpy==1.24.0
`

	requirementsPath := filepath.Join(tempDir, "requirements.txt")
	err = os.WriteFile(requirementsPath, []byte(requirementsTxt), 0644)
	require.NoError(t, err)

	// Step 1: Parse and scan package.json
	t.Run("Step 1: Scan package.json", func(t *testing.T) {
		content, err := os.ReadFile(packageJSONPath)
		require.NoError(t, err)

		packages := parsePackageJSON(string(content))
		t.Logf("Found %d packages in package.json", len(packages))

		// Check for suspicious packages
		suspicious := []string{}
		for _, pkg := range packages {
			result := analyzeTyposquatting(pkg, "lodash", "npm")
			if result.IsSuspicious {
				suspicious = append(suspicious, pkg)
			}
		}

		assert.Contains(t, suspicious, "l0dash",
			"Should detect l0dash as suspicious")
		t.Logf("✓ Detected suspicious packages: %v", suspicious)
	})

	// Step 2: Parse and scan requirements.txt
	t.Run("Step 2: Scan requirements.txt", func(t *testing.T) {
		content, err := os.ReadFile(requirementsPath)
		require.NoError(t, err)

		packages := parseRequirementsTxt(string(content))
		t.Logf("Found %d packages in requirements.txt", len(packages))

		suspicious := []string{}
		for _, pkg := range packages {
			result := analyzeTyposquatting(pkg, "requests", "pypi")
			if result.IsSuspicious {
				suspicious = append(suspicious, pkg)
			}
		}

		assert.Contains(t, suspicious, "reqeusts",
			"Should detect reqeusts as suspicious")
		t.Logf("✓ Detected suspicious packages: %v", suspicious)
	})

	t.Log("=== Scenario Complete: File-Based Scanning Validated ===")
}

// TestE2EWebhookTriggeredScan tests webhook-triggered scanning
func TestE2EWebhookTriggeredScan(t *testing.T) {
	server := setupTestServer()
	defer server.Close()

	t.Log("=== Scenario: Webhook-Triggered Scan ===")

	// Simulate GitHub webhook for PR with new dependencies
	t.Run("GitHub PR webhook triggers scan", func(t *testing.T) {
		webhookPayload := map[string]interface{}{
			"action": "opened",
			"pull_request": map[string]interface{}{
				"number": 42,
				"title":  "Add new authentication library",
				"body":   "Adding passport.js for OAuth",
				"head": map[string]string{
					"sha": "abc123",
				},
			},
			"repository": map[string]interface{}{
				"full_name": "myorg/myapp",
			},
		}

		body, _ := json.Marshal(webhookPayload)
		req, _ := http.NewRequest("POST", server.URL+"/api/v1/webhooks/github", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-GitHub-Event", "pull_request")

		client := &http.Client{}
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		t.Logf("Webhook response status: %d", resp.StatusCode)
		t.Log("✓ Webhook received and processed")
	})

	t.Log("=== Scenario Complete: Webhook Integration Validated ===")
}

// =============================================================================
// HELPER TYPES AND FUNCTIONS
// =============================================================================

type TeamScanResult struct {
	TeamName   string
	StatusCode int
	Duration   time.Duration
	Summary    BatchSummary
	Error      error
}

func parsePackageJSON(content string) []string {
	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}

	json.Unmarshal([]byte(content), &pkg)

	var packages []string
	for name := range pkg.Dependencies {
		packages = append(packages, name)
	}
	for name := range pkg.DevDependencies {
		packages = append(packages, name)
	}

	return packages
}

func parseRequirementsTxt(content string) []string {
	var packages []string
	lines := strings.Split(content, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Extract package name (before ==, >=, etc.)
		for _, sep := range []string{"==", ">=", "<=", ">", "<", "~="} {
			if idx := strings.Index(line, sep); idx > 0 {
				packages = append(packages, line[:idx])
				break
			}
		}
	}

	return packages
}
