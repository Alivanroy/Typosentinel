package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// E2ETestSuite represents the end-to-end test suite
type E2ETestSuite struct {
	baseURL      string
	cliPath      string
	samplesDir   string
	serverPort   string
	serverCmd    *exec.Cmd
}

// TestMain runs the E2E test suite
func TestMain(m *testing.M) {
	// Setup test environment
	suite := setupE2ETestSuite()
	
	// Start test server
	if err := suite.startServer(); err != nil {
		fmt.Printf("Failed to start test server: %v\n", err)
		os.Exit(1)
	}
	
	// Wait for server to be ready
	time.Sleep(3 * time.Second)
	
	// Run tests
	code := m.Run()
	
	// Cleanup
	suite.cleanup()
	os.Exit(code)
}

func setupE2ETestSuite() *E2ETestSuite {
	baseDir, _ := os.Getwd()
	
	return &E2ETestSuite{
		baseURL:    "http://localhost:8080",
		cliPath:    filepath.Join(baseDir, "typosentinel"),
		samplesDir: filepath.Join(baseDir, "samples"),
		serverPort: "8080",
	}
}

func (s *E2ETestSuite) startServer() error {
	// Build the CLI first
	if err := s.buildCLI(); err != nil {
		return fmt.Errorf("failed to build CLI: %w", err)
	}
	
	// Start server in background
	s.serverCmd = exec.Command(s.cliPath, "server", "--port", s.serverPort)
	s.serverCmd.Stdout = os.Stdout
	s.serverCmd.Stderr = os.Stderr
	
	return s.serverCmd.Start()
}

func (s *E2ETestSuite) buildCLI() error {
	cmd := exec.Command("go", "build", "-o", s.cliPath, ".")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func (s *E2ETestSuite) cleanup() {
	if s.serverCmd != nil && s.serverCmd.Process != nil {
		s.serverCmd.Process.Kill()
		s.serverCmd.Wait()
	}
}

// TestCLIAPIScan tests the complete flow: CLI → API → DB → Response
func TestCLIAPIScan(t *testing.T) {
	suite := setupE2ETestSuite()
	
	tests := []struct {
		name           string
		projectPath    string
		expectedStatus int
		minThreats     int
	}{
		{
			name:           "npm ecommerce sample",
			projectPath:    filepath.Join(suite.samplesDir, "npm-ecommerce"),
			expectedStatus: 0,
			minThreats:     1,
		},
		{
			name:           "python ml api sample", 
			projectPath:    filepath.Join(suite.samplesDir, "python-ml-api"),
			expectedStatus: 0,
			minThreats:     1,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Run CLI scan
			cmd := exec.Command(suite.cliPath, "scan", tt.projectPath, "--output", "json")
			output, err := cmd.CombinedOutput()
			
			// Check command succeeded
			require.NoError(t, err, "CLI scan failed: %s", string(output))
			
			// Parse JSON output
			var result map[string]interface{}
			err = json.Unmarshal(output, &result)
			require.NoError(t, err, "Failed to parse JSON output")
			
			// Verify threats were detected
			threats, ok := result["threats"].([]interface{})
			require.True(t, ok, "No threats field in result")
			assert.GreaterOrEqual(t, len(threats), tt.minThreats, 
				"Expected at least %d threats, got %d", tt.minThreats, len(threats))
			
			// Verify scan metadata
			assert.NotEmpty(t, result["scan_id"], "Missing scan_id")
			assert.NotEmpty(t, result["timestamp"], "Missing timestamp")
		})
	}
}

// TestAPIServerEndpoints tests the REST API endpoints
func TestAPIServerEndpoints(t *testing.T) {
	httpClient := &http.Client{Timeout: 10 * time.Second}
	
	tests := []struct {
		name           string
		method         string
		path           string
		body           interface{}
		expectedStatus int
	}{
		{
			name:           "health check",
			method:         "GET",
			path:           "/health",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "API readiness",
			method:         "GET", 
			path:           "/ready",
			expectedStatus: http.StatusOK,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var req *http.Request
			var err error
			
			if tt.body != nil {
				jsonBody, _ := json.Marshal(tt.body)
				req, err = http.NewRequest(tt.method, "http://localhost:8080"+tt.path, 
					bytes.NewBuffer(jsonBody))
				require.NoError(t, err)
				req.Header.Set("Content-Type", "application/json")
			} else {
				req, err = http.NewRequest(tt.method, "http://localhost:8080"+tt.path, nil)
				require.NoError(t, err)
			}
			
			resp, err := httpClient.Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()
			
			assert.Equal(t, tt.expectedStatus, resp.StatusCode)
		})
	}
}

// TestSBOMGeneration tests SBOM generation functionality
func TestSBOMGeneration(t *testing.T) {
	suite := setupE2ETestSuite()
	
	// Test SPDX format
	cmd := exec.Command(suite.cliPath, "scan", 
		filepath.Join(suite.samplesDir, "npm-ecommerce"),
		"--sbom-format", "spdx",
		"--sbom-output", "/tmp/test-spdx-sbom.json")
	
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "SPDX SBOM generation failed: %s", string(output))
	
	// Verify SBOM file was created
	_, err = os.Stat("/tmp/test-spdx-sbom.json")
	assert.NoError(t, err, "SPDX SBOM file was not created")
	
	// Test CycloneDX format
	cmd = exec.Command(suite.cliPath, "scan",
		filepath.Join(suite.samplesDir, "python-ml-api"),
		"--sbom-format", "cyclonedx", 
		"--sbom-output", "/tmp/test-cyclonedx-sbom.json")
	
	output, err = cmd.CombinedOutput()
	require.NoError(t, err, "CycloneDX SBOM generation failed: %s", string(output))
	
	// Verify SBOM file was created
	_, err = os.Stat("/tmp/test-cyclonedx-sbom.json")
	assert.NoError(t, err, "CycloneDX SBOM file was not created")
}