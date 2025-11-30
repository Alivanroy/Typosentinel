//go:build realworld

package realworld

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestE2EEdgeCases runs various edge case scenarios
func TestE2EEdgeCases(t *testing.T) {
	server := setupTestServer()
	defer server.Close()

	t.Log("=== Scenario: Edge Case Testing ===")

	// 1. Homoglyph Attack (Cyrillic 'a' vs Latin 'a')
	t.Run("Edge Case: Homoglyph Attack", func(t *testing.T) {
		// "react" with Cyrillic 'a' (U+0430)
		// react -> re\u0430ct
		homoglyphName := "re\u0430ct" 
		
		payload := map[string]string{
			"package_name": homoglyphName,
			"registry":     "npm",
		}
		body, _ := json.Marshal(payload)

		resp, err := http.Post(server.URL+"/v1/analyze", "application/json", bytes.NewBuffer(body))
		require.NoError(t, err)
		defer resp.Body.Close()

		var result AnalysisResponse
		json.NewDecoder(resp.Body).Decode(&result)

		// Should be detected as high risk
		assert.Greater(t, result.RiskLevel, 0, "Homoglyph should be detected as risk")
		t.Logf("✓ Detected homoglyph '%s' with risk level %d", homoglyphName, result.RiskLevel)
	})

	// 2. Deeply Nested Dependencies (Simulation)
	t.Run("Edge Case: Deep Dependency Chain", func(t *testing.T) {
		// We can't easily simulate a real deep chain without mocking the registry response or having a real deep repo.
		// For this E2E test, we'll check if the batch analyzer handles a large list of "chained" dependencies without timeout/error.
		
		// Create a chain of 50 dependencies
		packages := make([]map[string]string, 50)
		for i := 0; i < 50; i++ {
			packages[i] = map[string]string{
				"package_name": "express", // Using a safe package repeatedly to test throughput/depth handling
				"registry":     "npm",
			}
		}

		payload := map[string]interface{}{"packages": packages}
		body, _ := json.Marshal(payload)

		resp, err := http.Post(server.URL+"/v1/analyze/batch", "application/json", bytes.NewBuffer(body))
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		
		var result BatchAnalysisResponse
		json.NewDecoder(resp.Body).Decode(&result)
		
		assert.Equal(t, 50, result.Summary.Total)
		t.Log("✓ Successfully processed batch of 50 packages (simulating depth/volume)")
	})

	// 3. Mixed Ecosystems in Single Request
	t.Run("Edge Case: Mixed Ecosystems", func(t *testing.T) {
		packages := []map[string]string{
			{"package_name": "react", "registry": "npm"},
			{"package_name": "django", "registry": "pypi"},
			{"package_name": "github.com/gin-gonic/gin", "registry": "go"},
			{"package_name": "log4j", "registry": "maven"},
			{"package_name": "serde", "registry": "cargo"},
		}

		payload := map[string]interface{}{"packages": packages}
		body, _ := json.Marshal(payload)

		resp, err := http.Post(server.URL+"/v1/analyze/batch", "application/json", bytes.NewBuffer(body))
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		
		var result BatchAnalysisResponse
		json.NewDecoder(resp.Body).Decode(&result)
		
		assert.Equal(t, 5, result.Summary.Total)
		t.Log("✓ Successfully handled mixed ecosystem batch")
	})

	// 4. Zero-width characters (Obfuscation)
	t.Run("Edge Case: Zero-width Obfuscation", func(t *testing.T) {
		// "lodash" with zero-width space (U+200B) inserted
		// lo\u200bdash
		obfuscatedName := "lo\u200bdash"

		payload := map[string]string{
			"package_name": obfuscatedName,
			"registry":     "npm",
		}
		body, _ := json.Marshal(payload)

		resp, err := http.Post(server.URL+"/v1/analyze", "application/json", bytes.NewBuffer(body))
		require.NoError(t, err)
		defer resp.Body.Close()

		var result AnalysisResponse
		json.NewDecoder(resp.Body).Decode(&result)

		// Should be detected
		assert.Greater(t, result.RiskLevel, 0, "Zero-width obfuscation should be detected")
		t.Logf("✓ Detected zero-width obfuscation '%s' with risk level %d", obfuscatedName, result.RiskLevel)
	})
}
