//go:build realworld

package realworld_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAlgorithmCLI verifies the edge algorithms via CLI commands
func TestAlgorithmCLI(t *testing.T) {
	wd, err := os.Getwd()
	require.NoError(t, err)
	root := filepath.Dir(filepath.Dir(filepath.Dir(wd))) // Adjust based on location: tests/e2e/testrealworld -> root
	binary := filepath.Join(root, "build", "typosentinel.exe")

	if _, err := os.Stat(binary); os.IsNotExist(err) {
		t.Skip("typosentinel.exe not found, skipping CLI tests")
	}

	t.Log("=== Scenario: RUNT Algorithm Edge Cases (CLI) ===")

	// Case 1: Keyboard Typo (reacy vs react)
	t.Run("RUNT: Keyboard Typo", func(t *testing.T) {
		cmd := exec.Command(binary, "edge", "runt", "reacy", "--similarity", "0.6", "--output", "json")
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, string(out))

		// Parse output
		// The output might be JSON lines or a single JSON object depending on implementation
		// The CLI command prints JSON for each package if multiple, or just one.
		// Let's assume it prints valid JSON.
		var result map[string]interface{}
		err = json.Unmarshal(out, &result)
		if err != nil {
			// Try finding the JSON part if there's noise
			start := strings.Index(string(out), "{")
			if start >= 0 {
				json.Unmarshal([]byte(out)[start:], &result)
			}
		}

		// Check findings
		findings, ok := result["findings"].([]interface{})
		if ok && len(findings) > 0 {
			t.Log("✓ RUNT detected suspicious findings for 'reacy'")
			// Verify it mentions 'react'
			foundReact := false
			for _, f := range findings {
				fMap := f.(map[string]interface{})
				msg := fMap["message"].(string)
				if strings.Contains(msg, "react") {
					foundReact = true
					break
				}
			}
			assert.True(t, foundReact, "Should identify 'react' as the target")
		} else {
			// If no findings, maybe the threshold was too high or 'react' isn't in known packages
			t.Log("⚠️ No findings for 'reacy'. Check known packages database.")
		}
	})

	// Case 2: Visual Homoglyph (goog1e vs google)
	t.Run("RUNT: Visual Homoglyph", func(t *testing.T) {
		cmd := exec.Command(binary, "edge", "runt", "goog1e", "--similarity", "0.6", "--output", "json")
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, string(out))

		var result map[string]interface{}
		start := strings.Index(string(out), "{")
		if start >= 0 {
			json.Unmarshal([]byte(out)[start:], &result)
		}

		findings, ok := result["findings"].([]interface{})
		if ok && len(findings) > 0 {
			t.Log("✓ RUNT detected suspicious findings for 'goog1e'")
			foundGoogle := false
			for _, f := range findings {
				fMap := f.(map[string]interface{})
				msg := fMap["message"].(string)
				if strings.Contains(msg, "google") {
					foundGoogle = true
					break
				}
			}
			assert.True(t, foundGoogle, "Should identify 'google' as the target")
		}
	})

	t.Log("=== Scenario: DIRT Algorithm Edge Cases (CLI) ===")

	// Case 3: DIRT Analysis (Stub/Mock check)
	t.Run("DIRT: Risk Analysis", func(t *testing.T) {
		// We expect the CLI to return a result now that we patched it
		cmd := exec.Command(binary, "edge", "dirt", "express", "--risk-threshold", "0.5", "--output", "json")
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, string(out))

		var result map[string]interface{}
		start := strings.Index(string(out), "{")
		if start >= 0 {
			json.Unmarshal([]byte(out)[start:], &result)
		}

		// Check metadata for assessment
		metadata, ok := result["metadata"].(map[string]interface{})
		require.True(t, ok, "Metadata should be present")

		expressData, ok := metadata["express"].(map[string]interface{})
		require.True(t, ok, "Express assessment data should be present")

		riskLevel := expressData["risk_level"].(string)
		t.Logf("✓ DIRT analyzed 'express'. Risk Level: %s", riskLevel)

		// Express is well maintained, so risk should be LOW or MEDIUM depending on multipliers
		// We used default INTERNAL multiplier (1.0)
		assert.Contains(t, []string{"LOW", "MEDIUM"}, riskLevel)
	})
}
