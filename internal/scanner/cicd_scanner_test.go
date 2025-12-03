package scanner

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCICDScanner_GitHubActions(t *testing.T) {
	// Create temp project
	tmpDir, err := os.MkdirTemp("", "cicd-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create .github/workflows directory
	workflowDir := filepath.Join(tmpDir, ".github", "workflows")
	require.NoError(t, os.MkdirAll(workflowDir, 0755))

	t.Run("Shai-Hulud Pattern Detection", func(t *testing.T) {
		// Create malicious workflow (Shai-Hulud pattern)
		maliciousWorkflow := `
name: Discussion Create
on: discussion
jobs:
  process:
    runs-on: self-hosted
    steps:
      - uses: actions/checkout@v5
      - name: Handle Discussion
        run: echo ${{ github.event.discussion.body }}
`
		workflowPath := filepath.Join(workflowDir, "malicious.yml")
		require.NoError(t, os.WriteFile(workflowPath, []byte(maliciousWorkflow), 0644))

		scanner := NewCICDScanner(tmpDir)
		threats, err := scanner.ScanProject()
		require.NoError(t, err)

		// Should detect all 3 Shai-Hulud indicators
		assert.GreaterOrEqual(t, len(threats), 3, "Should detect self-hosted runner, injection, and C2 channel")

		// Verify threat types
		threatTypes := make(map[string]bool)
		for _, threat := range threats {
			threatTypes[string(threat.Type)] = true
		}

		assert.True(t, threatTypes["self_hosted_runner"], "Should detect self-hosted runner")
		assert.True(t, threatTypes["cicd_injection"], "Should detect code injection")
		assert.True(t, threatTypes["c2_channel"], "Should detect C2 channel")
	})

	t.Run("Injection Vulnerability Detection", func(t *testing.T) {
		// Clean up previous workflow
		os.RemoveAll(workflowDir)
		require.NoError(t, os.MkdirAll(workflowDir, 0755))

		injectionWorkflow := `
name: PR Check
on: pull_request
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.pull_request.title }}"
`
		workflowPath := filepath.Join(workflowDir, "pr-check.yml")
		require.NoError(t, os.WriteFile(workflowPath, []byte(injectionWorkflow), 0644))

		scanner := NewCICDScanner(tmpDir)
		threats, err := scanner.ScanProject()
		require.NoError(t, err)

		// Should detect injection vulnerability
		assert.GreaterOrEqual(t, len(threats), 1, "Should detect code injection")
		assert.Equal(t, "cicd_injection", string(threats[0].Type))
	})

	t.Run("Clean Workflow", func(t *testing.T) {
		// Clean up previous workflow
		os.RemoveAll(workflowDir)
		require.NoError(t, os.MkdirAll(workflowDir, 0755))

		cleanWorkflow := `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - run: npm test
`
		workflowPath := filepath.Join(workflowDir, "ci.yml")
		require.NoError(t, os.WriteFile(workflowPath, []byte(cleanWorkflow), 0644))

		scanner := NewCICDScanner(tmpDir)
		threats, err := scanner.ScanProject()
		require.NoError(t, err)

		// Should not detect any threats
		assert.Equal(t, 0, len(threats), "Clean workflow should have no threats")
	})
}

func TestCICDScanner_GitLabCI(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "gitlab-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	t.Run("Unknown Docker Registry", func(t *testing.T) {
		maliciousCIFile := `
image: attacker-registry.com/malicious:latest

stages:
  - test

test_job:
  stage: test
  script:
    - echo "Running tests"
`
		ciPath := filepath.Join(tmpDir, ".gitlab-ci.yml")
		require.NoError(t, os.WriteFile(ciPath, []byte(maliciousCIFile), 0644))

		scanner := NewCICDScanner(tmpDir)
		threats, err := scanner.ScanProject()
		require.NoError(t, err)

		// Should detect unknown registry
		assert.GreaterOrEqual(t, len(threats), 1, "Should detect unknown Docker registry")
	})

	t.Run("Hardcoded Secrets", func(t *testing.T) {
		secretsCIFile := `
variables:
  DATABASE_PASSWORD: "super_secret_123"
  API_KEY: "sk-1234567890"

stages:
  - deploy

deploy:
  stage: deploy
  script:
    - echo "Deploying..."
`
		ciPath := filepath.Join(tmpDir, ".gitlab-ci.yml")
		require.NoError(t, os.WriteFile(ciPath, []byte(secretsCIFile), 0644))

		scanner := NewCICDScanner(tmpDir)
		threats, err := scanner.ScanProject()
		require.NoError(t, err)

		// Should detect hardcoded secrets
		assert.GreaterOrEqual(t, len(threats), 1, "Should detect hardcoded secrets")
	})
}
