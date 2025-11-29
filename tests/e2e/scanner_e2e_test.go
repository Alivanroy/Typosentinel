// tests/e2e/scanner_e2e_test.go
//go:build e2e
// +build e2e

package e2e

import (
	"github.com/Alivanroy/Typosentinel/internal/analyzer"
	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
)

func TestE2E_ScanVulnerableNPMProject(t *testing.T) {
	// Setup
	projectPath := filepath.Join("test-projects", "npm-vulnerable")

	// Verify test project exists
	require.DirExists(t, projectPath)

	// Create analyzer with minimal config
	cfg := config.NewDefaultConfig()
	analyzerInstance, err := analyzer.New(cfg)
	require.NoError(t, err)

	// Execute scan
	result, err := analyzerInstance.Scan(projectPath, &analyzer.ScanOptions{
		CheckVulnerabilities: false, // Disable vulnerability checking for typosquatting focus
	})

	// Assertions
	require.NoError(t, err, "Scan should complete without error")
	require.NotNil(t, result, "Result should not be nil")

	// Should detect at least 2 typosquats (expresss and crossenv)
	assert.GreaterOrEqual(t, len(result.Threats), 2,
		"Should detect at least 2 typosquat threats")

	// Should identify specific threats
	threatNames := make(map[string]bool)
	for _, threat := range result.Threats {
		threatNames[threat.Package] = true
	}

	assert.True(t, threatNames["expresss"] || threatNames["crossenv"],
		"Should detect known typosquats")

	// Verify threat details
	for _, threat := range result.Threats {
		assert.NotEmpty(t, threat.Description, "Threat should have description")
		assert.NotEmpty(t, threat.Severity, "Threat should have severity")
		assert.Contains(t, []string{"low", "medium", "high", "critical"},
			threat.Severity.String(), "Severity should be valid")
	}
}

func TestE2E_ScanCleanProject(t *testing.T) {
	// Create clean project
	tmpDir := t.TempDir()
	cleanProject := filepath.Join(tmpDir, "clean")
	err := os.MkdirAll(cleanProject, 0755)
	require.NoError(t, err)

	// Create clean package.json
	packageJSON := `{
        "name": "clean-app",
        "version": "1.0.0",
        "dependencies": {
            "express": "^4.18.0",
            "lodash": "^4.17.21"
        }
    }`
	err = os.WriteFile(filepath.Join(cleanProject, "package.json"), []byte(packageJSON), 0644)
	require.NoError(t, err)

	// Create analyzer
	cfg := config.NewDefaultConfig()
	analyzerInstance, err := analyzer.New(cfg)
	require.NoError(t, err)

	// Execute scan
	result, err := analyzerInstance.Scan(cleanProject,
		&analyzer.ScanOptions{})

	// Assertions
	require.NoError(t, err)
	assert.Equal(t, 0, len(result.Threats),
		"Clean project should have no threats")
	assert.Greater(t, result.TotalPackages, 0,
		"Should have scanned packages")
}
