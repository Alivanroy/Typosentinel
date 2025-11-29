//go:build e2e

package e2e

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type cliScanEnvelope map[string]any

func TestCLI_ScanNpmProject(t *testing.T) {
	tmp := t.TempDir()
	pkg := `{
  "name": "e2e-npm-project",
  "version": "1.0.0",
  "dependencies": {
    "express": "^4.18.0",
    "expresss": "^1.0.0"
  }
}`
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "package.json"), []byte(pkg), 0o644))

	// Run CLI via go run from repo root
	wd, _ := os.Getwd()
	repoRoot := filepath.Dir(filepath.Dir(wd))
	cmd := exec.Command("go", "run", ".", "scan", tmp, "--output", "json")
	cmd.Dir = repoRoot
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
	// Extract JSON portion from mixed logs
	start := bytes.IndexByte(out, '{')
	require.GreaterOrEqual(t, start, 0, string(out))
	var res cliScanEnvelope
	require.NoError(t, json.Unmarshal(out[start:], &res))
	// Extract threats array in a tolerant way
	var threatsLen int
	if v, ok := res["Threats"]; ok {
		if arr, ok := v.([]any); ok {
			threatsLen = len(arr)
		}
	} else if v, ok := res["threats"]; ok {
		if arr, ok := v.([]any); ok {
			threatsLen = len(arr)
		}
	}
	assert.GreaterOrEqual(t, threatsLen, 1)
}
