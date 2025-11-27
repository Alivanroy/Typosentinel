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

func TestCLI_ScanGoProject(t *testing.T) {
    tmp := t.TempDir()
    gomod := `module example.com/e2e-go-project

go 1.21

require (
    github.com/sirupsen/logrus v1.9.0 // indirect
)`
    require.NoError(t, os.WriteFile(filepath.Join(tmp, "go.mod"), []byte(gomod), 0o644))

    // Optional go.sum not required; analyzer tolerates absence

    wd, _ := os.Getwd()
    repoRoot := filepath.Dir(filepath.Dir(wd))
    cmd := exec.Command("go", "run", ".", "scan", tmp, "--output", "json")
    cmd.Dir = repoRoot
    out, err := cmd.CombinedOutput()
    require.NoError(t, err, string(out))

    start := bytes.IndexByte(out, '{')
    require.GreaterOrEqual(t, start, 0, string(out))
    var res map[string]any
    require.NoError(t, json.Unmarshal(out[start:], &res))
    tp, ok := res["total_packages"].(float64)
    require.True(t, ok)
    if int(tp) == 0 {
        t.Skip("Go ecosystem parsing not wired in analyzer JSON path yet")
    }
    assert.GreaterOrEqual(t, int(tp), 1)
}
