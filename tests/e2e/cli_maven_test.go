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

func TestCLI_ScanMavenProject(t *testing.T) {
    tmp := t.TempDir()
    pom := `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>e2e-maven-project</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>org.apache.commons</groupId>
      <artifactId>commons-lang3</artifactId>
      <version>3.12.0</version>
    </dependency>
  </dependencies>
</project>`
    require.NoError(t, os.WriteFile(filepath.Join(tmp, "pom.xml"), []byte(pom), 0o644))

    // Run CLI via go run from repo root
    wd, _ := os.Getwd()
    repoRoot := filepath.Dir(filepath.Dir(wd))
    cmd := exec.Command("go", "run", ".", "scan", tmp, "--output", "json")
    cmd.Dir = repoRoot
    out, err := cmd.CombinedOutput()
    require.NoError(t, err, string(out))

    // Extract JSON portion
    start := bytes.IndexByte(out, '{')
    require.GreaterOrEqual(t, start, 0, string(out))

    // Parse and check total_packages >= 1
    var res map[string]any
    require.NoError(t, json.Unmarshal(out[start:], &res))
    tp, ok := res["total_packages"].(float64)
    require.True(t, ok)
    assert.GreaterOrEqual(t, int(tp), 1)
}
