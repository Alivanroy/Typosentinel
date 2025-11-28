//go:build realworld

package e2e

import (
    "bytes"
    "encoding/json"
    "os"
    "os/exec"
    "path/filepath"
    "testing"
    "github.com/stretchr/testify/require"
)

func TestRealGithubSBOMCycloneDXAndSPDX(t *testing.T){
    wd, err := os.Getwd()
    require.NoError(t, err)
    root := filepath.Dir(filepath.Dir(wd))
    tmp := t.TempDir()
    repos := []struct{ name, url string }{
        {"express", "https://github.com/expressjs/express.git"},
        {"gin", "https://github.com/gin-gonic/gin.git"},
    }
    for _, r := range repos {
        dst := filepath.Join(tmp, r.name)
        cmd := exec.Command("git", "clone", r.url, dst)
        out, err := cmd.CombinedOutput()
        require.NoError(t, err, string(out))

        cdx := exec.Command("go", "run", ".", "--", "scan", dst, "--output", "cyclonedx")
        cdx.Dir = root
        out1, err := cdx.CombinedOutput()
        require.NoError(t, err, string(out1))
        s1 := bytes.IndexByte(out1, '{')
        var obj1 map[string]interface{}
        if s1 >= 0 { require.NoError(t, json.Unmarshal(out1[s1:], &obj1)) }

        sp := exec.Command("go", "run", ".", "--", "scan", dst, "--output", "spdx")
        sp.Dir = root
        out2, err := sp.CombinedOutput()
        require.NoError(t, err, string(out2))
        s2 := bytes.IndexByte(out2, '{')
        var obj2 map[string]interface{}
        if s2 >= 0 { require.NoError(t, json.Unmarshal(out2[s2:], &obj2)) }
    }
}
