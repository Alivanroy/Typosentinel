//go:build e2e

package e2e

import (
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAPI_FullWorkflow(t *testing.T) {
	cmd := exec.Command("go", "run", "api/main.go")
	cmd.Env = append(os.Environ(), "PORT=18080", "API_AUTH_ENABLED=0")
	// Run from repo root so relative path api/main.go exists
	wd, _ := os.Getwd()
	cmd.Dir = filepath.Dir(filepath.Dir(wd))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	require.NoError(t, cmd.Start())
	defer func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()

	require.Eventually(t, func() bool {
		resp, err := http.Get("http://localhost:18080/health")
		return err == nil && resp.StatusCode == 200
	}, 10*time.Second, 200*time.Millisecond)

	payload := `{"package_name":"expresss","registry":"npm"}`
	resp, err := http.Post("http://localhost:18080/v1/analyze", "application/json", strings.NewReader(payload))
	require.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
}
