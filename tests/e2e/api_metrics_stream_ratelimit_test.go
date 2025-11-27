//go:build e2e

package e2e

import (
    "bytes"
    "encoding/json"
    "net/http"
    "os"
    "os/exec"
    "strings"
    "testing"
    "time"
)

func waitFor(url string, timeout time.Duration) bool {
    deadline := time.Now().Add(timeout)
    for time.Now().Before(deadline) {
        resp, err := http.Get(url)
        if err == nil && resp.StatusCode == http.StatusOK { return true }
        time.Sleep(200 * time.Millisecond)
    }
    return false
}

func startAPIServer(t *testing.T) *exec.Cmd {
    cmd := exec.Command("go", "run", "./api")
    cmd.Env = append(os.Environ(), "PORT=18080", "API_AUTH_ENABLED=false")
    if err := cmd.Start(); err != nil { t.Fatalf("failed to start api server: %v", err) }
    ok := waitFor("http://localhost:18080/health", 10*time.Second)
    if !ok { t.Fatalf("server not ready") }
    return cmd
}

func stopAPIServer(cmd *exec.Cmd) { _ = cmd.Process.Kill() }

func TestAPI_MetricsAndStreamAndRateLimit(t *testing.T){
    cmd := startAPIServer(t)
    defer stopAPIServer(cmd)

    // Metrics
    resp, err := http.Get("http://localhost:18080/metrics")
    if err != nil { t.Fatalf("metrics request failed: %v", err) }
    if resp.StatusCode != http.StatusOK { t.Fatalf("metrics status: %d", resp.StatusCode) }

    // SSE stream
    resp2, err := http.Get("http://localhost:18080/v1/stream")
    if err != nil { t.Fatalf("stream request failed: %v", err) }
    if resp2.StatusCode != http.StatusOK { t.Fatalf("stream status: %d", resp2.StatusCode) }
    buf := new(strings.Builder)
    _, _ = buf.ReadFrom(resp2.Body)
    if !strings.Contains(buf.String(), "data:") { t.Fatalf("expected sse data, got %q", buf.String()) }

    // Rate limit: send multiple analyze requests quickly expecting some 429
    payload := map[string]string{"package_name":"express","registry":"npm"}
    body, _ := json.Marshal(payload)
    client := &http.Client{ Timeout: 2 * time.Second }
    saw429 := false
    for i:=0; i<15; i++{
        req, _ := http.NewRequest("POST", "http://localhost:18080/v1/analyze", bytes.NewBuffer(body))
        req.Header.Set("Content-Type", "application/json")
        r, err := client.Do(req)
        if err != nil { continue }
        if r.StatusCode == http.StatusTooManyRequests { saw429 = true; break }
        time.Sleep(50 * time.Millisecond)
    }
    if !saw429 { t.Fatalf("expected at least one 429 response under rate limit") }
}

