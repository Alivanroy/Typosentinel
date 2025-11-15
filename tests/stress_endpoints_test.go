package tests

import (
    "bytes"
    "context"
    "fmt"
    "net/http"
    "os"
    "sync"
    "testing"
    "time"
    "github.com/Alivanroy/Typosentinel/internal/api/rest"
    "github.com/Alivanroy/Typosentinel/internal/config"
)

func TestStressEndpointsAnalyzeBatchPredict(t *testing.T) {
    os.Setenv("TYPOSENTINEL_ENVIRONMENT", "development")
    cfg := config.RESTAPIConfig{Enabled: true, Host: "127.0.0.1", Port: 8089, BasePath: "/api", Versioning: config.APIVersioning{Enabled: true, Strategy: "path", DefaultVersion: "v1", SupportedVersions: []string{"v1"}}}
    srv := rest.NewServer(cfg, nil, nil)
    go func() { _ = srv.Start(context.Background()) }()
    defer func() { _ = srv.Stop(context.Background()) }()
    deadline := time.Now().Add(20 * time.Second)
    for {
        if time.Now().After(deadline) { t.Skip("server not ready for stress endpoints") }
        r, err := http.Get("http://127.0.0.1:8089/health")
        if err == nil && r.StatusCode == 200 { r.Body.Close(); break }
        time.Sleep(100 * time.Millisecond)
    }

    clients := 5
    var wg sync.WaitGroup
    wg.Add(clients)
    var durs []time.Duration
    var mu sync.Mutex
    for i := 0; i < clients; i++ {
        go func() {
            defer wg.Done()
            body := []byte(`{"name":"react","ecosystem":"npm","version":"18.2.0","options":{"include_ml":true,"include_vulnerabilities":true}}`)
            start := time.Now()
            r, err := http.Post("http://127.0.0.1:8089/api/v1/analyze", "application/json", bytes.NewReader(body))
            if err != nil { t.Fatalf("analyze err: %v", err) }
            if r.StatusCode != 200 { t.Fatalf("analyze status: %d", r.StatusCode) }
            r.Body.Close()
            mu.Lock(); durs = append(durs, time.Since(start)); mu.Unlock()
            batch := []byte(`{"packages":[{"name":"react","ecosystem":"npm","version":"18.2.0"},{"name":"lodash","ecosystem":"npm","version":"4.17.21"}],"options":{"include_ml":true,"include_vulnerabilities":true}}`)
            start = time.Now()
            r, err = http.Post("http://127.0.0.1:8089/api/v1/batch-analyze", "application/json", bytes.NewReader(batch))
            if err != nil { t.Fatalf("batch analyze err: %v", err) }
            if r.StatusCode != 200 { t.Fatalf("batch analyze status: %d", r.StatusCode) }
            r.Body.Close()
            mu.Lock(); durs = append(durs, time.Since(start)); mu.Unlock()
            start = time.Now()
            r, err = http.Post("http://127.0.0.1:8089/api/v1/ml/predict/typosquatting", "application/json", bytes.NewReader([]byte(`{"package":{"name":"react","registry":"npm"}}`)))
            if err != nil { t.Fatalf("predict err: %v", err) }
            if r.StatusCode != 200 { t.Fatalf("predict status: %d", r.StatusCode) }
            r.Body.Close()
            mu.Lock(); durs = append(durs, time.Since(start)); mu.Unlock()
        }()
    }
    wg.Wait()
    // SLO: p95 latency assertion
    if len(durs) > 0 {
        // simple percentile calc
        for i := 0; i < len(durs)-1; i++ {
            for j := i + 1; j < len(durs); j++ {
                if durs[j] < durs[i] { durs[i], durs[j] = durs[j], durs[i] }
            }
        }
        idx := int(float64(len(durs))*0.95) - 1
        if idx < 0 { idx = 0 }
        p95 := durs[idx]
        sloMs := 1000
        if v := os.Getenv("SLO_P95_MS"); v != "" { if m, err := parseInt(v); err == nil { sloMs = m } }
        if p95 > time.Duration(sloMs)*time.Millisecond { t.Fatalf("p95 latency %v exceeds SLO %dms", p95, sloMs) }
    }
}

func parseInt(s string) (int, error) { var n int; _, err := fmt.Sscanf(s, "%d", &n); return n, err }
