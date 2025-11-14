package tests

import (
    "bytes"
    "context"
    "net/http"
    "testing"
    "time"
    "github.com/Alivanroy/Typosentinel/internal/api/rest"
    "github.com/Alivanroy/Typosentinel/internal/config"
)

func TestNegativeEndpoints(t *testing.T) {
    cfg := config.RESTAPIConfig{Enabled: true, Host: "127.0.0.1", Port: 8086, BasePath: "/api", Versioning: config.APIVersioning{Enabled: true, Strategy: "path", DefaultVersion: "v1", SupportedVersions: []string{"v1"}}}
    srv := rest.NewServer(cfg, nil, nil)
    go func() { _ = srv.Start(context.Background()) }()
    defer func() { _ = srv.Stop(context.Background()) }()
    deadline := time.Now().Add(10 * time.Second)
    for {
        if time.Now().After(deadline) { t.Fatalf("server not ready") }
        r, err := http.Get("http://127.0.0.1:8086/health")
        if err == nil && r.StatusCode == 200 { r.Body.Close(); break }
        time.Sleep(100 * time.Millisecond)
    }

    if r, _ := http.Post("http://127.0.0.1:8086/api/v1/vulnerabilities/scan/npm/react", "application/json", bytes.NewReader([]byte(`{"ecosystem":"npm"}`))); r.StatusCode != 400 { t.Fatalf("expected 400 for missing name, got %d", r.StatusCode) }
    if r, _ := http.Post("http://127.0.0.1:8086/api/v1/ml/predict/typosquatting", "application/json", bytes.NewReader([]byte(`{}`))); r.StatusCode != 400 { t.Fatalf("expected 400 for missing package, got %d", r.StatusCode) }
    if r, _ := http.Post("http://127.0.0.1:8086/api/v1/analyze", "application/json", bytes.NewReader([]byte(`{"packages":[]}`))); r.StatusCode != 400 { t.Fatalf("expected 400 for empty analyze packages, got %d", r.StatusCode) }
}
