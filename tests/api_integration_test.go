package tests

import (
    "context"
    "net/http"
    "testing"
    "time"
    "os"
    "github.com/Alivanroy/Typosentinel/internal/api/rest"
    "github.com/Alivanroy/Typosentinel/internal/config"
)

func TestServerHealthReady(t *testing.T) {
    os.Setenv("TYPOSENTINEL_ENVIRONMENT", "development")
    cfg := config.RESTAPIConfig{Enabled: true, Host: "127.0.0.1", Port: 8082, BasePath: "/api", Versioning: config.APIVersioning{Enabled: true, Strategy: "path", DefaultVersion: "v1", SupportedVersions: []string{"v1"}}}
    srv := rest.NewServer(cfg, nil, nil)
    go func() { _ = srv.Start(context.Background()) }()
    defer func() { _ = srv.Stop(context.Background()) }()
    time.Sleep(500 * time.Millisecond)
    r1, err := http.Get("http://127.0.0.1:8082/health")
    if err != nil { t.Fatalf("health: %v", err) }
    if r1.StatusCode != 200 { t.Fatalf("health status: %d", r1.StatusCode) }
    r2, err := http.Get("http://127.0.0.1:8082/ready")
    if err != nil { t.Fatalf("ready: %v", err) }
    if r2.StatusCode != 200 && r2.StatusCode != 503 { t.Fatalf("ready status: %d", r2.StatusCode) }
}
