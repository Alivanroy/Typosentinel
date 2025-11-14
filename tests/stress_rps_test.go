package tests

import (
    "context"
    "net/http"
    "sync"
    "testing"
    "time"
    "github.com/Alivanroy/Typosentinel/internal/api/rest"
    "github.com/Alivanroy/Typosentinel/internal/config"
)

func TestStressHighRPSHealth(t *testing.T) {
    cfg := config.RESTAPIConfig{Enabled: true, Host: "127.0.0.1", Port: 8087, BasePath: "/api", Versioning: config.APIVersioning{Enabled: true, Strategy: "path", DefaultVersion: "v1", SupportedVersions: []string{"v1"}}}
    srv := rest.NewServer(cfg, nil, nil)
    go func() { _ = srv.Start(context.Background()) }()
    defer func() { _ = srv.Stop(context.Background()) }()
    time.Sleep(500 * time.Millisecond)

    clients := 200
    requestsPerClient := 50
    var wg sync.WaitGroup
    wg.Add(clients)
    for i := 0; i < clients; i++ {
        go func() {
            defer wg.Done()
            for j := 0; j < requestsPerClient; j++ {
                r, err := http.Get("http://127.0.0.1:8087/health")
                if err != nil || r.StatusCode != 200 { t.Fatalf("health: %v %d", err, r.StatusCode) }
            }
        }()
    }
    wg.Wait()
}

