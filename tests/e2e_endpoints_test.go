package tests

import (
    "bytes"
    "context"
    "encoding/json"
    "io"
    "net/http"
    "testing"
    "time"
    "os"
    "github.com/Alivanroy/Typosentinel/internal/api/rest"
    "github.com/Alivanroy/Typosentinel/internal/config"
)

func TestE2E_CoreEndpoints(t *testing.T) {
    os.Setenv("TYPOSENTINEL_ENVIRONMENT", "development")
    cfg := config.RESTAPIConfig{Enabled: true, Host: "127.0.0.1", Port: 8084, BasePath: "/api", Versioning: config.APIVersioning{Enabled: true, Strategy: "path", DefaultVersion: "v1", SupportedVersions: []string{"v1"}}, CORS: &config.CORSConfig{Enabled: true, AllowedOrigins: []string{"http://example.com"}, AllowedMethods: []string{"GET","POST","OPTIONS"}, AllowedHeaders: []string{"Origin","Content-Type","Authorization"}}}
    srv := rest.NewServer(cfg, nil, nil)
    go func() { _ = srv.Start(context.Background()) }()
    defer func() { _ = srv.Stop(context.Background()) }()
    time.Sleep(600 * time.Millisecond)

    if r, err := http.Get("http://127.0.0.1:8084/health"); err != nil || r.StatusCode != 200 { t.Fatalf("health: %v %d", err, r.StatusCode) }
    if r, err := http.Get("http://127.0.0.1:8084/api/v1/ml/models/status"); err != nil || r.StatusCode != 200 { t.Fatalf("ml status: %v %d", err, r.StatusCode) }
    if r, err := http.Get("http://127.0.0.1:8084/api/v1/docs/openapi"); err != nil || r.StatusCode != 200 { t.Fatalf("docs: %v %d", err, r.StatusCode) }
    if r, err := http.Get("http://127.0.0.1:8084/api/v1/system/status"); err != nil || r.StatusCode != 200 { t.Fatalf("system: %v %d", err, r.StatusCode) }
    if r, err := http.Get("http://127.0.0.1:8084/api/v1/dashboard/metrics"); err != nil || r.StatusCode != 200 { t.Fatalf("dashboard metrics: %v %d", err, r.StatusCode) }

    body := []byte(`{"name":"react","ecosystem":"npm","version":"18.2.0","options":{"include_ml":false,"include_vulnerabilities":true}}`)
    if r, err := http.Post("http://127.0.0.1:8084/api/v1/analyze", "application/json", bytes.NewReader(body)); err != nil || r.StatusCode != 200 { t.Fatalf("analyze: %v %d", err, r.StatusCode) } else {
        b, _ := io.ReadAll(r.Body); _ = r.Body.Close()
        var resp map[string]interface{}
        _ = json.Unmarshal(b, &resp)
        if resp["risk_level"] == nil { t.Fatalf("analyze payload missing risk_level") }
        if rs, ok := resp["risk_score"].(float64); !ok { t.Fatalf("analyze payload missing risk_score") } else if rs == 0.65 { t.Fatalf("risk_score appears hardcoded: %v", rs) }
    }
    batch := []byte(`{"packages":[{"name":"react","ecosystem":"npm","version":"18.2.0"},{"name":"lodash","ecosystem":"npm","version":"4.17.21"}],"options":{"include_ml":false,"include_vulnerabilities":true}}`)
    if r, err := http.Post("http://127.0.0.1:8084/api/v1/batch-analyze", "application/json", bytes.NewReader(batch)); err != nil || r.StatusCode != 200 { t.Fatalf("batch analyze: %v %d", err, r.StatusCode) } else {
        b, _ := io.ReadAll(r.Body); _ = r.Body.Close()
        var resp map[string]interface{}
        _ = json.Unmarshal(b, &resp)
        if resp["results"] == nil { t.Fatalf("batch analyze payload missing results") }
    }
    if r, err := http.Post("http://127.0.0.1:8084/api/v1/system/cache/clear", "application/json", bytes.NewReader([]byte(`{}`))); err != nil || r.StatusCode != 200 { t.Fatalf("cache clear: %v %d", err, r.StatusCode) }

    if r, err := http.Get("http://127.0.0.1:8084/api/v1/package/npm/react"); err != nil || r.StatusCode != 200 { t.Fatalf("analyze by name: %v %d", err, r.StatusCode) } else {
        b, _ := io.ReadAll(r.Body); _ = r.Body.Close()
        var resp map[string]interface{}
        _ = json.Unmarshal(b, &resp)
        ts, ok := resp["threats"].([]interface{})
        if !ok || len(ts) == 0 { t.Fatalf("analyze by name payload missing threats") }
    }
    if r, err := http.Post("http://127.0.0.1:8084/api/v1/vulnerabilities/scan/npm/react", "application/json", bytes.NewReader([]byte(`{"name":"react","ecosystem":"npm","version":"1.0.0"}`))); err != nil || (r.StatusCode != 200 && r.StatusCode != 500) { t.Fatalf("vuln scan: %v %d", err, r.StatusCode) } else if r.StatusCode == 200 {
        b, _ := io.ReadAll(r.Body); _ = r.Body.Close()
        var resp map[string]interface{}
        _ = json.Unmarshal(b, &resp)
        vulns := resp["vulnerabilities"].([]interface{})
        if len(vulns) == 0 { t.Fatalf("vuln scan payload empty vulnerabilities") }
        v0 := vulns[0].(map[string]interface{})
        if v0["id"] == nil || v0["severity"] == nil || v0["description"] == nil { t.Fatalf("vuln scan payload missing fields") }
    }
    // CORS preflight validation (DAST)
    preflightReq, _ := http.NewRequest("OPTIONS", "http://127.0.0.1:8084/api/v1/analyze", nil)
    preflightReq.Header.Set("Origin", "http://example.com")
    preflightReq.Header.Set("Access-Control-Request-Method", "POST")
    preflightResp, err := http.DefaultClient.Do(preflightReq)
    if err != nil || (preflightResp.StatusCode != 200 && preflightResp.StatusCode != 204) { t.Fatalf("preflight: %v %d", err, preflightResp.StatusCode) }
    _ = preflightResp.Body.Close()

    if r, err := http.Post("http://127.0.0.1:8084/api/v1/ml/predict/typosquatting", "application/json", bytes.NewReader([]byte(`{"package":{"name":"react","registry":"npm"}}`))); err != nil || (r.StatusCode != 200 && r.StatusCode != 503) { t.Fatalf("ml predict: %v %d", err, r.StatusCode) }

    // Verify ML analysis via analyze with include_ml=true
    bodyML := []byte(`{"name":"react","ecosystem":"npm","version":"18.2.0","options":{"include_ml":true,"include_vulnerabilities":false}}`)
    if r, err := http.Post("http://127.0.0.1:8084/api/v1/analyze", "application/json", bytes.NewReader(bodyML)); err != nil || r.StatusCode != 200 { t.Fatalf("analyze ML: %v %d", err, r.StatusCode) } else {
        b, _ := io.ReadAll(r.Body); _ = r.Body.Close()
        var resp map[string]interface{}
        _ = json.Unmarshal(b, &resp)
        if resp["ml_analysis"] == nil { t.Fatalf("analyze ML payload missing ml_analysis") }
    }
}
