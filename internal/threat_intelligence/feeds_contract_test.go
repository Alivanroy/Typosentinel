package threat_intelligence

import (
    "context"
    "net/http"
    "net/http/httptest"
    "testing"
    "time"
)

func TestOSVFeedRetry429Then200(t *testing.T) {
    calls := 0
    srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        calls++
        if calls == 1 {
            w.WriteHeader(429)
            return
        }
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(200)
        w.Write([]byte(`{"vulns":[{"id":"OSV-1","summary":"s","details":"d","modified":"2025-11-10T00:00:00Z","affected":[{"package":{"name":"react","ecosystem":"npm"},"severity":[{"type":"cvss","score":"HIGH"}]}],"references":[{"type":"web","url":"https://example.com"}]}]}`))
    }))
    defer srv.Close()

    f := NewOSVFeed(nil)
    f.baseURL = srv.URL
    if err := f.Initialize(context.Background(), map[string]interface{}{"rps": 5, "cache_ttl": time.Minute}); err != nil { t.Fatalf("init: %v", err) }
    th, err := f.FetchThreats(context.Background(), time.Time{})
    if err != nil { t.Fatalf("fetch: %v", err) }
    if len(th) == 0 { t.Fatalf("no threats") }
    t0 := th[0]
    if t0.Source == "" || t0.PackageName == "" || t0.Ecosystem == "" || t0.Severity == "" { t.Fatalf("missing fields") }
}

func TestGitHubFeedRetry500Then200(t *testing.T) {
    calls := 0
    srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        calls++
        if calls == 1 {
            w.WriteHeader(500)
            return
        }
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(200)
        w.Write([]byte(`{"data":{"securityAdvisories":{"nodes":[{"ghsaId":"GHSA-1","summary":"s","description":"d","severity":"HIGH","updatedAt":"2025-11-10T00:00:00Z","publishedAt":"2025-11-09T00:00:00Z","vulnerabilities":{"nodes":[{"package":{"name":"react","ecosystem":"npm"},"vulnerableVersionRange":">=0","firstPatchedVersion":{"identifier":"1.0.1"}}]}}]}}}`))
    }))
    defer srv.Close()

    f := NewGitHubAdvisoryFeed(nil)
    f.baseURL = srv.URL
    if err := f.Initialize(context.Background(), map[string]interface{}{"rps": 5, "cache_ttl": time.Minute}); err != nil { t.Fatalf("init: %v", err) }
    th, err := f.FetchThreats(context.Background(), time.Time{})
    if err != nil { t.Fatalf("fetch: %v", err) }
    if len(th) == 0 { t.Fatalf("no threats") }
    t0 := th[0]
    if t0.Source == "" || t0.PackageName == "" || t0.Ecosystem == "" || t0.Severity == "" { t.Fatalf("missing fields") }
}
