package threat_intelligence

import (
    "context"
    "net/http"
    "net/http/httptest"
    "testing"
    "time"
)

func TestOSVPaginationNextToken(t *testing.T) {
    calls := 0
    srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        calls++
        w.Header().Set("Content-Type", "application/json")
        if calls == 1 {
            w.WriteHeader(200)
            w.Write([]byte(`{"vulns":[{"id":"OSV-1","summary":"s","details":"d","modified":"2025-11-10T00:00:00Z","affected":[{"package":{"name":"react","ecosystem":"npm"},"severity":[{"type":"cvss","score":"HIGH"}]}],"references":[{"type":"web","url":"https://example.com"}]}],"next":"TOKEN"}`))
            return
        }
        w.WriteHeader(200)
        w.Write([]byte(`{"vulns":[{"id":"OSV-2","summary":"s2","details":"d2","modified":"2025-11-11T00:00:00Z","affected":[{"package":{"name":"lodash","ecosystem":"npm"},"severity":[{"type":"cvss","score":"LOW"}]}],"references":[{"type":"web","url":"https://example2.com"}]}]}`))
    }))
    defer srv.Close()

    f := NewOSVFeed(nil)
    f.baseURL = srv.URL
    if err := f.Initialize(context.Background(), map[string]interface{}{"rps": 5, "cache_ttl": time.Minute}); err != nil { t.Fatalf("init: %v", err) }
    th, err := f.FetchThreats(context.Background(), time.Time{})
    if err != nil { t.Fatalf("fetch: %v", err) }
    if len(th) != 2 { t.Fatalf("expected 2 threats, got %d", len(th)) }
}
