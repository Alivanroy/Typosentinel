package threat_intelligence

import (
    "context"
    "testing"
    "time"
)

func TestNVDFeedRealModeFallback(t *testing.T) {
    f := NewNVDFeed(nil)
    if err := f.Initialize(context.Background(), map[string]interface{}{"mode": "real", "update_interval": time.Hour}); err != nil {
        t.Fatalf("init: %v", err)
    }
    _, err := f.FetchThreats(context.Background(), time.Time{})
    if err != nil { t.Fatalf("fetch: %v", err) }
}

