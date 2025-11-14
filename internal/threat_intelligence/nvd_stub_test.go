package threat_intelligence

import (
    "context"
    "testing"
    "time"
    "github.com/Alivanroy/Typosentinel/pkg/logger"
)

func TestNVDStubFetchThreats(t *testing.T) {
    log := &logger.Logger{}
    f := NewNVDFeed(log)
    if err := f.Initialize(context.Background(), map[string]interface{}{"mode": "stub", "update_interval": time.Hour}); err != nil {
        t.Fatalf("init: %v", err)
    }
    th, err := f.FetchThreats(context.Background(), time.Time{})
    if err != nil { t.Fatalf("fetch: %v", err) }
    if len(th) == 0 { t.Fatalf("no threats") }
    for _, t1 := range th {
        if t1.ID == "" || t1.PackageName == "" || t1.Ecosystem == "" { t.Fatalf("invalid threat") }
    }
}

