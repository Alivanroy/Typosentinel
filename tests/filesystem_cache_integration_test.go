package tests

import (
    "os"
    "path/filepath"
    "testing"
    "time"
    rep "github.com/Alivanroy/Typosentinel/internal/reputation"
)

func TestFilesystemCache_SetGetExpiryDeleteClear(t *testing.T) {
    dir := t.TempDir()
    fc := rep.NewFilesystemCache(dir)
    key := "pkgA-1.0.0-npm"
    res := &rep.EnhancedReputationResult{PackageName: "pkgA", Registry: "npm", Version: "1.0.0"}

    if err := fc.Set(key, res, 50*time.Millisecond); err != nil {
        t.Fatalf("set err: %v", err)
    }

    got, err := fc.Get(key)
    if err != nil || got == nil || got.PackageName != "pkgA" {
        t.Fatalf("get failed: %v", err)
    }

    time.Sleep(60 * time.Millisecond)
    _, err = fc.Get(key)
    if err == nil {
        t.Fatalf("expected expiry error")
    }

    // Recreate and delete
    if err := fc.Set(key, res, time.Second); err != nil {
        t.Fatalf("set err: %v", err)
    }
    if err := fc.Delete(key); err != nil {
        t.Fatalf("delete err: %v", err)
    }
    if _, err := os.Stat(filepath.Join(dir, key+".json")); !os.IsNotExist(err) {
        t.Fatalf("file still exists after delete")
    }

    // Create multiple and clear
    _ = fc.Set("k1", res, time.Second)
    _ = fc.Set("k2", res, time.Second)
    if err := fc.Clear(); err != nil {
        t.Fatalf("clear err: %v", err)
    }
    entries, _ := os.ReadDir(dir)
    for _, e := range entries {
        if !e.IsDir() {
            t.Fatalf("cache not cleared: %s", e.Name())
        }
    }
}