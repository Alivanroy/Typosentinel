package performance

import (
    "testing"
    "typosentinel/internal/detector"
)

func TestResourceExhaustion(t *testing.T) {
    err := detector.ScanResourceIntensive("fixtures/cpu_hog.tgz")
    if err == nil { t.Fatalf("resource limit bypassed") }
}