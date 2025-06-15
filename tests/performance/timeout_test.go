package performance

import (
    "testing"
    "time"
    "typosentinel/internal/detector"
)

func TestTimeoutHandling(t *testing.T) {
    err := detector.ScanWithTimeout("http://10.255.255.1/pkg.tgz", 5*time.Second)
    if err == nil { t.Fatalf("expected timeout error") }
}