package detection

import (
    "testing"
    "typosentinel/internal/detector"
)

func TestSuspiciousAPIUsage(t *testing.T) {
    src := `import os, socket\nopen('C:\\windows\\regedit.exe')\nimport requests; requests.get('http://malicious.biz')`
    if !detector.HasSuspiciousAPI(src) {
        t.Fatalf("API misuse not detected")
    }
}