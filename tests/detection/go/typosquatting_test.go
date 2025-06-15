package detection

import (
    "testing"
    "time"
    "typosentinel/internal/detector" // real detector implementation
)

var cases = []struct{
    original string
    mutated  string
}{
    {"numpy", "nump0y"},
    {"requests", "requesls"},
    {"selenium", "s3lenium"},
    {"tensorflow", "tensоrflow"}, // Cyrillic 'o'
    {"pandas", "ρandas"},           // Greek rho
    {"django", "djаngo"},            // Latin ext. a
}

func TestTyposquattingDetection(t *testing.T) {
    for _, c := range cases {
        start := time.Now()
        ok := detector.Typosquat(c.mutated, c.original)
        elapsed := time.Since(start)
        if !ok {
            t.Fatalf("%s was NOT flagged as typosquat of %s", c.mutated, c.original)
        }
        if elapsed > 2*time.Second {
            t.Fatalf("detection exceeded latency budget: %s", elapsed)
        }
    }
}