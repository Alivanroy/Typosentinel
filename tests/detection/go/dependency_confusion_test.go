package detection

import (
    "testing"
    "typosentinel/internal/detector"
)

func TestDependencyConfusion(t *testing.T) {
    internal := detector.DependencyConfusionMeta{
        Name:    "acme-core-utils",
        Version: "1.2.3",
        Registry:"https://registry.acme.local",
    }

    malicious := detector.DependencyConfusionMeta{
        Name:    "acme-core-utils",
        Version: "99.0.0",              // higher semver
        Registry:"https://pypi.org",
        Description: "Core utils package (official)",
    }

    if !detector.DetectDependencyConfusion(malicious, internal) {
        t.Fatalf("failed to identify dependency‑confusion candidate")
    }
}