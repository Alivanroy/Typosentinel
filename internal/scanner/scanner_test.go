package scanner

import (
    "testing"
    "github.com/Alivanroy/Typosentinel/internal/config"
    "github.com/stretchr/testify/require"
    "github.com/stretchr/testify/assert"
)

func TestScanner_ScanProject_NpmClean(t *testing.T) {
    cfg := config.NewDefaultConfig()
    s, err := New(cfg)
    require.NoError(t, err)
    res, err := s.ScanProject("../../examples/npm-clean")
    require.NoError(t, err)
    assert.GreaterOrEqual(t, len(res.Packages), 2)
}

func TestScanner_ScanProject_NpmVulnerable(t *testing.T) {
    cfg := config.NewDefaultConfig()
    s, err := New(cfg)
    require.NoError(t, err)
    res, err := s.ScanProject("../../examples/npm-vulnerable")
    require.NoError(t, err)
    hasThreat := false
    for _, p := range res.Packages {
        if len(p.Threats) > 0 { hasThreat = true; break }
    }
    assert.True(t, hasThreat)
}

func TestScanner_ScanProject_GoMinimal(t *testing.T) {
    cfg := config.NewDefaultConfig()
    s, err := New(cfg)
    require.NoError(t, err)
    res, err := s.ScanProject("../../examples/go-minimal")
    require.NoError(t, err)
    assert.GreaterOrEqual(t, len(res.Packages), 1)
}

func TestScanner_ScanProject_MavenMinimal(t *testing.T) {
    cfg := config.NewDefaultConfig()
    s, err := New(cfg)
    require.NoError(t, err)
    res, err := s.ScanProject("../../examples/maven-minimal")
    require.NoError(t, err)
    assert.GreaterOrEqual(t, len(res.Packages), 1)
}
