package tests

import (
    "os"
    "path/filepath"
    "strings"
    "testing"
    "github.com/Alivanroy/Typosentinel/internal/analyzer"
    "github.com/Alivanroy/Typosentinel/internal/config"
)

func TestPythonCLIParsesRequirements(t *testing.T) {
    cfg := &config.Config{}
    a, err := analyzer.New(cfg)
    if err != nil { t.Fatal(err) }
    wd, _ := os.Getwd()
    if strings.HasSuffix(wd, "/tests") { wd = filepath.Dir(wd) }
    p := filepath.Join(wd, "tests/python-parser-variants/basic")
    res, err := a.Scan(p, &analyzer.ScanOptions{AllowEmptyProjects: true})
    if err != nil { t.Fatal(err) }
    if res.TotalPackages == 0 { t.Fatalf("expected packages > 0, got %d", res.TotalPackages) }
}

func TestPythonCLIParsesPyprojectAndPipfile(t *testing.T) {
    cfg := &config.Config{}
    a, err := analyzer.New(cfg)
    if err != nil { t.Fatal(err) }
    wd, _ := os.Getwd()
    if strings.HasSuffix(wd, "/tests") { wd = filepath.Dir(wd) }
    p1 := filepath.Join(wd, "tests/python-parser-variants/specifiers")
    res1, err := a.Scan(p1, &analyzer.ScanOptions{AllowEmptyProjects: true})
    if err != nil { t.Fatal(err) }
    p2 := filepath.Join(wd, "tests/python-parser-variants/extras_markers")
    res2, err := a.Scan(p2, &analyzer.ScanOptions{AllowEmptyProjects: true})
    if err != nil { t.Fatal(err) }
    if res1.TotalPackages == 0 { t.Fatalf("expected pyproject packages > 0, got %d", res1.TotalPackages) }
    if res2.TotalPackages == 0 { t.Fatalf("expected requirements packages > 0, got %d", res2.TotalPackages) }
}
