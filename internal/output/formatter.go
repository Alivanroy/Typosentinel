package output

import (
    "encoding/json"
    "fmt"
    "strings"

    "github.com/Alivanroy/Typosentinel/internal/analyzer"
    "github.com/Alivanroy/Typosentinel/internal/detector"
)

type FuturisticFormatter struct {
    verbose bool
    json    bool
}

func NewFuturisticFormatter(verbose, json bool) *FuturisticFormatter {
	return &FuturisticFormatter{
		verbose: verbose,
		json:    json,
	}
}

func (f *FuturisticFormatter) PrintVersion(version string) {
	if f.json {
		fmt.Printf(`{"version": "%s"}`+"\n", version)
		return
	}

	// ASCII art banner for version display
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("🛡️  TYPOSENTINEL - ADVANCED PACKAGE SECURITY SCANNER")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("Version: %s\n", version)
	fmt.Println("⚡ Powered by Behavioral Analysis & Threat Intelligence")
	fmt.Println(strings.Repeat("=", 60))
}

func (f *FuturisticFormatter) PrintBanner() {
    if f.json { return }
    fmt.Println(strings.Repeat("-", 40))
}

func (f *FuturisticFormatter) PrintScanStart(path string) {
    if f.json { return }
    fmt.Printf("Scanning: %s\n", path)
}

func (f *FuturisticFormatter) PrintScanResults(result *analyzer.ScanResult) {
    if f.json {
        b, _ := json.Marshal(result)
        fmt.Println(string(b))
        return
    }
    fmt.Printf("Threats: %d, Warnings: %d\n", len(result.Threats), len(result.Warnings))
}

func (f *FuturisticFormatter) PrintAnalysisResults(result *detector.CheckPackageResult) {
    if f.json {
        b, _ := json.Marshal(result)
        fmt.Println(string(b))
        return
    }
    fmt.Printf("Findings: %d, Warnings: %d\n", len(result.Threats), len(result.Warnings))
}
