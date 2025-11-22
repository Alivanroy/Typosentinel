package output

import (
	"fmt"
	"strings"
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
