package output

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/Alivanroy/Typosentinel/internal/analyzer"
	"github.com/Alivanroy/Typosentinel/internal/detector"
	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// FuturisticFormatter provides a modern, professional CLI interface
type FuturisticFormatter struct {
	writer      io.Writer
	colorOutput bool
	verbose     bool
	colors      *FuturisticColorScheme
}

// FuturisticColorScheme defines the futuristic color palette
type FuturisticColorScheme struct {
	// Primary colors
	ElectricBlue   *color.Color // #00D4FF
	NeonGreen      *color.Color // #39FF14
	CyberPurple    *color.Color // #9D00FF
	QuantumOrange  *color.Color // #FF6B00
	
	// Status colors
	Critical       *color.Color // #FF0040
	High           *color.Color // #FF4500
	Medium         *color.Color // #FFB000
	Low            *color.Color // #00BFFF
	Safe           *color.Color // #00FF7F
	
	// UI elements
	Header         *color.Color // Bright white with effects
	Subheader      *color.Color // Silver
	Text           *color.Color // Light gray
	Accent         *color.Color // Electric blue
	Success        *color.Color // Neon green
	Warning        *color.Color // Quantum orange
	Error          *color.Color // Critical red
	
	// Special effects
	Gradient       *color.Color // For gradient text
	Glow           *color.Color // For glowing effects
	Hologram       *color.Color // For holographic text
}

// Unicode symbols for futuristic design
const (
	// Geometric shapes
	SymbolDiamond     = "◆"
	SymbolTriangle    = "▲"
	SymbolSquare      = "■"
	SymbolCircle      = "●"
	SymbolHexagon     = "⬢"
	
	// Arrows and pointers
	SymbolArrowRight  = "▶"
	SymbolArrowUp     = "▲"
	SymbolArrowDown   = "▼"
	SymbolPointer     = "➤"
	
	// Status indicators
	SymbolCheck       = "✓"
	SymbolCross       = "✗"
	SymbolWarning     = "⚠"
	SymbolInfo        = "ℹ"
	SymbolStar        = "★"
	SymbolShield      = "🛡"
	
	// Tech symbols
	SymbolCpu         = "⚡"
	SymbolNetwork     = "🌐"
	SymbolDatabase    = "🗄"
	SymbolScan        = "🔍"
	SymbolLock        = "🔒"
	SymbolKey         = "🔑"
	
	// Progress indicators
	SymbolSpinner     = "◐◓◑◒"
	SymbolDots        = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
	SymbolBars        = "▁▂▃▄▅▆▇█"
)

// NewFuturisticFormatter creates a new futuristic formatter
func NewFuturisticFormatter(colorOutput, verbose bool) *FuturisticFormatter {
	colors := &FuturisticColorScheme{
		// Primary colors
		ElectricBlue:   color.New(color.FgCyan, color.Bold),
		NeonGreen:      color.New(color.FgGreen, color.Bold),
		CyberPurple:    color.New(color.FgMagenta, color.Bold),
		QuantumOrange:  color.New(color.FgYellow, color.Bold),
		
		// Status colors
		Critical:       color.New(color.FgRed, color.Bold, color.BlinkSlow),
		High:           color.New(color.FgRed, color.Bold),
		Medium:         color.New(color.FgYellow, color.Bold),
		Low:            color.New(color.FgBlue),
		Safe:           color.New(color.FgGreen),
		
		// UI elements
		Header:         color.New(color.FgWhite, color.Bold, color.Underline),
		Subheader:      color.New(color.FgWhite, color.Bold),
		Text:           color.New(color.FgWhite),
		Accent:         color.New(color.FgCyan, color.Bold),
		Success:        color.New(color.FgGreen, color.Bold),
		Warning:        color.New(color.FgYellow, color.Bold),
		Error:          color.New(color.FgRed, color.Bold),
		
		// Special effects
		Gradient:       color.New(color.FgCyan, color.Bold),
		Glow:           color.New(color.FgWhite, color.Bold),
		Hologram:       color.New(color.FgMagenta, color.Italic),
	}

	if !colorOutput {
		color.NoColor = true
	}

	return &FuturisticFormatter{
		writer:      os.Stdout,
		colorOutput: colorOutput,
		verbose:     verbose,
		colors:      colors,
	}
}

// PrintBanner displays the futuristic TypoSentinel banner
func (f *FuturisticFormatter) PrintBanner() {
	banner := `
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║  ████████╗██╗   ██╗██████╗  ██████╗ ███████╗███████╗███╗   ██╗████████╗    ║
║  ╚══██╔══╝╚██╗ ██╔╝██╔══██╗██╔═══██╗██╔════╝██╔════╝████╗  ██║╚══██╔══╝    ║
║     ██║    ╚████╔╝ ██████╔╝██║   ██║███████╗█████╗  ██╔██╗ ██║   ██║       ║
║     ██║     ╚██╔╝  ██╔═══╝ ██║   ██║╚════██║██╔══╝  ██║╚██╗██║   ██║       ║
║     ██║      ██║   ██║     ╚██████╔╝███████║███████╗██║ ╚████║   ██║       ║
║     ╚═╝      ╚═╝   ╚═╝      ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝       ║
║                                                                              ║
║                    ⚡ NEXT-GEN SUPPLY CHAIN SECURITY ⚡                     ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝`

	f.colors.ElectricBlue.Fprintln(f.writer, banner)
	f.colors.CyberPurple.Fprintf(f.writer, "\n%s AI-POWERED THREAT DETECTION SYSTEM %s\n", SymbolShield, SymbolShield)
	f.colors.Text.Fprintf(f.writer, "%s Scanning the digital frontier for malicious packages...\n\n", SymbolScan)
}

// PrintScanStart displays scan initialization
func (f *FuturisticFormatter) PrintScanStart(path string) {
	f.printSectionHeader("INITIALIZING QUANTUM SCAN PROTOCOL")
	
	f.colors.Accent.Fprintf(f.writer, "%s Target Path: ", SymbolPointer)
	f.colors.Text.Fprintf(f.writer, "%s\n", path)
	
	f.colors.Accent.Fprintf(f.writer, "%s Scan Mode: ", SymbolCpu)
	f.colors.NeonGreen.Fprintf(f.writer, "DEEP NEURAL ANALYSIS\n")
	
	f.colors.Accent.Fprintf(f.writer, "%s Threat Database: ", SymbolDatabase)
	f.colors.Text.Fprintf(f.writer, "SYNCHRONIZED\n")
	
	f.colors.Accent.Fprintf(f.writer, "%s ML Models: ", SymbolNetwork)
	f.colors.NeonGreen.Fprintf(f.writer, "LOADED & OPTIMIZED\n\n")
}

// PrintProgress shows a futuristic progress bar
func (f *FuturisticFormatter) PrintProgress(current, total int, message string) {
	if !f.colorOutput {
		fmt.Fprintf(f.writer, "[%d/%d] %s\n", current, total, message)
		return
	}

	percentage := float64(current) / float64(total) * 100
	barWidth := 40
	filled := int(float64(barWidth) * percentage / 100)
	
	bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)
	
	f.colors.ElectricBlue.Fprintf(f.writer, "\r%s [", SymbolScan)
	f.colors.NeonGreen.Fprintf(f.writer, "%s", bar)
	f.colors.ElectricBlue.Fprintf(f.writer, "] ")
	f.colors.Text.Fprintf(f.writer, "%.1f%% ", percentage)
	f.colors.Accent.Fprintf(f.writer, "%s", message)
}

// PrintScanResults displays scan results in futuristic format
func (f *FuturisticFormatter) PrintScanResults(result *analyzer.ScanResult) {
	f.printSectionHeader("QUANTUM SCAN ANALYSIS COMPLETE")
	
	// Scan metadata
	f.printMetadata(result)
	
	// Threat summary with visual indicators
	f.printThreatSummary(result.Summary)
	
	// Detailed threats if any
	if len(result.Threats) > 0 {
		f.printThreats(result.Threats)
	}
	
	// Warnings
	if len(result.Warnings) > 0 {
		f.printWarnings(result.Warnings)
	}
	
	// Final assessment
	f.printFinalAssessment(result)
}

// PrintAnalysisResults displays package analysis results
func (f *FuturisticFormatter) PrintAnalysisResults(result *detector.CheckPackageResult) {
	f.printSectionHeader("NEURAL PACKAGE ANALYSIS")
	
	// Package info
	f.colors.Accent.Fprintf(f.writer, "%s Package: ", SymbolHexagon)
	f.colors.Text.Fprintf(f.writer, "%s\n", result.Package)
	
	f.colors.Accent.Fprintf(f.writer, "%s Registry: ", SymbolNetwork)
	f.colors.Text.Fprintf(f.writer, "%s\n", result.Registry)
	
	// Threat level with visual indicator
	f.printThreatLevel(result.ThreatLevel, result.Confidence)
	
	// Threats
	if len(result.Threats) > 0 {
		f.printPackageThreats(result.Threats)
	}
	
	// Similar packages
	if len(result.SimilarPackages) > 0 {
		f.printSimilarPackages(result.SimilarPackages)
	}
}

// Helper methods for formatting

func (f *FuturisticFormatter) printSectionHeader(title string) {
	border := strings.Repeat("═", len(title)+4)
	f.colors.ElectricBlue.Fprintf(f.writer, "\n╔%s╗\n", border)
	f.colors.Header.Fprintf(f.writer, "║ %s ║\n", title)
	f.colors.ElectricBlue.Fprintf(f.writer, "╚%s╝\n\n", border)
}

func (f *FuturisticFormatter) printMetadata(result *analyzer.ScanResult) {
	f.colors.Subheader.Fprintf(f.writer, "%s SCAN METADATA\n", SymbolInfo)
	f.colors.Accent.Fprintf(f.writer, "  %s Scan ID: ", SymbolKey)
	f.colors.Text.Fprintf(f.writer, "%s\n", result.ScanID)
	
	f.colors.Accent.Fprintf(f.writer, "  %s Duration: ", SymbolCpu)
	f.colors.Text.Fprintf(f.writer, "%v\n", result.Duration)
	
	f.colors.Accent.Fprintf(f.writer, "  %s Packages: ", SymbolDatabase)
	f.colors.Text.Fprintf(f.writer, "%d analyzed\n\n", result.TotalPackages)
}

func (f *FuturisticFormatter) printThreatSummary(summary analyzer.ScanSummary) {
	f.colors.Subheader.Fprintf(f.writer, "%s THREAT MATRIX\n", SymbolShield)
	
	// Visual threat level indicators
	f.printThreatCount("CRITICAL", summary.CriticalThreats, f.colors.Critical)
	f.printThreatCount("HIGH", summary.HighThreats, f.colors.High)
	f.printThreatCount("MEDIUM", summary.MediumThreats, f.colors.Medium)
	f.printThreatCount("LOW", summary.LowThreats, f.colors.Low)
	f.printThreatCount("CLEAN", summary.CleanPackages, f.colors.Safe)
	
	fmt.Fprintln(f.writer)
}

func (f *FuturisticFormatter) printThreatCount(level string, count int, levelColor *color.Color) {
	indicator := f.getThreatIndicator(level, count)
	f.colors.Accent.Fprintf(f.writer, "  %s ", indicator)
	levelColor.Fprintf(f.writer, "%-8s", level)
	f.colors.Text.Fprintf(f.writer, " %d\n", count)
}

func (f *FuturisticFormatter) getThreatIndicator(level string, count int) string {
	if count == 0 {
		return SymbolCircle
	}
	
	switch level {
	case "CRITICAL":
		return SymbolCross
	case "HIGH":
		return SymbolWarning
	case "MEDIUM":
		return SymbolTriangle
	case "LOW":
		return SymbolDiamond
	default:
		return SymbolCheck
	}
}

func (f *FuturisticFormatter) printThreats(threats []types.Threat) {
	f.colors.Subheader.Fprintf(f.writer, "%s DETECTED THREATS\n", SymbolWarning)
	
	for i, threat := range threats {
		f.printThreatItem(i+1, threat)
	}
	fmt.Fprintln(f.writer)
}

func (f *FuturisticFormatter) printThreatItem(index int, threat types.Threat) {
	// Threat header
	f.colors.Accent.Fprintf(f.writer, "  %s [%02d] ", SymbolPointer, index)
	f.getSeverityColor(threat.Severity.String()).Fprintf(f.writer, "%s", strings.ToUpper(threat.Severity.String()))
	f.colors.Text.Fprintf(f.writer, " %s\n", threat.Package)
	
	// Description
	f.colors.Text.Fprintf(f.writer, "      %s %s\n", SymbolInfo, threat.Description)
	
	// Confidence
	f.colors.Accent.Fprintf(f.writer, "      %s Confidence: ", SymbolStar)
	f.printConfidenceBar(threat.Confidence)
	
	fmt.Fprintln(f.writer)
}

func (f *FuturisticFormatter) printConfidenceBar(confidence float64) {
	barWidth := 20
	filled := int(confidence * float64(barWidth))
	bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)
	
	confidenceColor := f.getConfidenceColor(confidence)
	confidenceColor.Fprintf(f.writer, "%s %.1f%%\n", bar, confidence*100)
}

func (f *FuturisticFormatter) getConfidenceColor(confidence float64) *color.Color {
	switch {
	case confidence >= 0.8:
		return f.colors.Critical
	case confidence >= 0.6:
		return f.colors.High
	case confidence >= 0.4:
		return f.colors.Medium
	default:
		return f.colors.Low
	}
}

func (f *FuturisticFormatter) getSeverityColor(severity string) *color.Color {
	switch strings.ToLower(severity) {
	case "critical":
		return f.colors.Critical
	case "high":
		return f.colors.High
	case "medium":
		return f.colors.Medium
	case "low":
		return f.colors.Low
	default:
		return f.colors.Text
	}
}

func (f *FuturisticFormatter) printWarnings(warnings []types.Warning) {
	f.colors.Subheader.Fprintf(f.writer, "%s SYSTEM WARNINGS\n", SymbolWarning)
	
	for _, warning := range warnings {
		f.colors.Warning.Fprintf(f.writer, "  %s %s: ", SymbolTriangle, warning.Package)
		f.colors.Text.Fprintf(f.writer, "%s\n", warning.Message)
		if warning.Suggestion != "" {
			f.colors.Accent.Fprintf(f.writer, "      %s Suggestion: ", SymbolInfo)
			f.colors.Text.Fprintf(f.writer, "%s\n", warning.Suggestion)
		}
	}
	fmt.Fprintln(f.writer)
}

func (f *FuturisticFormatter) printThreatLevel(level string, confidence float64) {
	f.colors.Accent.Fprintf(f.writer, "%s Threat Level: ", SymbolShield)
	
	levelColor := f.getSeverityColor(level)
	levelColor.Fprintf(f.writer, "%s ", strings.ToUpper(level))
	
	f.colors.Accent.Fprintf(f.writer, "(")
	f.printConfidenceBar(confidence)
	f.colors.Accent.Fprintf(f.writer, ")\n\n")
}

func (f *FuturisticFormatter) printPackageThreats(threats []types.Threat) {
	f.colors.Subheader.Fprintf(f.writer, "%s THREAT ANALYSIS\n", SymbolWarning)
	
	for _, threat := range threats {
		f.colors.Accent.Fprintf(f.writer, "  %s ", SymbolPointer)
		f.getSeverityColor(threat.Severity.String()).Fprintf(f.writer, "[%s] ", strings.ToUpper(threat.Severity.String()))
		f.colors.Text.Fprintf(f.writer, "%s\n", threat.Description)
		
		if threat.SimilarTo != "" {
			f.colors.Accent.Fprintf(f.writer, "      %s Similar to: ", SymbolInfo)
			f.colors.Text.Fprintf(f.writer, "%s\n", threat.SimilarTo)
		}
	}
	fmt.Fprintln(f.writer)
}

func (f *FuturisticFormatter) printSimilarPackages(packages []string) {
	f.colors.Subheader.Fprintf(f.writer, "%s SIMILAR PACKAGES\n", SymbolNetwork)
	f.colors.Text.Fprintf(f.writer, "  %s\n\n", strings.Join(packages, ", "))
}

func (f *FuturisticFormatter) printFinalAssessment(result *analyzer.ScanResult) {
	f.printSectionHeader("FINAL SECURITY ASSESSMENT")
	
	// Overall status
	status := f.getOverallStatus(result.Summary)
	statusColor := f.getStatusColor(status)
	
	statusColor.Fprintf(f.writer, "%s SYSTEM STATUS: %s\n", SymbolShield, status)
	
	// Recommendations
	if result.Summary.CriticalThreats > 0 || result.Summary.HighThreats > 0 {
		f.colors.Error.Fprintf(f.writer, "%s IMMEDIATE ACTION REQUIRED\n", SymbolWarning)
		f.colors.Text.Fprintf(f.writer, "  Review and remediate detected threats before deployment.\n")
	} else if result.Summary.MediumThreats > 0 {
		f.colors.Warning.Fprintf(f.writer, "%s CAUTION ADVISED\n", SymbolTriangle)
		f.colors.Text.Fprintf(f.writer, "  Monitor flagged packages and consider alternatives.\n")
	} else {
		f.colors.Success.Fprintf(f.writer, "%s SECURITY CLEARANCE GRANTED\n", SymbolCheck)
		f.colors.Text.Fprintf(f.writer, "  No significant threats detected. Proceed with confidence.\n")
	}
	
	fmt.Fprintln(f.writer)
}

func (f *FuturisticFormatter) getOverallStatus(summary analyzer.ScanSummary) string {
	if summary.CriticalThreats > 0 {
		return "CRITICAL THREAT DETECTED"
	} else if summary.HighThreats > 0 {
		return "HIGH RISK IDENTIFIED"
	} else if summary.MediumThreats > 0 {
		return "MODERATE RISK PRESENT"
	} else if summary.LowThreats > 0 {
		return "LOW RISK DETECTED"
	}
	return "SECURE"
}

func (f *FuturisticFormatter) getStatusColor(status string) *color.Color {
	if strings.Contains(status, "CRITICAL") {
		return f.colors.Critical
	} else if strings.Contains(status, "HIGH") {
		return f.colors.High
	} else if strings.Contains(status, "MODERATE") {
		return f.colors.Medium
	} else if strings.Contains(status, "LOW") {
		return f.colors.Low
	}
	return f.colors.Success
}

// PrintVersion displays version information with futuristic styling
func (f *FuturisticFormatter) PrintVersion(version string) {
	f.colors.ElectricBlue.Fprintf(f.writer, "\n%s TypoSentinel ", SymbolShield)
	f.colors.NeonGreen.Fprintf(f.writer, "v%s\n", version)
	f.colors.Text.Fprintf(f.writer, "%s Next-generation supply chain security platform\n", SymbolStar)
	f.colors.CyberPurple.Fprintf(f.writer, "%s Powered by quantum-enhanced AI threat detection\n\n", SymbolCpu)
}

// PrintError displays errors with futuristic styling
func (f *FuturisticFormatter) PrintError(err error) {
	f.colors.Error.Fprintf(f.writer, "\n%s SYSTEM ERROR\n", SymbolCross)
	f.colors.Text.Fprintf(f.writer, "  %s\n\n", err.Error())
}

// PrintSuccess displays success messages
func (f *FuturisticFormatter) PrintSuccess(message string) {
	f.colors.Success.Fprintf(f.writer, "%s %s\n", SymbolCheck, message)
}