package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"
	"gopkg.in/yaml.v3"

	"typosentinel/pkg/types"
)

// OutputFormat represents different output formats
type OutputFormat string

const (
	FormatJSON     OutputFormat = "json"
	FormatYAML     OutputFormat = "yaml"
	FormatText     OutputFormat = "text"
	FormatTable    OutputFormat = "table"
	FormatCompact  OutputFormat = "compact"
	FormatDetailed OutputFormat = "detailed"
	FormatSummary  OutputFormat = "summary"
)

// FormatterOptions controls output formatting behavior
type FormatterOptions struct {
	Format      OutputFormat `json:"format"`
	ColorOutput bool         `json:"color_output"`
	Quiet       bool         `json:"quiet"`
	Verbose     bool         `json:"verbose"`
	ShowProgress bool        `json:"show_progress"`
	OutputFile  string       `json:"output_file"`
	Indent      string       `json:"indent"`
	SortBy      string       `json:"sort_by"`
	FilterLevel string       `json:"filter_level"`
}

// ScanResult represents the scan results to be formatted
type ScanResult struct {
	Package            *types.Package                `json:"package"`
	StaticAnalysis     interface{}                   `json:"static_analysis,omitempty"`
	DynamicAnalysis    interface{}                   `json:"dynamic_analysis,omitempty"`
	MLAnalysis         interface{}                   `json:"ml_analysis,omitempty"`
	ProvenanceAnalysis interface{}                   `json:"provenance_analysis,omitempty"`
	OverallRisk        string                        `json:"overall_risk"`
	RiskScore          float64                       `json:"risk_score"`
	Recommendations    []string                      `json:"recommendations"`
	Summary            ScanSummary                   `json:"summary"`
	Metadata           ScanMetadata                  `json:"metadata"`
	Findings           []Finding                     `json:"findings"`
}

// ScanSummary provides a high-level summary
type ScanSummary struct {
	TotalFindings      int                 `json:"total_findings"`
	CriticalFindings   int                 `json:"critical_findings"`
	HighFindings       int                 `json:"high_findings"`
	MediumFindings     int                 `json:"medium_findings"`
	LowFindings        int                 `json:"low_findings"`
	FindingsByCategory map[string]int      `json:"findings_by_category"`
	EnginesUsed        []string            `json:"engines_used"`
	AnalysisTime       time.Duration       `json:"analysis_time"`
	Status             string              `json:"status"`
}

// ScanMetadata contains scan metadata
type ScanMetadata struct {
	ScanID      string    `json:"scan_id"`
	Timestamp   time.Time `json:"timestamp"`
	Version     string    `json:"version"`
	Environment string    `json:"environment"`
	User        string    `json:"user"`
	Hostname    string    `json:"hostname"`
}

// Finding represents a security finding
type Finding struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Severity    string                 `json:"severity"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Location    string                 `json:"location"`
	Evidence    map[string]interface{} `json:"evidence"`
	Remediation string                 `json:"remediation"`
	CVE         string                 `json:"cve,omitempty"`
	CWE         string                 `json:"cwe,omitempty"`
	Confidence  float64                `json:"confidence"`
}

// ProgressReporter handles progress reporting
type ProgressReporter struct {
	writer   io.Writer
	enabled  bool
	quiet    bool
	spinner  []string
	current  int
	message  string
	started  time.Time
}

// Formatter handles output formatting
type Formatter struct {
	options  FormatterOptions
	writer   io.Writer
	progress *ProgressReporter
	colors   *ColorScheme
}

// ColorScheme defines color mappings
type ColorScheme struct {
	Critical *color.Color
	High     *color.Color
	Medium   *color.Color
	Low      *color.Color
	Info     *color.Color
	Success  *color.Color
	Warning  *color.Color
	Error    *color.Color
	Header   *color.Color
	Bold     *color.Color
}

// NewFormatter creates a new output formatter
func NewFormatter(options FormatterOptions) *Formatter {
	writer := os.Stdout
	if options.OutputFile != "" {
		if file, err := os.Create(options.OutputFile); err == nil {
			writer = file
		}
	}

	colors := &ColorScheme{
		Critical: color.New(color.FgRed, color.Bold),
		High:     color.New(color.FgRed),
		Medium:   color.New(color.FgYellow),
		Low:      color.New(color.FgBlue),
		Info:     color.New(color.FgCyan),
		Success:  color.New(color.FgGreen),
		Warning:  color.New(color.FgYellow),
		Error:    color.New(color.FgRed),
		Header:   color.New(color.FgWhite, color.Bold),
		Bold:     color.New(color.Bold),
	}

	// Disable colors if requested or if not a terminal
	if !options.ColorOutput {
		color.NoColor = true
	}

	progress := &ProgressReporter{
		writer:  writer,
		enabled: options.ShowProgress && !options.Quiet,
		quiet:   options.Quiet,
		spinner: []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"},
		started: time.Now(),
	}

	return &Formatter{
		options:  options,
		writer:   writer,
		progress: progress,
		colors:   colors,
	}
}

// FormatResults formats and outputs scan results
func (f *Formatter) FormatResults(result *ScanResult) error {
	switch f.options.Format {
	case FormatJSON:
		return f.formatJSON(result)
	case FormatYAML:
		return f.formatYAML(result)
	case FormatText:
		return f.formatText(result)
	case FormatTable:
		return f.formatTable(result)
	case FormatCompact:
		return f.formatCompact(result)
	case FormatDetailed:
		return f.formatDetailed(result)
	case FormatSummary:
		return f.formatSummary(result)
	default:
		return f.formatJSON(result)
	}
}

// formatJSON outputs results in JSON format
func (f *Formatter) formatJSON(result *ScanResult) error {
	encoder := json.NewEncoder(f.writer)
	if f.options.Indent != "" {
		encoder.SetIndent("", f.options.Indent)
	} else {
		encoder.SetIndent("", "  ")
	}
	return encoder.Encode(result)
}

// formatYAML outputs results in YAML format
func (f *Formatter) formatYAML(result *ScanResult) error {
	encoder := yaml.NewEncoder(f.writer)
	encoder.SetIndent(2)
	defer encoder.Close()
	return encoder.Encode(result)
}

// formatText outputs results in human-readable text format
func (f *Formatter) formatText(result *ScanResult) error {
	f.printHeader("TypoSentinel Security Scan Report")
	f.printSeparator()

	// Package information
	f.printSection("Package Information")
	fmt.Fprintf(f.writer, "Name: %s\n", f.colorize(result.Package.Name, f.colors.Bold))
	fmt.Fprintf(f.writer, "Version: %s\n", result.Package.Version)
	fmt.Fprintf(f.writer, "Registry: %s\n", result.Package.Registry)
	fmt.Fprintf(f.writer, "Scan ID: %s\n", result.Metadata.ScanID)
	fmt.Fprintf(f.writer, "Timestamp: %s\n", result.Metadata.Timestamp.Format(time.RFC3339))
	fmt.Fprintln(f.writer)

	// Risk assessment
	f.printSection("Risk Assessment")
	riskColor := f.getRiskColor(result.OverallRisk)
	fmt.Fprintf(f.writer, "Overall Risk: %s (%.2f)\n", 
		f.colorize(strings.ToUpper(result.OverallRisk), riskColor), result.RiskScore)
	fmt.Fprintf(f.writer, "Analysis Time: %v\n", result.Summary.AnalysisTime)
	fmt.Fprintf(f.writer, "Engines Used: %s\n", strings.Join(result.Summary.EnginesUsed, ", "))
	fmt.Fprintln(f.writer)

	// Findings summary
	f.printSection("Findings Summary")
	fmt.Fprintf(f.writer, "Total Findings: %d\n", result.Summary.TotalFindings)
	if result.Summary.CriticalFindings > 0 {
		fmt.Fprintf(f.writer, "Critical: %s\n", f.colorize(fmt.Sprintf("%d", result.Summary.CriticalFindings), f.colors.Critical))
	}
	if result.Summary.HighFindings > 0 {
		fmt.Fprintf(f.writer, "High: %s\n", f.colorize(fmt.Sprintf("%d", result.Summary.HighFindings), f.colors.High))
	}
	if result.Summary.MediumFindings > 0 {
		fmt.Fprintf(f.writer, "Medium: %s\n", f.colorize(fmt.Sprintf("%d", result.Summary.MediumFindings), f.colors.Medium))
	}
	if result.Summary.LowFindings > 0 {
		fmt.Fprintf(f.writer, "Low: %s\n", f.colorize(fmt.Sprintf("%d", result.Summary.LowFindings), f.colors.Low))
	}
	fmt.Fprintln(f.writer)

	// Detailed findings
	if len(result.Findings) > 0 && !f.options.Quiet {
		f.printSection("Detailed Findings")
		for i, finding := range result.Findings {
			f.printFinding(finding, i+1)
		}
	}

	// Recommendations
	if len(result.Recommendations) > 0 {
		f.printSection("Recommendations")
		for i, rec := range result.Recommendations {
			fmt.Fprintf(f.writer, "%d. %s\n", i+1, rec)
		}
		fmt.Fprintln(f.writer)
	}

	f.printSeparator()
	return nil
}

// formatTable outputs results in table format
func (f *Formatter) formatTable(result *ScanResult) error {
	// Summary table
	table := tablewriter.NewWriter(f.writer)
	table.SetHeader([]string{"Metric", "Value"})
	table.SetBorder(true)
	table.SetRowLine(true)

	table.Append([]string{"Package", result.Package.Name + "@" + result.Package.Version})
	table.Append([]string{"Overall Risk", strings.ToUpper(result.OverallRisk)})
	table.Append([]string{"Risk Score", fmt.Sprintf("%.2f", result.RiskScore)})
	table.Append([]string{"Total Findings", strconv.Itoa(result.Summary.TotalFindings)})
	table.Append([]string{"Analysis Time", result.Summary.AnalysisTime.String()})
	table.Append([]string{"Engines Used", strings.Join(result.Summary.EnginesUsed, ", ")})

	table.Render()

	// Findings table
	if len(result.Findings) > 0 {
		fmt.Fprintln(f.writer)
		findingsTable := tablewriter.NewWriter(f.writer)
		findingsTable.SetHeader([]string{"ID", "Type", "Severity", "Title", "Confidence"})
		findingsTable.SetBorder(true)
		findingsTable.SetRowLine(true)

		for _, finding := range result.Findings {
			findingsTable.Append([]string{
				finding.ID,
				finding.Type,
				finding.Severity,
				finding.Title,
				fmt.Sprintf("%.1f%%", finding.Confidence*100),
			})
		}

		findingsTable.Render()
	}

	return nil
}

// formatCompact outputs results in compact format
func (f *Formatter) formatCompact(result *ScanResult) error {
	riskColor := f.getRiskColor(result.OverallRisk)
	fmt.Fprintf(f.writer, "%s@%s: %s (%.2f) - %d findings in %v\n",
		result.Package.Name,
		result.Package.Version,
		f.colorize(strings.ToUpper(result.OverallRisk), riskColor),
		result.RiskScore,
		result.Summary.TotalFindings,
		result.Summary.AnalysisTime,
	)
	return nil
}

// formatDetailed outputs results in detailed format
func (f *Formatter) formatDetailed(result *ScanResult) error {
	// Start with text format
	if err := f.formatText(result); err != nil {
		return err
	}

	// Add detailed analysis results
	if result.StaticAnalysis != nil {
		f.printSection("Static Analysis Details")
		if data, err := json.MarshalIndent(result.StaticAnalysis, "", "  "); err == nil {
			fmt.Fprintf(f.writer, "%s\n", string(data))
		}
	}

	if result.DynamicAnalysis != nil {
		f.printSection("Dynamic Analysis Details")
		if data, err := json.MarshalIndent(result.DynamicAnalysis, "", "  "); err == nil {
			fmt.Fprintf(f.writer, "%s\n", string(data))
		}
	}

	if result.MLAnalysis != nil {
		f.printSection("ML Analysis Details")
		if data, err := json.MarshalIndent(result.MLAnalysis, "", "  "); err == nil {
			fmt.Fprintf(f.writer, "%s\n", string(data))
		}
	}

	return nil
}

// formatSummary outputs results in summary format
func (f *Formatter) formatSummary(result *ScanResult) error {
	f.printHeader("Scan Summary")
	fmt.Fprintf(f.writer, "Package: %s@%s\n", result.Package.Name, result.Package.Version)
	riskColor := f.getRiskColor(result.OverallRisk)
	fmt.Fprintf(f.writer, "Risk: %s (%.2f)\n", 
		f.colorize(strings.ToUpper(result.OverallRisk), riskColor), result.RiskScore)
	fmt.Fprintf(f.writer, "Findings: %d\n", result.Summary.TotalFindings)
	fmt.Fprintf(f.writer, "Time: %v\n", result.Summary.AnalysisTime)
	return nil
}

// Helper methods

func (f *Formatter) printHeader(title string) {
	fmt.Fprintf(f.writer, "\n%s\n", f.colorize(title, f.colors.Header))
}

func (f *Formatter) printSection(title string) {
	fmt.Fprintf(f.writer, "\n%s\n", f.colorize(title, f.colors.Bold))
	fmt.Fprintf(f.writer, "%s\n", strings.Repeat("-", len(title)))
}

func (f *Formatter) printSeparator() {
	fmt.Fprintf(f.writer, "%s\n", strings.Repeat("=", 80))
}

func (f *Formatter) printFinding(finding Finding, index int) {
	severityColor := f.getSeverityColor(finding.Severity)
	fmt.Fprintf(f.writer, "\n%d. %s [%s]\n",
		index,
		f.colorize(finding.Title, f.colors.Bold),
		f.colorize(strings.ToUpper(finding.Severity), severityColor),
	)
	fmt.Fprintf(f.writer, "   Type: %s\n", finding.Type)
	fmt.Fprintf(f.writer, "   Location: %s\n", finding.Location)
	fmt.Fprintf(f.writer, "   Confidence: %.1f%%\n", finding.Confidence*100)
	if finding.Description != "" {
		fmt.Fprintf(f.writer, "   Description: %s\n", finding.Description)
	}
	if finding.Remediation != "" {
		fmt.Fprintf(f.writer, "   Remediation: %s\n", finding.Remediation)
	}
	if finding.CVE != "" {
		fmt.Fprintf(f.writer, "   CVE: %s\n", finding.CVE)
	}
}

func (f *Formatter) colorize(text string, color *color.Color) string {
	if f.options.ColorOutput {
		return color.Sprint(text)
	}
	return text
}

func (f *Formatter) getRiskColor(risk string) *color.Color {
	switch strings.ToLower(risk) {
	case "critical":
		return f.colors.Critical
	case "high":
		return f.colors.High
	case "medium":
		return f.colors.Medium
	case "low":
		return f.colors.Low
	default:
		return f.colors.Info
	}
}

func (f *Formatter) getSeverityColor(severity string) *color.Color {
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
		return f.colors.Info
	}
}

// Progress reporting methods

func (p *ProgressReporter) Start(message string) {
	if !p.enabled {
		return
	}
	p.message = message
	p.started = time.Now()
	fmt.Fprintf(p.writer, "\r%s %s", p.spinner[0], message)
}

func (p *ProgressReporter) Update(message string) {
	if !p.enabled {
		return
	}
	p.current = (p.current + 1) % len(p.spinner)
	p.message = message
	elapsed := time.Since(p.started)
	fmt.Fprintf(p.writer, "\r%s %s (%v)", p.spinner[p.current], message, elapsed.Truncate(time.Second))
}

func (p *ProgressReporter) Finish(message string) {
	if !p.enabled {
		return
	}
	elapsed := time.Since(p.started)
	fmt.Fprintf(p.writer, "\r✓ %s (%v)\n", message, elapsed.Truncate(time.Millisecond))
}

func (p *ProgressReporter) Error(message string) {
	if !p.enabled {
		return
	}
	elapsed := time.Since(p.started)
	fmt.Fprintf(p.writer, "\r✗ %s (%v)\n", message, elapsed.Truncate(time.Millisecond))
}