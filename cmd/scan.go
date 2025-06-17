package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"typosentinel/internal/config"
	"typosentinel/internal/dynamic"
	"typosentinel/internal/ml"
	"typosentinel/internal/provenance"
	"typosentinel/internal/static"
	"typosentinel/pkg/types"
)

// ScanResult represents the combined results from all analysis engines.
type ScanResult struct {
	Package            *types.Package                `json:"package"`
	StaticAnalysis     *static.AnalysisResult        `json:"static_analysis,omitempty"`
	DynamicAnalysis    *dynamic.AnalysisResult       `json:"dynamic_analysis,omitempty"`
	MLAnalysis         *ml.AnalysisResult            `json:"ml_analysis,omitempty"`
	ProvenanceAnalysis *provenance.AnalysisResult    `json:"provenance_analysis,omitempty"`
	OverallRisk        string                        `json:"overall_risk"`
	RiskScore          float64                       `json:"risk_score"`
	Recommendations    []string                      `json:"recommendations"`
	Summary            ScanSummary                   `json:"summary"`
	Metadata           ScanMetadata                  `json:"metadata"`
}

// ScanSummary provides a high-level summary of the scan results.
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

// ScanMetadata contains metadata about the scan.
type ScanMetadata struct {
	ScanID        string    `json:"scan_id"`
	Timestamp     time.Time `json:"timestamp"`
	Version       string    `json:"version"`
	Configuration string    `json:"configuration"`
	Environment   string    `json:"environment"`
	User          string    `json:"user"`
	Hostname      string    `json:"hostname"`
}

// Scanner orchestrates the analysis engines.
type Scanner struct {
	config             *config.EnhancedConfig
	staticAnalyzer     *static.StaticAnalyzer
	dynamicAnalyzer    *dynamic.DynamicAnalyzer
	mlAnalyzer         *ml.MLAnalyzer
	provenanceAnalyzer *provenance.ProvenanceAnalyzer
}

// NewScanner creates a new scanner instance.
func NewScanner(cfg *config.EnhancedConfig) (*Scanner, error) {
	scanner := &Scanner{
		config: cfg,
	}

	// Initialize analysis engines based on configuration
	if cfg.StaticAnalysis != nil && cfg.StaticAnalysis.Enabled {
		staticConfig := &static.Config{
			Enabled: cfg.StaticAnalysis.Enabled,
			AnalyzeInstallScripts: cfg.StaticAnalysis.ScanScripts,
			AnalyzeManifests: cfg.StaticAnalysis.ScanManifests,
			YaraRulesEnabled: cfg.StaticAnalysis.YaraRulesPath != "",
			YaraRulesPath: cfg.StaticAnalysis.YaraRulesPath,
			MaxFileSize: 10485760, // 10MB default
			Timeout: cfg.StaticAnalysis.Timeout,
			Verbose: false,
		}
		staticAnalyzer, err := static.NewStaticAnalyzer(staticConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create static analyzer: %w", err)
		}
		scanner.staticAnalyzer = staticAnalyzer
	}

	if cfg.DynamicAnalysis != nil && cfg.DynamicAnalysis.Enabled {
		dynamicConfig := &dynamic.Config{
			Enabled: cfg.DynamicAnalysis.Enabled,
			SandboxType: cfg.DynamicAnalysis.SandboxType,
			SandboxImage: cfg.DynamicAnalysis.SandboxImage,
			SandboxTimeout: cfg.DynamicAnalysis.Timeout,
			MaxConcurrentSandboxes: 1,
			AnalyzeInstallScripts: cfg.DynamicAnalysis.ExecuteInstallScripts,
			AnalyzeNetworkActivity: cfg.DynamicAnalysis.MonitorNetworkActivity,
			AnalyzeFileSystem: cfg.DynamicAnalysis.MonitorFileActivity,
			AnalyzeProcesses: cfg.DynamicAnalysis.MonitorProcessActivity,
			AnalyzeEnvironment: true,
			MaxExecutionTime: cfg.DynamicAnalysis.MaxExecutionTime,
			MaxMemoryUsage: 1073741824, // 1GB default
			MaxDiskUsage: 1073741824,   // 1GB default
			MaxNetworkConnections: 100,
			MonitoringInterval: "1s",
			Verbose: false,
			LogLevel: "info",
		}
		dynamicAnalyzer, err := dynamic.NewDynamicAnalyzer(dynamicConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create dynamic analyzer: %w", err)
		}
		scanner.dynamicAnalyzer = dynamicAnalyzer
	}

	if cfg.MLAnalysis != nil && cfg.MLAnalysis.Enabled {
		scanner.mlAnalyzer = ml.NewMLAnalyzer(*cfg.MLAnalysis)
	}

	if cfg.ProvenanceAnalysis != nil && cfg.ProvenanceAnalysis.Enabled {
		provenanceConfig := &provenance.Config{
			Enabled: cfg.ProvenanceAnalysis.Enabled,
			SigstoreEnabled: cfg.ProvenanceAnalysis.SigstoreEnabled,
			SigstoreRekorURL: cfg.ProvenanceAnalysis.SigstoreRekorURL,
			SigstoreFulcioURL: cfg.ProvenanceAnalysis.SigstoreFulcioURL,
			SigstoreCTLogURL: cfg.ProvenanceAnalysis.SigstoreCTLogURL,
			SLSAEnabled: cfg.ProvenanceAnalysis.SLSAEnabled,
			SLSAMinLevel: cfg.ProvenanceAnalysis.SLSAMinLevel,
			SLSARequiredBuilders: cfg.ProvenanceAnalysis.SLSARequiredBuilders,
			VerifySignatures: cfg.ProvenanceAnalysis.VerifySignatures,
			VerifyProvenance: cfg.ProvenanceAnalysis.VerifyProvenance,
			VerifyIntegrity: cfg.ProvenanceAnalysis.VerifyIntegrity,
			RequireTransparencyLog: cfg.ProvenanceAnalysis.RequireTransparencyLog,
			TrustedPublishers: cfg.ProvenanceAnalysis.TrustedPublishers,
			TrustedSigners: cfg.ProvenanceAnalysis.TrustedSigners,
			TrustedBuilders: cfg.ProvenanceAnalysis.TrustedBuilders,
			Timeout: cfg.ProvenanceAnalysis.Timeout,
			RetryAttempts: cfg.ProvenanceAnalysis.RetryAttempts,
		}
		provenanceAnalyzer, err := provenance.NewProvenanceAnalyzer(provenanceConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create provenance analyzer: %w", err)
		}
		scanner.provenanceAnalyzer = provenanceAnalyzer
	}

	return scanner, nil
}

// scanCmd represents the scan command
var scanCmd = &cobra.Command{
	Use:   "scan [package-name]",
	Short: "Scan a package for typosquatting and security issues",
	Long: `Scan analyzes a package using multiple detection engines to identify
typosquatting attempts, malicious code, and security vulnerabilities.

The scan command supports various package managers and registries:
- npm packages: scan lodash
- PyPI packages: scan --registry pypi requests
- Local packages: scan --local ./package.json

Example usage:
  typosentinel scan lodash
  typosentinel scan --registry pypi requests
  typosentinel scan --local ./package.json
  typosentinel scan --config custom-config.yaml express`,
	Args: cobra.MinimumNArgs(1),
	RunE: runScan,
}

var (
	// Scan command flags
	registry     string
	version      string
	local        string
	configFile   string
	outputFile   string
	outputFormat string
	verbose      bool
	quiet        bool
	noColor      bool
	timeout      string
	parallel     int
	skipEngines  []string
	onlyEngines  []string
	failFast     bool
	saveReport   bool
)

func init() {
	rootCmd.AddCommand(scanCmd)

	// Registry and package selection flags
	scanCmd.Flags().StringVarP(&registry, "registry", "r", "npm", "Package registry (npm, pypi, go, etc.)")
	scanCmd.Flags().StringVarP(&version, "version", "v", "latest", "Package version to scan")
	scanCmd.Flags().StringVarP(&local, "local", "l", "", "Scan local package file or directory")

	// Configuration flags
	scanCmd.Flags().StringVarP(&configFile, "config", "c", "", "Configuration file path")

	// Output flags
	scanCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file path")
	scanCmd.Flags().StringVarP(&outputFormat, "format", "f", "json", "Output format (json, yaml, text, table)")
	scanCmd.Flags().BoolVarP(&verbose, "verbose", "", false, "Enable verbose output")
	scanCmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "Suppress non-essential output")
	scanCmd.Flags().BoolVar(&noColor, "no-color", false, "Disable colored output")

	// Performance flags
	scanCmd.Flags().StringVarP(&timeout, "timeout", "t", "5m", "Scan timeout duration")
	scanCmd.Flags().IntVarP(&parallel, "parallel", "p", 1, "Number of parallel scans")

	// Engine control flags
	scanCmd.Flags().StringSliceVar(&skipEngines, "skip-engines", []string{}, "Analysis engines to skip")
	scanCmd.Flags().StringSliceVar(&onlyEngines, "only-engines", []string{}, "Only run specified analysis engines")
	scanCmd.Flags().BoolVar(&failFast, "fail-fast", false, "Stop on first critical finding")

	// Report flags
	scanCmd.Flags().BoolVar(&saveReport, "save-report", false, "Save detailed report to file")
}

func runScan(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Parse timeout
	scanTimeout, err := time.ParseDuration(timeout)
	if err != nil {
		return fmt.Errorf("invalid timeout format: %w", err)
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(ctx, scanTimeout)
	defer cancel()

	// Load configuration
	cfg, err := loadConfiguration()
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	// Override configuration with command line flags
	applyCommandLineOverrides(cfg)

	// Create scanner
	scanner, err := NewScanner(cfg)
	if err != nil {
		return fmt.Errorf("failed to create scanner: %w", err)
	}

	// Determine package to scan
	packageName := args[0]
	pkg, err := resolvePackage(packageName)
	if err != nil {
		return fmt.Errorf("failed to resolve package: %w", err)
	}

	if !quiet {
		fmt.Printf("Scanning package: %s@%s\n", pkg.Name, pkg.Version)
		fmt.Printf("Registry: %s\n", pkg.Registry)
		fmt.Println("Starting analysis...")
	}

	// Perform scan
	result, err := scanner.Scan(ctx, pkg)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	// Output results
	if err := outputResults(result); err != nil {
		return fmt.Errorf("failed to output results: %w", err)
	}

	// Save report if requested
	if saveReport {
		if err := saveDetailedReport(result); err != nil {
			fmt.Printf("Warning: failed to save detailed report: %v\n", err)
		}
	}

	// Exit with appropriate code based on findings
	return handleExitCode(result)
}

// Scan performs a comprehensive scan of the package.
func (s *Scanner) Scan(ctx context.Context, pkg *types.Package) (*ScanResult, error) {
	startTime := time.Now()

	// Initialize result
	result := &ScanResult{
		Package: pkg,
		Metadata: ScanMetadata{
			ScanID:      generateScanID(),
			Timestamp:   startTime,
			Version:     "1.0.0", // Should come from build info
			Environment: s.config.Core.Environment,
		},
	}

	// Track which engines are used
	enginesUsed := []string{}

	// Run static analysis
	if s.staticAnalyzer != nil && shouldRunEngine("static") {
		if verbose {
			fmt.Println("Running static analysis...")
		}
		staticResult, err := s.staticAnalyzer.AnalyzePackage(ctx, pkg.Name)
		if err != nil {
			if failFast {
				return nil, fmt.Errorf("static analysis failed: %w", err)
			}
			fmt.Printf("Warning: static analysis failed: %v\n", err)
		} else {
			result.StaticAnalysis = staticResult
			enginesUsed = append(enginesUsed, "static")
		}
	}

	// Run dynamic analysis
	if s.dynamicAnalyzer != nil && shouldRunEngine("dynamic") {
		if verbose {
			fmt.Println("Running dynamic analysis...")
		}
		dynamicResult, err := s.dynamicAnalyzer.AnalyzePackage(ctx, pkg.Name)
		if err != nil {
			if failFast {
				return nil, fmt.Errorf("dynamic analysis failed: %w", err)
			}
			fmt.Printf("Warning: dynamic analysis failed: %v\n", err)
		} else {
			result.DynamicAnalysis = dynamicResult
			enginesUsed = append(enginesUsed, "dynamic")
		}
	}

	// Run ML analysis
	if s.mlAnalyzer != nil && shouldRunEngine("ml") {
		if verbose {
			fmt.Println("Running ML analysis...")
		}
		mlResult, err := s.mlAnalyzer.Analyze(ctx, pkg)
		if err != nil {
			if failFast {
				return nil, fmt.Errorf("ML analysis failed: %w", err)
			}
			fmt.Printf("Warning: ML analysis failed: %v\n", err)
		} else {
			result.MLAnalysis = mlResult
			enginesUsed = append(enginesUsed, "ml")
		}
	}

	// Run provenance analysis
	if s.provenanceAnalyzer != nil && shouldRunEngine("provenance") {
		if verbose {
			fmt.Println("Running provenance analysis...")
		}
		provenanceResult, err := s.provenanceAnalyzer.AnalyzePackage(ctx, pkg.Name, pkg.Name, pkg.Version, pkg.Registry)
		if err != nil {
			if failFast {
				return nil, fmt.Errorf("provenance analysis failed: %w", err)
			}
			fmt.Printf("Warning: provenance analysis failed: %v\n", err)
		} else {
			result.ProvenanceAnalysis = provenanceResult
			enginesUsed = append(enginesUsed, "provenance")
		}
	}

	// Calculate overall risk and generate recommendations
	result.OverallRisk, result.RiskScore = s.calculateOverallRisk(result)
	result.Recommendations = s.generateRecommendations(result)

	// Generate summary
	result.Summary = s.generateSummary(result, enginesUsed, time.Since(startTime))

	return result, nil
}

// calculateOverallRisk calculates the overall risk assessment.
func (s *Scanner) calculateOverallRisk(result *ScanResult) (string, float64) {
	var totalScore float64
	var weights float64

	// Weight static analysis results
	if result.StaticAnalysis != nil {
		totalScore += result.StaticAnalysis.RiskScore * 0.3
		weights += 0.3
	}

	// Weight dynamic analysis results
	if result.DynamicAnalysis != nil {
		totalScore += result.DynamicAnalysis.RiskScore * 0.25
		weights += 0.25
	}

	// Weight ML analysis results
	if result.MLAnalysis != nil {
		totalScore += result.MLAnalysis.TyposquattingScore * 0.3
		weights += 0.3
	}

	// Weight provenance analysis results
	if result.ProvenanceAnalysis != nil {
		// Invert trust score to get risk score
		provenanceRisk := 1.0 - result.ProvenanceAnalysis.TrustAssessment.OverallTrustScore
		totalScore += provenanceRisk * 0.15
		weights += 0.15
	}

	// Calculate weighted average
	var riskScore float64
	if weights > 0 {
		riskScore = totalScore / weights
	}

	// Determine risk level
	var riskLevel string
	switch {
	case riskScore >= 0.8:
		riskLevel = "critical"
	case riskScore >= 0.6:
		riskLevel = "high"
	case riskScore >= 0.4:
		riskLevel = "medium"
	case riskScore >= 0.2:
		riskLevel = "low"
	default:
		riskLevel = "minimal"
	}

	return riskLevel, riskScore
}

// generateRecommendations generates overall recommendations.
func (s *Scanner) generateRecommendations(result *ScanResult) []string {
	recommendations := []string{}

	// Risk-based recommendations
	switch result.OverallRisk {
	case "critical":
		recommendations = append(recommendations, "🚨 DO NOT INSTALL: Package poses critical security risk")
		recommendations = append(recommendations, "Report this package to the registry security team")
	case "high":
		recommendations = append(recommendations, "⚠️  Exercise extreme caution before installation")
		recommendations = append(recommendations, "Perform thorough security review and testing")
	case "medium":
		recommendations = append(recommendations, "⚡ Review package carefully before installation")
		recommendations = append(recommendations, "Consider using alternative packages")
	case "low":
		recommendations = append(recommendations, "✅ Package appears relatively safe but monitor usage")
	default:
		recommendations = append(recommendations, "✅ Package appears safe for installation")
	}

	// Engine-specific recommendations
	if result.StaticAnalysis != nil {
		recommendations = append(recommendations, result.StaticAnalysis.Recommendations...)
	}
	if result.DynamicAnalysis != nil {
		recommendations = append(recommendations, result.DynamicAnalysis.Recommendations...)
	}
	if result.MLAnalysis != nil {
		recommendations = append(recommendations, result.MLAnalysis.Recommendations...)
	}
	if result.ProvenanceAnalysis != nil {
		recommendations = append(recommendations, result.ProvenanceAnalysis.Recommendations...)
	}

	// Remove duplicates
	recommendations = removeDuplicates(recommendations)

	return recommendations
}

// generateSummary generates a summary of the scan results.
func (s *Scanner) generateSummary(result *ScanResult, enginesUsed []string, analysisTime time.Duration) ScanSummary {
	summary := ScanSummary{
		EnginesUsed:        enginesUsed,
		AnalysisTime:       analysisTime,
		FindingsByCategory: make(map[string]int),
		Status:             "completed",
	}

	// Count findings from all engines
	allFindings := []interface{}{}

	if result.StaticAnalysis != nil {
		for _, finding := range result.StaticAnalysis.Findings {
			allFindings = append(allFindings, finding)
			summary.FindingsByCategory["static"]++
		}
	}

	if result.DynamicAnalysis != nil {
		for _, finding := range result.DynamicAnalysis.SecurityFindings {
			allFindings = append(allFindings, finding)
			summary.FindingsByCategory["dynamic"]++
		}
	}

	if result.MLAnalysis != nil {
		for _, finding := range result.MLAnalysis.Findings {
			allFindings = append(allFindings, finding)
			summary.FindingsByCategory["ml"]++
		}
	}

	if result.ProvenanceAnalysis != nil {
		for _, finding := range result.ProvenanceAnalysis.Findings {
			allFindings = append(allFindings, finding)
			summary.FindingsByCategory["provenance"]++
		}
	}

	summary.TotalFindings = len(allFindings)

	// Count by severity (this would need to be implemented based on actual finding structures)
	// For now, using placeholder logic
	switch result.OverallRisk {
	case "critical":
		summary.CriticalFindings = 1
	case "high":
		summary.HighFindings = 1
	case "medium":
		summary.MediumFindings = 1
	case "low":
		summary.LowFindings = 1
	}

	return summary
}

// Helper functions

func loadConfiguration() (*config.EnhancedConfig, error) {
	if configFile != "" {
		return config.LoadEnhancedConfig(configFile)
	}
	return config.DefaultEnhancedConfig(), nil
}

func applyCommandLineOverrides(cfg *config.EnhancedConfig) {
	if verbose {
		cfg.Output.VerboseOutput = true
		cfg.Logging.Level = "debug"
	}
	if quiet {
		cfg.Output.QuietMode = true
	}
	if noColor {
		cfg.Output.ColorEnabled = false
	}
	if outputFormat != "" {
		cfg.Output.Format = outputFormat
	}
}

func resolvePackage(packageName string) (*types.Package, error) {
	if local != "" {
		return resolveLocalPackage(local)
	}
	return resolveRegistryPackage(packageName, registry, version)
}

func resolveLocalPackage(path string) (*types.Package, error) {
	// Placeholder implementation for local package resolution
	return &types.Package{
		Name:     filepath.Base(path),
		Version:  "local",
		Registry: "local",
	}, nil
}

func resolveRegistryPackage(name, registry, version string) (*types.Package, error) {
	// Placeholder implementation for registry package resolution
	return &types.Package{
		Name:     name,
		Version:  version,
		Registry: registry,
	}, nil
}

func shouldRunEngine(engine string) bool {
	// Check if engine is in skip list
	for _, skip := range skipEngines {
		if skip == engine {
			return false
		}
	}

	// If only-engines is specified, check if engine is in the list
	if len(onlyEngines) > 0 {
		for _, only := range onlyEngines {
			if only == engine {
				return true
			}
		}
		return false
	}

	return true
}

func outputResults(result *ScanResult) error {
	switch outputFormat {
	case "json":
		return outputJSON(result)
	case "yaml":
		return outputYAML(result)
	case "text":
		return outputText(result)
	case "table":
		return outputTable(result)
	default:
		return outputJSON(result)
	}
}

func outputJSON(result *ScanResult) error {
	encoder := json.NewEncoder(getOutputWriter())
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

func outputYAML(result *ScanResult) error {
	// Placeholder - would use yaml package
	return outputJSON(result)
}

func outputText(result *ScanResult) error {
	w := getOutputWriter()
	fmt.Fprintf(w, "Package: %s@%s\n", result.Package.Name, result.Package.Version)
	fmt.Fprintf(w, "Registry: %s\n", result.Package.Registry)
	fmt.Fprintf(w, "Overall Risk: %s (%.2f)\n", result.OverallRisk, result.RiskScore)
	fmt.Fprintf(w, "Total Findings: %d\n", result.Summary.TotalFindings)
	fmt.Fprintf(w, "Analysis Time: %v\n", result.Summary.AnalysisTime)
	fmt.Fprintf(w, "Engines Used: %s\n", strings.Join(result.Summary.EnginesUsed, ", "))

	if len(result.Recommendations) > 0 {
		fmt.Fprintf(w, "\nRecommendations:\n")
		for _, rec := range result.Recommendations {
			fmt.Fprintf(w, "  - %s\n", rec)
		}
	}

	return nil
}

func outputTable(result *ScanResult) error {
	// Placeholder - would use table formatting library
	return outputText(result)
}

func getOutputWriter() *os.File {
	if outputFile != "" {
		file, err := os.Create(outputFile)
		if err != nil {
			fmt.Printf("Warning: failed to create output file, using stdout: %v\n", err)
			return os.Stdout
		}
		return file
	}
	return os.Stdout
}

func saveDetailedReport(result *ScanResult) error {
	reportFile := fmt.Sprintf("typosentinel-report-%s.json", result.Metadata.ScanID)
	file, err := os.Create(reportFile)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(result); err != nil {
		return err
	}

	if !quiet {
		fmt.Printf("Detailed report saved to: %s\n", reportFile)
	}
	return nil
}

func handleExitCode(result *ScanResult) error {
	// Exit with non-zero code for high-risk packages
	switch result.OverallRisk {
	case "critical":
		os.Exit(2)
	case "high":
		os.Exit(1)
	}
	return nil
}

func generateScanID() string {
	return fmt.Sprintf("%d", time.Now().Unix())
}

func removeDuplicates(slice []string) []string {
	seen := make(map[string]bool)
	result := []string{}
	for _, item := range slice {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}
	return result
}