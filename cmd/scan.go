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
	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/internal/dynamic"
	"github.com/Alivanroy/Typosentinel/internal/ml"
	"github.com/Alivanroy/Typosentinel/internal/provenance"
	"github.com/Alivanroy/Typosentinel/internal/scanner"
	"github.com/Alivanroy/Typosentinel/internal/static"
	"github.com/Alivanroy/Typosentinel/pkg/logger"
	"github.com/Alivanroy/Typosentinel/pkg/types"
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
	config             *config.Config
	staticAnalyzer     *static.StaticAnalyzer
	dynamicAnalyzer    *dynamic.DynamicAnalyzer
	mlAnalyzer         *ml.MLAnalyzer
	provenanceAnalyzer *provenance.ProvenanceAnalyzer
}

// NewScanner creates a new scanner instance.
func NewScanner(cfg *config.Config) (*Scanner, error) {
	logger.TraceFunction("NewScanner")
	logger.VerboseWithContext("Initializing scanner with configuration", map[string]interface{}{
		"debug":   cfg.Debug,
		"verbose": cfg.Verbose,
	})

	logger.DebugWithContext("Scanner configuration details", map[string]interface{}{
		"config_type": fmt.Sprintf("%T", cfg),
		"memory_addr": fmt.Sprintf("%p", cfg),
	})

	scanner := &Scanner{
		config: cfg,
	}

	// Initialize analysis engines with default configuration
	// Note: Complex analysis configurations have been simplified in the unified Config
	logger.VerboseWithContext("Initializing static analyzer", map[string]interface{}{
		"enabled": true,
	})
	staticConfig := &static.Config{
		Enabled: true,
		AnalyzeInstallScripts: true,
		AnalyzeManifests: true,
			YaraRulesEnabled: false,
		YaraRulesPath: "",
		MaxFileSize: 10485760, // 10MB default
		Timeout: "30s",
		Verbose: cfg.Verbose,
	}
	staticAnalyzer, err := static.NewStaticAnalyzer(staticConfig)
	if err != nil {
		logger.Error("Failed to create static analyzer", map[string]interface{}{
			"error": err.Error(),
		})
		return nil, fmt.Errorf("failed to create static analyzer: %w", err)
	}
	scanner.staticAnalyzer = staticAnalyzer
	logger.Info("Static analyzer initialized successfully")
	logger.DebugWithContext("Static analyzer details", map[string]interface{}{
		"analyzer_type": fmt.Sprintf("%T", staticAnalyzer),
		"config":       staticConfig,
	})

	// Dynamic analysis is disabled in the simplified configuration
	// Complex dynamic analysis configurations have been removed
	if false { // Disabled for now
		logger.VerboseWithContext("Dynamic analyzer disabled in simplified config", map[string]interface{}{})
		dynamicConfig := &dynamic.Config{
			Enabled: false,
			SandboxType: "docker",
			SandboxImage: "ubuntu:latest",
			SandboxTimeout: "30s",
			MaxConcurrentSandboxes: 1,
			AnalyzeInstallScripts: false,
			AnalyzeNetworkActivity: false,
			AnalyzeFileSystem: false,
			AnalyzeProcesses: false,
			AnalyzeEnvironment: false,
			MaxExecutionTime: "30s",
			MaxMemoryUsage: 1073741824, // 1GB default
			MaxDiskUsage: 1073741824,   // 1GB default
			MaxNetworkConnections: 100,
			MonitoringInterval: "1s",
			Verbose: cfg.Verbose,
			LogLevel: "info",
		}
		dynamicAnalyzer, err := dynamic.NewDynamicAnalyzer(dynamicConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create dynamic analyzer: %w", err)
		}
		scanner.dynamicAnalyzer = dynamicAnalyzer
		logger.Info("Dynamic analyzer initialized successfully")
		logger.DebugWithContext("Dynamic analyzer details", map[string]interface{}{
			"analyzer_type": fmt.Sprintf("%T", dynamicAnalyzer),
			"config":        dynamicConfig,
		})
	}

	// Initialize ML analyzer
	logger.VerboseWithContext("Initializing ML analyzer", map[string]interface{}{
		"enabled": cfg.MLService != nil && cfg.MLService.Enabled,
	})
	if cfg.MLService != nil && cfg.MLService.Enabled {
		// Create ML analysis config from MLService config
		mlConfig := config.MLAnalysisConfig{
			Enabled: true,
			ModelPath: "./models",
			SimilarityThreshold: 0.8,
			MaliciousThreshold: 0.7,
			ReputationThreshold: 0.6,
			BatchSize: int(cfg.MLService.BatchSize),
			MaxFeatures: 1000,
			CacheEmbeddings: true,
			ParallelProcessing: true,
			GPUAcceleration: false,
		}
		mlAnalyzer := ml.NewMLAnalyzer(mlConfig)
		scanner.mlAnalyzer = mlAnalyzer
		logger.Info("ML analyzer initialized successfully")
		logger.DebugWithContext("ML analyzer details", map[string]interface{}{
			"analyzer_type": fmt.Sprintf("%T", mlAnalyzer),
			"config": mlConfig,
		})
	} else {
		logger.VerboseWithContext("ML analyzer disabled - MLService not configured or disabled", map[string]interface{}{})
	}

	// Provenance analysis is disabled in the simplified configuration
	// Complex provenance analysis configurations have been removed
	if false { // Disabled for now
		logger.VerboseWithContext("Provenance analyzer disabled in simplified config", map[string]interface{}{})
		// Provenance analyzer initialization would go here if enabled
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
  typosentinel scan --config custom-config.yaml express
  typosentinel scan --format table --no-color
  typosentinel scan --format compact --quiet
  typosentinel scan --config custom.yaml`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// Initialize configuration and logger first
		if err := initializeConfig(cmd, args); err != nil {
			return err
		}
		return runScan(cmd, args)
	},
}

var (
	// Scan command flags
	registry     string
	version      string
	local        string
	configFile   string
	outputFile   string
	outputFormat string
	quiet        bool
	noColor      bool
	timeout      string
	parallel     int
	skipEngines  []string
	onlyEngines  []string
	failFast     bool
	saveReport   bool
	showProgress bool
)

func init() {
	// Add scan command to root
	rootCmd.AddCommand(scanCmd)

	// Registry and package selection flags
	scanCmd.Flags().StringVarP(&registry, "registry", "r", "npm", "Package registry (npm, pypi, go, etc.)")
	scanCmd.Flags().StringVar(&version, "pkg-version", "latest", "Package version to scan")
	scanCmd.Flags().StringVarP(&local, "local", "l", "", "Scan local package file or directory")

	// Configuration flags
	scanCmd.Flags().StringVarP(&configFile, "config", "c", "", "Configuration file path")

	// Output flags
	scanCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file path")
	scanCmd.Flags().StringVarP(&outputFormat, "format", "f", "json", "Output format (json, yaml, text, table, compact, detailed, summary)")
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
	scanCmd.Flags().BoolVar(&showProgress, "progress", true, "Show progress during scan")
}

func runScan(cmd *cobra.Command, args []string) error {
	logger.TraceFunction("runScan")
	ctx := context.Background()

	logger.VerboseWithContext("Starting scan command", map[string]interface{}{
		"args":         args,
		"registry":     registry,
		"version":      version,
		"local":        local,
		"output_format": outputFormat,
		"timeout":      timeout,
		"parallel":     parallel,
	})

	// Parse timeout
	scanTimeout, err := time.ParseDuration(timeout)
	if err != nil {
		logger.Error("Invalid timeout format", map[string]interface{}{
			"timeout": timeout,
			"error":   err.Error(),
		})
		return fmt.Errorf("invalid timeout format: %w", err)
	}

	logger.DebugWithContext("Parsed scan timeout", map[string]interface{}{
		"timeout_duration": scanTimeout.String(),
		"timeout_seconds":  scanTimeout.Seconds(),
	})

	// Create context with timeout
	ctx, cancel := context.WithTimeout(ctx, scanTimeout)
	defer cancel()

	// Load configuration
	logger.VerboseWithContext("Loading configuration", map[string]interface{}{
		"config_file": configFile,
	})
	cfg, err := loadConfiguration()
	if err != nil {
		logger.Error("Failed to load configuration", map[string]interface{}{
			"config_file": configFile,
			"error":       err.Error(),
		})
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	logger.DebugWithContext("Configuration loaded successfully", map[string]interface{}{
		"config_type": fmt.Sprintf("%T", cfg),
		"config_file": configFile,
	})

	// Override configuration with command line flags
	logger.Verbose("Applying command line overrides")
	applyCommandLineOverrides(cfg)

	// Create scanner
	logger.Verbose("Creating scanner instance")
	// Use the loaded config and enable ML service
	regularConfig := cfg
	if regularConfig.MLService != nil {
		regularConfig.MLService.Enabled = true
	}
	baseScanner, err := scanner.New(regularConfig)
	if err != nil {
		logger.Error("Failed to create scanner", map[string]interface{}{
			"error": err.Error(),
		})
		return fmt.Errorf("failed to create scanner: %w", err)
	}

	// Create optimized scanner wrapper for better performance
	optimizedScanner := scanner.NewOptimizedScanner(baseScanner, regularConfig)
	logger.Debug("Optimized scanner created successfully")

	// Determine package to scan
	packageName := args[0]
	logger.VerboseWithContext("Resolving package", map[string]interface{}{
		"package_name": packageName,
		"registry":     registry,
		"version":      version,
	})
	pkg, err := resolvePackage(packageName)
	if err != nil {
		logger.Error("Failed to resolve package", map[string]interface{}{
			"package_name": packageName,
			"error":        err.Error(),
		})
		return fmt.Errorf("failed to resolve package: %w", err)
	}

	logger.DebugWithContext("Package resolved successfully", map[string]interface{}{
		"package": pkg,
	})

	if !quiet {
		fmt.Printf("Scanning package: %s@%s\n", pkg.Name, pkg.Version)
		fmt.Printf("Registry: %s\n", pkg.Registry)
		fmt.Println("Starting analysis...")
	}

	// Create comprehensive scanner with ML analysis
	logger.Info("Starting package scan", map[string]interface{}{
		"package": pkg.Name,
		"version": pkg.Version,
		"registry": pkg.Registry,
	})
	
	// Create comprehensive scanner with all analyzers
	comprehensiveScanner, err := NewScanner(regularConfig)
	if err != nil {
		logger.Error("Failed to create comprehensive scanner", map[string]interface{}{
			"error": err.Error(),
		})
		return fmt.Errorf("failed to create comprehensive scanner: %w", err)
	}
	
	// Perform comprehensive scan
	result, err := comprehensiveScanner.Scan(ctx, pkg)
	if err != nil {
		logger.Error("Comprehensive scan failed, falling back to optimized scan", map[string]interface{}{
			"package": pkg.Name,
			"error":   err.Error(),
		})
		// Fallback to optimized scanning
		optimizedPkg, err := optimizedScanner.ScanPackageParallel(pkg)
		if err != nil {
			logger.Error("Optimized scan also failed", map[string]interface{}{
				"package": pkg.Name,
				"error":   err.Error(),
			})
			return fmt.Errorf("all scan methods failed: %w", err)
		}
		// Convert optimized result to standard ScanResult format
		result = &ScanResult{
			Package: optimizedPkg,
			OverallRisk: optimizedPkg.RiskLevel.String(),
			RiskScore: optimizedPkg.RiskScore,
			Summary: ScanSummary{
				TotalFindings: 1,
				EnginesUsed: []string{"optimized"},
				AnalysisTime: time.Since(time.Now()),
				Status: "completed",
			},
			Metadata: ScanMetadata{
				ScanID: generateScanID(),
				Timestamp: time.Now(),
				Version: "1.0.0",
			},
		}
	}

	logger.Info("Scan completed successfully", map[string]interface{}{
		"package":        pkg.Name,
		"overall_risk":   result.OverallRisk,
		"risk_score":     result.RiskScore,
		"total_findings": result.Summary.TotalFindings,
	})

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
	return handleExitCodeLegacy(result)
}

// Scan performs a comprehensive scan of the package.
func (s *Scanner) Scan(ctx context.Context, pkg *types.Package) (*ScanResult, error) {
	logger.TraceFunction("Scanner.Scan")
	startTime := time.Now()

	logger.VerboseWithContext("Starting comprehensive package scan", map[string]interface{}{
		"package":     pkg.Name,
		"version":     pkg.Version,
		"registry":    pkg.Registry,
		"start_time":  startTime.Format(time.RFC3339),
	})

	// Initialize result
	scanID := generateScanID()
	result := &ScanResult{
		Package: pkg,
		Metadata: ScanMetadata{
			ScanID:      scanID,
			Timestamp:   startTime,
			Version:     "1.0.0", // Should come from build info
			Environment: s.config.Core.Environment,
		},
	}

	logger.DebugWithContext("Scan result initialized", map[string]interface{}{
		"scan_id":     scanID,
		"environment": s.config.Core.Environment,
		"result_type": fmt.Sprintf("%T", result),
	})

	// Track which engines are used
	enginesUsed := []string{}

	// Run static analysis
	if s.staticAnalyzer != nil && shouldRunEngine("static") {
		logger.VerboseWithContext("Starting static analysis", map[string]interface{}{
			"package":    pkg.Name,
			"analyzer":   fmt.Sprintf("%T", s.staticAnalyzer),
			"fail_fast":  failFast,
		})
		if verbose {
			fmt.Println("Running static analysis...")
		}
		staticStart := time.Now()
		staticResult, err := s.staticAnalyzer.AnalyzePackage(ctx, pkg.Name)
		staticDuration := time.Since(staticStart)
		if err != nil {
			logger.Error("Static analysis failed", map[string]interface{}{
				"package":  pkg.Name,
				"duration": staticDuration.String(),
				"error":    err.Error(),
			})
			if failFast {
				return nil, fmt.Errorf("static analysis failed: %w", err)
			}
			fmt.Printf("Warning: static analysis failed: %v\n", err)
		} else {
			logger.VerboseWithContext("Static analysis completed", map[string]interface{}{
				"package":        pkg.Name,
				"duration":       staticDuration.String(),
				"findings_count": len(staticResult.Findings),
				"risk_score":     staticResult.RiskScore,
			})
			result.StaticAnalysis = staticResult
			enginesUsed = append(enginesUsed, "static")
		}
	}

	// Run dynamic analysis
	if s.dynamicAnalyzer != nil && shouldRunEngine("dynamic") {
		logger.VerboseWithContext("Starting dynamic analysis", map[string]interface{}{
			"package":   pkg.Name,
			"analyzer":  fmt.Sprintf("%T", s.dynamicAnalyzer),
			"fail_fast": failFast,
		})
		if verbose {
			fmt.Println("Running dynamic analysis...")
		}
		dynamicStart := time.Now()
		dynamicResult, err := s.dynamicAnalyzer.AnalyzePackage(ctx, pkg.Name)
		dynamicDuration := time.Since(dynamicStart)
		if err != nil {
			logger.Error("Dynamic analysis failed", map[string]interface{}{
				"package":  pkg.Name,
				"duration": dynamicDuration.String(),
				"error":    err.Error(),
			})
			if failFast {
				return nil, fmt.Errorf("dynamic analysis failed: %w", err)
			}
			fmt.Printf("Warning: dynamic analysis failed: %v\n", err)
		} else {
			logger.VerboseWithContext("Dynamic analysis completed", map[string]interface{}{
				"package":        pkg.Name,
				"duration":       dynamicDuration.String(),
				"findings_count": len(dynamicResult.SecurityFindings),
				"risk_score":     dynamicResult.RiskScore,
			})
			result.DynamicAnalysis = dynamicResult
			enginesUsed = append(enginesUsed, "dynamic")
		}
	}

	// Run ML analysis
	if s.mlAnalyzer != nil && shouldRunEngine("ml") {
		logger.VerboseWithContext("Starting ML analysis", map[string]interface{}{
			"package":   pkg.Name,
			"analyzer":  fmt.Sprintf("%T", s.mlAnalyzer),
			"fail_fast": failFast,
		})
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
			if verbose {
				fmt.Println("ML analysis completed")
			}
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

func loadConfiguration() (*config.Config, error) {
	if configFile != "" {
		return config.LoadConfig(configFile)
	}
	return config.NewDefaultConfig(), nil
}

func applyCommandLineOverrides(cfg *config.Config) {
	if verbose {
		cfg.Verbose = true
		if cfg.Logging != nil {
			cfg.Logging.Level = "debug"
		}
	}
	if quiet {
		// Set quiet mode - this would need to be added to Config if needed
	}
	if noColor {
		// Set color disabled - this would need to be added to Config if needed
	}
	if outputFormat != "" {
		// Set output format - this would need to be added to Config if needed
	}
}

func resolvePackage(packageName string) (*types.Package, error) {
	if local != "" {
		return resolveLocalPackage(local)
	}
	return resolveRegistryPackage(packageName, registry, version)
}

func resolveLocalPackage(path string) (*types.Package, error) {
	// Check if path exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, fmt.Errorf("path does not exist: %s", path)
	}

	// Determine if it's a file or directory
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("failed to stat path: %w", err)
	}

	var projectPath string
	if info.IsDir() {
		projectPath = path
	} else {
		// If it's a file, use its directory
		projectPath = filepath.Dir(path)
	}

	// Load configuration for scanner
	cfg, err := config.LoadConfig(configFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	// Create scanner instance
	localScanner, err := scanner.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create scanner: %w", err)
	}

	// Scan the project for dependencies
	scanResult, err := localScanner.ScanProject(projectPath)
	if err != nil {
		return nil, fmt.Errorf("failed to scan project: %w", err)
	}

	if len(scanResult.Packages) == 0 {
		return nil, fmt.Errorf("no packages found in project")
	}

	// Return the main package with its dependencies
	mainPkg := scanResult.Packages[0]
	if len(scanResult.Packages) > 1 {
		// Convert []*types.Package to []types.Dependency
		for _, pkg := range scanResult.Packages[1:] {
			dep := types.Dependency{
				Name:     pkg.Name,
				Version:  pkg.Version,
				Registry: pkg.Registry,
			}
			mainPkg.Dependencies = append(mainPkg.Dependencies, dep)
		}
	}

	return mainPkg, nil
}

func resolveRegistryPackage(name, registry, version string) (*types.Package, error) {
	// Resolve package from registry with basic validation
	if name == "" {
		return nil, fmt.Errorf("package name cannot be empty")
	}
	
	// Set default version if not specified
	if version == "" {
		version = "latest"
	}
	
	// Validate registry type
	validRegistries := map[string]bool{
		"npm":  true,
		"pypi": true,
		"go":   true,
		"gem":  true,
	}
	
	if !validRegistries[registry] {
		return nil, fmt.Errorf("unsupported registry: %s", registry)
	}
	
	// Create package with resolved information
	pkg := &types.Package{
		Name:     name,
		Version:  version,
		Registry: registry,
		Metadata: &types.PackageMetadata{
			Metadata: make(map[string]interface{}),
		},
	}
	
	// Add basic metadata based on registry
	if pkg.Metadata.Metadata == nil {
		pkg.Metadata.Metadata = make(map[string]interface{})
	}
	switch registry {
	case "npm":
		pkg.Metadata.Metadata["package_manager"] = "npm"
		pkg.Metadata.Metadata["ecosystem"] = "javascript"
	case "pypi":
		pkg.Metadata.Metadata["package_manager"] = "pip"
		pkg.Metadata.Metadata["ecosystem"] = "python"
	case "go":
		pkg.Metadata.Metadata["package_manager"] = "go"
		pkg.Metadata.Metadata["ecosystem"] = "golang"
	case "gem":
		pkg.Metadata.Metadata["package_manager"] = "gem"
		pkg.Metadata.Metadata["ecosystem"] = "ruby"
	}
	
	return pkg, nil
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

// Note: convertToOutputFormat function is defined in scan_helpers.go

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

// Note: outputJSON and outputYAML functions are defined in plugin.go to avoid duplication

func outputText(result *ScanResult) error {
	w, err := getOutputWriter("")
	if err != nil {
		return fmt.Errorf("failed to get output writer: %w", err)
	}
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
	// Create a simple table format for scan results
	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Printf("| %-20s | %-50s |\n", "SCAN SUMMARY", "")
	fmt.Println(strings.Repeat("=", 80))
	fmt.Printf("| %-20s | %-50s |\n", "Package", result.Package.Name)
	fmt.Printf("| %-20s | %-50s |\n", "Version", result.Package.Version)
	fmt.Printf("| %-20s | %-50s |\n", "Registry", result.Package.Registry)
	fmt.Printf("| %-20s | %-50s |\n", "Scan ID", result.Metadata.ScanID)
	fmt.Printf("| %-20s | %-50s |\n", "Timestamp", result.Metadata.Timestamp.Format("2006-01-02 15:04:05"))
	fmt.Printf("| %-20s | %-50d |\n", "Total Threats", result.Summary.TotalFindings)
	fmt.Println(strings.Repeat("=", 80))

	if result.Summary.TotalFindings > 0 {
		fmt.Println("\n" + strings.Repeat("-", 100))
		fmt.Printf("| %-15s | %-10s | %-10s | %-50s |\n", "TYPE", "SEVERITY", "CONFIDENCE", "DESCRIPTION")
		fmt.Println(strings.Repeat("-", 100))
		
		// Display threat summary since individual threats are in analysis results
		fmt.Printf("| %-15s | %-15s | %-15s | %-15s | %-15s |\n", "Critical", "High", "Medium", "Low", "Total")
		fmt.Printf("| %-15d | %-15d | %-15d | %-15d | %-15d |\n", 
			result.Summary.CriticalFindings, result.Summary.HighFindings, 
			result.Summary.MediumFindings, result.Summary.LowFindings, result.Summary.TotalFindings)
		fmt.Println(strings.Repeat("-", 100))
	} else {
		fmt.Println("\n✅ No threats detected!")
	}

	return nil
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



func handleExitCodeLegacy(result *ScanResult) error {
	// Exit with non-zero code for high-risk packages
	switch result.OverallRisk {
	case "critical":
		os.Exit(2)
	case "high":
		os.Exit(1)
	}
	return nil
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