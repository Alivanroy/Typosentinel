package cmd

import (
	"fmt"
	"log"
	"strings"

	"github.com/Alivanroy/Typosentinel/internal/analyzer"
	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func init() {
	RootCmd.AddCommand(scanCmd)
}

var scanCmd = &cobra.Command{
	Use:   "scan [path]",
	Short: "Scan a project for typosquatting and malicious packages (auto-detects project types)",
	Long: `Scan a project directory for typosquatting and malicious packages.

TypoSentinel automatically detects project types (Node.js, Python, Go, Rust, Java, .NET, PHP, Ruby)
based on manifest files and creates appropriate registry connectors. Use --recursive for monorepos
and multi-project directories. Specify --package-manager to limit scanning to specific ecosystems.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runScan,
}

func init() {
	// Scan command flags
	scanCmd.Flags().Bool("deep", false, "Enable deep analysis")
	scanCmd.Flags().Bool("include-dev", false, "Include development dependencies")
	scanCmd.Flags().Float64("threshold", 0.8, "Similarity threshold for detection")
	scanCmd.Flags().StringSlice("exclude", []string{}, "Packages to exclude from scan")
	scanCmd.Flags().String("file", "", "Specific dependency file to scan")
	scanCmd.Flags().Bool("check-vulnerabilities", false, "Enable vulnerability checking")
	scanCmd.Flags().StringSlice("vulnerability-db", []string{"osv", "nvd"}, "Vulnerability databases to use (osv, github, nvd)")
	scanCmd.Flags().String("vuln-config", "config/vulnerability_databases.yaml", "Path to vulnerability database configuration")
	// Recursive scanning flags
	scanCmd.Flags().Bool("recursive", false, "Enable recursive scanning for monorepos and multi-project directories")
	scanCmd.Flags().Bool("workspace-aware", false, "Enable workspace-aware scanning for monorepos")
	scanCmd.Flags().Bool("consolidate-report", false, "Generate consolidated report for multi-project scans")
	scanCmd.Flags().StringSlice("package-manager", []string{}, "Specific package managers to scan (npm, pypi, maven, nuget, rubygems, go, cargo, composer). Auto-detects if not specified")
	scanCmd.Flags().String("registry", "", "Force registry/package manager (npm, pypi, go, maven, cargo, rubygems, composer)")
	// SBOM generation flags
	scanCmd.Flags().String("sbom-format", "", "Generate SBOM in specified format (spdx, cyclonedx)")
	scanCmd.Flags().String("sbom-output", "", "Output file path for SBOM (if not specified, prints to stdout)")
	// Enhanced supply chain analysis flags
	scanCmd.Flags().Bool("supply-chain", false, "Enable enhanced supply chain analysis")
	scanCmd.Flags().Bool("advanced", false, "Enable advanced analysis features")
}

func runScan(cmd *cobra.Command, args []string) error {
	path := "."
	if len(args) > 0 {
		path = args[0]
	}

	// Load configuration
	cfg, err := config.LoadConfig(configFile)
	if err != nil {
		// Create default config if loading fails
		cfg = createDefaultConfig()
		if verbose {
			log.Printf("Using default config: %v", err)
		}
	}

	// Create analyzer
	analyzerInstance, err := analyzer.New(cfg)
	if err != nil {
		return fmt.Errorf("failed to create analyzer: %v", err)
	}

	// Get scan options from flags
	deepAnalysis, _ := cmd.Flags().GetBool("deep")
	includeDevDeps, _ := cmd.Flags().GetBool("include-dev")
	threshold, _ := cmd.Flags().GetFloat64("threshold")
	excludePackages, _ := cmd.Flags().GetStringSlice("exclude")
	specificFile, _ := cmd.Flags().GetString("file")
	checkVulnerabilities, _ := cmd.Flags().GetBool("check-vulnerabilities")
	vulnerabilityDBs, _ := cmd.Flags().GetStringSlice("vulnerability-db")
	vulnConfig, _ := cmd.Flags().GetString("vuln-config")
	sbomFormat, _ := cmd.Flags().GetString("sbom-format")
	sbomOutput, _ := cmd.Flags().GetString("sbom-output")
	// Recursive scanning options
	recursive, _ := cmd.Flags().GetBool("recursive")
	workspaceAware, _ := cmd.Flags().GetBool("workspace-aware")
	consolidateReport, _ := cmd.Flags().GetBool("consolidate-report")
	packageManagers, _ := cmd.Flags().GetStringSlice("package-manager")
	registryOverride, _ := cmd.Flags().GetString("registry")
	// Enhanced supply chain analysis options
	enableSupplyChain, _ := cmd.Flags().GetBool("supply-chain")
	advancedAnalysis, _ := cmd.Flags().GetBool("advanced")

	options := &analyzer.ScanOptions{
		OutputFormat:           outputFormat,
		SpecificFile:           specificFile,
		DeepAnalysis:           deepAnalysis,
		IncludeDevDependencies: includeDevDeps,
		SimilarityThreshold:    threshold,
		ExcludePackages:        excludePackages,
		AllowEmptyProjects:     true,
		CheckVulnerabilities:   checkVulnerabilities,
		VulnerabilityDBs:       vulnerabilityDBs,
		VulnConfigPath:         vulnConfig,
		Recursive:              recursive,
		WorkspaceAware:         workspaceAware,
		ConsolidateReport:      consolidateReport,
		PackageManagers:        packageManagers,
		EnableSupplyChain:      enableSupplyChain,
		AdvancedAnalysis:       advancedAnalysis,
	}

	// Map registry override to packageManagers if provided
	if registryOverride != "" {
		options.PackageManagers = []string{strings.ToLower(registryOverride)}
	}

	// Suppress logrus output for graph formats to prevent pollution
	graphFormats := []string{"dot", "svg", "mermaid"}
	for _, format := range graphFormats {
		if outputFormat == format {
			logrus.SetLevel(logrus.FatalLevel)
			break
		}
	}

	// Perform scan
	result, err := analyzerInstance.Scan(path, options)
	if err != nil {
		return fmt.Errorf("scan failed: %v", err)
	}

	// Save scan results to database if database is configured
	if dbErr := saveScanToDatabase(result, path); dbErr != nil {
		log.Printf("Warning: Failed to save scan to database: %v", dbErr)
	}

	// Handle SBOM generation if requested
	if sbomFormat != "" {
		outputSBOMWithFile(result, sbomFormat, sbomOutput)
		return nil
	}

	// Output results
	outputScanResult(result, outputFormat)
	return nil
}
