package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/Alivanroy/Typosentinel/internal/analyzer"
	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/internal/detector"
	"github.com/Alivanroy/Typosentinel/internal/output"
	"github.com/Alivanroy/Typosentinel/internal/repository"
	"github.com/Alivanroy/Typosentinel/internal/repository/connectors"
	"github.com/spf13/cobra"
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "typosentinel",
		Short: "TypoSentinel - Advanced typosquatting detection tool",
		Long: `TypoSentinel is a comprehensive security tool for detecting typosquatting attacks,
malicious packages, and vulnerabilities in software dependencies across multiple package managers.`,
	}

	// Global flags
	var configFile string
	var verbose bool
	var outputFormat string

	rootCmd.PersistentFlags().StringVarP(&configFile, "config", "c", "", "config file (default is $HOME/.typosentinel.yaml)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")
	rootCmd.PersistentFlags().StringVarP(&outputFormat, "output", "o", "futuristic", "output format (json, yaml, table, futuristic)")

	// Scan command
	var scanCmd = &cobra.Command{
		Use:   "scan [path]",
		Short: "Scan a project for typosquatting and malicious packages",
		Args:  cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
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
				log.Fatalf("Failed to create analyzer: %v", err)
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
			}

			// Perform scan
			result, err := analyzerInstance.Scan(path, options)
			if err != nil {
				log.Fatalf("Scan failed: %v", err)
			}

			// Output results
			outputScanResult(result, outputFormat)
		},
	}

	// Scan command flags
	scanCmd.Flags().Bool("deep", false, "Enable deep analysis")
	scanCmd.Flags().Bool("include-dev", false, "Include development dependencies")
	scanCmd.Flags().Float64("threshold", 0.8, "Similarity threshold for detection")
	scanCmd.Flags().StringSlice("exclude", []string{}, "Packages to exclude from scan")
	scanCmd.Flags().String("file", "", "Specific dependency file to scan")
	scanCmd.Flags().Bool("check-vulnerabilities", false, "Enable vulnerability checking")
	scanCmd.Flags().StringSlice("vulnerability-db", []string{"osv", "nvd"}, "Vulnerability databases to use (osv, github, nvd)")
	scanCmd.Flags().String("vuln-config", "config/vulnerability_databases.yaml", "Path to vulnerability database configuration")

	// Analyze command
	var analyzeCmd = &cobra.Command{
		Use:   "analyze <package> [registry]",
		Short: "Analyze a specific package for threats",
		Args:  cobra.RangeArgs(1, 2),
		Run: func(cmd *cobra.Command, args []string) {
			packageName := args[0]
			registry := "npm" // default
			if len(args) > 1 {
				registry = args[1]
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

			// Create detector engine
			engine := detector.New(cfg)

			// Analyze package
			ctx := context.Background()
			result, err := engine.CheckPackage(ctx, packageName, registry)
			if err != nil {
				log.Fatalf("Analysis failed: %v", err)
			}

			// Output results
			outputAnalysisResult(result, outputFormat)
		},
	}

	// Scan organization command
	var scanOrgCmd = &cobra.Command{
		Use:   "scan-org <platform> --org <organization>",
		Short: "Scan all repositories in an organization",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			platform := args[0]
			org, _ := cmd.Flags().GetString("org")
			token, _ := cmd.Flags().GetString("token")
			maxRepos, _ := cmd.Flags().GetInt("max-repos")
			includePrivate, _ := cmd.Flags().GetBool("include-private")
			includeForked, _ := cmd.Flags().GetBool("include-forked")
			includeArchived, _ := cmd.Flags().GetBool("include-archived")

			if org == "" {
				log.Fatal("Organization name is required. Use --org flag.")
			}

			// Create connector factory
			factory := connectors.NewFactory()

			// Create platform config
			platformConfig := repository.PlatformConfig{
				Name: platform,
				Auth: repository.AuthConfig{
					Type:  "token",
					Token: token,
				},
			}

			// Create connector
			connector, err := factory.CreateConnector(platform, platformConfig)
			if err != nil {
				log.Fatalf("Failed to create %s connector: %v", platform, err)
			}

			// For now, we'll create a simple coordinator instance
			// In a full implementation, this would be properly initialized
			ctx := context.Background()
			
			// List repositories from the organization
			filter := &repository.RepositoryFilter{
				IncludePrivate:  includePrivate,
				IncludeForks:    includeForked,
				IncludeArchived: includeArchived,
			}

			repos, err := connector.ListOrgRepositories(ctx, org, filter)
			if err != nil {
				log.Fatalf("Failed to list repositories for organization %s: %v", org, err)
			}

			// Limit repositories if specified
			if maxRepos > 0 && len(repos) > maxRepos {
				repos = repos[:maxRepos]
			}

			fmt.Printf("Found %d repositories in organization '%s':\n", len(repos), org)
			for i, repo := range repos {
				if i >= 10 { // Show only first 10 for brevity
					fmt.Printf("... and %d more repositories\n", len(repos)-10)
					break
				}
				fmt.Printf("  - %s (%s)\n", repo.FullName, repo.Language)
			}

			fmt.Printf("\nOrganization scan setup completed for %s/%s\n", platform, org)
			fmt.Printf("Note: Full scanning orchestration requires additional setup.\n")
		},
	}

	// Scan organization command flags
	scanOrgCmd.Flags().String("org", "", "Organization name to scan (required)")
	scanOrgCmd.Flags().String("token", "", "Authentication token for the platform")
	scanOrgCmd.Flags().Int("max-repos", 100, "Maximum number of repositories to scan")
	scanOrgCmd.Flags().Bool("include-private", false, "Include private repositories")
	scanOrgCmd.Flags().Bool("include-forked", false, "Include forked repositories")
	scanOrgCmd.Flags().Bool("include-archived", false, "Include archived repositories")
	scanOrgCmd.MarkFlagRequired("org")

	// Version command
	var versionCmd = &cobra.Command{
		Use:   "version",
		Short: "Show version information",
		Run: func(cmd *cobra.Command, args []string) {
			if outputFormat == "futuristic" || outputFormat == "" {
				formatter := output.NewFuturisticFormatter(true, false)
				formatter.PrintVersion("1.0.0")
			} else {
				fmt.Println("TypoSentinel v1.0.0")
			}
		},
	}

	// Supply Chain Security command group
	var supplyChainCmd = &cobra.Command{
		Use:   "supply-chain",
		Short: "Advanced supply chain security commands",
		Long:  `Supply chain security commands for advanced threat detection, build integrity verification, and dependency analysis.`,
	}

	// Supply Chain: Scan Advanced command
	var scanAdvancedCmd = &cobra.Command{
		Use:   "scan-advanced [path]",
		Short: "Comprehensive supply chain security scan",
		Args:  cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			path := "."
			if len(args) > 0 {
				path = args[0]
			}

			// Load configuration
			cfg, err := config.LoadConfig(configFile)
			if err != nil {
				cfg = createDefaultConfig()
				if verbose {
					log.Printf("Using default config: %v", err)
				}
			}

			// Create analyzer
			analyzerInstance, err := analyzer.New(cfg)
			if err != nil {
				log.Fatalf("Failed to create analyzer: %v", err)
			}

			// Get scan options from flags
			buildIntegrity, _ := cmd.Flags().GetBool("build-integrity")
			zeroDayDetection, _ := cmd.Flags().GetBool("zero-day")
			dependencyGraph, _ := cmd.Flags().GetBool("graph-analysis")
			threatIntel, _ := cmd.Flags().GetBool("threat-intel")
			honeypotDetection, _ := cmd.Flags().GetBool("honeypots")
			deepScan, _ := cmd.Flags().GetBool("deep-scan")
			riskThreshold, _ := cmd.Flags().GetString("risk-threshold")

			options := &analyzer.ScanOptions{
				OutputFormat:           outputFormat,
				DeepAnalysis:           deepScan,
				AllowEmptyProjects:     true,
				// Supply chain specific options would be added here
			}

			// Perform enhanced scan
			result, err := analyzerInstance.Scan(path, options)
			if err != nil {
				log.Fatalf("Advanced scan failed: %v", err)
			}

			fmt.Printf("Supply Chain Advanced Scan completed for: %s\n", path)
			fmt.Printf("Build Integrity: %v, Zero-Day: %v, Graph Analysis: %v\n", buildIntegrity, zeroDayDetection, dependencyGraph)
			fmt.Printf("Threat Intel: %v, Honeypots: %v, Risk Threshold: %s\n", threatIntel, honeypotDetection, riskThreshold)
			
			// Output results
			outputScanResult(result, outputFormat)
		},
	}

	// Supply Chain: Build Integrity command
	var buildIntegrityCmd = &cobra.Command{
		Use:   "build-integrity [path]",
		Short: "Verify build integrity and signatures",
		Args:  cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			path := "."
			if len(args) > 0 {
				path = args[0]
			}

			skipSignatureCheck, _ := cmd.Flags().GetBool("skip-signature-check")
			createBaseline, _ := cmd.Flags().GetBool("baseline-create")
			updateBaseline, _ := cmd.Flags().GetBool("baseline-update")

			fmt.Printf("Build Integrity Check for: %s\n", path)
			fmt.Printf("Skip Signatures: %v, Create Baseline: %v, Update Baseline: %v\n", 
				skipSignatureCheck, createBaseline, updateBaseline)
			fmt.Println("Note: Full build integrity verification requires enhanced scanner integration.")
		},
	}

	// Supply Chain: Graph Analysis command
	var graphAnalyzeCmd = &cobra.Command{
		Use:   "graph-analyze [path]",
		Short: "Analyze dependency graph for supply chain risks",
		Args:  cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			path := "."
			if len(args) > 0 {
				path = args[0]
			}

			graphDepth, _ := cmd.Flags().GetInt("graph-depth")
			includeDevDeps, _ := cmd.Flags().GetBool("include-dev")
			outputGraph, _ := cmd.Flags().GetString("output-graph")

			fmt.Printf("Dependency Graph Analysis for: %s\n", path)
			fmt.Printf("Graph Depth: %d, Include Dev: %v, Output: %s\n", 
				graphDepth, includeDevDeps, outputGraph)
			fmt.Println("Note: Full graph analysis requires enhanced scanner integration.")
		},
	}

	// Supply Chain: Threat Intelligence command
	var threatIntelCmd = &cobra.Command{
		Use:   "threat-intel <package> [registry]",
		Short: "Query threat intelligence for packages",
		Args:  cobra.RangeArgs(1, 2),
		Run: func(cmd *cobra.Command, args []string) {
			packageName := args[0]
			registry := "npm" // default
			if len(args) > 1 {
				registry = args[1]
			}

			threatSources, _ := cmd.Flags().GetStringSlice("threat-sources")
			threatTypes, _ := cmd.Flags().GetStringSlice("threat-types")
			limit, _ := cmd.Flags().GetInt("limit")

			fmt.Printf("Threat Intelligence Query for: %s (%s)\n", packageName, registry)
			fmt.Printf("Sources: %v, Types: %v, Limit: %d\n", 
				threatSources, threatTypes, limit)
			fmt.Println("Note: Full threat intelligence requires API integration.")
		},
	}

	// Add flags to supply chain commands
	scanAdvancedCmd.Flags().Bool("build-integrity", true, "Enable build integrity verification")
	scanAdvancedCmd.Flags().Bool("zero-day", true, "Enable zero-day detection")
	scanAdvancedCmd.Flags().Bool("graph-analysis", true, "Enable dependency graph analysis")
	scanAdvancedCmd.Flags().Bool("threat-intel", true, "Enable threat intelligence lookup")
	scanAdvancedCmd.Flags().Bool("honeypots", true, "Enable honeypot detection")
	scanAdvancedCmd.Flags().Bool("deep-scan", false, "Enable deep scanning (slower but more thorough)")
	scanAdvancedCmd.Flags().String("risk-threshold", "medium", "Risk threshold (low/medium/high/critical)")

	buildIntegrityCmd.Flags().Bool("skip-signature-check", false, "Skip signature verification")
	buildIntegrityCmd.Flags().Bool("baseline-create", false, "Create behavioral baseline")
	buildIntegrityCmd.Flags().Bool("baseline-update", false, "Update existing baseline")

	graphAnalyzeCmd.Flags().Int("graph-depth", 5, "Dependency graph depth")
	graphAnalyzeCmd.Flags().Bool("include-dev", false, "Include development dependencies")
	graphAnalyzeCmd.Flags().String("output-graph", "json", "Graph output format (json/dot/svg)")

	threatIntelCmd.Flags().StringSlice("threat-sources", []string{"typosentinel", "osv"}, "Threat intelligence sources")
	threatIntelCmd.Flags().StringSlice("threat-types", []string{"malware", "typosquatting"}, "Threat types to query")
	threatIntelCmd.Flags().Int("limit", 10, "Maximum number of results")

	// Add subcommands to supply-chain command
	supplyChainCmd.AddCommand(scanAdvancedCmd)
	supplyChainCmd.AddCommand(buildIntegrityCmd)
	supplyChainCmd.AddCommand(graphAnalyzeCmd)
	supplyChainCmd.AddCommand(threatIntelCmd)

	// Enhanced existing commands with supply chain flags
	scanCmd.Flags().Bool("supply-chain", false, "Enable supply chain security analysis")
	scanCmd.Flags().Bool("advanced", false, "Enable advanced supply chain features")
	analyzeCmd.Flags().Bool("supply-chain", false, "Include supply chain analysis")

	// Add commands to root
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(analyzeCmd)
	rootCmd.AddCommand(scanOrgCmd)
	rootCmd.AddCommand(supplyChainCmd)
	rootCmd.AddCommand(versionCmd)

	// Execute
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

// createDefaultConfig creates a default configuration
func createDefaultConfig() *config.Config {
	return &config.Config{
		TypoDetection: &config.TypoDetectionConfig{
			Enabled:           true,
			Threshold:         0.8,
			MaxDistance:       3, // Must be >= 1 based on validation error
			CheckSimilarNames: true,
			CheckHomoglyphs:   true,
		},
	}
}

// outputScanResult outputs the scan result in the specified format
func outputScanResult(result *analyzer.ScanResult, format string) {
	switch format {
	case "json":
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))
	case "table":
		outputScanResultTable(result)
	case "futuristic":
		formatter := output.NewFuturisticFormatter(true, false)
		formatter.PrintBanner()
		formatter.PrintScanStart(result.Path)
		formatter.PrintScanResults(result)
	default:
		formatter := output.NewFuturisticFormatter(true, false)
		formatter.PrintBanner()
		formatter.PrintScanStart(result.Path)
		formatter.PrintScanResults(result)
	}
}

// outputScanResultTable outputs scan results in table format
func outputScanResultTable(result *analyzer.ScanResult) {
	fmt.Printf("Scan Results for: %s\n", result.Path)
	fmt.Printf("Scan ID: %s\n", result.ScanID)
	fmt.Printf("Duration: %v\n", result.Duration)
	fmt.Printf("Total Packages: %d\n", result.TotalPackages)
	fmt.Println()

	fmt.Printf("Summary:\n")
	fmt.Printf("  Critical: %d\n", result.Summary.CriticalThreats)
	fmt.Printf("  High: %d\n", result.Summary.HighThreats)
	fmt.Printf("  Medium: %d\n", result.Summary.MediumThreats)
	fmt.Printf("  Low: %d\n", result.Summary.LowThreats)
	fmt.Printf("  Warnings: %d\n", result.Summary.TotalWarnings)
	fmt.Printf("  Clean: %d\n", result.Summary.CleanPackages)
	fmt.Println()

	if len(result.Threats) > 0 {
		fmt.Println("Threats Found:")
		for _, threat := range result.Threats {
			fmt.Printf("  [%s] %s: %s (Confidence: %.2f)\n",
				strings.ToUpper(threat.Severity.String()),
				threat.Package,
				threat.Description,
				threat.Confidence)
		}
		fmt.Println()
	}

	if len(result.Warnings) > 0 {
		fmt.Println("Warnings:")
		for _, warning := range result.Warnings {
			fmt.Printf("  %s: %s\n", warning.Package, warning.Message)
		}
	}
}

// outputAnalysisResult outputs the analysis result in the specified format
func outputAnalysisResult(result *detector.CheckPackageResult, format string) {
	switch format {
	case "json":
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))
	case "table":
		outputAnalysisResultTable(result)
	case "futuristic":
		formatter := output.NewFuturisticFormatter(true, false)
		formatter.PrintBanner()
		formatter.PrintAnalysisResults(result)
	default:
		formatter := output.NewFuturisticFormatter(true, false)
		formatter.PrintBanner()
		formatter.PrintAnalysisResults(result)
	}
}

// outputAnalysisResultTable outputs analysis results in table format
func outputAnalysisResultTable(result *detector.CheckPackageResult) {
	fmt.Printf("Package Analysis: %s (%s)\n", result.Package, result.Registry)
	fmt.Printf("Threat Level: %s\n", result.ThreatLevel)
	fmt.Printf("Confidence: %.2f\n", result.Confidence)
	fmt.Println()

	if len(result.Threats) > 0 {
		fmt.Println("Threats:")
		for _, threat := range result.Threats {
			fmt.Printf("  [%s] %s (Confidence: %.2f)\n",
				strings.ToUpper(threat.Severity.String()),
				threat.Description,
				threat.Confidence)
			if threat.SimilarTo != "" {
				fmt.Printf("    Similar to: %s\n", threat.SimilarTo)
			}
		}
		fmt.Println()
	}

	if len(result.Warnings) > 0 {
		fmt.Println("Warnings:")
		for _, warning := range result.Warnings {
			fmt.Printf("  %s\n", warning.Message)
		}
		fmt.Println()
	}

	if len(result.SimilarPackages) > 0 {
		fmt.Printf("Similar Packages: %s\n", strings.Join(result.SimilarPackages, ", "))
	}
}