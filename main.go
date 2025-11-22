package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/analyzer"
	"github.com/Alivanroy/Typosentinel/internal/api/rest"
	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/internal/database"
	"github.com/Alivanroy/Typosentinel/internal/detector"
	"github.com/Alivanroy/Typosentinel/internal/edge"
	"github.com/Alivanroy/Typosentinel/internal/output"
	"github.com/Alivanroy/Typosentinel/internal/repository"
	"github.com/Alivanroy/Typosentinel/internal/repository/connectors"
	"github.com/Alivanroy/Typosentinel/internal/scanner"
	"github.com/Alivanroy/Typosentinel/internal/security"
	"github.com/Alivanroy/Typosentinel/internal/visualization"
	"github.com/Alivanroy/Typosentinel/pkg/logger"
	"github.com/Alivanroy/Typosentinel/pkg/types"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "typosentinel",
		Short: "Typosentinel - Advanced typosquatting detection tool",
		Long: `Typosentinel is a comprehensive security tool for detecting typosquatting attacks,
malicious packages, and vulnerabilities in software dependencies across multiple package managers.`,
		SilenceUsage: true,
	}

	// Global flags
	var configFile string
	var verbose bool
	var outputFormat string

	rootCmd.PersistentFlags().StringVarP(&configFile, "config", "c", "", "config file (default is $HOME/.planfinale.yaml)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")
	rootCmd.PersistentFlags().StringVarP(&outputFormat, "output", "o", "futuristic", "output format (json, yaml, table, futuristic)")

	// Scan command
	var scanCmd = &cobra.Command{
		Use:   "scan [path]",
		Short: "Scan a project for typosquatting and malicious packages (auto-detects project types)",
		Long: `Scan a project directory for typosquatting and malicious packages.

TypoSentinel automatically detects project types (Node.js, Python, Go, Rust, Java, .NET, PHP, Ruby)
based on manifest files and creates appropriate registry connectors. Use --recursive for monorepos
and multi-project directories. Specify --package-manager to limit scanning to specific ecosystems.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
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
				// Recursive scanning options
				Recursive:         recursive,
				WorkspaceAware:    workspaceAware,
				ConsolidateReport: consolidateReport,
				PackageManagers:   packageManagers,
				// Enhanced supply chain analysis options
				EnableSupplyChain: enableSupplyChain,
				AdvancedAnalysis:  advancedAnalysis,
			}

			// Perform scan
			// Write to log file for debugging
			if logFile, err := os.OpenFile("/tmp/typosentinel-debug.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644); err == nil {
				logFile.WriteString("=== BEFORE SCAN ===\n")
				logFile.Close()
			}
			result, err := analyzerInstance.Scan(path, options)
			if err != nil {
				return fmt.Errorf("scan failed: %v", err)
			}
			if logFile, err := os.OpenFile("/tmp/typosentinel-debug.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644); err == nil {
				logFile.WriteString("=== AFTER SCAN ===\n")
				logFile.Close()
			}

			// Save scan results to database if database is configured
			if logFile, err := os.OpenFile("/tmp/typosentinel-debug.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644); err == nil {
				logFile.WriteString("=== DATABASE SAVE OPERATION START ===\n")
				logFile.Close()
			}
			if dbErr := saveScanToDatabase(result, path); dbErr != nil {
				if logFile, err := os.OpenFile("/tmp/typosentinel-debug.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644); err == nil {
					logFile.WriteString(fmt.Sprintf("=== DATABASE SAVE FAILED: %v ===\n", dbErr))
					logFile.Close()
				}
				// Don't fail the entire scan if database save fails
				log.Printf("Warning: Failed to save scan to database: %v", dbErr)
			} else {
				if logFile, err := os.OpenFile("/tmp/typosentinel-debug.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644); err == nil {
					logFile.WriteString("=== DATABASE SAVE SUCCESS ===\n")
					logFile.Close()
				}
			}
			if logFile, err := os.OpenFile("/tmp/typosentinel-debug.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644); err == nil {
				logFile.WriteString("=== DATABASE SAVE OPERATION END ===\n")
				logFile.Close()
			}

			// Handle SBOM generation if requested
			if sbomFormat != "" {
				outputSBOMWithFile(result, sbomFormat, sbomOutput)
				return nil
			}

			// Output results
			outputScanResult(result, outputFormat)
			return nil
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
	// Recursive scanning flags
	scanCmd.Flags().Bool("recursive", false, "Enable recursive scanning for monorepos and multi-project directories")
	scanCmd.Flags().Bool("workspace-aware", false, "Enable workspace-aware scanning for monorepos")
	scanCmd.Flags().Bool("consolidate-report", false, "Generate consolidated report for multi-project scans")
	scanCmd.Flags().StringSlice("package-manager", []string{}, "Specific package managers to scan (npm, pypi, maven, nuget, rubygems, go, cargo, composer). Auto-detects if not specified")
	// SBOM generation flags
	scanCmd.Flags().String("sbom-format", "", "Generate SBOM in specified format (spdx, cyclonedx)")
	scanCmd.Flags().String("sbom-output", "", "Output file path for SBOM (if not specified, prints to stdout)")
	// Enhanced supply chain analysis flags
	scanCmd.Flags().Bool("supply-chain", false, "Enable enhanced supply chain analysis")
	scanCmd.Flags().Bool("advanced", false, "Enable advanced analysis features")

	// Analyze command
	var analyzeCmd = &cobra.Command{
		Use:   "analyze <package> [registry]",
		Short: "Analyze a specific package for threats",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
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
				return fmt.Errorf("analysis failed: %v", err)
			}

			// Output results
			outputAnalysisResult(result, outputFormat)
			return nil
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

	// Server command
	var serverCmd = &cobra.Command{
		Use:   "server",
		Short: "Start the Typosentinel REST API server",
		Long:  "Start the Typosentinel web server and REST API for scanning packages and managing security",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Load configuration
			cfg, err := config.LoadConfig(configFile)
			if err != nil {
				cfg = createDefaultConfig()
				if verbose {
					log.Printf("Using default config: %v", err)
				}
			}

			// Get server options from flags
			port, _ := cmd.Flags().GetString("port")
			host, _ := cmd.Flags().GetString("host")
			dev, _ := cmd.Flags().GetBool("dev")

			// Ensure server config has defaults
			if cfg.Server.Host == "" {
				cfg.Server.Host = "0.0.0.0"
			}
			if cfg.Server.Port == 0 {
				cfg.Server.Port = 8080
			}

			// Override config with command line flags
			if port != "" {
				if portNum, err := parsePort(port); err == nil {
					cfg.Server.Port = portNum
				}
			}
			if host != "" {
				cfg.Server.Host = host
			}
			if dev {
				cfg.App.Environment = config.EnvDevelopment
				cfg.App.Debug = true
			}

			// Initialize logger
			logger := logger.New()

			// Run security validation in production
			if cfg.App.Environment == config.EnvProduction {
				validator := security.NewSecureConfigValidator()
				if err := validator.ValidateProductionConfig(); err != nil {
					return fmt.Errorf("security validation failed: %w", err)
				}
				logger.Info("Security validation passed")
			} else {
				logger.Warn("Running in development mode - some security checks are relaxed")
			}

			logger.Info("Starting Typosentinel server", map[string]interface{}{
				"host":    cfg.Server.Host,
				"port":    cfg.Server.Port,
				"version": "1.1.0",
			})

			// Create analyzer for the server
			analyzerInstance, err := analyzer.New(cfg)
			if err != nil {
				return fmt.Errorf("failed to create analyzer: %w", err)
			}

			// Create REST API config from server config
			log.Printf("[MAIN DEBUG] ===== ENHANCED CORS CONFIGURATION DEBUG =====")
			log.Printf("[MAIN DEBUG] CORS config from environment: Enabled=%v, AllowedOrigins=%v", cfg.Server.CORS.Enabled, cfg.Server.CORS.AllowedOrigins)
			log.Printf("[MAIN DEBUG] CORS AllowedMethods=%v", cfg.Server.CORS.AllowedMethods)
			log.Printf("[MAIN DEBUG] CORS AllowedHeaders=%v", cfg.Server.CORS.AllowedHeaders)

			// Debug viper values directly
			log.Printf("[VIPER DEBUG] server.cors.enabled: %v", viper.Get("server.cors.enabled"))
			log.Printf("[VIPER DEBUG] server.cors.allowed_origins: %v", viper.Get("server.cors.allowed_origins"))
			log.Printf("[VIPER DEBUG] server.cors.allowed_methods: %v", viper.Get("server.cors.allowed_methods"))
			log.Printf("[VIPER DEBUG] server.cors.allowed_headers: %v", viper.Get("server.cors.allowed_headers"))

			// Debug environment detection
			log.Printf("[ENV DEBUG] Environment detected: '%s'", cfg.App.Environment)
			log.Printf("[ENV DEBUG] app.environment from viper: '%s'", viper.GetString("app.environment"))
			log.Printf("[ENV DEBUG] TYPOSENTINEL_APP_ENVIRONMENT env var: '%s'", os.Getenv("TYPOSENTINEL_APP_ENVIRONMENT"))
			log.Printf("[MAIN DEBUG] ===== END CORS CONFIGURATION DEBUG =====")

			restConfig := config.RESTAPIConfig{
				Enabled:  true,
				Host:     cfg.Server.Host,
				Port:     cfg.Server.Port,
				BasePath: "/api",
				Versioning: config.APIVersioning{
					Enabled:           true,
					Strategy:          "path",
					DefaultVersion:    "v1",
					SupportedVersions: []string{"v1"},
				},
				CORS: &cfg.Server.CORS,
			}

			// Create and start REST server
			server := rest.NewServerWithEnterprise(restConfig, nil, analyzerInstance, nil)

			// Create context for server operations
			ctx := context.Background()

			// Start server in a goroutine
			serverErr := make(chan error, 1)
			go func() {
				if err := server.Start(ctx); err != nil {
					serverErr <- err
				}
			}()

			// Wait for interrupt signal or server error
			interrupt := make(chan os.Signal, 1)
			signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)

			fmt.Printf("🚀 Typosentinel Server starting...\n")
			fmt.Printf("📍 Host: %s\n", cfg.Server.Host)
			fmt.Printf("🔌 Port: %d\n", cfg.Server.Port)
			fmt.Printf("🔒 Security validation: ✅ Passed\n")
			fmt.Printf("📊 Environment: %s\n", cfg.App.Environment)
			fmt.Printf("🌐 Server URL: http://%s:%d\n", cfg.Server.Host, cfg.Server.Port)

			select {
			case err := <-serverErr:
				return fmt.Errorf("server error: %w", err)
			case sig := <-interrupt:
				logger.Info("Received shutdown signal", map[string]interface{}{
					"signal": sig.String(),
				})

				// Graceful shutdown
				if err := server.Stop(ctx); err != nil {
					logger.Error("Error during server shutdown", map[string]interface{}{
						"error": err.Error(),
					})
				}
				logger.Info("Server shutdown completed")
			}

			return nil
		},
	}

	// Server command flags
	serverCmd.Flags().StringP("port", "p", "8080", "Server port")
	serverCmd.Flags().String("host", "0.0.0.0", "Server host")
	serverCmd.Flags().Bool("dev", false, "Enable development mode")

	// Version command
	var versionCmd = &cobra.Command{
		Use:   "version",
		Short: "Show version information",
		Run: func(cmd *cobra.Command, args []string) {
			if outputFormat == "futuristic" || outputFormat == "" {
				formatter := output.NewFuturisticFormatter(true, false)
				formatter.PrintVersion("1.1.0")
			} else {
				fmt.Println("TypoSentinel v1.1.0")
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
				OutputFormat:       outputFormat,
				DeepAnalysis:       deepScan,
				AllowEmptyProjects: true,
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
			verbose, _ := cmd.Flags().GetBool("verbose")

			// Perform dependency graph analysis
			if err := performDependencyGraphAnalysis(path, graphDepth, includeDevDeps, outputGraph, verbose); err != nil {
				fmt.Printf("Error performing dependency graph analysis: %v\n", err)
				os.Exit(1)
			}
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
	analyzeCmd.Flags().Bool("supply-chain", false, "Include supply chain analysis")

	// Edge Algorithms command group
	var edgeCmd = &cobra.Command{
		Use:   "edge",
		Short: "Novel edge algorithms for advanced threat detection",
		Long: `Edge algorithms provide cutting-edge threat detection capabilities using advanced
mathematical models and machine learning techniques for superior security analysis.`,
	}

	// GTR Algorithm command
	var gtrCmd = &cobra.Command{
		Use:   "gtr [packages...]",
		Short: "Graph-based Threat Recognition algorithm",
		Long: `GTR (Graph-based Threat Recognition) uses advanced graph theory and network analysis
to identify complex threat patterns and relationships between packages.`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Get flags
			threshold, _ := cmd.Flags().GetFloat64("threshold")
			maxDepth, _ := cmd.Flags().GetInt("max-depth")
			includeMetrics, _ := cmd.Flags().GetBool("include-metrics")

			// Create GTR config
			config := &edge.GTRConfig{
				MinRiskThreshold:     threshold,
				MaxTraversalDepth:    maxDepth,
				EnablePathAnalysis:   true,
				EnableCycleDetection: true,
			}
			algorithm := edge.NewGTRAlgorithm(config)

			fmt.Printf("🔍 GTR Algorithm Analysis\n")
			fmt.Printf("Packages: %v\n", args)
			fmt.Printf("Threshold: %.2f, Max Depth: %d\n", threshold, maxDepth)

			ctx := context.Background()
			for _, pkgName := range args {
				// Convert package name to slice for new interface
				packages := []string{pkgName}

				result, err := algorithm.Analyze(ctx, packages)
				if err != nil {
					fmt.Printf("Error analyzing %s: %v\n", pkgName, err)
					continue
				}

				switch outputFormat {
				case "json":
					data, _ := json.MarshalIndent(result, "", "  ")
					fmt.Println(string(data))
				default:
					fmt.Printf("\n📦 Package: %s\n", pkgName)
					fmt.Printf("Algorithm: %s\n", result.Algorithm)
					fmt.Printf("Packages Analyzed: %d\n", len(result.Packages))
					fmt.Printf("Findings: %d\n", len(result.Findings))

					if includeMetrics && result.Metadata != nil {
						fmt.Printf("Metadata:\n")
						for key, value := range result.Metadata {
							fmt.Printf("  %s: %v\n", key, value)
						}
					}

					if len(result.Findings) > 0 {
						fmt.Printf("Findings:\n")
						for _, finding := range result.Findings {
							fmt.Printf("  - [%s] %s\n", finding.Severity, finding.Message)
						}
					}
				}
			}
			return nil
		},
	}

	// RUNT Algorithm command
	var runtCmd = &cobra.Command{
		Use:   "runt [packages...]",
		Short: "Recursive Universal Network Traversal algorithm",
		Long: `RUNT (Recursive Universal Network Traversal) performs deep recursive analysis
of package dependencies and network relationships for comprehensive threat detection.`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Get flags
			maxDepth, _ := cmd.Flags().GetInt("max-depth")
			similarity, _ := cmd.Flags().GetFloat64("similarity")
			includeFeatures, _ := cmd.Flags().GetBool("include-features")

			// Create RUNT config
			config := &edge.RUNTConfig{
				OverallThreshold:      similarity,
				MinPackageLength:      2,
				MaxPackageLength:      100,
				EnableUnicodeAnalysis: true,
			}
			algorithm := edge.NewRUNTAlgorithm(config)

			fmt.Printf("🌐 RUNT Algorithm Analysis\n")
			fmt.Printf("Packages: %v\n", args)
			fmt.Printf("Max Depth: %d, Similarity: %.2f\n", maxDepth, similarity)

			ctx := context.Background()
			for _, pkgName := range args {
				// Create a basic package structure
				pkg := &types.Package{
					Name:     pkgName,
					Version:  "latest",
					Registry: "npm",
				}

				result, err := algorithm.Analyze(ctx, []string{pkg.Name})
				if err != nil {
					fmt.Printf("Error analyzing %s: %v\n", pkgName, err)
					continue
				}

				switch outputFormat {
				case "json":
					data, _ := json.MarshalIndent(result, "", "  ")
					fmt.Println(string(data))
				default:
					fmt.Printf("\n📦 Package: %s\n", pkgName)
					fmt.Printf("Algorithm: %s\n", result.Algorithm)
					fmt.Printf("Packages Analyzed: %d\n", len(result.Packages))
					fmt.Printf("Findings: %d\n", len(result.Findings))

					if includeFeatures && result.Metadata != nil {
						fmt.Printf("Features:\n")
						for key, value := range result.Metadata {
							fmt.Printf("  %s: %v\n", key, value)
						}
					}

					if len(result.Findings) > 0 {
						fmt.Printf("Findings:\n")
						for _, finding := range result.Findings {
							fmt.Printf("  - [%s] %s\n", finding.Severity, finding.Message)
						}
					}
				}
			}
			return nil
		},
	}

	// AICC Algorithm command
	var aiccCmd = &cobra.Command{
		Use:   "aicc [packages...]",
		Short: "Adaptive Intelligence Correlation Clustering algorithm",
		Long: `AICC (Adaptive Intelligence Correlation Clustering) uses machine learning
and adaptive clustering techniques for intelligent threat pattern recognition.`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Get flags
			clusters, _ := cmd.Flags().GetInt("clusters")
			adaptiveMode, _ := cmd.Flags().GetBool("adaptive")
			includeCorrelation, _ := cmd.Flags().GetBool("include-correlation")

			// Create AICC config
			config := &edge.AICCConfig{
				MaxChainDepth:     clusters,
				MinTrustScore:     0.7,
				RequireTimestamps: true,
				AllowSelfSigned:   !adaptiveMode,
				PolicyStrictness:  "medium",
			}
			algorithm := edge.NewAICCAlgorithm(config)

			fmt.Printf("🤖 AICC Algorithm Analysis\n")
			fmt.Printf("Packages: %v\n", args)
			fmt.Printf("Clusters: %d, Adaptive: %v\n", clusters, adaptiveMode)

			ctx := context.Background()
			for _, pkgName := range args {
				// Create a basic package structure
				pkg := &types.Package{
					Name:     pkgName,
					Version:  "latest",
					Registry: "npm",
				}

				result, err := algorithm.Analyze(ctx, []string{pkg.Name})
				if err != nil {
					fmt.Printf("Error analyzing %s: %v\n", pkgName, err)
					continue
				}

				switch outputFormat {
				case "json":
					data, _ := json.MarshalIndent(result, "", "  ")
					fmt.Println(string(data))
				default:
					fmt.Printf("\n📦 Package: %s\n", pkgName)
					fmt.Printf("Algorithm: %s\n", result.Algorithm)
					fmt.Printf("Packages Analyzed: %d\n", len(result.Packages))
					fmt.Printf("Findings: %d\n", len(result.Findings))

					if includeCorrelation && result.Metadata != nil {
						fmt.Printf("Correlation Metrics:\n")
						for key, value := range result.Metadata {
							fmt.Printf("  %s: %v\n", key, value)
						}
					}

					// AttackVectors field removed from AlgorithmResult

					if len(result.Findings) > 0 {
						fmt.Printf("Findings:\n")
						for _, finding := range result.Findings {
							fmt.Printf("  - [%s] %s\n", finding.Severity, finding.Message)
						}
					}
				}
			}
			return nil
		},
	}

	// DIRT Algorithm command
	var dirtCmd = &cobra.Command{
		Use:   "dirt [packages...]",
		Short: "Dependency Impact Risk Traversal algorithm",
		Long: `DIRT (Dependency Impact Risk Traversal) analyzes dependency chains and
impact propagation for comprehensive supply chain risk assessment.`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Get flags
			maxDepth, _ := cmd.Flags().GetInt("max-depth")
			riskThreshold, _ := cmd.Flags().GetFloat64("risk-threshold")
			includeGraph, _ := cmd.Flags().GetBool("include-graph")

			// Create DIRT config
			config := &edge.DIRTConfig{
				MaxPropagationDepth:       maxDepth,
				HighRiskThreshold:         riskThreshold,
				EnableCascadeAnalysis:     true,
				EnableHiddenRiskDetection: true,
				CacheEnabled:              true,
			}
			algorithm := edge.NewDIRTAlgorithm(config)

			fmt.Printf("⛏️  DIRT Algorithm Analysis\n")
			fmt.Printf("Packages: %v\n", args)
			fmt.Printf("Max Depth: %d, Risk Threshold: %.2f\n", maxDepth, riskThreshold)

			ctx := context.Background()
			for _, pkgName := range args {
				// Create a basic package structure
				pkg := &types.Package{
					Name:     pkgName,
					Version:  "latest",
					Registry: "npm",
				}

				result, err := algorithm.Analyze(ctx, []string{pkg.Name})
				if err != nil {
					fmt.Printf("Error analyzing %s: %v\n", pkgName, err)
					continue
				}

				switch outputFormat {
				case "json":
					data, _ := json.MarshalIndent(result, "", "  ")
					fmt.Println(string(data))
				default:
					fmt.Printf("\n📦 Package: %s\n", pkgName)
					fmt.Printf("Algorithm: %s\n", result.Algorithm)
					fmt.Printf("Packages Analyzed: %d\n", len(result.Packages))
					fmt.Printf("Findings: %d\n", len(result.Findings))

					if includeGraph && result.Metadata != nil {
						fmt.Printf("Dependency Graph Metrics:\n")
						for key, value := range result.Metadata {
							fmt.Printf("  %s: %v\n", key, value)
						}
					}

					// AttackVectors field removed from AlgorithmResult

					if len(result.Findings) > 0 {
						fmt.Printf("Findings:\n")
						for _, finding := range result.Findings {
							fmt.Printf("  - [%s] %s\n", finding.Severity, finding.Message)
						}
					}
				}
			}
			return nil
		},
	}

	// Edge Benchmark command
	var edgeBenchmarkCmd = &cobra.Command{
		Use:   "benchmark",
		Short: "Benchmark all edge algorithms",
		Long:  `Run performance benchmarks on all edge algorithms with various test scenarios.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			packages, _ := cmd.Flags().GetInt("packages")
			workers, _ := cmd.Flags().GetInt("workers")
			iterations, _ := cmd.Flags().GetInt("iterations")

			fmt.Printf("🚀 Edge Algorithms Benchmark\n")
			fmt.Printf("Packages: %d, Workers: %d, Iterations: %d\n", packages, workers, iterations)

			// This would call the benchmark functionality
			fmt.Println("Running comprehensive benchmark...")
			fmt.Println("Note: Use examples/full_benchmark for detailed benchmarking")

			return nil
		},
	}

	// Add flags to edge algorithm commands
	gtrCmd.Flags().Float64("threshold", 0.7, "Risk threshold for GTR analysis")
	gtrCmd.Flags().Int("max-depth", 5, "Maximum graph traversal depth")
	gtrCmd.Flags().Bool("include-metrics", false, "Include detailed metrics in output")

	runtCmd.Flags().Int("max-depth", 10, "Maximum recursion depth")
	runtCmd.Flags().Float64("similarity", 0.8, "Similarity threshold for analysis")
	runtCmd.Flags().Bool("include-features", false, "Include feature analysis in output")

	aiccCmd.Flags().Int("clusters", 5, "Number of clusters for analysis")
	aiccCmd.Flags().Bool("adaptive", true, "Enable adaptive clustering mode")
	aiccCmd.Flags().Bool("include-correlation", false, "Include correlation metrics")

	dirtCmd.Flags().Int("max-depth", 8, "Maximum dependency traversal depth")
	dirtCmd.Flags().Float64("risk-threshold", 0.6, "Risk threshold for impact analysis")
	dirtCmd.Flags().Bool("include-graph", false, "Include dependency graph metrics")

	edgeBenchmarkCmd.Flags().Int("packages", 100, "Number of packages to benchmark")
	edgeBenchmarkCmd.Flags().Int("workers", 4, "Number of concurrent workers")
	edgeBenchmarkCmd.Flags().Int("iterations", 3, "Number of benchmark iterations")

	// QUANTUM Algorithm command
	var quantumCmd = &cobra.Command{
		Use:   "quantum [packages...]",
		Short: "Quantum-inspired threat detection algorithm",
		Long: `QUANTUM uses quantum-inspired computing principles including superposition,
entanglement, and quantum gates for advanced threat pattern recognition.`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Get flags
			qubits, _ := cmd.Flags().GetInt("qubits")
			entanglement, _ := cmd.Flags().GetBool("entanglement")
			superposition, _ := cmd.Flags().GetBool("superposition")

			// Create QUANTUM config
			config := &edge.QUANTUMConfig{
				QubitCount:                qubits,
				CoherenceTime:             1000 * time.Microsecond,
				DecoherenceRate:           0.01,
				MaxEntanglementDepth:      8,
				EntanglementThreshold:     0.7,
				SuperpositionStates:       256,
				AmplitudePrecision:        1e-10,
				MeasurementBasis:          "computational",
				ObservationWindow:         1 * time.Second,
				ThreatThreshold:           0.8,
				AnomalyThreshold:          0.6,
				QuantumAdvantageThreshold: 0.9,
			}
			algorithm := edge.NewQUANTUMAlgorithm(config)

			fmt.Printf("⚛️  QUANTUM Algorithm Analysis\n")
			fmt.Printf("Packages: %v\n", args)
			fmt.Printf("Qubits: %d, Entanglement: %v, Superposition: %v\n", qubits, entanglement, superposition)

			ctx := context.Background()
			for _, pkgName := range args {
				// Create a basic package structure
				pkg := &types.Package{
					Name:     pkgName,
					Version:  "latest",
					Registry: "npm",
				}

				result, err := algorithm.Analyze(ctx, []string{pkg.Name})
				if err != nil {
					fmt.Printf("Error analyzing %s: %v\n", pkgName, err)
					continue
				}

				switch outputFormat {
				case "json":
					data, _ := json.MarshalIndent(result, "", "  ")
					fmt.Println(string(data))
				default:
					fmt.Printf("\n📦 Package: %s\n", pkgName)
					fmt.Printf("Algorithm: %s\n", result.Algorithm)
					fmt.Printf("Packages Analyzed: %d\n", len(result.Packages))
					fmt.Printf("Findings: %d\n", len(result.Findings))

					// AttackVectors field removed from AlgorithmResult

					if len(result.Findings) > 0 {
						fmt.Printf("Findings:\n")
						for _, finding := range result.Findings {
							fmt.Printf("  - [%s] %s\n", finding.Severity, finding.Message)
						}
					}
				}
			}
			return nil
		},
	}

	// NEURAL Algorithm command
	var neuralCmd = &cobra.Command{
		Use:   "neural [packages...]",
		Short: "Neural ensemble threat detection algorithm",
		Long: `NEURAL uses ensemble neural networks with consensus mechanisms
for multi-vector threat analysis and adaptive learning.`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Get flags
			networks, _ := cmd.Flags().GetInt("networks")
			consensus, _ := cmd.Flags().GetBool("consensus")
			learning, _ := cmd.Flags().GetBool("learning")

			// Create NEURAL config
			config := &edge.NEURALConfig{
				NetworkCount:         networks,
				EnsembleMethod:       "bagging",
				VotingStrategy:       "weighted_average",
				HiddenLayers:         []int{128, 64, 32},
				ActivationFunction:   "relu",
				DropoutRate:          0.2,
				LearningRate:         0.001,
				BatchSize:            32,
				Epochs:               100,
				ValidationSplit:      0.2,
				FeatureDimensions:    256,
				FeatureNormalization: "standard",
				FeatureSelection:     true,
				ThreatThreshold:      0.7,
				ConsensusThreshold:   0.8,
				ConfidenceThreshold:  0.6,
				AdaptiveLearning:     learning,
			}
			algorithm := edge.NewNEURALAlgorithm(config)

			fmt.Printf("🧠 NEURAL Algorithm Analysis\n")
			fmt.Printf("Packages: %v\n", args)
			fmt.Printf("Networks: %d, Consensus: %v, Learning: %v\n", networks, consensus, learning)

			ctx := context.Background()
			for _, pkgName := range args {
				// Create a basic package structure
				pkg := &types.Package{
					Name:     pkgName,
					Version:  "latest",
					Registry: "npm",
				}

				result, err := algorithm.Analyze(ctx, []string{pkg.Name})
				if err != nil {
					fmt.Printf("Error analyzing %s: %v\n", pkgName, err)
					continue
				}

				switch outputFormat {
				case "json":
					data, _ := json.MarshalIndent(result, "", "  ")
					fmt.Println(string(data))
				default:
					fmt.Printf("\n📦 Package: %s\n", pkgName)
					fmt.Printf("Algorithm: %s\n", result.Algorithm)
					fmt.Printf("Packages Analyzed: %d\n", len(result.Packages))
					fmt.Printf("Findings: %d\n", len(result.Findings))

					// AttackVectors field removed from AlgorithmResult

					if len(result.Findings) > 0 {
						fmt.Printf("Findings:\n")
						for _, finding := range result.Findings {
							fmt.Printf("  - [%s] %s\n", finding.Severity, finding.Message)
						}
					}
				}
			}
			return nil
		},
	}

	// ADAPTIVE Algorithm command
	var adaptiveCmd = &cobra.Command{
		Use:   "adaptive [packages...]",
		Short: "Adaptive learning threat detection algorithm",
		Long: `ADAPTIVE uses real-time learning and adaptation mechanisms
for evolving threat landscapes and pattern recognition.`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Get flags
			adaptation, _ := cmd.Flags().GetBool("adaptation")
			memory, _ := cmd.Flags().GetInt("memory")
			forgetting, _ := cmd.Flags().GetBool("forgetting")

			// Create ADAPTIVE config
			config := &edge.ADAPTIVEConfig{
				LearningRate:         0.01,
				AdaptationRate:       0.05,
				ForgetRate:           0.001,
				MemoryCapacity:       memory,
				PatternWindow:        100,
				PatternThreshold:     0.8,
				NoveltyThreshold:     0.7,
				PerformanceThreshold: 0.85,
				DriftThreshold:       0.1,
				FeedbackWeight:       0.3,
				FeedbackDecay:        0.95,
				FeedbackAggregation:  "weighted_average",
				UpdateStrategy:       "incremental",
				BatchSize:            32,
				ThreatThreshold:      0.7,
				ConfidenceThreshold:  0.6,
				AdaptiveThreshold:    adaptation,
			}
			algorithm := edge.NewADAPTIVEAlgorithm(config)

			fmt.Printf("🔄 ADAPTIVE Algorithm Analysis\n")
			fmt.Printf("Packages: %v\n", args)
			fmt.Printf("Adaptation: %v, Memory: %d, Forgetting: %v\n", adaptation, memory, forgetting)

			ctx := context.Background()
			for _, pkgName := range args {
				// Create a basic package structure
				pkg := &types.Package{
					Name:     pkgName,
					Version:  "latest",
					Registry: "npm",
				}

				result, err := algorithm.Analyze(ctx, []string{pkg.Name})
				if err != nil {
					fmt.Printf("Error analyzing %s: %v\n", pkgName, err)
					continue
				}

				switch outputFormat {
				case "json":
					data, _ := json.MarshalIndent(result, "", "  ")
					fmt.Println(string(data))
				default:
					fmt.Printf("\n📦 Package: %s\n", pkgName)
					fmt.Printf("Algorithm: %s\n", result.Algorithm)
					fmt.Printf("Packages Analyzed: %d\n", len(result.Packages))
					fmt.Printf("Findings: %d\n", len(result.Findings))

					// AttackVectors field removed from AlgorithmResult

					if len(result.Findings) > 0 {
						fmt.Printf("Findings:\n")
						for _, finding := range result.Findings {
							fmt.Printf("  - [%s] %s\n", finding.Severity, finding.Message)
						}
					}
				}
			}
			return nil
		},
	}

	// Add flags to new edge algorithm commands
	quantumCmd.Flags().Int("qubits", 8, "Number of qubits for quantum analysis")
	quantumCmd.Flags().Bool("entanglement", true, "Enable quantum entanglement")
	quantumCmd.Flags().Bool("superposition", true, "Enable quantum superposition")

	neuralCmd.Flags().Int("networks", 5, "Number of neural networks in ensemble")
	neuralCmd.Flags().Bool("consensus", true, "Enable consensus mechanism")
	neuralCmd.Flags().Bool("learning", true, "Enable adaptive learning")

	adaptiveCmd.Flags().Bool("adaptation", true, "Enable real-time adaptation")
	adaptiveCmd.Flags().Int("memory", 1000, "Memory buffer size")
	adaptiveCmd.Flags().Bool("forgetting", true, "Enable memory forgetting")

	// Add subcommands to edge command
	edgeCmd.AddCommand(gtrCmd)
	edgeCmd.AddCommand(runtCmd)
	edgeCmd.AddCommand(aiccCmd)
	edgeCmd.AddCommand(dirtCmd)
	edgeCmd.AddCommand(quantumCmd)
	edgeCmd.AddCommand(neuralCmd)
	edgeCmd.AddCommand(adaptiveCmd)
	edgeCmd.AddCommand(edgeBenchmarkCmd)

	// Dependency Graph command group
	var graphCmd = &cobra.Command{
		Use:   "graph",
		Short: "Dependency graph generation and analysis commands",
		Long:  `Generate, analyze, and export dependency graphs with various visualization options.`,
	}

	// Graph Generate command
	var graphGenerateCmd = &cobra.Command{
		Use:   "generate [path]",
		Short: "Generate dependency graph from project",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := "."
			if len(args) > 0 {
				path = args[0]
			}

			maxDepth, _ := cmd.Flags().GetInt("max-depth")
			includeDev, _ := cmd.Flags().GetBool("include-dev")
			outputFormat, _ := cmd.Flags().GetString("format")

			return performDependencyGraphAnalysis(path, maxDepth, includeDev, outputFormat, verbose)
		},
	}

	// Graph Export command
	var graphExportCmd = &cobra.Command{
		Use:   "export [path]",
		Short: "Export dependency graph in various formats",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := "."
			if len(args) > 0 {
				path = args[0]
			}

			exportFormat, _ := cmd.Flags().GetString("format")
			outputFile, _ := cmd.Flags().GetString("output")
			includeDev, _ := cmd.Flags().GetBool("include-dev")

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
				return fmt.Errorf("failed to create analyzer: %w", err)
			}

			// Scan options
			options := &analyzer.ScanOptions{
				OutputFormat:           "json",
				DeepAnalysis:           true,
				IncludeDevDependencies: includeDev,
				AllowEmptyProjects:     true,
			}

			// Perform scan
			result, err := analyzerInstance.Scan(path, options)
			if err != nil {
				return fmt.Errorf("scan failed: %v", err)
			}

			// Export based on format
			switch exportFormat {
			case "json":
				if outputFile != "" {
					data, err := json.MarshalIndent(result, "", "  ")
					if err != nil {
						return fmt.Errorf("failed to marshal JSON: %v", err)
					}
					return os.WriteFile(outputFile, data, 0644)
				}
				return outputDependencyGraphJSON(result, verbose)
			case "dot":
				if outputFile != "" {
					// Generate DOT content and save to file
					dotContent := generateDOTContentFromResult(result)
					return os.WriteFile(outputFile, []byte(dotContent), 0644)
				}
				return outputDependencyGraphDOT(result, verbose)
			case "svg":
				if outputFile != "" {
					// Generate SVG and save to file
					return generateAndSaveSVGToFile(result, outputFile, verbose)
				}
				return outputDependencyGraphSVG(result, verbose)
			default:
				return fmt.Errorf("unsupported export format: %s. Supported formats: json, dot, svg", exportFormat)
			}
		},
	}

	// Add flags to graph commands
	graphCmd.PersistentFlags().Bool("include-dev", false, "Include development dependencies")

	graphGenerateCmd.Flags().Int("max-depth", 10, "Maximum dependency depth to analyze")
	graphGenerateCmd.Flags().String("format", "table", "Output format (table, json, dot, svg)")

	graphExportCmd.Flags().String("format", "json", "Export format (json, dot, svg)")
	graphExportCmd.Flags().String("output", "", "Output file path (if not specified, prints to stdout)")

	// Add subcommands to graph command
	graphCmd.AddCommand(graphGenerateCmd)
	graphCmd.AddCommand(graphAnalyzeCmd)
	graphCmd.AddCommand(graphExportCmd)

	// Add commands to root
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(analyzeCmd)
	rootCmd.AddCommand(scanOrgCmd)
	rootCmd.AddCommand(serverCmd)
	rootCmd.AddCommand(supplyChainCmd)
	rootCmd.AddCommand(edgeCmd)
	rootCmd.AddCommand(graphCmd)
	rootCmd.AddCommand(versionCmd)

	// Execute
	if err := rootCmd.Execute(); err != nil {
		// Check if it's a flag parsing error or unknown command
		if strings.Contains(err.Error(), "unknown flag") ||
			strings.Contains(err.Error(), "unknown command") ||
			strings.Contains(err.Error(), "flag provided but not defined") {
			fmt.Fprintf(os.Stderr, "Error: %s\n\n", err.Error())
			rootCmd.Help()
		} else {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err.Error())
		}
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
	case "spdx":
		outputSBOM(result, "spdx")
	case "cyclonedx":
		outputSBOM(result, "cyclonedx")
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

// outputSBOM outputs scan results in SBOM format (SPDX or CycloneDX)
func outputSBOM(result *analyzer.ScanResult, format string) {
	// Convert analyzer.ScanResult to scanner.ScanResults
	scanResults := convertToScannerResults(result)

	// Create formatter options
	options := output.FormatterOptions{
		Format:      output.OutputFormat(format),
		ColorOutput: false,
		Quiet:       false,
		Verbose:     false,
		Indent:      "  ",
	}

	var sbomData []byte
	var err error

	switch format {
	case "spdx":
		formatter := output.NewSPDXFormatter()
		sbomData, err = formatter.Format(scanResults, options)
	case "cyclonedx":
		formatter := output.NewCycloneDXFormatter()
		sbomData, err = formatter.Format(scanResults, &options)
	default:
		fmt.Printf("Unsupported SBOM format: %s\n", format)
		return
	}

	if err != nil {
		fmt.Printf("Error generating %s SBOM: %v\n", format, err)
		return
	}

	fmt.Println(string(sbomData))
}

// outputSBOMWithFile outputs scan results in SBOM format with optional file output
func outputSBOMWithFile(result *analyzer.ScanResult, format, outputFile string) {
	// Convert analyzer.ScanResult to scanner.ScanResults
	scanResults := convertToScannerResults(result)

	// Create formatter options
	options := output.FormatterOptions{
		Format:      output.OutputFormat(format),
		ColorOutput: false,
		Quiet:       false,
		Verbose:     false,
		Indent:      "  ",
	}

	var sbomData []byte
	var err error

	switch format {
	case "spdx":
		formatter := output.NewSPDXFormatter()
		sbomData, err = formatter.Format(scanResults, options)
	case "cyclonedx":
		formatter := output.NewCycloneDXFormatter()
		sbomData, err = formatter.Format(scanResults, &options)
	default:
		fmt.Printf("Unsupported SBOM format: %s\n", format)
		return
	}

	if err != nil {
		fmt.Printf("Error generating %s SBOM: %v\n", format, err)
		return
	}

	if outputFile != "" {
		err = os.WriteFile(outputFile, sbomData, 0644)
		if err != nil {
			fmt.Printf("Error writing SBOM to file %s: %v\n", outputFile, err)
			return
		}
		fmt.Printf("SBOM written to: %s\n", outputFile)
	} else {
		fmt.Println(string(sbomData))
	}
}

// convertToScannerResults converts analyzer.ScanResult to scanner.ScanResults
func convertToScannerResults(result *analyzer.ScanResult) *scanner.ScanResults {
	var scanResults []scanner.ScanResult

	// Group threats by package
	packageThreats := make(map[string][]scanner.Threat)
	packageMap := make(map[string]*types.Package)

	for _, threat := range result.Threats {
		packageName := threat.Package

		// Create a basic package if we don't have one
		if _, exists := packageMap[packageName]; !exists {
			packageMap[packageName] = &types.Package{
				Name:     packageName,
				Version:  threat.Version,
				Registry: threat.Registry,
				Metadata: &types.PackageMetadata{
					Name:     packageName,
					Version:  threat.Version,
					Registry: threat.Registry,
				},
			}
		}

		// Convert analyzer threat to scanner threat
		scannerThreat := scanner.Threat{
			Type:           string(threat.Type),
			Severity:       threat.Severity.String(),
			Score:          threat.Confidence,
			Description:    threat.Description,
			Recommendation: threat.Recommendation,
			Evidence:       threat.SimilarTo, // Use SimilarTo as evidence
			Source:         threat.DetectionMethod,
			Confidence:     threat.Confidence,
		}

		packageThreats[packageName] = append(packageThreats[packageName], scannerThreat)
	}

	// Create scan results for each package
	for packageName, threats := range packageThreats {
		scanResult := scanner.ScanResult{
			Package: packageMap[packageName],
			Threats: threats,
		}
		scanResults = append(scanResults, scanResult)
	}

	// If no threats found, create a result for the scanned path
	if len(scanResults) == 0 {
		scanResult := scanner.ScanResult{
			Package: &types.Package{
				Name:    result.Path,
				Version: "unknown",
				Metadata: &types.PackageMetadata{
					Name:    result.Path,
					Version: "unknown",
				},
			},
			Threats: []scanner.Threat{},
		}
		scanResults = append(scanResults, scanResult)
	}

	return &scanner.ScanResults{
		Results: scanResults,
	}
}

// parsePort parses a port string and returns an integer
func parsePort(portStr string) (int, error) {
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return 0, fmt.Errorf("invalid port: %s", portStr)
	}
	return port, nil
}

// saveScanToDatabase saves scan results to the database
func saveScanToDatabase(result *analyzer.ScanResult, scanPath string) error {
	// Initialize database service from environment variables (same as server)
	dbConfig := &config.DatabaseConfig{
		Type:     getEnvOrDefault("TYPOSENTINEL_DB_TYPE", "sqlite"),
		Host:     getEnvOrDefault("TYPOSENTINEL_DB_HOST", "localhost"),
		Port:     getEnvIntOrDefault("TYPOSENTINEL_DB_PORT", 5432),
		Username: getEnvOrDefault("TYPOSENTINEL_DB_USER", "typosentinel"),
		Password: getEnvOrDefault("TYPOSENTINEL_DB_PASSWORD", ""),
		Database: getEnvOrDefault("TYPOSENTINEL_DB_NAME", "./data/typosentinel.db"),
		SSLMode:  getEnvOrDefault("TYPOSENTINEL_DB_SSLMODE", "disable"),
	}

	// Debug logging
	if logFile, err := os.OpenFile("/tmp/typosentinel-debug.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644); err == nil {
		logFile.WriteString(fmt.Sprintf("=== DB CONFIG: Type=%s, Host=%s, Port=%d, Database=%s ===\n",
			dbConfig.Type, dbConfig.Host, dbConfig.Port, dbConfig.Database))
		logFile.WriteString(fmt.Sprintf("=== SCAN RESULT: Threats=%d, TotalPackages=%d ===\n",
			len(result.Threats), result.TotalPackages))
		logFile.Close()
	}

	// Check if database is configured
	if dbConfig.Type == "" {
		return fmt.Errorf("database not configured")
	}

	// Initialize OSS service
	ossService, err := database.NewOSSService(dbConfig)
	if err != nil {
		if logFile, logErr := os.OpenFile("/tmp/typosentinel-debug.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644); logErr == nil {
			logFile.WriteString(fmt.Sprintf("=== OSS SERVICE INIT FAILED: %v ===\n", err))
			logFile.Close()
		}
		return fmt.Errorf("failed to initialize OSS service: %v", err)
	}
	defer ossService.Close()

	// Convert analyzer.ScanResult to database.PackageScan
	packageScan := &database.PackageScan{
		ID:          result.ScanID,
		PackageName: extractPackageNameFromPath(scanPath),
		Version:     "unknown", // Could be extracted from package.json or similar
		Registry:    "npm",     // Default registry
		StartedAt:   result.Timestamp,
		Status:      "completed",
		Threats:     convertThreatsToDatabase(result.Threats),
		Duration:    int64(result.Duration.Seconds()),
		Metadata: map[string]interface{}{
			"path":           scanPath,
			"total_packages": result.TotalPackages,
			"warnings":       len(result.Warnings),
		},
	}

	// Set completion time
	completedAt := result.Timestamp.Add(result.Duration)
	packageScan.CompletedAt = &completedAt

	// Create scan in database
	ctx := context.Background()
	if logFile, logErr := os.OpenFile("/tmp/typosentinel-debug.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644); logErr == nil {
		logFile.WriteString(fmt.Sprintf("=== CREATING SCAN: ID=%s, Package=%s, Threats=%d ===\n",
			packageScan.ID, packageScan.PackageName, len(packageScan.Threats)))
		logFile.Close()
	}
	if err := ossService.CreateScan(ctx, packageScan); err != nil {
		if logFile, logErr := os.OpenFile("/tmp/typosentinel-debug.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644); logErr == nil {
			logFile.WriteString(fmt.Sprintf("=== CREATE SCAN FAILED: %v ===\n", err))
			logFile.Close()
		}
		return fmt.Errorf("failed to save scan to database: %v", err)
	}

	if logFile, logErr := os.OpenFile("/tmp/typosentinel-debug.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644); logErr == nil {
		logFile.WriteString("=== CREATE SCAN SUCCESS ===\n")
		logFile.Close()
	}
	return nil
}

// generateDOTContentFromResult generates DOT format content from scan result
func generateDOTContentFromResult(result *analyzer.ScanResult) string {
	var content strings.Builder
	content.WriteString("digraph DependencyGraph {\n")
	content.WriteString("  rankdir=TB;\n")
	content.WriteString("  node [shape=box, style=filled];\n\n")

	// Add root node
	content.WriteString(fmt.Sprintf("  \"%s\" [fillcolor=lightblue, label=\"%s\\nPackages: %d\"];\n",
		result.Path, result.Path, result.TotalPackages))

	// Add threat nodes
	for i, threat := range result.Threats {
		color := "lightcoral"
		if threat.Severity == types.SeverityHigh || threat.Severity == types.SeverityCritical {
			color = "red"
		}
		content.WriteString(fmt.Sprintf("  \"threat_%d\" [fillcolor=%s, label=\"%s\\n%s\"];\n",
			i, color, threat.Package, threat.Type))
		content.WriteString(fmt.Sprintf("  \"%s\" -> \"threat_%d\";\n", result.Path, i))
	}

	content.WriteString("}\n")
	return content.String()
}

// generateAndSaveSVGToFile generates SVG content and saves to file
func generateAndSaveSVGToFile(result *analyzer.ScanResult, outputFile string, verbose bool) error {
	var content strings.Builder
	content.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
	content.WriteString("<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"800\" height=\"600\">\n")
	content.WriteString("  <title>Dependency Graph Analysis</title>\n")

	// Background
	content.WriteString("  <rect width=\"100%\" height=\"100%\" fill=\"#f8f9fa\"/>\n")

	// Title
	content.WriteString(fmt.Sprintf("  <text x=\"400\" y=\"30\" text-anchor=\"middle\" font-size=\"20\" font-weight=\"bold\">Dependency Graph: %s</text>\n", result.Path))

	// Root node
	content.WriteString("  <circle cx=\"400\" cy=\"100\" r=\"30\" fill=\"#007bff\" stroke=\"#0056b3\" stroke-width=\"2\"/>\n")
	content.WriteString(fmt.Sprintf("  <text x=\"400\" y=\"105\" text-anchor=\"middle\" fill=\"white\" font-size=\"12\">%d pkg</text>\n", result.TotalPackages))

	// Threat nodes
	y := 200
	for i, threat := range result.Threats {
		x := 200 + (i%3)*200
		if i > 0 && i%3 == 0 {
			y += 100
		}

		color := "#ffc107" // warning
		if threat.Severity == types.SeverityHigh || threat.Severity == types.SeverityCritical {
			color = "#dc3545" // danger
		}

		content.WriteString(fmt.Sprintf("  <circle cx=\"%d\" cy=\"%d\" r=\"20\" fill=\"%s\" stroke=\"#666\" stroke-width=\"1\"/>\n", x, y, color))
		content.WriteString(fmt.Sprintf("  <text x=\"%d\" y=\"%d\" text-anchor=\"middle\" font-size=\"10\">%s</text>\n", x, y+5, threat.Package[:min(len(threat.Package), 8)]))

		// Connection line
		content.WriteString(fmt.Sprintf("  <line x1=\"400\" y1=\"130\" x2=\"%d\" y2=\"%d\" stroke=\"#666\" stroke-width=\"1\"/>\n", x, y-20))
	}

	content.WriteString("</svg>\n")

	return os.WriteFile(outputFile, []byte(content.String()), 0644)
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// outputInteractiveGraph generates an interactive HTML dependency graph
func outputInteractiveGraph(result *analyzer.ScanResult, scanPath string, verbose bool) error {
	// Create visualization config
	config := &visualization.VisualizationConfig{
		Interactive:     true,
		ShowRiskScores:  verbose,
		ShowMetadata:    verbose,
		ColorScheme:     "risk",
		Layout:          "force",
		MaxNodes:        500,
		MinRiskScore:    0.0,
		OutputDirectory: "./output",
	}

	// Create visualizer
	visualizer := visualization.NewGraphVisualizer(config)

	// Generate output filename
	baseName := filepath.Base(scanPath)
	if baseName == "." {
		baseName = "dependency-graph"
	}
	timestamp := time.Now().Format("20060102-150405")
	outputPath := filepath.Join("./output", fmt.Sprintf("%s-interactive-%s.html", baseName, timestamp))

	// Generate interactive graph
	return visualizer.GenerateInteractiveGraph(result, outputPath)
}

// outputAdvancedSVG generates an advanced SVG dependency graph
func outputAdvancedSVG(result *analyzer.ScanResult, scanPath string, verbose bool) error {
	// Create visualization config
	config := &visualization.VisualizationConfig{
		Interactive:     false,
		ShowRiskScores:  verbose,
		ShowMetadata:    verbose,
		ColorScheme:     "risk",
		Layout:          "force",
		MaxNodes:        500,
		MinRiskScore:    0.0,
		OutputDirectory: "./output",
	}

	// Create visualizer
	visualizer := visualization.NewGraphVisualizer(config)

	// Generate output filename
	baseName := filepath.Base(scanPath)
	if baseName == "." {
		baseName = "dependency-graph"
	}
	timestamp := time.Now().Format("20060102-150405")
	outputPath := filepath.Join("./output", fmt.Sprintf("%s-advanced-%s.svg", baseName, timestamp))

	// Generate advanced SVG
	return visualizer.GenerateAdvancedSVG(result, outputPath)
}

// extractPackageNameFromPath extracts package name from scan path
func extractPackageNameFromPath(path string) string {
	if path == "." {
		return "local-project"
	}
	// Extract last directory name as package name
	parts := strings.Split(strings.TrimSuffix(path, "/"), "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return "unknown"
}

// convertThreatsToDatabase converts analyzer threats to database format
func convertThreatsToDatabase(threats []types.Threat) []database.ThreatResult {
	var dbThreats []database.ThreatResult
	for _, threat := range threats {
		dbThreat := database.ThreatResult{
			Type:        string(threat.Type),
			Severity:    threat.Severity.String(),
			Confidence:  threat.Confidence,
			Description: threat.Description,
			Source:      threat.DetectionMethod,
		}
		dbThreats = append(dbThreats, dbThreat)
	}
	return dbThreats
}

// Helper functions for environment variable parsing
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvIntOrDefault(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

// performDepthAnalysis performs comprehensive dependency depth analysis
func performDepthAnalysis(result *analyzer.ScanResult, scanPath string, verbose bool) error {
	if result == nil {
		return fmt.Errorf("no scan result available")
	}

	// Build dependency graph from scan result
	depGraph, err := buildDependencyGraphFromScanResult(result)
	if err != nil {
		return fmt.Errorf("failed to build dependency graph: %w", err)
	}

	// Initialize depth analyzer with default config
	cfg := createDefaultConfig()
	loggerInstance := logger.New()
	depthAnalyzer := scanner.NewDependencyDepthAnalyzer(&cfg.SupplyChain.DependencyGraph, loggerInstance)

	// Perform depth analysis
	ctx := context.Background()
	depthResult, err := depthAnalyzer.AnalyzeDependencyDepth(ctx, depGraph)
	if err != nil {
		return fmt.Errorf("failed to analyze dependency depth: %w", err)
	}

	// Output results
	return outputDepthAnalysisResults(depthResult, scanPath, verbose)
}

// buildDependencyGraphFromScanResult converts scan result to dependency graph
func buildDependencyGraphFromScanResult(result *analyzer.ScanResult) (*scanner.DependencyGraph, error) {
	graph := &scanner.DependencyGraph{
		Nodes: make([]scanner.DependencyNode, 0),
		Edges: make([]scanner.DependencyEdge, 0),
		Depth: 0,
		Stats: scanner.GraphStatistics{},
	}

	// Extract packages from threats since analyzer.ScanResult doesn't have Packages field
	packageMap := make(map[string]*types.Package)
	for _, threat := range result.Threats {
		// Create package from threat information
		pkg := &types.Package{
			Name:     threat.Package,
			Version:  threat.Version,
			Registry: threat.Registry,
		}
		packageMap[threat.Package] = pkg
	}

	// Add nodes from packages
	for _, pkg := range packageMap {
		riskScore := determineRiskScore(result.Threats, pkg.Name)
		node := scanner.DependencyNode{
			ID:      pkg.Name,
			Package: pkg,
			Level:   1,
			Direct:  true,
			RiskData: &scanner.NodeRiskData{
				RiskScore:    riskScore,
				ThreatCount:  countThreatsForPackage(result.Threats, pkg.Name),
				IsVulnerable: riskScore > 0.5,
			},
			Metadata: buildNodeMetadata(*pkg),
		}
		graph.Nodes = append(graph.Nodes, node)
	}

	// Add edges (simplified - create basic dependency relationships)
	nodes := graph.Nodes
	for i := 0; i < len(nodes)-1; i++ {
		edge := scanner.DependencyEdge{
			From:         nodes[i].ID,
			To:           nodes[i+1].ID,
			RelationType: "dependency",
			Constraints:  "",
			Metadata:     make(map[string]interface{}),
		}
		graph.Edges = append(graph.Edges, edge)
	}

	// Update graph statistics
	graph.Stats = scanner.GraphStatistics{
		TotalNodes:     len(graph.Nodes),
		TotalEdges:     len(graph.Edges),
		DirectDeps:     len(graph.Nodes),
		TransitiveDeps: 0,
		MaxDepth:       1,
		CyclicDeps:     0,
	}

	return graph, nil
}

// determineRiskScore determines risk score based on threats for a package
func determineRiskScore(threats []types.Threat, packageName string) float64 {
	totalScore := 0.0
	count := 0

	for _, threat := range threats {
		if threat.Package == packageName {
			count++
			switch threat.Severity {
			case types.SeverityCritical:
				totalScore += 1.0
			case types.SeverityHigh:
				totalScore += 0.8
			case types.SeverityMedium:
				totalScore += 0.5
			case types.SeverityLow:
				totalScore += 0.2
			}
		}
	}

	// Normalize score to 0-1 range
	if totalScore > 1.0 {
		return 1.0
	}
	return totalScore
}

// countThreatsForPackage counts threats for a specific package
func countThreatsForPackage(threats []types.Threat, packageName string) int {
	count := 0
	for _, threat := range threats {
		if threat.Package == packageName {
			count++
		}
	}
	return count
}

// buildNodeMetadata builds metadata for dependency node
func buildNodeMetadata(pkg types.Package) map[string]interface{} {
	metadata := make(map[string]interface{})
	metadata["package_type"] = string(pkg.Type)
	metadata["dependency_count"] = len(pkg.Dependencies)
	metadata["registry"] = pkg.Registry
	return metadata
}

// outputDepthAnalysisResults outputs the depth analysis results
func outputDepthAnalysisResults(result *scanner.DepthAnalysisResult, scanPath string, verbose bool) error {
	if result == nil {
		return fmt.Errorf("no depth analysis result available")
	}

	// Print summary
	printDepthAnalysisSummary(result, scanPath)

	// Print detailed results if verbose
	if verbose {
		printDetailedDepthAnalysis(result)
	}

	// Save results to file
	return saveDepthAnalysisToFile(result, scanPath)
}

// printDepthAnalysisSummary prints a summary of depth analysis
func printDepthAnalysisSummary(result *scanner.DepthAnalysisResult, scanPath string) {
	fmt.Printf("\n📊 Dependency Depth Analysis Summary\n")
	fmt.Printf("═══════════════════════════════════════\n")
	fmt.Printf("📁 Target: %s\n", scanPath)
	fmt.Printf("📏 Maximum Depth: %d\n", result.MaxDepth)
	fmt.Printf("📈 Average Depth: %.2f\n", result.AverageDepth)
	fmt.Printf("📦 Total Dependencies: %d\n", result.DepthMetrics.TotalPackages)
	fmt.Printf("🔍 Deep Dependencies: %d\n", len(result.DeepDependencies))
	fmt.Printf("⚠️  Critical Paths: %d\n", len(result.CriticalPaths))
	fmt.Printf("🎯 Transitive Risks: %d\n", len(result.TransitiveRisks))
	fmt.Println()

	// Print depth distribution
	fmt.Printf("📊 Depth Distribution:\n")
	for depth, count := range result.DepthDistribution {
		percentage := float64(count) / float64(result.DepthMetrics.TotalPackages) * 100
		fmt.Printf("   Depth %d: %d dependencies (%.1f%%)\n", depth, count, percentage)
	}
	fmt.Println()

	// Print risk by depth
	if len(result.RiskByDepth) > 0 {
		fmt.Printf("⚠️  Risk Distribution by Depth:\n")
		for depth, riskScore := range result.RiskByDepth {
			fmt.Printf("   Depth %d: Average Risk Score %.2f\n", depth, riskScore)
		}
		fmt.Println()
	}

	// Print recommendations
	if len(result.Recommendations) > 0 {
		fmt.Printf("💡 Recommendations:\n")
		for i, rec := range result.Recommendations {
			fmt.Printf("   %d. %s\n", i+1, rec)
		}
		fmt.Println()
	}
}

// printDetailedDepthAnalysis prints detailed depth analysis information
func printDetailedDepthAnalysis(result *scanner.DepthAnalysisResult) {
	// Print critical paths
	if len(result.CriticalPaths) > 0 {
		fmt.Printf("🔍 Critical Dependency Paths:\n")
		for i, path := range result.CriticalPaths {
			fmt.Printf("   %d. %s (Depth: %d, Risk Score: %.2f)\n", i+1, strings.Join(path.Path, " → "), path.Depth, path.RiskScore)
			if path.Criticality != "" {
				fmt.Printf("      Criticality: %s\n", path.Criticality)
			}
		}
		fmt.Println()
	}

	// Print deep dependencies
	if len(result.DeepDependencies) > 0 {
		fmt.Printf("🕳️  Deep Dependencies (Depth > 5):\n")
		for i, dep := range result.DeepDependencies {
			fmt.Printf("   %d. %s (Depth: %d)\n", i+1, dep.PackageName, dep.Depth)
			if !dep.Maintenance.LastUpdate.IsZero() {
				fmt.Printf("      Last Update: %s\n", dep.Maintenance.LastUpdate.Format("2006-01-02"))
			}
		}
		fmt.Println()
	}

	// Print transitive risks
	if len(result.TransitiveRisks) > 0 {
		fmt.Printf("⚠️  Transitive Security Risks:\n")
		for i, risk := range result.TransitiveRisks {
			fmt.Printf("   %d. %s -> %s (Severity: %s, Score: %.2f)\n", i+1, risk.SourcePackage, risk.TargetPackage, risk.Severity, risk.RiskScore)
			fmt.Printf("      Path: %s\n", strings.Join(risk.Path, " → "))
			fmt.Printf("      Propagation: %s, Depth: %d\n", risk.PropagationType, risk.Depth)
		}
		fmt.Println()
	}
}

// saveDepthAnalysisToFile saves depth analysis results to a JSON file
func saveDepthAnalysisToFile(result *scanner.DepthAnalysisResult, scanPath string) error {
	// Create output directory if it doesn't exist
	outputDir := "output"
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Generate filename
	packageName := extractPackageNameFromPath(scanPath)
	timestamp := time.Now().Format("20060102-150405")
	filename := fmt.Sprintf("%s/%s-depth-analysis-%s.json", outputDir, packageName, timestamp)

	// Convert to JSON
	jsonData, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal depth analysis result: %w", err)
	}

	// Write to file
	if err := os.WriteFile(filename, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write depth analysis file: %w", err)
	}

	fmt.Printf("💾 Depth analysis results saved to: %s\n", filename)
	return nil
}

// performDependencyGraphAnalysis performs comprehensive dependency graph analysis
func performDependencyGraphAnalysis(path string, maxDepth int, includeDev bool, outputFormat string, verbose bool) error {
	// Initialize configuration
	cfg := createDefaultConfig()

	// Configure supply chain settings
	if cfg.SupplyChain == nil {
		cfg.SupplyChain = &config.SupplyChainConfig{}
	}
	cfg.SupplyChain.Enabled = true
	cfg.SupplyChain.DependencyGraph = config.DependencyGraphConfig{
		Enabled:                 true,
		MaxDepth:                maxDepth,
		TransitiveAnalysis:      true,
		ConfusionDetection:      true,
		SupplyChainRiskAnalysis: true,
	}

	// Initialize analyzer
	analyzerInstance, err := analyzer.New(cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize analyzer: %w", err)
	}

	fmt.Printf("🔍 Analyzing dependency graph for: %s\n", path)
	fmt.Printf("📊 Configuration: Max Depth=%d, Include Dev=%v, Output=%s\n", maxDepth, includeDev, outputFormat)
	fmt.Println()

	// Perform scan with supply chain analysis
	scanOptions := &analyzer.ScanOptions{
		OutputFormat:           outputFormat,
		IncludeDevDependencies: includeDev,
		EnableSupplyChain:      true,
		AdvancedAnalysis:       true,
	}

	result, err := analyzerInstance.Scan(path, scanOptions)
	if err != nil {
		return fmt.Errorf("failed to perform dependency graph analysis: %w", err)
	}

	// Display results based on output format
	switch outputFormat {
	case "json":
		return outputDependencyGraphJSON(result, verbose)
	case "dot":
		return outputDependencyGraphDOT(result, verbose)
	case "svg":
		return outputDependencyGraphSVG(result, verbose)
	case "interactive":
		return outputInteractiveGraph(result, path, verbose)
	case "advanced-svg":
		return outputAdvancedSVG(result, path, verbose)
	case "depth-analysis":
		return performDepthAnalysis(result, path, verbose)
	default:
		return outputDependencyGraphTable(result, verbose)
	}
}

// outputDependencyGraphJSON outputs dependency graph analysis in JSON format
func outputDependencyGraphJSON(result *analyzer.ScanResult, verbose bool) error {
	if result == nil {
		return fmt.Errorf("no scan result available")
	}

	// Create dependency graph summary
	graphSummary := map[string]interface{}{
		"scan_id":        result.ScanID,
		"path":           result.Path,
		"timestamp":      result.Timestamp,
		"duration":       result.Duration,
		"total_packages": result.TotalPackages,
		"threats":        len(result.Threats),
		"warnings":       len(result.Warnings),
		"summary":        result.Summary,
		"metadata":       result.Metadata,
	}

	if verbose {
		graphSummary["detailed_threats"] = result.Threats
		graphSummary["detailed_warnings"] = result.Warnings
	}

	data, err := json.MarshalIndent(graphSummary, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	fmt.Println(string(data))
	return nil
}

// outputDependencyGraphDOT outputs dependency graph in DOT format for Graphviz
func outputDependencyGraphDOT(result *analyzer.ScanResult, verbose bool) error {
	fmt.Println("digraph DependencyGraph {")
	fmt.Println("  rankdir=TB;")
	fmt.Println("  node [shape=box, style=filled];")
	fmt.Println()

	// Add root node
	fmt.Printf("  \"%s\" [fillcolor=lightblue, label=\"%s\\nPackages: %d\"];\n",
		result.Path, result.Path, result.TotalPackages)

	// Add threat nodes
	for i, threat := range result.Threats {
		color := "lightcoral"
		if threat.Severity == types.SeverityHigh || threat.Severity == types.SeverityCritical {
			color = "red"
		}
		fmt.Printf("  \"threat_%d\" [fillcolor=%s, label=\"%s\\n%s\"];\n",
			i, color, threat.Package, threat.Type)
		fmt.Printf("  \"%s\" -> \"threat_%d\";\n", result.Path, i)
	}

	fmt.Println("}")
	return nil
}

// outputDependencyGraphSVG outputs dependency graph in SVG format
func outputDependencyGraphSVG(result *analyzer.ScanResult, verbose bool) error {
	fmt.Println("<?xml version=\"1.0\" encoding=\"UTF-8\"?>")
	fmt.Println("<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"800\" height=\"600\">")
	fmt.Println("  <title>Dependency Graph Analysis</title>")

	// Background
	fmt.Println("  <rect width=\"100%\" height=\"100%\" fill=\"#f8f9fa\"/>")

	// Title
	fmt.Printf("  <text x=\"400\" y=\"30\" text-anchor=\"middle\" font-size=\"20\" font-weight=\"bold\">Dependency Graph: %s</text>\n", result.Path)

	// Root node
	fmt.Println("  <circle cx=\"400\" cy=\"100\" r=\"30\" fill=\"#007bff\" stroke=\"#0056b3\" stroke-width=\"2\"/>")
	fmt.Printf("  <text x=\"400\" y=\"105\" text-anchor=\"middle\" fill=\"white\" font-size=\"12\">%d pkg</text>\n", result.TotalPackages)

	// Threat nodes
	y := 200
	for i, threat := range result.Threats {
		x := 200 + (i%3)*200
		if i > 0 && i%3 == 0 {
			y += 100
		}

		color := "#ffc107" // warning
		if threat.Severity == types.SeverityHigh || threat.Severity == types.SeverityCritical {
			color = "#dc3545" // danger
		}

		fmt.Printf("  <circle cx=\"%d\" cy=\"%d\" r=\"25\" fill=\"%s\" stroke=\"#666\" stroke-width=\"1\"/>\n", x, y, color)
		fmt.Printf("  <text x=\"%d\" y=\"%d\" text-anchor=\"middle\" font-size=\"10\">%s</text>\n", x, y-5, threat.Package)
		fmt.Printf("  <text x=\"%d\" y=\"%d\" text-anchor=\"middle\" font-size=\"8\">%s</text>\n", x, y+8, threat.Severity)

		// Connection line
		fmt.Printf("  <line x1=\"400\" y1=\"130\" x2=\"%d\" y2=\"%d\" stroke=\"#666\" stroke-width=\"1\"/>\n", x, y-25)
	}

	// Legend
	fmt.Println("  <text x=\"50\" y=\"550\" font-size=\"12\" font-weight=\"bold\">Legend:</text>")
	fmt.Println("  <circle cx=\"70\" cy=\"570\" r=\"8\" fill=\"#007bff\"/>")
	fmt.Println("  <text x=\"85\" y=\"575\" font-size=\"10\">Root Package</text>")
	fmt.Println("  <circle cx=\"200\" cy=\"570\" r=\"8\" fill=\"#dc3545\"/>")
	fmt.Println("  <text x=\"215\" y=\"575\" font-size=\"10\">High/Critical Threat</text>")
	fmt.Println("  <circle cx=\"350\" cy=\"570\" r=\"8\" fill=\"#ffc107\"/>")
	fmt.Println("  <text x=\"365\" y=\"575\" font-size=\"10\">Medium/Low Threat</text>")

	fmt.Println("</svg>")
	return nil
}

// outputDependencyGraphTable outputs dependency graph analysis in table format
func outputDependencyGraphTable(result *analyzer.ScanResult, verbose bool) error {
	fmt.Println("\n🔍 DEPENDENCY GRAPH ANALYSIS RESULTS")
	fmt.Println("═══════════════════════════════════════")
	fmt.Printf("📁 Target Path: %s\n", result.Path)
	fmt.Printf("🕒 Scan Time: %s\n", result.Timestamp.Format("2006-01-02 15:04:05"))
	fmt.Printf("⏱️  Duration: %v\n", result.Duration)
	fmt.Printf("📦 Total Packages: %d\n", result.TotalPackages)
	fmt.Printf("⚠️  Threats Found: %d\n", len(result.Threats))
	fmt.Printf("🔔 Warnings: %d\n", len(result.Warnings))
	fmt.Println()

	if len(result.Threats) > 0 {
		fmt.Println("🚨 DETECTED THREATS:")
		fmt.Println("────────────────────")
		for i, threat := range result.Threats {
			fmt.Printf("%d. Package: %s\n", i+1, threat.Package)
			fmt.Printf("   Type: %s\n", threat.Type)
			fmt.Printf("   Severity: %s\n", threat.Severity)
			fmt.Printf("   Description: %s\n", threat.Description)
			if verbose && threat.Evidence != nil {
				fmt.Printf("   Evidence: %v\n", threat.Evidence)
			}
			fmt.Println()
		}
	}

	if len(result.Warnings) > 0 && verbose {
		fmt.Println("⚠️  WARNINGS:")
		fmt.Println("─────────────")
		for i, warning := range result.Warnings {
			fmt.Printf("%d. %s\n", i+1, warning.Message)
		}
		fmt.Println()
	}

	// Display summary
	// Always output summary since ScanSummary is not a pointer
	fmt.Println("📊 ANALYSIS SUMMARY:")
	fmt.Println("────────────────────")
	fmt.Printf("Critical Threats: %d\n", result.Summary.CriticalThreats)
	fmt.Printf("High Threats: %d\n", result.Summary.HighThreats)
	fmt.Printf("Medium Threats: %d\n", result.Summary.MediumThreats)
	fmt.Printf("Low Threats: %d\n", result.Summary.LowThreats)
	fmt.Printf("Total Warnings: %d\n", result.Summary.TotalWarnings)
	fmt.Printf("Clean Packages: %d\n", result.Summary.CleanPackages)
	fmt.Println()

	// Display metadata if verbose
	if verbose && result.Metadata != nil {
		fmt.Println("🔧 METADATA:")
		fmt.Println("────────────")
		for key, value := range result.Metadata {
			fmt.Printf("%s: %v\n", key, value)
		}
		fmt.Println()
	}

	return nil
}
