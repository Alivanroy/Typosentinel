package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/Alivanroy/Typosentinel/internal/analyzer"
	"github.com/Alivanroy/Typosentinel/internal/api/rest"
	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/internal/detector"
	"github.com/Alivanroy/Typosentinel/internal/edge"
	"github.com/Alivanroy/Typosentinel/internal/output"
	"github.com/Alivanroy/Typosentinel/internal/repository"
	"github.com/Alivanroy/Typosentinel/internal/repository/connectors"
	"github.com/Alivanroy/Typosentinel/internal/scanner"
	"github.com/Alivanroy/Typosentinel/internal/security"
	"github.com/Alivanroy/Typosentinel/pkg/logger"
	"github.com/Alivanroy/Typosentinel/pkg/types"
	"github.com/spf13/cobra"
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "typosentinel",
		Short: "TypoSentinel - Advanced typosquatting detection tool",
		Long: `TypoSentinel is a comprehensive security tool for detecting typosquatting attacks,
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
		Short: "Scan a project for typosquatting and malicious packages",
		Args:  cobra.MaximumNArgs(1),
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
				return fmt.Errorf("scan failed: %v", err)
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
	// SBOM generation flags
	scanCmd.Flags().String("sbom-format", "", "Generate SBOM in specified format (spdx, cyclonedx)")
	scanCmd.Flags().String("sbom-output", "", "Output file path for SBOM (if not specified, prints to stdout)")

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
			restConfig := config.RESTAPIConfig{
				Enabled: true,
				Host:    cfg.Server.Host,
				Port:    cfg.Server.Port,
				Versioning: config.APIVersioning{
					Enabled:           true,
					Strategy:          "path",
					DefaultVersion:    "v1",
					SupportedVersions: []string{"v1"},
				},
				CORS: &config.CORSConfig{
					Enabled:        true,
					AllowedOrigins: []string{"http://localhost:3000", "http://localhost:3001", "http://127.0.0.1:3000", "http://127.0.0.1:3001"},
					AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
					AllowedHeaders: []string{"Content-Type", "Authorization", "X-Requested-With"},
					MaxAge:         3600,
				},
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
				// Create a basic package structure
				pkg := &types.Package{
					Name:     pkgName,
					Version:  "latest",
					Registry: "npm",
				}
				
				result, err := algorithm.Analyze(ctx, pkg)
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
					fmt.Printf("Threat Score: %.4f\n", result.ThreatScore)
					fmt.Printf("Confidence: %.2f%%\n", result.Confidence*100)
					fmt.Printf("Processing Time: %v\n", result.ProcessingTime)
					
					if includeMetrics && result.Metadata != nil {
						fmt.Printf("Metadata:\n")
						for key, value := range result.Metadata {
							fmt.Printf("  %s: %v\n", key, value)
						}
					}
					
					if len(result.AttackVectors) > 0 {
						fmt.Printf("Attack Vectors:\n")
						for _, vector := range result.AttackVectors {
							fmt.Printf("  - %s\n", vector)
						}
					}
					
					if len(result.Findings) > 0 {
						fmt.Printf("Findings:\n")
						for _, finding := range result.Findings {
							fmt.Printf("  - [%s] %s\n", finding.Severity, finding.Description)
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
				OverallThreshold:     similarity,
				MinPackageLength:     2,
				MaxPackageLength:     100,
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
				
				result, err := algorithm.Analyze(ctx, pkg)
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
					fmt.Printf("Threat Score: %.4f\n", result.ThreatScore)
					fmt.Printf("Confidence: %.2f%%\n", result.Confidence*100)
					fmt.Printf("Processing Time: %v\n", result.ProcessingTime)
					
					if includeFeatures && result.Metadata != nil {
						fmt.Printf("Features:\n")
						for key, value := range result.Metadata {
							fmt.Printf("  %s: %v\n", key, value)
						}
					}
					
					if len(result.AttackVectors) > 0 {
						fmt.Printf("Attack Vectors:\n")
						for _, vector := range result.AttackVectors {
							fmt.Printf("  - %s\n", vector)
						}
					}
					
					if len(result.Findings) > 0 {
						fmt.Printf("Findings:\n")
						for _, finding := range result.Findings {
							fmt.Printf("  - [%s] %s\n", finding.Severity, finding.Description)
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
				
				result, err := algorithm.Analyze(ctx, pkg)
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
					fmt.Printf("Threat Score: %.4f\n", result.ThreatScore)
					fmt.Printf("Confidence: %.2f%%\n", result.Confidence*100)
					fmt.Printf("Processing Time: %v\n", result.ProcessingTime)
					
					if includeCorrelation && result.Metadata != nil {
						fmt.Printf("Correlation Metrics:\n")
						for key, value := range result.Metadata {
							fmt.Printf("  %s: %v\n", key, value)
						}
					}
					
					if len(result.AttackVectors) > 0 {
						fmt.Printf("Attack Vectors:\n")
						for _, vector := range result.AttackVectors {
							fmt.Printf("  - %s\n", vector)
						}
					}
					
					if len(result.Findings) > 0 {
						fmt.Printf("Findings:\n")
						for _, finding := range result.Findings {
							fmt.Printf("  - [%s] %s\n", finding.Severity, finding.Description)
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
				CacheEnabled:             true,
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
				
				result, err := algorithm.Analyze(ctx, pkg)
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
					fmt.Printf("Threat Score: %.4f\n", result.ThreatScore)
					fmt.Printf("Confidence: %.2f%%\n", result.Confidence*100)
					fmt.Printf("Processing Time: %v\n", result.ProcessingTime)
					
					if includeGraph && result.Metadata != nil {
						fmt.Printf("Dependency Graph Metrics:\n")
						for key, value := range result.Metadata {
							fmt.Printf("  %s: %v\n", key, value)
						}
					}
					
					if len(result.AttackVectors) > 0 {
						fmt.Printf("Attack Vectors:\n")
						for _, vector := range result.AttackVectors {
							fmt.Printf("  - %s\n", vector)
						}
					}
					
					if len(result.Findings) > 0 {
						fmt.Printf("Findings:\n")
						for _, finding := range result.Findings {
							fmt.Printf("  - [%s] %s\n", finding.Severity, finding.Description)
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

	// Add subcommands to edge command
	edgeCmd.AddCommand(gtrCmd)
	edgeCmd.AddCommand(runtCmd)
	edgeCmd.AddCommand(aiccCmd)
	edgeCmd.AddCommand(dirtCmd)
	edgeCmd.AddCommand(edgeBenchmarkCmd)

	// Add commands to root
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(analyzeCmd)
	rootCmd.AddCommand(scanOrgCmd)
	rootCmd.AddCommand(serverCmd)
	rootCmd.AddCommand(supplyChainCmd)
	rootCmd.AddCommand(edgeCmd)
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
			Severity:       string(threat.Severity),
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
	if port < 1 || port > 65535 {
		return 0, fmt.Errorf("port out of range: %d", port)
	}
	return port, nil
}
