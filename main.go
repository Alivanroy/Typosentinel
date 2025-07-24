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

	// Add commands to root
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(analyzeCmd)
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