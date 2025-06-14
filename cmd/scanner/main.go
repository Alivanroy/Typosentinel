package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/typosentinel/typosentinel/internal/config"
	"github.com/typosentinel/typosentinel/internal/ml"
	"github.com/typosentinel/typosentinel/internal/scanner"
	"github.com/typosentinel/typosentinel/pkg/types"
)

var (
	version    = "dev"
	buildTime  = "unknown"
	commitHash = "unknown"
	configFile string
	outputFile string
	format     string
	verbose    bool
	quiet      bool
	maxDepth   int
	includeDev bool
	registries []string
	threshold  float64
	// New flags for reporting and ML
	mlEnabled     bool
	mlURL         string
	reportType    string
	showMetadata  bool
	showEvidence  bool
	similarityK   int
	confidenceMin float64
	registry      string
)

var rootCmd = &cobra.Command{
	Use:   "typosentinel-scanner",
	Short: "TypoSentinel Project Scanner",
	Long: `TypoSentinel Project Scanner automatically detects and analyzes packages in your projects.

Supported project types:
  - Node.js (package.json, package-lock.json)
  - Python (requirements.txt, pyproject.toml, poetry.lock)
  - Go (go.mod, go.sum)
  - Rust (Cargo.toml, Cargo.lock)
  - Ruby (Gemfile, Gemfile.lock)
  - PHP (composer.json, composer.lock)
  - Java (pom.xml, build.gradle)
  - .NET (*.csproj, packages.config)

Examples:
  # Scan current directory
  typosentinel-scanner scan .

  # Scan specific project with custom depth
  typosentinel-scanner scan /path/to/project --max-depth 5

  # Output results to JSON file
  typosentinel-scanner scan . --output results.json --format json

  # Show dependency tree
  typosentinel-scanner tree . --interactive`,
}

var scanCmd = &cobra.Command{
	Use:   "scan [path]",
	Short: "Scan a project for package dependencies and security threats",
	Args:  cobra.MaximumNArgs(1),
	Run:   runScan,
}

var treeCmd = &cobra.Command{
	Use:   "tree [path]",
	Short: "Display dependency tree for a project",
	Args:  cobra.MaximumNArgs(1),
	Run:   runTree,
}

var watchCmd = &cobra.Command{
	Use:   "watch [path]",
	Short: "Watch a project for changes and automatically scan",
	Args:  cobra.MaximumNArgs(1),
	Run:   runWatch,
}

var reportCmd = &cobra.Command{
	Use:   "report [path]",
	Short: "Generate comprehensive package reports with ML analysis",
	Args:  cobra.MaximumNArgs(1),
	Run:   runReport,
}

var packageCmd = &cobra.Command{
	Use:   "package [package-name]",
	Short: "Analyze a specific package with detailed information",
	Args:  cobra.ExactArgs(1),
	Run:   runPackageAnalysis,
}

var mlCmd = &cobra.Command{
	Use:   "ml [path]",
	Short: "Run ML-powered analysis on packages",
	Args:  cobra.MaximumNArgs(1),
	Run:   runMLAnalysis,
}

// convertRegistriesToMap converts a slice of registry names to a map of RegistryConfig
func convertRegistriesToMap(registries []string) map[string]config.RegistryConfig {
	registryMap := make(map[string]config.RegistryConfig)
	for _, registry := range registries {
		registryMap[registry] = config.RegistryConfig{
			Enabled: true,
			Timeout: 30,
			RateLimit: 100,
		}
	}
	return registryMap
}

func main() {
	initConfig()
	addCommands()
	addFlags()

	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

func initConfig() {
	if configFile != "" {
		viper.SetConfigFile(configFile)
	} else {
		viper.SetConfigName("typosentinel")
		viper.SetConfigType("yaml")
		viper.AddConfigPath(".")
		viper.AddConfigPath("$HOME/.typosentinel")
		viper.AddConfigPath("/etc/typosentinel")
	}

	viper.AutomaticEnv()
	viper.SetEnvPrefix("TYPOSENTINEL")

	if err := viper.ReadInConfig(); err != nil {
		if !quiet {
			fmt.Printf("Warning: Config file not found: %v\n", err)
		}
	}
}

func addCommands() {
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(treeCmd)
	rootCmd.AddCommand(watchCmd)
	rootCmd.AddCommand(reportCmd)
	rootCmd.AddCommand(packageCmd)
	rootCmd.AddCommand(mlCmd)
	rootCmd.AddCommand(versionCmd)
}

func addFlags() {
	// Global flags
	rootCmd.PersistentFlags().StringVar(&configFile, "config", "", "config file (default is $HOME/.typosentinel/config.yaml)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")
	rootCmd.PersistentFlags().BoolVarP(&quiet, "quiet", "q", false, "quiet output")

	// ML flags (global)
	rootCmd.PersistentFlags().BoolVar(&mlEnabled, "ml-enabled", true, "enable ML analysis")
	rootCmd.PersistentFlags().StringVar(&mlURL, "ml-url", "http://localhost:8000", "ML service URL")

	// Scan command flags
	scanCmd.Flags().StringVarP(&outputFile, "output", "o", "", "output file path")
	scanCmd.Flags().StringVarP(&format, "format", "f", "table", "output format (table, json, yaml, csv)")
	scanCmd.Flags().IntVar(&maxDepth, "max-depth", 10, "maximum dependency depth to analyze")
	scanCmd.Flags().BoolVar(&includeDev, "include-dev", false, "include development dependencies")
	scanCmd.Flags().StringSliceVar(&registries, "registries", []string{"npm", "pypi"}, "registries to check")
	scanCmd.Flags().Float64Var(&threshold, "threshold", 0.5, "risk threshold (0.0-1.0)")

	// Tree command flags
	treeCmd.Flags().StringVarP(&format, "format", "f", "tree", "output format (tree, json, yaml)")
	treeCmd.Flags().IntVar(&maxDepth, "max-depth", 5, "maximum tree depth to display")
	treeCmd.Flags().BoolVar(&includeDev, "include-dev", false, "include development dependencies")
	treeCmd.Flags().Bool("interactive", false, "interactive tree navigation")
	treeCmd.Flags().Bool("show-risks", false, "highlight packages with security risks")

	// Watch command flags
	watchCmd.Flags().StringSliceVar(&registries, "registries", []string{"npm", "pypi"}, "registries to check")
	watchCmd.Flags().Float64Var(&threshold, "threshold", 0.5, "risk threshold (0.0-1.0)")
	watchCmd.Flags().Duration("interval", 0, "scan interval (0 for file system events)")

	// Report command flags
	reportCmd.Flags().StringVarP(&outputFile, "output", "o", "", "output file")
	reportCmd.Flags().StringVarP(&format, "format", "f", "detailed", "report format (detailed, summary, json, html)")
	reportCmd.Flags().StringVar(&reportType, "type", "full", "report type (full, security, dependencies, ml)")
	reportCmd.Flags().BoolVar(&showMetadata, "show-metadata", true, "include package metadata")
	reportCmd.Flags().BoolVar(&showEvidence, "show-evidence", true, "include threat evidence")
	reportCmd.Flags().BoolVar(&includeDev, "include-dev", false, "include development dependencies")

	// Package command flags
	packageCmd.Flags().StringVar(&registry, "registry", "npm", "package registry (npm, pypi, etc.)")
	packageCmd.Flags().StringVarP(&format, "format", "f", "detailed", "output format (detailed, json)")
	packageCmd.Flags().BoolVar(&showMetadata, "show-metadata", true, "show package metadata")
	packageCmd.Flags().BoolVar(&showEvidence, "show-evidence", true, "show threat evidence")
	packageCmd.Flags().IntVar(&similarityK, "similarity-k", 10, "number of similar packages to find")

	// ML command flags
	mlCmd.Flags().StringVarP(&outputFile, "output", "o", "", "output file")
	mlCmd.Flags().StringVarP(&format, "format", "f", "table", "output format (table, json)")
	mlCmd.Flags().Float64Var(&confidenceMin, "min-confidence", 0.7, "minimum confidence threshold")
	mlCmd.Flags().IntVar(&similarityK, "similarity-k", 10, "number of similar packages to find")
	mlCmd.Flags().BoolVar(&includeDev, "include-dev", false, "include development dependencies")
}

func runScan(cmd *cobra.Command, args []string) {
	projectPath := "."
	if len(args) > 0 {
		projectPath = args[0]
	}

	// Initialize scanner
	cfg := &config.Config{
		API: config.APIConfig{
			BaseURL: viper.GetString("api.base_url"),
			APIKey:  viper.GetString("api.key"),
		},
		Scanner: config.ScannerConfig{
			MaxDepth:           maxDepth,
			IncludeDevDeps:     includeDev,
			Registries:         convertRegistriesToMap(registries),
			RiskThreshold:      threshold,
			EnableMLAnalysis:   viper.GetBool("scanner.enable_ml"),
		},
	}

	scanner := scanner.New(cfg)

	if !quiet {
		fmt.Printf("Scanning project: %s\n", projectPath)
	}

	// Scan project
	result, err := scanner.ScanProject(projectPath)
	if err != nil {
		log.Fatalf("Scan failed: %v", err)
	}

	// Output results
	if err := outputResults(result, format, outputFile); err != nil {
		log.Fatalf("Failed to output results: %v", err)
	}

	if !quiet {
		fmt.Printf("\nScan completed. Found %d packages with %d threats.\n",
			result.Summary.TotalPackages, result.Summary.ThreatsFound)
	}

	// Exit with error code if threats found
	if result.Summary.ThreatsFound > 0 {
		os.Exit(1)
	}
}

func runTree(cmd *cobra.Command, args []string) {
	projectPath := "."
	if len(args) > 0 {
		projectPath = args[0]
	}

	cfg := &config.Config{
		Scanner: config.ScannerConfig{
			MaxDepth:       maxDepth,
			IncludeDevDeps: includeDev,
		},
	}

	scanner := scanner.New(cfg)

	if !quiet {
		fmt.Printf("Building dependency tree: %s\n", projectPath)
	}

	tree, err := scanner.BuildDependencyTree(projectPath)
	if err != nil {
		log.Fatalf("Failed to build dependency tree: %v", err)
	}

	interactive, _ := cmd.Flags().GetBool("interactive")
	showRisks, _ := cmd.Flags().GetBool("show-risks")

	if interactive {
		runInteractiveTree(tree, showRisks)
	} else {
		printTree(tree, format, showRisks)
	}
}

func runWatch(cmd *cobra.Command, args []string) {
	projectPath := "."
	if len(args) > 0 {
		projectPath = args[0]
	}

	interval, _ := cmd.Flags().GetDuration("interval")

	cfg := &config.Config{
		API: config.APIConfig{
			BaseURL: viper.GetString("api.base_url"),
			APIKey:  viper.GetString("api.key"),
		},
		Scanner: config.ScannerConfig{
			Registries:    convertRegistriesToMap(registries),
			RiskThreshold: threshold,
		},
	}

	scanner := scanner.New(cfg)

	if !quiet {
		fmt.Printf("Watching project: %s\n", projectPath)
		if interval > 0 {
			fmt.Printf("Scan interval: %v\n", interval)
		} else {
			fmt.Println("Using file system events")
		}
	}

	if err := scanner.WatchProject(projectPath, interval); err != nil {
		log.Fatalf("Watch failed: %v", err)
	}
}

func outputResults(result *types.ScanResult, format, outputFile string) error {
	var output []byte
	var err error

	switch strings.ToLower(format) {
	case "json":
		output, err = json.MarshalIndent(result, "", "  ")
	case "yaml":
		// TODO: Implement YAML output
		return fmt.Errorf("YAML output not implemented yet")
	case "csv":
		// TODO: Implement CSV output
		return fmt.Errorf("CSV output not implemented yet")
	default:
		return printTableResults(result)
	}

	if err != nil {
		return err
	}

	if outputFile != "" {
		return os.WriteFile(outputFile, output, 0644)
	}

	fmt.Print(string(output))
	return nil
}

func printTableResults(result *types.ScanResult) error {
	fmt.Printf("\n=== Scan Results ===\n")
	fmt.Printf("Target: %s\n", result.Target)
	fmt.Printf("Type: %s\n", result.Type)
	fmt.Printf("Status: %s\n", result.Status)
	fmt.Printf("Duration: %v\n", result.Duration)
	fmt.Printf("\n=== Summary ===\n")
	fmt.Printf("Total Packages: %d\n", result.Summary.TotalPackages)
	fmt.Printf("Threats Found: %d\n", result.Summary.ThreatsFound)
	fmt.Printf("Risk Distribution:\n")
	fmt.Printf("  High: %d\n", result.Summary.RiskDistribution["high"])
	fmt.Printf("  Medium: %d\n", result.Summary.RiskDistribution["medium"])
	fmt.Printf("  Low: %d\n", result.Summary.RiskDistribution["low"])
	fmt.Printf("  None: %d\n", result.Summary.RiskDistribution["none"])

	if len(result.Packages) > 0 {
		fmt.Printf("\n=== Packages with Threats ===\n")
		for _, pkg := range result.Packages {
			if len(pkg.Threats) > 0 {
				fmt.Printf("\n%s@%s (%s)\n", pkg.Name, pkg.Version, pkg.Registry)
				fmt.Printf("  Risk Level: %s (Score: %.2f)\n", pkg.RiskLevel, pkg.RiskScore)
				for _, threat := range pkg.Threats {
					fmt.Printf("  - %s (%s): %s\n", threat.Type, threat.Severity, threat.Description)
				}
			}
		}
	}

	return nil
}

func printTree(tree *types.DependencyTree, format string, showRisks bool) {
	switch strings.ToLower(format) {
	case "json":
		output, _ := json.MarshalIndent(tree, "", "  ")
		fmt.Print(string(output))
	default:
		printTreeNode(tree, "", true, showRisks)
	}
}

func printTreeNode(node *types.DependencyTree, prefix string, isLast bool, showRisks bool) {
	connector := "├── "
	if isLast {
		connector = "└── "
	}

	riskIndicator := ""
	if showRisks && len(node.Threats) > 0 {
		riskIndicator = fmt.Sprintf(" [%d threats]", len(node.Threats))
	}

	fmt.Printf("%s%s%s@%s%s\n", prefix, connector, node.Name, node.Version, riskIndicator)

	newPrefix := prefix
	if isLast {
		newPrefix += "    "
	} else {
		newPrefix += "│   "
	}

	for i, dep := range node.Dependencies {
		isLastDep := i == len(node.Dependencies)-1
		printTreeNode(&dep, newPrefix, isLastDep, showRisks)
	}
}

func runInteractiveTree(tree *types.DependencyTree, showRisks bool) {
	// TODO: Implement interactive tree navigation
	fmt.Println("Interactive tree navigation not implemented yet")
	printTree(tree, "tree", showRisks)
}

// runReport generates comprehensive package reports with ML analysis
func runReport(cmd *cobra.Command, args []string) {
	projectPath := "."
	if len(args) > 0 {
		projectPath = args[0]
	}

	cfg := &config.Config{
		Scanner: config.ScannerConfig{
			MaxDepth:       maxDepth,
			IncludeDevDeps: includeDev,
			Registries:     convertRegistriesToMap(registries),
			RiskThreshold:  threshold,
		},
	}

	scanner := scanner.New(cfg)

	if !quiet {
		fmt.Printf("Generating %s report for: %s\n", reportType, projectPath)
	}

	// Perform scan
	result, err := scanner.ScanProject(projectPath)
	if err != nil {
		log.Fatalf("Scan failed: %v", err)
	}

	// Generate ML analysis if enabled
	var mlResults map[string]interface{}
	if mlEnabled {
		mlResults = performMLAnalysis(result.Packages)
	}

	// Generate report based on type
	switch reportType {
	case "full":
		generateFullReport(result, mlResults)
	case "security":
		generateSecurityReport(result)
	case "dependencies":
		generateDependencyReport(result)
	case "ml":
		generateMLReport(result, mlResults)
	default:
		generateFullReport(result, mlResults)
	}
}

// runPackageAnalysis analyzes a specific package with detailed information
func runPackageAnalysis(cmd *cobra.Command, args []string) {
	packageName := args[0]

	if !quiet {
		fmt.Printf("Analyzing package: %s (registry: %s)\n", packageName, registry)
	}

	// Create ML client if enabled
	var mlClient *ml.Client
	if mlEnabled {
		apiKey := os.Getenv("TYPOSENTINEL_API_KEY")
		if apiKey == "" {
			apiKey = "dev-key-123" // Default development key
		}
		mlClient = ml.NewClient(mlURL, apiKey)
	}

	// Analyze package
	analysis := analyzeSpecificPackage(packageName, registry, mlClient)

	// Output results
	if format == "json" {
		output, _ := json.MarshalIndent(analysis, "", "  ")
		fmt.Println(string(output))
	} else {
		printPackageAnalysis(analysis)
	}
}

// runMLAnalysis runs ML-powered analysis on packages
func runMLAnalysis(cmd *cobra.Command, args []string) {
	projectPath := "."
	if len(args) > 0 {
		projectPath = args[0]
	}

	cfg := &config.Config{
		Scanner: config.ScannerConfig{
			MaxDepth:       maxDepth,
			IncludeDevDeps: includeDev,
		},
	}

	scanner := scanner.New(cfg)

	if !quiet {
		fmt.Printf("Running ML analysis on: %s\n", projectPath)
	}

	// Perform scan
	result, err := scanner.ScanProject(projectPath)
	if err != nil {
		log.Fatalf("Scan failed: %v", err)
	}

	// Perform ML analysis
	mlResults := performMLAnalysis(result.Packages)

	// Output results
	if format == "json" {
		output, _ := json.MarshalIndent(mlResults, "", "  ")
		fmt.Println(string(output))
	} else {
		printMLResults(mlResults)
	}
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("TypoSentinel Scanner\n")
		fmt.Printf("Version: %s\n", version)
		fmt.Printf("Build Time: %s\n", buildTime)
		fmt.Printf("Commit Hash: %s\n", commitHash)
	},
}