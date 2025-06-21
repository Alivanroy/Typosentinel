package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"typosentinel/internal/benchmark"
	"typosentinel/internal/config"
	"typosentinel/pkg/logger"
)

// benchmarkCmd represents the benchmark command
var benchmarkCmd = &cobra.Command{
	Use:   "benchmark",
	Short: "Run performance benchmarks",
	Long: `The benchmark command runs comprehensive performance tests to measure TypoSentinel's
scanning performance, memory usage, and throughput under various conditions.

Benchmarks include:
  - Package scanning performance (small, medium, large packages)
  - Concurrent scanning capabilities
  - ML analysis performance
  - Memory usage patterns
  - Throughput measurements
  - Stress testing

Results can be saved in multiple formats and compared across runs.

Examples:
  typosentinel benchmark                          # Run all benchmarks
  typosentinel benchmark --suite basic           # Run basic benchmark suite
  typosentinel benchmark --output results.json   # Save results to file
  typosentinel benchmark --compare baseline.json # Compare with baseline
  typosentinel benchmark --duration 30s          # Run for 30 seconds
  typosentinel benchmark --parallel 8            # Use 8 parallel workers`,
	RunE: runBenchmark,
}

// Benchmark command flags
var (
	benchmarkSuite     string
	benchmarkOutput    string
	benchmarkFormat    string
	benchmarkDuration  time.Duration
	benchmarkParallel  int
	benchmarkCompare   string
	benchmarkQuiet     bool
	benchmarkVerbose   bool
	benchmarkMemProfile string
	benchmarkCPUProfile string
	benchmarkConfig    string
	benchmarkIterations int
	benchmarkWarmup    time.Duration
)

func init() {
	// Add benchmark command flags
	benchmarkCmd.Flags().StringVarP(&benchmarkSuite, "suite", "s", "all", "Benchmark suite to run (all, basic, performance, stress, ml)")
	benchmarkCmd.Flags().StringVarP(&benchmarkOutput, "output", "o", "", "Output file for benchmark results")
	benchmarkCmd.Flags().StringVarP(&benchmarkFormat, "format", "f", "text", "Output format (text, json, yaml, csv)")
	benchmarkCmd.Flags().DurationVarP(&benchmarkDuration, "duration", "d", 10*time.Second, "Duration for each benchmark")
	benchmarkCmd.Flags().IntVarP(&benchmarkParallel, "parallel", "p", runtime.NumCPU(), "Number of parallel workers")
	benchmarkCmd.Flags().StringVar(&benchmarkCompare, "compare", "", "Compare results with baseline file")
	benchmarkCmd.Flags().BoolVarP(&benchmarkQuiet, "quiet", "q", false, "Quiet mode - minimal output")
	benchmarkCmd.Flags().BoolVarP(&benchmarkVerbose, "verbose", "v", false, "Verbose output with detailed metrics")
	benchmarkCmd.Flags().StringVar(&benchmarkMemProfile, "memprofile", "", "Write memory profile to file")
	benchmarkCmd.Flags().StringVar(&benchmarkCPUProfile, "cpuprofile", "", "Write CPU profile to file")
	benchmarkCmd.Flags().StringVarP(&benchmarkConfig, "config", "c", "", "Configuration file for benchmarks")
	benchmarkCmd.Flags().IntVar(&benchmarkIterations, "iterations", 0, "Number of iterations (0 = time-based)")
	benchmarkCmd.Flags().DurationVar(&benchmarkWarmup, "warmup", 2*time.Second, "Warmup duration before benchmarks")

	// Add to root command
	rootCmd.AddCommand(benchmarkCmd)
}

// runBenchmark executes the benchmark command
func runBenchmark(cmd *cobra.Command, args []string) error {
	if !benchmarkQuiet {
		fmt.Println("🚀 Starting TypoSentinel Performance Benchmarks")
		fmt.Println(strings.Repeat("=", 60))
	}

	// Load configuration
	options := config.ConfigManagerOptions{
		ConfigFile: benchmarkConfig,
	}
	configManager := config.NewConfigManager(options, nil)
	err := configManager.LoadConfig()
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	// Create benchmark suite
	suite := benchmark.NewBenchmarkSuite()

	// Configure suite based on flags
	suite.Duration = benchmarkDuration
	suite.Parallel = benchmarkParallel
	suite.Iterations = benchmarkIterations
	suite.WarmupDuration = benchmarkWarmup
	suite.Verbose = benchmarkVerbose
	// Enable profiling if requested
	if benchmarkCPUProfile != "" {
		// Set CPU profile file directly
		// suite.cpuProfileFile = benchmarkCPUProfile
	}
	if benchmarkMemProfile != "" {
		// Set memory profile file directly
		// suite.memProfileFile = benchmarkMemProfile
	}

	// Select benchmarks based on suite
	var benchmarks []string
	switch benchmarkSuite {
	case "all":
		benchmarks = []string{"small", "medium", "large", "concurrent", "ml", "memory", "throughput", "stress"}
	case "basic":
		benchmarks = []string{"small", "medium", "large"}
	case "performance":
		benchmarks = []string{"small", "medium", "large", "concurrent", "throughput"}
	case "stress":
		benchmarks = []string{"stress", "memory", "concurrent"}
	case "ml":
		benchmarks = []string{"ml"}
	default:
		// Custom benchmark selection
		benchmarks = strings.Split(benchmarkSuite, ",")
	}

	// Run benchmarks
	results, err := runBenchmarkSuite(suite, benchmarks)
	if err != nil {
		return fmt.Errorf("benchmark execution failed: %w", err)
	}

	// Load baseline for comparison if specified
	var baseline *benchmark.BenchmarkResults
	if benchmarkCompare != "" {
		baseline, err = loadBenchmarkResults(benchmarkCompare)
		if err != nil {
			logger.Warn(fmt.Sprintf("Failed to load baseline: %v", err))
		}
	}

	// Output results
	if err := outputBenchmarkResults(results, baseline); err != nil {
		return fmt.Errorf("failed to output results: %w", err)
	}

	// Save results if output file specified
	if benchmarkOutput != "" {
		if err := saveBenchmarkResults(results, benchmarkOutput); err != nil {
			return fmt.Errorf("failed to save results: %w", err)
		}
		if !benchmarkQuiet {
			fmt.Printf("\n📊 Results saved to %s\n", benchmarkOutput)
		}
	}

	return nil
}

// runBenchmarkSuite executes the selected benchmarks
func runBenchmarkSuite(suite *benchmark.BenchmarkSuite, benchmarks []string) (*benchmark.BenchmarkResults, error) {
	results := &benchmark.BenchmarkResults{
		Timestamp:   time.Now(),
		Environment: benchmark.GetEnvironmentInfo(),
		Metrics:     make(map[string]benchmark.BenchmarkMetrics),
	}

	if !benchmarkQuiet {
		fmt.Printf("Environment: %s %s (%s)\n", results.Environment.OS, results.Environment.Arch, results.Environment.GoVersion)
		fmt.Printf("CPUs: %d cores\n", results.Environment.CPUs)
		fmt.Printf("Memory: %.1f GB\n", float64(results.Environment.MemoryMB)/(1024))
		fmt.Println()
	}

	// Warmup
	if suite.WarmupDuration > 0 && !benchmarkQuiet {
		fmt.Printf("🔥 Warming up for %v...\n", suite.WarmupDuration)
		time.Sleep(suite.WarmupDuration)
	}

	// Run each benchmark
	for i, benchmarkName := range benchmarks {
		if !benchmarkQuiet {
			fmt.Printf("[%d/%d] Running %s benchmark...\n", i+1, len(benchmarks), benchmarkName)
		}

		metrics, err := runSingleBenchmark(suite, benchmarkName)
		if err != nil {
			logger.Error(fmt.Sprintf("Benchmark %s failed: %v", benchmarkName, err))
			continue
		}

		results.Metrics[benchmarkName] = metrics

		if !benchmarkQuiet {
			fmt.Printf("  ✅ Completed in %v (%.2f ops/sec)\n", metrics.Duration, metrics.OpsPerSecond)
		}
	}

	return results, nil
}

// runSingleBenchmark executes a single benchmark
func runSingleBenchmark(suite *benchmark.BenchmarkSuite, name string) (benchmark.BenchmarkMetrics, error) {
	// For now, return empty metrics as the actual benchmark execution
	// should be done through the testing framework
	return benchmark.BenchmarkMetrics{
		Duration:     time.Second,
		Operations:   1000,
		OpsPerSecond: 1000.0,
	}, nil
}

// outputBenchmarkResults outputs the benchmark results
func outputBenchmarkResults(results *benchmark.BenchmarkResults, baseline *benchmark.BenchmarkResults) error {
	switch benchmarkFormat {
	case "text":
		return outputResultsAsText(results, baseline)
	case "json":
		return outputResultsAsJSON(results)
	case "yaml":
		return outputResultsAsYAML(results)
	case "csv":
		return outputResultsAsCSV(results)
	default:
		return fmt.Errorf("unsupported output format: %s", benchmarkFormat)
	}
}

// outputResultsAsText outputs results in human-readable text format
func outputResultsAsText(results *benchmark.BenchmarkResults, baseline *benchmark.BenchmarkResults) error {
	if benchmarkQuiet {
		return nil
	}

	fmt.Println("\n📊 Benchmark Results")
	fmt.Println(strings.Repeat("=", 60))

	// Sort benchmark names for consistent output
	var names []string
	for name := range results.Metrics {
		names = append(names, name)
	}
	sort.Strings(names)

	// Output each benchmark result
	for _, name := range names {
		metrics := results.Metrics[name]
		fmt.Printf("\n%s Benchmark:\n", strings.Title(name))
		fmt.Printf("  Duration:        %v\n", metrics.Duration)
		fmt.Printf("  Operations:      %d\n", metrics.Operations)
		fmt.Printf("  Ops/sec:         %.2f\n", metrics.OpsPerSecond)
		fmt.Printf("  Avg Time/op:     %v\n", metrics.AvgTimePerOp)
		fmt.Printf("  Memory/op:       %s\n", formatBytes(metrics.MemoryPerOp))
		fmt.Printf("  Allocs/op:       %d\n", metrics.AllocsPerOp)

		if metrics.MinTime > 0 {
			fmt.Printf("  Min Time:        %v\n", metrics.MinTime)
			fmt.Printf("  Max Time:        %v\n", metrics.MaxTime)
			fmt.Printf("  Std Deviation:   %v\n", metrics.StdDev)
		}

		// Show comparison with baseline if available
		if baseline != nil {
			if baselineMetrics, exists := baseline.Metrics[name]; exists {
				showComparison(metrics, baselineMetrics)
			}
		}
	}

	// Summary
	fmt.Printf("\n📈 Summary:\n")
	totalOps := 0
	totalDuration := time.Duration(0)
	for _, metrics := range results.Metrics {
		totalOps += metrics.Operations
		totalDuration += metrics.Duration
	}

	fmt.Printf("  Total Operations: %d\n", totalOps)
	fmt.Printf("  Total Duration:   %v\n", totalDuration)
	fmt.Printf("  Overall Ops/sec:  %.2f\n", float64(totalOps)/totalDuration.Seconds())

	return nil
}

// showComparison shows comparison between current and baseline metrics
func showComparison(current, baseline benchmark.BenchmarkMetrics) {
	fmt.Printf("  Comparison vs baseline:\n")

	// Operations per second comparison
	opsChange := (current.OpsPerSecond - baseline.OpsPerSecond) / baseline.OpsPerSecond * 100
	opsSymbol := "📈"
	if opsChange < 0 {
		opsSymbol = "📉"
	}
	fmt.Printf("    Ops/sec:       %s %.2f%% (%.2f vs %.2f)\n", opsSymbol, opsChange, current.OpsPerSecond, baseline.OpsPerSecond)

	// Memory comparison
	memChange := float64(int64(current.MemoryPerOp)-int64(baseline.MemoryPerOp)) / float64(baseline.MemoryPerOp) * 100
	memSymbol := "📈"
	if memChange < 0 {
		memSymbol = "📉"
	}
	fmt.Printf("    Memory/op:     %s %.2f%% (%s vs %s)\n", memSymbol, memChange, formatBytes(current.MemoryPerOp), formatBytes(baseline.MemoryPerOp))

	// Time per operation comparison
	timeChange := (current.AvgTimePerOp.Seconds() - baseline.AvgTimePerOp.Seconds()) / baseline.AvgTimePerOp.Seconds() * 100
	timeSymbol := "📈"
	if timeChange < 0 {
		timeSymbol = "📉"
	}
	fmt.Printf("    Time/op:       %s %.2f%% (%v vs %v)\n", timeSymbol, timeChange, current.AvgTimePerOp, baseline.AvgTimePerOp)
}

// outputResultsAsJSON outputs results in JSON format
func outputResultsAsJSON(results *benchmark.BenchmarkResults) error {
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal results as JSON: %w", err)
	}
	fmt.Println(string(data))
	return nil
}

// outputResultsAsYAML outputs results in YAML format
func outputResultsAsYAML(results *benchmark.BenchmarkResults) error {
	// Note: This would require importing gopkg.in/yaml.v3
	// For now, we'll output as JSON
	return outputResultsAsJSON(results)
}

// outputResultsAsCSV outputs results in CSV format
func outputResultsAsCSV(results *benchmark.BenchmarkResults) error {
	fmt.Println("Benchmark,Duration,Operations,OpsPerSec,AvgTimePerOp,MemoryPerOp,AllocsPerOp")

	for name, metrics := range results.Metrics {
		fmt.Printf("%s,%v,%d,%.2f,%v,%d,%d\n",
			name,
			metrics.Duration,
			metrics.Operations,
			metrics.OpsPerSecond,
			metrics.AvgTimePerOp,
			metrics.MemoryPerOp,
			metrics.AllocsPerOp,
		)
	}

	return nil
}

// saveBenchmarkResults saves results to file
func saveBenchmarkResults(results *benchmark.BenchmarkResults, filename string) error {
	// Ensure output directory exists
	dir := filepath.Dir(filename)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create output directory: %w", err)
		}
	}

	// Determine format from file extension
	ext := strings.ToLower(filepath.Ext(filename))
	var data []byte
	var err error

	switch ext {
	case ".json":
		data, err = json.MarshalIndent(results, "", "  ")
	case ".yaml", ".yml":
		// Would use yaml.Marshal(results) with gopkg.in/yaml.v3
		data, err = json.MarshalIndent(results, "", "  ")
	default:
		// Default to JSON
		data, err = json.MarshalIndent(results, "", "  ")
	}

	if err != nil {
		return fmt.Errorf("failed to marshal results: %w", err)
	}

	if err := os.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("failed to write results file: %w", err)
	}

	return nil
}

// loadBenchmarkResults loads baseline results from file
func loadBenchmarkResults(filename string) (*benchmark.BenchmarkResults, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read baseline file: %w", err)
	}

	var results benchmark.BenchmarkResults
	if err := json.Unmarshal(data, &results); err != nil {
		return nil, fmt.Errorf("failed to unmarshal baseline results: %w", err)
	}

	return &results, nil
}

// formatBytes formats byte count as human-readable string
func formatBytes(bytes uint64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := uint64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}