package benchmark

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"typosentinel/internal/analyzer"
	"typosentinel/internal/config"
	"typosentinel/pkg/logger"
)

// BenchmarkMetrics holds performance metrics for a single benchmark
type BenchmarkMetrics struct {
	Duration      time.Duration `json:"duration"`
	Operations    int           `json:"operations"`
	OpsPerSecond  float64       `json:"ops_per_second"`
	AvgTimePerOp  time.Duration `json:"avg_time_per_op"`
	MemoryPerOp   uint64        `json:"memory_per_op"`
	AllocsPerOp   uint64        `json:"allocs_per_op"`
	MinTime       time.Duration `json:"min_time,omitempty"`
	MaxTime       time.Duration `json:"max_time,omitempty"`
	StdDev        time.Duration `json:"std_dev,omitempty"`
	ErrorRate     float64       `json:"error_rate,omitempty"`
	ThroughputMB  float64       `json:"throughput_mb,omitempty"`
}

// BenchmarkResults holds the complete results of a benchmark run
type BenchmarkResults struct {
	Timestamp   time.Time                    `json:"timestamp"`
	Environment EnvironmentInfo             `json:"environment"`
	Metrics     map[string]BenchmarkMetrics `json:"metrics"`
}

// BenchmarkSuite manages and executes performance benchmarks
type BenchmarkSuite struct {
	config          *config.Config
	scanner         *analyzer.Analyzer
	metrics         map[string]BenchmarkMetrics
	mu              sync.RWMutex
	Duration        time.Duration
	Parallel        int
	Iterations      int
	WarmupDuration  time.Duration
	Verbose         bool
	Config          *config.Config
	cpuProfileFile  string
	memProfileFile  string
	Name            string                     `json:"name"`
	Description     string                     `json:"description"`
	Results         map[string]BenchmarkMetrics `json:"results"`
	Timestamp       time.Time                  `json:"timestamp"`
	Environment     EnvironmentInfo            `json:"environment"`
}

// EnvironmentInfo captures system information
type EnvironmentInfo struct {
	OS           string `json:"os"`
	Arch         string `json:"arch"`
	CPUs         int    `json:"cpus"`
	GoVersion    string `json:"go_version"`
	MemoryMB     int64  `json:"memory_mb"`
	Hostname     string `json:"hostname"`
}

// BenchmarkSmallPackage tests performance with small packages (1-10 dependencies)
func BenchmarkSmallPackage(b *testing.B) {
	cfg := getOptimizedConfig()
	analyzer := analyzer.New(cfg)
	testDir := createSmallTestPackage(b)
	defer os.RemoveAll(testDir)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		options := &analyzer.ScanOptions{
			OutputFormat:        "json",
			DeepAnalysis:        false,
			SimilarityThreshold: 0.8,
		}
		_, err := analyzer.Scan(testDir, options)
		if err != nil {
			b.Fatalf("Scan failed: %v", err)
		}
	}
}

// BenchmarkMediumPackage tests performance with medium packages (10-50 dependencies)
func BenchmarkMediumPackage(b *testing.B) {
	cfg := getOptimizedConfig()
	analyzer := analyzer.New(cfg)
	testDir := createMediumTestPackage(b)
	defer os.RemoveAll(testDir)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		options := &analyzer.ScanOptions{
			OutputFormat:        "json",
			DeepAnalysis:        true,
			SimilarityThreshold: 0.8,
		}
		_, err := analyzer.Scan(testDir, options)
		if err != nil {
			b.Fatalf("Scan failed: %v", err)
		}
	}
}

// BenchmarkLargePackage tests performance with large packages (50+ dependencies)
func BenchmarkLargePackage(b *testing.B) {
	cfg := getOptimizedConfig()
	analyzer := analyzer.New(cfg)
	testDir := createLargeTestPackage(b)
	defer os.RemoveAll(testDir)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		options := &analyzer.ScanOptions{
			OutputFormat:        "json",
			DeepAnalysis:        true,
			SimilarityThreshold: 0.8,
		}
		_, err := analyzer.Scan(testDir, options)
		if err != nil {
			b.Fatalf("Scan failed: %v", err)
		}
	}
}

// BenchmarkConcurrentScans tests concurrent scanning performance
func BenchmarkConcurrentScans(b *testing.B) {
	cfg := getOptimizedConfig()
	analyzer := analyzer.New(cfg)
	testDir := createTestPackage(b)
	defer os.RemoveAll(testDir)

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			options := &analyzer.ScanOptions{
				OutputFormat:        "json",
				DeepAnalysis:        false,
				SimilarityThreshold: 0.8,
			}
			_, err := analyzer.Scan(testDir, options)
			if err != nil {
				b.Fatalf("Scan failed: %v", err)
			}
		}
	})
}

// BenchmarkMLAnalysis tests ML analysis performance
func BenchmarkMLAnalysis(b *testing.B) {
	cfg := getMLEnabledConfig()
	analyzer := analyzer.New(cfg)
	testDir := createTestPackage(b)
	defer os.RemoveAll(testDir)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		options := &analyzer.ScanOptions{
			OutputFormat:        "json",
			DeepAnalysis:        true,
			SimilarityThreshold: 0.9,
		}
		_, err := analyzer.Scan(testDir, options)
		if err != nil {
			b.Fatalf("Scan failed: %v", err)
		}
	}
}

// BenchmarkMemoryUsage tests memory usage patterns
func BenchmarkMemoryUsage(b *testing.B) {
	cfg := getOptimizedConfig()
	analyzer := analyzer.New(cfg)
	testDir := createLargeTestPackage(b)
	defer os.RemoveAll(testDir)

	var m1, m2 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m1)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		options := &analyzer.ScanOptions{
			OutputFormat:        "json",
			DeepAnalysis:        true,
			SimilarityThreshold: 0.8,
		}
		_, err := analyzer.Scan(testDir, options)
		if err != nil {
			b.Fatalf("Scan failed: %v", err)
		}
		if i%10 == 0 {
			runtime.GC() // Force GC periodically
		}
	}

	runtime.GC()
	runtime.ReadMemStats(&m2)
	b.Logf("Memory allocated: %d bytes", m2.TotalAlloc-m1.TotalAlloc)
	b.Logf("Memory in use: %d bytes", m2.Alloc)
	b.Logf("GC cycles: %d", m2.NumGC-m1.NumGC)
}

// BenchmarkThroughput tests scanning throughput
func BenchmarkThroughput(b *testing.B) {
	cfg := getOptimizedConfig()
	analyzer := analyzer.New(cfg)
	testDirs := make([]string, 10)
	for i := range testDirs {
		testDirs[i] = createTestPackage(b)
		defer os.RemoveAll(testDirs[i])
	}

	b.ResetTimer()
	b.ReportAllocs()

	start := time.Now()
	for i := 0; i < b.N; i++ {
		testDir := testDirs[i%len(testDirs)]
		options := &analyzer.ScanOptions{
			OutputFormat:        "json",
			DeepAnalysis:        false,
			SimilarityThreshold: 0.8,
		}
		_, err := analyzer.Scan(testDir, options)
		if err != nil {
			b.Fatalf("Scan failed: %v", err)
		}
	}
	duration := time.Since(start)
	throughput := float64(b.N) / duration.Seconds()
	b.Logf("Throughput: %.2f scans/second", throughput)
}

// BenchmarkStressTest performs stress testing with high concurrency
func BenchmarkStressTest(b *testing.B) {
	cfg := getOptimizedConfig()
	analyzer := analyzer.New(cfg)
	testDir := createTestPackage(b)
	defer os.RemoveAll(testDir)

	context, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	errorChan := make(chan error, 100)
	successCount := int64(0)
	errorCount := int64(0)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case <-context.Done():
				return
			default:
				options := &analyzer.ScanOptions{
					OutputFormat:        "json",
					DeepAnalysis:        false,
					SimilarityThreshold: 0.8,
				}
				_, err := analyzer.Scan(testDir, options)
				if err != nil {
					errorCount++
					select {
					case errorChan <- err:
					default:
					}
				} else {
					successCount++
				}
			}
		}()
	}

	wg.Wait()
	close(errorChan)

	b.Logf("Successful scans: %d", successCount)
	b.Logf("Failed scans: %d", errorCount)
	if errorCount > 0 {
		b.Logf("Error rate: %.2f%%", float64(errorCount)/float64(successCount+errorCount)*100)
	}
}

// Helper functions

func getOptimizedConfig() *config.Config {
	return &config.Config{
		Detection: config.DetectionConfig{
			SimilarityThreshold: 0.8,
		},
		Scanner: config.ScannerConfig{
			IncludeDevDeps: false,
			MaxDepth:       5,
		},
		Logging: config.LoggingConfig{
			Level: "error", // Reduce logging overhead
		},
	}
}

func getMLEnabledConfig() *config.Config {
	cfg := getOptimizedConfig()
	cfg.Scanner.EnableMLAnalysis = true
	return cfg
}

func createSmallTestPackage(b *testing.B) string {
	return createTestPackage(b)
}

func createMediumTestPackage(b *testing.B) string {
	testDir, err := os.MkdirTemp("", "typosentinel-bench-medium-*")
	if err != nil {
		b.Fatalf("Failed to create test directory: %v", err)
	}

	packageJSON := `{
	"name": "test-medium-package",
	"version": "2.1.0",
	"dependencies": {
		"lodash": "^4.17.21",
		"express": "^4.18.0",
		"axios": "^0.27.0",
		"react": "^18.2.0",
		"vue": "^3.2.0",
		"angular": "^14.0.0",
		"typescript": "^4.8.0",
		"webpack": "^5.74.0",
		"babel": "^7.18.0",
		"eslint": "^8.22.0"
	}
}`

	if err := os.WriteFile(filepath.Join(testDir, "package.json"), []byte(packageJSON), 0644); err != nil {
		b.Fatalf("Failed to write package.json: %v", err)
	}

	return testDir
}

func createLargeTestPackage(b *testing.B) string {
	testDir, err := os.MkdirTemp("", "typosentinel-bench-large-*")
	if err != nil {
		b.Fatalf("Failed to create test directory: %v", err)
	}

	packageJSON := `{
	"name": "test-large-package",
	"version": "3.0.0",
	"dependencies": {
		"lodash": "^4.17.21",
		"express": "^4.18.0",
		"axios": "^0.27.0",
		"react": "^18.2.0",
		"vue": "^3.2.0",
		"angular": "^14.0.0",
		"typescript": "^4.8.0",
		"webpack": "^5.74.0",
		"babel": "^7.18.0",
		"eslint": "^8.22.0",
		"jest": "^28.0.0",
		"mocha": "^10.0.0",
		"chai": "^4.3.0",
		"sinon": "^14.0.0",
		"cypress": "^10.0.0",
		"webpack-cli": "^4.10.0",
		"@babel/core": "^7.18.0",
		"@babel/preset-env": "^7.18.0",
		"@babel/preset-react": "^7.18.0",
		"sass": "^1.54.0",
		"postcss": "^8.4.0",
		"autoprefixer": "^10.4.0",
		"tailwindcss": "^3.1.0",
		"styled-components": "^5.3.0",
		"emotion": "^11.10.0",
		"material-ui": "^5.10.0",
		"antd": "^4.22.0",
		"bootstrap": "^5.2.0",
		"jquery": "^3.6.0",
		"moment": "^2.29.0",
		"date-fns": "^2.29.0",
		"ramda": "^0.28.0",
		"immutable": "^4.1.0",
		"redux": "^4.2.0",
		"mobx": "^6.6.0",
		"rxjs": "^7.5.0",
		"graphql": "^16.6.0",
		"apollo-client": "^3.6.0",
		"relay-runtime": "^14.1.0",
		"socket.io": "^4.5.0",
		"ws": "^8.8.0",
		"express-session": "^1.17.0",
		"passport": "^0.6.0",
		"bcrypt": "^5.0.0",
		"jsonwebtoken": "^8.5.0",
		"helmet": "^6.0.0",
		"cors": "^2.8.0",
		"morgan": "^1.10.0",
		"winston": "^3.8.0",
		"pino": "^8.5.0"
	}
}`

	if err := os.WriteFile(filepath.Join(testDir, "package.json"), []byte(packageJSON), 0644); err != nil {
		b.Fatalf("Failed to write package.json: %v", err)
	}

	return testDir
}

func createTestPackage(b *testing.B) string {
	testDir, err := os.MkdirTemp("", "typosentinel-bench-*")
	if err != nil {
		b.Fatalf("Failed to create test directory: %v", err)
	}

	packageJSON := `{
	"name": "test-package",
	"version": "1.0.0",
	"dependencies": {
		"lodash": "^4.17.21",
		"express": "^4.18.0",
		"axios": "^0.27.0"
	}
}`

	if err := os.WriteFile(filepath.Join(testDir, "package.json"), []byte(packageJSON), 0644); err != nil {
		b.Fatalf("Failed to write package.json: %v", err)
	}

	return testDir
}

// NewBenchmarkSuite creates a new benchmark suite
func NewBenchmarkSuite() *BenchmarkSuite {
	return &BenchmarkSuite{
		metrics:        make(map[string]BenchmarkMetrics),
		Duration:       10 * time.Second,
		Parallel:       runtime.NumCPU(),
		WarmupDuration: 2 * time.Second,
		Results:        make(map[string]BenchmarkMetrics),
	}
}

// RunBenchmarkSuite executes a comprehensive benchmark suite
func RunBenchmarkSuite() (*BenchmarkSuite, error) {
	logger.Info("Starting comprehensive benchmark suite...")

	suite := &BenchmarkSuite{
		Name:        "TypoSentinel Performance Benchmark Suite",
		Description: "Comprehensive performance testing for TypoSentinel",
		Results:     make(map[string]BenchmarkMetrics),
		Timestamp:   time.Now(),
		Environment: getEnvironmentInfo(),
		metrics:     make(map[string]BenchmarkMetrics),
	}

	// Run individual benchmarks and collect metrics
	benchmarks := []struct {
		name string
		fn   func(*testing.B)
	}{
		{"SmallPackage", BenchmarkSmallPackage},
		{"MediumPackage", BenchmarkMediumPackage},
		{"LargePackage", BenchmarkLargePackage},
		{"ConcurrentScans", BenchmarkConcurrentScans},
		{"MLAnalysis", BenchmarkMLAnalysis},
		{"MemoryUsage", BenchmarkMemoryUsage},
		{"Throughput", BenchmarkThroughput},
	}

	for _, bench := range benchmarks {
		logger.Info(fmt.Sprintf("Running benchmark: %s", bench.name))
		result := testing.Benchmark(bench.fn)
		metrics := extractMetrics(result)
		suite.Results[bench.name] = metrics
	}

	logger.Info("Benchmark suite completed")
	return suite, nil
}

func extractMetrics(result testing.BenchmarkResult) BenchmarkMetrics {
	return BenchmarkMetrics{
		Duration:     result.T,
		Operations:   result.N,
		OpsPerSecond: float64(result.N) / result.T.Seconds(),
		AvgTimePerOp: result.T / time.Duration(result.N),
		MemoryPerOp:  result.MemBytes,
		AllocsPerOp:  result.MemAllocs,
	}
}

// GetEnvironmentInfo collects system information for benchmark context
func GetEnvironmentInfo() EnvironmentInfo {
	hostname, _ := os.Hostname()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	return EnvironmentInfo{
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
		CPUs:      runtime.NumCPU(),
		GoVersion: runtime.Version(),
		MemoryMB:  int64(m.Sys / 1024 / 1024),
		Hostname:  hostname,
	}
}

func getEnvironmentInfo() EnvironmentInfo {
	return GetEnvironmentInfo()
}