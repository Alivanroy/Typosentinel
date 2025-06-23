package main

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// PerformanceMetrics holds performance test results
type PerformanceMetrics struct {
	ScanTime      time.Duration `json:"scan_time"`
	MemoryUsage   int64         `json:"memory_usage_mb"`
	CPUUsage      float64       `json:"cpu_usage_percent"`
	NetworkCalls  int           `json:"network_calls"`
	PackageName   string        `json:"package_name"`
	Success       bool          `json:"success"`
	ErrorMessage  string        `json:"error_message,omitempty"`
}

// BatchMetrics holds batch scanning performance results
type BatchMetrics struct {
	TotalTime     time.Duration `json:"total_time"`
	PackageCount  int           `json:"package_count"`
	SuccessCount  int           `json:"success_count"`
	FailureCount  int           `json:"failure_count"`
	AvgTimePerPkg time.Duration `json:"avg_time_per_package"`
	PeakMemory    int64         `json:"peak_memory_mb"`
	Concurrency   int           `json:"concurrency"`
}

// TestP001_1_SinglePackagePerformance tests individual package scan performance
func TestP001_1_SinglePackagePerformance(t *testing.T) {
	testPackages := []string{
		"lodash",        // Small package
		"express",       // Medium package
		"webpack",       // Large package
		"@angular/core", // Monorepo package
	}

	for _, pkg := range testPackages {
		t.Run(fmt.Sprintf("Package_%s", strings.ReplaceAll(pkg, "/", "_")), func(t *testing.T) {
			metrics := measureSinglePackagePerformance(pkg)
			
			// Log results
			logPerformanceMetrics(t, metrics)
			
			// Validate performance requirements
			if metrics.ScanTime > 2*time.Second {
				t.Errorf("Scan time %v exceeds 2 second limit for package %s", metrics.ScanTime, pkg)
			}
			
			if metrics.MemoryUsage > 100 {
				t.Errorf("Memory usage %d MB exceeds 100MB limit for package %s", metrics.MemoryUsage, pkg)
			}
			
			if metrics.CPUUsage > 50.0 {
				t.Errorf("CPU usage %.2f%% exceeds 50%% limit for package %s", metrics.CPUUsage, pkg)
			}
			
			if !metrics.Success {
				t.Errorf("Scan failed for package %s: %s", pkg, metrics.ErrorMessage)
			}
		})
	}
}

// TestP001_2_BatchScanningPerformance tests batch scanning performance
func TestP001_2_BatchScanningPerformance(t *testing.T) {
	batchSizes := []int{10, 100}
	
	for _, size := range batchSizes {
		t.Run(fmt.Sprintf("Batch_%d_packages", size), func(t *testing.T) {
			metrics := measureBatchPerformance(size)
			
			// Log results
			logBatchMetrics(t, metrics)
			
			// Validate performance requirements
			if size == 100 {
				if metrics.TotalTime > 30*time.Second {
					t.Errorf("Batch scan time %v exceeds 30 second limit for 100 packages", metrics.TotalTime)
				}
				
				if metrics.PeakMemory > 1024 {
					t.Errorf("Peak memory usage %d MB exceeds 1GB limit for 100 packages", metrics.PeakMemory)
				}
			}
			
			if metrics.FailureCount > 0 {
				t.Logf("Warning: %d packages failed out of %d", metrics.FailureCount, size)
			}
		})
	}
}

// TestP001_2_StressTest performs stress testing with 1000 packages
func TestP001_2_StressTest(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stress test in short mode")
	}
	
	t.Run("Stress_1000_packages", func(t *testing.T) {
		metrics := measureBatchPerformance(1000)
		
		// Log results
		logBatchMetrics(t, metrics)
		
		// Check for memory leaks and stability
		if metrics.PeakMemory > 2048 {
			t.Errorf("Peak memory usage %d MB exceeds 2GB limit for stress test", metrics.PeakMemory)
		}
		
		if float64(metrics.FailureCount)/float64(metrics.PackageCount) > 0.05 {
			t.Errorf("Failure rate %.2f%% exceeds 5%% threshold", float64(metrics.FailureCount)/float64(metrics.PackageCount)*100)
		}
	})
}

// measureSinglePackagePerformance measures performance for a single package scan
func measureSinglePackagePerformance(packageName string) PerformanceMetrics {
	var m runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m)
	
	startTime := time.Now()
	
	// Execute scan command
	cmd := exec.Command("go", "run", "main.go", "scan", packageName, "--format", "json")
	cmd.Dir = "/Users/alikorsi/Documents/Typosentinel"
	
	output, err := cmd.CombinedOutput()
	scanTime := time.Since(startTime)
	
	runtime.ReadMemStats(&m)
	memoryUsed := int64(m.Alloc / 1024 / 1024) // Convert to MB
	
	metrics := PerformanceMetrics{
		ScanTime:     scanTime,
		MemoryUsage:  memoryUsed,
		CPUUsage:     getCPUUsage(),
		NetworkCalls: countNetworkCalls(string(output)),
		PackageName:  packageName,
		Success:      err == nil,
	}
	
	if err != nil {
		metrics.ErrorMessage = err.Error()
	}
	
	return metrics
}

// measureBatchPerformance measures performance for batch scanning
func measureBatchPerformance(packageCount int) BatchMetrics {
	packages := generateTestPackages(packageCount)
	
	var m runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m)
	
	startTime := time.Now()
	var wg sync.WaitGroup
	var mu sync.Mutex
	successCount := 0
	failureCount := 0
	peakMemory := int64(0)
	
	// Use reasonable concurrency
	concurrency := min(10, packageCount)
	semaphore := make(chan struct{}, concurrency)
	
	for _, pkg := range packages {
		wg.Add(1)
		go func(packageName string) {
			defer wg.Done()
			semaphore <- struct{}{} // Acquire
			defer func() { <-semaphore }() // Release
			
			cmd := exec.Command("go", "run", "main.go", "scan", packageName, "--format", "json")
			cmd.Dir = "/Users/alikorsi/Documents/Typosentinel"
			
			_, err := cmd.CombinedOutput()
			
			mu.Lock()
			if err == nil {
				successCount++
			} else {
				failureCount++
			}
			
			// Check memory usage
			runtime.ReadMemStats(&m)
			currentMemory := int64(m.Alloc / 1024 / 1024)
			if currentMemory > peakMemory {
				peakMemory = currentMemory
			}
			mu.Unlock()
		}(pkg)
	}
	
	wg.Wait()
	totalTime := time.Since(startTime)
	
	return BatchMetrics{
		TotalTime:     totalTime,
		PackageCount:  packageCount,
		SuccessCount:  successCount,
		FailureCount:  failureCount,
		AvgTimePerPkg: totalTime / time.Duration(packageCount),
		PeakMemory:    peakMemory,
		Concurrency:   concurrency,
	}
}

// generateTestPackages generates a list of test packages
func generateTestPackages(count int) []string {
	basePackages := []string{
		"lodash", "express", "react", "vue", "angular",
		"webpack", "babel", "eslint", "typescript", "jest",
		"moment", "axios", "underscore", "jquery", "bootstrap",
		"chalk", "commander", "inquirer", "yargs", "debug",
	}
	
	packages := make([]string, 0, count)
	for i := 0; i < count; i++ {
		pkg := basePackages[i%len(basePackages)]
		if i >= len(basePackages) {
			// Add version suffix for uniqueness
			pkg = fmt.Sprintf("%s@%d.0.0", pkg, i/len(basePackages)+1)
		}
		packages = append(packages, pkg)
	}
	
	return packages
}

// getCPUUsage returns approximate CPU usage (simplified)
func getCPUUsage() float64 {
	// This is a simplified CPU usage calculation
	// In a real implementation, you'd want more accurate CPU monitoring
	return float64(runtime.NumGoroutine()) * 2.5 // Rough approximation
}

// countNetworkCalls counts network calls from command output
func countNetworkCalls(output string) int {
	// Count HTTP requests, API calls, etc. from verbose output
	count := 0
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "HTTP") || strings.Contains(line, "API") || strings.Contains(line, "request") {
			count++
		}
	}
	return count
}

// logPerformanceMetrics logs performance metrics
func logPerformanceMetrics(t *testing.T, metrics PerformanceMetrics) {
	jsonData, _ := json.MarshalIndent(metrics, "", "  ")
	t.Logf("Performance Metrics for %s:\n%s", metrics.PackageName, string(jsonData))
}

// logBatchMetrics logs batch performance metrics
func logBatchMetrics(t *testing.T, metrics BatchMetrics) {
	jsonData, _ := json.MarshalIndent(metrics, "", "  ")
	t.Logf("Batch Performance Metrics:\n%s", string(jsonData))
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// BenchmarkSinglePackageScan benchmarks single package scanning
func BenchmarkSinglePackageScan(b *testing.B) {
	packages := []string{"lodash", "express", "webpack"}
	
	for _, pkg := range packages {
		b.Run(pkg, func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				cmd := exec.Command("go", "run", "main.go", "scan", pkg, "--format", "json")
				cmd.Dir = "/Users/alikorsi/Documents/Typosentinel"
				_, err := cmd.CombinedOutput()
				if err != nil {
					b.Errorf("Scan failed for %s: %v", pkg, err)
				}
			}
		})
	}
}

// BenchmarkBatchScanning benchmarks batch scanning
func BenchmarkBatchScanning(b *testing.B) {
	batchSizes := []int{10, 50, 100}
	
	for _, size := range batchSizes {
		b.Run(fmt.Sprintf("Batch_%d", size), func(b *testing.B) {
			packages := generateTestPackages(size)
			b.ResetTimer()
			
			for i := 0; i < b.N; i++ {
				var wg sync.WaitGroup
				semaphore := make(chan struct{}, 5) // Limit concurrency
				
				for _, pkg := range packages {
					wg.Add(1)
					go func(packageName string) {
						defer wg.Done()
						semaphore <- struct{}{}
						defer func() { <-semaphore }()
						
						cmd := exec.Command("go", "run", "main.go", "scan", packageName, "--format", "json")
				cmd.Dir = "/Users/alikorsi/Documents/Typosentinel"
						_, _ = cmd.CombinedOutput()
					}(pkg)
				}
				
				wg.Wait()
			}
		})
	}
}