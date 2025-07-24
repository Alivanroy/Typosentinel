package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/dynamic"
)

func main() {
	fmt.Printf("🚀 TypoSentinel Dynamic Analyzer - Stress Test Suite\n")
	fmt.Printf("===================================================\n\n")

	// Test configurations
	configs := []*dynamic.Config{
		// Light load configuration
		{
			Enabled:                true,
			SandboxType:            "docker",
			SandboxImage:           "node:16-alpine",
			SandboxTimeout:         "30s",
			MaxConcurrentSandboxes: 2,
			AnalyzeInstallScripts:  true,
			AnalyzeNetworkActivity: true,
			AnalyzeFileSystem:      true,
			AnalyzeProcesses:       true,
			AnalyzeEnvironment:     true,
			MaxExecutionTime:       "15s",
			MaxMemoryUsage:         128 * 1024 * 1024, // 128MB
			MaxDiskUsage:           256 * 1024 * 1024, // 256MB
			MaxNetworkConnections:  5,
			MonitoringInterval:     "1s",
			Verbose:                false,
			LogLevel:               "info",
		},
		// Heavy load configuration
		{
			Enabled:                true,
			SandboxType:            "docker",
			SandboxImage:           "node:16-alpine",
			SandboxTimeout:         "60s",
			MaxConcurrentSandboxes: 5,
			AnalyzeInstallScripts:  true,
			AnalyzeNetworkActivity: true,
			AnalyzeFileSystem:      true,
			AnalyzeProcesses:       true,
			AnalyzeEnvironment:     true,
			MaxExecutionTime:       "30s",
			MaxMemoryUsage:         512 * 1024 * 1024,  // 512MB
			MaxDiskUsage:           1024 * 1024 * 1024, // 1GB
			MaxNetworkConnections:  20,
			MonitoringInterval:     "500ms",
			Verbose:                true,
			LogLevel:               "debug",
		},
	}

	// Run stress tests
	for i, config := range configs {
		configName := []string{"Light Load", "Heavy Load"}[i]
		fmt.Printf("🔬 Testing Configuration: %s\n", configName)
		fmt.Printf("----------------------------------------\n")
		
		if err := runStressTest(config, configName); err != nil {
			log.Printf("❌ Stress test failed for %s: %v\n", configName, err)
		} else {
			fmt.Printf("✅ Stress test completed for %s\n\n", configName)
		}
	}

	// Run concurrent analysis test
	fmt.Printf("🔄 Running Concurrent Analysis Test\n")
	fmt.Printf("===================================\n")
	if err := runConcurrentTest(); err != nil {
		log.Printf("❌ Concurrent test failed: %v\n", err)
	} else {
		fmt.Printf("✅ Concurrent test completed successfully\n\n")
	}

	// Run memory stress test
	fmt.Printf("💾 Running Memory Stress Test\n")
	fmt.Printf("=============================\n")
	if err := runMemoryStressTest(); err != nil {
		log.Printf("❌ Memory stress test failed: %v\n", err)
	} else {
		fmt.Printf("✅ Memory stress test completed successfully\n\n")
	}

	// Run performance benchmark
	fmt.Printf("⚡ Running Performance Benchmark\n")
	fmt.Printf("================================\n")
	if err := runPerformanceBenchmark(); err != nil {
		log.Printf("❌ Performance benchmark failed: %v\n", err)
	} else {
		fmt.Printf("✅ Performance benchmark completed successfully\n\n")
	}

	fmt.Printf("🎉 All stress tests completed!\n")
}

func runStressTest(config *dynamic.Config, configName string) error {
	analyzer, err := dynamic.NewDynamicAnalyzer(config)
	if err != nil {
		return fmt.Errorf("failed to create analyzer: %w", err)
	}

	// Create test packages
	testPackages := []string{"stress-test-1", "stress-test-2", "stress-test-3"}
	
	for _, packageName := range testPackages {
		testDir := filepath.Join("stress-test-results", packageName)
		if err := createTestPackage(testDir, packageName); err != nil {
			return fmt.Errorf("failed to create test package %s: %w", packageName, err)
		}

		// Measure analysis time
		startTime := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		
		result, err := analyzer.AnalyzePackage(ctx, testDir)
		cancel()
		
		duration := time.Since(startTime)
		
		if err != nil {
			fmt.Printf("   ⚠️  Package %s analysis failed: %v (took %v)\n", packageName, err, duration)
		} else {
			fmt.Printf("   ✅ Package %s analyzed successfully (took %v, risk: %.2f)\n", 
				packageName, duration, result.RiskScore)
		}
	}

	return nil
}

func runConcurrentTest() error {
	config := &dynamic.Config{
		Enabled:                true,
		SandboxType:            "docker",
		SandboxImage:           "node:16-alpine",
		SandboxTimeout:         "45s",
		MaxConcurrentSandboxes: 3,
		AnalyzeInstallScripts:  true,
		AnalyzeNetworkActivity: true,
		AnalyzeFileSystem:      true,
		AnalyzeProcesses:       true,
		AnalyzeEnvironment:     true,
		MaxExecutionTime:       "20s",
		MaxMemoryUsage:         256 * 1024 * 1024, // 256MB
		MaxDiskUsage:           512 * 1024 * 1024, // 512MB
		MaxNetworkConnections:  10,
		MonitoringInterval:     "1s",
		Verbose:                false,
		LogLevel:               "info",
	}

	analyzer, err := dynamic.NewDynamicAnalyzer(config)
	if err != nil {
		return fmt.Errorf("failed to create analyzer: %w", err)
	}

	// Create multiple test packages
	numPackages := 5
	var wg sync.WaitGroup
	results := make(chan string, numPackages)
	errors := make(chan error, numPackages)

	startTime := time.Now()

	for i := 0; i < numPackages; i++ {
		wg.Add(1)
		go func(packageIndex int) {
			defer wg.Done()
			
			packageName := fmt.Sprintf("concurrent-test-%d", packageIndex)
			testDir := filepath.Join("stress-test-results", packageName)
			
			if err := createTestPackage(testDir, packageName); err != nil {
				errors <- fmt.Errorf("failed to create package %s: %w", packageName, err)
				return
			}

			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()
			
			analysisStart := time.Now()
			result, err := analyzer.AnalyzePackage(ctx, testDir)
			analysisDuration := time.Since(analysisStart)
			
			if err != nil {
				errors <- fmt.Errorf("analysis failed for %s: %w", packageName, err)
				return
			}
			
			results <- fmt.Sprintf("Package %s: %.2f risk, %v duration", 
				packageName, result.RiskScore, analysisDuration)
		}(i)
	}

	wg.Wait()
	close(results)
	close(errors)

	totalDuration := time.Since(startTime)

	// Report results
	fmt.Printf("   📊 Concurrent Analysis Results (Total: %v)\n", totalDuration)
	for result := range results {
		fmt.Printf("   ✅ %s\n", result)
	}

	// Report errors
	errorCount := 0
	for err := range errors {
		fmt.Printf("   ❌ %v\n", err)
		errorCount++
	}

	if errorCount > 0 {
		return fmt.Errorf("%d out of %d concurrent analyses failed", errorCount, numPackages)
	}

	return nil
}

func runMemoryStressTest() error {
	config := &dynamic.Config{
		Enabled:                true,
		SandboxType:            "docker",
		SandboxImage:           "node:16-alpine",
		SandboxTimeout:         "30s",
		MaxConcurrentSandboxes: 1,
		AnalyzeInstallScripts:  true,
		AnalyzeNetworkActivity: true,
		AnalyzeFileSystem:      true,
		AnalyzeProcesses:       true,
		AnalyzeEnvironment:     true,
		MaxExecutionTime:       "15s",
		MaxMemoryUsage:         64 * 1024 * 1024,  // 64MB - low memory
		MaxDiskUsage:           128 * 1024 * 1024, // 128MB
		MaxNetworkConnections:  5,
		MonitoringInterval:     "500ms",
		Verbose:                false,
		LogLevel:               "info",
	}

	analyzer, err := dynamic.NewDynamicAnalyzer(config)
	if err != nil {
		return fmt.Errorf("failed to create analyzer: %w", err)
	}

	// Create a package with memory-intensive operations
	testDir := filepath.Join("stress-test-results", "memory-stress")
	if err := createMemoryStressPackage(testDir); err != nil {
		return fmt.Errorf("failed to create memory stress package: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	startTime := time.Now()
	result, err := analyzer.AnalyzePackage(ctx, testDir)
	duration := time.Since(startTime)

	if err != nil {
		fmt.Printf("   ⚠️  Memory stress test completed with error: %v (took %v)\n", err, duration)
		// This might be expected due to memory constraints
	} else {
		fmt.Printf("   ✅ Memory stress test completed successfully (took %v, risk: %.2f)\n", 
			duration, result.RiskScore)
	}

	return nil
}

func runPerformanceBenchmark() error {
	config := &dynamic.Config{
		Enabled:                true,
		SandboxType:            "docker",
		SandboxImage:           "node:16-alpine",
		SandboxTimeout:         "30s",
		MaxConcurrentSandboxes: 2,
		AnalyzeInstallScripts:  true,
		AnalyzeNetworkActivity: true,
		AnalyzeFileSystem:      true,
		AnalyzeProcesses:       true,
		AnalyzeEnvironment:     true,
		MaxExecutionTime:       "15s",
		MaxMemoryUsage:         256 * 1024 * 1024, // 256MB
		MaxDiskUsage:           512 * 1024 * 1024, // 512MB
		MaxNetworkConnections:  10,
		MonitoringInterval:     "1s",
		Verbose:                false,
		LogLevel:               "info",
	}

	analyzer, err := dynamic.NewDynamicAnalyzer(config)
	if err != nil {
		return fmt.Errorf("failed to create analyzer: %w", err)
	}

	// Benchmark different package sizes
	benchmarks := []struct {
		name     string
		fileSize string
		expected time.Duration
	}{
		{"Small Package", "small", 5 * time.Second},
		{"Medium Package", "medium", 15 * time.Second},
		{"Large Package", "large", 30 * time.Second},
	}

	fmt.Printf("   📈 Performance Benchmark Results:\n")
	fmt.Printf("   %-15s %-12s %-12s %-10s\n", "Package Size", "Duration", "Expected", "Status")
	fmt.Printf("   %s\n", "-------------------------------------------------------")

	for _, benchmark := range benchmarks {
		testDir := filepath.Join("stress-test-results", "benchmark-"+benchmark.fileSize)
		if err := createBenchmarkPackage(testDir, benchmark.fileSize); err != nil {
			return fmt.Errorf("failed to create benchmark package: %w", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		
		startTime := time.Now()
		result, err := analyzer.AnalyzePackage(ctx, testDir)
		duration := time.Since(startTime)
		cancel()

		status := "✅ PASS"
		if err != nil {
			status = "❌ FAIL"
		} else if duration > benchmark.expected {
			status = "⚠️  SLOW"
		}

		fmt.Printf("   %-15s %-12v %-12v %-10s", 
			benchmark.name, duration.Round(time.Millisecond), 
			benchmark.expected, status)
		
		if err == nil {
			fmt.Printf(" (Risk: %.2f)", result.RiskScore)
		}
		fmt.Printf("\n")
	}

	return nil
}

func createTestPackage(testDir, packageName string) error {
	if err := os.MkdirAll(testDir, 0755); err != nil {
		return err
	}

	// Create package.json
	packageJSON := fmt.Sprintf(`{
  "name": "%s",
  "version": "1.0.0",
  "description": "Stress test package for dynamic analysis",
  "main": "index.js",
  "scripts": {
    "install": "node install.js",
    "postinstall": "echo 'Package installed successfully'"
  },
  "dependencies": {},
  "author": "TypoSentinel Test Suite",
  "license": "MIT"
}`, packageName)

	if err := os.WriteFile(filepath.Join(testDir, "package.json"), []byte(packageJSON), 0644); err != nil {
		return err
	}

	// Create index.js
	indexJS := `console.log('Hello from stress test package');
module.exports = {
  test: function() {
    return 'Test function executed';
  }
};`

	if err := os.WriteFile(filepath.Join(testDir, "index.js"), []byte(indexJS), 0644); err != nil {
		return err
	}

	// Create install.js
	installJS := `console.log('Running install script...');
const fs = require('fs');
const path = require('path');

// Simulate some file operations
try {
  fs.writeFileSync('/tmp/test-install.txt', 'Install script executed');
  console.log('Install script completed successfully');
} catch (error) {
  console.log('Install script completed with limited permissions');
}`

	return os.WriteFile(filepath.Join(testDir, "install.js"), []byte(installJS), 0644)
}

func createMemoryStressPackage(testDir string) error {
	if err := os.MkdirAll(testDir, 0755); err != nil {
		return err
	}

	// Create package.json
	packageJSON := `{
  "name": "memory-stress-test",
  "version": "1.0.0",
  "description": "Memory stress test package",
  "main": "index.js",
  "scripts": {
    "install": "node install.js"
  },
  "author": "TypoSentinel Test Suite",
  "license": "MIT"
}`

	if err := os.WriteFile(filepath.Join(testDir, "package.json"), []byte(packageJSON), 0644); err != nil {
		return err
	}

	// Create memory-intensive install.js
	installJS := `console.log('Running memory stress test...');

// Create large arrays to stress memory
let memoryArrays = [];
for (let i = 0; i < 10; i++) {
  try {
    // Create 1MB arrays
    memoryArrays.push(new Array(1024 * 256).fill('x'));
    console.log('Created memory array', i + 1);
  } catch (error) {
    console.log('Memory limit reached at array', i + 1);
    break;
  }
}

console.log('Memory stress test completed');`

	return os.WriteFile(filepath.Join(testDir, "install.js"), []byte(installJS), 0644)
}

func createBenchmarkPackage(testDir, size string) error {
	if err := os.MkdirAll(testDir, 0755); err != nil {
		return err
	}

	// Create package.json
	packageJSON := fmt.Sprintf(`{
  "name": "benchmark-%s-package",
  "version": "1.0.0",
  "description": "Benchmark %s package",
  "main": "index.js",
  "scripts": {
    "install": "node install.js"
  },
  "author": "TypoSentinel Test Suite",
  "license": "MIT"
}`, size, size)

	if err := os.WriteFile(filepath.Join(testDir, "package.json"), []byte(packageJSON), 0644); err != nil {
		return err
	}

	// Create install.js with different complexities
	var installJS string
	switch size {
	case "small":
		installJS = `console.log('Small package install');
setTimeout(() => console.log('Install completed'), 100);`
	case "medium":
		installJS = `console.log('Medium package install');
for (let i = 0; i < 1000; i++) {
  if (i % 100 === 0) console.log('Processing...', i);
}
console.log('Install completed');`
	case "large":
		installJS = `console.log('Large package install');
const fs = require('fs');

// Simulate complex operations
for (let i = 0; i < 5000; i++) {
  if (i % 500 === 0) console.log('Processing...', i);
  // Simulate some CPU work
  Math.sqrt(i * 1000);
}

// Simulate file operations
try {
  for (let i = 0; i < 10; i++) {
    fs.writeFileSync('/tmp/benchmark-' + i + '.txt', 'test data ' + i);
  }
} catch (error) {
  console.log('File operations completed with limited permissions');
}

console.log('Large package install completed');`
	}

	return os.WriteFile(filepath.Join(testDir, "install.js"), []byte(installJS), 0644)
}