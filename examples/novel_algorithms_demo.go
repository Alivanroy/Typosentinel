package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/ml"
	"github.com/Alivanroy/Typosentinel/pkg/logger"
	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// DemoLogger implements a simple logger for demonstration
type DemoLogger struct{}

func (dl *DemoLogger) Debug(msg string, keysAndValues ...interface{}) {
	fmt.Printf("[DEBUG] %s\n", msg)
	for i := 0; i < len(keysAndValues); i += 2 {
		if i+1 < len(keysAndValues) {
			fmt.Printf("  %v: %v\n", keysAndValues[i], keysAndValues[i+1])
		}
	}
}

func (dl *DemoLogger) Info(msg string, keysAndValues ...interface{}) {
	fmt.Printf("[INFO] %s\n", msg)
	for i := 0; i < len(keysAndValues); i += 2 {
		if i+1 < len(keysAndValues) {
			fmt.Printf("  %v: %v\n", keysAndValues[i], keysAndValues[i+1])
		}
	}
}

func (dl *DemoLogger) Warn(msg string, keysAndValues ...interface{}) {
	fmt.Printf("[WARN] %s\n", msg)
	for i := 0; i < len(keysAndValues); i += 2 {
		if i+1 < len(keysAndValues) {
			fmt.Printf("  %v: %v\n", keysAndValues[i], keysAndValues[i+1])
		}
	}
}

func (dl *DemoLogger) Error(msg string, keysAndValues ...interface{}) {
	fmt.Printf("[ERROR] %s\n", msg)
	for i := 0; i < len(keysAndValues); i += 2 {
		if i+1 < len(keysAndValues) {
			fmt.Printf("  %v: %v\n", keysAndValues[i], keysAndValues[i+1])
		}
	}
}

func (dl *DemoLogger) With(keysAndValues ...interface{}) logger.Logger {
	return dl
}

// MockClassicDetector simulates the existing classic ML detector
type MockClassicDetector struct{}

type ClassicResult struct {
	PackageID       string
	ThreatScore     float64
	Confidence      float64
	ThreatLevel     string
	Recommendations []string
	AnalysisTime    time.Duration
}

func (mcd *MockClassicDetector) AnalyzePackage(ctx context.Context, pkg *types.Package) (*ClassicResult, error) {
	if pkg == nil {
		return nil, fmt.Errorf("package cannot be nil")
	}

	// Simulate classic ML analysis
	start := time.Now()
	time.Sleep(time.Millisecond * 50) // Simulate processing time

	result := &ClassicResult{
		PackageID:   pkg.Name,
		ThreatScore: 0.4, // Default moderate-low threat
		Confidence:  0.75,
		ThreatLevel: "MEDIUM",
		Recommendations: []string{"Monitor package activity", "Check author reputation"},
		AnalysisTime: time.Since(start),
	}

	// Adjust based on package characteristics
	if len(pkg.Dependencies) > 50 {
		result.ThreatScore += 0.2
		result.ThreatLevel = "HIGH"
		result.Recommendations = append(result.Recommendations, "Review large dependency tree")
	}

	if pkg.Name == "malicious-package" || pkg.Description == "Suspicious behavior detected" {
		result.ThreatScore = 0.95
		result.ThreatLevel = "CRITICAL"
		result.Recommendations = []string{"Block package immediately", "Report to security team", "Investigate author"}
	}

	return result, nil
}

// Demo packages for testing
func createDemoPackages() []*types.Package {
	return []*types.Package{
		{
			Name:        "safe-utility",
			Description: "A safe utility package for common operations",
			Version:     "1.2.3",
			Dependencies: []string{"lodash", "moment", "axios"},
			Registry:    "npm",
			Author:      "trusted-developer",
			License:     "MIT",
		},
		{
			Name:        "complex-framework",
			Description: "A complex framework with many dependencies",
			Version:     "2.0.0",
			Dependencies: generateDependencies(75), // Large dependency tree
			Registry:    "npm",
			Author:      "framework-team",
			License:     "Apache-2.0",
		},
		{
			Name:        "malicious-package",
			Description: "Suspicious behavior detected",
			Version:     "0.1.0",
			Dependencies: []string{"crypto", "fs", "child_process"},
			Registry:    "npm",
			Author:      "unknown-user",
			License:     "UNLICENSED",
		},
		{
			Name:        "typosquatting-lodash",
			Description: "A utility library similar to lodash",
			Version:     "4.17.21",
			Dependencies: []string{},
			Registry:    "npm",
			Author:      "fake-maintainer",
			License:     "MIT",
		},
		{
			Name:        "ai-ml-package",
			Description: "Advanced AI/ML package with sophisticated algorithms",
			Version:     "3.1.4",
			Dependencies: generateDependencies(120), // Very large dependency tree
			Registry:    "pypi",
			Author:      "ai-research-lab",
			License:     "BSD-3-Clause",
		},
	}
}

func generateDependencies(count int) []string {
	deps := make([]string, count)
	for i := 0; i < count; i++ {
		deps[i] = fmt.Sprintf("dependency-%d", i+1)
	}
	return deps
}

// Demo configuration
func createDemoNovelConfig() *ml.NovelAlgorithmConfig {
	return &ml.NovelAlgorithmConfig{
		QuantumInspiredEnabled:      true,
		GraphAttentionEnabled:       true,
		AdversarialDetectionEnabled: true,
		TransformerEnabled:          true,
		FederatedLearningEnabled:    true,
		CausalInferenceEnabled:      true,
		MetaLearningEnabled:         true,
		SwarmOptimizationEnabled:    true,
		NeuroEvolutionEnabled:       true,
		QuantumMLEnabled:            true,
		LearningRate:                0.001,
		BatchSize:                   32,
		Epochs:                      100,
		Regularization:              0.01,
		DropoutRate:                 0.2,
	}
}

func createDemoIntegrationConfig() *ml.NovelIntegrationConfig {
	return &ml.NovelIntegrationConfig{
		Enabled:           true,
		Strategy:          "adaptive",
		NovelWeight:       0.6,
		ClassicWeight:     0.4,
		AdaptiveThreshold: 0.7,
		PerformanceThresholds: &ml.PerformanceThresholds{
			LatencyMs:        5000,
			Accuracy:         0.85,
			Precision:        0.8,
			Recall:           0.8,
			F1Score:          0.8,
			ThroughputPerSec: 100,
		},
		Caching: &ml.CachingConfig{
			Enabled:    true,
			TTLMinutes: 60,
			MaxSize:    1000,
		},
		Monitoring: &ml.MonitoringConfig{
			Enabled:             true,
			MetricsInterval:     60,
			HealthCheckInterval: 30,
			AlertThresholds: map[string]float64{
				"error_rate":   0.05,
				"latency_p95":  3000,
				"memory_usage": 0.8,
				"cpu_usage":    0.7,
			},
		},
		MaxConcurrentAnalyses: 10,
		TimeoutSeconds:        30,
		RetryAttempts:         3,
		CircuitBreakerConfig: map[string]interface{}{
			"failure_threshold":  5,
			"recovery_timeout":   60,
			"half_open_requests": 3,
		},
	}
}

// Pretty print results
func printAnalysisResult(result *ml.IntegratedAnalysisResult) {
	fmt.Println("\n" + "="*80)
	fmt.Printf("PACKAGE ANALYSIS RESULT: %s\n", result.PackageID)
	fmt.Println("="*80)

	fmt.Printf("Strategy Used: %s\n", result.Strategy)
	fmt.Printf("Final Threat Score: %.3f\n", result.FinalScore)
	fmt.Printf("Final Threat Level: %s\n", result.FinalThreatLevel)
	fmt.Printf("Analysis Time: %v\n", result.Performance.TotalLatency)

	if result.NovelResult != nil {
		fmt.Println("\n--- NOVEL ALGORITHMS ANALYSIS ---")
		fmt.Printf("Ensemble Score: %.3f\n", result.NovelResult.EnsembleScore)
		fmt.Printf("Confidence: %.3f\n", result.NovelResult.Confidence)
		fmt.Printf("Threat Level: %s\n", result.NovelResult.ThreatLevel)
		fmt.Printf("Algorithms Used: %d\n", len(result.NovelResult.Algorithms))

		fmt.Println("\nAlgorithm Scores:")
		for name, algResult := range result.NovelResult.Algorithms {
			fmt.Printf("  %s: %.3f (confidence: %.3f)\n", name, algResult.Score, algResult.Confidence)
		}
	}

	if result.ClassicResult != nil {
		fmt.Println("\n--- CLASSIC ML ANALYSIS ---")
		fmt.Printf("Threat Score: %.3f\n", result.ClassicResult.ThreatScore)
		fmt.Printf("Confidence: %.3f\n", result.ClassicResult.Confidence)
		fmt.Printf("Threat Level: %s\n", result.ClassicResult.ThreatLevel)
		fmt.Printf("Analysis Time: %v\n", result.ClassicResult.AnalysisTime)
	}

	fmt.Println("\n--- RECOMMENDATIONS ---")
	for i, rec := range result.FinalRecommendations {
		fmt.Printf("%d. %s\n", i+1, rec)
	}

	if result.DetailedExplanation != nil {
		fmt.Println("\n--- DETAILED EXPLANATION ---")
		fmt.Printf("Summary: %s\n", result.DetailedExplanation.Summary)
		fmt.Printf("Reasoning: %s\n", result.DetailedExplanation.Reasoning)

		if len(result.DetailedExplanation.RiskFactors) > 0 {
			fmt.Println("\nRisk Factors:")
			for _, factor := range result.DetailedExplanation.RiskFactors {
				fmt.Printf("  - %s (Impact: %.2f, Confidence: %.2f)\n", 
					factor.Factor, factor.Impact, factor.Confidence)
				fmt.Printf("    %s\n", factor.Description)
			}
		}
	}

	fmt.Println("\n--- PERFORMANCE METRICS ---")
	fmt.Printf("Total Latency: %v\n", result.Performance.TotalLatency)
	fmt.Printf("Novel Analysis Time: %v\n", result.Performance.NovelAnalysisTime)
	fmt.Printf("Classic Analysis Time: %v\n", result.Performance.ClassicAnalysisTime)
	fmt.Printf("Cache Hit: %t\n", result.Performance.CacheHit)
	fmt.Printf("Memory Usage: %.2f MB\n", float64(result.Performance.MemoryUsageBytes)/(1024*1024))

	fmt.Println("\n" + "="*80)
}

func printMetrics(metrics map[string]interface{}) {
	fmt.Println("\n" + "-"*60)
	fmt.Println("SYSTEM METRICS")
	fmt.Println("-"*60)

	for key, value := range metrics {
		fmt.Printf("%s: %v\n", key, value)
	}
	fmt.Println("-"*60)
}

func demonstrateNovelAlgorithms() {
	fmt.Println("🚀 TypoSentinel Novel Algorithms Demonstration")
	fmt.Println("=============================================")

	// Initialize logger
	logger := &DemoLogger{}

	// Create novel algorithm suite
	novelConfig := createDemoNovelConfig()
	novelSuite := ml.NewNovelAlgorithmSuite(novelConfig, logger)

	// Create mock classic detector
	classicDetector := &MockClassicDetector{}

	// Create integration layer
	integrationConfig := createDemoIntegrationConfig()
	integrator := ml.NewNovelMLIntegrator(integrationConfig, novelSuite, classicDetector, logger)

	// Get demo packages
	packages := createDemoPackages()

	fmt.Printf("\n📦 Analyzing %d packages with novel algorithms...\n", len(packages))

	ctx := context.Background()

	// Analyze each package
	for i, pkg := range packages {
		fmt.Printf("\n[%d/%d] Analyzing package: %s\n", i+1, len(packages), pkg.Name)
		fmt.Printf("Description: %s\n", pkg.Description)
		fmt.Printf("Dependencies: %d\n", len(pkg.Dependencies))

		start := time.Now()
		result, err := integrator.AnalyzePackage(ctx, pkg)
		analysisTime := time.Since(start)

		if err != nil {
			fmt.Printf("❌ Error analyzing package %s: %v\n", pkg.Name, err)
			continue
		}

		fmt.Printf("✅ Analysis completed in %v\n", analysisTime)
		printAnalysisResult(result)

		// Add a small delay between analyses for demonstration
		time.Sleep(time.Millisecond * 500)
	}

	// Demonstrate different strategies
	fmt.Println("\n🔄 Demonstrating Different Analysis Strategies")
	fmt.Println("=============================================")

	testPkg := packages[1] // Use the complex framework
	strategies := []string{"novel_only", "classic_only", "hybrid", "adaptive"}

	for _, strategy := range strategies {
		fmt.Printf("\n--- Testing Strategy: %s ---\n", strategy)

		// Update configuration
		newConfig := createDemoIntegrationConfig()
		newConfig.Strategy = strategy
		integrator.UpdateConfiguration(newConfig)

		start := time.Now()
		result, err := integrator.AnalyzePackage(ctx, testPkg)
		analysisTime := time.Since(start)

		if err != nil {
			fmt.Printf("❌ Error with strategy %s: %v\n", strategy, err)
			continue
		}

		fmt.Printf("Strategy: %s | Score: %.3f | Level: %s | Time: %v\n",
			result.Strategy, result.FinalScore, result.FinalThreatLevel, analysisTime)
	}

	// Show system metrics
	fmt.Println("\n📊 System Performance Metrics")
	fmt.Println("=============================")
	metrics := integrator.GetMetrics()
	printMetrics(metrics)

	// Health check
	fmt.Println("\n🏥 System Health Check")
	fmt.Println("=====================")
	health := integrator.HealthCheck()
	healthJSON, _ := json.MarshalIndent(health, "", "  ")
	fmt.Println(string(healthJSON))

	// Demonstrate concurrent analysis
	fmt.Println("\n⚡ Concurrent Analysis Demonstration")
	fmt.Println("===================================")

	const numConcurrent = 5
	resultChan := make(chan *ml.IntegratedAnalysisResult, numConcurrent)
	errorChan := make(chan error, numConcurrent)

	start := time.Now()
	for i := 0; i < numConcurrent; i++ {
		go func(id int) {
			pkg := &types.Package{
				Name:        fmt.Sprintf("concurrent-test-%d", id),
				Description: fmt.Sprintf("Concurrent analysis test package %d", id),
				Version:     "1.0.0",
				Dependencies: generateDependencies(10 + id*5),
				Registry:    "npm",
				Author:      "test-author",
				License:     "MIT",
			}

			result, err := integrator.AnalyzePackage(ctx, pkg)
			if err != nil {
				errorChan <- err
			} else {
				resultChan <- result
			}
		}(i)
	}

	// Collect results
	successCount := 0
	errorCount := 0
	for i := 0; i < numConcurrent; i++ {
		select {
		case result := <-resultChan:
			successCount++
			fmt.Printf("✅ %s: %.3f (%s)\n", result.PackageID, result.FinalScore, result.FinalThreatLevel)
		case err := <-errorChan:
			errorCount++
			fmt.Printf("❌ Error: %v\n", err)
		case <-time.After(time.Second * 10):
			fmt.Println("⏰ Timeout waiting for result")
		}
	}

	concurrentTime := time.Since(start)
	fmt.Printf("\nConcurrent Analysis Summary:\n")
	fmt.Printf("Total Time: %v\n", concurrentTime)
	fmt.Printf("Successful: %d/%d\n", successCount, numConcurrent)
	fmt.Printf("Errors: %d/%d\n", errorCount, numConcurrent)
	fmt.Printf("Average Time per Analysis: %v\n", concurrentTime/time.Duration(numConcurrent))

	// Cleanup
	fmt.Println("\n🧹 Shutting down systems...")
	err := integrator.Shutdown(ctx)
	if err != nil {
		fmt.Printf("❌ Error during shutdown: %v\n", err)
	} else {
		fmt.Println("✅ Systems shut down gracefully")
	}

	fmt.Println("\n🎉 Novel Algorithms Demonstration Complete!")
	fmt.Println("===========================================")
}

func demonstrateConfigurationManagement() {
	fmt.Println("\n⚙️  Configuration Management Demonstration")
	fmt.Println("=========================================")

	// Load configuration from file
	configPath := "config/novel_algorithms.yaml"
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		fmt.Printf("⚠️  Configuration file not found: %s\n", configPath)
		fmt.Println("Using default configuration instead.")
	} else {
		fmt.Printf("📁 Loading configuration from: %s\n", configPath)
	}

	// Demonstrate configuration updates
	logger := &DemoLogger{}
	config := createDemoNovelConfig()
	suite := ml.NewNovelAlgorithmSuite(config, logger)

	fmt.Println("\n--- Initial Configuration ---")
	fmt.Printf("Learning Rate: %.4f\n", config.LearningRate)
	fmt.Printf("Batch Size: %d\n", config.BatchSize)
	fmt.Printf("Quantum Inspired: %t\n", config.QuantumInspiredEnabled)
	fmt.Printf("Graph Attention: %t\n", config.GraphAttentionEnabled)

	// Update configuration
	newConfig := createDemoNovelConfig()
	newConfig.LearningRate = 0.01
	newConfig.BatchSize = 64
	newConfig.QuantumInspiredEnabled = false
	newConfig.GraphAttentionEnabled = true

	fmt.Println("\n--- Updating Configuration ---")
	err := suite.UpdateConfiguration(newConfig)
	if err != nil {
		fmt.Printf("❌ Error updating configuration: %v\n", err)
	} else {
		fmt.Println("✅ Configuration updated successfully")
		fmt.Printf("New Learning Rate: %.4f\n", newConfig.LearningRate)
		fmt.Printf("New Batch Size: %d\n", newConfig.BatchSize)
		fmt.Printf("Quantum Inspired: %t\n", newConfig.QuantumInspiredEnabled)
		fmt.Printf("Graph Attention: %t\n", newConfig.GraphAttentionEnabled)
	}

	// Show metrics after configuration change
	fmt.Println("\n--- Metrics After Configuration Update ---")
	metrics := suite.GetMetrics()
	for key, value := range metrics {
		fmt.Printf("%s: %v\n", key, value)
	}
}

func main() {
	// Set up logging
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	fmt.Println("🎯 TypoSentinel Novel Algorithms Demo")
	fmt.Println("====================================")
	fmt.Println("This demo showcases the advanced ML algorithms")
	fmt.Println("integrated into TypoSentinel for enhanced threat detection.")
	fmt.Println()

	// Main demonstration
	demonstrate NovelAlgorithms()

	// Configuration management demo
	demonstrate ConfigurationManagement()

	fmt.Println("\n📚 Additional Information")
	fmt.Println("========================")
	fmt.Println("• Novel algorithms include quantum-inspired neural networks,")
	fmt.Println("  graph attention networks, adversarial ML detection, and more.")
	fmt.Println("• The system supports multiple analysis strategies: novel-only,")
	fmt.Println("  classic-only, hybrid, and adaptive.")
	fmt.Println("• Caching and performance monitoring are built-in for production use.")
	fmt.Println("• All algorithms can be configured and tuned via YAML configuration.")
	fmt.Println("• The system is designed for high-throughput, concurrent analysis.")
	fmt.Println()
	fmt.Println("For more information, see:")
	fmt.Println("• internal/ml/novel_algorithms.go - Core algorithm implementations")
	fmt.Println("• internal/ml/novel_integration.go - Integration layer")
	fmt.Println("• config/novel_algorithms.yaml - Configuration file")
	fmt.Println("• internal/ml/*_test.go - Comprehensive test suites")
	fmt.Println()
	fmt.Println("🚀 Ready to enhance your package security with novel algorithms!")
}