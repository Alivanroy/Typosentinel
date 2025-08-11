package ml

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/Alivanroy/Typosentinel/pkg/logger"
	"github.com/Alivanroy/Typosentinel/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test helpers for integration testing
func createTestIntegrationConfig() *NovelIntegrationConfig {
	return &NovelIntegrationConfig{
		Enabled:                   true,
		Strategy:                  "adaptive",
		NovelWeight:               0.6,
		ClassicWeight:             0.4,
		AdaptiveThreshold:         0.7,
		PerformanceThresholds: &PerformanceThresholds{
			LatencyMs:        5000,
			Accuracy:         0.85,
			Precision:        0.8,
			Recall:           0.8,
			F1Score:          0.8,
			ThroughputPerSec: 100,
		},
		Caching: &CachingConfig{
			Enabled:    true,
			TTLMinutes: 60,
			MaxSize:    1000,
		},
		Monitoring: &MonitoringConfig{
			Enabled:           true,
			MetricsInterval:   60,
			HealthCheckInterval: 30,
			AlertThresholds: map[string]float64{
				"error_rate":    0.05,
				"latency_p95":   3000,
				"memory_usage":  0.8,
				"cpu_usage":     0.7,
			},
		},
		MaxConcurrentAnalyses: 10,
		TimeoutSeconds:        30,
		RetryAttempts:         3,
		CircuitBreakerConfig: map[string]interface{}{
			"failure_threshold": 5,
			"recovery_timeout":  60,
			"half_open_requests": 3,
		},
	}
}

func createMockClassicMLDetector() *MockClassicMLDetector {
	return &MockClassicMLDetector{
		results: make(map[string]*ClassicAnalysisResult),
	}
}

type MockClassicMLDetector struct {
	results map[string]*ClassicAnalysisResult
	mu      sync.RWMutex
}

type ClassicAnalysisResult struct {
	PackageID     string
	ThreatScore   float64
	Confidence    float64
	ThreatLevel   string
	Recommendations []string
	AnalysisTime  time.Duration
}

func (m *MockClassicMLDetector) AnalyzePackage(ctx context.Context, pkg *types.Package) (*ClassicAnalysisResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if pkg == nil {
		return nil, fmt.Errorf("package cannot be nil")
	}

	// Simulate classic ML analysis
	result := &ClassicAnalysisResult{
		PackageID:   pkg.Name,
		ThreatScore: 0.5, // Default moderate threat
		Confidence:  0.8,
		ThreatLevel: "MEDIUM",
		Recommendations: []string{"Monitor package activity"},
		AnalysisTime: time.Millisecond * 100,
	}

	// Adjust based on package characteristics
	if len(pkg.Dependencies) > 50 {
		result.ThreatScore += 0.2
		result.ThreatLevel = "HIGH"
	}

	if pkg.Name == "malware-test" || pkg.Description == "Suspicious package" {
		result.ThreatScore = 0.9
		result.ThreatLevel = "CRITICAL"
		result.Recommendations = append(result.Recommendations, "Block package immediately")
	}

	m.results[pkg.Name] = result
	return result, nil
}

func (m *MockClassicMLDetector) GetResults() map[string]*ClassicAnalysisResult {
	m.mu.RLock()
	defer m.mu.RUnlock()

	results := make(map[string]*ClassicAnalysisResult)
	for k, v := range m.results {
		results[k] = v
	}
	return results
}

// Test Novel ML Integrator
func TestNewNovelMLIntegrator(t *testing.T) {
	config := createTestIntegrationConfig()
	novelSuite := NewNovelAlgorithmSuite(createTestConfig(), createTestLogger())
	classicDetector := createMockClassicMLDetector()
	logger := createTestLogger()

	integrator := NewNovelMLIntegrator(config, novelSuite, classicDetector, logger)

	assert.NotNil(t, integrator)
	assert.Equal(t, config, integrator.config)
	assert.NotNil(t, integrator.novelSuite)
	assert.NotNil(t, integrator.classicDetector)
	assert.NotNil(t, integrator.cache)
	assert.NotNil(t, integrator.metrics)
	assert.NotNil(t, integrator.performanceTracker)
}

func TestNovelMLIntegrator_AnalyzePackage_NovelOnly(t *testing.T) {
	config := createTestIntegrationConfig()
	config.Strategy = "novel_only"
	novelSuite := NewNovelAlgorithmSuite(createTestConfig(), createTestLogger())
	classicDetector := createMockClassicMLDetector()
	logger := createTestLogger()

	integrator := NewNovelMLIntegrator(config, novelSuite, classicDetector, logger)

	pkg := createTestPackage("novel-only-test", "Test package for novel-only strategy", 10)
	ctx := context.Background()

	result, err := integrator.AnalyzePackage(ctx, pkg)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, pkg.Name, result.PackageID)
	assert.Equal(t, "novel_only", result.Strategy)
	assert.NotNil(t, result.NovelResult)
	assert.Nil(t, result.ClassicResult)
	assert.GreaterOrEqual(t, result.FinalScore, 0.0)
	assert.LessOrEqual(t, result.FinalScore, 1.0)
	assert.NotEmpty(t, result.FinalThreatLevel)
	assert.NotEmpty(t, result.FinalRecommendations)
}

func TestNovelMLIntegrator_AnalyzePackage_ClassicOnly(t *testing.T) {
	config := createTestIntegrationConfig()
	config.Strategy = "classic_only"
	novelSuite := NewNovelAlgorithmSuite(createTestConfig(), createTestLogger())
	classicDetector := createMockClassicMLDetector()
	logger := createTestLogger()

	integrator := NewNovelMLIntegrator(config, novelSuite, classicDetector, logger)

	pkg := createTestPackage("classic-only-test", "Test package for classic-only strategy", 15)
	ctx := context.Background()

	result, err := integrator.AnalyzePackage(ctx, pkg)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, pkg.Name, result.PackageID)
	assert.Equal(t, "classic_only", result.Strategy)
	assert.Nil(t, result.NovelResult)
	assert.NotNil(t, result.ClassicResult)
	assert.GreaterOrEqual(t, result.FinalScore, 0.0)
	assert.LessOrEqual(t, result.FinalScore, 1.0)
	assert.NotEmpty(t, result.FinalThreatLevel)
	assert.NotEmpty(t, result.FinalRecommendations)
}

func TestNovelMLIntegrator_AnalyzePackage_Hybrid(t *testing.T) {
	config := createTestIntegrationConfig()
	config.Strategy = "hybrid"
	novelSuite := NewNovelAlgorithmSuite(createTestConfig(), createTestLogger())
	classicDetector := createMockClassicMLDetector()
	logger := createTestLogger()

	integrator := NewNovelMLIntegrator(config, novelSuite, classicDetector, logger)

	pkg := createTestPackage("hybrid-test", "Test package for hybrid strategy", 20)
	ctx := context.Background()

	result, err := integrator.AnalyzePackage(ctx, pkg)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, pkg.Name, result.PackageID)
	assert.Equal(t, "hybrid", result.Strategy)
	assert.NotNil(t, result.NovelResult)
	assert.NotNil(t, result.ClassicResult)
	assert.GreaterOrEqual(t, result.FinalScore, 0.0)
	assert.LessOrEqual(t, result.FinalScore, 1.0)
	assert.NotEmpty(t, result.FinalThreatLevel)
	assert.NotEmpty(t, result.FinalRecommendations)

	// Verify hybrid scoring combines both results
	expectedScore := (result.NovelResult.EnsembleScore*config.NovelWeight + 
					 result.ClassicResult.ThreatScore*config.ClassicWeight)
	assert.InDelta(t, expectedScore, result.FinalScore, 0.01)
}

func TestNovelMLIntegrator_AnalyzePackage_Adaptive(t *testing.T) {
	config := createTestIntegrationConfig()
	config.Strategy = "adaptive"
	novelSuite := NewNovelAlgorithmSuite(createTestConfig(), createTestLogger())
	classicDetector := createMockClassicMLDetector()
	logger := createTestLogger()

	integrator := NewNovelMLIntegrator(config, novelSuite, classicDetector, logger)

	testCases := []struct {
		name        string
		pkg         *types.Package
		expectedStrategy string
	}{
		{
			name: "simple_package_classic",
			pkg:  createTestPackage("simple-pkg", "Simple package", 5),
			expectedStrategy: "classic", // Low complexity, should use classic
		},
		{
			name: "complex_package_novel",
			pkg:  createTestPackage("complex-pkg", "Complex package with many dependencies", 100),
			expectedStrategy: "novel", // High complexity, should use novel
		},
		{
			name: "suspicious_package_novel",
			pkg:  createTestPackage("malware-test", "Suspicious package", 25),
			expectedStrategy: "novel", // Suspicious content, should use novel
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			result, err := integrator.AnalyzePackage(ctx, tc.pkg)

			assert.NoError(t, err)
			assert.NotNil(t, result)
			assert.Equal(t, tc.pkg.Name, result.PackageID)
			assert.Equal(t, "adaptive", result.Strategy)

			// Check that the adaptive strategy made the right choice
			if tc.expectedStrategy == "novel" {
				assert.NotNil(t, result.NovelResult, "Should use novel algorithms for complex/suspicious packages")
			} else {
				assert.NotNil(t, result.ClassicResult, "Should use classic algorithms for simple packages")
			}
		})
	}
}

func TestNovelMLIntegrator_Caching(t *testing.T) {
	config := createTestIntegrationConfig()
	config.Caching.Enabled = true
	config.Caching.TTLMinutes = 1 // Short TTL for testing
	novelSuite := NewNovelAlgorithmSuite(createTestConfig(), createTestLogger())
	classicDetector := createMockClassicMLDetector()
	logger := createTestLogger()

	integrator := NewNovelMLIntegrator(config, novelSuite, classicDetector, logger)

	pkg := createTestPackage("cache-test", "Test package for caching", 10)
	ctx := context.Background()

	// First analysis - should not be cached
	start1 := time.Now()
	result1, err := integrator.AnalyzePackage(ctx, pkg)
	duration1 := time.Since(start1)

	assert.NoError(t, err)
	assert.NotNil(t, result1)

	// Second analysis - should be cached and faster
	start2 := time.Now()
	result2, err := integrator.AnalyzePackage(ctx, pkg)
	duration2 := time.Since(start2)

	assert.NoError(t, err)
	assert.NotNil(t, result2)
	assert.Equal(t, result1.PackageID, result2.PackageID)
	assert.Equal(t, result1.FinalScore, result2.FinalScore)

	// Second analysis should be significantly faster due to caching
	assert.Less(t, duration2, duration1/2, "Cached analysis should be much faster")

	// Wait for cache to expire
	time.Sleep(time.Minute + time.Second)

	// Third analysis - cache expired, should take longer again
	start3 := time.Now()
	result3, err := integrator.AnalyzePackage(ctx, pkg)
	duration3 := time.Since(start3)

	assert.NoError(t, err)
	assert.NotNil(t, result3)
	assert.Greater(t, duration3, duration2, "Analysis after cache expiry should take longer")
}

func TestNovelMLIntegrator_PerformanceTracking(t *testing.T) {
	config := createTestIntegrationConfig()
	novelSuite := NewNovelAlgorithmSuite(createTestConfig(), createTestLogger())
	classicDetector := createMockClassicMLDetector()
	logger := createTestLogger()

	integrator := NewNovelMLIntegrator(config, novelSuite, classicDetector, logger)

	// Perform multiple analyses
	for i := 0; i < 5; i++ {
		pkg := createTestPackage(fmt.Sprintf("perf-test-%d", i), "Performance test package", 10+i*5)
		ctx := context.Background()
		_, err := integrator.AnalyzePackage(ctx, pkg)
		assert.NoError(t, err)
	}

	// Check performance metrics
	metrics := integrator.GetMetrics()
	assert.NotNil(t, metrics)
	assert.Contains(t, metrics, "total_analyses")
	assert.Contains(t, metrics, "average_latency_ms")
	assert.Contains(t, metrics, "success_rate")
	assert.Contains(t, metrics, "cache_hit_rate")

	totalAnalyses := metrics["total_analyses"].(int64)
	assert.GreaterOrEqual(t, totalAnalyses, int64(5))

	successRate := metrics["success_rate"].(float64)
	assert.Equal(t, 1.0, successRate) // All analyses should succeed
}

func TestNovelMLIntegrator_ConcurrentAnalyses(t *testing.T) {
	config := createTestIntegrationConfig()
	config.MaxConcurrentAnalyses = 5
	novelSuite := NewNovelAlgorithmSuite(createTestConfig(), createTestLogger())
	classicDetector := createMockClassicMLDetector()
	logger := createTestLogger()

	integrator := NewNovelMLIntegrator(config, novelSuite, classicDetector, logger)

	const numGoroutines = 10
	const analysesPerGoroutine = 3

	var wg sync.WaitGroup
	errorChan := make(chan error, numGoroutines*analysesPerGoroutine)
	resultChan := make(chan *IntegratedAnalysisResult, numGoroutines*analysesPerGoroutine)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < analysesPerGoroutine; j++ {
				pkg := createTestPackage(fmt.Sprintf("concurrent-test-%d-%d", id, j), "Concurrent test", 10)
				ctx := context.Background()
				result, err := integrator.AnalyzePackage(ctx, pkg)
				if err != nil {
					errorChan <- err
				} else {
					resultChan <- result
				}
			}
		}(i)
	}

	wg.Wait()
	close(errorChan)
	close(resultChan)

	// Check for errors
	errorCount := 0
	for err := range errorChan {
		t.Logf("Concurrent analysis error: %v", err)
		errorCount++
	}

	// Count successful results
	successCount := 0
	for range resultChan {
		successCount++
	}

	totalExpected := numGoroutines * analysesPerGoroutine
	assert.Equal(t, totalExpected, successCount+errorCount)
	assert.LessOrEqual(t, errorCount, totalExpected/10, "Error rate should be low")
}

func TestNovelMLIntegrator_ErrorHandling(t *testing.T) {
	config := createTestIntegrationConfig()
	novelSuite := NewNovelAlgorithmSuite(createTestConfig(), createTestLogger())
	classicDetector := createMockClassicMLDetector()
	logger := createTestLogger()

	integrator := NewNovelMLIntegrator(config, novelSuite, classicDetector, logger)

	// Test with nil package
	ctx := context.Background()
	result, err := integrator.AnalyzePackage(ctx, nil)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "package cannot be nil")

	// Test with cancelled context
	cancelCtx, cancel := context.WithCancel(context.Background())
	cancel()

	pkg := createTestPackage("cancel-test", "Context cancellation test", 5)
	result, err = integrator.AnalyzePackage(cancelCtx, pkg)
	if err != nil {
		assert.Contains(t, err.Error(), "context")
	}

	// Test with timeout
	timeoutCtx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	time.Sleep(time.Millisecond * 2) // Ensure timeout

	result, err = integrator.AnalyzePackage(timeoutCtx, pkg)
	if err != nil {
		assert.Contains(t, err.Error(), "context")
	}
}

func TestNovelMLIntegrator_ConfigurationUpdate(t *testing.T) {
	config := createTestIntegrationConfig()
	novelSuite := NewNovelAlgorithmSuite(createTestConfig(), createTestLogger())
	classicDetector := createMockClassicMLDetector()
	logger := createTestLogger()

	integrator := NewNovelMLIntegrator(config, novelSuite, classicDetector, logger)

	// Update configuration
	newConfig := createTestIntegrationConfig()
	newConfig.Strategy = "novel_only"
	newConfig.NovelWeight = 1.0
	newConfig.ClassicWeight = 0.0
	newConfig.MaxConcurrentAnalyses = 20

	err := integrator.UpdateConfiguration(newConfig)
	assert.NoError(t, err)
	assert.Equal(t, newConfig, integrator.config)

	// Test that new configuration is applied
	pkg := createTestPackage("config-update-test", "Configuration update test", 10)
	ctx := context.Background()
	result, err := integrator.AnalyzePackage(ctx, pkg)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "novel_only", result.Strategy)
}

func TestNovelMLIntegrator_HealthCheck(t *testing.T) {
	config := createTestIntegrationConfig()
	novelSuite := NewNovelAlgorithmSuite(createTestConfig(), createTestLogger())
	classicDetector := createMockClassicMLDetector()
	logger := createTestLogger()

	integrator := NewNovelMLIntegrator(config, novelSuite, classicDetector, logger)

	// Perform health check
	health := integrator.HealthCheck()
	assert.NotNil(t, health)
	assert.Contains(t, health, "status")
	assert.Contains(t, health, "novel_suite")
	assert.Contains(t, health, "classic_detector")
	assert.Contains(t, health, "cache")
	assert.Contains(t, health, "performance_tracker")

	status := health["status"].(string)
	assert.Equal(t, "healthy", status)
}

func TestNovelMLIntegrator_Shutdown(t *testing.T) {
	config := createTestIntegrationConfig()
	novelSuite := NewNovelAlgorithmSuite(createTestConfig(), createTestLogger())
	classicDetector := createMockClassicMLDetector()
	logger := createTestLogger()

	integrator := NewNovelMLIntegrator(config, novelSuite, classicDetector, logger)

	// Perform some analyses first
	for i := 0; i < 3; i++ {
		pkg := createTestPackage(fmt.Sprintf("shutdown-test-%d", i), "Shutdown test", 5)
		ctx := context.Background()
		_, err := integrator.AnalyzePackage(ctx, pkg)
		assert.NoError(t, err)
	}

	// Shutdown gracefully
	ctx := context.Background()
	err := integrator.Shutdown(ctx)
	assert.NoError(t, err)

	// Verify that analyses after shutdown fail gracefully
	pkg := createTestPackage("post-shutdown-test", "Post shutdown test", 5)
	result, err := integrator.AnalyzePackage(ctx, pkg)
	if err != nil {
		assert.Contains(t, err.Error(), "shutdown")
		assert.Nil(t, result)
	}
}

func TestThreatLevelCombination(t *testing.T) {
	config := createTestIntegrationConfig()
	novelSuite := NewNovelAlgorithmSuite(createTestConfig(), createTestLogger())
	classicDetector := createMockClassicMLDetector()
	logger := createTestLogger()

	integrator := NewNovelMLIntegrator(config, novelSuite, classicDetector, logger)

	testCases := []struct {
		novelLevel   string
		classicLevel string
		expected     string
	}{
		{"CRITICAL", "HIGH", "CRITICAL"},
		{"HIGH", "CRITICAL", "CRITICAL"},
		{"HIGH", "MEDIUM", "HIGH"},
		{"MEDIUM", "HIGH", "HIGH"},
		{"MEDIUM", "LOW", "MEDIUM"},
		{"LOW", "MEDIUM", "MEDIUM"},
		{"LOW", "MINIMAL", "LOW"},
		{"MINIMAL", "LOW", "LOW"},
		{"MINIMAL", "MINIMAL", "MINIMAL"},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%s_%s", tc.novelLevel, tc.classicLevel), func(t *testing.T) {
			combined := integrator.combineThreatLevels(tc.novelLevel, tc.classicLevel)
			assert.Equal(t, tc.expected, combined)
		})
	}
}

func TestRecommendationCombination(t *testing.T) {
	config := createTestIntegrationConfig()
	novelSuite := NewNovelAlgorithmSuite(createTestConfig(), createTestLogger())
	classicDetector := createMockClassicMLDetector()
	logger := createTestLogger()

	integrator := NewNovelMLIntegrator(config, novelSuite, classicDetector, logger)

	novelRecs := []string{"Use quantum analysis", "Apply graph attention", "Monitor dependencies"}
	classicRecs := []string{"Monitor package activity", "Check reputation", "Monitor dependencies"}

	combined := integrator.combineRecommendations(novelRecs, classicRecs)

	// Should contain unique recommendations from both sources
	assert.Contains(t, combined, "Use quantum analysis")
	assert.Contains(t, combined, "Apply graph attention")
	assert.Contains(t, combined, "Monitor dependencies")
	assert.Contains(t, combined, "Monitor package activity")
	assert.Contains(t, combined, "Check reputation")

	// Should not have duplicates
	count := 0
	for _, rec := range combined {
		if rec == "Monitor dependencies" {
			count++
		}
	}
	assert.Equal(t, 1, count, "Should not have duplicate recommendations")
}

// Benchmark tests
func BenchmarkNovelMLIntegrator_AnalyzePackage_NovelOnly(b *testing.B) {
	config := createTestIntegrationConfig()
	config.Strategy = "novel_only"
	novelSuite := NewNovelAlgorithmSuite(createTestConfig(), createTestLogger())
	classicDetector := createMockClassicMLDetector()
	logger := createTestLogger()

	integrator := NewNovelMLIntegrator(config, novelSuite, classicDetector, logger)
	pkg := createTestPackage("benchmark-novel", "Benchmark test for novel-only", 20)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := integrator.AnalyzePackage(ctx, pkg)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkNovelMLIntegrator_AnalyzePackage_Hybrid(b *testing.B) {
	config := createTestIntegrationConfig()
	config.Strategy = "hybrid"
	novelSuite := NewNovelAlgorithmSuite(createTestConfig(), createTestLogger())
	classicDetector := createMockClassicMLDetector()
	logger := createTestLogger()

	integrator := NewNovelMLIntegrator(config, novelSuite, classicDetector, logger)
	pkg := createTestPackage("benchmark-hybrid", "Benchmark test for hybrid", 20)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := integrator.AnalyzePackage(ctx, pkg)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkNovelMLIntegrator_AnalyzePackage_WithCaching(b *testing.B) {
	config := createTestIntegrationConfig()
	config.Caching.Enabled = true
	novelSuite := NewNovelAlgorithmSuite(createTestConfig(), createTestLogger())
	classicDetector := createMockClassicMLDetector()
	logger := createTestLogger()

	integrator := NewNovelMLIntegrator(config, novelSuite, classicDetector, logger)
	pkg := createTestPackage("benchmark-cache", "Benchmark test with caching", 20)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := integrator.AnalyzePackage(ctx, pkg)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkNovelMLIntegrator_ConcurrentAnalyses(b *testing.B) {
	config := createTestIntegrationConfig()
	config.MaxConcurrentAnalyses = 10
	novelSuite := NewNovelAlgorithmSuite(createTestConfig(), createTestLogger())
	classicDetector := createMockClassicMLDetector()
	logger := createTestLogger()

	integrator := NewNovelMLIntegrator(config, novelSuite, classicDetector, logger)
	ctx := context.Background()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			pkg := createTestPackage(fmt.Sprintf("benchmark-concurrent-%d", i), "Concurrent benchmark", 15)
			_, err := integrator.AnalyzePackage(ctx, pkg)
			if err != nil {
				b.Error(err)
			}
			i++
		}
	})
}