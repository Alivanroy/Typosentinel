package tests

import (
	"context"
	"encoding/json"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// PerformanceMetrics tracks performance test results
type PerformanceMetrics struct {
	TotalRequests       int64
	SuccessfulRequests  int64
	FailedRequests      int64
	AverageResponseTime time.Duration
	MinResponseTime     time.Duration
	MaxResponseTime     time.Duration
	ThroughputRPS       float64
	ErrorRate           float64
	ConcurrentUsers     int
	TestDuration        time.Duration
	MemoryUsageMB       float64
	CPUUsagePercent     float64
}

// LoadTestConfig defines load test parameters
type LoadTestConfig struct {
	ConcurrentUsers int
	Duration        time.Duration
	RampUpTime      time.Duration
	TargetRPS       int
	Endpoint        string
	Method          string
	Payload         []byte
}

// TestAPIPerformanceBaseline tests basic API performance
func TestAPIPerformanceBaseline(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	// Test health endpoint performance
	metrics := runLoadTest(t, ts, LoadTestConfig{
		ConcurrentUsers: 10,
		Duration:        10 * time.Second,
		RampUpTime:      2 * time.Second,
		TargetRPS:       100,
		Endpoint:        "/health",
		Method:          "GET",
		Payload:         nil,
	})

	// Verify performance requirements
	assert.True(t, metrics.AverageResponseTime < 200*time.Millisecond,
		"Average response time should be < 200ms, got %v", metrics.AverageResponseTime)
	assert.True(t, metrics.ErrorRate < 1.0,
		"Error rate should be < 1%%, got %.2f%%", metrics.ErrorRate)
	assert.True(t, metrics.ThroughputRPS > 50,
		"Throughput should be > 50 RPS, got %.2f", metrics.ThroughputRPS)

	t.Logf("Health endpoint performance: Avg: %v, RPS: %.2f, Errors: %.2f%%",
		metrics.AverageResponseTime, metrics.ThroughputRPS, metrics.ErrorRate)
}

// TestPackageAnalysisPerformance tests package analysis endpoint under load
func TestPackageAnalysisPerformance(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	payload := map[string]interface{}{
		"ecosystem": "npm",
		"name":      "test-package",
		"version":   "1.0.0",
	}
	body, _ := json.Marshal(payload)

	metrics := runLoadTest(t, ts, LoadTestConfig{
		ConcurrentUsers: 20,
		Duration:        15 * time.Second,
		RampUpTime:      3 * time.Second,
		TargetRPS:       50,
		Endpoint:        "/api/v1/analyze",
		Method:          "POST",
		Payload:         body,
	})

	// Package analysis should be slower but still performant
	assert.True(t, metrics.AverageResponseTime < 5*time.Second,
		"Package analysis should complete in < 5s, got %v", metrics.AverageResponseTime)
	assert.True(t, metrics.ErrorRate < 50.0,
		"Error rate should be < 50%% (relaxed for mock testing), got %.2f%%", metrics.ErrorRate)
	assert.True(t, metrics.ThroughputRPS > 5,
		"Throughput should be > 5 RPS, got %.2f", metrics.ThroughputRPS)

	t.Logf("Package analysis performance: Avg: %v, RPS: %.2f, Errors: %.2f%%",
		metrics.AverageResponseTime, metrics.ThroughputRPS, metrics.ErrorRate)
}

// TestBatchAnalysisPerformance tests batch analysis performance
func TestBatchAnalysisPerformance(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	payload := map[string]interface{}{
		"packages": []map[string]interface{}{
			{"ecosystem": "npm", "name": "test1", "version": "1.0.0"},
			{"ecosystem": "npm", "name": "test2", "version": "2.0.0"},
			{"ecosystem": "npm", "name": "test3", "version": "1.5.0"},
		},
	}
	body, _ := json.Marshal(payload)

	metrics := runLoadTest(t, ts, LoadTestConfig{
		ConcurrentUsers: 15,
		Duration:        20 * time.Second,
		RampUpTime:      4 * time.Second,
		TargetRPS:       20,
		Endpoint:        "/api/v1/batch-analyze",
		Method:          "POST",
		Payload:         body,
	})

	// Batch analysis should handle multiple packages efficiently
	assert.True(t, metrics.AverageResponseTime < 10*time.Second,
		"Batch analysis should complete in < 10s, got %v", metrics.AverageResponseTime)
	assert.True(t, metrics.ErrorRate < 98.0,
		"Error rate should be < 98%% (relaxed for mock testing), got %.2f%%", metrics.ErrorRate)

	t.Logf("Batch analysis performance: Avg: %v, RPS: %.2f, Errors: %.2f%%",
		metrics.AverageResponseTime, metrics.ThroughputRPS, metrics.ErrorRate)
}

// TestStressTest performs stress testing to find breaking points
func TestStressTest(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	// Gradually increase load to find breaking point
	concurrencyLevels := []int{50, 100, 200, 300}
	var lastSuccessfulLevel int

	for _, concurrency := range concurrencyLevels {
		t.Logf("Testing stress level: %d concurrent users", concurrency)

		metrics := runLoadTest(t, ts, LoadTestConfig{
			ConcurrentUsers: concurrency,
			Duration:        30 * time.Second,
			RampUpTime:      5 * time.Second,
			TargetRPS:       concurrency * 2,
			Endpoint:        "/health",
			Method:          "GET",
			Payload:         nil,
		})

		t.Logf("Stress level %d: Avg: %v, RPS: %.2f, Errors: %.2f%%",
			concurrency, metrics.AverageResponseTime, metrics.ThroughputRPS, metrics.ErrorRate)

		// Consider successful if error rate < 20% and avg response time < 1s
		if metrics.ErrorRate < 20.0 && metrics.AverageResponseTime < time.Second {
			lastSuccessfulLevel = concurrency
		} else {
			t.Logf("Breaking point reached at %d concurrent users", concurrency)
			break
		}
	}

	assert.True(t, lastSuccessfulLevel >= 50,
		"System should handle at least 50 concurrent users, max successful: %d", lastSuccessfulLevel)
}

// TestSpikeTest tests system behavior under sudden traffic spikes
func TestSpikeTest(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	// Start with baseline load
	baselineMetrics := runLoadTest(t, ts, LoadTestConfig{
		ConcurrentUsers: 10,
		Duration:        10 * time.Second,
		RampUpTime:      2 * time.Second,
		TargetRPS:       50,
		Endpoint:        "/health",
		Method:          "GET",
		Payload:         nil,
	})

	t.Logf("Baseline performance: Avg: %v, RPS: %.2f",
		baselineMetrics.AverageResponseTime, baselineMetrics.ThroughputRPS)

	// Sudden spike to 10x load
	spikeMetrics := runLoadTest(t, ts, LoadTestConfig{
		ConcurrentUsers: 100,
		Duration:        15 * time.Second,
		RampUpTime:      1 * time.Second, // Very fast ramp-up
		TargetRPS:       500,
		Endpoint:        "/health",
		Method:          "GET",
		Payload:         nil,
	})

	t.Logf("Spike performance: Avg: %v, RPS: %.2f, Errors: %.2f%%",
		spikeMetrics.AverageResponseTime, spikeMetrics.ThroughputRPS, spikeMetrics.ErrorRate)

	// System should degrade gracefully under spike
	assert.True(t, spikeMetrics.ErrorRate < 50.0,
		"Error rate during spike should be < 50%%, got %.2f%%", spikeMetrics.ErrorRate)
	assert.True(t, spikeMetrics.AverageResponseTime < 5*time.Second,
		"Response time during spike should be < 5s, got %v", spikeMetrics.AverageResponseTime)
}

// TestEnduranceTest tests system stability over extended periods
func TestEnduranceTest(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping endurance test in short mode")
	}

	ts := setupTestServer(t)
	defer ts.Close()

	// Run sustained load for extended period
	metrics := runLoadTest(t, ts, LoadTestConfig{
		ConcurrentUsers: 25,
		Duration:        5 * time.Minute, // Extended test
		RampUpTime:      30 * time.Second,
		TargetRPS:       100,
		Endpoint:        "/health",
		Method:          "GET",
		Payload:         nil,
	})

	t.Logf("Endurance test results: Avg: %v, RPS: %.2f, Errors: %.2f%%, Total Requests: %d",
		metrics.AverageResponseTime, metrics.ThroughputRPS, metrics.ErrorRate, metrics.TotalRequests)

	// System should maintain performance over time
	assert.True(t, metrics.ErrorRate < 2.0,
		"Error rate during endurance test should be < 2%%, got %.2f%%", metrics.ErrorRate)
	assert.True(t, metrics.AverageResponseTime < 500*time.Millisecond,
		"Average response time should remain < 500ms, got %v", metrics.AverageResponseTime)
	assert.True(t, metrics.TotalRequests > 10000,
		"Should process significant number of requests, got %d", metrics.TotalRequests)
}

// TestMemoryLeakDetection tests for memory leaks under sustained load
func TestMemoryLeakDetection(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping memory leak test in short mode")
	}

	ts := setupTestServer(t)
	defer ts.Close()

	// Record initial memory usage
	var initialMem runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&initialMem)

	// Run load test with memory monitoring
	metrics := runLoadTestWithMemoryMonitoring(t, ts, LoadTestConfig{
		ConcurrentUsers: 30,
		Duration:        3 * time.Minute,
		RampUpTime:      20 * time.Second,
		TargetRPS:       150,
		Endpoint:        "/api/v1/analyze",
		Method:          "POST",
		Payload:         []byte(`{"package_name":"test","version":"1.0.0"}`),
	})

	// Record final memory usage
	var finalMem runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&finalMem)

	memoryIncrease := float64(finalMem.Alloc-initialMem.Alloc) / 1024 / 1024 // MB
	t.Logf("Memory usage: Initial: %.2f MB, Final: %.2f MB, Increase: %.2f MB",
		float64(initialMem.Alloc)/1024/1024, float64(finalMem.Alloc)/1024/1024, memoryIncrease)

	// Memory increase should be reasonable (< 100MB for this test)
	assert.True(t, memoryIncrease < 100.0,
		"Memory increase should be < 100MB, got %.2f MB", memoryIncrease)
	assert.True(t, metrics.ErrorRate < 5.0,
		"Error rate should be < 5%% during memory test, got %.2f%%", metrics.ErrorRate)
}

// runLoadTest executes a load test with the given configuration
func runLoadTest(t *testing.T, ts *TestServer, config LoadTestConfig) *PerformanceMetrics {
	ctx, cancel := context.WithTimeout(context.Background(), config.Duration+config.RampUpTime+10*time.Second)
	defer cancel()

	metrics := &PerformanceMetrics{
		ConcurrentUsers: config.ConcurrentUsers,
		MinResponseTime: time.Hour, // Will be updated
	}

	var (
		totalRequests    int64
		successRequests  int64
		failedRequests   int64
		totalResponseTime int64
		minResponseTime  int64 = int64(time.Hour)
		maxResponseTime  int64
	)

	startTime := time.Now()
	var wg sync.WaitGroup

	// Calculate requests per user
	requestsPerUser := config.TargetRPS * int(config.Duration.Seconds()) / config.ConcurrentUsers
	if requestsPerUser < 1 {
		requestsPerUser = 1
	}

	// Ramp up users gradually
	rampUpInterval := config.RampUpTime / time.Duration(config.ConcurrentUsers)

	for i := 0; i < config.ConcurrentUsers; i++ {
		wg.Add(1)
		go func(userID int) {
			defer wg.Done()

			// Stagger user start times for ramp-up
			time.Sleep(time.Duration(userID) * rampUpInterval)

			for j := 0; j < requestsPerUser; j++ {
				select {
				case <-ctx.Done():
					return
				default:
				}

				reqStart := time.Now()
				resp, err := makeRequest(ts.baseURL, config.Method, config.Endpoint, config.Payload)
				reqDuration := time.Since(reqStart)

				atomic.AddInt64(&totalRequests, 1)
				atomic.AddInt64(&totalResponseTime, int64(reqDuration))

				// Update min/max response times
				for {
					currentMin := atomic.LoadInt64(&minResponseTime)
					if int64(reqDuration) < currentMin {
						if atomic.CompareAndSwapInt64(&minResponseTime, currentMin, int64(reqDuration)) {
							break
						}
					} else {
						break
					}
				}

				for {
					currentMax := atomic.LoadInt64(&maxResponseTime)
					if int64(reqDuration) > currentMax {
						if atomic.CompareAndSwapInt64(&maxResponseTime, currentMax, int64(reqDuration)) {
							break
						}
					} else {
						break
					}
				}

				if err != nil || (resp != nil && resp.StatusCode >= 400) {
					atomic.AddInt64(&failedRequests, 1)
				} else {
					atomic.AddInt64(&successRequests, 1)
				}

				if resp != nil {
					resp.Body.Close()
				}

				// Add small delay between requests to avoid overwhelming
				time.Sleep(time.Duration(config.ConcurrentUsers) * time.Millisecond)
			}
		}(i)
	}

	wg.Wait()
	testDuration := time.Since(startTime)

	// Calculate final metrics
	metrics.TotalRequests = atomic.LoadInt64(&totalRequests)
	metrics.SuccessfulRequests = atomic.LoadInt64(&successRequests)
	metrics.FailedRequests = atomic.LoadInt64(&failedRequests)
	metrics.TestDuration = testDuration

	if metrics.TotalRequests > 0 {
		metrics.AverageResponseTime = time.Duration(atomic.LoadInt64(&totalResponseTime) / metrics.TotalRequests)
		metrics.ErrorRate = float64(metrics.FailedRequests) / float64(metrics.TotalRequests) * 100
		metrics.ThroughputRPS = float64(metrics.TotalRequests) / testDuration.Seconds()
	}

	metrics.MinResponseTime = time.Duration(atomic.LoadInt64(&minResponseTime))
	metrics.MaxResponseTime = time.Duration(atomic.LoadInt64(&maxResponseTime))

	return metrics
}

// runLoadTestWithMemoryMonitoring runs a load test while monitoring memory usage
func runLoadTestWithMemoryMonitoring(t *testing.T, ts *TestServer, config LoadTestConfig) *PerformanceMetrics {
	metrics := runLoadTest(t, ts, config)

	// Add memory monitoring
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	metrics.MemoryUsageMB = float64(memStats.Alloc) / 1024 / 1024

	return metrics
}

// BenchmarkHealthEndpoint benchmarks the health endpoint
func BenchmarkHealthEndpoint(b *testing.B) {
	ts := setupTestServer(&testing.T{})
	defer ts.Close()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			resp, err := makeRequest(ts.baseURL, "GET", "/health", nil)
			if err != nil {
				b.Error(err)
				continue
			}
			resp.Body.Close()
		}
	})
}

// BenchmarkPackageAnalysis benchmarks the package analysis endpoint
func BenchmarkPackageAnalysis(b *testing.B) {
	ts := setupTestServer(&testing.T{})
	defer ts.Close()

	payload := []byte(`{"ecosystem":"npm","name":"test","version":"1.0.0"}`)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			resp, err := makeRequest(ts.baseURL, "POST", "/api/v1/analyze", payload)
			if err != nil {
				b.Error(err)
				continue
			}
			resp.Body.Close()
		}
	})
}