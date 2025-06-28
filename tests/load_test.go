package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// LoadTestMetrics holds load testing results
type LoadTestMetrics struct {
	TotalRequests     int64         `json:"total_requests"`
	SuccessfulReqs    int64         `json:"successful_requests"`
	FailedReqs        int64         `json:"failed_requests"`
	AvgResponseTime   time.Duration `json:"avg_response_time"`
	P95ResponseTime   time.Duration `json:"p95_response_time"`
	P99ResponseTime   time.Duration `json:"p99_response_time"`
	Throughput        float64       `json:"throughput_rps"`
	ErrorRate         float64       `json:"error_rate_percent"`
	TestDuration      time.Duration `json:"test_duration"`
	ConcurrentUsers   int           `json:"concurrent_users"`
	PeakMemoryUsage   int64         `json:"peak_memory_mb"`
}

// ResponseTimeRecord holds individual response time measurements
type ResponseTimeRecord struct {
	Timestamp    time.Time
	ResponseTime time.Duration
	Success      bool
	StatusCode   int
	Error        string
}

// LargeProjectMetrics holds metrics for large project testing
type LargeProjectMetrics struct {
	ProjectType       string        `json:"project_type"`
	DependencyCount   int           `json:"dependency_count"`
	ScanTime          time.Duration `json:"scan_time"`
	MemoryUsage       int64         `json:"memory_usage_mb"`
	AccuracyScore     float64       `json:"accuracy_score"`
	ProgressReported  bool          `json:"progress_reported"`
	Success           bool          `json:"success"`
	ErrorMessage      string        `json:"error_message,omitempty"`
}

// TestP002_1_APILoadTesting performs API load testing
func TestP002_1_APILoadTesting(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping load test in short mode")
	}
	
	// Start the API server first
	serverCmd := startAPIServer(t)
	defer stopAPIServer(serverCmd)
	
	// Wait for server to start
	time.Sleep(3 * time.Second)
	
	// Verify server is running
	if !isServerRunning("http://localhost:8080/health") {
		t.Skip("API server not available for load testing")
	}
	
	t.Run("Load_Test_100_Users_15min", func(t *testing.T) {
		metrics := performLoadTest(100, 15*time.Minute, 1000)
		
		// Log results
		logLoadTestMetrics(t, metrics)
		
		// Validate performance requirements
		if metrics.P95ResponseTime > 500*time.Millisecond {
			t.Errorf("95th percentile response time %v exceeds 500ms limit", metrics.P95ResponseTime)
		}
		
		if metrics.Throughput < 1000 {
			t.Errorf("Throughput %.2f RPS is below 1000 RPS requirement", metrics.Throughput)
		}
		
		if metrics.ErrorRate > 1.0 {
			t.Errorf("Error rate %.2f%% exceeds 1%% limit", metrics.ErrorRate)
		}
		
		if metrics.PeakMemoryUsage > 1024 {
			t.Logf("Warning: Peak memory usage %d MB is high", metrics.PeakMemoryUsage)
		}
	})
}

// TestP002_2_LargeProjectTesting tests enterprise-scale project scanning
func TestP002_2_LargeProjectTesting(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping large project test in short mode")
	}
	
	projectTypes := []struct {
		name        string
		projectPath string
		expectedDeps int
	}{
		{"React_App", "test-analysis/npm-project", 50},
		{"Node_Microservice", "test-analysis/npm-project", 30},
		{"Python_ML", "test-analysis/python-project", 20},
		{"Go_Application", "test-analysis/go-project", 10},
	}
	
	for _, project := range projectTypes {
		t.Run(project.name, func(t *testing.T) {
			metrics := measureLargeProjectPerformance(project.name, project.projectPath)
			
			// Log results
			logLargeProjectMetrics(t, metrics)
			
			// Validate performance requirements
			if metrics.ScanTime > 5*time.Minute {
				t.Errorf("Scan time %v exceeds 5 minute limit for %s", metrics.ScanTime, project.name)
			}
			
			if metrics.MemoryUsage > 2048 {
				t.Errorf("Memory usage %d MB exceeds 2GB limit for %s", metrics.MemoryUsage, project.name)
			}
			
			if !metrics.Success {
				t.Errorf("Scan failed for %s: %s", project.name, metrics.ErrorMessage)
			}
			
			if !metrics.ProgressReported {
				t.Logf("Warning: Progress reporting not detected for %s", project.name)
			}
		})
	}
}

// startAPIServer starts the API server for load testing
func startAPIServer(t *testing.T) *exec.Cmd {
	cmd := exec.Command("go", "run", "main.go", "serve", "--port", "8080")
	cmd.Dir = "/Users/alikorsi/Documents/Typosentinel"
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	
	err := cmd.Start()
	if err != nil {
		t.Logf("Failed to start API server: %v", err)
		return nil
	}
	
	t.Logf("Started API server with PID: %d", cmd.Process.Pid)
	return cmd
}

// stopAPIServer stops the API server
func stopAPIServer(cmd *exec.Cmd) {
	if cmd != nil && cmd.Process != nil {
		cmd.Process.Kill()
		cmd.Wait()
	}
}

// isServerRunning checks if the server is running
func isServerRunning(healthURL string) bool {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(healthURL)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// performLoadTest executes the load test
func performLoadTest(concurrentUsers int, duration time.Duration, targetRPM int) LoadTestMetrics {
	var (
		totalRequests   int64
		successfulReqs  int64
		failedReqs      int64
		responseTimes   []time.Duration
		responseTimesMu sync.Mutex
		peakMemory      int64
	)
	
	startTime := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()
	
	// Calculate request interval
	requestInterval := time.Minute / time.Duration(targetRPM)
	
	var wg sync.WaitGroup
	
	// Start concurrent users
	for i := 0; i < concurrentUsers; i++ {
		wg.Add(1)
		go func(userID int) {
			defer wg.Done()
			
			ticker := time.NewTicker(requestInterval)
			defer ticker.Stop()
			
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					// Make API request
					record := makeAPIRequest("http://localhost:8080/api/scan", "lodash")
					
					atomic.AddInt64(&totalRequests, 1)
					if record.Success {
						atomic.AddInt64(&successfulReqs, 1)
					} else {
						atomic.AddInt64(&failedReqs, 1)
					}
					
					// Record response time
					responseTimesMu.Lock()
					responseTimes = append(responseTimes, record.ResponseTime)
					responseTimesMu.Unlock()
					
					// Monitor memory usage
					var m runtime.MemStats
					runtime.ReadMemStats(&m)
					currentMemory := int64(m.Alloc / 1024 / 1024)
					if currentMemory > atomic.LoadInt64(&peakMemory) {
						atomic.StoreInt64(&peakMemory, currentMemory)
					}
				}
			}
		}(i)
	}
	
	wg.Wait()
	testDuration := time.Since(startTime)
	
	// Calculate metrics
	var avgResponseTime time.Duration
	if len(responseTimes) > 0 {
		var total time.Duration
		for _, rt := range responseTimes {
			total += rt
		}
		avgResponseTime = total / time.Duration(len(responseTimes))
	}
	
	p95ResponseTime := calculatePercentile(responseTimes, 0.95)
	p99ResponseTime := calculatePercentile(responseTimes, 0.99)
	throughput := float64(totalRequests) / testDuration.Seconds()
	errorRate := float64(failedReqs) / float64(totalRequests) * 100
	
	return LoadTestMetrics{
		TotalRequests:   totalRequests,
		SuccessfulReqs:  successfulReqs,
		FailedReqs:      failedReqs,
		AvgResponseTime: avgResponseTime,
		P95ResponseTime: p95ResponseTime,
		P99ResponseTime: p99ResponseTime,
		Throughput:      throughput,
		ErrorRate:       errorRate,
		TestDuration:    testDuration,
		ConcurrentUsers: concurrentUsers,
		PeakMemoryUsage: peakMemory,
	}
}

// makeAPIRequest makes a single API request and measures response time
func makeAPIRequest(url, packageName string) ResponseTimeRecord {
	startTime := time.Now()
	
	// Prepare request body
	requestBody := map[string]string{
		"package": packageName,
	}
	jsonBody, _ := json.Marshal(requestBody)
	
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Post(url, "application/json", bytes.NewBuffer(jsonBody))
	
	responseTime := time.Since(startTime)
	
	record := ResponseTimeRecord{
		Timestamp:    startTime,
		ResponseTime: responseTime,
		Success:      err == nil,
	}
	
	if err != nil {
		record.Error = err.Error()
		return record
	}
	
	defer resp.Body.Close()
	record.StatusCode = resp.StatusCode
	record.Success = resp.StatusCode >= 200 && resp.StatusCode < 300
	
	if !record.Success {
		body, _ := io.ReadAll(resp.Body)
		record.Error = fmt.Sprintf("HTTP %d: %s", resp.StatusCode, string(body))
	}
	
	return record
}

// measureLargeProjectPerformance measures performance for large project scanning
func measureLargeProjectPerformance(projectType, projectPath string) LargeProjectMetrics {
	var m runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m)
	
	startTime := time.Now()
	
	// Execute project scan
	cmd := exec.Command("go", "run", "main.go", "scan", "--local", projectPath, "--format", "json")
	cmd.Dir = "/Users/alikorsi/Documents/Typosentinel"
	
	output, err := cmd.CombinedOutput()
	scanTime := time.Since(startTime)
	
	runtime.ReadMemStats(&m)
	memoryUsed := int64(m.Alloc / 1024 / 1024)
	
	// Analyze output for progress reporting and dependency count
	outputStr := string(output)
	progressReported := containsProgressIndicators(outputStr)
	dependencyCount := countDependencies(outputStr)
	accuracyScore := calculateAccuracyScore(outputStr)
	
	metrics := LargeProjectMetrics{
		ProjectType:      projectType,
		DependencyCount:  dependencyCount,
		ScanTime:         scanTime,
		MemoryUsage:      memoryUsed,
		AccuracyScore:    accuracyScore,
		ProgressReported: progressReported,
		Success:          err == nil,
	}
	
	if err != nil {
		metrics.ErrorMessage = err.Error()
	}
	
	return metrics
}

// calculatePercentile calculates the specified percentile of response times
func calculatePercentile(times []time.Duration, percentile float64) time.Duration {
	if len(times) == 0 {
		return 0
	}
	
	// Sort times
	for i := 0; i < len(times)-1; i++ {
		for j := 0; j < len(times)-i-1; j++ {
			if times[j] > times[j+1] {
				times[j], times[j+1] = times[j+1], times[j]
			}
		}
	}
	
	index := int(float64(len(times)) * percentile)
	if index >= len(times) {
		index = len(times) - 1
	}
	
	return times[index]
}

// containsProgressIndicators checks if output contains progress indicators
func containsProgressIndicators(output string) bool {
	progressIndicators := []string{
		"progress", "scanning", "analyzing", "processing",
		"%", "completed", "finished", "done",
	}
	
	for _, indicator := range progressIndicators {
		if bytes.Contains([]byte(output), []byte(indicator)) {
			return true
		}
	}
	
	return false
}

// countDependencies counts dependencies from scan output
func countDependencies(output string) int {
	// This is a simplified dependency counter
	// In practice, you'd parse the JSON output more carefully
	count := 0
	lines := bytes.Split([]byte(output), []byte("\n"))
	for _, line := range lines {
		if bytes.Contains(line, []byte("dependency")) || bytes.Contains(line, []byte("package")) {
			count++
		}
	}
	return count
}

// calculateAccuracyScore calculates accuracy score from scan results
func calculateAccuracyScore(output string) float64 {
	// Simplified accuracy calculation based on successful detections
	if bytes.Contains([]byte(output), []byte("error")) {
		return 0.7 // Lower score if errors present
	}
	if bytes.Contains([]byte(output), []byte("completed")) {
		return 0.95 // High score for successful completion
	}
	return 0.8 // Default score
}

// logLoadTestMetrics logs load test metrics
func logLoadTestMetrics(t *testing.T, metrics LoadTestMetrics) {
	jsonData, _ := json.MarshalIndent(metrics, "", "  ")
	t.Logf("Load Test Metrics:\n%s", string(jsonData))
}

// logLargeProjectMetrics logs large project metrics
func logLargeProjectMetrics(t *testing.T, metrics LargeProjectMetrics) {
	jsonData, _ := json.MarshalIndent(metrics, "", "  ")
	t.Logf("Large Project Metrics for %s:\n%s", metrics.ProjectType, string(jsonData))
}

// BenchmarkAPIEndpoint benchmarks API endpoint performance
func BenchmarkAPIEndpoint(b *testing.B) {
	// This would require the API server to be running
	b.Skip("API server required for benchmark")
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		record := makeAPIRequest("http://localhost:8080/api/scan", "lodash")
		if !record.Success {
			b.Errorf("API request failed: %s", record.Error)
		}
	}
}

// BenchmarkLargeProjectScan benchmarks large project scanning
func BenchmarkLargeProjectScan(b *testing.B) {
	projectPath := "test-analysis/npm-project"
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cmd := exec.Command("go", "run", "main.go", "scan", "--local", projectPath, "--format", "json")
		cmd.Dir = "/Users/alikorsi/Documents/Typosentinel"
		_, err := cmd.CombinedOutput()
		if err != nil {
			b.Errorf("Project scan failed: %v", err)
		}
	}
}