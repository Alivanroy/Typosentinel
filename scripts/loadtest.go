package main

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/internal/detector"
)

func main() {
	// Load test configuration
	cfg := &config.Config{
		TypoDetection: &config.TypoDetectionConfig{
			Enabled:           true,
			Threshold:         0.8,
			MaxDistance:       2,
			CheckSimilarNames: true,
			CheckHomoglyphs:   true,
		},
	}

	engine := detector.New(cfg)

	// Test packages
	testPackages := []string{
		"lodash", "express", "react", "angular", "vue",
		"webpack", "babel", "eslint", "prettier", "typescript",
	}

	// Load test parameters
	concurrentUsers := 50
	requestsPerUser := 100
	totalRequests := concurrentUsers * requestsPerUser

	fmt.Printf("Starting load test with %d concurrent users, %d requests each\n", concurrentUsers, requestsPerUser)
	fmt.Printf("Total requests: %d\n", totalRequests)

	start := time.Now()
	var wg sync.WaitGroup
	var successCount, errorCount int64
	var mu sync.Mutex

	for i := 0; i < concurrentUsers; i++ {
		wg.Add(1)
		go func(userID int) {
			defer wg.Done()
			for j := 0; j < requestsPerUser; j++ {
				pkg := testPackages[j%len(testPackages)]
				ctx := context.Background()

				_, err := engine.CheckPackage(ctx, pkg, "npm")

				mu.Lock()
				if err != nil {
					errorCount++
				} else {
					successCount++
				}
				mu.Unlock()
			}
		}(i)
	}

	wg.Wait()
	duration := time.Since(start)

	// Calculate metrics
	requestsPerSecond := float64(totalRequests) / duration.Seconds()
	avgLatency := duration / time.Duration(totalRequests)
	errorRate := float64(errorCount) / float64(totalRequests) * 100

	fmt.Printf("\n=== Load Test Results ===\n")
	fmt.Printf("Duration: %v\n", duration)
	fmt.Printf("Total Requests: %d\n", totalRequests)
	fmt.Printf("Successful: %d\n", successCount)
	fmt.Printf("Errors: %d\n", errorCount)
	fmt.Printf("Requests/sec: %.2f\n", requestsPerSecond)
	fmt.Printf("Average Latency: %v\n", avgLatency)
	fmt.Printf("Error Rate: %.2f%%\n", errorRate)

	// Performance targets validation
	fmt.Printf("\n=== Performance Validation ===\n")
	if requestsPerSecond >= 100 {
		fmt.Printf("✅ Throughput target met (>= 100 req/s): %.2f req/s\n", requestsPerSecond)
	} else {
		fmt.Printf("❌ Throughput target missed (>= 100 req/s): %.2f req/s\n", requestsPerSecond)
	}

	if avgLatency <= 100*time.Millisecond {
		fmt.Printf("✅ Latency target met (<= 100ms): %v\n", avgLatency)
	} else {
		fmt.Printf("❌ Latency target missed (<= 100ms): %v\n", avgLatency)
	}

	if errorRate <= 1.0 {
		fmt.Printf("✅ Error rate target met (<= 1%%): %.2f%%\n", errorRate)
	} else {
		fmt.Printf("❌ Error rate target missed (<= 1%%): %.2f%%\n", errorRate)
	}
}
