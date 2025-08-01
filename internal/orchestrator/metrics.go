package orchestrator

import (
	"log"
	"sync"
	"time"
)

// DefaultMetricsCollector implements the MetricsCollector interface
type DefaultMetricsCollector struct {
	mu                    sync.RWMutex
	scanDurations         map[string][]time.Duration
	scanResults           map[string]map[bool]int64
	repositoriesDiscovered map[string]int64
	policyViolations      map[string]int64
	scanCounters          map[string]map[string]int64
	logger                *log.Logger
}

// NewDefaultMetricsCollector creates a new metrics collector
func NewDefaultMetricsCollector(logger *log.Logger) *DefaultMetricsCollector {
	if logger == nil {
		logger = log.New(log.Writer(), "[MetricsCollector] ", log.LstdFlags)
	}
	return &DefaultMetricsCollector{
		scanDurations:         make(map[string][]time.Duration),
		scanResults:           make(map[string]map[bool]int64),
		repositoriesDiscovered: make(map[string]int64),
		policyViolations:      make(map[string]int64),
		scanCounters:          make(map[string]map[string]int64),
		logger:                logger,
	}
}

// RecordScanDuration records the duration of a scan for a platform
func (mc *DefaultMetricsCollector) RecordScanDuration(platform string, duration time.Duration) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	if mc.scanDurations[platform] == nil {
		mc.scanDurations[platform] = make([]time.Duration, 0)
	}
	mc.scanDurations[platform] = append(mc.scanDurations[platform], duration)

	// Keep only the last 100 durations to prevent memory growth
	if len(mc.scanDurations[platform]) > 100 {
		mc.scanDurations[platform] = mc.scanDurations[platform][1:]
	}
}

// RecordScanResult records the result of a scan (success/failure)
func (mc *DefaultMetricsCollector) RecordScanResult(platform string, success bool) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	if mc.scanResults[platform] == nil {
		mc.scanResults[platform] = make(map[bool]int64)
	}
	mc.scanResults[platform][success]++
}

// RecordRepositoriesDiscovered records the number of repositories discovered for a platform
func (mc *DefaultMetricsCollector) RecordRepositoriesDiscovered(platform string, count int) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	mc.repositoriesDiscovered[platform] += int64(count)
}

// RecordPolicyViolations records the number of policy violations for a platform
func (mc *DefaultMetricsCollector) RecordPolicyViolations(platform string, count int) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	mc.policyViolations[platform] += int64(count)
}

// IncrementScanCounter increments a scan counter for a platform and scan type
func (mc *DefaultMetricsCollector) IncrementScanCounter(platform string, scanType string) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	if mc.scanCounters[platform] == nil {
		mc.scanCounters[platform] = make(map[string]int64)
	}
	mc.scanCounters[platform][scanType]++
}

// GetMetrics returns all collected metrics
func (mc *DefaultMetricsCollector) GetMetrics() map[string]interface{} {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	metrics := make(map[string]interface{})

	// Calculate average scan durations
	avgDurations := make(map[string]time.Duration)
	for platform, durations := range mc.scanDurations {
		if len(durations) > 0 {
			var total time.Duration
			for _, d := range durations {
				total += d
			}
			avgDurations[platform] = total / time.Duration(len(durations))
		}
	}

	// Calculate success rates
	successRates := make(map[string]float64)
	for platform, results := range mc.scanResults {
		total := results[true] + results[false]
		if total > 0 {
			successRates[platform] = float64(results[true]) / float64(total) * 100
		}
	}

	metrics["average_scan_durations"] = avgDurations
	metrics["success_rates"] = successRates
	metrics["scan_results"] = mc.scanResults
	metrics["repositories_discovered"] = mc.repositoriesDiscovered
	metrics["policy_violations"] = mc.policyViolations
	metrics["scan_counters"] = mc.scanCounters

	return metrics
}

// GetPlatformMetrics returns metrics for a specific platform
func (mc *DefaultMetricsCollector) GetPlatformMetrics(platform string) map[string]interface{} {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	metrics := make(map[string]interface{})

	// Average scan duration
	if durations, exists := mc.scanDurations[platform]; exists && len(durations) > 0 {
		var total time.Duration
		for _, d := range durations {
			total += d
		}
		metrics["average_scan_duration"] = total / time.Duration(len(durations))
		metrics["total_scans"] = len(durations)
	}

	// Success rate
	if results, exists := mc.scanResults[platform]; exists {
		total := results[true] + results[false]
		if total > 0 {
			metrics["success_rate"] = float64(results[true]) / float64(total) * 100
			metrics["successful_scans"] = results[true]
			metrics["failed_scans"] = results[false]
		}
	}

	// Other metrics
	if count, exists := mc.repositoriesDiscovered[platform]; exists {
		metrics["repositories_discovered"] = count
	}

	if count, exists := mc.policyViolations[platform]; exists {
		metrics["policy_violations"] = count
	}

	if counters, exists := mc.scanCounters[platform]; exists {
		metrics["scan_counters"] = counters
	}

	return metrics
}

// Reset clears all metrics
func (mc *DefaultMetricsCollector) Reset() {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	mc.scanDurations = make(map[string][]time.Duration)
	mc.scanResults = make(map[string]map[bool]int64)
	mc.repositoriesDiscovered = make(map[string]int64)
	mc.policyViolations = make(map[string]int64)
	mc.scanCounters = make(map[string]map[string]int64)
}