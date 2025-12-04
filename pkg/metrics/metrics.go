package metrics

import (
	"sync"
	"time"
)

// MetricsCollector interface for collecting metrics
type MetricsCollector interface {
	RecordScanDuration(duration time.Duration)
	RecordThreatDetected(severity string)
	RecordPackageScanned(registry string)
	GetMetrics() map[string]interface{}
}

// Counter represents a counter metric
type Counter struct {
	value int64
	mu    sync.RWMutex
}

// Inc increments the counter
func (c *Counter) Inc() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.value++
}

// WithLabelValues returns the counter (for compatibility)
func (c *Counter) WithLabelValues(labels ...string) *Counter {
	return c
}

// Metrics struct for metrics data
type Metrics struct {
	scans         int64
	threats       map[string]int64
	packages      map[string]int64
	totalDuration time.Duration
	configUpdates *Counter
	mu            sync.RWMutex
}

// SimpleMetricsCollector basic implementation
type SimpleMetricsCollector struct {
	scans         int64
	threats       map[string]int64
	packages      map[string]int64
	totalDuration time.Duration
}

var (
	instance *Metrics
	once     sync.Once
)

// GetInstance returns the singleton metrics instance
func GetInstance() *Metrics {
	once.Do(func() {
		instance = &Metrics{
			threats:       make(map[string]int64),
			packages:      make(map[string]int64),
			configUpdates: &Counter{},
		}
	})
	return instance
}

// NewSimpleMetricsCollector creates a new metrics collector
func NewSimpleMetricsCollector() *SimpleMetricsCollector {
	return &SimpleMetricsCollector{
		threats:  make(map[string]int64),
		packages: make(map[string]int64),
	}
}

// RecordScanDuration records scan duration
func (s *SimpleMetricsCollector) RecordScanDuration(duration time.Duration) {
	s.scans++
	s.totalDuration += duration
}

// RecordThreatDetected records a threat detection
func (s *SimpleMetricsCollector) RecordThreatDetected(severity string) {
	s.threats[severity]++
}

// RecordPackageScanned records a package scan
func (s *SimpleMetricsCollector) RecordPackageScanned(registry string) {
	s.packages[registry]++
}

// GetMetrics returns current metrics
func (s *SimpleMetricsCollector) GetMetrics() map[string]interface{} {
	return map[string]interface{}{
		"total_scans":          s.scans,
		"total_duration":       s.totalDuration.Seconds(),
		"threats":              s.threats,
		"packages_by_registry": s.packages,
	}
}

// RecordScanDuration records scan duration for Metrics
func (m *Metrics) RecordScanDuration(duration time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.scans++
	m.totalDuration += duration
}

// RecordThreatDetected records a threat detection for Metrics
func (m *Metrics) RecordThreatDetected(severity string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.threats[severity]++
}

// RecordPackageScanned records a package scan for Metrics
func (m *Metrics) RecordPackageScanned(registry string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.packages[registry]++
}

// GetMetrics returns current metrics for Metrics
func (m *Metrics) GetMetrics() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return map[string]interface{}{
		"total_scans":          m.scans,
		"total_duration":       m.totalDuration.Seconds(),
		"threats":              m.threats,
		"packages_by_registry": m.packages,
	}
}

// ConfigUpdates returns the config updates counter
func (m *Metrics) ConfigUpdates() *Counter {
	return m.configUpdates
}
