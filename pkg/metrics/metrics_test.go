package metrics

import (
	"testing"
	"time"
)

func TestSimpleMetricsCollector(t *testing.T) {
	c := NewSimpleMetricsCollector()
	c.RecordScanDuration(100 * time.Millisecond)
	c.RecordThreatDetected("high")
	c.RecordPackageScanned("npm")
	m := c.GetMetrics()
	if m["total_scans"].(int64) != 1 {
		t.Fatalf("expected scans 1")
	}
}

func TestSingletonMetrics(t *testing.T) {
	m := GetInstance()
	m.RecordScanDuration(50 * time.Millisecond)
	m.RecordThreatDetected("medium")
	m.RecordPackageScanned("pypi")
	if m.ConfigUpdates() == nil {
		t.Fatalf("expected config updates counter")
	}
	m.ConfigUpdates().Inc()
	got := m.GetMetrics()
	if got["total_scans"].(int64) < 1 {
		t.Fatalf("expected total scans >=1")
	}
}
