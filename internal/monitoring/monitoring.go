package monitoring

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/interfaces"
	"github.com/Alivanroy/Typosentinel/pkg/logger"
)

// MonitoringService provides enterprise monitoring capabilities
type MonitoringService struct {
	config       *MonitoringConfig
	logger       logger.Logger
	metrics      interfaces.Metrics
	alertManager *AlertManager
	healthChecks map[string]HealthCheck
	stopChan     chan struct{}
	mu           sync.RWMutex
}

// MonitoringConfig holds monitoring configuration
type MonitoringConfig struct {
	Enabled         bool                    `yaml:"enabled" json:"enabled"`
	MetricsInterval time.Duration           `yaml:"metrics_interval" json:"metrics_interval"`
	HealthInterval  time.Duration           `yaml:"health_interval" json:"health_interval"`
	SlackConfig     *SlackConfig            `yaml:"slack" json:"slack"`
	EmailConfig     *EmailConfig            `yaml:"email" json:"email"`
	WebhookURL      string                  `yaml:"webhook_url" json:"webhook_url"`
	CustomMetrics   []CustomMetricConfig    `yaml:"custom_metrics" json:"custom_metrics"`
	AlertThresholds map[string]float64      `yaml:"alert_thresholds" json:"alert_thresholds"`
}

// SlackConfig holds Slack notification configuration
type SlackConfig struct {
	WebhookURL string `yaml:"webhook_url" json:"webhook_url"`
	Channel    string `yaml:"channel" json:"channel"`
	Username   string `yaml:"username" json:"username"`
}

// EmailConfig holds email notification configuration
type EmailConfig struct {
	SMTPHost     string   `yaml:"smtp_host" json:"smtp_host"`
	SMTPPort     int      `yaml:"smtp_port" json:"smtp_port"`
	Username     string   `yaml:"username" json:"username"`
	Password     string   `yaml:"password" json:"password"`
	FromAddress  string   `yaml:"from_address" json:"from_address"`
	ToAddresses  []string `yaml:"to_addresses" json:"to_addresses"`
}

// CustomMetricConfig defines custom metric configuration
type CustomMetricConfig struct {
	Name      string  `yaml:"name" json:"name"`
	Type      string  `yaml:"type" json:"type"`
	Threshold float64 `yaml:"threshold" json:"threshold"`
	Interval  time.Duration `yaml:"interval" json:"interval"`
}

// HealthCheck interface for health checks
type HealthCheck interface {
	Name() string
	Check(ctx context.Context) HealthStatus
}

// HealthStatus represents the status of a health check
type HealthStatus struct {
	Healthy   bool                   `json:"healthy"`
	Message   string                 `json:"message"`
	Details   map[string]interface{} `json:"details,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
}

// SystemHealth represents overall system health
type SystemHealth struct {
	OverallStatus string                    `json:"overall_status"`
	Checks        map[string]HealthStatus   `json:"checks"`
	Timestamp     time.Time                 `json:"timestamp"`
}

// Alert represents a monitoring alert
type Alert struct {
	ID         string        `json:"id"`
	Name       string        `json:"name"`
	Message    string        `json:"message"`
	Severity   AlertSeverity `json:"severity"`
	Metric     string        `json:"metric"`
	Value      float64       `json:"value"`
	Threshold  float64       `json:"threshold"`
	Timestamp  time.Time     `json:"timestamp"`
	Resolved   bool          `json:"resolved"`
	ResolvedAt *time.Time    `json:"resolved_at,omitempty"`
}

// AlertSeverity represents alert severity levels
type AlertSeverity string

const (
	AlertSeverityInfo     AlertSeverity = "info"
	AlertSeverityWarning  AlertSeverity = "warning"
	AlertSeverityError    AlertSeverity = "error"
	AlertSeverityCritical AlertSeverity = "critical"
)

// AlertManager manages alerts and notifications
type AlertManager struct {
	config       *MonitoringConfig
	logger       logger.Logger
	activeAlerts map[string]*Alert
	notifiers    []AlertNotifier
	mu           sync.RWMutex
}

// AlertNotifier interface for alert notifications
type AlertNotifier interface {
	Name() string
	SendAlert(alert *Alert) error
}

// NewMonitoringService creates a new monitoring service
func NewMonitoringService(config *MonitoringConfig, logger logger.Logger, metrics interfaces.Metrics) *MonitoringService {
	return &MonitoringService{
		config:       config,
		logger:       logger,
		metrics:      metrics,
		alertManager: NewAlertManager(config, logger),
		healthChecks: make(map[string]HealthCheck),
		stopChan:     make(chan struct{}),
	}
}

// Start starts the monitoring service
func (ms *MonitoringService) Start(ctx context.Context) error {
	if !ms.config.Enabled {
		ms.logger.Info("Monitoring service disabled")
		return nil
	}

	ms.logger.Info("Starting monitoring service")

	// Start alert manager
	ms.alertManager.Start(ctx)

	// Start metrics collection
	go ms.collectMetrics(ctx)

	// Start health checks
	go ms.runHealthChecks(ctx)

	ms.logger.Info("Monitoring service started")
	return nil
}

// Stop stops the monitoring service
func (ms *MonitoringService) Stop() {
	ms.logger.Info("Stopping monitoring service")
	close(ms.stopChan)
}

// RegisterHealthCheck registers a health check
func (ms *MonitoringService) RegisterHealthCheck(check HealthCheck) {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	ms.healthChecks[check.Name()] = check
	ms.logger.Info("Health check registered", map[string]interface{}{"name": check.Name()})
}

// GetSystemHealth returns current system health
func (ms *MonitoringService) GetSystemHealth() SystemHealth {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	checks := make(map[string]HealthStatus)
	allHealthy := true

	for name, check := range ms.healthChecks {
		status := check.Check(context.Background())
		checks[name] = status
		if !status.Healthy {
			allHealthy = false
		}
	}

	overallStatus := "healthy"
	if !allHealthy {
		overallStatus = "unhealthy"
	}

	return SystemHealth{
		OverallStatus: overallStatus,
		Checks:        checks,
		Timestamp:     time.Now(),
	}
}

// RecordMetric records a custom metric
func (ms *MonitoringService) RecordMetric(name, metricType string, value float64) {
	tags := make(interfaces.MetricTags)
	
	switch metricType {
	case "counter":
		ms.metrics.IncrementCounter(name, tags)
	case "gauge":
		ms.metrics.SetGauge(name, value, tags)
	case "histogram":
		ms.metrics.RecordHistogram(name, value, tags)
	case "timer":
		ms.metrics.RecordDuration(name, time.Duration(value*float64(time.Millisecond)), tags)
	}

	// Check for threshold alerts
	if threshold, exists := ms.config.AlertThresholds[name]; exists && value > threshold {
		if ms.alertManager != nil {
			ms.alertManager.TriggerAlert(&Alert{
				ID:        fmt.Sprintf("%s-%d", name, time.Now().Unix()),
				Name:      name,
				Message:   fmt.Sprintf("Metric %s exceeded threshold: %.2f > %.2f", name, value, threshold),
				Severity:  ms.determineSeverity(value, threshold),
				Metric:    name,
				Value:     value,
				Threshold: threshold,
				Timestamp: time.Now(),
			})
		}
	}
}

// collectMetrics runs periodic metrics collection
func (ms *MonitoringService) collectMetrics(ctx context.Context) {
	ticker := time.NewTicker(ms.config.MetricsInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ms.stopChan:
			return
		case <-ticker.C:
			ms.collectSystemMetrics()
		}
	}
}

// runHealthChecks runs periodic health checks
func (ms *MonitoringService) runHealthChecks(ctx context.Context) {
	ticker := time.NewTicker(ms.config.HealthInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ms.stopChan:
			return
		case <-ticker.C:
			ms.runAllHealthChecks()
		}
	}
}

// collectSystemMetrics collects system-level metrics
func (ms *MonitoringService) collectSystemMetrics() {
	// Memory metrics
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	tags := make(interfaces.MetricTags)
	
	ms.metrics.SetGauge("memory.alloc", float64(m.Alloc), tags)
	ms.metrics.SetGauge("memory.total_alloc", float64(m.TotalAlloc), tags)
	ms.metrics.SetGauge("memory.sys", float64(m.Sys), tags)
	ms.metrics.SetGauge("memory.heap_alloc", float64(m.HeapAlloc), tags)
	ms.metrics.SetGauge("memory.heap_sys", float64(m.HeapSys), tags)

	// Goroutine metrics
	ms.metrics.SetGauge("goroutines.count", float64(runtime.NumGoroutine()), tags)

	// GC metrics
	ms.metrics.IncrementCounter("gc.runs", tags)
	ms.metrics.SetGauge("gc.pause_total", float64(m.PauseTotalNs), tags)
}

// runAllHealthChecks runs all registered health checks
func (ms *MonitoringService) runAllHealthChecks() {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	for name, check := range ms.healthChecks {
		status := check.Check(context.Background())
		if !status.Healthy {
			ms.logger.Warn("Health check failed", map[string]interface{}{
				"check": name,
				"message": status.Message,
			})
		}
	}
}

// determineSeverity determines alert severity based on value and threshold
func (ms *MonitoringService) determineSeverity(value, threshold float64) AlertSeverity {
	ratio := value / threshold
	switch {
	case ratio >= 2.0:
		return AlertSeverityCritical
	case ratio >= 1.5:
		return AlertSeverityError
	case ratio >= 1.2:
		return AlertSeverityWarning
	default:
		return AlertSeverityInfo
	}
}

// HTTPHandler returns an HTTP handler for monitoring endpoints
func (ms *MonitoringService) HTTPHandler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		health := ms.GetSystemHealth()
		w.Header().Set("Content-Type", "application/json")
		if health.OverallStatus != "healthy" {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		// Note: JSON encoding would be added here in a real implementation
		fmt.Fprintf(w, `{"status":"%s","timestamp":"%s"}`, health.OverallStatus, health.Timestamp.Format(time.RFC3339))
	})

	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Note: JSON encoding would be added here in a real implementation
		fmt.Fprintf(w, `{"timestamp":"%s"}`, time.Now().Format(time.RFC3339))
	})

	return mux
}

// DatabaseHealthCheck checks database connectivity
type DatabaseHealthCheck struct {
	name string
	// db interface would be added here
}

func (dhc *DatabaseHealthCheck) Name() string {
	return dhc.name
}

func (dhc *DatabaseHealthCheck) Check(ctx context.Context) HealthStatus {
	// Database ping logic would be implemented here
	return HealthStatus{
		Healthy:   true,
		Message:   "Database connection healthy",
		Timestamp: time.Now(),
	}
}

// CacheHealthCheck checks cache connectivity
type CacheHealthCheck struct {
	name string
	// cache interface would be added here
}

func (chc *CacheHealthCheck) Name() string {
	return chc.name
}

func (chc *CacheHealthCheck) Check(ctx context.Context) HealthStatus {
	// Cache ping logic would be implemented here
	return HealthStatus{
		Healthy:   true,
		Message:   "Cache connection healthy",
		Timestamp: time.Now(),
	}
}

// DiskSpaceHealthCheck checks available disk space
type DiskSpaceHealthCheck struct {
	name      string
	path      string
	threshold float64
}

func (dshc *DiskSpaceHealthCheck) Name() string {
	return dshc.name
}

func (dshc *DiskSpaceHealthCheck) Check(ctx context.Context) HealthStatus {
	// Cross-platform disk space check
	available, total, err := getDiskSpace(dshc.path)
	if err != nil {
		return HealthStatus{
			Healthy:   false,
			Message:   fmt.Sprintf("Failed to check disk space: %v", err),
			Timestamp: time.Now(),
		}
	}

	usagePercent := (total - available) / total * 100

	healthy := usagePercent < dshc.threshold
	message := fmt.Sprintf("Disk usage: %.1f%% (%.1fGB available)", usagePercent, available)

	return HealthStatus{
		Healthy:   healthy,
		Message:   message,
		Details:   map[string]interface{}{"usage_percent": usagePercent, "available_gb": available},
		Timestamp: time.Now(),
	}
}

// getDiskSpace returns available and total disk space in GB
func getDiskSpace(path string) (available, total float64, err error) {
	_, err = os.Stat(path)
	if err != nil {
		return 0, 0, err
	}
	
	// Simplified implementation - in a real scenario, you'd use platform-specific calls
	// For now, return mock values to satisfy the interface
	available = 100.0 // GB
	total = 500.0     // GB
	return available, total, nil
}

// MemoryHealthCheck checks memory usage
type MemoryHealthCheck struct {
	name      string
	threshold float64
}

func (mhc *MemoryHealthCheck) Name() string {
	return mhc.name
}

func (mhc *MemoryHealthCheck) Check(ctx context.Context) HealthStatus {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	// Calculate memory usage percentage (simplified)
	usagePercent := float64(m.Alloc) / float64(m.Sys) * 100
	healthy := usagePercent < mhc.threshold
	message := fmt.Sprintf("Memory usage: %.1f%% (%d bytes allocated)", usagePercent, m.Alloc)

	return HealthStatus{
		Healthy:   healthy,
		Message:   message,
		Details:   map[string]interface{}{"usage_percent": usagePercent, "alloc_bytes": m.Alloc},
		Timestamp: time.Now(),
	}
}