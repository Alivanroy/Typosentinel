package monitoring

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"runtime"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"

	"github.com/typosentinel/typosentinel/pkg/metrics"
)

// AlertLevel defines the severity of an alert
type AlertLevel int

const (
	AlertLevelInfo AlertLevel = iota
	AlertLevelWarning
	AlertLevelError
	AlertLevelCritical
)

func (al AlertLevel) String() string {
	switch al {
	case AlertLevelInfo:
		return "info"
	case AlertLevelWarning:
		return "warning"
	case AlertLevelError:
		return "error"
	case AlertLevelCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// Alert represents a system alert
type Alert struct {
	ID          string                 `json:"id"`
	Level       AlertLevel             `json:"level"`
	Title       string                 `json:"title"`
	Message     string                 `json:"message"`
	Component   string                 `json:"component"`
	Metric      string                 `json:"metric"`
	Value       float64                `json:"value"`
	Threshold   float64                `json:"threshold"`
	Timestamp   time.Time              `json:"timestamp"`
	Resolved    bool                   `json:"resolved"`
	ResolvedAt  *time.Time             `json:"resolved_at,omitempty"`
	Metadata    map[string]interface{} `json:"metadata"`
	Notified    bool                   `json:"notified"`
	NotifiedAt  *time.Time             `json:"notified_at,omitempty"`
}

// HealthStatus represents the health status of a component
type HealthStatus int

const (
	HealthStatusHealthy HealthStatus = iota
	HealthStatusDegraded
	HealthStatusUnhealthy
	HealthStatusUnknown
)

func (hs HealthStatus) String() string {
	switch hs {
	case HealthStatusHealthy:
		return "healthy"
	case HealthStatusDegraded:
		return "degraded"
	case HealthStatusUnhealthy:
		return "unhealthy"
	case HealthStatusUnknown:
		return "unknown"
	default:
		return "unknown"
	}
}

// HealthCheck represents a health check for a component
type HealthCheck struct {
	Name        string                 `json:"name"`
	Component   string                 `json:"component"`
	Status      HealthStatus           `json:"status"`
	Message     string                 `json:"message"`
	LastCheck   time.Time              `json:"last_check"`
	Duration    time.Duration          `json:"duration"`
	Metadata    map[string]interface{} `json:"metadata"`
	CheckFunc   func() HealthCheckResult `json:"-"`
	Interval    time.Duration          `json:"interval"`
	Timeout     time.Duration          `json:"timeout"`
	Enabled     bool                   `json:"enabled"`
}

// HealthCheckResult represents the result of a health check
type HealthCheckResult struct {
	Status   HealthStatus
	Message  string
	Metadata map[string]interface{}
	Error    error
}

// SystemMetrics represents system-wide metrics
type SystemMetrics struct {
	CPUUsage        float64   `json:"cpu_usage"`
	MemoryUsage     float64   `json:"memory_usage"`
	MemoryTotal     uint64    `json:"memory_total"`
	MemoryUsed      uint64    `json:"memory_used"`
	Goroutines      int       `json:"goroutines"`
	GCPauses        []float64 `json:"gc_pauses"`
	Uptime          time.Duration `json:"uptime"`
	Timestamp       time.Time `json:"timestamp"`
}

// ComponentMetrics represents metrics for a specific component
type ComponentMetrics struct {
	Component     string                 `json:"component"`
	Metrics       map[string]float64     `json:"metrics"`
	HealthStatus  HealthStatus           `json:"health_status"`
	LastUpdated   time.Time              `json:"last_updated"`
	Metadata      map[string]interface{} `json:"metadata"`
}

// Monitor manages system monitoring and alerting
type Monitor struct {
	healthChecks    map[string]*HealthCheck
	alerts          map[string]*Alert
	componentMetrics map[string]*ComponentMetrics
	redis           *redis.Client
	metrics         *metrics.Metrics
	config          MonitorConfig
	ctx             context.Context
	cancel          context.CancelFunc
	mu              sync.RWMutex
	alertsMu        sync.RWMutex
	metricsCollectors []MetricsCollector
	alertHandlers   []AlertHandler
	startTime       time.Time
	running         bool
}

// MonitorConfig holds configuration for the monitor
type MonitorConfig struct {
	HealthCheckInterval time.Duration `json:"health_check_interval"`
	MetricsInterval     time.Duration `json:"metrics_interval"`
	AlertRetention      time.Duration `json:"alert_retention"`
	MaxAlerts           int           `json:"max_alerts"`
	RedisKeyPrefix      string        `json:"redis_key_prefix"`
	EnableSystemMetrics bool          `json:"enable_system_metrics"`
	EnableAlerts        bool          `json:"enable_alerts"`
}

// MetricsCollector interface for collecting custom metrics
type MetricsCollector interface {
	CollectMetrics() (map[string]float64, error)
	GetComponent() string
}

// AlertHandler interface for handling alerts
type AlertHandler interface {
	HandleAlert(alert *Alert) error
	GetName() string
}

// AlertRule defines conditions for triggering alerts
type AlertRule struct {
	Name        string     `json:"name"`
	Component   string     `json:"component"`
	Metric      string     `json:"metric"`
	Operator    string     `json:"operator"` // >, <, >=, <=, ==, !=
	Threshold   float64    `json:"threshold"`
	Level       AlertLevel `json:"level"`
	Message     string     `json:"message"`
	Enabled     bool       `json:"enabled"`
	Cooldown    time.Duration `json:"cooldown"`
	LastTriggered *time.Time `json:"last_triggered,omitempty"`
}

// NewMonitor creates a new monitor instance
func NewMonitor(config MonitorConfig, redis *redis.Client) *Monitor {
	ctx, cancel := context.WithCancel(context.Background())

	// Set default values
	if config.HealthCheckInterval == 0 {
		config.HealthCheckInterval = 30 * time.Second
	}
	if config.MetricsInterval == 0 {
		config.MetricsInterval = 10 * time.Second
	}
	if config.AlertRetention == 0 {
		config.AlertRetention = 24 * time.Hour
	}
	if config.MaxAlerts == 0 {
		config.MaxAlerts = 1000
	}
	if config.RedisKeyPrefix == "" {
		config.RedisKeyPrefix = "typosentinel:monitor:"
	}

	return &Monitor{
		healthChecks:     make(map[string]*HealthCheck),
		alerts:           make(map[string]*Alert),
		componentMetrics: make(map[string]*ComponentMetrics),
		redis:            redis,
		metrics:          metrics.GetInstance(),
		config:           config,
		ctx:              ctx,
		cancel:           cancel,
		metricsCollectors: make([]MetricsCollector, 0),
		alertHandlers:    make([]AlertHandler, 0),
		startTime:        time.Now(),
	}
}

// Start starts the monitoring system
func (m *Monitor) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.running {
		return fmt.Errorf("monitor is already running")
	}

	m.running = true

	// Start health check routine
	go m.healthCheckRoutine()

	// Start metrics collection routine
	go m.metricsRoutine()

	// Start alert cleanup routine
	go m.alertCleanupRoutine()

	log.Println("Monitor started")
	return nil
}

// Stop stops the monitoring system
func (m *Monitor) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.running {
		return fmt.Errorf("monitor is not running")
	}

	m.cancel()
	m.running = false

	log.Println("Monitor stopped")
	return nil
}

// AddHealthCheck adds a health check
func (m *Monitor) AddHealthCheck(check *HealthCheck) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if check.Interval == 0 {
		check.Interval = m.config.HealthCheckInterval
	}
	if check.Timeout == 0 {
		check.Timeout = 5 * time.Second
	}
	if check.Metadata == nil {
		check.Metadata = make(map[string]interface{})
	}
	check.Enabled = true

	m.healthChecks[check.Name] = check
	log.Printf("Added health check: %s for component: %s", check.Name, check.Component)
}

// RemoveHealthCheck removes a health check
func (m *Monitor) RemoveHealthCheck(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.healthChecks, name)
	log.Printf("Removed health check: %s", name)
}

// AddMetricsCollector adds a metrics collector
func (m *Monitor) AddMetricsCollector(collector MetricsCollector) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.metricsCollectors = append(m.metricsCollectors, collector)
	log.Printf("Added metrics collector for component: %s", collector.GetComponent())
}

// AddAlertHandler adds an alert handler
func (m *Monitor) AddAlertHandler(handler AlertHandler) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.alertHandlers = append(m.alertHandlers, handler)
	log.Printf("Added alert handler: %s", handler.GetName())
}

// TriggerAlert triggers a new alert
func (m *Monitor) TriggerAlert(level AlertLevel, component, title, message string, metadata map[string]interface{}) {
	if !m.config.EnableAlerts {
		return
	}

	alert := &Alert{
		ID:        fmt.Sprintf("%s-%d", component, time.Now().UnixNano()),
		Level:     level,
		Title:     title,
		Message:   message,
		Component: component,
		Timestamp: time.Now(),
		Resolved:  false,
		Metadata:  metadata,
		Notified:  false,
	}

	m.alertsMu.Lock()
	m.alerts[alert.ID] = alert
	m.alertsMu.Unlock()

	// Handle the alert
	go m.handleAlert(alert)

	// Update metrics
	m.metrics.MonitoringAlerts.WithLabelValues(level.String(), component).Inc()

	log.Printf("Alert triggered: [%s] %s - %s", level.String(), title, message)
}

// ResolveAlert resolves an existing alert
func (m *Monitor) ResolveAlert(alertID string) {
	m.alertsMu.Lock()
	defer m.alertsMu.Unlock()

	if alert, exists := m.alerts[alertID]; exists {
		alert.Resolved = true
		now := time.Now()
		alert.ResolvedAt = &now
		log.Printf("Alert resolved: %s", alert.Title)
	}
}

// GetAlerts returns current alerts
func (m *Monitor) GetAlerts(level *AlertLevel, component string, resolved *bool) []*Alert {
	m.alertsMu.RLock()
	defer m.alertsMu.RUnlock()

	alerts := make([]*Alert, 0)
	for _, alert := range m.alerts {
		// Filter by level
		if level != nil && alert.Level != *level {
			continue
		}

		// Filter by component
		if component != "" && alert.Component != component {
			continue
		}

		// Filter by resolved status
		if resolved != nil && alert.Resolved != *resolved {
			continue
		}

		alerts = append(alerts, alert)
	}

	return alerts
}

// GetHealthStatus returns the health status of all components
func (m *Monitor) GetHealthStatus() map[string]HealthStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()

	status := make(map[string]HealthStatus)
	for _, check := range m.healthChecks {
		if check.Enabled {
			status[check.Component] = check.Status
		}
	}

	return status
}

// GetSystemMetrics returns current system metrics
func (m *Monitor) GetSystemMetrics() *SystemMetrics {
	if !m.config.EnableSystemMetrics {
		return nil
	}

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	return &SystemMetrics{
		MemoryUsage:  float64(memStats.Alloc) / float64(memStats.Sys) * 100,
		MemoryTotal:  memStats.Sys,
		MemoryUsed:   memStats.Alloc,
		Goroutines:   runtime.NumGoroutine(),
		Uptime:       time.Since(m.startTime),
		Timestamp:    time.Now(),
	}
}

// GetComponentMetrics returns metrics for all components
func (m *Monitor) GetComponentMetrics() map[string]*ComponentMetrics {
	m.mu.RLock()
	defer m.mu.RUnlock()

	metrics := make(map[string]*ComponentMetrics)
	for component, componentMetrics := range m.componentMetrics {
		metrics[component] = componentMetrics
	}

	return metrics
}

// healthCheckRoutine runs health checks periodically
func (m *Monitor) healthCheckRoutine() {
	ticker := time.NewTicker(m.config.HealthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.runHealthChecks()
		}
	}
}

// runHealthChecks executes all enabled health checks
func (m *Monitor) runHealthChecks() {
	m.mu.RLock()
	checks := make([]*HealthCheck, 0, len(m.healthChecks))
	for _, check := range m.healthChecks {
		if check.Enabled {
			checks = append(checks, check)
		}
	}
	m.mu.RUnlock()

	for _, check := range checks {
		go m.runHealthCheck(check)
	}
}

// runHealthCheck executes a single health check
func (m *Monitor) runHealthCheck(check *HealthCheck) {
	start := time.Now()

	// Create context with timeout
	ctx, cancel := context.WithTimeout(m.ctx, check.Timeout)
	defer cancel()

	// Run the health check
	result := make(chan HealthCheckResult, 1)
	go func() {
		result <- check.CheckFunc()
	}()

	var checkResult HealthCheckResult
	select {
	case checkResult = <-result:
	case <-ctx.Done():
		checkResult = HealthCheckResult{
			Status:  HealthStatusUnhealthy,
			Message: "Health check timed out",
			Error:   ctx.Err(),
		}
	}

	// Update check status
	m.mu.Lock()
	check.Status = checkResult.Status
	check.Message = checkResult.Message
	check.LastCheck = time.Now()
	check.Duration = time.Since(start)
	if checkResult.Metadata != nil {
		check.Metadata = checkResult.Metadata
	}
	m.mu.Unlock()

	// Update metrics
	m.metrics.MonitoringHealthChecks.WithLabelValues(check.Component, check.Name, checkResult.Status.String()).Inc()
	m.metrics.MonitoringHealthCheckDuration.WithLabelValues(check.Component, check.Name).Observe(check.Duration.Seconds())

	// Trigger alert if unhealthy
	if checkResult.Status == HealthStatusUnhealthy {
		m.TriggerAlert(
			AlertLevelError,
			check.Component,
			fmt.Sprintf("Health check failed: %s", check.Name),
			checkResult.Message,
			map[string]interface{}{
				"health_check": check.Name,
				"duration":     check.Duration.String(),
				"error":        checkResult.Error,
			},
		)
	}

	// Store health check result in Redis
	m.storeHealthCheckResult(check)
}

// metricsRoutine collects metrics periodically
func (m *Monitor) metricsRoutine() {
	ticker := time.NewTicker(m.config.MetricsInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.collectMetrics()
		}
	}
}

// collectMetrics collects metrics from all collectors
func (m *Monitor) collectMetrics() {
	m.mu.RLock()
	collectors := make([]MetricsCollector, len(m.metricsCollectors))
	copy(collectors, m.metricsCollectors)
	m.mu.RUnlock()

	for _, collector := range collectors {
		go m.collectComponentMetrics(collector)
	}

	// Collect system metrics if enabled
	if m.config.EnableSystemMetrics {
		m.collectSystemMetrics()
	}
}

// collectComponentMetrics collects metrics from a specific collector
func (m *Monitor) collectComponentMetrics(collector MetricsCollector) {
	metrics, err := collector.CollectMetrics()
	if err != nil {
		log.Printf("Failed to collect metrics for component %s: %v", collector.GetComponent(), err)
		return
	}

	componentMetrics := &ComponentMetrics{
		Component:    collector.GetComponent(),
		Metrics:      metrics,
		HealthStatus: HealthStatusHealthy, // Default to healthy
		LastUpdated:  time.Now(),
		Metadata:     make(map[string]interface{}),
	}

	// Determine health status based on metrics
	componentMetrics.HealthStatus = m.determineHealthStatus(componentMetrics)

	m.mu.Lock()
	m.componentMetrics[collector.GetComponent()] = componentMetrics
	m.mu.Unlock()

	// Store metrics in Redis
	m.storeComponentMetrics(componentMetrics)

	// Update Prometheus metrics
	for metricName, value := range metrics {
		m.metrics.MonitoringComponentMetrics.WithLabelValues(collector.GetComponent(), metricName).Set(value)
	}
}

// collectSystemMetrics collects system-wide metrics
func (m *Monitor) collectSystemMetrics() {
	systemMetrics := m.GetSystemMetrics()
	if systemMetrics == nil {
		return
	}

	// Update Prometheus metrics
	m.metrics.MonitoringSystemMetrics.WithLabelValues("memory_usage").Set(systemMetrics.MemoryUsage)
	m.metrics.MonitoringSystemMetrics.WithLabelValues("goroutines").Set(float64(systemMetrics.Goroutines))
	m.metrics.MonitoringSystemMetrics.WithLabelValues("uptime_seconds").Set(systemMetrics.Uptime.Seconds())

	// Store in Redis
	m.storeSystemMetrics(systemMetrics)
}

// determineHealthStatus determines health status based on component metrics
func (m *Monitor) determineHealthStatus(componentMetrics *ComponentMetrics) HealthStatus {
	// Simple heuristics for determining health status
	// This can be made more sophisticated based on specific requirements

	if errorRate, exists := componentMetrics.Metrics["error_rate"]; exists {
		if errorRate > 0.1 { // 10% error rate
			return HealthStatusUnhealthy
		} else if errorRate > 0.05 { // 5% error rate
			return HealthStatusDegraded
		}
	}

	if responseTime, exists := componentMetrics.Metrics["response_time"]; exists {
		if responseTime > 5000 { // 5 seconds
			return HealthStatusUnhealthy
		} else if responseTime > 2000 { // 2 seconds
			return HealthStatusDegraded
		}
	}

	if cpuUsage, exists := componentMetrics.Metrics["cpu_usage"]; exists {
		if cpuUsage > 90 {
			return HealthStatusUnhealthy
		} else if cpuUsage > 70 {
			return HealthStatusDegraded
		}
	}

	return HealthStatusHealthy
}

// handleAlert handles a triggered alert
func (m *Monitor) handleAlert(alert *Alert) {
	m.mu.RLock()
	handlers := make([]AlertHandler, len(m.alertHandlers))
	copy(handlers, m.alertHandlers)
	m.mu.RUnlock()

	for _, handler := range handlers {
		if err := handler.HandleAlert(alert); err != nil {
			log.Printf("Alert handler %s failed: %v", handler.GetName(), err)
		} else {
			alert.Notified = true
			now := time.Now()
			alert.NotifiedAt = &now
		}
	}

	// Store alert in Redis
	m.storeAlert(alert)
}

// alertCleanupRoutine cleans up old alerts
func (m *Monitor) alertCleanupRoutine() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.cleanupOldAlerts()
		}
	}
}

// cleanupOldAlerts removes old alerts
func (m *Monitor) cleanupOldAlerts() {
	m.alertsMu.Lock()
	defer m.alertsMu.Unlock()

	cutoff := time.Now().Add(-m.config.AlertRetention)
	for id, alert := range m.alerts {
		if alert.Timestamp.Before(cutoff) {
			delete(m.alerts, id)
		}
	}

	// Also limit the total number of alerts
	if len(m.alerts) > m.config.MaxAlerts {
		// Remove oldest alerts
		oldestAlerts := make([]*Alert, 0, len(m.alerts))
		for _, alert := range m.alerts {
			oldestAlerts = append(oldestAlerts, alert)
		}

		// Sort by timestamp (oldest first)
		for i := 0; i < len(oldestAlerts)-1; i++ {
			for j := i + 1; j < len(oldestAlerts); j++ {
				if oldestAlerts[i].Timestamp.After(oldestAlerts[j].Timestamp) {
					oldestAlerts[i], oldestAlerts[j] = oldestAlerts[j], oldestAlerts[i]
				}
			}
		}

		// Remove excess alerts
		excess := len(oldestAlerts) - m.config.MaxAlerts
		for i := 0; i < excess; i++ {
			delete(m.alerts, oldestAlerts[i].ID)
		}
	}
}

// storeHealthCheckResult stores health check result in Redis
func (m *Monitor) storeHealthCheckResult(check *HealthCheck) {
	key := fmt.Sprintf("%shealth:%s:%s", m.config.RedisKeyPrefix, check.Component, check.Name)
	data := map[string]interface{}{
		"status":      check.Status.String(),
		"message":     check.Message,
		"last_check":  check.LastCheck.Unix(),
		"duration_ms": check.Duration.Milliseconds(),
		"metadata":    check.Metadata,
	}

	m.redis.HMSet(m.ctx, key, data)
	m.redis.Expire(m.ctx, key, 1*time.Hour)
}

// storeComponentMetrics stores component metrics in Redis
func (m *Monitor) storeComponentMetrics(componentMetrics *ComponentMetrics) {
	key := fmt.Sprintf("%smetrics:%s", m.config.RedisKeyPrefix, componentMetrics.Component)
	data, err := json.Marshal(componentMetrics)
	if err != nil {
		log.Printf("Failed to marshal component metrics: %v", err)
		return
	}

	m.redis.Set(m.ctx, key, data, 1*time.Hour)
}

// storeSystemMetrics stores system metrics in Redis
func (m *Monitor) storeSystemMetrics(systemMetrics *SystemMetrics) {
	key := fmt.Sprintf("%ssystem_metrics", m.config.RedisKeyPrefix)
	data, err := json.Marshal(systemMetrics)
	if err != nil {
		log.Printf("Failed to marshal system metrics: %v", err)
		return
	}

	m.redis.Set(m.ctx, key, data, 1*time.Hour)
}

// storeAlert stores alert in Redis
func (m *Monitor) storeAlert(alert *Alert) {
	key := fmt.Sprintf("%salerts:%s", m.config.RedisKeyPrefix, alert.ID)
	data, err := json.Marshal(alert)
	if err != nil {
		log.Printf("Failed to marshal alert: %v", err)
		return
	}

	m.redis.Set(m.ctx, key, data, m.config.AlertRetention)
}

// IsRunning returns whether the monitor is running
func (m *Monitor) IsRunning() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.running
}

// GetOverallHealth returns the overall system health status
func (m *Monitor) GetOverallHealth() HealthStatus {
	healthStatuses := m.GetHealthStatus()

	if len(healthStatuses) == 0 {
		return HealthStatusUnknown
	}

	healthyCount := 0
	degradedCount := 0
	unhealthyCount := 0

	for _, status := range healthStatuses {
		switch status {
		case HealthStatusHealthy:
			healthyCount++
		case HealthStatusDegraded:
			degradedCount++
		case HealthStatusUnhealthy:
			unhealthyCount++
		}
	}

	// If any component is unhealthy, overall is unhealthy
	if unhealthyCount > 0 {
		return HealthStatusUnhealthy
	}

	// If any component is degraded, overall is degraded
	if degradedCount > 0 {
		return HealthStatusDegraded
	}

	// All components are healthy
	return HealthStatusHealthy
}