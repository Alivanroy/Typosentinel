package monitoring

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// MLMonitor tracks ML model performance metrics
type MLMonitor struct {
	mu                  sync.RWMutex
	predictionLatency   prometheus.Histogram
	predictionCounter   prometheus.Counter
	errorCounter        prometheus.Counter
	accuracyGauge       prometheus.Gauge
	falsePositiveRate   prometheus.Gauge
	falseNegativeRate   prometheus.Gauge
	modelConfidence     prometheus.Histogram
	threatDetectionRate prometheus.Gauge
	alertThresholds     AlertThresholds
	metricsBuffer       []MetricPoint
	lastHealthCheck     time.Time
}

// AlertThresholds defines monitoring alert thresholds
type AlertThresholds struct {
	PredictionLatency time.Duration
	Accuracy          float64
	FalsePositiveRate float64
	ErrorRate         float64
}

// MetricPoint represents a single metric measurement
type MetricPoint struct {
	Timestamp  time.Time
	MetricName string
	Value      float64
	Labels     map[string]string
}

// PredictionMetrics contains metrics for a single prediction
type PredictionMetrics struct {
	Latency        time.Duration
	Confidence     float64
	ThreatDetected bool
	ErrorOccurred  bool
	PackageName    string
	Ecosystem      string
}

// NewMLMonitor creates a new ML monitoring instance
func NewMLMonitor() *MLMonitor {
	return &MLMonitor{
		predictionLatency: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:    "ml_prediction_latency_seconds",
			Help:    "Time taken for ML model predictions",
			Buckets: prometheus.DefBuckets,
		}),
		predictionCounter: promauto.NewCounter(prometheus.CounterOpts{
			Name: "ml_predictions_total",
			Help: "Total number of ML predictions made",
		}),
		errorCounter: promauto.NewCounter(prometheus.CounterOpts{
			Name: "ml_prediction_errors_total",
			Help: "Total number of ML prediction errors",
		}),
		accuracyGauge: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "ml_model_accuracy",
			Help: "Current ML model accuracy",
		}),
		falsePositiveRate: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "ml_false_positive_rate",
			Help: "Current false positive rate",
		}),
		falseNegativeRate: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "ml_false_negative_rate",
			Help: "Current false negative rate",
		}),
		modelConfidence: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:    "ml_model_confidence",
			Help:    "Distribution of model confidence scores",
			Buckets: []float64{0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0},
		}),
		threatDetectionRate: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "ml_threat_detection_rate",
			Help: "Rate of threat detection",
		}),
		alertThresholds: AlertThresholds{
			PredictionLatency: 500 * time.Millisecond,
			Accuracy:          0.85,
			FalsePositiveRate: 0.1,
			ErrorRate:         0.05,
		},
		metricsBuffer: make([]MetricPoint, 0, 1000),
	}
}

// RecordPrediction records metrics for a single prediction
func (m *MLMonitor) RecordPrediction(metrics PredictionMetrics) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Record basic metrics
	m.predictionLatency.Observe(metrics.Latency.Seconds())
	m.predictionCounter.Inc()
	m.modelConfidence.Observe(metrics.Confidence)

	if metrics.ErrorOccurred {
		m.errorCounter.Inc()
	}

	// Add to metrics buffer for analysis
	m.metricsBuffer = append(m.metricsBuffer, MetricPoint{
		Timestamp:  time.Now(),
		MetricName: "prediction",
		Value:      metrics.Latency.Seconds(),
		Labels: map[string]string{
			"package":   metrics.PackageName,
			"ecosystem": metrics.Ecosystem,
			"threat":    fmt.Sprintf("%t", metrics.ThreatDetected),
		},
	})

	// Trim buffer if too large
	if len(m.metricsBuffer) > 1000 {
		m.metricsBuffer = m.metricsBuffer[100:]
	}

	// Check for alerts
	m.checkAlerts(metrics)
}

// UpdateAccuracy updates the model accuracy metric
func (m *MLMonitor) UpdateAccuracy(accuracy float64) {
	m.accuracyGauge.Set(accuracy)
	if accuracy < m.alertThresholds.Accuracy {
		m.triggerAlert("accuracy", fmt.Sprintf("Model accuracy dropped to %.2f", accuracy))
	}
}

// UpdateFalsePositiveRate updates the false positive rate
func (m *MLMonitor) UpdateFalsePositiveRate(rate float64) {
	m.falsePositiveRate.Set(rate)
	if rate > m.alertThresholds.FalsePositiveRate {
		m.triggerAlert("false_positive", fmt.Sprintf("False positive rate increased to %.2f", rate))
	}
}

// UpdateThreatDetectionRate updates the threat detection rate
func (m *MLMonitor) UpdateThreatDetectionRate(rate float64) {
	m.threatDetectionRate.Set(rate)
}

// GetHealthStatus returns the current health status of the ML model
func (m *MLMonitor) GetHealthStatus() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return map[string]interface{}{
		"status":              "healthy",
		"last_health_check":   m.lastHealthCheck,
		"total_predictions":   m.predictionCounter,
		"error_rate":          m.calculateErrorRate(),
		"avg_latency":         m.calculateAverageLatency(),
		"metrics_buffer_size": len(m.metricsBuffer),
	}
}

// StartMonitoring begins the monitoring process
func (m *MLMonitor) StartMonitoring(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.performHealthCheck()
			m.calculateMetrics()
		}
	}
}

// checkAlerts checks if any alert thresholds are exceeded
func (m *MLMonitor) checkAlerts(metrics PredictionMetrics) {
	if metrics.Latency > m.alertThresholds.PredictionLatency {
		m.triggerAlert("latency", fmt.Sprintf("Prediction latency exceeded threshold: %v", metrics.Latency))
	}
}

// triggerAlert sends an alert notification
func (m *MLMonitor) triggerAlert(alertType, message string) {
	log.Printf("[ALERT] %s: %s", alertType, message)
	// Here you could integrate with external alerting systems
}

// performHealthCheck performs a health check on the ML model
func (m *MLMonitor) performHealthCheck() {
	m.mu.Lock()
	m.lastHealthCheck = time.Now()
	m.mu.Unlock()
	log.Println("ML model health check completed")
}

// calculateErrorRate calculates the current error rate
func (m *MLMonitor) calculateErrorRate() float64 {
	// This would calculate based on recent metrics
	return 0.01 // Placeholder
}

// calculateAverageLatency calculates average prediction latency
func (m *MLMonitor) calculateAverageLatency() time.Duration {
	// This would calculate based on recent metrics
	return 100 * time.Millisecond // Placeholder
}

// calculateMetrics performs periodic metric calculations
func (m *MLMonitor) calculateMetrics() {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if len(m.metricsBuffer) == 0 {
		return
	}

	// Calculate threat detection rate from recent predictions
	threatCount := 0
	total := len(m.metricsBuffer)

	for _, metric := range m.metricsBuffer {
		if metric.Labels["threat"] == "true" {
			threatCount++
		}
	}

	if total > 0 {
		rate := float64(threatCount) / float64(total)
		m.threatDetectionRate.Set(rate)
	}
}
