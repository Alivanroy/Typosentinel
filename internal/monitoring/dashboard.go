package monitoring

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/gorilla/mux"
)

// DashboardHandler provides monitoring dashboard endpoints
type DashboardHandler struct {
	monitor *MLMonitor
}

// NewDashboardHandler creates a new dashboard handler
func NewDashboardHandler(monitor *MLMonitor) *DashboardHandler {
	return &DashboardHandler{
		monitor: monitor,
	}
}

// RegisterRoutes registers dashboard routes
func (h *DashboardHandler) RegisterRoutes(router *mux.Router) {
	router.HandleFunc("/api/v1/monitoring/health", h.HealthHandler).Methods("GET")
	router.HandleFunc("/api/v1/monitoring/metrics", h.MetricsHandler).Methods("GET")
	router.HandleFunc("/api/v1/monitoring/dashboard", h.DashboardHandler).Methods("GET")
	router.HandleFunc("/api/v1/monitoring/alerts", h.AlertsHandler).Methods("GET")
}

// HealthHandler returns ML model health status
func (h *DashboardHandler) HealthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	healthStatus := h.monitor.GetHealthStatus()
	json.NewEncoder(w).Encode(healthStatus)
}

// MetricsHandler returns current ML metrics
func (h *DashboardHandler) MetricsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	metrics := map[string]interface{}{
		"timestamp": time.Now(),
		"ml_model": map[string]interface{}{
			"status":                "active",
			"total_predictions":     h.getMetricValue("ml_predictions_total"),
			"error_rate":            h.getMetricValue("ml_prediction_errors_total"),
			"accuracy":              h.getMetricValue("ml_model_accuracy"),
			"false_positive_rate":   h.getMetricValue("ml_false_positive_rate"),
			"threat_detection_rate": h.getMetricValue("ml_threat_detection_rate"),
			"avg_latency_ms":        h.getAverageLatency(),
		},
		"performance": map[string]interface{}{
			"cpu_usage":    h.getCPUUsage(),
			"memory_usage": h.getMemoryUsage(),
			"disk_usage":   h.getDiskUsage(),
		},
	}

	json.NewEncoder(w).Encode(metrics)
}

// DashboardHandler returns dashboard data
func (h *DashboardHandler) DashboardHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	dashboard := map[string]interface{}{
		"title":     "Enhanced ML Model Monitoring Dashboard",
		"timestamp": time.Now(),
		"charts": []map[string]interface{}{
			{
				"id":    "prediction_latency",
				"title": "Prediction Latency",
				"type":  "line",
				"data":  h.getPredictionLatencyData(),
			},
			{
				"id":    "accuracy_trends",
				"title": "Model Accuracy Trends",
				"type":  "line",
				"data":  h.getAccuracyTrendsData(),
			},
			{
				"id":    "threat_detection",
				"title": "Threat Detection Rate",
				"type":  "gauge",
				"data":  h.getThreatDetectionData(),
			},
			{
				"id":    "confidence_distribution",
				"title": "Model Confidence Distribution",
				"type":  "histogram",
				"data":  h.getConfidenceDistributionData(),
			},
		},
		"alerts": h.getActiveAlerts(),
		"summary": map[string]interface{}{
			"total_predictions_today": h.getTotalPredictionsToday(),
			"threats_detected_today":  h.getThreatsDetectedToday(),
			"avg_response_time":       h.getAverageResponseTime(),
			"model_uptime":            h.getModelUptime(),
		},
	}

	json.NewEncoder(w).Encode(dashboard)
}

// AlertsHandler returns current alerts
func (h *DashboardHandler) AlertsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	alerts := map[string]interface{}{
		"active_alerts": h.getActiveAlerts(),
		"alert_history": h.getAlertHistory(),
		"alert_config": map[string]interface{}{
			"latency_threshold":        "500ms",
			"accuracy_threshold":       0.85,
			"false_positive_threshold": 0.1,
			"error_rate_threshold":     0.05,
		},
	}

	json.NewEncoder(w).Encode(alerts)
}

// Helper methods for data retrieval

func (h *DashboardHandler) getMetricValue(metricName string) float64 {
	// In a real implementation, this would query Prometheus or similar
	switch metricName {
	case "ml_predictions_total":
		return 1250.0
	case "ml_prediction_errors_total":
		return 12.0
	case "ml_model_accuracy":
		return 0.92
	case "ml_false_positive_rate":
		return 0.05
	case "ml_threat_detection_rate":
		return 0.15
	default:
		return 0.0
	}
}

func (h *DashboardHandler) getAverageLatency() float64 {
	return 125.5 // milliseconds
}

func (h *DashboardHandler) getCPUUsage() float64 {
	return 45.2 // percentage
}

func (h *DashboardHandler) getMemoryUsage() float64 {
	return 68.7 // percentage
}

func (h *DashboardHandler) getDiskUsage() float64 {
	return 23.1 // percentage
}

func (h *DashboardHandler) getPredictionLatencyData() []map[string]interface{} {
	// Generate sample time series data
	data := make([]map[string]interface{}, 0, 24)
	now := time.Now()

	for i := 23; i >= 0; i-- {
		timestamp := now.Add(-time.Duration(i) * time.Hour)
		latency := 100 + float64(i%5)*20 // Simulate varying latency

		data = append(data, map[string]interface{}{
			"timestamp": timestamp,
			"value":     latency,
		})
	}

	return data
}

func (h *DashboardHandler) getAccuracyTrendsData() []map[string]interface{} {
	// Generate sample accuracy trend data
	data := make([]map[string]interface{}, 0, 24)
	now := time.Now()

	for i := 23; i >= 0; i-- {
		timestamp := now.Add(-time.Duration(i) * time.Hour)
		accuracy := 0.88 + float64(i%3)*0.02 // Simulate varying accuracy

		data = append(data, map[string]interface{}{
			"timestamp": timestamp,
			"value":     accuracy,
		})
	}

	return data
}

func (h *DashboardHandler) getThreatDetectionData() map[string]interface{} {
	return map[string]interface{}{
		"current_rate": 0.15,
		"target_rate":  0.20,
		"status":       "normal",
	}
}

func (h *DashboardHandler) getConfidenceDistributionData() []map[string]interface{} {
	return []map[string]interface{}{
		{"range": "0.0-0.1", "count": 5},
		{"range": "0.1-0.2", "count": 12},
		{"range": "0.2-0.3", "count": 25},
		{"range": "0.3-0.4", "count": 45},
		{"range": "0.4-0.5", "count": 78},
		{"range": "0.5-0.6", "count": 120},
		{"range": "0.6-0.7", "count": 180},
		{"range": "0.7-0.8", "count": 220},
		{"range": "0.8-0.9", "count": 350},
		{"range": "0.9-1.0", "count": 465},
	}
}

func (h *DashboardHandler) getActiveAlerts() []map[string]interface{} {
	return []map[string]interface{}{
		{
			"id":        "alert_001",
			"type":      "warning",
			"message":   "Model accuracy slightly below target",
			"timestamp": time.Now().Add(-15 * time.Minute),
			"severity":  "medium",
		},
	}
}

func (h *DashboardHandler) getAlertHistory() []map[string]interface{} {
	return []map[string]interface{}{
		{
			"id":        "alert_002",
			"type":      "error",
			"message":   "High prediction latency detected",
			"timestamp": time.Now().Add(-2 * time.Hour),
			"resolved":  true,
			"severity":  "high",
		},
	}
}

func (h *DashboardHandler) getTotalPredictionsToday() int {
	return 1250
}

func (h *DashboardHandler) getThreatsDetectedToday() int {
	return 187
}

func (h *DashboardHandler) getAverageResponseTime() string {
	return "125ms"
}

func (h *DashboardHandler) getModelUptime() string {
	return "99.8%"
}
