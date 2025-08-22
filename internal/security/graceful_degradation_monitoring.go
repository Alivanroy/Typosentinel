package security

import (
	"context"
	"sync/atomic"
	"time"
)

// monitorResources monitors system resources continuously
func (gdm *GracefulDegradationManager) monitorResources(ctx context.Context) {
	ticker := time.NewTicker(gdm.config.MonitoringInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			gdm.resourceMonitor.UpdateMetrics()
			loadAverage := gdm.resourceMonitor.GetLoadAverage()
			gdm.loadShedder.UpdateLoad(loadAverage)
			gdm.updateSystemLoad(loadAverage)
		case <-gdm.shutdownChan:
			return
		case <-ctx.Done():
			return
		}
	}
}

// monitorServiceHealth monitors service health continuously
func (gdm *GracefulDegradationManager) monitorServiceHealth(ctx context.Context) {
	ticker := time.NewTicker(gdm.config.HealthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			gdm.serviceHealthMonitor.CheckHealth(ctx)
			gdm.updateHealthScore()
		case <-gdm.shutdownChan:
			return
		case <-ctx.Done():
			return
		}
	}
}

// updateMetrics updates degradation metrics continuously
func (gdm *GracefulDegradationManager) updateMetrics(ctx context.Context) {
	ticker := time.NewTicker(time.Second * 5) // Update metrics every 5 seconds
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			gdm.calculateMetrics()
		case <-gdm.shutdownChan:
			return
		case <-ctx.Done():
			return
		}
	}
}

// adaptiveOptimization performs adaptive optimization based on current conditions
func (gdm *GracefulDegradationManager) adaptiveOptimization(ctx context.Context) {
	if !gdm.config.AdaptiveMode {
		return
	}

	ticker := time.NewTicker(gdm.config.AdaptationInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			gdm.performAdaptiveOptimization()
		case <-gdm.shutdownChan:
			return
		case <-ctx.Done():
			return
		}
	}
}

// updateSystemLoad updates the system load in metrics
func (gdm *GracefulDegradationManager) updateSystemLoad(load float64) {
	gdm.metrics.mu.Lock()
	defer gdm.metrics.mu.Unlock()
	gdm.metrics.SystemLoad = load
	gdm.metrics.LastUpdated = time.Now()
}

// updateHealthScore updates the health score based on service health
func (gdm *GracefulDegradationManager) updateHealthScore() {
	gdm.metrics.mu.Lock()
	defer gdm.metrics.mu.Unlock()

	// Calculate health score based on overall service health
	switch gdm.serviceHealthMonitor.overallHealth {
	case Healthy:
		gdm.metrics.HealthScore = 1.0
	case Degraded:
		gdm.metrics.HealthScore = 0.7
	case Unhealthy:
		gdm.metrics.HealthScore = 0.3
	case Critical:
		gdm.metrics.HealthScore = 0.1
	default:
		gdm.metrics.HealthScore = 0.5
	}
}

// calculateMetrics calculates various degradation metrics
func (gdm *GracefulDegradationManager) calculateMetrics() {
	gdm.metrics.mu.Lock()
	defer gdm.metrics.mu.Unlock()

	totalRequests := atomic.LoadInt64(&gdm.metrics.TotalRequests)
	droppedRequests := atomic.LoadInt64(&gdm.metrics.DroppedRequests)
	fallbackRequests := atomic.LoadInt64(&gdm.metrics.FallbackRequests)

	// Calculate rates
	if totalRequests > 0 {
		gdm.metrics.LoadSheddingRate = float64(droppedRequests) / float64(totalRequests)
		gdm.metrics.FallbackRate = float64(fallbackRequests) / float64(totalRequests)
	}

	// Update degradation level
	gdm.metrics.DegradationLevel = int(gdm.GetDegradationLevel())
	gdm.metrics.LastUpdated = time.Now()
}

// performAdaptiveOptimization performs adaptive optimization
func (gdm *GracefulDegradationManager) performAdaptiveOptimization() {
	gdm.mu.Lock()
	defer gdm.mu.Unlock()

	currentLoad := gdm.resourceMonitor.loadAverage
	healthScore := gdm.metrics.HealthScore

	// Adjust thresholds based on current conditions
	if currentLoad > gdm.config.CriticalThreshold && healthScore < 0.5 {
		// System is under severe stress, enable more aggressive degradation
		gdm.fallbackManager.cacheOnlyMode = true
		gdm.fallbackManager.reducedFeatures = true
	} else if currentLoad < gdm.config.BackpressureThreshold && healthScore > 0.8 {
		// System is healthy, disable aggressive degradation
		gdm.fallbackManager.cacheOnlyMode = false
		gdm.fallbackManager.reducedFeatures = false
	} else {
		// Moderate conditions, enable reduced features but not cache-only
		gdm.fallbackManager.cacheOnlyMode = false
		gdm.fallbackManager.reducedFeatures = true
	}

	gdm.logger.Printf("Adaptive optimization: load=%.2f, health=%.2f, cache-only=%v, reduced=%v",
		currentLoad, healthScore, gdm.fallbackManager.cacheOnlyMode, gdm.fallbackManager.reducedFeatures)
}

// IsHealthy returns true if the system is operating normally
func (gdm *GracefulDegradationManager) IsHealthy() bool {
	return gdm.GetDegradationLevel() <= LightDegradation
}

// GetSystemStatus returns a comprehensive system status
func (gdm *GracefulDegradationManager) GetSystemStatus() map[string]interface{} {
	metrics := gdm.GetMetrics()
	degradationLevel := gdm.GetDegradationLevel()

	return map[string]interface{}{
		"degradation_level":    degradationLevel,
		"system_load":         metrics.SystemLoad,
		"health_score":        metrics.HealthScore,
		"load_shedding_rate":  metrics.LoadSheddingRate,
		"fallback_rate":       metrics.FallbackRate,
		"total_requests":      metrics.TotalRequests,
		"dropped_requests":    metrics.DroppedRequests,
		"fallback_requests":   metrics.FallbackRequests,
		"average_response_time": metrics.AverageResponseTime,
		"cache_only_mode":     gdm.fallbackManager.cacheOnlyMode,
		"reduced_features":    gdm.fallbackManager.reducedFeatures,
		"last_updated":        metrics.LastUpdated,
	}
}