package autoscaler

import (
	"context"
	"fmt"
	"log"
	"math"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"

	"github.com/typosentinel/typosentinel/pkg/metrics"
)

// ScalingPolicy defines when and how to scale
type ScalingPolicy struct {
	MetricName       string        `json:"metric_name"`
	TargetValue      float64       `json:"target_value"`
	ScaleUpThreshold float64       `json:"scale_up_threshold"`
	ScaleDownThreshold float64     `json:"scale_down_threshold"`
	MinInstances     int           `json:"min_instances"`
	MaxInstances     int           `json:"max_instances"`
	CooldownPeriod   time.Duration `json:"cooldown_period"`
	ScaleUpStep      int           `json:"scale_up_step"`
	ScaleDownStep    int           `json:"scale_down_step"`
}

// ScalingTarget represents a scalable component
type ScalingTarget struct {
	Name            string                 `json:"name"`
	CurrentInstances int                   `json:"current_instances"`
	DesiredInstances int                   `json:"desired_instances"`
	Policy          ScalingPolicy          `json:"policy"`
	LastScaleTime   time.Time              `json:"last_scale_time"`
	Metrics         map[string]float64     `json:"metrics"`
	Scaler          TargetScaler           `json:"-"`
	mu              sync.RWMutex           `json:"-"`
}

// TargetScaler interface for scaling different types of targets
type TargetScaler interface {
	ScaleUp(instances int) error
	ScaleDown(instances int) error
	GetCurrentInstances() (int, error)
	GetMetrics() (map[string]float64, error)
}

// AutoScaler manages automatic scaling of components
type AutoScaler struct {
	targets         map[string]*ScalingTarget
	redis           *redis.Client
	metrics         *metrics.Metrics
	ctx             context.Context
	cancel          context.CancelFunc
	mu              sync.RWMutex
	evaluationInterval time.Duration
	scalingHistory  []ScalingEvent
	historyMu       sync.RWMutex
}

// ScalingEvent records scaling actions
type ScalingEvent struct {
	Timestamp    time.Time `json:"timestamp"`
	TargetName   string    `json:"target_name"`
	Action       string    `json:"action"` // scale_up, scale_down
	FromInstances int      `json:"from_instances"`
	ToInstances  int       `json:"to_instances"`
	Reason       string    `json:"reason"`
	MetricValue  float64   `json:"metric_value"`
}

// AutoScalerConfig holds configuration for the autoscaler
type AutoScalerConfig struct {
	EvaluationInterval time.Duration `json:"evaluation_interval"`
	MaxHistorySize     int           `json:"max_history_size"`
}

// NewAutoScaler creates a new autoscaler instance
func NewAutoScaler(config AutoScalerConfig, redis *redis.Client) *AutoScaler {
	ctx, cancel := context.WithCancel(context.Background())

	if config.EvaluationInterval == 0 {
		config.EvaluationInterval = 30 * time.Second
	}
	if config.MaxHistorySize == 0 {
		config.MaxHistorySize = 1000
	}

	return &AutoScaler{
		targets:            make(map[string]*ScalingTarget),
		redis:              redis,
		metrics:            metrics.GetInstance(),
		ctx:                ctx,
		cancel:             cancel,
		evaluationInterval: config.EvaluationInterval,
		scalingHistory:     make([]ScalingEvent, 0, config.MaxHistorySize),
	}
}

// AddTarget adds a scaling target
func (as *AutoScaler) AddTarget(name string, policy ScalingPolicy, scaler TargetScaler) error {
	// Validate policy
	if err := as.validatePolicy(policy); err != nil {
		return fmt.Errorf("invalid scaling policy for %s: %w", name, err)
	}

	// Get current instances
	currentInstances, err := scaler.GetCurrentInstances()
	if err != nil {
		return fmt.Errorf("failed to get current instances for %s: %w", name, err)
	}

	target := &ScalingTarget{
		Name:             name,
		CurrentInstances: currentInstances,
		DesiredInstances: currentInstances,
		Policy:           policy,
		LastScaleTime:    time.Now(),
		Metrics:          make(map[string]float64),
		Scaler:           scaler,
	}

	as.mu.Lock()
	as.targets[name] = target
	as.mu.Unlock()

	log.Printf("Added scaling target %s with %d current instances", name, currentInstances)
	return nil
}

// RemoveTarget removes a scaling target
func (as *AutoScaler) RemoveTarget(name string) error {
	as.mu.Lock()
	defer as.mu.Unlock()

	if _, exists := as.targets[name]; !exists {
		return fmt.Errorf("scaling target %s not found", name)
	}

	delete(as.targets, name)
	log.Printf("Removed scaling target %s", name)
	return nil
}

// Start begins the autoscaling evaluation loop
func (as *AutoScaler) Start() {
	log.Printf("Starting autoscaler with evaluation interval %v", as.evaluationInterval)

	ticker := time.NewTicker(as.evaluationInterval)
	defer ticker.Stop()

	for {
		select {
		case <-as.ctx.Done():
			log.Println("Autoscaler stopped")
			return
		case <-ticker.C:
			as.evaluateTargets()
		}
	}
}

// evaluateTargets evaluates all scaling targets
func (as *AutoScaler) evaluateTargets() {
	as.mu.RLock()
	targets := make([]*ScalingTarget, 0, len(as.targets))
	for _, target := range as.targets {
		targets = append(targets, target)
	}
	as.mu.RUnlock()

	for _, target := range targets {
		as.evaluateTarget(target)
	}
}

// evaluateTarget evaluates a single scaling target
func (as *AutoScaler) evaluateTarget(target *ScalingTarget) {
	target.mu.Lock()
	defer target.mu.Unlock()

	// Check cooldown period
	if time.Since(target.LastScaleTime) < target.Policy.CooldownPeriod {
		return
	}

	// Get current metrics
	metrics, err := target.Scaler.GetMetrics()
	if err != nil {
		log.Printf("Failed to get metrics for target %s: %v", target.Name, err)
		return
	}

	target.Metrics = metrics

	// Get the metric value for scaling decision
	metricValue, exists := metrics[target.Policy.MetricName]
	if !exists {
		log.Printf("Metric %s not found for target %s", target.Policy.MetricName, target.Name)
		return
	}

	// Update current instances
	currentInstances, err := target.Scaler.GetCurrentInstances()
	if err != nil {
		log.Printf("Failed to get current instances for target %s: %v", target.Name, err)
		return
	}
	target.CurrentInstances = currentInstances

	// Make scaling decision
	desiredInstances := as.calculateDesiredInstances(target, metricValue)

	if desiredInstances != target.CurrentInstances {
		as.executeScaling(target, desiredInstances, metricValue)
	}
}

// calculateDesiredInstances calculates the desired number of instances
func (as *AutoScaler) calculateDesiredInstances(target *ScalingTarget, metricValue float64) int {
	current := target.CurrentInstances
	policy := target.Policy

	// Scale up if metric exceeds threshold
	if metricValue > policy.ScaleUpThreshold {
		// Calculate scale factor based on how much we exceed the threshold
		scaleFactor := metricValue / policy.TargetValue
		desired := int(math.Ceil(float64(current) * scaleFactor))
		
		// Apply step limit
		if desired > current+policy.ScaleUpStep {
			desired = current + policy.ScaleUpStep
		}
		
		// Apply max limit
		if desired > policy.MaxInstances {
			desired = policy.MaxInstances
		}
		
		return desired
	}

	// Scale down if metric is below threshold
	if metricValue < policy.ScaleDownThreshold {
		// Calculate scale factor based on how much we're below the threshold
		scaleFactor := metricValue / policy.TargetValue
		desired := int(math.Floor(float64(current) * scaleFactor))
		
		// Apply step limit
		if desired < current-policy.ScaleDownStep {
			desired = current - policy.ScaleDownStep
		}
		
		// Apply min limit
		if desired < policy.MinInstances {
			desired = policy.MinInstances
		}
		
		return desired
	}

	// No scaling needed
	return current
}

// executeScaling performs the actual scaling operation
func (as *AutoScaler) executeScaling(target *ScalingTarget, desiredInstances int, metricValue float64) {
	currentInstances := target.CurrentInstances
	var err error
	var action string

	if desiredInstances > currentInstances {
		// Scale up
		action = "scale_up"
		instancesToAdd := desiredInstances - currentInstances
		err = target.Scaler.ScaleUp(instancesToAdd)
	} else {
		// Scale down
		action = "scale_down"
		instancesToRemove := currentInstances - desiredInstances
		err = target.Scaler.ScaleDown(instancesToRemove)
	}

	if err != nil {
		log.Printf("Failed to %s target %s: %v", action, target.Name, err)
		as.metrics.AutoScalerErrors.WithLabelValues(target.Name, action).Inc()
		return
	}

	// Update target state
	target.DesiredInstances = desiredInstances
	target.LastScaleTime = time.Now()

	// Record scaling event
	event := ScalingEvent{
		Timestamp:     time.Now(),
		TargetName:    target.Name,
		Action:        action,
		FromInstances: currentInstances,
		ToInstances:   desiredInstances,
		Reason:        fmt.Sprintf("Metric %s: %.2f", target.Policy.MetricName, metricValue),
		MetricValue:   metricValue,
	}

	as.recordScalingEvent(event)

	// Update metrics
	as.metrics.AutoScalerActions.WithLabelValues(target.Name, action).Inc()
	as.metrics.AutoScalerInstances.WithLabelValues(target.Name).Set(float64(desiredInstances))

	log.Printf("Scaled %s from %d to %d instances (metric: %s=%.2f)",
		target.Name, currentInstances, desiredInstances, target.Policy.MetricName, metricValue)
}

// recordScalingEvent records a scaling event in history
func (as *AutoScaler) recordScalingEvent(event ScalingEvent) {
	as.historyMu.Lock()
	defer as.historyMu.Unlock()

	as.scalingHistory = append(as.scalingHistory, event)

	// Trim history if it exceeds max size
	if len(as.scalingHistory) > 1000 { // Max history size
		as.scalingHistory = as.scalingHistory[1:]
	}

	// Store in Redis for persistence
	as.storeEventInRedis(event)
}

// storeEventInRedis stores scaling event in Redis
func (as *AutoScaler) storeEventInRedis(event ScalingEvent) {
	key := fmt.Sprintf("autoscaler:events:%s", event.TargetName)
	value := fmt.Sprintf("%d:%s:%d:%d:%.2f",
		event.Timestamp.Unix(), event.Action, event.FromInstances, event.ToInstances, event.MetricValue)

	// Store with expiration (keep events for 7 days)
	as.redis.LPush(as.ctx, key, value)
	as.redis.LTrim(as.ctx, key, 0, 999) // Keep last 1000 events
	as.redis.Expire(as.ctx, key, 7*24*time.Hour)
}

// validatePolicy validates a scaling policy
func (as *AutoScaler) validatePolicy(policy ScalingPolicy) error {
	if policy.MinInstances < 1 {
		return fmt.Errorf("min_instances must be at least 1")
	}
	if policy.MaxInstances < policy.MinInstances {
		return fmt.Errorf("max_instances must be >= min_instances")
	}
	if policy.ScaleUpThreshold <= policy.ScaleDownThreshold {
		return fmt.Errorf("scale_up_threshold must be > scale_down_threshold")
	}
	if policy.TargetValue <= 0 {
		return fmt.Errorf("target_value must be > 0")
	}
	if policy.CooldownPeriod < time.Minute {
		return fmt.Errorf("cooldown_period must be at least 1 minute")
	}
	if policy.ScaleUpStep < 1 {
		return fmt.Errorf("scale_up_step must be at least 1")
	}
	if policy.ScaleDownStep < 1 {
		return fmt.Errorf("scale_down_step must be at least 1")
	}
	return nil
}

// GetTargetStatus returns the status of all scaling targets
func (as *AutoScaler) GetTargetStatus() map[string]interface{} {
	as.mu.RLock()
	defer as.mu.RUnlock()

	status := make(map[string]interface{})
	targets := make([]map[string]interface{}, 0, len(as.targets))

	for _, target := range as.targets {
		target.mu.RLock()
		targetStatus := map[string]interface{}{
			"name":              target.Name,
			"current_instances": target.CurrentInstances,
			"desired_instances": target.DesiredInstances,
			"last_scale_time":   target.LastScaleTime,
			"metrics":           target.Metrics,
			"policy":            target.Policy,
		}
		target.mu.RUnlock()
		targets = append(targets, targetStatus)
	}

	status["targets"] = targets
	status["evaluation_interval"] = as.evaluationInterval.String()

	return status
}

// GetScalingHistory returns recent scaling events
func (as *AutoScaler) GetScalingHistory(limit int) []ScalingEvent {
	as.historyMu.RLock()
	defer as.historyMu.RUnlock()

	if limit <= 0 || limit > len(as.scalingHistory) {
		limit = len(as.scalingHistory)
	}

	// Return the most recent events
	start := len(as.scalingHistory) - limit
	if start < 0 {
		start = 0
	}

	history := make([]ScalingEvent, limit)
	copy(history, as.scalingHistory[start:])

	return history
}

// UpdateTargetPolicy updates the scaling policy for a target
func (as *AutoScaler) UpdateTargetPolicy(name string, policy ScalingPolicy) error {
	if err := as.validatePolicy(policy); err != nil {
		return fmt.Errorf("invalid scaling policy: %w", err)
	}

	as.mu.RLock()
	target, exists := as.targets[name]
	as.mu.RUnlock()

	if !exists {
		return fmt.Errorf("scaling target %s not found", name)
	}

	target.mu.Lock()
	target.Policy = policy
	target.mu.Unlock()

	log.Printf("Updated scaling policy for target %s", name)
	return nil
}

// ForceScale manually scales a target to a specific number of instances
func (as *AutoScaler) ForceScale(name string, instances int) error {
	as.mu.RLock()
	target, exists := as.targets[name]
	as.mu.RUnlock()

	if !exists {
		return fmt.Errorf("scaling target %s not found", name)
	}

	target.mu.Lock()
	defer target.mu.Unlock()

	// Validate instance count
	if instances < target.Policy.MinInstances {
		return fmt.Errorf("instances %d is below minimum %d", instances, target.Policy.MinInstances)
	}
	if instances > target.Policy.MaxInstances {
		return fmt.Errorf("instances %d exceeds maximum %d", instances, target.Policy.MaxInstances)
	}

	currentInstances := target.CurrentInstances
	var err error
	var action string

	if instances > currentInstances {
		action = "force_scale_up"
		err = target.Scaler.ScaleUp(instances - currentInstances)
	} else if instances < currentInstances {
		action = "force_scale_down"
		err = target.Scaler.ScaleDown(currentInstances - instances)
	} else {
		// No change needed
		return nil
	}

	if err != nil {
		return fmt.Errorf("failed to force scale %s: %w", name, err)
	}

	// Update target state
	target.DesiredInstances = instances
	target.LastScaleTime = time.Now()

	// Record scaling event
	event := ScalingEvent{
		Timestamp:     time.Now(),
		TargetName:    name,
		Action:        action,
		FromInstances: currentInstances,
		ToInstances:   instances,
		Reason:        "Manual scaling",
		MetricValue:   0, // No metric value for manual scaling
	}

	as.recordScalingEvent(event)

	// Update metrics
	as.metrics.AutoScalerActions.WithLabelValues(name, action).Inc()
	as.metrics.AutoScalerInstances.WithLabelValues(name).Set(float64(instances))

	log.Printf("Force scaled %s from %d to %d instances", name, currentInstances, instances)
	return nil
}

// Shutdown gracefully shuts down the autoscaler
func (as *AutoScaler) Shutdown() error {
	log.Println("Shutting down autoscaler...")
	as.cancel()
	log.Println("Autoscaler shutdown complete")
	return nil
}

// GetMetrics returns autoscaler metrics
func (as *AutoScaler) GetMetrics() map[string]interface{} {
	as.mu.RLock()
	defer as.mu.RUnlock()

	totalTargets := len(as.targets)
	activeTargets := 0
	totalInstances := 0

	for _, target := range as.targets {
		target.mu.RLock()
		if target.CurrentInstances > 0 {
			activeTargets++
		}
		totalInstances += target.CurrentInstances
		target.mu.RUnlock()
	}

	as.historyMu.RLock()
	recentEvents := len(as.scalingHistory)
	as.historyMu.RUnlock()

	return map[string]interface{}{
		"total_targets":     totalTargets,
		"active_targets":    activeTargets,
		"total_instances":   totalInstances,
		"recent_events":     recentEvents,
		"evaluation_interval": as.evaluationInterval.String(),
	}
}