package ml

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/pkg/metrics"
)

// AutoRetrainer manages automated model retraining
type AutoRetrainer struct {
	config           *config.Config
	trainingPipeline *TrainingPipeline
	scheduler        *RetrainingScheduler
	monitor          *ModelPerformanceMonitor
	metrics          *metrics.Metrics
	
	mu       sync.RWMutex
	running  bool
	stopChan chan struct{}
}

// RetrainingScheduler handles scheduling of retraining tasks
type RetrainingScheduler struct {
	schedules map[string]*RetrainingSchedule
	ticker    *time.Ticker
	mu        sync.RWMutex
}

// RetrainingSchedule defines when and how to retrain a model
type RetrainingSchedule struct {
	ModelType           string        `json:"model_type"`
	Interval            time.Duration `json:"interval"`
	MinDataThreshold    int           `json:"min_data_threshold"`
	PerformanceThreshold float64      `json:"performance_threshold"`
	LastRetrain         time.Time     `json:"last_retrain"`
	NextRetrain         time.Time     `json:"next_retrain"`
	Enabled             bool          `json:"enabled"`
	AutoTrigger         bool          `json:"auto_trigger"`
}

// ModelPerformanceMonitor tracks model performance metrics
type ModelPerformanceMonitor struct {
	metrics     map[string]*PerformanceHistory
	thresholds  map[string]*PerformanceThresholds
	evaluator   *ModelEvaluator
	mu          sync.RWMutex
}

// PerformanceHistory stores historical performance data
type PerformanceHistory struct {
	ModelType   string                    `json:"model_type"`
	Metrics     []*PerformanceSnapshot    `json:"metrics"`
	Trend       PerformanceTrend          `json:"trend"`
	LastUpdated time.Time                 `json:"last_updated"`
}

// PerformanceSnapshot captures performance at a point in time
type PerformanceSnapshot struct {
	Timestamp   time.Time              `json:"timestamp"`
	Accuracy    float64                `json:"accuracy"`
	Precision   float64                `json:"precision"`
	Recall      float64                `json:"recall"`
	F1Score     float64                `json:"f1_score"`
	AUC         float64                `json:"auc"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// PerformanceTrend indicates performance direction
type PerformanceTrend string

const (
	TrendImproving PerformanceTrend = "improving"
	TrendStable    PerformanceTrend = "stable"
	TrendDeclining PerformanceTrend = "declining"
	TrendUnknown   PerformanceTrend = "unknown"
)

// PerformanceThresholds defines when retraining should be triggered
type PerformanceThresholds struct {
	MinAccuracy    float64 `json:"min_accuracy"`
	MinPrecision   float64 `json:"min_precision"`
	MinRecall      float64 `json:"min_recall"`
	MinF1Score     float64 `json:"min_f1_score"`
	MaxDecline     float64 `json:"max_decline"`
	WindowSize     int     `json:"window_size"`
}

// RetrainingTrigger represents reasons for triggering retraining
type RetrainingTrigger struct {
	Type        TriggerType            `json:"type"`
	ModelType   string                 `json:"model_type"`
	Reason      string                 `json:"reason"`
	Timestamp   time.Time              `json:"timestamp"`
	Metadata    map[string]interface{} `json:"metadata"`
	Severity    TriggerSeverity        `json:"severity"`
}

// TriggerType defines different trigger types
type TriggerType string

const (
	TriggerScheduled    TriggerType = "scheduled"
	TriggerPerformance  TriggerType = "performance"
	TriggerDataDrift    TriggerType = "data_drift"
	TriggerManual       TriggerType = "manual"
	TriggerNewData      TriggerType = "new_data"
)

// TriggerSeverity indicates urgency of retraining
type TriggerSeverity string

const (
	SeverityLow      TriggerSeverity = "low"
	SeverityMedium   TriggerSeverity = "medium"
	SeverityHigh     TriggerSeverity = "high"
	SeverityCritical TriggerSeverity = "critical"
)

// RetrainingResult contains the outcome of a retraining operation
type RetrainingResult struct {
	ModelType       string                 `json:"model_type"`
	Trigger         *RetrainingTrigger     `json:"trigger"`
	StartTime       time.Time              `json:"start_time"`
	EndTime         time.Time              `json:"end_time"`
	Duration        time.Duration          `json:"duration"`
	Success         bool                   `json:"success"`
	Error           string                 `json:"error,omitempty"`
	OldPerformance  *PerformanceSnapshot   `json:"old_performance"`
	NewPerformance  *PerformanceSnapshot   `json:"new_performance"`
	Improvement     float64                `json:"improvement"`
	Metadata        map[string]interface{} `json:"metadata"`
}

// NewAutoRetrainer creates a new automated retrainer
func NewAutoRetrainer(cfg *config.Config, trainingPipeline *TrainingPipeline, metricsCollector *metrics.Metrics) *AutoRetrainer {
	return &AutoRetrainer{
		config:           cfg,
		trainingPipeline: trainingPipeline,
		scheduler:        NewRetrainingScheduler(),
		monitor:          NewModelPerformanceMonitor(),
		metrics:          metricsCollector,
		stopChan:         make(chan struct{}),
	}
}

// Start begins the automated retraining process
func (ar *AutoRetrainer) Start(ctx context.Context) error {
	ar.mu.Lock()
	defer ar.mu.Unlock()

	if ar.running {
		return fmt.Errorf("auto retrainer is already running")
	}

	ar.running = true

	// Initialize default schedules
	ar.initializeDefaultSchedules()

	// Start scheduler
	go ar.scheduler.Start(ctx, ar.handleScheduledRetrain)

	// Start performance monitoring
	go ar.monitor.Start(ctx, ar.handlePerformanceTrigger)

	log.Println("Auto retrainer started successfully")
	return nil
}

// Stop stops the automated retraining process
func (ar *AutoRetrainer) Stop() error {
	ar.mu.Lock()
	defer ar.mu.Unlock()

	if !ar.running {
		return fmt.Errorf("auto retrainer is not running")
	}

	close(ar.stopChan)
	ar.scheduler.Stop()
	ar.monitor.Stop()
	ar.running = false

	log.Println("Auto retrainer stopped successfully")
	return nil
}

// TriggerRetrain manually triggers retraining for a model
func (ar *AutoRetrainer) TriggerRetrain(ctx context.Context, modelType string, reason string) (*RetrainingResult, error) {
	trigger := &RetrainingTrigger{
		Type:      TriggerManual,
		ModelType: modelType,
		Reason:    reason,
		Timestamp: time.Now(),
		Severity:  SeverityMedium,
		Metadata:  make(map[string]interface{}),
	}

	return ar.executeRetrain(ctx, trigger)
}

// UpdatePerformance updates performance metrics for a model
func (ar *AutoRetrainer) UpdatePerformance(modelType string, snapshot *PerformanceSnapshot) error {
	return ar.monitor.UpdatePerformance(modelType, snapshot)
}

// GetRetrainingStatus returns the current status of automated retraining
func (ar *AutoRetrainer) GetRetrainingStatus() map[string]interface{} {
	ar.mu.RLock()
	defer ar.mu.RUnlock()

	status := map[string]interface{}{
		"running":    ar.running,
		"schedules":  ar.scheduler.GetSchedules(),
		"performance": ar.monitor.GetPerformanceStatus(),
	}

	return status
}

// initializeDefaultSchedules sets up default retraining schedules
func (ar *AutoRetrainer) initializeDefaultSchedules() {
	defaultSchedules := []*RetrainingSchedule{
		{
			ModelType:            "typosquatting",
			Interval:             24 * time.Hour,
			MinDataThreshold:     1000,
			PerformanceThreshold: 0.85,
			Enabled:              true,
			AutoTrigger:          true,
		},
		{
			ModelType:            "reputation",
			Interval:             12 * time.Hour,
			MinDataThreshold:     500,
			PerformanceThreshold: 0.80,
			Enabled:              true,
			AutoTrigger:          true,
		},
		{
			ModelType:            "anomaly",
			Interval:             6 * time.Hour,
			MinDataThreshold:     200,
			PerformanceThreshold: 0.75,
			Enabled:              true,
			AutoTrigger:          true,
		},
	}

	for _, schedule := range defaultSchedules {
		schedule.NextRetrain = time.Now().Add(schedule.Interval)
		ar.scheduler.AddSchedule(schedule)
	}

	// Initialize performance thresholds
	ar.monitor.SetThresholds("typosquatting", &PerformanceThresholds{
		MinAccuracy:  0.85,
		MinPrecision: 0.80,
		MinRecall:    0.80,
		MinF1Score:   0.80,
		MaxDecline:   0.05,
		WindowSize:   10,
	})

	ar.monitor.SetThresholds("reputation", &PerformanceThresholds{
		MinAccuracy:  0.80,
		MinPrecision: 0.75,
		MinRecall:    0.75,
		MinF1Score:   0.75,
		MaxDecline:   0.10,
		WindowSize:   10,
	})

	ar.monitor.SetThresholds("anomaly", &PerformanceThresholds{
		MinAccuracy:  0.75,
		MinPrecision: 0.70,
		MinRecall:    0.70,
		MinF1Score:   0.70,
		MaxDecline:   0.15,
		WindowSize:   10,
	})
}

// handleScheduledRetrain handles scheduled retraining events
func (ar *AutoRetrainer) handleScheduledRetrain(schedule *RetrainingSchedule) {
	ctx := context.Background()

	trigger := &RetrainingTrigger{
		Type:      TriggerScheduled,
		ModelType: schedule.ModelType,
		Reason:    fmt.Sprintf("Scheduled retrain (interval: %v)", schedule.Interval),
		Timestamp: time.Now(),
		Severity:  SeverityLow,
		Metadata: map[string]interface{}{
			"schedule_interval": schedule.Interval.String(),
			"last_retrain":      schedule.LastRetrain,
		},
	}

	result, err := ar.executeRetrain(ctx, trigger)
	if err != nil {
		log.Printf("Scheduled retrain failed for %s: %v", schedule.ModelType, err)
		return
	}

	log.Printf("Scheduled retrain completed for %s: success=%v, improvement=%.4f",
		schedule.ModelType, result.Success, result.Improvement)

	// Update schedule
	schedule.LastRetrain = time.Now()
	schedule.NextRetrain = time.Now().Add(schedule.Interval)
}

// handlePerformanceTrigger handles performance-based retraining triggers
func (ar *AutoRetrainer) handlePerformanceTrigger(trigger *RetrainingTrigger) {
	ctx := context.Background()

	result, err := ar.executeRetrain(ctx, trigger)
	if err != nil {
		log.Printf("Performance-triggered retrain failed for %s: %v", trigger.ModelType, err)
		return
	}

	log.Printf("Performance-triggered retrain completed for %s: success=%v, improvement=%.4f",
		trigger.ModelType, result.Success, result.Improvement)
}

// executeRetrain executes the retraining process
func (ar *AutoRetrainer) executeRetrain(ctx context.Context, trigger *RetrainingTrigger) (*RetrainingResult, error) {
	startTime := time.Now()

	result := &RetrainingResult{
		ModelType: trigger.ModelType,
		Trigger:   trigger,
		StartTime: startTime,
		Metadata:  make(map[string]interface{}),
	}

	// Get current performance
	oldPerformance := ar.monitor.GetLatestPerformance(trigger.ModelType)
	result.OldPerformance = oldPerformance

	// Check if sufficient data is available
	if !ar.trainingPipeline.dataManager.HasSufficientData(trigger.ModelType) {
		result.Success = false
		result.Error = "insufficient training data"
		result.EndTime = time.Now()
		result.Duration = result.EndTime.Sub(result.StartTime)
		return result, fmt.Errorf("insufficient training data for %s", trigger.ModelType)
	}

	// Create training configuration
	trainingConfig := ar.createTrainingConfig(trigger.ModelType, trigger)

	// Start retraining
	session, err := ar.trainingPipeline.StartTraining(ctx, trigger.ModelType, trainingConfig)
	if err != nil {
		result.Success = false
		result.Error = err.Error()
		result.EndTime = time.Now()
		result.Duration = result.EndTime.Sub(result.StartTime)
		return result, fmt.Errorf("failed to start retraining: %w", err)
	}

	// Wait for training completion
	err = ar.waitForTrainingCompletion(ctx, session.ID)
	if err != nil {
		result.Success = false
		result.Error = err.Error()
		result.EndTime = time.Now()
		result.Duration = result.EndTime.Sub(result.StartTime)
		return result, fmt.Errorf("training failed: %w", err)
	}

	// Evaluate new model performance
	newPerformance, err := ar.evaluateNewModel(trigger.ModelType)
	if err != nil {
		result.Success = false
		result.Error = err.Error()
		result.EndTime = time.Now()
		result.Duration = result.EndTime.Sub(result.StartTime)
		return result, fmt.Errorf("failed to evaluate new model: %w", err)
	}

	result.NewPerformance = newPerformance
	result.Success = true
	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)

	// Calculate improvement
	if oldPerformance != nil {
		result.Improvement = newPerformance.Accuracy - oldPerformance.Accuracy
	}

	// Update performance history
	ar.monitor.UpdatePerformance(trigger.ModelType, newPerformance)

	// Record metrics
	ar.recordRetrainingMetrics(result)

	return result, nil
}

// createTrainingConfig creates training configuration for retraining
func (ar *AutoRetrainer) createTrainingConfig(modelType string, trigger *RetrainingTrigger) *TrainingConfig {
	config := &TrainingConfig{
		ModelType:       modelType,
		BatchSize:       32,
		Epochs:          10,
		LearningRate:    0.001,
		ValidationSplit: 0.2,
		EarlyStopping:   true,
		Patience:        3,
		MinDelta:        0.001,
		Hyperparameters: make(map[string]interface{}),
	}

	// Adjust configuration based on trigger type
	switch trigger.Type {
	case TriggerPerformance:
		// More aggressive training for performance issues
		config.Epochs = 15
		config.LearningRate = 0.0005
	case TriggerDataDrift:
		// Focus on adaptation for data drift
		config.Epochs = 20
		config.ValidationSplit = 0.3
	case TriggerScheduled:
		// Standard configuration for scheduled retraining
		config.Epochs = 10
	}

	// Model-specific adjustments
	switch modelType {
	case "typosquatting":
		config.BatchSize = 64
	case "reputation":
		config.BatchSize = 32
	case "anomaly":
		config.BatchSize = 16
		config.LearningRate = 0.0001
	}

	return config
}

// waitForTrainingCompletion waits for training to complete
func (ar *AutoRetrainer) waitForTrainingCompletion(ctx context.Context, sessionID string) error {
	timeout := time.After(30 * time.Minute) // 30-minute timeout
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timeout:
			return fmt.Errorf("training timeout")
		case <-ticker.C:
			if !ar.trainingPipeline.IsTraining() {
				// Check if training was successful
				history := ar.trainingPipeline.GetTrainingHistory()
				for _, session := range history {
					if session.ID == sessionID {
						if session.Status == TrainingStatusCompleted {
							return nil
						}
						return fmt.Errorf("training failed with status: %s", session.Status)
					}
				}
				return fmt.Errorf("training session not found")
			}
		}
	}
}

// evaluateNewModel evaluates the performance of a newly trained model
func (ar *AutoRetrainer) evaluateNewModel(modelType string) (*PerformanceSnapshot, error) {
	// Load test data
	testData, err := ar.trainingPipeline.dataManager.LoadTestData(modelType)
	if err != nil {
		return nil, fmt.Errorf("failed to load test data: %w", err)
	}

	// Get the latest trained model
	models := ar.trainingPipeline.GetModels()
	model, exists := models[modelType]
	if !exists {
		return nil, fmt.Errorf("model not found: %s", modelType)
	}

	// Evaluate model
	evaluationMetrics := ar.monitor.evaluator.EvaluateModel(model, testData)

	snapshot := &PerformanceSnapshot{
		Timestamp: time.Now(),
		Accuracy:  evaluationMetrics.Accuracy,
		Precision: evaluationMetrics.Precision,
		Recall:    evaluationMetrics.Recall,
		F1Score:   evaluationMetrics.F1Score,
		AUC:       evaluationMetrics.AUC,
		Metadata: map[string]interface{}{
			"test_samples": len(testData),
			"model_type":   modelType,
		},
	}

	return snapshot, nil
}

// recordRetrainingMetrics records metrics for the retraining operation
func (ar *AutoRetrainer) recordRetrainingMetrics(result *RetrainingResult) {
	if ar.metrics == nil {
		return
	}

	// Record retraining event
	ar.metrics.RecordEvent("model_retrain", map[string]interface{}{
		"model_type":  result.ModelType,
		"trigger":     result.Trigger.Type,
		"success":     result.Success,
		"duration":    result.Duration.Seconds(),
		"improvement": result.Improvement,
	})

	// Record performance metrics
	if result.NewPerformance != nil {
		ar.metrics.RecordGauge(fmt.Sprintf("model_accuracy_%s", result.ModelType), result.NewPerformance.Accuracy)
		ar.metrics.RecordGauge(fmt.Sprintf("model_precision_%s", result.ModelType), result.NewPerformance.Precision)
		ar.metrics.RecordGauge(fmt.Sprintf("model_recall_%s", result.ModelType), result.NewPerformance.Recall)
		ar.metrics.RecordGauge(fmt.Sprintf("model_f1_score_%s", result.ModelType), result.NewPerformance.F1Score)
	}
}

// NewRetrainingScheduler creates a new retraining scheduler
func NewRetrainingScheduler() *RetrainingScheduler {
	return &RetrainingScheduler{
		schedules: make(map[string]*RetrainingSchedule),
	}
}

// Start starts the retraining scheduler
func (rs *RetrainingScheduler) Start(ctx context.Context, handler func(*RetrainingSchedule)) {
	rs.ticker = time.NewTicker(1 * time.Minute) // Check every minute

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-rs.ticker.C:
				rs.checkSchedules(handler)
			}
		}
	}()
}

// Stop stops the retraining scheduler
func (rs *RetrainingScheduler) Stop() {
	if rs.ticker != nil {
		rs.ticker.Stop()
	}
}

// AddSchedule adds a retraining schedule
func (rs *RetrainingScheduler) AddSchedule(schedule *RetrainingSchedule) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.schedules[schedule.ModelType] = schedule
}

// GetSchedules returns all retraining schedules
func (rs *RetrainingScheduler) GetSchedules() map[string]*RetrainingSchedule {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	schedules := make(map[string]*RetrainingSchedule)
	for k, v := range rs.schedules {
		schedules[k] = v
	}
	return schedules
}

// checkSchedules checks if any scheduled retraining should be triggered
func (rs *RetrainingScheduler) checkSchedules(handler func(*RetrainingSchedule)) {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	now := time.Now()
	for _, schedule := range rs.schedules {
		if schedule.Enabled && schedule.AutoTrigger && now.After(schedule.NextRetrain) {
			go handler(schedule)
		}
	}
}

// NewModelPerformanceMonitor creates a new model performance monitor
func NewModelPerformanceMonitor() *ModelPerformanceMonitor {
	return &ModelPerformanceMonitor{
		metrics:    make(map[string]*PerformanceHistory),
		thresholds: make(map[string]*PerformanceThresholds),
		evaluator:  NewModelEvaluator(),
	}
}

// Start starts the performance monitor
func (mpm *ModelPerformanceMonitor) Start(ctx context.Context, handler func(*RetrainingTrigger)) {
	// Monitor performance trends and trigger retraining when needed
	ticker := time.NewTicker(5 * time.Minute)

	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				mpm.checkPerformanceThresholds(handler)
			}
		}
	}()
}

// Stop stops the performance monitor
func (mpm *ModelPerformanceMonitor) Stop() {
	// Cleanup if needed
}

// UpdatePerformance updates performance metrics for a model
func (mpm *ModelPerformanceMonitor) UpdatePerformance(modelType string, snapshot *PerformanceSnapshot) error {
	mpm.mu.Lock()
	defer mpm.mu.Unlock()

	history, exists := mpm.metrics[modelType]
	if !exists {
		history = &PerformanceHistory{
			ModelType: modelType,
			Metrics:   make([]*PerformanceSnapshot, 0),
			Trend:     TrendUnknown,
		}
		mpm.metrics[modelType] = history
	}

	// Add new snapshot
	history.Metrics = append(history.Metrics, snapshot)
	history.LastUpdated = time.Now()

	// Keep only recent metrics (last 100 snapshots)
	if len(history.Metrics) > 100 {
		history.Metrics = history.Metrics[len(history.Metrics)-100:]
	}

	// Update trend
	history.Trend = mpm.calculateTrend(history.Metrics)

	return nil
}

// GetLatestPerformance returns the latest performance snapshot for a model
func (mpm *ModelPerformanceMonitor) GetLatestPerformance(modelType string) *PerformanceSnapshot {
	mpm.mu.RLock()
	defer mpm.mu.RUnlock()

	history, exists := mpm.metrics[modelType]
	if !exists || len(history.Metrics) == 0 {
		return nil
	}

	return history.Metrics[len(history.Metrics)-1]
}

// SetThresholds sets performance thresholds for a model
func (mpm *ModelPerformanceMonitor) SetThresholds(modelType string, thresholds *PerformanceThresholds) {
	mpm.mu.Lock()
	defer mpm.mu.Unlock()
	mpm.thresholds[modelType] = thresholds
}

// GetPerformanceStatus returns the current performance status
func (mpm *ModelPerformanceMonitor) GetPerformanceStatus() map[string]interface{} {
	mpm.mu.RLock()
	defer mpm.mu.RUnlock()

	status := make(map[string]interface{})
	for modelType, history := range mpm.metrics {
		status[modelType] = map[string]interface{}{
			"trend":        history.Trend,
			"last_updated": history.LastUpdated,
			"metric_count": len(history.Metrics),
		}

		if len(history.Metrics) > 0 {
			latest := history.Metrics[len(history.Metrics)-1]
			status[modelType].(map[string]interface{})["latest_accuracy"] = latest.Accuracy
			status[modelType].(map[string]interface{})["latest_f1_score"] = latest.F1Score
		}
	}

	return status
}

// checkPerformanceThresholds checks if performance thresholds are violated
func (mpm *ModelPerformanceMonitor) checkPerformanceThresholds(handler func(*RetrainingTrigger)) {
	mpm.mu.RLock()
	defer mpm.mu.RUnlock()

	for modelType, history := range mpm.metrics {
		thresholds, exists := mpm.thresholds[modelType]
		if !exists || len(history.Metrics) == 0 {
			continue
		}

		latest := history.Metrics[len(history.Metrics)-1]

		// Check absolute thresholds
		if latest.Accuracy < thresholds.MinAccuracy ||
			latest.Precision < thresholds.MinPrecision ||
			latest.Recall < thresholds.MinRecall ||
			latest.F1Score < thresholds.MinF1Score {

			trigger := &RetrainingTrigger{
				Type:      TriggerPerformance,
				ModelType: modelType,
				Reason:    "Performance below threshold",
				Timestamp: time.Now(),
				Severity:  SeverityHigh,
				Metadata: map[string]interface{}{
					"current_accuracy":  latest.Accuracy,
					"current_precision": latest.Precision,
					"current_recall":    latest.Recall,
					"current_f1_score":  latest.F1Score,
					"threshold_accuracy":  thresholds.MinAccuracy,
					"threshold_precision": thresholds.MinPrecision,
					"threshold_recall":    thresholds.MinRecall,
					"threshold_f1_score":  thresholds.MinF1Score,
				},
			}

			go handler(trigger)
		}

		// Check performance decline
		if len(history.Metrics) >= thresholds.WindowSize {
			windowStart := len(history.Metrics) - thresholds.WindowSize
			oldAccuracy := history.Metrics[windowStart].Accuracy
			decline := oldAccuracy - latest.Accuracy

			if decline > thresholds.MaxDecline {
				trigger := &RetrainingTrigger{
					Type:      TriggerPerformance,
					ModelType: modelType,
					Reason:    "Performance decline detected",
					Timestamp: time.Now(),
					Severity:  SeverityMedium,
					Metadata: map[string]interface{}{
						"performance_decline": decline,
						"max_allowed_decline": thresholds.MaxDecline,
						"window_size":         thresholds.WindowSize,
					},
				}

				go handler(trigger)
			}
		}
	}
}

// calculateTrend calculates the performance trend
func (mpm *ModelPerformanceMonitor) calculateTrend(metrics []*PerformanceSnapshot) PerformanceTrend {
	if len(metrics) < 3 {
		return TrendUnknown
	}

	// Calculate trend over last 5 metrics
	windowSize := 5
	if len(metrics) < windowSize {
		windowSize = len(metrics)
	}

	recent := metrics[len(metrics)-windowSize:]
	
	// Simple linear trend calculation
	sumX, sumY, sumXY, sumX2 := 0.0, 0.0, 0.0, 0.0
	n := float64(len(recent))

	for i, snapshot := range recent {
		x := float64(i)
		y := snapshot.Accuracy
		sumX += x
		sumY += y
		sumXY += x * y
		sumX2 += x * x
	}

	// Calculate slope
	slope := (n*sumXY - sumX*sumY) / (n*sumX2 - sumX*sumX)

	if slope > 0.01 {
		return TrendImproving
	} else if slope < -0.01 {
		return TrendDeclining
	}
	return TrendStable
}