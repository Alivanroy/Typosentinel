package ml

import (
	"context"
	"fmt"
	"math"
	"math/rand"
	"sort"
	"sync"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/internal/interfaces"
	"github.com/Alivanroy/Typosentinel/pkg/logger"
)

// TrainingPipeline manages the complete ML model training lifecycle
type TrainingPipeline struct {
	config           *config.Config
	dataManager      *TrainingDataManager
	evaluator        *ModelEvaluator
	validator        *CrossValidator
	models           map[string]MLModel
	trainingHistory  []*TrainingSession
	mu               sync.RWMutex
	isTraining       bool
	metricsCollector interfaces.Metrics
}

// TrainingSession represents a complete training session
type TrainingSession struct {
	ID               string                 `json:"id"`
	ModelType        string                 `json:"model_type"`
	StartTime        time.Time              `json:"start_time"`
	EndTime          time.Time              `json:"end_time"`
	Duration         time.Duration          `json:"duration"`
	TrainingMetrics  *TrainingMetrics       `json:"training_metrics"`
	ValidationResult *CrossValidationResult `json:"validation_result"`
	Status           TrainingStatus         `json:"status"`
	Config           *TrainingConfig        `json:"config"`
	Metadata         map[string]interface{} `json:"metadata"`
}

// TrainingConfig holds configuration for training sessions
type TrainingConfig struct {
	ModelType       string                 `json:"model_type"`
	BatchSize       int                    `json:"batch_size"`
	Epochs          int                    `json:"epochs"`
	LearningRate    float64                `json:"learning_rate"`
	ValidationSplit float64                `json:"validation_split"`
	EarlyStopping   bool                   `json:"early_stopping"`
	Patience        int                    `json:"patience"`
	MinDelta        float64                `json:"min_delta"`
	Hyperparameters map[string]interface{} `json:"hyperparameters"`
}

// TrainingStatus represents the status of a training session
type TrainingStatus string

const (
	TrainingStatusPending   TrainingStatus = "pending"
	TrainingStatusRunning   TrainingStatus = "running"
	TrainingStatusCompleted TrainingStatus = "completed"
	TrainingStatusFailed    TrainingStatus = "failed"
	TrainingStatusCancelled TrainingStatus = "cancelled"
)

// ValidationResult holds cross-validation results
// ValidationResult struct moved to advanced_data_collector.go to avoid duplication

// FoldResult represents results from a single cross-validation fold
type FoldResult struct {
	FoldIndex int              `json:"fold_index"`
	Metrics   *TrainingMetrics `json:"metrics"`
	TestSize  int              `json:"test_size"`
	TrainSize int              `json:"train_size"`
}

// NewTrainingPipeline creates a new training pipeline instance
func NewTrainingPipeline(config *config.Config, metricsCollector interfaces.Metrics) *TrainingPipeline {
	return &TrainingPipeline{
		config:           config,
		dataManager:      NewTrainingDataManager(config),
		evaluator:        NewModelEvaluator(),
		validator:        NewCrossValidator(5), // 5-fold cross-validation
		models:           make(map[string]MLModel),
		trainingHistory:  make([]*TrainingSession, 0),
		metricsCollector: metricsCollector,
	}
}

// StartTraining initiates a training session for a specific model type
func (tp *TrainingPipeline) StartTraining(ctx context.Context, modelType string, config *TrainingConfig) (*TrainingSession, error) {
	tp.mu.Lock()
	defer tp.mu.Unlock()

	if tp.isTraining {
		return nil, fmt.Errorf("training already in progress")
	}

	// Validate training data availability
	if !tp.dataManager.HasSufficientData(modelType) {
		return nil, fmt.Errorf("insufficient training data for model type: %s", modelType)
	}

	// Create training session
	session := &TrainingSession{
		ID:        fmt.Sprintf("training_%s_%d", modelType, time.Now().Unix()),
		ModelType: modelType,
		StartTime: time.Now(),
		Status:    TrainingStatusRunning,
		Config:    config,
		Metadata:  make(map[string]interface{}),
	}

	tp.isTraining = true
	tp.trainingHistory = append(tp.trainingHistory, session)

	// Start training in background
	go tp.runTrainingSession(ctx, session)

	logger.Info("Training session started", map[string]interface{}{
		"session_id": session.ID,
		"model_type": modelType,
		"batch_size": config.BatchSize,
		"epochs":     config.Epochs,
	})

	return session, nil
}

// runTrainingSession executes the complete training workflow
func (tp *TrainingPipeline) runTrainingSession(ctx context.Context, session *TrainingSession) {
	defer func() {
		tp.mu.Lock()
		tp.isTraining = false
		session.EndTime = time.Now()
		session.Duration = session.EndTime.Sub(session.StartTime)
		tp.mu.Unlock()
	}()

	// Load training data
	trainingData, err := tp.dataManager.LoadTrainingData(session.ModelType)
	if err != nil {
		tp.failSession(session, fmt.Errorf("failed to load training data: %w", err))
		return
	}

	// Split data for validation
	trainData, validationData := tp.splitData(trainingData, session.Config.ValidationSplit)

	// Create model instance
	model, err := tp.createModel(session.ModelType, session.Config)
	if err != nil {
		tp.failSession(session, fmt.Errorf("failed to create model: %w", err))
		return
	}

	// Train the model
	trainingMetrics, err := tp.trainModel(ctx, model, trainData, validationData, session.Config)
	if err != nil {
		tp.failSession(session, fmt.Errorf("training failed: %w", err))
		return
	}

	session.TrainingMetrics = trainingMetrics

	// Perform cross-validation
	validationResult, err := tp.validator.ValidateModel(model, trainingData, session.Config)
	if err != nil {
		logger.DebugWithContext("Cross-validation failed", map[string]interface{}{
			"session_id": session.ID,
			"error":      err.Error(),
		})
	} else {
		session.ValidationResult = validationResult
	}

	// Update model in pipeline
	tp.mu.Lock()
	tp.models[session.ModelType] = model
	session.Status = TrainingStatusCompleted
	tp.mu.Unlock()

	// Record metrics
	if tp.metricsCollector != nil {
		tp.recordTrainingMetrics(session)
	}

	logger.Info("Training session completed", map[string]interface{}{
		"session_id":     session.ID,
		"model_type":     session.ModelType,
		"duration":       session.Duration.String(),
		"final_accuracy": trainingMetrics.Accuracy,
		"validation_score": func() float64 {
			if session.ValidationResult != nil {
				return session.ValidationResult.OverallScore
			}
			return 0.0
		}(),
	})
}

// trainModel performs the actual model training
func (tp *TrainingPipeline) trainModel(ctx context.Context, model MLModel, trainData, validationData []TrainingData, config *TrainingConfig) (*TrainingMetrics, error) {
	startTime := time.Now()

	// Initialize metrics tracking
	var bestAccuracy float64
	var patienceCounter int

	// Training loop
	for epoch := 0; epoch < config.Epochs; epoch++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		// Shuffle training data
		tp.shuffleData(trainData)

		// Train on batches
		err := tp.trainEpoch(model, trainData, config.BatchSize)
		if err != nil {
			return nil, fmt.Errorf("epoch %d training failed: %w", epoch, err)
		}

		// Evaluate on validation data
		accuracy := tp.evaluateAccuracy(model, validationData)

		// Early stopping check
		if config.EarlyStopping {
			if accuracy > bestAccuracy+config.MinDelta {
				bestAccuracy = accuracy
				patienceCounter = 0
			} else {
				patienceCounter++
				if patienceCounter >= config.Patience {
					logger.Info("Early stopping triggered", map[string]interface{}{
						"epoch":         epoch,
						"best_accuracy": bestAccuracy,
						"patience":      config.Patience,
					})
					break
				}
			}
		}

		// Log progress
		if epoch%10 == 0 {
			logger.DebugWithContext("Training progress", map[string]interface{}{
				"epoch":    epoch,
				"accuracy": accuracy,
			})
		}
	}

	// Calculate final metrics
	metrics := tp.evaluator.EvaluateModel(model, validationData)
	metrics.TrainingTime = time.Since(startTime)
	metrics.DatasetSize = len(trainData) + len(validationData)

	return metrics, nil
}

// trainEpoch trains the model for one epoch
func (tp *TrainingPipeline) trainEpoch(model MLModel, data []TrainingData, batchSize int) error {
	for i := 0; i < len(data); i += batchSize {
		end := i + batchSize
		if end > len(data) {
			end = len(data)
		}

		batch := data[i:end]
		err := model.Train(batch)
		if err != nil {
			return fmt.Errorf("batch training failed: %w", err)
		}
	}
	return nil
}

// evaluateAccuracy calculates model accuracy on given data
func (tp *TrainingPipeline) evaluateAccuracy(model MLModel, data []TrainingData) float64 {
	if len(data) == 0 {
		return 0.0
	}

	correct := 0
	for _, sample := range data {
		prediction, err := model.Predict(sample.Features)
		if err != nil {
			continue
		}

		// Simple threshold-based classification
		predicted := 0.0
		if prediction.Probability > 0.5 {
			predicted = 1.0
		}

		if math.Abs(predicted-sample.Label) < 0.1 {
			correct++
		}
	}

	return float64(correct) / float64(len(data))
}

// splitData splits training data into train and validation sets
func (tp *TrainingPipeline) splitData(data []TrainingData, validationSplit float64) ([]TrainingData, []TrainingData) {
	if validationSplit <= 0 || validationSplit >= 1 {
		return data, []TrainingData{}
	}

	// Shuffle data first
	shuffled := make([]TrainingData, len(data))
	copy(shuffled, data)
	tp.shuffleData(shuffled)

	splitIndex := int(float64(len(shuffled)) * (1.0 - validationSplit))
	return shuffled[:splitIndex], shuffled[splitIndex:]
}

// shuffleData randomly shuffles training data
func (tp *TrainingPipeline) shuffleData(data []TrainingData) {
	rand.Seed(time.Now().UnixNano())
	for i := len(data) - 1; i > 0; i-- {
		j := rand.Intn(i + 1)
		data[i], data[j] = data[j], data[i]
	}
}

// createModel creates a new model instance based on type and configuration
func (tp *TrainingPipeline) createModel(modelType string, config *TrainingConfig) (MLModel, error) {
	switch modelType {
	case "typosquatting":
		return NewTyposquattingModel(tp.convertToMLModelConfig(config)), nil
	case "reputation":
		return NewReputationModel(tp.convertToMLModelConfig(config)), nil
	case "anomaly":
		return NewAnomalyModel(tp.convertToMLModelConfig(config)), nil
	default:
		return nil, fmt.Errorf("unsupported model type: %s", modelType)
	}
}

// convertToMLModelConfig converts TrainingConfig to MLModelConfig
func (tp *TrainingPipeline) convertToMLModelConfig(trainingConfig *TrainingConfig) config.MLModelConfig {
	return config.MLModelConfig{
		Enabled:   true,
		Threshold: 0.7, // Default threshold
	}
}

// failSession marks a training session as failed
func (tp *TrainingPipeline) failSession(session *TrainingSession, err error) {
	tp.mu.Lock()
	defer tp.mu.Unlock()

	session.Status = TrainingStatusFailed
	session.EndTime = time.Now()
	session.Duration = session.EndTime.Sub(session.StartTime)
	session.Metadata["error"] = err.Error()

	logger.Error("Training session failed", map[string]interface{}{
		"session_id": session.ID,
		"error":      err.Error(),
	})
}

// recordTrainingMetrics records training metrics for monitoring
func (tp *TrainingPipeline) recordTrainingMetrics(session *TrainingSession) {
	if session.TrainingMetrics == nil {
		return
	}

	metrics := map[string]float64{
		"training_accuracy":    session.TrainingMetrics.Accuracy,
		"training_precision":   session.TrainingMetrics.Precision,
		"training_recall":      session.TrainingMetrics.Recall,
		"training_f1_score":    session.TrainingMetrics.F1Score,
		"training_duration_ms": float64(session.Duration.Milliseconds()),
	}

	if session.ValidationResult != nil {
		metrics["validation_accuracy"] = session.ValidationResult.MeanAccuracy
		metrics["validation_score"] = session.ValidationResult.OverallScore
	}

	for name, value := range metrics {
		tp.metricsCollector.SetGauge(name, value, map[string]string{
			"model_type": session.ModelType,
			"session_id": session.ID,
		})
	}
}

// GetTrainingHistory returns the history of training sessions
func (tp *TrainingPipeline) GetTrainingHistory() []*TrainingSession {
	tp.mu.RLock()
	defer tp.mu.RUnlock()

	history := make([]*TrainingSession, len(tp.trainingHistory))
	copy(history, tp.trainingHistory)
	return history
}

// GetTrainingStatus returns the current training status
func (tp *TrainingPipeline) GetTrainingStatus() map[string]interface{} {
	tp.mu.RLock()
	defer tp.mu.RUnlock()

	return map[string]interface{}{
		"is_training":      tp.isTraining,
		"total_sessions":   len(tp.trainingHistory),
		"available_models": tp.getAvailableModels(),
		"data_status":      tp.dataManager.GetDataStatus(),
	}
}

// getAvailableModels returns list of available model types
func (tp *TrainingPipeline) getAvailableModels() []string {
	models := make([]string, 0, len(tp.models))
	for modelType := range tp.models {
		models = append(models, modelType)
	}
	sort.Strings(models)
	return models
}

// IsTraining returns whether a training session is currently running
func (tp *TrainingPipeline) IsTraining() bool {
	tp.mu.RLock()
	defer tp.mu.RUnlock()
	return tp.isTraining
}

// GetTrainedModel returns a trained model by type
func (tp *TrainingPipeline) GetTrainedModel(modelType string) (MLModel, bool) {
	tp.mu.RLock()
	defer tp.mu.RUnlock()

	model, exists := tp.models[modelType]
	return model, exists
}

// GetModels returns the trained models
func (tp *TrainingPipeline) GetModels() map[string]MLModel {
	tp.mu.RLock()
	defer tp.mu.RUnlock()

	models := make(map[string]MLModel)
	for k, v := range tp.models {
		models[k] = v
	}
	return models
}
