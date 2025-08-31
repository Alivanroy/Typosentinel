package ml

import (
	"fmt"
	"os"
	"sync"
	"time"
)

// DeepLearningModelManager manages multiple deep learning models
type DeepLearningModelManager struct {
	mu                sync.RWMutex
	models            map[string]DeepLearningModel
	ensembleModel     *EnsembleModel
	modelMetrics      map[string]*ModelMetrics
	trainingHistory   map[string]*TrainingHistory
	modelConfig       *DeepLearningConfig
	featureProcessor  *AdvancedFeatureProcessor
	dataManager       *EnhancedTrainingDataManager
	optimizer         Optimizer
	lossFunction      LossFunction
	scheduler         LearningRateScheduler
	regularization    *RegularizationConfig
	earlyStopping     *EarlyStoppingConfig
	checkpointManager *CheckpointManager
}

// DeepLearningModel interface for all deep learning models
type DeepLearningModel interface {
	Initialize(config map[string]interface{}) error
	Train(data []TrainingData) (*TrainingResult, error)
	Predict(features []float64) (*NeuralPrediction, error)
	Evaluate(testData []TrainingData) (*EvaluationResult, error)
	SaveModel(path string) error
	LoadModel(path string) error
	GetModelInfo() *ModelInfo
	SetHyperparameters(params map[string]interface{}) error
	GetTrainingProgress() *TrainingProgress
	IsReady() bool
	GetID() string
	GetArchitecture() *NetworkArchitecture
}

// DeepLearningConfig contains configuration for deep learning models
type DeepLearningConfig struct {
	ModelType          string                 `json:"model_type"`
	Architecture       *NetworkArchitecture   `json:"architecture"`
	Hyperparameters    map[string]interface{} `json:"hyperparameters"`
	Optimizer          *OptimizerConfig       `json:"optimizer"`
	LossFunction       string                 `json:"loss_function"`
	Metrics            []string               `json:"metrics"`
	Regularization     *RegularizationConfig  `json:"regularization"`
	EarlyStopping      *EarlyStoppingConfig   `json:"early_stopping"`
	LearningSchedule   *ScheduleConfig        `json:"learning_schedule"`
	DataAugmentation   bool                   `json:"data_augmentation"`
	BatchNormalization bool                   `json:"batch_normalization"`
	DropoutRate        float64                `json:"dropout_rate"`
	WeightDecay        float64                `json:"weight_decay"`
	GradientClipping   float64                `json:"gradient_clipping"`
}

// ModelMetrics tracks model performance metrics
type ModelMetrics struct {
	Accuracy             float64                `json:"accuracy"`
	Precision            float64                `json:"precision"`
	Recall               float64                `json:"recall"`
	F1Score              float64                `json:"f1_score"`
	AUC                  float64                `json:"auc"`
	Loss                 float64                `json:"loss"`
	ValidationLoss       float64                `json:"validation_loss"`
	ConfusionMatrix      [][]int                `json:"confusion_matrix"`
	ClassificationReport map[string]interface{} `json:"classification_report"`
	ROCCurve             [][]float64            `json:"roc_curve"`
	PRCurve              [][]float64            `json:"pr_curve"`
	FeatureImportance    []float64              `json:"feature_importance"`
	PredictionStats      *PredictionStats       `json:"prediction_stats"`
	ComputeTime          time.Duration          `json:"compute_time"`
	MemoryUsage          int64                  `json:"memory_usage"`
}

// TrainingHistory tracks training progress over time
type TrainingHistory struct {
	Epochs             []int           `json:"epochs"`
	TrainingLoss       []float64       `json:"training_loss"`
	ValidationLoss     []float64       `json:"validation_loss"`
	TrainingAccuracy   []float64       `json:"training_accuracy"`
	ValidationAccuracy []float64       `json:"validation_accuracy"`
	LearningRates      []float64       `json:"learning_rates"`
	GradientNorms      []float64       `json:"gradient_norms"`
	WeightNorms        []float64       `json:"weight_norms"`
	TrainingTime       []time.Duration `json:"training_time"`
	MemoryUsage        []int64         `json:"memory_usage"`
	BestEpoch          int             `json:"best_epoch"`
	BestValidationLoss float64         `json:"best_validation_loss"`
	Converged          bool            `json:"converged"`
	EarlyStoppedAt     int             `json:"early_stopped_at"`
}

// EnsembleModel combines multiple models for improved performance
type EnsembleModel struct {
	mu                 sync.RWMutex
	models             []DeepLearningModel
	weights            []float64
	votingStrategy     string // "soft", "hard", "weighted"
	metaLearner        DeepLearningModel
	performanceHistory []EnsemblePerformance
	ready              bool
}

// EnsemblePerformance tracks ensemble model performance
type EnsemblePerformance struct {
	Timestamp      time.Time `json:"timestamp"`
	Accuracy       float64   `json:"accuracy"`
	Diversity      float64   `json:"diversity"`
	Agreement      float64   `json:"agreement"`
	IndividualPerf []float64 `json:"individual_performance"`
	EnsembleGain   float64   `json:"ensemble_gain"`
}

// ModelInfo type defined in client.go

// TrainingProgress tracks real-time training progress
type TrainingProgress struct {
	CurrentEpoch       int           `json:"current_epoch"`
	TotalEpochs        int           `json:"total_epochs"`
	CurrentBatch       int           `json:"current_batch"`
	TotalBatches       int           `json:"total_batches"`
	CurrentLoss        float64       `json:"current_loss"`
	CurrentAccuracy    float64       `json:"current_accuracy"`
	ValidationLoss     float64       `json:"validation_loss"`
	ValidationAccuracy float64       `json:"validation_accuracy"`
	LearningRate       float64       `json:"learning_rate"`
	ElapsedTime        time.Duration `json:"elapsed_time"`
	EstimatedTimeLeft  time.Duration `json:"estimated_time_left"`
	Status             string        `json:"status"`
	Message            string        `json:"message"`
}

// EvaluationResult type defined in advanced_evaluation.go

// PredictionStats provides statistics about model predictions
type PredictionStats struct {
	MeanConfidence         float64        `json:"mean_confidence"`
	StdConfidence          float64        `json:"std_confidence"`
	MeanUncertainty        float64        `json:"mean_uncertainty"`
	StdUncertainty         float64        `json:"std_uncertainty"`
	CalibrationError       float64        `json:"calibration_error"`
	PredictionDistribution map[string]int `json:"prediction_distribution"`
	ConfidenceHistogram    []int          `json:"confidence_histogram"`
	UncertaintyHistogram   []int          `json:"uncertainty_histogram"`
}

// RegularizationConfig defines regularization parameters
type RegularizationConfig struct {
	L1Lambda         float64 `json:"l1_lambda"`
	L2Lambda         float64 `json:"l2_lambda"`
	DropoutRate      float64 `json:"dropout_rate"`
	BatchNorm        bool    `json:"batch_norm"`
	LayerNorm        bool    `json:"layer_norm"`
	WeightDecay      float64 `json:"weight_decay"`
	GradientClipping float64 `json:"gradient_clipping"`
	NoiseInjection   float64 `json:"noise_injection"`
}

// EarlyStoppingConfig type defined in advanced_training_pipeline.go

// ScheduleConfig defines learning rate scheduling
type ScheduleConfig struct {
	Type         string                 `json:"type"`
	InitialLR    float64                `json:"initial_lr"`
	DecayRate    float64                `json:"decay_rate"`
	DecaySteps   int                    `json:"decay_steps"`
	WarmupSteps  int                    `json:"warmup_steps"`
	MinLR        float64                `json:"min_lr"`
	MaxLR        float64                `json:"max_lr"`
	CyclicPeriod int                    `json:"cyclic_period"`
	Parameters   map[string]interface{} `json:"parameters"`
}

// CheckpointManager type defined in advanced_training_pipeline.go

// CheckpointInfo contains information about a model checkpoint
type CheckpointInfo struct {
	Path      string                 `json:"path"`
	Epoch     int                    `json:"epoch"`
	Loss      float64                `json:"loss"`
	Accuracy  float64                `json:"accuracy"`
	Timestamp time.Time              `json:"timestamp"`
	ModelHash string                 `json:"model_hash"`
	Metadata  map[string]interface{} `json:"metadata"`
	FileSize  int64                  `json:"file_size"`
}

// NewDeepLearningModelManager creates a new deep learning model manager
func NewDeepLearningModelManager(config *DeepLearningConfig) *DeepLearningModelManager {
	dataManager, err := NewEnhancedTrainingDataManager(nil)
	if err != nil {
		// Handle error gracefully - use nil for now
		dataManager = nil
	}

	return &DeepLearningModelManager{
		models:            make(map[string]DeepLearningModel),
		modelMetrics:      make(map[string]*ModelMetrics),
		trainingHistory:   make(map[string]*TrainingHistory),
		modelConfig:       config,
		featureProcessor:  NewAdvancedFeatureProcessor(),
		dataManager:       dataManager,
		checkpointManager: NewCheckpointManager("./checkpoints"),
	}
}

// RegisterModel registers a new deep learning model
func (dlmm *DeepLearningModelManager) RegisterModel(name string, model DeepLearningModel) error {
	dlmm.mu.Lock()
	defer dlmm.mu.Unlock()

	if _, exists := dlmm.models[name]; exists {
		return fmt.Errorf("model %s already registered", name)
	}

	dlmm.models[name] = model
	dlmm.modelMetrics[name] = &ModelMetrics{}
	dlmm.trainingHistory[name] = &TrainingHistory{
		Epochs:             make([]int, 0),
		TrainingLoss:       make([]float64, 0),
		ValidationLoss:     make([]float64, 0),
		TrainingAccuracy:   make([]float64, 0),
		ValidationAccuracy: make([]float64, 0),
		LearningRates:      make([]float64, 0),
		GradientNorms:      make([]float64, 0),
		WeightNorms:        make([]float64, 0),
		TrainingTime:       make([]time.Duration, 0),
		MemoryUsage:        make([]int64, 0),
	}

	return nil
}

// TrainModel trains a specific model
func (dlmm *DeepLearningModelManager) TrainModel(modelName string, trainingData []TrainingData, validationData []TrainingData) (*TrainingResult, error) {
	dlmm.mu.RLock()
	model, exists := dlmm.models[modelName]
	if !exists {
		dlmm.mu.RUnlock()
		return nil, fmt.Errorf("model %s not found", modelName)
	}
	dlmm.mu.RUnlock()

	// Preprocess training data
	processedTrainingData, err := dlmm.preprocessTrainingData(trainingData)
	if err != nil {
		return nil, fmt.Errorf("failed to preprocess training data: %w", err)
	}

	// Train the model
	startTime := time.Now()
	result, err := model.Train(processedTrainingData)
	if err != nil {
		return nil, fmt.Errorf("training failed: %w", err)
	}

	// Update training history
	dlmm.updateTrainingHistory(modelName, result, time.Since(startTime))

	// Evaluate on validation data if provided
	if len(validationData) > 0 {
		processedValidationData, err := dlmm.preprocessTrainingData(validationData)
		if err == nil {
			evalResult, err := model.Evaluate(processedValidationData)
			if err == nil {
				// Convert map[string]float64 to *ModelMetrics
				modelMetrics := &ModelMetrics{
					Accuracy:       evalResult.Metrics["accuracy"],
					Precision:      evalResult.Metrics["precision"],
					Recall:         evalResult.Metrics["recall"],
					F1Score:        evalResult.Metrics["f1_score"],
					AUC:            evalResult.Metrics["auc"],
					Loss:           evalResult.Metrics["loss"],
					ValidationLoss: evalResult.Metrics["validation_loss"],
				}
				dlmm.updateModelMetrics(modelName, modelMetrics)
			}
		}
	}

	// Save checkpoint if auto-save is enabled
	if dlmm.checkpointManager.autoSave {
		checkpointPath := fmt.Sprintf("%s/%s_epoch_%d.ckpt", dlmm.checkpointManager.checkpointDir, modelName, result.TotalEpochs)
		if err := model.SaveModel(checkpointPath); err == nil {
			dlmm.checkpointManager.SaveCheckpoint(modelName, result.TotalEpochs, result.FinalLoss, result.FinalAccuracy, checkpointPath)
		}
	}

	return result, nil
}

// PredictWithModel makes predictions using a specific model
func (dlmm *DeepLearningModelManager) PredictWithModel(modelName string, features []float64) (*NeuralPrediction, error) {
	dlmm.mu.RLock()
	model, exists := dlmm.models[modelName]
	if !exists {
		dlmm.mu.RUnlock()
		return nil, fmt.Errorf("model %s not found", modelName)
	}
	dlmm.mu.RUnlock()

	// Preprocess features
	processedFeatures, err := dlmm.featureProcessor.ProcessFeatures(map[string]interface{}{
		"features": features,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to preprocess features: %w", err)
	}

	return model.Predict(processedFeatures.NormalizedFeatures)
}

// EvaluateModel evaluates a specific model
func (dlmm *DeepLearningModelManager) EvaluateModel(modelName string, testData []TrainingData) (*EvaluationResult, error) {
	dlmm.mu.RLock()
	model, exists := dlmm.models[modelName]
	if !exists {
		dlmm.mu.RUnlock()
		return nil, fmt.Errorf("model %s not found", modelName)
	}
	dlmm.mu.RUnlock()

	// Preprocess test data
	processedTestData, err := dlmm.preprocessTrainingData(testData)
	if err != nil {
		return nil, fmt.Errorf("failed to preprocess test data: %w", err)
	}

	// Evaluate the model
	evalResult, err := model.Evaluate(processedTestData)
	if err != nil {
		return nil, fmt.Errorf("evaluation failed: %w", err)
	}

	// Update model metrics
	modelMetrics := &ModelMetrics{
		Accuracy:       evalResult.Metrics["accuracy"],
		Precision:      evalResult.Metrics["precision"],
		Recall:         evalResult.Metrics["recall"],
		F1Score:        evalResult.Metrics["f1_score"],
		AUC:            evalResult.Metrics["auc"],
		Loss:           evalResult.Metrics["loss"],
		ValidationLoss: evalResult.Metrics["validation_loss"],
	}
	dlmm.updateModelMetrics(modelName, modelMetrics)

	return evalResult, nil
}

// CreateEnsemble creates an ensemble model from multiple base models
func (dlmm *DeepLearningModelManager) CreateEnsemble(modelNames []string, votingStrategy string) error {
	dlmm.mu.Lock()
	defer dlmm.mu.Unlock()

	models := make([]DeepLearningModel, 0, len(modelNames))
	weights := make([]float64, len(modelNames))

	for i, name := range modelNames {
		model, exists := dlmm.models[name]
		if !exists {
			return fmt.Errorf("model %s not found", name)
		}
		models = append(models, model)
		weights[i] = 1.0 / float64(len(modelNames)) // Equal weights initially
	}

	dlmm.ensembleModel = &EnsembleModel{
		models:             models,
		weights:            weights,
		votingStrategy:     votingStrategy,
		performanceHistory: make([]EnsemblePerformance, 0),
		ready:              true,
	}

	return nil
}

// PredictWithEnsemble makes predictions using the ensemble model
func (dlmm *DeepLearningModelManager) PredictWithEnsemble(features []float64) (*NeuralPrediction, error) {
	dlmm.mu.RLock()
	defer dlmm.mu.RUnlock()

	if dlmm.ensembleModel == nil || !dlmm.ensembleModel.ready {
		return nil, fmt.Errorf("ensemble model not ready")
	}

	return dlmm.ensembleModel.Predict(features)
}

// GetModelMetrics returns metrics for a specific model
func (dlmm *DeepLearningModelManager) GetModelMetrics(modelName string) (*ModelMetrics, error) {
	dlmm.mu.RLock()
	defer dlmm.mu.RUnlock()

	metrics, exists := dlmm.modelMetrics[modelName]
	if !exists {
		return nil, fmt.Errorf("metrics for model %s not found", modelName)
	}

	return metrics, nil
}

// GetTrainingHistory returns training history for a specific model
func (dlmm *DeepLearningModelManager) GetTrainingHistory(modelName string) (*TrainingHistory, error) {
	dlmm.mu.RLock()
	defer dlmm.mu.RUnlock()

	history, exists := dlmm.trainingHistory[modelName]
	if !exists {
		return nil, fmt.Errorf("training history for model %s not found", modelName)
	}

	return history, nil
}

// GetModel returns a specific model by name
func (dlmm *DeepLearningModelManager) GetModel(modelName string) (DeepLearningModel, error) {
	dlmm.mu.RLock()
	defer dlmm.mu.RUnlock()

	model, exists := dlmm.models[modelName]
	if !exists {
		return nil, fmt.Errorf("model %s not found", modelName)
	}

	return model, nil
}

// ListModels returns a list of registered models
func (dlmm *DeepLearningModelManager) ListModels() []string {
	dlmm.mu.RLock()
	defer dlmm.mu.RUnlock()

	names := make([]string, 0, len(dlmm.models))
	for name := range dlmm.models {
		names = append(names, name)
	}

	return names
}

// SaveModel saves a specific model
func (dlmm *DeepLearningModelManager) SaveModel(modelName, path string) error {
	dlmm.mu.RLock()
	model, exists := dlmm.models[modelName]
	if !exists {
		dlmm.mu.RUnlock()
		return fmt.Errorf("model %s not found", modelName)
	}
	dlmm.mu.RUnlock()

	return model.SaveModel(path)
}

// LoadModel loads a model from file
func (dlmm *DeepLearningModelManager) LoadModel(modelName, path string) error {
	dlmm.mu.RLock()
	model, exists := dlmm.models[modelName]
	if !exists {
		dlmm.mu.RUnlock()
		return fmt.Errorf("model %s not found", modelName)
	}
	dlmm.mu.RUnlock()

	return model.LoadModel(path)
}

// Helper methods

func (dlmm *DeepLearningModelManager) preprocessTrainingData(data []TrainingData) ([]TrainingData, error) {
	processedData := make([]TrainingData, len(data))

	for i, sample := range data {
		// Process features using the advanced feature processor
		processedFeatures, err := dlmm.featureProcessor.ProcessFeatures(map[string]interface{}{
			"features": sample.Features,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to process features for sample %d: %w", i, err)
		}

		processedData[i] = TrainingData{
			Features: processedFeatures.NormalizedFeatures,
			Label:    sample.Label,
			Weight:   sample.Weight,
			Metadata: sample.Metadata,
		}
	}

	return processedData, nil
}

func (dlmm *DeepLearningModelManager) updateTrainingHistory(modelName string, result *TrainingResult, trainingTime time.Duration) {
	dlmm.mu.Lock()
	defer dlmm.mu.Unlock()

	history, exists := dlmm.trainingHistory[modelName]
	if !exists {
		return
	}

	history.Epochs = append(history.Epochs, result.TotalEpochs)
	history.TrainingLoss = append(history.TrainingLoss, result.FinalLoss)
	history.TrainingAccuracy = append(history.TrainingAccuracy, result.FinalAccuracy)
	history.TrainingTime = append(history.TrainingTime, trainingTime)
	history.Converged = result.Converged

	// Update best metrics
	if len(history.TrainingLoss) == 1 || result.FinalLoss < history.BestValidationLoss {
		history.BestEpoch = result.TotalEpochs
		history.BestValidationLoss = result.FinalLoss
	}
}

func (dlmm *DeepLearningModelManager) updateModelMetrics(modelName string, metrics *ModelMetrics) {
	dlmm.mu.Lock()
	defer dlmm.mu.Unlock()

	dlmm.modelMetrics[modelName] = metrics
}

// Ensemble Model Implementation

// Predict makes predictions using the ensemble model
func (em *EnsembleModel) Predict(features []float64) (*NeuralPrediction, error) {
	em.mu.RLock()
	defer em.mu.RUnlock()

	if !em.ready || len(em.models) == 0 {
		return nil, fmt.Errorf("ensemble model not ready")
	}

	// Get predictions from all models
	predictions := make([]*NeuralPrediction, len(em.models))
	for i, model := range em.models {
		pred, err := model.Predict(features)
		if err != nil {
			return nil, fmt.Errorf("model %d prediction failed: %w", i, err)
		}
		predictions[i] = pred
	}

	// Combine predictions based on voting strategy
	switch em.votingStrategy {
	case "soft":
		return em.softVoting(predictions)
	case "hard":
		return em.hardVoting(predictions)
	case "weighted":
		return em.weightedVoting(predictions)
	default:
		return em.softVoting(predictions)
	}
}

func (em *EnsembleModel) softVoting(predictions []*NeuralPrediction) (*NeuralPrediction, error) {
	if len(predictions) == 0 {
		return nil, fmt.Errorf("no predictions to combine")
	}

	numClasses := len(predictions[0].Probabilities)
	combinedProbs := make([]float64, numClasses)

	// Average probabilities
	for _, pred := range predictions {
		for i, prob := range pred.Probabilities {
			if i < len(combinedProbs) {
				combinedProbs[i] += prob
			}
		}
	}

	for i := range combinedProbs {
		combinedProbs[i] /= float64(len(predictions))
	}

	// Find predicted class
	predictedClass := 0
	maxProb := combinedProbs[0]
	for i, prob := range combinedProbs {
		if prob > maxProb {
			maxProb = prob
			predictedClass = i
		}
	}

	// Calculate ensemble uncertainty
	uncertainty := em.calculateEnsembleUncertainty(predictions)

	return &NeuralPrediction{
		Probabilities:  combinedProbs,
		PredictedClass: predictedClass,
		Confidence:     maxProb,
		Uncertainty:    uncertainty,
		Explanation:    "Ensemble soft voting prediction",
	}, nil
}

func (em *EnsembleModel) hardVoting(predictions []*NeuralPrediction) (*NeuralPrediction, error) {
	if len(predictions) == 0 {
		return nil, fmt.Errorf("no predictions to combine")
	}

	// Count votes for each class
	votes := make(map[int]int)
	for _, pred := range predictions {
		votes[pred.PredictedClass]++
	}

	// Find class with most votes
	predictedClass := 0
	maxVotes := 0
	for class, count := range votes {
		if count > maxVotes {
			maxVotes = count
			predictedClass = class
		}
	}

	// Calculate confidence as vote ratio
	confidence := float64(maxVotes) / float64(len(predictions))

	// Create probability distribution based on votes
	numClasses := len(predictions[0].Probabilities)
	probabilities := make([]float64, numClasses)
	for class, count := range votes {
		if class < len(probabilities) {
			probabilities[class] = float64(count) / float64(len(predictions))
		}
	}

	// Calculate ensemble uncertainty
	uncertainty := em.calculateEnsembleUncertainty(predictions)

	return &NeuralPrediction{
		Probabilities:  probabilities,
		PredictedClass: predictedClass,
		Confidence:     confidence,
		Uncertainty:    uncertainty,
		Explanation:    "Ensemble hard voting prediction",
	}, nil
}

func (em *EnsembleModel) weightedVoting(predictions []*NeuralPrediction) (*NeuralPrediction, error) {
	if len(predictions) == 0 {
		return nil, fmt.Errorf("no predictions to combine")
	}

	numClasses := len(predictions[0].Probabilities)
	combinedProbs := make([]float64, numClasses)

	// Weighted average of probabilities
	totalWeight := 0.0
	for i, pred := range predictions {
		weight := 1.0
		if i < len(em.weights) {
			weight = em.weights[i]
		}
		totalWeight += weight

		for j, prob := range pred.Probabilities {
			if j < len(combinedProbs) {
				combinedProbs[j] += prob * weight
			}
		}
	}

	// Normalize by total weight
	for i := range combinedProbs {
		combinedProbs[i] /= totalWeight
	}

	// Find predicted class
	predictedClass := 0
	maxProb := combinedProbs[0]
	for i, prob := range combinedProbs {
		if prob > maxProb {
			maxProb = prob
			predictedClass = i
		}
	}

	// Calculate ensemble uncertainty
	uncertainty := em.calculateEnsembleUncertainty(predictions)

	return &NeuralPrediction{
		Probabilities:  combinedProbs,
		PredictedClass: predictedClass,
		Confidence:     maxProb,
		Uncertainty:    uncertainty,
		Explanation:    "Ensemble weighted voting prediction",
	}, nil
}

func (em *EnsembleModel) calculateEnsembleUncertainty(predictions []*NeuralPrediction) float64 {
	if len(predictions) == 0 {
		return 1.0
	}

	// Calculate disagreement between models
	disagreement := 0.0
	for i := 0; i < len(predictions); i++ {
		for j := i + 1; j < len(predictions); j++ {
			if predictions[i].PredictedClass != predictions[j].PredictedClass {
				disagreement += 1.0
			}
		}
	}

	// Normalize disagreement
	maxDisagreements := float64(len(predictions) * (len(predictions) - 1) / 2)
	if maxDisagreements > 0 {
		disagreement /= maxDisagreements
	}

	// Combine with average individual uncertainty
	avgUncertainty := 0.0
	for _, pred := range predictions {
		avgUncertainty += pred.Uncertainty
	}
	avgUncertainty /= float64(len(predictions))

	// Weighted combination of disagreement and average uncertainty
	return 0.6*disagreement + 0.4*avgUncertainty
}

// Checkpoint Manager Implementation

// NewCheckpointManager function defined in advanced_training_pipeline.go

// SaveCheckpoint saves a model checkpoint
func (cm *CheckpointManager) SaveCheckpoint(modelName string, epoch int, loss, accuracy float64, path string) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	// Create checkpoint info
	checkpoint := CheckpointInfo{
		Path:      path,
		Epoch:     epoch,
		Loss:      loss,
		Accuracy:  accuracy,
		Timestamp: time.Now(),
		ModelHash: fmt.Sprintf("%s_%d_%d", modelName, epoch, time.Now().Unix()),
		Metadata: map[string]interface{}{
			"model_name": modelName,
		},
	}

	// Get file size
	if info, err := os.Stat(path); err == nil {
		checkpoint.FileSize = info.Size()
	}

	// Add to checkpoints list
	cm.checkpoints = append(cm.checkpoints, checkpoint)

	// Update best checkpoint
	if cm.bestCheckpoint == nil || accuracy > cm.bestCheckpoint.Accuracy {
		cm.bestCheckpoint = &checkpoint
	}

	// Remove old checkpoints if exceeding max
	if len(cm.checkpoints) > cm.maxCheckpoints {
		// Remove oldest checkpoint
		oldestCheckpoint := cm.checkpoints[0]
		os.Remove(oldestCheckpoint.Path)
		cm.checkpoints = cm.checkpoints[1:]
	}

	return nil
}

// LoadBestCheckpoint loads the best checkpoint
func (cm *CheckpointManager) LoadBestCheckpoint() (*CheckpointInfo, error) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	if cm.bestCheckpoint == nil {
		return nil, fmt.Errorf("no best checkpoint available")
	}

	return cm.bestCheckpoint, nil
}

// ListCheckpoints returns all available checkpoints
func (cm *CheckpointManager) ListCheckpoints() []CheckpointInfo {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	checkpoints := make([]CheckpointInfo, len(cm.checkpoints))
	copy(checkpoints, cm.checkpoints)
	return checkpoints
}

// SetAutoSave enables or disables automatic checkpoint saving
func (cm *CheckpointManager) SetAutoSave(enabled bool) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	cm.autoSave = enabled
}

// SetSaveFrequency sets how often to save checkpoints (in epochs)
func (cm *CheckpointManager) SetSaveFrequency(frequency int) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	cm.saveFrequency = frequency
}

// SetMaxCheckpoints sets the maximum number of checkpoints to keep
func (cm *CheckpointManager) SetMaxCheckpoints(max int) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	cm.maxCheckpoints = max
}

// Utility functions for model evaluation

// CalculateConfusionMatrix calculates confusion matrix from predictions and true labels
func CalculateConfusionMatrix(predictions, trueLabels []int, numClasses int) [][]int {
	matrix := make([][]int, numClasses)
	for i := range matrix {
		matrix[i] = make([]int, numClasses)
	}

	for i := 0; i < len(predictions) && i < len(trueLabels); i++ {
		pred := predictions[i]
		true := trueLabels[i]
		if pred >= 0 && pred < numClasses && true >= 0 && true < numClasses {
			matrix[true][pred]++
		}
	}

	return matrix
}

// CalculateClassificationMetrics calculates precision, recall, and F1-score
func CalculateClassificationMetrics(confusionMatrix [][]int) (precision, recall, f1 float64) {
	numClasses := len(confusionMatrix)
	if numClasses == 0 {
		return 0, 0, 0
	}

	totalPrecision := 0.0
	totalRecall := 0.0
	validClasses := 0

	for i := 0; i < numClasses; i++ {
		tp := float64(confusionMatrix[i][i])
		fp := 0.0
		fn := 0.0

		// Calculate false positives and false negatives
		for j := 0; j < numClasses; j++ {
			if i != j {
				fp += float64(confusionMatrix[j][i]) // False positives
				fn += float64(confusionMatrix[i][j]) // False negatives
			}
		}

		// Calculate precision and recall for this class
		if tp+fp > 0 {
			classPrecision := tp / (tp + fp)
			totalPrecision += classPrecision
			validClasses++
		}

		if tp+fn > 0 {
			classRecall := tp / (tp + fn)
			totalRecall += classRecall
		}
	}

	if validClasses > 0 {
		precision = totalPrecision / float64(validClasses)
		recall = totalRecall / float64(numClasses)
	}

	// Calculate F1-score
	if precision+recall > 0 {
		f1 = 2 * (precision * recall) / (precision + recall)
	}

	return precision, recall, f1
}

// CalculateAccuracy calculates accuracy from confusion matrix
func CalculateAccuracy(confusionMatrix [][]int) float64 {
	correct := 0
	total := 0

	for i := 0; i < len(confusionMatrix); i++ {
		for j := 0; j < len(confusionMatrix[i]); j++ {
			total += confusionMatrix[i][j]
			if i == j {
				correct += confusionMatrix[i][j]
			}
		}
	}

	if total == 0 {
		return 0.0
	}

	return float64(correct) / float64(total)
}

// CalculateAUC calculates Area Under the ROC Curve (simplified implementation)
func CalculateAUC(probabilities []float64, trueLabels []int) float64 {
	if len(probabilities) != len(trueLabels) || len(probabilities) == 0 {
		return 0.5 // Random classifier
	}

	// Simple AUC calculation using trapezoidal rule
	// This is a simplified implementation
	type predictionPair struct {
		prob  float64
		label int
	}

	pairs := make([]predictionPair, len(probabilities))
	for i := range probabilities {
		pairs[i] = predictionPair{probabilities[i], trueLabels[i]}
	}

	// Sort by probability (descending)
	for i := 0; i < len(pairs)-1; i++ {
		for j := i + 1; j < len(pairs); j++ {
			if pairs[i].prob < pairs[j].prob {
				pairs[i], pairs[j] = pairs[j], pairs[i]
			}
		}
	}

	// Calculate AUC using trapezoidal rule
	tp := 0
	fp := 0
	totalPositives := 0
	totalNegatives := 0

	// Count total positives and negatives
	for _, pair := range pairs {
		if pair.label == 1 {
			totalPositives++
		} else {
			totalNegatives++
		}
	}

	if totalPositives == 0 || totalNegatives == 0 {
		return 0.5
	}

	auc := 0.0
	for _, pair := range pairs {
		if pair.label == 1 {
			tp++
		} else {
			fp++
			auc += float64(tp)
		}
	}

	auc /= float64(totalPositives * totalNegatives)
	return auc
}

// CreateDefaultDeepLearningConfig creates a default configuration for deep learning
func CreateDefaultDeepLearningConfig() *DeepLearningConfig {
	return &DeepLearningConfig{
		ModelType: "neural_network",
		Architecture: &NetworkArchitecture{
			InputSize:  100,
			OutputSize: 4,
			Layers:     []LayerConfig{{Type: "dense", Size: 64, Activation: "relu"}},
		},
		Hyperparameters: map[string]interface{}{
			"learning_rate": 0.001,
			"batch_size":    32,
			"epochs":        100,
		},
		Optimizer: &OptimizerConfig{
			Type:         "adam",
			LearningRate: 0.001,
			Parameters: map[string]interface{}{
				"beta1":   0.9,
				"beta2":   0.999,
				"epsilon": 1e-8,
			},
		},
		LossFunction: "categorical_crossentropy",
		Metrics:      []string{"accuracy", "precision", "recall", "f1_score"},
		Regularization: &RegularizationConfig{
			L1Lambda:         0.0,
			L2Lambda:         0.001,
			DropoutRate:      0.2,
			BatchNorm:        true,
			WeightDecay:      0.0001,
			GradientClipping: 1.0,
		},
		EarlyStopping: &EarlyStoppingConfig{
			Enabled:            true,
			Patience:           10,
			MinDelta:           0.001,
			Monitor:            "validation_loss",
			Mode:               "min",
			RestoreBestWeights: true,
		},
		LearningSchedule: &ScheduleConfig{
			Type:       "exponential_decay",
			InitialLR:  0.001,
			DecayRate:  0.95,
			DecaySteps: 1000,
			MinLR:      1e-6,
		},
		DataAugmentation:   true,
		BatchNormalization: true,
		DropoutRate:        0.2,
		WeightDecay:        0.0001,
		GradientClipping:   1.0,
	}
}
