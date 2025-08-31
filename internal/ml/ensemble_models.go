package ml

import (
	"context"
	"fmt"
	"math"
	"sort"
	"sync"
	"time"
)

// EnsembleModelManager manages multiple deep learning models for enhanced threat detection
type EnsembleModelManager struct {
	config             *EnsembleConfig
	models             map[string]DeepLearningModel
	fusionStrategies   map[string]FusionStrategy
	votingMechanism    VotingMechanism
	metaLearner        MetaLearner
	performanceTracker *PerformanceTracker
	modelWeights       map[string]float64
	adaptiveWeights    bool
	mu                 sync.RWMutex
	isInitialized      bool
}

// EnsembleConfig defines configuration for ensemble models
type EnsembleConfig struct {
	ModelConfigs         map[string]*DeepLearningConfig `json:"model_configs"`
	FusionStrategy       string                         `json:"fusion_strategy"`
	VotingMethod         string                         `json:"voting_method"`
	WeightingScheme      string                         `json:"weighting_scheme"`
	AdaptiveWeights      bool                           `json:"adaptive_weights"`
	MetaLearningEnabled  bool                           `json:"meta_learning_enabled"`
	DiversityThreshold   float64                        `json:"diversity_threshold"`
	PerformanceWindow    int                            `json:"performance_window"`
	UpdateFrequency      time.Duration                  `json:"update_frequency"`
	MinModels            int                            `json:"min_models"`
	MaxModels            int                            `json:"max_models"`
	CrossValidationFolds int                            `json:"cross_validation_folds"`
	EarlyStoppingConfig  *EarlyStoppingConfig           `json:"early_stopping_config"`
	RegularizationConfig *RegularizationConfig          `json:"regularization_config"`
}

// FusionStrategy defines how to combine model predictions
type FusionStrategy interface {
	GetName() string
	Fuse(predictions []*ModelPrediction, weights []float64) (*EnsemblePrediction, error)
	GetConfiguration() map[string]interface{}
	Validate(predictions []*ModelPrediction) error
}

// VotingMechanism defines voting strategies for ensemble decisions
type VotingMechanism interface {
	GetName() string
	Vote(predictions []*ModelPrediction, weights []float64) (*VotingResult, error)
	GetVotingStats() *VotingStats
	UpdateWeights(performance map[string]float64) error
}

// MetaLearner learns to combine base model predictions
type MetaLearner interface {
	GetName() string
	Train(basePredictions [][]*ModelPrediction, trueLabels []float64) error
	Predict(basePredictions []*ModelPrediction) (*MetaPrediction, error)
	GetMetaFeatures(predictions []*ModelPrediction) []float64
	SaveModel(path string) error
	LoadModel(path string) error
}

// ModelPrediction represents a prediction from a single model
type ModelPrediction struct {
	ModelName      string                 `json:"model_name"`
	ModelType      string                 `json:"model_type"`
	Prediction     float64                `json:"prediction"`
	Confidence     float64                `json:"confidence"`
	Probabilities  []float64              `json:"probabilities"`
	FeatureWeights []float64              `json:"feature_weights"`
	Uncertainty    float64                `json:"uncertainty"`
	Latency        time.Duration          `json:"latency"`
	Metadata       map[string]interface{} `json:"metadata"`
	Timestamp      time.Time              `json:"timestamp"`
}

// EnsemblePrediction represents the final ensemble prediction
type EnsemblePrediction struct {
	FinalPrediction    float64              `json:"final_prediction"`
	FinalConfidence    float64              `json:"final_confidence"`
	FinalProbabilities []float64            `json:"final_probabilities"`
	ModelContributions map[string]float64   `json:"model_contributions"`
	FusionStrategy     string               `json:"fusion_strategy"`
	VotingResult       *VotingResult        `json:"voting_result"`
	MetaPrediction     *MetaPrediction      `json:"meta_prediction"`
	UncertaintyMetrics *UncertaintyMetrics  `json:"uncertainty_metrics"`
	DiversityMetrics   *DiversityMetrics    `json:"diversity_metrics"`
	Explanation        *EnsembleExplanation `json:"explanation"`
	ProcessingTime     time.Duration        `json:"processing_time"`
	Timestamp          time.Time            `json:"timestamp"`
}

// VotingResult contains voting mechanism results
type VotingResult struct {
	VotingMethod   string             `json:"voting_method"`
	Votes          map[string]float64 `json:"votes"`
	WeightedVotes  map[string]float64 `json:"weighted_votes"`
	ConsensusScore float64            `json:"consensus_score"`
	MajorityVote   float64            `json:"majority_vote"`
	UnanimityScore float64            `json:"unanimity_score"`
}

// MetaPrediction contains meta-learner results
type MetaPrediction struct {
	MetaModelName   string    `json:"meta_model_name"`
	MetaPrediction  float64   `json:"meta_prediction"`
	MetaConfidence  float64   `json:"meta_confidence"`
	MetaFeatures    []float64 `json:"meta_features"`
	MetaUncertainty float64   `json:"meta_uncertainty"`
}

// UncertaintyMetrics quantifies prediction uncertainty
type UncertaintyMetrics struct {
	EpistemicUncertainty float64 `json:"epistemic_uncertainty"`
	AleatoricUncertainty float64 `json:"aleatoric_uncertainty"`
	TotalUncertainty     float64 `json:"total_uncertainty"`
	PredictionVariance   float64 `json:"prediction_variance"`
	ModelDisagreement    float64 `json:"model_disagreement"`
}

// DiversityMetrics measures ensemble diversity
type DiversityMetrics struct {
	PairwiseDiversity float64            `json:"pairwise_diversity"`
	KohoneDiversity   float64            `json:"kohone_diversity"`
	EntropyDiversity  float64            `json:"entropy_diversity"`
	CorrelationMatrix [][]float64        `json:"correlation_matrix"`
	DiversityByModel  map[string]float64 `json:"diversity_by_model"`
}

// EnsembleExplanation provides interpretability for ensemble decisions
type EnsembleExplanation struct {
	ModelExplanations map[string]*ModelExplanation `json:"model_explanations"`
	FeatureImportance map[string]float64           `json:"feature_importance"`
	DecisionPath      []DecisionStep               `json:"decision_path"`
	Counterfactuals   []Counterfactual             `json:"counterfactuals"`
	SimilarCases      []SimilarCase                `json:"similar_cases"`
	ConfidenceFactors []ConfidenceFactor           `json:"confidence_factors"`
}

// ModelExplanation explains individual model decisions
type ModelExplanation struct {
	ModelName          string             `json:"model_name"`
	FeatureWeights     map[string]float64 `json:"feature_weights"`
	ActivationMaps     [][]float64        `json:"activation_maps"`
	AttentionWeights   [][]float64        `json:"attention_weights"`
	LayerContributions map[string]float64 `json:"layer_contributions"`
	DecisionBoundary   []float64          `json:"decision_boundary"`
}

// DecisionStep represents a step in the ensemble decision process
type DecisionStep struct {
	Step        int                    `json:"step"`
	Description string                 `json:"description"`
	Inputs      map[string]interface{} `json:"inputs"`
	Outputs     map[string]interface{} `json:"outputs"`
	Confidence  float64                `json:"confidence"`
}

// ConfidenceFactor explains what contributes to confidence
type ConfidenceFactor struct {
	Factor       string  `json:"factor"`
	Contribution float64 `json:"contribution"`
	Description  string  `json:"description"`
}

// VotingStats tracks voting mechanism performance
type VotingStats struct {
	TotalVotes        int64              `json:"total_votes"`
	ConsensusRate     float64            `json:"consensus_rate"`
	AverageConfidence float64            `json:"average_confidence"`
	VotingAccuracy    float64            `json:"voting_accuracy"`
	ModelAgreement    map[string]float64 `json:"model_agreement"`
}

// PerformanceTracker tracks ensemble performance over time
type PerformanceTracker struct {
	windowSize         int
	performanceHistory []PerformanceSnapshot
	modelMetrics       map[string]*ModelMetrics
	mu                 sync.RWMutex
}

// PerformanceSnapshot captures performance at a point in time
type PerformanceSnapshot struct {
	Timestamp        time.Time          `json:"timestamp"`
	Accuracy         float64            `json:"accuracy"`
	Precision        float64            `json:"precision"`
	Recall           float64            `json:"recall"`
	F1Score          float64            `json:"f1_score"`
	AUC              float64            `json:"auc"`
	ModelPerformance map[string]float64 `json:"model_performance"`
	Latency          time.Duration      `json:"latency"`
}

// NewEnsembleModelManager creates a new ensemble model manager
func NewEnsembleModelManager(config *EnsembleConfig) *EnsembleModelManager {
	return &EnsembleModelManager{
		config:             config,
		models:             make(map[string]DeepLearningModel),
		fusionStrategies:   make(map[string]FusionStrategy),
		modelWeights:       make(map[string]float64),
		adaptiveWeights:    config.AdaptiveWeights,
		performanceTracker: NewPerformanceTracker(config.PerformanceWindow),
	}
}

// Initialize initializes the ensemble model manager
func (emm *EnsembleModelManager) Initialize(ctx context.Context) error {
	emm.mu.Lock()
	defer emm.mu.Unlock()

	// Initialize individual models
	for modelName, modelConfig := range emm.config.ModelConfigs {
		model, err := emm.createModel(modelName, modelConfig)
		if err != nil {
			return fmt.Errorf("failed to create model %s: %w", modelName, err)
		}
		emm.models[modelName] = model
		emm.modelWeights[modelName] = 1.0 / float64(len(emm.config.ModelConfigs))
	}

	// Initialize fusion strategies
	if err := emm.initializeFusionStrategies(); err != nil {
		return fmt.Errorf("failed to initialize fusion strategies: %w", err)
	}

	// Initialize voting mechanism
	if err := emm.initializeVotingMechanism(); err != nil {
		return fmt.Errorf("failed to initialize voting mechanism: %w", err)
	}

	// Initialize meta-learner if enabled
	if emm.config.MetaLearningEnabled {
		if err := emm.initializeMetaLearner(); err != nil {
			return fmt.Errorf("failed to initialize meta-learner: %w", err)
		}
	}

	emm.isInitialized = true
	return nil
}

// Predict generates ensemble predictions for given features
func (emm *EnsembleModelManager) Predict(ctx context.Context, features []float64) (*EnsemblePrediction, error) {
	emm.mu.RLock()
	defer emm.mu.RUnlock()

	if !emm.isInitialized {
		return nil, fmt.Errorf("ensemble model manager not initialized")
	}

	startTime := time.Now()

	// Get predictions from all models
	predictions := make([]*ModelPrediction, 0, len(emm.models))
	for modelName, model := range emm.models {
		predStart := time.Now()
		pred, err := model.Predict(features)
		if err != nil {
			continue // Skip failed predictions
		}

		modelPred := &ModelPrediction{
			ModelName:     modelName,
			ModelType:     model.GetArchitecture().Type,
			Prediction:    pred.Confidence, // Extract confidence as prediction value
			Confidence:    pred.Confidence,
			Probabilities: pred.Probabilities,
			Uncertainty:   pred.Uncertainty,
			Latency:       time.Since(predStart),
			Timestamp:     time.Now(),
		}
		predictions = append(predictions, modelPred)
	}

	if len(predictions) == 0 {
		return nil, fmt.Errorf("no valid predictions from ensemble models")
	}

	// Apply fusion strategy
	weights := emm.getModelWeights(predictions)
	fusionStrategy := emm.fusionStrategies[emm.config.FusionStrategy]
	ensemblePred, err := fusionStrategy.Fuse(predictions, weights)
	if err != nil {
		return nil, fmt.Errorf("fusion failed: %w", err)
	}

	// Apply voting mechanism
	votingResult, err := emm.votingMechanism.Vote(predictions, weights)
	if err != nil {
		return nil, fmt.Errorf("voting failed: %w", err)
	}
	ensemblePred.VotingResult = votingResult

	// Apply meta-learner if available
	if emm.metaLearner != nil {
		metaPred, err := emm.metaLearner.Predict(predictions)
		if err == nil {
			ensemblePred.MetaPrediction = metaPred
		}
	}

	// Calculate uncertainty and diversity metrics
	ensemblePred.UncertaintyMetrics = emm.calculateUncertaintyMetrics(predictions)
	ensemblePred.DiversityMetrics = emm.calculateDiversityMetrics(predictions)

	// Generate explanation
	ensemblePred.Explanation = emm.generateExplanation(predictions, ensemblePred)

	ensemblePred.ProcessingTime = time.Since(startTime)
	ensemblePred.Timestamp = time.Now()

	return ensemblePred, nil
}

// Train trains the ensemble models
func (emm *EnsembleModelManager) Train(ctx context.Context, trainingData []TrainingData) error {
	emm.mu.Lock()
	defer emm.mu.Unlock()

	// Train individual models
	for modelName, model := range emm.models {
		result, err := model.Train(trainingData)
		if err != nil {
			return fmt.Errorf("failed to train model %s: %w", modelName, err)
		}
		_ = result // Ignore result for now
	}

	// Train meta-learner if enabled
	if emm.config.MetaLearningEnabled && emm.metaLearner != nil {
		if err := emm.trainMetaLearner(trainingData); err != nil {
			return fmt.Errorf("failed to train meta-learner: %w", err)
		}
	}

	// Update model weights if adaptive
	if emm.adaptiveWeights {
		if err := emm.updateModelWeights(trainingData); err != nil {
			return fmt.Errorf("failed to update model weights: %w", err)
		}
	}

	return nil
}

// Evaluate evaluates the ensemble performance
func (emm *EnsembleModelManager) Evaluate(ctx context.Context, testData []TrainingData) (*EvaluationResult, error) {
	emm.mu.RLock()
	defer emm.mu.RUnlock()

	result := &EvaluationResult{
		Timestamp: time.Now(),
		Metrics:   make(map[string]float64),
	}

	// Evaluate ensemble predictions
	correctPredictions := 0
	totalPredictions := len(testData)

	for _, sample := range testData {
		pred, err := emm.Predict(ctx, sample.Features)
		if err != nil {
			continue
		}

		if math.Abs(pred.FinalPrediction-sample.Label) < 0.5 {
			correctPredictions++
		}
	}

	accuracy := float64(correctPredictions) / float64(totalPredictions)
	result.Metrics["accuracy"] = accuracy
	result.Metrics["total_predictions"] = float64(totalPredictions)
	result.Metrics["correct_predictions"] = float64(correctPredictions)

	return result, nil
}

// Helper methods

func (emm *EnsembleModelManager) createModel(name string, config *DeepLearningConfig) (DeepLearningModel, error) {
	// This would create specific model types based on configuration
	// For now, return a placeholder
	return &PlaceholderDeepLearningModel{name: name}, nil
}

func (emm *EnsembleModelManager) initializeFusionStrategies() error {
	// Initialize different fusion strategies
	emm.fusionStrategies["weighted_average"] = &WeightedAverageFusion{}
	emm.fusionStrategies["stacking"] = &StackingFusion{}
	emm.fusionStrategies["bayesian"] = &BayesianFusion{}
	return nil
}

func (emm *EnsembleModelManager) initializeVotingMechanism() error {
	switch emm.config.VotingMethod {
	case "majority":
		emm.votingMechanism = &MajorityVoting{}
	case "weighted":
		emm.votingMechanism = &WeightedVoting{}
	case "ranked":
		emm.votingMechanism = &RankedVoting{}
	default:
		emm.votingMechanism = &MajorityVoting{}
	}
	return nil
}

func (emm *EnsembleModelManager) initializeMetaLearner() error {
	emm.metaLearner = &NeuralMetaLearner{}
	return nil
}

func (emm *EnsembleModelManager) getModelWeights(predictions []*ModelPrediction) []float64 {
	weights := make([]float64, len(predictions))
	for i, pred := range predictions {
		if weight, exists := emm.modelWeights[pred.ModelName]; exists {
			weights[i] = weight
		} else {
			weights[i] = 1.0 / float64(len(predictions))
		}
	}
	return weights
}

func (emm *EnsembleModelManager) calculateConfidence(prediction float64) float64 {
	// Simple confidence calculation based on prediction certainty
	return math.Abs(prediction-0.5) * 2
}

func (emm *EnsembleModelManager) calculateUncertainty(prediction float64) float64 {
	// Simple uncertainty calculation
	return 1.0 - emm.calculateConfidence(prediction)
}

func (emm *EnsembleModelManager) calculateUncertaintyMetrics(predictions []*ModelPrediction) *UncertaintyMetrics {
	if len(predictions) == 0 {
		return &UncertaintyMetrics{}
	}

	// Calculate prediction variance
	mean := 0.0
	for _, pred := range predictions {
		mean += pred.Prediction
	}
	mean /= float64(len(predictions))

	variance := 0.0
	for _, pred := range predictions {
		variance += math.Pow(pred.Prediction-mean, 2)
	}
	variance /= float64(len(predictions))

	return &UncertaintyMetrics{
		PredictionVariance: variance,
		ModelDisagreement:  variance, // Simplified
		TotalUncertainty:   math.Sqrt(variance),
	}
}

func (emm *EnsembleModelManager) calculateDiversityMetrics(predictions []*ModelPrediction) *DiversityMetrics {
	if len(predictions) < 2 {
		return &DiversityMetrics{}
	}

	// Calculate pairwise diversity
	totalPairs := 0
	diversitySum := 0.0

	for i := 0; i < len(predictions); i++ {
		for j := i + 1; j < len(predictions); j++ {
			diff := math.Abs(predictions[i].Prediction - predictions[j].Prediction)
			diversitySum += diff
			totalPairs++
		}
	}

	pairwiseDiversity := 0.0
	if totalPairs > 0 {
		pairwiseDiversity = diversitySum / float64(totalPairs)
	}

	return &DiversityMetrics{
		PairwiseDiversity: pairwiseDiversity,
	}
}

func (emm *EnsembleModelManager) generateExplanation(predictions []*ModelPrediction, ensemblePred *EnsemblePrediction) *EnsembleExplanation {
	return &EnsembleExplanation{
		ModelExplanations: make(map[string]*ModelExplanation),
		FeatureImportance: make(map[string]float64),
		DecisionPath:      []DecisionStep{},
		Counterfactuals:   []Counterfactual{},
		SimilarCases:      []SimilarCase{},
		ConfidenceFactors: []ConfidenceFactor{},
	}
}

func (emm *EnsembleModelManager) trainMetaLearner(trainingData []TrainingData) error {
	// Generate base model predictions for training data
	basePredictions := make([][]*ModelPrediction, len(trainingData))
	trueLabels := make([]float64, len(trainingData))
	for i, sample := range trainingData {
		preds := make([]*ModelPrediction, 0, len(emm.models))
		for modelName, model := range emm.models {
			pred, err := model.Predict(sample.Features)
			if err != nil {
				continue
			}
			preds = append(preds, &ModelPrediction{
				ModelName:  modelName,
				Prediction: pred.Confidence,
			})
		}
		basePredictions[i] = preds
		trueLabels[i] = sample.Label
	}

	return emm.metaLearner.Train(basePredictions, trueLabels)
}

func (emm *EnsembleModelManager) updateModelWeights(trainingData []TrainingData) error {
	// Evaluate individual model performance and update weights
	performanceScores := make(map[string]float64)

	for modelName, model := range emm.models {
		correct := 0
		total := len(trainingData)

		for _, sample := range trainingData {
			pred, err := model.Predict(sample.Features)
			if err != nil {
				continue
			}

			if math.Abs(pred.Confidence-sample.Label) < 0.5 {
				correct++
			}
		}

		accuracy := float64(correct) / float64(total)
		performanceScores[modelName] = accuracy
	}

	// Normalize weights based on performance
	totalPerformance := 0.0
	for _, score := range performanceScores {
		totalPerformance += score
	}

	if totalPerformance > 0 {
		for modelName, score := range performanceScores {
			emm.modelWeights[modelName] = score / totalPerformance
		}
	}

	return nil
}

// NewPerformanceTracker creates a new performance tracker
func NewPerformanceTracker(windowSize int) *PerformanceTracker {
	return &PerformanceTracker{
		windowSize:         windowSize,
		performanceHistory: make([]PerformanceSnapshot, 0, windowSize),
		modelMetrics:       make(map[string]*ModelMetrics),
	}
}

// Placeholder implementations for interfaces

type PlaceholderDeepLearningModel struct {
	name string
}

func (p *PlaceholderDeepLearningModel) Initialize(config map[string]interface{}) error {
	return nil
}

func (p *PlaceholderDeepLearningModel) Train(data []TrainingData) (*TrainingResult, error) {
	return &TrainingResult{}, nil
}

func (p *PlaceholderDeepLearningModel) Predict(features []float64) (*NeuralPrediction, error) {
	return &NeuralPrediction{Confidence: 0.5}, nil
}

func (p *PlaceholderDeepLearningModel) Evaluate(testData []TrainingData) (*EvaluationResult, error) {
	return &EvaluationResult{Metrics: map[string]float64{"accuracy": 0.5}}, nil
}

func (p *PlaceholderDeepLearningModel) SaveModel(path string) error {
	return nil
}

func (p *PlaceholderDeepLearningModel) LoadModel(path string) error {
	return nil
}

func (p *PlaceholderDeepLearningModel) GetModelInfo() *ModelInfo {
	return &ModelInfo{}
}

func (p *PlaceholderDeepLearningModel) SetHyperparameters(params map[string]interface{}) error {
	return nil
}

func (p *PlaceholderDeepLearningModel) GetTrainingProgress() *TrainingProgress {
	return &TrainingProgress{}
}

func (p *PlaceholderDeepLearningModel) IsReady() bool {
	return true
}

func (p *PlaceholderDeepLearningModel) GetID() string {
	return p.name
}

func (p *PlaceholderDeepLearningModel) GetArchitecture() *NetworkArchitecture {
	return &NetworkArchitecture{}
}

// Removed duplicate methods - they are already defined above

// Fusion strategy implementations

type WeightedAverageFusion struct{}

func (w *WeightedAverageFusion) GetName() string {
	return "weighted_average"
}

func (w *WeightedAverageFusion) Fuse(predictions []*ModelPrediction, weights []float64) (*EnsemblePrediction, error) {
	if len(predictions) != len(weights) {
		return nil, fmt.Errorf("predictions and weights length mismatch")
	}

	weightedSum := 0.0
	weightSum := 0.0

	for i, pred := range predictions {
		weightedSum += pred.Prediction * weights[i]
		weightSum += weights[i]
	}

	finalPrediction := weightedSum / weightSum

	return &EnsemblePrediction{
		FinalPrediction: finalPrediction,
		FinalConfidence: 0.8, // Placeholder
		FusionStrategy:  w.GetName(),
	}, nil
}

func (w *WeightedAverageFusion) GetConfiguration() map[string]interface{} {
	return map[string]interface{}{"type": "weighted_average"}
}

func (w *WeightedAverageFusion) Validate(predictions []*ModelPrediction) error {
	return nil
}

type StackingFusion struct{}

func (s *StackingFusion) GetName() string {
	return "stacking"
}

func (s *StackingFusion) Fuse(predictions []*ModelPrediction, weights []float64) (*EnsemblePrediction, error) {
	// Placeholder stacking implementation
	return &EnsemblePrediction{
		FinalPrediction: 0.5,
		FinalConfidence: 0.7,
		FusionStrategy:  s.GetName(),
	}, nil
}

func (s *StackingFusion) GetConfiguration() map[string]interface{} {
	return map[string]interface{}{"type": "stacking"}
}

func (s *StackingFusion) Validate(predictions []*ModelPrediction) error {
	return nil
}

type BayesianFusion struct{}

func (b *BayesianFusion) GetName() string {
	return "bayesian"
}

func (b *BayesianFusion) Fuse(predictions []*ModelPrediction, weights []float64) (*EnsemblePrediction, error) {
	// Placeholder Bayesian fusion implementation
	return &EnsemblePrediction{
		FinalPrediction: 0.6,
		FinalConfidence: 0.9,
		FusionStrategy:  b.GetName(),
	}, nil
}

func (b *BayesianFusion) GetConfiguration() map[string]interface{} {
	return map[string]interface{}{"type": "bayesian"}
}

func (b *BayesianFusion) Validate(predictions []*ModelPrediction) error {
	return nil
}

// Voting mechanism implementations

type MajorityVoting struct {
	stats *VotingStats
}

func (m *MajorityVoting) GetName() string {
	return "majority"
}

func (m *MajorityVoting) Vote(predictions []*ModelPrediction, weights []float64) (*VotingResult, error) {
	votes := make(map[string]float64)
	for _, pred := range predictions {
		if pred.Prediction > 0.5 {
			votes["positive"]++
		} else {
			votes["negative"]++
		}
	}

	majorityVote := 0.0
	if votes["positive"] > votes["negative"] {
		majorityVote = 1.0
	}

	return &VotingResult{
		VotingMethod: m.GetName(),
		Votes:        votes,
		MajorityVote: majorityVote,
	}, nil
}

func (m *MajorityVoting) GetVotingStats() *VotingStats {
	if m.stats == nil {
		m.stats = &VotingStats{}
	}
	return m.stats
}

func (m *MajorityVoting) UpdateWeights(performance map[string]float64) error {
	return nil
}

type WeightedVoting struct {
	stats *VotingStats
}

func (w *WeightedVoting) GetName() string {
	return "weighted"
}

func (w *WeightedVoting) Vote(predictions []*ModelPrediction, weights []float64) (*VotingResult, error) {
	weightedVotes := make(map[string]float64)
	for i, pred := range predictions {
		if pred.Prediction > 0.5 {
			weightedVotes["positive"] += weights[i]
		} else {
			weightedVotes["negative"] += weights[i]
		}
	}

	majorityVote := 0.0
	if weightedVotes["positive"] > weightedVotes["negative"] {
		majorityVote = 1.0
	}

	return &VotingResult{
		VotingMethod:  w.GetName(),
		WeightedVotes: weightedVotes,
		MajorityVote:  majorityVote,
	}, nil
}

func (w *WeightedVoting) GetVotingStats() *VotingStats {
	if w.stats == nil {
		w.stats = &VotingStats{}
	}
	return w.stats
}

func (w *WeightedVoting) UpdateWeights(performance map[string]float64) error {
	return nil
}

type RankedVoting struct {
	stats *VotingStats
}

func (r *RankedVoting) GetName() string {
	return "ranked"
}

func (r *RankedVoting) Vote(predictions []*ModelPrediction, weights []float64) (*VotingResult, error) {
	// Sort predictions by confidence
	sort.Slice(predictions, func(i, j int) bool {
		return predictions[i].Confidence > predictions[j].Confidence
	})

	// Use top-ranked prediction
	majorityVote := predictions[0].Prediction

	return &VotingResult{
		VotingMethod: r.GetName(),
		MajorityVote: majorityVote,
	}, nil
}

func (r *RankedVoting) GetVotingStats() *VotingStats {
	if r.stats == nil {
		r.stats = &VotingStats{}
	}
	return r.stats
}

func (r *RankedVoting) UpdateWeights(performance map[string]float64) error {
	return nil
}

// Meta-learner implementation

type NeuralMetaLearner struct {
	model DeepLearningModel
}

func (n *NeuralMetaLearner) GetName() string {
	return "neural_meta_learner"
}

func (n *NeuralMetaLearner) Train(basePredictions [][]*ModelPrediction, trueLabels []float64) error {
	// Convert base predictions to meta-features
	trainingData := make([]TrainingData, len(basePredictions))
	for i, preds := range basePredictions {
		metaFeatures := n.GetMetaFeatures(preds)
		label := 0.0
		if i < len(trueLabels) {
			label = trueLabels[i]
		}
		trainingData[i] = TrainingData{
			Features: metaFeatures,
			Label:    label,
			Weight:   1.0,
			Metadata: make(map[string]interface{}),
		}
	}

	// Train meta-model
	result, err := n.model.Train(trainingData)
	if err != nil {
		return err
	}
	_ = result // Ignore result for now
	return nil
}

func (n *NeuralMetaLearner) Predict(basePredictions []*ModelPrediction) (*MetaPrediction, error) {
	metaFeatures := n.GetMetaFeatures(basePredictions)
	prediction, err := n.model.Predict(metaFeatures)
	if err != nil {
		return nil, err
	}

	return &MetaPrediction{
		MetaModelName:  n.GetName(),
		MetaPrediction: prediction.Confidence,
		MetaConfidence: prediction.Confidence,
		MetaFeatures:   metaFeatures,
	}, nil
}

func (n *NeuralMetaLearner) GetMetaFeatures(predictions []*ModelPrediction) []float64 {
	if len(predictions) == 0 {
		return []float64{}
	}

	// Extract meta-features from base predictions
	features := make([]float64, 0)

	// Add individual predictions
	for _, pred := range predictions {
		features = append(features, pred.Prediction, pred.Confidence, pred.Uncertainty)
	}

	// Add aggregate statistics
	mean := 0.0
	for _, pred := range predictions {
		mean += pred.Prediction
	}
	mean /= float64(len(predictions))
	features = append(features, mean)

	// Add variance
	variance := 0.0
	for _, pred := range predictions {
		variance += math.Pow(pred.Prediction-mean, 2)
	}
	variance /= float64(len(predictions))
	features = append(features, variance)

	return features
}

func (n *NeuralMetaLearner) SaveModel(path string) error {
	return n.model.SaveModel(path)
}

func (n *NeuralMetaLearner) LoadModel(path string) error {
	return n.model.LoadModel(path)
}

// DefaultEnsembleConfig returns a default ensemble configuration
func DefaultEnsembleConfig() *EnsembleConfig {
	return &EnsembleConfig{
		ModelConfigs:         make(map[string]*DeepLearningConfig),
		FusionStrategy:       "weighted_average",
		VotingMethod:         "majority",
		WeightingScheme:      "performance",
		AdaptiveWeights:      true,
		MetaLearningEnabled:  false,
		DiversityThreshold:   0.1,
		PerformanceWindow:    100,
		UpdateFrequency:      time.Hour,
		MinModels:            2,
		MaxModels:            10,
		CrossValidationFolds: 5,
		EarlyStoppingConfig: &EarlyStoppingConfig{
			Enabled:            true,
			Patience:           10,
			MinDelta:           0.001,
			Monitor:            "val_loss",
			Mode:               "min",
			Restore:            true,
			RestoreBestWeights: true,
		},
		RegularizationConfig: &RegularizationConfig{
			L1Lambda:         0.0,
			L2Lambda:         0.001,
			DropoutRate:      0.2,
			BatchNorm:        true,
			LayerNorm:        false,
			WeightDecay:      0.0001,
			GradientClipping: 1.0,
			NoiseInjection:   0.0,
		},
	}
}
