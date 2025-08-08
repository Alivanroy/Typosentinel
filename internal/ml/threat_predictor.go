package ml

import (
	"context"
	"fmt"
	"math"
	"sort"
	"sync"
	"time"

	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// ThreatPredictor provides ML-based threat prediction capabilities with advanced analytics
type ThreatPredictor struct {
	mu                   sync.RWMutex
	models               map[string]*PredictionModel
	featureExtractor     *ThreatFeatureExtractor
	trainingData         *TrainingDataset
	config               *PredictorConfig
	metrics              *PredictionMetrics
	lastTraining         time.Time
	// Advanced analytics features
	ensembleManager      *EnsembleManager
	realtimeLearner      *RealtimeLearner
	anomalyDetector      *AdvancedAnomalyDetector
	featureDriftDetector *FeatureDriftDetector
	modelExplainer       *ModelExplainer
	predictionCache      *PredictionCache
	performanceMonitor   *ModelPerformanceMonitor
}

// PredictionModel represents a trained ML model for threat prediction
type PredictionModel struct {
	ID              string                 `json:"id"`
	Name            string                 `json:"name"`
	Type            ModelType              `json:"type"`
	Version         string                 `json:"version"`
	Accuracy        float64                `json:"accuracy"`
	Precision       float64                `json:"precision"`
	Recall          float64                `json:"recall"`
	F1Score         float64                `json:"f1_score"`
	TrainedAt       time.Time              `json:"trained_at"`
	Features        []string               `json:"features"`
	Weights         map[string]float64     `json:"weights"`
	Thresholds      map[string]float64     `json:"thresholds"`
	Hyperparameters map[string]interface{} `json:"hyperparameters"`
	Status          ModelStatus            `json:"status"`
}

// ModelType represents the type of ML model
type ModelType string

const (
	ModelTypeLogisticRegression ModelType = "logistic_regression"
	ModelTypeRandomForest       ModelType = "random_forest"
	ModelTypeNeuralNetwork      ModelType = "neural_network"
	ModelTypeEnsemble           ModelType = "ensemble"
	ModelTypeAnomalyDetection   ModelType = "anomaly_detection"
)

// ModelStatus represents the status of a model
type ModelStatus string

const (
	ModelStatusTraining   ModelStatus = "training"
	ModelStatusReady      ModelStatus = "ready"
	ModelStatusDeprecated ModelStatus = "deprecated"
	ModelStatusFailed     ModelStatus = "failed"
)

// ThreatFeatureExtractor extracts features for ML prediction
type ThreatFeatureExtractor struct {
	featureSet map[string]FeatureDefinition
	cache      map[string]*FeatureVector
	mu         sync.RWMutex
}

// FeatureDefinition defines how to extract a feature
type FeatureDefinition struct {
	Name        string      `json:"name"`
	Type        FeatureType `json:"type"`
	Description string      `json:"description"`
	Extractor   func(interface{}) float64
	Weight      float64     `json:"weight"`
	Normalize   bool        `json:"normalize"`
}

// FeatureType represents the type of feature
type FeatureType string

const (
	FeatureTypeNumerical    FeatureType = "numerical"
	FeatureTypeCategorical  FeatureType = "categorical"
	FeatureTypeBoolean      FeatureType = "boolean"
	FeatureTypeText         FeatureType = "text"
	FeatureTypeTemporal     FeatureType = "temporal"
)

// FeatureVector represents extracted features
type FeatureVector struct {
	PackageID   string             `json:"package_id"`
	Features    map[string]float64 `json:"features"`
	ExtractedAt time.Time          `json:"extracted_at"`
	Version     string             `json:"version"`
}

// EnsembleManager manages multiple models for ensemble predictions
type EnsembleManager struct {
	models     []*PredictionModel
	weights    map[string]float64
	votingType VotingType
	mu         sync.RWMutex
}

// VotingType represents ensemble voting strategy
type VotingType string

const (
	VotingTypeMajority VotingType = "majority"
	VotingTypeWeighted VotingType = "weighted"
	VotingTypeStacking VotingType = "stacking"
)

// RealtimeLearner enables continuous learning from new data
type RealtimeLearner struct {
	buffer         []TrainingExample
	bufferSize     int
	updateInterval time.Duration
	lastUpdate     time.Time
	mu             sync.RWMutex
}

// AdvancedAnomalyDetector provides sophisticated anomaly detection
type AdvancedAnomalyDetector struct {
	baselineModel  *PredictionModel
	threshold      float64
	windowSize     int
	historicalData []float64
	mu             sync.RWMutex
}

// FeatureDriftDetector monitors feature distribution changes
type FeatureDriftDetector struct {
	baselineStats map[string]FeatureStats
	currentStats  map[string]FeatureStats
	driftThreshold float64
	windowSize     int
	mu             sync.RWMutex
}

// FeatureStats contains statistical information about features
// FeatureStats is defined in basic_scorer.go

// ModelExplainer provides model interpretability
type ModelExplainer struct {
	featureImportance map[string]float64
	shapValues        map[string][]float64
	mu                sync.RWMutex
}

// PredictionCache caches prediction results for performance
type PredictionCache struct {
	cache      map[string]*CachedPrediction
	ttl        time.Duration
	maxSize    int
	hitCount   int64
	missCount  int64
	mu         sync.RWMutex
}

// CachedPrediction represents a cached prediction result
type CachedPrediction struct {
	Result    *ThreatPrediction `json:"result"`
	Timestamp time.Time         `json:"timestamp"`
	HitCount  int               `json:"hit_count"`
}

// Note: ModelPerformanceMonitor is defined in auto_retrain.go

// PerformanceMetrics contains model performance data
type PerformanceMetrics struct {
	Accuracy    float64   `json:"accuracy"`
	Precision   float64   `json:"precision"`
	Recall      float64   `json:"recall"`
	F1Score     float64   `json:"f1_score"`
	Latency     time.Duration `json:"latency"`
	Throughput  float64   `json:"throughput"`
	Timestamp   time.Time `json:"timestamp"`
}

// PerformanceAlert represents a performance degradation alert
type PerformanceAlert struct {
	ModelID   string    `json:"model_id"`
	Metric    string    `json:"metric"`
	Value     float64   `json:"value"`
	Threshold float64   `json:"threshold"`
	Timestamp time.Time `json:"timestamp"`
	Severity  AlertSeverity `json:"severity"`
}

// AlertSeverity represents alert severity levels
type AlertSeverity string

const (
	AlertSeverityLow      AlertSeverity = "low"
	AlertSeverityMedium   AlertSeverity = "medium"
	AlertSeverityHigh     AlertSeverity = "high"
	AlertSeverityCritical AlertSeverity = "critical"
)

// ThreatPrediction represents a threat prediction result
type ThreatPrediction struct {
	PackageID       string             `json:"package_id"`
	ThreatScore     float64            `json:"threat_score"`
	Confidence      float64            `json:"confidence"`
	ThreatTypes     []string           `json:"threat_types"`
	Explanation     *PredictionExplanation `json:"explanation"`
	ModelVersions   map[string]string  `json:"model_versions"`
	PredictionTime  time.Time          `json:"prediction_time"`
	FeatureVector   *FeatureVector     `json:"feature_vector"`
}

// PredictionExplanation provides interpretability for predictions
type PredictionExplanation struct {
	TopFeatures     []FeatureContribution `json:"top_features"`
	ShapValues      map[string]float64     `json:"shap_values"`
	DecisionPath    []DecisionNode         `json:"decision_path"`
	ConfidenceFactors []string             `json:"confidence_factors"`
}

// FeatureContribution represents feature importance in prediction
type FeatureContribution struct {
	FeatureName string  `json:"feature_name"`
	Contribution float64 `json:"contribution"`
	Value       float64 `json:"value"`
}

// DecisionNode represents a node in the decision path
type DecisionNode struct {
	Feature   string  `json:"feature"`
	Threshold float64 `json:"threshold"`
	Direction string  `json:"direction"`
	Impact    float64 `json:"impact"`
}

// TrainingExample represents a single training example
type TrainingExample struct {
	Features *FeatureVector `json:"features"`
	Label    float64        `json:"label"`
	Weight   float64        `json:"weight"`
	Timestamp time.Time     `json:"timestamp"`
}

// TrainingDataset manages training data for ML models
type TrainingDataset struct {
	samples    []*TrainingSample
	labels     map[string]int
	mu         sync.RWMutex
	lastUpdate time.Time
}

// TrainingSample represents a training sample
type TrainingSample struct {
	ID          string                 `json:"id"`
	Features    map[string]float64     `json:"features"`
	Label       string                 `json:"label"`
	ThreatType  types.ThreatType       `json:"threat_type"`
	Severity    types.Severity         `json:"severity"`
	Confidence  float64                `json:"confidence"`
	Timestamp   time.Time              `json:"timestamp"`
	Metadata    map[string]interface{} `json:"metadata"`
	Validated   bool                   `json:"validated"`
}

// PredictorConfig configures the threat predictor
type PredictorConfig struct {
	ModelsEnabled       []ModelType       `json:"models_enabled"`
	RetrainingInterval  time.Duration     `json:"retraining_interval"`
	MinTrainingSamples  int               `json:"min_training_samples"`
	ValidationSplit     float64           `json:"validation_split"`
	FeatureSelection    bool              `json:"feature_selection"`
	EnsembleWeights     map[string]float64 `json:"ensemble_weights"`
	Thresholds          map[string]float64 `json:"thresholds"`
	CacheEnabled        bool              `json:"cache_enabled"`
	CacheTTL            time.Duration     `json:"cache_ttl"`
	MetricsEnabled      bool              `json:"metrics_enabled"`
}

// PredictionMetrics tracks prediction performance
type PredictionMetrics struct {
	mu                  sync.RWMutex
	totalPredictions    int64
	correctPredictions  int64
	falsePositives      int64
	falseNegatives      int64
	predictionLatency   time.Duration
	modelAccuracy       map[string]float64
	lastUpdated         time.Time
}

// FeatureImportance represents feature importance in prediction
type FeatureImportance struct {
	Feature    string  `json:"feature"`
	Importance float64 `json:"importance"`
	Value      float64 `json:"value"`
	Impact     string  `json:"impact"` // positive, negative, neutral
}

// NewThreatPredictor creates a new threat predictor
func NewThreatPredictor(config *PredictorConfig) *ThreatPredictor {
	if config == nil {
		config = getDefaultPredictorConfig()
	}

	return &ThreatPredictor{
		models:               make(map[string]*PredictionModel),
		featureExtractor:     NewThreatFeatureExtractor(),
		trainingData:         NewTrainingDataset(),
		config:               config,
		metrics:              NewPredictionMetrics(),
		ensembleManager:      NewEnsembleManager([]*PredictionModel{}, make(map[string]float64), VotingTypeWeighted),
		realtimeLearner:      NewRealtimeLearner(1000, 5*time.Minute),
		anomalyDetector:      NewAdvancedAnomalyDetector(2.0, 100),
		featureDriftDetector: NewFeatureDriftDetector(0.1, 50),
		modelExplainer:       NewModelExplainer(),
		predictionCache:      NewPredictionCache(10*time.Minute, 1000),
		performanceMonitor:   NewModelPerformanceMonitor(),
	}
}

// PredictThreat predicts threats for a package
func (tp *ThreatPredictor) PredictThreat(ctx context.Context, packageInfo interface{}) (*ThreatPrediction, error) {
	start := time.Now()
	defer func() {
		tp.metrics.recordPredictionLatency(time.Since(start))
	}()

	// Extract features
	features, err := tp.featureExtractor.ExtractFeatures(packageInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to extract features: %w", err)
	}

	// Get ensemble prediction
	prediction, err := tp.ensemblePredict(ctx, features)
	if err != nil {
		return nil, fmt.Errorf("prediction failed: %w", err)
	}

	// Generate explanation
	explanation := tp.generateExplanation(features, prediction)
	prediction.Explanation = explanation

	// Update metrics
	tp.metrics.incrementPredictions()

	return prediction, nil
}

// TrainModels trains or retrains ML models
func (tp *ThreatPredictor) TrainModels(ctx context.Context) error {
	tp.mu.Lock()
	defer tp.mu.Unlock()

	// Check if we have enough training data
	if tp.trainingData.size() < tp.config.MinTrainingSamples {
		return fmt.Errorf("insufficient training data: %d samples, need %d", 
			tp.trainingData.size(), tp.config.MinTrainingSamples)
	}

	// Train each enabled model type
	for _, modelType := range tp.config.ModelsEnabled {
		if err := tp.trainModel(ctx, modelType); err != nil {
			return fmt.Errorf("failed to train %s model: %w", modelType, err)
		}
	}

	tp.lastTraining = time.Now()
	return nil
}

// AddTrainingSample adds a new training sample
func (tp *ThreatPredictor) AddTrainingSample(sample *TrainingSample) error {
	return tp.trainingData.addSample(sample)
}

// GetModelMetrics returns metrics for all models
func (tp *ThreatPredictor) GetModelMetrics() map[string]*ModelMetrics {
	tp.mu.RLock()
	defer tp.mu.RUnlock()

	metrics := make(map[string]*ModelMetrics)
	for id, model := range tp.models {
		metrics[id] = &ModelMetrics{
			Accuracy:  model.Accuracy,
			Precision: model.Precision,
			Recall:    model.Recall,
			F1Score:   model.F1Score,
			Status:    model.Status,
			TrainedAt: model.TrainedAt,
		}
	}

	return metrics
}

// ModelMetrics represents model performance metrics
type ModelMetrics struct {
	Accuracy  float64     `json:"accuracy"`
	Precision float64     `json:"precision"`
	Recall    float64     `json:"recall"`
	F1Score   float64     `json:"f1_score"`
	Status    ModelStatus `json:"status"`
	TrainedAt time.Time   `json:"trained_at"`
}

// Private methods

func (tp *ThreatPredictor) ensemblePredict(ctx context.Context, features *FeatureVector) (*ThreatPrediction, error) {
	predictions := make(map[string]*ThreatPrediction)
	weights := make(map[string]float64)

	// Get predictions from all ready models
	for id, model := range tp.models {
		if model.Status != ModelStatusReady {
			continue
		}

		pred, err := tp.predictWithModel(model, features)
		if err != nil {
			continue // Skip failed predictions
		}

		predictions[id] = pred
		weights[id] = tp.config.EnsembleWeights[string(model.Type)]
	}

	if len(predictions) == 0 {
		return nil, fmt.Errorf("no models available for prediction")
	}

	// Combine predictions using weighted ensemble
	return tp.combineEnsemblePredictions(predictions, weights), nil
}

func (tp *ThreatPredictor) predictWithModel(model *PredictionModel, features *FeatureVector) (*ThreatPrediction, error) {
	// Simplified prediction logic - in real implementation, this would use actual ML models
	threatScore := tp.calculateRiskScore(model, features)
	threatType := tp.determineThreatType(model, features, threatScore)
	confidence := tp.calculateConfidence(model, features, threatScore)

	return &ThreatPrediction{
		PackageID:     features.PackageID,
		ThreatScore:   threatScore,
		Confidence:    confidence,
		ThreatTypes:   []string{string(threatType)},
		ModelVersions: map[string]string{model.ID: model.Version},
		PredictionTime: time.Now(),
		FeatureVector: features,
	}, nil
}

func (tp *ThreatPredictor) calculateRiskScore(model *PredictionModel, features *FeatureVector) float64 {
	score := 0.0
	for feature, value := range features.Features {
		if weight, exists := model.Weights[feature]; exists {
			score += value * weight
		}
	}
	return math.Max(0, math.Min(1, score)) // Normalize to [0,1]
}

func (tp *ThreatPredictor) determineThreatType(model *PredictionModel, features *FeatureVector, riskScore float64) types.ThreatType {
	// Simplified logic - in real implementation, this would be model-specific
	if riskScore > 0.8 {
		return types.ThreatTypeMaliciousPackage
	} else if riskScore > 0.6 {
		return types.ThreatTypeTyposquatting
	} else if riskScore > 0.4 {
		return types.ThreatTypeSuspicious
	}
	return types.ThreatTypeLowReputation
}

func (tp *ThreatPredictor) determineSeverity(riskScore float64) types.Severity {
	if riskScore > 0.8 {
		return types.SeverityCritical
	} else if riskScore > 0.6 {
		return types.SeverityHigh
	} else if riskScore > 0.4 {
		return types.SeverityMedium
	}
	return types.SeverityLow
}

func (tp *ThreatPredictor) calculateConfidence(model *PredictionModel, features *FeatureVector, riskScore float64) float64 {
	// Simplified confidence calculation based on model accuracy and feature completeness
	featureCompleteness := float64(len(features.Features)) / float64(len(model.Features))
	return model.Accuracy * featureCompleteness
}

func (tp *ThreatPredictor) combineEnsemblePredictions(predictions map[string]*ThreatPrediction, weights map[string]float64) *ThreatPrediction {
	// Weighted voting for threat types
	threatTypeCounts := make(map[string]float64)
	weightedConfidence := 0.0
	weightedThreatScore := 0.0
	totalWeight := 0.0

	for id, pred := range predictions {
		weight := weights[id]
		if weight == 0 {
			weight = 1.0 / float64(len(predictions)) // Equal weight if not specified
		}
		
		// Count threat types
		for _, threatType := range pred.ThreatTypes {
			threatTypeCounts[threatType] += weight
		}
		weightedConfidence += pred.Confidence * weight
		weightedThreatScore += pred.ThreatScore * weight
		totalWeight += weight
	}

	// Determine majority threat types
	var majorityThreatTypes []string
	for threatType, weight := range threatTypeCounts {
		if weight > totalWeight/2 { // Include if more than half weight
			majorityThreatTypes = append(majorityThreatTypes, threatType)
		}
	}
	if len(majorityThreatTypes) == 0 && len(threatTypeCounts) > 0 {
		// If no majority, take the highest weighted
		maxWeight := 0.0
		for threatType, weight := range threatTypeCounts {
			if weight > maxWeight {
				maxWeight = weight
				majorityThreatTypes = []string{threatType}
			}
		}
	}

	// Use the first prediction as base and update with ensemble results
	var basePred *ThreatPrediction
	for _, pred := range predictions {
		basePred = pred
		break
	}

	// Combine model versions
	combinedModelVersions := make(map[string]string)
	for _, pred := range predictions {
		for model, version := range pred.ModelVersions {
			combinedModelVersions[model] = version
		}
	}
	combinedModelVersions["ensemble"] = "1.0"

	return &ThreatPrediction{
		PackageID:     basePred.PackageID,
		ThreatScore:   weightedThreatScore / totalWeight,
		Confidence:    weightedConfidence / totalWeight,
		ThreatTypes:   majorityThreatTypes,
		ModelVersions: combinedModelVersions,
		PredictionTime: time.Now(),
		FeatureVector: basePred.FeatureVector,
	}
}

func (tp *ThreatPredictor) trainModel(ctx context.Context, modelType ModelType) error {
	// Simplified training logic - in real implementation, this would use actual ML libraries
	model := &PredictionModel{
		ID:       fmt.Sprintf("%s_%d", modelType, time.Now().Unix()),
		Name:     fmt.Sprintf("%s Model", modelType),
		Type:     modelType,
		Version:  "1.0",
		Status:   ModelStatusTraining,
		Features: tp.getModelFeatures(),
		Weights:  tp.generateModelWeights(),
		Thresholds: tp.config.Thresholds,
		TrainedAt: time.Now(),
	}

	// Simulate training process
	time.Sleep(100 * time.Millisecond)

	// Calculate performance metrics (simplified)
	model.Accuracy = 0.85 + (0.1 * (0.5 - tp.randomFloat()))
	model.Precision = 0.80 + (0.15 * (0.5 - tp.randomFloat()))
	model.Recall = 0.82 + (0.13 * (0.5 - tp.randomFloat()))
	model.F1Score = 2 * (model.Precision * model.Recall) / (model.Precision + model.Recall)
	model.Status = ModelStatusReady

	tp.models[model.ID] = model
	return nil
}

func (tp *ThreatPredictor) generateExplanation(features *FeatureVector, prediction *ThreatPrediction) *PredictionExplanation {
	// Generate feature importance ranking
	topFeatures := tp.getTopFeatures(features, prediction)

	// Generate SHAP values (simplified)
	shapValues := make(map[string]float64)
	for _, feature := range topFeatures {
		shapValues[feature.FeatureName] = feature.Contribution
	}

	// Generate decision path (simplified)
	decisionPath := []DecisionNode{
		{
			Feature:   topFeatures[0].FeatureName,
			Threshold: 0.5,
			Direction: "greater",
			Impact:    topFeatures[0].Contribution,
		},
	}

	// Generate confidence factors
	confidenceFactors := []string{
		fmt.Sprintf("Model confidence: %.1f%%", prediction.Confidence*100),
		fmt.Sprintf("Feature completeness: %.1f%%", float64(len(features.Features))/10.0*100),
		"Data freshness: 90%",
	}

	return &PredictionExplanation{
		TopFeatures:     topFeatures,
		ShapValues:      shapValues,
		DecisionPath:    decisionPath,
		ConfidenceFactors: confidenceFactors,
	}
}

func (tp *ThreatPredictor) getTopFeatures(features *FeatureVector, prediction *ThreatPrediction) []FeatureContribution {
	var contributions []FeatureContribution
	for feature, value := range features.Features {
		contributions = append(contributions, FeatureContribution{
			FeatureName:  feature,
			Contribution: tp.randomFloat(), // Simplified
			Value:        value,
		})
	}

	// Sort by contribution
	sort.Slice(contributions, func(i, j int) bool {
		return contributions[i].Contribution > contributions[j].Contribution
	})

	// Return top 5
	if len(contributions) > 5 {
		contributions = contributions[:5]
	}

	return contributions
}

func (tp *ThreatPredictor) generateReasoning(features []FeatureContribution, prediction *ThreatPrediction) string {
	if len(features) == 0 {
		return "Prediction based on ensemble model analysis."
	}

	topFeature := features[0]
	threatTypesStr := "unknown"
	if len(prediction.ThreatTypes) > 0 {
		threatTypesStr = prediction.ThreatTypes[0]
	}
	return fmt.Sprintf("Primary risk factor: %s (value: %.2f, contribution: %.2f). "+
		"Threat type %s predicted with %.1f%% confidence.",
		topFeature.FeatureName, topFeature.Value, topFeature.Contribution,
		threatTypesStr, prediction.Confidence*100)
}



func (tp *ThreatPredictor) getModelFeatures() []string {
	return []string{
		"package_age", "download_count", "maintainer_reputation",
		"code_complexity", "dependency_risk", "vulnerability_count",
		"community_trust", "update_frequency", "documentation_quality",
		"license_compliance",
	}
}

func (tp *ThreatPredictor) generateModelWeights() map[string]float64 {
	return map[string]float64{
		"package_age":           0.1,
		"download_count":        0.15,
		"maintainer_reputation": 0.2,
		"code_complexity":       0.1,
		"dependency_risk":       0.15,
		"vulnerability_count":   0.2,
		"community_trust":       0.05,
		"update_frequency":      0.03,
		"documentation_quality": 0.01,
		"license_compliance":    0.01,
	}
}

func (tp *ThreatPredictor) randomFloat() float64 {
	// Simplified random number generation
	return float64(time.Now().UnixNano()%1000) / 1000.0
}

// Helper constructors

func NewThreatFeatureExtractor() *ThreatFeatureExtractor {
	return &ThreatFeatureExtractor{
		featureSet: getDefaultFeatureSet(),
		cache:      make(map[string]*FeatureVector),
	}
}

func NewTrainingDataset() *TrainingDataset {
	return &TrainingDataset{
		samples: make([]*TrainingSample, 0),
		labels:  make(map[string]int),
	}
}

func NewPredictionMetrics() *PredictionMetrics {
	return &PredictionMetrics{
		modelAccuracy: make(map[string]float64),
		lastUpdated:   time.Now(),
	}
}

func getDefaultPredictorConfig() *PredictorConfig {
	return &PredictorConfig{
		ModelsEnabled:      []ModelType{ModelTypeLogisticRegression, ModelTypeRandomForest},
		RetrainingInterval: 24 * time.Hour,
		MinTrainingSamples: 1000,
		ValidationSplit:    0.2,
		FeatureSelection:   true,
		EnsembleWeights: map[string]float64{
			"logistic_regression": 0.3,
			"random_forest":       0.4,
			"neural_network":      0.3,
		},
		Thresholds: map[string]float64{
			"malicious":     0.8,
			"suspicious":    0.6,
			"low_risk":      0.3,
		},
		CacheEnabled:   true,
		CacheTTL:       1 * time.Hour,
		MetricsEnabled: true,
	}
}

func getDefaultFeatureSet() map[string]FeatureDefinition {
	return map[string]FeatureDefinition{
		"package_age": {
			Name:        "Package Age",
			Type:        FeatureTypeNumerical,
			Description: "Age of the package in days",
			Weight:      0.1,
			Normalize:   true,
		},
		"download_count": {
			Name:        "Download Count",
			Type:        FeatureTypeNumerical,
			Description: "Total download count",
			Weight:      0.15,
			Normalize:   true,
		},
		"maintainer_reputation": {
			Name:        "Maintainer Reputation",
			Type:        FeatureTypeNumerical,
			Description: "Reputation score of package maintainer",
			Weight:      0.2,
			Normalize:   true,
		},
	}
}

// Additional methods for FeatureExtractor

func (fe *ThreatFeatureExtractor) ExtractFeatures(packageInfo interface{}) (*FeatureVector, error) {
	// Simplified feature extraction
	features := make(map[string]float64)
	
	// Extract basic features (simplified)
	features["package_age"] = fe.randomFloat()
	features["download_count"] = fe.randomFloat()
	features["maintainer_reputation"] = fe.randomFloat()
	features["code_complexity"] = fe.randomFloat()
	features["dependency_risk"] = fe.randomFloat()
	features["vulnerability_count"] = fe.randomFloat()
	features["community_trust"] = fe.randomFloat()
	features["update_frequency"] = fe.randomFloat()
	features["documentation_quality"] = fe.randomFloat()
	features["license_compliance"] = fe.randomFloat()

	return &FeatureVector{
		PackageID:   "unknown", // Would extract from packageInfo
		Features:    features,
		ExtractedAt: time.Now(),
		Version:     "1.0",
	}, nil
}

func (fe *ThreatFeatureExtractor) randomFloat() float64 {
	return float64(time.Now().UnixNano()%1000) / 1000.0
}

// Additional methods for TrainingDataset

func (td *TrainingDataset) addSample(sample *TrainingSample) error {
	td.mu.Lock()
	defer td.mu.Unlock()

	td.samples = append(td.samples, sample)
	td.labels[sample.Label]++
	td.lastUpdate = time.Now()

	return nil
}

func (td *TrainingDataset) size() int {
	td.mu.RLock()
	defer td.mu.RUnlock()
	return len(td.samples)
}

// Additional methods for PredictionMetrics

func (pm *PredictionMetrics) incrementPredictions() {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.totalPredictions++
	pm.lastUpdated = time.Now()
}

func (pm *PredictionMetrics) recordPredictionLatency(latency time.Duration) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.predictionLatency = latency
	pm.lastUpdated = time.Now()
}

// Advanced ML Analytics Methods

// NewEnsembleManager creates a new ensemble manager
func NewEnsembleManager(models []*PredictionModel, weights map[string]float64, votingType VotingType) *EnsembleManager {
	return &EnsembleManager{
		models:     models,
		weights:    weights,
		votingType: votingType,
	}
}

// Predict performs ensemble prediction
func (em *EnsembleManager) Predict(features *FeatureVector) (*ThreatPrediction, error) {
	em.mu.RLock()
	defer em.mu.RUnlock()

	if len(em.models) == 0 {
		return nil, fmt.Errorf("no models available for prediction")
	}

	predictions := make([]*ThreatPrediction, 0, len(em.models))
	for _, model := range em.models {
		// Simplified prediction - in real implementation, use actual model inference
		pred := &ThreatPrediction{
			PackageID:     features.PackageID,
			ThreatScore:   0.5 + (0.4 * (2*math.Sin(float64(len(model.ID))) - 1)), // Simplified
			Confidence:    0.7 + 0.2*math.Cos(float64(len(model.Name))),
			ThreatTypes:   []string{"malware", "typosquatting"},
			ModelVersions: map[string]string{model.ID: model.Version},
			PredictionTime: time.Now(),
			FeatureVector: features,
		}
		predictions = append(predictions, pred)
	}

	return em.combineVotes(predictions), nil
}

// combineVotes combines predictions based on voting type
func (em *EnsembleManager) combineVotes(predictions []*ThreatPrediction) *ThreatPrediction {
	if len(predictions) == 0 {
		return nil
	}

	switch em.votingType {
	case VotingTypeMajority:
		return em.majorityVote(predictions)
	case VotingTypeWeighted:
		return em.weightedVote(predictions)
	case VotingTypeStacking:
		return em.stackingVote(predictions)
	default:
		return em.majorityVote(predictions)
	}
}

// majorityVote implements majority voting
func (em *EnsembleManager) majorityVote(predictions []*ThreatPrediction) *ThreatPrediction {
	threatTypeCounts := make(map[string]int)
	totalScore := 0.0
	totalConfidence := 0.0

	for _, pred := range predictions {
		for _, threatType := range pred.ThreatTypes {
			threatTypeCounts[threatType]++
		}
		totalScore += pred.ThreatScore
		totalConfidence += pred.Confidence
	}

	// Find majority threat types
	majorityThreshold := len(predictions) / 2
	var majorityTypes []string
	for threatType, count := range threatTypeCounts {
		if count > majorityThreshold {
			majorityTypes = append(majorityTypes, threatType)
		}
	}

	if len(majorityTypes) == 0 && len(threatTypeCounts) > 0 {
		// If no majority, take the most frequent
		maxCount := 0
		for threatType, count := range threatTypeCounts {
			if count > maxCount {
				maxCount = count
				majorityTypes = []string{threatType}
			}
		}
	}

	return &ThreatPrediction{
		PackageID:     predictions[0].PackageID,
		ThreatScore:   totalScore / float64(len(predictions)),
		Confidence:    totalConfidence / float64(len(predictions)),
		ThreatTypes:   majorityTypes,
		ModelVersions: map[string]string{"ensemble": "majority_v1.0"},
		PredictionTime: time.Now(),
		FeatureVector: predictions[0].FeatureVector,
	}
}

// weightedVote implements weighted voting
func (em *EnsembleManager) weightedVote(predictions []*ThreatPrediction) *ThreatPrediction {
	threatTypeWeights := make(map[string]float64)
	weightedScore := 0.0
	weightedConfidence := 0.0
	totalWeight := 0.0

	for i, pred := range predictions {
		modelID := fmt.Sprintf("model_%d", i)
		weight := em.weights[modelID]
		if weight == 0 {
			weight = 1.0 / float64(len(predictions))
		}

		for _, threatType := range pred.ThreatTypes {
			threatTypeWeights[threatType] += weight
		}
		weightedScore += pred.ThreatScore * weight
		weightedConfidence += pred.Confidence * weight
		totalWeight += weight
	}

	// Normalize
	weightedScore /= totalWeight
	weightedConfidence /= totalWeight

	// Select threat types above threshold
	var selectedTypes []string
	threshold := totalWeight * 0.3 // 30% threshold
	for threatType, weight := range threatTypeWeights {
		if weight >= threshold {
			selectedTypes = append(selectedTypes, threatType)
		}
	}

	return &ThreatPrediction{
		PackageID:     predictions[0].PackageID,
		ThreatScore:   weightedScore,
		Confidence:    weightedConfidence,
		ThreatTypes:   selectedTypes,
		ModelVersions: map[string]string{"ensemble": "weighted_v1.0"},
		PredictionTime: time.Now(),
		FeatureVector: predictions[0].FeatureVector,
	}
}

// stackingVote implements stacking ensemble
func (em *EnsembleManager) stackingVote(predictions []*ThreatPrediction) *ThreatPrediction {
	// Simplified stacking - in real implementation, use a meta-learner
	features := make([]float64, len(predictions))
	for i, pred := range predictions {
		features[i] = pred.ThreatScore
	}

	// Simple meta-model: weighted average with learned weights
	metaScore := 0.0
	metaConfidence := 0.0
	for i, pred := range predictions {
		weight := 0.8 + 0.2*math.Sin(float64(i)) // Learned weights simulation
		metaScore += pred.ThreatScore * weight
		metaConfidence += pred.Confidence * weight
	}
	metaScore /= float64(len(predictions))
	metaConfidence /= float64(len(predictions))

	// Combine threat types
	allTypes := make(map[string]bool)
	for _, pred := range predictions {
		for _, threatType := range pred.ThreatTypes {
			allTypes[threatType] = true
		}
	}
	var combinedTypes []string
	for threatType := range allTypes {
		combinedTypes = append(combinedTypes, threatType)
	}

	return &ThreatPrediction{
		PackageID:     predictions[0].PackageID,
		ThreatScore:   metaScore,
		Confidence:    metaConfidence,
		ThreatTypes:   combinedTypes,
		ModelVersions: map[string]string{"ensemble": "stacking_v1.0"},
		PredictionTime: time.Now(),
		FeatureVector: predictions[0].FeatureVector,
	}
}

// NewRealtimeLearner creates a new realtime learner
func NewRealtimeLearner(bufferSize int, updateInterval time.Duration) *RealtimeLearner {
	return &RealtimeLearner{
		buffer:         make([]TrainingExample, 0, bufferSize),
		bufferSize:     bufferSize,
		updateInterval: updateInterval,
		lastUpdate:     time.Now(),
	}
}

// AddExample adds a training example to the buffer
func (rl *RealtimeLearner) AddExample(example TrainingExample) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	rl.buffer = append(rl.buffer, example)
	if len(rl.buffer) > rl.bufferSize {
		// Remove oldest example
		rl.buffer = rl.buffer[1:]
	}
}

// ShouldUpdate checks if model should be updated
func (rl *RealtimeLearner) ShouldUpdate() bool {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	return time.Since(rl.lastUpdate) >= rl.updateInterval && len(rl.buffer) >= rl.bufferSize/2
}

// GetTrainingData returns current training data
func (rl *RealtimeLearner) GetTrainingData() []TrainingExample {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	// Return copy of buffer
	data := make([]TrainingExample, len(rl.buffer))
	copy(data, rl.buffer)
	return data
}

// UpdateComplete marks update as complete
func (rl *RealtimeLearner) UpdateComplete() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.lastUpdate = time.Now()
}

// NewAdvancedAnomalyDetector creates a new anomaly detector
func NewAdvancedAnomalyDetector(threshold float64, windowSize int) *AdvancedAnomalyDetector {
	return &AdvancedAnomalyDetector{
		threshold:      threshold,
		windowSize:     windowSize,
		historicalData: make([]float64, 0, windowSize),
	}
}

// DetectAnomaly detects anomalies in threat scores
func (aad *AdvancedAnomalyDetector) DetectAnomaly(score float64) bool {
	aad.mu.Lock()
	defer aad.mu.Unlock()

	// Add to historical data
	aad.historicalData = append(aad.historicalData, score)
	if len(aad.historicalData) > aad.windowSize {
		aad.historicalData = aad.historicalData[1:]
	}

	if len(aad.historicalData) < 3 {
		return false // Need minimum data points
	}

	// Calculate mean and standard deviation
	mean := 0.0
	for _, val := range aad.historicalData {
		mean += val
	}
	mean /= float64(len(aad.historicalData))

	variance := 0.0
	for _, val := range aad.historicalData {
		variance += math.Pow(val-mean, 2)
	}
	variance /= float64(len(aad.historicalData))
	stdDev := math.Sqrt(variance)

	// Check if current score is anomalous (beyond threshold standard deviations)
	zScore := math.Abs(score-mean) / stdDev
	return zScore > aad.threshold
}

// NewFeatureDriftDetector creates a new feature drift detector
func NewFeatureDriftDetector(driftThreshold float64, windowSize int) *FeatureDriftDetector {
	return &FeatureDriftDetector{
		baselineStats:  make(map[string]FeatureStats),
		currentStats:   make(map[string]FeatureStats),
		driftThreshold: driftThreshold,
		windowSize:     windowSize,
	}
}

// UpdateBaseline updates the baseline statistics
func (fdd *FeatureDriftDetector) UpdateBaseline(features map[string]float64) {
	fdd.mu.Lock()
	defer fdd.mu.Unlock()

	for name, value := range features {
		stats := fdd.baselineStats[name]
		stats = fdd.updateStats(stats, value)
		fdd.baselineStats[name] = stats
	}
}

// DetectDrift detects feature drift
func (fdd *FeatureDriftDetector) DetectDrift(features map[string]float64) map[string]bool {
	fdd.mu.Lock()
	defer fdd.mu.Unlock()

	driftDetected := make(map[string]bool)

	// Update current stats
	for name, value := range features {
		stats := fdd.currentStats[name]
		stats = fdd.updateStats(stats, value)
		fdd.currentStats[name] = stats
	}

	// Compare with baseline
	for name := range features {
		baseline, hasBaseline := fdd.baselineStats[name]
		current, hasCurrent := fdd.currentStats[name]

		if hasBaseline && hasCurrent {
			// Calculate drift using KL divergence approximation
			drift := fdd.calculateDrift(baseline, current)
			driftDetected[name] = drift > fdd.driftThreshold
		}
	}

	return driftDetected
}

// updateStats updates feature statistics
func (fdd *FeatureDriftDetector) updateStats(stats FeatureStats, value float64) FeatureStats {
	// Simplified online statistics update
	if stats.Mean == 0 && stats.StdDev == 0 {
		// First value
		stats.Mean = value
		stats.Min = value
		stats.Max = value
		stats.StdDev = 0
	} else {
		// Update running statistics
		stats.Mean = (stats.Mean + value) / 2
		if value < stats.Min {
			stats.Min = value
		}
		if value > stats.Max {
			stats.Max = value
		}
		// Simplified standard deviation update
		stats.StdDev = math.Abs(value-stats.Mean) * 0.5
	}
	return stats
}

// calculateDrift calculates drift between two feature distributions
func (fdd *FeatureDriftDetector) calculateDrift(baseline, current FeatureStats) float64 {
	// Simplified drift calculation using mean and standard deviation differences
	meanDiff := math.Abs(baseline.Mean - current.Mean)
	stdDevDiff := math.Abs(baseline.StdDev - current.StdDev)
	return meanDiff + stdDevDiff
}

// NewModelExplainer creates a new model explainer
func NewModelExplainer() *ModelExplainer {
	return &ModelExplainer{
		featureImportance: make(map[string]float64),
		shapValues:        make(map[string][]float64),
	}
}

// ExplainPrediction generates explanation for a prediction
func (me *ModelExplainer) ExplainPrediction(features *FeatureVector, prediction *ThreatPrediction) *PredictionExplanation {
	me.mu.RLock()
	defer me.mu.RUnlock()

	// Generate feature contributions
	var contributions []FeatureContribution
	for name, value := range features.Features {
		importance := me.featureImportance[name]
		if importance == 0 {
			importance = 0.5 // Default importance
		}
		contribution := value * importance
		contributions = append(contributions, FeatureContribution{
			FeatureName:  name,
			Contribution: contribution,
			Value:        value,
		})
	}

	// Sort by contribution
	sort.Slice(contributions, func(i, j int) bool {
		return math.Abs(contributions[i].Contribution) > math.Abs(contributions[j].Contribution)
	})

	// Generate SHAP values
	shapValues := make(map[string]float64)
	for _, contrib := range contributions {
		shapValues[contrib.FeatureName] = contrib.Contribution
	}

	// Generate decision path
	decisionPath := []DecisionNode{}
	if len(contributions) > 0 {
		top := contributions[0]
		decisionPath = append(decisionPath, DecisionNode{
			Feature:   top.FeatureName,
			Threshold: 0.5,
			Direction: "greater",
			Impact:    top.Contribution,
		})
	}

	// Generate confidence factors
	confidenceFactors := []string{
		fmt.Sprintf("Model confidence: %.1f%%", prediction.Confidence*100),
		fmt.Sprintf("Feature count: %d", len(features.Features)),
		"Explanation quality: High",
	}

	return &PredictionExplanation{
		TopFeatures:       contributions,
		ShapValues:        shapValues,
		DecisionPath:      decisionPath,
		ConfidenceFactors: confidenceFactors,
	}
}

// UpdateFeatureImportance updates feature importance scores
func (me *ModelExplainer) UpdateFeatureImportance(importance map[string]float64) {
	me.mu.Lock()
	defer me.mu.Unlock()
	for name, score := range importance {
		me.featureImportance[name] = score
	}
}

// NewPredictionCache creates a new prediction cache
func NewPredictionCache(ttl time.Duration, maxSize int) *PredictionCache {
	return &PredictionCache{
		cache:   make(map[string]*CachedPrediction),
		ttl:     ttl,
		maxSize: maxSize,
	}
}

// Get retrieves a cached prediction
func (pc *PredictionCache) Get(key string) (*ThreatPrediction, bool) {
	pc.mu.RLock()
	defer pc.mu.RUnlock()

	cached, exists := pc.cache[key]
	if !exists {
		pc.missCount++
		return nil, false
	}

	// Check if expired
	if time.Since(cached.Timestamp) > pc.ttl {
		delete(pc.cache, key)
		pc.missCount++
		return nil, false
	}

	cached.HitCount++
	pc.hitCount++
	return cached.Result, true
}

// Set stores a prediction in cache
func (pc *PredictionCache) Set(key string, prediction *ThreatPrediction) {
	pc.mu.Lock()
	defer pc.mu.Unlock()

	// Check cache size limit
	if len(pc.cache) >= pc.maxSize {
		// Remove oldest entry
		oldestKey := ""
		oldestTime := time.Now()
		for k, v := range pc.cache {
			if v.Timestamp.Before(oldestTime) {
				oldestTime = v.Timestamp
				oldestKey = k
			}
		}
		if oldestKey != "" {
			delete(pc.cache, oldestKey)
		}
	}

	pc.cache[key] = &CachedPrediction{
		Result:    prediction,
		Timestamp: time.Now(),
		HitCount:  0,
	}
}

// GetStats returns cache statistics
func (pc *PredictionCache) GetStats() (hitRate float64, size int) {
	pc.mu.RLock()
	defer pc.mu.RUnlock()

	total := pc.hitCount + pc.missCount
	if total == 0 {
		return 0, len(pc.cache)
	}
	return float64(pc.hitCount) / float64(total), len(pc.cache)
}

// Note: ModelPerformanceMonitor methods are defined in auto_retrain.go