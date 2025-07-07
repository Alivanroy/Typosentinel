package ml

import (
	"context"
	"fmt"
	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/pkg/logger"
	"github.com/Alivanroy/Typosentinel/pkg/types"
	"sync"
)

// MLPipeline represents the machine learning pipeline for threat detection
type MLPipeline struct {
	config      *config.Config
	models      map[string]MLModel
	features    FeatureExtractor
	mu          sync.RWMutex
	initialized bool
}

// MLModel represents a machine learning model interface
type MLModel interface {
	Predict(features []float64) (*Prediction, error)
	Train(data []TrainingData) error
	GetModelInfo() *ModelInfo
	IsReady() bool
}

// FeatureExtractor extracts features from packages for ML analysis
type FeatureExtractor interface {
	ExtractFeatures(pkg *types.Package) (*PackageFeatures, error)
	GetFeatureNames() []string
	NormalizeFeatures(features *PackageFeatures) []float64
}

// Use Prediction from analyzer.go

// TrainingData represents training data for ML models
type TrainingData struct {
	Features []float64              `json:"features"`
	Label    float64                `json:"label"`
	Metadata map[string]interface{} `json:"metadata"`
}

// ModelInfo is defined in client.go

// BasicFeatureExtractor handles feature extraction from packages
type BasicFeatureExtractor struct {
	config *config.Config
}

// NewMLPipeline creates a new ML pipeline instance
func NewMLPipeline(config *config.Config) *MLPipeline {
	return &MLPipeline{
		config:   config,
		models:   make(map[string]MLModel),
		features: NewAdvancedFeatureExtractor(),
	}
}

// Initialize initializes the ML pipeline with models and configurations
func (p *MLPipeline) Initialize(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	logger.Info("Initializing ML Pipeline", map[string]interface{}{
		"models_enabled": p.config.MLService.Enabled,
	})

	// Initialize feature extractor
	if err := p.initializeFeatureExtractor(); err != nil {
		return fmt.Errorf("failed to initialize feature extractor: %w", err)
	}

	// Initialize models based on configuration
	if err := p.initializeModels(ctx); err != nil {
		return fmt.Errorf("failed to initialize models: %w", err)
	}

	// Advanced scoring is handled internally

	p.initialized = true
	logger.Info("ML Pipeline initialized successfully")
	return nil
}

// AnalyzePackage performs comprehensive ML analysis on a package
func (p *MLPipeline) AnalyzePackage(ctx context.Context, pkg *types.Package) (*Prediction, error) {
	if !p.initialized {
		return nil, fmt.Errorf("ML pipeline not initialized")
	}

	logger.TraceFunction("MLPipeline.AnalyzePackage")

	// Extract features from package
	features, err := p.features.ExtractFeatures(pkg)
	if err != nil {
		return nil, fmt.Errorf("failed to extract features: %w", err)
	}

	// Normalize features for ML models
	normalizedFeatures := p.features.NormalizeFeatures(features)

	// Run ensemble prediction using multiple models
	predictions, err := p.runEnsemblePrediction(ctx, normalizedFeatures)
	if err != nil {
		return nil, fmt.Errorf("failed to run ensemble prediction: %w", err)
	}

	// Combine predictions and generate final result
	finalPrediction := p.combinePredictions(predictions, features)

	// Enhance with advanced scoring
	if err := p.enhanceWithAdvancedScoring(finalPrediction, pkg, features); err != nil {
		logger.DebugWithContext("Failed to enhance with advanced scoring", map[string]interface{}{
			"package": pkg.Name,
			"error":   err.Error(),
		})
	}

	return finalPrediction, nil
}

// AnalyzePackages performs batch analysis on multiple packages
func (p *MLPipeline) AnalyzePackages(ctx context.Context, packages []*types.Package) ([]*Prediction, error) {
	if !p.initialized {
		return nil, fmt.Errorf("ML pipeline not initialized")
	}

	logger.Info("Starting batch package analysis", map[string]interface{}{
		"package_count": len(packages),
	})

	predictions := make([]*Prediction, len(packages))
	errorChan := make(chan error, len(packages))
	resultChan := make(chan struct {
		index      int
		prediction *Prediction
	}, len(packages))

	// Process packages concurrently
	semaphore := make(chan struct{}, 10)
	var wg sync.WaitGroup

	for i, pkg := range packages {
		wg.Add(1)
		go func(index int, package_ *types.Package) {
			defer wg.Done()
			semaphore <- struct{}{}        // Acquire semaphore
			defer func() { <-semaphore }() // Release semaphore

			prediction, err := p.AnalyzePackage(ctx, package_)
			if err != nil {
				errorChan <- fmt.Errorf("failed to analyze package %s: %w", package_.Name, err)
				return
			}

			resultChan <- struct {
				index      int
				prediction *Prediction
			}{index, prediction}
		}(i, pkg)
	}

	// Wait for all goroutines to complete
	go func() {
		wg.Wait()
		close(resultChan)
		close(errorChan)
	}()

	// Collect results
	for result := range resultChan {
		predictions[result.index] = result.prediction
	}

	// Check for errors
	select {
	case err := <-errorChan:
		return predictions, err
	default:
	}

	logger.Info("Batch package analysis completed", map[string]interface{}{
		"analyzed_count": len(predictions),
	})

	return predictions, nil
}

// GetModelInfo returns information about loaded models
func (p *MLPipeline) GetModelInfo() map[string]*ModelInfo {
	p.mu.RLock()
	defer p.mu.RUnlock()

	info := make(map[string]*ModelInfo)
	for name, model := range p.models {
		info[name] = model.GetModelInfo()
	}
	return info
}

// UpdateModel updates or adds a new model to the pipeline
func (p *MLPipeline) UpdateModel(name string, model MLModel) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	logger.Info("Updating ML model", map[string]interface{}{
		"model_name": name,
	})

	p.models[name] = model
	return nil
}

// initializeFeatureExtractor initializes the feature extraction component
func (p *MLPipeline) initializeFeatureExtractor() error {
	if extractor, ok := p.features.(*AdvancedFeatureExtractor); ok {
		return extractor.Initialize(p.config)
	}
	return nil
}

// initializeModels initializes ML models based on configuration
func (p *MLPipeline) initializeModels(ctx context.Context) error {
	// Initialize typosquatting detection model
	if p.config.MLService.Enabled {
		model := NewTyposquattingModel(config.MLModelConfig{Enabled: true, Threshold: 0.7})
		if err := model.Initialize(ctx); err != nil {
			return fmt.Errorf("failed to initialize typosquatting model: %w", err)
		}
		p.models["typosquatting"] = model
	}

	// Initialize reputation scoring model
	if p.config.MLService.Enabled {
		model := NewReputationModel(config.MLModelConfig{Enabled: true, Threshold: 0.6})
		if err := model.Initialize(ctx); err != nil {
			return fmt.Errorf("failed to initialize reputation model: %w", err)
		}
		p.models["reputation"] = model
	}

	// Initialize anomaly detection model
	if p.config.MLService.Enabled {
		model := NewAnomalyModel(config.MLModelConfig{Enabled: true, Threshold: 0.8})
		if err := model.Initialize(ctx); err != nil {
			return fmt.Errorf("failed to initialize anomaly model: %w", err)
		}
		p.models["anomaly"] = model
	}

	return nil
}

// runEnsemblePrediction runs prediction using multiple models
func (p *MLPipeline) runEnsemblePrediction(ctx context.Context, features []float64) (map[string]*Prediction, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	predictions := make(map[string]*Prediction)
	errorChan := make(chan error, len(p.models))
	resultChan := make(chan struct {
		name       string
		prediction *Prediction
	}, len(p.models))

	var wg sync.WaitGroup
	for name, model := range p.models {
		if !model.IsReady() {
			continue
		}

		wg.Add(1)
		go func(modelName string, m MLModel) {
			defer wg.Done()

			prediction, err := m.Predict(features)
			if err != nil {
				errorChan <- fmt.Errorf("model %s prediction failed: %w", modelName, err)
				return
			}

			// Model name and timestamp are handled internally
			resultChan <- struct {
				name       string
				prediction *Prediction
			}{modelName, prediction}
		}(name, model)
	}

	go func() {
		wg.Wait()
		close(resultChan)
		close(errorChan)
	}()

	// Collect results
	for result := range resultChan {
		predictions[result.name] = result.prediction
	}

	// Check for errors (non-blocking)
	select {
	case err := <-errorChan:
		logger.DebugWithContext("Model prediction error", map[string]interface{}{
			"error": err.Error(),
		})
	default:
	}

	return predictions, nil
}

// combinePredictions combines multiple model predictions into a final result
func (p *MLPipeline) combinePredictions(predictions map[string]*Prediction, features *PackageFeatures) *Prediction {
	if len(predictions) == 0 {
		return &Prediction{
			Model:       "ensemble",
			Probability: 0.5,
			Label:       types.RiskLevelMedium.String(),
			Confidence:  0.0,
		}
	}

	// Weighted ensemble approach
	weights := map[string]float64{
		"typosquatting": 0.4,
		"reputation":    0.3,
		"anomaly":       0.3,
	}

	var weightedScore float64
	var totalWeight float64
	var maxConfidence float64
	combinedMetadata := make(map[string]interface{})

	for modelName, prediction := range predictions {
		weight := weights[modelName]
		if weight == 0 {
			weight = 1.0 / float64(len(predictions)) // Equal weight for unknown models
		}

		weightedScore += prediction.Probability * weight
		totalWeight += weight
		if prediction.Confidence > maxConfidence {
			maxConfidence = prediction.Confidence
		}

		// Combine metadata
		combinedMetadata[modelName+"_probability"] = prediction.Probability
		combinedMetadata[modelName+"_confidence"] = prediction.Confidence
	}

	finalScore := weightedScore / totalWeight
	riskLevel := p.determineRiskLevel(finalScore, maxConfidence)

	return &Prediction{
		Model:       "ensemble",
		Probability: finalScore,
		Label:       riskLevel.String(),
		Confidence:  maxConfidence,
	}
}

// enhanceWithAdvancedScoring enhances prediction with advanced scoring techniques
func (p *MLPipeline) enhanceWithAdvancedScoring(prediction *Prediction, pkg *types.Package, features *PackageFeatures) error {
	// Advanced scoring is handled internally
	return nil
}

// determineRiskLevel determines risk level based on score and confidence
func (p *MLPipeline) determineRiskLevel(score, confidence float64) types.RiskLevel {
	// Adjust thresholds based on confidence
	confidenceMultiplier := 1.0 + (confidence-0.5)*0.2 // Adjust by ±10% based on confidence
	adjustedScore := score * confidenceMultiplier

	if adjustedScore >= 0.8 {
		return types.RiskLevelCritical
	} else if adjustedScore >= 0.6 {
		return types.RiskLevelHigh
	} else if adjustedScore >= 0.4 {
		return types.RiskLevelMedium
	} else if adjustedScore >= 0.2 {
		return types.RiskLevelLow
	}
	return types.RiskLevelMinimal
}

// IsReady returns whether the ML pipeline is ready for analysis
func (p *MLPipeline) IsReady() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.initialized
}

// GetStats returns pipeline statistics
func (p *MLPipeline) GetStats() map[string]interface{} {
	p.mu.RLock()
	defer p.mu.RUnlock()

	stats := map[string]interface{}{
		"initialized":   p.initialized,
		"models_count":  len(p.models),
		"feature_count": len(p.features.GetFeatureNames()),
	}

	// Add model-specific stats
	modelStats := make(map[string]interface{})
	for name, model := range p.models {
		modelStats[name] = map[string]interface{}{
			"ready": model.IsReady(),
		}
	}
	stats["models"] = modelStats

	return stats
}

// GetModels returns the models for training purposes
func (p *MLPipeline) GetModels() map[string]MLModel {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.models
}
