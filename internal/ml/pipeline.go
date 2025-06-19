package ml

import (
	"context"
	"fmt"
	"math"
	"sort"
	"sync"
	"time"

	"typosentinel/internal/config"
	"typosentinel/internal/logger"
	"typosentinel/internal/types"
)

// MLPipeline represents the machine learning pipeline for threat detection
type MLPipeline struct {
	config      *config.Config
	models      map[string]MLModel
	features    FeatureExtractor
	scorer      *AdvancedScorer
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

// Prediction represents a model prediction result
type Prediction struct {
	Score      float64                `json:"score"`
	Confidence float64                `json:"confidence"`
	RiskLevel  types.RiskLevel        `json:"risk_level"`
	Threats    []types.Threat         `json:"threats"`
	Metadata   map[string]interface{} `json:"metadata"`
	ModelUsed  string                 `json:"model_used"`
	Timestamp  time.Time              `json:"timestamp"`
}

// TrainingData represents training data for ML models
type TrainingData struct {
	Features []float64              `json:"features"`
	Label    float64                `json:"label"`
	Metadata map[string]interface{} `json:"metadata"`
}

// ModelInfo contains information about a ML model
type ModelInfo struct {
	Name         string    `json:"name"`
	Version      string    `json:"version"`
	Type         string    `json:"type"`
	Accuracy     float64   `json:"accuracy"`
	TrainedAt    time.Time `json:"trained_at"`
	FeatureCount int       `json:"feature_count"`
	Description  string    `json:"description"`
}

// PackageFeatures represents extracted features from a package
type PackageFeatures struct {
	// Basic package features
	NameLength        float64 `json:"name_length"`
	VersionComplexity float64 `json:"version_complexity"`
	DescriptionLength float64 `json:"description_length"`
	DependencyCount   float64 `json:"dependency_count"`

	// Reputation features
	DownloadCount    float64 `json:"download_count"`
	StarCount        float64 `json:"star_count"`
	ForkCount        float64 `json:"fork_count"`
	ContributorCount float64 `json:"contributor_count"`
	AgeInDays        float64 `json:"age_in_days"`

	// Security features
	TyposquattingScore float64 `json:"typosquatting_score"`
	SuspiciousKeywords float64 `json:"suspicious_keywords"`
	VersionSpoofing    float64 `json:"version_spoofing"`
	DomainReputation   float64 `json:"domain_reputation"`

	// Behavioral features
	UpdateFrequency float64 `json:"update_frequency"`
	MaintainerCount float64 `json:"maintainer_count"`
	IssueCount      float64 `json:"issue_count"`
	LicenseScore    float64 `json:"license_score"`

	// Metadata
	Registry    string `json:"registry"`
	PackageType string `json:"package_type"`
}

// NewMLPipeline creates a new ML pipeline instance
func NewMLPipeline(config *config.Config) *MLPipeline {
	return &MLPipeline{
		config:   config,
		models:   make(map[string]MLModel),
		features: NewAdvancedFeatureExtractor(),
		scorer:   NewAdvancedScorer(config),
	}
}

// Initialize initializes the ML pipeline with models and configurations
func (p *MLPipeline) Initialize(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	logger.InfoWithContext("Initializing ML Pipeline", map[string]interface{}{
		"models_enabled": p.config.ML.ModelsEnabled,
	})

	// Initialize feature extractor
	if err := p.initializeFeatureExtractor(); err != nil {
		return fmt.Errorf("failed to initialize feature extractor: %w", err)
	}

	// Initialize models based on configuration
	if err := p.initializeModels(ctx); err != nil {
		return fmt.Errorf("failed to initialize models: %w", err)
	}

	// Initialize advanced scorer
	if err := p.scorer.Initialize(); err != nil {
		return fmt.Errorf("failed to initialize scorer: %w", err)
	}

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

	logger.InfoWithContext("Starting batch package analysis", map[string]interface{}{
		"package_count": len(packages),
	})

	predictions := make([]*Prediction, len(packages))
	errorChan := make(chan error, len(packages))
	resultChan := make(chan struct {
		index      int
		prediction *Prediction
	}, len(packages))

	// Process packages concurrently
	semaphore := make(chan struct{}, p.config.ML.MaxConcurrency)
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

	logger.InfoWithContext("Batch package analysis completed", map[string]interface{}{
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

	logger.InfoWithContext("Updating ML model", map[string]interface{}{
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
	if p.config.ML.TyposquattingModel.Enabled {
		model := NewTyposquattingModel(p.config.ML.TyposquattingModel)
		if err := model.Initialize(ctx); err != nil {
			return fmt.Errorf("failed to initialize typosquatting model: %w", err)
		}
		p.models["typosquatting"] = model
	}

	// Initialize reputation scoring model
	if p.config.ML.ReputationModel.Enabled {
		model := NewReputationModel(p.config.ML.ReputationModel)
		if err := model.Initialize(ctx); err != nil {
			return fmt.Errorf("failed to initialize reputation model: %w", err)
		}
		p.models["reputation"] = model
	}

	// Initialize anomaly detection model
	if p.config.ML.AnomalyModel.Enabled {
		model := NewAnomalyModel(p.config.ML.AnomalyModel)
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

			prediction.ModelUsed = modelName
			prediction.Timestamp = time.Now()
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
			Score:      0.5,
			Confidence: 0.0,
			RiskLevel:  types.RiskLevelMedium,
			Threats:    []types.Threat{},
			Metadata:   make(map[string]interface{}),
			ModelUsed:  "ensemble",
			Timestamp:  time.Now(),
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
	var allThreats []types.Threat
	var maxConfidence float64
	combinedMetadata := make(map[string]interface{})

	for modelName, prediction := range predictions {
		weight := weights[modelName]
		if weight == 0 {
			weight = 1.0 / float64(len(predictions)) // Equal weight for unknown models
		}

		weightedScore += prediction.Score * weight
		totalWeight += weight
		allThreats = append(allThreats, prediction.Threats...)
		if prediction.Confidence > maxConfidence {
			maxConfidence = prediction.Confidence
		}

		// Combine metadata
		combinedMetadata[modelName+"_score"] = prediction.Score
		combinedMetadata[modelName+"_confidence"] = prediction.Confidence
	}

	finalScore := weightedScore / totalWeight
	riskLevel := p.determineRiskLevel(finalScore, maxConfidence)

	return &Prediction{
		Score:      finalScore,
		Confidence: maxConfidence,
		RiskLevel:  riskLevel,
		Threats:    p.deduplicateThreats(allThreats),
		Metadata:   combinedMetadata,
		ModelUsed:  "ensemble",
		Timestamp:  time.Now(),
	}
}

// enhanceWithAdvancedScoring enhances prediction with advanced scoring techniques
func (p *MLPipeline) enhanceWithAdvancedScoring(prediction *Prediction, pkg *types.Package, features *PackageFeatures) error {
	// Get advanced scores
	advancedResult, err := p.scorer.CalculateAdvancedScore(pkg)
	if err != nil {
		return err
	}

	// Combine ML prediction with advanced scoring
	combinedScore := (prediction.Score + advancedResult.Score) / 2.0
	combinedConfidence := math.Max(prediction.Confidence, advancedResult.Confidence)

	// Update prediction
	prediction.Score = combinedScore
	prediction.Confidence = combinedConfidence
	prediction.RiskLevel = p.determineRiskLevel(combinedScore, combinedConfidence)

	// Add advanced scoring metadata
	prediction.Metadata["advanced_score"] = advancedResult.Score
	prediction.Metadata["reputation_score"] = advancedResult.ReputationScore
	prediction.Metadata["typosquatting_score"] = advancedResult.TyposquattingScore

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

// deduplicateThreats removes duplicate threats from the list
func (p *MLPipeline) deduplicateThreats(threats []types.Threat) []types.Threat {
	seen := make(map[string]bool)
	var unique []types.Threat

	for _, threat := range threats {
		key := fmt.Sprintf("%s:%s", threat.Type, threat.Description)
		if !seen[key] {
			seen[key] = true
			unique = append(unique, threat)
		}
	}

	// Sort threats by severity
	sort.Slice(unique, func(i, j int) bool {
		return unique[i].Severity > unique[j].Severity
	})

	return unique
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
		"initialized":  p.initialized,
		"model_count":  len(p.models),
		"ready_models": 0,
	}

	for _, model := range p.models {
		if model.IsReady() {
			stats["ready_models"] = stats["ready_models"].(int) + 1
		}
	}

	return stats
}
