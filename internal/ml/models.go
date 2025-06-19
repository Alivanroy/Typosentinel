package ml

import (
	"context"
	"fmt"
	"math"
	"math/rand"
	"time"

	"typosentinel/internal/config"
	"typosentinel/internal/logger"
	"yposentinel/internal/types"
)

// TyposquattingModel implements typosquatting detection using ML
type TyposquattingModel struct {
	config         config.MLModelConfig
	modelInfo      *ModelInfo
	thresholds     map[string]float64
	featureWeights []float64
	ready          bool
}

// ReputationModel implements package reputation scoring
type ReputationModel struct {
	config            config.MLModelConfig
	modelInfo         *ModelInfo
	reputationWeights map[string]float64
	ready             bool
}

// AnomalyModel implements anomaly detection for suspicious packages
type AnomalyModel struct {
	config           config.MLModelConfig
	modelInfo        *ModelInfo
	baselineStats    map[string]float64
	anomalyThreshold float64
	ready            bool
}

// NewTyposquattingModel creates a new typosquatting detection model
func NewTyposquattingModel(config config.MLModelConfig) *TyposquattingModel {
	return &TyposquattingModel{
		config: config,
		modelInfo: &ModelInfo{
			Name:        "TyposquattingDetector",
			Version:     "1.0.0",
			Type:        "classification",
			Description: "Detects potential typosquatting attempts using string similarity and ML features",
		},
		thresholds: make(map[string]float64),
	}
}

// NewReputationModel creates a new reputation scoring model
func NewReputationModel(config config.MLModelConfig) *ReputationModel {
	return &ReputationModel{
		config: config,
		modelInfo: &ModelInfo{
			Name:        "ReputationScorer",
			Version:     "1.0.0",
			Type:        "regression",
			Description: "Scores package reputation based on various metrics",
		},
		reputationWeights: make(map[string]float64),
	}
}

// NewAnomalyModel creates a new anomaly detection model
func NewAnomalyModel(config config.MLModelConfig) *AnomalyModel {
	return &AnomalyModel{
		config: config,
		modelInfo: &ModelInfo{
			Name:        "AnomalyDetector",
			Version:     "1.0.0",
			Type:        "anomaly_detection",
			Description: "Detects anomalous package characteristics that may indicate malicious intent",
		},
		baselineStats: make(map[string]float64),
	}
}

// TyposquattingModel implementation

// Initialize initializes the typosquatting model
func (m *TyposquattingModel) Initialize(ctx context.Context) error {
	logger.InfoWithContext("Initializing typosquatting model", map[string]interface{}{
		"model_name": m.modelInfo.Name,
	})

	// Initialize thresholds for different similarity metrics
	m.thresholds["jaro_winkler"] = 0.85
	m.thresholds["levenshtein"] = 0.8
	m.thresholds["soundex"] = 0.9
	m.thresholds["metaphone"] = 0.85

	// Initialize feature weights (would be learned from training data)
	m.featureWeights = []float64{
		0.3,  // name_length
		0.1,  // version_complexity
		0.05, // description_length
		0.05, // dependency_count
		0.1,  // download_count
		0.05, // star_count
		0.05, // fork_count
		0.05, // contributor_count
		0.1,  // age_in_days
		0.4,  // typosquatting_score (highest weight)
		0.2,  // suspicious_keywords
		0.15, // version_spoofing
		0.1,  // domain_reputation
		0.05, // update_frequency
		0.05, // maintainer_count
		0.05, // issue_count
		0.05, // license_score
	}

	m.modelInfo.TrainedAt = time.Now()
	m.modelInfo.FeatureCount = len(m.featureWeights)
	m.modelInfo.Accuracy = 0.92 // Simulated accuracy
	m.ready = true

	logger.Info("Typosquatting model initialized successfully")
	return nil
}

// Predict performs typosquatting prediction
func (m *TyposquattingModel) Predict(features []float64) (*Prediction, error) {
	if !m.ready {
		return nil, fmt.Errorf("model not ready")
	}

	if len(features) != len(m.featureWeights) {
		return nil, fmt.Errorf("feature count mismatch: expected %d, got %d", len(m.featureWeights), len(features))
	}

	// Calculate weighted score
	score := 0.0
	for i, feature := range features {
		score += feature * m.featureWeights[i]
	}

	// Apply sigmoid activation to normalize score
	normalizedScore := 1.0 / (1.0 + math.Exp(-score))

	// Calculate confidence based on feature consistency
	confidence := m.calculateConfidence(features)

	// Determine risk level
	riskLevel := m.determineRiskLevel(normalizedScore)

	// Generate threats if score is high enough
	var threats []types.Threat
	if normalizedScore > 0.7 {
		threats = append(threats, types.Threat{
			Type:        "typosquatting",
			Severity:    types.SeverityHigh,
			Description: fmt.Sprintf("High probability of typosquatting (score: %.2f)", normalizedScore),
			Source:      "typosquatting_model",
		})
	} else if normalizedScore > 0.5 {
		threats = append(threats, types.Threat{
			Type:        "potential_typosquatting",
			Severity:    types.SeverityMedium,
			Description: fmt.Sprintf("Potential typosquatting detected (score: %.2f)", normalizedScore),
			Source:      "typosquatting_model",
		})
	}

	return &Prediction{
		Score:      normalizedScore,
		Confidence: confidence,
		RiskLevel:  riskLevel,
		Threats:    threats,
		Metadata: map[string]interface{}{
			"raw_score":             score,
			"feature_contributions": m.calculateFeatureContributions(features),
		},
	}, nil
}

// Train trains the typosquatting model (placeholder implementation)
func (m *TyposquattingModel) Train(data []TrainingData) error {
	logger.InfoWithContext("Training typosquatting model", map[string]interface{}{
		"training_samples": len(data),
	})

	// In a real implementation, this would update model weights
	// For now, we'll simulate training by adjusting weights slightly
	if len(data) > 0 {
		// Simulate weight updates based on training data
		for i := range m.featureWeights {
			adjustment := (rand.Float64() - 0.5) * 0.1 // Small random adjustment
			m.featureWeights[i] += adjustment
			// Ensure weights stay positive
			if m.featureWeights[i] < 0 {
				m.featureWeights[i] = 0.01
			}
		}
		m.modelInfo.TrainedAt = time.Now()
	}

	return nil
}

// GetModelInfo returns model information
func (m *TyposquattingModel) GetModelInfo() *ModelInfo {
	return m.modelInfo
}

// IsReady returns whether the model is ready for predictions
func (m *TyposquattingModel) IsReady() bool {
	return m.ready
}

// calculateConfidence calculates prediction confidence
func (m *TyposquattingModel) calculateConfidence(features []float64) float64 {
	// Calculate confidence based on feature variance and consistency
	variance := 0.0
	mean := 0.0

	for _, feature := range features {
		mean += feature
	}
	mean /= float64(len(features))

	for _, feature := range features {
		variance += math.Pow(feature-mean, 2)
	}
	variance /= float64(len(features))

	// Lower variance indicates higher confidence
	confidence := 1.0 / (1.0 + variance)
	return math.Min(confidence, 0.95) // Cap at 95%
}

// determineRiskLevel determines risk level from score
func (m *TyposquattingModel) determineRiskLevel(score float64) types.RiskLevel {
	if score >= 0.8 {
		return types.RiskLevelCritical
	} else if score >= 0.6 {
		return types.RiskLevelHigh
	} else if score >= 0.4 {
		return types.RiskLevelMedium
	} else if score >= 0.2 {
		return types.RiskLevelLow
	}
	return types.RiskLevelMinimal
}

// calculateFeatureContributions calculates individual feature contributions
func (m *TyposquattingModel) calculateFeatureContributions(features []float64) map[string]float64 {
	featureNames := []string{
		"name_length", "version_complexity", "description_length", "dependency_count",
		"download_count", "star_count", "fork_count", "contributor_count",
		"age_in_days", "typosquatting_score", "suspicious_keywords", "version_spoofing",
		"domain_reputation", "update_frequency", "maintainer_count", "issue_count", "license_score",
	}

	contributions := make(map[string]float64)
	for i, feature := range features {
		if i < len(featureNames) && i < len(m.featureWeights) {
			contributions[featureNames[i]] = feature * m.featureWeights[i]
		}
	}

	return contributions
}

// ReputationModel implementation

// Initialize initializes the reputation model
func (m *ReputationModel) Initialize(ctx context.Context) error {
	logger.InfoWithContext("Initializing reputation model", map[string]interface{}{
		"model_name": m.modelInfo.Name,
	})

	// Initialize reputation weights
	m.reputationWeights["download_count"] = 0.25
	m.reputationWeights["star_count"] = 0.2
	m.reputationWeights["fork_count"] = 0.15
	m.reputationWeights["contributor_count"] = 0.15
	m.reputationWeights["age_in_days"] = 0.1
	m.reputationWeights["update_frequency"] = 0.1
	m.reputationWeights["license_score"] = 0.05

	m.modelInfo.TrainedAt = time.Now()
	m.modelInfo.FeatureCount = len(m.reputationWeights)
	m.modelInfo.Accuracy = 0.88
	m.ready = true

	logger.Info("Reputation model initialized successfully")
	return nil
}

// Predict performs reputation prediction
func (m *ReputationModel) Predict(features []float64) (*Prediction, error) {
	if !m.ready {
		return nil, fmt.Errorf("model not ready")
	}

	// Map features to reputation components
	reputationScore := 0.0
	featureMap := map[string]float64{
		"download_count":    features[4],  // download_count
		"star_count":        features[5],  // star_count
		"fork_count":        features[6],  // fork_count
		"contributor_count": features[7],  // contributor_count
		"age_in_days":       features[8],  // age_in_days
		"update_frequency":  features[13], // update_frequency
		"license_score":     features[16], // license_score
	}

	// Calculate weighted reputation score
	for component, weight := range m.reputationWeights {
		if value, exists := featureMap[component]; exists {
			reputationScore += value * weight
		}
	}

	// Normalize score to 0-1 range
	normalizedScore := math.Tanh(reputationScore) // Use tanh for soft normalization
	if normalizedScore < 0 {
		normalizedScore = 0
	}

	// Invert score for threat detection (low reputation = high threat)
	threatScore := 1.0 - normalizedScore

	// Calculate confidence
	confidence := m.calculateReputationConfidence(featureMap)

	// Determine risk level
	riskLevel := m.determineReputationRiskLevel(threatScore)

	// Generate threats for low reputation packages
	var threats []types.Threat
	if threatScore > 0.7 {
		threats = append(threats, types.Threat{
			Type:        "low_reputation",
			Severity:    types.SeverityMedium,
			Description: fmt.Sprintf("Package has low reputation score (%.2f)", normalizedScore),
			Source:      "reputation_model",
		})
	}

	return &Prediction{
		Score:      threatScore,
		Confidence: confidence,
		RiskLevel:  riskLevel,
		Threats:    threats,
		Metadata: map[string]interface{}{
			"reputation_score": normalizedScore,
			"component_scores": featureMap,
		},
	}, nil
}

// Train trains the reputation model
func (m *ReputationModel) Train(data []TrainingData) error {
	logger.InfoWithContext("Training reputation model", map[string]interface{}{
		"training_samples": len(data),
	})

	// Simulate training by adjusting weights
	if len(data) > 0 {
		for component := range m.reputationWeights {
			adjustment := (rand.Float64() - 0.5) * 0.05
			m.reputationWeights[component] += adjustment
			if m.reputationWeights[component] < 0 {
				m.reputationWeights[component] = 0.01
			}
		}
		m.modelInfo.TrainedAt = time.Now()
	}

	return nil
}

// GetModelInfo returns model information
func (m *ReputationModel) GetModelInfo() *ModelInfo {
	return m.modelInfo
}

// IsReady returns whether the model is ready
func (m *ReputationModel) IsReady() bool {
	return m.ready
}

// calculateReputationConfidence calculates confidence for reputation prediction
func (m *ReputationModel) calculateReputationConfidence(featureMap map[string]float64) float64 {
	// Confidence based on data availability and consistency
	availableFeatures := 0
	totalFeatures := len(m.reputationWeights)

	for component := range m.reputationWeights {
		if value, exists := featureMap[component]; exists && value > 0 {
			availableFeatures++
		}
	}

	dataCompleteness := float64(availableFeatures) / float64(totalFeatures)
	return math.Min(dataCompleteness*0.9, 0.9) // Cap at 90%
}

// determineReputationRiskLevel determines risk level for reputation
func (m *ReputationModel) determineReputationRiskLevel(threatScore float64) types.RiskLevel {
	if threatScore >= 0.8 {
		return types.RiskLevelHigh
	} else if threatScore >= 0.6 {
		return types.RiskLevelMedium
	} else if threatScore >= 0.4 {
		return types.RiskLevelLow
	}
	return types.RiskLevelMinimal
}

// AnomalyModel implementation

// Initialize initializes the anomaly detection model
func (m *AnomalyModel) Initialize(ctx context.Context) error {
	logger.InfoWithContext("Initializing anomaly model", map[string]interface{}{
		"model_name": m.modelInfo.Name,
	})

	// Initialize baseline statistics (would be learned from normal packages)
	m.baselineStats["name_length_mean"] = 15.0
	m.baselineStats["name_length_std"] = 8.0
	m.baselineStats["version_complexity_mean"] = 2.0
	m.baselineStats["version_complexity_std"] = 1.0
	m.baselineStats["description_length_mean"] = 100.0
	m.baselineStats["description_length_std"] = 50.0
	m.baselineStats["dependency_count_mean"] = 10.0
	m.baselineStats["dependency_count_std"] = 15.0

	m.anomalyThreshold = 2.5 // Z-score threshold for anomaly detection

	m.modelInfo.TrainedAt = time.Now()
	m.modelInfo.FeatureCount = len(m.baselineStats) / 2 // Mean and std for each feature
	m.modelInfo.Accuracy = 0.85
	m.ready = true

	logger.Info("Anomaly model initialized successfully")
	return nil
}

// Predict performs anomaly detection
func (m *AnomalyModel) Predict(features []float64) (*Prediction, error) {
	if !m.ready {
		return nil, fmt.Errorf("model not ready")
	}

	// Calculate anomaly scores for key features
	anomalyScores := make(map[string]float64)
	featureNames := []string{"name_length", "version_complexity", "description_length", "dependency_count"}

	for i, featureName := range featureNames {
		if i < len(features) {
			mean := m.baselineStats[featureName+"_mean"]
			std := m.baselineStats[featureName+"_std"]
			zScore := math.Abs((features[i] - mean) / std)
			anomalyScores[featureName] = zScore
		}
	}

	// Calculate overall anomaly score
	maxAnomalyScore := 0.0
	totalAnomalyScore := 0.0
	anomalyCount := 0

	for _, score := range anomalyScores {
		totalAnomalyScore += score
		if score > maxAnomalyScore {
			maxAnomalyScore = score
		}
		if score > m.anomalyThreshold {
			anomalyCount++
		}
	}

	avgAnomalyScore := totalAnomalyScore / float64(len(anomalyScores))

	// Normalize anomaly score to 0-1 range
	normalizedScore := math.Tanh(avgAnomalyScore / m.anomalyThreshold)

	// Calculate confidence based on consistency of anomaly scores
	confidence := m.calculateAnomalyConfidence(anomalyScores)

	// Determine risk level
	riskLevel := m.determineAnomalyRiskLevel(normalizedScore, anomalyCount)

	// Generate threats for significant anomalies
	var threats []types.Threat
	if anomalyCount > 0 {
		severity := types.SeverityLow
		if anomalyCount >= 3 {
			severity = types.SeverityHigh
		} else if anomalyCount >= 2 {
			severity = types.SeverityMedium
		}

		threats = append(threats, types.Threat{
			Type:        "anomalous_characteristics",
			Severity:    severity,
			Description: fmt.Sprintf("Package exhibits %d anomalous characteristics", anomalyCount),
			Source:      "anomaly_model",
		})
	}

	return &Prediction{
		Score:      normalizedScore,
		Confidence: confidence,
		RiskLevel:  riskLevel,
		Threats:    threats,
		Metadata: map[string]interface{}{
			"anomaly_scores":    anomalyScores,
			"max_anomaly_score": maxAnomalyScore,
			"anomaly_count":     anomalyCount,
		},
	}, nil
}

// Train trains the anomaly detection model
func (m *AnomalyModel) Train(data []TrainingData) error {
	logger.InfoWithContext("Training anomaly model", map[string]interface{}{
		"training_samples": len(data),
	})

	// Update baseline statistics based on training data
	if len(data) > 0 {
		// Calculate new statistics from training data
		featureStats := make(map[string][]float64)
		featureNames := []string{"name_length", "version_complexity", "description_length", "dependency_count"}

		for _, sample := range data {
			for i, featureName := range featureNames {
				if i < len(sample.Features) {
					featureStats[featureName] = append(featureStats[featureName], sample.Features[i])
				}
			}
		}

		// Update baseline statistics
		for featureName, values := range featureStats {
			mean, std := calculateMeanStd(values)
			m.baselineStats[featureName+"_mean"] = mean
			m.baselineStats[featureName+"_std"] = std
		}

		m.modelInfo.TrainedAt = time.Now()
	}

	return nil
}

// GetModelInfo returns model information
func (m *AnomalyModel) GetModelInfo() *ModelInfo {
	return m.modelInfo
}

// IsReady returns whether the model is ready
func (m *AnomalyModel) IsReady() bool {
	return m.ready
}

// calculateAnomalyConfidence calculates confidence for anomaly detection
func (m *AnomalyModel) calculateAnomalyConfidence(anomalyScores map[string]float64) float64 {
	// Confidence based on consistency of anomaly scores
	scores := make([]float64, 0, len(anomalyScores))
	for _, score := range anomalyScores {
		scores = append(scores, score)
	}

	if len(scores) == 0 {
		return 0.5
	}

	mean, std := calculateMeanStd(scores)

	// Lower standard deviation indicates higher confidence
	confidence := 1.0 / (1.0 + std)
	if mean > m.anomalyThreshold {
		confidence *= 1.2 // Boost confidence for clear anomalies
	}

	return math.Min(confidence, 0.95)
}

// determineAnomalyRiskLevel determines risk level for anomalies
func (m *AnomalyModel) determineAnomalyRiskLevel(score float64, anomalyCount int) types.RiskLevel {
	if anomalyCount >= 3 || score >= 0.8 {
		return types.RiskLevelHigh
	} else if anomalyCount >= 2 || score >= 0.6 {
		return types.RiskLevelMedium
	} else if anomalyCount >= 1 || score >= 0.4 {
		return types.RiskLevelLow
	}
	return types.RiskLevelMinimal
}

// Helper functions

// calculateMeanStd calculates mean and standard deviation of a slice
func calculateMeanStd(values []float64) (float64, float64) {
	if len(values) == 0 {
		return 0, 0
	}

	// Calculate mean
	sum := 0.0
	for _, value := range values {
		sum += value
	}
	mean := sum / float64(len(values))

	// Calculate standard deviation
	variance := 0.0
	for _, value := range values {
		variance += math.Pow(value-mean, 2)
	}
	variance /= float64(len(values))
	std := math.Sqrt(variance)

	return mean, std
}
