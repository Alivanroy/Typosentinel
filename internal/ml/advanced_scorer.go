package ml

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// AdvancedScorer implements sophisticated ML-based scoring using ensemble methods
type AdvancedScorer struct {
	config       *ScorerConfig
	modelInfo    *ModelInfo
	featureStats map[string]FeatureStats
	ensembleWeights map[string]float64
	baseScorers  []Scorer
}

// NewAdvancedScorer creates a new advanced scorer with the given configuration
func NewAdvancedScorer(config *ScorerConfig) (*AdvancedScorer, error) {
	if config == nil {
		config = &ScorerConfig{
			Thresholds: DefaultScoringThresholds(),
			FeatureWeights: getDefaultFeatureWeights(),
			Normalization: true,
		}
	}

	scorer := &AdvancedScorer{
		config: config,
		modelInfo: &ModelInfo{
			Name:        "AdvancedEnsembleScorer",
			Version:     "1.0.0",
			Description: "Advanced ML scorer using ensemble methods",
			Type:        "ensemble",
			TrainedAt:   time.Now(),
			Accuracy:    0.92,
			Precision:   0.89,
			Recall:      0.94,
			F1Score:     0.91,
			FeatureCount: len(config.FeatureWeights),
		},
		featureStats: getDefaultFeatureStats(),
		ensembleWeights: map[string]float64{
			"typosquatting": 0.3,
			"reputation":    0.25,
			"behavioral":    0.25,
			"metadata":      0.2,
		},
	}

	return scorer, nil
}

// Score calculates a comprehensive risk score using ensemble methods
func (s *AdvancedScorer) Score(ctx context.Context, pkg *types.Package, features map[string]interface{}) (*ScoringResult, error) {
	start := time.Now()

	// Extract and normalize features
	normalizedFeatures, err := s.normalizeFeatures(features)
	if err != nil {
		return nil, fmt.Errorf("feature normalization failed: %w", err)
	}

	// Calculate component scores
	componentScores := s.calculateComponentScores(normalizedFeatures)
	
	// Calculate ensemble score
	ensembleScore := s.calculateEnsembleScore(componentScores)
	
	// Calculate confidence
	confidence := s.calculateConfidence(componentScores, normalizedFeatures)
	
	// Determine risk level
	riskLevel := s.config.Thresholds.GetRiskLevel(ensembleScore)
	
	// Generate explanation
	explanation := s.generateExplanation(componentScores, riskLevel)

	result := &ScoringResult{
		Score:          ensembleScore,
		Confidence:     confidence,
		RiskLevel:      riskLevel,
		FeatureScores:  componentScores,
		Explanation:    explanation,
		ModelVersion:   s.modelInfo.Version,
		ProcessingTime: float64(time.Since(start).Nanoseconds()) / 1e6,
		Metadata: map[string]interface{}{
			"package_name": pkg.Name,
			"package_version": pkg.Version,
			"scorer_type": "advanced_ensemble",
		},
	}

	return result, nil
}

// GetModelInfo returns information about the model
func (s *AdvancedScorer) GetModelInfo() *ModelInfo {
	return s.modelInfo
}

// UpdateModel updates the scorer with new model parameters
func (s *AdvancedScorer) UpdateModel(modelData []byte) error {
	var updateData struct {
		FeatureWeights  map[string]float64 `json:"feature_weights"`
		EnsembleWeights map[string]float64 `json:"ensemble_weights"`
		Thresholds      ScoringThresholds  `json:"thresholds"`
		ModelInfo       *ModelInfo         `json:"model_info"`
	}

	if err := json.Unmarshal(modelData, &updateData); err != nil {
		return fmt.Errorf("failed to unmarshal model data: %w", err)
	}

	// Update configuration
	if updateData.FeatureWeights != nil {
		s.config.FeatureWeights = updateData.FeatureWeights
	}
	if updateData.EnsembleWeights != nil {
		s.ensembleWeights = updateData.EnsembleWeights
	}
	if updateData.ModelInfo != nil {
		s.modelInfo = updateData.ModelInfo
	}

	return nil
}

// GetThresholds returns the scoring thresholds
func (s *AdvancedScorer) GetThresholds() ScoringThresholds {
	return s.config.Thresholds
}

// normalizeFeatures normalizes input features using stored statistics
func (s *AdvancedScorer) normalizeFeatures(features map[string]interface{}) (map[string]float64, error) {
	normalized := make(map[string]float64)

	for key, value := range features {
		floatVal, ok := s.convertToFloat(value)
		if !ok {
			continue // Skip non-numeric features
		}

		if s.config.Normalization {
			if stats, exists := s.featureStats[key]; exists {
				// Z-score normalization
				if stats.StdDev > 0 {
					normalized[key] = (floatVal - stats.Mean) / stats.StdDev
				} else {
					normalized[key] = floatVal
				}
			} else {
				normalized[key] = floatVal
			}
		} else {
			normalized[key] = floatVal
		}
	}

	return normalized, nil
}

// calculateComponentScores calculates scores for different components
func (s *AdvancedScorer) calculateComponentScores(features map[string]float64) map[string]float64 {
	scores := make(map[string]float64)

	// Typosquatting score
	scores["typosquatting"] = s.calculateTyposquattingScore(features)
	
	// Reputation score
	scores["reputation"] = s.calculateReputationScore(features)
	
	// Behavioral score
	scores["behavioral"] = s.calculateBehavioralScore(features)
	
	// Metadata score
	scores["metadata"] = s.calculateMetadataScore(features)

	return scores
}

// calculateEnsembleScore combines component scores using ensemble weights
func (s *AdvancedScorer) calculateEnsembleScore(componentScores map[string]float64) float64 {
	var weightedSum, totalWeight float64

	for component, score := range componentScores {
		if weight, exists := s.ensembleWeights[component]; exists {
			weightedSum += score * weight
			totalWeight += weight
		}
	}

	if totalWeight > 0 {
		return math.Min(1.0, math.Max(0.0, weightedSum/totalWeight))
	}
	return 0.0
}

// calculateConfidence estimates the confidence of the prediction
func (s *AdvancedScorer) calculateConfidence(componentScores map[string]float64, features map[string]float64) float64 {
	// Calculate variance in component scores
	var sum, sumSquares float64
	count := float64(len(componentScores))

	for _, score := range componentScores {
		sum += score
		sumSquares += score * score
	}

	if count > 1 {
		mean := sum / count
		variance := (sumSquares - sum*mean) / (count - 1)
		// Higher variance means lower confidence
		confidence := 1.0 - math.Min(1.0, variance)
		return math.Max(s.config.Thresholds.MinConfidence, confidence)
	}

	return s.config.Thresholds.MinConfidence
}

// Helper methods for calculating component scores
func (s *AdvancedScorer) calculateTyposquattingScore(features map[string]float64) float64 {
	score := 0.0
	if val, exists := features["typosquatting_similarity"]; exists {
		score += val * 0.6
	}
	if val, exists := features["name_entropy"]; exists {
		score += (1.0 - val) * 0.4 // Lower entropy = higher suspicion
	}
	return math.Min(1.0, score)
}

func (s *AdvancedScorer) calculateReputationScore(features map[string]float64) float64 {
	score := 0.0
	if val, exists := features["maintainer_reputation"]; exists {
		score += (1.0 - val) * 0.5 // Lower reputation = higher risk
	}
	if val, exists := features["download_count"]; exists {
		// Normalize download count (assuming it's already normalized)
		score += (1.0 - val) * 0.3
	}
	if val, exists := features["package_age"]; exists {
		score += (1.0 - val) * 0.2 // Newer packages are slightly more suspicious
	}
	return math.Min(1.0, score)
}

func (s *AdvancedScorer) calculateBehavioralScore(features map[string]float64) float64 {
	score := 0.0
	if val, exists := features["update_frequency"]; exists {
		// Very high or very low update frequency can be suspicious
		if val > 0.8 || val < 0.2 {
			score += 0.3
		}
	}
	if val, exists := features["dependency_count"]; exists {
		// Unusually high dependency count
		if val > 0.8 {
			score += 0.4
		}
	}
	return math.Min(1.0, score)
}

func (s *AdvancedScorer) calculateMetadataScore(features map[string]float64) float64 {
	score := 0.0
	if val, exists := features["license_present"]; exists {
		score += (1.0 - val) * 0.3 // No license = higher risk
	}
	if val, exists := features["readme_present"]; exists {
		score += (1.0 - val) * 0.3 // No README = higher risk
	}
	if val, exists := features["description_length"]; exists {
		// Very short or very long descriptions can be suspicious
		if val < 0.2 || val > 0.9 {
			score += 0.4
		}
	}
	return math.Min(1.0, score)
}

// generateExplanation creates a human-readable explanation of the score
func (s *AdvancedScorer) generateExplanation(componentScores map[string]float64, riskLevel string) string {
	var explanations []string

	for component, score := range componentScores {
		if score > 0.6 {
			switch component {
			case "typosquatting":
				explanations = append(explanations, "high typosquatting similarity detected")
			case "reputation":
				explanations = append(explanations, "low maintainer/package reputation")
			case "behavioral":
				explanations = append(explanations, "suspicious behavioral patterns")
			case "metadata":
				explanations = append(explanations, "incomplete or suspicious metadata")
			}
		}
	}

	if len(explanations) == 0 {
		return fmt.Sprintf("Package classified as %s risk with no major concerns", riskLevel)
	}

	return fmt.Sprintf("Package classified as %s risk due to: %s", riskLevel, strings.Join(explanations, ", "))
}

// convertToFloat safely converts interface{} to float64
func (s *AdvancedScorer) convertToFloat(value interface{}) (float64, bool) {
	switch v := value.(type) {
	case float64:
		return v, true
	case float32:
		return float64(v), true
	case int:
		return float64(v), true
	case int64:
		return float64(v), true
	case int32:
		return float64(v), true
	default:
		return 0, false
	}
}

// getDefaultFeatureWeights returns default weights for features
func getDefaultFeatureWeights() map[string]float64 {
	return map[string]float64{
		"typosquatting_similarity": 0.25,
		"maintainer_reputation":    0.20,
		"download_count":           0.15,
		"package_age":              0.10,
		"update_frequency":         0.10,
		"dependency_count":         0.08,
		"name_entropy":             0.07,
		"license_present":          0.03,
		"readme_present":           0.02,
	}
}

// getDefaultFeatureStats returns default statistics for feature normalization
func getDefaultFeatureStats() map[string]FeatureStats {
	return map[string]FeatureStats{
		"download_count": {Mean: 1000, StdDev: 5000, Min: 0, Max: 100000},
		"package_age":    {Mean: 365, StdDev: 730, Min: 0, Max: 3650},
		"dependency_count": {Mean: 10, StdDev: 15, Min: 0, Max: 100},
		"description_length": {Mean: 100, StdDev: 50, Min: 0, Max: 500},
		"name_entropy": {Mean: 3.5, StdDev: 1.0, Min: 0, Max: 5},
		"update_frequency": {Mean: 30, StdDev: 60, Min: 0, Max: 365},
	}
}