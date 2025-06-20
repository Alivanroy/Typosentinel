package ml

import (
	"context"
	"typosentinel/pkg/types"
)

// Scorer defines the interface for ML-based package scoring
type Scorer interface {
	// Score calculates a risk score for a package based on extracted features
	Score(ctx context.Context, pkg *types.Package, features map[string]interface{}) (*ScoringResult, error)
	
	// GetModelInfo returns information about the underlying model
	GetModelInfo() *ModelInfo
	
	// UpdateModel updates the scorer with new model parameters
	UpdateModel(modelData []byte) error
	
	// GetThresholds returns the scoring thresholds used by this scorer
	GetThresholds() ScoringThresholds
}

// ScoringResult represents the output of a scoring operation
type ScoringResult struct {
	Score           float64            `json:"score"`
	Confidence      float64            `json:"confidence"`
	RiskLevel       string             `json:"risk_level"`
	FeatureScores   map[string]float64 `json:"feature_scores"`
	Explanation     string             `json:"explanation"`
	ModelVersion    string             `json:"model_version"`
	ProcessingTime  float64            `json:"processing_time_ms"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
}

// ScoringThresholds defines the thresholds for different risk levels
type ScoringThresholds struct {
	Malicious   float64 `json:"malicious"`
	Suspicious  float64 `json:"suspicious"`
	MinConfidence float64 `json:"min_confidence"`
}

// ScorerConfig provides configuration for scorers
type ScorerConfig struct {
	Thresholds       ScoringThresholds      `json:"thresholds"`
	FeatureWeights   map[string]float64     `json:"feature_weights"`
	Normalization    bool                   `json:"normalization"`
	ModelPath        string                 `json:"model_path"`
	UpdateInterval   string                 `json:"update_interval"`
	Metadata         map[string]interface{} `json:"metadata,omitempty"`
}

// DefaultScoringThresholds returns sensible default thresholds
func DefaultScoringThresholds() ScoringThresholds {
	return ScoringThresholds{
		Malicious:     0.8,
		Suspicious:    0.6,
		MinConfidence: 0.5,
	}
}

// GetRiskLevel determines the risk level based on score and thresholds
func (t ScoringThresholds) GetRiskLevel(score float64) string {
	if score >= t.Malicious {
		return "malicious"
	} else if score >= t.Suspicious {
		return "suspicious"
	}
	return "low"
}