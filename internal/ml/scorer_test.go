package ml

import (
	"context"
	"encoding/json"
	"github.com/Alivanroy/Typosentinel/pkg/types"
	"testing"
	"time"
)

func TestBasicMLScorerInterface(t *testing.T) {
	// Test that BasicMLScorer implements Scorer interface
	var _ Scorer = (*BasicMLScorer)(nil)

	scorer := NewBasicMLScorer()
	if scorer == nil {
		t.Fatal("NewBasicMLScorer returned nil")
	}
}

func TestBasicMLScorerScore(t *testing.T) {
	scorer := NewBasicMLScorer()
	ctx := context.Background()

	// Create test package
	pkg := &types.Package{
		Name:    "test-package",
		Version: "1.0.0",
	}

	// Create test features
	features := map[string]interface{}{
		"download_count":           1000.0,
		"maintainer_reputation":    0.8,
		"package_age":              365.0,
		"version_count":            5.0,
		"description_length":       100.0,
		"dependency_count":         3.0,
		"typosquatting_similarity": 0.1,
		"name_entropy":             2.5,
		"update_frequency":         0.1,
		"license_present":          1.0,
		"readme_present":           1.0,
		"homepage_present":         1.0,
		"repository_present":       1.0,
		"keyword_count":            5.0,
		"maintainer_count":         2.0,
	}

	result, err := scorer.Score(ctx, pkg, features)
	if err != nil {
		t.Fatalf("Score failed: %v", err)
	}

	if result == nil {
		t.Fatal("Score returned nil result")
	}

	// Validate result structure
	if result.Score < 0 || result.Score > 1 {
		t.Errorf("Score should be between 0 and 1, got %f", result.Score)
	}

	if result.Confidence < 0 || result.Confidence > 1 {
		t.Errorf("Confidence should be between 0 and 1, got %f", result.Confidence)
	}

	if result.RiskLevel == "" {
		t.Error("RiskLevel should not be empty")
	}

	if result.FeatureScores == nil {
		t.Error("FeatureScores should not be nil")
	}

	if result.ModelVersion == "" {
		t.Error("ModelVersion should not be empty")
	}

	if result.ProcessingTime <= 0 {
		t.Error("ProcessingTime should be positive")
	}

	if result.Metadata == nil {
		t.Error("Metadata should not be nil")
	}

	// Check metadata content
	if result.Metadata["package_name"] != pkg.Name {
		t.Errorf("Expected package_name %s, got %v", pkg.Name, result.Metadata["package_name"])
	}

	if result.Metadata["scorer_type"] != "basic_ml" {
		t.Errorf("Expected scorer_type basic_ml, got %v", result.Metadata["scorer_type"])
	}
}

func TestBasicMLScorerGetModelInfo(t *testing.T) {
	scorer := NewBasicMLScorer()
	modelInfo := scorer.GetModelInfo()

	if modelInfo == nil {
		t.Fatal("GetModelInfo returned nil")
	}

	if modelInfo.Name == "" {
		t.Error("Model name should not be empty")
	}

	if modelInfo.Version == "" {
		t.Error("Model version should not be empty")
	}

	if modelInfo.Type == "" {
		t.Error("Model type should not be empty")
	}

	if modelInfo.TrainedAt.IsZero() {
		t.Error("Training time should not be zero")
	}

	if modelInfo.FeatureCount <= 0 {
		t.Error("Feature count should be positive")
	}
}

func TestBasicMLScorerGetThresholds(t *testing.T) {
	scorer := NewBasicMLScorer()
	thresholds := scorer.GetThresholds()

	if thresholds.Malicious <= 0 || thresholds.Malicious > 1 {
		t.Errorf("Malicious threshold should be between 0 and 1, got %f", thresholds.Malicious)
	}

	if thresholds.Suspicious <= 0 || thresholds.Suspicious > 1 {
		t.Errorf("Suspicious threshold should be between 0 and 1, got %f", thresholds.Suspicious)
	}

	if thresholds.MinConfidence <= 0 || thresholds.MinConfidence > 1 {
		t.Errorf("MinConfidence should be between 0 and 1, got %f", thresholds.MinConfidence)
	}

	// Malicious threshold should be higher than suspicious
	if thresholds.Malicious <= thresholds.Suspicious {
		t.Error("Malicious threshold should be higher than suspicious threshold")
	}
}

func TestBasicMLScorerUpdateModel(t *testing.T) {
	scorer := NewBasicMLScorer()

	// Test valid model update
	updateData := map[string]interface{}{
		"feature_weights": map[string]float64{
			"download_count":        -0.5,
			"maintainer_reputation": -0.8,
		},
		"bias": 0.1,
		"thresholds": map[string]float64{
			"malicious":      0.8,
			"suspicious":     0.5,
			"min_confidence": 0.4,
		},
		"model_info": map[string]interface{}{
			"name":          "Updated Basic ML Scorer",
			"version":       "1.1.0",
			"description":   "Updated model",
			"type":          "logistic_regression",
			"training_time": time.Now().Format(time.RFC3339),
			"feature_count": 15,
			"metrics": map[string]float64{
				"accuracy":  0.92,
				"precision": 0.89,
				"recall":    0.87,
				"f1_score":  0.88,
			},
		},
	}

	modelBytes, err := json.Marshal(updateData)
	if err != nil {
		t.Fatalf("Failed to marshal update data: %v", err)
	}

	err = scorer.UpdateModel(modelBytes)
	if err != nil {
		t.Fatalf("UpdateModel failed: %v", err)
	}

	// Verify updates were applied
	thresholds := scorer.GetThresholds()
	if thresholds.Malicious != 0.8 {
		t.Errorf("Expected malicious threshold 0.8, got %f", thresholds.Malicious)
	}

	modelInfo := scorer.GetModelInfo()
	if modelInfo.Name != "Updated Basic ML Scorer" {
		t.Errorf("Expected model name 'Updated Basic ML Scorer', got %s", modelInfo.Name)
	}

	// Test invalid JSON
	err = scorer.UpdateModel([]byte("invalid json"))
	if err == nil {
		t.Error("Expected error for invalid JSON")
	}
}

// TODO: Add tests for AdvancedMLScorer when implemented
// func TestAdvancedMLScorerInterface(t *testing.T) {
// 	// Test that AdvancedMLScorer implements Scorer interface
// 	var _ Scorer = (*AdvancedMLScorer)(nil)
// }

func TestScoringThresholds(t *testing.T) {
	thresholds := ScoringThresholds{
		Malicious:     0.8,
		Suspicious:    0.5,
		MinConfidence: 0.3,
	}

	if thresholds.Malicious != 0.8 {
		t.Errorf("Expected malicious threshold 0.8, got %f", thresholds.Malicious)
	}

	if thresholds.Suspicious != 0.5 {
		t.Errorf("Expected suspicious threshold 0.5, got %f", thresholds.Suspicious)
	}

	if thresholds.MinConfidence != 0.3 {
		t.Errorf("Expected min confidence 0.3, got %f", thresholds.MinConfidence)
	}
}

func TestScoringResult(t *testing.T) {
	result := &ScoringResult{
		Score:          0.7,
		Confidence:     0.85,
		RiskLevel:      "HIGH",
		FeatureScores:  map[string]float64{"test_feature": 0.5},
		Explanation:    "Test explanation",
		ModelVersion:   "1.0.0",
		ProcessingTime: 10.5,
		Metadata:       map[string]interface{}{"test": "value"},
	}

	if result.Score != 0.7 {
		t.Errorf("Expected score 0.7, got %f", result.Score)
	}

	if result.Confidence != 0.85 {
		t.Errorf("Expected confidence 0.85, got %f", result.Confidence)
	}

	if result.RiskLevel != "HIGH" {
		t.Errorf("Expected risk level HIGH, got %s", result.RiskLevel)
	}

	if result.FeatureScores["test_feature"] != 0.5 {
		t.Errorf("Expected feature score 0.5, got %f", result.FeatureScores["test_feature"])
	}

	if result.Explanation != "Test explanation" {
		t.Errorf("Expected explanation 'Test explanation', got %s", result.Explanation)
	}

	if result.ModelVersion != "1.0.0" {
		t.Errorf("Expected model version 1.0.0, got %s", result.ModelVersion)
	}

	if result.ProcessingTime != 10.5 {
		t.Errorf("Expected processing time 10.5, got %f", result.ProcessingTime)
	}

	if result.Metadata["test"] != "value" {
		t.Errorf("Expected metadata test=value, got %v", result.Metadata["test"])
	}
}
