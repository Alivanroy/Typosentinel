package security

import (
	"context"
	"testing"
	"time"

	"github.com/Alivanroy/Typosentinel/pkg/logger"
	"github.com/Alivanroy/Typosentinel/pkg/types"
)

func TestMLHardeningSystem(t *testing.T) {
	// Create ML hardening system
	config := DefaultMLHardeningConfig()
	mlHardening := NewMLHardeningSystem(config, *logger.New())

	// Create test package
	pkg := &types.Package{
		Name:     "test-ml-package",
		Version:  "1.0.0",
		Registry: "npm",
	}

	// Create test features
	features := map[string]float64{
		"confidence_score":    0.95,
		"similarity_ratio":    0.87,
		"entropy_measure":     2.3,
		"feature_variance":    0.12,
		"prediction_strength": 0.91,
	}

	ctx := context.Background()

	// Test adversarial detection
	t.Run("AdversarialDetection", func(t *testing.T) {
		risk, err := mlHardening.detectAdversarialAttacks(ctx, pkg, features)
		if err != nil {
			t.Fatalf("Unexpected error in adversarial detection: %v", err)
		}
		if risk == nil {
			t.Fatal("Expected adversarial risk result, got nil")
		}
		if risk.RiskLevel == "" {
			t.Error("Expected risk level to be set")
		}
		if risk.ConfidenceScore < 0 || risk.ConfidenceScore > 1 {
			t.Errorf("Expected confidence score between 0-1, got %f", risk.ConfidenceScore)
		}
		t.Logf("Adversarial Risk Level: %s, Confidence: %.2f", risk.RiskLevel, risk.ConfidenceScore)
	})

	// Test feature poisoning detection
	t.Run("FeaturePoisoningDetection", func(t *testing.T) {
		risk, err := mlHardening.detectFeaturePoisoning(ctx, pkg, features)
		if err != nil {
			t.Fatalf("Unexpected error in feature poisoning detection: %v", err)
		}
		if risk == nil {
			t.Fatal("Expected feature poisoning risk result, got nil")
		}
		if risk.RiskLevel == "" {
			t.Error("Expected risk level to be set")
		}
		t.Logf("Feature Poisoning Risk Level: %s, Confidence: %.2f", risk.RiskLevel, risk.ConfidenceScore)
	})

	// Test input validation
	t.Run("InputValidation", func(t *testing.T) {
		result, err := mlHardening.validateInputs(ctx, pkg, features)
		if err != nil {
			t.Fatalf("Unexpected error in input validation: %v", err)
		}
		if result == nil {
			t.Fatal("Expected input validation result, got nil")
		}
		if result.ValidationStatus == "" {
			t.Error("Expected validation status to be set")
		}
		if result.ValidationMetrics == nil {
			t.Error("Expected validation metrics to be set")
		}
		t.Logf("Validation Status: %s, Anomaly Rate: %.2f", result.ValidationStatus, result.ValidationMetrics.AnomalyRate)
	})

	// Test model robustness validation
	t.Run("ModelRobustnessValidation", func(t *testing.T) {
		result, err := mlHardening.validateModelRobustness(ctx, pkg, features)
		if err != nil {
			t.Fatalf("Unexpected error in robustness validation: %v", err)
		}
		if result == nil {
			t.Fatal("Expected robustness validation result, got nil")
		}
		if result.RobustnessScore < 0 || result.RobustnessScore > 1 {
			t.Errorf("Expected robustness score between 0-1, got %f", result.RobustnessScore)
		}
		t.Logf("Robustness Score: %.2f", result.RobustnessScore)
	})

	// Test gradient analysis
	t.Run("GradientAnalysis", func(t *testing.T) {
		result, err := mlHardening.analyzeGradients(ctx, pkg, features)
		if err != nil {
			t.Fatalf("Unexpected error in gradient analysis: %v", err)
		}
		if result == nil {
			t.Fatal("Expected gradient analysis result, got nil")
		}
		if result.GradientMagnitude < 0 {
			t.Errorf("Expected non-negative gradient magnitude, got %f", result.GradientMagnitude)
		}
		if result.GradientStability < 0 || result.GradientStability > 1 {
			t.Errorf("Expected gradient stability between 0-1, got %f", result.GradientStability)
		}
		t.Logf("Gradient Magnitude: %.2f, Stability: %.2f", result.GradientMagnitude, result.GradientStability)
	})

	// Test ensemble defense
	t.Run("EnsembleDefense", func(t *testing.T) {
		result, err := mlHardening.performEnsembleDefense(ctx, pkg, features)
		if err != nil {
			t.Fatalf("Unexpected error in ensemble defense: %v", err)
		}
		if result == nil {
			t.Fatal("Expected ensemble defense result, got nil")
		}
		if result.EnsembleAgreement < 0 || result.EnsembleAgreement > 1 {
			t.Errorf("Expected ensemble agreement between 0-1, got %f", result.EnsembleAgreement)
		}
		if result.ConsensusScore < 0 || result.ConsensusScore > 1 {
			t.Errorf("Expected consensus score between 0-1, got %f", result.ConsensusScore)
		}
		t.Logf("Ensemble Agreement: %.2f, Consensus Score: %.2f", result.EnsembleAgreement, result.ConsensusScore)
	})

	// Test full ML hardening analysis
	t.Run("FullMLHardeningAnalysis", func(t *testing.T) {
		result, err := mlHardening.AnalyzeMLSecurity(ctx, pkg)
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
		if result == nil {
			t.Fatal("Expected ML hardening result, got nil")
		}
		if result.OverallSecurityScore < 0 || result.OverallSecurityScore > 1 {
			t.Errorf("Expected overall security score between 0-1, got %f", result.OverallSecurityScore)
		}
		t.Logf("Overall Security Score: %.2f", result.OverallSecurityScore)
		t.Logf("Detected Vulnerabilities: %d", len(result.DetectedVulnerabilities))
		t.Logf("Countermeasures: %d", len(result.Countermeasures))
		t.Logf("Recommendations: %d", len(result.Recommendations))
	})
}

func TestMLHardeningWithAnomalousFeatures(t *testing.T) {
	// Create ML hardening system
	config := DefaultMLHardeningConfig()
	mlHardening := NewMLHardeningSystem(config, *logger.New())

	// Create test package
	pkg := &types.Package{
		Name:     "test-anomalous-package",
		Version:  "1.0.0",
		Registry: "npm",
	}

	// Create anomalous features that should trigger high risk scores
	anomalousFeatures := map[string]float64{
		"confidence_score":    1.5,  // Out of range (should be 0-1)
		"similarity_ratio":    -0.3, // Negative value (should be 0-1)
		"entropy_measure":     15.0, // Very high entropy
		"feature_variance":    2.5,  // High variance
		"prediction_strength": 0.1,  // Very low prediction strength
	}

	ctx := context.Background()

	t.Run("AnomalousAdversarialDetection", func(t *testing.T) {
		risk, err := mlHardening.detectAdversarialAttacks(ctx, pkg, anomalousFeatures)
		if err != nil {
			t.Fatalf("Unexpected error in adversarial detection: %v", err)
		}
		if risk == nil {
			t.Fatal("Expected adversarial risk result, got nil")
		}
		// Should detect higher risk with anomalous features
		if risk.ConfidenceScore < 0.3 {
			t.Errorf("Expected higher confidence score for anomalous features, got %f", risk.ConfidenceScore)
		}
		t.Logf("Anomalous Adversarial Risk Level: %s, Confidence: %.2f", risk.RiskLevel, risk.ConfidenceScore)
	})

	t.Run("AnomalousInputValidation", func(t *testing.T) {
		result, err := mlHardening.validateInputs(ctx, pkg, anomalousFeatures)
		if err != nil {
			t.Fatalf("Unexpected error in input validation: %v", err)
		}
		if result == nil {
			t.Fatal("Expected input validation result, got nil")
		}
		// Should detect more anomalous inputs
		if result.ValidationMetrics.AnomalyRate < 0.2 {
			t.Errorf("Expected higher anomaly rate for anomalous features, got %f", result.ValidationMetrics.AnomalyRate)
		}
		t.Logf("Anomalous Validation Status: %s, Anomaly Rate: %.2f", result.ValidationStatus, result.ValidationMetrics.AnomalyRate)
	})
}

func TestMLHardeningConfiguration(t *testing.T) {
	t.Run("DefaultConfiguration", func(t *testing.T) {
		config := DefaultMLHardeningConfig()
		if !config.Enabled {
			t.Error("Expected default configuration to be enabled")
		}
		if !config.EnableAdversarialDetection {
			t.Error("Expected adversarial detection to be enabled by default")
		}
		if !config.EnableFeaturePoisoningCheck {
			t.Error("Expected feature poisoning check to be enabled by default")
		}
		if config.ValidationTimeout != 60*time.Second {
			t.Errorf("Expected default timeout to be 60s, got %v", config.ValidationTimeout)
		}
	})

	t.Run("CustomConfiguration", func(t *testing.T) {
		config := &MLHardeningConfig{
			EnableAdversarialDetection:  false,
			EnableFeaturePoisoningCheck: true,
			AdversarialThreshold:        0.9,
			PoisoningThreshold:          0.8,
			ValidationTimeout:           30 * time.Second,
			Enabled:                     true,
		}

		mlHardening := NewMLHardeningSystem(config, *logger.New())
		if mlHardening == nil {
			t.Fatal("Expected ML hardening system to be created")
		}
		if mlHardening.config.AdversarialThreshold != 0.9 {
			t.Errorf("Expected adversarial threshold to be 0.9, got %f", mlHardening.config.AdversarialThreshold)
		}
	})
}
