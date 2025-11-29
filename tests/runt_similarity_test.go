package tests

import (
	"context"
	"github.com/Alivanroy/Typosentinel/internal/edge"
	"testing"
)

func TestUnicodeConfusionReactCyrillic(t *testing.T) {
	algo := edge.NewRUNTAlgorithm(nil)
	algo.Configure(map[string]interface{}{"overall_threshold": 0.75})
	features := algo.ComputeAllSimilarityFeatures("react", "геасt")
	if features.Unicode <= 0.7 {
		t.Fatalf("expected Unicode > 0.7, got %.3f", features.Unicode)
	}
	attack := algo.ClassifyAttackType(features)
	if attack != "UNICODE_CONFUSION" {
		t.Fatalf("expected UNICODE_CONFUSION, got %s", attack)
	}
}

func TestKeyboardTypoAxiosAxois(t *testing.T) {
	algo := edge.NewRUNTAlgorithm(nil)
	features := algo.ComputeAllSimilarityFeatures("axios", "axois")
	if features.KeyboardLayout <= 0.7 {
		t.Fatalf("expected KeyboardLayout > 0.7, got %.3f", features.KeyboardLayout)
	}
	attack := algo.ClassifyAttackType(features)
	if attack != "KEYBOARD_TYPO" {
		t.Fatalf("expected KEYBOARD_TYPO, got %s", attack)
	}
}

func TestUnicodeConfusionNodeCyrillic(t *testing.T) {
	algo := edge.NewRUNTAlgorithm(nil)
	features := algo.ComputeAllSimilarityFeatures("node", "поde")
	if features.Unicode < 0.6 {
		t.Fatalf("expected Unicode >= 0.6, got %.3f", features.Unicode)
	}
	attack := algo.ClassifyAttackType(features)
	if attack != "UNICODE_CONFUSION" {
		t.Fatalf("expected UNICODE_CONFUSION, got %s", attack)
	}
}

func TestKeyboardTypoExpressExpres(t *testing.T) {
	algo := edge.NewRUNTAlgorithm(nil)
	features := algo.ComputeAllSimilarityFeatures("express", "expres")
	if features.KeyboardLayout <= 0.7 {
		t.Fatalf("expected KeyboardLayout > 0.7, got %.3f", features.KeyboardLayout)
	}
	attack := algo.ClassifyAttackType(features)
	if attack != "KEYBOARD_TYPO" {
		t.Fatalf("expected KEYBOARD_TYPO, got %s", attack)
	}
}

func TestKeyboardTypoLodashLoadsh(t *testing.T) {
	algo := edge.NewRUNTAlgorithm(nil)
	features := algo.ComputeAllSimilarityFeatures("lodash", "loadsh")
	if features.KeyboardLayout <= 0.7 {
		t.Fatalf("expected KeyboardLayout > 0.7, got %.3f", features.KeyboardLayout)
	}
	attack := algo.ClassifyAttackType(features)
	if attack != "KEYBOARD_TYPO" {
		t.Fatalf("expected KEYBOARD_TYPO, got %s", attack)
	}
}

func TestKeyboardTypoRequestReqiest(t *testing.T) {
	algo := edge.NewRUNTAlgorithm(nil)
	features := algo.ComputeAllSimilarityFeatures("request", "reqiest")
	if features.KeyboardLayout <= 0.7 {
		t.Fatalf("expected KeyboardLayout > 0.7, got %.3f", features.KeyboardLayout)
	}
	attack := algo.ClassifyAttackType(features)
	if attack != "KEYBOARD_TYPO" {
		t.Fatalf("expected KEYBOARD_TYPO, got %s", attack)
	}
}
func TestUnicodeConfusionMixedGreekCyrillic(t *testing.T) {
	algo := edge.NewRUNTAlgorithm(nil)
	features := algo.ComputeAllSimilarityFeatures("apollo", "αρоllо")
	if features.Unicode <= 0.7 {
		t.Fatalf("expected Unicode > 0.7, got %.3f", features.Unicode)
	}
	attack := algo.ClassifyAttackType(features)
	if attack != "UNICODE_CONFUSION" {
		t.Fatalf("expected UNICODE_CONFUSION, got %s", attack)
	}
}
func TestGeneralTypoCrossEnvVsCrossenv(t *testing.T) {
	algo := edge.NewRUNTAlgorithm(nil)
	features := algo.ComputeAllSimilarityFeatures("cross-env", "crossenv")
	if features.Semantic <= 0.7 {
		t.Fatalf("expected Semantic > 0.7, got %.3f", features.Semantic)
	}
	attack := algo.ClassifyAttackType(features)
	if attack == "UNICODE_CONFUSION" {
		t.Fatalf("unexpected UNICODE_CONFUSION classification")
	}
}

func TestSemanticReactRouterVsReactrouter(t *testing.T) {
	algo := edge.NewRUNTAlgorithm(nil)
	features := algo.ComputeAllSimilarityFeatures("react-router", "reactrouter")
	if features.Semantic <= 0.7 {
		t.Fatalf("expected Semantic > 0.7, got %.3f", features.Semantic)
	}
	if features.Unicode > 0.7 {
		t.Fatalf("unexpected Unicode confusion")
	}
}

func TestSemanticNodeFetchVsNodefetch(t *testing.T) {
	algo := edge.NewRUNTAlgorithm(nil)
	features := algo.ComputeAllSimilarityFeatures("node-fetch", "nodefetch")
	if features.Semantic <= 0.7 {
		t.Fatalf("expected Semantic > 0.7, got %.3f", features.Semantic)
	}
	if features.Unicode > 0.7 {
		t.Fatalf("unexpected Unicode confusion")
	}
}

func TestUnicodePriorityOverKeyboard(t *testing.T) {
	algo := edge.NewRUNTAlgorithm(nil)
	// Mix Cyrillic homoglyphs with potential keyboard adjacency
	// Target: 'axios' vs 'аxоis' (Cyrillic 'а' and 'о')
	features := algo.ComputeAllSimilarityFeatures("axios", "аxоis")
	if features.Unicode <= 0.7 {
		t.Fatalf("expected Unicode > 0.7, got %.3f", features.Unicode)
	}
	attack := algo.ClassifyAttackType(features)
	if attack != "UNICODE_CONFUSION" {
		t.Fatalf("expected UNICODE_CONFUSION priority, got %s", attack)
	}
}

func TestRUNTMetadataIncludesThresholds(t *testing.T) {
	algo := edge.NewRUNTAlgorithm(nil)
	res, err := algo.Analyze(context.Background(), []string{"axios"})
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}
	if res.Metadata == nil {
		t.Fatalf("missing metadata")
	}
	ats, ok := res.Metadata["attack_thresholds"].(map[string]float64)
	if !ok || len(ats) == 0 {
		t.Fatalf("attack_thresholds missing or empty")
	}
	// runt_overall_score and runt_risk_level are present only when findings exist
}
