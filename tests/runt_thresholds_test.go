package tests

import (
	"github.com/Alivanroy/Typosentinel/internal/edge"
	"testing"
)

func TestUnicodeThresholdConfigAffectsClassification(t *testing.T) {
	algo := edge.NewRUNTAlgorithm(nil)
	f := algo.ComputeAllSimilarityFeatures("react", "геасt")
	atk := algo.ClassifyAttackType(f)
	if atk != "UNICODE_CONFUSION" {
		t.Fatalf("expected initial UNICODE_CONFUSION, got %s", atk)
	}
	err := algo.Configure(map[string]interface{}{"unicode_attack_threshold": 0.99})
	if err != nil {
		t.Fatalf("configure error: %v", err)
	}
	atk2 := algo.ClassifyAttackType(f)
	if atk2 == "UNICODE_CONFUSION" {
		t.Fatalf("expected classification to change when unicode threshold raised, still %s", atk2)
	}
}
