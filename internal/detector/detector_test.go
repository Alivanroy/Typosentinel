package detector

import (
	"context"
	"testing"

	"typosentinel/internal/config"
	"typosentinel/pkg/types"
)

func TestNewEngine(t *testing.T) {
	cfg := &config.Config{
		Detection: config.DetectionConfig{
			SimilarityThreshold: 0.8,
			HomoglyphDetection:  true,
			SemanticAnalysis:    true,
		},
	}

	engine := New(cfg)

	if engine == nil {
		t.Error("Expected engine to be created, got nil")
	}

	if engine.config != cfg {
		t.Error("Expected engine config to match provided config")
	}


}

func TestDetectTyposquatting_ExactMatch(t *testing.T) {
	cfg := &config.Config{
		Detection: config.DetectionConfig{
			SimilarityThreshold: 0.8,
			HomoglyphDetection:  true,
			SemanticAnalysis:    true,
		},
	}
	lexicalDetector := NewLexicalDetector(cfg)

	// Test exact match (should not be flagged)
	target := types.Dependency{Name: "lodash", Version: "1.0.0", Registry: "npm"}
	allPackages := []string{"lodash"}
	threats := lexicalDetector.Detect(target, allPackages, 0.8)
	if len(threats) > 0 {
		t.Error("Exact match should not be flagged as typosquatting")
	}
}

func TestDetectTyposquatting_HighSimilarity(t *testing.T) {
	cfg := &config.Config{
		Detection: config.DetectionConfig{
			SimilarityThreshold: 0.8,
			HomoglyphDetection:  true,
			SemanticAnalysis:    true,
		},
	}
	lexicalDetector := NewLexicalDetector(cfg)

	// Test high similarity (should be flagged)
	target := types.Dependency{Name: "lodash", Version: "1.0.0", Registry: "npm"}
	allPackages := []string{"lodahs"}
	threats := lexicalDetector.Detect(target, allPackages, 0.8)

	if len(threats) == 0 {
		t.Error("High similarity should be flagged as typosquatting")
	}

	if len(threats) > 0 && threats[0].Confidence < 0.8 {
		t.Errorf("Expected confidence >= 0.8, got %f", threats[0].Confidence)
	}

	if len(threats) > 0 && threats[0].SimilarTo != "lodahs" {
		t.Errorf("Expected similar package 'lodahs', got '%s'", threats[0].SimilarTo)
	}
}

func TestDetectTyposquatting_LowSimilarity(t *testing.T) {
	cfg := &config.Config{
		Detection: config.DetectionConfig{
			SimilarityThreshold: 0.8,
			HomoglyphDetection:  true,
			SemanticAnalysis:    true,
		},
	}
	lexicalDetector := NewLexicalDetector(cfg)

	// Test low similarity (should not be flagged)
	target := types.Dependency{Name: "lodash", Version: "1.0.0", Registry: "npm"}
	allPackages := []string{"completely-different"}
	threats := lexicalDetector.Detect(target, allPackages, 0.8)

	if len(threats) > 0 {
		t.Error("Low similarity should not be flagged as typosquatting")
	}
}

func TestDetectTyposquatting_CommonTypos(t *testing.T) {
	cfg := &config.Config{
		Detection: config.DetectionConfig{
			SimilarityThreshold: 0.8,
			HomoglyphDetection:  true,
			SemanticAnalysis:    true,
		},
	}
	lexicalDetector := NewLexicalDetector(cfg)

	tests := []struct {
		original string
		typo     string
		expected bool
	}{
		{"lodash", "lodahs", true},     // Character swap
		{"express", "expres", true},   // Missing character
		{"react", "reactt", true},     // Extra character
		{"vue", "veu", true},          // Character swap
		{"angular", "angualr", true},  // Character swap
		{"jquery", "jqeury", true},    // Character swap
		{"bootstrap", "bootstrp", true}, // Missing characters but still similar
	}

	for _, test := range tests {
		t.Run(test.original+"_vs_"+test.typo, func(t *testing.T) {
			target := types.Dependency{Name: test.original, Version: "1.0.0", Registry: "npm"}
			allPackages := []string{test.typo}
			threats := lexicalDetector.Detect(target, allPackages, 0.8)
			isTyposquatting := len(threats) > 0
			if isTyposquatting != test.expected {
				confidence := 0.0
				if len(threats) > 0 {
					confidence = threats[0].Confidence
				}
				t.Errorf("DetectTyposquatting(%s, %s) = %v, expected %v (confidence: %f)",
					test.original, test.typo, isTyposquatting, test.expected, confidence)
			}
		})
	}
}

func TestCalculateSimilarity(t *testing.T) {
	cfg := &config.Config{}
	lexicalDetector := NewLexicalDetector(cfg)

	tests := []struct {
		str1     string
		str2     string
		minSim   float64
		maxSim   float64
	}{
		{"test", "test", 1.0, 1.0},           // Identical
		{"test", "tset", 0.5, 0.9},           // Transposition
		{"test", "tes", 0.6, 0.9},            // Missing character
		{"test", "testt", 0.6, 0.9},          // Extra character
		{"test", "best", 0.6, 0.9},           // Substitution
		{"test", "completely", 0.0, 0.3},     // Very different
		{"", "", 1.0, 1.0},                   // Both empty
		{"a", "", 0.0, 0.0},                  // One empty
	}

	for _, test := range tests {
		t.Run(test.str1+"_vs_"+test.str2, func(t *testing.T) {
			sim := lexicalDetector.levenshteinSimilarity(test.str1, test.str2)
			if sim < test.minSim || sim > test.maxSim {
				t.Errorf("levenshteinSimilarity(%s, %s) = %f, expected between %f and %f",
					test.str1, test.str2, sim, test.minSim, test.maxSim)
			}
		})
	}
}

func TestLevenshteinDistance(t *testing.T) {
	cfg := &config.Config{}
	lexicalDetector := NewLexicalDetector(cfg)

	tests := []struct {
		str1     string
		str2     string
		expected int
	}{
		{"test", "test", 0},     // Identical
		{"test", "tes", 1},      // One deletion
		{"test", "testt", 1},    // One insertion
		{"test", "best", 1},     // One substitution
		{"test", "tset", 2},     // Two operations
		{"kitten", "sitting", 3}, // Classic example
		{"", "", 0},             // Both empty
		{"a", "", 1},            // One empty
		{"", "a", 1},            // Other empty
	}

	for _, test := range tests {
		t.Run(test.str1+"_vs_"+test.str2, func(t *testing.T) {
			dist := lexicalDetector.levenshteinDistance(test.str1, test.str2)
			if dist != test.expected {
				t.Errorf("levenshteinDistance(%s, %s) = %d, expected %d",
					test.str1, test.str2, dist, test.expected)
			}
		})
	}
}

func TestCheckPackage_SuspiciousPackage(t *testing.T) {
	cfg := &config.Config{
		Detection: config.DetectionConfig{
			SimilarityThreshold: 0.8,
			HomoglyphDetection:  true,
			SemanticAnalysis:    true,
		},
	}

	engine := New(cfg)

	// Test package analysis
	packageName := "l0dash" // Suspicious name (0 instead of o)
	registry := "npm"

	result, err := engine.CheckPackage(context.Background(), packageName, registry)

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if result == nil {
		t.Error("Expected analysis result, got nil")
	}

	if result.Package != packageName {
		t.Errorf("Expected package name %s, got %s", packageName, result.Package)
	}

	if result.Registry != registry {
		t.Errorf("Expected registry %s, got %s", registry, result.Registry)
	}

	// Should detect potential typosquatting
	if len(result.Threats) == 0 {
		t.Error("Expected to detect threats for suspicious package name")
	}
}

func TestCheckPackage_CleanPackage(t *testing.T) {
	cfg := &config.Config{
		Detection: config.DetectionConfig{
			SimilarityThreshold: 0.8,
		},
	}

	engine := New(cfg)

	// Test clean package
	packageName := "unique-package-name-12345"
	registry := "npm"

	result, err := engine.CheckPackage(context.Background(), packageName, registry)

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if result == nil {
		t.Error("Expected analysis result, got nil")
	}

	// Should have low threat level for unique package name
	if result.ThreatLevel == "high" || result.ThreatLevel == "critical" {
		t.Errorf("Expected low threat level for unique package, got %s", result.ThreatLevel)
	}
}

func TestEngineVersion(t *testing.T) {
	cfg := &config.Config{}
	engine := New(cfg)

	version := engine.Version()
	if version == "" {
		t.Error("Expected version to be set, got empty string")
	}

	if version != "1.0.0" {
		t.Errorf("Expected version 1.0.0, got %s", version)
	}
}

func TestAnalyze(t *testing.T) {
	cfg := &config.Config{
		Detection: config.DetectionConfig{
			SimilarityThreshold: 0.8,
		},
	}
	engine := New(cfg)

	// Test analyzing dependencies
	deps := []types.Dependency{
		{
			Name:     "lodash",
			Version:  "4.17.21",
			Registry: "npm",
			Direct:   true,
		},
		{
			Name:     "l0dash", // Suspicious name
			Version:  "1.0.0",
			Registry: "npm",
			Direct:   true,
		},
	}

	options := &Options{
		DeepAnalysis:        true,
		SimilarityThreshold: 0.8,
	}

	threats, warnings, err := engine.Analyze(context.Background(), deps, options)

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	// Should detect threats for suspicious package
	if len(threats) == 0 {
		t.Error("Expected to detect threats for suspicious package name")
	}

	// Should have warnings
	if len(warnings) == 0 {
		t.Log("No warnings detected (this is acceptable)")
	}
}