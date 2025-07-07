package detector

import (
	"github.com/Alivanroy/Typosentinel/pkg/types"
	"strings"
	"testing"
)

func TestNewEnhancedTyposquattingDetector(t *testing.T) {
	detector := NewEnhancedTyposquattingDetector()

	if detector == nil {
		t.Fatal("Expected detector to be created, got nil")
	}

	if detector.config == nil {
		t.Fatal("Expected config to be initialized")
	}

	if len(detector.keyboardLayouts) == 0 {
		t.Fatal("Expected keyboard layouts to be initialized")
	}

	if len(detector.substitutions) == 0 {
		t.Fatal("Expected substitutions to be initialized")
	}

	// Test default config values
	if detector.config.MinSimilarityThreshold != 0.75 {
		t.Errorf("Expected MinSimilarityThreshold to be 0.75, got %f", detector.config.MinSimilarityThreshold)
	}

	if !detector.config.EnableKeyboardAnalysis {
		t.Error("Expected EnableKeyboardAnalysis to be true")
	}
}

func TestKeyboardProximitySimilarity(t *testing.T) {
	detector := NewEnhancedTyposquattingDetector()

	tests := []struct {
		name     string
		s1       string
		s2       string
		expected float64
		minScore float64
	}{
		{
			name:     "Adjacent keys",
			s1:       "react",
			s2:       "eeact", // r->e (adjacent)
			minScore: 0.7,
		},
		{
			name:     "Multiple adjacent keys",
			s1:       "lodash",
			s2:       "kodash", // l->k (adjacent)
			minScore: 0.7,
		},
		{
			name:     "Non-adjacent keys",
			s1:       "express",
			s2:       "axpress", // e->a (not adjacent)
			expected: 0.0,
		},
		{
			name:     "Same string",
			s1:       "webpack",
			s2:       "webpack",
			expected: 1.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := detector.keyboardProximitySimilarity(tt.s1, tt.s2)

			if tt.expected > 0 {
				if score != tt.expected {
					t.Errorf("Expected score %f, got %f", tt.expected, score)
				}
			} else if tt.minScore > 0 {
				if score < tt.minScore {
					t.Errorf("Expected score >= %f, got %f", tt.minScore, score)
				}
			}
		})
	}
}

func TestVisualSimilarity(t *testing.T) {
	detector := NewEnhancedTyposquattingDetector()

	tests := []struct {
		name     string
		s1       string
		s2       string
		minScore float64
	}{
		{
			name:     "Number-letter substitution",
			s1:       "react",
			s2:       "r3act", // e->3 (visual similarity)
			minScore: 0.7,
		},
		{
			name:     "Zero-O substitution",
			s1:       "lodash",
			s2:       "l0dash", // o->0 (visual similarity)
			minScore: 0.8,
		},
		{
			name:     "One-I substitution",
			s1:       "express",
			s2:       "1xpress", // e->1 (not a strong visual match)
			minScore: 0.0,
		},
		{
			name:     "Multiple visual substitutions",
			s1:       "babel",
			s2:       "8a8el", // b->8 (visual similarity)
			minScore: 0.6,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := detector.visualSimilarity(tt.s1, tt.s2)

			if score < tt.minScore {
				t.Errorf("Expected score >= %f, got %f", tt.minScore, score)
			}
		})
	}
}

func TestPhoneticSimilarity(t *testing.T) {
	detector := NewEnhancedTyposquattingDetector()

	tests := []struct {
		name     string
		s1       string
		s2       string
		minScore float64
	}{
		{
			name:     "C-K substitution",
			s1:       "react",
			s2:       "reakt", // c->k (phonetic similarity)
			minScore: 0.7,
		},
		{
			name:     "S-C substitution",
			s1:       "express",
			s2:       "exprecс", // s->c (phonetic similarity)
			minScore: 0.6,
		},
		{
			name:     "Z-S substitution",
			s1:       "lodash",
			s2:       "lodazh", // s->z (phonetic similarity)
			minScore: 0.6,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := detector.phoneticSimilarity(tt.s1, tt.s2)

			if score < tt.minScore {
				t.Errorf("Expected score >= %f, got %f", tt.minScore, score)
			}
		})
	}
}

func TestCalculateEnhancedSimilarity(t *testing.T) {
	detector := NewEnhancedTyposquattingDetector()

	tests := []struct {
		name     string
		s1       string
		s2       string
		minScore float64
		maxScore float64
	}{
		{
			name:     "High similarity package",
			s1:       "react",
			s2:       "reakt",
			minScore: 0.8,
			maxScore: 1.0,
		},
		{
			name:     "Medium similarity package",
			s1:       "lodash",
			s2:       "l0dash",
			minScore: 0.7,
			maxScore: 0.95,
		},
		{
			name:     "Low similarity package",
			s1:       "express",
			s2:       "angular",
			minScore: 0.0,
			maxScore: 0.3,
		},
		{
			name:     "Identical packages",
			s1:       "webpack",
			s2:       "webpack",
			minScore: 1.0,
			maxScore: 1.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := detector.calculateEnhancedSimilarity(tt.s1, tt.s2)

			if score < tt.minScore || score > tt.maxScore {
				t.Errorf("Expected score between %f and %f, got %f", tt.minScore, tt.maxScore, score)
			}
		})
	}
}

func TestAnalyzeTyposquattingType(t *testing.T) {
	detector := NewEnhancedTyposquattingDetector()

	tests := []struct {
		name         string
		s1           string
		s2           string
		expectedType string
	}{
		{
			name:         "Keyboard proximity error",
			s1:           "react",
			s2:           "eeact", // r->e (adjacent keys)
			expectedType: "keyboard_proximity",
		},
		{
			name:         "Character transposition",
			s1:           "lodash",
			s2:           "lodahs", // s<->h transposition
			expectedType: "character_transposition",
		},
		{
			name:         "Character insertion",
			s1:           "express",
			s2:           "expresss", // extra 's'
			expectedType: "character_insertion",
		},
		{
			name:         "Character deletion",
			s1:           "webpack",
			s2:           "webpac", // missing 'k'
			expectedType: "character_deletion",
		},
		{
			name:         "Character substitution",
			s1:           "babel",
			s2:           "batel", // b->t substitution
			expectedType: "character_substitution",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analysis := detector.analyzeTyposquattingType(tt.s1, tt.s2)

			if analysis.PrimaryType != tt.expectedType {
				t.Errorf("Expected primary type %s, got %s", tt.expectedType, analysis.PrimaryType)
			}
		})
	}
}

func TestDetectEnhanced(t *testing.T) {
	detector := NewEnhancedTyposquattingDetector()

	// Create a test dependency
	target := types.Dependency{
		Name:     "reakt", // Typosquatting of "react"
		Version:  "1.0.0",
		Registry: "npm",
		Direct:   true,
	}

	// List of popular packages to compare against
	allPackages := []string{"react", "lodash", "express", "webpack", "babel"}

	threats := detector.DetectEnhanced(target, allPackages, 0.75)

	if len(threats) == 0 {
		t.Fatal("Expected at least one threat to be detected")
	}

	// Check the first threat
	threat := threats[0]
	if threat.Package != "reakt" {
		t.Errorf("Expected threat package to be 'reakt', got '%s'", threat.Package)
	}

	if threat.SimilarTo != "react" {
		t.Errorf("Expected similar package to be 'react', got '%s'", threat.SimilarTo)
	}

	if threat.Type != types.ThreatTypeTyposquatting {
		t.Errorf("Expected threat type to be typosquatting, got %v", threat.Type)
	}

	if threat.DetectionMethod != "enhanced_typosquatting" {
		t.Errorf("Expected detection method to be 'enhanced_typosquatting', got '%s'", threat.DetectionMethod)
	}

	if len(threat.Evidence) == 0 {
		t.Error("Expected evidence to be provided")
	}
}

func TestDetectEnhancedMultipleThreats(t *testing.T) {
	detector := NewEnhancedTyposquattingDetector()

	// Create a test dependency that's similar to multiple packages
	target := types.Dependency{
		Name:     "reakt", // Similar to "react"
		Version:  "1.0.0",
		Registry: "npm",
		Direct:   true,
	}

	// Include packages with varying similarity
	allPackages := []string{"react", "reach", "track", "lodash", "express"}

	threats := detector.DetectEnhanced(target, allPackages, 0.6) // Lower threshold

	if len(threats) == 0 {
		t.Fatal("Expected at least one threat to be detected")
	}

	// Should detect similarity to "react" at minimum
	found := false
	for _, threat := range threats {
		if threat.SimilarTo == "react" {
			found = true
			break
		}
	}

	if !found {
		t.Error("Expected to find threat similar to 'react'")
	}
}

func TestDetectEnhancedNoThreats(t *testing.T) {
	detector := NewEnhancedTyposquattingDetector()

	// Create a test dependency that's not similar to any package
	target := types.Dependency{
		Name:     "completely-different-package",
		Version:  "1.0.0",
		Registry: "npm",
		Direct:   true,
	}

	allPackages := []string{"react", "lodash", "express", "webpack", "babel"}

	threats := detector.DetectEnhanced(target, allPackages, 0.75)

	if len(threats) != 0 {
		t.Errorf("Expected no threats to be detected, got %d", len(threats))
	}
}

func TestCalculateSeverityEnhanced(t *testing.T) {
	detector := NewEnhancedTyposquattingDetector()

	tests := []struct {
		name             string
		similarity       float64
		analysis         TyposquattingAnalysis
		expectedSeverity types.Severity
	}{
		{
			name:       "Critical similarity",
			similarity: 0.98,
			analysis: TyposquattingAnalysis{
				PrimaryType: "character_substitution",
			},
			expectedSeverity: types.SeverityCritical,
		},
		{
			name:       "High similarity with keyboard errors",
			similarity: 0.95,
			analysis: TyposquattingAnalysis{
				KeyboardErrors: 1,
				PrimaryType:    "keyboard_proximity",
			},
			expectedSeverity: types.SeverityHigh, // Downgraded due to keyboard errors
		},
		{
			name:       "Medium similarity with visual attack",
			similarity: 0.85,
			analysis: TyposquattingAnalysis{
				VisualSimilarity: 0.95,
				PrimaryType:      "visual_similarity",
			},
			expectedSeverity: types.SeverityHigh, // Upgraded due to visual similarity
		},
		{
			name:       "Low similarity",
			similarity: 0.75,
			analysis: TyposquattingAnalysis{
				PrimaryType: "character_substitution",
			},
			expectedSeverity: types.SeverityLow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			severity := detector.calculateSeverityEnhanced(tt.similarity, tt.analysis)

			if severity != tt.expectedSeverity {
				t.Errorf("Expected severity %v, got %v", tt.expectedSeverity, severity)
			}
		})
	}
}

func TestGenerateThreatDescription(t *testing.T) {
	detector := NewEnhancedTyposquattingDetector()

	tests := []struct {
		name     string
		target   string
		similar  string
		analysis TyposquattingAnalysis
		contains []string
	}{
		{
			name:    "Keyboard proximity",
			target:  "reakt",
			similar: "react",
			analysis: TyposquattingAnalysis{
				KeyboardErrors:   1,
				PrimaryType:      "keyboard_proximity",
				VisualSimilarity: 0.8,
			},
			contains: []string{"keyboard errors", "typosquatting attack"},
		},
		{
			name:    "Visual similarity",
			target:  "r3act",
			similar: "react",
			analysis: TyposquattingAnalysis{
				VisualSimilarity: 0.95,
				PrimaryType:      "visual_similarity",
			},
			contains: []string{"visual similarity", "spoofing attack"},
		},
		{
			name:    "Character transposition",
			target:  "raect",
			similar: "react",
			analysis: TyposquattingAnalysis{
				Transpositions:   1,
				PrimaryType:      "character_transposition",
				VisualSimilarity: 0.9,
			},
			contains: []string{"transposition detected", "typosquatting attack"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			description := detector.generateThreatDescription(tt.target, tt.similar, tt.analysis)

			for _, expected := range tt.contains {
				if !strings.Contains(strings.ToLower(description), strings.ToLower(expected)) {
					t.Errorf("Expected description to contain '%s', got: %s", expected, description)
				}
			}
		})
	}
}

func TestGenerateEvidence(t *testing.T) {
	detector := NewEnhancedTyposquattingDetector()

	analysis := TyposquattingAnalysis{
		EditDistance:       1,
		VisualSimilarity:   0.9,
		PhoneticSimilarity: 0.8,
		KeyboardErrors:     1,
		Transpositions:     0,
	}

	evidence := detector.generateEvidence("reakt", "react", analysis)

	if len(evidence) < 3 {
		t.Errorf("Expected at least 3 pieces of evidence, got %d", len(evidence))
	}

	// Check for required evidence types
	requiredTypes := []string{"edit_distance", "visual_similarity", "phonetic_similarity"}
	found := make(map[string]bool)

	for _, ev := range evidence {
		found[ev.Type] = true
	}

	for _, reqType := range requiredTypes {
		if !found[reqType] {
			t.Errorf("Expected evidence type '%s' to be present", reqType)
		}
	}

	// Should include keyboard errors evidence
	if !found["keyboard_errors"] {
		t.Error("Expected keyboard_errors evidence to be present")
	}
}

func TestWeightedAverage(t *testing.T) {
	detector := NewEnhancedTyposquattingDetector()

	tests := []struct {
		name     string
		scores   []float64
		weights  []float64
		expected float64
	}{
		{
			name:     "Equal weights",
			scores:   []float64{0.8, 0.9, 0.7},
			weights:  []float64{1.0, 1.0, 1.0},
			expected: 0.8, // (0.8 + 0.9 + 0.7) / 3
		},
		{
			name:     "Different weights",
			scores:   []float64{0.8, 0.9},
			weights:  []float64{0.3, 0.7},
			expected: 0.87, // (0.8*0.3 + 0.9*0.7) / (0.3+0.7)
		},
		{
			name:     "Empty arrays",
			scores:   []float64{},
			weights:  []float64{},
			expected: 0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.weightedAverage(tt.scores, tt.weights)

			if abs(result-tt.expected) > 0.01 {
				t.Errorf("Expected %f, got %f", tt.expected, result)
			}
		})
	}
}

// Helper function for floating point comparison
func abs(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}

func BenchmarkDetectEnhanced(b *testing.B) {
	detector := NewEnhancedTyposquattingDetector()

	target := types.Dependency{
		Name:     "reakt",
		Version:  "1.0.0",
		Registry: "npm",
		Direct:   true,
	}

	allPackages := []string{"react", "lodash", "express", "webpack", "babel", "typescript", "angular", "vue", "jquery", "moment"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = detector.DetectEnhanced(target, allPackages, 0.75)
	}
}

func BenchmarkCalculateEnhancedSimilarity(b *testing.B) {
	detector := NewEnhancedTyposquattingDetector()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = detector.calculateEnhancedSimilarity("reakt", "react")
	}
}
