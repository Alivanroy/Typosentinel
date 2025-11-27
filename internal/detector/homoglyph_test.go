package detector

import (
	"math"
	"testing"

	"github.com/Alivanroy/Typosentinel/pkg/types"
)

func TestNewHomoglyphDetector(t *testing.T) {
	detector := NewHomoglyphDetector()

	if detector == nil {
		t.Fatal("Expected non-nil detector")
	}

	if detector.homoglyphMap == nil {
		t.Fatal("Expected homoglyphMap to be initialized")
	}

	// Check that some common homoglyphs are present
	if _, exists := detector.homoglyphMap['a']; !exists {
		t.Error("Expected 'a' to have homoglyphs")
	}

	if _, exists := detector.homoglyphMap['e']; !exists {
		t.Error("Expected 'e' to have homoglyphs")
	}

	if _, exists := detector.homoglyphMap['o']; !exists {
		t.Error("Expected 'o' to have homoglyphs")
	}
}

func TestHomoglyphDetector_Detect(t *testing.T) {
	detector := NewHomoglyphDetector()

	tests := []struct {
		name            string
		target          types.Dependency
		allPackages     []string
		expectedThreats int
		minConfidence   float64
	}{
		{
			name: "detects Cyrillic homoglyph attack",
			target: types.Dependency{
				Name:     "еxpress", // Cyrillic 'е' instead of Latin 'e'
				Version:  "1.0.0",
				Registry: "npm",
			},
			allPackages:     []string{"express", "lodash", "react"},
			expectedThreats: 1,
			minConfidence:   0.7,
		},
		{
			name: "detects Greek homoglyph attack",
			target: types.Dependency{
				Name:     "εxpress", // Greek 'ε' instead of Latin 'e'
				Version:  "1.0.0",
				Registry: "npm",
			},
			allPackages:     []string{"express", "lodash", "react"},
			expectedThreats: 1,
			minConfidence:   0.7,
		},
		{
			name: "detects multiple character homoglyphs",
			target: types.Dependency{
				Name:     "rеаct", // Cyrillic 'р', 'е', 'а' instead of Latin
				Version:  "1.0.0",
				Registry: "npm",
			},
			allPackages:     []string{"express", "lodash", "react"},
			expectedThreats: 1,
			minConfidence:   0.7,
		},
		{
			name: "no detection for legitimate package",
			target: types.Dependency{
				Name:     "express",
				Version:  "1.0.0",
				Registry: "npm",
			},
			allPackages:     []string{"express", "lodash", "react"},
			expectedThreats: 0,
			minConfidence:   0.7,
		},
		{
			name: "no detection for different package",
			target: types.Dependency{
				Name:     "completely-different",
				Version:  "1.0.0",
				Registry: "npm",
			},
			allPackages:     []string{"express", "lodash", "react"},
			expectedThreats: 0,
			minConfidence:   0.7,
		},
		{
			name: "detection with moderate confidence",
			target: types.Dependency{
				Name:     "еxprеss", // Mixed homoglyphs
				Version:  "1.0.0",
				Registry: "npm",
			},
			allPackages:     []string{"express", "lodash", "react"},
			expectedThreats: 1,
			minConfidence:   0.85,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			threats := detector.Detect(tt.target, tt.allPackages)

			if len(threats) != tt.expectedThreats {
				t.Errorf("Expected %d threats, got %d", tt.expectedThreats, len(threats))
			}

			for _, threat := range threats {
				if threat.Type != types.ThreatTypeHomoglyph {
					t.Errorf("Expected threat type %s, got %s", types.ThreatTypeHomoglyph, threat.Type)
				}

				if threat.Confidence < tt.minConfidence {
					t.Errorf("Expected confidence >= %f, got %f", tt.minConfidence, threat.Confidence)
				}
			}
		})
	}
}

func TestHomoglyphDetector_generateHomoglyphVariants(t *testing.T) {
	detector := NewHomoglyphDetector()

	tests := []struct {
		name             string
		input            string
		expectedVariants int
		shouldContain    []string
	}{
		{
			name:             "single character with homoglyphs",
			input:            "a",
			expectedVariants: 3,                       // a has Cyrillic, Greek, and other variants
			shouldContain:    []string{"а", "ɑ", "α"}, // Cyrillic 'а', Latin 'ɑ', Greek 'α'
		},
		{
			name:             "multiple characters with homoglyphs",
			input:            "ae",
			expectedVariants: 5, // a has 3 variants, e has 2 variants
			shouldContain:    []string{"аe", "ɑe", "αe", "aе", "aε"},
		},
		{
			name:             "no homoglyphs",
			input:            "bdg",
			expectedVariants: 0,
			shouldContain:    []string{},
		},
		{
			name:             "mixed characters",
			input:            "test",
			expectedVariants: 6, // t(1) + e(2) + s(2) + t(1)
			shouldContain:    []string{"tеst", "tεst", "teѕt", "teσt", "τest"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			variants := detector.generateHomoglyphVariants(tt.input)

			if len(variants) != tt.expectedVariants {
				t.Errorf("Expected %d variants, got %d", tt.expectedVariants, len(variants))
			}

			for _, expected := range tt.shouldContain {
				found := false
				for _, variant := range variants {
					if variant == expected {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected variants to contain '%s', got %v", expected, variants)
				}
			}
		})
	}
}

func TestHomoglyphDetector_isHomoglyphVariant(t *testing.T) {
	detector := NewHomoglyphDetector()

	tests := []struct {
		name     string
		s1       string
		s2       string
		expected bool
	}{
		{
			name:     "single homoglyph substitution",
			s1:       "express",
			s2:       "еxpress", // Cyrillic 'е'
			expected: true,
		},
		{
			name:     "multiple homoglyph substitutions",
			s1:       "react",
			s2:       "rеаct", // Cyrillic 'р', 'е', 'а'
			expected: true,
		},
		{
			name:     "no homoglyphs",
			s1:       "test",
			s2:       "test",
			expected: false,
		},
		{
			name:     "different length",
			s1:       "test",
			s2:       "testing",
			expected: false,
		},
		{
			name:     "non-homoglyph difference",
			s1:       "test",
			s2:       "tost",
			expected: false,
		},
		{
			name:     "too many homoglyph substitutions",
			s1:       "test",
			s2:       "tеstіng", // More than 3 differences
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.isHomoglyphVariant(tt.s1, tt.s2)
			if result != tt.expected {
				t.Errorf("Expected %t, got %t", tt.expected, result)
			}
		})
	}
}

func TestHomoglyphDetector_areHomoglyphs(t *testing.T) {
	detector := NewHomoglyphDetector()

	tests := []struct {
		name     string
		char1    rune
		char2    rune
		expected bool
	}{
		{
			name:     "Latin a and Cyrillic а",
			char1:    'a',
			char2:    'а', // Cyrillic 'а'
			expected: true,
		},
		{
			name:     "Latin e and Greek ε",
			char1:    'e',
			char2:    'ε', // Greek 'ε'
			expected: true,
		},
		{
			name:     "Latin o and digit 0",
			char1:    'o',
			char2:    '0',
			expected: true,
		},
		{
			name:     "Same character",
			char1:    'a',
			char2:    'a',
			expected: false, // Same character is not a homoglyph pair
		},
		{
			name:     "Different non-homoglyph characters",
			char1:    'a',
			char2:    'b',
			expected: false,
		},
		{
			name:     "Reverse order check",
			char1:    'а', // Cyrillic 'а'
			char2:    'a',
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.areHomoglyphs(tt.char1, tt.char2)
			if result != tt.expected {
				t.Errorf("Expected %t, got %t", tt.expected, result)
			}
		})
	}
}

func TestHomoglyphDetector_calculateHomoglyphConfidence(t *testing.T) {
	detector := NewHomoglyphDetector()

	tests := []struct {
		name     string
		s1       string
		s2       string
		expected float64
	}{
		{
			name:     "perfect homoglyph variant",
			s1:       "test",
			s2:       "tеst", // One homoglyph
			expected: 0.85,   // 0.8 base + 0.05 for 1/4 characters
		},
		{
			name:     "multiple homoglyphs",
			s1:       "test",
			s2:       "tеst", // Still one homoglyph (same as above)
			expected: 0.85,
		},
		{
			name:     "different length",
			s1:       "test",
			s2:       "testing",
			expected: 0.0,
		},
		{
			name:     "no homoglyphs",
			s1:       "test",
			s2:       "test",
			expected: 0.0,
		},
		{
			name:     "non-homoglyph difference",
			s1:       "test",
			s2:       "tost",
			expected: 0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.calculateHomoglyphConfidence(tt.s1, tt.s2)
			if math.Abs(result-tt.expected) > 1e-6 {
				t.Errorf("Expected %f, got %f", tt.expected, result)
			}
		})
	}
}

func TestHomoglyphDetector_calculateHomoglyphSeverity(t *testing.T) {
	detector := NewHomoglyphDetector()

	tests := []struct {
		name       string
		confidence float64
		expected   types.Severity
	}{
		{
			name:       "critical confidence",
			confidence: 0.95,
			expected:   types.SeverityCritical,
		},
		{
			name:       "high confidence",
			confidence: 0.85,
			expected:   types.SeverityHigh,
		},
		{
			name:       "medium confidence",
			confidence: 0.75,
			expected:   types.SeverityMedium,
		},
		{
			name:       "low confidence",
			confidence: 0.5,
			expected:   types.SeverityLow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.calculateHomoglyphSeverity(tt.confidence)
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestHomoglyphDetector_buildHomoglyphEvidence(t *testing.T) {
	detector := NewHomoglyphDetector()

	evidence := detector.buildHomoglyphEvidence("express", "еxpress")

	if len(evidence) != 1 {
		t.Errorf("Expected 1 evidence item, got %d", len(evidence))
	}

	if len(evidence) > 0 {
		ev := evidence[0]
		if ev.Type != "homoglyph_substitution" {
			t.Errorf("Expected evidence type 'homoglyph_substitution', got '%s'", ev.Type)
		}

		if ev.Score != 0.9 {
			t.Errorf("Expected evidence score 0.9, got %f", ev.Score)
		}

		if ev.Value == nil {
			t.Error("Expected evidence to have value")
		}
	}
}

func TestHomoglyphDetector_normalizeForComparison(t *testing.T) {
	detector := NewHomoglyphDetector()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "normalize Cyrillic homoglyphs",
			input:    "еxprеss", // Cyrillic 'е'
			expected: "express",
		},
		{
			name:     "normalize Greek homoglyphs",
			input:    "εxprεss", // Greek 'ε'
			expected: "express",
		},
		{
			name:     "mixed homoglyphs",
			input:    "rеаct", // Cyrillic 'р', 'е', 'а'
			expected: "react",
		},
		{
			name:     "no homoglyphs",
			input:    "express",
			expected: "express",
		},
		{
			name:     "uppercase normalization",
			input:    "EXPRESS",
			expected: "express",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.normalizeForComparison(tt.input)
			if result != tt.expected {
				t.Errorf("Expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

func TestGetUnicodeScript(t *testing.T) {
	tests := []struct {
		name     string
		char     rune
		expected string
	}{
		{name: "Latin a", char: 'a', expected: "Latin"},
		{name: "Cyrillic а", char: 'а', expected: "Cyrillic"}, // Cyrillic 'а'
		{name: "Greek α", char: 'α', expected: "Greek"},       // Greek 'α'
		{name: "Digit 1", char: '1', expected: "Digit"},
		{name: "Symbol dash", char: '-', expected: "Symbol"},
		{name: "Symbol at", char: '@', expected: "Symbol"},
		{name: "Arabic character", char: '\u0600', expected: "Arabic"}, // Arabic character
		{name: "Hebrew character", char: '\u05D0', expected: "Hebrew"}, // Hebrew character
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getUnicodeScript(tt.char)
			if result != tt.expected {
				t.Errorf("Expected script '%s' for character '%c', got '%s'", tt.expected, tt.char, result)
			}
		})
	}
}

func TestHomoglyphDetector_detectMixedScripts(t *testing.T) {
	detector := NewHomoglyphDetector()

	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "single script",
			input:    "express",
			expected: false,
		},
		{
			name:     "mixed Latin and Cyrillic",
			input:    "еxpress", // Cyrillic 'е' + Latin
			expected: true,
		},
		{
			name:     "mixed Latin and Greek",
			input:    "εxpress", // Greek 'ε' + Latin
			expected: true,
		},
		{
			name:     "only symbols and digits",
			input:    "test-123",
			expected: false,
		},
		{
			name:     "mixed with symbols",
			input:    "еxprеss", // Cyrillic + Latin, symbols ignored
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.detectMixedScripts(tt.input)
			if result != tt.expected {
				t.Errorf("Expected %t, got %t", tt.expected, result)
			}
		})
	}
}
