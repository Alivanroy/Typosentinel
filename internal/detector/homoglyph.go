package detector

import (
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// HomoglyphDetector detects homoglyph-based typosquatting attacks
type HomoglyphDetector struct {
	homoglyphMap map[rune][]rune
}

// NewHomoglyphDetector creates a new homoglyph detector
func NewHomoglyphDetector() *HomoglyphDetector {
	return &HomoglyphDetector{
		homoglyphMap: buildHomoglyphMap(),
	}
}

// Detect finds potential homoglyph-based typosquatting
func (hd *HomoglyphDetector) Detect(target types.Dependency, allPackages []string) []types.Threat {
	var threats []types.Threat

	// Check if any existing packages match homoglyph variants
	for _, pkg := range allPackages {
		if pkg == target.Name {
			continue
		}

		// Check if this package could be a homoglyph variant
		if hd.isHomoglyphVariant(target.Name, pkg) {
			confidence := hd.calculateHomoglyphConfidence(target.Name, pkg)
			if confidence > 0.7 {
				threat := types.Threat{
					ID:              generateThreatID(),
					Package:         target.Name,
					Version:         target.Version,
					Registry:        target.Registry,
					Type:            types.ThreatTypeHomoglyph,
					Severity:        hd.calculateHomoglyphSeverity(confidence),
					Confidence:      confidence,
					Description:     fmt.Sprintf("Package '%s' uses homoglyph characters that make it visually similar to '%s'", target.Name, pkg),
					SimilarTo:       pkg,
					Recommendation:  fmt.Sprintf("Carefully verify package name. The intended package might be '%s' instead of '%s'.", pkg, target.Name),
					DetectedAt:      time.Now(),
					DetectionMethod: "homoglyph_detection",
					Evidence:        hd.buildHomoglyphEvidence(target.Name, pkg),
				}
				threats = append(threats, threat)
			}
		}
	}

	return threats
}

// generateHomoglyphVariants generates possible homoglyph variants of a string
func (hd *HomoglyphDetector) generateHomoglyphVariants(s string) []string {
	var variants []string

	runes := []rune(s)
	// For each rune, try replacing with homoglyphs
	for i, char := range runes {
		if homoglyphs, exists := hd.homoglyphMap[char]; exists {
			for _, homoglyph := range homoglyphs {
				replaced := make([]rune, len(runes))
				copy(replaced, runes)
				replaced[i] = homoglyph
				variants = append(variants, string(replaced))
			}
		}
	}

	return variants
}

// isHomoglyphVariant checks if two strings are homoglyph variants
func (hd *HomoglyphDetector) isHomoglyphVariant(s1, s2 string) bool {
	r1 := []rune(s1)
	r2 := []rune(s2)
	if len(r1) != len(r2) {
		return false
	}

	differences := 0
	for i := range r1 {
		char1 := r1[i]
		char2 := r2[i]
		if char1 != char2 {
			if !hd.areHomoglyphs(char1, char2) {
				return false
			}
			differences++
		}
	}

	return differences > 0 && differences <= 3
}

// areHomoglyphs checks if two characters are homoglyphs
func (hd *HomoglyphDetector) areHomoglyphs(char1, char2 rune) bool {
	if homoglyphs, exists := hd.homoglyphMap[char1]; exists {
		for _, h := range homoglyphs {
			if h == char2 {
				return true
			}
		}
	}

	if homoglyphs, exists := hd.homoglyphMap[char2]; exists {
		for _, h := range homoglyphs {
			if h == char1 {
				return true
			}
		}
	}

	return false
}

// calculateHomoglyphConfidence calculates confidence score for homoglyph detection
func (hd *HomoglyphDetector) calculateHomoglyphConfidence(s1, s2 string) float64 {
	r1 := []rune(s1)
	r2 := []rune(s2)
	if len(r1) != len(r2) {
		return 0.0
	}

	totalChars := len(r1)
	homoglyphChars := 0

	for i := range r1 {
		char1 := r1[i]
		char2 := r2[i]
		if char1 != char2 && hd.areHomoglyphs(char1, char2) {
			homoglyphChars++
		} else if char1 != char2 {
			return 0.0
		}
	}

	if homoglyphChars == 0 {
		return 0.0
	}

	confidence := 0.8 + 0.2*(float64(homoglyphChars)/float64(totalChars))
	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}

// calculateHomoglyphSeverity determines severity based on confidence
func (hd *HomoglyphDetector) calculateHomoglyphSeverity(confidence float64) types.Severity {
	if confidence >= 0.95 {
		return types.SeverityCritical
	} else if confidence >= 0.85 {
		return types.SeverityHigh
	} else if confidence >= 0.75 {
		return types.SeverityMedium
	}
	return types.SeverityLow
}

// buildHomoglyphEvidence builds evidence for homoglyph detection
func (hd *HomoglyphDetector) buildHomoglyphEvidence(s1, s2 string) []types.Evidence {
	var evidence []types.Evidence

	r1 := []rune(s1)
	r2 := []rune(s2)
	l := len(r1)
	if l != len(r2) {
		return evidence
	}

	for i := 0; i < l; i++ {
		char1 := r1[i]
		char2 := r2[i]
		if char1 != char2 && hd.areHomoglyphs(char1, char2) {
			evidence = append(evidence, types.Evidence{
				Type:        "homoglyph_substitution",
				Description: fmt.Sprintf("Character '%c' (U+%04X) replaced with '%c' (U+%04X) at position %d", char1, char1, char2, char2, i),
				Value: map[string]interface{}{
					"original":           string(char1),
					"substitute":         string(char2),
					"position":           i,
					"original_unicode":   fmt.Sprintf("U+%04X", char1),
					"substitute_unicode": fmt.Sprintf("U+%04X", char2),
				},
				Score: 0.9,
			})
		}
	}

	return evidence
}

// buildHomoglyphMap creates a mapping of characters to their homoglyphs
func buildHomoglyphMap() map[rune][]rune {
	homoglyphs := map[rune][]rune{
		// Latin to Cyrillic homoglyphs
		'a': {'а', 'ɑ', 'α'},           // Latin 'a' vs Cyrillic 'а', Greek 'α'
		'e': {'е', 'ε'},                // Latin 'e' vs Cyrillic 'е', Greek 'ε'
		'o': {'о', 'ο', '0'},           // Latin 'o' vs Cyrillic 'о', Greek 'ο', digit '0'
		'p': {'р', 'ρ'},                // Latin 'p' vs Cyrillic 'р', Greek 'ρ'
		'c': {'с', 'ϲ'},                // Latin 'c' vs Cyrillic 'с', Greek 'ϲ'
		'x': {'х', 'χ'},                // Latin 'x' vs Cyrillic 'х', Greek 'χ'
		'y': {'у', 'γ'},                // Latin 'y' vs Cyrillic 'у', Greek 'γ'
		'i': {'і', 'ι', '1', 'l', '|'}, // Latin 'i' vs Cyrillic 'і', Greek 'ι', digit '1', 'l', pipe
		'j': {'ј'},                     // Latin 'j' vs Cyrillic 'ј'
		's': {'ѕ', 'σ'},                // Latin 's' vs Cyrillic 'ѕ', Greek 'σ'
		'h': {'һ'},                     // Latin 'h' vs Cyrillic 'һ'
		'k': {'κ'},                     // Latin 'k' vs Greek 'κ'
		'n': {'η'},                     // Latin 'n' vs Greek 'η'
		'm': {'м'},                     // Latin 'm' vs Cyrillic 'м'
		'r': {'г'},                     // Latin 'r' vs Cyrillic 'г'
		't': {'τ'},                     // Latin 't' vs Greek 'τ'
		'u': {'υ'},                     // Latin 'u' vs Greek 'υ'
		'v': {'ν'},                     // Latin 'v' vs Greek 'ν'
		'w': {'ω'},                     // Latin 'w' vs Greek 'ω'
		'z': {'ζ'},                     // Latin 'z' vs Greek 'ζ'

		// Uppercase variants
		'A': {'А', 'Α'}, // Latin 'A' vs Cyrillic 'А', Greek 'Α'
		'B': {'В', 'Β'}, // Latin 'B' vs Cyrillic 'В', Greek 'Β'
		'C': {'С'},      // Latin 'C' vs Cyrillic 'С'
		'E': {'Е', 'Ε'}, // Latin 'E' vs Cyrillic 'Е', Greek 'Ε'
		'H': {'Н', 'Η'}, // Latin 'H' vs Cyrillic 'Н', Greek 'Η'
		'I': {'І', 'Ι'}, // Latin 'I' vs Cyrillic 'І', Greek 'Ι'
		'J': {'Ј'},      // Latin 'J' vs Cyrillic 'Ј'
		'K': {'К', 'Κ'}, // Latin 'K' vs Cyrillic 'К', Greek 'Κ'
		'M': {'М', 'Μ'}, // Latin 'M' vs Cyrillic 'М', Greek 'Μ'
		'N': {'Ν'},      // Latin 'N' vs Greek 'Ν'
		'O': {'О', 'Ο'}, // Latin 'O' vs Cyrillic 'О', Greek 'Ο'
		'P': {'Р', 'Ρ'}, // Latin 'P' vs Cyrillic 'Р', Greek 'Ρ'
		'S': {'Ѕ'},      // Latin 'S' vs Cyrillic 'Ѕ'
		'T': {'Т', 'Τ'}, // Latin 'T' vs Cyrillic 'Т', Greek 'Τ'
		'X': {'Х', 'Χ'}, // Latin 'X' vs Cyrillic 'Х', Greek 'Χ'
		'Y': {'У', 'Υ'}, // Latin 'Y' vs Cyrillic 'У', Greek 'Υ'
		'Z': {'Ζ'},      // Latin 'Z' vs Greek 'Ζ'

		// Numbers and symbols
		'0': {'О', 'о', 'Ο', 'ο'}, // Digit '0' vs letters
		'1': {'l', 'I', 'і', '|'}, // Digit '1' vs letters
		'2': {'Ζ'},                // Digit '2' vs Greek 'Ζ'
		'3': {'Ε'},                // Digit '3' vs Greek 'Ε'
		'5': {'Ѕ'},                // Digit '5' vs Cyrillic 'Ѕ'
		'6': {'б'},                // Digit '6' vs Cyrillic 'б'

		// Special characters that look similar
		'-': {'‐', '‑', '‒', '–', '—', '―'}, // Various dash types
		'_': {'‿'},                          // Underscore variants
		'.': {'․', '‧'},                     // Period variants
	}

	// Add reverse mappings
	reverse := make(map[rune][]rune)
	for original, variants := range homoglyphs {
		for _, variant := range variants {
			if _, exists := reverse[variant]; !exists {
				reverse[variant] = []rune{}
			}
			reverse[variant] = append(reverse[variant], original)
		}
	}

	// Merge reverse mappings
	for char, variants := range reverse {
		if _, exists := homoglyphs[char]; !exists {
			homoglyphs[char] = variants
		} else {
			homoglyphs[char] = append(homoglyphs[char], variants...)
		}
	}

	return homoglyphs
}

// isVisuallyConfusing checks if a character substitution would be visually confusing
func (hd *HomoglyphDetector) isVisuallyConfusing(original, substitute rune) bool {
	// Check if characters are in different scripts but look similar
	originalScript := getUnicodeScript(original)
	substituteScript := getUnicodeScript(substitute)

	// Different scripts with similar appearance are more suspicious
	return originalScript != substituteScript && hd.areHomoglyphs(original, substitute)
}

// getUnicodeScript determines the Unicode script of a character
func getUnicodeScript(r rune) string {
	switch {
	case unicode.In(r, unicode.Latin):
		return "Latin"
	case unicode.In(r, unicode.Cyrillic):
		return "Cyrillic"
	case unicode.In(r, unicode.Greek):
		return "Greek"
	case unicode.In(r, unicode.Arabic):
		return "Arabic"
	case unicode.In(r, unicode.Hebrew):
		return "Hebrew"
	case unicode.In(r, unicode.Han):
		return "Han"
	case unicode.In(r, unicode.Hiragana):
		return "Hiragana"
	case unicode.In(r, unicode.Katakana):
		return "Katakana"
	case unicode.IsDigit(r):
		return "Digit"
	case unicode.IsSymbol(r) || unicode.IsPunct(r):
		return "Symbol"
	default:
		return "Unknown"
	}
}

// detectMixedScripts detects packages using mixed scripts (potential homoglyph attack)
func (hd *HomoglyphDetector) detectMixedScripts(packageName string) bool {
	scripts := make(map[string]bool)

	for _, char := range packageName {
		script := getUnicodeScript(char)
		if script != "Symbol" && script != "Digit" { // Ignore symbols and digits
			scripts[script] = true
		}
	}

	// Suspicious if more than one script is used
	return len(scripts) > 1
}

// normalizeForComparison normalizes strings for homoglyph comparison
func (hd *HomoglyphDetector) normalizeForComparison(s string) string {
	// Convert to lowercase and normalize similar characters
	normalized := strings.ToLower(s)

	// Replace common homoglyphs with their Latin equivalents
	replacements := map[string]string{
		"а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
		"х": "x", "у": "y", "і": "i", "ј": "j", "ѕ": "s",
		"α": "a", "ε": "e", "ο": "o", "ρ": "p", "ϲ": "c",
		"χ": "x", "γ": "y", "ι": "i", "σ": "s", "κ": "k",
		"η": "n", "τ": "t", "υ": "u", "ν": "v", "ω": "w", "ζ": "z",
	}

	for homoglyph, latin := range replacements {
		normalized = strings.ReplaceAll(normalized, homoglyph, latin)
	}

	return normalized
}
