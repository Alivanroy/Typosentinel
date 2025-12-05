package detector

import "strings"

// visualSimilarity analyzes visual character similarity
func (etd *EnhancedTyposquattingDetector) visualSimilarity(s1, s2 string) float64 {
	if len(s1) == 0 || len(s2) == 0 {
		return 0.0
	}

	// Convert to normalized forms for visual comparison
	norm1 := etd.normalizeForVisualComparison(s1)
	norm2 := etd.normalizeForVisualComparison(s2)

	// Calculate similarity based on visual substitutions
	return etd.substitutionSimilarity(norm1, norm2, "visual")
}

// normalizeForVisualComparison normalizes strings for visual comparison
func (etd *EnhancedTyposquattingDetector) normalizeForVisualComparison(s string) string {
	result := strings.Builder{}
	for _, r := range s {
		// Apply visual substitutions
		substituted := false
		for _, sub := range etd.substitutions {
			if sub.Type == "visual" {
				for _, substitute := range sub.Substitutes {
					if r == substitute {
						result.WriteRune(sub.Original)
						substituted = true
						break
					}
				}
				if substituted {
					break
				}
			}
		}
		if !substituted {
			result.WriteRune(r)
		}
	}
	return result.String()
}
