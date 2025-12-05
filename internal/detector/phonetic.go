package detector

import "strings"

// phoneticSimilarity analyzes phonetic similarity
func (etd *EnhancedTyposquattingDetector) phoneticSimilarity(s1, s2 string) float64 {
	if len(s1) == 0 || len(s2) == 0 {
		return 0.0
	}

	// Convert to phonetic representations
	phonetic1 := etd.toPhoneticForm(s1)
	phonetic2 := etd.toPhoneticForm(s2)

	// Calculate similarity based on phonetic substitutions
	return etd.substitutionSimilarity(phonetic1, phonetic2, "phonetic")
}

// toPhoneticForm converts string to phonetic representation
func (etd *EnhancedTyposquattingDetector) toPhoneticForm(s string) string {
	result := strings.Builder{}
	for _, r := range s {
		// Apply phonetic substitutions
		substituted := false
		for _, sub := range etd.substitutions {
			if sub.Type == "phonetic" {
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
