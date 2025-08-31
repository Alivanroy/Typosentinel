package ml

import (
	"regexp"
	"strings"
	"unicode"
)

// Helper functions for enhanced ML algorithms

// Mathematical utility functions
func (ema *EnhancedMLAlgorithms) min3(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}

func (ema *EnhancedMLAlgorithms) minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (ema *EnhancedMLAlgorithms) maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func (ema *EnhancedMLAlgorithms) minInt3(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}

// String processing utilities
func (ema *EnhancedMLAlgorithms) generateNGrams(s string, n int) map[string]int {
	ngrams := make(map[string]int)
	if len(s) < n {
		ngrams[s] = 1
		return ngrams
	}

	for i := 0; i <= len(s)-n; i++ {
		ngram := s[i : i+n]
		ngrams[ngram]++
	}
	return ngrams
}

func (ema *EnhancedMLAlgorithms) cosineSimilarity(ngrams1, ngrams2 map[string]int) float64 {
	// Calculate dot product
	dotProduct := 0
	for ngram, count1 := range ngrams1 {
		if count2, exists := ngrams2[ngram]; exists {
			dotProduct += count1 * count2
		}
	}

	// Calculate magnitudes
	magnitude1 := 0
	for _, count := range ngrams1 {
		magnitude1 += count * count
	}

	magnitude2 := 0
	for _, count := range ngrams2 {
		magnitude2 += count * count
	}

	if magnitude1 == 0 || magnitude2 == 0 {
		return 0.0
	}

	return float64(dotProduct) / (float64(magnitude1) * float64(magnitude2))
}

func (ema *EnhancedMLAlgorithms) soundex(s string) string {
	if len(s) == 0 {
		return ""
	}

	s = strings.ToUpper(s)
	result := string(s[0])

	// Soundex mapping
	mapping := map[rune]rune{
		'B': '1', 'F': '1', 'P': '1', 'V': '1',
		'C': '2', 'G': '2', 'J': '2', 'K': '2', 'Q': '2', 'S': '2', 'X': '2', 'Z': '2',
		'D': '3', 'T': '3',
		'L': '4',
		'M': '5', 'N': '5',
		'R': '6',
	}

	prev := '0'
	for _, char := range s[1:] {
		if code, exists := mapping[char]; exists {
			if code != prev {
				result += string(code)
				if len(result) == 4 {
					break
				}
			}
			prev = code
		} else {
			prev = '0'
		}
	}

	// Pad with zeros if necessary
	for len(result) < 4 {
		result += "0"
	}

	return result
}

func (ema *EnhancedMLAlgorithms) longestCommonPrefix(s1, s2 string) string {
	minLen := ema.minInt(len(s1), len(s2))
	for i := 0; i < minLen; i++ {
		if s1[i] != s2[i] {
			return s1[:i]
		}
	}
	return s1[:minLen]
}

func (ema *EnhancedMLAlgorithms) longestCommonSuffix(s1, s2 string) string {
	len1, len2 := len(s1), len(s2)
	minLen := ema.minInt(len1, len2)

	for i := 0; i < minLen; i++ {
		if s1[len1-1-i] != s2[len2-1-i] {
			return s1[len1-i:]
		}
	}
	return s1[len1-minLen:]
}

func (ema *EnhancedMLAlgorithms) extractWords(s string) []string {
	// Split on common separators and case changes
	var words []string
	var current strings.Builder

	for i, char := range s {
		if char == '-' || char == '_' || char == '.' {
			if current.Len() > 0 {
				words = append(words, current.String())
				current.Reset()
			}
		} else if i > 0 && unicode.IsUpper(char) && unicode.IsLower(rune(s[i-1])) {
			if current.Len() > 0 {
				words = append(words, current.String())
				current.Reset()
			}
			current.WriteRune(unicode.ToLower(char))
		} else {
			current.WriteRune(unicode.ToLower(char))
		}
	}

	if current.Len() > 0 {
		words = append(words, current.String())
	}

	return words
}

func (ema *EnhancedMLAlgorithms) calculateWordSimilarity(words1, words2 []string) float64 {
	if len(words1) == 0 || len(words2) == 0 {
		return 0.0
	}

	matches := 0
	for _, word1 := range words1 {
		for _, word2 := range words2 {
			if word1 == word2 {
				matches++
				break
			}
		}
	}

	return float64(matches) / float64(ema.maxInt(len(words1), len(words2)))
}

func (ema *EnhancedMLAlgorithms) containsAnyTerm(s string, terms []string) bool {
	s = strings.ToLower(s)
	for _, term := range terms {
		if strings.Contains(s, strings.ToLower(term)) {
			return true
		}
	}
	return false
}

// Typosquatting detection helpers
func (ema *EnhancedMLAlgorithms) hasCharacterSubstitutions(s1, s2 string) bool {
	// Common character substitutions in typosquatting
	substitutions := map[rune][]rune{
		'0': {'o', 'O'},
		'1': {'l', 'I'},
		'5': {'s', 'S'},
		'3': {'e', 'E'},
		'a': {'@'},
		'e': {'3'},
		'i': {'1', '!'},
		'o': {'0'},
		's': {'5', '$'},
	}

	if len(s1) != len(s2) {
		return false
	}

	differences := 0
	for i := 0; i < len(s1); i++ {
		if s1[i] != s2[i] {
			differences++
			if differences > 2 {
				return false
			}

			// Check if it's a common substitution
			if subs, exists := substitutions[rune(s1[i])]; exists {
				found := false
				for _, sub := range subs {
					if rune(s2[i]) == sub {
						found = true
						break
					}
				}
				if !found {
					return false
				}
			} else {
				return false
			}
		}
	}

	return differences > 0 && differences <= 2
}

func (ema *EnhancedMLAlgorithms) hasInsertionDeletionPatterns(s1, s2 string) bool {
	// Check for single character insertions or deletions
	lenDiff := len(s1) - len(s2)
	if lenDiff < -1 || lenDiff > 1 {
		return false
	}

	if lenDiff == 0 {
		return false // No insertion/deletion
	}

	longer, shorter := s1, s2
	if lenDiff < 0 {
		longer, shorter = s2, s1
	}

	// Try to find the insertion point
	for i := 0; i < len(longer); i++ {
		if i < len(shorter) && longer[i] != shorter[i] {
			// Check if removing this character makes them equal
			candidate := longer[:i] + longer[i+1:]
			return candidate == shorter
		}
	}

	return true // Insertion at the end
}

// Suspicious pattern detection helpers
func (ema *EnhancedMLAlgorithms) hasSuspiciousNaming(name string) bool {
	suspiciousPatterns := []string{
		`^[a-z]+\d+$`,         // letters followed by numbers
		`^[a-z]{1,3}\d{3,}$`,  // short letters with many numbers
		`^test[a-z]*$`,        // starts with "test"
		`^temp[a-z]*$`,        // starts with "temp"
		`^[a-z]*admin[a-z]*$`, // contains "admin"
		`^[a-z]*hack[a-z]*$`,  // contains "hack"
	}

	for _, pattern := range suspiciousPatterns {
		if matched, _ := regexp.MatchString(pattern, strings.ToLower(name)); matched {
			return true
		}
	}

	return false
}

func (ema *EnhancedMLAlgorithms) hasSuspiciousDescription(description string) bool {
	if len(description) < 5 {
		return true
	}

	suspiciousKeywords := []string{
		"test", "temp", "temporary", "placeholder", "example",
		"hack", "crack", "exploit", "malware", "virus",
		"backdoor", "trojan", "keylogger", "stealer",
	}

	desc := strings.ToLower(description)
	for _, keyword := range suspiciousKeywords {
		if strings.Contains(desc, keyword) {
			return true
		}
	}

	return false
}

func (ema *EnhancedMLAlgorithms) hasSuspiciousAuthor(author string) bool {
	if len(author) < 2 {
		return true
	}

	suspiciousPatterns := []string{
		`^[a-z]+\d+$`,   // letters followed by numbers
		`^user\d+$`,     // user followed by numbers
		`^test[a-z]*$`,  // starts with test
		`^admin[a-z]*$`, // starts with admin
	}

	for _, pattern := range suspiciousPatterns {
		if matched, _ := regexp.MatchString(pattern, strings.ToLower(author)); matched {
			return true
		}
	}

	return false
}

func (ema *EnhancedMLAlgorithms) hasSuspiciousVersion(version string) bool {
	suspiciousPatterns := []string{
		`^0\.0\.1$`,            // very early version
		`^1\.0\.0$`,            // exactly 1.0.0 (could be placeholder)
		`^\d+\.\d+\.\d+-test$`, // test versions
		`^\d+\.\d+\.\d+-dev$`,  // dev versions
	}

	for _, pattern := range suspiciousPatterns {
		if matched, _ := regexp.MatchString(pattern, version); matched {
			return true
		}
	}

	return false
}

func (ema *EnhancedMLAlgorithms) hasGenericDescription(description string) bool {
	genericPhrases := []string{
		"a package",
		"this package",
		"simple package",
		"basic package",
		"package for",
		"test package",
		"example package",
		"placeholder",
		"todo",
		"coming soon",
	}

	desc := strings.ToLower(description)
	for _, phrase := range genericPhrases {
		if strings.Contains(desc, phrase) {
			return true
		}
	}

	return false
}

// Initialization functions
func initializeMaliciousHashes() map[string]bool {
	// Initialize with known malicious package hashes
	return map[string]bool{
		// Add known malicious hashes here
		"example_malicious_hash_1": true,
		"example_malicious_hash_2": true,
		// These would be populated from threat intelligence feeds
	}
}

func initializeSuspiciousPatterns() []*regexp.Regexp {
	patterns := []string{
		`^[a-z]+\d+$`,                    // letters followed by numbers
		`^[a-z]+[A-Z][a-z]*$`,            // camelCase variations
		`^[a-z]+-[a-z]+\d+$`,             // hyphenated with numbers
		`^[a-z]+_[a-z]+\d+$`,             // underscore with numbers
		`^[a-z]{1,3}[0-9]{3,}$`,          // short letters with many numbers
		`^[a-z]+[0-9]+[a-z]+$`,           // letters-numbers-letters pattern
		`^(test|temp|admin|hack)[a-z]*$`, // suspicious prefixes
	}

	var regexps []*regexp.Regexp
	for _, pattern := range patterns {
		if re, err := regexp.Compile(pattern); err == nil {
			regexps = append(regexps, re)
		}
	}

	return regexps
}

func initializeTyposquattingPatterns() []*regexp.Regexp {
	patterns := []string{
		`^[a-z]*[0-9]+[a-z]*$`,       // contains numbers
		`^[a-z]*[_-][a-z]*$`,         // contains separators
		`^[a-z]*[A-Z][a-z]*$`,        // mixed case
		`^[a-z]*[!@#$%^&*()][a-z]*$`, // special characters
	}

	var regexps []*regexp.Regexp
	for _, pattern := range patterns {
		if re, err := regexp.Compile(pattern); err == nil {
			regexps = append(regexps, re)
		}
	}

	return regexps
}

func initializeFeatureWeights() map[string]float64 {
	return map[string]float64{
		"name_similarity":   0.3,
		"pattern_analysis":  0.2,
		"behavioral_score":  0.2,
		"metadata_analysis": 0.15,
		"reputation_score":  0.15,
	}
}
