package similarity

import (
	"math"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// SimilarityEngine provides various string similarity algorithms
type SimilarityEngine struct {
	config *Config
	homoglyphMap map[rune][]rune
	typoPatterns []*regexp.Regexp
}

// Config contains similarity engine configuration
type Config struct {
	DamerauLevenshteinThreshold float64 `yaml:"damerau_levenshtein_threshold"`
	JaroWinklerThreshold        float64 `yaml:"jaro_winkler_threshold"`
	HomoglyphDetection          bool    `yaml:"homoglyph_detection"`
	TypoPatternDetection        bool    `yaml:"typo_pattern_detection"`
	CaseSensitive               bool    `yaml:"case_sensitive"`
	NormalizeUnicode            bool    `yaml:"normalize_unicode"`
}

// SimilarityResult represents the result of similarity analysis
type SimilarityResult struct {
	Package1                string                 `json:"package1"`
	Package2                string                 `json:"package2"`
	DamerauLevenshtein      float64                `json:"damerau_levenshtein"`
	JaroWinkler             float64                `json:"jaro_winkler"`
	HomoglyphDetected       bool                   `json:"homoglyph_detected"`
	TypoPatterns            []TypoPattern          `json:"typo_patterns"`
	OverallSimilarity       float64                `json:"overall_similarity"`
	RiskScore               float64                `json:"risk_score"`
	SuspiciousFeatures      []string               `json:"suspicious_features"`
	Metadata                map[string]interface{} `json:"metadata"`
}

// TypoPattern represents detected typosquatting patterns
type TypoPattern struct {
	Type        string  `json:"type"`
	Description string  `json:"description"`
	Confidence  float64 `json:"confidence"`
	Position    int     `json:"position,omitempty"`
	Original    string  `json:"original,omitempty"`
	Modified    string  `json:"modified,omitempty"`
}

// NewSimilarityEngine creates a new similarity engine
func NewSimilarityEngine(config *Config) *SimilarityEngine {
	if config == nil {
		config = DefaultConfig()
	}
	
	engine := &SimilarityEngine{
		config: config,
		homoglyphMap: buildHomoglyphMap(),
		typoPatterns: buildTypoPatterns(),
	}
	
	return engine
}

// DefaultConfig returns default similarity engine configuration
func DefaultConfig() *Config {
	return &Config{
		DamerauLevenshteinThreshold: 0.8,
		JaroWinklerThreshold:        0.9,
		HomoglyphDetection:          true,
		TypoPatternDetection:        true,
		CaseSensitive:               false,
		NormalizeUnicode:            true,
	}
}

// AnalyzeSimilarity performs comprehensive similarity analysis
func (se *SimilarityEngine) AnalyzeSimilarity(pkg1, pkg2 string) *SimilarityResult {
	// Normalize inputs
	norm1 := se.normalizeString(pkg1)
	norm2 := se.normalizeString(pkg2)
	
	result := &SimilarityResult{
		Package1:           pkg1,
		Package2:           pkg2,
		SuspiciousFeatures: []string{},
		Metadata:           make(map[string]interface{}),
	}
	
	// Calculate Damerau-Levenshtein distance
	result.DamerauLevenshtein = se.DamerauLevenshteinSimilarity(norm1, norm2)
	
	// Calculate Jaro-Winkler similarity
	result.JaroWinkler = se.JaroWinklerSimilarity(norm1, norm2)
	
	// Detect homoglyphs
	if se.config.HomoglyphDetection {
		result.HomoglyphDetected = se.DetectHomoglyphs(norm1, norm2)
		if result.HomoglyphDetected {
			result.SuspiciousFeatures = append(result.SuspiciousFeatures, "homoglyph_attack")
		}
	}
	
	// Detect typo patterns
	if se.config.TypoPatternDetection {
		result.TypoPatterns = se.DetectTypoPatterns(norm1, norm2)
		if len(result.TypoPatterns) > 0 {
			result.SuspiciousFeatures = append(result.SuspiciousFeatures, "typo_patterns")
		}
	}
	
	// Calculate overall similarity
	result.OverallSimilarity = se.calculateOverallSimilarity(result)
	
	// Calculate risk score
	result.RiskScore = se.calculateRiskScore(result)
	
	return result
}

// DamerauLevenshteinSimilarity calculates Damerau-Levenshtein similarity
func (se *SimilarityEngine) DamerauLevenshteinSimilarity(s1, s2 string) float64 {
	distance := se.damerauLevenshteinDistance(s1, s2)
	maxLen := math.Max(float64(len(s1)), float64(len(s2)))
	if maxLen == 0 {
		return 1.0
	}
	return 1.0 - (float64(distance) / maxLen)
}

// JaroWinklerSimilarity calculates Jaro-Winkler similarity
func (se *SimilarityEngine) JaroWinklerSimilarity(s1, s2 string) float64 {
	if s1 == s2 {
		return 1.0
	}
	
	len1, len2 := len(s1), len(s2)
	if len1 == 0 || len2 == 0 {
		return 0.0
	}
	
	// Calculate match window
	matchWindow := (int(math.Max(float64(len1), float64(len2))) / 2) - 1
	if matchWindow < 0 {
		matchWindow = 0
	}
	
	// Track matches
	s1Matches := make([]bool, len1)
	s2Matches := make([]bool, len2)
	
	matches := 0
	transpositions := 0
	
	// Find matches
	for i := 0; i < len1; i++ {
		start := int(math.Max(0, float64(i-matchWindow)))
		end := int(math.Min(float64(i+matchWindow+1), float64(len2)))
		
		for j := start; j < end; j++ {
			if s2Matches[j] || s1[i] != s2[j] {
				continue
			}
			s1Matches[i] = true
			s2Matches[j] = true
			matches++
			break
		}
	}
	
	if matches == 0 {
		return 0.0
	}
	
	// Count transpositions
	k := 0
	for i := 0; i < len1; i++ {
		if !s1Matches[i] {
			continue
		}
		for !s2Matches[k] {
			k++
		}
		if s1[i] != s2[k] {
			transpositions++
		}
		k++
	}
	
	// Calculate Jaro similarity
	jaro := (float64(matches)/float64(len1) + float64(matches)/float64(len2) + float64(matches-transpositions/2)/float64(matches)) / 3.0
	
	// Calculate common prefix length (up to 4 characters)
	prefixLen := 0
	for i := 0; i < int(math.Min(float64(len1), math.Min(float64(len2), 4))); i++ {
		if s1[i] == s2[i] {
			prefixLen++
		} else {
			break
		}
	}
	
	// Calculate Jaro-Winkler similarity
	return jaro + (0.1 * float64(prefixLen) * (1.0 - jaro))
}

// DetectHomoglyphs detects homoglyph attacks
func (se *SimilarityEngine) DetectHomoglyphs(s1, s2 string) bool {
	if len(s1) != len(s2) {
		return false
	}
	
	runes1 := []rune(s1)
	runes2 := []rune(s2)
	
	if len(runes1) != len(runes2) {
		return false
	}
	
	homoglyphCount := 0
	for i := 0; i < len(runes1); i++ {
		if runes1[i] != runes2[i] {
			if se.areHomoglyphs(runes1[i], runes2[i]) {
				homoglyphCount++
			} else {
				return false
			}
		}
	}
	
	return homoglyphCount > 0
}

// DetectTypoPatterns detects common typosquatting patterns
func (se *SimilarityEngine) DetectTypoPatterns(s1, s2 string) []TypoPattern {
	var patterns []TypoPattern
	
	// Character substitution
	if subst := se.detectSubstitution(s1, s2); subst != nil {
		patterns = append(patterns, *subst)
	}
	
	// Character insertion
	if insert := se.detectInsertion(s1, s2); insert != nil {
		patterns = append(patterns, *insert)
	}
	
	// Character deletion
	if delete := se.detectDeletion(s1, s2); delete != nil {
		patterns = append(patterns, *delete)
	}
	
	// Character reordering
	if reorder := se.detectReordering(s1, s2); reorder != nil {
		patterns = append(patterns, *reorder)
	}
	
	// Prefix/suffix addition
	if prefix := se.detectPrefixSuffix(s1, s2); prefix != nil {
		patterns = append(patterns, *prefix)
	}
	
	// Delimiter changes
	if delim := se.detectDelimiterChanges(s1, s2); delim != nil {
		patterns = append(patterns, *delim)
	}
	
	// Case swaps
	if caseSwap := se.detectCaseSwaps(s1, s2); caseSwap != nil {
		patterns = append(patterns, *caseSwap)
	}
	
	return patterns
}

// normalizeString normalizes string for comparison
func (se *SimilarityEngine) normalizeString(s string) string {
	if !se.config.CaseSensitive {
		s = strings.ToLower(s)
	}
	
	if se.config.NormalizeUnicode {
		// Basic Unicode normalization
		s = strings.TrimSpace(s)
	}
	
	return s
}

// damerauLevenshteinDistance calculates Damerau-Levenshtein distance
func (se *SimilarityEngine) damerauLevenshteinDistance(s1, s2 string) int {
	len1, len2 := utf8.RuneCountInString(s1), utf8.RuneCountInString(s2)
	runes1, runes2 := []rune(s1), []rune(s2)
	
	// Create distance matrix
	matrix := make([][]int, len1+2)
	for i := range matrix {
		matrix[i] = make([]int, len2+2)
	}
	
	// Initialize matrix
	maxDist := len1 + len2
	matrix[0][0] = maxDist
	
	for i := 0; i <= len1; i++ {
		matrix[i+1][0] = maxDist
		matrix[i+1][1] = i
	}
	for j := 0; j <= len2; j++ {
		matrix[0][j+1] = maxDist
		matrix[1][j+1] = j
	}
	
	// Character frequency map
	charMap := make(map[rune]int)
	
	// Fill matrix
	for i := 1; i <= len1; i++ {
		db := 0
		for j := 1; j <= len2; j++ {
			k := charMap[runes2[j-1]]
			l := db
			cost := 1
			if runes1[i-1] == runes2[j-1] {
				cost = 0
				db = j
			}
			
			matrix[i+1][j+1] = min4(
				matrix[i][j]+cost,                    // substitution
				matrix[i+1][j]+1,                     // insertion
				matrix[i][j+1]+1,                     // deletion
				matrix[k][l]+(i-k-1)+1+(j-l-1),      // transposition
			)
		}
		charMap[runes1[i-1]] = i
	}
	
	return matrix[len1+1][len2+1]
}

// areHomoglyphs checks if two runes are homoglyphs
func (se *SimilarityEngine) areHomoglyphs(r1, r2 rune) bool {
	if homoglyphs, exists := se.homoglyphMap[r1]; exists {
		for _, h := range homoglyphs {
			if h == r2 {
				return true
			}
		}
	}
	return false
}

// buildHomoglyphMap creates a map of homoglyph characters
func buildHomoglyphMap() map[rune][]rune {
	return map[rune][]rune{
		'a': {'а', 'α', 'ɑ'},           // Latin a, Cyrillic а, Greek α, etc.
		'e': {'е', 'ε'},               // Latin e, Cyrillic е, Greek ε
		'o': {'о', 'ο', '0'},          // Latin o, Cyrillic о, Greek ο, digit 0
		'p': {'р', 'ρ'},               // Latin p, Cyrillic р, Greek ρ
		'c': {'с', 'ϲ'},               // Latin c, Cyrillic с, Greek ϲ
		'x': {'х', 'χ'},               // Latin x, Cyrillic х, Greek χ
		'y': {'у', 'γ'},               // Latin y, Cyrillic у, Greek γ
		'i': {'і', 'ι', '1', 'l'},     // Latin i, Cyrillic і, Greek ι, digit 1, Latin l
		'l': {'1', 'I', 'і'},          // Latin l, digit 1, Latin I, Cyrillic і
		'0': {'O', 'о', 'ο'},          // Digit 0, Latin O, Cyrillic о, Greek ο
		'1': {'l', 'I', 'і'},          // Digit 1, Latin l, Latin I, Cyrillic і
	}
}

// buildTypoPatterns creates regex patterns for typo detection
func buildTypoPatterns() []*regexp.Regexp {
	patterns := []string{
		// Common character substitutions
		`([a-z])\1+`,     // repeated characters
		`[0-9]+[a-z]+`,   // numbers mixed with letters
		`[a-z]+[0-9]+`,   // letters mixed with numbers
	}
	
	var compiled []*regexp.Regexp
	for _, pattern := range patterns {
		if re, err := regexp.Compile(pattern); err == nil {
			compiled = append(compiled, re)
		}
	}
	
	return compiled
}

// Helper functions for typo pattern detection
func (se *SimilarityEngine) detectSubstitution(s1, s2 string) *TypoPattern {
	if len(s1) != len(s2) {
		return nil
	}
	
	diffs := 0
	pos := -1
	for i, r1 := range s1 {
		if i < len(s2) && r1 != rune(s2[i]) {
			diffs++
			if pos == -1 {
				pos = i
			}
		}
	}
	
	if diffs == 1 {
		return &TypoPattern{
			Type:        "substitution",
			Description: "Single character substitution",
			Confidence:  0.9,
			Position:    pos,
			Original:    string(s1[pos]),
			Modified:    string(s2[pos]),
		}
	}
	
	return nil
}

func (se *SimilarityEngine) detectInsertion(s1, s2 string) *TypoPattern {
	if len(s2) != len(s1)+1 {
		return nil
	}
	
	for i := 0; i < len(s2); i++ {
		test := s2[:i] + s2[i+1:]
		if test == s1 {
			return &TypoPattern{
				Type:        "insertion",
				Description: "Single character insertion",
				Confidence:  0.9,
				Position:    i,
				Modified:    string(s2[i]),
			}
		}
	}
	
	return nil
}

func (se *SimilarityEngine) detectDeletion(s1, s2 string) *TypoPattern {
	if len(s1) != len(s2)+1 {
		return nil
	}
	
	for i := 0; i < len(s1); i++ {
		test := s1[:i] + s1[i+1:]
		if test == s2 {
			return &TypoPattern{
				Type:        "deletion",
				Description: "Single character deletion",
				Confidence:  0.9,
				Position:    i,
				Original:    string(s1[i]),
			}
		}
	}
	
	return nil
}

func (se *SimilarityEngine) detectReordering(s1, s2 string) *TypoPattern {
	if len(s1) != len(s2) || len(s1) < 2 {
		return nil
	}
	
	// Check for adjacent character swaps
	for i := 0; i < len(s1)-1; i++ {
		if s1[i] == s2[i+1] && s1[i+1] == s2[i] {
			// Check if rest of string matches
			if s1[:i] == s2[:i] && s1[i+2:] == s2[i+2:] {
				return &TypoPattern{
					Type:        "transposition",
					Description: "Adjacent character swap",
					Confidence:  0.95,
					Position:    i,
				}
			}
		}
	}
	
	return nil
}

func (se *SimilarityEngine) detectPrefixSuffix(s1, s2 string) *TypoPattern {
	// Check for prefix addition
	if strings.HasSuffix(s2, s1) && len(s2) > len(s1) {
		return &TypoPattern{
			Type:        "prefix_addition",
			Description: "Prefix added to package name",
			Confidence:  0.8,
			Modified:    s2[:len(s2)-len(s1)],
		}
	}
	
	// Check for suffix addition
	if strings.HasPrefix(s2, s1) && len(s2) > len(s1) {
		return &TypoPattern{
			Type:        "suffix_addition",
			Description: "Suffix added to package name",
			Confidence:  0.8,
			Modified:    s2[len(s1):],
		}
	}
	
	return nil
}

func (se *SimilarityEngine) detectDelimiterChanges(s1, s2 string) *TypoPattern {
	delimiters := []string{"-", "_", ".", ""}
	
	for _, d1 := range delimiters {
		for _, d2 := range delimiters {
			if d1 != d2 {
				if strings.ReplaceAll(s1, d1, d2) == s2 {
					return &TypoPattern{
						Type:        "delimiter_change",
						Description: "Delimiter character changed",
						Confidence:  0.85,
						Original:    d1,
						Modified:    d2,
					}
				}
			}
		}
	}
	
	return nil
}

func (se *SimilarityEngine) detectCaseSwaps(s1, s2 string) *TypoPattern {
	if strings.ToLower(s1) == strings.ToLower(s2) && s1 != s2 {
		return &TypoPattern{
			Type:        "case_swap",
			Description: "Case changes in package name",
			Confidence:  0.7,
		}
	}
	
	return nil
}

// calculateOverallSimilarity calculates weighted overall similarity
func (se *SimilarityEngine) calculateOverallSimilarity(result *SimilarityResult) float64 {
	weights := map[string]float64{
		"damerau_levenshtein": 0.4,
		"jaro_winkler":        0.4,
		"homoglyph_bonus":     0.1,
		"typo_pattern_bonus":  0.1,
	}
	
	score := result.DamerauLevenshtein*weights["damerau_levenshtein"] +
		result.JaroWinkler*weights["jaro_winkler"]
	
	if result.HomoglyphDetected {
		score += weights["homoglyph_bonus"]
	}
	
	if len(result.TypoPatterns) > 0 {
		score += weights["typo_pattern_bonus"]
	}
	
	return math.Min(score, 1.0)
}

// calculateRiskScore calculates risk score based on similarity features
func (se *SimilarityEngine) calculateRiskScore(result *SimilarityResult) float64 {
	risk := 0.0
	
	// High similarity is suspicious
	if result.OverallSimilarity > 0.8 {
		risk += 0.4
	} else if result.OverallSimilarity > 0.6 {
		risk += 0.2
	}
	
	// Homoglyph attacks are high risk
	if result.HomoglyphDetected {
		risk += 0.3
	}
	
	// Typo patterns increase risk
	for _, pattern := range result.TypoPatterns {
		switch pattern.Type {
		case "substitution", "transposition":
			risk += 0.2
		case "insertion", "deletion":
			risk += 0.15
		case "prefix_addition", "suffix_addition":
			risk += 0.1
		default:
			risk += 0.05
		}
	}
	
	return math.Min(risk, 1.0)
}

// Helper function for minimum of 4 values
func min4(a, b, c, d int) int {
	min := a
	if b < min {
		min = b
	}
	if c < min {
		min = c
	}
	if d < min {
		min = d
	}
	return min
}