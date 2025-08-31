package ml

import (
	"context"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// Enhanced ML algorithm types and structures

// SimilarityAnalysisResult holds the results of advanced similarity analysis
type SimilarityAnalysisResult struct {
	PackageName        string                   `json:"package_name"`
	AnalysisTime       time.Time                `json:"analysis_time"`
	MaxSimilarity      float64                  `json:"max_similarity"`
	BestMatch          EnhancedSimilarPackage   `json:"best_match"`
	SimilarPackages    []EnhancedSimilarPackage `json:"similar_packages"`
	IsTyposquatting    bool                     `json:"is_typosquatting"`
	TyposquattingScore float64                  `json:"typosquatting_score"`
}

// EnhancedSimilarPackage represents an enhanced similar package analysis
type EnhancedSimilarPackage struct {
	Name              string            `json:"name"`
	SimilarityMetrics SimilarityMetrics `json:"similarity_metrics"`
	TyposquattingRisk float64           `json:"typosquatting_risk"`
	ConfidenceScore   float64           `json:"confidence_score"`
}

// SimilarityMetrics holds multiple similarity algorithm results
type SimilarityMetrics struct {
	LevenshteinSimilarity float64 `json:"levenshtein_similarity"`
	JaroWinklerSimilarity float64 `json:"jaro_winkler_similarity"`
	CosineSimilarity      float64 `json:"cosine_similarity"`
	JaccardSimilarity     float64 `json:"jaccard_similarity"`
	PhoneticSimilarity    float64 `json:"phonetic_similarity"`
	StructuralSimilarity  float64 `json:"structural_similarity"`
	SemanticSimilarity    float64 `json:"semantic_similarity"`
	OverallScore          float64 `json:"overall_score"`
}

// MaliciousDetectionResult holds the results of malicious package detection
type MaliciousDetectionResult struct {
	PackageName     string                       `json:"package_name"`
	AnalysisTime    time.Time                    `json:"analysis_time"`
	MaliciousScore  float64                      `json:"malicious_score"`
	IsMalicious     bool                         `json:"is_malicious"`
	ConfidenceLevel float64                      `json:"confidence_level"`
	Indicators      []EnhancedMaliciousIndicator `json:"indicators"`
}

// EnhancedMaliciousIndicator represents a specific malicious indicator
type EnhancedMaliciousIndicator struct {
	Type        string  `json:"type"`
	Severity    string  `json:"severity"`
	Score       float64 `json:"score"`
	Description string  `json:"description"`
	Evidence    string  `json:"evidence"`
}

// EnhancedMLAlgorithms provides advanced ML algorithms for package analysis
type EnhancedMLAlgorithms struct {
	config                Config
	knownMaliciousHashes  map[string]bool
	suspiciousPatterns    []*regexp.Regexp
	typosquattingPatterns []*regexp.Regexp
	featureWeights        map[string]float64
}

// NewEnhancedMLAlgorithms creates a new instance of enhanced ML algorithms
func NewEnhancedMLAlgorithms(config Config) *EnhancedMLAlgorithms {
	return &EnhancedMLAlgorithms{
		config:                config,
		knownMaliciousHashes:  initializeMaliciousHashes(),
		suspiciousPatterns:    initializeSuspiciousPatterns(),
		typosquattingPatterns: initializeTyposquattingPatterns(),
		featureWeights:        initializeFeatureWeights(),
	}
}

// AdvancedSimilarityAnalysis performs multi-algorithm similarity analysis
func (ema *EnhancedMLAlgorithms) AdvancedSimilarityAnalysis(pkg *types.Package, popularPackages []string) SimilarityAnalysisResult {
	result := SimilarityAnalysisResult{
		PackageName:     pkg.Name,
		AnalysisTime:    time.Now(),
		SimilarPackages: make([]EnhancedSimilarPackage, 0),
	}

	maxSimilarity := 0.0
	var bestMatch EnhancedSimilarPackage

	for _, popular := range popularPackages {
		if pkg.Name == popular {
			continue // Skip exact matches
		}

		similarity := ema.calculateMultiAlgorithmSimilarity(pkg.Name, popular)

		if similarity.OverallScore > 0.3 { // Only include meaningful similarities
			enhancedSim := EnhancedSimilarPackage{
				Name:              popular,
				SimilarityMetrics: similarity,
				TyposquattingRisk: ema.assessTyposquattingRisk(pkg.Name, popular),
				ConfidenceScore:   ema.calculateConfidenceScore(similarity),
			}

			result.SimilarPackages = append(result.SimilarPackages, enhancedSim)

			if similarity.OverallScore > maxSimilarity {
				maxSimilarity = similarity.OverallScore
				bestMatch = enhancedSim
			}
		}
	}

	// Sort by similarity score
	sort.Slice(result.SimilarPackages, func(i, j int) bool {
		return result.SimilarPackages[i].SimilarityMetrics.OverallScore >
			result.SimilarPackages[j].SimilarityMetrics.OverallScore
	})

	// Keep only top 10 most similar
	if len(result.SimilarPackages) > 10 {
		result.SimilarPackages = result.SimilarPackages[:10]
	}

	result.MaxSimilarity = maxSimilarity
	result.BestMatch = bestMatch

	// Enhanced typosquatting detection
	typosquattingRisk := 0.0
	for _, similar := range result.SimilarPackages {
		// Lower threshold for similarity to catch more typosquatting attempts
		if similar.SimilarityMetrics.OverallScore > 0.5 {
			risk := ema.assessTyposquattingRisk(pkg.Name, similar.Name)
			if risk > typosquattingRisk {
				typosquattingRisk = risk
			}
		}
	}

	// Additional typosquatting checks for common patterns
	if typosquattingRisk < 0.6 {
		for _, popularPkg := range popularPackages {
			// Check for single character differences
			if len(pkg.Name) == len(popularPkg) {
				diff := 0
				for i := 0; i < len(pkg.Name); i++ {
					if pkg.Name[i] != popularPkg[i] {
						diff++
					}
				}
				if diff == 1 {
					typosquattingRisk = math.Max(typosquattingRisk, 0.8)
				}
			}

			// Check for single character deletion
			if len(pkg.Name) == len(popularPkg)-1 {
				similarity := ema.normalizedLevenshteinSimilarity(pkg.Name, popularPkg)
				if similarity > 0.8 {
					typosquattingRisk = math.Max(typosquattingRisk, 0.8)
				}

				// Special case: check if it's just the last character removed
				if len(popularPkg) > 0 && pkg.Name == popularPkg[:len(popularPkg)-1] {
					typosquattingRisk = math.Max(typosquattingRisk, 0.9)
				}
			}

			// Check for single character insertion
			if len(pkg.Name) == len(popularPkg)+1 {
				similarity := ema.normalizedLevenshteinSimilarity(pkg.Name, popularPkg)
				if similarity > 0.85 {
					typosquattingRisk = math.Max(typosquattingRisk, 0.75)
				}
			}
		}
	}

	result.IsTyposquatting = typosquattingRisk > 0.6 || (maxSimilarity > 0.7 && bestMatch.TyposquattingRisk > 0.6)
	result.TyposquattingScore = typosquattingRisk

	return result
}

// calculateMultiAlgorithmSimilarity combines multiple similarity algorithms
func (ema *EnhancedMLAlgorithms) calculateMultiAlgorithmSimilarity(name1, name2 string) SimilarityMetrics {
	metrics := SimilarityMetrics{}

	// 1. Levenshtein Distance (normalized)
	metrics.LevenshteinSimilarity = ema.normalizedLevenshteinSimilarity(name1, name2)

	// 2. Jaro-Winkler Similarity
	metrics.JaroWinklerSimilarity = ema.jaroWinklerSimilarity(name1, name2)

	// 3. Cosine Similarity (character n-grams)
	metrics.CosineSimilarity = ema.cosineCharacterSimilarity(name1, name2)

	// 4. Jaccard Similarity (character sets)
	metrics.JaccardSimilarity = ema.jaccardSimilarity(name1, name2)

	// 5. Phonetic Similarity (Soundex-based)
	metrics.PhoneticSimilarity = ema.phoneticSimilarity(name1, name2)

	// 6. Structural Similarity (pattern-based)
	metrics.StructuralSimilarity = ema.structuralSimilarity(name1, name2)

	// 7. Semantic Similarity (context-based)
	metrics.SemanticSimilarity = ema.semanticSimilarity(name1, name2)

	// Calculate weighted overall score with enhanced typosquatting detection
	weights := map[string]float64{
		"levenshtein":  0.25,
		"jaro_winkler": 0.20,
		"cosine":       0.15,
		"jaccard":      0.10,
		"phonetic":     0.10,
		"structural":   0.10,
		"semantic":     0.10,
	}

	// Check for potential typosquatting (single character difference)
	lenDiff := int(math.Abs(float64(len(name1) - len(name2))))
	isLikelyTyposquatting := (lenDiff <= 1 && metrics.LevenshteinSimilarity > 0.8) ||
		(lenDiff == 0 && metrics.LevenshteinSimilarity > 0.85)

	// Adjust weights for typosquatting cases
	if isLikelyTyposquatting {
		weights["levenshtein"] = 0.4 // Increase Levenshtein weight
		weights["jaro_winkler"] = 0.25
		weights["cosine"] = 0.15
		weights["jaccard"] = 0.08
		weights["phonetic"] = 0.05
		weights["structural"] = 0.04
		weights["semantic"] = 0.03
	}

	metrics.OverallScore =
		metrics.LevenshteinSimilarity*weights["levenshtein"] +
			metrics.JaroWinklerSimilarity*weights["jaro_winkler"] +
			metrics.CosineSimilarity*weights["cosine"] +
			metrics.JaccardSimilarity*weights["jaccard"] +
			metrics.PhoneticSimilarity*weights["phonetic"] +
			metrics.StructuralSimilarity*weights["structural"] +
			metrics.SemanticSimilarity*weights["semantic"]

	return metrics
}

// AdvancedMaliciousDetection performs comprehensive malicious package detection
func (ema *EnhancedMLAlgorithms) AdvancedMaliciousDetection(ctx context.Context, pkg *types.Package) MaliciousDetectionResult {
	result := MaliciousDetectionResult{
		PackageName:  pkg.Name,
		AnalysisTime: time.Now(),
		Indicators:   make([]EnhancedMaliciousIndicator, 0),
	}

	// 1. Pattern-based detection
	patternScore := ema.patternBasedDetection(pkg)
	if patternScore > 0.3 {
		result.Indicators = append(result.Indicators, EnhancedMaliciousIndicator{
			Type:        "suspicious_pattern",
			Severity:    ema.getSeverityFromScore(patternScore),
			Score:       patternScore,
			Description: "Package contains suspicious naming or content patterns",
			Evidence:    fmt.Sprintf("Suspicious patterns detected in %s", pkg.Name),
		})
	}

	// 2. Behavioral analysis
	behaviorScore := ema.behavioralAnalysis(pkg)
	if behaviorScore > 0.4 {
		result.Indicators = append(result.Indicators, EnhancedMaliciousIndicator{
			Type:        "suspicious_behavior",
			Severity:    ema.getSeverityFromScore(behaviorScore),
			Score:       behaviorScore,
			Description: "Package exhibits suspicious behavioral patterns",
			Evidence:    fmt.Sprintf("Behavioral anomalies detected in %s", pkg.Name),
		})
	}

	// 3. Metadata analysis
	metadataScore := ema.metadataAnalysis(pkg)
	if metadataScore > 0.3 {
		result.Indicators = append(result.Indicators, EnhancedMaliciousIndicator{
			Type:        "suspicious_metadata",
			Severity:    ema.getSeverityFromScore(metadataScore),
			Score:       metadataScore,
			Description: "Package metadata contains suspicious elements",
			Evidence:    fmt.Sprintf("Metadata anomalies detected in %s", pkg.Name),
		})
	}

	// Calculate overall malicious score
	if len(result.Indicators) > 0 {
		totalScore := 0.0
		maxScore := 0.0
		for _, indicator := range result.Indicators {
			totalScore += indicator.Score
			if indicator.Score > maxScore {
				maxScore = indicator.Score
			}
		}
		// Use weighted average with emphasis on highest score
		result.MaliciousScore = (totalScore/float64(len(result.Indicators)))*0.6 + maxScore*0.4
	}

	result.IsMalicious = result.MaliciousScore > 0.7
	result.ConfidenceLevel = ema.calculateMaliciousConfidence(result)

	return result
}

// Similarity algorithm implementations

// normalizedLevenshteinSimilarity calculates normalized Levenshtein similarity
func (ema *EnhancedMLAlgorithms) normalizedLevenshteinSimilarity(s1, s2 string) float64 {
	if s1 == s2 {
		return 1.0
	}

	distance := ema.levenshteinDistance(s1, s2)
	maxLen := math.Max(float64(len(s1)), float64(len(s2)))

	if maxLen == 0 {
		return 1.0
	}

	return 1.0 - (float64(distance) / maxLen)
}

// levenshteinDistance calculates the Levenshtein distance between two strings
func (ema *EnhancedMLAlgorithms) levenshteinDistance(s1, s2 string) int {
	if len(s1) == 0 {
		return len(s2)
	}
	if len(s2) == 0 {
		return len(s1)
	}

	matrix := make([][]int, len(s1)+1)
	for i := range matrix {
		matrix[i] = make([]int, len(s2)+1)
		matrix[i][0] = i
	}
	for j := 0; j <= len(s2); j++ {
		matrix[0][j] = j
	}

	for i := 1; i <= len(s1); i++ {
		for j := 1; j <= len(s2); j++ {
			cost := 0
			if s1[i-1] != s2[j-1] {
				cost = 1
			}
			matrix[i][j] = ema.min3(
				matrix[i-1][j]+1,      // deletion
				matrix[i][j-1]+1,      // insertion
				matrix[i-1][j-1]+cost, // substitution
			)
		}
	}

	return matrix[len(s1)][len(s2)]
}

// jaroWinklerSimilarity calculates Jaro-Winkler similarity
func (ema *EnhancedMLAlgorithms) jaroWinklerSimilarity(s1, s2 string) float64 {
	if s1 == s2 {
		return 1.0
	}

	len1, len2 := len(s1), len(s2)
	if len1 == 0 || len2 == 0 {
		return 0.0
	}

	matchWindow := ema.maxInt(len1, len2)/2 - 1
	if matchWindow < 0 {
		matchWindow = 0
	}

	s1Matches := make([]bool, len1)
	s2Matches := make([]bool, len2)
	matches := 0

	// Find matches
	for i := 0; i < len1; i++ {
		start := ema.maxInt(0, i-matchWindow)
		end := ema.minInt(i+matchWindow+1, len2)

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

	// Calculate transpositions
	transpositions := 0
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
	jaro := (float64(matches)/float64(len1) +
		float64(matches)/float64(len2) +
		float64(matches-transpositions/2)/float64(matches)) / 3.0

	// Calculate common prefix length (up to 4 characters)
	prefixLength := 0
	for i := 0; i < ema.minInt3(len1, len2, 4); i++ {
		if s1[i] == s2[i] {
			prefixLength++
		} else {
			break
		}
	}

	// Calculate Jaro-Winkler similarity
	return jaro + (0.1 * float64(prefixLength) * (1.0 - jaro))
}

// cosineCharacterSimilarity calculates cosine similarity based on character n-grams
func (ema *EnhancedMLAlgorithms) cosineCharacterSimilarity(s1, s2 string) float64 {
	ngrams1 := ema.generateNGrams(s1, 2)
	ngrams2 := ema.generateNGrams(s2, 2)

	return ema.cosineSimilarity(ngrams1, ngrams2)
}

// jaccardSimilarity calculates Jaccard similarity between character sets
func (ema *EnhancedMLAlgorithms) jaccardSimilarity(s1, s2 string) float64 {
	set1 := make(map[rune]bool)
	set2 := make(map[rune]bool)

	for _, char := range s1 {
		set1[char] = true
	}
	for _, char := range s2 {
		set2[char] = true
	}

	intersection := 0
	union := len(set1)

	for char := range set2 {
		if set1[char] {
			intersection++
		} else {
			union++
		}
	}

	if union == 0 {
		return 1.0
	}

	return float64(intersection) / float64(union)
}

// phoneticSimilarity calculates phonetic similarity using Soundex algorithm
func (ema *EnhancedMLAlgorithms) phoneticSimilarity(s1, s2 string) float64 {
	soundex1 := ema.soundex(s1)
	soundex2 := ema.soundex(s2)

	if soundex1 == soundex2 {
		return 1.0
	}

	// Calculate similarity between soundex codes
	return ema.normalizedLevenshteinSimilarity(soundex1, soundex2)
}

// structuralSimilarity analyzes structural patterns in package names
func (ema *EnhancedMLAlgorithms) structuralSimilarity(s1, s2 string) float64 {
	// Analyze structural patterns like prefixes, suffixes, word boundaries
	score := 0.0

	// Check for common prefixes and suffixes
	commonPrefix := ema.longestCommonPrefix(s1, s2)
	commonSuffix := ema.longestCommonSuffix(s1, s2)

	prefixScore := float64(len(commonPrefix)) / math.Max(float64(len(s1)), float64(len(s2)))
	suffixScore := float64(len(commonSuffix)) / math.Max(float64(len(s1)), float64(len(s2)))

	score = (prefixScore + suffixScore) / 2.0

	// Check for word boundary similarities
	words1 := ema.extractWords(s1)
	words2 := ema.extractWords(s2)

	if len(words1) > 0 && len(words2) > 0 {
		wordSimilarity := ema.calculateWordSimilarity(words1, words2)
		score = (score + wordSimilarity) / 2.0
	}

	return score
}

// semanticSimilarity analyzes semantic relationships between package names
func (ema *EnhancedMLAlgorithms) semanticSimilarity(s1, s2 string) float64 {
	// Simple semantic analysis based on common programming terms and patterns
	semanticTerms := map[string][]string{
		"web":    {"http", "server", "client", "api", "rest", "web"},
		"data":   {"json", "xml", "csv", "data", "parse", "format"},
		"crypto": {"hash", "encrypt", "crypto", "secure", "auth"},
		"util":   {"util", "helper", "tool", "lib", "common"},
		"test":   {"test", "mock", "spec", "assert", "check"},
		"log":    {"log", "debug", "trace", "monitor"},
	}

	score := 0.0
	matches := 0

	for _, terms := range semanticTerms {
		s1HasTerm := ema.containsAnyTerm(s1, terms)
		s2HasTerm := ema.containsAnyTerm(s2, terms)

		if s1HasTerm && s2HasTerm {
			score += 1.0
			matches++
		}
	}

	if matches > 0 {
		return score / float64(len(semanticTerms))
	}

	return 0.0
}

// Helper methods for analysis

func (ema *EnhancedMLAlgorithms) assessTyposquattingRisk(name1, name2 string) float64 {
	risk := 0.0

	// Calculate similarity first
	similarity := ema.normalizedLevenshteinSimilarity(name1, name2)

	// High similarity indicates potential typosquatting
	if similarity > 0.8 {
		risk += 0.6
	} else if similarity > 0.7 {
		risk += 0.4
	}

	// Check for specific typosquatting patterns
	lenDiff := int(math.Abs(float64(len(name1) - len(name2))))

	// Single character difference (deletion, insertion, substitution)
	if lenDiff <= 1 && similarity > 0.8 {
		risk += 0.4
	}

	// Check for common typosquatting patterns
	for _, pattern := range ema.typosquattingPatterns {
		if pattern.MatchString(name1) {
			risk += 0.2
		}
	}

	// Check for character substitutions
	if ema.hasCharacterSubstitutions(name1, name2) {
		risk += 0.3
	}

	// Check for insertion/deletion patterns
	if ema.hasInsertionDeletionPatterns(name1, name2) {
		risk += 0.3
	}

	// Special case: if one name is a substring of another with high similarity
	if (strings.Contains(name2, name1) || strings.Contains(name1, name2)) && similarity > 0.7 {
		risk += 0.3
	}

	return math.Min(risk, 1.0)
}

func (ema *EnhancedMLAlgorithms) calculateConfidenceScore(metrics SimilarityMetrics) float64 {
	// Calculate confidence based on consistency across algorithms
	scores := []float64{
		metrics.LevenshteinSimilarity,
		metrics.JaroWinklerSimilarity,
		metrics.CosineSimilarity,
		metrics.JaccardSimilarity,
	}

	mean := 0.0
	for _, score := range scores {
		mean += score
	}
	mean /= float64(len(scores))

	variance := 0.0
	for _, score := range scores {
		variance += math.Pow(score-mean, 2)
	}
	variance /= float64(len(scores))

	// Lower variance means higher confidence
	confidence := 1.0 - math.Min(variance, 1.0)
	return confidence
}

func (ema *EnhancedMLAlgorithms) patternBasedDetection(pkg *types.Package) float64 {
	score := 0.0

	// Check against suspicious patterns
	for _, pattern := range ema.suspiciousPatterns {
		if pattern.MatchString(pkg.Name) {
			score += 0.2
		}
	}

	// Check for suspicious naming conventions
	if ema.hasSuspiciousNaming(pkg.Name) {
		score += 0.3
	}

	return math.Min(score, 1.0)
}

func (ema *EnhancedMLAlgorithms) behavioralAnalysis(pkg *types.Package) float64 {
	score := 0.0

	// Analyze package metadata for suspicious behavior indicators
	if pkg.Metadata != nil {
		if ema.hasSuspiciousDescription(pkg.Metadata.Description) {
			score += 0.3
		}

		if ema.hasSuspiciousAuthor(pkg.Metadata.Author) {
			score += 0.2
		}

		if ema.hasSuspiciousVersion(pkg.Version) {
			score += 0.2
		}
	}

	return math.Min(score, 1.0)
}

func (ema *EnhancedMLAlgorithms) metadataAnalysis(pkg *types.Package) float64 {
	score := 0.0

	if pkg.Metadata == nil {
		return 0.5 // Missing metadata is suspicious
	}

	// Check for minimal or suspicious metadata
	if len(pkg.Metadata.Description) < 10 {
		score += 0.3
	}

	if pkg.Metadata.Author == "" {
		score += 0.2
	}

	if ema.hasGenericDescription(pkg.Metadata.Description) {
		score += 0.3
	}

	return math.Min(score, 1.0)
}

func (ema *EnhancedMLAlgorithms) calculateMaliciousConfidence(result MaliciousDetectionResult) float64 {
	if len(result.Indicators) == 0 {
		return 0.0
	}

	// Higher confidence with more indicators and higher scores
	avgScore := 0.0
	for _, indicator := range result.Indicators {
		avgScore += indicator.Score
	}
	avgScore /= float64(len(result.Indicators))

	// Confidence increases with number of indicators and average score
	confidence := (float64(len(result.Indicators))/5.0)*0.5 + avgScore*0.5
	return math.Min(confidence, 1.0)
}

func (ema *EnhancedMLAlgorithms) getSeverityFromScore(score float64) string {
	if score >= 0.8 {
		return "critical"
	} else if score >= 0.6 {
		return "high"
	} else if score >= 0.4 {
		return "medium"
	}
	return "low"
}

// Additional helper methods will be implemented in the next part...
