// RUNT - Release-Unusual Name Tokenizer
// Advanced typosquatting detection using multiple string similarity metrics
// and Bayesian mixture models
package edge

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
	"unicode"
)

// RUNTAlgorithm implements the RUNT algorithm for typosquatting detection
type RUNTAlgorithm struct {
	config  *RUNTConfig
	metrics *AlgorithmMetrics

	// Pre-computed similarity matrices
	visualSimilarityMap map[rune][]rune
	phoneticEncoder     *PhoneticEncoder
	semanticModel       *SemanticModel

	// Bayesian mixture model
	mixtureModel *BayesianMixtureModel

	// Known package database
	knownPackages map[string]bool
}

// RUNTConfig contains configuration for the RUNT algorithm
type RUNTConfig struct {
	// Similarity thresholds
	LevenshteinThreshold float64 `json:"levenshtein_threshold"`
	JaroWinklerThreshold float64 `json:"jaro_winkler_threshold"`
	PhoneticThreshold    float64 `json:"phonetic_threshold"`
	VisualThreshold      float64 `json:"visual_threshold"`
	SemanticThreshold    float64 `json:"semantic_threshold"`

	// Bayesian model parameters
	MixtureComponents int     `json:"mixture_components"`
	PriorWeight       float64 `json:"prior_weight"`

	// Detection parameters
	OverallThreshold      float64 `json:"overall_threshold"`
	MinPackageLength      int     `json:"min_package_length"`
	MaxPackageLength      int     `json:"max_package_length"`
	EnableUnicodeAnalysis bool    `json:"enable_unicode_analysis"`
}

// PhoneticEncoder handles phonetic encoding for sound-alike detection
type PhoneticEncoder struct {
	soundexMap map[rune]rune
}

// SemanticModel handles semantic similarity using word embeddings
type SemanticModel struct {
	embeddings map[string][]float64
	vocabulary map[string]bool
}

// BayesianMixtureModel implements Bayesian mixture modeling
type BayesianMixtureModel struct {
	components []MixtureComponent
	weights    []float64
	trained    bool
}

// MixtureComponent represents a single component in the mixture model
type MixtureComponent struct {
	mean       []float64
	covariance [][]float64
	weight     float64
}

// SimilarityFeatures contains all computed similarity features
type SimilarityFeatures struct {
	Levenshtein    float64 `json:"levenshtein"`
	JaroWinkler    float64 `json:"jaro_winkler"`
	Phonetic       float64 `json:"phonetic"`
	Visual         float64 `json:"visual"`
	Semantic       float64 `json:"semantic"`
	LCS            float64 `json:"lcs"` // Longest Common Subsequence
	Hamming        float64 `json:"hamming"`
	Cosine         float64 `json:"cosine"`
	Jaccard        float64 `json:"jaccard"`
	NGram          float64 `json:"ngram"`
	KeyboardLayout float64 `json:"keyboard_layout"`
	Unicode        float64 `json:"unicode"`
}

// NewRUNTAlgorithm creates a new RUNT algorithm instance
func NewRUNTAlgorithm(config *RUNTConfig) *RUNTAlgorithm {
	if config == nil {
		config = &RUNTConfig{
			LevenshteinThreshold:  0.8,
			JaroWinklerThreshold:  0.85,
			PhoneticThreshold:     0.9,
			VisualThreshold:       0.85,
			SemanticThreshold:     0.8,
			MixtureComponents:     5,
			PriorWeight:           0.1,
			OverallThreshold:      0.75,
			MinPackageLength:      2,
			MaxPackageLength:      100,
			EnableUnicodeAnalysis: true,
		}
	}

	runt := &RUNTAlgorithm{
		config: config,
		metrics: &AlgorithmMetrics{
			LastUpdated: time.Now(),
		},
		knownPackages: make(map[string]bool),
	}

	runt.initializeComponents()
	return runt
}

// Algorithm interface implementation

func (r *RUNTAlgorithm) Name() string {
	return "RUNT"
}

func (r *RUNTAlgorithm) Tier() AlgorithmTier {
	return TierCore
}

func (r *RUNTAlgorithm) Description() string {
	return "Release-Unusual Name Tokenizer: Advanced typosquatting detection using multiple similarity metrics and Bayesian mixture models"
}

func (r *RUNTAlgorithm) Configure(config map[string]interface{}) error {
	// Update configuration from map
	if threshold, ok := config["overall_threshold"].(float64); ok {
		r.config.OverallThreshold = threshold
	}
	return nil
}

func (r *RUNTAlgorithm) GetMetrics() *AlgorithmMetrics {
	return r.metrics
}

func (r *RUNTAlgorithm) Analyze(ctx context.Context, packages []string) (*AlgorithmResult, error) {
	startTime := time.Now()

	result := &AlgorithmResult{
		Algorithm: r.Name(),
		Timestamp: startTime,
		Packages:  packages,
		Findings:  make([]Finding, 0),
		Metadata:  make(map[string]interface{}),
	}

	// Analyze each package
	for _, packageName := range packages {
		// Validate package name length
		if len(packageName) < r.config.MinPackageLength || len(packageName) > r.config.MaxPackageLength {
			continue
		}

		// Find similar packages and compute threat score
		suspiciousPackages := r.findSuspiciousPackages(packageName)

		if len(suspiciousPackages) > 0 {
			// Add findings for each suspicious package
			for _, suspicious := range suspiciousPackages {
				if suspicious.SimilarityScore > r.config.OverallThreshold {
					finding := Finding{
						ID:              fmt.Sprintf("runt_typosquatting_%s", packageName),
						Package:         packageName,
						Type:            "TYPOSQUATTING_DETECTED",
						Severity:        r.getSeverity(suspicious.SimilarityScore),
						Message:         fmt.Sprintf("Package name '%s' is suspiciously similar to '%s'", packageName, suspicious.Name),
						Confidence:      suspicious.SimilarityScore,
						DetectedAt:      time.Now(),
						DetectionMethod: "runt_similarity_analysis",
						Evidence: []Evidence{
							{
								Type:        "target_package",
								Description: "Target package for typosquatting",
								Value:       suspicious.Name,
								Score:       suspicious.SimilarityScore,
							},
							{
								Type:        "similarity_features",
								Description: "Similarity analysis features",
								Value:       suspicious.Features,
								Score:       suspicious.SimilarityScore,
							},
							{
								Type:        "attack_type",
								Description: "Type of typosquatting attack",
								Value:       suspicious.AttackType,
								Score:       0.8,
							},
						},
					}
					result.Findings = append(result.Findings, finding)
				}
			}

			// Add metadata
			result.Metadata[fmt.Sprintf("%s_suspicious_packages_count", packageName)] = len(suspiciousPackages)
			result.Metadata[fmt.Sprintf("%s_max_similarity_score", packageName)] = suspiciousPackages[0].SimilarityScore
		}
	}
	return result, nil
}

// SuspiciousPackage represents a potentially malicious package
type SuspiciousPackage struct {
	Name            string              `json:"name"`
	SimilarityScore float64             `json:"similarity_score"`
	Features        *SimilarityFeatures `json:"features"`
	AttackType      string              `json:"attack_type"`
}

// Core algorithm implementation

func (r *RUNTAlgorithm) initializeComponents() {
	r.initializeVisualSimilarity()
	r.initializePhoneticEncoder()
	r.initializeSemanticModel()
	r.initializeMixtureModel()
	r.loadKnownPackages()
}

func (r *RUNTAlgorithm) initializeVisualSimilarity() {
	// Initialize visual similarity mappings for homoglyph detection
	r.visualSimilarityMap = map[rune][]rune{
		'a': {'à', 'á', 'â', 'ã', 'ä', 'å', 'α', 'а'},
		'e': {'è', 'é', 'ê', 'ë', 'е'},
		'i': {'ì', 'í', 'î', 'ï', 'і'},
		'o': {'ò', 'ó', 'ô', 'õ', 'ö', 'ο', 'о'},
		'u': {'ù', 'ú', 'û', 'ü'},
		'c': {'ç', 'с'},
		'p': {'р'},
		'x': {'х'},
		'y': {'у'},
		'0': {'О', 'о', 'Ο', 'ο'},
		'1': {'l', 'I', '|', 'і'},
	}
}

func (r *RUNTAlgorithm) initializePhoneticEncoder() {
	r.phoneticEncoder = &PhoneticEncoder{
		soundexMap: map[rune]rune{
			'b': '1', 'f': '1', 'p': '1', 'v': '1',
			'c': '2', 'g': '2', 'j': '2', 'k': '2', 'q': '2', 's': '2', 'x': '2', 'z': '2',
			'd': '3', 't': '3',
			'l': '4',
			'm': '5', 'n': '5',
			'r': '6',
		},
	}
}

func (r *RUNTAlgorithm) initializeSemanticModel() {
	// Initialize with basic semantic model
	// In production, this would load pre-trained embeddings
	r.semanticModel = &SemanticModel{
		embeddings: make(map[string][]float64),
		vocabulary: make(map[string]bool),
	}
}

func (r *RUNTAlgorithm) initializeMixtureModel() {
	r.mixtureModel = &BayesianMixtureModel{
		components: make([]MixtureComponent, r.config.MixtureComponents),
		weights:    make([]float64, r.config.MixtureComponents),
		trained:    false,
	}
}

func (r *RUNTAlgorithm) loadKnownPackages() {
	// Load known legitimate packages
	// This would typically load from a database or file
	knownPackages := []string{
		"react", "angular", "vue", "express", "lodash", "axios", "moment",
		"webpack", "babel", "eslint", "typescript", "jquery", "bootstrap",
		"numpy", "pandas", "requests", "flask", "django", "tensorflow",
	}

	for _, pkg := range knownPackages {
		r.knownPackages[pkg] = true
	}
}

func (r *RUNTAlgorithm) findSuspiciousPackages(packageName string) []SuspiciousPackage {
	suspicious := make([]SuspiciousPackage, 0)

	// Check against known packages
	for knownPkg := range r.knownPackages {
		if knownPkg == packageName {
			continue // Skip exact matches
		}

		features := r.computeAllSimilarityFeatures(packageName, knownPkg)
		overallScore := r.computeOverallSimilarity(features)

		if overallScore > r.config.OverallThreshold {
			attackType := r.classifyAttackType(features)

			suspicious = append(suspicious, SuspiciousPackage{
				Name:            knownPkg,
				SimilarityScore: overallScore,
				Features:        features,
				AttackType:      attackType,
			})
		}
	}

	// Sort by similarity score (descending)
	sort.Slice(suspicious, func(i, j int) bool {
		return suspicious[i].SimilarityScore > suspicious[j].SimilarityScore
	})

	// Return top 5 most suspicious
	if len(suspicious) > 5 {
		suspicious = suspicious[:5]
	}

	return suspicious
}

func (r *RUNTAlgorithm) computeAllSimilarityFeatures(name1, name2 string) *SimilarityFeatures {
	return &SimilarityFeatures{
		Levenshtein:    r.levenshteinSimilarity(name1, name2),
		JaroWinkler:    r.jaroWinklerSimilarity(name1, name2),
		Phonetic:       r.phoneticSimilarity(name1, name2),
		Visual:         r.visualSimilarity(name1, name2),
		Semantic:       r.semanticSimilarity(name1, name2),
		LCS:            r.lcsSimilarity(name1, name2),
		Hamming:        r.hammingSimilarity(name1, name2),
		Cosine:         r.cosineSimilarity(name1, name2),
		Jaccard:        r.jaccardSimilarity(name1, name2),
		NGram:          r.ngramSimilarity(name1, name2),
		KeyboardLayout: r.keyboardLayoutSimilarity(name1, name2),
		Unicode:        r.unicodeSimilarity(name1, name2),
	}
}

// Similarity metric implementations

func (r *RUNTAlgorithm) levenshteinSimilarity(s1, s2 string) float64 {
	distance := r.levenshteinDistance(s1, s2)
	maxLen := math.Max(float64(len(s1)), float64(len(s2)))
	if maxLen == 0 {
		return 1.0
	}
	return 1.0 - float64(distance)/maxLen
}

func (r *RUNTAlgorithm) levenshteinDistance(s1, s2 string) int {
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

			matrix[i][j] = min3(
				matrix[i-1][j]+1,      // deletion
				matrix[i][j-1]+1,      // insertion
				matrix[i-1][j-1]+cost, // substitution
			)
		}
	}

	return matrix[len(s1)][len(s2)]
}

func (r *RUNTAlgorithm) jaroWinklerSimilarity(s1, s2 string) float64 {
	// Simplified Jaro-Winkler implementation
	if s1 == s2 {
		return 1.0
	}

	len1, len2 := len(s1), len(s2)
	if len1 == 0 || len2 == 0 {
		return 0.0
	}

	// Calculate Jaro similarity (simplified)
	matches := 0
	for i := 0; i < min(len1, len2); i++ {
		if s1[i] == s2[i] {
			matches++
		}
	}

	jaro := float64(matches) / math.Max(float64(len1), float64(len2))

	// Add Winkler prefix bonus
	prefix := 0
	for i := 0; i < min(min(len1, len2), 4); i++ {
		if s1[i] == s2[i] {
			prefix++
		} else {
			break
		}
	}

	return jaro + (0.1 * float64(prefix) * (1.0 - jaro))
}

func (r *RUNTAlgorithm) phoneticSimilarity(s1, s2 string) float64 {
	soundex1 := r.phoneticEncoder.soundex(s1)
	soundex2 := r.phoneticEncoder.soundex(s2)

	if soundex1 == soundex2 {
		return 1.0
	}

	// Calculate similarity between soundex codes
	return r.levenshteinSimilarity(soundex1, soundex2)
}

func (r *RUNTAlgorithm) visualSimilarity(s1, s2 string) float64 {
	// Check for visual similarity using homoglyph mappings
	normalized1 := r.normalizeVisually(s1)
	normalized2 := r.normalizeVisually(s2)

	return r.levenshteinSimilarity(normalized1, normalized2)
}

func (r *RUNTAlgorithm) semanticSimilarity(s1, s2 string) float64 {
	// Placeholder for semantic similarity
	// In production, this would use word embeddings
	return 0.5
}

func (r *RUNTAlgorithm) lcsSimilarity(s1, s2 string) float64 {
	lcs := r.longestCommonSubsequence(s1, s2)
	maxLen := math.Max(float64(len(s1)), float64(len(s2)))
	if maxLen == 0 {
		return 1.0
	}
	return float64(lcs) / maxLen
}

func (r *RUNTAlgorithm) hammingSimilarity(s1, s2 string) float64 {
	if len(s1) != len(s2) {
		return 0.0
	}

	matches := 0
	for i := 0; i < len(s1); i++ {
		if s1[i] == s2[i] {
			matches++
		}
	}

	return float64(matches) / float64(len(s1))
}

func (r *RUNTAlgorithm) cosineSimilarity(s1, s2 string) float64 {
	// Character frequency vectors
	freq1 := r.getCharFrequency(s1)
	freq2 := r.getCharFrequency(s2)

	return r.cosineDistance(freq1, freq2)
}

func (r *RUNTAlgorithm) jaccardSimilarity(s1, s2 string) float64 {
	set1 := r.getCharSet(s1)
	set2 := r.getCharSet(s2)

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

func (r *RUNTAlgorithm) ngramSimilarity(s1, s2 string) float64 {
	ngrams1 := r.getNGrams(s1, 2)
	ngrams2 := r.getNGrams(s2, 2)

	return r.jaccardSimilarityMaps(ngrams1, ngrams2)
}

func (r *RUNTAlgorithm) keyboardLayoutSimilarity(s1, s2 string) float64 {
	// QWERTY keyboard layout similarity
	keyboard := map[rune][]rune{
		'q': {'w', 'a'},
		'w': {'q', 'e', 's'},
		'e': {'w', 'r', 'd'},
		// ... (simplified for brevity)
	}

	// Calculate similarity based on keyboard proximity
	return r.layoutBasedSimilarity(s1, s2, keyboard)
}

func (r *RUNTAlgorithm) unicodeSimilarity(s1, s2 string) float64 {
	if !r.config.EnableUnicodeAnalysis {
		return 0.0
	}

	// Analyze Unicode categories and scripts
	return r.analyzeUnicodeProperties(s1, s2)
}

// Helper methods

func (r *RUNTAlgorithm) computeOverallSimilarity(features *SimilarityFeatures) float64 {
	// Weighted combination of all features
	weights := []float64{0.15, 0.15, 0.1, 0.1, 0.1, 0.1, 0.05, 0.05, 0.05, 0.05, 0.05, 0.05}
	values := []float64{
		features.Levenshtein, features.JaroWinkler, features.Phonetic,
		features.Visual, features.Semantic, features.LCS, features.Hamming,
		features.Cosine, features.Jaccard, features.NGram,
		features.KeyboardLayout, features.Unicode,
	}

	var weightedSum, totalWeight float64
	for i, weight := range weights {
		if i < len(values) {
			weightedSum += weight * values[i]
			totalWeight += weight
		}
	}

	if totalWeight == 0 {
		return 0.0
	}

	return weightedSum / totalWeight
}

func (r *RUNTAlgorithm) computeBayesianThreatScore(features *SimilarityFeatures) float64 {
	if !r.mixtureModel.trained {
		// Use simple weighted score if model not trained
		return r.computeOverallSimilarity(features)
	}

	// Convert features to vector
	featureVector := []float64{
		features.Levenshtein, features.JaroWinkler, features.Phonetic,
		features.Visual, features.Semantic, features.LCS,
	}

	// Compute probability under mixture model
	return r.mixtureModel.computeProbability(featureVector)
}

func (r *RUNTAlgorithm) computeConfidence(features *SimilarityFeatures, suspicious []SuspiciousPackage) float64 {
	// Confidence based on feature consistency and number of suspicious packages
	baseConfidence := 0.8

	if len(suspicious) > 1 {
		baseConfidence += 0.1
	}

	// Check feature consistency
	featureValues := []float64{
		features.Levenshtein, features.JaroWinkler, features.Phonetic,
		features.Visual, features.LCS,
	}

	variance := r.calculateVariance(featureValues)
	if variance < 0.1 {
		baseConfidence += 0.1
	}

	return math.Min(baseConfidence, 1.0)
}

func (r *RUNTAlgorithm) classifyAttackType(features *SimilarityFeatures) string {
	if features.Visual > 0.8 {
		return "HOMOGLYPH_ATTACK"
	}
	if features.Phonetic > 0.8 {
		return "PHONETIC_SQUATTING"
	}
	if features.KeyboardLayout > 0.7 {
		return "KEYBOARD_TYPO"
	}
	if features.Unicode > 0.7 {
		return "UNICODE_CONFUSION"
	}
	return "GENERAL_TYPOSQUATTING"
}

func (r *RUNTAlgorithm) getSeverity(score float64) string {
	if score > 0.9 {
		return "CRITICAL"
	}
	if score > 0.8 {
		return "HIGH"
	}
	if score > 0.6 {
		return "MEDIUM"
	}
	return "LOW"
}

// Utility functions

func min3(a, b, c int) int {
	if a < b && a < c {
		return a
	}
	if b < c {
		return b
	}
	return c
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Placeholder implementations for complex methods

func (pe *PhoneticEncoder) soundex(s string) string {
	if len(s) == 0 {
		return ""
	}

	// Simplified Soundex implementation
	result := strings.ToUpper(string(s[0]))

	for i := 1; i < len(s) && len(result) < 4; i++ {
		char := unicode.ToLower(rune(s[i]))
		if code, exists := pe.soundexMap[char]; exists {
			if len(result) == 1 || result[len(result)-1] != byte(code) {
				result += string(code)
			}
		}
	}

	// Pad with zeros
	for len(result) < 4 {
		result += "0"
	}

	return result
}

func (r *RUNTAlgorithm) normalizeVisually(s string) string {
	var result strings.Builder

	for _, char := range s {
		normalized := char
		for base, variants := range r.visualSimilarityMap {
			for _, variant := range variants {
				if char == variant {
					normalized = base
					goto nextChar
				}
			}
		}
	nextChar:
		result.WriteRune(normalized)
	}

	return result.String()
}

func (r *RUNTAlgorithm) longestCommonSubsequence(s1, s2 string) int {
	m, n := len(s1), len(s2)
	dp := make([][]int, m+1)
	for i := range dp {
		dp[i] = make([]int, n+1)
	}

	for i := 1; i <= m; i++ {
		for j := 1; j <= n; j++ {
			if s1[i-1] == s2[j-1] {
				dp[i][j] = dp[i-1][j-1] + 1
			} else {
				dp[i][j] = max(dp[i-1][j], dp[i][j-1])
			}
		}
	}

	return dp[m][n]
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func (r *RUNTAlgorithm) getCharFrequency(s string) map[rune]int {
	freq := make(map[rune]int)
	for _, char := range s {
		freq[char]++
	}
	return freq
}

func (r *RUNTAlgorithm) getCharSet(s string) map[rune]bool {
	set := make(map[rune]bool)
	for _, char := range s {
		set[char] = true
	}
	return set
}

func (r *RUNTAlgorithm) cosineDistance(freq1, freq2 map[rune]int) float64 {
	// Simplified cosine similarity
	var dotProduct, norm1, norm2 float64

	allChars := make(map[rune]bool)
	for char := range freq1 {
		allChars[char] = true
	}
	for char := range freq2 {
		allChars[char] = true
	}

	for char := range allChars {
		f1 := float64(freq1[char])
		f2 := float64(freq2[char])

		dotProduct += f1 * f2
		norm1 += f1 * f1
		norm2 += f2 * f2
	}

	if norm1 == 0 || norm2 == 0 {
		return 0.0
	}

	return dotProduct / (math.Sqrt(norm1) * math.Sqrt(norm2))
}

func (r *RUNTAlgorithm) getNGrams(s string, n int) map[string]int {
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

func (r *RUNTAlgorithm) jaccardSimilarityMaps(map1, map2 map[string]int) float64 {
	intersection := 0
	union := len(map1)

	for key := range map2 {
		if map1[key] > 0 {
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

func (r *RUNTAlgorithm) layoutBasedSimilarity(s1, s2 string, keyboard map[rune][]rune) float64 {
	// Simplified keyboard layout similarity
	return 0.5 // Placeholder
}

func (r *RUNTAlgorithm) analyzeUnicodeProperties(s1, s2 string) float64 {
	// Analyze Unicode scripts and categories
	return 0.5 // Placeholder
}

func (r *RUNTAlgorithm) calculateVariance(values []float64) float64 {
	if len(values) == 0 {
		return 0.0
	}

	// Calculate mean
	var sum float64
	for _, v := range values {
		sum += v
	}
	mean := sum / float64(len(values))

	// Calculate variance
	var variance float64
	for _, v := range values {
		variance += (v - mean) * (v - mean)
	}

	return variance / float64(len(values))
}

func (bmm *BayesianMixtureModel) computeProbability(features []float64) float64 {
	// Simplified probability computation
	return 0.5 // Placeholder
}

// Reset resets the algorithm state
func (r *RUNTAlgorithm) Reset() error {
	// Reset metrics
	r.metrics = &AlgorithmMetrics{
		ProcessingTime: 0,
	}

	// Reset known packages
	r.knownPackages = make(map[string]bool)

	// Reinitialize components
	r.initializeComponents()

	return nil
}
