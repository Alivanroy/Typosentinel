package ml

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// FeatureVectorExtractor extracts features as float64 slices for ML models
type FeatureVectorExtractor interface {
	ExtractFeatures(pkg *types.Package) ([]float64, error)
	GetFeatureNames() []string
	NormalizeFeatures(features []float64) []float64
}

// FeatureEngineer handles feature extraction and engineering for ML models
type FeatureEngineer struct {
	extractors map[string]FeatureVectorExtractor
	normalizer *FeatureNormalizer
}

// FeatureSet represents a collection of features for a package
type FeatureSet struct {
	PackageName string                 `json:"package_name"`
	Features    map[string]float64     `json:"features"`
	Metadata    map[string]interface{} `json:"metadata"`
	ModelType   string                 `json:"model_type"`
}

// FeatureNormalizer handles feature normalization and scaling
type FeatureNormalizer struct {
	stats map[string]*FeatureStatistics
}

// FeatureStatistics contains statistics for feature normalization
type FeatureStatistics struct {
	Mean   float64 `json:"mean"`
	StdDev float64 `json:"std_dev"`
	Min    float64 `json:"min"`
	Max    float64 `json:"max"`
	Count  int     `json:"count"`
}

// TyposquattingFeatureExtractor extracts features for typosquatting detection
type TyposquattingFeatureExtractor struct {
	popularPackages map[string]bool
	commonWords     map[string]bool
}

// ReputationFeatureExtractor extracts features for reputation analysis
type ReputationFeatureExtractor struct {
	knownMaintainers map[string]float64
	trustedDomains   map[string]bool
}

// AnomalyFeatureExtractor extracts features for anomaly detection
type AnomalyFeatureExtractor struct {
	baselineStats map[string]*FeatureStats
}

// NewFeatureEngineer creates a new feature engineer
func NewFeatureEngineer() *FeatureEngineer {
	fe := &FeatureEngineer{
		extractors: make(map[string]FeatureVectorExtractor),
		normalizer: NewFeatureNormalizer(),
	}

	// Register specific extractors
	fe.RegisterExtractor("typosquatting", NewTyposquattingFeatureExtractor())
	fe.RegisterExtractor("reputation", NewReputationFeatureExtractor())
	fe.RegisterExtractor("anomaly", NewAnomalyFeatureExtractor())

	return fe
}

// RegisterExtractor registers a feature extractor for a model type
func (fe *FeatureEngineer) RegisterExtractor(modelType string, extractor FeatureVectorExtractor) {
	fe.extractors[modelType] = extractor
}

// ExtractFeatures extracts features for a package based on model type
func (fe *FeatureEngineer) ExtractFeatures(pkg *types.Package, modelType string) (*FeatureSet, error) {
	extractor, exists := fe.extractors[modelType]
	if !exists {
		return nil, fmt.Errorf("no feature extractor registered for model type: %s", modelType)
	}

	features, err := extractor.ExtractFeatures(pkg)
	if err != nil {
		return nil, fmt.Errorf("feature extraction failed: %w", err)
	}

	featureSet := &FeatureSet{
		PackageName: pkg.Name,
		Features:    make(map[string]float64),
		Metadata:    make(map[string]interface{}),
		ModelType:   modelType,
	}

	// Convert features to map
	featureNames := extractor.GetFeatureNames()
	if len(features) != len(featureNames) {
		return nil, fmt.Errorf("feature count mismatch: got %d, expected %d", len(features), len(featureNames))
	}

	for i, name := range featureNames {
		featureSet.Features[name] = features[i]
	}

	// Add metadata
	featureSet.Metadata["extraction_time"] = pkg.AnalyzedAt
	featureSet.Metadata["package_version"] = pkg.Version
	featureSet.Metadata["feature_count"] = len(features)

	return featureSet, nil
}

// NormalizeFeatures normalizes features using stored statistics
func (fe *FeatureEngineer) NormalizeFeatures(featureSet *FeatureSet) error {
	return fe.normalizer.Normalize(featureSet)
}

// UpdateNormalizationStats updates normalization statistics with new data
func (fe *FeatureEngineer) UpdateNormalizationStats(featureSets []*FeatureSet) error {
	return fe.normalizer.UpdateStats(featureSets)
}

// GetFeatureImportance calculates feature importance for a model type
func (fe *FeatureEngineer) GetFeatureImportance(modelType string, samples []*FeatureSet) (map[string]float64, error) {
	if len(samples) == 0 {
		return nil, fmt.Errorf("no samples provided for feature importance calculation")
	}

	importance := make(map[string]float64)
	
	// Calculate variance-based importance
	for featureName := range samples[0].Features {
		values := make([]float64, len(samples))
		for i, sample := range samples {
			values[i] = sample.Features[featureName]
		}
		
		variance := calculateVariance(values)
		importance[featureName] = variance
	}

	// Normalize importance scores
	maxImportance := 0.0
	for _, score := range importance {
		if score > maxImportance {
			maxImportance = score
		}
	}

	if maxImportance > 0 {
		for name := range importance {
			importance[name] /= maxImportance
		}
	}

	return importance, nil
}

// NewFeatureNormalizer creates a new feature normalizer
func NewFeatureNormalizer() *FeatureNormalizer {
	return &FeatureNormalizer{
		stats: make(map[string]*FeatureStatistics),
	}
}

// Normalize normalizes features in a feature set
func (fn *FeatureNormalizer) Normalize(featureSet *FeatureSet) error {
	for name, value := range featureSet.Features {
		stats, exists := fn.stats[name]
		if !exists {
			continue // Skip normalization if no stats available
		}

		// Z-score normalization
		if stats.StdDev > 0 {
			normalized := (value - stats.Mean) / stats.StdDev
			featureSet.Features[name] = normalized
		}
	}

	return nil
}

// UpdateStats updates normalization statistics
func (fn *FeatureNormalizer) UpdateStats(featureSets []*FeatureSet) error {
	if len(featureSets) == 0 {
		return nil
	}

	// Collect all feature values
	featureValues := make(map[string][]float64)
	for _, fs := range featureSets {
		for name, value := range fs.Features {
			featureValues[name] = append(featureValues[name], value)
		}
	}

	// Calculate statistics for each feature
	for name, values := range featureValues {
		stats := &FeatureStatistics{
			Count: len(values),
		}

		// Calculate mean
		sum := 0.0
		for _, v := range values {
			sum += v
		}
		stats.Mean = sum / float64(len(values))

		// Calculate standard deviation, min, max
		sumSquares := 0.0
		stats.Min = values[0]
		stats.Max = values[0]

		for _, v := range values {
			diff := v - stats.Mean
			sumSquares += diff * diff

			if v < stats.Min {
				stats.Min = v
			}
			if v > stats.Max {
				stats.Max = v
			}
		}

		stats.StdDev = math.Sqrt(sumSquares / float64(len(values)))
		fn.stats[name] = stats
	}

	return nil
}

// NewTyposquattingFeatureExtractor creates a new typosquatting feature extractor
func NewTyposquattingFeatureExtractor() *TyposquattingFeatureExtractor {
	return &TyposquattingFeatureExtractor{
		popularPackages: loadPopularPackages(),
		commonWords:     loadCommonWords(),
	}
}

// ExtractFeatures extracts typosquatting-related features
func (tfe *TyposquattingFeatureExtractor) ExtractFeatures(pkg *types.Package) ([]float64, error) {
	features := make([]float64, 0, 20)

	// Basic string features
	features = append(features, float64(len(pkg.Name)))                    // name_length
	features = append(features, float64(strings.Count(pkg.Name, "-")))     // hyphen_count
	features = append(features, float64(strings.Count(pkg.Name, "_")))     // underscore_count
	features = append(features, float64(strings.Count(pkg.Name, ".")))     // dot_count
	features = append(features, calculateDigitRatio(pkg.Name))             // digit_ratio
	features = append(features, calculateVowelRatio(pkg.Name))             // vowel_ratio
	features = append(features, calculateConsonantClusters(pkg.Name))      // consonant_clusters

	// Similarity features
	features = append(features, tfe.calculatePopularSimilarity(pkg.Name))  // popular_similarity
	features = append(features, tfe.calculateCommonWordSimilarity(pkg.Name)) // common_word_similarity

	// Pattern features
	features = append(features, calculateRepeatedChars(pkg.Name))          // repeated_chars
	features = append(features, calculateAlternatingCase(pkg.Name))        // alternating_case
	features = append(features, calculateSpecialPatterns(pkg.Name))        // special_patterns

	// Entropy and randomness
	features = append(features, calculateEntropyFeature(pkg.Name))         // entropy
	features = append(features, calculateRandomness(pkg.Name))             // randomness

	// Metadata features
	description := ""
	if pkg.Metadata != nil {
		description = pkg.Metadata.Description
	}
	features = append(features, float64(len(description)))             // description_length
	features = append(features, calculateDescriptionQuality(description)) // description_quality

	// Version and update patterns
	features = append(features, calculateVersionComplexity(pkg.Version))   // version_complexity
	features = append(features, calculateUpdateFrequencyFeature(pkg))             // update_frequency

	// Repository features
	features = append(features, calculateRepoTrust(pkg))                   // repo_trust
	features = append(features, calculateMaintainerTrust(pkg))             // maintainer_trust

	// Download and usage patterns
	downloadCount := int64(0)
	if pkg.Metadata != nil {
		downloadCount = pkg.Metadata.Downloads
	}
	features = append(features, math.Log1p(float64(downloadCount)))    // log_downloads

	return features, nil
}

// GetFeatureNames returns the names of extracted features
func (tfe *TyposquattingFeatureExtractor) GetFeatureNames() []string {
	return []string{
		"name_length", "hyphen_count", "underscore_count", "dot_count",
		"digit_ratio", "vowel_ratio", "consonant_clusters",
		"popular_similarity", "common_word_similarity",
		"repeated_chars", "alternating_case", "special_patterns",
		"entropy", "randomness",
		"description_length", "description_quality",
		"version_complexity", "update_frequency",
		"repo_trust", "maintainer_trust", "log_downloads",
	}
}

// NormalizeFeatures normalizes the extracted features
func (tfe *TyposquattingFeatureExtractor) NormalizeFeatures(features []float64) []float64 {
	// Simple min-max normalization for demonstration
	normalized := make([]float64, len(features))
	copy(normalized, features)
	
	// Apply feature-specific normalization
	if len(normalized) > 0 {
		// Normalize name_length (0-100 characters)
		normalized[0] = math.Min(normalized[0]/100.0, 1.0)
	}
	
	return normalized
}

// NewReputationFeatureExtractor creates a new reputation feature extractor
func NewReputationFeatureExtractor() *ReputationFeatureExtractor {
	return &ReputationFeatureExtractor{
		knownMaintainers: loadKnownMaintainers(),
		trustedDomains:   loadTrustedDomains(),
	}
}

// ExtractFeatures extracts reputation-related features
func (rfe *ReputationFeatureExtractor) ExtractFeatures(pkg *types.Package) ([]float64, error) {
	features := make([]float64, 0, 15)

	// Maintainer reputation
	features = append(features, rfe.calculateMaintainerReputation(pkg))    // maintainer_reputation
	maintainerCount := 0.0
	if pkg.Metadata != nil && pkg.Metadata.Maintainers != nil {
		maintainerCount = float64(len(pkg.Metadata.Maintainers))
	}
	features = append(features, maintainerCount)                           // maintainer_count

	// Package maturity
	features = append(features, calculatePackageAge(pkg))                  // package_age
	features = append(features, 1.0)                                       // version_count (placeholder)
	features = append(features, calculateReleaseFrequency(pkg))            // release_frequency

	// Community engagement
	downloadCount := 0.0
	if pkg.Metadata != nil {
		downloadCount = float64(pkg.Metadata.Downloads)
	}
	features = append(features, math.Log1p(downloadCount))                 // log_downloads
	features = append(features, 0.0)                                       // star_count (placeholder)
	features = append(features, 0.0)                                       // fork_count (placeholder)
	features = append(features, 0.0)                                       // issue_count (placeholder)

	// Quality indicators
	features = append(features, calculateDocumentationQuality(pkg))        // documentation_quality
	features = append(features, calculateTestCoverage(pkg))                // test_coverage
	features = append(features, calculateCodeQuality(pkg))                 // code_quality

	// Security indicators
	features = append(features, calculateSecurityScore(pkg))               // security_score
	features = append(features, float64(len(pkg.Dependencies)))            // dependency_count
	features = append(features, calculateDependencyRisk(pkg))              // dependency_risk

	// Trust indicators
	features = append(features, rfe.calculateDomainTrust(pkg))             // domain_trust

	return features, nil
}

// GetFeatureNames returns the names of extracted features
func (rfe *ReputationFeatureExtractor) GetFeatureNames() []string {
	return []string{
		"maintainer_reputation", "maintainer_count",
		"package_age", "version_count", "release_frequency",
		"log_downloads", "star_count", "fork_count", "issue_count",
		"documentation_quality", "test_coverage", "code_quality",
		"security_score", "dependency_count", "dependency_risk",
		"domain_trust",
	}
}

// NormalizeFeatures normalizes the extracted features
func (rfe *ReputationFeatureExtractor) NormalizeFeatures(features []float64) []float64 {
	normalized := make([]float64, len(features))
	copy(normalized, features)
	return normalized
}

// NewAnomalyFeatureExtractor creates a new anomaly feature extractor
func NewAnomalyFeatureExtractor() *AnomalyFeatureExtractor {
	return &AnomalyFeatureExtractor{
		baselineStats: make(map[string]*FeatureStats),
	}
}

// ExtractFeatures extracts anomaly detection features
func (afe *AnomalyFeatureExtractor) ExtractFeatures(pkg *types.Package) ([]float64, error) {
	features := make([]float64, 0, 12)

	// Behavioral anomalies
	features = append(features, calculateDownloadAnomaly(pkg))              // download_anomaly
	features = append(features, calculateUpdateAnomaly(pkg))                // update_anomaly
	features = append(features, calculateSizeAnomaly(pkg))                  // size_anomaly

	// Metadata anomalies
	features = append(features, calculateDescriptionAnomaly(pkg))           // description_anomaly
	features = append(features, calculateVersionAnomaly(pkg))               // version_anomaly
	features = append(features, calculateMaintainerAnomaly(pkg))            // maintainer_anomaly

	// Dependency anomalies
	features = append(features, calculateDependencyAnomaly(pkg))            // dependency_anomaly
	features = append(features, calculateCircularDependency(pkg))           // circular_dependency

	// Temporal anomalies
	features = append(features, calculateTemporalAnomaly(pkg))              // temporal_anomaly
	features = append(features, calculateActivityAnomaly(pkg))              // activity_anomaly

	// Content anomalies
	features = append(features, calculateContentAnomaly(pkg))               // content_anomaly
	features = append(features, calculateStructureAnomaly(pkg))             // structure_anomaly

	return features, nil
}

// GetFeatureNames returns the names of extracted features
func (afe *AnomalyFeatureExtractor) GetFeatureNames() []string {
	return []string{
		"download_anomaly", "update_anomaly", "size_anomaly",
		"description_anomaly", "version_anomaly", "maintainer_anomaly",
		"dependency_anomaly", "circular_dependency",
		"temporal_anomaly", "activity_anomaly",
		"content_anomaly", "structure_anomaly",
	}
}

// NormalizeFeatures normalizes the extracted features
func (afe *AnomalyFeatureExtractor) NormalizeFeatures(features []float64) []float64 {
	normalized := make([]float64, len(features))
	copy(normalized, features)
	return normalized
}

// Helper functions for feature calculation

func calculateDigitRatioFeature(name string) float64 {
	if len(name) == 0 {
		return 0.0
	}
	
	digitCount := 0
	for _, r := range name {
		if unicode.IsDigit(r) {
			digitCount++
		}
	}
	
	return float64(digitCount) / float64(len(name))
}

func calculateVowelRatioFeature(name string) float64 {
	if len(name) == 0 {
		return 0.0
	}
	
	vowels := "aeiouAEIOU"
	vowelCount := 0
	
	for _, r := range name {
		if strings.ContainsRune(vowels, r) {
			vowelCount++
		}
	}
	
	return float64(vowelCount) / float64(len(name))
}

func calculateConsonantClusters(name string) float64 {
	vowels := "aeiouAEIOU"
	clusters := 0
	inCluster := false
	
	for _, r := range name {
		isVowel := strings.ContainsRune(vowels, r)
		
		if !isVowel && unicode.IsLetter(r) {
			if !inCluster {
				clusters++
				inCluster = true
			}
		} else {
			inCluster = false
		}
	}
	
	return float64(clusters)
}

func calculateRepeatedChars(name string) float64 {
	if len(name) <= 1 {
		return 0.0
	}
	
	repeated := 0
	for i := 1; i < len(name); i++ {
		if name[i] == name[i-1] {
			repeated++
		}
	}
	
	return float64(repeated) / float64(len(name)-1)
}

func calculateAlternatingCase(name string) float64 {
	if len(name) <= 1 {
		return 0.0
	}
	
	alternating := 0
	for i := 1; i < len(name); i++ {
		prev := unicode.IsUpper(rune(name[i-1]))
		curr := unicode.IsUpper(rune(name[i]))
		
		if prev != curr && unicode.IsLetter(rune(name[i-1])) && unicode.IsLetter(rune(name[i])) {
			alternating++
		}
	}
	
	return float64(alternating) / float64(len(name)-1)
}

func calculateSpecialPatterns(name string) float64 {
	patterns := []string{
		`\d{3,}`,           // 3+ consecutive digits
		`[a-z]{10,}`,       // 10+ consecutive lowercase
		`[A-Z]{3,}`,        // 3+ consecutive uppercase
		`[_-]{2,}`,         // 2+ consecutive separators
		`^[0-9]`,           // starts with digit
		`[0-9]$`,           // ends with digit
	}
	
	matches := 0
	for _, pattern := range patterns {
		if matched, _ := regexp.MatchString(pattern, name); matched {
			matches++
		}
	}
	
	return float64(matches) / float64(len(patterns))
}

func calculateEntropyFeature(name string) float64 {
	if len(name) == 0 {
		return 0.0
	}
	
	freq := make(map[rune]int)
	for _, r := range name {
		freq[r]++
	}
	
	entropy := 0.0
	length := float64(len(name))
	
	for _, count := range freq {
		p := float64(count) / length
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}
	
	return entropy
}

func calculateRandomness(name string) float64 {
	if len(name) <= 1 {
		return 0.0
	}
	
	// Calculate bigram entropy as a measure of randomness
	bigrams := make(map[string]int)
	for i := 0; i < len(name)-1; i++ {
		bigram := name[i : i+2]
		bigrams[bigram]++
	}
	
	entropy := 0.0
	total := float64(len(name) - 1)
	
	for _, count := range bigrams {
		p := float64(count) / total
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}
	
	// Normalize by maximum possible entropy
	maxEntropy := math.Log2(total)
	if maxEntropy > 0 {
		return entropy / maxEntropy
	}
	
	return 0.0
}

func calculateVariance(values []float64) float64 {
	if len(values) <= 1 {
		return 0.0
	}
	
	// Calculate mean
	sum := 0.0
	for _, v := range values {
		sum += v
	}
	mean := sum / float64(len(values))
	
	// Calculate variance
	sumSquares := 0.0
	for _, v := range values {
		diff := v - mean
		sumSquares += diff * diff
	}
	
	return sumSquares / float64(len(values)-1)
}

// Placeholder functions for data loading and complex calculations
func loadPopularPackages() map[string]bool {
	// In a real implementation, this would load from a database or file
	return map[string]bool{
		"react":     true,
		"lodash":    true,
		"express":   true,
		"axios":     true,
		"moment":    true,
		"jquery":    true,
		"bootstrap": true,
	}
}

func loadCommonWords() map[string]bool {
	return map[string]bool{
		"the": true, "and": true, "for": true, "are": true,
		"but": true, "not": true, "you": true, "all": true,
		"can": true, "had": true, "her": true, "was": true,
		"one": true, "our": true, "out": true, "day": true,
	}
}

func loadKnownMaintainers() map[string]float64 {
	return map[string]float64{
		"npm":       0.95,
		"facebook":  0.90,
		"google":    0.95,
		"microsoft": 0.90,
		"jquery":    0.85,
	}
}

func loadTrustedDomains() map[string]bool {
	return map[string]bool{
		"github.com":    true,
		"gitlab.com":    true,
		"bitbucket.org": true,
		"npmjs.com":     true,
	}
}

// Placeholder implementations for complex feature calculations
func (tfe *TyposquattingFeatureExtractor) calculatePopularSimilarity(name string) float64 {
	maxSimilarity := 0.0
	for popular := range tfe.popularPackages {
		similarity := calculateStringSimilarity(name, popular)
		if similarity > maxSimilarity {
			maxSimilarity = similarity
		}
	}
	return maxSimilarity
}

func (tfe *TyposquattingFeatureExtractor) calculateCommonWordSimilarity(name string) float64 {
	maxSimilarity := 0.0
	for word := range tfe.commonWords {
		similarity := calculateStringSimilarity(name, word)
		if similarity > maxSimilarity {
			maxSimilarity = similarity
		}
	}
	return maxSimilarity
}

func calculateStringSimilarity(s1, s2 string) float64 {
	// Simple Levenshtein distance-based similarity
	if len(s1) == 0 && len(s2) == 0 {
		return 1.0
	}
	
	maxLen := len(s1)
	if len(s2) > maxLen {
		maxLen = len(s2)
	}
	
	distance := levenshteinDistanceFeature(s1, s2)
	return 1.0 - float64(distance)/float64(maxLen)
}

func levenshteinDistanceFeature(s1, s2 string) int {
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
			
			matrix[i][j] = minThree(
				matrix[i-1][j]+1,      // deletion
				matrix[i][j-1]+1,      // insertion
				matrix[i-1][j-1]+cost, // substitution
			)
		}
	}
	
	return matrix[len(s1)][len(s2)]
}

func minThree(a, b, c int) int {
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

// Enhanced feature calculation implementations
func calculateDescriptionQuality(description string) float64 {
	if len(description) == 0 {
		return 0.0
	}
	
	score := 0.0
	words := strings.Fields(description)
	
	// Length score (optimal around 100-500 characters)
	length := float64(len(description))
	if length >= 50 && length <= 500 {
		score += 0.25
	} else if length >= 20 && length < 50 {
		score += 0.15
	} else if length > 500 && length <= 1000 {
		score += 0.15
	}
	
	// Word count score (optimal 10-100 words)
	wordCount := len(words)
	if wordCount >= 10 && wordCount <= 100 {
		score += 0.25
	} else if wordCount >= 5 && wordCount < 10 {
		score += 0.15
	}
	
	// Sentence structure score
	sentences := strings.Split(description, ".")
	if len(sentences) >= 2 && len(sentences) <= 10 {
		score += 0.2
	}
	
	// Capitalization and grammar indicators
	if len(description) > 0 && unicode.IsUpper(rune(description[0])) {
		score += 0.1
	}
	
	// Check for meaningful content (not just repeated characters)
	uniqueChars := make(map[rune]bool)
	for _, char := range description {
		uniqueChars[char] = true
	}
	if len(uniqueChars) > 10 {
		score += 0.1
	}
	
	// Check for technical keywords that indicate quality
	technicalKeywords := []string{"api", "library", "framework", "tool", "utility", "package", "module"}
	for _, keyword := range technicalKeywords {
		if strings.Contains(strings.ToLower(description), keyword) {
			score += 0.05
			break
		}
	}
	
	// Penalize very short or very long descriptions
	if length < 10 {
		score *= 0.5
	} else if length > 2000 {
		score *= 0.7
	}
	
	return score
}

func calculateVersionComplexity(version string) float64 {
	if version == "" {
		return 0.0
	}
	
	// Count version components (e.g., "1.2.3-beta.1" has 4 components)
	parts := strings.FieldsFunc(version, func(r rune) bool {
		return r == '.' || r == '-' || r == '+'
	})
	
	complexity := float64(len(parts)) / 5.0 // Normalize to 0-1 range
	if complexity > 1.0 {
		complexity = 1.0
	}
	
	return complexity
}

func calculateUpdateFrequencyFeature(pkg *types.Package) float64 {
	// Placeholder: calculate based on version history
	// Since VersionCount doesn't exist, use a default value
	versionCount := 1.0
	
	// Simple approximation based on version count and package age
	age := calculatePackageAge(pkg)
	if age > 0 {
		return versionCount / age
	}
	
	return 0.0
}

func calculateRepoTrust(pkg *types.Package) float64 {
	// Placeholder: calculate repository trust score
	score := 0.0
	
	// Since Repository field doesn't exist, use placeholder logic
	// In real implementation, would check pkg.Metadata for repository info
	score += 0.5 // Default trust score
	
	return score
}

func calculateMaintainerTrust(pkg *types.Package) float64 {
	// Placeholder: calculate maintainer trust score
	maintainerCount := 0
	if pkg.Metadata != nil && pkg.Metadata.Maintainers != nil {
		maintainerCount = len(pkg.Metadata.Maintainers)
	}
	
	if maintainerCount == 0 {
		return 0.0
	}
	
	// Simple score based on maintainer count and known maintainers
	score := math.Min(float64(maintainerCount)/5.0, 1.0)
	return score
}

// Reputation feature calculation functions
func (rfe *ReputationFeatureExtractor) calculateMaintainerReputation(pkg *types.Package) float64 {
	if pkg.Metadata == nil || pkg.Metadata.Maintainers == nil || len(pkg.Metadata.Maintainers) == 0 {
		return 0.0
	}
	
	totalReputation := 0.0
	for _, maintainer := range pkg.Metadata.Maintainers {
		if reputation, exists := rfe.knownMaintainers[maintainer]; exists {
			totalReputation += reputation
		} else {
			totalReputation += 0.5 // Default reputation for unknown maintainers
		}
	}
	
	return totalReputation / float64(len(pkg.Metadata.Maintainers))
}

func calculatePackageAge(pkg *types.Package) float64 {
	if pkg.Metadata == nil {
		return 0.0
	}
	
	// Use PublishedAt if available, otherwise fall back to CreatedAt
	var packageTime time.Time
	if pkg.Metadata.PublishedAt != nil && !pkg.Metadata.PublishedAt.IsZero() {
		packageTime = *pkg.Metadata.PublishedAt
	} else if pkg.Metadata.CreationDate != nil && !pkg.Metadata.CreationDate.IsZero() {
		packageTime = *pkg.Metadata.CreationDate
	} else if !pkg.Metadata.CreatedAt.IsZero() {
		packageTime = pkg.Metadata.CreatedAt
	} else {
		return 0.0
	}
	
	// Calculate age in days
	ageInDays := time.Since(packageTime).Hours() / 24
	return math.Max(0, ageInDays)
}

func calculateReleaseFrequency(pkg *types.Package) float64 {
	if pkg.Metadata == nil {
		return 0.0
	}
	
	// Calculate time span between creation and last update
	var creationTime, lastUpdateTime time.Time
	
	// Get creation time
	if pkg.Metadata.PublishedAt != nil && !pkg.Metadata.PublishedAt.IsZero() {
		creationTime = *pkg.Metadata.PublishedAt
	} else if pkg.Metadata.CreationDate != nil && !pkg.Metadata.CreationDate.IsZero() {
		creationTime = *pkg.Metadata.CreationDate
	} else if !pkg.Metadata.CreatedAt.IsZero() {
		creationTime = pkg.Metadata.CreatedAt
	} else {
		return 0.0
	}
	
	// Get last update time
	if pkg.Metadata.LastUpdated != nil && !pkg.Metadata.LastUpdated.IsZero() {
		lastUpdateTime = *pkg.Metadata.LastUpdated
	} else if !pkg.Metadata.UpdatedAt.IsZero() {
		lastUpdateTime = pkg.Metadata.UpdatedAt
	} else {
		// If no update time, assume single release
		return 0.1 // Low frequency for single release
	}
	
	// Calculate time span in days
	timeSpan := lastUpdateTime.Sub(creationTime).Hours() / 24
	if timeSpan <= 0 {
		return 0.1 // Single release or invalid data
	}
	
	// Estimate release frequency (releases per month)
	// Assume at least 2 releases (creation + update) over the time span
	minReleases := 2.0
	releaseFrequency := minReleases / (timeSpan / 30.0) // releases per month
	
	// Cap the frequency to reasonable bounds
	return math.Min(releaseFrequency, 10.0) // Max 10 releases per month
}

func calculateDocumentationQuality(pkg *types.Package) float64 {
	if pkg.Metadata == nil {
		return 0.0
	}
	
	score := 0.0
	
	// Check for description quality
	description := pkg.Metadata.Description
	if len(description) > 50 {
		score += 0.2
		if len(description) > 200 {
			score += 0.1 // Bonus for detailed description
		}
	}
	
	// Check for homepage
	if pkg.Metadata.Homepage != "" {
		score += 0.2
	}
	
	// Check for repository
	if pkg.Metadata.Repository != "" {
		score += 0.2
	}
	
	// Check for license information
	if pkg.Metadata.License != "" {
		score += 0.1
	}
	
	// Check for keywords (indicates thoughtful categorization)
	if len(pkg.Metadata.Keywords) > 0 {
		score += 0.1
		if len(pkg.Metadata.Keywords) >= 3 {
			score += 0.1 // Bonus for multiple keywords
		}
	}
	
	return math.Min(score, 1.0) // Cap at 1.0
}

func calculateTestCoverage(pkg *types.Package) float64 {
	if pkg.Metadata == nil {
		return 0.0
	}
	
	score := 0.0
	
	// Check if package has test-related keywords
	for _, keyword := range pkg.Metadata.Keywords {
		lowerKeyword := strings.ToLower(keyword)
		if strings.Contains(lowerKeyword, "test") || strings.Contains(lowerKeyword, "testing") {
			score += 0.3
			break
		}
	}
	
	// Estimate based on file count (more files might indicate tests)
	if pkg.Metadata.FileCount > 10 {
		score += 0.2
		if pkg.Metadata.FileCount > 50 {
			score += 0.2 // Bonus for larger projects
		}
	}
	
	// Check for common test patterns in description
	description := strings.ToLower(pkg.Metadata.Description)
	if strings.Contains(description, "test") || strings.Contains(description, "coverage") || 
	   strings.Contains(description, "spec") || strings.Contains(description, "jest") ||
	   strings.Contains(description, "mocha") || strings.Contains(description, "pytest") {
		score += 0.3
	}
	
	return math.Min(score, 1.0) // Cap at 1.0
}

func calculateCodeQuality(pkg *types.Package) float64 {
	if pkg.Metadata == nil {
		return 0.0
	}
	
	score := 0.0
	
	// Base score for having metadata
	score += 0.1
	
	// Check for license (indicates professional development)
	if pkg.Metadata.License != "" {
		score += 0.2
	}
	
	// Check for repository (indicates version control)
	if pkg.Metadata.Repository != "" {
		score += 0.2
	}
	
	// Check for maintainers (indicates active maintenance)
	if len(pkg.Metadata.Maintainers) > 0 {
		score += 0.1
		if len(pkg.Metadata.Maintainers) > 1 {
			score += 0.1 // Bonus for multiple maintainers
		}
	}
	
	// Check for reasonable file count (not too small, not too large)
	if pkg.Metadata.FileCount >= 5 && pkg.Metadata.FileCount <= 1000 {
		score += 0.1
	}
	
	// Check for quality indicators in description
	description := strings.ToLower(pkg.Metadata.Description)
	qualityKeywords := []string{"typescript", "eslint", "prettier", "lint", "quality", "standard", "clean"}
	for _, keyword := range qualityKeywords {
		if strings.Contains(description, keyword) {
			score += 0.05
		}
	}
	
	// Check for reasonable package size (not too small, not too large)
	if pkg.Metadata.Size > 1024 && pkg.Metadata.Size < 10*1024*1024 { // 1KB to 10MB
		score += 0.1
	}
	
	return math.Min(score, 1.0) // Cap at 1.0
}

func calculateSecurityScore(pkg *types.Package) float64 {
	if pkg.Metadata == nil {
		return 0.0
	}
	
	score := 1.0 // Start with perfect security score
	
	// Penalize for detected threats
	for _, threat := range pkg.Threats {
		switch threat.Severity {
		case types.SeverityCritical:
			score -= 0.5
		case types.SeverityHigh:
			score -= 0.3
		case types.SeverityMedium:
			score -= 0.2
		case types.SeverityLow:
			score -= 0.1
		}
	}
	
	// Bonus for security-related indicators
	description := strings.ToLower(pkg.Metadata.Description)
	securityKeywords := []string{"security", "secure", "crypto", "encryption", "auth", "ssl", "tls"}
	for _, keyword := range securityKeywords {
		if strings.Contains(description, keyword) {
			score += 0.05 // Small bonus for security focus
			break
		}
	}
	
	// Check for checksums (indicates integrity verification)
	if len(pkg.Metadata.Checksums) > 0 {
		score += 0.1
	}
	
	// Penalize for install scripts (potential security risk)
	if pkg.Metadata.HasInstallScript {
		score -= 0.1
	}
	
	// Bonus for established packages (age indicates stability)
	age := calculatePackageAge(pkg)
	if age > 365 { // More than 1 year old
		score += 0.05
	}
	
	return math.Max(0.0, math.Min(score, 1.0)) // Clamp between 0 and 1
}

func calculateDependencyRisk(pkg *types.Package) float64 {
	if len(pkg.Dependencies) == 0 {
		return 0.0
	}
	
	// Simple risk calculation based on dependency count
	risk := float64(len(pkg.Dependencies)) / 100.0
	if risk > 1.0 {
		risk = 1.0
	}
	
	return risk
}

func (rfe *ReputationFeatureExtractor) calculateDomainTrust(pkg *types.Package) float64 {
	// Placeholder since Repository field doesn't exist
	repository := "" // Placeholder
	if repository == "" {
		return 0.5 // Default trust score
	}
	
	for domain := range rfe.trustedDomains {
		if strings.Contains(repository, domain) {
			return 1.0
		}
	}
	
	return 0.0
}

// Anomaly detection feature calculation functions
func calculateDownloadAnomaly(pkg *types.Package) float64 {
	// Analyze package name patterns that might indicate fake popularity
	score := 0.0
	
	// Check for suspicious download-boosting patterns
	suspiciousPatterns := []string{"popular", "trending", "viral", "hot", "top"}
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(strings.ToLower(pkg.Name), pattern) {
			score += 0.3
			break
		}
	}
	
	// Very short names might be trying to get accidental downloads
	if len(pkg.Name) < 3 {
		score += 0.4
	}
	
	// Names with excessive numbers might be suspicious
	digitCount := 0
	for _, char := range pkg.Name {
		if unicode.IsDigit(char) {
			digitCount++
		}
	}
	if digitCount > len(pkg.Name)/2 {
		score += 0.3
	}
	
	return math.Min(score, 1.0)
}

func calculateUpdateAnomaly(pkg *types.Package) float64 {
	// Analyze version patterns for unusual update behavior
	version := pkg.Version
	if version == "" {
		return 0.5 // Missing version is anomalous
	}
	
	score := 0.0
	
	// Check for unusual version patterns
	if strings.Contains(version, "999") || strings.Contains(version, "000") {
		score += 0.4 // Suspicious version numbers
	}
	
	// Check for very high version numbers (might indicate version spam)
	parts := strings.Split(version, ".")
	for _, part := range parts {
		if num, err := strconv.Atoi(part); err == nil && num > 100 {
			score += 0.3
			break
		}
	}
	
	// Check for non-standard version formats
	semverPattern := `^\d+\.\d+\.\d+`
	if matched, _ := regexp.MatchString(semverPattern, version); !matched {
		score += 0.2
	}
	
	return math.Min(score, 1.0)
}

func calculateSizeAnomaly(pkg *types.Package) float64 {
	// Estimate size anomalies based on name and dependency patterns
	score := 0.0
	
	// Packages with many dependencies might be unusually large
	depCount := len(pkg.Dependencies)
	if depCount > 50 {
		score += 0.4
	} else if depCount > 20 {
		score += 0.2
	}
	
	// Very short names might indicate minimal packages
	if len(pkg.Name) < 4 {
		score += 0.2
	}
	
	// Names suggesting size issues
	sizeKeywords := []string{"tiny", "micro", "mini", "huge", "massive", "bloated"}
	for _, keyword := range sizeKeywords {
		if strings.Contains(strings.ToLower(pkg.Name), keyword) {
			score += 0.3
			break
		}
	}
	
	return math.Min(score, 1.0)
}

func calculateDescriptionAnomaly(pkg *types.Package) float64 {
	description := ""
	if pkg.Metadata != nil {
		description = pkg.Metadata.Description
	}
	
	if description == "" {
		return 0.6 // Missing description is anomalous
	}
	
	score := 0.0
	
	// Check for very short or very long descriptions
	descLen := len(description)
	if descLen < 10 {
		score += 0.4
	} else if descLen > 500 {
		score += 0.3
	}
	
	// Check for suspicious content
	suspiciousWords := []string{"hack", "crack", "exploit", "malware", "virus"}
	for _, word := range suspiciousWords {
		if strings.Contains(strings.ToLower(description), word) {
			score += 0.8
			break
		}
	}
	
	// Check for excessive repetition
	words := strings.Fields(description)
	if len(words) > 0 {
		wordCount := make(map[string]int)
		for _, word := range words {
			wordCount[strings.ToLower(word)]++
		}
		
		maxRepeat := 0
		for _, count := range wordCount {
			if count > maxRepeat {
				maxRepeat = count
			}
		}
		
		if maxRepeat > len(words)/3 {
			score += 0.3 // Too much repetition
		}
	}
	
	return math.Min(score, 1.0)
}

func calculateVersionAnomaly(pkg *types.Package) float64 {
	version := pkg.Version
	if version == "" {
		return 0.7 // Missing version is highly anomalous
	}
	
	score := 0.0
	
	// Check for suspicious version patterns
	suspiciousPatterns := []string{
		`0\.0\.0`,     // Null version
		`999\.`,       // Suspicious high numbers
		`\.999`,       // Suspicious high numbers
		`[a-zA-Z]{5,}`, // Long alphabetic strings
	}
	
	for _, pattern := range suspiciousPatterns {
		if matched, _ := regexp.MatchString(pattern, version); matched {
			score += 0.4
			break
		}
	}
	
	// Check for unusual characters
	allowedChars := regexp.MustCompile(`^[0-9a-zA-Z.\-+]+$`)
	if !allowedChars.MatchString(version) {
		score += 0.3
	}
	
	// Check for excessive length
	if len(version) > 20 {
		score += 0.2
	}
	
	return math.Min(score, 1.0)
}

func calculateMaintainerAnomaly(pkg *types.Package) float64 {
	if pkg.Metadata == nil || pkg.Metadata.Maintainers == nil {
		return 0.5 // No maintainer info is somewhat anomalous
	}
	
	maintainerCount := len(pkg.Metadata.Maintainers)
	score := 0.0
	
	// No maintainers is highly anomalous
	if maintainerCount == 0 {
		return 0.8
	}
	
	// Too many maintainers might be suspicious
	if maintainerCount > 10 {
		score += 0.3
	}
	
	// Check for suspicious maintainer patterns
	for _, maintainer := range pkg.Metadata.Maintainers {
		maintainerLower := strings.ToLower(maintainer)
		
		// Very short maintainer names
		if len(maintainer) < 3 {
			score += 0.2
		}
		
		// Suspicious keywords
		suspiciousKeywords := []string{"admin", "root", "test", "fake", "temp"}
		for _, keyword := range suspiciousKeywords {
			if strings.Contains(maintainerLower, keyword) {
				score += 0.4
				break
			}
		}
	}
	
	return math.Min(score, 1.0)
}

func calculateDependencyAnomaly(pkg *types.Package) float64 {
	depCount := len(pkg.Dependencies)
	score := 0.0
	
	// Excessive dependencies
	if depCount > 100 {
		score += 0.6
	} else if depCount > 50 {
		score += 0.4
	} else if depCount > 20 {
		score += 0.2
	}
	
	// No dependencies for non-utility packages might be suspicious
	if depCount == 0 {
		utilityKeywords := []string{"util", "helper", "tool", "lib", "core"}
		isUtility := false
		for _, keyword := range utilityKeywords {
			if strings.Contains(strings.ToLower(pkg.Name), keyword) {
				isUtility = true
				break
			}
		}
		if !isUtility {
			score += 0.3
		}
	}
	
	// Check for suspicious dependency patterns
	for _, dep := range pkg.Dependencies {
		// Dependencies with very short names
		if len(dep.Name) < 3 {
			score += 0.1
		}
		
		// Self-referential dependencies
		if dep.Name == pkg.Name {
			score += 0.5
		}
	}
	
	return math.Min(score, 1.0)
}

func calculateCircularDependency(pkg *types.Package) float64 {
	// Simple circular dependency detection
	score := 0.0
	
	// Check if package depends on itself
	for _, dep := range pkg.Dependencies {
		if dep.Name == pkg.Name {
			return 1.0 // Direct self-dependency
		}
		
		// Check for similar names (potential circular dependencies)
		if calculateLevenshteinDistance(dep.Name, pkg.Name) <= 2 && len(dep.Name) > 3 {
			score += 0.3
		}
	}
	
	return math.Min(score, 1.0)
}

// calculateLevenshteinDistance calculates the Levenshtein distance between two strings
func calculateLevenshteinDistance(s1, s2 string) int {
	if len(s1) == 0 {
		return len(s2)
	}
	if len(s2) == 0 {
		return len(s1)
	}

	matrix := make([][]int, len(s1)+1)
	for i := range matrix {
		matrix[i] = make([]int, len(s2)+1)
	}

	for i := 0; i <= len(s1); i++ {
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

// min3 returns the minimum of three integers
func min3(a, b, c int) int {
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

func calculateTemporalAnomaly(pkg *types.Package) float64 {
	// Analyze temporal patterns based on version and naming
	score := 0.0
	
	// Check for time-related keywords that might indicate temporal manipulation
	timeKeywords := []string{"time", "date", "clock", "schedule", "cron", "timer"}
	for _, keyword := range timeKeywords {
		if strings.Contains(strings.ToLower(pkg.Name), keyword) {
			// These packages might legitimately have temporal features
			return 0.1
		}
	}
	
	// Check for suspicious version timing patterns
	version := pkg.Version
	if version != "" {
		// Multiple zeros might indicate timestamp manipulation
		if strings.Count(version, "0") > len(version)/2 {
			score += 0.3
		}
	}
	
	return math.Min(score, 1.0)
}

func calculateActivityAnomaly(pkg *types.Package) float64 {
	// Analyze activity patterns based on available data
	score := 0.0
	
	// Check for activity-related keywords
	activityKeywords := []string{"active", "busy", "idle", "dormant", "dead"}
	for _, keyword := range activityKeywords {
		if strings.Contains(strings.ToLower(pkg.Name), keyword) {
			score += 0.2
			break
		}
	}
	
	// Packages with no dependencies might be inactive
	if len(pkg.Dependencies) == 0 {
		score += 0.1
	}
	
	// Very simple version numbers might indicate low activity
	if pkg.Version == "1.0.0" || pkg.Version == "0.1.0" {
		score += 0.2
	}
	
	return math.Min(score, 1.0)
}

func calculateContentAnomaly(pkg *types.Package) float64 {
	// Analyze content patterns for anomalies
	score := 0.0
	
	// Check package name for content-related anomalies
	name := pkg.Name
	
	// Names with mixed case might be suspicious
	hasUpper := false
	hasLower := false
	for _, char := range name {
		if unicode.IsUpper(char) {
			hasUpper = true
		}
		if unicode.IsLower(char) {
			hasLower = true
		}
	}
	if hasUpper && hasLower {
		score += 0.2
	}
	
	// Check for content-related suspicious keywords
	suspiciousContent := []string{"content", "data", "payload", "binary", "encoded"}
	for _, keyword := range suspiciousContent {
		if strings.Contains(strings.ToLower(name), keyword) {
			score += 0.3
			break
		}
	}
	
	// Check description for content anomalies
	if pkg.Metadata != nil && pkg.Metadata.Description != "" {
		desc := strings.ToLower(pkg.Metadata.Description)
		if strings.Contains(desc, "binary") || strings.Contains(desc, "encoded") {
			score += 0.4
		}
	}
	
	return math.Min(score, 1.0)
}

func calculateStructureAnomaly(pkg *types.Package) float64 {
	// Analyze package structure for anomalies
	score := 0.0
	
	// Check for structural keywords in name
	structureKeywords := []string{"struct", "schema", "format", "layout", "template"}
	for _, keyword := range structureKeywords {
		if strings.Contains(strings.ToLower(pkg.Name), keyword) {
			// These might legitimately have structural features
			return 0.1
		}
	}
	
	// Check for unusual naming structure
	name := pkg.Name
	
	// Names with many separators might be suspicious
	separatorCount := strings.Count(name, "-") + strings.Count(name, "_") + strings.Count(name, ".")
	if separatorCount > len(name)/3 {
		score += 0.3
	}
	
	// Names starting or ending with separators
	if strings.HasPrefix(name, "-") || strings.HasPrefix(name, "_") ||
	   strings.HasSuffix(name, "-") || strings.HasSuffix(name, "_") {
		score += 0.4
	}
	
	// Check dependency structure
	depCount := len(pkg.Dependencies)
	if depCount > 0 {
		// All dependencies being very short might indicate structural issues
		shortDeps := 0
		for _, dep := range pkg.Dependencies {
			if len(dep.Name) < 4 {
				shortDeps++
			}
		}
		if shortDeps > depCount/2 {
			score += 0.3
		}
	}
	
	return math.Min(score, 1.0)
}