package ml

import (
	"fmt"
	"math"
	"strings"
	"time"

	"typosentinel/pkg/types"
)

// BasicMLScorer implements a simple machine learning scoring algorithm
// for detecting malicious packages based on extracted features
type BasicMLScorer struct {
	config *BasicScorerConfig
	weights map[string]float64
	bias float64
	featureStats map[string]FeatureStats
}

// BasicScorerConfig holds configuration for the basic ML scorer
type BasicScorerConfig struct {
	MaliciousThreshold float64
	SuspiciousThreshold float64
	MinConfidence float64
	FeatureWeights map[string]float64
	NormalizationEnabled bool
}

// FeatureStats holds statistics for feature normalization
type FeatureStats struct {
	Mean float64
	StdDev float64
	Min float64
	Max float64
}

// BasicPackageFeatures represents extracted features from a package for basic ML scoring
type BasicPackageFeatures struct {
	DownloadCount float64
	MaintainerReputation float64
	PackageAge float64
	VersionCount float64
	DescriptionLength float64
	DependencyCount float64
	TyposquattingSimilarity float64
	NameEntropy float64
	UpdateFrequency float64
	LicensePresent float64
	ReadmePresent float64
	HomepagePresent float64
	RepositoryPresent float64
	KeywordCount float64
	MaintainerCount float64
}

// MLScore represents the output of the ML scoring algorithm
type MLScore struct {
	MaliciousScore float64
	Confidence float64
	RiskLevel string
	Features BasicPackageFeatures
	ContributingFactors []string
	Recommendation string
	Timestamp time.Time
}

// NewBasicMLScorer creates a new basic ML scorer with default configuration
func NewBasicMLScorer() *BasicMLScorer {
	config := &BasicScorerConfig{
		MaliciousThreshold: 0.7,
		SuspiciousThreshold: 0.4,
		MinConfidence: 0.6,
		NormalizationEnabled: true,
		FeatureWeights: map[string]float64{
			"download_count": -0.3, // More downloads = less suspicious
			"maintainer_reputation": -0.4, // Better reputation = less suspicious
			"package_age": -0.2, // Older packages = less suspicious
			"version_count": -0.1, // More versions = less suspicious
			"description_length": -0.1, // Longer description = less suspicious
			"dependency_count": 0.05, // More dependencies = slightly more suspicious
			"typosquatting_similarity": 0.8, // High similarity = very suspicious
			"name_entropy": 0.3, // Random names = suspicious
			"update_frequency": -0.1, // Regular updates = less suspicious
			"license_present": -0.2, // License present = less suspicious
			"readme_present": -0.15, // README present = less suspicious
			"homepage_present": -0.1, // Homepage present = less suspicious
			"repository_present": -0.25, // Repository present = less suspicious
			"keyword_count": -0.05, // More keywords = less suspicious
			"maintainer_count": -0.1, // More maintainers = less suspicious
		},
	}

	scorer := &BasicMLScorer{
		config: config,
		weights: config.FeatureWeights,
		bias: 0.5, // Default bias
		featureStats: make(map[string]FeatureStats),
	}

	// Initialize feature statistics with reasonable defaults
	scorer.initializeFeatureStats()

	return scorer
}

// initializeFeatureStats sets up default feature statistics for normalization
func (bms *BasicMLScorer) initializeFeatureStats() {
	// These are rough estimates based on typical package statistics
	bms.featureStats = map[string]FeatureStats{
		"download_count": {Mean: 10000, StdDev: 50000, Min: 0, Max: 1000000},
		"maintainer_reputation": {Mean: 0.5, StdDev: 0.3, Min: 0, Max: 1},
		"package_age": {Mean: 365, StdDev: 500, Min: 0, Max: 3650}, // days
		"version_count": {Mean: 10, StdDev: 20, Min: 1, Max: 100},
		"description_length": {Mean: 100, StdDev: 80, Min: 0, Max: 500},
		"dependency_count": {Mean: 5, StdDev: 10, Min: 0, Max: 50},
		"typosquatting_similarity": {Mean: 0.1, StdDev: 0.2, Min: 0, Max: 1},
		"name_entropy": {Mean: 3.0, StdDev: 1.0, Min: 0, Max: 5},
		"update_frequency": {Mean: 0.1, StdDev: 0.2, Min: 0, Max: 1}, // updates per day
		"license_present": {Mean: 0.8, StdDev: 0.4, Min: 0, Max: 1},
		"readme_present": {Mean: 0.9, StdDev: 0.3, Min: 0, Max: 1},
		"homepage_present": {Mean: 0.6, StdDev: 0.5, Min: 0, Max: 1},
		"repository_present": {Mean: 0.85, StdDev: 0.35, Min: 0, Max: 1},
		"keyword_count": {Mean: 3, StdDev: 3, Min: 0, Max: 20},
		"maintainer_count": {Mean: 1.5, StdDev: 1.0, Min: 1, Max: 10},
	}
}

// ExtractFeatures extracts features from a package dependency
func (bms *BasicMLScorer) ExtractFeatures(dep types.Dependency, metadata map[string]interface{}) BasicPackageFeatures {
	features := BasicPackageFeatures{}

	// Extract download count
	if downloads, ok := metadata["downloads"].(float64); ok {
		features.DownloadCount = downloads
	}

	// Extract maintainer reputation (simplified)
	if maintainers, ok := metadata["maintainers"].([]interface{}); ok {
		features.MaintainerCount = float64(len(maintainers))
		// Simple reputation based on maintainer count and package age
		features.MaintainerReputation = math.Min(1.0, float64(len(maintainers))*0.3+0.2)
	}

	// Extract package age
	if createdAt, ok := metadata["created"].(time.Time); ok {
		features.PackageAge = time.Since(createdAt).Hours() / 24 // days
	}

	// Extract version count
	if versions, ok := metadata["versions"].([]interface{}); ok {
		features.VersionCount = float64(len(versions))
	}

	// Extract description length
	if description, ok := metadata["description"].(string); ok {
		features.DescriptionLength = float64(len(description))
	}

	// Extract dependency count
	if dependencies, ok := metadata["dependencies"].(map[string]interface{}); ok {
		features.DependencyCount = float64(len(dependencies))
	}

	// Calculate name entropy
	features.NameEntropy = bms.calculateEntropy(dep.Name)

	// Extract boolean features
	features.LicensePresent = bms.boolToFloat(metadata["license"] != nil)
	features.ReadmePresent = bms.boolToFloat(metadata["readme"] != nil)
	features.HomepagePresent = bms.boolToFloat(metadata["homepage"] != nil)
	features.RepositoryPresent = bms.boolToFloat(metadata["repository"] != nil)

	// Extract keyword count
	if keywords, ok := metadata["keywords"].([]interface{}); ok {
		features.KeywordCount = float64(len(keywords))
	}

	// Calculate update frequency (simplified)
	if lastModified, ok := metadata["modified"].(time.Time); ok {
		if features.PackageAge > 0 {
			daysSinceUpdate := time.Since(lastModified).Hours() / 24
			features.UpdateFrequency = 1.0 / (daysSinceUpdate + 1) // Inverse of days since last update
		}
	}

	return features
}

// ScorePackage calculates a malicious score for a package
func (bms *BasicMLScorer) ScorePackage(features BasicPackageFeatures) MLScore {
	// Normalize features if enabled
	normalizedFeatures := features
	if bms.config.NormalizationEnabled {
		normalizedFeatures = bms.normalizeFeatures(features)
	}

	// Calculate weighted sum (logistic regression)
	weightedSum := bms.bias
	contributingFactors := []string{}

	// Apply weights to each feature
	featureMap := bms.featuresToMap(normalizedFeatures)
	for featureName, value := range featureMap {
		if weight, exists := bms.weights[featureName]; exists {
			contribution := weight * value
			weightedSum += contribution

			// Track significant contributing factors
			if math.Abs(contribution) > 0.1 {
				if contribution > 0 {
					contributingFactors = append(contributingFactors, fmt.Sprintf("+%s (%.2f)", featureName, contribution))
				} else {
					contributingFactors = append(contributingFactors, fmt.Sprintf("%s (%.2f)", featureName, contribution))
				}
			}
		}
	}

	// Apply sigmoid function to get probability
	maliciousScore := bms.sigmoid(weightedSum)

	// Calculate confidence based on feature completeness and score extremity
	confidence := bms.calculateConfidence(features, maliciousScore)

	// Determine risk level
	riskLevel := bms.determineRiskLevel(maliciousScore)

	// Generate recommendation
	recommendation := bms.generateRecommendation(maliciousScore, contributingFactors)

	return MLScore{
		MaliciousScore: maliciousScore,
		Confidence: confidence,
		RiskLevel: riskLevel,
		Features: features,
		ContributingFactors: contributingFactors,
		Recommendation: recommendation,
		Timestamp: time.Now(),
	}
}

// normalizeFeatures normalizes features using z-score normalization
func (bms *BasicMLScorer) normalizeFeatures(features BasicPackageFeatures) BasicPackageFeatures {
	normalized := features
	featureMap := bms.featuresToMap(features)

	for featureName, value := range featureMap {
		if stats, exists := bms.featureStats[featureName]; exists && stats.StdDev > 0 {
			normalizedValue := (value - stats.Mean) / stats.StdDev
			// Clamp to reasonable range
			normalizedValue = math.Max(-3, math.Min(3, normalizedValue))
			bms.setFeatureValue(&normalized, featureName, normalizedValue)
		}
	}

	return normalized
}

// featuresToMap converts BasicPackageFeatures struct to map for easier processing
func (bms *BasicMLScorer) featuresToMap(features BasicPackageFeatures) map[string]float64 {
	return map[string]float64{
		"download_count": features.DownloadCount,
		"maintainer_reputation": features.MaintainerReputation,
		"package_age": features.PackageAge,
		"version_count": features.VersionCount,
		"description_length": features.DescriptionLength,
		"dependency_count": features.DependencyCount,
		"typosquatting_similarity": features.TyposquattingSimilarity,
		"name_entropy": features.NameEntropy,
		"update_frequency": features.UpdateFrequency,
		"license_present": features.LicensePresent,
		"readme_present": features.ReadmePresent,
		"homepage_present": features.HomepagePresent,
		"repository_present": features.RepositoryPresent,
		"keyword_count": features.KeywordCount,
		"maintainer_count": features.MaintainerCount,
	}
}

// setFeatureValue sets a feature value by name
func (bms *BasicMLScorer) setFeatureValue(features *BasicPackageFeatures, name string, value float64) {
	switch name {
	case "download_count":
		features.DownloadCount = value
	case "maintainer_reputation":
		features.MaintainerReputation = value
	case "package_age":
		features.PackageAge = value
	case "version_count":
		features.VersionCount = value
	case "description_length":
		features.DescriptionLength = value
	case "dependency_count":
		features.DependencyCount = value
	case "typosquatting_similarity":
		features.TyposquattingSimilarity = value
	case "name_entropy":
		features.NameEntropy = value
	case "update_frequency":
		features.UpdateFrequency = value
	case "license_present":
		features.LicensePresent = value
	case "readme_present":
		features.ReadmePresent = value
	case "homepage_present":
		features.HomepagePresent = value
	case "repository_present":
		features.RepositoryPresent = value
	case "keyword_count":
		features.KeywordCount = value
	case "maintainer_count":
		features.MaintainerCount = value
	}
}

// sigmoid applies the sigmoid activation function
func (bms *BasicMLScorer) sigmoid(x float64) float64 {
	return 1.0 / (1.0 + math.Exp(-x))
}

// calculateEntropy calculates the entropy of a string (measure of randomness)
func (bms *BasicMLScorer) calculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	// Count character frequencies
	freq := make(map[rune]int)
	for _, char := range strings.ToLower(s) {
		freq[char]++
	}

	// Calculate entropy
	entropy := 0.0
	length := float64(len(s))
	for _, count := range freq {
		p := float64(count) / length
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

// boolToFloat converts boolean to float64
func (bms *BasicMLScorer) boolToFloat(b bool) float64 {
	if b {
		return 1.0
	}
	return 0.0
}

// calculateConfidence calculates confidence based on feature completeness and score
func (bms *BasicMLScorer) calculateConfidence(features BasicPackageFeatures, score float64) float64 {
	// Count non-zero features (feature completeness)
	featureMap := bms.featuresToMap(features)
	nonZeroFeatures := 0
	totalFeatures := len(featureMap)

	for _, value := range featureMap {
		if value != 0 {
			nonZeroFeatures++
		}
	}

	completeness := float64(nonZeroFeatures) / float64(totalFeatures)

	// Higher confidence for extreme scores and complete features
	scoreConfidence := math.Abs(score - 0.5) * 2 // 0 at score=0.5, 1 at score=0 or 1

	// Combine completeness and score confidence
	confidence := (completeness*0.6 + scoreConfidence*0.4)

	// Ensure minimum confidence threshold
	return math.Max(bms.config.MinConfidence, confidence)
}

// determineRiskLevel determines risk level based on malicious score
func (bms *BasicMLScorer) determineRiskLevel(score float64) string {
	if score >= bms.config.MaliciousThreshold {
		return "HIGH"
	} else if score >= bms.config.SuspiciousThreshold {
		return "MEDIUM"
	}
	return "LOW"
}

// generateRecommendation generates a recommendation based on the analysis
func (bms *BasicMLScorer) generateRecommendation(score float64, factors []string) string {
	if score >= bms.config.MaliciousThreshold {
		return "BLOCK: High probability of malicious package. Do not install."
	} else if score >= bms.config.SuspiciousThreshold {
		return "CAUTION: Suspicious package detected. Review carefully before installation."
	}
	return "PROCEED: Package appears safe based on available features."
}

// UpdateFeatureStats updates feature statistics for better normalization
func (bms *BasicMLScorer) UpdateFeatureStats(features []BasicPackageFeatures) {
	if len(features) == 0 {
		return
	}

	// Calculate statistics for each feature
	for featureName := range bms.featureStats {
		values := make([]float64, len(features))
		for i, feature := range features {
				featureMap := bms.featuresToMap(feature)
			values[i] = featureMap[featureName]
		}

		// Calculate mean
		sum := 0.0
		for _, v := range values {
			sum += v
		}
		mean := sum / float64(len(values))

		// Calculate standard deviation
		varSum := 0.0
		for _, v := range values {
			varSum += (v - mean) * (v - mean)
		}
		stdDev := math.Sqrt(varSum / float64(len(values)))

		// Find min and max
		min, max := values[0], values[0]
		for _, v := range values {
			if v < min {
				min = v
			}
			if v > max {
				max = v
			}
		}

		// Update feature stats
		bms.featureStats[featureName] = FeatureStats{
			Mean: mean,
			StdDev: stdDev,
			Min: min,
			Max: max,
		}
	}
}