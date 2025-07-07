package ml

import (
	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/pkg/logger"
	"github.com/Alivanroy/Typosentinel/pkg/types"
	"math"
	"regexp"
	"strings"
	"time"
)

// AdvancedFeatureExtractor implements sophisticated feature extraction for ML models
type AdvancedFeatureExtractor struct {
	config              *config.Config
	popularPackages     map[string][]string // Registry -> package names
	suspiciousKeywords  []string
	domainReputations   map[string]float64
	licenseScores       map[string]float64
	normalizationParams *NormalizationParams
}

// NormalizationParams contains parameters for feature normalization
type NormalizationParams struct {
	Means   []float64 `json:"means"`
	StdDevs []float64 `json:"std_devs"`
	Mins    []float64 `json:"mins"`
	Maxs    []float64 `json:"maxs"`
}

// NewAdvancedFeatureExtractor creates a new advanced feature extractor
func NewAdvancedFeatureExtractor() *AdvancedFeatureExtractor {
	return &AdvancedFeatureExtractor{
		popularPackages:     make(map[string][]string),
		domainReputations:   make(map[string]float64),
		licenseScores:       make(map[string]float64),
		normalizationParams: &NormalizationParams{},
	}
}

// Initialize initializes the feature extractor with configuration and data
func (e *AdvancedFeatureExtractor) Initialize(config *config.Config) error {
	e.config = config

	// Initialize popular packages lists
	e.initializePopularPackages()

	// Initialize suspicious keywords
	e.initializeSuspiciousKeywords()

	// Initialize domain reputations
	e.initializeDomainReputations()

	// Initialize license scores
	e.initializeLicenseScores()

	// Initialize normalization parameters
	e.initializeNormalizationParams()

	logger.Info("Advanced feature extractor initialized")
	return nil
}

// ExtractFeatures extracts comprehensive features from a package
func (e *AdvancedFeatureExtractor) ExtractFeatures(pkg *types.Package) (*PackageFeatures, error) {
	logger.TraceFunction("AdvancedFeatureExtractor.ExtractFeatures")

	features := &PackageFeatures{
		Registry:    pkg.Registry,
		PackageType: pkg.Type,
	}

	// Extract basic package features
	e.extractBasicFeatures(pkg, features)

	// Extract reputation features
	e.extractReputationFeatures(pkg, features)

	// Extract security features
	e.extractSecurityFeatures(pkg, features)

	// Extract behavioral features
	e.extractBehavioralFeatures(pkg, features)

	return features, nil
}

// GetFeatureNames returns the names of all extracted features
func (e *AdvancedFeatureExtractor) GetFeatureNames() []string {
	return []string{
		"name_length",
		"version_complexity",
		"description_length",
		"dependency_count",
		"download_count",
		"star_count",
		"fork_count",
		"contributor_count",
		"age_in_days",
		"typosquatting_score",
		"suspicious_keywords",
		"version_spoofing",
		"domain_reputation",
		"update_frequency",
		"maintainer_count",
		"issue_count",
		"license_score",
	}
}

// NormalizeFeatures normalizes features for ML model input
func (e *AdvancedFeatureExtractor) NormalizeFeatures(features *PackageFeatures) []float64 {
	// Convert features to slice
	rawFeatures := []float64{
		float64(features.NameLength),
		features.VersionComplexity,
		float64(features.DescriptionLength),
		float64(features.DependencyCount),
		float64(features.DownloadCount),
		float64(features.StarCount),
		float64(features.ForkCount),
		float64(features.ContributorCount),
		float64(features.AgeInDays),
		features.TyposquattingScore,
		float64(features.SuspiciousKeywords),
		features.VersionSpoofing,
		features.DomainReputation,
		features.UpdateFrequency,
		float64(features.MaintainerCount),
		float64(features.IssueCount),
		features.LicenseScore,
	}

	// Apply normalization
	normalized := make([]float64, len(rawFeatures))
	for i, value := range rawFeatures {
		normalized[i] = e.normalizeValue(value, i)
	}

	return normalized
}

// extractBasicFeatures extracts basic package characteristics
func (e *AdvancedFeatureExtractor) extractBasicFeatures(pkg *types.Package, features *PackageFeatures) {
	// Name length (normalized)
	features.NameLength = len(pkg.Name)

	// Version complexity (number of dots, pre-release indicators, etc.)
	features.VersionComplexity = e.calculateVersionComplexity(pkg.Version)

	// Description length
	if pkg.Metadata != nil {
		if desc, ok := pkg.Metadata.Metadata["description"].(string); ok {
			features.DescriptionLength = len(desc)
		}
	}

	// Dependency count
	if pkg.Metadata != nil && pkg.Metadata.Dependencies != nil {
		features.DependencyCount = len(pkg.Metadata.Dependencies)
	}
}

// extractReputationFeatures extracts reputation-based features
func (e *AdvancedFeatureExtractor) extractReputationFeatures(pkg *types.Package, features *PackageFeatures) {
	if pkg.Metadata == nil {
		return
	}

	// Download count (log-scaled)
	if downloads, ok := pkg.Metadata.Metadata["downloads"].(float64); ok {
		features.DownloadCount = int64(math.Log10(downloads + 1))
	}

	// Star count (log-scaled)
	if stars, ok := pkg.Metadata.Metadata["stars"].(float64); ok {
		features.StarCount = int(math.Log10(stars + 1))
	}

	// Fork count (log-scaled)
	if forks, ok := pkg.Metadata.Metadata["forks"].(float64); ok {
		features.ForkCount = int(math.Log10(forks + 1))
	}

	// Contributor count
	if contributors, ok := pkg.Metadata.Metadata["contributors"].(float64); ok {
		features.ContributorCount = int(contributors)
	}

	// Age in days
	if createdAt, ok := pkg.Metadata.Metadata["created_at"].(time.Time); ok {
		features.AgeInDays = int(time.Since(createdAt).Hours() / 24)
	} else if createdStr, ok := pkg.Metadata.Metadata["created_at"].(string); ok {
		if createdTime, err := time.Parse(time.RFC3339, createdStr); err == nil {
			features.AgeInDays = int(time.Since(createdTime).Hours() / 24)
		}
	}
}

// extractSecurityFeatures extracts security-related features
func (e *AdvancedFeatureExtractor) extractSecurityFeatures(pkg *types.Package, features *PackageFeatures) {
	// Typosquatting score
	features.TyposquattingScore = e.calculateTyposquattingScore(pkg.Name, pkg.Registry)

	// Suspicious keywords score
	features.SuspiciousKeywords = int(e.calculateSuspiciousKeywordsScore(pkg))

	// Version spoofing score
	features.VersionSpoofing = e.calculateVersionSpoofingScore(pkg.Version)

	// Domain reputation score
	features.DomainReputation = e.calculateDomainReputationScore(pkg.Name)
}

// extractBehavioralFeatures extracts behavioral features
func (e *AdvancedFeatureExtractor) extractBehavioralFeatures(pkg *types.Package, features *PackageFeatures) {
	if pkg.Metadata == nil {
		return
	}

	// Update frequency (releases per month)
	if lastUpdate, ok := pkg.Metadata.Metadata["last_updated"].(time.Time); ok {
		if createdAt, ok := pkg.Metadata.Metadata["created_at"].(time.Time); ok {
			duration := lastUpdate.Sub(createdAt)
			if duration.Hours() > 0 {
				months := duration.Hours() / (24 * 30)
				if releases, ok := pkg.Metadata.Metadata["release_count"].(float64); ok {
					features.UpdateFrequency = releases / months
				}
			}
		}
	}

	// Maintainer count
	if maintainers, ok := pkg.Metadata.Metadata["maintainers"].(float64); ok {
		features.MaintainerCount = int(maintainers)
	}

	// Issue count (normalized by age)
	if issues, ok := pkg.Metadata.Metadata["open_issues"].(float64); ok {
		if features.AgeInDays > 0 {
			features.IssueCount = int(issues / (float64(features.AgeInDays) / 365)) // Issues per year
		} else {
			features.IssueCount = int(issues)
		}
	}

	// License score
	if license, ok := pkg.Metadata.Metadata["license"].(string); ok {
		features.LicenseScore = e.calculateLicenseScore(license)
	}
}

// calculateVersionComplexity calculates the complexity of a version string
func (e *AdvancedFeatureExtractor) calculateVersionComplexity(version string) float64 {
	if version == "" {
		return 0
	}

	complexity := 0.0

	// Count dots (semantic versioning components)
	complexity += float64(strings.Count(version, "."))

	// Pre-release indicators
	preReleasePatterns := []string{"alpha", "beta", "rc", "dev", "snapshot"}
	for _, pattern := range preReleasePatterns {
		if strings.Contains(strings.ToLower(version), pattern) {
			complexity += 0.5
		}
	}

	// Build metadata
	if strings.Contains(version, "+") {
		complexity += 0.3
	}

	// Very long versions might be suspicious
	if len(version) > 20 {
		complexity += 1.0
	}

	return complexity
}

// calculateTyposquattingScore calculates typosquatting likelihood
func (e *AdvancedFeatureExtractor) calculateTyposquattingScore(packageName, registry string) float64 {
	popularPackages, exists := e.popularPackages[registry]
	if !exists {
		return 0.0
	}

	maxSimilarity := 0.0
	for _, popular := range popularPackages {
		similarity := e.calculateStringSimilarity(packageName, popular)
		if similarity > maxSimilarity && packageName != popular {
			maxSimilarity = similarity
		}
	}

	// Convert similarity to suspicion score
	if maxSimilarity > 0.8 {
		return maxSimilarity
	}
	return 0.0
}

// calculateSuspiciousKeywordsScore calculates suspicious keywords score
func (e *AdvancedFeatureExtractor) calculateSuspiciousKeywordsScore(pkg *types.Package) float64 {
	score := 0.0
	totalWords := 0

	// Check package name
	nameLower := strings.ToLower(pkg.Name)
	nameWords := strings.FieldsFunc(nameLower, func(r rune) bool {
		return r == '-' || r == '_' || r == '.' || r == '/'
	})
	totalWords += len(nameWords)

	for _, word := range nameWords {
		for _, suspicious := range e.suspiciousKeywords {
			if strings.Contains(word, suspicious) {
				score += 1.0
				break
			}
		}
	}

	// Check description if available
	if pkg.Metadata != nil {
		if desc, ok := pkg.Metadata.Metadata["description"].(string); ok {
			descLower := strings.ToLower(desc)
			descWords := strings.Fields(descLower)
			totalWords += len(descWords)

			for _, word := range descWords {
				for _, suspicious := range e.suspiciousKeywords {
					if strings.Contains(word, suspicious) {
						score += 0.5 // Lower weight for description
						break
					}
				}
			}
		}
	}

	if totalWords == 0 {
		return 0.0
	}

	return score / float64(totalWords)
}

// calculateVersionSpoofingScore calculates version spoofing likelihood
func (e *AdvancedFeatureExtractor) calculateVersionSpoofingScore(version string) float64 {
	if version == "" {
		return 0.0
	}

	score := 0.0

	// Very high version numbers
	if strings.Contains(version, "999") || strings.Contains(version, "9999") {
		score += 0.8
	}

	// Suspicious pre-release patterns
	suspiciousPatterns := []string{"dev999", "alpha999", "beta999", "rc999"}
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(version, pattern) {
			score += 0.6
			break
		}
	}

	// Extremely long version strings
	if len(version) > 50 {
		score += 0.4
	}

	// Multiple consecutive numbers
	if matched, _ := regexp.MatchString(`\d{5,}`, version); matched {
		score += 0.3
	}

	return math.Min(score, 1.0)
}

// calculateDomainReputationScore calculates domain reputation score
func (e *AdvancedFeatureExtractor) calculateDomainReputationScore(packageName string) float64 {
	// Extract domain from package name (for packages like github.com/user/repo)
	parts := strings.Split(packageName, "/")
	if len(parts) == 0 {
		return 0.5 // Neutral score
	}

	domain := parts[0]
	if reputation, exists := e.domainReputations[domain]; exists {
		return reputation
	}

	// Default reputation based on domain characteristics
	if strings.Contains(domain, "github.com") || strings.Contains(domain, "gitlab.com") {
		return 0.8 // High reputation
	}
	if strings.Contains(domain, "bitbucket.org") {
		return 0.7
	}

	// Check for suspicious domain patterns
	suspiciousDomains := []string{"bit.ly", "tinyurl.com", "t.co", "goo.gl"}
	for _, suspicious := range suspiciousDomains {
		if strings.Contains(domain, suspicious) {
			return 0.1 // Very low reputation
		}
	}

	return 0.5 // Neutral score for unknown domains
}

// calculateLicenseScore calculates license trustworthiness score
func (e *AdvancedFeatureExtractor) calculateLicenseScore(license string) float64 {
	if license == "" {
		return 0.3 // Low score for missing license
	}

	licenseLower := strings.ToLower(license)
	if score, exists := e.licenseScores[licenseLower]; exists {
		return score
	}

	// Default scoring for unknown licenses
	if strings.Contains(licenseLower, "mit") || strings.Contains(licenseLower, "apache") ||
		strings.Contains(licenseLower, "bsd") || strings.Contains(licenseLower, "gpl") {
		return 0.8
	}

	return 0.5 // Neutral score for unknown licenses
}

// calculateStringSimilarity calculates similarity between two strings using Jaro-Winkler
func (e *AdvancedFeatureExtractor) calculateStringSimilarity(s1, s2 string) float64 {
	if s1 == s2 {
		return 1.0
	}

	// Simple implementation of Jaro similarity
	len1, len2 := len(s1), len(s2)
	if len1 == 0 || len2 == 0 {
		return 0.0
	}

	matchWindow := max(len1, len2)/2 - 1
	if matchWindow < 0 {
		matchWindow = 0
	}

	s1Matches := make([]bool, len1)
	s2Matches := make([]bool, len2)
	matches := 0
	transpositions := 0

	// Find matches
	for i := 0; i < len1; i++ {
		start := max(0, i-matchWindow)
		end := minInt(i+matchWindow+1, len2)

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

	return jaro
}

// normalizeValue normalizes a single feature value
func (e *AdvancedFeatureExtractor) normalizeValue(value float64, index int) float64 {
	if len(e.normalizationParams.Means) <= index {
		return value // No normalization parameters available
	}

	// Z-score normalization
	mean := e.normalizationParams.Means[index]
	stdDev := e.normalizationParams.StdDevs[index]

	if stdDev == 0 {
		return 0 // Avoid division by zero
	}

	return (value - mean) / stdDev
}

// initializePopularPackages initializes lists of popular packages by registry
func (e *AdvancedFeatureExtractor) initializePopularPackages() {
	e.popularPackages["npm"] = []string{
		"react", "lodash", "express", "axios", "webpack", "babel-core",
		"typescript", "eslint", "moment", "jquery", "vue", "angular",
	}

	e.popularPackages["pypi"] = []string{
		"requests", "urllib3", "numpy", "pandas", "tensorflow", "django",
		"flask", "pytest", "setuptools", "pip", "wheel", "six",
	}

	e.popularPackages["go"] = []string{
		"github.com/gorilla/mux", "github.com/gin-gonic/gin",
		"github.com/labstack/echo", "github.com/sirupsen/logrus",
		"github.com/stretchr/testify", "go.uber.org/zap",
	}

	e.popularPackages["rubygems"] = []string{
		"rails", "bundler", "rake", "rspec", "nokogiri", "activesupport",
		"thor", "json", "minitest", "rack", "puma", "devise",
	}
}

// initializeSuspiciousKeywords initializes list of suspicious keywords
func (e *AdvancedFeatureExtractor) initializeSuspiciousKeywords() {
	e.suspiciousKeywords = []string{
		"bitcoin", "crypto", "wallet", "private", "key", "password",
		"credential", "token", "secret", "hack", "exploit", "malware",
		"virus", "trojan", "backdoor", "keylog", "steal", "phish",
		"download", "install", "execute", "run", "eval", "exec",
		"shell", "cmd", "system", "process", "spawn", "fork",
	}
}

// initializeDomainReputations initializes domain reputation scores
func (e *AdvancedFeatureExtractor) initializeDomainReputations() {
	e.domainReputations["github.com"] = 0.9
	e.domainReputations["gitlab.com"] = 0.85
	e.domainReputations["bitbucket.org"] = 0.8
	e.domainReputations["sourceforge.net"] = 0.7
	e.domainReputations["codeplex.com"] = 0.6

	// Suspicious domains
	e.domainReputations["bit.ly"] = 0.1
	e.domainReputations["tinyurl.com"] = 0.1
	e.domainReputations["t.co"] = 0.2
	e.domainReputations["goo.gl"] = 0.2
}

// initializeLicenseScores initializes license trustworthiness scores
func (e *AdvancedFeatureExtractor) initializeLicenseScores() {
	e.licenseScores["mit"] = 0.9
	e.licenseScores["apache-2.0"] = 0.9
	e.licenseScores["bsd-3-clause"] = 0.85
	e.licenseScores["bsd-2-clause"] = 0.85
	e.licenseScores["gpl-3.0"] = 0.8
	e.licenseScores["gpl-2.0"] = 0.8
	e.licenseScores["lgpl-3.0"] = 0.75
	e.licenseScores["lgpl-2.1"] = 0.75
	e.licenseScores["mpl-2.0"] = 0.7
	e.licenseScores["isc"] = 0.85
	e.licenseScores["unlicense"] = 0.6
	e.licenseScores["wtfpl"] = 0.5
}

// initializeNormalizationParams initializes normalization parameters
func (e *AdvancedFeatureExtractor) initializeNormalizationParams() {
	// These would typically be learned from training data
	// For now, using reasonable defaults
	featureCount := len(e.GetFeatureNames())

	e.normalizationParams.Means = make([]float64, featureCount)
	e.normalizationParams.StdDevs = make([]float64, featureCount)
	e.normalizationParams.Mins = make([]float64, featureCount)
	e.normalizationParams.Maxs = make([]float64, featureCount)

	// Set default normalization parameters
	for i := 0; i < featureCount; i++ {
		e.normalizationParams.Means[i] = 0.0
		e.normalizationParams.StdDevs[i] = 1.0
		e.normalizationParams.Mins[i] = 0.0
		e.normalizationParams.Maxs[i] = 1.0
	}
}

// Helper functions
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
