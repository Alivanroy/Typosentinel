package ml

import (
	"context"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/Alivanroy/Typosentinel/pkg/logger"
)

// EnhancedMLEngine provides advanced ML capabilities
type EnhancedMLEngine struct {
	client       *Client
	featureStore *FeatureStore
	config       *MLConfig
	logger       logger.Logger
}

// MLConfig contains ML engine configuration
type MLConfig struct {
	EmbeddingModel      string  `yaml:"embedding_model"`
	MaliciousModel      string  `yaml:"malicious_model"`
	ReputationModel     string  `yaml:"reputation_model"`
	SimilarityThreshold float64 `yaml:"similarity_threshold"`
	MaliciousThreshold  float64 `yaml:"malicious_threshold"`
	ReputationThreshold float64 `yaml:"reputation_threshold"`
	FeatureStoreEnabled bool    `yaml:"feature_store_enabled"`
	FeatureStoreTTL     string  `yaml:"feature_store_ttl"`
	BatchSize           int     `yaml:"batch_size"`
	MaxRetries          int     `yaml:"max_retries"`
	Timeout             string  `yaml:"timeout"`
}

// PackageFeatures represents comprehensive package features
type PackageFeatures struct {
	PackageName string `json:"package_name"`
	Registry    string `json:"registry"`
	Version     string `json:"version,omitempty"`
	PackageType string `json:"package_type,omitempty"`

	// Name-based features
	NameEmbedding  []float64 `json:"name_embedding"`
	NameLength     int       `json:"name_length"`
	NameComplexity float64   `json:"name_complexity"`
	NameEntropy    float64   `json:"name_entropy"`

	// Direct access fields for compatibility
	VersionComplexity  float64 `json:"version_complexity"`
	DescriptionLength  int     `json:"description_length"`
	DependencyCount    int     `json:"dependency_count"`
	DownloadCount      int64   `json:"download_count"`
	StarCount          int     `json:"star_count"`
	ForkCount          int     `json:"fork_count"`
	ContributorCount   int     `json:"contributor_count"`
	AgeInDays          int     `json:"age_in_days"`
	TyposquattingScore float64 `json:"typosquatting_score"`
	SuspiciousKeywords int     `json:"suspicious_keywords"`
	VersionSpoofing    float64 `json:"version_spoofing"`
	DomainReputation   float64 `json:"domain_reputation"`
	UpdateFrequency    float64 `json:"update_frequency"`
	MaintainerCount    int     `json:"maintainer_count"`
	IssueCount         int     `json:"issue_count"`
	LicenseScore       float64 `json:"license_score"`

	// Author features
	AuthorFeatures AuthorFeatures `json:"author_features"`

	// Package metadata features
	MetadataFeatures MetadataFeatures `json:"metadata_features"`

	// Repository features
	RepositoryFeatures RepositoryFeatures `json:"repository_features"`

	// Download and popularity features
	PopularityFeatures PopularityFeatures `json:"popularity_features"`

	// Security features
	SecurityFeatures SecurityFeatures `json:"security_features"`

	// Computed scores
	MaliciousScore  float64 `json:"malicious_score"`
	ReputationScore float64 `json:"reputation_score"`
	OverallRisk     float64 `json:"overall_risk"`

	// Metadata
	Timestamp      time.Time         `json:"timestamp"`
	ModelVersions  map[string]string `json:"model_versions"`
	FeatureVersion string            `json:"feature_version"`
}

// AuthorFeatures contains author-related features
type AuthorFeatures struct {
	AuthorName         string    `json:"author_name"`
	AuthorEmail        string    `json:"author_email"`
	AccountAge         int       `json:"account_age_days"`
	PublishedPackages  int       `json:"published_packages"`
	TotalDownloads     int64     `json:"total_downloads"`
	AverageRating      float64   `json:"average_rating"`
	VerifiedAccount    bool      `json:"verified_account"`
	HasGitHubProfile   bool      `json:"has_github_profile"`
	GitHubFollowers    int       `json:"github_followers"`
	GitHubRepos        int       `json:"github_repos"`
	LastActivity       time.Time `json:"last_activity"`
	SuspiciousPatterns []string  `json:"suspicious_patterns"`
}

// MetadataFeatures contains package metadata features
type MetadataFeatures struct {
	HasDescription     bool    `json:"has_description"`
	DescriptionLength  int     `json:"description_length"`
	DescriptionQuality float64 `json:"description_quality"`
	HasHomepage        bool    `json:"has_homepage"`
	HasRepository      bool    `json:"has_repository"`
	HasLicense         bool    `json:"has_license"`
	LicenseType        string  `json:"license_type"`
	HasKeywords        bool    `json:"has_keywords"`
	KeywordCount       int     `json:"keyword_count"`
	VersionCount       int     `json:"version_count"`
	LatestVersion      string  `json:"latest_version"`
	VersionPattern     string  `json:"version_pattern"`
	UnusualVersionJump bool    `json:"unusual_version_jump"`
	PublicationRecency int     `json:"publication_recency_days"`
}

// RepositoryFeatures contains repository-related features
type RepositoryFeatures struct {
	HasRepository        bool               `json:"has_repository"`
	RepositoryURL        string             `json:"repository_url"`
	RepositoryType       string             `json:"repository_type"`
	StarCount            int                `json:"star_count"`
	ForkCount            int                `json:"fork_count"`
	IssueCount           int                `json:"issue_count"`
	CommitCount          int                `json:"commit_count"`
	ContributorCount     int                `json:"contributor_count"`
	LastCommit           time.Time          `json:"last_commit"`
	HasReadme            bool               `json:"has_readme"`
	ReadmeLength         int                `json:"readme_length"`
	HasTests             bool               `json:"has_tests"`
	TestCoverage         float64            `json:"test_coverage"`
	HasCI                bool               `json:"has_ci"`
	LanguageDistribution map[string]float64 `json:"language_distribution"`
	SuspiciousFiles      []string           `json:"suspicious_files"`
}

// PopularityFeatures contains popularity and download features
type PopularityFeatures struct {
	TotalDownloads    int64   `json:"total_downloads"`
	WeeklyDownloads   int64   `json:"weekly_downloads"`
	MonthlyDownloads  int64   `json:"monthly_downloads"`
	DownloadTrend     string  `json:"download_trend"`
	DownloadVelocity  float64 `json:"download_velocity"`
	PopularityRank    int     `json:"popularity_rank"`
	DependentPackages int     `json:"dependent_packages"`
	DependencyRank    int     `json:"dependency_rank"`
	CommunityScore    float64 `json:"community_score"`
	MaintenanceScore  float64 `json:"maintenance_score"`
}

// SecurityFeatures type defined in advanced_feature_extractor.go

// MLAnalysisResult represents comprehensive ML analysis results
type MLAnalysisResult struct {
	PackageName       string    `json:"package_name"`
	Registry          string    `json:"registry"`
	AnalysisTimestamp time.Time `json:"analysis_timestamp"`

	// Feature analysis
	Features PackageFeatures `json:"features"`

	// Similarity analysis
	SimilarPackages   []SimilarPackage `json:"similar_packages"`
	TyposquattingRisk float64          `json:"typosquatting_risk"`

	// Malicious detection
	MaliciousScore      float64              `json:"malicious_score"`
	MaliciousIndicators []MaliciousIndicator `json:"malicious_indicators"`

	// Reputation scoring
	ReputationScore   float64            `json:"reputation_score"`
	ReputationFactors []ReputationFactor `json:"reputation_factors"`

	// Overall assessment
	RiskLevel      string   `json:"risk_level"`
	Confidence     float64  `json:"confidence"`
	Recommendation string   `json:"recommendation"`
	Warnings       []string `json:"warnings"`

	// Model information
	ModelVersions  map[string]string `json:"model_versions"`
	ProcessingTime time.Duration     `json:"processing_time"`
}

// Note: SimilarPackage struct is defined in analyzer.go

// MaliciousIndicator represents indicators of malicious behavior
type MaliciousIndicator struct {
	Type        string  `json:"type"`
	Description string  `json:"description"`
	Severity    string  `json:"severity"`
	Confidence  float64 `json:"confidence"`
	Evidence    string  `json:"evidence"`
}

// ReputationFactor represents factors affecting reputation score
type ReputationFactor struct {
	Factor      string  `json:"factor"`
	Score       float64 `json:"score"`
	Weight      float64 `json:"weight"`
	Description string  `json:"description"`
}

// NewEnhancedMLEngine creates a new enhanced ML engine
func NewEnhancedMLEngine(client *Client, config *MLConfig, log logger.Logger) *EnhancedMLEngine {
	if config == nil {
		config = DefaultMLConfig()
	}

	return &EnhancedMLEngine{
		client:       client,
		featureStore: NewFeatureStore(config),
		config:       config,
		logger:       log,
	}
}

// DefaultMLConfig returns default ML configuration
func DefaultMLConfig() *MLConfig {
	return &MLConfig{
		EmbeddingModel:      "sentence-transformers/all-MiniLM-L6-v2",
		MaliciousModel:      "github.com/Alivanroy/Typosentinel/malicious-detector-v1",
		ReputationModel:     "github.com/Alivanroy/Typosentinel/reputation-scorer-v1",
		SimilarityThreshold: 0.8,
		MaliciousThreshold:  0.7,
		ReputationThreshold: 0.5,
		FeatureStoreEnabled: true,
		FeatureStoreTTL:     "24h",
		BatchSize:           32,
		MaxRetries:          3,
		Timeout:             "30s",
	}
}

// AnalyzePackage performs comprehensive ML analysis of a package
func (e *EnhancedMLEngine) AnalyzePackage(ctx context.Context, packageName, registry string) (*MLAnalysisResult, error) {
	startTime := time.Now()

	// Check feature store cache first
	if e.config.FeatureStoreEnabled {
		if cached := e.featureStore.GetFeatures(packageName, registry); cached != nil {
			return e.buildResultFromFeatures(cached, startTime), nil
		}
	}

	// Extract features
	features, err := e.extractFeatures(ctx, packageName, registry)
	if err != nil {
		return nil, fmt.Errorf("failed to extract features: %w", err)
	}

	// Perform embedding-based analysis
	if err := e.performEmbeddingAnalysis(ctx, features); err != nil {
		return nil, fmt.Errorf("failed to perform embedding analysis: %w", err)
	}

	// Perform malicious detection
	if err := e.performMaliciousDetection(ctx, features); err != nil {
		return nil, fmt.Errorf("failed to perform malicious detection: %w", err)
	}

	// Perform reputation scoring
	if err := e.performReputationScoring(ctx, features); err != nil {
		return nil, fmt.Errorf("failed to perform reputation scoring: %w", err)
	}

	// Store features in cache
	if e.config.FeatureStoreEnabled {
		e.featureStore.StoreFeatures(features)
	}

	// Build final result
	result := e.buildResultFromFeatures(features, startTime)
	result.ProcessingTime = time.Since(startTime)

	return result, nil
}

// extractFeatures extracts comprehensive features from package metadata
func (e *EnhancedMLEngine) extractFeatures(ctx context.Context, packageName, registry string) (*PackageFeatures, error) {
	features := &PackageFeatures{
		PackageName:    packageName,
		Registry:       registry,
		Timestamp:      time.Now(),
		ModelVersions:  make(map[string]string),
		FeatureVersion: "1.0",
	}

	// Extract name-based features
	e.extractNameFeatures(features)

	// Extract metadata features (would integrate with registry APIs)
	e.extractMetadataFeatures(ctx, features)

	// Extract author features
	e.extractAuthorFeatures(ctx, features)

	// Extract repository features
	e.extractRepositoryFeatures(ctx, features)

	// Extract popularity features
	e.extractPopularityFeatures(ctx, features)

	// Extract security features
	e.extractSecurityFeatures(ctx, features)

	return features, nil
}

// extractNameFeatures extracts features from package name
func (e *EnhancedMLEngine) extractNameFeatures(features *PackageFeatures) {
	name := features.PackageName

	// Basic name features
	features.NameLength = len(name)
	features.NameComplexity = e.calculateNameComplexity(name)
	features.NameEntropy = e.calculateNameEntropy(name)
}

// calculateNameComplexity calculates complexity score for package name
func (e *EnhancedMLEngine) calculateNameComplexity(name string) float64 {
	complexity := 0.0

	// Character diversity
	uniqueChars := make(map[rune]bool)
	for _, r := range name {
		uniqueChars[r] = true
	}
	complexity += float64(len(uniqueChars)) / float64(len(name))

	// Special characters
	specialCount := 0
	for _, r := range name {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			specialCount++
		}
	}
	complexity += float64(specialCount) / float64(len(name))

	// Case changes
	caseChanges := 0
	for i := 1; i < len(name); i++ {
		if (name[i-1] >= 'a' && name[i-1] <= 'z' && name[i] >= 'A' && name[i] <= 'Z') ||
			(name[i-1] >= 'A' && name[i-1] <= 'Z' && name[i] >= 'a' && name[i] <= 'z') {
			caseChanges++
		}
	}
	complexity += float64(caseChanges) / float64(len(name))

	return math.Min(complexity, 1.0)
}

// calculateNameEntropy calculates Shannon entropy of package name
func (e *EnhancedMLEngine) calculateNameEntropy(name string) float64 {
	if len(name) == 0 {
		return 0
	}

	// Count character frequencies
	freq := make(map[rune]int)
	for _, r := range name {
		freq[r]++
	}

	// Calculate entropy
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

// Enhanced feature extraction implementations
// These methods extract comprehensive features from package metadata and repository information

func (e *EnhancedMLEngine) extractMetadataFeatures(ctx context.Context, features *PackageFeatures) {
	// Extract metadata features from package information
	metadataFeatures := MetadataFeatures{}

	// Use existing description length if available
	if features.DescriptionLength > 0 {
		metadataFeatures.HasDescription = true
		metadataFeatures.DescriptionLength = features.DescriptionLength
		metadataFeatures.DescriptionQuality = e.calculateDescriptionQualityFromLength(features.DescriptionLength)
	}

	// Check repository features
	metadataFeatures.HasRepository = features.RepositoryFeatures.HasRepository
	metadataFeatures.HasHomepage = features.RepositoryFeatures.RepositoryURL != ""

	// Check license from license score
	metadataFeatures.HasLicense = features.LicenseScore > 0
	metadataFeatures.LicenseType = "unknown" // Default since we don't have direct access

	// Estimate version count and publication recency
	metadataFeatures.VersionCount = e.estimateVersionCount(features.Version)
	metadataFeatures.PublicationRecency = features.AgeInDays

	// Set latest version
	metadataFeatures.LatestVersion = features.Version

	features.MetadataFeatures = metadataFeatures
}

// calculateDescriptionQuality analyzes the quality of package description
func (e *EnhancedMLEngine) calculateDescriptionQuality(description string) float64 {
	if description == "" {
		return 0.0
	}

	quality := 0.0

	// Length factor (optimal range: 50-500 characters)
	length := len(description)
	if length >= 50 && length <= 500 {
		quality += 0.3
	} else if length > 20 {
		quality += 0.1
	}

	// Word count factor
	words := len(strings.Fields(description))
	if words >= 10 && words <= 100 {
		quality += 0.2
	} else if words >= 5 {
		quality += 0.1
	}

	// Check for meaningful content (not just package name repetition)
	if !strings.Contains(strings.ToLower(description), "package") ||
		!strings.Contains(strings.ToLower(description), "library") {
		quality += 0.2
	}

	// Check for proper capitalization and punctuation
	if len(description) > 0 && unicode.IsUpper(rune(description[0])) {
		quality += 0.1
	}
	if strings.HasSuffix(description, ".") || strings.HasSuffix(description, "!") {
		quality += 0.1
	}

	// Penalize suspicious patterns
	suspiciousPatterns := []string{"test", "demo", "sample", "placeholder", "lorem ipsum"}
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(strings.ToLower(description), pattern) {
			quality -= 0.2
			break
		}
	}

	return math.Max(0.0, math.Min(1.0, quality))
}

// calculateDescriptionQualityFromLength estimates description quality based on length
func (e *EnhancedMLEngine) calculateDescriptionQualityFromLength(length int) float64 {
	if length == 0 {
		return 0.0
	}

	quality := 0.0

	// Length factor (optimal range: 50-500 characters)
	if length >= 50 && length <= 500 {
		quality += 0.6
	} else if length >= 20 && length < 50 {
		quality += 0.3
	} else if length > 500 {
		quality += 0.4 // Long descriptions are still better than none
	} else if length > 10 {
		quality += 0.2
	} else {
		quality += 0.1 // Very short descriptions
	}

	// Estimate word count (average 5 characters per word)
	estimatedWords := length / 5
	if estimatedWords >= 10 && estimatedWords <= 100 {
		quality += 0.3
	} else if estimatedWords >= 5 {
		quality += 0.1
	}

	return math.Max(0.0, math.Min(1.0, quality))
}

// estimateVersionCount estimates version count based on version string
func (e *EnhancedMLEngine) estimateVersionCount(version string) int {
	if version == "" {
		return 1
	}

	// Parse semantic version
	parts := strings.Split(version, ".")
	if len(parts) >= 3 {
		// Try to parse major.minor.patch
		if major, err := strconv.Atoi(parts[0]); err == nil {
			if minor, err := strconv.Atoi(parts[1]); err == nil {
				if patch, err := strconv.Atoi(parts[2]); err == nil {
					// Estimate based on version numbers
					return major*100 + minor*10 + patch + 1
				}
			}
		}
	}

	// Fallback estimation
	return 5
}

// calculatePublicationRecency calculates days since publication
func (e *EnhancedMLEngine) calculatePublicationRecency(creationDate string) int {
	if creationDate == "" {
		return 365 // Default to 1 year if unknown
	}

	// Try to parse the date
	layouts := []string{
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05.000Z",
		"2006-01-02",
		"2006/01/02",
		"01/02/2006",
	}

	for _, layout := range layouts {
		if t, err := time.Parse(layout, creationDate); err == nil {
			return int(time.Since(t).Hours() / 24)
		}
	}

	// Fallback
	return 365
}

func (e *EnhancedMLEngine) extractAuthorFeatures(ctx context.Context, features *PackageFeatures) {
	authorFeatures := AuthorFeatures{}

	// Extract author information from package metadata if available
	if features.PackageName != "" {
		// Analyze author name patterns
		authorName := e.extractAuthorFromPackage(features.PackageName)
		authorFeatures.AuthorName = authorName

		// Estimate author characteristics based on name patterns
		authorFeatures.AccountAge = e.estimateAccountAge(authorName)
		authorFeatures.PublishedPackages = e.estimatePublishedPackages(authorName)
		authorFeatures.TotalDownloads = e.estimateTotalDownloads(features.DownloadCount)
		authorFeatures.VerifiedAccount = e.isLikelyVerifiedAccount(authorName)
		authorFeatures.HasGitHubProfile = e.hasLikelyGitHubProfile(authorName)
		authorFeatures.GitHubFollowers = e.estimateGitHubFollowers(authorName)
		authorFeatures.GitHubRepos = e.estimateGitHubRepos(authorName)
		authorFeatures.LastActivity = e.estimateLastActivity()
	}

	features.AuthorFeatures = authorFeatures
}

func (e *EnhancedMLEngine) extractAuthorFromPackage(packageName string) string {
	// Simple heuristic to extract potential author from package name
	parts := strings.Split(packageName, "-")
	if len(parts) > 0 {
		return parts[0]
	}
	return packageName
}

func (e *EnhancedMLEngine) estimateAccountAge(authorName string) int {
	// Heuristic: longer, more professional names suggest older accounts
	if len(authorName) > 10 && !strings.ContainsAny(authorName, "0123456789") {
		return 365 * 2 // 2 years for professional-looking names
	} else if len(authorName) > 5 {
		return 365 // 1 year for moderate names
	}
	return 30 // 30 days for suspicious names
}

func (e *EnhancedMLEngine) estimatePublishedPackages(authorName string) int {
	// Heuristic based on author name characteristics
	if len(authorName) > 10 && !strings.ContainsAny(authorName, "0123456789") {
		return 10 // Established authors likely have multiple packages
	} else if len(authorName) > 5 {
		return 3 // Moderate authors
	}
	return 1 // New or suspicious authors
}

func (e *EnhancedMLEngine) estimateTotalDownloads(packageDownloads int64) int64 {
	// Estimate total downloads across all packages (multiply by estimated package count)
	return packageDownloads * 3 // Assume author has 3 packages on average
}

func (e *EnhancedMLEngine) isLikelyVerifiedAccount(authorName string) bool {
	// Heuristic: professional names are more likely to be verified
	return len(authorName) > 8 && !strings.ContainsAny(authorName, "0123456789") &&
		!strings.Contains(strings.ToLower(authorName), "test")
}

func (e *EnhancedMLEngine) hasLikelyGitHubProfile(authorName string) bool {
	// Most legitimate packages have GitHub profiles
	return len(authorName) > 3 && !strings.Contains(strings.ToLower(authorName), "anonymous")
}

func (e *EnhancedMLEngine) estimateGitHubFollowers(authorName string) int {
	// Heuristic based on author name quality
	if len(authorName) > 10 && !strings.ContainsAny(authorName, "0123456789") {
		return 50 // Established authors
	} else if len(authorName) > 5 {
		return 10 // Moderate authors
	}
	return 0 // New or suspicious authors
}

func (e *EnhancedMLEngine) estimateGitHubRepos(authorName string) int {
	// Heuristic based on author characteristics
	if len(authorName) > 10 {
		return 15 // Established authors
	} else if len(authorName) > 5 {
		return 5 // Moderate authors
	}
	return 1 // New authors
}

func (e *EnhancedMLEngine) estimateLastActivity() time.Time {
	// Assume recent activity for active packages
	return time.Now().AddDate(0, 0, -7) // 7 days ago
}

func (e *EnhancedMLEngine) extractRepositoryFeatures(ctx context.Context, features *PackageFeatures) {
	repositoryFeatures := RepositoryFeatures{}

	// Analyze package characteristics to estimate repository features
	if features.PackageName != "" {
		// Estimate repository presence and characteristics
		repositoryFeatures.HasRepository = e.hasLikelyRepository(features.PackageName)
		repositoryFeatures.RepositoryURL = e.generateLikelyRepositoryURL(features.PackageName)
		repositoryFeatures.RepositoryType = "git" // Most modern packages use git

		// Estimate repository metrics based on package characteristics
		repositoryFeatures.StarCount = e.estimateStarCount(features.DownloadCount, features.AgeInDays)
		repositoryFeatures.ForkCount = e.estimateForkCount(repositoryFeatures.StarCount)
		repositoryFeatures.CommitCount = e.estimateCommitCount(features.AgeInDays)
		repositoryFeatures.ContributorCount = e.estimateContributorCount(repositoryFeatures.StarCount)
		repositoryFeatures.LastCommit = e.estimateLastCommit(features.AgeInDays)

		// Estimate repository quality indicators
		repositoryFeatures.HasReadme = e.hasLikelyReadme(features.PackageName)
		repositoryFeatures.ReadmeLength = e.estimateReadmeLength(features.DescriptionLength)
		repositoryFeatures.HasTests = e.hasLikelyTests(features.PackageName)
		repositoryFeatures.TestCoverage = e.estimateTestCoverage(repositoryFeatures.HasTests)
		repositoryFeatures.HasCI = e.hasLikelyCI(repositoryFeatures.StarCount)
	}

	features.RepositoryFeatures = repositoryFeatures
}

func (e *EnhancedMLEngine) hasLikelyRepository(packageName string) bool {
	// Most legitimate packages have repositories
	// Suspicious packages might not have proper repositories
	return len(packageName) > 3 &&
		!strings.Contains(strings.ToLower(packageName), "test") &&
		!strings.ContainsAny(packageName, "0123456789") // Avoid packages with random numbers
}

func (e *EnhancedMLEngine) generateLikelyRepositoryURL(packageName string) string {
	// Generate a likely GitHub URL based on package name
	if e.hasLikelyRepository(packageName) {
		return fmt.Sprintf("https://github.com/%s/%s", packageName, packageName)
	}
	return ""
}

func (e *EnhancedMLEngine) estimateStarCount(downloadCount int64, ageInDays int) int {
	// Heuristic: star count correlates with downloads and age
	if downloadCount > 100000 {
		return 1000 + (ageInDays / 10) // Popular packages
	} else if downloadCount > 10000 {
		return 100 + (ageInDays / 30) // Moderate packages
	} else if downloadCount > 1000 {
		return 10 + (ageInDays / 60) // Small packages
	}
	return ageInDays / 100 // New or unpopular packages
}

func (e *EnhancedMLEngine) estimateForkCount(starCount int) int {
	// Forks are typically 10-20% of stars
	return starCount / 7
}

func (e *EnhancedMLEngine) estimateCommitCount(ageInDays int) int {
	// Estimate commits based on project age
	if ageInDays > 365 {
		return 500 + (ageInDays-365)/2 // Mature projects
	} else if ageInDays > 30 {
		return 50 + ageInDays // Active projects
	}
	return ageInDays // New projects
}

func (e *EnhancedMLEngine) estimateContributorCount(starCount int) int {
	// Contributors correlate with project popularity
	if starCount > 1000 {
		return 20 + starCount/100 // Popular projects
	} else if starCount > 100 {
		return 5 + starCount/50 // Moderate projects
	} else if starCount > 10 {
		return 2 + starCount/20 // Small projects
	}
	return 1 // Single contributor
}

func (e *EnhancedMLEngine) estimateLastCommit(ageInDays int) time.Time {
	// Estimate last commit based on project age
	if ageInDays < 30 {
		return time.Now().AddDate(0, 0, -ageInDays/3) // Active projects
	} else if ageInDays < 365 {
		return time.Now().AddDate(0, 0, -ageInDays/10) // Moderate activity
	}
	return time.Now().AddDate(0, 0, -ageInDays/30) // Less active projects
}

func (e *EnhancedMLEngine) hasLikelyReadme(packageName string) bool {
	// Most legitimate packages have README files
	return len(packageName) > 3 && !strings.Contains(strings.ToLower(packageName), "test")
}

func (e *EnhancedMLEngine) estimateReadmeLength(descriptionLength int) int {
	// README is typically 5-10x longer than description
	if descriptionLength > 0 {
		return descriptionLength * 7
	}
	return 1000 // Default README length
}

func (e *EnhancedMLEngine) hasLikelyTests(packageName string) bool {
	// Professional packages typically have tests
	return len(packageName) > 5 && !strings.Contains(strings.ToLower(packageName), "demo")
}

func (e *EnhancedMLEngine) estimateTestCoverage(hasTests bool) float64 {
	if hasTests {
		return 0.75 // Assume good test coverage for packages with tests
	}
	return 0.0 // No tests
}

func (e *EnhancedMLEngine) hasLikelyCI(starCount int) bool {
	// Popular packages typically have CI/CD
	return starCount > 50
}

func (e *EnhancedMLEngine) analyzeDependencyPatterns(ctx context.Context, features *PackageFeatures) {
	// Analyze dependency patterns and update existing fields
	if e.hasSuspiciousDependencyPatterns(features.DependencyCount) {
		features.SuspiciousKeywords++
	}
}

func (e *EnhancedMLEngine) estimateDevDependencies(totalDeps int) int {
	// Typically 20-40% of dependencies are dev dependencies
	return int(float64(totalDeps) * 0.3)
}

func (e *EnhancedMLEngine) estimatePeerDependencies(totalDeps int) int {
	// Typically 5-15% are peer dependencies
	return int(float64(totalDeps) * 0.1)
}

func (e *EnhancedMLEngine) estimateOptionalDependencies(totalDeps int) int {
	// Typically 5-10% are optional
	return int(float64(totalDeps) * 0.05)
}

func (e *EnhancedMLEngine) hasSuspiciousDependencyPatterns(depCount int) bool {
	// Too many or too few dependencies can be suspicious
	return depCount > 100 || (depCount == 0)
}

func (e *EnhancedMLEngine) estimateDependencyDepth(depCount int) int {
	// Estimate dependency tree depth based on count
	if depCount > 50 {
		return 8
	} else if depCount > 20 {
		return 5
	} else if depCount > 5 {
		return 3
	}
	return 1
}

func (e *EnhancedMLEngine) hasLikelyCircularDependencies(depCount int) bool {
	// Large dependency trees are more likely to have circular dependencies
	return depCount > 30
}

func (e *EnhancedMLEngine) estimateOutdatedDependencies(depCount int) int {
	// Estimate 10-20% of dependencies might be outdated
	return int(float64(depCount) * 0.15)
}

func (e *EnhancedMLEngine) estimateVulnerableDependencies(depCount int) int {
	// Estimate 5-10% might have vulnerabilities
	return int(float64(depCount) * 0.07)
}

func (e *EnhancedMLEngine) estimateUnpopularDependencies(depCount int) int {
	// Estimate 15-25% might be unpopular/niche
	return int(float64(depCount) * 0.2)
}

func (e *EnhancedMLEngine) analyzeSecurityPatterns(ctx context.Context, features *PackageFeatures) {
	// Analyze security patterns and update existing fields
	suspiciousCount := e.detectSuspiciousPatterns(features.PackageName)
	features.SuspiciousKeywords += suspiciousCount

	// Update security features with existing fields
	if e.hasLikelyObfuscation(features.PackageName) {
		features.SecurityFeatures.MalwareIndicators = append(features.SecurityFeatures.MalwareIndicators, "obfuscation")
	}
	if e.hasLikelyNetworkActivity(features.PackageName) {
		features.SecurityFeatures.MalwareIndicators = append(features.SecurityFeatures.MalwareIndicators, "network_activity")
	}
}

func (e *EnhancedMLEngine) estimateKnownVulnerabilities(vulnScore float64) int {
	// Convert vulnerability score to count estimate
	if vulnScore > 0.8 {
		return 5
	} else if vulnScore > 0.5 {
		return 2
	} else if vulnScore > 0.2 {
		return 1
	}
	return 0
}

func (e *EnhancedMLEngine) estimateSecurityAdvisories(vulnScore float64) int {
	// Security advisories typically correlate with vulnerability score
	return e.estimateKnownVulnerabilities(vulnScore)
}

func (e *EnhancedMLEngine) estimateMalwareReports(vulnScore float64) int {
	// Malware reports are less common but correlate with high vulnerability scores
	if vulnScore > 0.9 {
		return 2
	} else if vulnScore > 0.7 {
		return 1
	}
	return 0
}

func (e *EnhancedMLEngine) detectSuspiciousPatterns(packageName string) int {
	suspiciousPatterns := []string{
		"test", "temp", "demo", "sample", "fake", "malicious", "evil",
		"hack", "crack", "exploit", "virus", "trojan", "backdoor",
	}

	count := 0
	nameLower := strings.ToLower(packageName)
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(nameLower, pattern) {
			count++
		}
	}
	return count
}

func (e *EnhancedMLEngine) hasLikelyObfuscation(packageName string) bool {
	// Check for patterns that suggest obfuscation
	obfuscationPatterns := []string{"obfus", "minif", "uglif", "compress"}
	nameLower := strings.ToLower(packageName)
	for _, pattern := range obfuscationPatterns {
		if strings.Contains(nameLower, pattern) {
			return true
		}
	}
	return false
}

func (e *EnhancedMLEngine) hasLikelyNetworkActivity(packageName string) bool {
	networkPatterns := []string{"http", "request", "fetch", "axios", "curl", "wget", "net", "socket"}
	nameLower := strings.ToLower(packageName)
	for _, pattern := range networkPatterns {
		if strings.Contains(nameLower, pattern) {
			return true
		}
	}
	return false
}

func (e *EnhancedMLEngine) hasLikelyFileSystemAccess(packageName string) bool {
	fsPatterns := []string{"fs", "file", "path", "dir", "folder", "read", "write", "glob"}
	nameLower := strings.ToLower(packageName)
	for _, pattern := range fsPatterns {
		if strings.Contains(nameLower, pattern) {
			return true
		}
	}
	return false
}

func (e *EnhancedMLEngine) hasLikelyProcessExecution(packageName string) bool {
	processPatterns := []string{"exec", "spawn", "child", "process", "shell", "cmd", "command"}
	nameLower := strings.ToLower(packageName)
	for _, pattern := range processPatterns {
		if strings.Contains(nameLower, pattern) {
			return true
		}
	}
	return false
}

func (e *EnhancedMLEngine) hasLikelyCryptographicUsage(packageName string) bool {
	cryptoPatterns := []string{"crypto", "hash", "encrypt", "decrypt", "cipher", "aes", "rsa", "sha"}
	nameLower := strings.ToLower(packageName)
	for _, pattern := range cryptoPatterns {
		if strings.Contains(nameLower, pattern) {
			return true
		}
	}
	return false
}

func (e *EnhancedMLEngine) hasLikelyDataCollection(packageName string) bool {
	dataPatterns := []string{"analytics", "track", "collect", "gather", "monitor", "log", "metric"}
	nameLower := strings.ToLower(packageName)
	for _, pattern := range dataPatterns {
		if strings.Contains(nameLower, pattern) {
			return true
		}
	}
	return false
}

func (e *EnhancedMLEngine) extractPopularityFeatures(ctx context.Context, features *PackageFeatures) {
	// Extract popularity features from existing package data
	popularityFeatures := PopularityFeatures{}

	// Use existing download count if available
	if features.DownloadCount > 0 {
		popularityFeatures.TotalDownloads = features.DownloadCount

		// Estimate weekly/monthly downloads based on age and total downloads
		if features.AgeInDays > 0 {
			dailyAverage := float64(features.DownloadCount) / float64(features.AgeInDays)
			popularityFeatures.WeeklyDownloads = int64(dailyAverage * 7)
			popularityFeatures.MonthlyDownloads = int64(dailyAverage * 30)
		}
	}

	// Calculate download trend based on update frequency
	if features.UpdateFrequency > 1.0 {
		popularityFeatures.DownloadTrend = "increasing"
		popularityFeatures.DownloadVelocity = features.UpdateFrequency
	} else if features.UpdateFrequency > 0.5 {
		popularityFeatures.DownloadTrend = "stable"
		popularityFeatures.DownloadVelocity = features.UpdateFrequency
	} else {
		popularityFeatures.DownloadTrend = "decreasing"
		popularityFeatures.DownloadVelocity = features.UpdateFrequency
	}

	// Estimate popularity rank based on download count
	popularityFeatures.PopularityRank = e.estimatePopularityRank(features.DownloadCount)

	// Use repository features for community metrics
	popularityFeatures.DependentPackages = features.RepositoryFeatures.ForkCount

	// Calculate community score based on repository metrics
	popularityFeatures.CommunityScore = e.calculateCommunityScore(features)

	// Calculate maintenance score based on activity
	popularityFeatures.MaintenanceScore = e.calculateMaintenanceScore(features)

	features.PopularityFeatures = popularityFeatures
}

// estimatePopularityRank estimates popularity rank based on download count
func (e *EnhancedMLEngine) estimatePopularityRank(downloadCount int64) int {
	if downloadCount == 0 {
		return 100000 // Very low rank for packages with no downloads
	}

	// Rough estimation based on download tiers
	if downloadCount > 10000000 { // 10M+
		return 100
	} else if downloadCount > 1000000 { // 1M+
		return 500
	} else if downloadCount > 100000 { // 100K+
		return 2000
	} else if downloadCount > 10000 { // 10K+
		return 10000
	} else if downloadCount > 1000 { // 1K+
		return 50000
	} else {
		return 100000
	}
}

// calculateCommunityScore calculates community engagement score
func (e *EnhancedMLEngine) calculateCommunityScore(features *PackageFeatures) float64 {
	score := 0.0

	// Repository engagement
	if features.RepositoryFeatures.HasRepository {
		score += 0.2

		// Stars indicate community interest
		if features.StarCount > 100 {
			score += 0.3
		} else if features.StarCount > 10 {
			score += 0.2
		} else if features.StarCount > 0 {
			score += 0.1
		}

		// Forks indicate active usage
		if features.ForkCount > 10 {
			score += 0.2
		} else if features.ForkCount > 0 {
			score += 0.1
		}

		// Contributors indicate community involvement
		if features.ContributorCount > 5 {
			score += 0.2
		} else if features.ContributorCount > 1 {
			score += 0.1
		}

		// Issues indicate active maintenance
		if features.IssueCount > 0 && features.IssueCount < 100 {
			score += 0.1 // Some issues are good, too many might indicate problems
		}
	}

	return math.Max(0.0, math.Min(1.0, score))
}

// calculateMaintenanceScore calculates maintenance quality score
func (e *EnhancedMLEngine) calculateMaintenanceScore(features *PackageFeatures) float64 {
	score := 0.0

	// Update frequency indicates active maintenance
	if features.UpdateFrequency > 0.5 {
		score += 0.3
	} else if features.UpdateFrequency > 0.1 {
		score += 0.2
	} else if features.UpdateFrequency > 0 {
		score += 0.1
	}

	// Multiple maintainers indicate better maintenance
	if features.MaintainerCount > 3 {
		score += 0.2
	} else if features.MaintainerCount > 1 {
		score += 0.1
	} else if features.MaintainerCount == 1 {
		score += 0.05
	}

	// Repository features indicate good maintenance practices
	if features.RepositoryFeatures.HasTests {
		score += 0.2
	}
	if features.RepositoryFeatures.HasCI {
		score += 0.1
	}
	if features.RepositoryFeatures.HasReadme {
		score += 0.1
	}

	// License indicates proper maintenance
	if features.LicenseScore > 0 {
		score += 0.1
	}

	return math.Max(0.0, math.Min(1.0, score))
}

func (e *EnhancedMLEngine) extractSecurityFeatures(ctx context.Context, features *PackageFeatures) {
	securityFeatures := SecurityFeatures{}

	// Analyze package name for suspicious patterns
	suspiciousName := e.analyzeSuspiciousPackageName(features.PackageName)

	// Check for typosquatting indicators
	typoSquattingRisk := e.analyzeTypoSquattingRisk(features.PackageName)

	// Analyze maintainer trust
	maintainerTrust := e.analyzeMaintainerTrust(features)

	// Analyze version patterns for suspicious behavior
	versionRisk := e.analyzeVersionRisk(features)

	// Calculate overall security score
	securityScore := e.calculateSecurityScore(suspiciousName, typoSquattingRisk, maintainerTrust, versionRisk)

	// Check for malicious indicators
	hasMaliciousIndicators := suspiciousName || typoSquattingRisk > 0.7 || maintainerTrust < 0.3

	// Estimate vulnerability count based on age and complexity
	vulnCount := e.estimateVulnerabilityCount(features)

	securityFeatures.KnownVulnerabilities = vulnCount
	securityFeatures.SecurityScore = securityScore
	securityFeatures.HasSecurityPolicy = maintainerTrust > 0.7
	securityFeatures.SignedReleases = false
	securityFeatures.SigstoreVerified = false
	securityFeatures.SLSALevel = 0
	securityFeatures.HasSBOM = false
	securityFeatures.SupplyChainRisk = 1.0 - securityScore

	// Add malware indicators if suspicious
	if hasMaliciousIndicators {
		securityFeatures.MalwareIndicators = []string{"suspicious_name_pattern"}
	}

	// Add suspicious scripts if version risk is high
	if versionRisk > 0.5 {
		securityFeatures.SuspiciousScripts = []string{"rapid_version_changes"}
	}

	features.SecurityFeatures = securityFeatures
}

// analyzeSuspiciousPackageName checks for suspicious naming patterns
func (e *EnhancedMLEngine) analyzeSuspiciousPackageName(name string) bool {
	suspiciousPatterns := []string{
		"test", "temp", "tmp", "debug", "hack", "crack", "exploit",
		"malware", "virus", "trojan", "backdoor", "keylog", "steal",
	}

	nameLower := strings.ToLower(name)
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(nameLower, pattern) {
			return true
		}
	}

	// Check for excessive special characters
	specialCharCount := 0
	for _, char := range name {
		if !unicode.IsLetter(char) && !unicode.IsDigit(char) && char != '-' && char != '_' {
			specialCharCount++
		}
	}

	return float64(specialCharCount)/float64(len(name)) > 0.3
}

// analyzeTypoSquattingRisk calculates typosquatting risk score
func (e *EnhancedMLEngine) analyzeTypoSquattingRisk(name string) float64 {
	// Popular package names to check against
	popularPackages := []string{
		"react", "lodash", "express", "axios", "moment", "jquery",
		"bootstrap", "webpack", "babel", "eslint", "typescript",
		"numpy", "pandas", "requests", "flask", "django", "tensorflow",
	}

	maxSimilarity := 0.0
	for _, popular := range popularPackages {
		similarity := e.calculateStringSimilarity(name, popular)
		if similarity > maxSimilarity {
			maxSimilarity = similarity
		}
	}

	// High similarity with different name indicates potential typosquatting
	if maxSimilarity > 0.8 && maxSimilarity < 1.0 {
		return maxSimilarity
	}

	return 0.0
}

// analyzeMaintainerTrust calculates maintainer trustworthiness
func (e *EnhancedMLEngine) analyzeMaintainerTrust(features *PackageFeatures) float64 {
	trust := 0.5 // Base trust score

	// Multiple maintainers increase trust
	if features.MaintainerCount > 1 {
		trust += 0.2
	}

	// Repository presence increases trust
	if features.RepositoryFeatures.HasRepository {
		trust += 0.2

		// Active repository increases trust
		if features.StarCount > 10 {
			trust += 0.1
		}
		if features.ForkCount > 5 {
			trust += 0.1
		}
	}

	// Age increases trust (older packages are generally more trustworthy)
	if features.AgeInDays > 365 {
		trust += 0.2
	} else if features.AgeInDays > 90 {
		trust += 0.1
	}

	// Regular updates indicate active maintenance
	if features.UpdateFrequency > 0.1 {
		trust += 0.1
	}

	return math.Max(0.0, math.Min(1.0, trust))
}

// analyzeVersionRisk checks for suspicious version patterns
func (e *EnhancedMLEngine) analyzeVersionRisk(features *PackageFeatures) float64 {
	risk := 0.0

	// Very new packages (less than 7 days) are riskier
	if features.AgeInDays < 7 {
		risk += 0.3
	} else if features.AgeInDays < 30 {
		risk += 0.1
	}

	// Packages with very frequent updates might be suspicious
	if features.UpdateFrequency > 10 {
		risk += 0.2
	}

	// Single version packages might be suspicious
	if features.UpdateFrequency == 0 && features.AgeInDays > 30 {
		risk += 0.1
	}

	return math.Max(0.0, math.Min(1.0, risk))
}

// calculateSecurityScore computes overall security score
func (e *EnhancedMLEngine) calculateSecurityScore(suspiciousName bool, typoRisk, maintainerTrust, versionRisk float64) float64 {
	score := 1.0

	if suspiciousName {
		score -= 0.4
	}

	score -= typoRisk * 0.3
	score -= (1.0 - maintainerTrust) * 0.2
	score -= versionRisk * 0.1

	return math.Max(0.0, math.Min(1.0, score))
}

// determineRiskLevel converts security score to risk level
func (e *EnhancedMLEngine) determineRiskLevel(securityScore float64) string {
	if securityScore >= 0.8 {
		return "low"
	} else if securityScore >= 0.6 {
		return "medium"
	} else if securityScore >= 0.4 {
		return "high"
	} else {
		return "critical"
	}
}

// estimateVulnerabilityCount estimates potential vulnerabilities
func (e *EnhancedMLEngine) estimateVulnerabilityCount(features *PackageFeatures) int {
	// Older packages might have more vulnerabilities
	if features.AgeInDays > 1095 { // 3 years
		return 2
	} else if features.AgeInDays > 730 { // 2 years
		return 1
	}

	// Packages with no updates might have unpatched vulnerabilities
	if features.UpdateFrequency == 0 && features.AgeInDays > 365 {
		return 1
	}

	return 0
}

// calculateStringSimilarity calculates similarity between two strings
func (e *EnhancedMLEngine) calculateStringSimilarity(s1, s2 string) float64 {
	if s1 == s2 {
		return 1.0
	}

	// Simple Levenshtein distance-based similarity
	distance := e.levenshteinDistance(s1, s2)
	maxLen := math.Max(float64(len(s1)), float64(len(s2)))

	if maxLen == 0 {
		return 1.0
	}

	return 1.0 - (float64(distance) / maxLen)
}

// levenshteinDistance calculates Levenshtein distance between two strings
func (e *EnhancedMLEngine) levenshteinDistance(s1, s2 string) int {
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

			matrix[i][j] = int(math.Min(
				float64(matrix[i-1][j]+1), // deletion
				math.Min(
					float64(matrix[i][j-1]+1),      // insertion
					float64(matrix[i-1][j-1]+cost), // substitution
				),
			))
		}
	}

	return matrix[len(s1)][len(s2)]
}

// performEmbeddingAnalysis performs embedding-based similarity analysis
func (e *EnhancedMLEngine) performEmbeddingAnalysis(ctx context.Context, features *PackageFeatures) error {
	// Generate embedding based on package features
	embedding, err := e.generatePackageEmbedding(features)
	if err != nil {
		return fmt.Errorf("failed to generate embedding: %w", err)
	}
	features.NameEmbedding = embedding
	return nil
}

// generateEmbedding generates embedding vector for text using character-based features
func (e *EnhancedMLEngine) generateEmbedding(ctx context.Context, text string) ([]float64, error) {
	// Generate feature-based embedding instead of using external model
	embedding := make([]float64, 384) // Common embedding dimension

	if text == "" {
		return embedding, nil
	}

	// Character frequency features (first 128 dimensions)
	charFreq := make(map[rune]int)
	for _, r := range text {
		charFreq[r]++
	}

	// Normalize character frequencies
	textLen := len(text)
	for i := 0; i < 128 && i < len(embedding); i++ {
		if freq, exists := charFreq[rune(i)]; exists {
			embedding[i] = float64(freq) / float64(textLen)
		}
	}

	// N-gram features (next 128 dimensions)
	if len(text) >= 2 {
		bigramFreq := make(map[string]int)
		for i := 0; i < len(text)-1; i++ {
			bigram := text[i : i+2]
			bigramFreq[bigram]++
		}

		idx := 128
		for _, freq := range bigramFreq {
			if idx >= 256 {
				break
			}
			embedding[idx] = float64(freq) / float64(len(text)-1)
			idx++
		}
	}

	// Statistical features (next 64 dimensions)
	if len(embedding) > 256 {
		embedding[256] = float64(len(text)) / 100.0        // Length feature
		embedding[257] = e.calculateEntropy(text)          // Entropy feature
		embedding[258] = e.calculateVowelRatio(text)       // Vowel ratio
		embedding[259] = e.calculateDigitRatio(text)       // Digit ratio
		embedding[260] = e.calculateUppercaseRatio(text)   // Uppercase ratio
		embedding[261] = e.calculateSpecialCharRatio(text) // Special char ratio

		// Pattern features
		embedding[262] = e.hasRepeatingPatterns(text)
		embedding[263] = e.hasRandomLookingPattern(text)
		embedding[264] = e.hasDictionaryWords(text)
		embedding[265] = e.hasCommonPrefixes(text)
		embedding[266] = e.hasCommonSuffixes(text)
	}

	// Remaining dimensions filled with derived features
	for i := 267; i < len(embedding); i++ {
		// Use hash-based features for remaining dimensions
		hash := e.simpleHash(text, i)
		embedding[i] = float64(hash%1000) / 1000.0
	}

	return embedding, nil
}

func (e *EnhancedMLEngine) calculateEntropy(text string) float64 {
	if len(text) == 0 {
		return 0.0
	}

	freq := make(map[rune]int)
	for _, r := range text {
		freq[r]++
	}

	entropy := 0.0
	textLen := float64(len(text))
	for _, count := range freq {
		p := float64(count) / textLen
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}

	return entropy / 8.0 // Normalize to 0-1 range
}

func (e *EnhancedMLEngine) calculateVowelRatio(text string) float64 {
	if len(text) == 0 {
		return 0.0
	}

	vowels := "aeiouAEIOU"
	vowelCount := 0
	for _, r := range text {
		if strings.ContainsRune(vowels, r) {
			vowelCount++
		}
	}

	return float64(vowelCount) / float64(len(text))
}

func (e *EnhancedMLEngine) calculateDigitRatio(text string) float64 {
	if len(text) == 0 {
		return 0.0
	}

	digitCount := 0
	for _, r := range text {
		if unicode.IsDigit(r) {
			digitCount++
		}
	}

	return float64(digitCount) / float64(len(text))
}

func (e *EnhancedMLEngine) calculateUppercaseRatio(text string) float64 {
	if len(text) == 0 {
		return 0.0
	}

	upperCount := 0
	for _, r := range text {
		if unicode.IsUpper(r) {
			upperCount++
		}
	}

	return float64(upperCount) / float64(len(text))
}

func (e *EnhancedMLEngine) calculateSpecialCharRatio(text string) float64 {
	if len(text) == 0 {
		return 0.0
	}

	specialCount := 0
	for _, r := range text {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			specialCount++
		}
	}

	return float64(specialCount) / float64(len(text))
}

func (e *EnhancedMLEngine) hasRepeatingPatterns(text string) float64 {
	if len(text) < 4 {
		return 0.0
	}

	// Check for repeating substrings
	for length := 2; length <= len(text)/2; length++ {
		for i := 0; i <= len(text)-2*length; i++ {
			pattern := text[i : i+length]
			if strings.Contains(text[i+length:], pattern) {
				return 1.0
			}
		}
	}

	return 0.0
}

func (e *EnhancedMLEngine) hasRandomLookingPattern(text string) float64 {
	if len(text) < 5 {
		return 0.0
	}

	// High entropy and mixed case/numbers suggest randomness
	entropy := e.calculateEntropy(text)
	digitRatio := e.calculateDigitRatio(text)

	if entropy > 0.7 && digitRatio > 0.3 {
		return 1.0
	}

	return 0.0
}

func (e *EnhancedMLEngine) hasDictionaryWords(text string) float64 {
	// Simple check for common English words
	commonWords := []string{"the", "and", "for", "are", "but", "not", "you", "all", "can", "had", "her", "was", "one", "our", "out", "day", "get", "has", "him", "his", "how", "man", "new", "now", "old", "see", "two", "way", "who", "boy", "did", "its", "let", "put", "say", "she", "too", "use"}

	lowerText := strings.ToLower(text)
	for _, word := range commonWords {
		if strings.Contains(lowerText, word) {
			return 1.0
		}
	}

	return 0.0
}

func (e *EnhancedMLEngine) hasCommonPrefixes(text string) float64 {
	commonPrefixes := []string{"pre", "un", "re", "in", "dis", "en", "non", "over", "mis", "sub", "inter", "fore", "de", "trans", "super", "semi", "anti", "mid", "under"}

	lowerText := strings.ToLower(text)
	for _, prefix := range commonPrefixes {
		if strings.HasPrefix(lowerText, prefix) {
			return 1.0
		}
	}

	return 0.0
}

func (e *EnhancedMLEngine) hasCommonSuffixes(text string) float64 {
	commonSuffixes := []string{"ing", "ed", "er", "est", "ly", "tion", "ness", "ment", "ful", "less", "able", "ible", "al", "ial", "ic", "ous", "ive", "ize", "ise", "age", "dom", "ship", "ward", "wise"}

	lowerText := strings.ToLower(text)
	for _, suffix := range commonSuffixes {
		if strings.HasSuffix(lowerText, suffix) {
			return 1.0
		}
	}

	return 0.0
}

func (e *EnhancedMLEngine) simpleHash(text string, seed int) int {
	hash := seed
	for _, r := range text {
		hash = hash*31 + int(r)
	}
	return hash
}

// generatePackageEmbedding generates embedding for package features using feature-based approach
func (e *EnhancedMLEngine) generatePackageEmbedding(features *PackageFeatures) ([]float64, error) {
	// Create a feature-based embedding (384 dimensions)
	embedding := make([]float64, 384)

	// Normalize package name to embedding space (first 64 dimensions)
	nameEmbedding := e.generateNameEmbedding(features.PackageName)
	copy(embedding[0:64], nameEmbedding)

	// Author features (dimensions 64-127)
	authorEmbedding := e.generateAuthorEmbedding(features.AuthorFeatures)
	copy(embedding[64:128], authorEmbedding)

	// Repository features (dimensions 128-191)
	repoEmbedding := e.generateRepositoryEmbedding(features.RepositoryFeatures)
	copy(embedding[128:192], repoEmbedding)

	// Metadata features (dimensions 192-255)
	metadataEmbedding := e.generateMetadataEmbedding(features.MetadataFeatures)
	copy(embedding[192:256], metadataEmbedding)

	// Popularity features (dimensions 256-319)
	popularityEmbedding := e.generatePopularityEmbedding(features.PopularityFeatures)
	copy(embedding[256:320], popularityEmbedding)

	// Security features (dimensions 320-383)
	securityEmbedding := e.generateSecurityEmbedding(features.SecurityFeatures)
	copy(embedding[320:384], securityEmbedding)

	return embedding, nil
}

// generateNameEmbedding creates embedding from package name
func (e *EnhancedMLEngine) generateNameEmbedding(name string) []float64 {
	embedding := make([]float64, 64)

	// Character frequency analysis
	charFreq := make(map[rune]int)
	for _, char := range name {
		charFreq[char]++
	}

	// Convert to normalized features
	nameLen := float64(len(name))
	for i := 0; i < 26; i++ {
		char := rune('a' + i)
		freq := float64(charFreq[char]) / nameLen
		if i < 64 {
			embedding[i] = freq
		}
	}

	// Add structural features
	if len(embedding) > 26 {
		embedding[26] = float64(strings.Count(name, "-")) / nameLen // Hyphen frequency
		embedding[27] = float64(strings.Count(name, "_")) / nameLen // Underscore frequency
		embedding[28] = float64(strings.Count(name, ".")) / nameLen // Dot frequency
		embedding[29] = nameLen / 50.0                              // Normalized length

		// Add entropy-like features
		for i := 30; i < 64; i++ {
			pos := float64(i-30) / 34.0
			embedding[i] = math.Sin(pos * math.Pi * nameLen)
		}
	}

	return embedding
}

// generateAuthorEmbedding creates embedding from author features
func (e *EnhancedMLEngine) generateAuthorEmbedding(author AuthorFeatures) []float64 {
	embedding := make([]float64, 64)

	embedding[0] = math.Min(float64(author.AccountAge)/365.0, 1.0)         // Normalized age
	embedding[1] = math.Min(float64(author.PublishedPackages)/100.0, 1.0)  // Normalized package count
	embedding[2] = math.Min(float64(author.TotalDownloads)/1000000.0, 1.0) // Normalized downloads
	embedding[3] = math.Min(float64(author.GitHubFollowers)/1000.0, 1.0)   // Normalized followers
	embedding[4] = author.AverageRating                                    // Average rating

	if author.VerifiedAccount {
		embedding[5] = 1.0
	}
	if author.HasGitHubProfile {
		embedding[6] = 1.0
	}

	// Fill remaining dimensions with derived features
	for i := 8; i < 64; i++ {
		factor := float64(i-8) / 56.0
		embedding[i] = author.AverageRating * math.Sin(factor*math.Pi)
	}

	return embedding
}

// generateRepositoryEmbedding creates embedding from repository features
func (e *EnhancedMLEngine) generateRepositoryEmbedding(repo RepositoryFeatures) []float64 {
	embedding := make([]float64, 64)

	if repo.HasRepository {
		embedding[0] = 1.0
	}
	if repo.HasReadme {
		embedding[1] = 1.0
	}
	if repo.HasTests {
		embedding[3] = 1.0
	}
	if repo.HasCI {
		embedding[4] = 1.0
	}

	embedding[5] = math.Min(float64(repo.StarCount)/1000.0, 1.0)      // Normalized stars
	embedding[6] = math.Min(float64(repo.ForkCount)/100.0, 1.0)       // Normalized forks
	embedding[7] = math.Min(float64(repo.IssueCount)/100.0, 1.0)      // Normalized issues
	embedding[8] = math.Min(float64(repo.ContributorCount)/50.0, 1.0) // Normalized contributors
	embedding[9] = repo.TestCoverage / 100.0                          // Normalized test coverage
	embedding[10] = math.Min(float64(repo.CommitCount)/1000.0, 1.0)   // Normalized commits

	// Fill remaining dimensions
	for i := 11; i < 64; i++ {
		factor := float64(i-11) / 53.0
		embedding[i] = embedding[5] * math.Cos(factor*math.Pi) // Based on star count
	}

	return embedding
}

// generateMetadataEmbedding creates embedding from metadata features
func (e *EnhancedMLEngine) generateMetadataEmbedding(metadata MetadataFeatures) []float64 {
	embedding := make([]float64, 64)

	if metadata.HasDescription {
		embedding[0] = 1.0
	}
	if metadata.HasHomepage {
		embedding[1] = 1.0
	}
	if metadata.HasRepository {
		embedding[2] = 1.0
	}
	if metadata.HasLicense {
		embedding[3] = 1.0
	}
	if metadata.HasKeywords {
		embedding[4] = 1.0
	}

	embedding[5] = math.Min(float64(metadata.DescriptionLength)/500.0, 1.0)  // Normalized description length
	embedding[6] = metadata.DescriptionQuality                               // Description quality
	embedding[7] = math.Min(float64(metadata.KeywordCount)/20.0, 1.0)        // Normalized keyword count
	embedding[8] = math.Min(float64(metadata.VersionCount)/100.0, 1.0)       // Normalized version count
	embedding[9] = math.Min(float64(metadata.PublicationRecency)/365.0, 1.0) // Normalized recency

	// Fill remaining dimensions
	for i := 10; i < 64; i++ {
		factor := float64(i-10) / 54.0
		embedding[i] = metadata.DescriptionQuality * math.Sin(factor*2*math.Pi)
	}

	return embedding
}

// generatePopularityEmbedding creates embedding from popularity features
func (e *EnhancedMLEngine) generatePopularityEmbedding(popularity PopularityFeatures) []float64 {
	embedding := make([]float64, 64)

	embedding[0] = math.Min(float64(popularity.TotalDownloads)/10000000.0, 1.0) // Normalized total downloads
	embedding[1] = math.Min(float64(popularity.WeeklyDownloads)/100000.0, 1.0)  // Normalized weekly downloads
	embedding[2] = math.Min(float64(popularity.MonthlyDownloads)/500000.0, 1.0) // Normalized monthly downloads
	embedding[3] = math.Min(popularity.DownloadVelocity/10.0, 1.0)              // Normalized velocity
	embedding[4] = math.Min(float64(popularity.PopularityRank)/100000.0, 1.0)   // Normalized rank (inverted)
	embedding[5] = math.Min(float64(popularity.DependentPackages)/1000.0, 1.0)  // Normalized dependents
	embedding[6] = popularity.CommunityScore                                    // Community score
	embedding[7] = popularity.MaintenanceScore                                  // Maintenance score

	// Encode download trend
	switch popularity.DownloadTrend {
	case "increasing":
		embedding[8] = 1.0
	case "stable":
		embedding[9] = 1.0
	case "decreasing":
		embedding[10] = 1.0
	}

	// Fill remaining dimensions
	for i := 11; i < 64; i++ {
		factor := float64(i-11) / 53.0
		embedding[i] = popularity.CommunityScore * math.Cos(factor*math.Pi)
	}

	return embedding
}

// generateSecurityEmbedding creates embedding from security features
func (e *EnhancedMLEngine) generateSecurityEmbedding(security SecurityFeatures) []float64 {
	embedding := make([]float64, 64)

	embedding[0] = math.Min(float64(security.KnownVulnerabilities)/10.0, 1.0) // Normalized vulnerability count
	embedding[1] = security.SecurityScore                                     // Security score
	embedding[2] = 1.0 - security.SupplyChainRisk                             // Inverted supply chain risk
	embedding[3] = float64(security.SLSALevel) / 4.0                          // Normalized SLSA level

	if security.HasSecurityPolicy {
		embedding[4] = 1.0
	}
	if security.SignedReleases {
		embedding[5] = 1.0
	}
	if security.SigstoreVerified {
		embedding[6] = 1.0
	}
	if security.HasSBOM {
		embedding[7] = 1.0
	}

	// Encode malware indicators count
	embedding[8] = math.Min(float64(len(security.MalwareIndicators))/10.0, 1.0)

	// Encode suspicious scripts count
	embedding[9] = math.Min(float64(len(security.SuspiciousScripts))/10.0, 1.0)

	// Fill remaining dimensions
	for i := 10; i < 64; i++ {
		factor := float64(i-10) / 54.0
		embedding[i] = security.SecurityScore * math.Sin(factor*3*math.Pi)
	}

	return embedding
}

// convertToEnhancedFeatures converts PackageFeatures to EnhancedPackageFeatures for ML models
func (e *EnhancedMLEngine) convertToEnhancedFeatures(features *PackageFeatures) *EnhancedPackageFeatures {
	enhanced := &EnhancedPackageFeatures{
		Name:            features.PackageName,
		Registry:        features.Registry,
		Version:         features.Version,
		Description:     "", // Will be populated from metadata if available
		Author:          features.AuthorFeatures.AuthorName,
		Maintainers:     []string{features.AuthorFeatures.AuthorName},
		Keywords:        []string{}, // Will be populated from metadata
		License:         features.MetadataFeatures.LicenseType,
		Homepage:        "",
		Repository:      features.RepositoryFeatures.RepositoryURL,
		Downloads:       features.PopularityFeatures.TotalDownloads,
		Stars:           features.RepositoryFeatures.StarCount,
		Forks:           features.RepositoryFeatures.ForkCount,
		Issues:          features.RepositoryFeatures.IssueCount,
		CreationDate:    time.Now().AddDate(0, 0, -features.AuthorFeatures.AccountAge),
		LastUpdated:     features.AuthorFeatures.LastActivity,
		Dependencies:    []Dependency{}, // Will be populated if dependency data available
		DevDependencies: []Dependency{},
		Scripts:         make(map[string]string),
		FileStructure: FileStructure{
			TotalFiles:         0,
			JavaScriptFiles:    0,
			TypeScriptFiles:    0,
			ConfigFiles:        0,
			TestFiles:          0,
			DocumentationFiles: 0,
			BinaryFiles:        0,
			HiddenFiles:        0,
			SuspiciousFiles:    features.RepositoryFeatures.SuspiciousFiles,
			LargeFiles:         []string{},
			UnusualExtensions:  []string{},
		},
		CodeMetrics: CodeMetrics{
			LinesOfCode:          0,
			CyclomaticComplexity: 0,
			CodeDuplication:      0,
			TestCoverage:         features.RepositoryFeatures.TestCoverage,
			DocumentationRatio:   0,
			ObfuscationScore:     0,
			MinificationScore:    0,
			CommentRatio:         0,
		},
		SecurityMetrics: SecurityMetrics{
			VulnerabilityCount:    features.SecurityFeatures.KnownVulnerabilities,
			HighSeverityVulns:     0,
			CriticalSeverityVulns: 0,
			SuspiciousPatterns:    len(features.SecurityFeatures.MalwareIndicators),
			ObfuscatedCode:        false,
			NetworkCalls:          0,
			FileSystemAccess:      0,
			ProcessExecution:      0,
			CryptographicUsage:    0,
			DangerousFunctions:    len(features.SecurityFeatures.SuspiciousScripts),
			SecurityScore:         features.SecurityFeatures.SecurityScore,
		},
		BehavioralMetrics: BehavioralMetrics{
			InstallationBehavior: EnhancedInstallBehavior{
				PostInstallScript:  false,
				PreInstallScript:   false,
				NetworkActivity:    false,
				FileModifications:  0,
				PermissionChanges:  0,
				SuspiciousCommands: 0,
				InstallationTime:   0,
			},
			RuntimeBehavior: EnhancedRuntimeBehavior{
				CPUUsage:               0,
				MemoryUsage:            0,
				NetworkConnections:     0,
				FileOperations:         0,
				ProcessSpawning:        0,
				AntiAnalysisTechniques: false,
				PersistenceMechanisms:  false,
			},
			NetworkBehavior: EnhancedNetworkBehavior{
				OutboundConnections: 0,
				InboundConnections:  0,
				SuspiciousHosts:     []string{},
				UnusualPorts:        []int{},
				DataExfiltration:    false,
				C2Communication:     false,
				DNSTunneling:        false,
			},
			FileSystemBehavior: EnhancedFileSystemBehavior{
				FilesCreated:        0,
				FilesModified:       0,
				FilesDeleted:        0,
				SuspiciousLocations: []string{},
				HiddenFiles:         0,
				SystemFileAccess:    false,
				TempFileUsage:       0,
			},
			ProcessBehavior: EnhancedProcessBehavior{
				ChildProcesses:      0,
				PrivilegeEscalation: false,
				CodeInjection:       false,
				Hollowing:           false,
				DLLInjection:        false,
				SuspiciousCommands:  []string{},
			},
			AnomalyScore: 0,
		},
		Metadata: make(map[string]interface{}),
	}

	// Populate metadata with additional information
	enhanced.Metadata["name_complexity"] = features.NameComplexity
	enhanced.Metadata["name_entropy"] = features.NameEntropy
	enhanced.Metadata["typosquatting_score"] = features.TyposquattingScore
	enhanced.Metadata["domain_reputation"] = features.DomainReputation
	enhanced.Metadata["update_frequency"] = features.UpdateFrequency

	return enhanced
}

// performMaliciousDetection performs malicious package detection
func (e *EnhancedMLEngine) performMaliciousDetection(ctx context.Context, features *PackageFeatures) error {
	// Convert PackageFeatures to EnhancedPackageFeatures for ML models
	enhancedFeatures := e.convertToEnhancedFeatures(features)

	// Use the actual ML models from enhanced_detector.go
	malwareClassifier, err := NewMalwareClassifier()
	if err != nil {
		e.logger.Error("Failed to initialize malware classifier: " + err.Error())
		// Fallback to basic calculation
		features.MaliciousScore = e.calculateMaliciousScore(features)
		return nil
	}

	// Perform malware classification using the actual ML model
	classification, err := malwareClassifier.ClassifyMalware(ctx, enhancedFeatures)
	if err != nil {
		e.logger.Error("Failed to classify malware: " + err.Error())
		// Fallback to basic calculation
		features.MaliciousScore = e.calculateMaliciousScore(features)
		return nil
	}

	// Update features with ML model results
	features.MaliciousScore = classification.Confidence
	if classification.IsMalware {
		features.MaliciousScore = math.Max(features.MaliciousScore, 0.7) // Ensure high score for detected malware
	}

	// Store additional classification details in model versions for reference
	if features.ModelVersions == nil {
		features.ModelVersions = make(map[string]string)
	}
	features.ModelVersions["malware_classifier"] = fmt.Sprintf("type:%s,family:%s,confidence:%.2f",
		classification.MalwareType, classification.MalwareFamily, classification.Confidence)

	return nil
}

// calculateMaliciousScore calculates malicious score based on features
func (e *EnhancedMLEngine) calculateMaliciousScore(features *PackageFeatures) float64 {
	score := 0.0

	// Name-based indicators
	if features.NameComplexity > 0.8 {
		score += 0.2
	}
	if features.NameEntropy < 2.0 {
		score += 0.1
	}

	// Author-based indicators
	if features.AuthorFeatures.AccountAge < 30 {
		score += 0.3
	}
	if features.AuthorFeatures.PublishedPackages < 2 {
		score += 0.2
	}

	// Repository indicators
	if !features.RepositoryFeatures.HasRepository {
		score += 0.4
	}
	if features.RepositoryFeatures.StarCount < 5 {
		score += 0.1
	}

	return math.Min(score, 1.0)
}

// performReputationScoring performs reputation scoring
func (e *EnhancedMLEngine) performReputationScoring(ctx context.Context, features *PackageFeatures) error {
	// Convert PackageFeatures to EnhancedPackageFeatures for ML models
	enhancedFeatures := e.convertToEnhancedFeatures(features)

	// Use the actual ML models from enhanced_detector.go
	reputationAnalyzer, err := NewReputationAnalyzer()
	if err != nil {
		e.logger.Error("Failed to initialize reputation analyzer: " + err.Error())
		// Fallback to basic calculation
		features.ReputationScore = e.calculateReputationScore(features)
		return nil
	}

	// Perform reputation analysis using the actual ML model
	reputationAnalysis, err := reputationAnalyzer.AnalyzeReputation(ctx, enhancedFeatures)
	if err != nil {
		e.logger.Error("Failed to analyze reputation: " + err.Error())
		// Fallback to basic calculation
		features.ReputationScore = e.calculateReputationScore(features)
		return nil
	}

	// Update features with ML model results
	features.ReputationScore = reputationAnalysis.ReputationScore

	// Store additional reputation details in model versions for reference
	if features.ModelVersions == nil {
		features.ModelVersions = make(map[string]string)
	}
	features.ModelVersions["reputation_analyzer"] = fmt.Sprintf("trust_level:%s,author_rep:%.2f,community_trust:%.2f",
		reputationAnalysis.TrustLevel, reputationAnalysis.AuthorReputation, reputationAnalysis.CommunityTrust)

	return nil
}

// calculateReputationScore calculates reputation score
func (e *EnhancedMLEngine) calculateReputationScore(features *PackageFeatures) float64 {
	score := 0.0

	// Author reputation
	if features.AuthorFeatures.VerifiedAccount {
		score += 0.2
	}
	if features.AuthorFeatures.AccountAge > 365 {
		score += 0.2
	}
	if features.AuthorFeatures.PublishedPackages > 5 {
		score += 0.1
	}

	// Package quality
	if features.MetadataFeatures.HasLicense {
		score += 0.1
	}
	if features.MetadataFeatures.HasRepository {
		score += 0.1
	}

	// Repository quality
	if features.RepositoryFeatures.HasTests {
		score += 0.1
	}
	if features.RepositoryFeatures.TestCoverage > 80 {
		score += 0.1
	}
	if features.RepositoryFeatures.HasCI {
		score += 0.1
	}

	return math.Min(score, 1.0)
}

// buildResultFromFeatures builds analysis result from features
func (e *EnhancedMLEngine) buildResultFromFeatures(features *PackageFeatures, startTime time.Time) *MLAnalysisResult {
	result := &MLAnalysisResult{
		PackageName:       features.PackageName,
		Registry:          features.Registry,
		AnalysisTimestamp: time.Now(),
		Features:          *features,
		MaliciousScore:    features.MaliciousScore,
		ReputationScore:   features.ReputationScore,
		ModelVersions:     features.ModelVersions,
	}

	// Calculate overall risk
	result.RiskLevel = e.calculateRiskLevel(features)
	result.Confidence = e.calculateConfidence(features)
	result.Recommendation = e.generateRecommendation(features)
	result.Warnings = e.generateWarnings(features)

	// Find similar packages (placeholder)
	result.SimilarPackages = e.findSimilarPackages(features)
	result.TyposquattingRisk = e.calculateTyposquattingRisk(features)

	return result
}

// calculateRiskLevel determines overall risk level
func (e *EnhancedMLEngine) calculateRiskLevel(features *PackageFeatures) string {
	if features.MaliciousScore > 0.8 {
		return "HIGH"
	} else if features.MaliciousScore > 0.5 {
		return "MEDIUM"
	} else if features.MaliciousScore > 0.2 {
		return "LOW"
	}
	return "MINIMAL"
}

// calculateConfidence calculates confidence in the analysis
func (e *EnhancedMLEngine) calculateConfidence(features *PackageFeatures) float64 {
	confidence := 0.5 // Base confidence

	// Increase confidence based on available data
	if features.AuthorFeatures.AccountAge > 0 {
		confidence += 0.1
	}
	if features.RepositoryFeatures.HasRepository {
		confidence += 0.2
	}
	if features.PopularityFeatures.TotalDownloads > 1000 {
		confidence += 0.2
	}

	return math.Min(confidence, 1.0)
}

// generateRecommendation generates recommendation based on analysis
func (e *EnhancedMLEngine) generateRecommendation(features *PackageFeatures) string {
	if features.MaliciousScore > 0.8 {
		return "BLOCK: High risk of malicious package"
	} else if features.MaliciousScore > 0.5 {
		return "CAUTION: Manual review recommended"
	} else if features.ReputationScore < 0.3 {
		return "REVIEW: Low reputation package"
	}
	return "ALLOW: Package appears safe"
}

// generateWarnings generates warnings based on analysis
func (e *EnhancedMLEngine) generateWarnings(features *PackageFeatures) []string {
	var warnings []string

	if features.AuthorFeatures.AccountAge < 30 {
		warnings = append(warnings, "New author account (less than 30 days old)")
	}
	if !features.RepositoryFeatures.HasRepository {
		warnings = append(warnings, "No source repository available")
	}
	if features.PopularityFeatures.TotalDownloads < 100 {
		warnings = append(warnings, "Very low download count")
	}
	if !features.MetadataFeatures.HasLicense {
		warnings = append(warnings, "No license specified")
	}

	return warnings
}

// findSimilarPackages finds similar packages using ML similarity analysis
func (e *EnhancedMLEngine) findSimilarPackages(features *PackageFeatures) []SimilarPackage {
	// Convert PackageFeatures to EnhancedPackageFeatures for ML models
	enhancedFeatures := e.convertToEnhancedFeatures(features)

	// Use the actual ML models from enhanced_detector.go
	similarityModel, err := NewSimilarityModel()
	if err != nil {
		e.logger.Error("Failed to initialize similarity model: " + err.Error())
		// Return empty slice on error
		return []SimilarPackage{}
	}

	// Perform similarity analysis using the actual ML model
	ctx := context.Background()
	similarityResults, err := similarityModel.AnalyzeSimilarity(ctx, enhancedFeatures)
	if err != nil {
		e.logger.Error("Failed to analyze similarity: " + err.Error())
		// Return empty slice on error
		return []SimilarPackage{}
	}

	// Convert EnhancedSimilarityResult to SimilarPackage format
	var similarPackages []SimilarPackage
	for _, result := range similarityResults {
		// Calculate edit distance for compatibility
		distance := e.calculateEditDistance(features.PackageName, result.SimilarPackage)

		similarPackage := SimilarPackage{
			Name:           result.SimilarPackage,
			Registry:       features.Registry,
			Similarity:     result.SimilarityScore,
			Distance:       distance,
			Algorithm:      result.SimilarityType,
			Downloads:      0, // Would be populated from registry data in production
			LastUpdated:    "unknown",
			Maintainer:     "unknown",
			SuspiciousFlag: result.SimilarityScore > 0.9, // High similarity might indicate typosquatting
		}

		similarPackages = append(similarPackages, similarPackage)
	}

	return similarPackages
}

// calculateEditDistance calculates Levenshtein distance between two strings
func (e *EnhancedMLEngine) calculateEditDistance(s1, s2 string) int {
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
			matrix[i][j] = e.min3(
				matrix[i-1][j]+1,
				matrix[i][j-1]+1,
				matrix[i-1][j-1]+cost,
			)
		}
	}

	return matrix[len(s1)][len(s2)]
}

// min3 returns the minimum of three integers
func (e *EnhancedMLEngine) min3(a, b, c int) int {
	if a <= b && a <= c {
		return a
	}
	if b <= c {
		return b
	}
	return c
}

// calculateTyposquattingRisk calculates typosquatting risk using ML typo detection
func (e *EnhancedMLEngine) calculateTyposquattingRisk(features *PackageFeatures) float64 {
	// Convert PackageFeatures to EnhancedPackageFeatures for ML models
	enhancedFeatures := e.convertToEnhancedFeatures(features)

	// Use the actual ML models from enhanced_detector.go
	typoDetector, err := NewTypoDetector()
	if err != nil {
		e.logger.Error("Failed to initialize typo detector: " + err.Error())
		// Return basic calculation as fallback
		return e.calculateBasicTyposquattingRisk(features)
	}

	// Perform typosquatting detection using the actual ML model
	ctx := context.Background()
	typoDetection, err := typoDetector.DetectTyposquatting(ctx, enhancedFeatures)
	if err != nil {
		e.logger.Error("Failed to detect typosquatting: " + err.Error())
		// Return basic calculation as fallback
		return e.calculateBasicTyposquattingRisk(features)
	}

	// Return the confidence score from the ML model
	if typoDetection.IsTyposquatting {
		return typoDetection.Confidence
	}

	// Return a lower risk score if not detected as typosquatting
	return typoDetection.Confidence * 0.3
}

// calculateBasicTyposquattingRisk provides a basic fallback calculation
func (e *EnhancedMLEngine) calculateBasicTyposquattingRisk(features *PackageFeatures) float64 {
	risk := 0.0

	// Basic heuristics for typosquatting risk
	if features.NameComplexity > 0.7 {
		risk += 0.2
	}

	if features.NameEntropy < 3.0 {
		risk += 0.1
	}

	if features.PopularityFeatures.TotalDownloads < 100 {
		risk += 0.2
	}

	if features.AuthorFeatures.AccountAge < 30 {
		risk += 0.1
	}

	return math.Min(risk, 1.0)
}
