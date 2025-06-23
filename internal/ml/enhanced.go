package ml

import (
	"context"
	"fmt"
	"math"
	"time"
)

// EnhancedMLEngine provides advanced ML capabilities
type EnhancedMLEngine struct {
	client      *Client
	featureStore *FeatureStore
	config      *MLConfig
}

// MLConfig contains ML engine configuration
type MLConfig struct {
	EmbeddingModel        string  `yaml:"embedding_model"`
	MaliciousModel        string  `yaml:"malicious_model"`
	ReputationModel       string  `yaml:"reputation_model"`
	SimilarityThreshold   float64 `yaml:"similarity_threshold"`
	MaliciousThreshold    float64 `yaml:"malicious_threshold"`
	ReputationThreshold   float64 `yaml:"reputation_threshold"`
	FeatureStoreEnabled   bool    `yaml:"feature_store_enabled"`
	FeatureStoreTTL       string  `yaml:"feature_store_ttl"`
	BatchSize             int     `yaml:"batch_size"`
	MaxRetries            int     `yaml:"max_retries"`
	Timeout               string  `yaml:"timeout"`
}

// PackageFeatures represents comprehensive package features
type PackageFeatures struct {
	PackageName     string                 `json:"package_name"`
	Registry        string                 `json:"registry"`
	Version         string                 `json:"version,omitempty"`
	PackageType     string                 `json:"package_type,omitempty"`
	
	// Name-based features
	NameEmbedding   []float64              `json:"name_embedding"`
	NameLength      int                    `json:"name_length"`
	NameComplexity  float64                `json:"name_complexity"`
	NameEntropy     float64                `json:"name_entropy"`
	
	// Direct access fields for compatibility
	VersionComplexity    float64           `json:"version_complexity"`
	DescriptionLength    int               `json:"description_length"`
	DependencyCount      int               `json:"dependency_count"`
	DownloadCount        int64             `json:"download_count"`
	StarCount           int               `json:"star_count"`
	ForkCount           int               `json:"fork_count"`
	ContributorCount    int               `json:"contributor_count"`
	AgeInDays           int               `json:"age_in_days"`
	TyposquattingScore  float64           `json:"typosquatting_score"`
	SuspiciousKeywords  int               `json:"suspicious_keywords"`
	VersionSpoofing     float64           `json:"version_spoofing"`
	DomainReputation    float64           `json:"domain_reputation"`
	UpdateFrequency     float64           `json:"update_frequency"`
	MaintainerCount     int               `json:"maintainer_count"`
	IssueCount          int               `json:"issue_count"`
	LicenseScore        float64           `json:"license_score"`
	
	// Author features
	AuthorFeatures  AuthorFeatures         `json:"author_features"`
	
	// Package metadata features
	MetadataFeatures MetadataFeatures      `json:"metadata_features"`
	
	// Repository features
	RepositoryFeatures RepositoryFeatures  `json:"repository_features"`
	
	// Download and popularity features
	PopularityFeatures PopularityFeatures  `json:"popularity_features"`
	
	// Security features
	SecurityFeatures SecurityFeatures      `json:"security_features"`
	
	// Computed scores
	MaliciousScore   float64               `json:"malicious_score"`
	ReputationScore  float64               `json:"reputation_score"`
	OverallRisk      float64               `json:"overall_risk"`
	
	// Metadata
	Timestamp        time.Time             `json:"timestamp"`
	ModelVersions    map[string]string     `json:"model_versions"`
	FeatureVersion   string                `json:"feature_version"`
}

// AuthorFeatures contains author-related features
type AuthorFeatures struct {
	AuthorName          string    `json:"author_name"`
	AuthorEmail         string    `json:"author_email"`
	AccountAge          int       `json:"account_age_days"`
	PublishedPackages   int       `json:"published_packages"`
	TotalDownloads      int64     `json:"total_downloads"`
	AverageRating       float64   `json:"average_rating"`
	VerifiedAccount     bool      `json:"verified_account"`
	HasGitHubProfile    bool      `json:"has_github_profile"`
	GitHubFollowers     int       `json:"github_followers"`
	GitHubRepos         int       `json:"github_repos"`
	LastActivity        time.Time `json:"last_activity"`
	SuspiciousPatterns  []string  `json:"suspicious_patterns"`
}

// MetadataFeatures contains package metadata features
type MetadataFeatures struct {
	HasDescription      bool      `json:"has_description"`
	DescriptionLength   int       `json:"description_length"`
	DescriptionQuality  float64   `json:"description_quality"`
	HasHomepage         bool      `json:"has_homepage"`
	HasRepository       bool      `json:"has_repository"`
	HasLicense          bool      `json:"has_license"`
	LicenseType         string    `json:"license_type"`
	HasKeywords         bool      `json:"has_keywords"`
	KeywordCount        int       `json:"keyword_count"`
	VersionCount        int       `json:"version_count"`
	LatestVersion       string    `json:"latest_version"`
	VersionPattern      string    `json:"version_pattern"`
	UnusualVersionJump  bool      `json:"unusual_version_jump"`
	PublicationRecency  int       `json:"publication_recency_days"`
}

// RepositoryFeatures contains repository-related features
type RepositoryFeatures struct {
	HasRepository       bool      `json:"has_repository"`
	RepositoryURL       string    `json:"repository_url"`
	RepositoryType      string    `json:"repository_type"`
	StarCount           int       `json:"star_count"`
	ForkCount           int       `json:"fork_count"`
	IssueCount          int       `json:"issue_count"`
	CommitCount         int       `json:"commit_count"`
	ContributorCount    int       `json:"contributor_count"`
	LastCommit          time.Time `json:"last_commit"`
	HasReadme           bool      `json:"has_readme"`
	ReadmeLength        int       `json:"readme_length"`
	HasTests            bool      `json:"has_tests"`
	TestCoverage        float64   `json:"test_coverage"`
	HasCI               bool      `json:"has_ci"`
	LanguageDistribution map[string]float64 `json:"language_distribution"`
	SuspiciousFiles     []string  `json:"suspicious_files"`
}

// PopularityFeatures contains popularity and download features
type PopularityFeatures struct {
	TotalDownloads      int64     `json:"total_downloads"`
	WeeklyDownloads     int64     `json:"weekly_downloads"`
	MonthlyDownloads    int64     `json:"monthly_downloads"`
	DownloadTrend       string    `json:"download_trend"`
	DownloadVelocity    float64   `json:"download_velocity"`
	PopularityRank      int       `json:"popularity_rank"`
	DependentPackages   int       `json:"dependent_packages"`
	DependencyRank      int       `json:"dependency_rank"`
	CommunityScore      float64   `json:"community_score"`
	MaintenanceScore    float64   `json:"maintenance_score"`
}

// SecurityFeatures contains security-related features
type SecurityFeatures struct {
	KnownVulnerabilities int       `json:"known_vulnerabilities"`
	SecurityScore        float64   `json:"security_score"`
	HasSecurityPolicy    bool      `json:"has_security_policy"`
	SignedReleases       bool      `json:"signed_releases"`
	SigstoreVerified     bool      `json:"sigstore_verified"`
	SLSALevel            int       `json:"slsa_level"`
	HasSBOM              bool      `json:"has_sbom"`
	SupplyChainRisk      float64   `json:"supply_chain_risk"`
	MalwareIndicators    []string  `json:"malware_indicators"`
	SuspiciousScripts    []string  `json:"suspicious_scripts"`
}

// MLAnalysisResult represents comprehensive ML analysis results
type MLAnalysisResult struct {
	PackageName         string                 `json:"package_name"`
	Registry            string                 `json:"registry"`
	AnalysisTimestamp   time.Time              `json:"analysis_timestamp"`
	
	// Feature analysis
	Features            PackageFeatures        `json:"features"`
	
	// Similarity analysis
	SimilarPackages     []SimilarPackage       `json:"similar_packages"`
	TyposquattingRisk   float64                `json:"typosquatting_risk"`
	
	// Malicious detection
	MaliciousScore      float64                `json:"malicious_score"`
	MaliciousIndicators []MaliciousIndicator   `json:"malicious_indicators"`
	
	// Reputation scoring
	ReputationScore     float64                `json:"reputation_score"`
	ReputationFactors   []ReputationFactor     `json:"reputation_factors"`
	
	// Overall assessment
	RiskLevel           string                 `json:"risk_level"`
	Confidence          float64                `json:"confidence"`
	Recommendation      string                 `json:"recommendation"`
	Warnings            []string               `json:"warnings"`
	
	// Model information
	ModelVersions       map[string]string      `json:"model_versions"`
	ProcessingTime      time.Duration          `json:"processing_time"`
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
func NewEnhancedMLEngine(client *Client, config *MLConfig) *EnhancedMLEngine {
	if config == nil {
		config = DefaultMLConfig()
	}
	
	return &EnhancedMLEngine{
		client:       client,
		featureStore: NewFeatureStore(config),
		config:       config,
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

// Placeholder implementations for feature extraction
// In production, these would integrate with actual registry APIs and databases

func (e *EnhancedMLEngine) extractMetadataFeatures(ctx context.Context, features *PackageFeatures) {
	// Placeholder - would fetch from registry API
	features.MetadataFeatures = MetadataFeatures{
		HasDescription:     true,
		DescriptionLength:  100,
		DescriptionQuality: 0.8,
		HasHomepage:        true,
		HasRepository:      true,
		HasLicense:         true,
		LicenseType:        "MIT",
		VersionCount:       10,
		PublicationRecency: 30,
	}
}

func (e *EnhancedMLEngine) extractAuthorFeatures(ctx context.Context, features *PackageFeatures) {
	// Placeholder - would fetch from registry and GitHub APIs
	features.AuthorFeatures = AuthorFeatures{
		AuthorName:        "example-author",
		AuthorEmail:       "author@example.com",
		AccountAge:        365,
		PublishedPackages: 5,
		TotalDownloads:    10000,
		VerifiedAccount:   true,
		HasGitHubProfile:  true,
		GitHubFollowers:   100,
		GitHubRepos:       20,
		LastActivity:      time.Now().AddDate(0, 0, -7),
	}
}

func (e *EnhancedMLEngine) extractRepositoryFeatures(ctx context.Context, features *PackageFeatures) {
	// Placeholder - would fetch from GitHub/GitLab APIs
	features.RepositoryFeatures = RepositoryFeatures{
		HasRepository:    true,
		RepositoryURL:    "https://github.com/example/repo",
		RepositoryType:   "git",
		StarCount:        100,
		ForkCount:        20,
		CommitCount:      500,
		ContributorCount: 5,
		LastCommit:       time.Now().AddDate(0, 0, -1),
		HasReadme:        true,
		ReadmeLength:     2000,
		HasTests:         true,
		TestCoverage:     85.5,
		HasCI:            true,
	}
}

func (e *EnhancedMLEngine) extractPopularityFeatures(ctx context.Context, features *PackageFeatures) {
	// Placeholder - would fetch from registry APIs
	features.PopularityFeatures = PopularityFeatures{
		TotalDownloads:    100000,
		WeeklyDownloads:   1000,
		MonthlyDownloads:  5000,
		DownloadTrend:     "increasing",
		DownloadVelocity:  1.2,
		PopularityRank:    1000,
		DependentPackages: 50,
		CommunityScore:    0.8,
		MaintenanceScore:  0.9,
	}
}

func (e *EnhancedMLEngine) extractSecurityFeatures(ctx context.Context, features *PackageFeatures) {
	// Placeholder - would integrate with security databases
	features.SecurityFeatures = SecurityFeatures{
		KnownVulnerabilities: 0,
		SecurityScore:        0.9,
		HasSecurityPolicy:    true,
		SignedReleases:       false,
		SigstoreVerified:     false,
		SLSALevel:            0,
		HasSBOM:              false,
		SupplyChainRisk:      0.2,
	}
}

// performEmbeddingAnalysis performs embedding-based similarity analysis
func (e *EnhancedMLEngine) performEmbeddingAnalysis(ctx context.Context, features *PackageFeatures) error {
	// Generate embedding for package name
	embedding, err := e.generateEmbedding(ctx, features.PackageName)
	if err != nil {
		return fmt.Errorf("failed to generate embedding: %w", err)
	}
	
	features.NameEmbedding = embedding
	return nil
}

// generateEmbedding generates embedding vector for text
func (e *EnhancedMLEngine) generateEmbedding(ctx context.Context, text string) ([]float64, error) {
	// Placeholder - would call actual embedding model
	// For now, return a dummy embedding
	embedding := make([]float64, 384) // Common embedding dimension
	for i := range embedding {
		embedding[i] = math.Sin(float64(i) * 0.1) // Dummy values
	}
	return embedding, nil
}

// performMaliciousDetection performs malicious package detection
func (e *EnhancedMLEngine) performMaliciousDetection(ctx context.Context, features *PackageFeatures) error {
	// Placeholder - would call actual ML model
	features.MaliciousScore = e.calculateMaliciousScore(features)
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
	// Placeholder - would call actual ML model
	features.ReputationScore = e.calculateReputationScore(features)
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

// findSimilarPackages finds similar packages (placeholder)
func (e *EnhancedMLEngine) findSimilarPackages(features *PackageFeatures) []SimilarPackage {
	// Placeholder implementation
	return []SimilarPackage{
		{
			Name:           "similar-package",
			Registry:       features.Registry,
			Similarity:     0.85,
			Distance:       2,
			Algorithm:      "embedding",
			Downloads:      50000,
			LastUpdated:    "2024-01-01",
			Maintainer:     "example-maintainer",
			SuspiciousFlag: false,
		},
	}
}

// calculateTyposquattingRisk calculates typosquatting risk
func (e *EnhancedMLEngine) calculateTyposquattingRisk(features *PackageFeatures) float64 {
	// Placeholder - would use similarity analysis with popular packages
	return 0.3
}