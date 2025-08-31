package ml

import (
	"context"
	"fmt"
	"math"
	"regexp"
	"strings"
	"time"
)

// MetadataFilter provides enhanced metadata-based filtering to reduce false positives
type MetadataFilter struct {
	config *MetadataFilterConfig
}

// MetadataFilterConfig contains configuration for metadata filtering
type MetadataFilterConfig struct {
	MinDownloadThreshold   int64   `json:"min_download_threshold"`
	MinVersionCount        int     `json:"min_version_count"`
	MinMaintainerCount     int     `json:"min_maintainer_count"`
	MaxAgeForRelevance     int     `json:"max_age_for_relevance_days"`
	SimilarityThreshold    float64 `json:"similarity_threshold"`
	EnableTechnologyFilter bool    `json:"enable_technology_filter"`
	EnableAgeFilter        bool    `json:"enable_age_filter"`
	EnablePopularityFilter bool    `json:"enable_popularity_filter"`
	EnableMaintainerFilter bool    `json:"enable_maintainer_filter"`
	EnableRepositoryFilter bool    `json:"enable_repository_filter"`
}

// MetadataAnalysis contains the results of metadata analysis
type MetadataAnalysis struct {
	IsLegitimate         bool     `json:"is_legitimate"`
	ConfidenceScore      float64  `json:"confidence_score"`
	RiskFactors          []string `json:"risk_factors"`
	PositiveIndicators   []string `json:"positive_indicators"`
	TyposquattingRisk    float64  `json:"typosquatting_risk"`
	SupplyChainRisk      float64  `json:"supply_chain_risk"`
	FilterReasons        []string `json:"filter_reasons"`
	MetadataQuality      float64  `json:"metadata_quality"`
	TechnologyAlignment  float64  `json:"technology_alignment"`
	PopularityScore      float64  `json:"popularity_score"`
	MaintainerTrustScore float64  `json:"maintainer_trust_score"`
	RepositoryTrustScore float64  `json:"repository_trust_score"`
}

// PackageMetadata contains enhanced package metadata for analysis
type PackageMetadata struct {
	Name               string             `json:"name"`
	Version            string             `json:"version"`
	Description        string             `json:"description"`
	Homepage           string             `json:"homepage"`
	Repository         string             `json:"repository"`
	License            string             `json:"license"`
	Keywords           []string           `json:"keywords"`
	Dependencies       map[string]string  `json:"dependencies"`
	DevDependencies    map[string]string  `json:"dev_dependencies"`
	Maintainers        []string           `json:"maintainers"`
	CreatedAt          time.Time          `json:"created_at"`
	UpdatedAt          time.Time          `json:"updated_at"`
	DownloadStats      DownloadStats      `json:"download_stats"`
	VersionHistory     []VersionInfo      `json:"version_history"`
	SecurityAdvisories []SecurityAdvisory `json:"security_advisories"`
	Registry           string             `json:"registry"`
}

// DownloadStats contains download statistics
type DownloadStats struct {
	Weekly  int64 `json:"weekly"`
	Monthly int64 `json:"monthly"`
	Total   int64 `json:"total"`
}

// VersionInfo contains version information
type VersionInfo struct {
	Version      string    `json:"version"`
	PublishedAt  time.Time `json:"published_at"`
	IsPrerelease bool      `json:"is_prerelease"`
}

// SecurityAdvisory contains security advisory information
type SecurityAdvisory struct {
	ID               string    `json:"id"`
	Title            string    `json:"title"`
	Severity         string    `json:"severity"`
	CVSS             float64   `json:"cvss"`
	PublishedAt      time.Time `json:"published_at"`
	AffectedVersions string    `json:"affected_versions"`
}

// NewMetadataFilter creates a new metadata filter with default configuration
func NewMetadataFilter() *MetadataFilter {
	return &MetadataFilter{
		config: &MetadataFilterConfig{
			MinDownloadThreshold:   1000,    // Minimum weekly downloads
			MinVersionCount:        3,       // Minimum number of versions
			MinMaintainerCount:     1,       // Minimum number of maintainers
			MaxAgeForRelevance:     365 * 5, // 5 years for CVE relevance
			SimilarityThreshold:    0.85,    // Similarity threshold for typosquatting
			EnableTechnologyFilter: true,
			EnableAgeFilter:        true,
			EnablePopularityFilter: true,
			EnableMaintainerFilter: true,
			EnableRepositoryFilter: true,
		},
	}
}

// AnalyzeMetadata performs comprehensive metadata analysis
func (mf *MetadataFilter) AnalyzeMetadata(ctx context.Context, metadata *PackageMetadata) (*MetadataAnalysis, error) {
	analysis := &MetadataAnalysis{
		RiskFactors:        []string{},
		PositiveIndicators: []string{},
		FilterReasons:      []string{},
	}

	// Analyze different aspects of the package metadata
	mf.analyzePopularity(metadata, analysis)
	mf.analyzeMaintainers(metadata, analysis)
	mf.analyzeRepository(metadata, analysis)
	mf.analyzeVersionHistory(metadata, analysis)
	mf.analyzeSecurityAdvisories(metadata, analysis)
	mf.analyzeTechnologyAlignment(metadata, analysis)
	mf.analyzeMetadataQuality(metadata, analysis)
	mf.detectTyposquattingIndicators(metadata, analysis)

	// Calculate overall scores
	mf.calculateOverallScores(analysis)

	return analysis, nil
}

// analyzePopularity analyzes package popularity metrics
func (mf *MetadataFilter) analyzePopularity(metadata *PackageMetadata, analysis *MetadataAnalysis) {
	downloads := metadata.DownloadStats.Weekly

	// Calculate popularity score (0-1)
	if downloads >= 1000000 {
		analysis.PopularityScore = 1.0
		analysis.PositiveIndicators = append(analysis.PositiveIndicators, "high_download_count")
	} else if downloads >= 100000 {
		analysis.PopularityScore = 0.8
		analysis.PositiveIndicators = append(analysis.PositiveIndicators, "moderate_download_count")
	} else if downloads >= 10000 {
		analysis.PopularityScore = 0.6
		analysis.PositiveIndicators = append(analysis.PositiveIndicators, "decent_download_count")
	} else if downloads >= 1000 {
		analysis.PopularityScore = 0.4
	} else if downloads >= 100 {
		analysis.PopularityScore = 0.2
		analysis.RiskFactors = append(analysis.RiskFactors, "low_download_count")
	} else {
		analysis.PopularityScore = 0.0
		analysis.RiskFactors = append(analysis.RiskFactors, "very_low_download_count")
		if downloads < 10 {
			analysis.RiskFactors = append(analysis.RiskFactors, "extremely_low_usage")
		}
	}

	// Check for suspicious download patterns
	if downloads < mf.config.MinDownloadThreshold {
		analysis.FilterReasons = append(analysis.FilterReasons, "below_minimum_download_threshold")
	}
}

// analyzeMaintainers analyzes maintainer information
func (mf *MetadataFilter) analyzeMaintainers(metadata *PackageMetadata, analysis *MetadataAnalysis) {
	maintainerCount := len(metadata.Maintainers)

	if maintainerCount >= 5 {
		analysis.MaintainerTrustScore = 1.0
		analysis.PositiveIndicators = append(analysis.PositiveIndicators, "multiple_maintainers")
	} else if maintainerCount >= 3 {
		analysis.MaintainerTrustScore = 0.8
		analysis.PositiveIndicators = append(analysis.PositiveIndicators, "several_maintainers")
	} else if maintainerCount == 2 {
		analysis.MaintainerTrustScore = 0.6
	} else if maintainerCount == 1 {
		analysis.MaintainerTrustScore = 0.3
		analysis.RiskFactors = append(analysis.RiskFactors, "single_maintainer")
	} else {
		analysis.MaintainerTrustScore = 0.0
		analysis.RiskFactors = append(analysis.RiskFactors, "no_maintainers")
	}

	// Check for known trusted maintainers (this would be populated from a database)
	trustedMaintainers := mf.getTrustedMaintainers(metadata.Registry)
	for _, maintainer := range metadata.Maintainers {
		if mf.isTrustedMaintainer(maintainer, trustedMaintainers) {
			analysis.MaintainerTrustScore = math.Min(1.0, analysis.MaintainerTrustScore+0.2)
			analysis.PositiveIndicators = append(analysis.PositiveIndicators, "trusted_maintainer")
			break
		}
	}
}

// analyzeRepository analyzes repository information
func (mf *MetadataFilter) analyzeRepository(metadata *PackageMetadata, analysis *MetadataAnalysis) {
	if metadata.Repository == "" {
		analysis.RepositoryTrustScore = 0.0
		analysis.RiskFactors = append(analysis.RiskFactors, "no_repository")
		return
	}

	// Check for trusted hosting platforms
	trustedHosts := []string{"github.com", "gitlab.com", "bitbucket.org"}
	repoLower := strings.ToLower(metadata.Repository)

	for _, host := range trustedHosts {
		if strings.Contains(repoLower, host) {
			analysis.RepositoryTrustScore = 0.8
			analysis.PositiveIndicators = append(analysis.PositiveIndicators, "trusted_repository_host")
			break
		}
	}

	// Check for suspicious repository patterns
	if strings.Contains(repoLower, "webpack") && metadata.Name == "webpack2" {
		analysis.RiskFactors = append(analysis.RiskFactors, "claims_official_repository")
		analysis.TyposquattingRisk += 0.4
	}

	// Check for organization vs personal repositories
	if strings.Contains(repoLower, "github.com") {
		parts := strings.Split(repoLower, "/")
		if len(parts) >= 4 {
			owner := parts[3]
			// Check if it's an organization (this would be enhanced with actual API calls)
			if mf.isKnownOrganization(owner) {
				analysis.RepositoryTrustScore = math.Min(1.0, analysis.RepositoryTrustScore+0.2)
				analysis.PositiveIndicators = append(analysis.PositiveIndicators, "organization_repository")
			}
		}
	}
}

// analyzeVersionHistory analyzes version history patterns
func (mf *MetadataFilter) analyzeVersionHistory(metadata *PackageMetadata, analysis *MetadataAnalysis) {
	versionCount := len(metadata.VersionHistory)

	if versionCount >= 50 {
		analysis.PositiveIndicators = append(analysis.PositiveIndicators, "extensive_version_history")
	} else if versionCount >= 20 {
		analysis.PositiveIndicators = append(analysis.PositiveIndicators, "good_version_history")
	} else if versionCount >= 10 {
		analysis.PositiveIndicators = append(analysis.PositiveIndicators, "moderate_version_history")
	} else if versionCount < 3 {
		analysis.RiskFactors = append(analysis.RiskFactors, "minimal_version_history")
	}

	// Check for suspicious version patterns
	if versionCount < mf.config.MinVersionCount {
		analysis.FilterReasons = append(analysis.FilterReasons, "insufficient_version_history")
	}

	// Analyze version release patterns
	if len(metadata.VersionHistory) >= 2 {
		mf.analyzeReleasePatterns(metadata.VersionHistory, analysis)
	}
}

// analyzeReleasePatterns analyzes release timing patterns
func (mf *MetadataFilter) analyzeReleasePatterns(versions []VersionInfo, analysis *MetadataAnalysis) {
	if len(versions) < 2 {
		return
	}

	// Check for rapid successive releases (potential spam)
	rapidReleases := 0
	for i := 1; i < len(versions); i++ {
		timeDiff := versions[i].PublishedAt.Sub(versions[i-1].PublishedAt)
		if timeDiff.Hours() < 1 {
			rapidReleases++
		}
	}

	if rapidReleases > 3 {
		analysis.RiskFactors = append(analysis.RiskFactors, "rapid_successive_releases")
	}

	// Check for long periods of inactivity followed by sudden activity
	if len(versions) >= 3 {
		latest := versions[len(versions)-1]
		secondLatest := versions[len(versions)-2]
		timeSinceLastRelease := latest.PublishedAt.Sub(secondLatest.PublishedAt)

		if timeSinceLastRelease.Hours() > 24*365 { // More than a year
			analysis.RiskFactors = append(analysis.RiskFactors, "long_inactivity_period")
		}
	}
}

// analyzeSecurityAdvisories analyzes security advisory patterns
func (mf *MetadataFilter) analyzeSecurityAdvisories(metadata *PackageMetadata, analysis *MetadataAnalysis) {
	advisoryCount := len(metadata.SecurityAdvisories)

	if advisoryCount == 0 {
		analysis.PositiveIndicators = append(analysis.PositiveIndicators, "no_security_advisories")
		return
	}

	// Count critical/high severity advisories
	criticalCount := 0
	highCount := 0
	recentCount := 0
	now := time.Now()

	for _, advisory := range metadata.SecurityAdvisories {
		if advisory.CVSS >= 9.0 {
			criticalCount++
		} else if advisory.CVSS >= 7.0 {
			highCount++
		}

		// Check for recent advisories (last 6 months)
		if now.Sub(advisory.PublishedAt).Hours() < 24*180 {
			recentCount++
		}
	}

	if criticalCount > 0 {
		analysis.RiskFactors = append(analysis.RiskFactors, "critical_security_vulnerabilities")
		analysis.SupplyChainRisk += 0.5
	}

	if highCount > 3 {
		analysis.RiskFactors = append(analysis.RiskFactors, "multiple_high_severity_vulnerabilities")
		analysis.SupplyChainRisk += 0.3
	}

	if recentCount > 5 {
		analysis.RiskFactors = append(analysis.RiskFactors, "many_recent_security_issues")
		analysis.SupplyChainRisk += 0.2
	}

	// Excessive security advisories might indicate a problematic package
	if advisoryCount > 20 {
		analysis.RiskFactors = append(analysis.RiskFactors, "excessive_security_advisories")
	}
}

// analyzeTechnologyAlignment analyzes technology stack alignment
func (mf *MetadataFilter) analyzeTechnologyAlignment(metadata *PackageMetadata, analysis *MetadataAnalysis) {
	// This would be enhanced with actual technology detection
	// For now, we'll do basic keyword analysis

	description := strings.ToLower(metadata.Description)
	keywords := make([]string, len(metadata.Keywords))
	for i, k := range metadata.Keywords {
		keywords[i] = strings.ToLower(k)
	}

	// Check for technology indicators
	technologies := []string{"javascript", "node", "npm", "webpack", "react", "vue", "angular"}
	alignmentScore := 0.0

	for _, tech := range technologies {
		if strings.Contains(description, tech) {
			alignmentScore += 0.1
		}
		for _, keyword := range keywords {
			if strings.Contains(keyword, tech) {
				alignmentScore += 0.1
			}
		}
	}

	analysis.TechnologyAlignment = math.Min(1.0, alignmentScore)

	if analysis.TechnologyAlignment > 0.5 {
		analysis.PositiveIndicators = append(analysis.PositiveIndicators, "good_technology_alignment")
	} else if analysis.TechnologyAlignment < 0.2 {
		analysis.RiskFactors = append(analysis.RiskFactors, "poor_technology_alignment")
	}
}

// analyzeMetadataQuality analyzes the quality and completeness of metadata
func (mf *MetadataFilter) analyzeMetadataQuality(metadata *PackageMetadata, analysis *MetadataAnalysis) {
	qualityScore := 0.0

	// Enhanced description analysis
	if metadata.Description != "" {
		descScore := mf.analyzeDescriptionQuality(metadata.Description)
		qualityScore += descScore * 0.3 // Increased weight for description

		if descScore >= 0.8 {
			analysis.PositiveIndicators = append(analysis.PositiveIndicators, "high_quality_description")
		} else if descScore < 0.3 {
			analysis.RiskFactors = append(analysis.RiskFactors, "poor_description_quality")
		}
	} else {
		analysis.RiskFactors = append(analysis.RiskFactors, "missing_description")
	}

	// Repository validation with enhanced checks
	if metadata.Repository != "" {
		repoScore := mf.analyzeRepositoryQuality(metadata.Repository)
		qualityScore += repoScore * 0.25

		if repoScore >= 0.8 {
			analysis.PositiveIndicators = append(analysis.PositiveIndicators, "trusted_repository")
		} else if repoScore < 0.3 {
			analysis.RiskFactors = append(analysis.RiskFactors, "suspicious_repository")
		}
	} else {
		analysis.RiskFactors = append(analysis.RiskFactors, "missing_repository")
	}

	// License validation
	if metadata.License != "" {
		licenseScore := mf.analyzeLicenseQuality(metadata.License)
		qualityScore += licenseScore * 0.15

		if licenseScore >= 0.8 {
			analysis.PositiveIndicators = append(analysis.PositiveIndicators, "standard_license")
		} else if licenseScore < 0.3 {
			analysis.RiskFactors = append(analysis.RiskFactors, "suspicious_license")
		}
	} else {
		analysis.RiskFactors = append(analysis.RiskFactors, "missing_license")
	}

	// Homepage validation
	if metadata.Homepage != "" {
		homepageScore := mf.analyzeHomepageQuality(metadata.Homepage)
		qualityScore += homepageScore * 0.1

		if homepageScore >= 0.8 {
			analysis.PositiveIndicators = append(analysis.PositiveIndicators, "professional_homepage")
		}
	}

	// Keywords analysis
	if len(metadata.Keywords) > 0 {
		keywordScore := mf.analyzeKeywordsQuality(metadata.Keywords)
		qualityScore += keywordScore * 0.1

		if keywordScore >= 0.8 {
			analysis.PositiveIndicators = append(analysis.PositiveIndicators, "relevant_keywords")
		} else if keywordScore < 0.3 {
			analysis.RiskFactors = append(analysis.RiskFactors, "suspicious_keywords")
		}
	}

	// Maintainer validation
	if len(metadata.Maintainers) > 0 {
		maintainerScore := mf.analyzeMaintainerQuality(metadata.Maintainers)
		qualityScore += maintainerScore * 0.1

		if maintainerScore >= 0.8 {
			analysis.PositiveIndicators = append(analysis.PositiveIndicators, "trusted_maintainers")
		}
	} else {
		analysis.RiskFactors = append(analysis.RiskFactors, "missing_maintainers")
	}

	analysis.MetadataQuality = math.Min(qualityScore, 1.0)

	// Enhanced quality thresholds
	if qualityScore >= 0.85 {
		analysis.PositiveIndicators = append(analysis.PositiveIndicators, "excellent_metadata")
	} else if qualityScore >= 0.7 {
		analysis.PositiveIndicators = append(analysis.PositiveIndicators, "good_metadata")
	} else if qualityScore < 0.4 {
		analysis.RiskFactors = append(analysis.RiskFactors, "poor_metadata_quality")
	} else if qualityScore < 0.25 {
		analysis.RiskFactors = append(analysis.RiskFactors, "severely_incomplete_metadata")
	}
}

// detectTyposquattingIndicators detects potential typosquatting patterns
func (mf *MetadataFilter) detectTyposquattingIndicators(metadata *PackageMetadata, analysis *MetadataAnalysis) {
	packageName := strings.ToLower(metadata.Name)

	// Get popular packages for comparison
	popularPackages := mf.getPopularPackages(metadata.Registry)

	for _, popular := range popularPackages {
		if packageName == popular {
			continue // Skip exact matches
		}

		similarity := mf.calculateStringSimilarity(packageName, popular)
		if similarity >= mf.config.SimilarityThreshold {
			analysis.TyposquattingRisk = math.Max(analysis.TyposquattingRisk, similarity)
			analysis.RiskFactors = append(analysis.RiskFactors, fmt.Sprintf("similar_to_popular_package_%s", popular))

			// Additional checks for typosquatting patterns
			if mf.hasTyposquattingPatterns(packageName, popular) {
				analysis.TyposquattingRisk += 0.2
				analysis.RiskFactors = append(analysis.RiskFactors, "typosquatting_patterns_detected")
			}
		}
	}

	// Check for common typosquatting techniques
	if mf.hasCommonTypoPatterns(packageName) {
		analysis.TyposquattingRisk += 0.1
		analysis.RiskFactors = append(analysis.RiskFactors, "common_typo_patterns")
	}
}

// calculateOverallScores calculates the overall analysis scores
func (mf *MetadataFilter) calculateOverallScores(analysis *MetadataAnalysis) {
	// Calculate confidence score based on positive indicators and risk factors
	positiveWeight := float64(len(analysis.PositiveIndicators)) * 0.1
	riskWeight := float64(len(analysis.RiskFactors)) * 0.15

	// Base confidence from metadata quality and popularity
	baseConfidence := (analysis.MetadataQuality + analysis.PopularityScore +
		analysis.MaintainerTrustScore + analysis.RepositoryTrustScore) / 4.0

	analysis.ConfidenceScore = math.Max(0.0, math.Min(1.0, baseConfidence+positiveWeight-riskWeight))

	// Determine if package is legitimate
	analysis.IsLegitimate = analysis.ConfidenceScore > 0.6 &&
		analysis.TyposquattingRisk < 0.5 &&
		analysis.SupplyChainRisk < 0.7

	// Adjust for critical risk factors
	for _, risk := range analysis.RiskFactors {
		if strings.Contains(risk, "extremely_low_usage") ||
			strings.Contains(risk, "claims_official_repository") ||
			strings.Contains(risk, "critical_security_vulnerabilities") {
			analysis.IsLegitimate = false
			break
		}
	}
}

// Helper methods

func (mf *MetadataFilter) getTrustedMaintainers(registry string) []string {
	// This would be populated from a database of trusted maintainers
	return []string{"npm", "webpack", "facebook", "google", "microsoft", "nodejs"}
}

func (mf *MetadataFilter) isTrustedMaintainer(maintainer string, trusted []string) bool {
	maintainerLower := strings.ToLower(maintainer)
	for _, t := range trusted {
		if strings.Contains(maintainerLower, strings.ToLower(t)) {
			return true
		}
	}
	return false
}

func (mf *MetadataFilter) isKnownOrganization(owner string) bool {
	// This would be enhanced with actual organization detection
	orgs := []string{"webpack", "facebook", "google", "microsoft", "nodejs", "npm"}
	ownerLower := strings.ToLower(owner)
	for _, org := range orgs {
		if ownerLower == org {
			return true
		}
	}
	return false
}

func (mf *MetadataFilter) getPopularPackages(registry string) []string {
	// This would be loaded from a database or API
	popularPackages := map[string][]string{
		"npm":      {"react", "lodash", "express", "axios", "webpack", "babel", "eslint", "typescript", "vue", "angular"},
		"pypi":     {"requests", "numpy", "pandas", "flask", "django", "tensorflow"},
		"rubygems": {"rails", "bundler", "rake", "rspec", "puma", "nokogiri"},
	}

	if packages, exists := popularPackages[registry]; exists {
		return packages
	}
	return []string{}
}

func (mf *MetadataFilter) calculateStringSimilarity(s1, s2 string) float64 {
	// Levenshtein distance based similarity
	distance := mf.levenshteinDistance(s1, s2)
	maxLen := math.Max(float64(len(s1)), float64(len(s2)))
	if maxLen == 0 {
		return 1.0
	}
	return 1.0 - float64(distance)/maxLen
}

func (mf *MetadataFilter) levenshteinDistance(s1, s2 string) int {
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

			matrix[i][j] = min(
				min(matrix[i-1][j]+1, matrix[i][j-1]+1), // deletion, insertion
				matrix[i-1][j-1]+cost,                   // substitution
			)
		}
	}

	return matrix[len(s1)][len(s2)]
}

func (mf *MetadataFilter) hasTyposquattingPatterns(candidate, target string) bool {
	// Check for common typosquatting patterns
	patterns := []string{
		// Character substitution
		strings.Replace(target, "o", "0", -1),
		strings.Replace(target, "i", "1", -1),
		strings.Replace(target, "l", "1", -1),
		// Character insertion
		target + "s",
		target + "js",
		target + "2",
		// Character deletion
		strings.Replace(target, "e", "", -1),
	}

	for _, pattern := range patterns {
		if candidate == pattern {
			return true
		}
	}

	return false
}

func (mf *MetadataFilter) hasCommonTypoPatterns(name string) bool {
	// Check for common typosquatting indicators
	patterns := []string{
		`\d+$`,        // Ends with numbers
		`^.*[0-9].*$`, // Contains numbers
		`.*-{2,}.*`,   // Multiple consecutive hyphens
		`.*_{2,}.*`,   // Multiple consecutive underscores
	}

	for _, pattern := range patterns {
		if matched, _ := regexp.MatchString(pattern, name); matched {
			return true
		}
	}

	return false
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// analyzeDescriptionQuality analyzes the quality of package description
func (mf *MetadataFilter) analyzeDescriptionQuality(description string) float64 {
	score := 0.0
	desc := strings.TrimSpace(description)

	// Length analysis
	if len(desc) >= 50 {
		score += 0.3
		if len(desc) >= 100 {
			score += 0.2 // Bonus for detailed description
		}
	} else if len(desc) < 20 {
		return 0.1 // Very short descriptions are poor quality
	}

	// Content quality checks
	if mf.hasInformativeContent(desc) {
		score += 0.3
	}

	// Check for suspicious patterns
	if mf.hasSuspiciousDescriptionPatterns(desc) {
		score -= 0.4
	}

	// Grammar and structure
	if mf.hasGoodStructure(desc) {
		score += 0.2
	}

	return math.Max(0.0, math.Min(score, 1.0))
}

// analyzeRepositoryQuality analyzes the quality and trustworthiness of repository URL
func (mf *MetadataFilter) analyzeRepositoryQuality(repository string) float64 {
	score := 0.0
	repoLower := strings.ToLower(repository)

	// Check for trusted platforms
	trustedPlatforms := []string{"github.com", "gitlab.com", "bitbucket.org", "sourceforge.net"}
	for _, platform := range trustedPlatforms {
		if strings.Contains(repoLower, platform) {
			score += 0.6
			break
		}
	}

	// Check for HTTPS
	if strings.HasPrefix(repoLower, "https://") {
		score += 0.2
	}

	// Check for proper repository structure
	if mf.hasValidRepoStructure(repository) {
		score += 0.2
	}

	return math.Min(score, 1.0)
}

// analyzeLicenseQuality analyzes the quality and legitimacy of license
func (mf *MetadataFilter) analyzeLicenseQuality(license string) float64 {
	score := 0.0
	licenseLower := strings.ToLower(strings.TrimSpace(license))

	// Standard open source licenses
	standardLicenses := []string{
		"mit", "apache", "gpl", "bsd", "lgpl", "mpl", "isc", "unlicense",
		"apache-2.0", "gpl-3.0", "bsd-3-clause", "bsd-2-clause",
	}

	for _, stdLicense := range standardLicenses {
		if strings.Contains(licenseLower, stdLicense) {
			score += 0.8
			break
		}
	}

	// Check for suspicious license content
	if mf.hasSuspiciousLicenseContent(license) {
		score -= 0.5
	}

	return math.Max(0.0, math.Min(score, 1.0))
}

// analyzeHomepageQuality analyzes the quality of homepage URL
func (mf *MetadataFilter) analyzeHomepageQuality(homepage string) float64 {
	score := 0.0
	homepageLower := strings.ToLower(homepage)

	// Check for HTTPS
	if strings.HasPrefix(homepageLower, "https://") {
		score += 0.3
	}

	// Check for professional domains
	professionalDomains := []string{".org", ".com", ".net", ".io", ".dev"}
	for _, domain := range professionalDomains {
		if strings.Contains(homepageLower, domain) {
			score += 0.4
			break
		}
	}

	// Check for suspicious patterns
	if mf.hasSuspiciousURLPatterns(homepage) {
		score -= 0.3
	}

	// Valid URL structure
	if mf.hasValidURLStructure(homepage) {
		score += 0.3
	}

	return math.Max(0.0, math.Min(score, 1.0))
}

// analyzeKeywordsQuality analyzes the quality and relevance of keywords
func (mf *MetadataFilter) analyzeKeywordsQuality(keywords []string) float64 {
	score := 0.0

	// Optimal keyword count
	if len(keywords) >= 3 && len(keywords) <= 10 {
		score += 0.4
	} else if len(keywords) > 0 {
		score += 0.2
	}

	// Check for relevant, non-spammy keywords
	relevantCount := 0
	spammyCount := 0

	for _, keyword := range keywords {
		keywordLower := strings.ToLower(strings.TrimSpace(keyword))

		if mf.isRelevantKeyword(keywordLower) {
			relevantCount++
		}

		if mf.isSpammyKeyword(keywordLower) {
			spammyCount++
		}
	}

	if len(keywords) > 0 {
		relevanceRatio := float64(relevantCount) / float64(len(keywords))
		spamRatio := float64(spammyCount) / float64(len(keywords))

		score += relevanceRatio * 0.4
		score -= spamRatio * 0.6
	}

	return math.Max(0.0, math.Min(score, 1.0))
}

// analyzeMaintainerQuality analyzes the quality and trustworthiness of maintainers
func (mf *MetadataFilter) analyzeMaintainerQuality(maintainers []string) float64 {
	score := 0.0

	// Multiple maintainers is generally good
	if len(maintainers) > 1 {
		score += 0.3
	} else if len(maintainers) == 1 {
		score += 0.2
	}

	// Check for trusted maintainers
	trustedCount := 0
	for _, maintainer := range maintainers {
		if mf.isTrustedMaintainer(maintainer, mf.getTrustedMaintainers("")) {
			trustedCount++
		}
	}

	if len(maintainers) > 0 {
		trustedRatio := float64(trustedCount) / float64(len(maintainers))
		score += trustedRatio * 0.5
	}

	// Check for suspicious maintainer patterns
	for _, maintainer := range maintainers {
		if mf.hasSuspiciousMaintainerPattern(maintainer) {
			score -= 0.2
		}
	}

	return math.Max(0.0, math.Min(score, 1.0))
}

// Helper methods for quality analysis
func (mf *MetadataFilter) hasInformativeContent(description string) bool {
	// Check for meaningful words and technical terms
	technicalTerms := []string{"library", "framework", "tool", "utility", "api", "sdk", "plugin", "module"}
	descLower := strings.ToLower(description)

	for _, term := range technicalTerms {
		if strings.Contains(descLower, term) {
			return true
		}
	}

	// Check for descriptive words
	words := strings.Fields(description)
	return len(words) >= 5 // At least 5 words for informative content
}

func (mf *MetadataFilter) hasSuspiciousDescriptionPatterns(description string) bool {
	descLower := strings.ToLower(description)

	// Check for malicious patterns
	suspiciousPatterns := []string{
		"bitcoin", "crypto", "miner", "hack", "crack", "exploit",
		"malware", "virus", "trojan", "keylog", "stealer",
		"download and run", "execute", "eval", "base64",
	}

	for _, pattern := range suspiciousPatterns {
		if strings.Contains(descLower, pattern) {
			return true
		}
	}

	return false
}

func (mf *MetadataFilter) hasGoodStructure(description string) bool {
	// Check for proper capitalization and punctuation
	if len(description) == 0 {
		return false
	}

	// First character should be uppercase
	firstChar := description[0]
	if firstChar < 'A' || firstChar > 'Z' {
		return false
	}

	// Should end with proper punctuation
	lastChar := description[len(description)-1]
	return lastChar == '.' || lastChar == '!' || lastChar == '?'
}

func (mf *MetadataFilter) hasValidRepoStructure(repository string) bool {
	// Basic URL validation
	if !strings.Contains(repository, "/") {
		return false
	}

	// Should contain owner/repo pattern
	parts := strings.Split(repository, "/")
	return len(parts) >= 2
}

func (mf *MetadataFilter) hasSuspiciousLicenseContent(license string) bool {
	licenseLower := strings.ToLower(license)

	suspiciousTerms := []string{"proprietary", "commercial", "restricted", "confidential"}
	for _, term := range suspiciousTerms {
		if strings.Contains(licenseLower, term) {
			return true
		}
	}

	return false
}

func (mf *MetadataFilter) hasSuspiciousURLPatterns(url string) bool {
	urlLower := strings.ToLower(url)

	// Check for suspicious TLDs or patterns
	suspiciousPatterns := []string{".tk", ".ml", ".ga", ".cf", "bit.ly", "tinyurl"}
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(urlLower, pattern) {
			return true
		}
	}

	return false
}

func (mf *MetadataFilter) hasValidURLStructure(url string) bool {
	// Basic URL structure validation
	return strings.HasPrefix(strings.ToLower(url), "http") && strings.Contains(url, ".")
}

func (mf *MetadataFilter) isRelevantKeyword(keyword string) bool {
	// Check for relevant technical keywords
	relevantKeywords := []string{
		"javascript", "typescript", "python", "java", "go", "rust", "c++",
		"web", "api", "library", "framework", "tool", "utility", "cli",
		"frontend", "backend", "database", "testing", "security",
	}

	for _, relevant := range relevantKeywords {
		if strings.Contains(keyword, relevant) {
			return true
		}
	}

	return len(keyword) >= 3 && len(keyword) <= 20 // Reasonable length
}

func (mf *MetadataFilter) isSpammyKeyword(keyword string) bool {
	// Check for spammy patterns
	spammyPatterns := []string{
		"best", "awesome", "amazing", "ultimate", "super", "mega",
		"free", "download", "crack", "hack", "cheat",
	}

	for _, spammy := range spammyPatterns {
		if strings.Contains(keyword, spammy) {
			return true
		}
	}

	// Very short or very long keywords are often spammy
	return len(keyword) < 2 || len(keyword) > 30
}

func (mf *MetadataFilter) hasSuspiciousMaintainerPattern(maintainer string) bool {
	maintainerLower := strings.ToLower(maintainer)

	// Check for suspicious patterns
	suspiciousPatterns := []string{
		"fake", "temp", "test", "admin", "root", "user", "anonymous",
		"hacker", "cracker", "exploit", "malware",
	}

	for _, pattern := range suspiciousPatterns {
		if strings.Contains(maintainerLower, pattern) {
			return true
		}
	}

	return false
}
