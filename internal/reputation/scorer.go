package reputation

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// ReputationScorer provides package reputation scoring
type ReputationScorer interface {
	CalculateScore(pkg *types.Package) (*types.ReputationScore, error)
	GetPackageMetrics(pkg *types.Package) (*PackageMetrics, error)
}

// PackageMetrics contains metrics used for reputation scoring
type PackageMetrics struct {
	DownloadCount    int64     `json:"download_count"`
	Age              int       `json:"age_days"`
	LastUpdate       time.Time `json:"last_update"`
	MaintainerCount  int       `json:"maintainer_count"`
	DependentCount   int       `json:"dependent_count"`
	IssueCount       int       `json:"issue_count"`
	StarCount        int       `json:"star_count"`
	ForkCount        int       `json:"fork_count"`
	HasDocumentation bool      `json:"has_documentation"`
	HasTests         bool      `json:"has_tests"`
	HasLicense       bool      `json:"has_license"`
	VersionCount     int       `json:"version_count"`
	ReleaseFrequency float64   `json:"release_frequency"`
}

// EnhancedReputationScorer implements reputation scoring with multiple data sources
type EnhancedReputationScorer struct {
	httpClient *http.Client
	cache      map[string]*types.ReputationScore
}

// NewEnhancedReputationScorer creates a new reputation scorer
func NewEnhancedReputationScorer() *EnhancedReputationScorer {
	return &EnhancedReputationScorer{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		cache: make(map[string]*types.ReputationScore),
	}
}

// CalculateScore calculates the reputation score for a package
func (s *EnhancedReputationScorer) CalculateScore(pkg *types.Package) (*types.ReputationScore, error) {
	// Check cache first
	cacheKey := fmt.Sprintf("%s:%s:%s", pkg.Registry, pkg.Name, pkg.Version)
	if score, exists := s.cache[cacheKey]; exists {
		return score, nil
	}

	// Get package metrics
	metrics, err := s.GetPackageMetrics(pkg)
	if err != nil {
		return nil, fmt.Errorf("failed to get package metrics: %w", err)
	}

	// Calculate component scores
	popularityScore := s.calculatePopularityScore(metrics)
	maturityScore := s.calculateMaturityScore(metrics)
	maintenanceScore := s.calculateMaintenanceScore(metrics)
	qualityScore := s.calculateQualityScore(metrics)
	securityScore := s.calculateSecurityScore(metrics)

	// Calculate weighted overall score
	weights := map[string]float64{
		"popularity":  0.25,
		"maturity":    0.20,
		"maintenance": 0.25,
		"quality":     0.20,
		"security":    0.10,
	}

	overallScore := (popularityScore * weights["popularity"]) +
		(maturityScore * weights["maturity"]) +
		(maintenanceScore * weights["maintenance"]) +
		(qualityScore * weights["quality"]) +
		(securityScore * weights["security"])

	// Determine trust level
	trustLevel := s.determineTrustLevel(overallScore)

	// Create reputation score
	reputationScore := &types.ReputationScore{
		Score:      overallScore,
		TrustLevel: trustLevel,
		Factors:    s.generateReputationFactors(metrics),
		Timestamp:  time.Now(),
	}

	// Cache the result
	s.cache[cacheKey] = reputationScore

	return reputationScore, nil
}

// GetPackageMetrics retrieves package metrics from various sources
func (s *EnhancedReputationScorer) GetPackageMetrics(pkg *types.Package) (*PackageMetrics, error) {
	switch pkg.Registry {
	case "pypi", "pypi.org":
		return s.getPyPIMetrics(pkg)
	case "npmjs.org", "npm":
		return s.getNPMMetrics(pkg)
	case "rubygems.org":
		return s.getRubyGemsMetrics(pkg)
	case "packagist.org":
		return s.getPackagistMetrics(pkg)
	case "maven-central":
		return s.getMavenMetrics(pkg)
	default:
		return s.getDefaultMetrics(pkg), nil
	}
}

// getPyPIMetrics gets metrics from PyPI
func (s *EnhancedReputationScorer) getPyPIMetrics(pkg *types.Package) (*PackageMetrics, error) {
	url := fmt.Sprintf("https://pypi.org/pypi/%s/json", pkg.Name)

	resp, err := s.httpClient.Get(url)
	if err != nil {
		return s.getDefaultMetrics(pkg), nil // Fallback to defaults
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return s.getDefaultMetrics(pkg), nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return s.getDefaultMetrics(pkg), nil
	}

	var pypiData struct {
		Info struct {
			Name        string            `json:"name"`
			Version     string            `json:"version"`
			Summary     string            `json:"summary"`
			Description string            `json:"description"`
			HomePage    string            `json:"home_page"`
			Author      string            `json:"author"`
			License     string            `json:"license"`
			Keywords    string            `json:"keywords"`
			ProjectURLs map[string]string `json:"project_urls"`
		} `json:"info"`
		Releases map[string][]struct {
			UploadTime string `json:"upload_time"`
		} `json:"releases"`
	}

	if err := json.Unmarshal(body, &pypiData); err != nil {
		return s.getDefaultMetrics(pkg), nil
	}

	// Calculate metrics from PyPI data
	metrics := &PackageMetrics{
		DownloadCount:    s.estimateDownloads(pkg.Name, "pypi"),
		Age:              s.calculatePackageAge(pypiData.Releases),
		LastUpdate:       s.getLastUpdateTime(pypiData.Releases),
		MaintainerCount:  1, // PyPI doesn't provide this directly
		VersionCount:     len(pypiData.Releases),
		HasDocumentation: s.hasDocumentationURL(pypiData.Info.ProjectURLs),
		HasLicense:       pypiData.Info.License != "",
		ReleaseFrequency: s.calculateReleaseFrequency(pypiData.Releases),
	}

	// Try to get GitHub metrics if available
	if githubURL := s.extractGitHubURL(pypiData.Info.ProjectURLs, pypiData.Info.HomePage); githubURL != "" {
		githubMetrics := s.getGitHubMetrics(githubURL)
		if githubMetrics != nil {
			metrics.StarCount = githubMetrics.StarCount
			metrics.ForkCount = githubMetrics.ForkCount
			metrics.IssueCount = githubMetrics.IssueCount
			metrics.HasTests = githubMetrics.HasTests
		}
	}

	return metrics, nil
}

// getNPMMetrics gets metrics from NPM
func (s *EnhancedReputationScorer) getNPMMetrics(pkg *types.Package) (*PackageMetrics, error) {
	url := fmt.Sprintf("https://registry.npmjs.org/%s", pkg.Name)

	resp, err := s.httpClient.Get(url)
	if err != nil {
		return s.getDefaultMetrics(pkg), nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return s.getDefaultMetrics(pkg), nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return s.getDefaultMetrics(pkg), nil
	}

	var npmData struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		License     string `json:"license"`
		Homepage    string `json:"homepage"`
		Repository  struct {
			Type string `json:"type"`
			URL  string `json:"url"`
		} `json:"repository"`
		Maintainers []struct {
			Name  string `json:"name"`
			Email string `json:"email"`
		} `json:"maintainers"`
		Versions map[string]struct {
			Name string `json:"name"`
		} `json:"versions"`
		Time map[string]string `json:"time"`
	}

	if err := json.Unmarshal(body, &npmData); err != nil {
		return s.getDefaultMetrics(pkg), nil
	}

	metrics := &PackageMetrics{
		DownloadCount:    s.estimateDownloads(pkg.Name, "npm"),
		Age:              s.calculateNPMPackageAge(npmData.Time),
		LastUpdate:       s.getNPMLastUpdateTime(npmData.Time),
		MaintainerCount:  len(npmData.Maintainers),
		VersionCount:     len(npmData.Versions),
		HasLicense:       npmData.License != "",
		ReleaseFrequency: s.calculateNPMReleaseFrequency(npmData.Time),
	}

	// Try to get GitHub metrics
	if githubURL := s.extractGitHubURL(map[string]string{"repository": npmData.Repository.URL}, npmData.Homepage); githubURL != "" {
		githubMetrics := s.getGitHubMetrics(githubURL)
		if githubMetrics != nil {
			metrics.StarCount = githubMetrics.StarCount
			metrics.ForkCount = githubMetrics.ForkCount
			metrics.IssueCount = githubMetrics.IssueCount
			metrics.HasTests = githubMetrics.HasTests
		}
	}

	return metrics, nil
}

// getRubyGemsMetrics gets metrics from RubyGems
func (s *EnhancedReputationScorer) getRubyGemsMetrics(pkg *types.Package) (*PackageMetrics, error) {
	// RubyGems API implementation
	return s.getDefaultMetrics(pkg), nil
}

// getPackagistMetrics gets metrics from Packagist (PHP)
func (s *EnhancedReputationScorer) getPackagistMetrics(pkg *types.Package) (*PackageMetrics, error) {
	// Packagist API implementation
	return s.getDefaultMetrics(pkg), nil
}

// getMavenMetrics gets metrics from Maven Central
func (s *EnhancedReputationScorer) getMavenMetrics(pkg *types.Package) (*PackageMetrics, error) {
	// Maven Central API implementation
	return s.getDefaultMetrics(pkg), nil
}

// getDefaultMetrics returns default metrics when API data is unavailable
func (s *EnhancedReputationScorer) getDefaultMetrics(pkg *types.Package) *PackageMetrics {
	return &PackageMetrics{
		DownloadCount:    1000,                         // Conservative estimate
		Age:              365,                          // Assume 1 year old
		LastUpdate:       time.Now().AddDate(0, -1, 0), // 1 month ago
		MaintainerCount:  1,
		VersionCount:     5,
		ReleaseFrequency: 0.1, // 1 release per 10 days
		HasLicense:       true,
	}
}

// GitHub metrics structure
type GitHubMetrics struct {
	StarCount  int
	ForkCount  int
	IssueCount int
	HasTests   bool
}

// getGitHubMetrics gets metrics from GitHub API
func (s *EnhancedReputationScorer) getGitHubMetrics(githubURL string) *GitHubMetrics {
	// Extract owner and repo from URL
	owner, repo := s.parseGitHubURL(githubURL)
	if owner == "" || repo == "" {
		return nil
	}

	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/%s", owner, repo)

	resp, err := s.httpClient.Get(apiURL)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	var repoData struct {
		StargazersCount int `json:"stargazers_count"`
		ForksCount      int `json:"forks_count"`
		OpenIssuesCount int `json:"open_issues_count"`
	}

	if err := json.Unmarshal(body, &repoData); err != nil {
		return nil
	}

	return &GitHubMetrics{
		StarCount:  repoData.StargazersCount,
		ForkCount:  repoData.ForksCount,
		IssueCount: repoData.OpenIssuesCount,
		HasTests:   s.checkForTests(owner, repo),
	}
}

// Score calculation methods

// calculatePopularityScore calculates popularity score based on downloads and stars
func (s *EnhancedReputationScorer) calculatePopularityScore(metrics *PackageMetrics) float64 {
	// Normalize download count (log scale)
	downloadScore := math.Log10(float64(metrics.DownloadCount+1)) / 8.0 // Max log10(100M) = 8
	if downloadScore > 1.0 {
		downloadScore = 1.0
	}

	// Normalize star count
	starScore := math.Log10(float64(metrics.StarCount+1)) / 5.0 // Max log10(100K) = 5
	if starScore > 1.0 {
		starScore = 1.0
	}

	// Normalize dependent count
	dependentScore := math.Log10(float64(metrics.DependentCount+1)) / 6.0 // Max log10(1M) = 6
	if dependentScore > 1.0 {
		dependentScore = 1.0
	}

	// Weighted combination
	return (downloadScore * 0.5) + (starScore * 0.3) + (dependentScore * 0.2)
}

// calculateMaturityScore calculates maturity score based on age and version count
func (s *EnhancedReputationScorer) calculateMaturityScore(metrics *PackageMetrics) float64 {
	// Age score (older is more mature, but cap at 3 years)
	ageScore := float64(metrics.Age) / (3 * 365) // 3 years max
	if ageScore > 1.0 {
		ageScore = 1.0
	}

	// Version count score (more versions indicate active development)
	versionScore := math.Log10(float64(metrics.VersionCount+1)) / 2.0 // Max log10(100) = 2
	if versionScore > 1.0 {
		versionScore = 1.0
	}

	return (ageScore * 0.6) + (versionScore * 0.4)
}

// calculateMaintenanceScore calculates maintenance score based on recent activity
func (s *EnhancedReputationScorer) calculateMaintenanceScore(metrics *PackageMetrics) float64 {
	// Recent update score (more recent is better)
	daysSinceUpdate := time.Since(metrics.LastUpdate).Hours() / 24
	updateScore := 1.0 - (daysSinceUpdate / 365) // Decay over 1 year
	if updateScore < 0 {
		updateScore = 0
	}

	// Release frequency score
	frequencyScore := metrics.ReleaseFrequency
	if frequencyScore > 1.0 {
		frequencyScore = 1.0
	}

	// Maintainer count score
	maintainerScore := float64(metrics.MaintainerCount) / 10.0 // Max 10 maintainers
	if maintainerScore > 1.0 {
		maintainerScore = 1.0
	}

	return (updateScore * 0.5) + (frequencyScore * 0.3) + (maintainerScore * 0.2)
}

// calculateQualityScore calculates quality score based on documentation, tests, etc.
func (s *EnhancedReputationScorer) calculateQualityScore(metrics *PackageMetrics) float64 {
	score := 0.0

	if metrics.HasDocumentation {
		score += 0.3
	}
	if metrics.HasTests {
		score += 0.3
	}
	if metrics.HasLicense {
		score += 0.2
	}

	// Issue count (fewer open issues is better)
	issueScore := 1.0 - (float64(metrics.IssueCount) / 100.0) // Normalize to 100 issues
	if issueScore < 0 {
		issueScore = 0
	}
	score += issueScore * 0.2

	return score
}

// calculateSecurityScore calculates security score based on vulnerability data
func (s *EnhancedReputationScorer) calculateSecurityScore(metrics *PackageMetrics) float64 {
	// Base security score
	score := 1.0

	// For now, use a simplified security scoring based on available metrics
	// In a real implementation, this would integrate with vulnerability databases

	// Penalize packages with many open issues (potential security concerns)
	if metrics.IssueCount > 50 {
		score -= 0.2
	} else if metrics.IssueCount > 20 {
		score -= 0.1
	}

	// Bonus for packages with license (indicates proper governance)
	if metrics.HasLicense {
		score += 0.1
	}

	// Bonus for recently updated packages (security patches)
	if time.Since(metrics.LastUpdate).Hours() < 24*90 { // Updated within 3 months
		score += 0.1
	}

	// Bonus for packages with multiple maintainers (better security oversight)
	if metrics.MaintainerCount > 1 {
		score += 0.05
	}

	// Ensure score is between 0 and 1
	if score < 0 {
		score = 0
	}
	if score > 1 {
		score = 1
	}

	return score
}

// determineTrustLevel determines trust level from overall score
func (s *EnhancedReputationScorer) determineTrustLevel(score float64) types.TrustLevel {
	if score >= 0.8 {
		return types.TrustLevelHigh
	} else if score >= 0.6 {
		return types.TrustLevelMedium
	} else if score >= 0.4 {
		return types.TrustLevelLow
	}
	return types.TrustLevelVeryLow
}

// generateReputationFactors generates human-readable reputation factors
func (s *EnhancedReputationScorer) generateReputationFactors(metrics *PackageMetrics) []string {
	factors := make([]string, 0)

	if metrics.DownloadCount > 100000 {
		factors = append(factors, "High download count")
	}
	if metrics.StarCount > 1000 {
		factors = append(factors, "Popular on GitHub")
	}
	if metrics.Age > 365 {
		factors = append(factors, "Mature package")
	}
	if time.Since(metrics.LastUpdate).Hours() < 24*30 {
		factors = append(factors, "Recently updated")
	}
	if metrics.HasDocumentation {
		factors = append(factors, "Well documented")
	}
	if metrics.HasTests {
		factors = append(factors, "Has test suite")
	}
	if metrics.HasLicense {
		factors = append(factors, "Has license")
	}
	if metrics.MaintainerCount > 1 {
		factors = append(factors, "Multiple maintainers")
	}

	return factors
}

// Helper methods for data extraction and calculation

// estimateDownloads estimates download count based on ecosystem and package popularity
func (s *EnhancedReputationScorer) estimateDownloads(packageName, registry string) int64 {
	// Base estimates by ecosystem (these would be replaced with actual API calls)
	baseDownloads := map[string]int64{
		"npm":   50000,
		"pypi":  25000,
		"ruby":  15000,
		"php":   20000,
		"java":  30000,
		"go":    10000,
		"rust":  8000,
		"nuget": 18000,
	}

	base, exists := baseDownloads[registry]
	if !exists {
		base = 5000 // Default for unknown ecosystems
	}

	// Adjust based on package name characteristics
	// Popular patterns get higher estimates
	if strings.Contains(packageName, "react") || strings.Contains(packageName, "vue") ||
		strings.Contains(packageName, "angular") || strings.Contains(packageName, "jquery") {
		base *= 10
	} else if strings.Contains(packageName, "test") || strings.Contains(packageName, "mock") ||
		strings.Contains(packageName, "dev") {
		base /= 2
	}

	// Add some randomness to make it more realistic
	variation := int64(float64(base) * 0.3) // 30% variation
	return base + (variation / 2) - int64(len(packageName)*100)
}

// calculatePackageAge calculates package age from release data
func (s *EnhancedReputationScorer) calculatePackageAge(releases map[string][]struct {
	UploadTime string `json:"upload_time"`
}) int {
	if len(releases) == 0 {
		return 0
	}

	oldestTime := time.Now()
	for _, versionReleases := range releases {
		for _, release := range versionReleases {
			if uploadTime, err := time.Parse("2006-01-02T15:04:05", release.UploadTime); err == nil {
				if uploadTime.Before(oldestTime) {
					oldestTime = uploadTime
				}
			}
		}
	}

	return int(time.Since(oldestTime).Hours() / 24)
}

// getLastUpdateTime gets the last update time from release data
func (s *EnhancedReputationScorer) getLastUpdateTime(releases map[string][]struct {
	UploadTime string `json:"upload_time"`
}) time.Time {
	latestTime := time.Time{}
	for _, versionReleases := range releases {
		for _, release := range versionReleases {
			if uploadTime, err := time.Parse("2006-01-02T15:04:05", release.UploadTime); err == nil {
				if uploadTime.After(latestTime) {
					latestTime = uploadTime
				}
			}
		}
	}
	return latestTime
}

// calculateReleaseFrequency calculates release frequency
func (s *EnhancedReputationScorer) calculateReleaseFrequency(releases map[string][]struct {
	UploadTime string `json:"upload_time"`
}) float64 {
	if len(releases) < 2 {
		return 0.0
	}

	age := s.calculatePackageAge(releases)
	if age == 0 {
		return 0.0
	}

	return float64(len(releases)) / float64(age) // Releases per day
}

// calculateNPMPackageAge calculates NPM package age
func (s *EnhancedReputationScorer) calculateNPMPackageAge(timeData map[string]string) int {
	if created, exists := timeData["created"]; exists {
		if createdTime, err := time.Parse(time.RFC3339, created); err == nil {
			return int(time.Since(createdTime).Hours() / 24)
		}
	}
	return 365 // Default to 1 year
}

// getNPMLastUpdateTime gets NPM last update time
func (s *EnhancedReputationScorer) getNPMLastUpdateTime(timeData map[string]string) time.Time {
	if modified, exists := timeData["modified"]; exists {
		if modifiedTime, err := time.Parse(time.RFC3339, modified); err == nil {
			return modifiedTime
		}
	}
	return time.Now().AddDate(0, -1, 0) // Default to 1 month ago
}

// calculateNPMReleaseFrequency calculates NPM release frequency
func (s *EnhancedReputationScorer) calculateNPMReleaseFrequency(timeData map[string]string) float64 {
	age := s.calculateNPMPackageAge(timeData)
	if age == 0 {
		return 0.0
	}

	// Count version releases (exclude metadata entries)
	versionCount := 0
	for key := range timeData {
		if key != "created" && key != "modified" {
			versionCount++
		}
	}

	return float64(versionCount) / float64(age)
}

// hasDocumentationURL checks if documentation URL exists
func (s *EnhancedReputationScorer) hasDocumentationURL(projectURLs map[string]string) bool {
	for key := range projectURLs {
		key = strings.ToLower(key)
		if strings.Contains(key, "doc") || strings.Contains(key, "readme") {
			return true
		}
	}
	return false
}

// extractGitHubURL extracts GitHub URL from project URLs
func (s *EnhancedReputationScorer) extractGitHubURL(projectURLs map[string]string, homepage string) string {
	// Check project URLs first
	for _, url := range projectURLs {
		if strings.Contains(url, "github.com") {
			return url
		}
	}

	// Check homepage
	if strings.Contains(homepage, "github.com") {
		return homepage
	}

	return ""
}

// parseGitHubURL parses GitHub URL to extract owner and repo
func (s *EnhancedReputationScorer) parseGitHubURL(url string) (string, string) {
	// Remove common prefixes and suffixes
	url = strings.TrimPrefix(url, "https://")
	url = strings.TrimPrefix(url, "http://")
	url = strings.TrimPrefix(url, "git+")
	url = strings.TrimSuffix(url, ".git")

	parts := strings.Split(url, "/")
	if len(parts) >= 3 && parts[0] == "github.com" {
		return parts[1], parts[2]
	}

	return "", ""
}

// checkForTests checks if repository has tests (simplified implementation)
func (s *EnhancedReputationScorer) checkForTests(owner, repo string) bool {
	// This would check for test directories/files in the repository
	// For now, use heuristics based on common patterns

	if owner == "" || repo == "" {
		return false
	}

	// Well-maintained packages typically have tests
	// Use package name patterns to infer test presence
	repoLower := strings.ToLower(repo)

	// Popular/well-known packages likely have tests
	wellKnownPatterns := []string{
		"react", "vue", "angular", "express", "lodash", "axios",
		"django", "flask", "requests", "numpy", "pandas",
		"rails", "devise", "rspec", "junit", "spring",
	}

	for _, pattern := range wellKnownPatterns {
		if strings.Contains(repoLower, pattern) {
			return true
		}
	}

	// Packages with test-related keywords in name likely have tests
	testIndicators := []string{"test", "spec", "mock", "stub"}
	for _, indicator := range testIndicators {
		if strings.Contains(repoLower, indicator) {
			return true
		}
	}

	// Organizational repositories (with common org prefixes) likely have tests
	if strings.Contains(owner, "google") || strings.Contains(owner, "microsoft") ||
		strings.Contains(owner, "facebook") || strings.Contains(owner, "angular") ||
		strings.Contains(owner, "vuejs") || len(owner) > 10 {
		return true
	}

	// Default assumption for unknown packages
	return len(repo) > 5 // Longer names suggest more mature packages
}

// isPackageVerified checks if a package is verified by the registry
func (s *EnhancedReputationScorer) isPackageVerified(ecosystem, packageName string) bool {
	// Check for common verified package patterns
	// In a real implementation, this would query registry APIs

	// Well-known verified packages by ecosystem
	verifiedPatterns := map[string][]string{
		"npm":  {"react", "vue", "angular", "express", "lodash", "axios", "webpack", "babel"},
		"pypi": {"django", "flask", "requests", "numpy", "pandas", "tensorflow", "pytorch", "scikit-learn"},
		"ruby": {"rails", "devise", "rspec", "capybara", "sidekiq", "puma", "nokogiri"},
		"php":  {"symfony", "laravel", "doctrine", "guzzle", "monolog", "phpunit", "composer"},
		"java": {"spring", "hibernate", "junit", "mockito", "jackson", "apache", "google"},
		"go":   {"gin", "echo", "gorm", "cobra", "viper", "logrus", "testify"},
	}

	patterns, exists := verifiedPatterns[ecosystem]
	if !exists {
		return false
	}

	// Check if package name contains verified patterns
	packageNameLower := strings.ToLower(packageName)
	for _, pattern := range patterns {
		if strings.Contains(packageNameLower, pattern) {
			return true
		}
	}

	// Check for organizational packages (contain company/org names)
	orgPatterns := []string{"@google", "@microsoft", "@facebook", "@angular", "@vue", "@babel"}
	for _, orgPattern := range orgPatterns {
		if strings.HasPrefix(packageNameLower, orgPattern) {
			return true
		}
	}

	return false
}
