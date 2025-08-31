package reputation

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// analyzeThreatIntelligence performs threat intelligence analysis
func (ers *EnhancedReputationSystem) analyzeThreatIntelligence(ctx context.Context, pkg *types.Package) ([]ThreatIntelResult, error) {
	var results []ThreatIntelResult

	// Query threat intelligence manager for package threats
	correlationResult, err := ers.threatIntelManager.CorrelateThreats(ctx, pkg)
	if err != nil {
		return results, fmt.Errorf("failed to correlate package with threat intelligence: %w", err)
	}

	// Convert correlation results to ThreatIntelResult format
	for _, match := range correlationResult.Matches {
		result := ThreatIntelResult{
			Source:      match.Source,
			ThreatType:  match.ThreatType,
			Severity:    match.Severity,
			Confidence:  match.MatchConfidence,
			Description: match.Description,
			FirstSeen:   match.FirstSeen,
			LastSeen:    time.Now(),
			Metadata: map[string]interface{}{
				"threat_id":  match.ThreatID,
				"match_type": match.MatchType,
			},
		}
		results = append(results, result)
	}

	// Query additional threat intelligence sources
	for _, source := range ers.config.ThreatIntelSources {
		if !source.Enabled {
			continue
		}

		sourceResults, err := ers.queryThreatIntelSource(ctx, pkg, source)
		if err != nil {
			ers.logger.Warn("Failed to query threat intel source", map[string]interface{}{
				"source": source.Name,
				"error":  err.Error(),
			})
			continue
		}

		results = append(results, sourceResults...)
	}

	return results, nil
}

// queryThreatIntelSource queries a specific threat intelligence source
func (ers *EnhancedReputationSystem) queryThreatIntelSource(ctx context.Context, pkg *types.Package, source ThreatIntelSource) ([]ThreatIntelResult, error) {
	var results []ThreatIntelResult

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: source.Timeout,
	}

	// Build query URL
	queryURL := fmt.Sprintf("%s?package=%s&ecosystem=%s", source.URL, pkg.Name, pkg.Registry)

	req, err := http.NewRequestWithContext(ctx, "GET", queryURL, nil)
	if err != nil {
		return results, fmt.Errorf("failed to create request: %w", err)
	}

	// Add headers
	for key, value := range source.Headers {
		req.Header.Set(key, value)
	}

	if source.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+source.APIKey)
	}

	resp, err := client.Do(req)
	if err != nil {
		return results, fmt.Errorf("failed to query source: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return results, fmt.Errorf("source returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return results, fmt.Errorf("failed to read response: %w", err)
	}

	// Parse response based on source type
	switch source.Type {
	case "osv":
		return ers.parseOSVResponse(body, source)
	case "nvd":
		return ers.parseNVDResponse(body, source)
	case "malware_db":
		return ers.parseMalwareDBResponse(body, source)
	default:
		return ers.parseGenericResponse(body, source)
	}
}

// parseOSVResponse parses OSV database response
func (ers *EnhancedReputationSystem) parseOSVResponse(body []byte, source ThreatIntelSource) ([]ThreatIntelResult, error) {
	var results []ThreatIntelResult

	var osvResponse struct {
		Vulns []struct {
			ID       string `json:"id"`
			Summary  string `json:"summary"`
			Details  string `json:"details"`
			Severity []struct {
				Type  string `json:"type"`
				Score string `json:"score"`
			} `json:"severity"`
			References []struct {
				Type string `json:"type"`
				URL  string `json:"url"`
			} `json:"references"`
			Modified string `json:"modified"`
		} `json:"vulns"`
	}

	if err := json.Unmarshal(body, &osvResponse); err != nil {
		return results, fmt.Errorf("failed to parse OSV response: %w", err)
	}

	for _, vuln := range osvResponse.Vulns {
		severity := "medium"
		if len(vuln.Severity) > 0 {
			severity = ers.mapSeverityFromCVSS(vuln.Severity[0].Score)
		}

		references := make([]string, len(vuln.References))
		for i, ref := range vuln.References {
			references[i] = ref.URL
		}

		modified, _ := time.Parse(time.RFC3339, vuln.Modified)

		result := ThreatIntelResult{
			Source:      source.Name,
			ThreatType:  "vulnerability",
			Severity:    severity,
			Confidence:  source.Reliability,
			Description: vuln.Summary,
			References:  references,
			FirstSeen:   modified,
			LastSeen:    time.Now(),
			Metadata: map[string]interface{}{
				"osv_id":  vuln.ID,
				"details": vuln.Details,
			},
		}

		results = append(results, result)
	}

	return results, nil
}

// parseNVDResponse parses NVD database response
func (ers *EnhancedReputationSystem) parseNVDResponse(body []byte, source ThreatIntelSource) ([]ThreatIntelResult, error) {
	var results []ThreatIntelResult

	var nvdResponse struct {
		Result struct {
			CVEItems []struct {
				CVE struct {
					CVEDataMeta struct {
						ID string `json:"ID"`
					} `json:"CVE_data_meta"`
					Description struct {
						DescriptionData []struct {
							Value string `json:"value"`
						} `json:"description_data"`
					} `json:"description"`
				} `json:"cve"`
				Impact struct {
					BaseMetricV3 struct {
						CVSSV3 struct {
							BaseScore float64 `json:"baseScore"`
						} `json:"cvssV3"`
					} `json:"baseMetricV3"`
				} `json:"impact"`
				PublishedDate    string `json:"publishedDate"`
				LastModifiedDate string `json:"lastModifiedDate"`
			} `json:"CVE_Items"`
		} `json:"result"`
	}

	if err := json.Unmarshal(body, &nvdResponse); err != nil {
		return results, fmt.Errorf("failed to parse NVD response: %w", err)
	}

	for _, item := range nvdResponse.Result.CVEItems {
		description := ""
		if len(item.CVE.Description.DescriptionData) > 0 {
			description = item.CVE.Description.DescriptionData[0].Value
		}

		severity := ers.mapSeverityFromCVSS(fmt.Sprintf("%.1f", item.Impact.BaseMetricV3.CVSSV3.BaseScore))
		published, _ := time.Parse(time.RFC3339, item.PublishedDate)

		result := ThreatIntelResult{
			Source:      source.Name,
			ThreatType:  "vulnerability",
			Severity:    severity,
			Confidence:  source.Reliability,
			Description: description,
			FirstSeen:   published,
			LastSeen:    time.Now(),
			Metadata: map[string]interface{}{
				"cve_id":     item.CVE.CVEDataMeta.ID,
				"cvss_score": item.Impact.BaseMetricV3.CVSSV3.BaseScore,
			},
		}

		results = append(results, result)
	}

	return results, nil
}

// parseMalwareDBResponse parses malware database response
func (ers *EnhancedReputationSystem) parseMalwareDBResponse(body []byte, source ThreatIntelSource) ([]ThreatIntelResult, error) {
	var results []ThreatIntelResult

	var malwareResponse struct {
		Threats []struct {
			ID          string   `json:"id"`
			Type        string   `json:"type"`
			Severity    string   `json:"severity"`
			Description string   `json:"description"`
			Indicators  []string `json:"indicators"`
			FirstSeen   string   `json:"first_seen"`
			LastSeen    string   `json:"last_seen"`
		} `json:"threats"`
	}

	if err := json.Unmarshal(body, &malwareResponse); err != nil {
		return results, fmt.Errorf("failed to parse malware DB response: %w", err)
	}

	for _, threat := range malwareResponse.Threats {
		firstSeen, _ := time.Parse(time.RFC3339, threat.FirstSeen)
		lastSeen, _ := time.Parse(time.RFC3339, threat.LastSeen)

		result := ThreatIntelResult{
			Source:      source.Name,
			ThreatType:  threat.Type,
			Severity:    threat.Severity,
			Confidence:  source.Reliability,
			Description: threat.Description,
			Indicators:  threat.Indicators,
			FirstSeen:   firstSeen,
			LastSeen:    lastSeen,
			Metadata: map[string]interface{}{
				"threat_id": threat.ID,
			},
		}

		results = append(results, result)
	}

	return results, nil
}

// parseGenericResponse parses generic threat intelligence response
func (ers *EnhancedReputationSystem) parseGenericResponse(body []byte, source ThreatIntelSource) ([]ThreatIntelResult, error) {
	var results []ThreatIntelResult

	var genericResponse struct {
		Threats []struct {
			Type        string                 `json:"type"`
			Severity    string                 `json:"severity"`
			Confidence  float64                `json:"confidence"`
			Description string                 `json:"description"`
			Metadata    map[string]interface{} `json:"metadata"`
		} `json:"threats"`
	}

	if err := json.Unmarshal(body, &genericResponse); err != nil {
		return results, fmt.Errorf("failed to parse generic response: %w", err)
	}

	for _, threat := range genericResponse.Threats {
		result := ThreatIntelResult{
			Source:      source.Name,
			ThreatType:  threat.Type,
			Severity:    threat.Severity,
			Confidence:  threat.Confidence * source.Reliability,
			Description: threat.Description,
			FirstSeen:   time.Now(),
			LastSeen:    time.Now(),
			Metadata:    threat.Metadata,
		}

		results = append(results, result)
	}

	return results, nil
}

// analyzeMaintainer performs maintainer reputation analysis
func (ers *EnhancedReputationSystem) analyzeMaintainer(pkg *types.Package, metrics *PackageMetrics) MaintainerAnalysisResult {
	result := MaintainerAnalysisResult{
		MaintainerName:     "unknown",
		AccountAge:         0,
		PublishedPackages:  0,
		VerifiedAccount:    false,
		ReputationScore:    0.5,
		SuspiciousPatterns: []string{},
		TrustLevel:         "unknown",
		LastActivity:       time.Now(),
		SocialPresence:     false,
		OrganizationMember: false,
	}

	// Extract maintainer information from package metadata
	if pkg.Metadata != nil && pkg.Metadata.Author != "" {
		result.MaintainerName = pkg.Metadata.Author

		// Check for suspicious patterns
		authorLower := strings.ToLower(pkg.Metadata.Author)
		for _, pattern := range ers.config.MaintainerAnalysis.SuspiciousPatterns {
			if strings.Contains(authorLower, pattern) {
				result.SuspiciousPatterns = append(result.SuspiciousPatterns, pattern)
			}
		}

		// Check against trusted maintainers
		for _, trusted := range ers.config.MaintainerAnalysis.TrustedMaintainers {
			if strings.EqualFold(pkg.Metadata.Author, trusted) {
				result.ReputationScore = 0.9
				result.TrustLevel = "high"
				result.VerifiedAccount = true
				break
			}
		}

		// Check against blacklisted maintainers
		for _, blacklisted := range ers.config.MaintainerAnalysis.BlacklistedMaintainers {
			if strings.EqualFold(pkg.Metadata.Author, blacklisted) {
				result.ReputationScore = 0.1
				result.TrustLevel = "low"
				break
			}
		}
	}

	// Calculate reputation score based on various factors
	if len(result.SuspiciousPatterns) == 0 && result.TrustLevel == "unknown" {
		score := 0.5

		// Account age factor
		if result.AccountAge >= ers.config.MaintainerAnalysis.MinAccountAge {
			score += 0.2
		}

		// Published packages factor
		if result.PublishedPackages >= ers.config.MaintainerAnalysis.MinPublishedPackages {
			score += 0.1
		}

		// Verified account factor
		if result.VerifiedAccount {
			score += 0.1
		}

		// Organization member factor
		if result.OrganizationMember {
			score += 0.1
		}

		result.ReputationScore = score
	}

	// Determine trust level based on score
	if result.TrustLevel == "unknown" {
		if result.ReputationScore >= 0.8 {
			result.TrustLevel = "high"
		} else if result.ReputationScore >= 0.6 {
			result.TrustLevel = "medium"
		} else if result.ReputationScore >= 0.4 {
			result.TrustLevel = "low"
		} else {
			result.TrustLevel = "very_low"
		}
	}

	return result
}

// analyzeCommunity performs community reputation analysis
func (ers *EnhancedReputationSystem) analyzeCommunity(pkg *types.Package, metrics *PackageMetrics) CommunityAnalysisResult {
	result := CommunityAnalysisResult{
		Stars:              metrics.StarCount,
		Forks:              metrics.ForkCount,
		Downloads:          metrics.DownloadCount,
		Issues:             metrics.IssueCount,
		DocumentationScore: 0.5,
		CommunityScore:     0.5,
		ActiveContributors: 1,
		RecentActivity:     false,
		CommunityHealth:    "unknown",
	}

	// Calculate issue ratio
	if metrics.StarCount > 0 {
		result.IssueRatio = float64(metrics.IssueCount) / float64(metrics.StarCount)
	}

	// Check recent activity
	if time.Since(metrics.LastUpdate) < 30*24*time.Hour { // 30 days
		result.RecentActivity = true
	}

	// Calculate community score
	score := 0.0

	// Stars factor
	if metrics.StarCount >= ers.config.CommunityAnalysis.MinStars {
		score += 0.3
	}

	// Forks factor
	if metrics.ForkCount >= ers.config.CommunityAnalysis.MinForks {
		score += 0.2
	}

	// Downloads factor
	if metrics.DownloadCount >= ers.config.CommunityAnalysis.MinDownloads {
		score += 0.2
	}

	// Issue ratio factor
	if result.IssueRatio <= ers.config.CommunityAnalysis.MaxIssueRatio {
		score += 0.1
	}

	// Recent activity factor
	if result.RecentActivity {
		score += 0.1
	}

	// Documentation factor
	if metrics.HasDocumentation {
		score += 0.1
		result.DocumentationScore = 0.8
	}

	result.CommunityScore = score

	// Determine community health
	if score >= 0.8 {
		result.CommunityHealth = "excellent"
	} else if score >= 0.6 {
		result.CommunityHealth = "good"
	} else if score >= 0.4 {
		result.CommunityHealth = "fair"
	} else {
		result.CommunityHealth = "poor"
	}

	return result
}

// analyzeSecurityMetrics performs security-specific analysis
func (ers *EnhancedReputationSystem) analyzeSecurityMetrics(pkg *types.Package, metrics *PackageMetrics) SecurityAnalysisResult {
	result := SecurityAnalysisResult{
		VulnerabilityCount: 0,
		CriticalVulns:      0,
		HighVulns:          0,
		LastSecurityUpdate: time.Now().AddDate(-1, 0, 0), // Default to 1 year ago
		SecurityScore:      0.8,                          // Default good score
		HasSecurityPolicy:  false,
		SignedReleases:     false,
		SecurityAudits:     0,
		ComplianceScore:    0.5,
	}

	// Analyze package for security indicators
	if pkg.Metadata != nil {
		// Check for security policy
		if pkg.Metadata.Description != "" {
			desc := strings.ToLower(pkg.Metadata.Description)
			if strings.Contains(desc, "security") || strings.Contains(desc, "vulnerability") {
				result.HasSecurityPolicy = true
			}
		}

		// Check for signed releases (simplified check)
		if pkg.Metadata.License != "" {
			result.SignedReleases = true // Assume packages with licenses are more likely to be signed
		}
	}

	// Calculate security score based on various factors
	score := 0.8 // Start with good baseline

	// Vulnerability penalty
	if result.VulnerabilityCount > 0 {
		score -= float64(result.CriticalVulns) * 0.3
		score -= float64(result.HighVulns) * 0.1
	}

	// Security policy bonus
	if result.HasSecurityPolicy {
		score += 0.1
	}

	// Signed releases bonus
	if result.SignedReleases {
		score += 0.1
	}

	// Ensure score is within bounds
	if score > 1.0 {
		score = 1.0
	} else if score < 0.0 {
		score = 0.0
	}

	result.SecurityScore = score
	result.ComplianceScore = score * 0.9 // Slightly lower compliance score

	return result
}

// analyzeQualityMetrics performs code quality analysis
func (ers *EnhancedReputationSystem) analyzeQualityMetrics(pkg *types.Package, metrics *PackageMetrics) QualityMetrics {
	result := QualityMetrics{
		TestCoverage:        0.5,
		CodeQualityScore:    0.5,
		DocumentationScore:  0.5,
		LicenseCompliance:   false,
		DependencyHealth:    0.5,
		BuildStatus:         "unknown",
		CIIntegration:       false,
		StaticAnalysisScore: 0.5,
	}

	// Check license compliance
	if metrics.HasLicense {
		result.LicenseCompliance = true
		result.CodeQualityScore += 0.1
	}

	// Check documentation
	if metrics.HasDocumentation {
		result.DocumentationScore = 0.8
		result.CodeQualityScore += 0.1
	}

	// Check tests
	if metrics.HasTests {
		result.TestCoverage = 0.7
		result.CIIntegration = true
		result.CodeQualityScore += 0.2
	}

	// Ensure scores are within bounds
	if result.CodeQualityScore > 1.0 {
		result.CodeQualityScore = 1.0
	}

	return result
}

// calculateThreatIntelScore calculates threat intelligence score
func (ers *EnhancedReputationSystem) calculateThreatIntelScore(results []ThreatIntelResult) float64 {
	if len(results) == 0 {
		return 1.0 // No threats found = good score
	}

	score := 1.0
	for _, result := range results {
		penalty := 0.0
		switch result.Severity {
		case "critical":
			penalty = 0.5
		case "high":
			penalty = 0.3
		case "medium":
			penalty = 0.1
		case "low":
			penalty = 0.05
		}

		// Apply confidence weighting
		penalty *= result.Confidence

		score -= penalty
	}

	if score < 0.0 {
		score = 0.0
	}

	return score
}

// calculateDocumentationScore calculates documentation quality score
func (ers *EnhancedReputationSystem) calculateDocumentationScore(metrics *PackageMetrics) float64 {
	score := 0.0

	if metrics.HasDocumentation {
		score += 0.5
	}

	if metrics.HasLicense {
		score += 0.3
	}

	// Additional documentation indicators could be added here

	if score > 1.0 {
		score = 1.0
	}

	return score
}

// calculateTestingScore calculates testing quality score
func (ers *EnhancedReputationSystem) calculateTestingScore(metrics *PackageMetrics) float64 {
	score := 0.0

	if metrics.HasTests {
		score += 0.7
	}

	// Additional testing indicators could be added here

	if score > 1.0 {
		score = 1.0
	}

	return score
}

// mapSeverityFromCVSS maps CVSS score to severity level
func (ers *EnhancedReputationSystem) mapSeverityFromCVSS(cvssScore string) string {
	// Simple CVSS to severity mapping
	switch {
	case strings.Contains(cvssScore, "9.") || strings.Contains(cvssScore, "10."):
		return "critical"
	case strings.Contains(cvssScore, "7.") || strings.Contains(cvssScore, "8."):
		return "high"
	case strings.Contains(cvssScore, "4.") || strings.Contains(cvssScore, "5.") || strings.Contains(cvssScore, "6."):
		return "medium"
	default:
		return "low"
	}
}

// determineRiskLevel determines risk level based on overall score
func (ers *EnhancedReputationSystem) determineRiskLevel(score float64) string {
	thresholds := ers.config.RiskThresholds

	if score <= thresholds.Critical {
		return "critical"
	} else if score <= thresholds.High {
		return "high"
	} else if score <= thresholds.Medium {
		return "medium"
	} else if score <= thresholds.Low {
		return "low"
	}

	return "very_low"
}

// determineTrustLevel determines trust level based on overall score
func (ers *EnhancedReputationSystem) determineTrustLevel(score float64) string {
	if score >= 0.9 {
		return "very_high"
	} else if score >= 0.8 {
		return "high"
	} else if score >= 0.6 {
		return "medium"
	} else if score >= 0.4 {
		return "low"
	}

	return "very_low"
}

// generateReputationFlags generates reputation flags based on analysis results
func (ers *EnhancedReputationSystem) generateReputationFlags(result *EnhancedReputationResult) []ReputationFlag {
	var flags []ReputationFlag

	// Check for threat intelligence flags
	for _, threat := range result.ThreatIntelResults {
		if threat.Severity == "critical" || threat.Severity == "high" {
			flags = append(flags, ReputationFlag{
				Type:        "threat_intelligence",
				Severity:    threat.Severity,
				Description: fmt.Sprintf("Package flagged by %s: %s", threat.Source, threat.Description),
				Evidence:    threat.Indicators,
				Source:      threat.Source,
				Timestamp:   time.Now(),
			})
		}
	}

	// Check for maintainer flags
	if len(result.MaintainerAnalysis.SuspiciousPatterns) > 0 {
		flags = append(flags, ReputationFlag{
			Type:        "maintainer_suspicious",
			Severity:    "medium",
			Description: "Maintainer name contains suspicious patterns",
			Evidence:    result.MaintainerAnalysis.SuspiciousPatterns,
			Source:      "maintainer_analysis",
			Timestamp:   time.Now(),
		})
	}

	// Check for security flags
	if result.SecurityAnalysis.CriticalVulns > 0 {
		flags = append(flags, ReputationFlag{
			Type:        "security_vulnerability",
			Severity:    "critical",
			Description: fmt.Sprintf("Package has %d critical vulnerabilities", result.SecurityAnalysis.CriticalVulns),
			Evidence:    []string{fmt.Sprintf("critical_vulns: %d", result.SecurityAnalysis.CriticalVulns)},
			Source:      "security_analysis",
			Timestamp:   time.Now(),
		})
	}

	// Check for community flags
	if result.CommunityAnalysis.CommunityHealth == "poor" {
		flags = append(flags, ReputationFlag{
			Type:        "community_health",
			Severity:    "low",
			Description: "Package has poor community health indicators",
			Evidence:    []string{fmt.Sprintf("community_score: %.2f", result.CommunityAnalysis.CommunityScore)},
			Source:      "community_analysis",
			Timestamp:   time.Now(),
		})
	}

	return flags
}

// generateRecommendations generates recommendations based on analysis results
func (ers *EnhancedReputationSystem) generateRecommendations(result *EnhancedReputationResult) []string {
	var recommendations []string

	// Risk-based recommendations
	switch result.RiskLevel {
	case "critical":
		recommendations = append(recommendations, "CRITICAL: Do not use this package - high security risk")
		recommendations = append(recommendations, "Consider finding alternative packages")
	case "high":
		recommendations = append(recommendations, "Use with extreme caution - implement additional security measures")
		recommendations = append(recommendations, "Monitor for security updates regularly")
	case "medium":
		recommendations = append(recommendations, "Review package thoroughly before use")
		recommendations = append(recommendations, "Implement security monitoring")
	case "low":
		recommendations = append(recommendations, "Package appears safe but monitor for updates")
	}

	// Threat intelligence recommendations
	if len(result.ThreatIntelResults) > 0 {
		recommendations = append(recommendations, "Package flagged by threat intelligence - investigate thoroughly")
	}

	// Maintainer recommendations
	if len(result.MaintainerAnalysis.SuspiciousPatterns) > 0 {
		recommendations = append(recommendations, "Verify maintainer identity and reputation")
	}

	// Security recommendations
	if result.SecurityAnalysis.VulnerabilityCount > 0 {
		recommendations = append(recommendations, "Update to latest version to address known vulnerabilities")
	}

	// Community recommendations
	if result.CommunityAnalysis.CommunityHealth == "poor" {
		recommendations = append(recommendations, "Consider packages with better community support")
	}

	return recommendations
}
