package detector

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// ReputationEngine analyzes package reputation using multiple data sources
type ReputationEngine struct {
	client          *http.Client
	malwareDBURL    string
	vulnDBURL       string
	cacheTimeout    time.Duration
	reputationCache map[string]*ReputationData
	lastCacheUpdate time.Time
}

// ReputationData holds reputation information for a package
type ReputationData struct {
	PackageName     string                 `json:"package_name"`
	Registry        string                 `json:"registry"`
	ReputationScore float64                `json:"reputation_score"`
	TrustLevel      string                 `json:"trust_level"`
	DownloadCount   int64                  `json:"download_count"`
	MaintainerCount int                    `json:"maintainer_count"`
	LastUpdated     time.Time              `json:"last_updated"`
	CreatedAt       time.Time              `json:"created_at"`
	Vulnerabilities []VulnerabilityInfo    `json:"vulnerabilities"`
	MalwareReports  []MalwareReport        `json:"malware_reports"`
	CommunityFlags  []CommunityFlag        `json:"community_flags"`
	Metadata        map[string]interface{} `json:"metadata"`
	CachedAt        time.Time              `json:"cached_at"`
}

// VulnerabilityInfo represents a known vulnerability
type VulnerabilityInfo struct {
	CVE         string    `json:"cve"`
	Severity    string    `json:"severity"`
	Description string    `json:"description"`
	PublishedAt time.Time `json:"published_at"`
	FixedIn     string    `json:"fixed_in"`
}

// MalwareReport represents a malware detection report
type MalwareReport struct {
	Source      string    `json:"source"`
	Type        string    `json:"type"`
	Description string    `json:"description"`
	Confidence  float64   `json:"confidence"`
	ReportedAt  time.Time `json:"reported_at"`
}

// CommunityFlag represents community-reported issues
type CommunityFlag struct {
	Type        string    `json:"type"`
	Description string    `json:"description"`
	Reporter    string    `json:"reporter"`
	ReportedAt  time.Time `json:"reported_at"`
	Verified    bool      `json:"verified"`
}

// NewReputationEngine creates a new reputation engine
func NewReputationEngine(cfg *config.Config) *ReputationEngine {
	return &ReputationEngine{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		malwareDBURL:    "https://api.malware-db.com/v1/packages",
		vulnDBURL:       "https://api.vuln-db.com/v1/packages",
		cacheTimeout:    1 * time.Hour,
		reputationCache: make(map[string]*ReputationData),
	}
}

// Analyze analyzes the reputation of a package (alias for AnalyzeReputation)
func (re *ReputationEngine) Analyze(dep types.Dependency) []types.Threat {
	return re.AnalyzeReputation(dep)
}

// AnalyzeReputation analyzes the reputation of a package
func (re *ReputationEngine) AnalyzeReputation(dep types.Dependency) []types.Threat {
	var threats []types.Threat

	// Get reputation data
	reputationData, err := re.getReputationData(dep)
	if err != nil {
		// If we can't get reputation data, create a warning
		threats = append(threats, types.Threat{
			ID:              generateThreatID(),
			Package:         dep.Name,
			Version:         dep.Version,
			Registry:        dep.Registry,
			Type:            types.ThreatTypeUnknownPackage,
			Severity:        types.SeverityLow,
			Confidence:      0.3,
			Description:     fmt.Sprintf("Unable to verify reputation for package '%s'", dep.Name),
			Recommendation:  "Manually verify this package before use",
			DetectedAt:      time.Now(),
			DetectionMethod: "reputation_analysis",
			Evidence: []types.Evidence{{
				Type:        "reputation_check_failed",
				Description: fmt.Sprintf("Failed to retrieve reputation data: %v", err),
				Value:       map[string]interface{}{"error": err.Error()},
				Score:       0.3,
			}},
		})
		return threats
	}

	// Analyze reputation score
	if reputationData.ReputationScore < 0.3 {
		threats = append(threats, re.createReputationThreat(dep, reputationData, "low_reputation"))
	}

	// Check for malware reports
	if len(reputationData.MalwareReports) > 0 {
		threats = append(threats, re.createMalwareThreat(dep, reputationData))
	}

	// Check for vulnerabilities
	if len(reputationData.Vulnerabilities) > 0 {
		threats = append(threats, re.createVulnerabilityThreat(dep, reputationData))
	}

	// Check for suspicious patterns
	if re.isSuspiciousPackage(reputationData) {
		threats = append(threats, re.createSuspiciousThreat(dep, reputationData))
	}

	// Check for community flags
	if len(reputationData.CommunityFlags) > 0 {
		threats = append(threats, re.createCommunityFlagThreat(dep, reputationData))
	}

	return threats
}

// getReputationData retrieves reputation data for a package
func (re *ReputationEngine) getReputationData(dep types.Dependency) (*ReputationData, error) {
	cacheKey := fmt.Sprintf("%s:%s:%s", dep.Registry, dep.Name, dep.Version)

	// Check cache first
	if cached, exists := re.reputationCache[cacheKey]; exists {
		if time.Since(cached.CachedAt) < re.cacheTimeout {
			return cached, nil
		}
	}

	// Fetch fresh data
	reputationData, err := re.fetchReputationData(dep)
	if err != nil {
		return nil, err
	}

	// Cache the result
	reputationData.CachedAt = time.Now()
	re.reputationCache[cacheKey] = reputationData

	return reputationData, nil
}

// fetchReputationData fetches reputation data from external sources
func (re *ReputationEngine) fetchReputationData(dep types.Dependency) (*ReputationData, error) {
	// Initialize reputation data
	reputationData := &ReputationData{
		PackageName:     dep.Name,
		Registry:        dep.Registry,
		ReputationScore: 0.5, // Default neutral score
		TrustLevel:      "unknown",
		Metadata:        make(map[string]interface{}),
	}

	// Fetch registry-specific data
	switch dep.Registry {
	case "npm":
		err := re.fetchNPMData(reputationData)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch NPM data: %w", err)
		}
	case "pypi":
		err := re.fetchPyPIData(reputationData)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch PyPI data: %w", err)
		}
	case "go":
		err := re.fetchGoData(reputationData)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch Go data: %w", err)
		}
	default:
		// For unknown registries, use generic analysis
		re.performGenericAnalysis(reputationData)
	}

	// Fetch vulnerability data
	err := re.fetchVulnerabilityData(reputationData)
	if err != nil {
		// Log error but don't fail the entire operation
		fmt.Printf("Warning: failed to fetch vulnerability data: %v\n", err)
	}

	// Fetch malware data
	err = re.fetchMalwareData(reputationData)
	if err != nil {
		// Log error but don't fail the entire operation
		fmt.Printf("Warning: failed to fetch malware data: %v\n", err)
	}

	// Calculate final reputation score
	re.calculateReputationScore(reputationData)

	return reputationData, nil
}

// fetchNPMData fetches NPM-specific reputation data
func (re *ReputationEngine) fetchNPMData(data *ReputationData) error {
	// Simulate NPM API call
	// In a real implementation, this would call the NPM API
	data.Metadata["registry_api"] = "npm"
	data.DownloadCount = 1000 // Placeholder
	data.MaintainerCount = 1
	data.CreatedAt = time.Now().AddDate(-1, 0, 0) // 1 year ago
	data.LastUpdated = time.Now().AddDate(0, -1, 0) // 1 month ago

	return nil
}

// fetchPyPIData fetches PyPI-specific reputation data
func (re *ReputationEngine) fetchPyPIData(data *ReputationData) error {
	// Simulate PyPI API call
	data.Metadata["registry_api"] = "pypi"
	data.DownloadCount = 5000 // Placeholder
	data.MaintainerCount = 2
	data.CreatedAt = time.Now().AddDate(-2, 0, 0) // 2 years ago
	data.LastUpdated = time.Now().AddDate(0, 0, -7) // 1 week ago

	return nil
}

// fetchGoData fetches Go-specific reputation data
func (re *ReputationEngine) fetchGoData(data *ReputationData) error {
	// Simulate Go module proxy API call
	data.Metadata["registry_api"] = "go"
	data.DownloadCount = 500 // Placeholder
	data.MaintainerCount = 1
	data.CreatedAt = time.Now().AddDate(0, -6, 0) // 6 months ago
	data.LastUpdated = time.Now().AddDate(0, 0, -1) // 1 day ago

	return nil
}

// performGenericAnalysis performs generic reputation analysis
func (re *ReputationEngine) performGenericAnalysis(data *ReputationData) {
	data.Metadata["analysis_type"] = "generic"
	data.ReputationScore = 0.5 // Neutral score for unknown packages
	data.TrustLevel = "unknown"
}

// fetchVulnerabilityData fetches known vulnerabilities
func (re *ReputationEngine) fetchVulnerabilityData(data *ReputationData) error {
	// Simulate vulnerability database query
	// In a real implementation, this would query CVE databases, Snyk, etc.
	return nil
}

// fetchMalwareData fetches malware reports
func (re *ReputationEngine) fetchMalwareData(data *ReputationData) error {
	// Simulate malware database query
	// In a real implementation, this would query malware databases
	return nil
}

// calculateReputationScore calculates the final reputation score
func (re *ReputationEngine) calculateReputationScore(data *ReputationData) {
	score := 0.5 // Base score

	// Adjust based on download count
	if data.DownloadCount > 100000 {
		score += 0.2
	} else if data.DownloadCount > 10000 {
		score += 0.1
	} else if data.DownloadCount < 100 {
		score -= 0.2
	}

	// Adjust based on age
	age := time.Since(data.CreatedAt)
	if age > 2*365*24*time.Hour { // > 2 years
		score += 0.1
	} else if age < 30*24*time.Hour { // < 30 days
		score -= 0.3
	}

	// Adjust based on maintenance
	lastUpdate := time.Since(data.LastUpdated)
	if lastUpdate < 30*24*time.Hour { // Updated within 30 days
		score += 0.1
	} else if lastUpdate > 365*24*time.Hour { // Not updated for over a year
		score -= 0.2
	}

	// Adjust based on maintainer count
	if data.MaintainerCount > 3 {
		score += 0.1
	} else if data.MaintainerCount == 0 {
		score -= 0.3
	}

	// Penalize for vulnerabilities
	for _, vuln := range data.Vulnerabilities {
		switch strings.ToLower(vuln.Severity) {
		case "critical":
			score -= 0.4
		case "high":
			score -= 0.3
		case "medium":
			score -= 0.2
		case "low":
			score -= 0.1
		}
	}

	// Penalize for malware reports
	for _, malware := range data.MalwareReports {
		score -= 0.5 * malware.Confidence
	}

	// Penalize for community flags
	for _, flag := range data.CommunityFlags {
		if flag.Verified {
			score -= 0.3
		} else {
			score -= 0.1
		}
	}

	// Ensure score is within bounds
	if score > 1.0 {
		score = 1.0
	} else if score < 0.0 {
		score = 0.0
	}

	data.ReputationScore = score

	// Set trust level based on score
	if score >= 0.8 {
		data.TrustLevel = "high"
	} else if score >= 0.6 {
		data.TrustLevel = "medium"
	} else if score >= 0.4 {
		data.TrustLevel = "low"
	} else {
		data.TrustLevel = "very_low"
	}
}

// isSuspiciousPackage checks for suspicious patterns
func (re *ReputationEngine) isSuspiciousPackage(data *ReputationData) bool {
	// Very new package with high download count (potential fake downloads)
	age := time.Since(data.CreatedAt)
	if age < 7*24*time.Hour && data.DownloadCount > 10000 {
		return true
	}

	// Package with no maintainers
	if data.MaintainerCount == 0 {
		return true
	}

	// Package not updated for a very long time but still being downloaded
	lastUpdate := time.Since(data.LastUpdated)
	if lastUpdate > 2*365*24*time.Hour && data.DownloadCount > 1000 {
		return true
	}

	return false
}

// createReputationThreat creates a threat based on reputation analysis
func (re *ReputationEngine) createReputationThreat(dep types.Dependency, data *ReputationData, threatType string) types.Threat {
	severity := types.SeverityMedium
	confidence := 0.7

	if data.ReputationScore < 0.2 {
		severity = types.SeverityHigh
		confidence = 0.9
	} else if data.ReputationScore < 0.1 {
		severity = types.SeverityCritical
		confidence = 0.95
	}

	return types.Threat{
		ID:              generateThreatID(),
		Package:         dep.Name,
		Version:         dep.Version,
		Registry:        dep.Registry,
		Type:            types.ThreatTypeLowReputation,
		Severity:        severity,
		Confidence:      confidence,
		Description:     fmt.Sprintf("Package '%s' has a low reputation score (%.2f)", dep.Name, data.ReputationScore),
		Recommendation:  "Consider using a more reputable alternative or thoroughly audit this package",
		DetectedAt:      time.Now(),
		DetectionMethod: "reputation_analysis",
		Evidence: []types.Evidence{{
			Type:        "reputation_score",
			Description: fmt.Sprintf("Reputation score: %.2f, Trust level: %s", data.ReputationScore, data.TrustLevel),
			Value: map[string]interface{}{
				"reputation_score": data.ReputationScore,
				"trust_level":      data.TrustLevel,
				"download_count":   data.DownloadCount,
				"maintainer_count": data.MaintainerCount,
				"age_days":         int(time.Since(data.CreatedAt).Hours() / 24),
			},
			Score: confidence,
		}},
	}
}

// createMalwareThreat creates a threat based on malware reports
func (re *ReputationEngine) createMalwareThreat(dep types.Dependency, data *ReputationData) types.Threat {
	highestConfidence := 0.0
	for _, report := range data.MalwareReports {
		if report.Confidence > highestConfidence {
			highestConfidence = report.Confidence
		}
	}

	severity := types.SeverityCritical
	if highestConfidence < 0.7 {
		severity = types.SeverityHigh
	}

	evidence := make([]types.Evidence, len(data.MalwareReports))
	for i, report := range data.MalwareReports {
		evidence[i] = types.Evidence{
			Type:        "malware_report",
			Description: fmt.Sprintf("Malware detected by %s: %s", report.Source, report.Description),
			Value: map[string]interface{}{
				"source":      report.Source,
				"type":        report.Type,
				"confidence":  report.Confidence,
				"reported_at": report.ReportedAt,
			},
			Score: report.Confidence,
		}
	}

	return types.Threat{
		ID:              generateThreatID(),
		Package:         dep.Name,
		Version:         dep.Version,
		Registry:        dep.Registry,
		Type:            types.ThreatTypeMalicious,
		Severity:        severity,
		Confidence:      highestConfidence,
		Description:     fmt.Sprintf("Package '%s' has been reported as malware by %d source(s)", dep.Name, len(data.MalwareReports)),
		Recommendation:  "DO NOT USE this package. Remove it immediately from your dependencies.",
		DetectedAt:      time.Now(),
		DetectionMethod: "malware_database",
		Evidence:        evidence,
	}
}

// createVulnerabilityThreat creates a threat based on known vulnerabilities
func (re *ReputationEngine) createVulnerabilityThreat(dep types.Dependency, data *ReputationData) types.Threat {
	highestSeverity := "low"
	for _, vuln := range data.Vulnerabilities {
		if re.compareSeverity(vuln.Severity, highestSeverity) > 0 {
			highestSeverity = vuln.Severity
		}
	}

	severity := re.mapVulnSeverity(highestSeverity)
	evidence := make([]types.Evidence, len(data.Vulnerabilities))
	for i, vuln := range data.Vulnerabilities {
		evidence[i] = types.Evidence{
			Type:        "vulnerability",
			Description: fmt.Sprintf("CVE %s (%s): %s", vuln.CVE, vuln.Severity, vuln.Description),
			Value: map[string]interface{}{
				"cve":          vuln.CVE,
				"severity":     vuln.Severity,
				"published_at": vuln.PublishedAt,
				"fixed_in":     vuln.FixedIn,
			},
			Score: re.vulnSeverityToScore(vuln.Severity),
		}
	}

	return types.Threat{
		ID:              generateThreatID(),
		Package:         dep.Name,
		Version:         dep.Version,
		Registry:        dep.Registry,
		Type:            types.ThreatTypeVulnerable,
		Severity:        severity,
		Confidence:      0.95,
		Description:     fmt.Sprintf("Package '%s' has %d known vulnerabilit(ies), highest severity: %s", dep.Name, len(data.Vulnerabilities), highestSeverity),
		Recommendation:  "Update to a patched version or find an alternative package",
		DetectedAt:      time.Now(),
		DetectionMethod: "vulnerability_database",
		Evidence:        evidence,
	}
}

// createSuspiciousThreat creates a threat for suspicious patterns
func (re *ReputationEngine) createSuspiciousThreat(dep types.Dependency, data *ReputationData) types.Threat {
	return types.Threat{
		ID:              generateThreatID(),
		Package:         dep.Name,
		Version:         dep.Version,
		Registry:        dep.Registry,
		Type:            types.ThreatTypeSuspicious,
		Severity:        types.SeverityMedium,
		Confidence:      0.6,
		Description:     fmt.Sprintf("Package '%s' exhibits suspicious patterns", dep.Name),
		Recommendation:  "Manually review this package before use",
		DetectedAt:      time.Now(),
		DetectionMethod: "pattern_analysis",
		Evidence: []types.Evidence{{
			Type:        "suspicious_pattern",
			Description: "Package exhibits unusual download/maintenance patterns",
			Value: map[string]interface{}{
				"download_count":   data.DownloadCount,
				"maintainer_count": data.MaintainerCount,
				"age_days":         int(time.Since(data.CreatedAt).Hours() / 24),
				"days_since_update": int(time.Since(data.LastUpdated).Hours() / 24),
			},
			Score: 0.6,
		}},
	}
}

// createCommunityFlagThreat creates a threat based on community flags
func (re *ReputationEngine) createCommunityFlagThreat(dep types.Dependency, data *ReputationData) types.Threat {
	verifiedFlags := 0
	for _, flag := range data.CommunityFlags {
		if flag.Verified {
			verifiedFlags++
		}
	}

	severity := types.SeverityLow
	confidence := 0.4
	if verifiedFlags > 0 {
		severity = types.SeverityMedium
		confidence = 0.7
	}
	if verifiedFlags > 2 {
		severity = types.SeverityHigh
		confidence = 0.9
	}

	evidence := make([]types.Evidence, len(data.CommunityFlags))
	for i, flag := range data.CommunityFlags {
		evidence[i] = types.Evidence{
			Type:        "community_flag",
			Description: fmt.Sprintf("Community flag (%s): %s", flag.Type, flag.Description),
			Value: map[string]interface{}{
				"type":        flag.Type,
				"reporter":    flag.Reporter,
				"verified":    flag.Verified,
				"reported_at": flag.ReportedAt,
			},
			Score: map[bool]float64{true: 0.8, false: 0.4}[flag.Verified],
		}
	}

	return types.Threat{
		ID:              generateThreatID(),
		Package:         dep.Name,
		Version:         dep.Version,
		Registry:        dep.Registry,
		Type:            types.ThreatTypeCommunityFlag,
		Severity:        severity,
		Confidence:      confidence,
		Description:     fmt.Sprintf("Package '%s' has been flagged by the community (%d verified flags)", dep.Name, verifiedFlags),
		Recommendation:  "Review community concerns before using this package",
		DetectedAt:      time.Now(),
		DetectionMethod: "community_reports",
		Evidence:        evidence,
	}
}

// Helper functions

func (re *ReputationEngine) compareSeverity(sev1, sev2 string) int {
	severityOrder := map[string]int{
		"low":      1,
		"medium":   2,
		"high":     3,
		"critical": 4,
	}

	val1, ok1 := severityOrder[strings.ToLower(sev1)]
	val2, ok2 := severityOrder[strings.ToLower(sev2)]

	if !ok1 {
		val1 = 0
	}
	if !ok2 {
		val2 = 0
	}

	return val1 - val2
}

func (re *ReputationEngine) mapVulnSeverity(vulnSev string) types.Severity {
	switch strings.ToLower(vulnSev) {
	case "critical":
		return types.SeverityCritical
	case "high":
		return types.SeverityHigh
	case "medium":
		return types.SeverityMedium
	default:
		return types.SeverityLow
	}
}

func (re *ReputationEngine) vulnSeverityToScore(severity string) float64 {
	switch strings.ToLower(severity) {
	case "critical":
		return 0.95
	case "high":
		return 0.85
	case "medium":
		return 0.65
	default:
		return 0.45
	}
}

// ClearCache clears the reputation cache
func (re *ReputationEngine) ClearCache() {
	re.reputationCache = make(map[string]*ReputationData)
	re.lastCacheUpdate = time.Time{}
}

// GetCacheStats returns cache statistics
func (re *ReputationEngine) GetCacheStats() map[string]interface{} {
	return map[string]interface{}{
		"cache_size":        len(re.reputationCache),
		"last_cache_update": re.lastCacheUpdate,
		"cache_timeout":     re.cacheTimeout,
	}
}