package detector

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/internal/ml"
	"github.com/Alivanroy/Typosentinel/pkg/types"
)



// SupplyChainDetector detects compromised packages and malicious maintainer takeovers
type SupplyChainDetector struct {
	config     *config.Config
	mlAnalyzer *ml.MLAnalyzer
	logger     Logger
}

// SupplyChainResult represents the result of supply chain analysis
type SupplyChainResult struct {
	IsCompromised       bool                   `json:"is_compromised"`
	RiskScore          float64                `json:"risk_score"`
	MaintainerAnalysis MaintainerAnalysis     `json:"maintainer_analysis"`
	VersionAnalysis    VersionAnalysis        `json:"version_analysis"`
	IntegrityAnalysis  IntegrityAnalysis      `json:"integrity_analysis"`
	Anomalies          []SupplyChainAnomaly   `json:"anomalies"`
	Recommendations    []string               `json:"recommendations"`
	Details            map[string]interface{} `json:"details"`
}

// MaintainerAnalysis represents maintainer reputation and change analysis
type MaintainerAnalysis struct {
	CurrentMaintainers    []Maintainer `json:"current_maintainers"`
	RecentChanges         []MaintainerChange `json:"recent_changes"`
	ReputationScore       float64      `json:"reputation_score"`
	SuspiciousActivities  []string     `json:"suspicious_activities"`
	VerificationStatus    string       `json:"verification_status"`
}

// VersionAnalysis represents version pattern and history analysis
type VersionAnalysis struct {
	VersionHistory        []VersionInfo `json:"version_history"`
	UnusualPatterns       []string      `json:"unusual_patterns"`
	ReleaseFrequency      float64       `json:"release_frequency"`
	VersionJumps          []VersionJump `json:"version_jumps"`
	DependencyChanges     []DependencyChange `json:"dependency_changes"`
}

// IntegrityAnalysis represents package integrity verification
type IntegrityAnalysis struct {
	ChecksumVerification  bool     `json:"checksum_verification"`
	SignatureVerification bool     `json:"signature_verification"`
	SourceConsistency     bool     `json:"source_consistency"`
	IntegrityScore        float64  `json:"integrity_score"`
	IntegrityIssues       []string `json:"integrity_issues"`
}

// Supporting types
type Maintainer struct {
	Username        string    `json:"username"`
	Email          string    `json:"email"`
	JoinDate       time.Time `json:"join_date"`
	PackageCount    int       `json:"package_count"`
	ActivityLevel   string    `json:"activity_level"`
	ReputationScore float64   `json:"reputation_score"`
	Verified       bool      `json:"verified"`
	Suspicious     bool      `json:"suspicious"`
}

type MaintainerChange struct {
	Type        string    `json:"type"` // "added", "removed", "permissions_changed"
	Maintainer  Maintainer `json:"maintainer"`
	Timestamp   time.Time `json:"timestamp"`
	Description string    `json:"description"`
}

type VersionInfo struct {
	Version     string    `json:"version"`
	ReleaseDate time.Time `json:"release_date"`
	Maintainer  string    `json:"maintainer"`
	Changes     []string  `json:"changes"`
	Size        int64     `json:"size"`
}

type VersionJump struct {
	FromVersion string  `json:"from_version"`
	ToVersion   string  `json:"to_version"`
	JumpSize    float64 `json:"jump_size"`
	Suspicious  bool    `json:"suspicious"`
}

type DependencyChange struct {
	Type        string `json:"type"` // "added", "removed", "updated"
	Dependency  string `json:"dependency"`
	OldVersion  string `json:"old_version,omitempty"`
	NewVersion  string `json:"new_version,omitempty"`
	Suspicious  bool   `json:"suspicious"`
}

type SupplyChainAnomaly struct {
	Type        string                 `json:"type"`
	Severity    string                 `json:"severity"`
	Description string                 `json:"description"`
	Evidence    map[string]interface{} `json:"evidence"`
	Timestamp   time.Time              `json:"timestamp"`
}

// NewSupplyChainDetector creates a new supply chain detector
func NewSupplyChainDetector(config *config.Config, mlAnalyzer *ml.MLAnalyzer, logger Logger) *SupplyChainDetector {
	return &SupplyChainDetector{
		config:     config,
		mlAnalyzer: mlAnalyzer,
		logger:     logger,
	}
}

// Analyze performs supply chain analysis on a package
func (s *SupplyChainDetector) Analyze(ctx context.Context, pkg *types.Package) (*SupplyChainResult, error) {
	start := time.Now()
	s.logger.Debug("Starting supply chain analysis", map[string]interface{}{"package": pkg.Name})

	result := &SupplyChainResult{
		Anomalies: []SupplyChainAnomaly{},
		Details:   make(map[string]interface{}),
	}

	// Analyze maintainer reputation and changes
	maintainerAnalysis, err := s.analyzeMaintainers(ctx, pkg)
	if err != nil {
		return nil, fmt.Errorf("maintainer analysis failed: %w", err)
	}
	result.MaintainerAnalysis = *maintainerAnalysis

	// Analyze version patterns and history
	versionAnalysis, err := s.analyzeVersionHistory(ctx, pkg)
	if err != nil {
		return nil, fmt.Errorf("version analysis failed: %w", err)
	}
	result.VersionAnalysis = *versionAnalysis

	// Analyze package integrity
	integrityAnalysis, err := s.analyzeIntegrity(ctx, pkg)
	if err != nil {
		return nil, fmt.Errorf("integrity analysis failed: %w", err)
	}
	result.IntegrityAnalysis = *integrityAnalysis

	// Detect anomalies
	anomalies := s.detectAnomalies(maintainerAnalysis, versionAnalysis, integrityAnalysis)
	result.Anomalies = anomalies

	// Calculate overall risk score
	riskScore := s.calculateRiskScore(maintainerAnalysis, versionAnalysis, integrityAnalysis, anomalies)
	result.RiskScore = riskScore

	// Determine if package is compromised
	threshold := 0.7 // Default threshold
	// Note: ThreatDetection config would need to be added to config struct
	result.IsCompromised = riskScore >= threshold

	// Generate recommendations
	result.Recommendations = s.generateRecommendations(result)

	// Add analysis metadata
	result.Details["analysis_duration"] = time.Since(start).Milliseconds()
	result.Details["detector_version"] = "1.0.0"
	result.Details["threshold_used"] = threshold

	s.logger.Debug("Supply chain analysis completed", map[string]interface{}{
		"package": pkg.Name,
		"risk_score": riskScore,
		"is_compromised": result.IsCompromised,
		"anomalies": len(anomalies),
		"duration": time.Since(start),
	})

	return result, nil
}

// analyzeMaintainers analyzes maintainer reputation and recent changes
func (s *SupplyChainDetector) analyzeMaintainers(ctx context.Context, pkg *types.Package) (*MaintainerAnalysis, error) {
	analysis := &MaintainerAnalysis{
		CurrentMaintainers:   []Maintainer{},
		RecentChanges:        []MaintainerChange{},
		SuspiciousActivities: []string{},
	}

	// Get current maintainers
	maintainers, err := s.getCurrentMaintainers(pkg)
	if err != nil {
		return nil, fmt.Errorf("failed to get current maintainers: %w", err)
	}
	analysis.CurrentMaintainers = maintainers

	// Get recent maintainer changes
	changes, err := s.getRecentMaintainerChanges(pkg)
	if err != nil {
		return nil, fmt.Errorf("failed to get maintainer changes: %w", err)
	}
	analysis.RecentChanges = changes

	// Calculate reputation score
	analysis.ReputationScore = s.calculateMaintainerReputation(maintainers)

	// Detect suspicious activities
	analysis.SuspiciousActivities = s.detectSuspiciousMaintainerActivities(maintainers, changes)

	// Determine verification status
	analysis.VerificationStatus = s.determineMaintainerVerificationStatus(maintainers)

	return analysis, nil
}

// analyzeVersionHistory analyzes version patterns and release history
func (s *SupplyChainDetector) analyzeVersionHistory(ctx context.Context, pkg *types.Package) (*VersionAnalysis, error) {
	analysis := &VersionAnalysis{
		VersionHistory:    []VersionInfo{},
		UnusualPatterns:   []string{},
		VersionJumps:      []VersionJump{},
		DependencyChanges: []DependencyChange{},
	}

	// Get version history
	versionHistory, err := s.getVersionHistory(pkg)
	if err != nil {
		return nil, fmt.Errorf("failed to get version history: %w", err)
	}
	analysis.VersionHistory = versionHistory

	// Calculate release frequency
	analysis.ReleaseFrequency = s.calculateReleaseFrequency(versionHistory)

	// Detect unusual version patterns
	analysis.UnusualPatterns = s.detectUnusualVersionPatterns(versionHistory)

	// Detect suspicious version jumps
	analysis.VersionJumps = s.detectVersionJumps(versionHistory)

	// Analyze dependency changes
	analysis.DependencyChanges = s.analyzeDependencyChanges(versionHistory)

	return analysis, nil
}

// analyzeIntegrity analyzes package integrity and consistency
func (s *SupplyChainDetector) analyzeIntegrity(ctx context.Context, pkg *types.Package) (*IntegrityAnalysis, error) {
	analysis := &IntegrityAnalysis{
		IntegrityIssues: []string{},
	}

	// Verify checksums
	analysis.ChecksumVerification = s.verifyChecksums(pkg)
	if !analysis.ChecksumVerification {
		analysis.IntegrityIssues = append(analysis.IntegrityIssues, "Checksum verification failed")
	}

	// Verify signatures
	analysis.SignatureVerification = s.verifySignatures(pkg)
	if !analysis.SignatureVerification {
		analysis.IntegrityIssues = append(analysis.IntegrityIssues, "Signature verification failed")
	}

	// Check source consistency
	analysis.SourceConsistency = s.checkSourceConsistency(pkg)
	if !analysis.SourceConsistency {
		analysis.IntegrityIssues = append(analysis.IntegrityIssues, "Source consistency check failed")
	}

	// Calculate integrity score
	analysis.IntegrityScore = s.calculateIntegrityScore(analysis)

	return analysis, nil
}

// detectAnomalies detects supply chain anomalies
func (s *SupplyChainDetector) detectAnomalies(maintainer *MaintainerAnalysis, version *VersionAnalysis, integrity *IntegrityAnalysis) []SupplyChainAnomaly {
	anomalies := []SupplyChainAnomaly{}

	// Maintainer-related anomalies
	if len(maintainer.RecentChanges) > 0 {
		for _, change := range maintainer.RecentChanges {
			if change.Type == "added" && change.Maintainer.Suspicious {
				anomalies = append(anomalies, SupplyChainAnomaly{
					Type:        "suspicious_maintainer_added",
					Severity:    "high",
					Description: "Suspicious maintainer was recently added to the package",
					Evidence: map[string]interface{}{
						"maintainer": change.Maintainer.Username,
						"timestamp": change.Timestamp,
					},
					Timestamp: change.Timestamp,
				})
			}
		}
	}

	// Version-related anomalies
	for _, jump := range version.VersionJumps {
		if jump.Suspicious {
			anomalies = append(anomalies, SupplyChainAnomaly{
				Type:        "suspicious_version_jump",
				Severity:    "medium",
				Description: "Unusual version jump detected",
				Evidence: map[string]interface{}{
					"from_version": jump.FromVersion,
					"to_version":   jump.ToVersion,
					"jump_size":    jump.JumpSize,
				},
				Timestamp: time.Now(),
			})
		}
	}

	// Integrity-related anomalies
	if len(integrity.IntegrityIssues) > 0 {
		anomalies = append(anomalies, SupplyChainAnomaly{
			Type:        "integrity_violation",
			Severity:    "critical",
			Description: "Package integrity verification failed",
			Evidence: map[string]interface{}{
				"issues": integrity.IntegrityIssues,
			},
			Timestamp: time.Now(),
		})
	}

	return anomalies
}

// calculateRiskScore calculates the overall supply chain risk score
func (s *SupplyChainDetector) calculateRiskScore(maintainer *MaintainerAnalysis, version *VersionAnalysis, integrity *IntegrityAnalysis, anomalies []SupplyChainAnomaly) float64 {
	score := 0.0

	// Maintainer reputation (30% weight)
	maintainerScore := 1.0 - maintainer.ReputationScore
	score += maintainerScore * 0.3

	// Version analysis (25% weight)
	versionScore := 0.0
	if len(version.UnusualPatterns) > 0 {
		versionScore += 0.3
	}
	for _, jump := range version.VersionJumps {
		if jump.Suspicious {
			versionScore += 0.2
		}
	}
	score += versionScore * 0.25

	// Integrity analysis (25% weight)
	integrityScore := 1.0 - integrity.IntegrityScore
	score += integrityScore * 0.25

	// Anomalies (20% weight)
	anomalyScore := 0.0
	for _, anomaly := range anomalies {
		switch anomaly.Severity {
		case "critical":
			anomalyScore += 0.4
		case "high":
			anomalyScore += 0.3
		case "medium":
			anomalyScore += 0.2
		case "low":
			anomalyScore += 0.1
		}
	}
	score += anomalyScore * 0.2

	// Ensure score doesn't exceed 1.0
	if score > 1.0 {
		score = 1.0
	}

	return score
}

// generateRecommendations generates security recommendations
func (s *SupplyChainDetector) generateRecommendations(result *SupplyChainResult) []string {
	recommendations := []string{}

	if result.IsCompromised {
		recommendations = append(recommendations, "CRITICAL: This package shows signs of supply chain compromise")
		recommendations = append(recommendations, "Do not use this package in production environments")
		recommendations = append(recommendations, "Report this package to the registry security team")
	}

	if result.MaintainerAnalysis.ReputationScore < 0.5 {
		recommendations = append(recommendations, "Low maintainer reputation detected")
		recommendations = append(recommendations, "Verify maintainer authenticity before using")
	}

	if len(result.MaintainerAnalysis.RecentChanges) > 0 {
		recommendations = append(recommendations, "Recent maintainer changes detected")
		recommendations = append(recommendations, "Review recent package changes carefully")
	}

	if !result.IntegrityAnalysis.ChecksumVerification {
		recommendations = append(recommendations, "Package checksum verification failed")
		recommendations = append(recommendations, "Use alternative package sources")
	}

	if len(result.Anomalies) > 0 {
		recommendations = append(recommendations, "Multiple supply chain anomalies detected")
		recommendations = append(recommendations, "Conduct thorough security review before deployment")
	}

	return recommendations
}

// Helper methods (simplified implementations)
func (s *SupplyChainDetector) getCurrentMaintainers(pkg *types.Package) ([]Maintainer, error) {
	maintainers := []Maintainer{}
	
	// Extract maintainer information based on package registry
	switch pkg.Registry {
	case "npm":
		return s.getNPMMaintainers(pkg)
	case "pypi":
		return s.getPyPIMaintainers(pkg)
	case "go":
		return s.getGoMaintainers(pkg)
	default:
		// Generic maintainer extraction from package metadata
		if pkg.Metadata != nil && len(pkg.Metadata.Metadata) > 0 {
			if author := getStringFromMetadata(pkg.Metadata.Metadata, "author"); author != "" {
				maintainers = append(maintainers, Maintainer{
					Username:        author,
			Email:           getStringFromMetadata(pkg.Metadata.Metadata, "author_email"),
					JoinDate:     time.Now().AddDate(-1, 0, 0), // Default to 1 year ago
					PackageCount: 1,
					ActivityLevel: "medium",
					ReputationScore: 0.5,
					Verified:     false,
					Suspicious:   false,
				})
			}
		}
	}
	
	return maintainers, nil
}

func (s *SupplyChainDetector) getRecentMaintainerChanges(pkg *types.Package) ([]MaintainerChange, error) {
	changes := []MaintainerChange{}
	
	// Check for recent maintainer changes in the last 6 months
	cutoffDate := time.Now().AddDate(0, -6, 0)
	
	// This would typically query a database or API for maintainer history
	// For now, we'll simulate based on package metadata patterns
	if pkg.Metadata != nil && len(pkg.Metadata.Metadata) > 0 {
		// Look for signs of maintainer changes
		if publishedDate := getStringFromMetadata(pkg.Metadata.Metadata, "published_date"); publishedDate != "" {
			if published, err := time.Parse(time.RFC3339, publishedDate); err == nil {
				if published.After(cutoffDate) {
					// Recent publication might indicate new maintainer
					maintainer := Maintainer{
						Username: getStringFromMetadata(pkg.Metadata.Metadata, "author"),
						Email: getStringFromMetadata(pkg.Metadata.Metadata, "author_email"),
						JoinDate: published,
						PackageCount: 1,
						ActivityLevel: "medium",
						ReputationScore: 0.5,
						Verified: false,
						Suspicious: false,
					}
					changes = append(changes, MaintainerChange{
						Type:        "added",
						Maintainer:  maintainer,
						Timestamp:   published,
						Description: "New maintainer added during package update",
					})
				}
			}
		}
	}
	
	return changes, nil
}

func (s *SupplyChainDetector) calculateMaintainerReputation(maintainers []Maintainer) float64 {
	if len(maintainers) == 0 {
		return 0.0
	}
	
	totalScore := 0.0
	for _, maintainer := range maintainers {
		score := 0.0
		
		// Account age (30% weight)
		accountAge := time.Since(maintainer.JoinDate).Hours() / (24 * 365) // years
		ageScore := math.Min(accountAge/2.0, 1.0) // Max score at 2+ years
		score += ageScore * 0.3
		
		// Package count (25% weight)
		packageScore := math.Min(float64(maintainer.PackageCount)/10.0, 1.0) // Max score at 10+ packages
		score += packageScore * 0.25
		
		// Verification status (25% weight)
		if maintainer.Verified {
			score += 0.25
		}
		
		// Activity level (20% weight)
		activityScore := 0.0
		switch maintainer.ActivityLevel {
		case "high":
			activityScore = 1.0
		case "medium":
			activityScore = 0.6
		case "low":
			activityScore = 0.3
		default:
			activityScore = 0.5
		}
		score += activityScore * 0.2
		
		totalScore += score
	}
	
	return totalScore / float64(len(maintainers))
}

func (s *SupplyChainDetector) detectSuspiciousMaintainerActivities(maintainers []Maintainer, changes []MaintainerChange) []string {
	suspiciousActivities := []string{}
	
	// Check for new maintainers with low reputation
	for _, maintainer := range maintainers {
		accountAge := time.Since(maintainer.JoinDate).Hours() / (24 * 30) // months
		if accountAge < 3 && maintainer.PackageCount < 2 {
			suspiciousActivities = append(suspiciousActivities, "new_maintainer_low_reputation")
		}
		
		if !maintainer.Verified && maintainer.PackageCount > 5 {
			suspiciousActivities = append(suspiciousActivities, "unverified_prolific_maintainer")
		}
	}
	
	// Check for frequent maintainer changes
	recentChanges := 0
	cutoffDate := time.Now().AddDate(0, -3, 0) // Last 3 months
	for _, change := range changes {
		if change.Timestamp.After(cutoffDate) {
			recentChanges++
		}
	}
	
	if recentChanges > 2 {
		suspiciousActivities = append(suspiciousActivities, "frequent_maintainer_changes")
	}
	
	// Check for ownership transfers without clear reason
	for _, change := range changes {
		if change.Type == "ownership_transfer" && change.Description == "" {
			suspiciousActivities = append(suspiciousActivities, "unexplained_ownership_transfer")
		}
	}
	
	return suspiciousActivities
}

func (s *SupplyChainDetector) determineMaintainerVerificationStatus(maintainers []Maintainer) string {
	if len(maintainers) == 0 {
		return "no_maintainers"
	}
	
	verifiedCount := 0
	for _, maintainer := range maintainers {
		if maintainer.Verified {
			verifiedCount++
		}
	}
	
	verificationRatio := float64(verifiedCount) / float64(len(maintainers))
	
	switch {
	case verificationRatio == 1.0:
		return "fully_verified"
	case verificationRatio >= 0.5:
		return "partially_verified"
	case verificationRatio > 0:
		return "minimally_verified"
	default:
		return "unverified"
	}
}

func (s *SupplyChainDetector) getVersionHistory(pkg *types.Package) ([]VersionInfo, error) {
	versions := []VersionInfo{}
	
	// Create mock version history based on package metadata
	if pkg.Metadata != nil && len(pkg.Metadata.Metadata) > 0 {
		// Add current version
		currentVersion := VersionInfo{
			Version:     pkg.Version,
			ReleaseDate: time.Now().AddDate(0, 0, -7), // Released a week ago
			Maintainer:  getStringFromMetadata(pkg.Metadata.Metadata, "author"),
			Changes:     []string{"Bug fixes", "Security updates"},
			Size:        1024 * 1024, // 1MB default
		}
		versions = append(versions, currentVersion)
		
		// Add some historical versions
		for i := 1; i <= 5; i++ {
			version := VersionInfo{
				Version:     fmt.Sprintf("1.%d.0", 10-i),
				ReleaseDate: time.Now().AddDate(0, 0, -7*i-7),
				Maintainer:  getStringFromMetadata(pkg.Metadata.Metadata, "author"),
				Changes:     []string{fmt.Sprintf("Version %d updates", 10-i)},
				Size:        int64(1024 * 1024 * (1 + i/10)), // Gradually increasing size
			}
			versions = append(versions, version)
		}
	}
	
	return versions, nil
}

func (s *SupplyChainDetector) calculateReleaseFrequency(versions []VersionInfo) float64 {
	if len(versions) < 2 {
		return 0.0
	}
	
	// Sort versions by release date
	sort.Slice(versions, func(i, j int) bool {
		return versions[i].ReleaseDate.Before(versions[j].ReleaseDate)
	})
	
	// Calculate average days between releases
	totalDays := 0.0
	for i := 1; i < len(versions); i++ {
		days := versions[i].ReleaseDate.Sub(versions[i-1].ReleaseDate).Hours() / 24
		totalDays += days
	}
	
	avgDaysBetweenReleases := totalDays / float64(len(versions)-1)
	
	// Return releases per month
	if avgDaysBetweenReleases > 0 {
		return 30.0 / avgDaysBetweenReleases
	}
	return 0.0
}

func (s *SupplyChainDetector) detectUnusualVersionPatterns(versions []VersionInfo) []string {
	patterns := []string{}
	
	if len(versions) < 2 {
		return patterns
	}
	
	// Check for rapid successive releases
	rapidReleases := 0
	for i := 1; i < len(versions); i++ {
		daysDiff := versions[i].ReleaseDate.Sub(versions[i-1].ReleaseDate).Hours() / 24
		if daysDiff < 1 { // Released within 24 hours
			rapidReleases++
		}
	}
	
	if rapidReleases > 2 {
		patterns = append(patterns, "rapid_successive_releases")
	}
	
	// Check for unusual size changes
	for i := 1; i < len(versions); i++ {
		sizeRatio := float64(versions[i].Size) / float64(versions[i-1].Size)
		if sizeRatio > 5.0 {
			patterns = append(patterns, "dramatic_size_increase")
			break
		} else if sizeRatio < 0.2 {
			patterns = append(patterns, "dramatic_size_decrease")
			break
		}
	}
	
	// Check for maintainer changes
	maintainerChanges := 0
	for i := 1; i < len(versions); i++ {
		if versions[i].Maintainer != versions[i-1].Maintainer {
			maintainerChanges++
		}
	}
	
	if maintainerChanges > len(versions)/3 {
		patterns = append(patterns, "frequent_maintainer_changes")
	}
	
	return patterns
}

func (s *SupplyChainDetector) detectVersionJumps(versions []VersionInfo) []VersionJump {
	jumps := []VersionJump{}
	
	if len(versions) < 2 {
		return jumps
	}
	
	// Sort versions by release date
	sort.Slice(versions, func(i, j int) bool {
		return versions[i].ReleaseDate.Before(versions[j].ReleaseDate)
	})
	
	for i := 1; i < len(versions); i++ {
		fromVer := versions[i-1].Version
		toVer := versions[i].Version
		
		// Simple version jump detection (looking for major version jumps)
		jumpSize := s.calculateVersionJumpSize(fromVer, toVer)
		suspicious := jumpSize > 5.0 // Major version jump of more than 5
		
		if jumpSize > 1.0 {
			jumps = append(jumps, VersionJump{
				FromVersion: fromVer,
				ToVersion:   toVer,
				JumpSize:    jumpSize,
				Suspicious:  suspicious,
			})
		}
	}
	
	return jumps
}

func (s *SupplyChainDetector) analyzeDependencyChanges(versions []VersionInfo) []DependencyChange {
	changes := []DependencyChange{}
	
	// Mock dependency change analysis
	// In a real implementation, this would parse dependency files for each version
	if len(versions) >= 2 {
		// Simulate some dependency changes
		changes = append(changes, DependencyChange{
			Type:       "added",
			Dependency: "lodash",
			NewVersion: "4.17.21",
			Suspicious: false,
		})
		
		changes = append(changes, DependencyChange{
			Type:       "updated",
			Dependency: "express",
			OldVersion: "4.17.1",
			NewVersion: "4.18.2",
			Suspicious: false,
		})
		
		// Add a suspicious change
		changes = append(changes, DependencyChange{
			Type:       "added",
			Dependency: "suspicious-package",
			NewVersion: "1.0.0",
			Suspicious: true,
		})
	}
	
	return changes
}

func (s *SupplyChainDetector) verifyChecksums(pkg *types.Package) bool {
	// TODO: Implement checksum verification
	return true
}

func (s *SupplyChainDetector) verifySignatures(pkg *types.Package) bool {
	// TODO: Implement signature verification
	return true
}

func (s *SupplyChainDetector) checkSourceConsistency(pkg *types.Package) bool {
	// TODO: Implement source consistency check
	return true
}

func (s *SupplyChainDetector) calculateIntegrityScore(analysis *IntegrityAnalysis) float64 {
	score := 1.0
	if !analysis.ChecksumVerification {
		score -= 0.4
	}
	if !analysis.SignatureVerification {
		score -= 0.3
	}
	if !analysis.SourceConsistency {
		score -= 0.3
	}
	if score < 0 {
		score = 0
	}
	return score
}

// Ecosystem-specific maintainer lookup functions
func (s *SupplyChainDetector) getNPMMaintainers(pkg *types.Package) ([]Maintainer, error) {
	maintainers := []Maintainer{}
	
	// Extract from npm package.json metadata
	if pkg.Metadata != nil && len(pkg.Metadata.Metadata) > 0 {
		if author := getStringFromMetadata(pkg.Metadata.Metadata, "author"); author != "" {
			maintainers = append(maintainers, Maintainer{
				Username:        author,
			Email:           getStringFromMetadata(pkg.Metadata.Metadata, "author_email"),
				JoinDate:        time.Now().AddDate(-2, 0, 0), // Default to 2 years ago
				PackageCount:    5, // Default moderate package count
				ActivityLevel:   "medium", // Default moderate activity
				ReputationScore: 0.7,
				Verified:        getStringFromMetadata(pkg.Metadata.Metadata, "verified") == "true",
				Suspicious:      false,
			})
		}
		
		// Check for contributors/maintainers array
		if contributors := getStringFromMetadata(pkg.Metadata.Metadata, "contributors"); contributors != "" {
			// Parse contributors string/array if available
			_ = contributors // Placeholder for contributor parsing
		}
	}
	
	return maintainers, nil
}

func (s *SupplyChainDetector) getPyPIMaintainers(pkg *types.Package) ([]Maintainer, error) {
	maintainers := []Maintainer{}
	
	// Extract from PyPI metadata
	if pkg.Metadata != nil && len(pkg.Metadata.Metadata) > 0 {
		if author := getStringFromMetadata(pkg.Metadata.Metadata, "author"); author != "" {
			maintainers = append(maintainers, Maintainer{
				Username:        author,
			Email:           getStringFromMetadata(pkg.Metadata.Metadata, "author_email"),
				JoinDate:        time.Now().AddDate(-3, 0, 0), // Default to 3 years ago
				PackageCount:    3, // Default package count
				ActivityLevel:   "low", // Default activity level
				ReputationScore: 0.6,
				Verified:        getStringFromMetadata(pkg.Metadata.Metadata, "verified") == "true",
				Suspicious:      false,
			})
		}
		
		if maintainer := getStringFromMetadata(pkg.Metadata.Metadata, "maintainer"); maintainer != "" {
			maintainers = append(maintainers, Maintainer{
				Username:        maintainer,
				Email:           getStringFromMetadata(pkg.Metadata.Metadata, "maintainer_email"),
				JoinDate:        time.Now().AddDate(-2, 0, 0),
				PackageCount:    2,
				ActivityLevel:   "low",
				ReputationScore: 0.5,
				Verified:        false,
				Suspicious:      false,
			})
		}
	}
	
	return maintainers, nil
}

func (s *SupplyChainDetector) getGoMaintainers(pkg *types.Package) ([]Maintainer, error) {
	maintainers := []Maintainer{}
	
	// Extract from Go module metadata
	if pkg.Metadata != nil && len(pkg.Metadata.Metadata) > 0 {
		// Go modules often use repository information
		if repoOwner := getStringFromMetadata(pkg.Metadata.Metadata, "repo_owner"); repoOwner != "" {
			maintainers = append(maintainers, Maintainer{
				Username:        repoOwner,
			Email:           getStringFromMetadata(pkg.Metadata.Metadata, "owner_email"),
				JoinDate:        time.Now().AddDate(-4, 0, 0), // Default to 4 years ago
				PackageCount:    8, // Go developers often have multiple modules
				ActivityLevel:   "high", // Higher activity for Go ecosystem
				ReputationScore: 0.8,
				Verified:        true, // Go modules often have better verification
				Suspicious:      false,
			})
		}
		
		if author := getStringFromMetadata(pkg.Metadata.Metadata, "author"); author != "" {
			maintainers = append(maintainers, Maintainer{
				Username:        author,
				Email:           getStringFromMetadata(pkg.Metadata.Metadata, "author_email"),
				JoinDate:        time.Now().AddDate(-3, 0, 0),
				PackageCount:    5,
				ActivityLevel:   "medium",
				ReputationScore: 0.7,
				Verified:        getStringFromMetadata(pkg.Metadata.Metadata, "verified") == "true",
				Suspicious:      false,
			})
		}
	}
	
	return maintainers, nil
}

// Helper function to safely extract string from metadata
func getStringFromMetadata(metadata map[string]interface{}, key string) string {
	if value, ok := metadata[key]; ok {
		if str, ok := value.(string); ok {
			return str
		}
	}
	return ""
}

// calculateVersionJumpSize calculates the size of a version jump
func (s *SupplyChainDetector) calculateVersionJumpSize(fromVersion, toVersion string) float64 {
	// Simple version comparison - extract major version numbers
	fromMajor := s.extractMajorVersion(fromVersion)
	toMajor := s.extractMajorVersion(toVersion)
	
	if toMajor > fromMajor {
		return float64(toMajor - fromMajor)
	}
	return 0.0
}

// extractMajorVersion extracts the major version number from a version string
func (s *SupplyChainDetector) extractMajorVersion(version string) int {
	// Remove 'v' prefix if present
	version = strings.TrimPrefix(version, "v")
	
	// Split by dots and get first part
	parts := strings.Split(version, ".")
	if len(parts) > 0 {
		if major, err := strconv.Atoi(parts[0]); err == nil {
			return major
		}
	}
	return 0
}