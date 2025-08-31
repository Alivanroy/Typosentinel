package scanner

import (
	"fmt"
	"strings"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/internal/logging"
	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// ThreatIntelAnalyzer provides threat intelligence analysis capabilities
type ThreatIntelAnalyzer interface {
	AnalyzeThreatIntelligence(packages []*types.Package) (*ReputationAnalysis, error)
	CorrelateThreats(findings []ThreatIntelFinding) (*ThreatContext, error)
	EnrichWithIntelligence(pkg *types.Package) (*ReputationAnalysis, error)
	DetectEmergingThreats(packages []*types.Package) ([]ThreatIntelFinding, error)
}

// ThreatIntelAnalyzerImpl implements the ThreatIntelAnalyzer interface
type ThreatIntelAnalyzerImpl struct {
	config *config.Config
	logger *logging.Logger
}

// NewThreatIntelAnalyzer creates a new threat intelligence analyzer
func NewThreatIntelAnalyzer(cfg *config.Config, logger *logging.Logger) ThreatIntelAnalyzer {
	return &ThreatIntelAnalyzerImpl{
		config: cfg,
		logger: logger,
	}
}

// AnalyzeThreatIntelligence performs comprehensive threat intelligence analysis
func (tia *ThreatIntelAnalyzerImpl) AnalyzeThreatIntelligence(packages []*types.Package) (*ReputationAnalysis, error) {
	tia.logger.Info("Starting threat intelligence analysis")

	var allFindings []ThreatIntelFinding

	// Analyze each package for threat intelligence
	for _, pkg := range packages {
		findings := tia.analyzePackageThreatIntel(pkg)
		allFindings = append(allFindings, findings...)
	}

	// Calculate overall reputation score
	score := tia.calculateReputationScore(allFindings)
	tia.logger.Info("Completed threat intelligence analysis")

	return &ReputationAnalysis{
		Score:      score,
		TrustLevel: tia.getTrustLevel(score),
		Factors:    tia.getReputationFactors(allFindings),
	}, nil
}

// CorrelateThreats correlates threat findings to identify patterns
func (tia *ThreatIntelAnalyzerImpl) CorrelateThreats(findings []ThreatIntelFinding) (*ThreatContext, error) {
	if len(findings) == 0 {
		return &ThreatContext{
			ThreatID:    "no-threats",
			Description: "No threats found",
			Severity:    "low",
			References:  []string{},
		}, nil
	}

	// Use the first finding as primary threat
	primaryThreat := findings[0]
	return &ThreatContext{
		ThreatID:    primaryThreat.ID,
		Description: primaryThreat.Description,
		Severity:    primaryThreat.Severity.String(),
		References:  primaryThreat.References,
	}, nil
}

// EnrichWithIntelligence enriches package data with threat intelligence
func (tia *ThreatIntelAnalyzerImpl) EnrichWithIntelligence(pkg *types.Package) (*ReputationAnalysis, error) {
	// Analyze package reputation
	score := tia.calculatePackageReputation(pkg)
	tia.logger.Info("Enriched package with intelligence")

	return &ReputationAnalysis{
		Score:      score,
		TrustLevel: tia.getTrustLevel(score),
		Factors:    tia.getPackageFactors(pkg),
	}, nil
}

// DetectEmergingThreats detects emerging threats in packages
func (tia *ThreatIntelAnalyzerImpl) DetectEmergingThreats(packages []*types.Package) ([]ThreatIntelFinding, error) {
	var threats []ThreatIntelFinding

	for _, pkg := range packages {
		emergingThreats := tia.analyzeEmergingThreats(pkg)
		threats = append(threats, emergingThreats...)
	}

	return threats, nil
}

// Helper methods

func (tia *ThreatIntelAnalyzerImpl) analyzePackageThreatIntel(pkg *types.Package) []ThreatIntelFinding {
	var findings []ThreatIntelFinding

	// Check for known malicious indicators
	if tia.hasKnownMaliciousIndicators(pkg) {
		findings = append(findings, ThreatIntelFinding{
			ID:          fmt.Sprintf("malicious-%s", pkg.Name),
			Source:      "threat_database",
			Type:        "malicious_package",
			Severity:    types.SeverityCritical,
			Confidence:  0.9,
			Description: fmt.Sprintf("Package %s matches known malicious indicators", pkg.Name),
			Indicators:  []MaliciousIndicator{{Type: "malicious", Value: pkg.Name, Confidence: 0.9, Description: "Known malicious package"}},
			References:  []string{"threat_database"},
			DetectedAt:  time.Now(),
			Metadata:    make(map[string]interface{}),
		})
	}

	// Check for suspicious patterns
	if tia.hasSuspiciousPatterns(pkg) {
		findings = append(findings, ThreatIntelFinding{
			ID:          fmt.Sprintf("suspicious-%s", pkg.Name),
			Source:      "behavioral_analysis",
			Type:        "suspicious_activity",
			Severity:    types.SeverityMedium,
			Confidence:  0.6,
			Description: fmt.Sprintf("Package %s exhibits suspicious patterns", pkg.Name),
			Indicators:  []MaliciousIndicator{{Type: "suspicious", Value: pkg.Name, Confidence: 0.6, Description: "Suspicious behavior detected"}},
			References:  []string{"behavioral_analysis"},
			DetectedAt:  time.Now(),
			Metadata:    make(map[string]interface{}),
		})
	}

	return findings
}

func (tia *ThreatIntelAnalyzerImpl) calculateReputationScore(findings []ThreatIntelFinding) float64 {
	if len(findings) == 0 {
		return 1.0 // High trust when no threats found
	}

	totalRisk := 0.0
	for _, finding := range findings {
		severityWeight := tia.getSeverityWeight(finding.Severity)
		totalRisk += finding.Confidence * severityWeight
	}

	// Convert risk to reputation (inverse relationship)
	avgRisk := totalRisk / float64(len(findings))
	return 1.0 - avgRisk
}

func (tia *ThreatIntelAnalyzerImpl) getTrustLevel(score float64) string {
	if score >= 0.8 {
		return "high"
	} else if score >= 0.6 {
		return "medium"
	} else if score >= 0.4 {
		return "low"
	}
	return "very_low"
}

func (tia *ThreatIntelAnalyzerImpl) getReputationFactors(findings []ThreatIntelFinding) []string {
	var factors []string
	threatTypes := make(map[string]bool)

	for _, finding := range findings {
		if !threatTypes[finding.Type] {
			factors = append(factors, finding.Type)
			threatTypes[finding.Type] = true
		}
	}

	if len(factors) == 0 {
		factors = append(factors, "clean_reputation")
	}

	return factors
}

func (tia *ThreatIntelAnalyzerImpl) calculatePackageReputation(pkg *types.Package) float64 {
	// Base reputation score
	score := 0.8

	// Reduce score based on existing threats
	if len(pkg.Threats) > 0 {
		score -= float64(len(pkg.Threats)) * 0.1
	}

	// Adjust based on risk score
	if pkg.RiskScore > 0.5 {
		score -= pkg.RiskScore * 0.3
	}

	// Ensure score is within bounds
	if score < 0.0 {
		score = 0.0
	} else if score > 1.0 {
		score = 1.0
	}

	return score
}

func (tia *ThreatIntelAnalyzerImpl) getPackageFactors(pkg *types.Package) []string {
	var factors []string

	if tia.hasNameSimilarity(pkg) {
		factors = append(factors, "name_similarity")
	}

	if tia.hasVersionAnomalies(pkg) {
		factors = append(factors, "version_anomaly")
	}

	if len(pkg.Threats) > 0 {
		factors = append(factors, "existing_threats")
	}

	if pkg.RiskScore > 0.5 {
		factors = append(factors, "high_risk_score")
	}

	if len(factors) == 0 {
		factors = append(factors, "clean_package")
	}

	return factors
}

// Remove unused method

func (tia *ThreatIntelAnalyzerImpl) analyzeEmergingThreats(pkg *types.Package) []ThreatIntelFinding {
	var threats []ThreatIntelFinding

	// Detect emerging threat patterns
	if tia.hasEmergingThreatPatterns(pkg) {
		threats = append(threats, ThreatIntelFinding{
			ID:          fmt.Sprintf("emerging-%s", pkg.Name),
			Source:      "behavioral_analysis",
			Type:        "emerging_threat",
			Severity:    types.SeverityHigh,
			Confidence:  0.7,
			Description: fmt.Sprintf("Emerging threat pattern detected in %s", pkg.Name),
			Indicators:  []MaliciousIndicator{{Type: "emerging", Value: pkg.Name, Confidence: 0.7, Description: "Emerging threat pattern"}},
			References:  []string{"behavioral_analysis"},
			DetectedAt:  time.Now(),
			Metadata:    make(map[string]interface{}),
		})
	}

	return threats
}

// Remove unused method

func (tia *ThreatIntelAnalyzerImpl) getSeverityWeight(severity types.Severity) float64 {
	switch severity {
	case types.SeverityCritical:
		return 1.0
	case types.SeverityHigh:
		return 0.8
	case types.SeverityMedium:
		return 0.6
	case types.SeverityLow:
		return 0.4
	default:
		return 0.2
	}
}

// Detection helper methods

func (tia *ThreatIntelAnalyzerImpl) hasKnownMaliciousIndicators(pkg *types.Package) bool {
	// Check against known malicious package indicators
	return strings.Contains(pkg.Name, "malicious") || strings.Contains(pkg.Name, "evil")
}

func (tia *ThreatIntelAnalyzerImpl) hasSuspiciousPatterns(pkg *types.Package) bool {
	// Check for suspicious patterns in package metadata
	return len(pkg.Name) < 3 || strings.Contains(pkg.Name, "test")
}

func (tia *ThreatIntelAnalyzerImpl) hasNameSimilarity(pkg *types.Package) bool {
	// Check for name similarity to popular packages
	return strings.Contains(pkg.Name, "react") || strings.Contains(pkg.Name, "angular")
}

func (tia *ThreatIntelAnalyzerImpl) hasVersionAnomalies(pkg *types.Package) bool {
	// Check for version anomalies
	return strings.Contains(pkg.Version, "alpha") || strings.Contains(pkg.Version, "beta")
}

func (tia *ThreatIntelAnalyzerImpl) hasEmergingThreatPatterns(pkg *types.Package) bool {
	// Check for emerging threat patterns
	return len(pkg.Threats) > 0 && pkg.RiskScore > 0.7
}
