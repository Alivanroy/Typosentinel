package security

import (
	"context"
	"time"

	"github.com/Alivanroy/Typosentinel/pkg/logger"
	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// SecurityCoordinator provides basic security analysis coordination
type SecurityCoordinator struct {
	config             *SecurityCoordinatorConfig
	complexityAnalyzer *ComplexityAnalyzer
	trustValidator     *TrustValidator
	logger             logger.Logger
}

// SecurityCoordinatorConfig holds configuration for the security coordinator
type SecurityCoordinatorConfig struct {
	Enabled                    bool
	ComplexityAnalysisEnabled  bool
	TrustValidationEnabled     bool
	MaxAnalysisTime            time.Duration
	ConfidenceThreshold        float64
}

// NewSecurityCoordinator creates a new security coordinator
func NewSecurityCoordinator(config *SecurityCoordinatorConfig, logger logger.Logger) *SecurityCoordinator {
	return &SecurityCoordinator{
		config:             config,
		complexityAnalyzer: NewComplexityAnalyzer(DefaultComplexityAnalyzerConfig(), logger),
		trustValidator:     NewTrustValidator(DefaultTrustValidatorConfig(), logger),
		logger:             logger,
	}
}

// AnalyzeSecurity performs basic security analysis
func (sc *SecurityCoordinator) AnalyzeSecurity(ctx context.Context, packageData *types.Package) (*SecurityAnalysisResult, error) {
	result := &SecurityAnalysisResult{
		PackageName:      packageData.Name,
		AnalysisTime:     time.Now(),
		Threats:          []SecurityThreat{},
		Recommendations:  []SecurityRecommendation{},
		OverallRiskScore: 0.0,
	}

	// Perform complexity analysis
	if sc.config.ComplexityAnalysisEnabled {
		complexityResult, err := sc.complexityAnalyzer.AnalyzeComplexity(ctx, packageData)
		if err != nil {
			sc.logger.Warn("Complexity analysis failed", map[string]interface{}{"error": err})
		} else if complexityResult != nil {
			result.ComplexityScore = complexityResult.ComplexityScore
			if complexityResult.Severity == types.SeverityCritical || complexityResult.Severity == types.SeverityHigh {
				result.Threats = append(result.Threats, SecurityThreat{
					Type:        "complexity_anomaly",
					Severity:    severityToString(complexityResult.Severity),
					Description: "Package exhibits unusual complexity patterns",
					Confidence:  0.7,
				})
			}
		}
	}

	// Perform trust validation
	if sc.config.TrustValidationEnabled {
		trustResult, err := sc.trustValidator.ValidateTrust(ctx, packageData)
		if err != nil {
			sc.logger.Warn("Trust validation failed", map[string]interface{}{"error": err})
		} else if trustResult != nil {
			result.TrustScore = trustResult.OverallTrustScore
			if trustResult.TrustLevel == "untrusted" || trustResult.TrustLevel == "low" {
				result.Threats = append(result.Threats, SecurityThreat{
					Type:        "untrusted_package",
					Severity:    "high",
					Description: "Package fails trust validation checks",
					Confidence:  0.8,
				})
			}
		}
	}

	// Calculate overall risk score
	result.OverallRiskScore = sc.calculateOverallRisk(result)

	return result, nil
}

func (sc *SecurityCoordinator) calculateOverallRisk(result *SecurityAnalysisResult) float64 {
	baseScore := 0.0
	
	// Factor in complexity score
	if result.ComplexityScore > 0.7 {
		baseScore += 0.3
	}
	
	// Factor in trust score
	if result.TrustScore < 0.5 {
		baseScore += 0.4
	}
	
	// Factor in threats
	for _, threat := range result.Threats {
		switch threat.Severity {
		case "high":
			baseScore += 0.3
		case "medium":
			baseScore += 0.2
		case "low":
			baseScore += 0.1
		}
	}
	
	if baseScore > 1.0 {
		return 1.0
	}
	return baseScore
}

// Helper function to convert severity to string
func severityToString(severity types.Severity) string {
	switch severity {
	case types.SeverityCritical:
		return "critical"
	case types.SeverityHigh:
		return "high"
	case types.SeverityMedium:
		return "medium"
	case types.SeverityLow:
		return "low"
	default:
		return "unknown"
	}
}

// SecurityAnalysisResult represents the result of security analysis
type SecurityAnalysisResult struct {
	PackageName      string                    `json:"package_name"`
	AnalysisTime     time.Time                 `json:"analysis_time"`
	ComplexityScore  float64                   `json:"complexity_score"`
	TrustScore       float64                   `json:"trust_score"`
	Threats          []SecurityThreat          `json:"threats"`
	Recommendations  []SecurityRecommendation  `json:"recommendations"`
	OverallRiskScore float64                   `json:"overall_risk_score"`
}

// SecurityThreat represents a detected security threat
type SecurityThreat struct {
	Type        string  `json:"type"`
	Severity    string  `json:"severity"`
	Description string  `json:"description"`
	Confidence  float64 `json:"confidence"`
}

// SecurityRecommendation represents a security recommendation
type SecurityRecommendation struct {
	Type        string `json:"type"`
	Priority    string `json:"priority"`
	Description string `json:"description"`
	Action      string `json:"action"`
}
