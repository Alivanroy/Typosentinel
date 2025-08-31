package ml

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// ConfidenceFilter filters results based on confidence threshold
type ConfidenceFilter struct {
	MinConfidence float64 `json:"min_confidence"`
	Priority      int     `json:"priority"`
	Name          string  `json:"name"`
}

// Filter implements the ResultFilter interface
func (cf *ConfidenceFilter) Filter(ctx context.Context, result *IntegrationResult) (*IntegrationResult, error) {
	if result.MLPrediction == nil {
		return result, nil
	}

	// Filter out results with low confidence
	if result.MLPrediction.Score < cf.MinConfidence {
		// Add warning about low confidence
		warning := IntegrationWarning{
			Code:      "LOW_CONFIDENCE",
			Message:   fmt.Sprintf("ML prediction confidence (%.2f) below threshold (%.2f)", result.MLPrediction.Score, cf.MinConfidence),
			Source:    "confidence_filter",
			Timestamp: time.Now(),
			Context: map[string]interface{}{
				"confidence": result.MLPrediction.Score,
				"threshold":  cf.MinConfidence,
			},
		}
		result.Warnings = append(result.Warnings, warning)

		// Reduce the weight of ML prediction in combined result
		if result.CombinedResult != nil {
			result.CombinedResult.Confidence *= 0.5 // Reduce confidence
			result.CombinedResult.Score *= 0.8      // Reduce score
		}
	}

	return result, nil
}

// GetName returns the filter name
func (cf *ConfidenceFilter) GetName() string {
	if cf.Name != "" {
		return cf.Name
	}
	return "confidence_filter"
}

// GetPriority returns the filter priority
func (cf *ConfidenceFilter) GetPriority() int {
	return cf.Priority
}

// ThreatTypeFilter filters results based on allowed threat types
type ThreatTypeFilter struct {
	AllowedTypes []string `json:"allowed_types"`
	BlockedTypes []string `json:"blocked_types"`
	Priority     int      `json:"priority"`
	Name         string   `json:"name"`
}

// Filter implements the ResultFilter interface
func (ttf *ThreatTypeFilter) Filter(ctx context.Context, result *IntegrationResult) (*IntegrationResult, error) {
	if result.MLPrediction == nil {
		return result, nil
	}

	threatType := result.MLPrediction.ThreatType

	// Check if threat type is blocked
	for _, blocked := range ttf.BlockedTypes {
		if strings.EqualFold(threatType, blocked) {
			// Block this threat type
			warning := IntegrationWarning{
				Code:      "BLOCKED_THREAT_TYPE",
				Message:   fmt.Sprintf("Threat type '%s' is blocked by filter", threatType),
				Source:    "threat_type_filter",
				Timestamp: time.Now(),
				Context: map[string]interface{}{
					"threat_type": threatType,
					"action":      "blocked",
				},
			}
			result.Warnings = append(result.Warnings, warning)

			// Set threat to false
			if result.CombinedResult != nil {
				result.CombinedResult.IsThreat = false
				result.CombinedResult.Score = 0.0
			}
			return result, nil
		}
	}

	// Check if threat type is in allowed list (if specified)
	if len(ttf.AllowedTypes) > 0 {
		allowed := false
		for _, allowedType := range ttf.AllowedTypes {
			if strings.EqualFold(threatType, allowedType) {
				allowed = true
				break
			}
		}

		if !allowed {
			// Threat type not in allowed list
			warning := IntegrationWarning{
				Code:      "UNALLOWED_THREAT_TYPE",
				Message:   fmt.Sprintf("Threat type '%s' not in allowed list", threatType),
				Source:    "threat_type_filter",
				Timestamp: time.Now(),
				Context: map[string]interface{}{
					"threat_type":   threatType,
					"allowed_types": ttf.AllowedTypes,
				},
			}
			result.Warnings = append(result.Warnings, warning)

			// Reduce confidence
			if result.CombinedResult != nil {
				result.CombinedResult.Confidence *= 0.7
				result.CombinedResult.Score *= 0.7
			}
		}
	}

	return result, nil
}

// GetName returns the filter name
func (ttf *ThreatTypeFilter) GetName() string {
	if ttf.Name != "" {
		return ttf.Name
	}
	return "threat_type_filter"
}

// GetPriority returns the filter priority
func (ttf *ThreatTypeFilter) GetPriority() int {
	return ttf.Priority
}

// SeverityFilter filters results based on severity levels
type SeverityFilter struct {
	MinSeverity string `json:"min_severity"` // "low", "medium", "high", "critical"
	Priority    int    `json:"priority"`
	Name        string `json:"name"`
}

// Filter implements the ResultFilter interface
func (sf *SeverityFilter) Filter(ctx context.Context, result *IntegrationResult) (*IntegrationResult, error) {
	if result.CombinedResult == nil {
		return result, nil
	}

	severityLevels := map[string]int{
		"low":      1,
		"medium":   2,
		"high":     3,
		"critical": 4,
	}

	currentSeverity := strings.ToLower(result.CombinedResult.Severity)
	minSeverity := strings.ToLower(sf.MinSeverity)

	currentLevel, exists := severityLevels[currentSeverity]
	if !exists {
		currentLevel = 1 // Default to low
	}

	minLevel, exists := severityLevels[minSeverity]
	if !exists {
		minLevel = 1 // Default to low
	}

	if currentLevel < minLevel {
		// Severity below threshold
		warning := IntegrationWarning{
			Code:      "LOW_SEVERITY",
			Message:   fmt.Sprintf("Threat severity '%s' below minimum '%s'", currentSeverity, minSeverity),
			Source:    "severity_filter",
			Timestamp: time.Now(),
			Context: map[string]interface{}{
				"current_severity": currentSeverity,
				"min_severity":     minSeverity,
			},
		}
		result.Warnings = append(result.Warnings, warning)

		// Reduce threat score
		result.CombinedResult.Score *= 0.6
		result.CombinedResult.Confidence *= 0.8
	}

	return result, nil
}

// GetName returns the filter name
func (sf *SeverityFilter) GetName() string {
	if sf.Name != "" {
		return sf.Name
	}
	return "severity_filter"
}

// GetPriority returns the filter priority
func (sf *SeverityFilter) GetPriority() int {
	return sf.Priority
}

// MetadataEnricher enriches results with additional metadata
type MetadataEnricher struct {
	Priority int    `json:"priority"`
	Name     string `json:"name"`
}

// Enrich implements the ResultEnricher interface
func (me *MetadataEnricher) Enrich(ctx context.Context, result *IntegrationResult) (*IntegrationResult, error) {
	if result.Metadata == nil {
		result.Metadata = &IntegrationMetadata{}
	}

	// Add enrichment metadata
	if result.Metadata.Configuration == nil {
		result.Metadata.Configuration = make(map[string]interface{})
	}

	result.Metadata.Configuration["enriched_by"] = me.GetName()
	result.Metadata.Configuration["enrichment_time"] = time.Now()

	// Add processing statistics
	if len(result.ProcessingSteps) > 0 {
		totalDuration := time.Duration(0)
		for _, step := range result.ProcessingSteps {
			totalDuration += step.Duration
		}
		result.Metadata.Configuration["total_processing_time"] = totalDuration
		result.Metadata.Configuration["processing_steps_count"] = len(result.ProcessingSteps)
	}

	// Add evidence summary
	if result.CombinedResult != nil && len(result.CombinedResult.Evidence) > 0 {
		evidenceSummary := map[string]int{}
		for _, evidence := range result.CombinedResult.Evidence {
			evidenceSummary[evidence.Source]++
		}
		result.Metadata.Configuration["evidence_summary"] = evidenceSummary
	}

	return result, nil
}

// GetName returns the enricher name
func (me *MetadataEnricher) GetName() string {
	if me.Name != "" {
		return me.Name
	}
	return "metadata_enricher"
}

// GetPriority returns the enricher priority
func (me *MetadataEnricher) GetPriority() int {
	return me.Priority
}

// ExplanationEnricher enriches results with detailed explanations
type ExplanationEnricher struct {
	Priority int    `json:"priority"`
	Name     string `json:"name"`
}

// Enrich implements the ResultEnricher interface
func (ee *ExplanationEnricher) Enrich(ctx context.Context, result *IntegrationResult) (*IntegrationResult, error) {
	if result.CombinedResult == nil {
		return result, nil
	}

	// Create or enhance explanation
	if result.CombinedResult.Explanation == nil {
		result.CombinedResult.Explanation = &CombinedExplanation{}
	}

	// Generate scanner explanation
	if result.ScannerResult != nil {
		if len(result.ScannerResult.Threats) > 0 {
			threat := result.ScannerResult.Threats[0]
			result.CombinedResult.Explanation.ScannerExplanation = fmt.Sprintf(
				"Scanner detected %s threat with severity %s",
				threat.Type,
				threat.Severity,
			)
		} else {
			result.CombinedResult.Explanation.ScannerExplanation = "Scanner did not detect any threats"
		}
	}

	// Generate combination logic explanation
	if len(result.CombinedResult.Sources) > 1 {
		result.CombinedResult.Explanation.CombinationLogic = fmt.Sprintf(
			"Results combined from %d sources: %s",
			len(result.CombinedResult.Sources),
			strings.Join(result.CombinedResult.Sources, ", "),
		)
	}

	// Generate decision factors
	decisionFactors := []string{}

	if result.CombinedResult.Confidence > 0.8 {
		decisionFactors = append(decisionFactors, "High confidence prediction")
	} else if result.CombinedResult.Confidence < 0.5 {
		decisionFactors = append(decisionFactors, "Low confidence prediction")
	}

	if result.CombinedResult.Score > 0.7 {
		decisionFactors = append(decisionFactors, "High threat score")
	} else if result.CombinedResult.Score < 0.3 {
		decisionFactors = append(decisionFactors, "Low threat score")
	}

	if len(result.CombinedResult.Evidence) > 2 {
		decisionFactors = append(decisionFactors, "Multiple evidence sources")
	}

	if len(result.Warnings) > 0 {
		decisionFactors = append(decisionFactors, fmt.Sprintf("%d warnings generated", len(result.Warnings)))
	}

	result.CombinedResult.Explanation.DecisionFactors = decisionFactors

	return result, nil
}

// GetName returns the enricher name
func (ee *ExplanationEnricher) GetName() string {
	if ee.Name != "" {
		return ee.Name
	}
	return "explanation_enricher"
}

// GetPriority returns the enricher priority
func (ee *ExplanationEnricher) GetPriority() int {
	return ee.Priority
}

// RiskEnricher enriches results with risk assessment
type RiskEnricher struct {
	Priority int    `json:"priority"`
	Name     string `json:"name"`
}

// Enrich implements the ResultEnricher interface
func (re *RiskEnricher) Enrich(ctx context.Context, result *IntegrationResult) (*IntegrationResult, error) {
	if result.CombinedResult == nil {
		return result, nil
	}

	// Initialize risk factors if not present
	if result.CombinedResult.RiskFactors == nil {
		result.CombinedResult.RiskFactors = make(map[string]float64)
	}

	// Calculate risk factors based on various indicators

	// Confidence risk
	if result.CombinedResult.Confidence < 0.5 {
		result.CombinedResult.RiskFactors["low_confidence"] = 1.0 - result.CombinedResult.Confidence
	}

	// Evidence diversity risk
	sources := make(map[string]bool)
	for _, evidence := range result.CombinedResult.Evidence {
		sources[evidence.Source] = true
	}
	if len(sources) < 2 {
		result.CombinedResult.RiskFactors["limited_evidence"] = 0.3
	}

	// Warning risk
	if len(result.Warnings) > 0 {
		result.CombinedResult.RiskFactors["warnings_present"] = float64(len(result.Warnings)) * 0.1
	}

	// Processing error risk
	if len(result.Errors) > 0 {
		result.CombinedResult.RiskFactors["processing_errors"] = float64(len(result.Errors)) * 0.2
	}

	// Severity risk
	severityRisk := map[string]float64{
		"low":      0.1,
		"medium":   0.3,
		"high":     0.6,
		"critical": 1.0,
	}
	if risk, exists := severityRisk[strings.ToLower(result.CombinedResult.Severity)]; exists {
		result.CombinedResult.RiskFactors["severity_risk"] = risk
	}

	// Calculate overall risk score
	totalRisk := 0.0
	for _, risk := range result.CombinedResult.RiskFactors {
		totalRisk += risk
	}
	result.CombinedResult.RiskFactors["overall_risk"] = totalRisk / float64(len(result.CombinedResult.RiskFactors))

	return result, nil
}

// GetName returns the enricher name
func (re *RiskEnricher) GetName() string {
	if re.Name != "" {
		return re.Name
	}
	return "risk_enricher"
}

// GetPriority returns the enricher priority
func (re *RiskEnricher) GetPriority() int {
	return re.Priority
}

// RecommendationEnricher enriches results with actionable recommendations
type RecommendationEnricher struct {
	Priority int    `json:"priority"`
	Name     string `json:"name"`
}

// Enrich implements the ResultEnricher interface
func (re *RecommendationEnricher) Enrich(ctx context.Context, result *IntegrationResult) (*IntegrationResult, error) {
	if result.CombinedResult == nil {
		return result, nil
	}

	// Generate recommendations based on the threat assessment
	recommendations := []string{}

	if result.CombinedResult.IsThreat {
		switch strings.ToLower(result.CombinedResult.ThreatType) {
		case "malware":
			recommendations = append(recommendations, "Immediately quarantine the package")
			recommendations = append(recommendations, "Scan the system for additional malware")
			recommendations = append(recommendations, "Review package installation history")

		case "typosquatting":
			recommendations = append(recommendations, "Verify the intended package name")
			recommendations = append(recommendations, "Check package author and repository")
			recommendations = append(recommendations, "Use package name verification tools")

		case "suspicious":
			recommendations = append(recommendations, "Conduct manual review of package contents")
			recommendations = append(recommendations, "Check package reputation and reviews")
			recommendations = append(recommendations, "Monitor package behavior if installed")

		default:
			recommendations = append(recommendations, "Investigate the detected threat further")
			recommendations = append(recommendations, "Consider alternative packages")
		}

		// Severity-based recommendations
		switch strings.ToLower(result.CombinedResult.Severity) {
		case "critical":
			recommendations = append(recommendations, "Take immediate action - do not install")
			recommendations = append(recommendations, "Report to security team")
		case "high":
			recommendations = append(recommendations, "Block installation until further review")
		case "medium":
			recommendations = append(recommendations, "Proceed with caution and monitoring")
		case "low":
			recommendations = append(recommendations, "Consider additional verification")
		}
	} else {
		recommendations = append(recommendations, "Package appears safe for installation")
		recommendations = append(recommendations, "Continue with standard security practices")
	}

	// Confidence-based recommendations
	if result.CombinedResult.Confidence < 0.5 {
		recommendations = append(recommendations, "Low confidence - consider manual review")
		recommendations = append(recommendations, "Gather additional threat intelligence")
	}

	// Warning-based recommendations
	if len(result.Warnings) > 0 {
		recommendations = append(recommendations, "Review warnings before proceeding")
	}

	// Error-based recommendations
	if len(result.Errors) > 0 {
		recommendations = append(recommendations, "Resolve processing errors for accurate assessment")
	}

	// Merge with existing recommendations
	existingRecs := make(map[string]bool)
	for _, rec := range result.CombinedResult.Recommendations {
		existingRecs[rec] = true
	}

	for _, rec := range recommendations {
		if !existingRecs[rec] {
			result.CombinedResult.Recommendations = append(result.CombinedResult.Recommendations, rec)
		}
	}

	return result, nil
}

// GetName returns the enricher name
func (re *RecommendationEnricher) GetName() string {
	if re.Name != "" {
		return re.Name
	}
	return "recommendation_enricher"
}

// GetPriority returns the enricher priority
func (re *RecommendationEnricher) GetPriority() int {
	return re.Priority
}
