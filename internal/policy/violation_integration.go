package policy

import (
	"context"
	"fmt"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/analyzer"
	"github.com/Alivanroy/Typosentinel/internal/auth"
	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// ViolationIntegrator connects policy violations to scan results
type ViolationIntegrator struct {
	policyManager *auth.EnterprisePolicyManager
	remediationEngine *RemediationEngine
	notificationService NotificationService
	auditLogger AuditLogger
}

// NotificationService interface for sending notifications
type NotificationService interface {
	SendViolationAlert(violation *auth.PolicyViolation) error
	SendRemediationUpdate(violation *auth.PolicyViolation, action *auth.RemediationAction) error
}

// AuditLogger interface for audit logging
type AuditLogger interface {
	LogViolation(violation *auth.PolicyViolation) error
	LogRemediation(violation *auth.PolicyViolation, action *auth.RemediationAction) error
}

// ScanResultWithViolations extends scan results with policy violations
type ScanResultWithViolations struct {
	*analyzer.ScanResult
	Violations []ViolationDetails `json:"violations"`
	EnforcementResult *auth.EnforcementResult `json:"enforcement_result"`
	RemediationActions []RemediationDetails `json:"remediation_actions"`
}

// ViolationDetails provides detailed information about a policy violation
type ViolationDetails struct {
	*auth.PolicyViolation
	AffectedPackages []string `json:"affected_packages"`
	ThreatContext *ThreatContext `json:"threat_context"`
	RiskAssessment *RiskAssessment `json:"risk_assessment"`
}

// ThreatContext provides context about threats related to the violation
type ThreatContext struct {
	ThreatTypes []string `json:"threat_types"`
	SeverityDistribution map[string]int `json:"severity_distribution"`
	AffectedFiles []string `json:"affected_files"`
	CVEReferences []string `json:"cve_references"`
}

// RiskAssessment provides risk assessment for the violation
type RiskAssessment struct {
	OverallRiskScore float64 `json:"overall_risk_score"`
	ImpactScore float64 `json:"impact_score"`
	LikelihoodScore float64 `json:"likelihood_score"`
	MitigationComplexity string `json:"mitigation_complexity"`
	BusinessImpact string `json:"business_impact"`
}

// RemediationDetails provides details about remediation actions
type RemediationDetails struct {
	ViolationID     string                 `json:"violation_id"`
	RemediationType string                 `json:"remediation_type"`
	Status          string                 `json:"status"`
	Steps           []RemediationStep      `json:"steps"`
	StartedAt       time.Time              `json:"started_at"`
	CompletedAt     *time.Time             `json:"completed_at,omitempty"`
	Duration        time.Duration          `json:"duration"`
	Success         bool                   `json:"success"`
	ErrorMessage    string                 `json:"error_message,omitempty"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
}

// NewViolationIntegrator creates a new violation integrator
func NewViolationIntegrator(
	policyManager *auth.EnterprisePolicyManager,
	remediationEngine *RemediationEngine,
	notificationService NotificationService,
	auditLogger AuditLogger,
) *ViolationIntegrator {
	return &ViolationIntegrator{
		policyManager: policyManager,
		remediationEngine: remediationEngine,
		notificationService: notificationService,
		auditLogger: auditLogger,
	}
}

// ProcessScanResult processes scan results and integrates policy violations
func (vi *ViolationIntegrator) ProcessScanResult(ctx context.Context, scanResult *analyzer.ScanResult) (*ScanResultWithViolations, error) {
	// Create policy evaluation context from scan result
	evalCtx := &auth.PolicyEvaluationContext{
		ScanResult: &types.ScanResult{
			ID:     scanResult.ScanID,
			Target: scanResult.Path,
			Summary: &types.ScanSummary{
				TotalPackages:   scanResult.TotalPackages,
				HighestSeverity: types.SeverityUnknown,
			},
		},
		User: &auth.User{
			ID:       "system",
			Username: "system",
			Email:    "system@internal",
			Roles:    []string{"system"},
		},
		Environment: "production",
		Metadata:    make(map[string]interface{}),
	}

	// Evaluate policies and enforce them
	enforcementResult, err := vi.policyManager.EvaluateAndEnforce(ctx, evalCtx)
	if err != nil {
		return nil, fmt.Errorf("policy evaluation failed: %w", err)
	}

	// Create enhanced scan result
	enhancedResult := &ScanResultWithViolations{
		ScanResult: scanResult,
		Violations: make([]ViolationDetails, 0),
		EnforcementResult: enforcementResult,
		RemediationActions: make([]RemediationDetails, 0),
	}

	// Process violations
	for _, violation := range enforcementResult.Violations {
		violationDetails := vi.createViolationDetails(&violation, scanResult)
		enhancedResult.Violations = append(enhancedResult.Violations, violationDetails)

		// Log violation for audit
		if vi.auditLogger != nil {
			if err := vi.auditLogger.LogViolation(&violation); err != nil {
				// Log error but don't fail the process
				fmt.Printf("Failed to log violation: %v\n", err)
			}
		}

		// Send notification
		if vi.notificationService != nil {
			if err := vi.notificationService.SendViolationAlert(&violation); err != nil {
				// Log error but don't fail the process
				fmt.Printf("Failed to send violation alert: %v\n", err)
			}
		}

		// Process automated remediation if configured
		if violation.Remediation != nil && vi.remediationEngine != nil {
			remediationDetails, err := vi.processRemediation(ctx, &violation)
			if err != nil {
				fmt.Printf("Failed to process remediation: %v\n", err)
			} else {
				enhancedResult.RemediationActions = append(enhancedResult.RemediationActions, *remediationDetails)
			}
		}
	}

	return enhancedResult, nil
}

// createViolationDetails creates detailed violation information
func (vi *ViolationIntegrator) createViolationDetails(violation *auth.PolicyViolation, scanResult *analyzer.ScanResult) ViolationDetails {
	affectedPackages := vi.extractAffectedPackages(violation, scanResult)
	threatContext := vi.createThreatContext(violation, scanResult)
	riskAssessment := vi.assessRisk(violation, scanResult)

	return ViolationDetails{
		PolicyViolation: violation,
		AffectedPackages: affectedPackages,
		ThreatContext: threatContext,
		RiskAssessment: riskAssessment,
	}
}

// extractAffectedPackages extracts package names affected by the violation
func (vi *ViolationIntegrator) extractAffectedPackages(violation *auth.PolicyViolation, scanResult *analyzer.ScanResult) []string {
	packages := make([]string, 0)
	
	// Extract from threats in scan result
	for _, threat := range scanResult.Threats {
		if threat.Severity.String() == violation.Severity {
			packages = append(packages, threat.Package)
		}
	}
	
	return packages
}

// createThreatContext creates threat context from scan results
func (vi *ViolationIntegrator) createThreatContext(violation *auth.PolicyViolation, scanResult *analyzer.ScanResult) *ThreatContext {
	threatTypes := make([]string, 0)
	severityDist := make(map[string]int)
	cveRefs := make([]string, 0)
	
	for _, threat := range scanResult.Threats {
		threatTypes = append(threatTypes, string(threat.Type))
		severityDist[threat.Severity.String()]++
		cveRefs = append(cveRefs, threat.CVEs...)
	}
	
	return &ThreatContext{
		ThreatTypes:          threatTypes,
		SeverityDistribution: severityDist,
		AffectedFiles:        []string{scanResult.Path},
		CVEReferences:        cveRefs,
	}
}

// assessRisk performs risk assessment for the violation
func (vi *ViolationIntegrator) assessRisk(violation *auth.PolicyViolation, scanResult *analyzer.ScanResult) *RiskAssessment {
	// Simple risk assessment algorithm
	var impactScore, likelihoodScore float64

	// Calculate impact based on severity
	switch violation.Severity {
	case "critical":
		impactScore = 9.0
	case "high":
		impactScore = 7.0
	case "medium":
		impactScore = 5.0
	case "low":
		impactScore = 3.0
	default:
		impactScore = 1.0
	}

	// Calculate likelihood based on threat count and types
	threatCount := len(scanResult.Threats)
	if threatCount > 10 {
		likelihoodScore = 8.0
	} else if threatCount > 5 {
		likelihoodScore = 6.0
	} else if threatCount > 0 {
		likelihoodScore = 4.0
	} else {
		likelihoodScore = 1.0
	}

	overallRiskScore := (impactScore + likelihoodScore) / 2

	// Determine mitigation complexity
	var mitigationComplexity string
	if overallRiskScore >= 8.0 {
		mitigationComplexity = "high"
	} else if overallRiskScore >= 6.0 {
		mitigationComplexity = "medium"
	} else {
		mitigationComplexity = "low"
	}

	// Determine business impact
	var businessImpact string
	if violation.Severity == "critical" {
		businessImpact = "severe"
	} else if violation.Severity == "high" {
		businessImpact = "significant"
	} else {
		businessImpact = "minimal"
	}

	return &RiskAssessment{
		OverallRiskScore: overallRiskScore,
		ImpactScore: impactScore,
		LikelihoodScore: likelihoodScore,
		MitigationComplexity: mitigationComplexity,
		BusinessImpact: businessImpact,
	}
}

// processRemediation processes automated remediation for a violation
func (vi *ViolationIntegrator) processRemediation(ctx context.Context, violation *auth.PolicyViolation) (*RemediationDetails, error) {
	if vi.remediationEngine == nil {
		return nil, fmt.Errorf("remediation engine not configured")
	}
	
	// Execute remediation
	result, err := (*vi.remediationEngine).ExecuteRemediation(ctx, violation)
	if err != nil {
		return nil, fmt.Errorf("remediation execution failed: %w", err)
	}
	
	// Update violation status if remediation was successful
	if result.Status == "completed" {
		violation.Status = auth.ViolationStatusRemediated
		violation.ResolvedAt = &result.CompletedAt
	}
	
	return &RemediationDetails{
		ViolationID:     violation.ID,
		RemediationType: violation.Remediation.Type,
		Status:          string(result.Status),
		Steps:           []RemediationStep{}, // Steps not available in RemediationResult
		StartedAt:       time.Now(), // Use current time as started
		CompletedAt:     &result.CompletedAt,
		Duration:        time.Since(time.Now()), // Calculate duration
		Success:         result.Status == "completed",
		ErrorMessage:    result.Error,
		Metadata:        result.Metadata,
	}, nil
}

// Helper methods

func (vi *ViolationIntegrator) convertThreats(threats []types.Threat) []types.Threat {
	converted := make([]types.Threat, len(threats))
	for i, threat := range threats {
		converted[i] = types.Threat{
			ID: threat.ID,
			Type: threat.Type,
			Severity: threat.Severity,
			Package: threat.Package,
			Description: threat.Description,
			References: threat.References,
		}
	}
	return converted
}

func (vi *ViolationIntegrator) removeDuplicates(slice []string) []string {
	keys := make(map[string]bool)
	result := []string{}
	for _, item := range slice {
		if !keys[item] {
			keys[item] = true
			result = append(result, item)
		}
	}
	return result
}

func (vi *ViolationIntegrator) mapKeysToSlice(m map[string]bool) []string {
	result := make([]string, 0, len(m))
	for key := range m {
		result = append(result, key)
	}
	return result
}

func (vi *ViolationIntegrator) estimateEffort(violation *auth.PolicyViolation) string {
	switch violation.Severity {
	case "critical":
		return "high"
	case "high":
		return "medium"
	default:
		return "low"
	}
}

func (vi *ViolationIntegrator) getPrerequisites(violation *auth.PolicyViolation) []string {
	switch violation.Remediation.Type {
	case "block":
		return []string{"deployment_pipeline_access", "approval_workflow"}
	case "quarantine":
		return []string{"quarantine_system_access", "backup_verification"}
	default:
		return []string{"basic_access_permissions"}
	}
}

func (vi *ViolationIntegrator) getValidationSteps(violation *auth.PolicyViolation) []string {
	return []string{
		"Verify remediation action completed successfully",
		"Run security scan to confirm threat mitigation",
		"Update compliance documentation",
		"Notify stakeholders of resolution",
	}
}

func (vi *ViolationIntegrator) getRollbackPlan(violation *auth.PolicyViolation) string {
	switch violation.Remediation.Type {
	case "block":
		return "Restore previous deployment state and re-enable pipeline"
	case "quarantine":
		return "Remove quarantine restrictions and restore normal access"
	default:
		return "Revert configuration changes and restore previous state"
	}
}