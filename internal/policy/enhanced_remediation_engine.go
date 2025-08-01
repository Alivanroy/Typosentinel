package policy

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/auth"
	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// EnhancedRemediationEngine provides specific remediation actions for each threat type
type EnhancedRemediationEngine struct {
	*DefaultRemediationEngine
	dependencyUpdater DependencyUpdater
	prGenerator       PullRequestGenerator
	repositoryManager RepositoryManager
}

// DependencyUpdater interface for automated dependency updates
type DependencyUpdater interface {
	UpdateDependency(ctx context.Context, pkg *types.Package, targetVersion string) (*UpdateResult, error)
	FindSafeVersion(ctx context.Context, pkg *types.Package) (*SafeVersionResult, error)
	ValidateUpdate(ctx context.Context, pkg *types.Package, newVersion string) (*ValidationResult, error)
}

// PullRequestGenerator interface for creating remediation pull requests
type PullRequestGenerator interface {
	CreateRemediationPR(ctx context.Context, request *PRRequest) (*PRResult, error)
	GetPRTemplate(threatType types.ThreatType) *PRTemplate
}

// RepositoryManager interface for repository operations
type RepositoryManager interface {
	GetRepository(ctx context.Context, repoURL string) (*Repository, error)
	CreateBranch(ctx context.Context, repo *Repository, branchName string) error
	CommitChanges(ctx context.Context, repo *Repository, changes []FileChange) error
}

// UpdateResult represents the result of a dependency update
type UpdateResult struct {
	Package     *types.Package `json:"package"`
	OldVersion  string         `json:"old_version"`
	NewVersion  string         `json:"new_version"`
	Success     bool           `json:"success"`
	ChangedFiles []string      `json:"changed_files"`
	Error       string         `json:"error,omitempty"`
}

// SafeVersionResult represents a safe version recommendation
type SafeVersionResult struct {
	Package         *types.Package `json:"package"`
	RecommendedVersion string      `json:"recommended_version"`
	Reason          string         `json:"reason"`
	Confidence      float64        `json:"confidence"`
	Alternatives    []string       `json:"alternatives,omitempty"`
}

// ValidationResult represents validation of a dependency update
type ValidationResult struct {
	Valid       bool     `json:"valid"`
	Reason      string   `json:"reason"`
	Warnings    []string `json:"warnings,omitempty"`
	BreakingChanges bool `json:"breaking_changes"`
}

// PRRequest represents a pull request creation request
type PRRequest struct {
	Repository    *Repository           `json:"repository"`
	ThreatType    types.ThreatType      `json:"threat_type"`
	Violation     *auth.PolicyViolation `json:"violation"`
	Changes       []FileChange          `json:"changes"`
	Title         string                `json:"title"`
	Description   string                `json:"description"`
	BranchName    string                `json:"branch_name"`
	Assignees     []string              `json:"assignees,omitempty"`
	Reviewers     []string              `json:"reviewers,omitempty"`
}

// PRResult represents the result of pull request creation
type PRResult struct {
	PRNumber    int    `json:"pr_number"`
	PRURL       string `json:"pr_url"`
	BranchName  string `json:"branch_name"`
	Success     bool   `json:"success"`
	Error       string `json:"error,omitempty"`
}

// PRTemplate represents a pull request template
type PRTemplate struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Labels      []string `json:"labels"`
	Assignees   []string `json:"assignees,omitempty"`
	Reviewers   []string `json:"reviewers,omitempty"`
}

// Repository represents a code repository
type Repository struct {
	URL         string `json:"url"`
	Owner       string `json:"owner"`
	Name        string `json:"name"`
	DefaultBranch string `json:"default_branch"`
	ClonePath   string `json:"clone_path"`
}

// FileChange represents a file modification
type FileChange struct {
	Path    string `json:"path"`
	Content string `json:"content"`
	Action  string `json:"action"` // create, update, delete
}

// NewEnhancedRemediationEngine creates a new enhanced remediation engine
func NewEnhancedRemediationEngine(
	baseEngine *DefaultRemediationEngine,
	dependencyUpdater DependencyUpdater,
	prGenerator PullRequestGenerator,
	repoManager RepositoryManager,
) *EnhancedRemediationEngine {
	return &EnhancedRemediationEngine{
		DefaultRemediationEngine: baseEngine,
		dependencyUpdater:        dependencyUpdater,
		prGenerator:              prGenerator,
		repositoryManager:        repoManager,
	}
}

// ExecuteRemediation executes enhanced remediation based on threat type
func (e *EnhancedRemediationEngine) ExecuteRemediation(ctx context.Context, violation *auth.PolicyViolation) (*RemediationResult, error) {
	// Create remediation status
	status := &RemediationStatus{
		ID:        fmt.Sprintf("remediation_%d", time.Now().UnixNano()),
		Status:    "running",
		Progress:  0.0,
		StartedAt: time.Now(),
		Steps:     e.createEnhancedRemediationSteps(violation),
	}

	e.activeRemediations[status.ID] = status

	// Execute threat-specific remediation
	result, err := e.executeEnhancedRemediationByThreatType(ctx, violation, status)
	if err != nil {
		status.Status = "failed"
		status.Error = err.Error()
		now := time.Now()
		status.CompletedAt = &now
		return nil, err
	}

	status.Status = "completed"
	status.Progress = 1.0
	now := time.Now()
	status.CompletedAt = &now

	return result, nil
}

// executeEnhancedRemediationByThreatType executes remediation based on specific threat type
func (e *EnhancedRemediationEngine) executeEnhancedRemediationByThreatType(ctx context.Context, violation *auth.PolicyViolation, status *RemediationStatus) (*RemediationResult, error) {
	// Extract threat type from violation metadata
	threatType := e.extractThreatType(violation)

	switch threatType {
	case types.ThreatTypeTyposquatting:
		return e.executeTyposquattingRemediation(ctx, violation, status)
	case types.ThreatTypeMaliciousPackage, types.ThreatTypeMalicious:
		return e.executeMaliciousPackageRemediation(ctx, violation, status)
	case types.ThreatTypeVulnerable:
		return e.executeVulnerabilityRemediation(ctx, violation, status)
	case types.ThreatTypeDependencyConfusion:
		return e.executeDependencyConfusionRemediation(ctx, violation, status)
	case types.ThreatTypeSupplyChainRisk, types.ThreatTypeSupplyChain:
		return e.executeSupplyChainRemediation(ctx, violation, status)
	case types.ThreatTypeLowReputation, types.ThreatTypeReputationRisk:
		return e.executeReputationRemediation(ctx, violation, status)
	case types.ThreatTypeSuspicious:
		return e.executeSuspiciousPackageRemediation(ctx, violation, status)
	default:
		// Fall back to default remediation
		return e.DefaultRemediationEngine.executeRemediationByType(ctx, violation, status)
	}
}

// executeTyposquattingRemediation handles typosquatting threats
func (e *EnhancedRemediationEngine) executeTyposquattingRemediation(ctx context.Context, violation *auth.PolicyViolation, status *RemediationStatus) (*RemediationResult, error) {
	e.updateStepStatus(status, "analyze_typosquatting", "running")
	
	// Extract package information
	pkg := e.extractPackageFromViolation(violation)
	if pkg == nil {
		return nil, fmt.Errorf("could not extract package information")
	}

	// Find legitimate alternative
	e.updateStepStatus(status, "analyze_typosquatting", "completed")
	e.updateStepStatus(status, "find_legitimate_package", "running")
	status.Progress = 0.3

	legitimatePackage := e.findLegitimateAlternative(pkg)
	if legitimatePackage == "" {
		return nil, fmt.Errorf("could not find legitimate alternative for %s", pkg.Name)
	}

	e.updateStepStatus(status, "find_legitimate_package", "completed")
	e.updateStepStatus(status, "create_replacement_pr", "running")
	status.Progress = 0.6

	// Create pull request to replace with legitimate package
	prResult, err := e.createPackageReplacementPR(ctx, pkg, legitimatePackage, violation)
	if err != nil {
		return nil, fmt.Errorf("failed to create replacement PR: %w", err)
	}

	e.updateStepStatus(status, "create_replacement_pr", "completed")
	e.updateStepStatus(status, "notify_security_team", "running")
	status.Progress = 0.9

	// Notify security team
	notificationErr := e.notifySecurityTeam(ctx, violation, fmt.Sprintf("Typosquatting detected: %s should be replaced with %s. PR created: %s", pkg.Name, legitimatePackage, prResult.PRURL))
	if notificationErr != nil {
		// Log but don't fail the remediation
		fmt.Printf("Warning: failed to notify security team: %v\n", notificationErr)
	}

	e.updateStepStatus(status, "notify_security_team", "completed")
	status.Progress = 1.0

	return &RemediationResult{
		ID:          status.ID,
		Status:      "completed",
		Message:     fmt.Sprintf("Typosquatting remediation completed. Replacement PR created: %s", prResult.PRURL),
		Completed:   true,
		CompletedAt: time.Now(),
		Metadata: map[string]interface{}{
			"action_type":         "typosquatting_replacement",
			"malicious_package":   pkg.Name,
			"legitimate_package": legitimatePackage,
			"pr_url":             prResult.PRURL,
			"pr_number":          prResult.PRNumber,
		},
	}, nil
}

// executeMaliciousPackageRemediation handles malicious package threats
func (e *EnhancedRemediationEngine) executeMaliciousPackageRemediation(ctx context.Context, violation *auth.PolicyViolation, status *RemediationStatus) (*RemediationResult, error) {
	e.updateStepStatus(status, "quarantine_package", "running")
	
	pkg := e.extractPackageFromViolation(violation)
	if pkg == nil {
		return nil, fmt.Errorf("could not extract package information")
	}

	// Immediate quarantine
	err := e.quarantinePackage(ctx, pkg)
	if err != nil {
		return nil, fmt.Errorf("failed to quarantine package: %w", err)
	}

	e.updateStepStatus(status, "quarantine_package", "completed")
	e.updateStepStatus(status, "remove_from_dependencies", "running")
	status.Progress = 0.4

	// Create PR to remove malicious package
	prResult, err := e.createPackageRemovalPR(ctx, pkg, violation)
	if err != nil {
		return nil, fmt.Errorf("failed to create removal PR: %w", err)
	}

	e.updateStepStatus(status, "remove_from_dependencies", "completed")
	e.updateStepStatus(status, "alert_incident_response", "running")
	status.Progress = 0.8

	// Alert incident response team
	alertErr := e.alertIncidentResponse(ctx, violation, fmt.Sprintf("CRITICAL: Malicious package %s detected and quarantined. Removal PR: %s", pkg.Name, prResult.PRURL))
	if alertErr != nil {
		fmt.Printf("Warning: failed to alert incident response: %v\n", alertErr)
	}

	e.updateStepStatus(status, "alert_incident_response", "completed")
	status.Progress = 1.0

	return &RemediationResult{
		ID:          status.ID,
		Status:      "completed",
		Message:     fmt.Sprintf("Malicious package %s quarantined and removal PR created: %s", pkg.Name, prResult.PRURL),
		Completed:   true,
		CompletedAt: time.Now(),
		Metadata: map[string]interface{}{
			"action_type":       "malicious_package_removal",
			"malicious_package": pkg.Name,
			"quarantined":       true,
			"pr_url":           prResult.PRURL,
			"pr_number":        prResult.PRNumber,
		},
	}, nil
}

// executeVulnerabilityRemediation handles vulnerable package threats
func (e *EnhancedRemediationEngine) executeVulnerabilityRemediation(ctx context.Context, violation *auth.PolicyViolation, status *RemediationStatus) (*RemediationResult, error) {
	e.updateStepStatus(status, "analyze_vulnerability", "running")
	
	pkg := e.extractPackageFromViolation(violation)
	if pkg == nil {
		return nil, fmt.Errorf("could not extract package information")
	}

	// Find safe version
	safeVersionResult, err := e.dependencyUpdater.FindSafeVersion(ctx, pkg)
	if err != nil {
		return nil, fmt.Errorf("failed to find safe version: %w", err)
	}

	e.updateStepStatus(status, "analyze_vulnerability", "completed")
	e.updateStepStatus(status, "update_to_safe_version", "running")
	status.Progress = 0.5

	// Create PR to update to safe version
	prResult, err := e.createVersionUpdatePR(ctx, pkg, safeVersionResult.RecommendedVersion, violation)
	if err != nil {
		return nil, fmt.Errorf("failed to create update PR: %w", err)
	}

	e.updateStepStatus(status, "update_to_safe_version", "completed")
	e.updateStepStatus(status, "notify_development_team", "running")
	status.Progress = 0.9

	// Notify development team
	notificationErr := e.notifyDevelopmentTeam(ctx, violation, fmt.Sprintf("Vulnerability in %s v%s. Update PR created to v%s: %s", pkg.Name, pkg.Version, safeVersionResult.RecommendedVersion, prResult.PRURL))
	if notificationErr != nil {
		fmt.Printf("Warning: failed to notify development team: %v\n", notificationErr)
	}

	e.updateStepStatus(status, "notify_development_team", "completed")
	status.Progress = 1.0

	return &RemediationResult{
		ID:          status.ID,
		Status:      "completed",
		Message:     fmt.Sprintf("Vulnerability remediation completed. Update PR created: %s", prResult.PRURL),
		Completed:   true,
		CompletedAt: time.Now(),
		Metadata: map[string]interface{}{
			"action_type":          "vulnerability_update",
			"vulnerable_package":   pkg.Name,
			"current_version":      pkg.Version,
			"recommended_version":  safeVersionResult.RecommendedVersion,
			"pr_url":              prResult.PRURL,
			"pr_number":           prResult.PRNumber,
		},
	}, nil
}

// Helper methods

func (e *EnhancedRemediationEngine) extractThreatType(violation *auth.PolicyViolation) types.ThreatType {
	if violation.Metadata != nil {
		if threatType, ok := violation.Metadata["threat_type"].(string); ok {
			return types.ThreatType(threatType)
		}
	}
	return types.ThreatTypeSuspicious // default
}

func (e *EnhancedRemediationEngine) extractPackageFromViolation(violation *auth.PolicyViolation) *types.Package {
	if violation.Metadata == nil {
		return nil
	}
	
	name, _ := violation.Metadata["package_name"].(string)
	version, _ := violation.Metadata["package_version"].(string)
	registry, _ := violation.Metadata["package_registry"].(string)
	
	if name == "" {
		return nil
	}
	
	return &types.Package{
		Name:     name,
		Version:  version,
		Registry: registry,
	}
}

func (e *EnhancedRemediationEngine) findLegitimateAlternative(pkg *types.Package) string {
	// Simple heuristic - remove common typosquatting patterns
	name := pkg.Name
	
	// Common typosquatting patterns
	patterns := map[string]string{
		"expres":     "express",
		"lodas":      "lodash",
		"reqeust":    "request",
		"momnet":     "moment",
		"chalkk":     "chalk",
		"axios-":     "axios",
		"react-":     "react",
		"vue-":       "vue",
	}
	
	for typo, legitimate := range patterns {
		if strings.Contains(name, typo) {
			return legitimate
		}
	}
	
	// If no pattern match, return empty (manual review needed)
	return ""
}

func (e *EnhancedRemediationEngine) createPackageReplacementPR(ctx context.Context, maliciousPkg *types.Package, legitimatePkg string, violation *auth.PolicyViolation) (*PRResult, error) {
	// This would integrate with the actual PR generation system
	return &PRResult{
		PRNumber:   123,
		PRURL:      fmt.Sprintf("https://github.com/example/repo/pull/123"),
		BranchName: fmt.Sprintf("fix/replace-%s-with-%s", maliciousPkg.Name, legitimatePkg),
		Success:    true,
	}, nil
}

func (e *EnhancedRemediationEngine) createPackageRemovalPR(ctx context.Context, pkg *types.Package, violation *auth.PolicyViolation) (*PRResult, error) {
	return &PRResult{
		PRNumber:   124,
		PRURL:      fmt.Sprintf("https://github.com/example/repo/pull/124"),
		BranchName: fmt.Sprintf("security/remove-malicious-%s", pkg.Name),
		Success:    true,
	}, nil
}

func (e *EnhancedRemediationEngine) createVersionUpdatePR(ctx context.Context, pkg *types.Package, newVersion string, violation *auth.PolicyViolation) (*PRResult, error) {
	return &PRResult{
		PRNumber:   125,
		PRURL:      fmt.Sprintf("https://github.com/example/repo/pull/125"),
		BranchName: fmt.Sprintf("security/update-%s-to-%s", pkg.Name, newVersion),
		Success:    true,
	}, nil
}

func (e *EnhancedRemediationEngine) quarantinePackage(ctx context.Context, pkg *types.Package) error {
	// Implementation would integrate with package management systems
	fmt.Printf("Quarantining package: %s@%s\n", pkg.Name, pkg.Version)
	return nil
}

func (e *EnhancedRemediationEngine) notifySecurityTeam(ctx context.Context, violation *auth.PolicyViolation, message string) error {
	// Implementation would integrate with notification systems
	fmt.Printf("Security team notification: %s\n", message)
	return nil
}

func (e *EnhancedRemediationEngine) alertIncidentResponse(ctx context.Context, violation *auth.PolicyViolation, message string) error {
	// Implementation would integrate with incident response systems
	fmt.Printf("Incident response alert: %s\n", message)
	return nil
}

func (e *EnhancedRemediationEngine) notifyDevelopmentTeam(ctx context.Context, violation *auth.PolicyViolation, message string) error {
	// Implementation would integrate with development team notification systems
	fmt.Printf("Development team notification: %s\n", message)
	return nil
}

func (e *EnhancedRemediationEngine) createEnhancedRemediationSteps(violation *auth.PolicyViolation) []RemediationStep {
	threatType := e.extractThreatType(violation)
	
	switch threatType {
	case types.ThreatTypeTyposquatting:
		return []RemediationStep{
			{ID: "analyze_typosquatting", Name: "Analyze Typosquatting", Description: "Analyze the typosquatting threat", Status: "pending"},
			{ID: "find_legitimate_package", Name: "Find Legitimate Package", Description: "Identify the legitimate alternative", Status: "pending"},
			{ID: "create_replacement_pr", Name: "Create Replacement PR", Description: "Create pull request to replace with legitimate package", Status: "pending"},
			{ID: "notify_security_team", Name: "Notify Security Team", Description: "Alert security team of the remediation", Status: "pending"},
		}
	case types.ThreatTypeMaliciousPackage, types.ThreatTypeMalicious:
		return []RemediationStep{
			{ID: "quarantine_package", Name: "Quarantine Package", Description: "Immediately quarantine the malicious package", Status: "pending"},
			{ID: "remove_from_dependencies", Name: "Remove Dependencies", Description: "Create PR to remove malicious package", Status: "pending"},
			{ID: "alert_incident_response", Name: "Alert Incident Response", Description: "Alert incident response team", Status: "pending"},
		}
	case types.ThreatTypeVulnerable:
		return []RemediationStep{
			{ID: "analyze_vulnerability", Name: "Analyze Vulnerability", Description: "Analyze the vulnerability and find safe version", Status: "pending"},
			{ID: "update_to_safe_version", Name: "Update to Safe Version", Description: "Create PR to update to safe version", Status: "pending"},
			{ID: "notify_development_team", Name: "Notify Development Team", Description: "Alert development team of the update", Status: "pending"},
		}
	default:
		return e.DefaultRemediationEngine.createRemediationSteps(violation.Remediation)
	}
}

// Additional remediation methods for other threat types

func (e *EnhancedRemediationEngine) executeDependencyConfusionRemediation(ctx context.Context, violation *auth.PolicyViolation, status *RemediationStatus) (*RemediationResult, error) {
	// Implementation for dependency confusion attacks
	return e.executeTyposquattingRemediation(ctx, violation, status) // Similar approach
}

func (e *EnhancedRemediationEngine) executeSupplyChainRemediation(ctx context.Context, violation *auth.PolicyViolation, status *RemediationStatus) (*RemediationResult, error) {
	// Implementation for supply chain risks
	return e.executeVulnerabilityRemediation(ctx, violation, status) // Similar approach
}

func (e *EnhancedRemediationEngine) executeReputationRemediation(ctx context.Context, violation *auth.PolicyViolation, status *RemediationStatus) (*RemediationResult, error) {
	// Implementation for reputation-based risks
	return e.executeSuspiciousPackageRemediation(ctx, violation, status)
}

func (e *EnhancedRemediationEngine) executeSuspiciousPackageRemediation(ctx context.Context, violation *auth.PolicyViolation, status *RemediationStatus) (*RemediationResult, error) {
	e.updateStepStatus(status, "review_package", "running")
	
	pkg := e.extractPackageFromViolation(violation)
	if pkg == nil {
		return nil, fmt.Errorf("could not extract package information")
	}

	// Flag for manual review
	e.updateStepStatus(status, "review_package", "completed")
	e.updateStepStatus(status, "create_review_ticket", "running")
	status.Progress = 0.5

	// Create review ticket/issue
	ticketResult, err := e.createReviewTicket(ctx, pkg, violation)
	if err != nil {
		return nil, fmt.Errorf("failed to create review ticket: %w", err)
	}

	e.updateStepStatus(status, "create_review_ticket", "completed")
	e.updateStepStatus(status, "notify_security_team", "running")
	status.Progress = 0.9

	// Notify security team for manual review
	notificationErr := e.notifySecurityTeam(ctx, violation, fmt.Sprintf("Suspicious package %s flagged for manual review. Ticket: %s", pkg.Name, ticketResult))
	if notificationErr != nil {
		fmt.Printf("Warning: failed to notify security team: %v\n", notificationErr)
	}

	e.updateStepStatus(status, "notify_security_team", "completed")
	status.Progress = 1.0

	return &RemediationResult{
		ID:          status.ID,
		Status:      "completed",
		Message:     fmt.Sprintf("Suspicious package %s flagged for manual review. Ticket: %s", pkg.Name, ticketResult),
		Completed:   true,
		CompletedAt: time.Now(),
		Metadata: map[string]interface{}{
			"action_type":        "manual_review",
			"suspicious_package": pkg.Name,
			"review_ticket":      ticketResult,
		},
	}, nil
}

func (e *EnhancedRemediationEngine) createReviewTicket(ctx context.Context, pkg *types.Package, violation *auth.PolicyViolation) (string, error) {
	// Implementation would integrate with ticketing systems
	ticketID := fmt.Sprintf("SECURITY-%d", time.Now().Unix())
	fmt.Printf("Created review ticket %s for package %s\n", ticketID, pkg.Name)
	return ticketID, nil
}