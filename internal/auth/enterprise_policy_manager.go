package auth

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// EnterprisePolicyManager manages enterprise-level security policies
type EnterprisePolicyManager struct {
	policyEngine *PolicyEngine
	rbacEngine   *RBACEngine
	logger       Logger
	mu           sync.RWMutex

	// Policy templates for common enterprise scenarios
	templates map[string]*SecurityPolicy

	// Active enforcement rules
	enforcement *PolicyEnforcement
}

// PolicyEnforcement manages policy enforcement settings
type PolicyEnforcement struct {
	Enabled              bool                       `json:"enabled"`
	StrictMode           bool                       `json:"strict_mode"`           // Block on any policy violation
	GracePeriod          time.Duration              `json:"grace_period"`          // Grace period for new policies
	NotificationChannels []NotificationChannel      `json:"notification_channels"`
	ApprovalWorkflows    map[string]ApprovalWorkflow `json:"approval_workflows"`
	AuditSettings        AuditSettings              `json:"audit_settings"`
}

// NotificationChannel represents a notification channel
type NotificationChannel struct {
	Type     string            `json:"type"`     // email, slack, webhook, teams
	Enabled  bool              `json:"enabled"`
	Settings map[string]string `json:"settings"`
}

// ApprovalWorkflow defines approval requirements for policy actions
type ApprovalWorkflow struct {
	Required         bool     `json:"required"`
	MinApprovers     int      `json:"min_approvers"`
	RequiredRoles    []string `json:"required_roles"`
	TimeoutDuration  time.Duration `json:"timeout_duration"`
	EscalationRoles  []string `json:"escalation_roles"`
	AutoApproveRoles []string `json:"auto_approve_roles"`
}

// AuditSettings defines audit logging settings
type AuditSettings struct {
	Enabled           bool          `json:"enabled"`
	LogAllEvaluations bool          `json:"log_all_evaluations"`
	RetentionPeriod   time.Duration `json:"retention_period"`
	ExportEnabled     bool          `json:"export_enabled"`
	ExportFormat      string        `json:"export_format"` // json, csv, siem
}

// PolicyViolation represents a policy violation
type PolicyViolation struct {
	ID               string                     `json:"id"`
	PolicyID         string                     `json:"policy_id"`
	PolicyName       string                     `json:"policy_name"`
	Severity         string                     `json:"severity"`
	Description      string                     `json:"description"`
	Context          *PolicyEvaluationContext   `json:"context"`
	Result           *PolicyEvaluationResult    `json:"result"`
	Status           ViolationStatus            `json:"status"`
	ApprovalRequired bool                       `json:"approval_required"`
	Approvals        []PolicyApproval           `json:"approvals"`
	Remediation      *RemediationAction         `json:"remediation"`
	CreatedAt        time.Time                  `json:"created_at"`
	ResolvedAt       *time.Time                 `json:"resolved_at"`
	Metadata         map[string]interface{}     `json:"metadata"`
}

// ViolationStatus represents the status of a policy violation
type ViolationStatus string

const (
	ViolationStatusOpen       ViolationStatus = "open"
	ViolationStatusPending    ViolationStatus = "pending_approval"
	ViolationStatusApproved   ViolationStatus = "approved"
	ViolationStatusRejected   ViolationStatus = "rejected"
	ViolationStatusRemediated ViolationStatus = "remediated"
	ViolationStatusIgnored    ViolationStatus = "ignored"
)

// PolicyApproval represents an approval for a policy violation
type PolicyApproval struct {
	ID          string    `json:"id"`
	ApproverID  string    `json:"approver_id"`
	Approver    string    `json:"approver"`
	Decision    string    `json:"decision"` // approved, rejected
	Reason      string    `json:"reason"`
	ApprovedAt  time.Time `json:"approved_at"`
	ExpiresAt   *time.Time `json:"expires_at"`
}

// RemediationAction represents an action to remediate a policy violation
type RemediationAction struct {
	Type        string                 `json:"type"`        // block, quarantine, notify, manual
	Status      string                 `json:"status"`      // pending, in_progress, completed, failed
	Description string                 `json:"description"`
	Actions     []string               `json:"actions"`
	AssignedTo  string                 `json:"assigned_to"`
	DueDate     *time.Time             `json:"due_date"`
	CompletedAt *time.Time             `json:"completed_at"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// NewEnterprisePolicyManager creates a new enterprise policy manager
func NewEnterprisePolicyManager(policyEngine *PolicyEngine, rbacEngine *RBACEngine, logger Logger) *EnterprisePolicyManager {
	epm := &EnterprisePolicyManager{
		policyEngine: policyEngine,
		rbacEngine:   rbacEngine,
		logger:       logger,
		templates:    make(map[string]*SecurityPolicy),
		enforcement: &PolicyEnforcement{
			Enabled:              true,
			StrictMode:           false,
			GracePeriod:          24 * time.Hour,
			NotificationChannels: []NotificationChannel{},
			ApprovalWorkflows:    make(map[string]ApprovalWorkflow),
			AuditSettings: AuditSettings{
				Enabled:           true,
				LogAllEvaluations: false,
				RetentionPeriod:   90 * 24 * time.Hour,
				ExportEnabled:     false,
				ExportFormat:      "json",
			},
		},
	}

	// Initialize default policy templates
	epm.initializeDefaultTemplates()

	return epm
}

// initializeDefaultTemplates creates default enterprise policy templates
func (epm *EnterprisePolicyManager) initializeDefaultTemplates() {
	// Block Critical Threats Policy
	blockCritical := &SecurityPolicy{
		ID:          "block-critical-threats",
		Name:        "Block Critical Threats",
		Description: "Automatically block packages with critical security threats",
		Enabled:     true,
		Priority:    100,
		Conditions: []PolicyCondition{
			{
				Field:    "threat.severity",
				Operator: "==",
				Value:    "critical",
			},
		},
		Action: PolicyActionBlock,
		Parameters: map[string]string{
			"block_deployment": "true",
			"notify_security": "true",
		},
		Notifications: []string{"security-team@company.com"},
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	// Require Approval for High Risk Policy
	requireApprovalHigh := &SecurityPolicy{
		ID:          "require-approval-high-risk",
		Name:        "Require Approval for High Risk Packages",
		Description: "Require security team approval for high-risk packages",
		Enabled:     true,
		Priority:    90,
		Conditions: []PolicyCondition{
			{
				Field:    "threat.severity",
				Operator: "==",
				Value:    "high",
			},
		},
		Action: PolicyActionRequireApproval,
		Parameters: map[string]string{
			"approval_timeout": "48h",
			"escalation_time": "24h",
		},
		Approvers: []string{"security_admin", "security_analyst"},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Production Environment Restrictions
	prodRestrictions := &SecurityPolicy{
		ID:          "production-restrictions",
		Name:        "Production Environment Restrictions",
		Description: "Enhanced security checks for production deployments",
		Enabled:     true,
		Priority:    95,
		Conditions: []PolicyCondition{
			{
				Field:    "environment",
				Operator: "==",
				Value:    "production",
			},
			{
				Field:    "threat.severity",
				Operator: "in",
				Value:    []string{"medium", "high", "critical"},
			},
		},
		Action: PolicyActionRequireApproval,
		Parameters: map[string]string{
			"require_spdx": "true",
			"enhanced_scanning": "true",
		},
		Approvers: []string{"security_admin"},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Low Reputation Package Policy
	lowReputation := &SecurityPolicy{
		ID:          "low-reputation-warning",
		Name:        "Low Reputation Package Warning",
		Description: "Warn about packages with low reputation scores",
		Enabled:     true,
		Priority:    50,
		Conditions: []PolicyCondition{
			{
				Field:    "package.downloads",
				Operator: "<",
				Value:    1000,
			},
			{
				Field:    "package.age",
				Operator: "<",
				Value:    30, // days
			},
		},
		Action: PolicyActionNotify,
		Parameters: map[string]string{
			"warning_level": "medium",
			"require_review": "true",
		},
		Notifications: []string{"dev-team@company.com"},
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	epm.templates["block-critical-threats"] = blockCritical
	epm.templates["require-approval-high-risk"] = requireApprovalHigh
	epm.templates["production-restrictions"] = prodRestrictions
	epm.templates["low-reputation-warning"] = lowReputation
}

// EvaluateAndEnforce evaluates policies and enforces them based on configuration
func (epm *EnterprisePolicyManager) EvaluateAndEnforce(ctx context.Context, evalCtx *PolicyEvaluationContext) (*EnforcementResult, error) {
	epm.mu.RLock()
	enforcement := epm.enforcement
	epm.mu.RUnlock()

	if !enforcement.Enabled {
		return &EnforcementResult{
			Allowed: true,
			Reason:  "Policy enforcement disabled",
		}, nil
	}

	// Evaluate policies
	results, err := epm.policyEngine.EvaluatePolicies(ctx, evalCtx)
	if err != nil {
		return nil, fmt.Errorf("policy evaluation failed: %w", err)
	}

	// Process results and determine enforcement action
	enforcementResult := &EnforcementResult{
		Allowed:         true,
		PolicyResults:   results,
		Violations:      []PolicyViolation{},
		RequiredActions: []string{},
		EvaluatedAt:     time.Now(),
	}

	for _, result := range results {
		if result.Triggered {
			violation := epm.createViolation(result, evalCtx)
			enforcementResult.Violations = append(enforcementResult.Violations, *violation)

			// Determine enforcement action
			switch result.Action {
			case PolicyActionBlock, PolicyActionDeny:
				enforcementResult.Allowed = false
				enforcementResult.Reason = fmt.Sprintf("Blocked by policy: %s", result.PolicyName)
				enforcementResult.RequiredActions = append(enforcementResult.RequiredActions, "block_deployment")

			case PolicyActionRequireApproval:
				if !epm.hasValidApproval(violation, evalCtx.User) {
					enforcementResult.Allowed = false
					enforcementResult.Reason = fmt.Sprintf("Approval required for policy: %s", result.PolicyName)
					enforcementResult.RequiredActions = append(enforcementResult.RequiredActions, "require_approval")
				}

			case PolicyActionQuarantine:
				enforcementResult.RequiredActions = append(enforcementResult.RequiredActions, "quarantine")

			case PolicyActionNotify:
				enforcementResult.RequiredActions = append(enforcementResult.RequiredActions, "notify")

			case PolicyActionGenerateSPDX:
				enforcementResult.RequiredActions = append(enforcementResult.RequiredActions, "generate_spdx")
			}

			// In strict mode, any violation blocks the action
			if enforcement.StrictMode && result.Action != PolicyActionLog {
				enforcementResult.Allowed = false
				if enforcementResult.Reason == "" {
					enforcementResult.Reason = fmt.Sprintf("Strict mode violation: %s", result.PolicyName)
				}
			}
		}
	}

	// Log audit trail if enabled
	if enforcement.AuditSettings.Enabled {
		epm.logAuditTrail(ctx, evalCtx, enforcementResult)
	}

	// Send notifications if required
	if len(enforcementResult.Violations) > 0 {
		epm.sendNotifications(ctx, enforcementResult)
	}

	return enforcementResult, nil
}

// EnforcementResult represents the result of policy enforcement
type EnforcementResult struct {
	Allowed         bool                      `json:"allowed"`
	Reason          string                    `json:"reason"`
	PolicyResults   []*PolicyEvaluationResult `json:"policy_results"`
	Violations      []PolicyViolation         `json:"violations"`
	RequiredActions []string                  `json:"required_actions"`
	ApprovalURL     string                    `json:"approval_url,omitempty"`
	EvaluatedAt     time.Time                 `json:"evaluated_at"`
	Metadata        map[string]interface{}    `json:"metadata"`
}

// createViolation creates a policy violation from evaluation result
func (epm *EnterprisePolicyManager) createViolation(result *PolicyEvaluationResult, evalCtx *PolicyEvaluationContext) *PolicyViolation {
	violation := &PolicyViolation{
		ID:               fmt.Sprintf("violation-%d", time.Now().UnixNano()),
		PolicyID:         result.PolicyID,
		PolicyName:       result.PolicyName,
		Severity:         epm.determineSeverity(result.Action),
		Description:      result.Reason,
		Context:          evalCtx,
		Result:           result,
		Status:           ViolationStatusOpen,
		ApprovalRequired: result.Action == PolicyActionRequireApproval,
		Approvals:        []PolicyApproval{},
		CreatedAt:        time.Now(),
		Metadata:         make(map[string]interface{}),
	}

	// Set remediation action based on policy action
	violation.Remediation = &RemediationAction{
		Type:        string(result.Action),
		Status:      "pending",
		Description: fmt.Sprintf("Remediation required for policy violation: %s", result.PolicyName),
		Actions:     []string{string(result.Action)},
		Metadata:    make(map[string]interface{}),
	}

	return violation
}

// determineSeverity determines violation severity based on policy action
func (epm *EnterprisePolicyManager) determineSeverity(action PolicyAction) string {
	switch action {
	case PolicyActionBlock, PolicyActionDeny:
		return "critical"
	case PolicyActionRequireApproval:
		return "high"
	case PolicyActionQuarantine:
		return "medium"
	case PolicyActionNotify:
		return "low"
	default:
		return "info"
	}
}

// hasValidApproval checks if a violation has valid approval
func (epm *EnterprisePolicyManager) hasValidApproval(violation *PolicyViolation, user *User) bool {
	// Check if user has auto-approve role
	workflow, exists := epm.enforcement.ApprovalWorkflows[violation.PolicyID]
	if exists {
		for _, _ = range workflow.AutoApproveRoles {
			if epm.rbacEngine.CheckPermission(context.Background(), &User{ID: user.ID}, Permission("policy:auto_approve")) {
				return true
			}
		}
	}

	// Check existing approvals
	validApprovals := 0
	for _, approval := range violation.Approvals {
		if approval.Decision == "approved" {
			// Check if approval is not expired
			if approval.ExpiresAt == nil || time.Now().Before(*approval.ExpiresAt) {
				validApprovals++
			}
		}
	}

	if exists && validApprovals >= workflow.MinApprovers {
		return true
	}

	return false
}

// logAuditTrail logs policy evaluation for audit purposes
func (epm *EnterprisePolicyManager) logAuditTrail(ctx context.Context, evalCtx *PolicyEvaluationContext, result *EnforcementResult) {
	if epm.logger != nil {
		auditData := map[string]interface{}{
			"user_id":         evalCtx.User.ID,
			"environment":     evalCtx.Environment,
			"allowed":         result.Allowed,
			"violations":      len(result.Violations),
			"required_actions": result.RequiredActions,
			"timestamp":       result.EvaluatedAt,
		}

		if evalCtx.Package != nil {
			auditData["package_name"] = evalCtx.Package.Name
			auditData["package_version"] = evalCtx.Package.Version
		}

		if evalCtx.Repository != nil {
			auditData["repository"] = evalCtx.Repository.Name
			auditData["repository_owner"] = evalCtx.Repository.Owner
		}

		epm.logger.Info("Policy enforcement audit", "audit_data", auditData)
	}
}

// sendNotifications sends notifications for policy violations
func (epm *EnterprisePolicyManager) sendNotifications(ctx context.Context, result *EnforcementResult) {
	// Implementation would integrate with notification systems
	// For now, just log the notification requirement
	if epm.logger != nil {
		for _, violation := range result.Violations {
			epm.logger.Info("Policy violation notification", 
				"violation_id", violation.ID,
				"policy_name", violation.PolicyName,
				"severity", violation.Severity)
		}
	}
}

// GetPolicyTemplate retrieves a policy template by ID
func (epm *EnterprisePolicyManager) GetPolicyTemplate(templateID string) (*SecurityPolicy, error) {
	epm.mu.RLock()
	defer epm.mu.RUnlock()

	template, exists := epm.templates[templateID]
	if !exists {
		return nil, fmt.Errorf("policy template not found: %s", templateID)
	}

	return template, nil
}

// ListPolicyTemplates returns all available policy templates
func (epm *EnterprisePolicyManager) ListPolicyTemplates() []*SecurityPolicy {
	epm.mu.RLock()
	defer epm.mu.RUnlock()

	templates := make([]*SecurityPolicy, 0, len(epm.templates))
	for _, template := range epm.templates {
		templates = append(templates, template)
	}

	return templates
}

// CreatePolicyFromTemplate creates a new policy from a template
func (epm *EnterprisePolicyManager) CreatePolicyFromTemplate(templateID, policyID string, customizations map[string]interface{}) (*SecurityPolicy, error) {
	template, err := epm.GetPolicyTemplate(templateID)
	if err != nil {
		return nil, err
	}

	// Create a copy of the template
	newPolicy := *template
	newPolicy.ID = policyID
	newPolicy.CreatedAt = time.Now()
	newPolicy.UpdatedAt = time.Now()

	// Apply customizations
	if name, ok := customizations["name"].(string); ok {
		newPolicy.Name = name
	}
	if description, ok := customizations["description"].(string); ok {
		newPolicy.Description = description
	}
	if enabled, ok := customizations["enabled"].(bool); ok {
		newPolicy.Enabled = enabled
	}
	if priority, ok := customizations["priority"].(int); ok {
		newPolicy.Priority = priority
	}

	// Add the policy to the engine
	err = epm.policyEngine.AddPolicy(&newPolicy)
	if err != nil {
		return nil, fmt.Errorf("failed to add policy: %w", err)
	}

	return &newPolicy, nil
}

// UpdateEnforcementSettings updates policy enforcement settings
func (epm *EnterprisePolicyManager) UpdateEnforcementSettings(settings *PolicyEnforcement) error {
	epm.mu.Lock()
	defer epm.mu.Unlock()

	epm.enforcement = settings

	if epm.logger != nil {
		epm.logger.Info("Policy enforcement settings updated", 
			"enabled", settings.Enabled,
			"strict_mode", settings.StrictMode)
	}

	return nil
}

// GetEnforcementSettings returns current enforcement settings
func (epm *EnterprisePolicyManager) GetEnforcementSettings() *PolicyEnforcement {
	epm.mu.RLock()
	defer epm.mu.RUnlock()
	return epm.enforcement
}

// Policy management methods that delegate to the policy engine
func (epm *EnterprisePolicyManager) ListPolicies() []*SecurityPolicy {
	return epm.policyEngine.ListPolicies()
}

func (epm *EnterprisePolicyManager) AddPolicy(policy *SecurityPolicy) {
	epm.policyEngine.AddPolicy(policy)
}

func (epm *EnterprisePolicyManager) GetPolicy(policyID string) (*SecurityPolicy, error) {
	return epm.policyEngine.GetPolicy(policyID)
}

func (epm *EnterprisePolicyManager) RemovePolicy(policyID string) {
	epm.policyEngine.RemovePolicy(policyID)
}