// Package supplychain implements supply chain security policies and enforcement
package supplychain

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/edge"
	"github.com/Alivanroy/Typosentinel/internal/security"
	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// PolicyAction represents the action to take when a policy is triggered
type PolicyAction string

const (
	ActionBlock  PolicyAction = "BLOCK"
	ActionAlert  PolicyAction = "ALERT"
	ActionReview PolicyAction = "REVIEW"
	ActionAllow  PolicyAction = "ALLOW"
	ActionLog    PolicyAction = "LOG"
)

// SupplyChainPolicy represents a supply chain security policy
type SupplyChainPolicy struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Enabled     bool                   `json:"enabled"`
	Priority    int                    `json:"priority"`
	Conditions  []PolicyCondition      `json:"conditions"`
	Actions     []PolicyAction         `json:"actions"`
	Metadata    map[string]interface{} `json:"metadata"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

// PolicyCondition represents a condition that triggers a policy
type PolicyCondition struct {
	Field       string      `json:"field"`
	Operator    string      `json:"operator"`
	Value       interface{} `json:"value"`
	Type        string      `json:"type"`
	Description string      `json:"description"`
}

// SupplyChainPolicyContext provides context for policy evaluation
type SupplyChainPolicyContext struct {
	Package          *types.Package
	BusinessRisk     float64
	AssetCriticality edge.AssetCriticality
	DependencyDepth  int
	IsDirect         bool
	Registry         string
	Timestamp        time.Time
	Metadata         map[string]interface{}
}

// PolicyEvaluationResult represents the result of policy evaluation
type PolicyEvaluationResult struct {
	PolicyID   string                 `json:"policy_id"`
	PolicyName string                 `json:"policy_name"`
	Triggered  bool                   `json:"triggered"`
	Action     PolicyAction           `json:"action"`
	Reason     string                 `json:"reason"`
	Details    map[string]interface{} `json:"details"`
	Timestamp  time.Time              `json:"timestamp"`
}

// PolicyEngine manages supply chain security policies
type PolicyEngine struct {
	policies    map[string]*SupplyChainPolicy
	dirt        *edge.DIRTAlgorithm
	auditLogger *security.AuditLogger
	mu          sync.RWMutex
}

// NewPolicyEngine creates a new supply chain policy engine
func NewPolicyEngine(dirt *edge.DIRTAlgorithm, auditLogger *security.AuditLogger) *PolicyEngine {
	engine := &PolicyEngine{
		policies:    make(map[string]*SupplyChainPolicy),
		dirt:        dirt,
		auditLogger: auditLogger,
	}

	// Load default policies
	engine.loadDefaultPolicies()

	return engine
}

// loadDefaultPolicies loads the 5 default supply chain security policies
func (pe *PolicyEngine) loadDefaultPolicies() {
	policies := []*SupplyChainPolicy{
		{
			ID:          "block-critical-risk",
			Name:        "Block Critical Risk Packages",
			Description: "Automatically block packages with critical business risk scores",
			Enabled:     true,
			Priority:    1,
			Conditions: []PolicyCondition{
				{
					Field:       "BusinessRisk",
					Operator:    ">=",
					Value:       0.9,
					Type:        "risk_threshold",
					Description: "Business risk score >= 0.9",
				},
			},
			Actions: []PolicyAction{ActionBlock},
			Metadata: map[string]interface{}{
				"category":    "risk_blocking",
				"severity":    "critical",
				"auto_action": true,
			},
		},
		{
			ID:          "alert-typosquatting",
			Name:        "Alert on Typosquatting Detection",
			Description: "Alert security team when typosquatting is detected",
			Enabled:     true,
			Priority:    2,
			Conditions: []PolicyCondition{
				{
					Field:       "Package.Threats.Type",
					Operator:    "contains",
					Value:       "typosquatting",
					Type:        "threat_type",
					Description: "Package contains typosquatting threats",
				},
			},
			Actions: []PolicyAction{ActionAlert, ActionLog},
			Metadata: map[string]interface{}{
				"category": "threat_detection",
				"severity": "high",
			},
		},
		{
			ID:          "require-signatures",
			Name:        "Require Package Signatures",
			Description: "Block packages without valid cryptographic signatures",
			Enabled:     true,
			Priority:    3,
			Conditions: []PolicyCondition{
				{
					Field:       "Package.Metadata.Checksums",
					Operator:    "empty",
					Value:       nil,
					Type:        "integrity_check",
					Description: "Package lacks checksums/signatures",
				},
			},
			Actions: []PolicyAction{ActionBlock},
			Metadata: map[string]interface{}{
				"category":    "integrity",
				"severity":    "medium",
				"auto_action": true,
			},
		},
		{
			ID:          "review-unmaintained",
			Name:        "Review Unmaintained Packages",
			Description: "Flag packages that haven't been updated in over a year",
			Enabled:     true,
			Priority:    4,
			Conditions: []PolicyCondition{
				{
					Field:       "Package.Metadata.LastUpdated",
					Operator:    "older_than",
					Value:       "365d",
					Type:        "maintenance_check",
					Description: "Package not updated in over 365 days",
				},
			},
			Actions: []PolicyAction{ActionReview, ActionLog},
			Metadata: map[string]interface{}{
				"category": "maintenance",
				"severity": "medium",
			},
		},
		{
			ID:          "block-critical-vulns",
			Name:        "Block Critical Vulnerabilities",
			Description: "Block packages with critical security vulnerabilities",
			Enabled:     true,
			Priority:    5,
			Conditions: []PolicyCondition{
				{
					Field:       "Package.Threats.Severity",
					Operator:    "contains",
					Value:       "critical",
					Type:        "vulnerability_severity",
					Description: "Package contains critical vulnerabilities",
				},
			},
			Actions: []PolicyAction{ActionBlock, ActionAlert},
			Metadata: map[string]interface{}{
				"category":    "vulnerability",
				"severity":    "critical",
				"auto_action": true,
			},
		},
	}

	for _, policy := range policies {
		policy.CreatedAt = time.Now()
		policy.UpdatedAt = time.Now()
		pe.policies[policy.ID] = policy
	}
}

// AddPolicy adds a new supply chain policy
func (pe *PolicyEngine) AddPolicy(policy *SupplyChainPolicy) error {
	pe.mu.Lock()
	defer pe.mu.Unlock()

	if policy.ID == "" {
		return fmt.Errorf("policy ID is required")
	}

	policy.CreatedAt = time.Now()
	policy.UpdatedAt = time.Now()

	pe.policies[policy.ID] = policy

	// Log policy addition
	if pe.auditLogger != nil {
		pe.auditLogger.LogSystemEvent("SUPPLY_CHAIN_POLICY", "ADD_POLICY",
			fmt.Sprintf("Added supply chain policy: %s", policy.Name),
			map[string]interface{}{
				"policy_id":   policy.ID,
				"policy_name": policy.Name,
			})
	}

	return nil
}

// EvaluatePolicies evaluates all enabled policies against the given context
func (pe *PolicyEngine) EvaluatePolicies(ctx *SupplyChainPolicyContext) ([]PolicyEvaluationResult, error) {
	pe.mu.RLock()
	defer pe.mu.RUnlock()

	var results []PolicyEvaluationResult

	// First, perform DIRT analysis if we have a package
	if ctx.Package != nil && pe.dirt != nil {
		assessment, err := pe.dirt.AnalyzeWithCriticality(context.Background(), ctx.Package, ctx.AssetCriticality)
		if err != nil {
			return nil, fmt.Errorf("failed to analyze package with DIRT: %w", err)
		}
		ctx.BusinessRisk = assessment.BusinessRisk
	}

	// Evaluate each enabled policy
	for _, policy := range pe.policies {
		if !policy.Enabled {
			continue
		}

		result := pe.evaluatePolicy(policy, ctx)
		results = append(results, result)

		// Log policy evaluation
		if pe.auditLogger != nil && result.Triggered {
			pe.auditLogger.LogSystemEvent("SUPPLY_CHAIN_POLICY", "POLICY_TRIGGERED",
				fmt.Sprintf("Policy %s triggered for package %s", policy.Name, ctx.Package.Name),
				map[string]interface{}{
					"policy_id":  policy.ID,
					"package":    ctx.Package.Name,
					"action":     result.Action,
					"risk_score": ctx.BusinessRisk,
				})
		}
	}

	return results, nil
}

// evaluatePolicy evaluates a single policy against the context
func (pe *PolicyEngine) evaluatePolicy(policy *SupplyChainPolicy, ctx *SupplyChainPolicyContext) PolicyEvaluationResult {
	result := PolicyEvaluationResult{
		PolicyID:   policy.ID,
		PolicyName: policy.Name,
		Triggered:  false,
		Action:     ActionAllow,
		Timestamp:  time.Now(),
		Details:    make(map[string]interface{}),
	}

	// Check if all conditions are met
	allConditionsMet := true
	triggeredConditions := []string{}

	for _, condition := range policy.Conditions {
		conditionMet := pe.evaluateCondition(condition, ctx)
		if !conditionMet {
			allConditionsMet = false
		} else {
			triggeredConditions = append(triggeredConditions, condition.Description)
		}
	}

	if allConditionsMet && len(policy.Conditions) > 0 {
		result.Triggered = true
		result.Action = policy.Actions[0] // Take the first action
		result.Reason = fmt.Sprintf("Policy conditions met: %v", triggeredConditions)
		result.Details["triggered_conditions"] = triggeredConditions
		result.Details["policy_metadata"] = policy.Metadata
	}

	return result
}

// evaluateCondition evaluates a single condition against the context
func (pe *PolicyEngine) evaluateCondition(condition PolicyCondition, ctx *SupplyChainPolicyContext) bool {
	switch condition.Field {
	case "BusinessRisk":
		return pe.evaluateRiskCondition(condition, ctx.BusinessRisk)
	case "Package.Threats.Type":
		return pe.evaluateThreatTypeCondition(condition, ctx.Package)
	case "Package.Threats.Severity":
		return pe.evaluateThreatSeverityCondition(condition, ctx.Package)
	case "Package.Metadata.Checksums":
		return pe.evaluateChecksumCondition(condition, ctx.Package)
	case "Package.Metadata.LastUpdated":
		return pe.evaluateMaintenanceCondition(condition, ctx.Package)
	case "AssetCriticality":
		return pe.evaluateCriticalityCondition(condition, ctx.AssetCriticality)
	default:
		return false
	}
}

// evaluateRiskCondition evaluates risk-based conditions
func (pe *PolicyEngine) evaluateRiskCondition(condition PolicyCondition, businessRisk float64) bool {
	switch condition.Operator {
	case ">=":
		return businessRisk >= condition.Value.(float64)
	case ">":
		return businessRisk > condition.Value.(float64)
	case "<=":
		return businessRisk <= condition.Value.(float64)
	case "<":
		return businessRisk < condition.Value.(float64)
	case "==":
		return businessRisk == condition.Value.(float64)
	default:
		return false
	}
}

// evaluateThreatTypeCondition evaluates threat type conditions
func (pe *PolicyEngine) evaluateThreatTypeCondition(condition PolicyCondition, pkg *types.Package) bool {
	if pkg == nil {
		return false
	}

	for _, threat := range pkg.Threats {
		if string(threat.Type) == condition.Value.(string) {
			return true
		}
	}
	return false
}

// evaluateThreatSeverityCondition evaluates threat severity conditions
func (pe *PolicyEngine) evaluateThreatSeverityCondition(condition PolicyCondition, pkg *types.Package) bool {
	if pkg == nil {
		return false
	}

	for _, threat := range pkg.Threats {
		if threat.Severity.String() == condition.Value.(string) {
			return true
		}
	}
	return false
}

// evaluateChecksumCondition evaluates package integrity conditions
func (pe *PolicyEngine) evaluateChecksumCondition(condition PolicyCondition, pkg *types.Package) bool {
	if pkg == nil || pkg.Metadata == nil {
		return condition.Operator == "empty"
	}

	hasChecksums := pkg.Metadata.Checksums != nil && len(pkg.Metadata.Checksums) > 0

	switch condition.Operator {
	case "empty":
		return !hasChecksums
	case "not_empty":
		return hasChecksums
	default:
		return false
	}
}

// evaluateMaintenanceCondition evaluates package maintenance conditions
func (pe *PolicyEngine) evaluateMaintenanceCondition(condition PolicyCondition, pkg *types.Package) bool {
	if pkg == nil || pkg.Metadata == nil || pkg.Metadata.LastUpdated == nil {
		return false
	}

	lastUpdated := *pkg.Metadata.LastUpdated
	timeDiff := time.Since(lastUpdated)

	switch condition.Value.(string) {
	case "365d":
		return timeDiff > 365*24*time.Hour
	case "180d":
		return timeDiff > 180*24*time.Hour
	case "90d":
		return timeDiff > 90*24*time.Hour
	default:
		return false
	}
}

// evaluateCriticalityCondition evaluates asset criticality conditions
func (pe *PolicyEngine) evaluateCriticalityCondition(condition PolicyCondition, criticality edge.AssetCriticality) bool {
	return string(criticality) == condition.Value.(string)
}

// GetPolicy retrieves a policy by ID
func (pe *PolicyEngine) GetPolicy(policyID string) (*SupplyChainPolicy, bool) {
	pe.mu.RLock()
	defer pe.mu.RUnlock()

	policy, exists := pe.policies[policyID]
	return policy, exists
}

// GetAllPolicies returns all policies
func (pe *PolicyEngine) GetAllPolicies() []*SupplyChainPolicy {
	pe.mu.RLock()
	defer pe.mu.RUnlock()

	policies := make([]*SupplyChainPolicy, 0, len(pe.policies))
	for _, policy := range pe.policies {
		policies = append(policies, policy)
	}
	return policies
}

// EnablePolicy enables a policy
func (pe *PolicyEngine) EnablePolicy(policyID string) error {
	pe.mu.Lock()
	defer pe.mu.Unlock()

	policy, exists := pe.policies[policyID]
	if !exists {
		return fmt.Errorf("policy %s not found", policyID)
	}

	policy.Enabled = true
	policy.UpdatedAt = time.Now()

	return nil
}

// DisablePolicy disables a policy
func (pe *PolicyEngine) DisablePolicy(policyID string) error {
	pe.mu.Lock()
	defer pe.mu.Unlock()

	policy, exists := pe.policies[policyID]
	if !exists {
		return fmt.Errorf("policy %s not found", policyID)
	}

	policy.Enabled = false
	policy.UpdatedAt = time.Now()

	return nil
}
