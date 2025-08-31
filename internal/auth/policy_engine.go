package auth

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// PolicyAction represents an action to take when a policy is triggered
type PolicyAction string

const (
	PolicyActionAllow           PolicyAction = "allow"
	PolicyActionDeny            PolicyAction = "deny"
	PolicyActionBlock           PolicyAction = "block_deployment"
	PolicyActionRequireApproval PolicyAction = "require_approval"
	PolicyActionGenerateSPDX    PolicyAction = "generate_spdx"
	PolicyActionNotify          PolicyAction = "notify"
	PolicyActionQuarantine      PolicyAction = "quarantine"
	PolicyActionLog             PolicyAction = "log"
)

// PolicyCondition represents a condition that must be met for a policy to trigger
type PolicyCondition struct {
	Field    string      `json:"field"`    // e.g., "threat.severity", "package.downloads"
	Operator string      `json:"operator"` // e.g., "==", ">", "<", "contains", "matches"
	Value    interface{} `json:"value"`    // The value to compare against
}

// SecurityPolicy represents a security policy
type SecurityPolicy struct {
	ID            string            `json:"id"`
	Name          string            `json:"name"`
	Description   string            `json:"description"`
	Enabled       bool              `json:"enabled"`
	Priority      int               `json:"priority"` // Higher number = higher priority
	Conditions    []PolicyCondition `json:"conditions"`
	Action        PolicyAction      `json:"action"`
	Parameters    map[string]string `json:"parameters"`    // Additional parameters for the action
	Notifications []string          `json:"notifications"` // Email addresses or webhook URLs
	Approvers     []string          `json:"approvers"`     // Users who can approve
	Schedule      string            `json:"schedule"`      // Cron expression for scheduled actions
	CreatedAt     time.Time         `json:"created_at"`
	UpdatedAt     time.Time         `json:"updated_at"`
	CreatedBy     string            `json:"created_by"`
}

// PolicyEvaluationResult represents the result of policy evaluation
type PolicyEvaluationResult struct {
	PolicyID      string                 `json:"policy_id"`
	PolicyName    string                 `json:"policy_name"`
	Triggered     bool                   `json:"triggered"`
	Action        PolicyAction           `json:"action"`
	Reason        string                 `json:"reason"`
	Parameters    map[string]string      `json:"parameters"`
	Notifications []string               `json:"notifications"`
	Approvers     []string               `json:"approvers"`
	Metadata      map[string]interface{} `json:"metadata"`
	EvaluatedAt   time.Time              `json:"evaluated_at"`
}

// PolicyEvaluationContext contains context for policy evaluation
type PolicyEvaluationContext struct {
	ScanResult  *types.ScanResult      `json:"scan_result"`
	Package     *types.Package         `json:"package"`
	Repository  *RepositoryInfo        `json:"repository"`
	User        *User                  `json:"user"`
	Environment string                 `json:"environment"` // e.g., "production", "staging", "development"
	Metadata    map[string]interface{} `json:"metadata"`
}

// RepositoryInfo contains repository information for policy evaluation
type RepositoryInfo struct {
	Name         string            `json:"name"`
	Owner        string            `json:"owner"`
	URL          string            `json:"url"`
	Branch       string            `json:"branch"`
	IsProduction bool              `json:"is_production"`
	Tags         []string          `json:"tags"`
	Attributes   map[string]string `json:"attributes"`
}

// PolicyEngine manages and evaluates security policies
type PolicyEngine struct {
	policies map[string]*SecurityPolicy
	mu       sync.RWMutex
	logger   Logger // Assuming a logger interface exists
}

// Logger interface for policy engine logging
type Logger interface {
	Info(msg string, fields ...interface{})
	Warn(msg string, fields ...interface{})
	Error(msg string, fields ...interface{})
	Debug(msg string, fields ...interface{})
}

// NewPolicyEngine creates a new policy engine
func NewPolicyEngine(logger Logger) *PolicyEngine {
	return &PolicyEngine{
		policies: make(map[string]*SecurityPolicy),
		logger:   logger,
	}
}

// AddPolicy adds a new policy to the engine
func (pe *PolicyEngine) AddPolicy(policy *SecurityPolicy) error {
	if policy.ID == "" {
		return fmt.Errorf("policy ID cannot be empty")
	}

	if policy.Name == "" {
		return fmt.Errorf("policy name cannot be empty")
	}

	// Validate conditions
	for _, condition := range policy.Conditions {
		if err := pe.validateCondition(&condition); err != nil {
			return fmt.Errorf("invalid condition: %w", err)
		}
	}

	pe.mu.Lock()
	defer pe.mu.Unlock()

	policy.UpdatedAt = time.Now()
	if policy.CreatedAt.IsZero() {
		policy.CreatedAt = time.Now()
	}

	pe.policies[policy.ID] = policy

	if pe.logger != nil {
		pe.logger.Info("Policy added", "policy_id", policy.ID, "policy_name", policy.Name)
	}

	return nil
}

// RemovePolicy removes a policy from the engine
func (pe *PolicyEngine) RemovePolicy(policyID string) error {
	pe.mu.Lock()
	defer pe.mu.Unlock()

	if _, exists := pe.policies[policyID]; !exists {
		return fmt.Errorf("policy not found: %s", policyID)
	}

	delete(pe.policies, policyID)

	if pe.logger != nil {
		pe.logger.Info("Policy removed", "policy_id", policyID)
	}

	return nil
}

// GetPolicy retrieves a policy by ID
func (pe *PolicyEngine) GetPolicy(policyID string) (*SecurityPolicy, error) {
	pe.mu.RLock()
	defer pe.mu.RUnlock()

	policy, exists := pe.policies[policyID]
	if !exists {
		return nil, fmt.Errorf("policy not found: %s", policyID)
	}

	return policy, nil
}

// ListPolicies returns all policies
func (pe *PolicyEngine) ListPolicies() []*SecurityPolicy {
	pe.mu.RLock()
	defer pe.mu.RUnlock()

	policies := make([]*SecurityPolicy, 0, len(pe.policies))
	for _, policy := range pe.policies {
		policies = append(policies, policy)
	}

	return policies
}

// EvaluatePolicies evaluates all policies against the given context
func (pe *PolicyEngine) EvaluatePolicies(ctx context.Context, evalCtx *PolicyEvaluationContext) ([]*PolicyEvaluationResult, error) {
	pe.mu.RLock()
	policies := make([]*SecurityPolicy, 0, len(pe.policies))
	for _, policy := range pe.policies {
		if policy.Enabled {
			policies = append(policies, policy)
		}
	}
	pe.mu.RUnlock()

	// Sort policies by priority (higher priority first)
	for i := 0; i < len(policies)-1; i++ {
		for j := i + 1; j < len(policies); j++ {
			if policies[i].Priority < policies[j].Priority {
				policies[i], policies[j] = policies[j], policies[i]
			}
		}
	}

	results := make([]*PolicyEvaluationResult, 0)

	for _, policy := range policies {
		result, err := pe.evaluatePolicy(ctx, policy, evalCtx)
		if err != nil {
			if pe.logger != nil {
				pe.logger.Error("Policy evaluation failed", "policy_id", policy.ID, "error", err)
			}
			continue
		}

		results = append(results, result)

		// If this is a blocking action, stop evaluation
		if result.Triggered && (result.Action == PolicyActionBlock || result.Action == PolicyActionDeny) {
			break
		}
	}

	return results, nil
}

// evaluatePolicy evaluates a single policy
func (pe *PolicyEngine) evaluatePolicy(ctx context.Context, policy *SecurityPolicy, evalCtx *PolicyEvaluationContext) (*PolicyEvaluationResult, error) {
	result := &PolicyEvaluationResult{
		PolicyID:      policy.ID,
		PolicyName:    policy.Name,
		Triggered:     false,
		Action:        policy.Action,
		Parameters:    policy.Parameters,
		Notifications: policy.Notifications,
		Approvers:     policy.Approvers,
		Metadata:      make(map[string]interface{}),
		EvaluatedAt:   time.Now(),
	}

	// Evaluate all conditions (AND logic)
	allConditionsMet := true
	for _, condition := range policy.Conditions {
		met, reason, err := pe.evaluateCondition(&condition, evalCtx)
		if err != nil {
			return nil, fmt.Errorf("failed to evaluate condition: %w", err)
		}

		if !met {
			allConditionsMet = false
			result.Reason = fmt.Sprintf("Condition not met: %s", reason)
			break
		}
	}

	if allConditionsMet {
		result.Triggered = true
		result.Reason = "All policy conditions met"

		if pe.logger != nil {
			pe.logger.Info("Policy triggered", "policy_id", policy.ID, "policy_name", policy.Name, "action", policy.Action)
		}
	}

	return result, nil
}

// evaluateCondition evaluates a single condition
func (pe *PolicyEngine) evaluateCondition(condition *PolicyCondition, evalCtx *PolicyEvaluationContext) (bool, string, error) {
	actualValue, err := pe.getFieldValue(condition.Field, evalCtx)
	if err != nil {
		return false, "", fmt.Errorf("failed to get field value: %w", err)
	}

	met, err := pe.compareValues(actualValue, condition.Operator, condition.Value)
	if err != nil {
		return false, "", fmt.Errorf("failed to compare values: %w", err)
	}

	reason := fmt.Sprintf("%s %s %v (actual: %v)", condition.Field, condition.Operator, condition.Value, actualValue)
	return met, reason, nil
}

// getFieldValue extracts a field value from the evaluation context
func (pe *PolicyEngine) getFieldValue(field string, evalCtx *PolicyEvaluationContext) (interface{}, error) {
	parts := strings.Split(field, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid field format: %s", field)
	}

	switch parts[0] {
	case "threat":
		// Find threats from packages in scan result
		if evalCtx.ScanResult == nil || len(evalCtx.ScanResult.Packages) == 0 {
			return nil, nil
		}
		// Collect all threats from packages
		var allThreats []types.Threat
		for _, pkg := range evalCtx.ScanResult.Packages {
			if pkg.Threats != nil {
				allThreats = append(allThreats, pkg.Threats...)
			}
		}
		if len(allThreats) == 0 {
			return nil, nil
		}
		// Use the highest severity threat
		highestThreat := allThreats[0]
		for _, threat := range allThreats {
			if pe.getSeverityLevel(threat.Severity.String()) > pe.getSeverityLevel(highestThreat.Severity.String()) {
				highestThreat = threat
			}
		}
		return pe.getThreatField(parts[1], &highestThreat)

	case "package":
		if evalCtx.Package == nil {
			return nil, nil
		}
		return pe.getPackageField(parts[1], evalCtx.Package)

	case "repository":
		if evalCtx.Repository == nil {
			return nil, nil
		}
		return pe.getRepositoryField(parts[1], evalCtx.Repository)

	case "user":
		if evalCtx.User == nil {
			return nil, nil
		}
		return pe.getUserField(parts[1], evalCtx.User)

	case "scan":
		if evalCtx.ScanResult == nil {
			return nil, nil
		}
		return pe.getScanField(parts[1], evalCtx.ScanResult)

	case "environment":
		return evalCtx.Environment, nil

	default:
		return nil, fmt.Errorf("unknown field prefix: %s", parts[0])
	}
}

// getThreatField extracts a field from a threat
func (pe *PolicyEngine) getThreatField(field string, threat *types.Threat) (interface{}, error) {
	switch field {
	case "severity":
		return threat.Severity.String(), nil
	case "confidence":
		return threat.Confidence, nil
	case "type":
		return string(threat.Type), nil
	case "description":
		return threat.Description, nil
	default:
		return nil, fmt.Errorf("unknown threat field: %s", field)
	}
}

// getPackageField extracts a field from a package
func (pe *PolicyEngine) getPackageField(field string, pkg *types.Package) (interface{}, error) {
	switch field {
	case "name":
		return pkg.Name, nil
	case "version":
		return pkg.Version, nil
	case "registry":
		return pkg.Registry, nil
	case "downloads":
		if pkg.Metadata != nil {
			return pkg.Metadata.Downloads, nil
		}
		return 0, nil
	case "age":
		if pkg.Metadata != nil && pkg.Metadata.PublishedAt != nil && !pkg.Metadata.PublishedAt.IsZero() {
			return int(time.Since(*pkg.Metadata.PublishedAt).Hours() / 24), nil
		}
		return 0, nil
	default:
		return nil, fmt.Errorf("unknown package field: %s", field)
	}
}

// getRepositoryField extracts a field from repository info
func (pe *PolicyEngine) getRepositoryField(field string, repo *RepositoryInfo) (interface{}, error) {
	switch field {
	case "name":
		return repo.Name, nil
	case "owner":
		return repo.Owner, nil
	case "production":
		return repo.IsProduction, nil
	case "branch":
		return repo.Branch, nil
	default:
		if value, exists := repo.Attributes[field]; exists {
			return value, nil
		}
		return nil, fmt.Errorf("unknown repository field: %s", field)
	}
}

// getUserField extracts a field from user info
func (pe *PolicyEngine) getUserField(field string, user *User) (interface{}, error) {
	switch field {
	case "id":
		return user.ID, nil
	case "username":
		return user.Username, nil
	case "email":
		return user.Email, nil
	case "roles":
		return user.Roles, nil
	default:
		if value, exists := user.Attributes[field]; exists {
			return value, nil
		}
		return nil, fmt.Errorf("unknown user field: %s", field)
	}
}

// getScanField extracts a field from scan result
func (pe *PolicyEngine) getScanField(field string, result *types.ScanResult) (interface{}, error) {
	switch field {
	case "risk_score":
		return result.RiskScore, nil
	case "overall_risk":
		return result.OverallRisk, nil
	case "threat_count":
		// Count threats from all packages
		threatCount := 0
		for _, pkg := range result.Packages {
			if pkg.Threats != nil {
				threatCount += len(pkg.Threats)
			}
		}
		return threatCount, nil
	case "package_count":
		return len(result.Packages), nil
	default:
		return nil, fmt.Errorf("unknown scan field: %s", field)
	}
}

// compareValues compares two values using the specified operator
func (pe *PolicyEngine) compareValues(actual interface{}, operator string, expected interface{}) (bool, error) {
	switch operator {
	case "==", "eq":
		return pe.equals(actual, expected), nil
	case "!=", "ne":
		return !pe.equals(actual, expected), nil
	case ">", "gt":
		return pe.greaterThan(actual, expected)
	case ">=", "gte":
		return pe.greaterThanOrEqual(actual, expected)
	case "<", "lt":
		return pe.lessThan(actual, expected)
	case "<=", "lte":
		return pe.lessThanOrEqual(actual, expected)
	case "contains":
		return pe.contains(actual, expected), nil
	case "matches":
		return pe.matches(actual, expected)
	case "in":
		return pe.in(actual, expected), nil
	default:
		return false, fmt.Errorf("unknown operator: %s", operator)
	}
}

// Helper comparison functions
func (pe *PolicyEngine) equals(a, b interface{}) bool {
	return fmt.Sprintf("%v", a) == fmt.Sprintf("%v", b)
}

func (pe *PolicyEngine) greaterThan(a, b interface{}) (bool, error) {
	numA, errA := pe.toFloat64(a)
	numB, errB := pe.toFloat64(b)
	if errA != nil || errB != nil {
		return false, fmt.Errorf("cannot compare non-numeric values")
	}
	return numA > numB, nil
}

func (pe *PolicyEngine) greaterThanOrEqual(a, b interface{}) (bool, error) {
	numA, errA := pe.toFloat64(a)
	numB, errB := pe.toFloat64(b)
	if errA != nil || errB != nil {
		return false, fmt.Errorf("cannot compare non-numeric values")
	}
	return numA >= numB, nil
}

func (pe *PolicyEngine) lessThan(a, b interface{}) (bool, error) {
	numA, errA := pe.toFloat64(a)
	numB, errB := pe.toFloat64(b)
	if errA != nil || errB != nil {
		return false, fmt.Errorf("cannot compare non-numeric values")
	}
	return numA < numB, nil
}

func (pe *PolicyEngine) lessThanOrEqual(a, b interface{}) (bool, error) {
	numA, errA := pe.toFloat64(a)
	numB, errB := pe.toFloat64(b)
	if errA != nil || errB != nil {
		return false, fmt.Errorf("cannot compare non-numeric values")
	}
	return numA <= numB, nil
}

func (pe *PolicyEngine) contains(a, b interface{}) bool {
	strA := fmt.Sprintf("%v", a)
	strB := fmt.Sprintf("%v", b)
	return strings.Contains(strA, strB)
}

func (pe *PolicyEngine) matches(a, b interface{}) (bool, error) {
	strA := fmt.Sprintf("%v", a)
	pattern := fmt.Sprintf("%v", b)
	matched, err := regexp.MatchString(pattern, strA)
	return matched, err
}

func (pe *PolicyEngine) in(a, b interface{}) bool {
	strA := fmt.Sprintf("%v", a)
	switch v := b.(type) {
	case []string:
		for _, item := range v {
			if item == strA {
				return true
			}
		}
	case []interface{}:
		for _, item := range v {
			if fmt.Sprintf("%v", item) == strA {
				return true
			}
		}
	case string:
		// Treat as comma-separated list
		items := strings.Split(v, ",")
		for _, item := range items {
			if strings.TrimSpace(item) == strA {
				return true
			}
		}
	}
	return false
}

func (pe *PolicyEngine) toFloat64(v interface{}) (float64, error) {
	switch val := v.(type) {
	case float64:
		return val, nil
	case float32:
		return float64(val), nil
	case int:
		return float64(val), nil
	case int64:
		return float64(val), nil
	case int32:
		return float64(val), nil
	case string:
		return strconv.ParseFloat(val, 64)
	default:
		return 0, fmt.Errorf("cannot convert %T to float64", v)
	}
}

func (pe *PolicyEngine) getSeverityLevel(severity string) int {
	switch strings.ToLower(severity) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func (pe *PolicyEngine) validateCondition(condition *PolicyCondition) error {
	if condition.Field == "" {
		return fmt.Errorf("condition field cannot be empty")
	}

	if condition.Operator == "" {
		return fmt.Errorf("condition operator cannot be empty")
	}

	validOperators := []string{"==", "!=", ">", ">=", "<", "<=", "contains", "matches", "in", "eq", "ne", "gt", "gte", "lt", "lte"}
	validOperator := false
	for _, op := range validOperators {
		if condition.Operator == op {
			validOperator = true
			break
		}
	}

	if !validOperator {
		return fmt.Errorf("invalid operator: %s", condition.Operator)
	}

	return nil
}
