package security

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

// PolicyEngine enforces security policies
type PolicyEngine struct {
	policies    map[string]*SecurityPolicy
	auditLogger *AuditLogger
}

// SecurityPolicy defines a security policy
type SecurityPolicy struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Type        PolicyType             `json:"type"`
	Enabled     bool                   `json:"enabled"`
	Priority    int                    `json:"priority"`
	Rules       []PolicyRule           `json:"rules"`
	Actions     []PolicyAction         `json:"actions"`
	Metadata    map[string]interface{} `json:"metadata"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

// PolicyType defines types of security policies
type PolicyType string

const (
	PolicyTypeAccess       PolicyType = "access"
	PolicyTypeInput        PolicyType = "input"
	PolicyTypeRate         PolicyType = "rate"
	PolicyTypeData         PolicyType = "data"
	PolicyTypeCompliance   PolicyType = "compliance"
	PolicyTypeAuthentication PolicyType = "authentication"
)

// PolicyRule defines a policy rule
type PolicyRule struct {
	ID          string                 `json:"id"`
	Condition   string                 `json:"condition"`
	Field       string                 `json:"field"`
	Operator    RuleOperator           `json:"operator"`
	Value       interface{}            `json:"value"`
	Description string                 `json:"description"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// RuleOperator defines rule operators
type RuleOperator string

const (
	OperatorEquals       RuleOperator = "equals"
	OperatorNotEquals    RuleOperator = "not_equals"
	OperatorContains     RuleOperator = "contains"
	OperatorNotContains  RuleOperator = "not_contains"
	OperatorMatches      RuleOperator = "matches"
	OperatorNotMatches   RuleOperator = "not_matches"
	OperatorGreaterThan  RuleOperator = "greater_than"
	OperatorLessThan     RuleOperator = "less_than"
	OperatorIn           RuleOperator = "in"
	OperatorNotIn        RuleOperator = "not_in"
	OperatorStartsWith   RuleOperator = "starts_with"
	OperatorEndsWith     RuleOperator = "ends_with"
)

// PolicyAction defines actions to take when a policy is violated
type PolicyAction struct {
	Type        ActionType             `json:"type"`
	Parameters  map[string]interface{} `json:"parameters"`
	Description string                 `json:"description"`
}

// ActionType defines types of policy actions
type ActionType string

const (
	ActionBlock    ActionType = "block"
	ActionAllow    ActionType = "allow"
	ActionLog      ActionType = "log"
	ActionAlert    ActionType = "alert"
	ActionThrottle ActionType = "throttle"
	ActionRedirect ActionType = "redirect"
	ActionQuarantine ActionType = "quarantine"
)

// PolicyContext provides context for policy evaluation
type PolicyContext struct {
	UserID      string                 `json:"user_id"`
	IPAddress   string                 `json:"ip_address"`
	UserAgent   string                 `json:"user_agent"`
	Endpoint    string                 `json:"endpoint"`
	Method      string                 `json:"method"`
	Headers     map[string]string      `json:"headers"`
	Parameters  map[string]interface{} `json:"parameters"`
	Body        string                 `json:"body"`
	Timestamp   time.Time              `json:"timestamp"`
	SessionID   string                 `json:"session_id"`
	RequestID   string                 `json:"request_id"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// PolicyResult represents the result of policy evaluation
type PolicyResult struct {
	PolicyID    string                 `json:"policy_id"`
	RuleID      string                 `json:"rule_id"`
	Action      ActionType             `json:"action"`
	Allowed     bool                   `json:"allowed"`
	Message     string                 `json:"message"`
	Details     map[string]interface{} `json:"details"`
	Timestamp   time.Time              `json:"timestamp"`
}

// NewPolicyEngine creates a new policy engine
func NewPolicyEngine(auditLogger *AuditLogger) *PolicyEngine {
	engine := &PolicyEngine{
		policies:    make(map[string]*SecurityPolicy),
		auditLogger: auditLogger,
	}

	// Load default policies
	engine.loadDefaultPolicies()

	return engine
}

// AddPolicy adds a security policy
func (pe *PolicyEngine) AddPolicy(policy *SecurityPolicy) error {
	if policy.ID == "" {
		return fmt.Errorf("policy ID is required")
	}

	policy.CreatedAt = time.Now()
	policy.UpdatedAt = time.Now()

	pe.policies[policy.ID] = policy

	if pe.auditLogger != nil {
		pe.auditLogger.LogSystemEvent("POLICY_MANAGEMENT", "ADD_POLICY", 
			fmt.Sprintf("Added security policy: %s", policy.Name), 
			map[string]interface{}{
				"policy_id": policy.ID,
				"policy_type": policy.Type,
			})
	}

	return nil
}

// RemovePolicy removes a security policy
func (pe *PolicyEngine) RemovePolicy(policyID string) error {
	if _, exists := pe.policies[policyID]; !exists {
		return fmt.Errorf("policy not found: %s", policyID)
	}

	delete(pe.policies, policyID)

	if pe.auditLogger != nil {
		pe.auditLogger.LogSystemEvent("POLICY_MANAGEMENT", "REMOVE_POLICY", 
			fmt.Sprintf("Removed security policy: %s", policyID), 
			map[string]interface{}{
				"policy_id": policyID,
			})
	}

	return nil
}

// EvaluatePolicy evaluates a policy against the given context
func (pe *PolicyEngine) EvaluatePolicy(policyID string, context *PolicyContext) (*PolicyResult, error) {
	policy, exists := pe.policies[policyID]
	if !exists {
		return nil, fmt.Errorf("policy not found: %s", policyID)
	}

	if !policy.Enabled {
		return &PolicyResult{
			PolicyID:  policyID,
			Action:    ActionAllow,
			Allowed:   true,
			Message:   "Policy disabled",
			Timestamp: time.Now(),
		}, nil
	}

	// Evaluate rules
	for _, rule := range policy.Rules {
		if pe.evaluateRule(&rule, context) {
			// Rule matched, execute actions
			result := &PolicyResult{
				PolicyID:  policyID,
				RuleID:    rule.ID,
				Timestamp: time.Now(),
				Details:   make(map[string]interface{}),
			}

			// Execute actions
			for _, action := range policy.Actions {
				pe.executeAction(&action, context, result)
			}

			// Log policy evaluation
			if pe.auditLogger != nil {
				pe.auditLogger.LogSystemEvent("POLICY_EVALUATION", "RULE_MATCHED", 
					fmt.Sprintf("Policy rule matched: %s/%s", policyID, rule.ID), 
					map[string]interface{}{
						"policy_id": policyID,
						"rule_id": rule.ID,
						"action": result.Action,
						"allowed": result.Allowed,
						"user_id": context.UserID,
						"ip_address": context.IPAddress,
					})
			}

			return result, nil
		}
	}

	// No rules matched, allow by default
	return &PolicyResult{
		PolicyID:  policyID,
		Action:    ActionAllow,
		Allowed:   true,
		Message:   "No rules matched",
		Timestamp: time.Now(),
	}, nil
}

// EvaluateAllPolicies evaluates all enabled policies
func (pe *PolicyEngine) EvaluateAllPolicies(context *PolicyContext) ([]*PolicyResult, error) {
	var results []*PolicyResult

	// Sort policies by priority
	sortedPolicies := pe.getSortedPolicies()

	for _, policy := range sortedPolicies {
		if !policy.Enabled {
			continue
		}

		result, err := pe.EvaluatePolicy(policy.ID, context)
		if err != nil {
			continue // Skip failed evaluations
		}

		results = append(results, result)

		// If policy blocks, stop evaluation
		if !result.Allowed {
			break
		}
	}

	return results, nil
}

// evaluateRule evaluates a single policy rule
func (pe *PolicyEngine) evaluateRule(rule *PolicyRule, context *PolicyContext) bool {
	fieldValue := pe.getFieldValue(rule.Field, context)
	if fieldValue == nil {
		return false
	}

	switch rule.Operator {
	case OperatorEquals:
		return pe.compareValues(fieldValue, rule.Value, "equals")
	case OperatorNotEquals:
		return !pe.compareValues(fieldValue, rule.Value, "equals")
	case OperatorContains:
		return pe.stringContains(fieldValue, rule.Value)
	case OperatorNotContains:
		return !pe.stringContains(fieldValue, rule.Value)
	case OperatorMatches:
		return pe.regexMatches(fieldValue, rule.Value)
	case OperatorNotMatches:
		return !pe.regexMatches(fieldValue, rule.Value)
	case OperatorGreaterThan:
		return pe.compareValues(fieldValue, rule.Value, "greater")
	case OperatorLessThan:
		return pe.compareValues(fieldValue, rule.Value, "less")
	case OperatorIn:
		return pe.valueInList(fieldValue, rule.Value)
	case OperatorNotIn:
		return !pe.valueInList(fieldValue, rule.Value)
	case OperatorStartsWith:
		return pe.stringStartsWith(fieldValue, rule.Value)
	case OperatorEndsWith:
		return pe.stringEndsWith(fieldValue, rule.Value)
	default:
		return false
	}
}

// getFieldValue extracts field value from context
func (pe *PolicyEngine) getFieldValue(field string, context *PolicyContext) interface{} {
	switch field {
	case "user_id":
		return context.UserID
	case "ip_address":
		return context.IPAddress
	case "user_agent":
		return context.UserAgent
	case "endpoint":
		return context.Endpoint
	case "method":
		return context.Method
	case "body":
		return context.Body
	case "session_id":
		return context.SessionID
	case "request_id":
		return context.RequestID
	default:
		// Check headers
		if strings.HasPrefix(field, "header.") {
			headerName := strings.TrimPrefix(field, "header.")
			return context.Headers[headerName]
		}
		// Check parameters
		if strings.HasPrefix(field, "param.") {
			paramName := strings.TrimPrefix(field, "param.")
			return context.Parameters[paramName]
		}
		// Check metadata
		if strings.HasPrefix(field, "meta.") {
			metaName := strings.TrimPrefix(field, "meta.")
			return context.Metadata[metaName]
		}
		return nil
	}
}

// compareValues compares two values
func (pe *PolicyEngine) compareValues(a, b interface{}, operation string) bool {
	switch operation {
	case "equals":
		return fmt.Sprintf("%v", a) == fmt.Sprintf("%v", b)
	case "greater":
		// Try numeric comparison
		if aNum, aOk := a.(float64); aOk {
			if bNum, bOk := b.(float64); bOk {
				return aNum > bNum
			}
		}
		// Fall back to string comparison
		return fmt.Sprintf("%v", a) > fmt.Sprintf("%v", b)
	case "less":
		// Try numeric comparison
		if aNum, aOk := a.(float64); aOk {
			if bNum, bOk := b.(float64); bOk {
				return aNum < bNum
			}
		}
		// Fall back to string comparison
		return fmt.Sprintf("%v", a) < fmt.Sprintf("%v", b)
	default:
		return false
	}
}

// stringContains checks if string contains substring
func (pe *PolicyEngine) stringContains(value, substring interface{}) bool {
	valueStr := fmt.Sprintf("%v", value)
	subStr := fmt.Sprintf("%v", substring)
	return strings.Contains(strings.ToLower(valueStr), strings.ToLower(subStr))
}

// regexMatches checks if string matches regex pattern
func (pe *PolicyEngine) regexMatches(value, pattern interface{}) bool {
	valueStr := fmt.Sprintf("%v", value)
	patternStr := fmt.Sprintf("%v", pattern)
	
	regex, err := regexp.Compile(patternStr)
	if err != nil {
		return false
	}
	
	return regex.MatchString(valueStr)
}

// valueInList checks if value is in list
func (pe *PolicyEngine) valueInList(value, list interface{}) bool {
	valueStr := fmt.Sprintf("%v", value)
	
	switch listVal := list.(type) {
	case []interface{}:
		for _, item := range listVal {
			if fmt.Sprintf("%v", item) == valueStr {
				return true
			}
		}
	case []string:
		for _, item := range listVal {
			if item == valueStr {
				return true
			}
		}
	}
	
	return false
}

// stringStartsWith checks if string starts with prefix
func (pe *PolicyEngine) stringStartsWith(value, prefix interface{}) bool {
	valueStr := fmt.Sprintf("%v", value)
	prefixStr := fmt.Sprintf("%v", prefix)
	return strings.HasPrefix(strings.ToLower(valueStr), strings.ToLower(prefixStr))
}

// stringEndsWith checks if string ends with suffix
func (pe *PolicyEngine) stringEndsWith(value, suffix interface{}) bool {
	valueStr := fmt.Sprintf("%v", value)
	suffixStr := fmt.Sprintf("%v", suffix)
	return strings.HasSuffix(strings.ToLower(valueStr), strings.ToLower(suffixStr))
}

// executeAction executes a policy action
func (pe *PolicyEngine) executeAction(action *PolicyAction, context *PolicyContext, result *PolicyResult) {
	switch action.Type {
	case ActionBlock:
		result.Action = ActionBlock
		result.Allowed = false
		result.Message = "Access blocked by security policy"
	case ActionAllow:
		result.Action = ActionAllow
		result.Allowed = true
		result.Message = "Access allowed by security policy"
	case ActionLog:
		result.Action = ActionLog
		result.Allowed = true
		result.Message = "Access logged by security policy"
		// Additional logging handled by audit logger
	case ActionAlert:
		result.Action = ActionAlert
		result.Allowed = true
		result.Message = "Security alert triggered"
		// Alert handling would be implemented here
	case ActionThrottle:
		result.Action = ActionThrottle
		result.Allowed = true
		result.Message = "Request throttled by security policy"
		// Throttling logic would be implemented here
	case ActionRedirect:
		result.Action = ActionRedirect
		result.Allowed = false
		result.Message = "Request redirected by security policy"
		if redirectURL, ok := action.Parameters["url"].(string); ok {
			result.Details["redirect_url"] = redirectURL
		}
	case ActionQuarantine:
		result.Action = ActionQuarantine
		result.Allowed = false
		result.Message = "Request quarantined by security policy"
	}

	// Add action parameters to result details
	for key, value := range action.Parameters {
		result.Details[key] = value
	}
}

// getSortedPolicies returns policies sorted by priority
func (pe *PolicyEngine) getSortedPolicies() []*SecurityPolicy {
	policies := make([]*SecurityPolicy, 0, len(pe.policies))
	for _, policy := range pe.policies {
		policies = append(policies, policy)
	}

	// Simple bubble sort by priority (higher priority first)
	for i := 0; i < len(policies)-1; i++ {
		for j := 0; j < len(policies)-i-1; j++ {
			if policies[j].Priority < policies[j+1].Priority {
				policies[j], policies[j+1] = policies[j+1], policies[j]
			}
		}
	}

	return policies
}

// loadDefaultPolicies loads default security policies
func (pe *PolicyEngine) loadDefaultPolicies() {
	// SQL Injection Protection Policy
	sqlInjectionPolicy := &SecurityPolicy{
		ID:          "sql_injection_protection",
		Name:        "SQL Injection Protection",
		Description: "Blocks requests containing SQL injection patterns",
		Type:        PolicyTypeInput,
		Enabled:     true,
		Priority:    100,
		Rules: []PolicyRule{
			{
				ID:          "sql_injection_rule",
				Condition:   "body_contains_sql_patterns",
				Field:       "body",
				Operator:    OperatorMatches,
				Value:       `(?i)(union\s+select|drop\s+table|insert\s+into|delete\s+from|update\s+set|exec\s*\(|script\s*>)`,
				Description: "Detects common SQL injection patterns",
			},
		},
		Actions: []PolicyAction{
			{
				Type:        ActionBlock,
				Description: "Block request with SQL injection attempt",
			},
		},
	}

	// XSS Protection Policy
	xssPolicy := &SecurityPolicy{
		ID:          "xss_protection",
		Name:        "XSS Protection",
		Description: "Blocks requests containing XSS patterns",
		Type:        PolicyTypeInput,
		Enabled:     true,
		Priority:    95,
		Rules: []PolicyRule{
			{
				ID:          "xss_rule",
				Condition:   "body_contains_xss_patterns",
				Field:       "body",
				Operator:    OperatorMatches,
				Value:       `(?i)(<script|javascript:|onload=|onerror=|onclick=|onmouseover=)`,
				Description: "Detects common XSS patterns",
			},
		},
		Actions: []PolicyAction{
			{
				Type:        ActionBlock,
				Description: "Block request with XSS attempt",
			},
		},
	}

	// Rate Limiting Policy
	rateLimitPolicy := &SecurityPolicy{
		ID:          "rate_limiting",
		Name:        "Rate Limiting",
		Description: "Enforces rate limits on API endpoints",
		Type:        PolicyTypeRate,
		Enabled:     true,
		Priority:    90,
		Rules: []PolicyRule{
			{
				ID:          "api_rate_limit",
				Condition:   "endpoint_starts_with_api",
				Field:       "endpoint",
				Operator:    OperatorStartsWith,
				Value:       "/api/",
				Description: "Apply rate limiting to API endpoints",
			},
		},
		Actions: []PolicyAction{
			{
				Type:        ActionThrottle,
				Description: "Apply rate limiting",
				Parameters: map[string]interface{}{
					"requests_per_minute": 60,
					"burst_size":         10,
				},
			},
		},
	}

	// Add default policies
	pe.AddPolicy(sqlInjectionPolicy)
	pe.AddPolicy(xssPolicy)
	pe.AddPolicy(rateLimitPolicy)
}

// GetPolicies returns all policies
func (pe *PolicyEngine) GetPolicies() map[string]*SecurityPolicy {
	return pe.policies
}

// GetPolicy returns a specific policy
func (pe *PolicyEngine) GetPolicy(policyID string) (*SecurityPolicy, bool) {
	policy, exists := pe.policies[policyID]
	return policy, exists
}