package policy

import (
	"time"
)

// Note: PRRequest, PRResult, PRTemplate, Repository, and FileChange types
// are defined in enhanced_remediation_engine.go to avoid duplication

// PRStatus represents the status of a pull request
type PRStatus string

const (
	PRStatusOpen   PRStatus = "open"
	PRStatusClosed PRStatus = "closed"
	PRStatusMerged PRStatus = "merged"
	PRStatusDraft  PRStatus = "draft"
)

// PREvent represents events related to pull requests
type PREvent struct {
	ID        string                 `json:"id"`
	Type      string                 `json:"type"` // created, updated, merged, closed
	PRID      string                 `json:"pr_id"`
	Timestamp time.Time              `json:"timestamp"`
	Actor     string                 `json:"actor"`
	Data      map[string]interface{} `json:"data,omitempty"`
}

// RemediationPRConfig configuration for remediation pull requests
type RemediationPRConfig struct {
	Enabled             bool              `json:"enabled"`
	AutoApprove         bool              `json:"auto_approve"`
	AutoMerge           bool              `json:"auto_merge"`
	RequiredApprovals   int               `json:"required_approvals"`
	DefaultReviewers    []string          `json:"default_reviewers"`
	DefaultAssignees    []string          `json:"default_assignees"`
	BranchPrefix        string            `json:"branch_prefix"`
	CommitMessagePrefix string            `json:"commit_message_prefix"`
	Labels              map[string][]string `json:"labels"`
	Templates           map[string]string `json:"templates"`
	Notifications       *NotificationConfig `json:"notifications,omitempty"`
}

// NotificationConfig configuration for PR notifications
type NotificationConfig struct {
	Enabled   bool     `json:"enabled"`
	Channels  []string `json:"channels"` // slack, email, webhook
	Webhooks  []string `json:"webhooks,omitempty"`
	SlackURL  string   `json:"slack_url,omitempty"`
	EmailTo   []string `json:"email_to,omitempty"`
}

// PRMetrics represents metrics for pull request operations
type PRMetrics struct {
	TotalCreated    int64                    `json:"total_created"`
	TotalMerged     int64                    `json:"total_merged"`
	TotalClosed     int64                    `json:"total_closed"`
	AverageTime     time.Duration            `json:"average_time"`
	ByThreatType    map[string]int64         `json:"by_threat_type"`
	ByRepository    map[string]int64         `json:"by_repository"`
	SuccessRate     float64                  `json:"success_rate"`
	LastUpdated     time.Time                `json:"last_updated"`
}

// PRWorkflow represents a workflow for pull request processing
type PRWorkflow struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Steps       []WorkflowStep         `json:"steps"`
	Triggers    []WorkflowTrigger      `json:"triggers"`
	Conditions  []WorkflowCondition    `json:"conditions"`
	Enabled     bool                   `json:"enabled"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// WorkflowStep represents a step in a PR workflow
type WorkflowStep struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Type        string                 `json:"type"` // action, condition, notification
	Action      string                 `json:"action"`
	Parameters  map[string]interface{} `json:"parameters,omitempty"`
	Conditions  []string               `json:"conditions,omitempty"`
	Timeout     time.Duration          `json:"timeout,omitempty"`
	RetryCount  int                    `json:"retry_count,omitempty"`
}

// WorkflowTrigger represents a trigger for a PR workflow
type WorkflowTrigger struct {
	Type       string                 `json:"type"` // threat_detected, pr_created, pr_updated
	Conditions map[string]interface{} `json:"conditions,omitempty"`
	Filters    map[string]interface{} `json:"filters,omitempty"`
}

// WorkflowCondition represents a condition in a PR workflow
type WorkflowCondition struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"` // equals, contains, greater_than, etc.
	Value    interface{} `json:"value"`
	Logic    string      `json:"logic,omitempty"` // and, or
}

// PRApprovalRule represents rules for PR approval
type PRApprovalRule struct {
	ID                string   `json:"id"`
	Name              string   `json:"name"`
	RequiredApprovals int      `json:"required_approvals"`
	RequiredReviewers []string `json:"required_reviewers"`
	ThreatTypes       []string `json:"threat_types"`
	SeverityLevels    []string `json:"severity_levels"`
	AutoApprove       bool     `json:"auto_approve"`
	BypassUsers       []string `json:"bypass_users,omitempty"`
}

// PRIntegration represents integration settings for PR operations
type PRIntegration struct {
	Provider    string                 `json:"provider"` // github, gitlab, bitbucket
	Enabled     bool                   `json:"enabled"`
	Credentials map[string]string      `json:"credentials"`
	Settings    map[string]interface{} `json:"settings"`
	Webhooks    []string               `json:"webhooks,omitempty"`
	RateLimit   *RateLimitConfig       `json:"rate_limit,omitempty"`
}

// RateLimitConfig represents rate limiting configuration
type RateLimitConfig struct {
	Enabled     bool          `json:"enabled"`
	RequestsPer time.Duration `json:"requests_per"`
	BurstSize   int           `json:"burst_size"`
	RetryAfter  time.Duration `json:"retry_after"`
}

// PRAuditLog represents audit logging for PR operations
type PRAuditLog struct {
	ID          string                 `json:"id"`
	Timestamp   time.Time              `json:"timestamp"`
	Action      string                 `json:"action"`
	PRID        string                 `json:"pr_id,omitempty"`
	Repository  string                 `json:"repository"`
	User        string                 `json:"user"`
	ThreatType  string                 `json:"threat_type,omitempty"`
	Details     map[string]interface{} `json:"details,omitempty"`
	Result      string                 `json:"result"` // success, failure, pending
	Error       string                 `json:"error,omitempty"`
}