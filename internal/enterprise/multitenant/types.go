package multitenant

import (
	"time"
)

// Tenant represents a tenant in the multi-tenant system
type Tenant struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Owner       string                 `json:"owner"`
	Plan        string                 `json:"plan"` // basic, premium, enterprise
	Quotas      *TenantQuotas          `json:"quotas"`
	Settings    *TenantSettings        `json:"settings"`
	Status      TenantStatus           `json:"status"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// TenantStatus represents the status of a tenant
type TenantStatus string

const (
	TenantStatusActive    TenantStatus = "active"
	TenantStatusSuspended TenantStatus = "suspended"
	TenantStatusInactive  TenantStatus = "inactive"
	TenantStatusDeleted   TenantStatus = "deleted"
)

// TenantQuotas defines resource quotas for a tenant
type TenantQuotas struct {
	MaxRepositories     int `json:"max_repositories"`
	MaxScansPerDay      int `json:"max_scans_per_day"`
	MaxUsers            int `json:"max_users"`
	MaxStorageGB        int `json:"max_storage_gb"`
	MaxAPICallsPerHour  int `json:"max_api_calls_per_hour"`
	MaxPolicies         int `json:"max_policies"`
	MaxIntegrations     int `json:"max_integrations"`
	MaxRetentionDays    int `json:"max_retention_days"`
}

// TenantSettings defines configuration settings for a tenant
type TenantSettings struct {
	TimeZone            string            `json:"timezone"`
	Language            string            `json:"language"`
	Notifications       *NotificationSettings `json:"notifications"`
	Security            *SecuritySettings     `json:"security"`
	Integrations        *IntegrationSettings  `json:"integrations"`
	CustomFields        map[string]interface{} `json:"custom_fields,omitempty"`
}

// NotificationSettings defines notification preferences
type NotificationSettings struct {
	EmailEnabled    bool     `json:"email_enabled"`
	SlackEnabled    bool     `json:"slack_enabled"`
	WebhookEnabled  bool     `json:"webhook_enabled"`
	EmailRecipients []string `json:"email_recipients,omitempty"`
	SlackChannels   []string `json:"slack_channels,omitempty"`
	WebhookURLs     []string `json:"webhook_urls,omitempty"`
}

// SecuritySettings defines security preferences
type SecuritySettings struct {
	MFARequired         bool `json:"mfa_required"`
	PasswordPolicy      *PasswordPolicy `json:"password_policy"`
	SessionTimeout      int `json:"session_timeout_minutes"`
	IPWhitelist         []string `json:"ip_whitelist,omitempty"`
	AuditLogging        bool `json:"audit_logging"`
	DataEncryption      bool `json:"data_encryption"`
}

// PasswordPolicy defines password requirements
type PasswordPolicy struct {
	MinLength        int  `json:"min_length"`
	RequireUppercase bool `json:"require_uppercase"`
	RequireLowercase bool `json:"require_lowercase"`
	RequireNumbers   bool `json:"require_numbers"`
	RequireSymbols   bool `json:"require_symbols"`
	ExpirationDays   int  `json:"expiration_days"`
}

// IntegrationSettings defines integration preferences
type IntegrationSettings struct {
	GitHubEnabled    bool `json:"github_enabled"`
	GitLabEnabled    bool `json:"gitlab_enabled"`
	BitbucketEnabled bool `json:"bitbucket_enabled"`
	JiraEnabled      bool `json:"jira_enabled"`
	SlackEnabled     bool `json:"slack_enabled"`
	SplunkEnabled    bool `json:"splunk_enabled"`
}

// MultiTenantConfig defines configuration for multi-tenant system
type MultiTenantConfig struct {
	MaxTenants           int                `json:"max_tenants"`
	DefaultQuotas        *TenantQuotas      `json:"default_quotas"`
	IsolationLevel       IsolationLevel     `json:"isolation_level"`
	ResourcePooling      bool               `json:"resource_pooling"`
	AuditingEnabled      bool               `json:"auditing_enabled"`
	MetricsEnabled       bool               `json:"metrics_enabled"`
	AutoScaling          bool               `json:"auto_scaling"`
	DataRetentionDays    int                `json:"data_retention_days"`
	BackupEnabled        bool               `json:"backup_enabled"`
	EncryptionEnabled    bool               `json:"encryption_enabled"`
	DatabaseConfig       *DatabaseConfig    `json:"database_config"`
	CacheConfig          *CacheConfig       `json:"cache_config"`
}

// IsolationLevel defines the level of tenant isolation
type IsolationLevel string

const (
	IsolationLevelShared IsolationLevel = "shared"
	IsolationLevelSchema IsolationLevel = "schema"
	IsolationLevelStrict IsolationLevel = "strict"
)

// DatabaseConfig defines database configuration for multi-tenancy
type DatabaseConfig struct {
	Type             string `json:"type"` // shared, schema, database
	ConnectionString string `json:"connection_string"`
	MaxConnections   int    `json:"max_connections"`
	SchemaPrefix     string `json:"schema_prefix"`
	Encryption       bool   `json:"encryption"`
}

// CacheConfig defines cache configuration for multi-tenancy
type CacheConfig struct {
	Type        string `json:"type"` // redis, memory
	URL         string `json:"url"`
	KeyPrefix   string `json:"key_prefix"`
	TTL         int    `json:"ttl_seconds"`
	MaxMemoryMB int    `json:"max_memory_mb"`
}

// CreateTenantRequest represents a request to create a new tenant
type CreateTenantRequest struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Owner       string                 `json:"owner"`
	Plan        string                 `json:"plan"`
	Quotas      *TenantQuotas          `json:"quotas,omitempty"`
	Settings    *TenantSettings        `json:"settings,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// UpdateTenantRequest represents a request to update a tenant
type UpdateTenantRequest struct {
	Name        string                 `json:"name,omitempty"`
	Description string                 `json:"description,omitempty"`
	Plan        string                 `json:"plan,omitempty"`
	Quotas      *TenantQuotas          `json:"quotas,omitempty"`
	Settings    *TenantSettings        `json:"settings,omitempty"`
	Status      TenantStatus           `json:"status,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// TenantFilter defines filters for listing tenants
type TenantFilter struct {
	Status TenantStatus `json:"status,omitempty"`
	Plan   string       `json:"plan,omitempty"`
	Owner  string       `json:"owner,omitempty"`
	Limit  int          `json:"limit,omitempty"`
	Offset int          `json:"offset,omitempty"`
}

// TenantUsage represents usage statistics for a tenant
type TenantUsage struct {
	TenantID            string    `json:"tenant_id"`
	RepositoryCount     int       `json:"repository_count"`
	ScansToday          int       `json:"scans_today"`
	UserCount           int       `json:"user_count"`
	StorageUsedGB       float64   `json:"storage_used_gb"`
	APICallsThisHour    int       `json:"api_calls_this_hour"`
	PolicyCount         int       `json:"policy_count"`
	IntegrationCount    int       `json:"integration_count"`
	LastScanTime        time.Time `json:"last_scan_time"`
	QuotaUtilization    map[string]float64 `json:"quota_utilization"`
}

// QuotaOperation represents an operation that consumes quota
type QuotaOperation struct {
	Type     string `json:"type"` // scan, api_call, storage, etc.
	Amount   int    `json:"amount"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// TenantMetrics represents metrics for tenant operations
type TenantMetrics struct {
	TotalTenants    int64                    `json:"total_tenants"`
	ActiveTenants   int64                    `json:"active_tenants"`
	TenantsByPlan   map[string]int64         `json:"tenants_by_plan"`
	ResourceUsage   map[string]float64       `json:"resource_usage"`
	QuotaViolations int64                    `json:"quota_violations"`
	LastUpdated     time.Time                `json:"last_updated"`
}

// TenantMetricsSnapshot represents a snapshot of tenant metrics
type TenantMetricsSnapshot struct {
	Timestamp       time.Time                `json:"timestamp"`
	TotalTenants    int64                    `json:"total_tenants"`
	ActiveTenants   int64                    `json:"active_tenants"`
	TenantsByPlan   map[string]int64         `json:"tenants_by_plan"`
	TenantsByStatus map[string]int64         `json:"tenants_by_status"`
	ResourceUsage   map[string]float64       `json:"resource_usage"`
	QuotaViolations int64                    `json:"quota_violations"`
	Performance     *PerformanceMetrics      `json:"performance"`
}

// PerformanceMetrics represents performance metrics
type PerformanceMetrics struct {
	AverageResponseTime time.Duration `json:"average_response_time"`
	Throughput          float64       `json:"throughput"`
	ErrorRate           float64       `json:"error_rate"`
	CPUUsage            float64       `json:"cpu_usage"`
	MemoryUsage         float64       `json:"memory_usage"`
	DiskUsage           float64       `json:"disk_usage"`
}

// TenantEvent represents events in the tenant lifecycle
type TenantEvent struct {
	ID        string                 `json:"id"`
	TenantID  string                 `json:"tenant_id"`
	Type      string                 `json:"type"` // created, updated, suspended, deleted
	Timestamp time.Time              `json:"timestamp"`
	Actor     string                 `json:"actor"`
	Data      map[string]interface{} `json:"data,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// TenantAuditLog represents audit log entries for tenant operations
type TenantAuditLog struct {
	ID        string                 `json:"id"`
	TenantID  string                 `json:"tenant_id"`
	Action    string                 `json:"action"`
	Resource  string                 `json:"resource"`
	User      string                 `json:"user"`
	Timestamp time.Time              `json:"timestamp"`
	IPAddress string                 `json:"ip_address"`
	UserAgent string                 `json:"user_agent"`
	Details   map[string]interface{} `json:"details,omitempty"`
	Result    string                 `json:"result"` // success, failure
	Error     string                 `json:"error,omitempty"`
}

// ResourceAllocation represents resource allocation for a tenant
type ResourceAllocation struct {
	TenantID    string    `json:"tenant_id"`
	CPUCores    float64   `json:"cpu_cores"`
	MemoryMB    int       `json:"memory_mb"`
	StorageGB   int       `json:"storage_gb"`
	NetworkMbps int       `json:"network_mbps"`
	AllocatedAt time.Time `json:"allocated_at"`
	ExpiresAt   time.Time `json:"expires_at,omitempty"`
}

// TenantBackup represents backup information for a tenant
type TenantBackup struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	Type        string    `json:"type"` // full, incremental
	Status      string    `json:"status"` // pending, running, completed, failed
	StartTime   time.Time `json:"start_time"`
	EndTime     time.Time `json:"end_time,omitempty"`
	SizeBytes   int64     `json:"size_bytes"`
	Location    string    `json:"location"`
	Checksum    string    `json:"checksum"`
	Error       string    `json:"error,omitempty"`
}