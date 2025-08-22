package types

import (
	"time"
)

// Severity represents the severity level of a threat
type Severity int

const (
	SeverityLow Severity = iota
	SeverityMedium
	SeverityHigh
	SeverityCritical
	SeverityUnknown
)

// String returns the string representation of severity
func (s Severity) String() string {
	switch s {
	case SeverityLow:
		return "low"
	case SeverityMedium:
		return "medium"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// RiskLevel represents the risk level of a package
type RiskLevel int

const (
	RiskLevelMinimal RiskLevel = iota
	RiskLevelLow
	RiskLevelMedium
	RiskLevelHigh
	RiskLevelCritical
)

// String returns the string representation of risk level
func (r RiskLevel) String() string {
	switch r {
	case RiskLevelMinimal:
		return "minimal"
	case RiskLevelLow:
		return "low"
	case RiskLevelMedium:
		return "medium"
	case RiskLevelHigh:
		return "high"
	case RiskLevelCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// ThreatType represents the type of security threat
type ThreatType string

const (
	ThreatTypeTyposquatting       ThreatType = "typosquatting"
	ThreatTypeDependencyConfusion ThreatType = "dependency_confusion"
	ThreatTypeMaliciousPackage    ThreatType = "malicious_package"
	ThreatTypeHomoglyph           ThreatType = "homoglyph"
	ThreatTypeReputationRisk      ThreatType = "reputation_risk"
	ThreatTypeSemanticSimilarity  ThreatType = "semantic_similarity"
	ThreatTypeSupplyChainRisk     ThreatType = "supply_chain_risk"
	ThreatTypeUnknownPackage      ThreatType = "unknown_package"
	ThreatTypeLowReputation       ThreatType = "low_reputation"
	ThreatTypeMalicious           ThreatType = "malicious"
	ThreatTypeVulnerable          ThreatType = "vulnerable"
	ThreatTypeSuspicious          ThreatType = "suspicious"
	ThreatTypeCommunityFlag       ThreatType = "community_flag"
	ThreatTypeZeroDay             ThreatType = "zero_day"
	ThreatTypeSupplyChain         ThreatType = "supply_chain"
	ThreatTypeEnterprisePolicy    ThreatType = "enterprise_policy"
)

// Dependency represents a package dependency
type Dependency struct {
	Name        string                 `json:"name"`
	Version     string                 `json:"version"`
	Registry    string                 `json:"registry"`
	Source      string                 `json:"source"`      // file where dependency was found
	Direct      bool                   `json:"direct"`      // true if direct dependency, false if transitive
	Development bool                   `json:"development"` // true if dev dependency
	Metadata    PackageMetadata        `json:"metadata,omitempty"`
	Constraints string                 `json:"constraints,omitempty"` // version constraints
	ExtraData   map[string]interface{} `json:"extra_data,omitempty"`
}

// PackageMetadata contains metadata about a package
type PackageMetadata struct {
	Name             string                 `json:"name"`
	Version          string                 `json:"version"`
	Registry         string                 `json:"registry"`
	Description      string                 `json:"description,omitempty"`
	Author           string                 `json:"author,omitempty"`
	Maintainers      []string               `json:"maintainers,omitempty"`
	Homepage         string                 `json:"homepage,omitempty"`
	Repository       string                 `json:"repository,omitempty"`
	License          string                 `json:"license,omitempty"`
	Keywords         []string               `json:"keywords,omitempty"`
	Downloads        int64                  `json:"downloads,omitempty"`
	PublishedAt      *time.Time             `json:"published_at,omitempty"`
	LastUpdated      *time.Time             `json:"last_updated,omitempty"`
	CreationDate     *time.Time             `json:"creation_date,omitempty"`
	CreatedAt        time.Time              `json:"created_at"`
	UpdatedAt        time.Time              `json:"updated_at"`
	Dependencies     []string               `json:"dependencies,omitempty"`
	HasInstallScript bool                   `json:"has_install_script"`
	FileCount        int                    `json:"file_count,omitempty"`
	Size             int64                  `json:"size,omitempty"`
	Checksums        map[string]string      `json:"checksums,omitempty"`
	Tags             []string               `json:"tags,omitempty"`
	Metadata         map[string]interface{} `json:"metadata,omitempty"`
}

// Threat represents a detected security threat
type Threat struct {
	ID                 string                 `json:"id"`
	Package            string                 `json:"package"`
	Version            string                 `json:"version,omitempty"`
	Registry           string                 `json:"registry"`
	Type               ThreatType             `json:"type"`
	Severity           Severity               `json:"severity"`
	Confidence         float64                `json:"confidence"` // 0.0 to 1.0
	Description        string                 `json:"description"`
	SimilarTo          string                 `json:"similar_to,omitempty"`
	Recommendation     string                 `json:"recommendation,omitempty"`
	Evidence           []Evidence             `json:"evidence,omitempty"`
	CVEs               []string               `json:"cves,omitempty"`
	References         []string               `json:"references,omitempty"`
	DetectedAt         time.Time              `json:"detected_at"`
	DetectionMethod    string                 `json:"detection_method"`
	Metadata           map[string]interface{} `json:"metadata,omitempty"`
	AffectedVersions   string                 `json:"affected_versions,omitempty"`
	FixedVersion       string                 `json:"fixed_version,omitempty"`
	ProposedCorrection string                 `json:"proposed_correction,omitempty"`
	CVE                string                 `json:"cve,omitempty"`
}

// AnalysisResult represents the result of package analysis
type AnalysisResult struct {
	ID        string                 `json:"id"`
	Package   *Dependency            `json:"package"`
	Threats   []Threat               `json:"threats"`
	RiskLevel Severity               `json:"risk_level"`
	Timestamp time.Time              `json:"timestamp"`
	Metadata  map[string]interface{} `json:"metadata"`
}

// Evidence represents evidence supporting a threat detection
type Evidence struct {
	Type        string      `json:"type"`
	Description string      `json:"description"`
	Value       interface{} `json:"value"`
	Score       float64     `json:"score,omitempty"`
}

// ThreatEvidence represents evidence for a specific threat
type ThreatEvidence struct {
	Type        string      `json:"type"`
	Description string      `json:"description"`
	Confidence  float64     `json:"confidence"`
	Value       interface{} `json:"value,omitempty"`
}

// Warning represents a non-critical security warning
type Warning struct {
	ID         string                 `json:"id"`
	Package    string                 `json:"package"`
	Version    string                 `json:"version,omitempty"`
	Registry   string                 `json:"registry"`
	Type       string                 `json:"type"`
	Message    string                 `json:"message"`
	Suggestion string                 `json:"suggestion,omitempty"`
	DetectedAt time.Time              `json:"detected_at"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

// ScanRequest represents a scan request
type ScanRequest struct {
	ID             string                 `json:"id"`
	UserID         string                 `json:"user_id,omitempty"`
	OrganizationID string                 `json:"organization_id,omitempty"`
	Path           string                 `json:"path,omitempty"`
	Dependencies   []Dependency           `json:"dependencies,omitempty"`
	Options        ScanRequestOptions     `json:"options"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt      time.Time              `json:"created_at"`
	StartedAt      *time.Time             `json:"started_at,omitempty"`
	CompletedAt    *time.Time             `json:"completed_at,omitempty"`
	ErrorMessage   *string                `json:"error_message,omitempty"`
	Status         ScanStatus             `json:"status"`
}

// ScanRequestOptions contains options for a scan request
type ScanRequestOptions struct {
	DeepAnalysis           bool     `json:"deep_analysis"`
	IncludeDevDependencies bool     `json:"include_dev_dependencies"`
	SimilarityThreshold    float64  `json:"similarity_threshold"`
	ExcludePackages        []string `json:"exclude_packages,omitempty"`
	Registries             []string `json:"registries,omitempty"`
	PolicyID               string   `json:"policy_id,omitempty"`
}

// ScanResponse represents a scan response
type ScanResponse struct {
	ID             string                 `json:"id"`
	ScanID         string                 `json:"scan_id"`
	PackageName    string                 `json:"package_name"`
	PackageVersion string                 `json:"package_version"`
	Registry       string                 `json:"registry"`
	Status         ScanStatus             `json:"status"`
	Progress       float64                `json:"progress"` // 0.0 to 1.0
	StartedAt      time.Time              `json:"started_at"`
	CompletedAt    *time.Time             `json:"completed_at,omitempty"`
	Duration       *time.Duration         `json:"duration,omitempty"`
	Threats        []Threat               `json:"threats,omitempty"`
	Warnings       []Warning              `json:"warnings,omitempty"`
	Summary        *ScanSummary           `json:"summary,omitempty"`
	Error          string                 `json:"error,omitempty"`
	Timestamp      time.Time              `json:"timestamp"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

// ScanStatus represents the status of a scan
type ScanStatus string

const (
	ScanStatusPending   ScanStatus = "pending"
	ScanStatusRunning   ScanStatus = "running"
	ScanStatusCompleted ScanStatus = "completed"
	ScanStatusFailed    ScanStatus = "failed"
	ScanStatusCancelled ScanStatus = "cancelled"
)

// ScanSummary provides a summary of scan results
type ScanSummary struct {
	TotalPackages    int            `json:"total_packages"`
	ScannedPackages  int            `json:"scanned_packages"`
	CleanPackages    int            `json:"clean_packages"`
	CriticalThreats  int            `json:"critical_threats"`
	HighThreats      int            `json:"high_threats"`
	MediumThreats    int            `json:"medium_threats"`
	LowThreats       int            `json:"low_threats"`
	TotalThreats     int            `json:"total_threats"`
	TotalWarnings    int            `json:"total_warnings"`
	HighestSeverity  Severity       `json:"highest_severity"`
	ThreatsFound     int            `json:"threats_found"`
	RiskDistribution map[string]int `json:"risk_distribution"`
	EnginesUsed      []string       `json:"engines_used,omitempty"`
}

// Policy represents a security policy
type Policy struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	Rules       []PolicyRule           `json:"rules"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	CreatedBy   string                 `json:"created_by"`
	Active      bool                   `json:"active"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// PolicyRule represents a rule within a policy
type PolicyRule struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	Type        PolicyRuleType         `json:"type"`
	Action      PolicyAction           `json:"action"`
	Conditions  []PolicyCondition      `json:"conditions"`
	Enabled     bool                   `json:"enabled"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// PolicyRuleType represents the type of policy rule
type PolicyRuleType string

const (
	PolicyRuleTypeBlock   PolicyRuleType = "block"
	PolicyRuleTypeAllow   PolicyRuleType = "allow"
	PolicyRuleTypeWarn    PolicyRuleType = "warn"
	PolicyRuleTypeMonitor PolicyRuleType = "monitor"
)

// PolicyAction represents the action to take when a rule matches
type PolicyAction string

const (
	PolicyActionBlock  PolicyAction = "block"
	PolicyActionWarn   PolicyAction = "warn"
	PolicyActionAllow  PolicyAction = "allow"
	PolicyActionIgnore PolicyAction = "ignore"
)

// PolicyCondition represents a condition in a policy rule
type PolicyCondition struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"`
	Value    interface{} `json:"value"`
}

// User represents a user in the system
type User struct {
	ID             int       `json:"id"`
	Username       string    `json:"username"`
	Email          string    `json:"email"`
	Role           string    `json:"role"`
	OrganizationID int       `json:"organization_id"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// Organization represents an organization in the system
type Organization struct {
	ID        int                   `json:"id"`
	Name      string                `json:"name"`
	Settings  *OrganizationSettings `json:"settings,omitempty"`
	CreatedAt time.Time             `json:"created_at"`
	UpdatedAt time.Time             `json:"updated_at"`
}

// OrganizationSettings contains organization-specific settings
type OrganizationSettings struct {
	CustomRegistries     []*CustomRegistry     `json:"custom_registries,omitempty"`
	ScanSettings         *ScanSettings         `json:"scan_settings,omitempty"`
	NotificationSettings *NotificationSettings `json:"notification_settings,omitempty"`
}

// CustomRegistry represents a custom package registry
type CustomRegistry struct {
	ID             int       `json:"id"`
	OrganizationID int       `json:"organization_id"`
	Name           string    `json:"name"`
	Type           string    `json:"type"` // npm, pypi, maven, nuget, etc.
	URL            string    `json:"url"`
	AuthType       string    `json:"auth_type"` // none, basic, token, oauth
	Username       string    `json:"username,omitempty"`
	Password       string    `json:"password,omitempty"`
	Token          string    `json:"token,omitempty"`
	Enabled        bool      `json:"enabled"`
	Priority       int       `json:"priority"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// ScanSettings contains scan configuration
type ScanSettings struct {
	AutoScan               bool    `json:"auto_scan"`
	ScanOnPush             bool    `json:"scan_on_push"`
	ScanSchedule           string  `json:"scan_schedule"` // cron format
	RiskThreshold          float64 `json:"risk_threshold"`
	IncludeDevDependencies bool    `json:"include_dev_dependencies"`
	MaxDepth               int     `json:"max_depth"`
}

// NotificationSettings contains notification configuration
type NotificationSettings struct {
	EmailEnabled   bool   `json:"email_enabled"`
	SlackEnabled   bool   `json:"slack_enabled"`
	SlackWebhook   string `json:"slack_webhook,omitempty"`
	WebhookEnabled bool   `json:"webhook_enabled"`
	WebhookURL     string `json:"webhook_url,omitempty"`
	NotifyOnHigh   bool   `json:"notify_on_high"`
	NotifyOnMedium bool   `json:"notify_on_medium"`
	NotifyOnLow    bool   `json:"notify_on_low"`
}

// Package represents a scanned package with its analysis results
type Package struct {
	Name         string           `json:"name"`
	Version      string           `json:"version"`
	Type         string           `json:"type,omitempty"`
	Registry     string           `json:"registry"`
	Threats      []Threat         `json:"threats,omitempty"`
	Warnings     []Warning        `json:"warnings,omitempty"`
	RiskLevel    Severity         `json:"risk_level"`
	RiskScore    float64          `json:"risk_score"`
	Metadata     *PackageMetadata `json:"metadata,omitempty"`
	Dependencies []Dependency     `json:"dependencies,omitempty"`
	AnalyzedAt   time.Time        `json:"analyzed_at"`
}

// DependencyTree represents a tree structure of package dependencies
type DependencyTree struct {
	Name         interface{}      `json:"name"`
	Version      interface{}      `json:"version"`
	Type         string           `json:"type"`
	Threats      []Threat         `json:"threats,omitempty"`
	Dependencies []DependencyTree `json:"dependencies"`
	Depth        int              `json:"depth,omitempty"`
	TotalCount   int              `json:"total_count,omitempty"`
	CreatedAt    time.Time        `json:"created_at,omitempty"`
}

// ScanResult represents the result of a package scan
type ScanResult struct {
	ID             string                 `json:"id"`
	ProjectID      int                    `json:"project_id,omitempty"`
	PackageID      string                 `json:"package_id,omitempty"`
	OrganizationID string                 `json:"organization_id,omitempty"`
	Target         string                 `json:"target"`
	Type           string                 `json:"type"`
	ScanType       string                 `json:"scan_type,omitempty"`
	Status         string                 `json:"status"`
	OverallRisk    string                 `json:"overall_risk,omitempty"`
	RiskScore      float64                `json:"risk_score,omitempty"`
	Packages       []*Package             `json:"packages"`
	Findings       []interface{}          `json:"findings,omitempty"`
	Summary        *ScanSummary           `json:"summary"`
	Duration       time.Duration          `json:"duration"`
	ScanDurationMs int64                  `json:"scan_duration_ms,omitempty"`
	Recommendations []string              `json:"recommendations,omitempty"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt      time.Time              `json:"created_at"`
	Error          string                 `json:"error,omitempty"`
}

// VulnerabilityCredit represents credit for vulnerability discovery/reporting
type VulnerabilityCredit struct {
	Name    string   `json:"name"`
	Contact []string `json:"contact,omitempty"`
	Type    string   `json:"type,omitempty"` // finder, reporter, analyst, coordinator, remediation_developer, remediation_reviewer, remediation_verifier, tool, sponsor, other
}

// VersionRange represents a range of affected versions
type VersionRange struct {
	Type   string         `json:"type"` // ECOSYSTEM, SEMVER, GIT
	Repo   string         `json:"repo,omitempty"`
	Events []VersionEvent `json:"events"`
}

// VersionEvent represents a version event (introduced, fixed, etc.)
type VersionEvent struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}

// VulnerabilityDatabase interface for vulnerability database implementations
type VulnerabilityDatabase interface {
	CheckVulnerabilities(pkg *Package) ([]*Vulnerability, error)
	GetVulnerabilityByID(id string) (*Vulnerability, error)
	SearchVulnerabilities(query string) ([]*Vulnerability, error)
}

// VulnerabilityDatabaseConfig represents configuration for vulnerability databases
type VulnerabilityDatabaseConfig struct {
	Type    string                 `json:"type"` // osv, github, nvd
	Enabled bool                   `json:"enabled"`
	APIKey  string                 `json:"api_key,omitempty"`
	BaseURL string                 `json:"base_url,omitempty"`
	Timeout time.Duration          `json:"timeout,omitempty"`
	Options map[string]interface{} `json:"options,omitempty"`
}

// ProjectScan represents a project that can be scanned
type ProjectScan struct {
	ID             int         `json:"id"`
	Name           string      `json:"name"`
	Path           string      `json:"path"`
	Type           string      `json:"type"` // nodejs, python, go, etc.
	OrganizationID int         `json:"organization_id"`
	LastScan       *ScanResult `json:"last_scan,omitempty"`
	AutoScan       bool        `json:"auto_scan"`
	CreatedAt      time.Time   `json:"created_at"`
	UpdatedAt      time.Time   `json:"updated_at"`
}

// UserRole represents a user's role
type UserRole string

const (
	UserRoleAdmin   UserRole = "admin"
	UserRoleMember  UserRole = "member"
	UserRoleViewer  UserRole = "viewer"
	UserRoleAPIOnly UserRole = "api_only"
)

// APIKey represents an API key for authentication
type APIKey struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	KeyHash     string     `json:"key_hash"` // Never expose the actual key
	Permissions []string   `json:"permissions,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
	Active      bool       `json:"active"`
}

// RegistryInfo represents information about a package registry
type RegistryInfo struct {
	Name        string                 `json:"name"`
	Type        string                 `json:"type"`
	URL         string                 `json:"url"`
	Description string                 `json:"description,omitempty"`
	Supported   bool                   `json:"supported"`
	Features    []string               `json:"features,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// DetectionResult represents the result of a detection algorithm
type DetectionResult struct {
	Algorithm  string                 `json:"algorithm"`
	Confidence float64                `json:"confidence"`
	Matches    []DetectionMatch       `json:"matches,omitempty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
	Duration   time.Duration          `json:"duration"`
}

// DetectionMatch represents a match found by a detection algorithm
type DetectionMatch struct {
	Package    string                 `json:"package"`
	Similarity float64                `json:"similarity"`
	Type       string                 `json:"type"`
	Evidence   []Evidence             `json:"evidence,omitempty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

// MLModelInfo represents information about an ML model
type MLModelInfo struct {
	Name        string                 `json:"name"`
	Version     string                 `json:"version"`
	Type        string                 `json:"type"`
	Description string                 `json:"description,omitempty"`
	Accuracy    float64                `json:"accuracy,omitempty"`
	TrainedAt   *time.Time             `json:"trained_at,omitempty"`
	Active      bool                   `json:"active"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// BatchJob represents a batch processing job
type BatchJob struct {
	ID             string                 `json:"id"`
	OrganizationID string                 `json:"organization_id"`
	UserID         string                 `json:"user_id"`
	Name           string                 `json:"name"`
	Description    string                 `json:"description,omitempty"`
	Status         string                 `json:"status"`
	Progress       float64                `json:"progress"`
	TotalPackages  int                    `json:"total_packages"`
	ProcessedCount int                    `json:"processed_count"`
	SuccessCount   int                    `json:"success_count"`
	FailureCount   int                    `json:"failure_count"`
	CreatedAt      time.Time              `json:"created_at"`
	UpdatedAt      time.Time              `json:"updated_at"`
	CompletedAt    *time.Time             `json:"completed_at,omitempty"`
	Configuration  map[string]interface{} `json:"configuration,omitempty"`
	Results        []AnalysisResult       `json:"results,omitempty"`
	Errors         []string               `json:"errors,omitempty"`
}

// TrustLevel represents the trust level of a package
type TrustLevel string

const (
	TrustLevelVeryLow TrustLevel = "very_low"
	TrustLevelLow     TrustLevel = "low"
	TrustLevelMedium  TrustLevel = "medium"
	TrustLevelHigh    TrustLevel = "high"
)

// ReputationScore represents the reputation score of a package
type ReputationScore struct {
	Score      float64    `json:"score"`
	TrustLevel TrustLevel `json:"trust_level"`
	Factors    []string   `json:"factors,omitempty"`
	Timestamp  time.Time  `json:"timestamp"`
}

// Vulnerability represents a security vulnerability
type Vulnerability struct {
	ID                string                 `json:"id"`
	CVE               string                 `json:"cve,omitempty"`
	Title             string                 `json:"title"`
	Description       string                 `json:"description"`
	Severity          Severity               `json:"severity"`
	CVSS              string                 `json:"cvss,omitempty"` // CVSS vector string or score
	CVSSScore         float64                `json:"cvss_score,omitempty"`
	Package           string                 `json:"package"`
	Versions          []string               `json:"versions,omitempty"`
	AffectedPackages  []AffectedPackage      `json:"affected_packages,omitempty"`
	References        []string               `json:"references,omitempty"`
	Aliases           []string               `json:"aliases,omitempty"`   // Alternative IDs (CVE, GHSA, etc.)
	Published         string                 `json:"published,omitempty"` // Published date as string
	Modified          string                 `json:"modified,omitempty"`  // Modified date as string
	PublishedAt       time.Time              `json:"published_at,omitempty"`
	UpdatedAt         time.Time              `json:"updated_at,omitempty"`
	Withdrawn         string                 `json:"withdrawn,omitempty"`          // Withdrawn date if applicable
	Source            string                 `json:"source,omitempty"`             // Source database (OSV, GitHub, NVD)
	DatabaseSpecific  map[string]interface{} `json:"database_specific,omitempty"`  // Database-specific fields
	EcosystemSpecific map[string]interface{} `json:"ecosystem_specific,omitempty"` // Ecosystem-specific fields
	Credits           []VulnerabilityCredit  `json:"credits,omitempty"`            // Credits for discovery/reporting
	Metadata          map[string]interface{} `json:"metadata,omitempty"`
}

// AffectedPackage represents a package affected by a vulnerability
type AffectedPackage struct {
	Name              string                 `json:"name"`
	Vendor            string                 `json:"vendor,omitempty"`
	Version           string                 `json:"version,omitempty"`
	Versions          []string               `json:"versions,omitempty"` // Multiple affected versions
	VersionRange      string                 `json:"version_range,omitempty"`
	Ecosystem         string                 `json:"ecosystem,omitempty"`
	PURL              string                 `json:"purl,omitempty"`   // Package URL
	Ranges            []VersionRange         `json:"ranges,omitempty"` // Version ranges with events
	DatabaseSpecific  map[string]interface{} `json:"database_specific,omitempty"`
	EcosystemSpecific map[string]interface{} `json:"ecosystem_specific,omitempty"`
}

// AuditLog represents an audit log entry
type AuditLog struct {
	ID             string                 `json:"id"`
	UserID         string                 `json:"user_id,omitempty"`
	OrganizationID string                 `json:"organization_id,omitempty"`
	Action         string                 `json:"action"`
	Resource       string                 `json:"resource"`
	ResourceID     string                 `json:"resource_id,omitempty"`
	ResourceType   string                 `json:"resource_type,omitempty"`
	Details        map[string]interface{} `json:"details,omitempty"`
	IPAddress      string                 `json:"ip_address,omitempty"`
	UserAgent      string                 `json:"user_agent,omitempty"`
	Timestamp      time.Time              `json:"timestamp"`
	Success        bool                   `json:"success"`
	Error          string                 `json:"error,omitempty"`
}
