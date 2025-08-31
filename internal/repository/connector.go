package repository

import (
	"context"
	"time"
)

// Repository represents a code repository
type Repository struct {
	ID            string                 `json:"id"`
	Name          string                 `json:"name"`
	FullName      string                 `json:"full_name"`
	URL           string                 `json:"url"`
	CloneURL      string                 `json:"clone_url"`
	SSHURL        string                 `json:"ssh_url"`
	DefaultBranch string                 `json:"default_branch"`
	Language      string                 `json:"language"`
	Languages     map[string]int         `json:"languages"`
	Private       bool                   `json:"private"`
	Archived      bool                   `json:"archived"`
	Fork          bool                   `json:"fork"`
	Size          int64                  `json:"size"`
	StarCount     int                    `json:"star_count"`
	ForkCount     int                    `json:"fork_count"`
	Topics        []string               `json:"topics"`
	CreatedAt     time.Time              `json:"created_at"`
	UpdatedAt     time.Time              `json:"updated_at"`
	PushedAt      time.Time              `json:"pushed_at"`
	Metadata      map[string]interface{} `json:"metadata"`
	Platform      string                 `json:"platform"`
	Owner         Owner                  `json:"owner"`
}

// Owner represents the repository owner
type Owner struct {
	ID        string `json:"id"`
	Login     string `json:"login"`
	Name      string `json:"name"`
	Type      string `json:"type"` // user, organization, group
	AvatarURL string `json:"avatar_url"`
}

// Organization represents a platform organization/group
type Organization struct {
	ID          string                 `json:"id"`
	Login       string                 `json:"login"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	URL         string                 `json:"url"`
	AvatarURL   string                 `json:"avatar_url"`
	Type        string                 `json:"type"`
	Platform    string                 `json:"platform"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// RepositoryFilter defines filtering criteria for repositories
type RepositoryFilter struct {
	Languages         []string               `json:"languages"`
	Topics            []string               `json:"topics"`
	IncludePrivate    bool                   `json:"include_private"`
	IncludeArchived   bool                   `json:"include_archived"`
	IncludeForks      bool                   `json:"include_forks"`
	MinStars          int                    `json:"min_stars"`
	MaxSize           int64                  `json:"max_size"`
	UpdatedAfter      *time.Time             `json:"updated_after"`
	UpdatedBefore     *time.Time             `json:"updated_before"`
	NamePattern       string                 `json:"name_pattern"`
	ExcludePatterns   []string               `json:"exclude_patterns"`
	CustomFilters     map[string]interface{} `json:"custom_filters"`
	HasPackageManager bool                   `json:"has_package_manager"`
}

// ScanRequest represents a repository scan request
type ScanRequest struct {
	Repository  *Repository `json:"repository"`
	Branch      string      `json:"branch"`
	CommitSHA   string      `json:"commit_sha"`
	ScanID      string      `json:"scan_id"`
	RequestedBy string      `json:"requested_by"`
	Priority    int         `json:"priority"`
	Options     ScanOptions `json:"options"`
	CreatedAt   time.Time   `json:"created_at"`
}

// ScanOptions defines scanning configuration
type ScanOptions struct {
	DeepScan         bool          `json:"deep_scan"`
	IncludeDev       bool          `json:"include_dev"`
	Timeout          time.Duration `json:"timeout"`
	MaxFileSize      int64         `json:"max_file_size"`
	ExcludePatterns  []string      `json:"exclude_patterns"`
	LanguageOverride string        `json:"language_override"`
	CustomRules      []string      `json:"custom_rules"`
	OutputFormats    []string      `json:"output_formats"`
	// Legacy fields for compatibility
	OutputFormat           string   `json:"output_format"`
	DeepAnalysis           bool     `json:"deep_analysis"`
	IncludeDevDependencies bool     `json:"include_dev_dependencies"`
	SimilarityThreshold    float64  `json:"similarity_threshold"`
	ExcludePackages        []string `json:"exclude_packages"`
	CheckVulnerabilities   bool     `json:"check_vulnerabilities"`
}

// ScanResult represents the result of a repository scan
type ScanResult struct {
	Repository      *Repository            `json:"repository"`
	ScanID          string                 `json:"scan_id"`
	Status          string                 `json:"status"`
	StartTime       time.Time              `json:"start_time"`
	EndTime         time.Time              `json:"end_time"`
	Duration        time.Duration          `json:"duration"`
	Error           string                 `json:"error,omitempty"`
	Message         string                 `json:"message,omitempty"`
	AnalysisResult  interface{}            `json:"analysis_result,omitempty"`
	DependencyFiles []string               `json:"dependency_files"`
	Metadata        map[string]interface{} `json:"metadata"`
}

// AuthConfig represents authentication configuration
type AuthConfig struct {
	Type         string            `json:"type"` // token, oauth, ssh
	Token        string            `json:"token"`
	Username     string            `json:"username"`
	Password     string            `json:"password"`
	ClientID     string            `json:"client_id"`
	ClientSecret string            `json:"client_secret"`
	SSHKey       string            `json:"ssh_key"`
	SSHKeyPath   string            `json:"ssh_key_path"`
	Metadata     map[string]string `json:"metadata"`
}

// PlatformConfig represents platform-specific configuration
type PlatformConfig struct {
	Name          string                 `json:"name"`
	BaseURL       string                 `json:"base_url"`
	APIVersion    string                 `json:"api_version"`
	Auth          AuthConfig             `json:"auth"`
	RateLimit     RateLimitConfig        `json:"rate_limit"`
	Timeout       time.Duration          `json:"timeout"`
	Retries       int                    `json:"retries"`
	Organizations []string               `json:"organizations"`
	Repositories  []string               `json:"repositories"`
	Metadata      map[string]interface{} `json:"metadata"`
}

// RateLimitConfig defines rate limiting configuration
type RateLimitConfig struct {
	RequestsPerHour   int    `json:"requests_per_hour"`
	RequestsPerMinute int    `json:"requests_per_minute"`
	BurstLimit        int    `json:"burst_limit"`
	BackoffStrategy   string `json:"backoff_strategy"`
	MaxRetries        int    `json:"max_retries"`
}

// Connector defines the interface for repository platform connectors
type Connector interface {
	// Platform information
	GetPlatformName() string
	GetPlatformType() string
	GetAPIVersion() string

	// Authentication
	Authenticate(ctx context.Context, config AuthConfig) error
	ValidateAuth(ctx context.Context) error
	RefreshAuth(ctx context.Context) error

	// Organization/Group operations
	ListOrganizations(ctx context.Context) ([]*Organization, error)
	GetOrganization(ctx context.Context, name string) (*Organization, error)

	// Repository discovery
	ListRepositories(ctx context.Context, owner string, filter *RepositoryFilter) ([]*Repository, error)
	ListOrgRepositories(ctx context.Context, org string, filter *RepositoryFilter) ([]*Repository, error)
	GetRepository(ctx context.Context, owner, name string) (*Repository, error)
	SearchRepositories(ctx context.Context, query string, filter *RepositoryFilter) ([]*Repository, error)

	// Repository content
	GetRepositoryContent(ctx context.Context, repo *Repository, path string, ref string) ([]byte, error)
	ListRepositoryFiles(ctx context.Context, repo *Repository, path string, ref string) ([]string, error)
	GetPackageFiles(ctx context.Context, repo *Repository, ref string) (map[string][]byte, error)

	// Repository metadata
	GetRepositoryLanguages(ctx context.Context, repo *Repository) (map[string]int, error)
	GetRepositoryTopics(ctx context.Context, repo *Repository) ([]string, error)
	GetRepositoryBranches(ctx context.Context, repo *Repository) ([]string, error)
	GetRepositoryCommits(ctx context.Context, repo *Repository, branch string, limit int) ([]Commit, error)

	// Webhooks and events
	CreateWebhook(ctx context.Context, repo *Repository, webhookURL string, events []string) error
	DeleteWebhook(ctx context.Context, repo *Repository, webhookID string) error
	ListWebhooks(ctx context.Context, repo *Repository) ([]Webhook, error)

	// Rate limiting and health
	GetRateLimit(ctx context.Context) (*RateLimit, error)
	HealthCheck(ctx context.Context) error

	// Cleanup
	Close() error
}

// Commit represents a repository commit
type Commit struct {
	SHA     string    `json:"sha"`
	Message string    `json:"message"`
	Author  string    `json:"author"`
	Email   string    `json:"email"`
	Date    time.Time `json:"date"`
	URL     string    `json:"url"`
}

// Webhook represents a repository webhook
type Webhook struct {
	ID     string   `json:"id"`
	URL    string   `json:"url"`
	Events []string `json:"events"`
	Active bool     `json:"active"`
}

// RateLimit represents API rate limit information
type RateLimit struct {
	Limit     int       `json:"limit"`
	Remaining int       `json:"remaining"`
	ResetTime time.Time `json:"reset_time"`
	Used      int       `json:"used"`
}

// ConnectorFactory creates platform-specific connectors
type ConnectorFactory interface {
	CreateConnector(platform string, config PlatformConfig) (Connector, error)
	GetSupportedPlatforms() []string
	ValidateConfig(platform string, config PlatformConfig) error
}

// RepositoryManager manages multiple repository connectors
type RepositoryManager interface {
	// Connector management
	AddConnector(name string, connector Connector) error
	RemoveConnector(name string) error
	GetConnector(name string) (Connector, error)
	ListConnectors() []string

	// Multi-platform operations
	DiscoverRepositories(ctx context.Context, platforms []string, filter *RepositoryFilter) ([]*Repository, error)
	ScanRepository(ctx context.Context, request *ScanRequest) error
	BulkScan(ctx context.Context, requests []*ScanRequest) error

	// Configuration
	LoadConfig(configPath string) error
	ValidateConfiguration() error
	GetConfiguration() map[string]PlatformConfig

	// Health and monitoring
	HealthCheck(ctx context.Context) map[string]error
	GetMetrics(ctx context.Context) map[string]interface{}
}
