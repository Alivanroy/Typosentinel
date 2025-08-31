package config

import (
	"fmt"
	"time"
)

// RepositoryConfig holds repository scanning configuration
type RepositoryConfig struct {
	Enabled   bool                      `yaml:"enabled" json:"enabled"`
	Platforms map[string]PlatformConfig `yaml:"platforms" json:"platforms"`
	Discovery DiscoveryConfig           `yaml:"discovery" json:"discovery"`
	Scanning  ScanningConfig            `yaml:"scanning" json:"scanning"`
	Webhooks  RepositoryWebhookConfig   `yaml:"webhooks" json:"webhooks"`
	Filters   GlobalRepositoryFilters   `yaml:"filters" json:"filters"`
	Scheduled []ScheduledRepositoryScan `yaml:"scheduled" json:"scheduled"`
}

// PlatformConfig holds platform-specific configuration
type PlatformConfig struct {
	Enabled   bool                      `yaml:"enabled" json:"enabled"`
	BaseURL   string                    `yaml:"base_url" json:"base_url"`
	Auth      AuthenticationConfig      `yaml:"auth" json:"auth"`
	Timeout   time.Duration             `yaml:"timeout" json:"timeout"`
	RateLimit RepositoryRateLimitConfig `yaml:"rate_limit" json:"rate_limit"`
	Settings  map[string]interface{}    `yaml:"settings" json:"settings"`
	Targets   []ScanTarget              `yaml:"targets" json:"targets"`
}

// AuthenticationConfig holds authentication settings
type AuthenticationConfig struct {
	Type         string `yaml:"type" json:"type"` // token, oauth, app, ssh
	Token        string `yaml:"token" json:"-"`
	ClientID     string `yaml:"client_id" json:"client_id"`
	ClientSecret string `yaml:"client_secret" json:"-"`
	AppID        string `yaml:"app_id" json:"app_id"`
	PrivateKey   string `yaml:"private_key" json:"-"`
	Username     string `yaml:"username" json:"username"`
	Password     string `yaml:"password" json:"-"`
	SSHKey       string `yaml:"ssh_key" json:"-"`
}

// RepositoryRateLimitConfig holds repository-specific rate limiting configuration
type RepositoryRateLimitConfig struct {
	RequestsPerHour int           `yaml:"requests_per_hour" json:"requests_per_hour"`
	Burst           int           `yaml:"burst" json:"burst"`
	RetryDelay      time.Duration `yaml:"retry_delay" json:"retry_delay"`
	MaxRetries      int           `yaml:"max_retries" json:"max_retries"`
}

// ScanTarget represents a scanning target
type ScanTarget struct {
	Type         string                 `yaml:"type" json:"type"` // organization, user, repository, search
	Name         string                 `yaml:"name" json:"name"`
	Organization string                 `yaml:"organization" json:"organization"`
	User         string                 `yaml:"user" json:"user"`
	Group        string                 `yaml:"group" json:"group"`
	Project      string                 `yaml:"project" json:"project"`
	Repositories []string               `yaml:"repositories" json:"repositories"`
	SearchQuery  string                 `yaml:"search_query" json:"search_query"`
	IncludeAll   bool                   `yaml:"include_all" json:"include_all"`
	Filter       *RepositoryFilter      `yaml:"filter" json:"filter"`
	Metadata     map[string]interface{} `yaml:"metadata" json:"metadata"`
}

// RepositoryFilter holds repository filtering options
type RepositoryFilter struct {
	Languages       []string   `yaml:"languages" json:"languages"`
	Topics          []string   `yaml:"topics" json:"topics"`
	IncludePrivate  bool       `yaml:"include_private" json:"include_private"`
	IncludeArchived bool       `yaml:"include_archived" json:"include_archived"`
	IncludeForks    bool       `yaml:"include_forks" json:"include_forks"`
	MinStars        int        `yaml:"min_stars" json:"min_stars"`
	MaxStars        int        `yaml:"max_stars" json:"max_stars"`
	MinSize         int64      `yaml:"min_size" json:"min_size"`
	MaxSize         int64      `yaml:"max_size" json:"max_size"`
	NamePattern     string     `yaml:"name_pattern" json:"name_pattern"`
	ExcludePatterns []string   `yaml:"exclude_patterns" json:"exclude_patterns"`
	CreatedAfter    *time.Time `yaml:"created_after" json:"created_after"`
	CreatedBefore   *time.Time `yaml:"created_before" json:"created_before"`
	UpdatedAfter    *time.Time `yaml:"updated_after" json:"updated_after"`
	UpdatedBefore   *time.Time `yaml:"updated_before" json:"updated_before"`
}

// DiscoveryConfig holds repository discovery configuration
type DiscoveryConfig struct {
	Enabled             bool                      `yaml:"enabled" json:"enabled"`
	Interval            time.Duration             `yaml:"interval" json:"interval"`
	MaxReposPerPlatform int                       `yaml:"max_repos_per_platform" json:"max_repos_per_platform"`
	Workers             int                       `yaml:"workers" json:"workers"`
	Timeout             time.Duration             `yaml:"timeout" json:"timeout"`
	Platforms           []PlatformDiscoveryConfig `yaml:"platforms" json:"platforms"`
	Cache               DiscoveryCacheConfig      `yaml:"cache" json:"cache"`
}

// PlatformDiscoveryConfig holds platform-specific discovery settings
type PlatformDiscoveryConfig struct {
	Platform      string            `yaml:"platform" json:"platform"`
	Enabled       bool              `yaml:"enabled" json:"enabled"`
	Organizations []string          `yaml:"organizations" json:"organizations"`
	Users         []string          `yaml:"users" json:"users"`
	Groups        []string          `yaml:"groups" json:"groups"`
	Projects      []string          `yaml:"projects" json:"projects"`
	Repositories  []string          `yaml:"repositories" json:"repositories"`
	SearchQueries []string          `yaml:"search_queries" json:"search_queries"`
	Filter        *RepositoryFilter `yaml:"filter" json:"filter"`
}

// DiscoveryCacheConfig holds discovery caching configuration
type DiscoveryCacheConfig struct {
	Enabled bool          `yaml:"enabled" json:"enabled"`
	TTL     time.Duration `yaml:"ttl" json:"ttl"`
	Backend string        `yaml:"backend" json:"backend"` // memory, redis, database
}

// ScanningConfig holds scanning configuration
type ScanningConfig struct {
	Concurrency     ConcurrencyConfig  `yaml:"concurrency" json:"concurrency"`
	Timeouts        TimeoutConfig      `yaml:"timeouts" json:"timeouts"`
	Cache           ScanCacheConfig    `yaml:"cache" json:"cache"`
	Filters         ScanFilterConfig   `yaml:"filters" json:"filters"`
	PackageManagers []string           `yaml:"package_managers" json:"package_managers"`
	ScanTypes       []string           `yaml:"scan_types" json:"scan_types"`
	OutputFormats   []string           `yaml:"output_formats" json:"output_formats"`
	Policies        []ScanPolicyConfig `yaml:"policies" json:"policies"`
}

// ConcurrencyConfig holds concurrency settings
type ConcurrencyConfig struct {
	MaxConcurrentRepos int `yaml:"max_concurrent_repos" json:"max_concurrent_repos"`
	MaxConcurrentFiles int `yaml:"max_concurrent_files" json:"max_concurrent_files"`
	WorkerPoolSize     int `yaml:"worker_pool_size" json:"worker_pool_size"`
}

// TimeoutConfig holds timeout settings
type TimeoutConfig struct {
	RepositoryClone time.Duration `yaml:"repository_clone" json:"repository_clone"`
	PackageAnalysis time.Duration `yaml:"package_analysis" json:"package_analysis"`
	TotalScan       time.Duration `yaml:"total_scan" json:"total_scan"`
	APIRequest      time.Duration `yaml:"api_request" json:"api_request"`
}

// ScanCacheConfig holds scan caching configuration
type ScanCacheConfig struct {
	Enabled bool          `yaml:"enabled" json:"enabled"`
	TTL     time.Duration `yaml:"ttl" json:"ttl"`
	Backend string        `yaml:"backend" json:"backend"`
}

// ScanFilterConfig holds scan filtering configuration
type ScanFilterConfig struct {
	FileSizeLimit    int64    `yaml:"file_size_limit" json:"file_size_limit"`
	ExcludePatterns  []string `yaml:"exclude_patterns" json:"exclude_patterns"`
	IncludePatterns  []string `yaml:"include_patterns" json:"include_patterns"`
	IncludeLanguages []string `yaml:"include_languages" json:"include_languages"`
	ExcludeLanguages []string `yaml:"exclude_languages" json:"exclude_languages"`
}

// ScanPolicyConfig holds scan policy configuration
type ScanPolicyConfig struct {
	Name        string                 `yaml:"name" json:"name"`
	Description string                 `yaml:"description" json:"description"`
	Enabled     bool                   `yaml:"enabled" json:"enabled"`
	Conditions  []PolicyCondition      `yaml:"conditions" json:"conditions"`
	Actions     []PolicyAction         `yaml:"actions" json:"actions"`
	Metadata    map[string]interface{} `yaml:"metadata" json:"metadata"`
}

// PolicyCondition represents a policy condition
type PolicyCondition struct {
	Field    string      `yaml:"field" json:"field"`
	Operator string      `yaml:"operator" json:"operator"` // eq, ne, gt, lt, gte, lte, in, contains
	Value    interface{} `yaml:"value" json:"value"`
}

// PolicyAction represents a policy action
type PolicyAction struct {
	Type       string                 `yaml:"type" json:"type"` // block, warn, notify, approve
	Parameters map[string]interface{} `yaml:"parameters" json:"parameters"`
}

// RepositoryWebhookConfig holds repository webhook configuration
type RepositoryWebhookConfig struct {
	Enabled   bool                             `yaml:"enabled" json:"enabled"`
	Endpoint  string                           `yaml:"endpoint" json:"endpoint"`
	Secret    string                           `yaml:"secret" json:"-"`
	Events    []string                         `yaml:"events" json:"events"`
	Platforms map[string]WebhookPlatformConfig `yaml:"platforms" json:"platforms"`
	Security  WebhookSecurityConfig            `yaml:"security" json:"security"`
}

// WebhookPlatformConfig holds platform-specific webhook settings
type WebhookPlatformConfig struct {
	Enabled     bool                   `yaml:"enabled" json:"enabled"`
	ContentType string                 `yaml:"content_type" json:"content_type"`
	SSLVerify   bool                   `yaml:"ssl_verify" json:"ssl_verify"`
	Events      []string               `yaml:"events" json:"events"`
	Settings    map[string]interface{} `yaml:"settings" json:"settings"`
}

// WebhookSecurityConfig holds webhook security settings
type WebhookSecurityConfig struct {
	ValidateSignature bool     `yaml:"validate_signature" json:"validate_signature"`
	AllowedIPs        []string `yaml:"allowed_ips" json:"allowed_ips"`
	RateLimit         int      `yaml:"rate_limit" json:"rate_limit"`
}

// GlobalRepositoryFilters holds global filtering options
type GlobalRepositoryFilters struct {
	IncludePrivate  bool     `yaml:"include_private" json:"include_private"`
	IncludeArchived bool     `yaml:"include_archived" json:"include_archived"`
	IncludeForks    bool     `yaml:"include_forks" json:"include_forks"`
	MinStars        int      `yaml:"min_stars" json:"min_stars"`
	Languages       []string `yaml:"languages" json:"languages"`
	ExcludePatterns []string `yaml:"exclude_patterns" json:"exclude_patterns"`
}

// ScheduledRepositoryScan holds scheduled scan configuration
type ScheduledRepositoryScan struct {
	ID          string                 `yaml:"id" json:"id"`
	Name        string                 `yaml:"name" json:"name"`
	Description string                 `yaml:"description" json:"description"`
	Enabled     bool                   `yaml:"enabled" json:"enabled"`
	Schedule    string                 `yaml:"schedule" json:"schedule"` // Cron expression
	Timezone    string                 `yaml:"timezone" json:"timezone"`
	Targets     []ScanTarget           `yaml:"targets" json:"targets"`
	Options     ScanningConfig         `yaml:"options" json:"options"`
	Output      []OutputConfig         `yaml:"output" json:"output"`
	Policies    []ScanPolicyConfig     `yaml:"policies" json:"policies"`
	Metadata    map[string]interface{} `yaml:"metadata" json:"metadata"`
	CreatedAt   time.Time              `yaml:"created_at" json:"created_at"`
	UpdatedAt   time.Time              `yaml:"updated_at" json:"updated_at"`
}

// OutputConfig holds output configuration
type OutputConfig struct {
	Format      string                 `yaml:"format" json:"format"` // sarif, spdx, cyclonedx, json, csv
	Destination string                 `yaml:"destination" json:"destination"`
	Template    string                 `yaml:"template" json:"template"`
	Options     map[string]interface{} `yaml:"options" json:"options"`
	Enabled     bool                   `yaml:"enabled" json:"enabled"`
}

// DefaultRepositoryConfig returns default repository configuration
func DefaultRepositoryConfig() *RepositoryConfig {
	return &RepositoryConfig{
		Enabled: true,
		Platforms: map[string]PlatformConfig{
			"github": {
				Enabled: false,
				BaseURL: "https://api.github.com",
				Timeout: 30 * time.Second,
				RateLimit: RepositoryRateLimitConfig{
					RequestsPerHour: 5000,
					Burst:           100,
					RetryDelay:      5 * time.Second,
					MaxRetries:      3,
				},
			},
			"gitlab": {
				Enabled: false,
				BaseURL: "https://gitlab.com/api/v4",
				Timeout: 30 * time.Second,
				RateLimit: RepositoryRateLimitConfig{
					RequestsPerHour: 2000,
					Burst:           50,
					RetryDelay:      5 * time.Second,
					MaxRetries:      3,
				},
			},
			"bitbucket": {
				Enabled: false,
				BaseURL: "https://api.bitbucket.org/2.0",
				Timeout: 30 * time.Second,
				RateLimit: RepositoryRateLimitConfig{
					RequestsPerHour: 1000,
					Burst:           25,
					RetryDelay:      5 * time.Second,
					MaxRetries:      3,
				},
			},
			"azuredevops": {
				Enabled: false,
				BaseURL: "https://dev.azure.com",
				Timeout: 30 * time.Second,
				RateLimit: RepositoryRateLimitConfig{
					RequestsPerHour: 3000,
					Burst:           75,
					RetryDelay:      5 * time.Second,
					MaxRetries:      3,
				},
			},
		},
		Discovery: DiscoveryConfig{
			Enabled:             true,
			Interval:            1 * time.Hour,
			MaxReposPerPlatform: 1000,
			Workers:             4,
			Timeout:             5 * time.Minute,
			Cache: DiscoveryCacheConfig{
				Enabled: true,
				TTL:     24 * time.Hour,
				Backend: "memory",
			},
		},
		Scanning: ScanningConfig{
			Concurrency: ConcurrencyConfig{
				MaxConcurrentRepos: 10,
				MaxConcurrentFiles: 50,
				WorkerPoolSize:     4,
			},
			Timeouts: TimeoutConfig{
				RepositoryClone: 5 * time.Minute,
				PackageAnalysis: 10 * time.Minute,
				TotalScan:       30 * time.Minute,
				APIRequest:      30 * time.Second,
			},
			Cache: ScanCacheConfig{
				Enabled: true,
				TTL:     24 * time.Hour,
				Backend: "memory",
			},
			Filters: ScanFilterConfig{
				FileSizeLimit: 10 * 1024 * 1024, // 10MB
				ExcludePatterns: []string{
					"**/node_modules/**",
					"**/vendor/**",
					"**/.git/**",
					"**/test/**",
					"**/tests/**",
				},
				IncludeLanguages: []string{
					"javascript", "python", "go", "java", "csharp",
				},
			},
			PackageManagers: []string{
				"npm", "pip", "go", "maven", "nuget", "composer", "cargo",
			},
			ScanTypes: []string{
				"dependency", "vulnerability", "license", "secret",
			},
			OutputFormats: []string{
				"json", "sarif", "spdx",
			},
		},
		Webhooks: RepositoryWebhookConfig{
			Enabled: false,
			Events:  []string{"push", "pull_request", "release"},
			Security: WebhookSecurityConfig{
				ValidateSignature: true,
				RateLimit:         100,
			},
		},
		Filters: GlobalRepositoryFilters{
			IncludePrivate:  false,
			IncludeArchived: false,
			IncludeForks:    false,
			MinStars:        1,
			Languages: []string{
				"Go", "Python", "JavaScript", "TypeScript", "Java", "C#",
			},
			ExcludePatterns: []string{
				"test-*", "demo-*", "example-*",
			},
		},
	}
}

// Validate validates the repository configuration
func (rc *RepositoryConfig) Validate() error {
	if !rc.Enabled {
		return nil
	}

	// Validate platforms
	enabledPlatforms := 0
	for name, platform := range rc.Platforms {
		if platform.Enabled {
			enabledPlatforms++
			if platform.BaseURL == "" {
				return fmt.Errorf("platform %s: base_url is required", name)
			}
			if platform.Auth.Type == "" {
				return fmt.Errorf("platform %s: auth.type is required", name)
			}
		}
	}

	if enabledPlatforms == 0 {
		return fmt.Errorf("at least one platform must be enabled")
	}

	// Validate discovery configuration
	if rc.Discovery.Enabled {
		if rc.Discovery.Workers <= 0 {
			return fmt.Errorf("discovery.workers must be greater than 0")
		}
		if rc.Discovery.MaxReposPerPlatform <= 0 {
			return fmt.Errorf("discovery.max_repos_per_platform must be greater than 0")
		}
	}

	// Validate scanning configuration
	if rc.Scanning.Concurrency.MaxConcurrentRepos <= 0 {
		return fmt.Errorf("scanning.concurrency.max_concurrent_repos must be greater than 0")
	}
	if rc.Scanning.Concurrency.MaxConcurrentFiles <= 0 {
		return fmt.Errorf("scanning.concurrency.max_concurrent_files must be greater than 0")
	}

	return nil
}

// GetEnabledPlatforms returns a list of enabled platforms
func (rc *RepositoryConfig) GetEnabledPlatforms() []string {
	var platforms []string
	for name, config := range rc.Platforms {
		if config.Enabled {
			platforms = append(platforms, name)
		}
	}
	return platforms
}

// GetPlatformConfig returns configuration for a specific platform
func (rc *RepositoryConfig) GetPlatformConfig(platform string) (*PlatformConfig, bool) {
	config, exists := rc.Platforms[platform]
	return &config, exists
}

// IsWebhookEnabled checks if webhooks are enabled for a platform
func (rc *RepositoryConfig) IsWebhookEnabled(platform string) bool {
	if !rc.Webhooks.Enabled {
		return false
	}
	platformConfig, exists := rc.Webhooks.Platforms[platform]
	return exists && platformConfig.Enabled
}
