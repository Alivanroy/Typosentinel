package config

import (
	"fmt"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/cache"
	"github.com/Alivanroy/Typosentinel/internal/monitoring"
)

// EnterpriseConfig holds enterprise-specific configuration
type EnterpriseConfig struct {
	Enabled    bool                        `yaml:"enabled" json:"enabled"`
	License    LicenseConfig              `yaml:"license" json:"license"`
	Cache      *cache.CacheConfig         `yaml:"cache" json:"cache"`
	Monitoring *monitoring.MonitoringConfig `yaml:"monitoring" json:"monitoring"`
	EnterpriseSecurity   EnterpriseSecurityConfig             `yaml:"enterprise_security" json:"enterprise_security"`
	Audit      AuditConfig                `yaml:"audit" json:"audit"`
	EnterpriseRateLimit  EnterpriseRateLimitConfig            `yaml:"enterprise_rate_limit" json:"enterprise_rate_limit"`
	SSO        SSOConfig                  `yaml:"sso" json:"sso"`
	Reporting  ReportingConfig            `yaml:"reporting" json:"reporting"`
	Repository RepositoryConfig          `yaml:"repository" json:"repository"`
}

// LicenseConfig holds license configuration
type LicenseConfig struct {
	Key        string    `yaml:"key" json:"key"`
	Type       string    `yaml:"type" json:"type"` // "trial", "standard", "premium", "enterprise"
	ExpiresAt  time.Time `yaml:"expires_at" json:"expires_at"`
	MaxUsers   int       `yaml:"max_users" json:"max_users"`
	MaxScans   int       `yaml:"max_scans" json:"max_scans"`
	Features   []string  `yaml:"features" json:"features"`
	Validated  bool      `yaml:"-" json:"-"`
}

// EnterpriseSecurityConfig holds security-related configuration
type EnterpriseSecurityConfig struct {
	EnterpriseEncryption    EnterpriseEncryptionConfig    `yaml:"encryption" json:"encryption"`
	Authentication AuthConfig        `yaml:"authentication" json:"authentication"`
	Authorization  AuthzConfig       `yaml:"authorization" json:"authorization"`
	EnterpriseTLS           EnterpriseTLSConfig         `yaml:"tls" json:"tls"`
	Secrets       SecretsConfig     `yaml:"secrets" json:"secrets"`
}

// EnterpriseEncryptionConfig holds encryption settings
type EnterpriseEncryptionConfig struct {
	Enabled   bool   `yaml:"enabled" json:"enabled"`
	Algorithm string `yaml:"algorithm" json:"algorithm"` // "AES-256-GCM", "ChaCha20-Poly1305"
	KeyFile   string `yaml:"key_file" json:"key_file"`
	Rotation  time.Duration `yaml:"rotation" json:"rotation"`
}

// AuthConfig holds authentication configuration
type AuthConfig struct {
	Enabled      bool          `yaml:"enabled" json:"enabled"`
	Method       string        `yaml:"method" json:"method"` // "jwt", "oauth2", "ldap", "saml"
	JWT          EnterpriseJWTConfig     `yaml:"jwt" json:"jwt"`
	OAuth2       OAuth2Config  `yaml:"oauth2" json:"oauth2"`
	LDAP         LDAPConfig    `yaml:"ldap" json:"ldap"`
	SAML         SAMLConfig    `yaml:"saml" json:"saml"`
	SessionTimeout time.Duration `yaml:"session_timeout" json:"session_timeout"`
	MFA          MFAConfig     `yaml:"mfa" json:"mfa"`
}

// EnterpriseJWTConfig holds JWT configuration
type EnterpriseJWTConfig struct {
	Secret     string        `yaml:"secret" json:"-"`
	Expiration time.Duration `yaml:"expiration" json:"expiration"`
	Issuer     string        `yaml:"issuer" json:"issuer"`
	Audience   string        `yaml:"audience" json:"audience"`
}

// OAuth2Config holds OAuth2 configuration
type OAuth2Config struct {
	ClientID     string   `yaml:"client_id" json:"client_id"`
	ClientSecret string   `yaml:"client_secret" json:"-"`
	RedirectURL  string   `yaml:"redirect_url" json:"redirect_url"`
	Scopes       []string `yaml:"scopes" json:"scopes"`
	AuthURL      string   `yaml:"auth_url" json:"auth_url"`
	TokenURL     string   `yaml:"token_url" json:"token_url"`
	UserInfoURL  string   `yaml:"user_info_url" json:"user_info_url"`
}

// LDAPConfig holds LDAP configuration
type LDAPConfig struct {
	Host         string `yaml:"host" json:"host"`
	Port         int    `yaml:"port" json:"port"`
	BindDN       string `yaml:"bind_dn" json:"bind_dn"`
	BindPassword string `yaml:"bind_password" json:"-"`
	BaseDN       string `yaml:"base_dn" json:"base_dn"`
	UserFilter   string `yaml:"user_filter" json:"user_filter"`
	GroupFilter  string `yaml:"group_filter" json:"group_filter"`
	TLS          bool   `yaml:"tls" json:"tls"`
}

// SAMLConfig holds SAML configuration
type SAMLConfig struct {
	EntityID     string `yaml:"entity_id" json:"entity_id"`
	SSOURL       string `yaml:"sso_url" json:"sso_url"`
	Certificate  string `yaml:"certificate" json:"certificate"`
	PrivateKey   string `yaml:"private_key" json:"-"`
	MetadataURL  string `yaml:"metadata_url" json:"metadata_url"`
}

// MFAConfig holds multi-factor authentication configuration
type MFAConfig struct {
	Enabled  bool     `yaml:"enabled" json:"enabled"`
	Methods  []string `yaml:"methods" json:"methods"` // "totp", "sms", "email"
	Required bool     `yaml:"required" json:"required"`
}

// AuthzConfig holds authorization configuration
type AuthzConfig struct {
	Enabled bool          `yaml:"enabled" json:"enabled"`
	Model   string        `yaml:"model" json:"model"` // "rbac", "abac", "acl"
	Roles   []RoleConfig  `yaml:"roles" json:"roles"`
	Policies []PolicyConfig `yaml:"policies" json:"policies"`
}

// RoleConfig defines a role
type RoleConfig struct {
	Name        string   `yaml:"name" json:"name"`
	Description string   `yaml:"description" json:"description"`
	Permissions []string `yaml:"permissions" json:"permissions"`
	Inherits    []string `yaml:"inherits" json:"inherits"`
}

// PolicyConfig defines an authorization policy
type PolicyConfig struct {
	Name      string            `yaml:"name" json:"name"`
	Effect    string            `yaml:"effect" json:"effect"` // "allow", "deny"
	Actions   []string          `yaml:"actions" json:"actions"`
	Resources []string          `yaml:"resources" json:"resources"`
	Conditions map[string]string `yaml:"conditions" json:"conditions"`
}

// EnterpriseTLSConfig holds TLS configuration
type EnterpriseTLSConfig struct {
	Enabled    bool   `yaml:"enabled" json:"enabled"`
	CertFile   string `yaml:"cert_file" json:"cert_file"`
	KeyFile    string `yaml:"key_file" json:"key_file"`
	CAFile     string `yaml:"ca_file" json:"ca_file"`
	MinVersion string `yaml:"min_version" json:"min_version"`
	CipherSuites []string `yaml:"cipher_suites" json:"cipher_suites"`
}

// SecretsConfig holds secrets management configuration
type SecretsConfig struct {
	Provider string            `yaml:"provider" json:"provider"` // "vault", "aws", "azure", "gcp"
	Vault    VaultConfig       `yaml:"vault" json:"vault"`
	AWS      AWSSecretsConfig  `yaml:"aws" json:"aws"`
	Azure    AzureSecretsConfig `yaml:"azure" json:"azure"`
	GCP      GCPSecretsConfig  `yaml:"gcp" json:"gcp"`
}

// VaultConfig holds HashiCorp Vault configuration
type VaultConfig struct {
	Address   string `yaml:"address" json:"address"`
	Token     string `yaml:"token" json:"-"`
	Namespace string `yaml:"namespace" json:"namespace"`
	Path      string `yaml:"path" json:"path"`
}

// AWSSecretsConfig holds AWS Secrets Manager configuration
type AWSSecretsConfig struct {
	Region    string `yaml:"region" json:"region"`
	AccessKey string `yaml:"access_key" json:"access_key"`
	SecretKey string `yaml:"secret_key" json:"-"`
	Profile   string `yaml:"profile" json:"profile"`
}

// AzureSecretsConfig holds Azure Key Vault configuration
type AzureSecretsConfig struct {
	VaultURL     string `yaml:"vault_url" json:"vault_url"`
	ClientID     string `yaml:"client_id" json:"client_id"`
	ClientSecret string `yaml:"client_secret" json:"-"`
	TenantID     string `yaml:"tenant_id" json:"tenant_id"`
}

// GCPSecretsConfig holds Google Secret Manager configuration
type GCPSecretsConfig struct {
	ProjectID   string `yaml:"project_id" json:"project_id"`
	Credentials string `yaml:"credentials" json:"credentials"`
}

// AuditConfig holds audit logging configuration
type AuditConfig struct {
	Enabled    bool          `yaml:"enabled" json:"enabled"`
	Level      string        `yaml:"level" json:"level"` // "basic", "detailed", "full"
	Destination string       `yaml:"destination" json:"destination"` // "file", "database", "syslog", "webhook"
	File       FileAuditConfig `yaml:"file" json:"file"`
	Database   DBAuditConfig `yaml:"database" json:"database"`
	Syslog     SyslogAuditConfig `yaml:"syslog" json:"syslog"`
	Webhook    WebhookAuditConfig `yaml:"webhook" json:"webhook"`
	Retention  time.Duration `yaml:"retention" json:"retention"`
	Compression bool         `yaml:"compression" json:"compression"`
}

// FileAuditConfig holds file-based audit configuration
type FileAuditConfig struct {
	Path       string `yaml:"path" json:"path"`
	MaxSize    int64  `yaml:"max_size" json:"max_size"`
	MaxBackups int    `yaml:"max_backups" json:"max_backups"`
	MaxAge     int    `yaml:"max_age" json:"max_age"`
}

// DBAuditConfig holds database audit configuration
type DBAuditConfig struct {
	Driver   string `yaml:"driver" json:"driver"`
	DSN      string `yaml:"dsn" json:"-"`
	Table    string `yaml:"table" json:"table"`
	BatchSize int   `yaml:"batch_size" json:"batch_size"`
}

// SyslogAuditConfig holds syslog audit configuration
type SyslogAuditConfig struct {
	Network  string `yaml:"network" json:"network"`
	Address  string `yaml:"address" json:"address"`
	Facility string `yaml:"facility" json:"facility"`
	Tag      string `yaml:"tag" json:"tag"`
}

// WebhookAuditConfig holds webhook audit configuration
type WebhookAuditConfig struct {
	URL     string            `yaml:"url" json:"url"`
	Headers map[string]string `yaml:"headers" json:"headers"`
	Timeout time.Duration     `yaml:"timeout" json:"timeout"`
	Retries int               `yaml:"retries" json:"retries"`
}

// EnterpriseRateLimitConfig holds rate limiting configuration
type EnterpriseRateLimitConfig struct {
	Enabled   bool              `yaml:"enabled" json:"enabled"`
	Global    GlobalRateLimit   `yaml:"global" json:"global"`
	PerUser   PerUserRateLimit  `yaml:"per_user" json:"per_user"`
	PerIP     PerIPRateLimit    `yaml:"per_ip" json:"per_ip"`
	Endpoints []EndpointRateLimit `yaml:"endpoints" json:"endpoints"`
}

// GlobalRateLimit holds global rate limiting settings
type GlobalRateLimit struct {
	Requests int           `yaml:"requests" json:"requests"`
	Window   time.Duration `yaml:"window" json:"window"`
}

// PerUserRateLimit holds per-user rate limiting settings
type PerUserRateLimit struct {
	Requests int           `yaml:"requests" json:"requests"`
	Window   time.Duration `yaml:"window" json:"window"`
}

// PerIPRateLimit holds per-IP rate limiting settings
type PerIPRateLimit struct {
	Requests int           `yaml:"requests" json:"requests"`
	Window   time.Duration `yaml:"window" json:"window"`
}

// EndpointRateLimit holds endpoint-specific rate limiting
type EndpointRateLimit struct {
	Path     string        `yaml:"path" json:"path"`
	Method   string        `yaml:"method" json:"method"`
	Requests int           `yaml:"requests" json:"requests"`
	Window   time.Duration `yaml:"window" json:"window"`
}

// SSOConfig holds single sign-on configuration
type SSOConfig struct {
	Enabled   bool              `yaml:"enabled" json:"enabled"`
	Providers []SSOProvider    `yaml:"providers" json:"providers"`
	Default   string           `yaml:"default" json:"default"`
	Mapping   UserMapping      `yaml:"mapping" json:"mapping"`
}

// SSOProvider defines an SSO provider
type SSOProvider struct {
	Name     string            `yaml:"name" json:"name"`
	Type     string            `yaml:"type" json:"type"` // "oidc", "saml", "oauth2"
	Config   map[string]interface{} `yaml:"config" json:"config"`
	Enabled  bool              `yaml:"enabled" json:"enabled"`
}

// UserMapping defines how to map SSO user attributes
type UserMapping struct {
	Username string `yaml:"username" json:"username"`
	Email    string `yaml:"email" json:"email"`
	Name     string `yaml:"name" json:"name"`
	Groups   string `yaml:"groups" json:"groups"`
	Roles    string `yaml:"roles" json:"roles"`
}

// ReportingConfig holds reporting configuration
type ReportingConfig struct {
	Enabled    bool                `yaml:"enabled" json:"enabled"`
	Scheduled  []ScheduledReport   `yaml:"scheduled" json:"scheduled"`
	Templates  []ReportTemplate    `yaml:"templates" json:"templates"`
	Delivery   ReportDelivery      `yaml:"delivery" json:"delivery"`
	Retention  time.Duration       `yaml:"retention" json:"retention"`
}

// ScheduledReport defines a scheduled report
type ScheduledReport struct {
	Name      string   `yaml:"name" json:"name"`
	Template  string   `yaml:"template" json:"template"`
	Schedule  string   `yaml:"schedule" json:"schedule"` // Cron expression
	Recipients []string `yaml:"recipients" json:"recipients"`
	Enabled   bool     `yaml:"enabled" json:"enabled"`
}

// ReportTemplate defines a report template
type ReportTemplate struct {
	Name        string            `yaml:"name" json:"name"`
	Description string            `yaml:"description" json:"description"`
	Format      string            `yaml:"format" json:"format"` // "pdf", "html", "csv", "json"
	Query       string            `yaml:"query" json:"query"`
	Parameters  map[string]string `yaml:"parameters" json:"parameters"`
}

// ReportDelivery defines report delivery options
type ReportDelivery struct {
	Email   EmailDelivery   `yaml:"email" json:"email"`
	Webhook WebhookDelivery `yaml:"webhook" json:"webhook"`
	S3      S3Delivery      `yaml:"s3" json:"s3"`
}

// EmailDelivery holds email delivery configuration
type EmailDelivery struct {
	Enabled  bool   `yaml:"enabled" json:"enabled"`
	SMTP     SMTPConfig `yaml:"smtp" json:"smtp"`
	From     string `yaml:"from" json:"from"`
	Subject  string `yaml:"subject" json:"subject"`
	Template string `yaml:"template" json:"template"`
}

// SMTPConfig holds SMTP configuration
type SMTPConfig struct {
	Host     string `yaml:"host" json:"host"`
	Port     int    `yaml:"port" json:"port"`
	Username string `yaml:"username" json:"username"`
	Password string `yaml:"password" json:"-"`
	TLS      bool   `yaml:"tls" json:"tls"`
}

// WebhookDelivery holds webhook delivery configuration
type WebhookDelivery struct {
	Enabled bool              `yaml:"enabled" json:"enabled"`
	URL     string            `yaml:"url" json:"url"`
	Headers map[string]string `yaml:"headers" json:"headers"`
	Timeout time.Duration     `yaml:"timeout" json:"timeout"`
}

// S3Delivery holds S3 delivery configuration
type S3Delivery struct {
	Enabled   bool   `yaml:"enabled" json:"enabled"`
	Bucket    string `yaml:"bucket" json:"bucket"`
	Prefix    string `yaml:"prefix" json:"prefix"`
	Region    string `yaml:"region" json:"region"`
	AccessKey string `yaml:"access_key" json:"access_key"`
	SecretKey string `yaml:"secret_key" json:"-"`
}

// DefaultEnterpriseConfig returns default enterprise configuration
func DefaultEnterpriseConfig() *EnterpriseConfig {
	return &EnterpriseConfig{
		Enabled: false,
		License: LicenseConfig{
			Type:     "trial",
			MaxUsers: 5,
			MaxScans: 100,
			Features: []string{"basic_scanning"},
		},
		Cache: &cache.CacheConfig{
			Type:           "memory",
			DefaultTTL:     time.Hour,
			MaxMemory:      100 * 1024 * 1024, // 100MB
			EvictionPolicy: "lru",
			Enabled:        true,
		},
		Monitoring: &monitoring.MonitoringConfig{
			Enabled: false,
		},
		EnterpriseSecurity: EnterpriseSecurityConfig{
			EnterpriseEncryption: EnterpriseEncryptionConfig{
				Enabled:   false,
				Algorithm: "AES-256-GCM",
			},
			Authentication: AuthConfig{
				Enabled:        false,
				Method:         "jwt",
				SessionTimeout: time.Hour * 24,
				JWT: EnterpriseJWTConfig{
					Expiration: time.Hour * 24,
					Issuer:     "typosentinel",
				},
			},
			Authorization: AuthzConfig{
				Enabled: false,
				Model:   "rbac",
			},
			EnterpriseTLS: EnterpriseTLSConfig{
				Enabled:    false,
				MinVersion: "1.2",
			},
		},
		Audit: AuditConfig{
			Enabled:     false,
			Level:       "basic",
			Destination: "file",
			Retention:   time.Hour * 24 * 90, // 90 days
		},
		EnterpriseRateLimit: EnterpriseRateLimitConfig{
			Enabled: false,
			Global: GlobalRateLimit{
				Requests: 1000,
				Window:   time.Minute,
			},
			PerUser: PerUserRateLimit{
				Requests: 100,
				Window:   time.Minute,
			},
			PerIP: PerIPRateLimit{
				Requests: 200,
				Window:   time.Minute,
			},
		},
		SSO: SSOConfig{
			Enabled: false,
			Mapping: UserMapping{
				Username: "preferred_username",
				Email:    "email",
				Name:     "name",
				Groups:   "groups",
				Roles:    "roles",
			},
		},
		Reporting: ReportingConfig{
			Enabled:   false,
			Retention: time.Hour * 24 * 365, // 1 year
		},
		Repository: *DefaultRepositoryConfig(),
	}
}

// Validate validates the enterprise configuration
func (ec *EnterpriseConfig) Validate() error {
	if !ec.Enabled {
		return nil
	}

	// Validate license
	if ec.License.Key == "" {
		return fmt.Errorf("license key is required when enterprise features are enabled")
	}

	// Validate cache configuration
	if ec.Cache != nil && ec.Cache.Enabled {
		if ec.Cache.Type == "" {
			ec.Cache.Type = "memory"
		}
		if ec.Cache.DefaultTTL == 0 {
			ec.Cache.DefaultTTL = time.Hour
		}
	}

	// Validate monitoring configuration
	if ec.Monitoring != nil && ec.Monitoring.Enabled {
		// Monitoring validation can be added here
	}

	// Validate security configuration
	if ec.EnterpriseSecurity.Authentication.Enabled {
		if ec.EnterpriseSecurity.Authentication.Method == "" {
			return fmt.Errorf("authentication method is required")
		}
		if ec.EnterpriseSecurity.Authentication.Method == "jwt" && ec.EnterpriseSecurity.Authentication.JWT.Secret == "" {
			return fmt.Errorf("JWT secret is required")
		}
	}

	return nil
}

// IsFeatureEnabled checks if a specific feature is enabled
func (ec *EnterpriseConfig) IsFeatureEnabled(feature string) bool {
	if !ec.Enabled {
		return false
	}

	for _, f := range ec.License.Features {
		if f == feature {
			return true
		}
	}
	return false
}

// GetMaxUsers returns the maximum number of users allowed
func (ec *EnterpriseConfig) GetMaxUsers() int {
	if !ec.Enabled {
		return 1 // Single user for community edition
	}
	return ec.License.MaxUsers
}

// GetMaxScans returns the maximum number of scans allowed
func (ec *EnterpriseConfig) GetMaxScans() int {
	if !ec.Enabled {
		return 10 // Limited scans for community edition
	}
	return ec.License.MaxScans
}