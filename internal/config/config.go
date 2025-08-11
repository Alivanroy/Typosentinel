// Package config provides configuration management for Typosentinel
// This package implements structured configuration with validation and environment support
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/spf13/viper"

	"github.com/Alivanroy/Typosentinel/internal/errors"
)

// Environment represents the application environment
type Environment string

const (
	EnvDevelopment Environment = "development"
	EnvTesting     Environment = "testing"
	EnvStaging     Environment = "staging"
	EnvProduction  Environment = "production"
)

// Config represents the application configuration
type Config struct {
	// Application settings
	App AppConfig `mapstructure:"app" validate:"required"`

	// Server settings
	Server ServerConfig `mapstructure:"server" validate:"required"`

	// Database settings
	Database DatabaseConfig `mapstructure:"database" validate:"required"`

	// Redis settings
	Redis RedisConfig `mapstructure:"redis" validate:"required"`

	// Logging settings
	Logging LoggingConfig `mapstructure:"logging" validate:"required"`

	// Metrics settings
	Metrics MetricsConfig `mapstructure:"metrics" validate:"required"`

	// Security settings
	Security SecurityConfig `mapstructure:"security" validate:"required"`

	// ML settings
	ML MLConfig `mapstructure:"ml" validate:"required"`

	// ML Service settings
	MLService *MLServiceConfig `mapstructure:"ml_service"`

	// Scanner settings
	Scanner *ScannerConfig `mapstructure:"scanner"`

	// API settings
	API APIConfig `mapstructure:"api" validate:"required"`

	// Rate limiting settings
	RateLimit RateLimitConfig `mapstructure:"rate_limit" validate:"required"`

	// Threat Intelligence settings
	ThreatIntelligence *ThreatIntelligenceConfig `mapstructure:"threat_intelligence"`

	// Plugins settings
	Plugins *PluginsConfig `mapstructure:"plugins"`

	// Cache settings
	Cache *CacheConfig `mapstructure:"cache"`

	// Typo Detection settings
	TypoDetection *TypoDetectionConfig `mapstructure:"typo_detection"`

	// Registries settings
	Registries RegistriesConfig `mapstructure:"registries"`

	// ML Analysis settings
	MLAnalysis *MLAnalysisConfig `mapstructure:"ml_analysis"`

	// Features settings
	Features FeatureConfig `mapstructure:"features" validate:"required"`

	// Policies settings
	Policies PoliciesConfig `mapstructure:"policies" validate:"required"`

	// Integrations settings
	Integrations *IntegrationsConfig `mapstructure:"integrations"`

	// Supply Chain Security settings
	SupplyChain *SupplyChainConfig `mapstructure:"supply_chain"`
}

// AppConfig contains application-level configuration
type AppConfig struct {
	Name        string      `mapstructure:"name" validate:"required,min=1"`
	Version     string      `mapstructure:"version" validate:"required,semver"`
	Environment Environment `mapstructure:"environment" validate:"required,oneof=development testing staging production"`
	Debug       bool        `mapstructure:"debug"`
	Verbose     bool        `mapstructure:"verbose"`
	LogLevel    string      `mapstructure:"log_level" validate:"required,oneof=debug info warn error"`
	DataDir     string      `mapstructure:"data_dir" validate:"required,dir"`
	TempDir     string      `mapstructure:"temp_dir" validate:"required"`
	MaxWorkers  int         `mapstructure:"max_workers" validate:"required,min=1,max=100"`
}

// ServerConfig contains HTTP server configuration
type ServerConfig struct {
	Host            string        `mapstructure:"host" validate:"required,hostname_rfc1123|ip"`
	Port            int           `mapstructure:"port" validate:"required,min=1,max=65535"`
	ReadTimeout     time.Duration `mapstructure:"read_timeout" validate:"required,min=1s"`
	WriteTimeout    time.Duration `mapstructure:"write_timeout" validate:"required,min=1s"`
	IdleTimeout     time.Duration `mapstructure:"idle_timeout" validate:"required,min=1s"`
	ShutdownTimeout time.Duration `mapstructure:"shutdown_timeout" validate:"required,min=1s"`
	TLS             TLSConfig     `mapstructure:"tls"`
	CORS            CORSConfig    `mapstructure:"cors"`
}

// TLSConfig contains TLS configuration
type TLSConfig struct {
	Enabled  bool   `mapstructure:"enabled"`
	CertFile string `mapstructure:"cert_file" validate:"required_if=Enabled true,omitempty,file"`
	KeyFile  string `mapstructure:"key_file" validate:"required_if=Enabled true,omitempty,file"`
	CAFile   string `mapstructure:"ca_file" validate:"omitempty,file"`
}

// CORSConfig contains CORS configuration
type CORSConfig struct {
	Enabled          bool     `mapstructure:"enabled"`
	AllowedOrigins   []string `mapstructure:"allowed_origins"`
	AllowedMethods   []string `mapstructure:"allowed_methods"`
	AllowedHeaders   []string `mapstructure:"allowed_headers"`
	ExposedHeaders   []string `mapstructure:"exposed_headers"`
	AllowCredentials bool     `mapstructure:"allow_credentials"`
	MaxAge           int      `mapstructure:"max_age" validate:"min=0"`
}

// DatabaseConfig contains database configuration
type DatabaseConfig struct {
	Type            string        `mapstructure:"type" validate:"required,oneof=sqlite postgres mysql"`
	Host            string        `mapstructure:"host" validate:"required_unless=Type sqlite,omitempty,hostname_rfc1123|ip"`
	Port            int           `mapstructure:"port" validate:"required_unless=Type sqlite,omitempty,min=1,max=65535"`
	Database        string        `mapstructure:"database" validate:"required,min=1"`
	Username        string        `mapstructure:"username" validate:"required_unless=Type sqlite"`
	Password        string        `mapstructure:"password" validate:"required_unless=Type sqlite"`
	SSLMode         string        `mapstructure:"ssl_mode" validate:"omitempty,oneof=disable require verify-ca verify-full"`
	MaxOpenConns    int           `mapstructure:"max_open_conns" validate:"min=1,max=100"`
	MaxIdleConns    int           `mapstructure:"max_idle_conns" validate:"min=1,max=50"`
	ConnMaxLifetime time.Duration `mapstructure:"conn_max_lifetime" validate:"min=1m"`
	MigrationsPath  string        `mapstructure:"migrations_path" validate:"required,dir"`
}

// RedisConfig contains Redis configuration
type RedisConfig struct {
	Enabled      bool          `mapstructure:"enabled"`
	Host         string        `mapstructure:"host" validate:"required_if=Enabled true,omitempty,hostname_rfc1123|ip"`
	Port         int           `mapstructure:"port" validate:"required_if=Enabled true,omitempty,min=1,max=65535"`
	Password     string        `mapstructure:"password"`
	Database     int           `mapstructure:"database" validate:"min=0,max=15"`
	PoolSize     int           `mapstructure:"pool_size" validate:"min=1,max=100"`
	DialTimeout  time.Duration `mapstructure:"dial_timeout" validate:"min=1s"`
	ReadTimeout  time.Duration `mapstructure:"read_timeout" validate:"min=1s"`
	WriteTimeout time.Duration `mapstructure:"write_timeout" validate:"min=1s"`
	IdleTimeout  time.Duration `mapstructure:"idle_timeout" validate:"min=1m"`
	TTL          time.Duration `mapstructure:"ttl" validate:"min=1m"`
}

// LoggingConfig contains logging configuration
type LoggingConfig struct {
	Level      string `mapstructure:"level" validate:"required,oneof=debug info warn error"`
	Format     string `mapstructure:"format" validate:"required,oneof=json text"`
	Output     string `mapstructure:"output" validate:"required,oneof=stdout stderr file"`
	File       string `mapstructure:"file" validate:"required_if=Output file"`
	MaxSize    int    `mapstructure:"max_size" validate:"min=1,max=1000"`
	MaxBackups int    `mapstructure:"max_backups" validate:"min=1,max=100"`
	MaxAge     int    `mapstructure:"max_age" validate:"min=1,max=365"`
	Compress   bool   `mapstructure:"compress"`
}

// MetricsConfig contains metrics configuration
type MetricsConfig struct {
	Enabled   bool          `mapstructure:"enabled"`
	Provider  string        `mapstructure:"provider" validate:"required_if=Enabled true,omitempty,oneof=prometheus statsd"`
	Address   string        `mapstructure:"address" validate:"required_if=Enabled true,omitempty"`
	Namespace string        `mapstructure:"namespace" validate:"required_if=Enabled true,omitempty,min=1"`
	Interval  time.Duration `mapstructure:"interval" validate:"min=1s"`
	Buckets   []float64     `mapstructure:"buckets"`
}

// SecurityConfig contains security configuration
type SecurityConfig struct {
	JWT            JWTConfig            `mapstructure:"jwt"`
	APIKeys        APIKeysConfig        `mapstructure:"api_keys"`
	Encryption     EncryptionConfig     `mapstructure:"encryption"`
	PasswordPolicy PasswordPolicyConfig `mapstructure:"password_policy"`
	CSRF           CSRFConfig           `mapstructure:"csrf"`
}

// JWTConfig contains JWT configuration
type JWTConfig struct {
	Enabled           bool          `mapstructure:"enabled"`
	Secret            string        `mapstructure:"secret" validate:"required_if=Enabled true,omitempty,min=32"`
	Expiration        time.Duration `mapstructure:"expiration" validate:"required_if=Enabled true,omitempty,min=1m"`
	RefreshExpiration time.Duration `mapstructure:"refresh_expiration" validate:"required_if=Enabled true,omitempty,min=1h"`
	Issuer            string        `mapstructure:"issuer" validate:"required_if=Enabled true,omitempty,min=1"`
	Audience          string        `mapstructure:"audience" validate:"required_if=Enabled true,omitempty,min=1"`
}

// APIKeysConfig contains API keys configuration
type APIKeysConfig struct {
	Enabled bool     `mapstructure:"enabled"`
	Keys    []string `mapstructure:"keys" validate:"required_if=Enabled true,omitempty,dive,min=32"`
}

// EncryptionConfig contains encryption configuration
type EncryptionConfig struct {
	Key       string `mapstructure:"key" validate:"required,min=32"`
	Algorithm string `mapstructure:"algorithm" validate:"required,oneof=aes-256-gcm chacha20-poly1305"`
}

// PasswordPolicyConfig contains password policy configuration
type PasswordPolicyConfig struct {
	MinLength     int  `mapstructure:"min_length" validate:"min=8,max=128"`
	RequireUpper  bool `mapstructure:"require_upper"`
	RequireLower  bool `mapstructure:"require_lower"`
	RequireDigit  bool `mapstructure:"require_digit"`
	RequireSymbol bool `mapstructure:"require_symbol"`
}

// CSRFConfig contains CSRF protection configuration
type CSRFConfig struct {
	Enabled    bool   `mapstructure:"enabled"`
	Secret     string `mapstructure:"secret" validate:"required_if=Enabled true,omitempty,min=32"`
	CookieName string `mapstructure:"cookie_name" validate:"required_if=Enabled true,omitempty,min=1"`
	HeaderName string `mapstructure:"header_name" validate:"required_if=Enabled true,omitempty,min=1"`
}

// MLConfig contains machine learning configuration
type MLConfig struct {
	Enabled        bool          `mapstructure:"enabled"`
	ModelPath      string        `mapstructure:"model_path" validate:"required_if=Enabled true,omitempty,file"`
	Threshold      float64       `mapstructure:"threshold" validate:"min=0,max=1"`
	BatchSize      int           `mapstructure:"batch_size" validate:"min=1,max=1000"`
	Timeout        time.Duration `mapstructure:"timeout" validate:"min=1s"`
	CacheSize      int           `mapstructure:"cache_size" validate:"min=100,max=10000"`
	UpdateInterval time.Duration `mapstructure:"update_interval" validate:"min=1h"`
	MLModelConfig  MLModelConfig `mapstructure:"model_config"`
}

// MLModelConfig contains ML model configuration
type MLModelConfig struct {
	Enabled        bool                   `mapstructure:"enabled"`
	Threshold      float64                `mapstructure:"threshold" validate:"min=0,max=1"`
	Type           string                 `mapstructure:"type" validate:"required,oneof=tensorflow pytorch sklearn"`
	Version        string                 `mapstructure:"version"`
	Parameters     map[string]interface{} `mapstructure:"parameters"`
	Features       []string               `mapstructure:"features"`
	Preprocessing  PreprocessingConfig    `mapstructure:"preprocessing"`
	Postprocessing PostprocessingConfig   `mapstructure:"postprocessing"`
}

// MLAnalysisConfig contains ML analysis configuration
type MLAnalysisConfig struct {
	Enabled             bool               `mapstructure:"enabled"`
	ModelPath           string             `mapstructure:"model_path" validate:"required_if=Enabled true"`
	Threshold           float64            `mapstructure:"threshold" validate:"min=0,max=1"`
	SimilarityThreshold float64            `mapstructure:"similarity_threshold" validate:"min=0,max=1"`
	MaliciousThreshold  float64            `mapstructure:"malicious_threshold" validate:"min=0,max=1"`
	ReputationThreshold float64            `mapstructure:"reputation_threshold" validate:"min=0,max=1"`
	BatchSize           int                `mapstructure:"batch_size" validate:"min=1,max=1000"`
	MaxFeatures         int                `mapstructure:"max_features" validate:"min=1"`
	Timeout             time.Duration      `mapstructure:"timeout" validate:"min=1s"`
	CacheEmbeddings     bool               `mapstructure:"cache_embeddings"`
	ParallelProcessing  bool               `mapstructure:"parallel_processing"`
	GPUAcceleration     bool               `mapstructure:"gpu_acceleration"`
	FeatureStore        FeatureStoreConfig `mapstructure:"feature_store"`
	ModelUpdates        ModelUpdatesConfig `mapstructure:"model_updates"`
}

// MLServiceConfig contains ML service configuration
type MLServiceConfig struct {
	Enabled   bool          `mapstructure:"enabled"`
	Endpoint  string        `mapstructure:"endpoint" validate:"required_if=Enabled true,url"`
	Timeout   time.Duration `mapstructure:"timeout" validate:"min=1s"`
	Retries   int           `mapstructure:"retries" validate:"min=0,max=10"`
	APIKey    string        `mapstructure:"api_key"`
	BatchSize int           `mapstructure:"batch_size" validate:"min=1,max=1000"`
}

// FeatureStoreConfig contains feature store configuration
type FeatureStoreConfig struct {
	Enabled    bool          `mapstructure:"enabled"`
	Provider   string        `mapstructure:"provider" validate:"required_if=Enabled true,oneof=redis postgres"`
	Connection string        `mapstructure:"connection" validate:"required_if=Enabled true"`
	TTL        time.Duration `mapstructure:"ttl" validate:"min=1m"`
}

// ModelUpdatesConfig contains model updates configuration
type ModelUpdatesConfig struct {
	Enabled   bool          `mapstructure:"enabled"`
	Interval  time.Duration `mapstructure:"interval" validate:"min=1h"`
	Source    string        `mapstructure:"source" validate:"required_if=Enabled true"`
	AutoApply bool          `mapstructure:"auto_apply"`
}

// PreprocessingConfig contains preprocessing configuration
type PreprocessingConfig struct {
	Normalization    bool             `mapstructure:"normalization"`
	Scaling          string           `mapstructure:"scaling" validate:"oneof=standard minmax robust"`
	FeatureSelection bool             `mapstructure:"feature_selection"`
	CustomSteps      []ProcessingStep `mapstructure:"custom_steps"`
}

// PostprocessingConfig contains postprocessing configuration
type PostprocessingConfig struct {
	ThresholdAdjustment bool             `mapstructure:"threshold_adjustment"`
	Calibration         bool             `mapstructure:"calibration"`
	CustomSteps         []ProcessingStep `mapstructure:"custom_steps"`
}

// ProcessingStep contains processing step configuration
type ProcessingStep struct {
	Name       string                 `mapstructure:"name" validate:"required"`
	Type       string                 `mapstructure:"type" validate:"required"`
	Parameters map[string]interface{} `mapstructure:"parameters"`
}

// ScannerConfig contains scanner configuration
type ScannerConfig struct {
	MaxConcurrency int              `mapstructure:"max_concurrency" validate:"min=1,max=50"`
	Timeout        time.Duration    `mapstructure:"timeout" validate:"min=1s"`
	RetryAttempts  int              `mapstructure:"retry_attempts" validate:"min=0,max=10"`
	RetryDelay     time.Duration    `mapstructure:"retry_delay" validate:"min=1s"`
	UserAgent      string           `mapstructure:"user_agent" validate:"required,min=1"`
	IncludeDevDeps bool             `mapstructure:"include_dev_deps"`
	EnrichMetadata bool             `mapstructure:"enrich_metadata"`
	Registries     RegistriesConfig `mapstructure:"registries"`
}

// RegistriesConfig contains package registry configuration
type RegistriesConfig []RegistryConfig

// RegistryConfig contains individual registry configuration
type RegistryConfig struct {
	Enabled bool          `mapstructure:"enabled"`
	URL     string        `mapstructure:"url" validate:"required_if=Enabled true,omitempty,url"`
	APIKey  string        `mapstructure:"api_key"`
	Timeout time.Duration `mapstructure:"timeout" validate:"min=1s"`
	Private PrivateConfig `mapstructure:"private"`
}

// PrivateConfig contains private registry configuration
type PrivateConfig struct {
	Namespaces []string `mapstructure:"namespaces"`
}

// APIConfig contains API configuration
type APIConfig struct {
	Prefix        string              `mapstructure:"prefix" validate:"required,min=1"`
	Version       string              `mapstructure:"version" validate:"required,min=1"`
	Documentation DocumentationConfig `mapstructure:"documentation"`
	REST          RESTAPIConfig       `mapstructure:"rest"`
	RateLimit     APIRateLimiting     `mapstructure:"rate_limit"`
	Auth          APIAuthentication   `mapstructure:"auth"`
}

// RESTAPIConfig contains REST API configuration
type RESTAPIConfig struct {
	Enabled        bool               `mapstructure:"enabled"`
	Host           string             `mapstructure:"host"`
	Port           int                `mapstructure:"port"`
	BasePath       string             `mapstructure:"base_path"`
	Prefix         string             `mapstructure:"prefix"`
	Version        string             `mapstructure:"version"`
	Versioning     APIVersioning      `mapstructure:"versioning"`
	MaxBodySize    int64              `mapstructure:"max_body_size"`
	CORS           *CORSConfig        `mapstructure:"cors"`
	RateLimiting   *APIRateLimiting   `mapstructure:"rate_limiting"`
	Authentication *APIAuthentication `mapstructure:"authentication"`
	Documentation  APIDocumentation   `mapstructure:"documentation"`
}

// APIRateLimiting contains API rate limiting configuration
type APIRateLimiting struct {
	Enabled bool                  `mapstructure:"enabled"`
	RPS     int                   `mapstructure:"rps"`
	Burst   int                   `mapstructure:"burst"`
	Window  time.Duration         `mapstructure:"window"`
	Global  GlobalRateLimitConfig `mapstructure:"global"`
}

// GlobalRateLimitConfig contains global rate limiting configuration
type GlobalRateLimitConfig struct {
	Enabled           bool `mapstructure:"enabled"`
	RPS               int  `mapstructure:"rps"`
	RequestsPerSecond int  `mapstructure:"requests_per_second"`
	Burst             int  `mapstructure:"burst"`
	BurstSize         int  `mapstructure:"burst_size"`
}

// APIVersioning contains API versioning configuration
type APIVersioning struct {
	Enabled           bool     `mapstructure:"enabled"`
	Strategy          string   `mapstructure:"strategy" validate:"oneof=path header query"`
	DefaultVersion    string   `mapstructure:"default_version" validate:"required"`
	SupportedVersions []string `mapstructure:"supported_versions" validate:"required,dive,required"`
}

// APIDocumentation contains API documentation configuration
type APIDocumentation struct {
	Enabled bool   `mapstructure:"enabled"`
	Path    string `mapstructure:"path" validate:"required_if=Enabled true"`
	Title   string `mapstructure:"title"`
	Version string `mapstructure:"version"`
}

// APIAuthentication contains API authentication configuration
type APIAuthentication struct {
	Enabled   bool            `mapstructure:"enabled"`
	Method    string          `mapstructure:"method"`
	Methods   []string        `mapstructure:"methods"`
	JWT       JWTConfig       `mapstructure:"jwt"`
	JWTSecret string          `mapstructure:"jwt_secret"`
	APIKeys   []string        `mapstructure:"api_keys"`
	BasicAuth BasicAuthConfig `mapstructure:"basic_auth"`
}

// BasicAuthConfig contains basic auth configuration
type BasicAuthConfig struct {
	Users map[string]string `mapstructure:"users"`
}

// DocumentationConfig contains API documentation configuration
type DocumentationConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	Path    string `mapstructure:"path" validate:"required_if=Enabled true,omitempty,min=1"`
	Title   string `mapstructure:"title" validate:"required_if=Enabled true,omitempty,min=1"`
	Version string `mapstructure:"version" validate:"required_if=Enabled true,omitempty,min=1"`
}

// RateLimitConfig contains rate limiting configuration
type RateLimitConfig struct {
	Enabled   bool          `mapstructure:"enabled"`
	Requests  int           `mapstructure:"requests" validate:"required_if=Enabled true,omitempty,min=1"`
	Window    time.Duration `mapstructure:"window" validate:"required_if=Enabled true,omitempty,min=1s"`
	Burst     int           `mapstructure:"burst" validate:"required_if=Enabled true,omitempty,min=1"`
	SkipPaths []string      `mapstructure:"skip_paths"`
	Headers   bool          `mapstructure:"headers"`
}

// ThreatIntelligenceConfig contains threat intelligence configuration
type ThreatIntelligenceConfig struct {
	Enabled        bool               `mapstructure:"enabled"`
	UpdateInterval time.Duration      `mapstructure:"update_interval" validate:"min=1m"`
	Feeds          []ThreatFeedConfig `mapstructure:"feeds"`
	Alerting       AlertingConfig     `mapstructure:"alerting"`
}

// ThreatFeedConfig contains threat feed configuration
type ThreatFeedConfig struct {
	Name     string        `mapstructure:"name" validate:"required"`
	URL      string        `mapstructure:"url" validate:"required,url"`
	Enabled  bool          `mapstructure:"enabled"`
	Interval time.Duration `mapstructure:"interval" validate:"min=1m"`
	APIKey   string        `mapstructure:"api_key"`
}

// AlertingConfig contains alerting configuration
type AlertingConfig struct {
	Enabled    bool             `mapstructure:"enabled"`
	Channels   []AlertChannel   `mapstructure:"channels"`
	Throttling ThrottlingConfig `mapstructure:"throttling"`
}

// AlertChannel contains alert channel configuration
type AlertChannel struct {
	Type   string            `mapstructure:"type" validate:"required,oneof=email slack webhook"`
	Config map[string]string `mapstructure:"config"`
}

// ThrottlingConfig contains throttling configuration
type ThrottlingConfig struct {
	Enabled        bool          `mapstructure:"enabled"`
	MaxPerMinute   int           `mapstructure:"max_per_minute" validate:"min=1"`
	CooldownPeriod time.Duration `mapstructure:"cooldown_period" validate:"min=1m"`
}

// PluginsConfig contains plugins configuration
type PluginsConfig struct {
	Enabled         bool                    `mapstructure:"enabled"`
	Directory       string                  `mapstructure:"directory" validate:"required_if=Enabled true"`
	PluginDirectory string                  `mapstructure:"plugin_directory" validate:"required_if=Enabled true"`
	AutoLoad        bool                    `mapstructure:"auto_load"`
	Plugins         map[string]PluginConfig `mapstructure:"plugins"`
	Webhooks        WebhookConfig           `mapstructure:"webhooks"`
	CICD            CICDConfig              `mapstructure:"cicd"`
}

// CICDConfig contains CI/CD integration configuration
type CICDConfig []CICDProvider

// CICDProvider contains CI/CD provider configuration
type CICDProvider struct {
	Name     string                 `mapstructure:"name" validate:"required"`
	Enabled  bool                   `mapstructure:"enabled"`
	Config   map[string]string      `mapstructure:"config"`
	Settings map[string]interface{} `mapstructure:"settings"`
}

// PluginConfig contains individual plugin configuration
type PluginConfig struct {
	Name     string                 `mapstructure:"name" validate:"required"`
	Enabled  bool                   `mapstructure:"enabled"`
	Path     string                 `mapstructure:"path" validate:"required_if=Enabled true"`
	Config   map[string]string      `mapstructure:"config"`
	Settings map[string]interface{} `mapstructure:"settings"`
	Timeout  time.Duration          `mapstructure:"timeout" validate:"min=1s"`
	Retries  int                    `mapstructure:"retries" validate:"min=0,max=10"`
}

// PluginEntry contains plugin entry information
type PluginEntry struct {
	Name        string                 `mapstructure:"name" validate:"required"`
	Path        string                 `mapstructure:"path" validate:"required"`
	Version     string                 `mapstructure:"version" validate:"required"`
	Description string                 `mapstructure:"description"`
	Author      string                 `mapstructure:"author"`
	Enabled     bool                   `mapstructure:"enabled"`
	Config      map[string]interface{} `mapstructure:"config"`
}

// CacheConfig contains cache configuration
type CacheConfig struct {
	Enabled         bool          `mapstructure:"enabled"`
	Provider        string        `mapstructure:"provider" validate:"required_if=Enabled true,omitempty,oneof=memory redis"`
	CacheDir        string        `mapstructure:"cache_dir" validate:"required_if=Enabled true"`
	TTL             time.Duration `mapstructure:"ttl" validate:"min=1m"`
	MaxSize         int           `mapstructure:"max_size" validate:"min=100"`
	CleanupInterval time.Duration `mapstructure:"cleanup_interval" validate:"min=1m"`
}

// TypoDetectionConfig contains typo detection configuration
type TypoDetectionConfig struct {
	Enabled               bool    `mapstructure:"enabled"`
	Threshold             float64 `mapstructure:"threshold" validate:"min=0,max=1"`
	SimilarityThreshold   float64 `mapstructure:"similarity_threshold" validate:"min=0,max=1"`
	EditDistanceThreshold int     `mapstructure:"edit_distance_threshold" validate:"min=1"`
	MaxDistance           int     `mapstructure:"max_distance" validate:"min=1"`
	PhoneticMatching      bool    `mapstructure:"phonetic_matching"`
	CheckSimilarNames     bool    `mapstructure:"check_similar_names"`
	CheckHomoglyphs       bool    `mapstructure:"check_homoglyphs"`
	DictionaryPath        string  `mapstructure:"dictionary_path"`
}

// WebhookConfig contains webhook configuration
type WebhookConfig struct {
	Enabled   bool              `mapstructure:"enabled"`
	Endpoints []WebhookEndpoint `mapstructure:"endpoints"`
	Timeout   time.Duration     `mapstructure:"timeout" validate:"min=1s"`
	Retries   int               `mapstructure:"retries" validate:"min=0,max=10"`
}

// WebhookEndpoint contains webhook endpoint configuration
type WebhookEndpoint struct {
	Name    string            `mapstructure:"name" validate:"required"`
	URL     string            `mapstructure:"url" validate:"required,url"`
	Method  string            `mapstructure:"method" validate:"required,oneof=GET POST PUT PATCH DELETE"`
	Headers map[string]string `mapstructure:"headers"`
	Events  []string          `mapstructure:"events"`
}

// FeatureConfig contains feature flags
type FeatureConfig struct {
	MLScoring        bool `mapstructure:"ml_scoring"`
	AdvancedMetrics  bool `mapstructure:"advanced_metrics"`
	Caching          bool `mapstructure:"caching"`
	AsyncProcessing  bool `mapstructure:"async_processing"`
	Webhooks         bool `mapstructure:"webhooks"`
	BulkScanning     bool `mapstructure:"bulk_scanning"`
	HistoricalData   bool `mapstructure:"historical_data"`
	ExperimentalAPIs bool `mapstructure:"experimental_apis"`
}

// PoliciesConfig contains policy configuration
type PoliciesConfig struct {
	FailOnThreats  bool   `mapstructure:"fail_on_threats"`
	MinThreatLevel string `mapstructure:"min_threat_level" validate:"oneof=low medium high critical"`
}

// Manager manages application configuration
type Manager struct {
	config    *Config
	validator *validator.Validate
	env       Environment
	configDir string
}

// NewManager creates a new configuration manager
func NewManager() *Manager {
	return &Manager{
		validator: validator.New(),
	}
}

// Load loads configuration from files and environment variables
func (m *Manager) Load(configDir string) error {
	m.configDir = configDir

	// Set up Viper
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(configDir)
	viper.AddConfigPath(".")
	viper.AddConfigPath("./config")
	viper.AddConfigPath("/etc/typosentinel")

	// Environment variable configuration
	viper.SetEnvPrefix("TYPOSENTINEL")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	// Set defaults
	m.setDefaults()

	// Read configuration file
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return errors.Wrap(err, errors.ErrCodeConfig, "failed to read config file")
		}
	}

	// Load environment-specific configuration
	env := Environment(viper.GetString("app.environment"))
	m.env = env

	if env != "" {
		envConfigFile := fmt.Sprintf("config.%s", env)
		viper.SetConfigName(envConfigFile)
		if err := viper.MergeInConfig(); err != nil {
			if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
				return errors.Wrap(err, errors.ErrCodeConfig, "failed to read environment config file")
			}
		}
	}

	// Unmarshal configuration
	m.config = &Config{}
	if err := viper.Unmarshal(m.config); err != nil {
		return errors.Wrap(err, errors.ErrCodeConfig, "failed to unmarshal configuration")
	}

	// Validate configuration
	if err := m.validate(); err != nil {
		return errors.Wrap(err, errors.ErrCodeValidation, "configuration validation failed")
	}

	// Post-process configuration
	if err := m.postProcess(); err != nil {
		return errors.Wrap(err, errors.ErrCodeConfig, "configuration post-processing failed")
	}

	return nil
}

// Get returns the current configuration
func (m *Manager) Get() *Config {
	return m.config
}

// GetEnvironment returns the current environment
func (m *Manager) GetEnvironment() Environment {
	return m.env
}

// IsProduction returns true if running in production environment
func (m *Manager) IsProduction() bool {
	return m.env == EnvProduction
}

// IsDevelopment returns true if running in development environment
func (m *Manager) IsDevelopment() bool {
	return m.env == EnvDevelopment
}

// IsTesting returns true if running in testing environment
func (m *Manager) IsTesting() bool {
	return m.env == EnvTesting
}

// Reload reloads the configuration
func (m *Manager) Reload() error {
	return m.Load(m.configDir)
}

// setDefaults sets default configuration values
func (m *Manager) setDefaults() {
	// App defaults
	viper.SetDefault("app.name", "Typosentinel")
	viper.SetDefault("app.version", "1.0.0")
	viper.SetDefault("app.environment", "development")
	viper.SetDefault("app.debug", false)
	viper.SetDefault("app.log_level", "info")
	viper.SetDefault("app.data_dir", "./data")
	viper.SetDefault("app.temp_dir", "/tmp")
	viper.SetDefault("app.max_workers", 10)

	// Server defaults
	viper.SetDefault("server.host", "localhost")
	viper.SetDefault("server.port", 8080)
	viper.SetDefault("server.read_timeout", "30s")
	viper.SetDefault("server.write_timeout", "30s")
	viper.SetDefault("server.idle_timeout", "60s")
	viper.SetDefault("server.shutdown_timeout", "30s")
	viper.SetDefault("server.tls.enabled", false)
	viper.SetDefault("server.cors.enabled", true)
	viper.SetDefault("server.cors.allowed_origins", []string{"http://localhost:3000", "http://localhost:8080"})
	viper.SetDefault("server.cors.allowed_methods", []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"})
	viper.SetDefault("server.cors.allowed_headers", []string{"Origin", "Content-Type", "Authorization", "X-API-Key"})
	viper.SetDefault("server.cors.max_age", 3600)

	// Database defaults
	viper.SetDefault("database.type", "sqlite")
	viper.SetDefault("database.database", "./data/typosentinel.db")
	viper.SetDefault("database.max_open_conns", 25)
	viper.SetDefault("database.max_idle_conns", 5)
	viper.SetDefault("database.conn_max_lifetime", "5m")
	viper.SetDefault("database.migrations_path", "./migrations")

	// Redis defaults
	viper.SetDefault("redis.enabled", false)
	viper.SetDefault("redis.host", "localhost")
	viper.SetDefault("redis.port", 6379)
	viper.SetDefault("redis.database", 0)
	viper.SetDefault("redis.pool_size", 10)
	viper.SetDefault("redis.dial_timeout", "5s")
	viper.SetDefault("redis.read_timeout", "3s")
	viper.SetDefault("redis.write_timeout", "3s")
	viper.SetDefault("redis.idle_timeout", "5m")
	viper.SetDefault("redis.ttl", "1h")

	// Logging defaults
	viper.SetDefault("logging.level", "info")
	viper.SetDefault("logging.format", "json")
	viper.SetDefault("logging.output", "stdout")
	viper.SetDefault("logging.max_size", 100)
	viper.SetDefault("logging.max_backups", 3)
	viper.SetDefault("logging.max_age", 28)
	viper.SetDefault("logging.compress", true)

	// Metrics defaults
	viper.SetDefault("metrics.enabled", false)
	viper.SetDefault("metrics.provider", "prometheus")
	viper.SetDefault("metrics.address", ":9090")
	viper.SetDefault("metrics.namespace", "typosentinel")
	viper.SetDefault("metrics.interval", "15s")
	viper.SetDefault("metrics.buckets", []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10})

	// Security defaults
	viper.SetDefault("security.jwt.enabled", false)
	viper.SetDefault("security.jwt.expiration", "1h")
	viper.SetDefault("security.jwt.refresh_expiration", "24h")
	viper.SetDefault("security.api_keys.enabled", false)
	viper.SetDefault("security.encryption.algorithm", "aes-256-gcm")
	viper.SetDefault("security.encryption.key", "default-encryption-key-32-chars-long")
	viper.SetDefault("security.password_policy.min_length", 8)
	viper.SetDefault("security.password_policy.require_upper", true)
	viper.SetDefault("security.password_policy.require_lower", true)
	viper.SetDefault("security.password_policy.require_digit", true)
	viper.SetDefault("security.password_policy.require_symbol", false)
	viper.SetDefault("security.csrf.enabled", false)
	viper.SetDefault("security.csrf.cookie_name", "_csrf_token")
	viper.SetDefault("security.csrf.header_name", "X-CSRF-Token")

	// ML defaults
	viper.SetDefault("ml.enabled", false)
	viper.SetDefault("ml.threshold", 0.5)
	viper.SetDefault("ml.batch_size", 100)
	viper.SetDefault("ml.timeout", "30s")
	viper.SetDefault("ml.cache_size", 1000)
	viper.SetDefault("ml.update_interval", "24h")
	viper.SetDefault("ml.model_config.type", "tensorflow")
	viper.SetDefault("ml.model_config.preprocessing.scaling", "standard")

	// Scanner defaults
	viper.SetDefault("scanner.max_concurrency", 10)
	viper.SetDefault("scanner.timeout", "30s")
	viper.SetDefault("scanner.retry_attempts", 3)
	viper.SetDefault("scanner.retry_delay", "1s")
	viper.SetDefault("scanner.user_agent", "Typosentinel/1.0")
	viper.SetDefault("scanner.registries.npm.enabled", true)
	viper.SetDefault("scanner.registries.npm.url", "https://registry.npmjs.org")
	viper.SetDefault("scanner.registries.npm.timeout", "10s")
	viper.SetDefault("scanner.registries.pypi.enabled", true)
	viper.SetDefault("scanner.registries.pypi.url", "https://pypi.org")
	viper.SetDefault("scanner.registries.pypi.timeout", "10s")
	viper.SetDefault("scanner.registries.rubygems.enabled", false)
	viper.SetDefault("scanner.registries.rubygems.url", "https://rubygems.org")
	viper.SetDefault("scanner.registries.rubygems.timeout", "10s")

	// API defaults
	viper.SetDefault("api.prefix", "/api")
	viper.SetDefault("api.version", "v1")
	viper.SetDefault("api.documentation.enabled", true)
	viper.SetDefault("api.documentation.path", "/docs")
	viper.SetDefault("api.documentation.title", "Typosentinel API")
	viper.SetDefault("api.documentation.version", "1.0.0")
	viper.SetDefault("api.rest.versioning.strategy", "path")
	viper.SetDefault("api.rest.versioning.default_version", "v1")
	viper.SetDefault("api.rest.versioning.supported_versions", []string{"v1"})

	// Rate limit defaults
	viper.SetDefault("rate_limit.enabled", true)
	viper.SetDefault("rate_limit.requests", 100)
	viper.SetDefault("rate_limit.window", "1m")
	viper.SetDefault("rate_limit.burst", 10)
	viper.SetDefault("rate_limit.headers", true)
	viper.SetDefault("rate_limit.skip_paths", []string{"/health", "/metrics"})

	// Feature defaults
	viper.SetDefault("features.ml_scoring", false)
	viper.SetDefault("features.advanced_metrics", false)
	viper.SetDefault("features.caching", true)
	viper.SetDefault("features.async_processing", false)
	viper.SetDefault("features.webhooks", false)
	viper.SetDefault("features.bulk_scanning", true)
	viper.SetDefault("features.historical_data", false)
	viper.SetDefault("features.experimental_apis", false)

	// Policies defaults
	viper.SetDefault("policies.fail_on_threats", false)
	viper.SetDefault("policies.min_threat_level", "medium")

	// Typo detection defaults
	viper.SetDefault("typo_detection.max_distance", 2)

	// ML analysis defaults
	viper.SetDefault("ml_analysis.batch_size", 100)
	viper.SetDefault("ml_analysis.max_features", 1000)
	viper.SetDefault("ml_analysis.timeout", "30s")
	viper.SetDefault("ml_analysis.feature_store.provider", "redis")
	viper.SetDefault("ml_analysis.feature_store.ttl", "1h")
	viper.SetDefault("ml_analysis.model_updates.interval", "24h")
}

// IntegrationsConfig contains integrations configuration
type IntegrationsConfig struct {
	Enabled      bool                        `mapstructure:"enabled"`
	Connectors   map[string]ConnectorConfig `mapstructure:"connectors"`
	EventRouting map[string][]string         `mapstructure:"event_routing"`
	Filters      []FilterConfig             `mapstructure:"filters"`
}

// ConnectorConfig contains connector configuration
type ConnectorConfig struct {
	Type     string                 `mapstructure:"type" validate:"required,oneof=splunk slack webhook email"`
	Enabled  bool                   `mapstructure:"enabled"`
	Settings map[string]interface{} `mapstructure:"settings" validate:"required"`
	Retry    RetryConfig            `mapstructure:"retry"`
	Filters  []string               `mapstructure:"filters"`
}

// RetryConfig contains retry configuration
type RetryConfig struct {
	Enabled     bool          `mapstructure:"enabled"`
	MaxAttempts int           `mapstructure:"max_attempts" validate:"min=1,max=10"`
	InitialDelay time.Duration `mapstructure:"initial_delay" validate:"min=1s"`
	MaxDelay     time.Duration `mapstructure:"max_delay" validate:"min=1s"`
	BackoffFactor float64      `mapstructure:"backoff_factor" validate:"min=1.0,max=10.0"`
}

// FilterConfig contains filter configuration
type FilterConfig struct {
	Name      string                 `mapstructure:"name" validate:"required"`
	Type      string                 `mapstructure:"type" validate:"required,oneof=severity package_name threat_type"`
	Condition string                 `mapstructure:"condition" validate:"required,oneof=equals contains regex"`
	Value     interface{}            `mapstructure:"value" validate:"required"`
	Metadata  map[string]interface{} `mapstructure:"metadata"`
}

// SupplyChainConfig contains supply chain security configuration
type SupplyChainConfig struct {
	Enabled             bool                      `mapstructure:"enabled"`
	BuildIntegrity      BuildIntegrityConfig      `mapstructure:"build_integrity"`
	ZeroDayDetection    ZeroDayDetectionConfig    `mapstructure:"zero_day_detection"`
	DependencyGraph     DependencyGraphConfig     `mapstructure:"dependency_graph"`
	ThreatIntelligence  ThreatIntelConfig         `mapstructure:"threat_intelligence"`
	HoneypotDetection   HoneypotDetectionConfig   `mapstructure:"honeypot_detection"`
	RiskCalculation     RiskCalculationConfig     `mapstructure:"risk_calculation"`
	DataStorage         SupplyChainStorageConfig  `mapstructure:"data_storage"`
}

// BuildIntegrityConfig contains build integrity detection configuration
type BuildIntegrityConfig struct {
	Enabled           bool          `mapstructure:"enabled"`
	SignatureCheck    bool          `mapstructure:"signature_check"`
	TamperingDetection bool         `mapstructure:"tampering_detection"`
	BuildAnalysis     bool          `mapstructure:"build_analysis"`
	Timeout           time.Duration `mapstructure:"timeout" validate:"min=1s"`
}

// ZeroDayDetectionConfig contains zero-day detection configuration
type ZeroDayDetectionConfig struct {
	Enabled            bool          `mapstructure:"enabled"`
	BehavioralAnalysis bool          `mapstructure:"behavioral_analysis"`
	CodeAnomalyDetection bool        `mapstructure:"code_anomaly_detection"`
	RuntimeAnalysis    bool          `mapstructure:"runtime_analysis"`
	AnomalyThreshold   float64       `mapstructure:"anomaly_threshold" validate:"min=0,max=1"`
	Timeout            time.Duration `mapstructure:"timeout" validate:"min=1s"`
}

// DependencyGraphConfig contains dependency graph analysis configuration
type DependencyGraphConfig struct {
	Enabled               bool `mapstructure:"enabled"`
	MaxDepth              int  `mapstructure:"max_depth" validate:"min=1,max=20"`
	TransitiveAnalysis    bool `mapstructure:"transitive_analysis"`
	ConfusionDetection    bool `mapstructure:"confusion_detection"`
	SupplyChainRiskAnalysis bool `mapstructure:"supply_chain_risk_analysis"`
}

// ThreatIntelConfig contains threat intelligence configuration
type ThreatIntelConfig struct {
	Enabled           bool                    `mapstructure:"enabled"`
	Sources           []ThreatIntelSource     `mapstructure:"sources"`
	CacheEnabled      bool                    `mapstructure:"cache_enabled"`
	CacheTTL          time.Duration           `mapstructure:"cache_ttl" validate:"min=1m"`
	Timeout           time.Duration           `mapstructure:"timeout" validate:"min=1s"`
	Retries           int                     `mapstructure:"retries" validate:"min=0,max=5"`
}

// ThreatIntelSource contains threat intelligence source configuration
type ThreatIntelSource struct {
	Name     string            `mapstructure:"name" validate:"required"`
	Type     string            `mapstructure:"type" validate:"required,oneof=api feed database"`
	Enabled  bool              `mapstructure:"enabled"`
	URL      string            `mapstructure:"url" validate:"required_if=Type api,omitempty,url"`
	APIKey   string            `mapstructure:"api_key"`
	Headers  map[string]string `mapstructure:"headers"`
	Priority int               `mapstructure:"priority" validate:"min=1,max=10"`
}

// HoneypotDetectionConfig contains honeypot detection configuration
type HoneypotDetectionConfig struct {
	Enabled              bool          `mapstructure:"enabled"`
	PackageTrapDetection bool          `mapstructure:"package_trap_detection"`
	AuthenticityValidation bool        `mapstructure:"authenticity_validation"`
	ConfidenceThreshold  float64       `mapstructure:"confidence_threshold" validate:"min=0,max=1"`
	Timeout              time.Duration `mapstructure:"timeout" validate:"min=1s"`
}

// RiskCalculationConfig contains risk calculation configuration
type RiskCalculationConfig struct {
	Enabled           bool                    `mapstructure:"enabled"`
	Weights           RiskWeights             `mapstructure:"weights"`
	Thresholds        RiskThresholds          `mapstructure:"thresholds"`
	Factors           []string                `mapstructure:"factors"`
	CustomRules       []CustomRiskRule        `mapstructure:"custom_rules"`
}

// RiskWeights contains weights for different risk factors
type RiskWeights struct {
	BuildIntegrity    float64 `mapstructure:"build_integrity" validate:"min=0,max=1"`
	ZeroDayThreats    float64 `mapstructure:"zero_day_threats" validate:"min=0,max=1"`
	ThreatIntel       float64 `mapstructure:"threat_intel" validate:"min=0,max=1"`
	HoneypotDetection float64 `mapstructure:"honeypot_detection" validate:"min=0,max=1"`
	DependencyRisk    float64 `mapstructure:"dependency_risk" validate:"min=0,max=1"`
}

// RiskThresholds contains thresholds for risk levels
type RiskThresholds struct {
	Low      float64 `mapstructure:"low" validate:"min=0,max=1"`
	Medium   float64 `mapstructure:"medium" validate:"min=0,max=1"`
	High     float64 `mapstructure:"high" validate:"min=0,max=1"`
	Critical float64 `mapstructure:"critical" validate:"min=0,max=1"`
}

// CustomRiskRule contains custom risk calculation rules
type CustomRiskRule struct {
	Name        string                 `mapstructure:"name" validate:"required"`
	Condition   string                 `mapstructure:"condition" validate:"required"`
	RiskScore   float64                `mapstructure:"risk_score" validate:"min=0,max=1"`
	Description string                 `mapstructure:"description"`
	Metadata    map[string]interface{} `mapstructure:"metadata"`
}

// SupplyChainStorageConfig contains storage configuration for supply chain data
type SupplyChainStorageConfig struct {
	Enabled        bool                  `mapstructure:"enabled"`
	GraphDatabase  GraphDatabaseConfig   `mapstructure:"graph_database"`
	TimeSeriesDB   TimeSeriesDBConfig    `mapstructure:"time_series_db"`
	RetentionPolicy RetentionPolicyConfig `mapstructure:"retention_policy"`
}

// GraphDatabaseConfig contains graph database configuration
type GraphDatabaseConfig struct {
	Enabled  bool   `mapstructure:"enabled"`
	Type     string `mapstructure:"type" validate:"required_if=Enabled true,omitempty,oneof=neo4j arangodb"`
	Host     string `mapstructure:"host" validate:"required_if=Enabled true,omitempty,hostname_rfc1123|ip"`
	Port     int    `mapstructure:"port" validate:"required_if=Enabled true,omitempty,min=1,max=65535"`
	Database string `mapstructure:"database" validate:"required_if=Enabled true,omitempty,min=1"`
	Username string `mapstructure:"username" validate:"required_if=Enabled true,omitempty,min=1"`
	Password string `mapstructure:"password" validate:"required_if=Enabled true,omitempty,min=1"`
}

// TimeSeriesDBConfig contains time series database configuration
type TimeSeriesDBConfig struct {
	Enabled      bool   `mapstructure:"enabled"`
	Type         string `mapstructure:"type" validate:"required_if=Enabled true,omitempty,oneof=influxdb prometheus"`
	Host         string `mapstructure:"host" validate:"required_if=Enabled true,omitempty,hostname_rfc1123|ip"`
	Port         int    `mapstructure:"port" validate:"required_if=Enabled true,omitempty,min=1,max=65535"`
	Database     string `mapstructure:"database" validate:"required_if=Enabled true,omitempty,min=1"`
	Username     string `mapstructure:"username"`
	Password     string `mapstructure:"password"`
	Organization string `mapstructure:"organization"`
	Bucket       string `mapstructure:"bucket"`
	Token        string `mapstructure:"token"`
}

// RetentionPolicyConfig contains data retention policy configuration
type RetentionPolicyConfig struct {
	Enabled           bool          `mapstructure:"enabled"`
	ScanResults       time.Duration `mapstructure:"scan_results" validate:"min=24h"`
	ThreatIntel       time.Duration `mapstructure:"threat_intel" validate:"min=24h"`
	DependencyGraphs  time.Duration `mapstructure:"dependency_graphs" validate:"min=24h"`
	BuildIntegrity    time.Duration `mapstructure:"build_integrity" validate:"min=24h"`
	ZeroDayFindings   time.Duration `mapstructure:"zero_day_findings" validate:"min=24h"`
	HoneypotDetections time.Duration `mapstructure:"honeypot_detections" validate:"min=24h"`
}

// validate validates the configuration
func (m *Manager) validate() error {
	// Register custom validators
	m.registerCustomValidators()

	// Validate the configuration struct
	if err := m.validator.Struct(m.config); err != nil {
		return err
	}

	// Custom validation logic
	return m.customValidation()
}

// registerCustomValidators registers custom validation functions
func (m *Manager) registerCustomValidators() {
	// Register semver validator
	m.validator.RegisterValidation("semver", func(fl validator.FieldLevel) bool {
		// Simplified semver validation
		value := fl.Field().String()
		return len(value) > 0 && strings.Contains(value, ".")
	})

	// Register directory validator
	m.validator.RegisterValidation("dir", func(fl validator.FieldLevel) bool {
		path := fl.Field().String()
		if path == "" {
			return false
		}
		info, err := os.Stat(path)
		return err == nil && info.IsDir()
	})
}

// customValidation performs custom validation logic
func (m *Manager) customValidation() error {
	// Validate environment-specific requirements
	if m.config.App.Environment == EnvProduction {
		if m.config.App.Debug {
			return errors.NewValidationError("debug mode should be disabled in production")
		}
		if m.config.Security.JWT.Enabled && len(m.config.Security.JWT.Secret) < 32 {
			return errors.NewValidationError("JWT secret must be at least 32 characters in production")
		}
	}

	// Validate TLS configuration
	if m.config.Server.TLS.Enabled {
		if m.config.Server.TLS.CertFile == "" || m.config.Server.TLS.KeyFile == "" {
			return errors.NewValidationError("TLS cert and key files are required when TLS is enabled")
		}
	}

	// Validate database configuration
	if m.config.Database.Type != "sqlite" {
		if m.config.Database.Host == "" || m.config.Database.Username == "" {
			return errors.NewValidationError("database host and username are required for non-SQLite databases")
		}
	}

	// Validate Redis configuration
	if m.config.Redis.Enabled {
		if m.config.Redis.Host == "" {
			return errors.NewValidationError("Redis host is required when Redis is enabled")
		}
	}

	return nil
}

// postProcess performs post-processing on the configuration
func (m *Manager) postProcess() error {
	// Ensure directories exist
	dirs := []string{
		m.config.App.DataDir,
		m.config.App.TempDir,
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return errors.Wrapf(err, errors.ErrCodeConfig, "failed to create directory: %s", dir)
		}
	}

	// Resolve relative paths
	if !filepath.IsAbs(m.config.App.DataDir) {
		abs, err := filepath.Abs(m.config.App.DataDir)
		if err != nil {
			return errors.Wrap(err, errors.ErrCodeConfig, "failed to resolve data directory path")
		}
		m.config.App.DataDir = abs
	}

	// Set environment-specific adjustments
	switch m.config.App.Environment {
	case EnvDevelopment:
		m.config.App.Debug = true
		m.config.Logging.Level = "debug"
	case EnvProduction:
		m.config.App.Debug = false
		if m.config.Logging.Level == "debug" {
			m.config.Logging.Level = "info"
		}
	}

	return nil
}

// GetDatabaseDSN returns the database connection string
func (c *Config) GetDatabaseDSN() string {
	switch c.Database.Type {
	case "sqlite":
		return c.Database.Database
	case "postgres":
		return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
			c.Database.Host, c.Database.Port, c.Database.Username,
			c.Database.Password, c.Database.Database, c.Database.SSLMode)
	case "mysql":
		return fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?parseTime=true",
			c.Database.Username, c.Database.Password,
			c.Database.Host, c.Database.Port, c.Database.Database)
	default:
		return ""
	}
}

// GetRedisAddr returns the Redis address
func (c *Config) GetRedisAddr() string {
	return fmt.Sprintf("%s:%d", c.Redis.Host, c.Redis.Port)
}

// GetServerAddr returns the server address
func (c *Config) GetServerAddr() string {
	return fmt.Sprintf("%s:%d", c.Server.Host, c.Server.Port)
}

// IsFeatureEnabled checks if a feature is enabled
func (c *Config) IsFeatureEnabled(feature string) bool {
	switch feature {
	case "ml_scoring":
		return c.Features.MLScoring
	case "advanced_metrics":
		return c.Features.AdvancedMetrics
	case "caching":
		return c.Features.Caching
	case "async_processing":
		return c.Features.AsyncProcessing
	case "webhooks":
		return c.Features.Webhooks
	case "bulk_scanning":
		return c.Features.BulkScanning
	case "historical_data":
		return c.Features.HistoricalData
	case "experimental_apis":
		return c.Features.ExperimentalAPIs
	default:
		return false
	}
}

// LoadConfig loads configuration from a file
func LoadConfig(configFile string) (*Config, error) {
	manager := NewManager()

	if configFile != "" {
		// Load from specific file
		dir := filepath.Dir(configFile)
		if err := manager.Load(dir); err != nil {
			return nil, fmt.Errorf("failed to load config from %s: %w", configFile, err)
		}
	} else {
		// Load from default locations
		if err := manager.Load("."); err != nil {
			return nil, fmt.Errorf("failed to load default config: %w", err)
		}
	}

	return manager.Get(), nil
}

// NewDefaultConfig creates a new configuration with default values
func NewDefaultConfig() *Config {
	manager := NewManager()
	manager.setDefaults()

	// Create config with defaults from viper
	config := &Config{
		App: AppConfig{
			Name:        viper.GetString("app.name"),
			Version:     viper.GetString("app.version"),
			Environment: Environment(viper.GetString("app.environment")),
			Debug:       viper.GetBool("app.debug"),
			Verbose:     false, // Default verbose to false
			LogLevel:    viper.GetString("app.log_level"),
			DataDir:     viper.GetString("app.data_dir"),
			TempDir:     viper.GetString("app.temp_dir"),
			MaxWorkers:  viper.GetInt("app.max_workers"),
		},
		Server: ServerConfig{
			Host:            viper.GetString("server.host"),
			Port:            viper.GetInt("server.port"),
			ReadTimeout:     viper.GetDuration("server.read_timeout"),
			WriteTimeout:    viper.GetDuration("server.write_timeout"),
			IdleTimeout:     viper.GetDuration("server.idle_timeout"),
			ShutdownTimeout: viper.GetDuration("server.shutdown_timeout"),
			TLS: TLSConfig{
				Enabled: viper.GetBool("server.tls.enabled"),
			},
		},
		Database: DatabaseConfig{
			Type:            viper.GetString("database.type"),
			Database:        viper.GetString("database.database"),
			MaxOpenConns:    viper.GetInt("database.max_open_conns"),
			MaxIdleConns:    viper.GetInt("database.max_idle_conns"),
			ConnMaxLifetime: viper.GetDuration("database.conn_max_lifetime"),
			MigrationsPath:  viper.GetString("database.migrations_path"),
		},
		Logging: LoggingConfig{
			Level:      viper.GetString("logging.level"),
			Format:     viper.GetString("logging.format"),
			Output:     viper.GetString("logging.output"),
			MaxSize:    viper.GetInt("logging.max_size"),
			MaxBackups: viper.GetInt("logging.max_backups"),
			MaxAge:     viper.GetInt("logging.max_age"),
			Compress:   viper.GetBool("logging.compress"),
		},
		Features: FeatureConfig{
			MLScoring:        viper.GetBool("features.ml_scoring"),
			AdvancedMetrics:  viper.GetBool("features.advanced_metrics"),
			Caching:          viper.GetBool("features.caching"),
			AsyncProcessing:  viper.GetBool("features.async_processing"),
			Webhooks:         viper.GetBool("features.webhooks"),
			BulkScanning:     viper.GetBool("features.bulk_scanning"),
			HistoricalData:   viper.GetBool("features.historical_data"),
			ExperimentalAPIs: viper.GetBool("features.experimental_apis"),
		},
		Policies: PoliciesConfig{
			FailOnThreats:  viper.GetBool("policies.fail_on_threats"),
			MinThreatLevel: viper.GetString("policies.min_threat_level"),
		},
	}

	return config
}
