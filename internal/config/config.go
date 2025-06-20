package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

// Config represents the application configuration
type Config struct {
	// Global settings
	Verbose bool `mapstructure:"verbose" yaml:"verbose"`
	Debug   bool `mapstructure:"debug" yaml:"debug"`

	// API settings
	API APIConfig `mapstructure:"api" yaml:"api"`

	// Database settings
	Database DatabaseConfig `mapstructure:"database" yaml:"database"`

	// ML service settings
	MLService MLServiceConfig `mapstructure:"ml_service" yaml:"ml_service"`

	// Detection settings
	Detection DetectionConfig `mapstructure:"detection" yaml:"detection"`

	// Scanner settings
	Scanner ScannerConfig `mapstructure:"scanner" yaml:"scanner"`

	// Registry settings
	Registries map[string]RegistryConfig `mapstructure:"registries" yaml:"registries"`

	// Policy settings
	Policies PolicyConfig `mapstructure:"policies" yaml:"policies"`

	// Logging settings
	Logging LoggingConfig `mapstructure:"logging" yaml:"logging"`

	// Cache settings
	Cache *CacheConfig `mapstructure:"cache" yaml:"cache"`
}

// LoggingConfig represents logging configuration
type LoggingConfig struct {
	Level     string `yaml:"level" default:"info"`
	Format    string `yaml:"format" default:"text"`
	Output    string `yaml:"output" default:"stdout"`
	Timestamp bool   `yaml:"timestamp" default:"true"`
	Caller    bool   `yaml:"caller" default:"false"`
	Prefix    string `yaml:"prefix" default:"[TYPOSENTINEL]"`
	Rotation  LogRotationConfig `yaml:"rotation"`
}

// LogRotationConfig represents log rotation settings
type LogRotationConfig struct {
	Enabled    bool   `yaml:"enabled" default:"false"`
	MaxSize    int    `yaml:"max_size" default:"100"`    // MB
	MaxBackups int    `yaml:"max_backups" default:"3"`
	MaxAge     int    `yaml:"max_age" default:"28"`      // days
	Compress   bool   `yaml:"compress" default:"true"`
}

// APIConfig contains API server configuration
type APIConfig struct {
	Host    string `mapstructure:"host" yaml:"host"`
	Port    int    `mapstructure:"port" yaml:"port"`
	BaseURL string `mapstructure:"base_url" yaml:"base_url"`
	APIKey  string `mapstructure:"api_key" yaml:"api_key"`
	TLS     struct {
		Enabled  bool   `mapstructure:"enabled" yaml:"enabled"`
		CertFile string `mapstructure:"cert_file" yaml:"cert_file"`
		KeyFile  string `mapstructure:"key_file" yaml:"key_file"`
	} `mapstructure:"tls" yaml:"tls"`
	Auth struct {
		Enabled   bool   `mapstructure:"enabled" yaml:"enabled"`
		JWTSecret string `mapstructure:"jwt_secret" yaml:"jwt_secret"`
	} `mapstructure:"auth" yaml:"auth"`
}

// DatabaseConfig contains database configuration
type DatabaseConfig struct {
	Host     string `mapstructure:"host" yaml:"host"`
	Port     int    `mapstructure:"port" yaml:"port"`
	Name     string `mapstructure:"name" yaml:"name"`
	User     string `mapstructure:"user" yaml:"user"`
	Password string `mapstructure:"password" yaml:"password"`
	SSLMode  string `mapstructure:"ssl_mode" yaml:"ssl_mode"`
	Redis    struct {
		Host     string `mapstructure:"host" yaml:"host"`
		Port     int    `mapstructure:"port" yaml:"port"`
		Password string `mapstructure:"password" yaml:"password"`
		DB       int    `mapstructure:"db" yaml:"db"`
	} `mapstructure:"redis" yaml:"redis"`
}

// MLServiceConfig contains ML service configuration
type MLServiceConfig struct {
	Enabled  bool   `mapstructure:"enabled" yaml:"enabled"`
	Endpoint string `mapstructure:"endpoint" yaml:"endpoint"`
	Timeout  int    `mapstructure:"timeout" yaml:"timeout"`
	Models   struct {
		SemanticSimilarity string `mapstructure:"semantic_similarity" yaml:"semantic_similarity"`
		MaliciousDetection string `mapstructure:"malicious_detection" yaml:"malicious_detection"`
	} `mapstructure:"models" yaml:"models"`
}

// MLModelConfig contains ML model configuration
type MLModelConfig struct {
	Enabled        bool    `mapstructure:"enabled" yaml:"enabled"`
	ModelPath      string  `mapstructure:"model_path" yaml:"model_path"`
	Threshold      float64 `mapstructure:"threshold" yaml:"threshold"`
	BatchSize      int     `mapstructure:"batch_size" yaml:"batch_size"`
	MaxConcurrency int     `mapstructure:"max_concurrency" yaml:"max_concurrency"`
}

// DetectionConfig contains detection algorithm configuration
type DetectionConfig struct {
	SimilarityThreshold    float64 `mapstructure:"similarity_threshold" yaml:"similarity_threshold"`
	HomoglyphDetection     bool    `mapstructure:"homoglyph_detection" yaml:"homoglyph_detection"`
	SemanticAnalysis       bool    `mapstructure:"semantic_analysis" yaml:"semantic_analysis"`
	ReputationScoring      bool    `mapstructure:"reputation_scoring" yaml:"reputation_scoring"`
	DependencyConfusion    bool    `mapstructure:"dependency_confusion" yaml:"dependency_confusion"`
	EnhancedTyposquatting  bool    `mapstructure:"enhanced_typosquatting" yaml:"enhanced_typosquatting"`
	MaxEditDistance        int     `mapstructure:"max_edit_distance" yaml:"max_edit_distance"`
	MinPackageNameLength   int     `mapstructure:"min_package_name_length" yaml:"min_package_name_length"`
	ExcludeCommonPrefixes  bool    `mapstructure:"exclude_common_prefixes" yaml:"exclude_common_prefixes"`
}

// RegistryConfig contains registry-specific configuration
type RegistryConfig struct {
	Enabled     bool              `mapstructure:"enabled" yaml:"enabled"`
	URL         string            `mapstructure:"url" yaml:"url"`
	Timeout     int               `mapstructure:"timeout" yaml:"timeout"`
	RateLimit   int               `mapstructure:"rate_limit" yaml:"rate_limit"`
	Credentials map[string]string `mapstructure:"credentials" yaml:"credentials"`
	Private     struct {
		Namespaces []string `mapstructure:"namespaces" yaml:"namespaces"`
		Monitor    bool     `mapstructure:"monitor" yaml:"monitor"`
	} `mapstructure:"private" yaml:"private"`
}

// PolicyConfig contains policy configuration
type PolicyConfig struct {
	StrictMode       bool     `mapstructure:"strict_mode" yaml:"strict_mode"`
	FailOnThreats    bool     `mapstructure:"fail_on_threats" yaml:"fail_on_threats"`
	AllowedPackages  []string `mapstructure:"allowed_packages" yaml:"allowed_packages"`
	BlockedPackages  []string `mapstructure:"blocked_packages" yaml:"blocked_packages"`
	TrustedAuthors   []string `mapstructure:"trusted_authors" yaml:"trusted_authors"`
	MinThreatLevel   string   `mapstructure:"min_threat_level" yaml:"min_threat_level"`
	Notifications    struct {
		Enabled   bool     `mapstructure:"enabled" yaml:"enabled"`
		Webhooks  []string `mapstructure:"webhooks" yaml:"webhooks"`
		Email     []string `mapstructure:"email" yaml:"email"`
		Slack     string   `mapstructure:"slack" yaml:"slack"`
	} `mapstructure:"notifications" yaml:"notifications"`
}

// ScannerConfig contains scanner configuration
type ScannerConfig struct {
	IncludeDevDeps     bool                        `mapstructure:"include_dev_deps" yaml:"include_dev_deps"`
	MaxDepth           int                         `mapstructure:"max_depth" yaml:"max_depth"`
	EnableMLAnalysis   bool                        `mapstructure:"enable_ml_analysis" yaml:"enable_ml_analysis"`
	IncludeTransitive  bool                        `mapstructure:"include_transitive" yaml:"include_transitive"`
	EnrichMetadata     bool                        `mapstructure:"enrich_metadata" yaml:"enrich_metadata"`
	Registries         map[string]RegistryConfig   `mapstructure:"registries" yaml:"registries"`
	RiskThreshold      float64                     `mapstructure:"risk_threshold" yaml:"risk_threshold"`
}

// CacheConfig contains cache configuration
type CacheConfig struct {
	Enabled     bool          `mapstructure:"enabled" yaml:"enabled"`
	Type        string        `mapstructure:"type" yaml:"type"` // "memory", "file", "redis"
	TTL         time.Duration `mapstructure:"ttl" yaml:"ttl"`
	MaxSize     int64         `mapstructure:"max_size" yaml:"max_size"`
	CacheDir    string        `mapstructure:"cache_dir" yaml:"cache_dir"`
	RedisURL    string        `mapstructure:"redis_url" yaml:"redis_url"`
	Compression bool          `mapstructure:"compression" yaml:"compression"`
	Encryption  bool          `mapstructure:"encryption" yaml:"encryption"`
}

// Load loads configuration from file and environment variables
func Load() (*Config, error) {
	v := viper.New()

	// Set defaults
	setDefaults(v)

	// Configuration file settings
	v.SetConfigName(".typosentinel")
	v.SetConfigType("yaml")
	v.AddConfigPath(".")
	v.AddConfigPath("$HOME")
	v.AddConfigPath("/etc/typosentinel/")

	// Environment variables
	v.SetEnvPrefix("TYPOSENTINEL")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	// Read configuration file
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
		// Config file not found is OK, we'll use defaults
	}

	// Unmarshal configuration
	var config Config
	if err := v.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return &config, nil
}

// Initialize creates a default configuration file
func Initialize() error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %w", err)
	}

	configPath := filepath.Join(homeDir, ".typosentinel.yaml")

	// Check if config file already exists
	if _, err := os.Stat(configPath); err == nil {
		return fmt.Errorf("configuration file already exists at %s", configPath)
	}

	// Create default configuration
	defaultConfig := getDefaultConfig()

	// Write configuration file
	data, err := yaml.Marshal(defaultConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(configPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	fmt.Printf("Configuration file created at %s\n", configPath)
	return nil
}

// Show displays the current configuration
func Show(config *Config) error {
	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	fmt.Print(string(data))
	return nil
}

func setDefaults(v *viper.Viper) {
	// Global defaults
	v.SetDefault("verbose", false)
	v.SetDefault("debug", false)

	// API defaults
	v.SetDefault("api.host", "localhost")
	v.SetDefault("api.port", 8080)
	v.SetDefault("api.tls.enabled", false)
	v.SetDefault("api.auth.enabled", false)

	// Database defaults
	v.SetDefault("database.host", "localhost")
	v.SetDefault("database.port", 5432)
	v.SetDefault("database.name", "typosentinel")
	v.SetDefault("database.user", "typosentinel")
	v.SetDefault("database.ssl_mode", "disable")
	v.SetDefault("database.redis.host", "localhost")
	v.SetDefault("database.redis.port", 6379)
	v.SetDefault("database.redis.db", 0)

	// ML service defaults
	v.SetDefault("ml_service.enabled", true)
	v.SetDefault("ml_service.endpoint", "http://localhost:8081")
	v.SetDefault("ml_service.timeout", 30)

	// Detection defaults
	v.SetDefault("detection.similarity_threshold", 0.8)
	v.SetDefault("detection.homoglyph_detection", true)
	v.SetDefault("detection.semantic_analysis", true)
	v.SetDefault("detection.reputation_scoring", true)
	v.SetDefault("detection.dependency_confusion", true)
	v.SetDefault("detection.enhanced_typosquatting", true)
	v.SetDefault("detection.max_edit_distance", 3)
	v.SetDefault("detection.min_package_name_length", 2)
	v.SetDefault("detection.exclude_common_prefixes", true)

	// Registry defaults
	v.SetDefault("registries.npm.enabled", true)
	v.SetDefault("registries.npm.url", "https://registry.npmjs.org")
	v.SetDefault("registries.npm.timeout", 10)
	v.SetDefault("registries.npm.rate_limit", 100)

	v.SetDefault("registries.pypi.enabled", true)
	v.SetDefault("registries.pypi.url", "https://pypi.org")
	v.SetDefault("registries.pypi.timeout", 10)
	v.SetDefault("registries.pypi.rate_limit", 100)

	// Policy defaults
	v.SetDefault("policies.strict_mode", false)
	v.SetDefault("policies.fail_on_threats", false)
	v.SetDefault("policies.min_threat_level", "medium")
	v.SetDefault("policies.notifications.enabled", false)
}

func getDefaultConfig() *Config {
	return &Config{
		Verbose: false,
		Debug:   false,
		API: APIConfig{
			Host: "localhost",
			Port: 8080,
		},
		Database: DatabaseConfig{
			Host:    "localhost",
			Port:    5432,
			Name:    "typosentinel",
			User:    "typosentinel",
			SSLMode: "disable",
		},
		MLService: MLServiceConfig{
			Enabled:  true,
			Endpoint: "http://localhost:8081",
			Timeout:  30,
		},
		Detection: DetectionConfig{
			SimilarityThreshold:   0.8,
			HomoglyphDetection:    true,
			SemanticAnalysis:      true,
			ReputationScoring:     true,
			DependencyConfusion:   true,
			MaxEditDistance:       3,
			MinPackageNameLength:  2,
			ExcludeCommonPrefixes: true,
		},
		Registries: map[string]RegistryConfig{
			"npm": {
				Enabled:   true,
				URL:       "https://registry.npmjs.org",
				Timeout:   10,
				RateLimit: 100,
			},
			"pypi": {
				Enabled:   true,
				URL:       "https://pypi.org",
				Timeout:   10,
				RateLimit: 100,
			},
		},
		Scanner: ScannerConfig{
			IncludeDevDeps:    true,
			MaxDepth:          10,
			EnableMLAnalysis:  true,
			IncludeTransitive: true,
			Registries:        make(map[string]RegistryConfig),
			RiskThreshold:     0.5,
		},
		Policies: PolicyConfig{
			StrictMode:     false,
			FailOnThreats:  false,
			MinThreatLevel: "medium",
		},
	}
}