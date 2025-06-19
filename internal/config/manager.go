package config

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"

	"typosentinel/pkg/logger"
)

// ConfigManager handles configuration loading, validation, and management
type ConfigManager struct {
	viper       *viper.Viper
	configPaths []string
	envPrefix   string
	validators  map[string]func(interface{}) error
}

// ConfigTemplate represents a configuration template
type ConfigTemplate struct {
	Name        string                 `yaml:"name"`
	Description string                 `yaml:"description"`
	Version     string                 `yaml:"version"`
	Config      map[string]interface{} `yaml:"config"`
	Required    []string               `yaml:"required"`
	Optional    []string               `yaml:"optional"`
}

// ValidationError represents a configuration validation error
type ValidationError struct {
	Field   string `json:"field"`
	Value   string `json:"value"`
	Message string `json:"message"`
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("validation error for field '%s': %s (value: %s)", e.Field, e.Message, e.Value)
}

// ValidationResult holds validation results
type ValidationResult struct {
	Valid   bool              `json:"valid"`
	Errors  []ValidationError `json:"errors"`
	Warnings []string         `json:"warnings"`
}

// NewConfigManager creates a new configuration manager
func NewConfigManager() *ConfigManager {
	v := viper.New()
	v.SetEnvPrefix("TYPOSENTINEL")
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))

	cm := &ConfigManager{
		viper:      v,
		envPrefix:  "TYPOSENTINEL",
		validators: make(map[string]func(interface{}) error),
	}

	// Set default config paths
	cm.configPaths = []string{
		"./typosentinel.yaml",
		"./typosentinel.yml",
		"./config/typosentinel.yaml",
		"./config/typosentinel.yml",
		"~/.typosentinel.yaml",
		"~/.typosentinel.yml",
		"~/.config/typosentinel/config.yaml",
		"/etc/typosentinel/config.yaml",
	}

	// Register built-in validators
	cm.registerBuiltinValidators()

	return cm
}

// LoadConfig loads configuration from multiple sources
func (cm *ConfigManager) LoadConfig(configFile string) (*Config, error) {
	// Set config file if provided
	if configFile != "" {
		cm.viper.SetConfigFile(configFile)
	} else {
		// Try default paths
		for _, path := range cm.configPaths {
			expandedPath := expandPath(path)
			if _, err := os.Stat(expandedPath); err == nil {
				cm.viper.SetConfigFile(expandedPath)
				break
			}
		}
	}

	// Set defaults
	cm.setDefaults()

	// Read config file
	if err := cm.viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
		// Config file not found, use defaults
		logger.Info("No config file found, using defaults")
	} else {
		logger.Info(fmt.Sprintf("Using config file: %s", cm.viper.ConfigFileUsed()))
	}

	// Unmarshal into config struct
	var config Config
	if err := cm.viper.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Validate configuration
	if result := cm.ValidateConfig(&config); !result.Valid {
		return nil, fmt.Errorf("configuration validation failed: %v", result.Errors)
	}

	// Apply environment variable overrides
	cm.applyEnvOverrides(&config)

	return &config, nil
}

// ValidateConfig validates the configuration
func (cm *ConfigManager) ValidateConfig(config *Config) ValidationResult {
	result := ValidationResult{
		Valid:    true,
		Errors:   []ValidationError{},
		Warnings: []string{},
	}

	// Validate API configuration
	if config.API.Port < 1 || config.API.Port > 65535 {
		result.Errors = append(result.Errors, ValidationError{
			Field:   "api.port",
			Value:   fmt.Sprintf("%d", config.API.Port),
			Message: "port must be between 1 and 65535",
		})
	}

	// Validate detection thresholds
	if config.Detection.SimilarityThreshold < 0 || config.Detection.SimilarityThreshold > 1 {
		result.Errors = append(result.Errors, ValidationError{
			Field:   "detection.similarity_threshold",
			Value:   fmt.Sprintf("%.2f", config.Detection.SimilarityThreshold),
			Message: "similarity threshold must be between 0 and 1",
		})
	}

	if config.Detection.MaxEditDistance < 1 {
		result.Errors = append(result.Errors, ValidationError{
			Field:   "detection.max_edit_distance",
			Value:   fmt.Sprintf("%d", config.Detection.MaxEditDistance),
			Message: "max edit distance must be at least 1",
		})
	}

	// Validate scanner configuration
	if config.Scanner.MaxDepth < 1 {
		result.Errors = append(result.Errors, ValidationError{
			Field:   "scanner.max_depth",
			Value:   fmt.Sprintf("%d", config.Scanner.MaxDepth),
			Message: "max depth must be at least 1",
		})
	}

	if config.Scanner.RiskThreshold < 0 || config.Scanner.RiskThreshold > 1 {
		result.Errors = append(result.Errors, ValidationError{
			Field:   "scanner.risk_threshold",
			Value:   fmt.Sprintf("%.2f", config.Scanner.RiskThreshold),
			Message: "risk threshold must be between 0 and 1",
		})
	}

	// Validate registry configurations
	for name, registry := range config.Registries {
		if registry.Timeout < 1 {
			result.Errors = append(result.Errors, ValidationError{
				Field:   fmt.Sprintf("registries.%s.timeout", name),
				Value:   fmt.Sprintf("%d", registry.Timeout),
				Message: "timeout must be at least 1 second",
			})
		}

		if registry.RateLimit < 1 {
			result.Errors = append(result.Errors, ValidationError{
				Field:   fmt.Sprintf("registries.%s.rate_limit", name),
				Value:   fmt.Sprintf("%d", registry.RateLimit),
				Message: "rate limit must be at least 1",
			})
		}

		if registry.URL == "" {
			result.Errors = append(result.Errors, ValidationError{
				Field:   fmt.Sprintf("registries.%s.url", name),
				Value:   "",
				Message: "URL cannot be empty",
			})
		}
	}

	// Validate logging configuration
	validLogLevels := []string{"debug", "info", "warn", "error"}
	if !contains(validLogLevels, config.Logging.Level) {
		result.Errors = append(result.Errors, ValidationError{
			Field:   "logging.level",
			Value:   config.Logging.Level,
			Message: fmt.Sprintf("invalid log level, must be one of: %s", strings.Join(validLogLevels, ", ")),
		})
	}

	validLogFormats := []string{"text", "json"}
	if !contains(validLogFormats, config.Logging.Format) {
		result.Errors = append(result.Errors, ValidationError{
			Field:   "logging.format",
			Value:   config.Logging.Format,
			Message: fmt.Sprintf("invalid log format, must be one of: %s", strings.Join(validLogFormats, ", ")),
		})
	}

	// Check for warnings
	if config.Detection.SimilarityThreshold > 0.95 {
		result.Warnings = append(result.Warnings, "Very high similarity threshold may miss legitimate typosquatting attempts")
	}

	if config.Scanner.MaxDepth > 20 {
		result.Warnings = append(result.Warnings, "Very high max depth may impact performance")
	}

	// Set overall validity
	result.Valid = len(result.Errors) == 0

	return result
}

// CreateTemplate creates a configuration template
func (cm *ConfigManager) CreateTemplate(name, description string, config *Config) (*ConfigTemplate, error) {
	configMap := make(map[string]interface{})
	
	// Convert config struct to map
	configBytes, err := yaml.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := yaml.Unmarshal(configBytes, &configMap); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config to map: %w", err)
	}

	template := &ConfigTemplate{
		Name:        name,
		Description: description,
		Version:     "1.0",
		Config:      configMap,
		Required:    []string{"detection.similarity_threshold", "scanner.max_depth"},
		Optional:    []string{"api.port", "logging.level"},
	}

	return template, nil
}

// SaveTemplate saves a configuration template to file
func (cm *ConfigManager) SaveTemplate(template *ConfigTemplate, filename string) error {
	data, err := yaml.Marshal(template)
	if err != nil {
		return fmt.Errorf("failed to marshal template: %w", err)
	}

	if err := os.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("failed to write template file: %w", err)
	}

	return nil
}

// LoadTemplate loads a configuration template from file
func (cm *ConfigManager) LoadTemplate(filename string) (*ConfigTemplate, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read template file: %w", err)
	}

	var template ConfigTemplate
	if err := yaml.Unmarshal(data, &template); err != nil {
		return nil, fmt.Errorf("failed to unmarshal template: %w", err)
	}

	return &template, nil
}

// ApplyTemplate applies a template to create a new configuration
func (cm *ConfigManager) ApplyTemplate(template *ConfigTemplate, overrides map[string]interface{}) (*Config, error) {
	// Start with template config
	configMap := make(map[string]interface{})
	for k, v := range template.Config {
		configMap[k] = v
	}

	// Apply overrides
	for k, v := range overrides {
		configMap[k] = v
	}

	// Convert back to config struct
	configBytes, err := yaml.Marshal(configMap)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal config map: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(configBytes, &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return &config, nil
}

// GenerateConfigFile generates a configuration file with comments and examples
func (cm *ConfigManager) GenerateConfigFile(filename string, template string) error {
	var configContent string

	switch template {
	case "minimal":
		configContent = cm.getMinimalConfigTemplate()
	case "development":
		configContent = cm.getDevelopmentConfigTemplate()
	case "production":
		configContent = cm.getProductionConfigTemplate()
	case "security-focused":
		configContent = cm.getSecurityFocusedConfigTemplate()
	default:
		configContent = cm.getDefaultConfigTemplate()
	}

	if err := os.WriteFile(filename, []byte(configContent), 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// GetConfigInfo returns information about the current configuration
func (cm *ConfigManager) GetConfigInfo() map[string]interface{} {
	return map[string]interface{}{
		"config_file":    cm.viper.ConfigFileUsed(),
		"config_paths":   cm.configPaths,
		"env_prefix":     cm.envPrefix,
		"env_variables":  cm.getEnvVariables(),
		"all_settings":   cm.viper.AllSettings(),
	}
}

// Helper methods

func (cm *ConfigManager) setDefaults() {
	// Core defaults
	cm.viper.SetDefault("verbose", false)
	cm.viper.SetDefault("debug", false)

	// API defaults
	cm.viper.SetDefault("api.host", "localhost")
	cm.viper.SetDefault("api.port", 8080)
	cm.viper.SetDefault("api.tls.enabled", false)
	cm.viper.SetDefault("api.auth.enabled", false)

	// Database defaults
	cm.viper.SetDefault("database.host", "localhost")
	cm.viper.SetDefault("database.port", 5432)
	cm.viper.SetDefault("database.name", "typosentinel")
	cm.viper.SetDefault("database.ssl_mode", "disable")

	// Detection defaults
	cm.viper.SetDefault("detection.similarity_threshold", 0.8)
	cm.viper.SetDefault("detection.homoglyph_detection", true)
	cm.viper.SetDefault("detection.semantic_analysis", true)
	cm.viper.SetDefault("detection.max_edit_distance", 3)
	cm.viper.SetDefault("detection.min_package_name_length", 2)

	// Scanner defaults
	cm.viper.SetDefault("scanner.include_dev_deps", true)
	cm.viper.SetDefault("scanner.max_depth", 10)
	cm.viper.SetDefault("scanner.enable_ml_analysis", true)
	cm.viper.SetDefault("scanner.risk_threshold", 0.5)

	// Logging defaults
	cm.viper.SetDefault("logging.level", "info")
	cm.viper.SetDefault("logging.format", "text")
	cm.viper.SetDefault("logging.output", "stdout")
	cm.viper.SetDefault("logging.timestamp", true)

	// Registry defaults
	cm.viper.SetDefault("registries.npm.enabled", true)
	cm.viper.SetDefault("registries.npm.url", "https://registry.npmjs.org")
	cm.viper.SetDefault("registries.npm.timeout", 10)
	cm.viper.SetDefault("registries.npm.rate_limit", 100)

	cm.viper.SetDefault("registries.pypi.enabled", true)
	cm.viper.SetDefault("registries.pypi.url", "https://pypi.org")
	cm.viper.SetDefault("registries.pypi.timeout", 10)
	cm.viper.SetDefault("registries.pypi.rate_limit", 100)
}

func (cm *ConfigManager) applyEnvOverrides(config *Config) {
	// Apply environment variable overrides using reflection
	v := reflect.ValueOf(config).Elem()
	cm.applyEnvOverridesRecursive(v, "")
}

func (cm *ConfigManager) applyEnvOverridesRecursive(v reflect.Value, prefix string) {
	t := v.Type()

	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		fieldType := t.Field(i)
		fieldName := strings.ToLower(fieldType.Name)
		
		envKey := cm.envPrefix
		if prefix != "" {
			envKey += "_" + prefix
		}
		envKey += "_" + strings.ToUpper(fieldName)

		if field.Kind() == reflect.Struct {
			newPrefix := prefix
			if newPrefix != "" {
				newPrefix += "_"
			}
			newPrefix += fieldName
			cm.applyEnvOverridesRecursive(field, newPrefix)
		} else if field.CanSet() {
			if envValue := os.Getenv(envKey); envValue != "" {
				cm.setFieldFromEnv(field, envValue)
			}
		}
	}
}

func (cm *ConfigManager) setFieldFromEnv(field reflect.Value, envValue string) {
	switch field.Kind() {
	case reflect.String:
		field.SetString(envValue)
	case reflect.Bool:
		if val, err := strconv.ParseBool(envValue); err == nil {
			field.SetBool(val)
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if val, err := strconv.ParseInt(envValue, 10, 64); err == nil {
			field.SetInt(val)
		}
	case reflect.Float32, reflect.Float64:
		if val, err := strconv.ParseFloat(envValue, 64); err == nil {
			field.SetFloat(val)
		}
	}
}

func (cm *ConfigManager) getEnvVariables() []string {
	var envVars []string
	for _, env := range os.Environ() {
		if strings.HasPrefix(env, cm.envPrefix+"_") {
			envVars = append(envVars, env)
		}
	}
	return envVars
}

func (cm *ConfigManager) registerBuiltinValidators() {
	// Register common validators
	cm.validators["port"] = func(value interface{}) error {
		if port, ok := value.(int); ok {
			if port < 1 || port > 65535 {
				return fmt.Errorf("port must be between 1 and 65535")
			}
		}
		return nil
	}

	cm.validators["threshold"] = func(value interface{}) error {
		if threshold, ok := value.(float64); ok {
			if threshold < 0 || threshold > 1 {
				return fmt.Errorf("threshold must be between 0 and 1")
			}
		}
		return nil
	}

	cm.validators["timeout"] = func(value interface{}) error {
		if timeout, ok := value.(time.Duration); ok {
			if timeout < time.Second {
				return fmt.Errorf("timeout must be at least 1 second")
			}
		}
		return nil
	}
}

// Configuration templates

func (cm *ConfigManager) getDefaultConfigTemplate() string {
	return `# TypoSentinel Configuration File
# This is the default configuration with recommended settings

# Core Configuration
verbose: false
debug: false

# API Configuration
api:
  host: "localhost"
  port: 8080
  tls:
    enabled: false
    cert_file: ""
    key_file: ""
  auth:
    enabled: false
    jwt_secret: ""

# Database Configuration
database:
  host: "localhost"
  port: 5432
  name: "typosentinel"
  user: "typosentinel"
  password: ""
  ssl_mode: "disable"
  redis:
    host: "localhost"
    port: 6379
    password: ""
    db: 0

# Detection Configuration
detection:
  similarity_threshold: 0.8        # Threshold for typosquatting detection (0.0-1.0)
  homoglyph_detection: true        # Enable homoglyph character detection
  semantic_analysis: true          # Enable semantic analysis
  reputation_scoring: true         # Enable reputation-based scoring
  dependency_confusion: true       # Enable dependency confusion detection
  max_edit_distance: 3            # Maximum edit distance for similarity
  min_package_name_length: 2      # Minimum package name length to analyze
  exclude_common_prefixes: true   # Exclude common prefixes from analysis

# Scanner Configuration
scanner:
  include_dev_deps: true          # Include development dependencies
  max_depth: 10                   # Maximum dependency tree depth
  enable_ml_analysis: true        # Enable ML-based analysis
  include_transitive: true        # Include transitive dependencies
  risk_threshold: 0.5             # Risk threshold for flagging packages

# Registry Configuration
registries:
  npm:
    enabled: true
    url: "https://registry.npmjs.org"
    timeout: 10                   # Timeout in seconds
    rate_limit: 100              # Requests per minute
    auth_token: ""               # Optional authentication token
  pypi:
    enabled: true
    url: "https://pypi.org"
    timeout: 10
    rate_limit: 100
    auth_token: ""

# Logging Configuration
logging:
  level: "info"                   # debug, info, warn, error
  format: "text"                  # text or json
  output: "stdout"                # stdout, stderr, or file path
  timestamp: true                 # Include timestamps
  caller: false                   # Include caller information
  prefix: "[TYPOSENTINEL]"        # Log prefix
  rotation:
    enabled: false              # Enable log rotation
    max_size: 100               # Maximum size in MB
    max_backups: 3              # Number of backup files
    max_age: 28                 # Maximum age in days
    compress: true              # Compress rotated files

# Policy Configuration
policies:
  strict_mode: false              # Enable strict security policies
  fail_on_threats: false          # Exit with error on threats
  min_threat_level: "medium"      # Minimum threat level to report
  notifications:
    enabled: false              # Enable notifications
    webhook_url: ""             # Webhook URL for notifications
    email_recipients: []        # Email recipients for notifications
`
}

func (cm *ConfigManager) getMinimalConfigTemplate() string {
	return `# Minimal TypoSentinel Configuration

# Detection settings
detection:
  similarity_threshold: 0.8

# Scanner settings
scanner:
  max_depth: 10
  enable_ml_analysis: true

# Logging
logging:
  level: "info"
  format: "text"
`
}

func (cm *ConfigManager) getDevelopmentConfigTemplate() string {
	return `# Development Configuration for TypoSentinel

# Enable verbose logging for development
verbose: true
debug: true

# Detection with relaxed thresholds for testing
detection:
  similarity_threshold: 0.7
  homoglyph_detection: true
  semantic_analysis: true
  max_edit_distance: 4

# Scanner with detailed analysis
scanner:
  include_dev_deps: true
  max_depth: 15
  enable_ml_analysis: true
  include_transitive: true

# Detailed logging
logging:
  level: "debug"
  format: "text"
  timestamp: true
  caller: true
  prefix: "[TYPOSENTINEL-DEV]"

# Development-friendly policies
policies:
  strict_mode: false
  fail_on_threats: false
  min_threat_level: "low"
`
}

func (cm *ConfigManager) getProductionConfigTemplate() string {
	return `# Production Configuration for TypoSentinel

# Minimal logging for production
verbose: false
debug: false

# Strict detection settings
detection:
  similarity_threshold: 0.85
  homoglyph_detection: true
  semantic_analysis: true
  reputation_scoring: true
  dependency_confusion: true
  max_edit_distance: 2
  exclude_common_prefixes: true

# Optimized scanner settings
scanner:
  include_dev_deps: false
  max_depth: 8
  enable_ml_analysis: true
  include_transitive: true
  risk_threshold: 0.6

# Production logging
logging:
  level: "warn"
  format: "json"
  output: "/var/log/typosentinel/typosentinel.log"
  timestamp: true
  rotation:
    enabled: true
    max_size: 100
    max_backups: 5
    max_age: 30
    compress: true

# Strict security policies
policies:
  strict_mode: true
  fail_on_threats: true
  min_threat_level: "medium"
  notifications:
    enabled: true
    webhook_url: "${TYPOSENTINEL_WEBHOOK_URL}"
`
}

func (cm *ConfigManager) getSecurityFocusedConfigTemplate() string {
	return `# Security-Focused Configuration for TypoSentinel

# Maximum security settings
verbose: false
debug: false

# Aggressive detection settings
detection:
  similarity_threshold: 0.9
  homoglyph_detection: true
  semantic_analysis: true
  reputation_scoring: true
  dependency_confusion: true
  enhanced_typosquatting: true
  max_edit_distance: 1
  min_package_name_length: 3
  exclude_common_prefixes: true

# Comprehensive scanner settings
scanner:
  include_dev_deps: true
  max_depth: 20
  enable_ml_analysis: true
  include_transitive: true
  risk_threshold: 0.3

# Security-focused logging
logging:
  level: "info"
  format: "json"
  timestamp: true
  caller: true

# Maximum security policies
policies:
  strict_mode: true
  fail_on_threats: true
  min_threat_level: "low"
  notifications:
    enabled: true
`
}

// Utility functions

func expandPath(path string) string {
	if strings.HasPrefix(path, "~/") {
		homeDir, err := os.UserHomeDir()
		if err == nil {
			return filepath.Join(homeDir, path[2:])
		}
	}
	return path
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}