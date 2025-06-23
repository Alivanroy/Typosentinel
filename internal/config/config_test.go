package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/viper"
)

func TestLoadConfig_DefaultValues(t *testing.T) {
	// Test loading config with default values
	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatalf("Expected successful config load, got error: %v", err)
	}

	if cfg == nil {
		t.Error("Expected config to be loaded, got nil")
	}

	// Test default values
	if cfg.API.Port == 0 {
		t.Error("Expected default API port to be set")
	}

	if cfg.Logging.Level == "" {
		t.Error("Expected default logging level to be set")
	}
}

func TestLoadConfig_FromFile(t *testing.T) {
	// Create temporary config file
	tempDir, err := os.MkdirTemp("", "config_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	configFile := filepath.Join(tempDir, "test_config.yaml")
	configContent := `
verbose: true
debug: true
api:
  host: "localhost"
  port: 8080
  base_url: "http://localhost:8080"
database:
  host: "localhost"
  port: 5432
  name: "typosentinel"
  user: "postgres"
detection:
  enabled: true
  thresholds:
    similarity: 0.85
    confidence: 0.7
logging:
  level: "debug"
  format: "json"
  output: "stdout"
`

	err = os.WriteFile(configFile, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	cfg, err := LoadConfig(configFile)
	if err != nil {
		t.Fatalf("Expected successful config load, got error: %v", err)
	}

	if !cfg.Verbose {
		t.Error("Expected verbose to be true")
	}

	if !cfg.Debug {
		t.Error("Expected debug to be true")
	}

	if cfg.API.Host != "localhost" {
		t.Errorf("Expected API host localhost, got %s", cfg.API.Host)
	}

	if cfg.API.Port != 8080 {
		t.Errorf("Expected API port 8080, got %d", cfg.API.Port)
	}

	if cfg.Database.Host != "localhost" {
		t.Errorf("Expected database host localhost, got %s", cfg.Database.Host)
	}

	if cfg.Database.Port != 5432 {
		t.Errorf("Expected database port 5432, got %d", cfg.Database.Port)
	}

	if cfg.Logging.Level != "debug" {
		t.Errorf("Expected logging level debug, got %s", cfg.Logging.Level)
	}

	if cfg.Logging.Format != "json" {
		t.Errorf("Expected logging format json, got %s", cfg.Logging.Format)
	}
}

func TestLoadConfig_InvalidFile(t *testing.T) {
	// Test loading non-existent config file
	_, err := LoadConfig("/non/existent/config.yaml")
	if err == nil {
		t.Error("Expected error for non-existent config file")
	}
}

func TestLoadConfig_InvalidYAML(t *testing.T) {
	// Create temporary invalid YAML file
	tempDir, err := os.MkdirTemp("", "config_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	configFile := filepath.Join(tempDir, "invalid_config.yaml")
	invalidYAML := `
verbose: true
debug: [
  - invalid
  - yaml
  structure
`

	err = os.WriteFile(configFile, []byte(invalidYAML), 0644)
	if err != nil {
		t.Fatalf("Failed to write invalid config file: %v", err)
	}

	_, err = LoadConfig(configFile)
	if err == nil {
		t.Error("Expected error for invalid YAML config file")
	}
}

func TestLoadConfig_EnvironmentOverrides(t *testing.T) {
	// Set environment variables
	os.Setenv("TYPOSENTINEL_VERBOSE", "true")
	os.Setenv("TYPOSENTINEL_API_PORT", "9090")
	os.Setenv("TYPOSENTINEL_DATABASE_HOST", "remote-db")
	defer func() {
		os.Unsetenv("TYPOSENTINEL_VERBOSE")
		os.Unsetenv("TYPOSENTINEL_API_PORT")
		os.Unsetenv("TYPOSENTINEL_DATABASE_HOST")
	}()

	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatalf("Expected successful config load, got error: %v", err)
	}

	if !cfg.Verbose {
		t.Error("Expected verbose to be overridden by environment variable")
	}

	if cfg.API.Port != 9090 {
		t.Errorf("Expected API port to be overridden to 9090, got %d", cfg.API.Port)
	}

	if cfg.Database.Host != "remote-db" {
		t.Errorf("Expected database host to be overridden to remote-db, got %s", cfg.Database.Host)
	}
}

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name        string
		config      *Config
		expectError bool
	}{
		{
			name: "valid config",
			config: &Config{
				API: &APIConfig{
					Host: "localhost",
					Port: 8080,
				},
				Database: &DatabaseConfig{
					Host: "localhost",
					Port: 5432,
					Name: "typosentinel",
					User: "postgres",
				},
				Detection: &DetectionConfig{
					Enabled: true,
					Thresholds: ThresholdConfig{
						Similarity: 0.8,
						Confidence: 0.7,
					},
				},
				Logging: &LoggingConfig{
					Level:  "info",
					Format: "text",
					Output: "stdout",
				},
			},
			expectError: false,
		},
		{
			name: "invalid API port",
			config: &Config{
				API: &APIConfig{
					Host: "localhost",
					Port: -1, // Invalid port
				},
			},
			expectError: true,
		},
		{
			name: "invalid similarity threshold",
			config: &Config{
				Detection: &DetectionConfig{
					Thresholds: ThresholdConfig{
						Similarity: 1.5, // Invalid threshold > 1
					},
				},
			},
			expectError: true,
		},
		{
			name: "invalid confidence threshold",
			config: &Config{
				Detection: &DetectionConfig{
					Thresholds: ThresholdConfig{
						Confidence: -0.1, // Invalid threshold < 0
					},
				},
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateConfig(tt.config)
			if tt.expectError && err == nil {
				t.Error("Expected validation error, got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no validation error, got: %v", err)
			}
		})
	}
}

func TestAPIConfig(t *testing.T) {
	apiConfig := APIConfig{
		Host:    "0.0.0.0",
		Port:    8080,
		BaseURL: "https://api.typosentinel.com",
		APIKey:  "test-api-key",
	}

	apiConfig.TLS.Enabled = true
	apiConfig.TLS.CertFile = "/path/to/cert.pem"
	apiConfig.TLS.KeyFile = "/path/to/key.pem"

	apiConfig.Auth.Enabled = true
	apiConfig.Auth.JWTSecret = "jwt-secret-key"

	if apiConfig.Host != "0.0.0.0" {
		t.Errorf("Expected host 0.0.0.0, got %s", apiConfig.Host)
	}

	if apiConfig.Port != 8080 {
		t.Errorf("Expected port 8080, got %d", apiConfig.Port)
	}

	if !apiConfig.TLS.Enabled {
		t.Error("Expected TLS to be enabled")
	}

	if !apiConfig.Auth.Enabled {
		t.Error("Expected Auth to be enabled")
	}
}

func TestDatabaseConfig(t *testing.T) {
	dbConfig := DatabaseConfig{
		Host:     "localhost",
		Port:     5432,
		Name:     "typosentinel",
		User:     "postgres",
		Password: "password",
		SSLMode:  "require",
	}

	dbConfig.Redis.Host = "localhost"
	dbConfig.Redis.Port = 6379
	dbConfig.Redis.Password = "redis-password"
	dbConfig.Redis.Database = 0

	if dbConfig.Host != "localhost" {
		t.Errorf("Expected host localhost, got %s", dbConfig.Host)
	}

	if dbConfig.Port != 5432 {
		t.Errorf("Expected port 5432, got %d", dbConfig.Port)
	}

	if dbConfig.Redis.Host != "localhost" {
		t.Errorf("Expected Redis host localhost, got %s", dbConfig.Redis.Host)
	}

	if dbConfig.Redis.Port != 6379 {
		t.Errorf("Expected Redis port 6379, got %d", dbConfig.Redis.Port)
	}
}

func TestMLServiceConfig(t *testing.T) {
	mlConfig := MLServiceConfig{
		Enabled:  true,
		Endpoint: "http://localhost:8001",
		APIKey:   "ml-api-key",
		Timeout:  30 * time.Second,
	}

	if !mlConfig.Enabled {
		t.Error("Expected ML service to be enabled")
	}

	if mlConfig.Endpoint != "http://localhost:8001" {
		t.Errorf("Expected endpoint http://localhost:8001, got %s", mlConfig.Endpoint)
	}

	if mlConfig.Timeout != 30*time.Second {
		t.Errorf("Expected timeout 30s, got %v", mlConfig.Timeout)
	}
}

func TestDetectionConfig(t *testing.T) {
	detectionConfig := DetectionConfig{
		Enabled: true,
		Thresholds: ThresholdConfig{
			Similarity: 0.85,
			Confidence: 0.75,
			Reputation: 0.6,
		},
		Algorithms: AlgorithmConfig{
			Lexical:   true,
			Homoglyph: true,
			ML:        true,
		},
	}

	if !detectionConfig.Enabled {
		t.Error("Expected detection to be enabled")
	}

	if detectionConfig.Thresholds.Similarity != 0.85 {
		t.Errorf("Expected similarity threshold 0.85, got %f", detectionConfig.Thresholds.Similarity)
	}

	if !detectionConfig.Algorithms.Lexical {
		t.Error("Expected lexical algorithm to be enabled")
	}

	if !detectionConfig.Algorithms.Homoglyph {
		t.Error("Expected homoglyph algorithm to be enabled")
	}

	if !detectionConfig.Algorithms.ML {
		t.Error("Expected ML algorithm to be enabled")
	}
}

func TestLoggingConfig(t *testing.T) {
	loggingConfig := LoggingConfig{
		Level:     "debug",
		Format:    "json",
		Output:    "file",
		Timestamp: true,
		Caller:    true,
		Prefix:    "[TYPOSENTINEL]",
	}

	loggingConfig.Rotation.Enabled = true
	loggingConfig.Rotation.MaxSize = 100
	loggingConfig.Rotation.MaxBackups = 5
	loggingConfig.Rotation.MaxAge = 30
	loggingConfig.Rotation.Compress = true

	if loggingConfig.Level != "debug" {
		t.Errorf("Expected level debug, got %s", loggingConfig.Level)
	}

	if loggingConfig.Format != "json" {
		t.Errorf("Expected format json, got %s", loggingConfig.Format)
	}

	if !loggingConfig.Timestamp {
		t.Error("Expected timestamp to be enabled")
	}

	if !loggingConfig.Rotation.Enabled {
		t.Error("Expected log rotation to be enabled")
	}

	if loggingConfig.Rotation.MaxSize != 100 {
		t.Errorf("Expected max size 100, got %d", loggingConfig.Rotation.MaxSize)
	}
}

func TestRegistryConfig(t *testing.T) {
	registryConfig := RegistryConfig{
		Enabled:  true,
		BaseURL:  "https://registry.npmjs.org",
		APIKey:   "npm-api-key",
		Timeout: "10s",
		RateLimit: RateLimitConfig{
			Enabled: true,
			RPS:     100,
			Burst:   200,
		},
	}

	if !registryConfig.Enabled {
		t.Error("Expected registry to be enabled")
	}

	if registryConfig.BaseURL != "https://registry.npmjs.org" {
		t.Errorf("Expected base URL https://registry.npmjs.org, got %s", registryConfig.BaseURL)
	}

	if registryConfig.Timeout != "10s" {
		t.Errorf("Expected timeout 10s, got %v", registryConfig.Timeout)
	}

	if !registryConfig.RateLimit.Enabled {
		t.Error("Expected rate limit to be enabled")
	}

	if registryConfig.RateLimit.RPS != 100 {
		t.Errorf("Expected RPS 100, got %d", registryConfig.RateLimit.RPS)
	}
}

func TestPolicyConfig(t *testing.T) {
	policyConfig := PolicyConfig{
		Enabled: true,
		Rules: []PolicyRule{
			{
				Name:        "block-high-risk",
				Enabled:     true,

				Description: "Block packages with high risk",
			},
			{
				Name:        "warn-medium-risk",
				Enabled:     true,

				Description: "Warn about packages with medium risk",
			},
		},

	}

	if !policyConfig.Enabled {
		t.Error("Expected policy to be enabled")
	}

	if len(policyConfig.Rules) != 2 {
		t.Errorf("Expected 2 policy rules, got %d", len(policyConfig.Rules))
	}

	if policyConfig.Rules[0].Name != "block-high-risk" {
		t.Errorf("Expected rule name block-high-risk, got %s", policyConfig.Rules[0].Name)
	}

}

func TestViperIntegration(t *testing.T) {
	// Test that viper is properly configured
	viper.Reset()
	viper.SetConfigType("yaml")
	viper.SetEnvPrefix("TYPOSENTINEL")
	viper.AutomaticEnv()

	// Set some test values
	viper.Set("verbose", true)
	viper.Set("api.port", 9000)
	viper.Set("database.host", "test-db")

	var cfg Config
	err := viper.Unmarshal(&cfg)
	if err != nil {
		t.Fatalf("Failed to unmarshal config: %v", err)
	}

	if !cfg.Verbose {
		t.Error("Expected verbose to be true")
	}

	if cfg.API.Port != 9000 {
		t.Errorf("Expected API port 9000, got %d", cfg.API.Port)
	}

	if cfg.Database.Host != "test-db" {
		t.Errorf("Expected database host test-db, got %s", cfg.Database.Host)
	}
}

func TestConfigSerialization(t *testing.T) {
	// Test that config can be serialized to YAML
	cfg := &Config{
		Verbose: true,
		Debug:   false,
		API: &APIConfig{
			Host: "localhost",
			Port: 8080,
		},
		Logging: &LoggingConfig{
			Level:  "info",
			Format: "text",
		},
	}

	yamlData, err := cfg.ToYAML()
	if err != nil {
		t.Fatalf("Failed to serialize config to YAML: %v", err)
	}

	if len(yamlData) == 0 {
		t.Error("Expected non-empty YAML data")
	}

	// Test that we can deserialize it back
	var newCfg Config
	err = newCfg.FromYAML(yamlData)
	if err != nil {
		t.Fatalf("Failed to deserialize config from YAML: %v", err)
	}

	if newCfg.Verbose != cfg.Verbose {
		t.Error("Verbose setting not preserved after serialization")
	}

	if newCfg.API.Port != cfg.API.Port {
		t.Error("API port not preserved after serialization")
	}
}