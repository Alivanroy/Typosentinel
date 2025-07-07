package config

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestLoadConfigFromEnv(t *testing.T) {
	tests := []struct {
		name     string
		envVars  map[string]string
		validate func(*testing.T, *Config)
	}{
		{
			name: "server config from env",
			envVars: map[string]string{
				"SERVER_HOST":         "0.0.0.0",
				"SERVER_PORT":         "9090",
				"SERVER_READ_TIMEOUT": "45s",
			},
			validate: func(t *testing.T, cfg *Config) {
				assert.Equal(t, "0.0.0.0", cfg.Server.Host)
				assert.Equal(t, 9090, cfg.Server.Port)
				assert.Equal(t, 45*time.Second, cfg.Server.ReadTimeout)
			},
		},
		{
			name: "database config from env",
			envVars: map[string]string{
				"POSTGRES_HOST":     "localhost",
				"POSTGRES_PORT":     "5432",
				"POSTGRES_DB":       "typosentinel",
				"POSTGRES_USER":     "testuser",
				"POSTGRES_PASSWORD": "testpass",
			},
			validate: func(t *testing.T, cfg *Config) {
				assert.Equal(t, "localhost", cfg.Database.PostgreSQL.Host)
				assert.Equal(t, 5432, cfg.Database.PostgreSQL.Port)
				assert.Equal(t, "typosentinel", cfg.Database.PostgreSQL.Database)
				assert.Equal(t, "testuser", cfg.Database.PostgreSQL.Username)
				assert.Equal(t, "testpass", cfg.Database.PostgreSQL.Password)
			},
		},
		{
			name: "redis config from env",
			envVars: map[string]string{
				"REDIS_ADDRESS":  "redis.example.com:6380",
				"REDIS_PASSWORD": "redispass",
				"REDIS_DB":       "2",
			},
			validate: func(t *testing.T, cfg *Config) {
				assert.Equal(t, "redis.example.com:6380", cfg.Redis.Address)
				assert.Equal(t, "redispass", cfg.Redis.Password)
				assert.Equal(t, 2, cfg.Redis.DB)
			},
		},
		{
			name: "ml config from env",
			envVars: map[string]string{
				"ML_ENABLED":          "true",
				"ML_MODEL_PATH":       "/models/typo.model",
				"ML_BATCH_SIZE":       "64",
				"ML_BATCH_PREDICTION": "true",
			},
			validate: func(t *testing.T, cfg *Config) {
				assert.True(t, cfg.ML.Enabled)
				assert.Equal(t, "/models/typo.model", cfg.ML.ModelPath)
				assert.Equal(t, 64, cfg.ML.BatchSize)
				assert.True(t, cfg.ML.BatchPrediction)
			},
		},
		{
			name: "security config from env",
			envVars: map[string]string{
				"JWT_SECRET":                     "test-jwt-secret",
				"JWT_EXPIRATION":                 "24h",
				"ENCRYPTION_KEY":                 "test-encryption-key",
				"RATE_LIMIT_REQUESTS_PER_MINUTE": "1000",
				"RATE_LIMIT_WINDOW_SIZE":         "1m",
			},
			validate: func(t *testing.T, cfg *Config) {
				assert.Equal(t, "test-jwt-secret", cfg.Security.JWT.Secret)
				assert.Equal(t, 24*time.Hour, cfg.Security.JWT.Expiration)
				assert.Equal(t, "test-encryption-key", cfg.Security.Encryption.Key)
				assert.Equal(t, 1000, cfg.RateLimit.RequestsPerMinute)
				assert.Equal(t, time.Minute, cfg.RateLimit.WindowSize)
			},
		},
		{
			name: "storage config from env",
			envVars: map[string]string{
				"MINIO_ENDPOINT":          "minio.example.com:9000",
				"MINIO_ACCESS_KEY_ID":     "testkey",
				"MINIO_SECRET_ACCESS_KEY": "testsecret",
				"MINIO_USE_SSL":           "true",
				"LOCAL_STORAGE_ENABLED":   "false",
			},
			validate: func(t *testing.T, cfg *Config) {
				assert.Equal(t, "minio.example.com:9000", cfg.Storage.MinIO.Endpoint)
				assert.Equal(t, "testkey", cfg.Storage.MinIO.AccessKeyID)
				assert.Equal(t, "testsecret", cfg.Storage.MinIO.SecretAccessKey)
				assert.True(t, cfg.Storage.MinIO.UseSSL)
				assert.False(t, cfg.Storage.Local.Enabled)
			},
		},
		{
			name: "monitoring config from env",
			envVars: map[string]string{
				"PROMETHEUS_ENABLED": "true",
				"PROMETHEUS_PORT":    "9091",
				"JAEGER_ENABLED":     "true",
				"JAEGER_ENDPOINT":    "http://jaeger:14268/api/traces",
				"LOG_LEVEL":          "debug",
				"LOG_FORMAT":         "json",
			},
			validate: func(t *testing.T, cfg *Config) {
				assert.True(t, cfg.Monitoring.Prometheus.Enabled)
				assert.Equal(t, 9091, cfg.Monitoring.Prometheus.Port)
				assert.True(t, cfg.Monitoring.Jaeger.Enabled)
				assert.Equal(t, "http://jaeger:14268/api/traces", cfg.Monitoring.Jaeger.Endpoint)
				assert.Equal(t, "debug", cfg.Monitoring.Logging.Level)
				assert.Equal(t, "json", cfg.Monitoring.Logging.Format)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set environment variables
			for key, value := range tt.envVars {
				os.Setenv(key, value)
				defer os.Unsetenv(key)
			}

			cfg, err := Load()
			assert.NoError(t, err)
			assert.NotNil(t, cfg)

			if tt.validate != nil {
				tt.validate(t, cfg)
			}
		})
	}
}

func TestHelperFunctions(t *testing.T) {
	t.Run("getEnv", func(t *testing.T) {
		// Test with existing env var
		os.Setenv("TEST_ENV", "test_value")
		defer os.Unsetenv("TEST_ENV")
		result := getEnv("TEST_ENV", "default")
		assert.Equal(t, "test_value", result)

		// Test with non-existing env var
		result = getEnv("NON_EXISTING_ENV", "default")
		assert.Equal(t, "default", result)

		// Test with empty env var
		os.Setenv("EMPTY_ENV", "")
		defer os.Unsetenv("EMPTY_ENV")
		result = getEnv("EMPTY_ENV", "default")
		assert.Equal(t, "default", result)
	})

	t.Run("getEnvAsInt", func(t *testing.T) {
		// Test with valid int
		os.Setenv("TEST_INT", "123")
		defer os.Unsetenv("TEST_INT")
		result := getEnvAsInt("TEST_INT", 456)
		assert.Equal(t, 123, result)

		// Test with invalid int
		os.Setenv("INVALID_INT", "not_a_number")
		defer os.Unsetenv("INVALID_INT")
		result = getEnvAsInt("INVALID_INT", 456)
		assert.Equal(t, 456, result)

		// Test with non-existing env var
		result = getEnvAsInt("NON_EXISTING_INT", 789)
		assert.Equal(t, 789, result)

		// Test with negative int
		os.Setenv("NEGATIVE_INT", "-42")
		defer os.Unsetenv("NEGATIVE_INT")
		result = getEnvAsInt("NEGATIVE_INT", 0)
		assert.Equal(t, -42, result)
	})

	t.Run("getEnvAsInt64", func(t *testing.T) {
		// Test with valid int64
		os.Setenv("TEST_INT64", "9223372036854775807")
		defer os.Unsetenv("TEST_INT64")
		result := getEnvAsInt64("TEST_INT64", 0)
		assert.Equal(t, int64(9223372036854775807), result)

		// Test with invalid int64
		os.Setenv("INVALID_INT64", "not_a_number")
		defer os.Unsetenv("INVALID_INT64")
		result = getEnvAsInt64("INVALID_INT64", 123)
		assert.Equal(t, int64(123), result)

		// Test with non-existing env var
		result = getEnvAsInt64("NON_EXISTING_INT64", 456)
		assert.Equal(t, int64(456), result)
	})

	t.Run("getEnvAsFloat", func(t *testing.T) {
		// Test with valid float
		os.Setenv("TEST_FLOAT", "3.14159")
		defer os.Unsetenv("TEST_FLOAT")
		result := getEnvAsFloat("TEST_FLOAT", 0.0)
		assert.Equal(t, 3.14159, result)

		// Test with invalid float
		os.Setenv("INVALID_FLOAT", "not_a_number")
		defer os.Unsetenv("INVALID_FLOAT")
		result = getEnvAsFloat("INVALID_FLOAT", 2.71)
		assert.Equal(t, 2.71, result)

		// Test with non-existing env var
		result = getEnvAsFloat("NON_EXISTING_FLOAT", 1.23)
		assert.Equal(t, 1.23, result)

		// Test with integer as float
		os.Setenv("INT_AS_FLOAT", "42")
		defer os.Unsetenv("INT_AS_FLOAT")
		result = getEnvAsFloat("INT_AS_FLOAT", 0.0)
		assert.Equal(t, 42.0, result)
	})

	t.Run("getEnvAsBool", func(t *testing.T) {
		// Test with valid true values
		trueValues := []string{"true", "True", "TRUE", "1", "t", "T"}
		for _, val := range trueValues {
			os.Setenv("TEST_BOOL", val)
			result := getEnvAsBool("TEST_BOOL", false)
			assert.True(t, result, "Expected true for value: %s", val)
		}
		defer os.Unsetenv("TEST_BOOL")

		// Test with valid false values
		falseValues := []string{"false", "False", "FALSE", "0", "f", "F"}
		for _, val := range falseValues {
			os.Setenv("TEST_BOOL", val)
			result := getEnvAsBool("TEST_BOOL", true)
			assert.False(t, result, "Expected false for value: %s", val)
		}

		// Test with invalid bool
		os.Setenv("INVALID_BOOL", "maybe")
		result := getEnvAsBool("INVALID_BOOL", true)
		assert.True(t, result)

		// Test with non-existing env var
		result = getEnvAsBool("NON_EXISTING_BOOL", false)
		assert.False(t, result)
	})

	t.Run("getEnvAsDuration", func(t *testing.T) {
		// Test with valid duration
		os.Setenv("TEST_DURATION", "5m30s")
		defer os.Unsetenv("TEST_DURATION")
		result := getEnvAsDuration("TEST_DURATION", time.Minute)
		assert.Equal(t, 5*time.Minute+30*time.Second, result)

		// Test with invalid duration
		os.Setenv("INVALID_DURATION", "not_a_duration")
		defer os.Unsetenv("INVALID_DURATION")
		result = getEnvAsDuration("INVALID_DURATION", time.Hour)
		assert.Equal(t, time.Hour, result)

		// Test with non-existing env var
		result = getEnvAsDuration("NON_EXISTING_DURATION", 2*time.Hour)
		assert.Equal(t, 2*time.Hour, result)

		// Test with various duration formats
		durationTests := map[string]time.Duration{
			"1h":    time.Hour,
			"30m":   30 * time.Minute,
			"45s":   45 * time.Second,
			"100ms": 100 * time.Millisecond,
			"1h30m": time.Hour + 30*time.Minute,
		}
		for durStr, expected := range durationTests {
			os.Setenv("DURATION_TEST", durStr)
			result := getEnvAsDuration("DURATION_TEST", 0)
			assert.Equal(t, expected, result, "Failed for duration: %s", durStr)
		}
		defer os.Unsetenv("DURATION_TEST")
	})

	t.Run("getEnvAsSlice", func(t *testing.T) {
		// Test with comma-separated values
		os.Setenv("TEST_SLICE", "value1,value2,value3")
		defer os.Unsetenv("TEST_SLICE")
		result := getEnvAsSlice("TEST_SLICE", []string{"default"})
		expected := []string{"value1", "value2", "value3"}
		assert.Equal(t, expected, result)

		// Test with single value
		os.Setenv("SINGLE_VALUE", "single")
		defer os.Unsetenv("SINGLE_VALUE")
		result = getEnvAsSlice("SINGLE_VALUE", []string{"default"})
		expected = []string{"single"}
		assert.Equal(t, expected, result)

		// Test with empty values
		os.Setenv("EMPTY_VALUES", "value1,,value3")
		defer os.Unsetenv("EMPTY_VALUES")
		result = getEnvAsSlice("EMPTY_VALUES", []string{"default"})
		expected = []string{"value1", "", "value3"}
		assert.Equal(t, expected, result)

		// Test with non-existing env var
		defaultSlice := []string{"default1", "default2"}
		result = getEnvAsSlice("NON_EXISTING_SLICE", defaultSlice)
		assert.Equal(t, defaultSlice, result)

		// Test with empty env var
		os.Setenv("EMPTY_SLICE", "")
		defer os.Unsetenv("EMPTY_SLICE")
		result = getEnvAsSlice("EMPTY_SLICE", []string{"default"})
		assert.Equal(t, []string{"default"}, result)
	})
}

func TestLoadConfigDefaults(t *testing.T) {
	// Clear all environment variables that might affect the test
	envVars := []string{
		"SERVER_HOST", "SERVER_PORT", "SERVER_READ_TIMEOUT", "SERVER_WRITE_TIMEOUT",
		"POSTGRES_HOST", "POSTGRES_PORT", "POSTGRES_DB", "POSTGRES_USER", "POSTGRES_PASSWORD",
		"REDIS_ADDRESS", "REDIS_PASSWORD", "REDIS_DB",
		"ML_ENABLED", "ML_MODEL_PATH", "ML_BATCH_SIZE",
		"JWT_SECRET", "ENCRYPTION_KEY",
		"MINIO_ENDPOINT", "MINIO_ACCESS_KEY_ID", "MINIO_SECRET_ACCESS_KEY",
	}

	for _, envVar := range envVars {
		os.Unsetenv(envVar)
	}

	// Set minimal required values to avoid validation errors
	os.Setenv("POSTGRES_PASSWORD", "test-password")
	os.Setenv("JWT_SECRET", "test-jwt-secret")
	os.Setenv("ENCRYPTION_KEY", "test-encryption-key")
	os.Setenv("MINIO_SECRET_ACCESS_KEY", "test-minio-secret")
	defer func() {
		os.Unsetenv("POSTGRES_PASSWORD")
		os.Unsetenv("JWT_SECRET")
		os.Unsetenv("ENCRYPTION_KEY")
		os.Unsetenv("MINIO_SECRET_ACCESS_KEY")
	}()

	cfg, err := Load()
	assert.NoError(t, err)
	assert.NotNil(t, cfg)

	// Test default values
	assert.Equal(t, "0.0.0.0", cfg.Server.Host)
	assert.Equal(t, 8080, cfg.Server.Port)
	assert.Equal(t, 30*time.Second, cfg.Server.ReadTimeout)
	assert.Equal(t, 30*time.Second, cfg.Server.WriteTimeout)

	assert.Equal(t, "localhost", cfg.Database.PostgreSQL.Host)
	assert.Equal(t, 5432, cfg.Database.PostgreSQL.Port)
	assert.Equal(t, "typosentinel", cfg.Database.PostgreSQL.Database)
	assert.Equal(t, "admin", cfg.Database.PostgreSQL.Username)

	assert.Equal(t, "localhost:6379", cfg.Redis.Address)
	assert.Equal(t, 0, cfg.Redis.DB)

	assert.True(t, cfg.ML.Enabled)
	assert.Equal(t, "./models", cfg.ML.ModelPath)
	assert.Equal(t, 32, cfg.ML.BatchSize)

	assert.Equal(t, 24*time.Hour, cfg.Security.JWT.Expiration)

	assert.Equal(t, "localhost:9000", cfg.Storage.MinIO.Endpoint)
	assert.Equal(t, "admin", cfg.Storage.MinIO.AccessKeyID)
	assert.False(t, cfg.Storage.MinIO.UseSSL)

	assert.True(t, cfg.Storage.Local.Enabled)
	assert.Equal(t, "./storage", cfg.Storage.Local.BasePath)

	assert.True(t, cfg.Monitoring.Prometheus.Enabled)
	assert.Equal(t, 9090, cfg.Monitoring.Prometheus.Port)
	assert.Equal(t, "/metrics", cfg.Monitoring.Prometheus.Path)

	assert.False(t, cfg.Monitoring.Jaeger.Enabled)
	assert.Equal(t, "http://localhost:14268/api/traces", cfg.Monitoring.Jaeger.Endpoint)

	assert.Equal(t, "info", cfg.Monitoring.Logging.Level)
	assert.Equal(t, "json", cfg.Monitoring.Logging.Format)
	assert.Equal(t, "stdout", cfg.Monitoring.Logging.Output)

	assert.True(t, cfg.Monitoring.HealthCheck.Enabled)
	assert.Equal(t, 30*time.Second, cfg.Monitoring.HealthCheck.Interval)
	assert.Equal(t, 5*time.Second, cfg.Monitoring.HealthCheck.Timeout)
	assert.Equal(t, "/health", cfg.Monitoring.HealthCheck.Endpoint)

	assert.True(t, cfg.WebSocket.Enabled)
	assert.Equal(t, 1024, cfg.WebSocket.ReadBufferSize)
	assert.Equal(t, 1024, cfg.WebSocket.WriteBufferSize)
	assert.Equal(t, 54*time.Second, cfg.WebSocket.PingPeriod)
	assert.Equal(t, 60*time.Second, cfg.WebSocket.PongWait)
	assert.Equal(t, 10*time.Second, cfg.WebSocket.WriteWait)
	assert.Equal(t, int64(512), cfg.WebSocket.MaxMessageSize)
	assert.False(t, cfg.WebSocket.Compression)
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name        string
		config      *Config
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid config",
			config: &Config{
				Database: DatabaseConfig{
					PostgreSQL: PostgreSQLConfig{
						Password: "validpassword",
					},
				},
				Security: SecurityConfig{
					JWT: JWTConfig{
						Secret: "valid-jwt-secret",
					},
					Encryption: EncryptionConfig{
						Key: "valid-encryption-key",
					},
				},
				Storage: StorageConfig{
					MinIO: MinIOConfig{
						SecretAccessKey: "valid-secret",
					},
				},
			},
			expectError: false,
		},
		{
			name: "missing postgres password",
			config: &Config{
				Database: DatabaseConfig{
					PostgreSQL: PostgreSQLConfig{
						Password: "",
					},
				},
				Security: SecurityConfig{
					JWT:        JWTConfig{Secret: "valid-secret"},
					Encryption: EncryptionConfig{Key: "valid-key"},
				},
				Storage: StorageConfig{
					MinIO: MinIOConfig{SecretAccessKey: "valid-secret"},
				},
			},
			expectError: true,
			errorMsg:    "PostgreSQL password is required",
		},
		{
			name: "missing jwt secret",
			config: &Config{
				Database: DatabaseConfig{
					PostgreSQL: PostgreSQLConfig{Password: "valid-password"},
				},
				Security: SecurityConfig{
					JWT:        JWTConfig{Secret: ""},
					Encryption: EncryptionConfig{Key: "valid-key"},
				},
				Storage: StorageConfig{
					MinIO: MinIOConfig{SecretAccessKey: "valid-secret"},
				},
			},
			expectError: true,
			errorMsg:    "JWT secret must be set and not use default value",
		},
		{
			name: "default jwt secret",
			config: &Config{
				Database: DatabaseConfig{
					PostgreSQL: PostgreSQLConfig{Password: "valid-password"},
				},
				Security: SecurityConfig{
					JWT:        JWTConfig{Secret: "your-secret-key"},
					Encryption: EncryptionConfig{Key: "valid-key"},
				},
				Storage: StorageConfig{
					MinIO: MinIOConfig{SecretAccessKey: "valid-secret"},
				},
			},
			expectError: true,
			errorMsg:    "JWT secret must be set and not use default value",
		},
		{
			name: "missing encryption key",
			config: &Config{
				Database: DatabaseConfig{
					PostgreSQL: PostgreSQLConfig{Password: "valid-password"},
				},
				Security: SecurityConfig{
					JWT:        JWTConfig{Secret: "valid-secret"},
					Encryption: EncryptionConfig{Key: ""},
				},
				Storage: StorageConfig{
					MinIO: MinIOConfig{SecretAccessKey: "valid-secret"},
				},
			},
			expectError: true,
			errorMsg:    "encryption key is required",
		},
		{
			name: "missing minio secret",
			config: &Config{
				Database: DatabaseConfig{
					PostgreSQL: PostgreSQLConfig{Password: "valid-password"},
				},
				Security: SecurityConfig{
					JWT:        JWTConfig{Secret: "valid-secret"},
					Encryption: EncryptionConfig{Key: "valid-key"},
				},
				Storage: StorageConfig{
					MinIO: MinIOConfig{SecretAccessKey: ""},
				},
			},
			expectError: true,
			errorMsg:    "MinIO secret access key is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
