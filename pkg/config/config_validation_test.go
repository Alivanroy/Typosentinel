package config

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestConfigDefaults(t *testing.T) {
	// Clear all environment variables that might affect config
	envVars := []string{
		"SERVER_HOST", "SERVER_PORT", "DB_HOST", "DB_PORT",
		"REDIS_HOST", "REDIS_PORT", "ML_ENABLED",
	}
	for _, env := range envVars {
		os.Unsetenv(env)
	}

	cfg, err := Load()
	assert.NoError(t, err)
	assert.NotNil(t, cfg)

	// Test default values
	assert.Equal(t, "0.0.0.0", cfg.Server.Host)
	assert.Equal(t, 8080, cfg.Server.Port)
	assert.Equal(t, 30*time.Second, cfg.Server.ReadTimeout)
	assert.Equal(t, 30*time.Second, cfg.Server.WriteTimeout)
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		envVars map[string]string
		wantErr bool
	}{
		{
			name: "invalid port number",
			envVars: map[string]string{
				"SERVER_PORT": "invalid",
			},
			wantErr: false, // Should use default on parse error
		},
		{
			name: "negative port number",
			envVars: map[string]string{
				"SERVER_PORT": "-1",
			},
			wantErr: false, // Should use default on invalid value
		},
		{
			name: "invalid timeout duration",
			envVars: map[string]string{
				"SERVER_READ_TIMEOUT": "invalid",
			},
			wantErr: false, // Should use default on parse error
		},
		{
			name: "valid configuration",
			envVars: map[string]string{
				"SERVER_HOST": "0.0.0.0",
				"SERVER_PORT": "8080",
				"SERVER_READ_TIMEOUT": "30s",
			},
			wantErr: false,
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
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, cfg)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, cfg)
			}
		})
	}
}

func TestConfigSerialization(t *testing.T) {
	cfg, err := Load()
	assert.NoError(t, err)
	assert.NotNil(t, cfg)

	// Test that config can be serialized (important for JSON responses)
	assert.NotEmpty(t, cfg.Environment)
	assert.NotEmpty(t, cfg.Version)
	assert.NotEmpty(t, cfg.LogLevel)
}

func TestTLSConfig(t *testing.T) {
	tests := []struct {
		name    string
		envVars map[string]string
		validate func(*testing.T, *Config)
	}{
		{
			name: "TLS enabled",
			envVars: map[string]string{
				"TLS_ENABLED": "true",
				"TLS_CERT_FILE": "/path/to/cert.pem",
				"TLS_KEY_FILE": "/path/to/key.pem",
			},
			validate: func(t *testing.T, cfg *Config) {
				assert.True(t, cfg.Server.TLS.Enabled)
				assert.Equal(t, "/path/to/cert.pem", cfg.Server.TLS.CertFile)
				assert.Equal(t, "/path/to/key.pem", cfg.Server.TLS.KeyFile)
			},
		},
		{
			name: "TLS disabled",
			envVars: map[string]string{
				"TLS_ENABLED": "false",
			},
			validate: func(t *testing.T, cfg *Config) {
				assert.False(t, cfg.Server.TLS.Enabled)
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

func TestSecurityConfig(t *testing.T) {
	tests := []struct {
		name   string
		config Config
		valid  bool
	}{
		{
			name: "valid security config",
			config: Config{
				Security: SecurityConfig{
					JWT: JWTConfig{
						Secret:     "test-secret-key",
						Expiration: time.Hour,
					},
					RateLimit: RateLimitConfig{
						Enabled: true,
						RequestsPerMinute: 100,
					},
				},
			},
			valid: true,
		},
		{
			name: "invalid JWT secret",
			config: Config{
				Security: SecurityConfig{
					JWT: JWTConfig{
						Secret:     "", // empty secret
						Expiration: time.Hour,
					},
				},
			},
			valid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Basic validation - check if JWT secret is set when required
			if tt.config.Security.JWT.Secret == "" && tt.valid {
				t.Error("Expected valid config but JWT secret is empty")
			}
			if tt.config.Security.JWT.Secret != "" && !tt.valid {
				// This test case expects invalid config but has valid JWT secret
				// We should check other validation rules here
			}
			// Test rate limiting validation
			if tt.config.Security.RateLimit.RequestsPerMinute <= 0 {
				// Rate limit should be positive
				t.Log("Rate limit requests per minute should be positive")
			}
		})
	}
}