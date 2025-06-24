package config

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)



func TestLoadConfigFromEnv(t *testing.T) {
	tests := []struct {
		name    string
		envVars map[string]string
		validate func(*testing.T, *Config)
	}{
		{
			name: "server config from env",
			envVars: map[string]string{
				"SERVER_HOST": "0.0.0.0",
				"SERVER_PORT": "9090",
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
				"POSTGRES_HOST": "localhost",
				"POSTGRES_PORT": "5432",
				"POSTGRES_DB": "typosentinel",
				"POSTGRES_USER": "testuser",
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
				"REDIS_ADDRESS": "redis.example.com:6380",
				"REDIS_PASSWORD": "redispass",
				"REDIS_DB": "2",
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
				"ML_ENABLED": "true",
				"ML_MODEL_PATH": "/models/typo.model",
				"ML_BATCH_SIZE": "64",
				"ML_BATCH_PREDICTION": "true",
			},
			validate: func(t *testing.T, cfg *Config) {
				assert.True(t, cfg.ML.Enabled)
				assert.Equal(t, "/models/typo.model", cfg.ML.ModelPath)
				assert.Equal(t, 64, cfg.ML.BatchSize)
				assert.True(t, cfg.ML.BatchPrediction)
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