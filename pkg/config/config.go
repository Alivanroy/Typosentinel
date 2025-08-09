package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

// Config holds all configuration for the Typosentinel application
type Config struct {
	Environment string           `json:"environment"`
	Version     string           `json:"version"`
	LogLevel    string           `json:"log_level"`
	Server      ServerConfig     `json:"server"`
	Database    DatabaseConfig   `json:"database"`
	Redis       RedisConfig      `json:"redis"`
	Queue       QueueConfig      `json:"queue"`
	Batch       BatchConfig      `json:"batch"`
	ML          MLConfig         `json:"ml"`
	Security    SecurityConfig   `json:"security"`
	Monitoring  MonitoringConfig `json:"monitoring"`
	Storage     StorageConfig    `json:"storage"`
	WebSocket   WebSocketConfig  `json:"websocket"`
	RateLimit   RateLimitConfig  `json:"rate_limit"`
}

// ServerConfig holds HTTP server configuration
type ServerConfig struct {
	Port         int           `json:"port"`
	Host         string        `json:"host"`
	ReadTimeout  time.Duration `json:"read_timeout"`
	WriteTimeout time.Duration `json:"write_timeout"`
	IdleTimeout  time.Duration `json:"idle_timeout"`
	TLS          TLSConfig     `json:"tls"`
	CORS         CORSConfig    `json:"cors"`
}

// TLSConfig holds TLS configuration
type TLSConfig struct {
	Enabled  bool   `json:"enabled"`
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`
}

// CORSConfig holds CORS configuration
type CORSConfig struct {
	AllowedOrigins []string `json:"allowed_origins"`
	AllowedMethods []string `json:"allowed_methods"`
	AllowedHeaders []string `json:"allowed_headers"`
}

// DatabaseConfig holds database configuration
type DatabaseConfig struct {
	PostgreSQL PostgreSQLConfig `json:"postgresql"`
	ClickHouse ClickHouseConfig `json:"clickhouse"`
	Migrations MigrationsConfig `json:"migrations"`
}

// PostgreSQLConfig holds PostgreSQL configuration
type PostgreSQLConfig struct {
	Host            string          `json:"host"`
	Port            int             `json:"port"`
	Database        string          `json:"database"`
	Username        string          `json:"username"`
	Password        string          `json:"password"`
	SSLMode         string          `json:"ssl_mode"`
	MaxOpenConns    int             `json:"max_open_conns"`
	MaxIdleConns    int             `json:"max_idle_conns"`
	ConnMaxLifetime time.Duration   `json:"conn_max_lifetime"`
	ConnMaxIdleTime time.Duration   `json:"conn_max_idle_time"`
	Replicas        []ReplicaConfig `json:"replicas"`
}

// ReplicaConfig holds database replica configuration
type ReplicaConfig struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Weight   int    `json:"weight"`
	ReadOnly bool   `json:"read_only"`
}

// ClickHouseConfig holds ClickHouse configuration
type ClickHouseConfig struct {
	Host            string        `json:"host"`
	Port            int           `json:"port"`
	Database        string        `json:"database"`
	Username        string        `json:"username"`
	Password        string        `json:"password"`
	MaxOpenConns    int           `json:"max_open_conns"`
	MaxIdleConns    int           `json:"max_idle_conns"`
	ConnMaxLifetime time.Duration `json:"conn_max_lifetime"`
	Cluster         string        `json:"cluster"`
}

// MigrationsConfig holds database migrations configuration
type MigrationsConfig struct {
	Enabled   bool   `json:"enabled"`
	Directory string `json:"directory"`
	Table     string `json:"table"`
}

// RedisConfig holds Redis configuration
type RedisConfig struct {
	Address      string              `json:"address"`
	Password     string              `json:"password"`
	DB           int                 `json:"db"`
	PoolSize     int                 `json:"pool_size"`
	MinIdleConns int                 `json:"min_idle_conns"`
	DialTimeout  time.Duration       `json:"dial_timeout"`
	ReadTimeout  time.Duration       `json:"read_timeout"`
	WriteTimeout time.Duration       `json:"write_timeout"`
	IdleTimeout  time.Duration       `json:"idle_timeout"`
	Cluster      RedisClusterConfig  `json:"cluster"`
	Sentinel     RedisSentinelConfig `json:"sentinel"`
}

// RedisClusterConfig holds Redis cluster configuration
type RedisClusterConfig struct {
	Enabled   bool     `json:"enabled"`
	Addresses []string `json:"addresses"`
}

// RedisSentinelConfig holds Redis Sentinel configuration
type RedisSentinelConfig struct {
	Enabled    bool     `json:"enabled"`
	MasterName string   `json:"master_name"`
	Sentinels  []string `json:"sentinels"`
	Password   string   `json:"password"`
}

// QueueConfig holds queue configuration
type QueueConfig struct {
	Workers           int           `json:"workers"`
	MaxRetries        int           `json:"max_retries"`
	RetryDelay        time.Duration `json:"retry_delay"`
	VisibilityTimeout time.Duration `json:"visibility_timeout"`
	PollInterval      time.Duration `json:"poll_interval"`
	Priorities        []string      `json:"priorities"`
	DeadLetterQueue   bool          `json:"dead_letter_queue"`
}

// BatchConfig holds batch processing configuration
type BatchConfig struct {
	Concurrency       int           `json:"concurrency"`
	BatchSize         int           `json:"batch_size"`
	MaxBatchSize      int           `json:"max_batch_size"`
	ProcessingTimeout time.Duration `json:"processing_timeout"`
	RetentionPeriod   time.Duration `json:"retention_period"`
}

// MLConfig holds machine learning configuration
type MLConfig struct {
	Enabled            bool                     `json:"enabled"`
	ModelPath          string                   `json:"model_path"`
	PredictionTimeout  time.Duration            `json:"prediction_timeout"`
	BatchPrediction    bool                     `json:"batch_prediction"`
	BatchSize          int                      `json:"batch_size"`
	ContinuousLearning ContinuousLearningConfig `json:"continuous_learning"`
	Models             map[string]ModelConfig   `json:"models"`
}

// ContinuousLearningConfig holds continuous learning configuration
type ContinuousLearningConfig struct {
	Enabled              bool          `json:"enabled"`
	RetrainingInterval   time.Duration `json:"retraining_interval"`
	MinFeedbackCount     int           `json:"min_feedback_count"`
	ValidationSplit      float64       `json:"validation_split"`
	PerformanceThreshold float64       `json:"performance_threshold"`
}

// ModelConfig holds individual model configuration
type ModelConfig struct {
	Enabled     bool    `json:"enabled"`
	Version     string  `json:"version"`
	Weight      float64 `json:"weight"`
	Threshold   float64 `json:"threshold"`
	MaxFeatures int     `json:"max_features"`
}

// SecurityConfig holds security configuration
type SecurityConfig struct {
	JWT             JWTConfig             `json:"jwt"`
	RateLimit       RateLimitConfig       `json:"rate_limit"`
	Encryption      EncryptionConfig      `json:"encryption"`
	AuditLog        AuditLogConfig        `json:"audit_log"`
	ThreatDetection ThreatDetectionConfig `json:"threat_detection"`
}

// JWTConfig holds JWT configuration
type JWTConfig struct {
	Secret            string        `json:"secret"`
	Expiration        time.Duration `json:"expiration"`
	RefreshExpiration time.Duration `json:"refresh_expiration"`
	Issuer            string        `json:"issuer"`
	Audience          string        `json:"audience"`
}

// EncryptionConfig holds encryption configuration
type EncryptionConfig struct {
	Key         string                      `json:"key"`
	Algorithm   string                      `json:"algorithm"`
	KeyRotation EncryptionKeyRotationConfig `json:"key_rotation"`
}

// EncryptionKeyRotationConfig holds key rotation configuration
type EncryptionKeyRotationConfig struct {
	Enabled  bool          `json:"enabled"`
	Interval time.Duration `json:"interval"`
}

// AuditLogConfig holds audit log configuration
type AuditLogConfig struct {
	Enabled     bool          `json:"enabled"`
	Destination string        `json:"destination"`
	Format      string        `json:"format"`
	Retention   time.Duration `json:"retention"`
}

// ThreatDetectionConfig holds threat detection configuration
type ThreatDetectionConfig struct {
	Enabled            bool          `json:"enabled"`
	RealTimeScanning   bool          `json:"real_time_scanning"`
	ScanTimeout        time.Duration `json:"scan_timeout"`
	MaxConcurrentScans int           `json:"max_concurrent_scans"`
	QuarantineEnabled  bool          `json:"quarantine_enabled"`
}

// RateLimitConfig holds rate limiting configuration
type RateLimitConfig struct {
	Enabled           bool                     `json:"enabled"`
	RequestsPerMinute int                      `json:"requests_per_minute"`
	BurstSize         int                      `json:"burst_size"`
	WindowSize        time.Duration            `json:"window_size"`
	CleanupInterval   time.Duration            `json:"cleanup_interval"`
	Tiers             map[string]RateLimitTier `json:"tiers"`
}

// RateLimitTier holds rate limit tier configuration
type RateLimitTier struct {
	RequestsPerMinute int `json:"requests_per_minute"`
	RequestsPerHour   int `json:"requests_per_hour"`
	RequestsPerDay    int `json:"requests_per_day"`
	BurstSize         int `json:"burst_size"`
}

// MonitoringConfig holds monitoring configuration
type MonitoringConfig struct {
	Enabled     bool              `json:"enabled"`
	Prometheus  PrometheusConfig  `json:"prometheus"`
	Jaeger      JaegerConfig      `json:"jaeger"`
	Logging     LoggingConfig     `json:"logging"`
	HealthCheck HealthCheckConfig `json:"health_check"`
}

// PrometheusConfig holds Prometheus configuration
type PrometheusConfig struct {
	Enabled   bool   `json:"enabled"`
	Port      int    `json:"port"`
	Path      string `json:"path"`
	Namespace string `json:"namespace"`
	Subsystem string `json:"subsystem"`
}

// JaegerConfig holds Jaeger configuration
type JaegerConfig struct {
	Enabled     bool    `json:"enabled"`
	Endpoint    string  `json:"endpoint"`
	ServiceName string  `json:"service_name"`
	SampleRate  float64 `json:"sample_rate"`
}

// LoggingConfig holds logging configuration
type LoggingConfig struct {
	Level      string            `json:"level"`
	Format     string            `json:"format"`
	Output     string            `json:"output"`
	Rotation   LogRotationConfig `json:"rotation"`
	Structured bool              `json:"structured"`
}

// LogRotationConfig holds log rotation configuration
type LogRotationConfig struct {
	Enabled    bool `json:"enabled"`
	MaxSize    int  `json:"max_size"`
	MaxAge     int  `json:"max_age"`
	MaxBackups int  `json:"max_backups"`
	Compress   bool `json:"compress"`
}

// HealthCheckConfig holds health check configuration
type HealthCheckConfig struct {
	Enabled  bool          `json:"enabled"`
	Interval time.Duration `json:"interval"`
	Timeout  time.Duration `json:"timeout"`
	Endpoint string        `json:"endpoint"`
}

// StorageConfig holds storage configuration
type StorageConfig struct {
	MinIO MinIOConfig        `json:"minio"`
	Local LocalStorageConfig `json:"local"`
}

// MinIOConfig holds MinIO configuration
type MinIOConfig struct {
	Endpoint        string `json:"endpoint"`
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	UseSSL          bool   `json:"use_ssl"`
	BucketName      string `json:"bucket_name"`
	Region          string `json:"region"`
}

// LocalStorageConfig holds local storage configuration
type LocalStorageConfig struct {
	Enabled   bool          `json:"enabled"`
	BasePath  string        `json:"base_path"`
	MaxSize   int64         `json:"max_size"`
	Retention time.Duration `json:"retention"`
}

// WebSocketConfig holds WebSocket configuration
type WebSocketConfig struct {
	Enabled         bool          `json:"enabled"`
	ReadBufferSize  int           `json:"read_buffer_size"`
	WriteBufferSize int           `json:"write_buffer_size"`
	PingPeriod      time.Duration `json:"ping_period"`
	PongWait        time.Duration `json:"pong_wait"`
	WriteWait       time.Duration `json:"write_wait"`
	MaxMessageSize  int64         `json:"max_message_size"`
	Compression     bool          `json:"compression"`
}

// Load loads configuration from environment variables and .env file
func Load() (*Config, error) {
	// Load .env file if it exists
	if err := godotenv.Load(); err != nil {
		// .env file is optional, so we don't return an error
	}

	config := &Config{
		Environment: getEnv("ENVIRONMENT", "development"),
		Version:     getEnv("VERSION", "1.1.0"),
		LogLevel:    getEnv("LOG_LEVEL", "info"),
	}

	// Load server configuration
	config.Server = ServerConfig{
		Port:         getEnvAsInt("SERVER_PORT", 8080),
		Host:         getEnv("SERVER_HOST", "0.0.0.0"),
		ReadTimeout:  getEnvAsDuration("SERVER_READ_TIMEOUT", 30*time.Second),
		WriteTimeout: getEnvAsDuration("SERVER_WRITE_TIMEOUT", 30*time.Second),
		IdleTimeout:  getEnvAsDuration("SERVER_IDLE_TIMEOUT", 120*time.Second),
		TLS: TLSConfig{
			Enabled:  getEnvAsBool("TLS_ENABLED", false),
			CertFile: getEnv("TLS_CERT_FILE", ""),
			KeyFile:  getEnv("TLS_KEY_FILE", ""),
		},
		CORS: CORSConfig{
			AllowedOrigins: getEnvAsSlice("CORS_ALLOWED_ORIGINS", []string{"*"}),
			AllowedMethods: getEnvAsSlice("CORS_ALLOWED_METHODS", []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}),
			AllowedHeaders: getEnvAsSlice("CORS_ALLOWED_HEADERS", []string{"Origin", "Content-Type", "Authorization"}),
		},
	}

	// Load database configuration
	config.Database = DatabaseConfig{
		PostgreSQL: PostgreSQLConfig{
			Host:            getEnv("POSTGRES_HOST", "localhost"),
			Port:            getEnvAsInt("POSTGRES_PORT", 5432),
			Database:        getEnv("POSTGRES_DB", "typosentinel"),
			Username:        getEnv("POSTGRES_USER", "admin"),
			Password:        getEnv("POSTGRES_PASSWORD", ""),
			SSLMode:         getEnv("POSTGRES_SSL_MODE", "disable"),
			MaxOpenConns:    getEnvAsInt("POSTGRES_MAX_OPEN_CONNS", 25),
			MaxIdleConns:    getEnvAsInt("POSTGRES_MAX_IDLE_CONNS", 5),
			ConnMaxLifetime: getEnvAsDuration("POSTGRES_CONN_MAX_LIFETIME", 5*time.Minute),
			ConnMaxIdleTime: getEnvAsDuration("POSTGRES_CONN_MAX_IDLE_TIME", 5*time.Minute),
		},
		ClickHouse: ClickHouseConfig{
			Host:            getEnv("CLICKHOUSE_HOST", "localhost"),
			Port:            getEnvAsInt("CLICKHOUSE_PORT", 9000),
			Database:        getEnv("CLICKHOUSE_DB", "typosentinel_analytics"),
			Username:        getEnv("CLICKHOUSE_USER", "default"),
			Password:        getEnv("CLICKHOUSE_PASSWORD", ""),
			MaxOpenConns:    getEnvAsInt("CLICKHOUSE_MAX_OPEN_CONNS", 10),
			MaxIdleConns:    getEnvAsInt("CLICKHOUSE_MAX_IDLE_CONNS", 2),
			ConnMaxLifetime: getEnvAsDuration("CLICKHOUSE_CONN_MAX_LIFETIME", 5*time.Minute),
			Cluster:         getEnv("CLICKHOUSE_CLUSTER", ""),
		},
		Migrations: MigrationsConfig{
			Enabled:   getEnvAsBool("MIGRATIONS_ENABLED", true),
			Directory: getEnv("MIGRATIONS_DIRECTORY", "./migrations"),
			Table:     getEnv("MIGRATIONS_TABLE", "schema_migrations"),
		},
	}

	// Load Redis configuration
	config.Redis = RedisConfig{
		Address:      getEnv("REDIS_ADDRESS", "localhost:6379"),
		Password:     getEnv("REDIS_PASSWORD", ""),
		DB:           getEnvAsInt("REDIS_DB", 0),
		PoolSize:     getEnvAsInt("REDIS_POOL_SIZE", 10),
		MinIdleConns: getEnvAsInt("REDIS_MIN_IDLE_CONNS", 2),
		DialTimeout:  getEnvAsDuration("REDIS_DIAL_TIMEOUT", 5*time.Second),
		ReadTimeout:  getEnvAsDuration("REDIS_READ_TIMEOUT", 3*time.Second),
		WriteTimeout: getEnvAsDuration("REDIS_WRITE_TIMEOUT", 3*time.Second),
		IdleTimeout:  getEnvAsDuration("REDIS_IDLE_TIMEOUT", 5*time.Minute),
		Cluster: RedisClusterConfig{
			Enabled:   getEnvAsBool("REDIS_CLUSTER_ENABLED", false),
			Addresses: getEnvAsSlice("REDIS_CLUSTER_ADDRESSES", []string{}),
		},
	}

	// Load queue configuration
	config.Queue = QueueConfig{
		Workers:           getEnvAsInt("QUEUE_WORKERS", 5),
		MaxRetries:        getEnvAsInt("QUEUE_MAX_RETRIES", 3),
		RetryDelay:        getEnvAsDuration("QUEUE_RETRY_DELAY", 30*time.Second),
		VisibilityTimeout: getEnvAsDuration("QUEUE_VISIBILITY_TIMEOUT", 5*time.Minute),
		PollInterval:      getEnvAsDuration("QUEUE_POLL_INTERVAL", 1*time.Second),
		Priorities:        getEnvAsSlice("QUEUE_PRIORITIES", []string{"critical", "high", "normal", "low"}),
		DeadLetterQueue:   getEnvAsBool("QUEUE_DEAD_LETTER_ENABLED", true),
	}

	// Load batch configuration
	config.Batch = BatchConfig{
		Concurrency:       getEnvAsInt("BATCH_CONCURRENCY", 10),
		BatchSize:         getEnvAsInt("BATCH_SIZE", 100),
		MaxBatchSize:      getEnvAsInt("BATCH_MAX_SIZE", 1000),
		ProcessingTimeout: getEnvAsDuration("BATCH_PROCESSING_TIMEOUT", 30*time.Minute),
		RetentionPeriod:   getEnvAsDuration("BATCH_RETENTION_PERIOD", 7*24*time.Hour),
	}

	// Load ML configuration
	config.ML = MLConfig{
		Enabled:           getEnvAsBool("ML_ENABLED", true),
		ModelPath:         getEnv("ML_MODEL_PATH", "./models"),
		PredictionTimeout: getEnvAsDuration("ML_PREDICTION_TIMEOUT", 30*time.Second),
		BatchPrediction:   getEnvAsBool("ML_BATCH_PREDICTION", true),
		BatchSize:         getEnvAsInt("ML_BATCH_SIZE", 32),
		ContinuousLearning: ContinuousLearningConfig{
			Enabled:              getEnvAsBool("ML_CONTINUOUS_LEARNING_ENABLED", true),
			RetrainingInterval:   getEnvAsDuration("ML_RETRAINING_INTERVAL", 24*time.Hour),
			MinFeedbackCount:     getEnvAsInt("ML_MIN_FEEDBACK_COUNT", 100),
			ValidationSplit:      getEnvAsFloat("ML_VALIDATION_SPLIT", 0.2),
			PerformanceThreshold: getEnvAsFloat("ML_PERFORMANCE_THRESHOLD", 0.85),
		},
	}

	// Load security configuration
	config.Security = SecurityConfig{
		JWT: JWTConfig{
			Secret:            getEnv("JWT_SECRET", "your-secret-key"),
			Expiration:        getEnvAsDuration("JWT_EXPIRATION", 24*time.Hour),
			RefreshExpiration: getEnvAsDuration("JWT_REFRESH_EXPIRATION", 7*24*time.Hour),
			Issuer:            getEnv("JWT_ISSUER", "typosentinel"),
			Audience:          getEnv("JWT_AUDIENCE", "typosentinel-api"),
		},
		Encryption: EncryptionConfig{
			Key:       getEnv("ENCRYPTION_KEY", ""),
			Algorithm: getEnv("ENCRYPTION_ALGORITHM", "AES-256-GCM"),
			KeyRotation: EncryptionKeyRotationConfig{
				Enabled:  getEnvAsBool("ENCRYPTION_KEY_ROTATION_ENABLED", false),
				Interval: getEnvAsDuration("ENCRYPTION_KEY_ROTATION_INTERVAL", 30*24*time.Hour),
			},
		},
		AuditLog: AuditLogConfig{
			Enabled:     getEnvAsBool("AUDIT_LOG_ENABLED", true),
			Destination: getEnv("AUDIT_LOG_DESTINATION", "file"),
			Format:      getEnv("AUDIT_LOG_FORMAT", "json"),
			Retention:   getEnvAsDuration("AUDIT_LOG_RETENTION", 90*24*time.Hour),
		},
		ThreatDetection: ThreatDetectionConfig{
			Enabled:            getEnvAsBool("THREAT_DETECTION_ENABLED", true),
			RealTimeScanning:   getEnvAsBool("THREAT_DETECTION_REAL_TIME", true),
			ScanTimeout:        getEnvAsDuration("THREAT_DETECTION_SCAN_TIMEOUT", 5*time.Minute),
			MaxConcurrentScans: getEnvAsInt("THREAT_DETECTION_MAX_CONCURRENT", 10),
			QuarantineEnabled:  getEnvAsBool("THREAT_DETECTION_QUARANTINE", true),
		},
	}

	// Load rate limit configuration
	config.RateLimit = RateLimitConfig{
		Enabled:           getEnvAsBool("RATE_LIMIT_ENABLED", true),
		RequestsPerMinute: getEnvAsInt("RATE_LIMIT_REQUESTS_PER_MINUTE", 60),
		BurstSize:         getEnvAsInt("RATE_LIMIT_BURST_SIZE", 10),
		WindowSize:        getEnvAsDuration("RATE_LIMIT_WINDOW_SIZE", 1*time.Minute),
		CleanupInterval:   getEnvAsDuration("RATE_LIMIT_CLEANUP_INTERVAL", 5*time.Minute),
	}

	// Load monitoring configuration
	config.Monitoring = MonitoringConfig{
		Enabled: getEnvAsBool("MONITORING_ENABLED", true),
		Prometheus: PrometheusConfig{
			Enabled:   getEnvAsBool("PROMETHEUS_ENABLED", true),
			Port:      getEnvAsInt("PROMETHEUS_PORT", 9090),
			Path:      getEnv("PROMETHEUS_PATH", "/metrics"),
			Namespace: getEnv("PROMETHEUS_NAMESPACE", "typosentinel"),
			Subsystem: getEnv("PROMETHEUS_SUBSYSTEM", ""),
		},
		Jaeger: JaegerConfig{
			Enabled:     getEnvAsBool("JAEGER_ENABLED", false),
			Endpoint:    getEnv("JAEGER_ENDPOINT", "http://localhost:14268/api/traces"),
			ServiceName: getEnv("JAEGER_SERVICE_NAME", "typosentinel"),
			SampleRate:  getEnvAsFloat("JAEGER_SAMPLE_RATE", 0.1),
		},
		Logging: LoggingConfig{
			Level:      getEnv("LOG_LEVEL", "info"),
			Format:     getEnv("LOG_FORMAT", "json"),
			Output:     getEnv("LOG_OUTPUT", "stdout"),
			Structured: getEnvAsBool("LOG_STRUCTURED", true),
			Rotation: LogRotationConfig{
				Enabled:    getEnvAsBool("LOG_ROTATION_ENABLED", false),
				MaxSize:    getEnvAsInt("LOG_ROTATION_MAX_SIZE", 100),
				MaxAge:     getEnvAsInt("LOG_ROTATION_MAX_AGE", 7),
				MaxBackups: getEnvAsInt("LOG_ROTATION_MAX_BACKUPS", 3),
				Compress:   getEnvAsBool("LOG_ROTATION_COMPRESS", true),
			},
		},
		HealthCheck: HealthCheckConfig{
			Enabled:  getEnvAsBool("HEALTH_CHECK_ENABLED", true),
			Interval: getEnvAsDuration("HEALTH_CHECK_INTERVAL", 30*time.Second),
			Timeout:  getEnvAsDuration("HEALTH_CHECK_TIMEOUT", 5*time.Second),
			Endpoint: getEnv("HEALTH_CHECK_ENDPOINT", "/health"),
		},
	}

	// Load storage configuration
	config.Storage = StorageConfig{
		MinIO: MinIOConfig{
			Endpoint:        getEnv("MINIO_ENDPOINT", "localhost:9000"),
			AccessKeyID:     getEnv("MINIO_ACCESS_KEY_ID", "admin"),
			SecretAccessKey: getEnv("MINIO_SECRET_ACCESS_KEY", ""),
			UseSSL:          getEnvAsBool("MINIO_USE_SSL", false),
			BucketName:      getEnv("MINIO_BUCKET_NAME", "typosentinel"),
			Region:          getEnv("MINIO_REGION", "us-east-1"),
		},
		Local: LocalStorageConfig{
			Enabled:   getEnvAsBool("LOCAL_STORAGE_ENABLED", true),
			BasePath:  getEnv("LOCAL_STORAGE_BASE_PATH", "./storage"),
			MaxSize:   getEnvAsInt64("LOCAL_STORAGE_MAX_SIZE", 10*1024*1024*1024), // 10GB
			Retention: getEnvAsDuration("LOCAL_STORAGE_RETENTION", 30*24*time.Hour),
		},
	}

	// Load WebSocket configuration
	config.WebSocket = WebSocketConfig{
		Enabled:         getEnvAsBool("WEBSOCKET_ENABLED", true),
		ReadBufferSize:  getEnvAsInt("WEBSOCKET_READ_BUFFER_SIZE", 1024),
		WriteBufferSize: getEnvAsInt("WEBSOCKET_WRITE_BUFFER_SIZE", 1024),
		PingPeriod:      getEnvAsDuration("WEBSOCKET_PING_PERIOD", 54*time.Second),
		PongWait:        getEnvAsDuration("WEBSOCKET_PONG_WAIT", 60*time.Second),
		WriteWait:       getEnvAsDuration("WEBSOCKET_WRITE_WAIT", 10*time.Second),
		MaxMessageSize:  getEnvAsInt64("WEBSOCKET_MAX_MESSAGE_SIZE", 512),
		Compression:     getEnvAsBool("WEBSOCKET_COMPRESSION", false),
	}

	return config, nil
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.Database.PostgreSQL.Password == "" {
		return fmt.Errorf("PostgreSQL password is required")
	}

	if c.Security.JWT.Secret == "" || c.Security.JWT.Secret == "your-secret-key" {
		return fmt.Errorf("JWT secret must be set and not use default value")
	}

	if c.Security.Encryption.Key == "" {
		return fmt.Errorf("encryption key is required")
	}

	if c.Storage.MinIO.SecretAccessKey == "" {
		return fmt.Errorf("MinIO secret access key is required")
	}

	return nil
}

// Helper functions for environment variable parsing
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvAsInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getEnvAsInt64(key string, defaultValue int64) int64 {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.ParseInt(value, 10, 64); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getEnvAsFloat(key string, defaultValue float64) float64 {
	if value := os.Getenv(key); value != "" {
		if floatValue, err := strconv.ParseFloat(value, 64); err == nil {
			return floatValue
		}
	}
	return defaultValue
}

func getEnvAsBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
}

func getEnvAsDuration(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
	}
	return defaultValue
}

func getEnvAsSlice(key string, defaultValue []string) []string {
	if value := os.Getenv(key); value != "" {
		return strings.Split(value, ",")
	}
	return defaultValue
}
