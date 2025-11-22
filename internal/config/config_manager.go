package config

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	"gopkg.in/yaml.v2"

	"github.com/Alivanroy/Typosentinel/pkg/logger"
	"github.com/Alivanroy/Typosentinel/pkg/metrics"
)

// ConfigSource defines where configuration comes from
type ConfigSource int

const (
	ConfigSourceFile ConfigSource = iota
	ConfigSourceRedis
	ConfigSourceEnvironment
	ConfigSourceDefault
)

func (cs ConfigSource) String() string {
	switch cs {
	case ConfigSourceFile:
		return "file"
	case ConfigSourceRedis:
		return "redis"
	case ConfigSourceEnvironment:
		return "environment"
	case ConfigSourceDefault:
		return "default"
	default:
		return "unknown"
	}
}

// ConfigEntry represents a configuration entry
type ConfigEntry struct {
	Key         string                 `json:"key"`
	Value       interface{}            `json:"value"`
	Source      ConfigSource           `json:"source"`
	LastUpdated time.Time              `json:"last_updated"`
	Version     int64                  `json:"version"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// ConfigChangeEvent represents a configuration change
type ConfigChangeEvent struct {
	Key       string       `json:"key"`
	OldValue  interface{}  `json:"old_value"`
	NewValue  interface{}  `json:"new_value"`
	Source    ConfigSource `json:"source"`
	Timestamp time.Time    `json:"timestamp"`
	Version   int64        `json:"version"`
}

// ConfigWatcher interface for watching configuration changes
type ConfigWatcher interface {
	OnConfigChange(event ConfigChangeEvent) error
	GetWatchedKeys() []string
}

// ConfigValidator interface for validating configuration values
type ConfigValidator interface {
	Validate(key string, value interface{}) error
	GetValidatedKeys() []string
}

// ConfigManager manages application configuration
type ConfigManager struct {
	config         map[string]*ConfigEntry
	watchers       []ConfigWatcher
	validators     []ConfigValidator
	redis          *redis.Client
	metrics        *metrics.Metrics
	configFile     string
	redisKeyPrefix string
	ctx            context.Context
	cancel         context.CancelFunc
	mu             sync.RWMutex
	watchersMu     sync.RWMutex
	validatorsMu   sync.RWMutex
	version        int64
	running        bool
	changeHistory  []ConfigChangeEvent
	historyMu      sync.RWMutex
	maxHistorySize int
}

// ConfigManagerOptions holds options for creating a config manager
type ConfigManagerOptions struct {
	ConfigFile      string        `json:"config_file"`
	RedisKeyPrefix  string        `json:"redis_key_prefix"`
	WatchInterval   time.Duration `json:"watch_interval"`
	MaxHistorySize  int           `json:"max_history_size"`
	EnableRedisSync bool          `json:"enable_redis_sync"`
	EnableFileWatch bool          `json:"enable_file_watch"`
}

// ApplicationConfig represents the main application configuration
type ApplicationConfig struct {
	// Server configuration
	Server ServerConfig `yaml:"server" json:"server"`

	// Database configuration
	Database DatabaseConfig `yaml:"database" json:"database"`

	// Redis configuration
	Redis RedisConfig `yaml:"redis" json:"redis"`

	// Scanner configuration
	Scanner ScannerConfig `yaml:"scanner" json:"scanner"`

	// Queue configuration
	Queue QueueConfig `yaml:"queue" json:"queue"`

	// Worker pool configuration
	WorkerPool WorkerPoolConfig `yaml:"worker_pool" json:"worker_pool"`

	// Cache configuration
	Cache CacheConfig `yaml:"cache" json:"cache"`

	// Monitoring configuration
	Monitoring MonitoringConfig `yaml:"monitoring" json:"monitoring"`

	// Load balancer configuration
	LoadBalancer LoadBalancerConfig `yaml:"load_balancer" json:"load_balancer"`

	// Auto scaler configuration
	AutoScaler AutoScalerConfig `yaml:"auto_scaler" json:"auto_scaler"`

	// Batch processor configuration
	BatchProcessor BatchProcessorConfig `yaml:"batch_processor" json:"batch_processor"`

	// Security configuration
	Security SecurityConfig `yaml:"security" json:"security"`

	// Logging configuration
	Logging LoggingConfig `yaml:"logging" json:"logging"`
}

// ServerConfig, DatabaseConfig, and RedisConfig are defined in config.go

// MonitoringConfig holds monitoring configuration
type MonitoringConfig struct {
	Enabled  bool          `yaml:"enabled" json:"enabled"`
	Interval time.Duration `yaml:"interval" json:"interval"`
	Endpoint string        `yaml:"endpoint" json:"endpoint"`
	Timeout  time.Duration `yaml:"timeout" json:"timeout"`
	Retries  int           `yaml:"retries" json:"retries"`
	Metrics  []string      `yaml:"metrics" json:"metrics"`
}

// ScannerConfig is defined in config.go

// QueueConfig holds queue configuration
type QueueConfig struct {
	MaxRetries        int           `yaml:"max_retries" json:"max_retries"`
	RetryDelay        time.Duration `yaml:"retry_delay" json:"retry_delay"`
	VisibilityTimeout time.Duration `yaml:"visibility_timeout" json:"visibility_timeout"`
	PollInterval      time.Duration `yaml:"poll_interval" json:"poll_interval"`
	DeadLetterQueue   string        `yaml:"dead_letter_queue" json:"dead_letter_queue"`
	BatchSize         int           `yaml:"batch_size" json:"batch_size"`
}

// WorkerPoolConfig holds worker pool configuration
type WorkerPoolConfig struct {
	MinWorkers          int           `yaml:"min_workers" json:"min_workers"`
	MaxWorkers          int           `yaml:"max_workers" json:"max_workers"`
	InitialWorkers      int           `yaml:"initial_workers" json:"initial_workers"`
	TaskTimeout         time.Duration `yaml:"task_timeout" json:"task_timeout"`
	IdleTimeout         time.Duration `yaml:"idle_timeout" json:"idle_timeout"`
	HealthCheckInterval time.Duration `yaml:"health_check_interval" json:"health_check_interval"`
	MaxErrorRate        float64       `yaml:"max_error_rate" json:"max_error_rate"`
	ScaleUpThreshold    float64       `yaml:"scale_up_threshold" json:"scale_up_threshold"`
	ScaleDownThreshold  float64       `yaml:"scale_down_threshold" json:"scale_down_threshold"`
	AutoScale           bool          `yaml:"auto_scale" json:"auto_scale"`
}

// Note: CacheConfig is defined in config.go

// L1CacheConfig holds L1 cache configuration
type L1CacheConfig struct {
	MaxSize        int64         `yaml:"max_size" json:"max_size"`
	MaxEntries     int           `yaml:"max_entries" json:"max_entries"`
	TTL            time.Duration `yaml:"ttl" json:"ttl"`
	EvictionPolicy string        `yaml:"eviction_policy" json:"eviction_policy"`
}

// L2CacheConfig holds L2 cache configuration
type L2CacheConfig struct {
	KeyPrefix   string        `yaml:"key_prefix" json:"key_prefix"`
	TTL         time.Duration `yaml:"ttl" json:"ttl"`
	MaxSize     int64         `yaml:"max_size" json:"max_size"`
	Compression bool          `yaml:"compression" json:"compression"`
}

// L3CacheConfig holds L3 cache configuration
type L3CacheConfig struct {
	Enabled     bool          `yaml:"enabled" json:"enabled"`
	StoragePath string        `yaml:"storage_path" json:"storage_path"`
	TTL         time.Duration `yaml:"ttl" json:"ttl"`
	MaxSize     int64         `yaml:"max_size" json:"max_size"`
}

// MonitoringConfig is defined in enhanced.go

// LoadBalancerConfig holds load balancer configuration
type LoadBalancerConfig struct {
	Strategy            string        `yaml:"strategy" json:"strategy"`
	HealthCheckPath     string        `yaml:"health_check_path" json:"health_check_path"`
	HealthCheckInterval time.Duration `yaml:"health_check_interval" json:"health_check_interval"`
	HealthCheckTimeout  time.Duration `yaml:"health_check_timeout" json:"health_check_timeout"`
	MaxRetries          int           `yaml:"max_retries" json:"max_retries"`
	RetryDelay          time.Duration `yaml:"retry_delay" json:"retry_delay"`
}

// AutoScalerConfig holds auto scaler configuration
type AutoScalerConfig struct {
	EvaluationInterval time.Duration `yaml:"evaluation_interval" json:"evaluation_interval"`
	MaxHistorySize     int           `yaml:"max_history_size" json:"max_history_size"`
}

// BatchProcessorConfig holds batch processor configuration
type BatchProcessorConfig struct {
	MaxConcurrency int           `yaml:"max_concurrency" json:"max_concurrency"`
	BatchSize      int           `yaml:"batch_size" json:"batch_size"`
	Timeout        time.Duration `yaml:"timeout" json:"timeout"`
}

// SecurityConfig is defined in enhanced.go

// LoggingConfig is defined in enhanced.go

// NewConfigManager creates a new configuration manager
func NewConfigManager(options ConfigManagerOptions, redis *redis.Client) *ConfigManager {
	ctx, cancel := context.WithCancel(context.Background())

	// Set default values
	if options.RedisKeyPrefix == "" {
		options.RedisKeyPrefix = "typosentinel:config:"
	}
	if options.WatchInterval == 0 {
		options.WatchInterval = 30 * time.Second
	}
	if options.MaxHistorySize == 0 {
		options.MaxHistorySize = 1000
	}

	return &ConfigManager{
		config:         make(map[string]*ConfigEntry),
		watchers:       make([]ConfigWatcher, 0),
		validators:     make([]ConfigValidator, 0),
		redis:          redis,
		metrics:        metrics.GetInstance(),
		configFile:     options.ConfigFile,
		redisKeyPrefix: options.RedisKeyPrefix,
		ctx:            ctx,
		cancel:         cancel,
		version:        1,
		changeHistory:  make([]ConfigChangeEvent, 0, options.MaxHistorySize),
		maxHistorySize: options.MaxHistorySize,
	}
}

// LoadConfig loads configuration from various sources
func (cm *ConfigManager) LoadConfig() error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	// Load from file if specified
	if cm.configFile != "" {
		if err := cm.loadFromFile(); err != nil {
			logger.Error("Failed to load config from file", map[string]interface{}{
				"error": err.Error(),
			})
		}
	}

	// Load from Redis
	if cm.redis != nil {
		if err := cm.loadFromRedis(); err != nil {
			logger.Error("Failed to load config from Redis", map[string]interface{}{
				"error": err.Error(),
			})
		}
	}

	// Load from environment variables
	cm.loadFromEnvironment()

	// Set default values for missing configuration
	cm.setDefaults()

	logger.Info("Configuration loaded", map[string]interface{}{
		"entries_count": len(cm.config),
	})
	return nil
}

// loadFromFile loads configuration from a file
func (cm *ConfigManager) loadFromFile() error {
	if _, err := os.Stat(cm.configFile); os.IsNotExist(err) {
		return fmt.Errorf("config file does not exist: %s", cm.configFile)
	}

	data, err := os.ReadFile(cm.configFile)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	var appConfig ApplicationConfig
	ext := filepath.Ext(cm.configFile)

	switch ext {
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(data, &appConfig); err != nil {
			return fmt.Errorf("failed to parse YAML config: %w", err)
		}
	case ".json":
		if err := json.Unmarshal(data, &appConfig); err != nil {
			return fmt.Errorf("failed to parse JSON config: %w", err)
		}
	default:
		return fmt.Errorf("unsupported config file format: %s", ext)
	}

	// Convert struct to flat key-value pairs
	cm.flattenConfig("", reflect.ValueOf(appConfig), ConfigSourceFile)

	return nil
}

// loadFromRedis loads configuration from Redis
func (cm *ConfigManager) loadFromRedis() error {
	pattern := cm.redisKeyPrefix + "*"
	keys, err := cm.redis.Keys(cm.ctx, pattern).Result()
	if err != nil {
		return fmt.Errorf("failed to get config keys from Redis: %w", err)
	}

	for _, key := range keys {
		configKey := strings.TrimPrefix(key, cm.redisKeyPrefix)
		value, err := cm.redis.Get(cm.ctx, key).Result()
		if err != nil {
			logger.Error("Failed to get config value from Redis", map[string]interface{}{
				"key":   configKey,
				"error": err.Error(),
			})
			continue
		}

		// Try to parse as JSON first, then as string
		var parsedValue interface{}
		if err := json.Unmarshal([]byte(value), &parsedValue); err != nil {
			parsedValue = value
		}

		cm.config[configKey] = &ConfigEntry{
			Key:         configKey,
			Value:       parsedValue,
			Source:      ConfigSourceRedis,
			LastUpdated: time.Now(),
			Version:     cm.version,
			Metadata:    make(map[string]interface{}),
		}
	}

	return nil
}

// loadFromEnvironment loads configuration from environment variables
func (cm *ConfigManager) loadFromEnvironment() {
	envPrefix := "TYPOSENTINEL_"
	for _, env := range os.Environ() {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := parts[0]
		value := parts[1]

		if strings.HasPrefix(key, envPrefix) {
			configKey := strings.ToLower(strings.TrimPrefix(key, envPrefix))
			configKey = strings.ReplaceAll(configKey, "_", ".")

			// Try to parse as JSON first, then as string
			var parsedValue interface{}
			if err := json.Unmarshal([]byte(value), &parsedValue); err != nil {
				parsedValue = value
			}

			cm.config[configKey] = &ConfigEntry{
				Key:         configKey,
				Value:       parsedValue,
				Source:      ConfigSourceEnvironment,
				LastUpdated: time.Now(),
				Version:     cm.version,
				Metadata:    make(map[string]interface{}),
			}
		}
	}
}

// setDefaults sets default configuration values
func (cm *ConfigManager) setDefaults() {
	defaults := map[string]interface{}{
		"server.host":                      "0.0.0.0",
		"server.port":                      8080,
		"server.read_timeout":              "30s",
		"server.write_timeout":             "30s",
		"server.idle_timeout":              "60s",
		"database.host":                    "localhost",
		"database.port":                    5432,
		"database.ssl_mode":                "disable",
		"database.max_open_conns":          25,
		"database.max_idle_conns":          5,
		"database.conn_max_lifetime":       "5m",
		"redis.host":                       "localhost",
		"redis.port":                       6379,
		"redis.database":                   0,
		"redis.pool_size":                  10,
		"redis.min_idle_conns":             2,
		"redis.dial_timeout":               "5s",
		"redis.read_timeout":               "3s",
		"redis.write_timeout":              "3s",
		"scanner.timeout":                  "30s",
		"scanner.max_retries":              3,
		"scanner.retry_delay":              "1s",
		"scanner.concurrency":              10,
		"scanner.rate_limit_rps":           100,
		"scanner.cache_enabled":            true,
		"scanner.cache_ttl":                "1h",
		"queue.max_retries":                3,
		"queue.retry_delay":                "30s",
		"queue.visibility_timeout":         "5m",
		"queue.poll_interval":              "1s",
		"queue.batch_size":                 10,
		"worker_pool.min_workers":          1,
		"worker_pool.max_workers":          20,
		"worker_pool.initial_workers":      5,
		"worker_pool.task_timeout":         "5m",
		"worker_pool.idle_timeout":         "10m",
		"worker_pool.auto_scale":           true,
		"cache.default_ttl":                "1h",
		"cache.cleanup_interval":           "10m",
		"monitoring.health_check_interval": "30s",
		"monitoring.metrics_interval":      "10s",
		"monitoring.enable_system_metrics": true,
		"monitoring.enable_alerts":         true,
		"security.jwt_expiration":          "24h",
		"security.password_min_length":     8,
		"security.rate_limit_enabled":      true,
		"security.rate_limit_rps":          100,
		"security.cors_enabled":            true,
		"logging.level":                    "info",
		"logging.format":                   "json",
		"logging.output":                   "stdout",
	}

	for key, value := range defaults {
		if _, exists := cm.config[key]; !exists {
			cm.config[key] = &ConfigEntry{
				Key:         key,
				Value:       value,
				Source:      ConfigSourceDefault,
				LastUpdated: time.Now(),
				Version:     cm.version,
				Metadata:    make(map[string]interface{}),
			}
		}
	}
}

// flattenConfig flattens a nested struct into flat key-value pairs
func (cm *ConfigManager) flattenConfig(prefix string, v reflect.Value, source ConfigSource) {
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}

	if v.Kind() != reflect.Struct {
		return
	}

	t := v.Type()
	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		fieldType := t.Field(i)

		// Get the key from yaml or json tag
		key := fieldType.Tag.Get("yaml")
		if key == "" {
			key = fieldType.Tag.Get("json")
		}
		if key == "" {
			key = strings.ToLower(fieldType.Name)
		}

		// Remove options from tag (e.g., "omitempty")
		if idx := strings.Index(key, ","); idx != -1 {
			key = key[:idx]
		}

		fullKey := key
		if prefix != "" {
			fullKey = prefix + "." + key
		}

		if field.Kind() == reflect.Struct {
			// Recursively flatten nested structs
			cm.flattenConfig(fullKey, field, source)
		} else {
			// Store the value
			cm.config[fullKey] = &ConfigEntry{
				Key:         fullKey,
				Value:       field.Interface(),
				Source:      source,
				LastUpdated: time.Now(),
				Version:     cm.version,
				Metadata:    make(map[string]interface{}),
			}
		}
	}
}

// Get retrieves a configuration value
func (cm *ConfigManager) Get(key string) (interface{}, bool) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	entry, exists := cm.config[key]
	if !exists {
		return nil, false
	}

	return entry.Value, true
}

// GetString retrieves a string configuration value
func (cm *ConfigManager) GetString(key string) string {
	value, exists := cm.Get(key)
	if !exists {
		return ""
	}

	if str, ok := value.(string); ok {
		return str
	}

	return fmt.Sprintf("%v", value)
}

// GetInt retrieves an integer configuration value
func (cm *ConfigManager) GetInt(key string) int {
	value, exists := cm.Get(key)
	if !exists {
		return 0
	}

	switch v := value.(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	default:
		return 0
	}
}

// GetBool retrieves a boolean configuration value
func (cm *ConfigManager) GetBool(key string) bool {
	value, exists := cm.Get(key)
	if !exists {
		return false
	}

	if b, ok := value.(bool); ok {
		return b
	}

	str := strings.ToLower(fmt.Sprintf("%v", value))
	return str == "true" || str == "1" || str == "yes" || str == "on"
}

// GetDuration retrieves a duration configuration value
func (cm *ConfigManager) GetDuration(key string) time.Duration {
	value, exists := cm.Get(key)
	if !exists {
		return 0
	}

	if d, ok := value.(time.Duration); ok {
		return d
	}

	if str, ok := value.(string); ok {
		if d, err := time.ParseDuration(str); err == nil {
			return d
		}
	}

	return 0
}

// Set updates a configuration value
func (cm *ConfigManager) Set(key string, value interface{}, source ConfigSource) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	// Validate the value if validators are registered
	if err := cm.validateValue(key, value); err != nil {
		return fmt.Errorf("validation failed for key %s: %w", key, err)
	}

	oldEntry := cm.config[key]
	var oldValue interface{}
	if oldEntry != nil {
		oldValue = oldEntry.Value
	}

	// Create new entry
	cm.version++
	newEntry := &ConfigEntry{
		Key:         key,
		Value:       value,
		Source:      source,
		LastUpdated: time.Now(),
		Version:     cm.version,
		Metadata:    make(map[string]interface{}),
	}

	cm.config[key] = newEntry

	// Create change event
	event := ConfigChangeEvent{
		Key:       key,
		OldValue:  oldValue,
		NewValue:  value,
		Source:    source,
		Timestamp: time.Now(),
		Version:   cm.version,
	}

	// Record change in history
	cm.recordChange(event)

	// Notify watchers
	go cm.notifyWatchers(event)

	// Store in Redis if enabled
	if cm.redis != nil && source != ConfigSourceRedis {
		go cm.storeInRedis(key, value)
	}

	// Update metrics
	cm.metrics.ConfigUpdates().WithLabelValues(key, source.String()).Inc()

	logger.Info("Configuration updated", map[string]interface{}{
		"key":    key,
		"value":  value,
		"source": source.String(),
	})
	return nil
}

// Delete removes a configuration entry
func (cm *ConfigManager) Delete(key string) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	entry, exists := cm.config[key]
	if !exists {
		return fmt.Errorf("configuration key not found: %s", key)
	}

	delete(cm.config, key)

	// Create change event
	event := ConfigChangeEvent{
		Key:       key,
		OldValue:  entry.Value,
		NewValue:  nil,
		Source:    entry.Source,
		Timestamp: time.Now(),
		Version:   cm.version,
	}

	// Record change in history
	cm.recordChange(event)

	// Notify watchers
	go cm.notifyWatchers(event)

	// Remove from Redis
	if cm.redis != nil {
		go cm.deleteFromRedis(key)
	}

	logger.Info("Configuration deleted", map[string]interface{}{
		"key": key,
	})
	return nil
}

// AddWatcher adds a configuration watcher
func (cm *ConfigManager) AddWatcher(watcher ConfigWatcher) {
	cm.watchersMu.Lock()
	defer cm.watchersMu.Unlock()

	cm.watchers = append(cm.watchers, watcher)
	logger.Info("Added config watcher", map[string]interface{}{
		"watched_keys": watcher.GetWatchedKeys(),
	})
}

// AddValidator adds a configuration validator
func (cm *ConfigManager) AddValidator(validator ConfigValidator) {
	cm.validatorsMu.Lock()
	defer cm.validatorsMu.Unlock()

	cm.validators = append(cm.validators, validator)
	logger.Info("Added config validator", map[string]interface{}{
		"validated_keys": validator.GetValidatedKeys(),
	})
}

// GetChangeHistory returns the configuration change history
func (cm *ConfigManager) GetChangeHistory(limit int) []ConfigChangeEvent {
	cm.historyMu.RLock()
	defer cm.historyMu.RUnlock()

	if limit <= 0 || limit > len(cm.changeHistory) {
		limit = len(cm.changeHistory)
	}

	// Return the most recent changes
	start := len(cm.changeHistory) - limit
	if start < 0 {
		start = 0
	}

	history := make([]ConfigChangeEvent, limit)
	copy(history, cm.changeHistory[start:])

	return history
}

// GetAllConfig returns all configuration entries
func (cm *ConfigManager) GetAllConfig() map[string]*ConfigEntry {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	config := make(map[string]*ConfigEntry)
	for key, entry := range cm.config {
		config[key] = entry
	}

	return config
}

// validateValue validates a configuration value using registered validators
func (cm *ConfigManager) validateValue(key string, value interface{}) error {
	cm.validatorsMu.RLock()
	defer cm.validatorsMu.RUnlock()

	for _, validator := range cm.validators {
		for _, validatedKey := range validator.GetValidatedKeys() {
			if validatedKey == key || strings.HasPrefix(key, validatedKey+".") {
				if err := validator.Validate(key, value); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

// notifyWatchers notifies all watchers of a configuration change
func (cm *ConfigManager) notifyWatchers(event ConfigChangeEvent) {
	cm.watchersMu.RLock()
	defer cm.watchersMu.RUnlock()

	for _, watcher := range cm.watchers {
		for _, watchedKey := range watcher.GetWatchedKeys() {
			if watchedKey == event.Key || strings.HasPrefix(event.Key, watchedKey+".") {
				if err := watcher.OnConfigChange(event); err != nil {
					logger.Error("Config watcher error", map[string]interface{}{
						"error": err.Error(),
						"key":   event.Key,
					})
				}
				break
			}
		}
	}
}

// recordChange records a configuration change in history
func (cm *ConfigManager) recordChange(event ConfigChangeEvent) {
	cm.historyMu.Lock()
	defer cm.historyMu.Unlock()

	cm.changeHistory = append(cm.changeHistory, event)

	// Trim history if it exceeds max size
	if len(cm.changeHistory) > cm.maxHistorySize {
		cm.changeHistory = cm.changeHistory[1:]
	}
}

// storeInRedis stores a configuration value in Redis
func (cm *ConfigManager) storeInRedis(key string, value interface{}) {
	redisKey := cm.redisKeyPrefix + key
	data, err := json.Marshal(value)
	if err != nil {
		logger.Error("Failed to marshal config value for Redis", map[string]interface{}{
			"error": err.Error(),
			"key":   key,
		})
		return
	}

	if err := cm.redis.Set(cm.ctx, redisKey, data, 0).Err(); err != nil {
		logger.Error("Failed to store config in Redis", map[string]interface{}{
			"error": err.Error(),
			"key":   key,
		})
	}
}

// deleteFromRedis removes a configuration value from Redis
func (cm *ConfigManager) deleteFromRedis(key string) {
	redisKey := cm.redisKeyPrefix + key
	if err := cm.redis.Del(cm.ctx, redisKey).Err(); err != nil {
		logger.Error("Failed to delete config from Redis", map[string]interface{}{
			"error": err.Error(),
			"key":   key,
		})
	}
}

// Shutdown gracefully shuts down the configuration manager
func (cm *ConfigManager) Shutdown() error {
	logger.Info("Shutting down configuration manager")
	cm.cancel()
	logger.Info("Configuration manager shutdown complete")
	return nil
}
