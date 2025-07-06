package config

import (
	"time"
)

// EnhancedConfig represents the complete configuration for Typosentinel
type EnhancedConfig struct {
	// Core configuration
	Core CoreConfig `yaml:"core" json:"core"`

	// Detection configuration
	Detection DetectionConfig `yaml:"detection" json:"detection"`

	// Machine Learning configuration
	ML MLConfig `yaml:"ml" json:"ml"`

	// Plugin configuration
	Plugins PluginsConfig `yaml:"plugins" json:"plugins"`

	// Threat Intelligence configuration
	ThreatIntelligence ThreatIntelligenceConfig `yaml:"threat_intelligence" json:"threat_intelligence"`

	// Logging configuration
	Logging LoggingConfig `yaml:"logging" json:"logging"`

	// Performance configuration
	Performance PerformanceConfig `yaml:"performance" json:"performance"`

	// Security configuration
	Security SecurityConfig `yaml:"security" json:"security"`
}

// CoreConfig contains core application settings
type CoreConfig struct {
	Version     string `yaml:"version" json:"version"`
	Environment string `yaml:"environment" json:"environment"`
	Debug       bool   `yaml:"debug" json:"debug"`
	Verbose     bool   `yaml:"verbose" json:"verbose"`
	DataDir     string `yaml:"data_dir" json:"data_dir"`
	CacheDir    string `yaml:"cache_dir" json:"cache_dir"`
	TempDir     string `yaml:"temp_dir" json:"temp_dir"`
	ConfigDir   string `yaml:"config_dir" json:"config_dir"`
}

// DetectionConfig contains detection engine settings
type DetectionConfig struct {
	// Typosquatting detection
	Typosquatting TyposquattingConfig `yaml:"typosquatting" json:"typosquatting"`

	// Dependency confusion detection
	DependencyConfusion DependencyConfusionConfig `yaml:"dependency_confusion" json:"dependency_confusion"`

	// Supply chain detection
	SupplyChain SupplyChainConfig `yaml:"supply_chain" json:"supply_chain"`

	// General detection settings
	Enabled          bool     `yaml:"enabled" json:"enabled"`
	ParallelScans    int      `yaml:"parallel_scans" json:"parallel_scans"`
	Timeout          int      `yaml:"timeout_seconds" json:"timeout_seconds"`
	MaxPackageSize   int64    `yaml:"max_package_size_mb" json:"max_package_size_mb"`
	SkipPatterns     []string `yaml:"skip_patterns" json:"skip_patterns"`
	WhitelistPackages []string `yaml:"whitelist_packages" json:"whitelist_packages"`
}

// TyposquattingConfig contains typosquatting detection settings
type TyposquattingConfig struct {
	Enabled           bool    `yaml:"enabled" json:"enabled"`
	SimilarityThreshold float64 `yaml:"similarity_threshold" json:"similarity_threshold"`
	MinLength         int     `yaml:"min_length" json:"min_length"`
	MaxDistance       int     `yaml:"max_distance" json:"max_distance"`
	Algorithms        []string `yaml:"algorithms" json:"algorithms"`
	PopularPackages   []string `yaml:"popular_packages" json:"popular_packages"`
	CustomDictionary  []string `yaml:"custom_dictionary" json:"custom_dictionary"`
}

// DependencyConfusionConfig contains dependency confusion detection settings
type DependencyConfusionConfig struct {
	Enabled              bool     `yaml:"enabled" json:"enabled"`
	CheckPrivateRepos    bool     `yaml:"check_private_repos" json:"check_private_repos"`
	PrivateRegistries    []string `yaml:"private_registries" json:"private_registries"`
	NamespacePatterns    []string `yaml:"namespace_patterns" json:"namespace_patterns"`
	ScopeIndicators      []string `yaml:"scope_indicators" json:"scope_indicators"`
	ConfusionThreshold   float64  `yaml:"confusion_threshold" json:"confusion_threshold"`
	VersionAnalysis      bool     `yaml:"version_analysis" json:"version_analysis"`
	DownloadAnalysis     bool     `yaml:"download_analysis" json:"download_analysis"`
}

// SupplyChainConfig contains supply chain detection settings
type SupplyChainConfig struct {
	Enabled                bool     `yaml:"enabled" json:"enabled"`
	MaintainerAnalysis     bool     `yaml:"maintainer_analysis" json:"maintainer_analysis"`
	VersionPatternAnalysis bool     `yaml:"version_pattern_analysis" json:"version_pattern_analysis"`
	IntegrityChecks        bool     `yaml:"integrity_checks" json:"integrity_checks"`
	AnomalyDetection       bool     `yaml:"anomaly_detection" json:"anomaly_detection"`
	TrustedMaintainers     []string `yaml:"trusted_maintainers" json:"trusted_maintainers"`
	SuspiciousPatterns     []string `yaml:"suspicious_patterns" json:"suspicious_patterns"`
	MinMaintainerAge       int      `yaml:"min_maintainer_age_days" json:"min_maintainer_age_days"`
	MinPackageAge          int      `yaml:"min_package_age_days" json:"min_package_age_days"`
	ReputationThreshold    float64  `yaml:"reputation_threshold" json:"reputation_threshold"`
}

// MLConfig contains machine learning settings
type MLConfig struct {
	Enabled           bool                    `yaml:"enabled" json:"enabled"`
	AdaptiveThresholds AdaptiveThresholdsConfig `yaml:"adaptive_thresholds" json:"adaptive_thresholds"`
	ModelPath         string                  `yaml:"model_path" json:"model_path"`
	TrainingData      string                  `yaml:"training_data" json:"training_data"`
	UpdateInterval    int                     `yaml:"update_interval_hours" json:"update_interval_hours"`
	MinTrainingSize   int                     `yaml:"min_training_size" json:"min_training_size"`
	ValidationSplit   float64                 `yaml:"validation_split" json:"validation_split"`
	FeatureEngineering FeatureEngineeringConfig `yaml:"feature_engineering" json:"feature_engineering"`
}

// AdaptiveThresholdsConfig contains adaptive threshold settings
type AdaptiveThresholdsConfig struct {
	Enabled              bool                           `yaml:"enabled" json:"enabled"`
	Ecosystems           map[string]EcosystemMLConfig   `yaml:"ecosystems" json:"ecosystems"`
	PerformanceTargets   PerformanceTargetsConfig       `yaml:"performance_targets" json:"performance_targets"`
	AdaptationFrequency  int                            `yaml:"adaptation_frequency_hours" json:"adaptation_frequency_hours"`
	MinSamplesForAdapt   int                            `yaml:"min_samples_for_adapt" json:"min_samples_for_adapt"`
	MaxThresholdChange   float64                        `yaml:"max_threshold_change" json:"max_threshold_change"`
	StabilityPeriod      int                            `yaml:"stability_period_hours" json:"stability_period_hours"`
}

// EcosystemMLConfig contains ML settings for specific ecosystems
type EcosystemMLConfig struct {
	Enabled            bool    `yaml:"enabled" json:"enabled"`
	Typosquatting      float64 `yaml:"typosquatting_threshold" json:"typosquatting_threshold"`
	DependencyConfusion float64 `yaml:"dependency_confusion_threshold" json:"dependency_confusion_threshold"`
	SupplyChain        float64 `yaml:"supply_chain_threshold" json:"supply_chain_threshold"`
	ModelVersion       string  `yaml:"model_version" json:"model_version"`
	LastUpdated        string  `yaml:"last_updated" json:"last_updated"`
}

// PerformanceTargetsConfig contains performance target settings
type PerformanceTargetsConfig struct {
	TargetPrecision float64 `yaml:"target_precision" json:"target_precision"`
	TargetRecall    float64 `yaml:"target_recall" json:"target_recall"`
	TargetF1Score   float64 `yaml:"target_f1_score" json:"target_f1_score"`
	MaxFalsePositiveRate float64 `yaml:"max_false_positive_rate" json:"max_false_positive_rate"`
}

// FeatureEngineeringConfig contains feature engineering settings
type FeatureEngineeringConfig struct {
	StringFeatures    []string `yaml:"string_features" json:"string_features"`
	NumericalFeatures []string `yaml:"numerical_features" json:"numerical_features"`
	CategoricalFeatures []string `yaml:"categorical_features" json:"categorical_features"`
	CustomFeatures    []string `yaml:"custom_features" json:"custom_features"`
	Normalization     string   `yaml:"normalization" json:"normalization"`
	Dimensionality    int      `yaml:"dimensionality" json:"dimensionality"`
}

// PluginsConfig contains plugin system settings
type PluginsConfig struct {
	Enabled         bool                    `yaml:"enabled" json:"enabled"`
	PluginDirectory string                  `yaml:"plugin_directory" json:"plugin_directory"`
	AutoLoad        bool                    `yaml:"auto_load" json:"auto_load"`
	Timeout         int                     `yaml:"timeout_seconds" json:"timeout_seconds"`
	MaxPlugins      int                     `yaml:"max_plugins" json:"max_plugins"`
	Plugins         []PluginEntry           `yaml:"plugins" json:"plugins"`
	CICD            map[string]PluginConfig `yaml:"cicd" json:"cicd"`
	Webhooks        []WebhookConfig         `yaml:"webhooks" json:"webhooks"`
	Custom          map[string]interface{}  `yaml:"custom" json:"custom"`
}

// PluginEntry contains individual plugin entry settings
type PluginEntry struct {
	Name    string                 `yaml:"name" json:"name"`
	Path    string                 `yaml:"path" json:"path"`
	Enabled bool                   `yaml:"enabled" json:"enabled"`
	Config  map[string]interface{} `yaml:"config" json:"config"`
}

// PluginConfig contains individual plugin settings
type PluginConfig struct {
	Enabled  bool                   `yaml:"enabled" json:"enabled"`
	Settings map[string]interface{} `yaml:"settings" json:"settings"`
	Priority int                    `yaml:"priority" json:"priority"`
	Timeout  int                    `yaml:"timeout_seconds" json:"timeout_seconds"`
}

// WebhookConfig contains webhook settings
type WebhookConfig struct {
	Name            string            `yaml:"name" json:"name"`
	URL             string            `yaml:"url" json:"url"`
	Method          string            `yaml:"method" json:"method"`
	Headers         map[string]string `yaml:"headers" json:"headers"`
	Secret          string            `yaml:"secret" json:"secret"`
	Timeout         int               `yaml:"timeout_seconds" json:"timeout_seconds"`
	RetryAttempts   int               `yaml:"retry_attempts" json:"retry_attempts"`
	FilterSeverity  []string          `yaml:"filter_severity" json:"filter_severity"`
	FailOnCritical  bool              `yaml:"fail_on_critical" json:"fail_on_critical"`
	FailOnHigh      bool              `yaml:"fail_on_high" json:"fail_on_high"`
}

// ThreatIntelligenceConfig contains threat intelligence settings
type ThreatIntelligenceConfig struct {
	Enabled       bool                    `yaml:"enabled" json:"enabled"`
	Database      DatabaseConfig          `yaml:"database" json:"database"`
	Feeds         []ThreatFeedConfig      `yaml:"feeds" json:"feeds"`
	Correlation   CorrelationConfig       `yaml:"correlation" json:"correlation"`
	Alerting      AlertingConfig          `yaml:"alerting" json:"alerting"`
	RealTimeUpdates RealTimeUpdatesConfig `yaml:"real_time_updates" json:"real_time_updates"`
	Retention     RetentionConfig         `yaml:"retention" json:"retention"`
}

// DatabaseConfig contains threat database settings
type DatabaseConfig struct {
	Type           string `yaml:"type" json:"type"`
	Path           string `yaml:"path" json:"path"`
	ConnectionString string `yaml:"connection_string" json:"connection_string"`
	MaxConnections int    `yaml:"max_connections" json:"max_connections"`
	Timeout        int    `yaml:"timeout_seconds" json:"timeout_seconds"`
	Encryption     bool   `yaml:"encryption" json:"encryption"`
	Backup         BackupConfig `yaml:"backup" json:"backup"`
}

// BackupConfig contains database backup settings
type BackupConfig struct {
	Enabled   bool   `yaml:"enabled" json:"enabled"`
	Interval  int    `yaml:"interval_hours" json:"interval_hours"`
	Retention int    `yaml:"retention_days" json:"retention_days"`
	Path      string `yaml:"path" json:"path"`
	Compress  bool   `yaml:"compress" json:"compress"`
}

// ThreatFeedConfig contains threat feed settings
type ThreatFeedConfig struct {
	Name           string            `yaml:"name" json:"name"`
	Type           string            `yaml:"type" json:"type"`
	URL            string            `yaml:"url" json:"url"`
	APIKey         string            `yaml:"api_key" json:"api_key"`
	UpdateInterval int               `yaml:"update_interval_minutes" json:"update_interval_minutes"`
	Enabled        bool              `yaml:"enabled" json:"enabled"`
	Priority       int               `yaml:"priority" json:"priority"`
	Format         string            `yaml:"format" json:"format"`
	Headers        map[string]string `yaml:"headers" json:"headers"`
	Timeout        int               `yaml:"timeout_seconds" json:"timeout_seconds"`
	RetryAttempts  int               `yaml:"retry_attempts" json:"retry_attempts"`
}

// CorrelationConfig contains threat correlation settings
type CorrelationConfig struct {
	Enabled           bool    `yaml:"enabled" json:"enabled"`
	SimilarityThreshold float64 `yaml:"similarity_threshold" json:"similarity_threshold"`
	CacheSize         int     `yaml:"cache_size" json:"cache_size"`
	CacheTTL          int     `yaml:"cache_ttl_minutes" json:"cache_ttl_minutes"`
	MaxConcurrent     int     `yaml:"max_concurrent" json:"max_concurrent"`
	Timeout           int     `yaml:"timeout_seconds" json:"timeout_seconds"`
}

// AlertingConfig contains alerting system settings
type AlertingConfig struct {
	Enabled      bool                    `yaml:"enabled" json:"enabled"`
	Channels     map[string]AlertChannel `yaml:"channels" json:"channels"`
	Throttling   ThrottlingConfig        `yaml:"throttling" json:"throttling"`
	Filters      []AlertFilter           `yaml:"filters" json:"filters"`
	Templates    map[string]string       `yaml:"templates" json:"templates"`
	Escalation   EscalationConfig        `yaml:"escalation" json:"escalation"`
}

// AlertChannel contains alert channel settings
type AlertChannel struct {
	Type     string                 `yaml:"type" json:"type"`
	Enabled  bool                   `yaml:"enabled" json:"enabled"`
	Settings map[string]interface{} `yaml:"settings" json:"settings"`
	Filters  []string               `yaml:"filters" json:"filters"`
	Priority int                    `yaml:"priority" json:"priority"`
}

// ThrottlingConfig contains alert throttling settings
type ThrottlingConfig struct {
	Enabled       bool `yaml:"enabled" json:"enabled"`
	MaxPerMinute  int  `yaml:"max_per_minute" json:"max_per_minute"`
	MaxPerHour    int  `yaml:"max_per_hour" json:"max_per_hour"`
	MaxPerDay     int  `yaml:"max_per_day" json:"max_per_day"`
	BurstLimit    int  `yaml:"burst_limit" json:"burst_limit"`
	CooldownPeriod int `yaml:"cooldown_period_minutes" json:"cooldown_period_minutes"`
}

// AlertFilter contains alert filtering settings
type AlertFilter struct {
	Name      string   `yaml:"name" json:"name"`
	Type      string   `yaml:"type" json:"type"`
	Condition string   `yaml:"condition" json:"condition"`
	Values    []string `yaml:"values" json:"values"`
	Action    string   `yaml:"action" json:"action"`
}

// EscalationConfig contains alert escalation settings
type EscalationConfig struct {
	Enabled   bool              `yaml:"enabled" json:"enabled"`
	Rules     []EscalationRule  `yaml:"rules" json:"rules"`
	Timeout   int               `yaml:"timeout_minutes" json:"timeout_minutes"`
	MaxLevels int               `yaml:"max_levels" json:"max_levels"`
}

// EscalationRule contains escalation rule settings
type EscalationRule struct {
	Level     int      `yaml:"level" json:"level"`
	Delay     int      `yaml:"delay_minutes" json:"delay_minutes"`
	Channels  []string `yaml:"channels" json:"channels"`
	Condition string   `yaml:"condition" json:"condition"`
}

// RealTimeUpdatesConfig contains real-time update settings
type RealTimeUpdatesConfig struct {
	Enabled        bool                    `yaml:"enabled" json:"enabled"`
	Channels       []UpdateChannelConfig   `yaml:"channels" json:"channels"`
	Processors     map[string]ProcessorConfig `yaml:"processors" json:"processors"`
	BufferSize     int                     `yaml:"buffer_size" json:"buffer_size"`
	BatchSize      int                     `yaml:"batch_size" json:"batch_size"`
	FlushInterval  int                     `yaml:"flush_interval_seconds" json:"flush_interval_seconds"`
	MaxRetries     int                     `yaml:"max_retries" json:"max_retries"`
	ErrorHandling  ErrorHandlingConfig     `yaml:"error_handling" json:"error_handling"`
}

// UpdateChannelConfig contains update channel settings
type UpdateChannelConfig struct {
	Name     string                 `yaml:"name" json:"name"`
	Type     string                 `yaml:"type" json:"type"`
	Enabled  bool                   `yaml:"enabled" json:"enabled"`
	Settings map[string]interface{} `yaml:"settings" json:"settings"`
	Priority int                    `yaml:"priority" json:"priority"`
}

// ProcessorConfig contains processor settings
type ProcessorConfig struct {
	Enabled      bool                   `yaml:"enabled" json:"enabled"`
	Workers      int                    `yaml:"workers" json:"workers"`
	QueueSize    int                    `yaml:"queue_size" json:"queue_size"`
	Timeout      int                    `yaml:"timeout_seconds" json:"timeout_seconds"`
	Settings     map[string]interface{} `yaml:"settings" json:"settings"`
}

// ErrorHandlingConfig contains error handling settings
type ErrorHandlingConfig struct {
	Strategy      string `yaml:"strategy" json:"strategy"`
	MaxRetries    int    `yaml:"max_retries" json:"max_retries"`
	RetryDelay    int    `yaml:"retry_delay_seconds" json:"retry_delay_seconds"`
	DeadLetterQueue bool `yaml:"dead_letter_queue" json:"dead_letter_queue"`
	LogErrors     bool   `yaml:"log_errors" json:"log_errors"`
	AlertOnError  bool   `yaml:"alert_on_error" json:"alert_on_error"`
}

// RetentionConfig contains data retention settings
type RetentionConfig struct {
	ThreatData    int `yaml:"threat_data_days" json:"threat_data_days"`
	ScanResults   int `yaml:"scan_results_days" json:"scan_results_days"`
	Logs          int `yaml:"logs_days" json:"logs_days"`
	Metrics       int `yaml:"metrics_days" json:"metrics_days"`
	Backups       int `yaml:"backups_days" json:"backups_days"`
	CleanupInterval int `yaml:"cleanup_interval_hours" json:"cleanup_interval_hours"`
}

// LoggingConfig contains logging settings
type LoggingConfig struct {
	Level      string            `yaml:"level" json:"level"`
	Format     string            `yaml:"format" json:"format"`
	Output     []string          `yaml:"output" json:"output"`
	File       LogFileConfig     `yaml:"file" json:"file"`
	Syslog     SyslogConfig      `yaml:"syslog" json:"syslog"`
	Structured bool              `yaml:"structured" json:"structured"`
	Fields     map[string]string `yaml:"fields" json:"fields"`
	Sampling   SamplingConfig    `yaml:"sampling" json:"sampling"`
}

// LogFileConfig contains log file settings
type LogFileConfig struct {
	Path       string `yaml:"path" json:"path"`
	MaxSize    int    `yaml:"max_size_mb" json:"max_size_mb"`
	MaxAge     int    `yaml:"max_age_days" json:"max_age_days"`
	MaxBackups int    `yaml:"max_backups" json:"max_backups"`
	Compress   bool   `yaml:"compress" json:"compress"`
}

// SyslogConfig contains syslog settings
type SyslogConfig struct {
	Network  string `yaml:"network" json:"network"`
	Address  string `yaml:"address" json:"address"`
	Priority string `yaml:"priority" json:"priority"`
	Tag      string `yaml:"tag" json:"tag"`
}

// SamplingConfig contains log sampling settings
type SamplingConfig struct {
	Enabled    bool `yaml:"enabled" json:"enabled"`
	Rate       int  `yaml:"rate" json:"rate"`
	Burst      int  `yaml:"burst" json:"burst"`
	Threshold  int  `yaml:"threshold" json:"threshold"`
}

// PerformanceConfig contains performance settings
type PerformanceConfig struct {
	MaxConcurrency   int           `yaml:"max_concurrency" json:"max_concurrency"`
	WorkerPoolSize   int           `yaml:"worker_pool_size" json:"worker_pool_size"`
	QueueSize        int           `yaml:"queue_size" json:"queue_size"`
	Timeout          time.Duration `yaml:"timeout" json:"timeout"`
	MemoryLimit      int64         `yaml:"memory_limit_mb" json:"memory_limit_mb"`
	CPULimit         float64       `yaml:"cpu_limit_percent" json:"cpu_limit_percent"`
	Caching          CachingConfig `yaml:"caching" json:"caching"`
	Profiling        ProfilingConfig `yaml:"profiling" json:"profiling"`
	Metrics          MetricsConfig `yaml:"metrics" json:"metrics"`
}

// CachingConfig contains caching settings
type CachingConfig struct {
	Enabled     bool `yaml:"enabled" json:"enabled"`
	MaxSize     int  `yaml:"max_size_mb" json:"max_size_mb"`
	TTL         int  `yaml:"ttl_minutes" json:"ttl_minutes"`
	CleanupInterval int `yaml:"cleanup_interval_minutes" json:"cleanup_interval_minutes"`
	Persistent  bool `yaml:"persistent" json:"persistent"`
	Path        string `yaml:"path" json:"path"`
}

// ProfilingConfig contains profiling settings
type ProfilingConfig struct {
	Enabled    bool   `yaml:"enabled" json:"enabled"`
	CPU        bool   `yaml:"cpu" json:"cpu"`
	Memory     bool   `yaml:"memory" json:"memory"`
	Goroutine  bool   `yaml:"goroutine" json:"goroutine"`
	Block      bool   `yaml:"block" json:"block"`
	Mutex      bool   `yaml:"mutex" json:"mutex"`
	OutputDir  string `yaml:"output_dir" json:"output_dir"`
	Duration   int    `yaml:"duration_seconds" json:"duration_seconds"`
}

// MetricsConfig contains metrics settings
type MetricsConfig struct {
	Enabled    bool              `yaml:"enabled" json:"enabled"`
	Port       int               `yaml:"port" json:"port"`
	Path       string            `yaml:"path" json:"path"`
	Namespace  string            `yaml:"namespace" json:"namespace"`
	Labels     map[string]string `yaml:"labels" json:"labels"`
	Collectors []string          `yaml:"collectors" json:"collectors"`
	Exporters  []ExporterConfig  `yaml:"exporters" json:"exporters"`
}

// ExporterConfig contains metrics exporter settings
type ExporterConfig struct {
	Type     string                 `yaml:"type" json:"type"`
	Enabled  bool                   `yaml:"enabled" json:"enabled"`
	Settings map[string]interface{} `yaml:"settings" json:"settings"`
}

// SecurityConfig contains security settings
type SecurityConfig struct {
	Encryption   EncryptionConfig   `yaml:"encryption" json:"encryption"`
	Authentication AuthConfig       `yaml:"authentication" json:"authentication"`
	Authorization  AuthzConfig      `yaml:"authorization" json:"authorization"`
	Audit        AuditConfig        `yaml:"audit" json:"audit"`
	RateLimit    RateLimitConfig    `yaml:"rate_limit" json:"rate_limit"`
	Secrets      SecretsConfig      `yaml:"secrets" json:"secrets"`
}

// EncryptionConfig contains encryption settings
type EncryptionConfig struct {
	Enabled    bool   `yaml:"enabled" json:"enabled"`
	Algorithm  string `yaml:"algorithm" json:"algorithm"`
	KeySize    int    `yaml:"key_size" json:"key_size"`
	KeyPath    string `yaml:"key_path" json:"key_path"`
	Rotation   bool   `yaml:"rotation" json:"rotation"`
	RotationInterval int `yaml:"rotation_interval_days" json:"rotation_interval_days"`
}

// AuthConfig contains authentication settings
type AuthConfig struct {
	Enabled  bool              `yaml:"enabled" json:"enabled"`
	Type     string            `yaml:"type" json:"type"`
	Settings map[string]interface{} `yaml:"settings" json:"settings"`
	TokenTTL int               `yaml:"token_ttl_minutes" json:"token_ttl_minutes"`
}

// AuthzConfig contains authorization settings
type AuthzConfig struct {
	Enabled bool              `yaml:"enabled" json:"enabled"`
	Type    string            `yaml:"type" json:"type"`
	Roles   map[string][]string `yaml:"roles" json:"roles"`
	Policies map[string]interface{} `yaml:"policies" json:"policies"`
}

// AuditConfig contains audit settings
type AuditConfig struct {
	Enabled   bool     `yaml:"enabled" json:"enabled"`
	Events    []string `yaml:"events" json:"events"`
	Output    []string `yaml:"output" json:"output"`
	Retention int      `yaml:"retention_days" json:"retention_days"`
	Format    string   `yaml:"format" json:"format"`
}

// RateLimitConfig contains rate limiting settings
type RateLimitConfig struct {
	Enabled     bool `yaml:"enabled" json:"enabled"`
	RequestsPerMinute int `yaml:"requests_per_minute" json:"requests_per_minute"`
	RequestsPerHour   int `yaml:"requests_per_hour" json:"requests_per_hour"`
	BurstLimit        int `yaml:"burst_limit" json:"burst_limit"`
	Whitelist         []string `yaml:"whitelist" json:"whitelist"`
}

// SecretsConfig contains secrets management settings
type SecretsConfig struct {
	Provider string                 `yaml:"provider" json:"provider"`
	Settings map[string]interface{} `yaml:"settings" json:"settings"`
	Rotation bool                   `yaml:"rotation" json:"rotation"`
	RotationInterval int            `yaml:"rotation_interval_days" json:"rotation_interval_days"`
}

// Note: ConfigManager functionality has been moved to config_manager.go
// to avoid duplication and conflicts

// Note: Default configuration functionality has been moved to config_manager.go
// to avoid duplication and conflicts

// Note: ConfigManager methods have been moved to config_manager.go
// to avoid duplication and conflicts