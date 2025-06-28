package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)



// Config represents the enhanced configuration for TypoSentinel
type Config struct {
	// Core configuration
	Core *CoreConfig `yaml:"core"`
	Verbose bool `yaml:"verbose"`
	Debug bool `yaml:"debug"`
	API *APIConfig `yaml:"api"`
	Database *DatabaseConfig `yaml:"database"`
	
	// Analysis engines
	StaticAnalysis *StaticAnalysisConfig `yaml:"static_analysis"`
	DynamicAnalysis *DynamicAnalysisConfig `yaml:"dynamic_analysis"`
	MLAnalysis *MLAnalysisConfig `yaml:"ml_analysis"`
	MLService *MLServiceConfig `yaml:"ml_service"`
	ProvenanceAnalysis *ProvenanceAnalysisConfig `yaml:"provenance_analysis"`
	
	// Detection and scanning
	Detection *DetectionConfig `yaml:"detection"`
	Registries []RegistryConfig `yaml:"registries"`
	Scanner *ScannerConfig `yaml:"scanner"`
	Plugins *PluginsConfig `yaml:"plugins"`
	TypoDetection *TypoDetectionConfig `yaml:"typo_detection"`
	MalwareDetection *MalwareDetectionConfig `yaml:"malware_detection"`
	VulnerabilityScanning *VulnerabilityScanningConfig `yaml:"vulnerability_scanning"`
	
	// Reporting and output
	Reporting *ReportingConfig `yaml:"reporting"`
	Output    *OutputConfig    `yaml:"output"`
	Cache     *CacheConfig     `yaml:"cache"`
	
	// Performance and caching
	Performance *PerformanceConfig `yaml:"performance"`
	Caching *CachingConfig `yaml:"caching"`
	
	// Security and privacy
	Security *SecurityConfig `yaml:"security"`
	Privacy *PrivacyConfig `yaml:"privacy"`
	Policies *PolicyConfig `yaml:"policies"`
	
	// Integration and APIs
	Integrations *IntegrationsConfig `yaml:"integrations"`
	
	// Logging and monitoring
	Logging *LoggingConfig `yaml:"logging"`
	Monitoring *MonitoringConfig `yaml:"monitoring"`
}

// CoreConfig contains core application settings
type CoreConfig struct {
	Version string `yaml:"version"`
	Environment string `yaml:"environment"` // development, staging, production
	Debug bool `yaml:"debug"`
	Verbose bool `yaml:"verbose"`
	Quiet bool `yaml:"quiet"`
	ConfigPath string `yaml:"config_path"`
	DataDir string `yaml:"data_dir"`
	TempDir string `yaml:"temp_dir"`
	MaxConcurrency int `yaml:"max_concurrency"`
	Timeout time.Duration `yaml:"timeout"`
	RetryAttempts int `yaml:"retry_attempts"`
	RetryDelay string `yaml:"retry_delay"`
}

// StaticAnalysisConfig contains static analysis settings
type StaticAnalysisConfig struct {
	Enabled bool `yaml:"enabled"`
	RulesPath string `yaml:"rules_path"`
	YaraRulesPath string `yaml:"yara_rules_path"`
	CustomRulesPath string `yaml:"custom_rules_path"`
	MaxFileSize string `yaml:"max_file_size"`
	MaxFiles int `yaml:"max_files"`
	Timeout string `yaml:"timeout"`
	DeepScan bool `yaml:"deep_scan"`
	ScanArchives bool `yaml:"scan_archives"`
	ScanBinaries bool `yaml:"scan_binaries"`
	ScanScripts bool `yaml:"scan_scripts"`
	ScanManifests bool `yaml:"scan_manifests"`
	RiskThreshold float64 `yaml:"risk_threshold"`
	ExcludePatterns []string `yaml:"exclude_patterns"`
	IncludePatterns []string `yaml:"include_patterns"`
	Parallelism int `yaml:"parallelism"`
}

// DynamicAnalysisConfig contains dynamic analysis settings
type DynamicAnalysisConfig struct {
	Enabled bool `yaml:"enabled"`
	SandboxType string `yaml:"sandbox_type"` // docker, chroot, vm
	SandboxDir string `yaml:"sandbox_dir"`
	SandboxImage string `yaml:"sandbox_image"`
	Timeout string `yaml:"timeout"`
	MaxMemory string `yaml:"max_memory"`
	MaxCPU string `yaml:"max_cpu"`
	NetworkIsolation bool `yaml:"network_isolation"`
	FileSystemIsolation bool `yaml:"filesystem_isolation"`
	MonitorNetworkActivity bool `yaml:"monitor_network_activity"`
	MonitorFileActivity bool `yaml:"monitor_file_activity"`
	MonitorProcessActivity bool `yaml:"monitor_process_activity"`
	MonitorSystemCalls bool `yaml:"monitor_system_calls"`
	ExecuteInstallScripts bool `yaml:"execute_install_scripts"`
	ExecuteMainScript bool `yaml:"execute_main_script"`
	CleanupAfterAnalysis bool `yaml:"cleanup_after_analysis"`
	MaxExecutionTime string `yaml:"max_execution_time"`
	ResourceLimits *ResourceLimits `yaml:"resource_limits"`
}

// ResourceLimits defines resource constraints for dynamic analysis
type ResourceLimits struct {
	MaxMemoryMB int `yaml:"max_memory_mb"`
	MaxCPUPercent int `yaml:"max_cpu_percent"`
	MaxDiskMB int `yaml:"max_disk_mb"`
	MaxNetworkKBps int `yaml:"max_network_kbps"`
	MaxProcesses int `yaml:"max_processes"`
	MaxOpenFiles int `yaml:"max_open_files"`
}

// MLAnalysisConfig contains machine learning analysis settings
type MLAnalysisConfig struct {
	Enabled bool `yaml:"enabled"`
	ModelPath string `yaml:"model_path"`
	EmbeddingModel string `yaml:"embedding_model"`
	EmbeddingDimensions int `yaml:"embedding_dimensions"`
	SimilarityThreshold float64 `yaml:"similarity_threshold"`
	MaliciousThreshold float64 `yaml:"malicious_threshold"`
	ReputationThreshold float64 `yaml:"reputation_threshold"`
	FeatureStore *FeatureStoreConfig `yaml:"feature_store"`
	ModelUpdates *ModelUpdatesConfig `yaml:"model_updates"`
	BatchSize int `yaml:"batch_size"`
	MaxFeatures int `yaml:"max_features"`
	CacheEmbeddings bool `yaml:"cache_embeddings"`
	ParallelProcessing bool `yaml:"parallel_processing"`
	GPUAcceleration bool `yaml:"gpu_acceleration"`
}

// FeatureStoreConfig contains feature store settings
type FeatureStoreConfig struct {
	Enabled bool `yaml:"enabled"`
	Backend string `yaml:"backend"` // memory, redis, file
	ConnectionString string `yaml:"connection_string"`
	TTL string `yaml:"ttl"`
	MaxSize int `yaml:"max_size"`
	CompressionEnabled bool `yaml:"compression_enabled"`
	EncryptionEnabled bool `yaml:"encryption_enabled"`
	BackupEnabled bool `yaml:"backup_enabled"`
	BackupInterval string `yaml:"backup_interval"`
	CleanupInterval string `yaml:"cleanup_interval"`
}

// ModelUpdatesConfig contains model update settings
type ModelUpdatesConfig struct {
	Enabled bool `yaml:"enabled"`
	UpdateInterval string `yaml:"update_interval"`
	UpdateURL string `yaml:"update_url"`
	AutoUpdate bool `yaml:"auto_update"`
	VerifySignatures bool `yaml:"verify_signatures"`
	BackupOldModels bool `yaml:"backup_old_models"`
	MaxModelVersions int `yaml:"max_model_versions"`
}

// ProvenanceAnalysisConfig contains provenance analysis settings
type ProvenanceAnalysisConfig struct {
	Enabled bool `yaml:"enabled"`
	
	// Sigstore configuration
	SigstoreEnabled bool `yaml:"sigstore_enabled"`
	SigstoreRekorURL string `yaml:"sigstore_rekor_url"`
	SigstoreFulcioURL string `yaml:"sigstore_fulcio_url"`
	SigstoreCTLogURL string `yaml:"sigstore_ctlog_url"`
	
	// SLSA configuration
	SLSAEnabled bool `yaml:"slsa_enabled"`
	SLSAMinLevel int `yaml:"slsa_min_level"`
	SLSARequiredBuilders []string `yaml:"slsa_required_builders"`
	
	// Verification settings
	VerifySignatures bool `yaml:"verify_signatures"`
	VerifyProvenance bool `yaml:"verify_provenance"`
	VerifyIntegrity bool `yaml:"verify_integrity"`
	RequireTransparencyLog bool `yaml:"require_transparency_log"`
	
	// Trust settings
	TrustedPublishers []string `yaml:"trusted_publishers"`
	TrustedSigners []string `yaml:"trusted_signers"`
	TrustedBuilders []string `yaml:"trusted_builders"`
	
	// Timeout and retry settings
	Timeout string `yaml:"timeout"`
	RetryAttempts int `yaml:"retry_attempts"`
	Verbose bool `yaml:"verbose"`
}

// DetectionConfig contains threat detection settings
type DetectionConfig struct {
	Enabled                 bool    `yaml:"enabled"`
	MinPackageNameLength   int     `yaml:"min_package_name_length"`
	EnhancedTyposquatting  bool    `yaml:"enhanced_typosquatting"`
	HomoglyphDetection     bool    `yaml:"homoglyph_detection"`
	DependencyConfusion    bool    `yaml:"dependency_confusion"`
	ReputationScoring      bool    `yaml:"reputation_scoring"`
	Thresholds             ThresholdConfig `yaml:"thresholds"`
	Algorithms             AlgorithmConfig `yaml:"algorithms"`
}

// ThresholdConfig contains detection threshold settings
type ThresholdConfig struct {
	Similarity  float64 `yaml:"similarity"`
	Confidence  float64 `yaml:"confidence"`
	Reputation  float64 `yaml:"reputation"`
}

// AlgorithmConfig contains algorithm enablement settings
type AlgorithmConfig struct {
	Lexical   bool `yaml:"lexical"`
	Homoglyph bool `yaml:"homoglyph"`
	ML        bool `yaml:"ml"`
}

// RegistryConfig contains registry configuration settings
type RegistryConfig struct {
	Enabled   bool            `yaml:"enabled"`
	Name      string          `yaml:"name"`
	BaseURL   string          `yaml:"base_url"`
	APIKey    string          `yaml:"api_key"`
	Timeout   string          `yaml:"timeout"`
	RateLimit RateLimitConfig `yaml:"rate_limit"`
	Private   PrivateConfig   `yaml:"private"`
}

// RateLimitConfig contains rate limiting settings
type RateLimitConfig struct {
	Enabled bool `yaml:"enabled"`
	RPS     int  `yaml:"rps"`
	Burst   int  `yaml:"burst"`
}

// PrivateConfig contains private registry settings
type PrivateConfig struct {
	Namespaces []string `yaml:"namespaces"`
}

// PolicyConfig contains policy settings
type PolicyConfig struct {
	Enabled bool         `yaml:"enabled" json:"enabled"`
	Rules   []PolicyRule `yaml:"rules" json:"rules"`
	FailOnThreats bool   `yaml:"fail_on_threats" json:"fail_on_threats"`
	MinThreatLevel string `yaml:"min_threat_level" json:"min_threat_level"`
}

// PolicyRule represents a policy rule
type PolicyRule struct {
	Name        string   `yaml:"name" json:"name"`
	Description string   `yaml:"description" json:"description"`
	Enabled     bool     `yaml:"enabled" json:"enabled"`
	Conditions  []string `yaml:"conditions" json:"conditions"`
	Actions     []string `yaml:"actions" json:"actions"`
}

// MLModelConfig contains ML model configuration
type MLModelConfig struct {
	Enabled    bool   `yaml:"enabled"`
	ModelPath  string `yaml:"model_path"`
	ModelType  string `yaml:"model_type"`
	Threshold  float64 `yaml:"threshold"`
	BatchSize  int    `yaml:"batch_size"`
	Timeout    time.Duration `yaml:"timeout"`
}

// MLServiceConfig contains ML service configuration
type MLServiceConfig struct {
	Enabled     bool   `yaml:"enabled"`
	Endpoint    string `yaml:"endpoint"`
	APIKey      string `yaml:"api_key"`
	Timeout     time.Duration `yaml:"timeout"`
	MaxRetries  int    `yaml:"max_retries"`
	BatchSize   int    `yaml:"batch_size"`
}

// TypoDetectionConfig contains typosquatting detection settings
type TypoDetectionConfig struct {
	Enabled bool `yaml:"enabled"`
	Algorithms []string `yaml:"algorithms"` // levenshtein, jaro_winkler, soundex, etc.
	Threshold float64 `yaml:"threshold"`
	MaxDistance int `yaml:"max_distance"`
	CheckSimilarNames bool `yaml:"check_similar_names"`
	CheckHomoglyphs bool `yaml:"check_homoglyphs"`
	CheckKeyboardLayout bool `yaml:"check_keyboard_layout"`
	CheckCommonTypos bool `yaml:"check_common_typos"`
	WhitelistPath string `yaml:"whitelist_path"`
	BlacklistPath string `yaml:"blacklist_path"`
	PopularPackagesPath string `yaml:"popular_packages_path"`
	CustomDictionary []string `yaml:"custom_dictionary"`
	LanguageSpecific bool `yaml:"language_specific"`
	CaseSensitive bool `yaml:"case_sensitive"`
}

// MalwareDetectionConfig contains malware detection settings
type MalwareDetectionConfig struct {
	Enabled bool `yaml:"enabled"`
	SignatureDatabase string `yaml:"signature_database"`
	HeuristicAnalysis bool `yaml:"heuristic_analysis"`
	BehavioralAnalysis bool `yaml:"behavioral_analysis"`
	SandboxAnalysis bool `yaml:"sandbox_analysis"`
	CloudScanning bool `yaml:"cloud_scanning"`
	RealTimeProtection bool `yaml:"real_time_protection"`
	QuarantineEnabled bool `yaml:"quarantine_enabled"`
	QuarantinePath string `yaml:"quarantine_path"`
	UpdateInterval string `yaml:"update_interval"`
	MaxScanSize string `yaml:"max_scan_size"`
	ScanTimeout string `yaml:"scan_timeout"`
	ExcludeExtensions []string `yaml:"exclude_extensions"`
	IncludeExtensions []string `yaml:"include_extensions"`
}

// VulnerabilityScanningConfig contains vulnerability scanning settings
type VulnerabilityScanningConfig struct {
	Enabled bool `yaml:"enabled"`
	Databases []string `yaml:"databases"` // nvd, osv, github, etc.
	APIKeys map[string]string `yaml:"api_keys"`
	UpdateInterval string `yaml:"update_interval"`
	SeverityThreshold string `yaml:"severity_threshold"` // low, medium, high, critical
	IncludeDevDependencies bool `yaml:"include_dev_dependencies"`
	IncludeTransitiveDependencies bool `yaml:"include_transitive_dependencies"`
	MaxDepth int `yaml:"max_depth"`
	IgnoreFile string `yaml:"ignore_file"`
	FailOnVulnerabilities bool `yaml:"fail_on_vulnerabilities"`
	Timeout string `yaml:"timeout"`
	RetryAttempts int `yaml:"retry_attempts"`
	CacheResults bool `yaml:"cache_results"`
	CacheTTL string `yaml:"cache_ttl"`
}

// ReportingConfig contains reporting settings
type ReportingConfig struct {
	Enabled bool `yaml:"enabled"`
	Formats []string `yaml:"formats"` // json, yaml, xml, html, pdf, csv
	OutputDir string `yaml:"output_dir"`
	Template string `yaml:"template"`
	CustomTemplates map[string]string `yaml:"custom_templates"`
	IncludeSummary bool `yaml:"include_summary"`
	IncludeDetails bool `yaml:"include_details"`
	IncludeRecommendations bool `yaml:"include_recommendations"`
	IncludeMetadata bool `yaml:"include_metadata"`
	IncludeTimestamps bool `yaml:"include_timestamps"`
	GroupByCategory bool `yaml:"group_by_category"`
	SortBySeverity bool `yaml:"sort_by_severity"`
	FilterBySeverity []string `yaml:"filter_by_severity"`
	MaxReportSize string `yaml:"max_report_size"`
	CompressionEnabled bool `yaml:"compression_enabled"`
	EncryptionEnabled bool `yaml:"encryption_enabled"`
}

// OutputConfig contains output settings
type OutputConfig struct {
	Format string `yaml:"format"` // json, yaml, table, csv
	File string `yaml:"file"`
	Stdout bool `yaml:"stdout"`
	ColorEnabled bool `yaml:"color_enabled"`
	ProgressBar bool `yaml:"progress_bar"`
	VerboseOutput bool `yaml:"verbose_output"`
	QuietMode bool `yaml:"quiet_mode"`
	Timestamps bool `yaml:"timestamps"`
	LineNumbers bool `yaml:"line_numbers"`
	PrettyPrint bool `yaml:"pretty_print"`
	MaxWidth int `yaml:"max_width"`
	TruncateOutput bool `yaml:"truncate_output"`
	MaxLines int `yaml:"max_lines"`
}

// PerformanceConfig contains performance settings
type PerformanceConfig struct {
	MaxConcurrency int `yaml:"max_concurrency"`
	WorkerPoolSize int `yaml:"worker_pool_size"`
	QueueSize int `yaml:"queue_size"`
	BatchSize int `yaml:"batch_size"`
	MemoryLimit string `yaml:"memory_limit"`
	CPULimit string `yaml:"cpu_limit"`
	IOLimit string `yaml:"io_limit"`
	NetworkLimit string `yaml:"network_limit"`
	Timeouts *TimeoutConfig `yaml:"timeouts"`
	RateLimiting *RateLimitingConfig `yaml:"rate_limiting"`
	CircuitBreaker *CircuitBreakerConfig `yaml:"circuit_breaker"`
	LoadBalancing *LoadBalancingConfig `yaml:"load_balancing"`
}

// TimeoutConfig contains timeout settings
type TimeoutConfig struct {
	Global string `yaml:"global"`
	Connection string `yaml:"connection"`
	Read string `yaml:"read"`
	Write string `yaml:"write"`
	Idle string `yaml:"idle"`
	KeepAlive string `yaml:"keep_alive"`
	Shutdown string `yaml:"shutdown"`
}

// RateLimitingConfig contains rate limiting settings
type RateLimitingConfig struct {
	Enabled bool `yaml:"enabled"`
	RequestsPerSecond int `yaml:"requests_per_second"`
	BurstSize int `yaml:"burst_size"`
	WindowSize string `yaml:"window_size"`
	BackoffStrategy string `yaml:"backoff_strategy"` // linear, exponential, fixed
	MaxRetries int `yaml:"max_retries"`
	RetryDelay string `yaml:"retry_delay"`
}

// CircuitBreakerConfig contains circuit breaker settings
type CircuitBreakerConfig struct {
	Enabled bool `yaml:"enabled"`
	FailureThreshold int `yaml:"failure_threshold"`
	SuccessThreshold int `yaml:"success_threshold"`
	Timeout string `yaml:"timeout"`
	MaxRequests int `yaml:"max_requests"`
	Interval string `yaml:"interval"`
	OnStateChange string `yaml:"on_state_change"`
}

// LoadBalancingConfig contains load balancing settings
type LoadBalancingConfig struct {
	Enabled bool `yaml:"enabled"`
	Strategy string `yaml:"strategy"` // round_robin, least_connections, weighted
	HealthCheck *HealthCheckConfig `yaml:"health_check"`
	Failover *FailoverConfig `yaml:"failover"`
}

// HealthCheckConfig contains health check settings
type HealthCheckConfig struct {
	Enabled bool `yaml:"enabled"`
	Interval string `yaml:"interval"`
	Timeout string `yaml:"timeout"`
	Path string `yaml:"path"`
	Method string `yaml:"method"`
	ExpectedStatus int `yaml:"expected_status"`
	Retries int `yaml:"retries"`
}

// FailoverConfig contains failover settings
type FailoverConfig struct {
	Enabled bool `yaml:"enabled"`
	MaxFailures int `yaml:"max_failures"`
	RecoveryTime string `yaml:"recovery_time"`
	BackupEndpoints []string `yaml:"backup_endpoints"`
}

// CachingConfig contains caching settings
type CachingConfig struct {
	Enabled bool `yaml:"enabled"`
	Backend string `yaml:"backend"` // memory, redis, file, hybrid
	ConnectionString string `yaml:"connection_string"`
	TTL string `yaml:"ttl"`
	MaxSize string `yaml:"max_size"`
	MaxEntries int `yaml:"max_entries"`
	EvictionPolicy string `yaml:"eviction_policy"` // lru, lfu, fifo, random
	CompressionEnabled bool `yaml:"compression_enabled"`
	EncryptionEnabled bool `yaml:"encryption_enabled"`
	PersistenceEnabled bool `yaml:"persistence_enabled"`
	PersistenceInterval string `yaml:"persistence_interval"`
	ClusteringEnabled bool `yaml:"clustering_enabled"`
	ReplicationFactor int `yaml:"replication_factor"`
	ConsistencyLevel string `yaml:"consistency_level"`
}

// SecurityConfig contains security settings
type SecurityConfig struct {
	EncryptionEnabled bool `yaml:"encryption_enabled"`
	EncryptionAlgorithm string `yaml:"encryption_algorithm"`
	KeyManagement *KeyManagementConfig `yaml:"key_management"`
	Authentication *AuthenticationConfig `yaml:"authentication"`
	Authorization *AuthorizationConfig `yaml:"authorization"`
	AuditLogging *AuditLoggingConfig `yaml:"audit_logging"`
	SecureTransport *SecureTransportConfig `yaml:"secure_transport"`
	InputValidation *InputValidationConfig `yaml:"input_validation"`
	OutputSanitization *OutputSanitizationConfig `yaml:"output_sanitization"`
}

// KeyManagementConfig contains key management settings
type KeyManagementConfig struct {
	Provider string `yaml:"provider"` // local, vault, aws_kms, azure_kv
	KeyStore string `yaml:"key_store"`
	KeyRotationEnabled bool `yaml:"key_rotation_enabled"`
	KeyRotationInterval string `yaml:"key_rotation_interval"`
	KeyDerivationFunction string `yaml:"key_derivation_function"`
	KeyStrength int `yaml:"key_strength"`
}

// AuthenticationConfig contains authentication settings
type AuthenticationConfig struct {
	Enabled bool `yaml:"enabled"`
	Method string `yaml:"method"` // basic, bearer, oauth2, jwt
	TokenExpiry string `yaml:"token_expiry"`
	RefreshTokenEnabled bool `yaml:"refresh_token_enabled"`
	MFAEnabled bool `yaml:"mfa_enabled"`
	SessionTimeout string `yaml:"session_timeout"`
}

// AuthorizationConfig contains authorization settings
type AuthorizationConfig struct {
	Enabled bool `yaml:"enabled"`
	Model string `yaml:"model"` // rbac, abac, acl
	PolicyFile string `yaml:"policy_file"`
	DefaultDeny bool `yaml:"default_deny"`
	CacheEnabled bool `yaml:"cache_enabled"`
	CacheTTL string `yaml:"cache_ttl"`
}

// AuditLoggingConfig contains audit logging settings
type AuditLoggingConfig struct {
	Enabled bool `yaml:"enabled"`
	Level string `yaml:"level"`
	Format string `yaml:"format"`
	Output string `yaml:"output"`
	RotationEnabled bool `yaml:"rotation_enabled"`
	MaxSize string `yaml:"max_size"`
	MaxAge string `yaml:"max_age"`
	MaxBackups int `yaml:"max_backups"`
	CompressionEnabled bool `yaml:"compression_enabled"`
}

// SecureTransportConfig contains secure transport settings
type SecureTransportConfig struct {
	TLSEnabled bool `yaml:"tls_enabled"`
	TLSVersion string `yaml:"tls_version"`
	CertificateFile string `yaml:"certificate_file"`
	PrivateKeyFile string `yaml:"private_key_file"`
	CAFile string `yaml:"ca_file"`
	InsecureSkipVerify bool `yaml:"insecure_skip_verify"`
	CipherSuites []string `yaml:"cipher_suites"`
	ClientAuth string `yaml:"client_auth"`
}

// InputValidationConfig contains input validation settings
type InputValidationConfig struct {
	Enabled bool `yaml:"enabled"`
	MaxInputSize string `yaml:"max_input_size"`
	AllowedCharacters string `yaml:"allowed_characters"`
	BlockedPatterns []string `yaml:"blocked_patterns"`
	SanitizationEnabled bool `yaml:"sanitization_enabled"`
	ValidationRules []string `yaml:"validation_rules"`
}

// OutputSanitizationConfig contains output sanitization settings
type OutputSanitizationConfig struct {
	Enabled bool `yaml:"enabled"`
	RedactSensitiveData bool `yaml:"redact_sensitive_data"`
	SensitivePatterns []string `yaml:"sensitive_patterns"`
	MaskingCharacter string `yaml:"masking_character"`
	HashSensitiveData bool `yaml:"hash_sensitive_data"`
	HashAlgorithm string `yaml:"hash_algorithm"`
}

// PrivacyConfig contains privacy settings
type PrivacyConfig struct {
	DataMinimization bool `yaml:"data_minimization"`
	Anonymization bool `yaml:"anonymization"`
	Pseudonymization bool `yaml:"pseudonymization"`
	DataRetention *DataRetentionConfig `yaml:"data_retention"`
	ConsentManagement *ConsentManagementConfig `yaml:"consent_management"`
	DataSubjectRights *DataSubjectRightsConfig `yaml:"data_subject_rights"`
	PrivacyByDesign bool `yaml:"privacy_by_design"`
	GDPRCompliance bool `yaml:"gdpr_compliance"`
	CCPACompliance bool `yaml:"ccpa_compliance"`
}

// DataRetentionConfig contains data retention settings
type DataRetentionConfig struct {
	Enabled bool `yaml:"enabled"`
	DefaultRetentionPeriod string `yaml:"default_retention_period"`
	RetentionPolicies map[string]string `yaml:"retention_policies"`
	AutomaticDeletion bool `yaml:"automatic_deletion"`
	DeletionSchedule string `yaml:"deletion_schedule"`
	ArchivingEnabled bool `yaml:"archiving_enabled"`
	ArchiveLocation string `yaml:"archive_location"`
}

// ConsentManagementConfig contains consent management settings
type ConsentManagementConfig struct {
	Enabled bool `yaml:"enabled"`
	ConsentRequired bool `yaml:"consent_required"`
	ConsentGranularity string `yaml:"consent_granularity"` // global, feature, data_type
	ConsentStorage string `yaml:"consent_storage"`
	ConsentExpiry string `yaml:"consent_expiry"`
	WithdrawalEnabled bool `yaml:"withdrawal_enabled"`
}

// DataSubjectRightsConfig contains data subject rights settings
type DataSubjectRightsConfig struct {
	Enabled bool `yaml:"enabled"`
	AccessRight bool `yaml:"access_right"`
	RectificationRight bool `yaml:"rectification_right"`
	ErasureRight bool `yaml:"erasure_right"`
	PortabilityRight bool `yaml:"portability_right"`
	ObjectionRight bool `yaml:"objection_right"`
	RequestProcessingTime string `yaml:"request_processing_time"`
}

// IntegrationsConfig contains integration settings
type IntegrationsConfig struct {
	CI *CIIntegrationConfig `yaml:"ci"`
	IDE *IDEIntegrationConfig `yaml:"ide"`
	PackageManagers *PackageManagersConfig `yaml:"package_managers"`
	SecurityTools *SecurityToolsConfig `yaml:"security_tools"`
	Notifications *NotificationsConfig `yaml:"notifications"`
	Webhooks *WebhooksConfig `yaml:"webhooks"`
	APIs *APIsConfig `yaml:"apis"`
}

// CIIntegrationConfig contains CI/CD integration settings
type CIIntegrationConfig struct {
	Enabled bool `yaml:"enabled"`
	Providers []string `yaml:"providers"` // github, gitlab, jenkins, etc.
	FailOnFindings bool `yaml:"fail_on_findings"`
	SeverityThreshold string `yaml:"severity_threshold"`
	ReportFormat string `yaml:"report_format"`
	ArtifactUpload bool `yaml:"artifact_upload"`
	BadgeGeneration bool `yaml:"badge_generation"`
	PullRequestComments bool `yaml:"pull_request_comments"`
}

// IDEIntegrationConfig contains IDE integration settings
type IDEIntegrationConfig struct {
	Enabled bool `yaml:"enabled"`
	LanguageServer bool `yaml:"language_server"`
	RealTimeScanning bool `yaml:"real_time_scanning"`
	InlineWarnings bool `yaml:"inline_warnings"`
	QuickFixes bool `yaml:"quick_fixes"`
	CodeCompletion bool `yaml:"code_completion"`
	Refactoring bool `yaml:"refactoring"`
}

// PackageManagersConfig contains package manager integration settings
type PackageManagersConfig struct {
	NPM *PackageManagerConfig `yaml:"npm"`
	PyPI *PackageManagerConfig `yaml:"pypi"`
	RubyGems *PackageManagerConfig `yaml:"rubygems"`
	Cargo *PackageManagerConfig `yaml:"cargo"`
	NuGet *PackageManagerConfig `yaml:"nuget"`
	Maven *PackageManagerConfig `yaml:"maven"`
	Gradle *PackageManagerConfig `yaml:"gradle"`
	Composer *PackageManagerConfig `yaml:"composer"`
	GoModules *PackageManagerConfig `yaml:"go_modules"`
}

// PackageManagerConfig contains individual package manager settings
type PackageManagerConfig struct {
	Enabled bool `yaml:"enabled"`
	RegistryURL string `yaml:"registry_url"`
	APIKey string `yaml:"api_key"`
	Timeout string `yaml:"timeout"`
	RetryAttempts int `yaml:"retry_attempts"`
	CacheEnabled bool `yaml:"cache_enabled"`
	CacheTTL string `yaml:"cache_ttl"`
	ProxyEnabled bool `yaml:"proxy_enabled"`
	ProxyURL string `yaml:"proxy_url"`
}

// SecurityToolsConfig contains security tools integration settings
type SecurityToolsConfig struct {
	SAST []SecurityToolConfig `yaml:"sast"`
	DAST []SecurityToolConfig `yaml:"dast"`
	SCA []SecurityToolConfig `yaml:"sca"`
	IAST []SecurityToolConfig `yaml:"iast"`
	SecretScanning []SecurityToolConfig `yaml:"secret_scanning"`
	ContainerScanning []SecurityToolConfig `yaml:"container_scanning"`
	InfrastructureScanning []SecurityToolConfig `yaml:"infrastructure_scanning"`
}

// SecurityToolConfig contains individual security tool settings
type SecurityToolConfig struct {
	Name string `yaml:"name"`
	Enabled bool `yaml:"enabled"`
	Endpoint string `yaml:"endpoint"`
	APIKey string `yaml:"api_key"`
	Timeout string `yaml:"timeout"`
	Configuration map[string]interface{} `yaml:"configuration"`
}

// NotificationsConfig contains notification settings
type NotificationsConfig struct {
	Enabled bool `yaml:"enabled"`
	Channels []NotificationChannel `yaml:"channels"`
	SeverityFilters []string `yaml:"severity_filters"`
	RateLimiting *NotificationRateLimiting `yaml:"rate_limiting"`
	Templates map[string]string `yaml:"templates"`
}

// NotificationChannel contains notification channel settings
type NotificationChannel struct {
	Type string `yaml:"type"` // email, slack, teams, webhook
	Enabled bool `yaml:"enabled"`
	Configuration map[string]interface{} `yaml:"configuration"`
	Filters []string `yaml:"filters"`
}

// NotificationRateLimiting contains notification rate limiting settings
type NotificationRateLimiting struct {
	Enabled bool `yaml:"enabled"`
	MaxNotificationsPerHour int `yaml:"max_notifications_per_hour"`
	BurstSize int `yaml:"burst_size"`
	CooldownPeriod string `yaml:"cooldown_period"`
}

// WebhooksConfig contains webhook settings
type WebhooksConfig struct {
	Enabled bool `yaml:"enabled"`
	Endpoints []WebhookEndpoint `yaml:"endpoints"`
	RetryPolicy *WebhookRetryPolicy `yaml:"retry_policy"`
	Security *WebhookSecurity `yaml:"security"`
}

// WebhookEndpoint contains webhook endpoint settings
type WebhookEndpoint struct {
	URL string `yaml:"url"`
	Enabled bool `yaml:"enabled"`
	Events []string `yaml:"events"`
	Headers map[string]string `yaml:"headers"`
	Timeout string `yaml:"timeout"`
	Secret string `yaml:"secret"`
}

// WebhookRetryPolicy contains webhook retry policy settings
type WebhookRetryPolicy struct {
	MaxRetries int `yaml:"max_retries"`
	InitialDelay string `yaml:"initial_delay"`
	MaxDelay string `yaml:"max_delay"`
	BackoffMultiplier float64 `yaml:"backoff_multiplier"`
}

// WebhookSecurity contains webhook security settings
type WebhookSecurity struct {
	SignatureValidation bool `yaml:"signature_validation"`
	SignatureHeader string `yaml:"signature_header"`
	SignatureAlgorithm string `yaml:"signature_algorithm"`
	TimestampValidation bool `yaml:"timestamp_validation"`
	TimestampTolerance string `yaml:"timestamp_tolerance"`
}

// APIsConfig contains API integration settings
type APIsConfig struct {
	REST *RESTAPIConfig `yaml:"rest"`
	GraphQL *GraphQLAPIConfig `yaml:"graphql"`
	gRPC *GRPCAPIConfig `yaml:"grpc"`
	WebSocket *WebSocketAPIConfig `yaml:"websocket"`
}

// RESTAPIConfig contains REST API settings
type RESTAPIConfig struct {
	Enabled bool `yaml:"enabled"`
	Host string `yaml:"host"`
	Port int `yaml:"port"`
	BasePath string `yaml:"base_path"`
	Versioning *APIVersioning `yaml:"versioning"`
	Authentication *APIAuthentication `yaml:"authentication"`
	RateLimiting *APIRateLimiting `yaml:"rate_limiting"`
	CORS *CORSConfig `yaml:"cors"`
	Documentation *APIDocumentation `yaml:"documentation"`
}

// GraphQLAPIConfig contains GraphQL API settings
type GraphQLAPIConfig struct {
	Enabled bool `yaml:"enabled"`
	Host string `yaml:"host"`
	Port int `yaml:"port"`
	Path string `yaml:"path"`
	Playground bool `yaml:"playground"`
	Introspection bool `yaml:"introspection"`
	ComplexityAnalysis bool `yaml:"complexity_analysis"`
	MaxComplexity int `yaml:"max_complexity"`
	MaxDepth int `yaml:"max_depth"`
}

// GRPCAPIConfig contains gRPC API settings
type GRPCAPIConfig struct {
	Enabled bool `yaml:"enabled"`
	Host string `yaml:"host"`
	Port int `yaml:"port"`
	TLSEnabled bool `yaml:"tls_enabled"`
	Reflection bool `yaml:"reflection"`
	HealthCheck bool `yaml:"health_check"`
	MaxMessageSize string `yaml:"max_message_size"`
	Keepalive *GRPCKeepalive `yaml:"keepalive"`
}

// WebSocketAPIConfig contains WebSocket API settings
type WebSocketAPIConfig struct {
	Enabled bool `yaml:"enabled"`
	Host string `yaml:"host"`
	Port int `yaml:"port"`
	Path string `yaml:"path"`
	MaxConnections int `yaml:"max_connections"`
	MessageSizeLimit string `yaml:"message_size_limit"`
	PingInterval string `yaml:"ping_interval"`
	PongTimeout string `yaml:"pong_timeout"`
}

// APIVersioning contains API versioning settings
type APIVersioning struct {
	Enabled bool `yaml:"enabled"`
	Strategy string `yaml:"strategy"` // header, query, path
	HeaderName string `yaml:"header_name"`
	QueryParam string `yaml:"query_param"`
	DefaultVersion string `yaml:"default_version"`
	SupportedVersions []string `yaml:"supported_versions"`
}

// APIAuthentication contains API authentication settings
type APIAuthentication struct {
	Enabled bool `yaml:"enabled"`
	Methods []string `yaml:"methods"` // api_key, bearer, oauth2, jwt
	APIKeyHeader string `yaml:"api_key_header"`
	JWTSecret string `yaml:"jwt_secret"`
	JWTExpiry string `yaml:"jwt_expiry"`
	OAuth2Config *OAuth2Config `yaml:"oauth2_config"`
}

// OAuth2Config contains OAuth2 settings
type OAuth2Config struct {
	ClientID string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
	AuthURL string `yaml:"auth_url"`
	TokenURL string `yaml:"token_url"`
	RedirectURL string `yaml:"redirect_url"`
	Scopes []string `yaml:"scopes"`
}

// APIRateLimiting contains API rate limiting settings
type APIRateLimiting struct {
	Enabled bool `yaml:"enabled"`
	Global *RateLimitRule `yaml:"global"`
	PerUser *RateLimitRule `yaml:"per_user"`
	PerEndpoint map[string]*RateLimitRule `yaml:"per_endpoint"`
	Storage string `yaml:"storage"` // memory, redis
	KeyGenerator string `yaml:"key_generator"`
}

// RateLimitRule contains rate limit rule settings
type RateLimitRule struct {
	RequestsPerSecond int `yaml:"requests_per_second"`
	RequestsPerMinute int `yaml:"requests_per_minute"`
	RequestsPerHour int `yaml:"requests_per_hour"`
	RequestsPerDay int `yaml:"requests_per_day"`
	BurstSize int `yaml:"burst_size"`
}

// CORSConfig contains CORS settings
type CORSConfig struct {
	Enabled bool `yaml:"enabled"`
	AllowedOrigins []string `yaml:"allowed_origins"`
	AllowedMethods []string `yaml:"allowed_methods"`
	AllowedHeaders []string `yaml:"allowed_headers"`
	ExposedHeaders []string `yaml:"exposed_headers"`
	AllowCredentials bool `yaml:"allow_credentials"`
	MaxAge string `yaml:"max_age"`
}

// APIDocumentation contains API documentation settings
type APIDocumentation struct {
	Enabled bool `yaml:"enabled"`
	SwaggerEnabled bool `yaml:"swagger_enabled"`
	SwaggerPath string `yaml:"swagger_path"`
	RedocEnabled bool `yaml:"redoc_enabled"`
	RedocPath string `yaml:"redoc_path"`
	OpenAPISpec string `yaml:"openapi_spec"`
	Title string `yaml:"title"`
	Description string `yaml:"description"`
	Version string `yaml:"version"`
	Contact *APIContact `yaml:"contact"`
	License *APILicense `yaml:"license"`
}

// APIContact contains API contact information
type APIContact struct {
	Name string `yaml:"name"`
	Email string `yaml:"email"`
	URL string `yaml:"url"`
}

// APILicense contains API license information
type APILicense struct {
	Name string `yaml:"name"`
	URL string `yaml:"url"`
}

// GRPCKeepalive contains gRPC keepalive settings
type GRPCKeepalive struct {
	Time string `yaml:"time"`
	Timeout string `yaml:"timeout"`
	PermitWithoutStream bool `yaml:"permit_without_stream"`
	MinTime string `yaml:"min_time"`
}



// MonitoringConfig contains monitoring settings
type MonitoringConfig struct {
	Enabled bool `yaml:"enabled"`
	Metrics *MetricsConfig `yaml:"metrics"`
	Tracing *TracingConfig `yaml:"tracing"`
	Profiling *ProfilingConfig `yaml:"profiling"`
	HealthChecks *HealthChecksConfig `yaml:"health_checks"`
	Alerting *AlertingConfig `yaml:"alerting"`
}

// MetricsConfig contains metrics settings
type MetricsConfig struct {
	Enabled bool `yaml:"enabled"`
	Provider string `yaml:"provider"` // prometheus, statsd, datadog
	Endpoint string `yaml:"endpoint"`
	Interval string `yaml:"interval"`
	Namespace string `yaml:"namespace"`
	Labels map[string]string `yaml:"labels"`
	CustomMetrics []CustomMetric `yaml:"custom_metrics"`
	HistogramBuckets []float64 `yaml:"histogram_buckets"`
}

// CustomMetric contains custom metric settings
type CustomMetric struct {
	Name string `yaml:"name"`
	Type string `yaml:"type"` // counter, gauge, histogram, summary
	Description string `yaml:"description"`
	Labels []string `yaml:"labels"`
	Buckets []float64 `yaml:"buckets,omitempty"`
	Objectives map[float64]float64 `yaml:"objectives,omitempty"`
}

// TracingConfig contains tracing settings
type TracingConfig struct {
	Enabled bool `yaml:"enabled"`
	Provider string `yaml:"provider"` // jaeger, zipkin, datadog
	Endpoint string `yaml:"endpoint"`
	SamplingRate float64 `yaml:"sampling_rate"`
	ServiceName string `yaml:"service_name"`
	ServiceVersion string `yaml:"service_version"`
	Environment string `yaml:"environment"`
	Tags map[string]string `yaml:"tags"`
	BatchTimeout string `yaml:"batch_timeout"`
	MaxPacketSize int `yaml:"max_packet_size"`
}

// ProfilingConfig contains profiling settings
type ProfilingConfig struct {
	Enabled bool `yaml:"enabled"`
	CPUProfiling bool `yaml:"cpu_profiling"`
	MemoryProfiling bool `yaml:"memory_profiling"`
	GoroutineProfiling bool `yaml:"goroutine_profiling"`
	BlockProfiling bool `yaml:"block_profiling"`
	MutexProfiling bool `yaml:"mutex_profiling"`
	ProfilePath string `yaml:"profile_path"`
	ProfileDuration string `yaml:"profile_duration"`
	ProfileInterval string `yaml:"profile_interval"`
	HTTPEndpoint string `yaml:"http_endpoint"`
}

// HealthChecksConfig contains health check settings
type HealthChecksConfig struct {
	Enabled bool `yaml:"enabled"`
	Endpoint string `yaml:"endpoint"`
	Interval string `yaml:"interval"`
	Timeout string `yaml:"timeout"`
	Checks []HealthCheck `yaml:"checks"`
	FailureThreshold int `yaml:"failure_threshold"`
	SuccessThreshold int `yaml:"success_threshold"`
}

// HealthCheck contains individual health check settings
type HealthCheck struct {
	Name string `yaml:"name"`
	Type string `yaml:"type"` // http, tcp, exec, custom
	Enabled bool `yaml:"enabled"`
	Interval string `yaml:"interval"`
	Timeout string `yaml:"timeout"`
	Configuration map[string]interface{} `yaml:"configuration"`
}

// AlertingConfig contains alerting settings
type AlertingConfig struct {
	Enabled bool `yaml:"enabled"`
	Providers []AlertProvider `yaml:"providers"`
	Rules []AlertRule `yaml:"rules"`
	Silencing *AlertSilencing `yaml:"silencing"`
	Escalation *AlertEscalation `yaml:"escalation"`
}

// AlertProvider contains alert provider settings
type AlertProvider struct {
	Name string `yaml:"name"`
	Type string `yaml:"type"` // email, slack, pagerduty, webhook
	Enabled bool `yaml:"enabled"`
	Configuration map[string]interface{} `yaml:"configuration"`
}

// AlertRule contains alert rule settings
type AlertRule struct {
	Name string `yaml:"name"`
	Enabled bool `yaml:"enabled"`
	Condition string `yaml:"condition"`
	Severity string `yaml:"severity"`
	Duration string `yaml:"duration"`
	Labels map[string]string `yaml:"labels"`
	Annotations map[string]string `yaml:"annotations"`
	Providers []string `yaml:"providers"`
}

// AlertSilencing contains alert silencing settings
type AlertSilencing struct {
	Enabled bool `yaml:"enabled"`
	DefaultDuration string `yaml:"default_duration"`
	MaxDuration string `yaml:"max_duration"`
	Matchers []SilenceMatcher `yaml:"matchers"`
}

// SilenceMatcher contains silence matcher settings
type SilenceMatcher struct {
	Name string `yaml:"name"`
	Value string `yaml:"value"`
	IsRegex bool `yaml:"is_regex"`
}

// AlertEscalation contains alert escalation settings
type AlertEscalation struct {
	Enabled bool `yaml:"enabled"`
	Levels []EscalationLevel `yaml:"levels"`
	DefaultLevel int `yaml:"default_level"`
}

// EscalationLevel contains escalation level settings
type EscalationLevel struct {
	Level int `yaml:"level"`
	Delay string `yaml:"delay"`
	Providers []string `yaml:"providers"`
	Conditions []string `yaml:"conditions"`
}

// LoggingConfig contains logging settings
type LoggingConfig struct {
	Level      string         `yaml:"level" json:"level"`
	Format     string         `yaml:"format" json:"format"`
	Output     string         `yaml:"output" json:"output"`
	Structured bool           `yaml:"structured" json:"structured"`
	Timestamp  bool           `yaml:"timestamp" json:"timestamp"`
	Caller     bool           `yaml:"caller" json:"caller"`
	Prefix     string         `yaml:"prefix" json:"prefix"`
	Rotation   RotationConfig `yaml:"rotation" json:"rotation"`
}

// RotationConfig contains log rotation settings
type RotationConfig struct {
	Enabled    bool `yaml:"enabled" json:"enabled"`
	MaxSize    int  `yaml:"max_size" json:"max_size"`
	MaxAge     int  `yaml:"max_age" json:"max_age"`
	MaxBackups int  `yaml:"max_backups" json:"max_backups"`
	Compress   bool `yaml:"compress" json:"compress"`
}

// APIConfig contains API server settings
type APIConfig struct {
	Host    string    `yaml:"host" json:"host"`
	Port    int       `yaml:"port" json:"port"`
	BaseURL string    `yaml:"base_url" json:"base_url"`
	APIKey  string    `yaml:"api_key" json:"api_key"`
	TLS     TLSConfig `yaml:"tls" json:"tls"`
	Auth    AuthConfig `yaml:"auth" json:"auth"`
}

// TLSConfig contains TLS settings
type TLSConfig struct {
	Enabled  bool   `yaml:"enabled" json:"enabled"`
	CertFile string `yaml:"cert_file" json:"cert_file"`
	KeyFile  string `yaml:"key_file" json:"key_file"`
}

// AuthConfig contains authentication settings
type AuthConfig struct {
	Enabled   bool   `yaml:"enabled" json:"enabled"`
	JWTSecret string `yaml:"jwt_secret" json:"jwt_secret"`
}

// DatabaseConfig contains database settings
type DatabaseConfig struct {
	Host     string      `yaml:"host" json:"host"`
	Port     int         `yaml:"port" json:"port"`
	Name     string      `yaml:"name" json:"name"`
	User     string      `yaml:"user" json:"user"`
	Password string      `yaml:"password" json:"password"`
	SSLMode  string      `yaml:"ssl_mode" json:"ssl_mode"`
	Redis    RedisConfig `yaml:"redis" json:"redis"`
}

// RedisConfig is defined in config_manager.go

// ValidateConfig validates the configuration
func ValidateConfig(cfg *Config) error {
	if cfg == nil {
		return fmt.Errorf("config cannot be nil")
	}

	// Validate API config
	if cfg.API != nil {
		if cfg.API.Port <= 0 || cfg.API.Port > 65535 {
			return fmt.Errorf("invalid API port: %d", cfg.API.Port)
		}
	}

	// Validate Detection config
	if cfg.Detection != nil {
		if cfg.Detection.Thresholds.Similarity < 0 || cfg.Detection.Thresholds.Similarity > 1 {
			return fmt.Errorf("invalid similarity threshold: %f", cfg.Detection.Thresholds.Similarity)
		}
		if cfg.Detection.Thresholds.Confidence < 0 || cfg.Detection.Thresholds.Confidence > 1 {
			return fmt.Errorf("invalid confidence threshold: %f", cfg.Detection.Thresholds.Confidence)
		}
	}

	return nil
}

// ToYAML converts the config to YAML format
func (c *Config) ToYAML() ([]byte, error) {
	return yaml.Marshal(c)
}

// FromYAML loads config from YAML data
func (c *Config) FromYAML(data []byte) error {
	return yaml.Unmarshal(data, c)
}

// ScannerConfig contains scanner settings
type ScannerConfig struct {
	Enabled        bool `yaml:"enabled" json:"enabled"`
	Concurrency    int  `yaml:"concurrency" json:"concurrency"`
	IncludeDevDeps bool `yaml:"include_dev_deps" json:"include_dev_deps"`
	EnrichMetadata bool `yaml:"enrich_metadata" json:"enrich_metadata"`
}

// PluginsConfig contains plugin settings
type PluginsConfig struct {
	Enabled         bool          `yaml:"enabled" json:"enabled"`
	Path            string        `yaml:"path" json:"path"`
	PluginDirectory string        `yaml:"plugin_directory" json:"plugin_directory"`
	AutoLoad        bool          `yaml:"auto_load" json:"auto_load"`
	Plugins         []PluginEntry `yaml:"plugins" json:"plugins"`
}

// PluginEntry represents a plugin configuration entry
type PluginEntry struct {
	Name    string                 `yaml:"name" json:"name"`
	Path    string                 `yaml:"path" json:"path"`
	Enabled bool                   `yaml:"enabled" json:"enabled"`
	Config  map[string]interface{} `yaml:"config" json:"config"`
}

// CacheConfig contains cache settings
type CacheConfig struct {
	Enabled  bool          `yaml:"enabled" json:"enabled"`
	TTL      time.Duration `yaml:"ttl" json:"ttl"`
	CacheDir string        `yaml:"cache_dir" json:"cache_dir"`
}

// Note: EnhancedConfig functions have been consolidated into the unified Config structure above
// Use LoadConfig(), SaveConfig(), and NewDefaultConfig() instead

// EnhancedConfig methods have been consolidated into the unified Config structure.
// Use NewDefaultConfig() for default configuration initialization.

// getDefaultConfigPath returns the default configuration file path
func getDefaultConfigPath() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "typosentinel.yaml"
	}
	return filepath.Join(homeDir, ".typosentinel", "config.yaml")
}

// GetConfigDir returns the configuration directory
func GetConfigDir() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "."
	}
	return filepath.Join(homeDir, ".typosentinel")
}

// EnsureConfigDir ensures the configuration directory exists
func EnsureConfigDir() error {
	configDir := GetConfigDir()
	return os.MkdirAll(configDir, 0755)
}

// EnhancedConfig merge functionality has been consolidated into the unified Config structure.

// EnhancedConfig clone functionality has been consolidated into the unified Config structure.

// EnhancedConfig YAML functionality has been consolidated into the unified Config structure.
// Use LoadConfig() and SaveConfig() methods instead.

// EnhancedConfig feature flag functionality has been consolidated into the unified Config structure.

// EnhancedConfig feature checking functionality has been consolidated into the unified Config structure.

// EnhancedConfig timeout functionality has been consolidated into the unified Config structure.

// EnhancedConfig retry functionality has been consolidated into the unified Config structure.

// EnhancedConfig conversion functionality has been consolidated into the unified Config structure.

// EnhancedConfig summary functionality has been consolidated into the unified Config structure.

// LoadConfig loads the configuration from a file
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Start with default configuration
	config := NewDefaultConfig()
	
	// Unmarshal the file data into the default config to override defaults
	if err := yaml.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return config, nil
}

// SaveConfig saves the configuration to a file
func (c *Config) SaveConfig(path string) error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// NewDefaultConfig creates a new default configuration
func NewDefaultConfig() *Config {
	return &Config{
		Verbose: false,
		Debug:   false,
		API: &APIConfig{
			Host: "localhost",
			Port: 8080,
		},
		Database: &DatabaseConfig{
			Host:    "localhost",
			Port:    5432,
			Name:    "typosentinel",
			User:    "postgres",
			SSLMode: "disable",
		},
		Core: &CoreConfig{
			Version: "1.0.0",
			Environment: "development",
			Debug: false,
			Verbose: false,
			MaxConcurrency: 10,
			Timeout: 30 * time.Second,
			RetryAttempts: 3,
			RetryDelay: "1s",
		},
		Logging: &LoggingConfig{
			Level: "info",
			Format: "json",
			Output: "stdout",
			Structured: true,
		},
		Performance: &PerformanceConfig{
			MaxConcurrency: 10,
			WorkerPoolSize: 5,
			QueueSize: 100,
			BatchSize: 10,
		},
		Detection: &DetectionConfig{
			Enabled:               true,
			MinPackageNameLength: 3,
			EnhancedTyposquatting: true,
			HomoglyphDetection:   true,
			DependencyConfusion:  true,
			ReputationScoring:    true,
			Thresholds: ThresholdConfig{
				Similarity: 0.8,
				Confidence: 0.7,
				Reputation: 0.6,
			},
			Algorithms: AlgorithmConfig{
				Lexical:   true,
				Homoglyph: true,
				ML:        true,
			},
		},
		Scanner: &ScannerConfig{
			Enabled:        true,
			Concurrency:    4,
			IncludeDevDeps: false,
			EnrichMetadata: true,
		},
		Plugins: &PluginsConfig{
			Enabled:         false,
			Path:            "./plugins",
			PluginDirectory: "./plugins",
			AutoLoad:        false,
			Plugins:         []PluginEntry{},
		},
		Cache: &CacheConfig{
			Enabled:  true,
			TTL:      time.Hour,
			CacheDir: "./cache",
		},
		MLService: &MLServiceConfig{
			Enabled:    false,
			Endpoint:   "http://localhost:8001",
			APIKey:     "",
			Timeout:    30 * time.Second,
			MaxRetries: 3,
			BatchSize:  10,
		},
		Registries: []RegistryConfig{},
	}
}