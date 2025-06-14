package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// EnhancedConfig represents the enhanced configuration for TypoSentinel
type EnhancedConfig struct {
	// Core configuration
	Core *CoreConfig `yaml:"core"`
	
	// Analysis engines
	StaticAnalysis *StaticAnalysisConfig `yaml:"static_analysis"`
	DynamicAnalysis *DynamicAnalysisConfig `yaml:"dynamic_analysis"`
	MLAnalysis *MLAnalysisConfig `yaml:"ml_analysis"`
	ProvenanceAnalysis *ProvenanceAnalysisConfig `yaml:"provenance_analysis"`
	
	// Detection and scanning
	TypoDetection *TypoDetectionConfig `yaml:"typo_detection"`
	MalwareDetection *MalwareDetectionConfig `yaml:"malware_detection"`
	VulnerabilityScanning *VulnerabilityScanningConfig `yaml:"vulnerability_scanning"`
	
	// Reporting and output
	Reporting *ReportingConfig `yaml:"reporting"`
	Output *OutputConfig `yaml:"output"`
	
	// Performance and caching
	Performance *PerformanceConfig `yaml:"performance"`
	Caching *CachingConfig `yaml:"caching"`
	
	// Security and privacy
	Security *SecurityConfig `yaml:"security"`
	Privacy *PrivacyConfig `yaml:"privacy"`
	
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
	Timeout string `yaml:"timeout"`
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

// LoggingConfig contains logging settings
type LoggingConfig struct {
	Level string `yaml:"level"` // debug, info, warn, error, fatal
	Format string `yaml:"format"` // json, text, structured
	Output []string `yaml:"output"` // stdout, stderr, file, syslog
	File *LogFileConfig `yaml:"file"`
	Syslog *SyslogConfig `yaml:"syslog"`
	Structured *StructuredLoggingConfig `yaml:"structured"`
	Sampling *LogSamplingConfig `yaml:"sampling"`
	Hooks []LogHookConfig `yaml:"hooks"`
	Fields map[string]interface{} `yaml:"fields"`
	Redaction *LogRedactionConfig `yaml:"redaction"`
}

// LogFileConfig contains log file settings
type LogFileConfig struct {
	Path string `yaml:"path"`
	MaxSize string `yaml:"max_size"`
	MaxAge string `yaml:"max_age"`
	MaxBackups int `yaml:"max_backups"`
	Compress bool `yaml:"compress"`
	LocalTime bool `yaml:"local_time"`
}

// SyslogConfig contains syslog settings
type SyslogConfig struct {
	Network string `yaml:"network"`
	Address string `yaml:"address"`
	Priority string `yaml:"priority"`
	Tag string `yaml:"tag"`
	Facility string `yaml:"facility"`
}

// StructuredLoggingConfig contains structured logging settings
type StructuredLoggingConfig struct {
	Enabled bool `yaml:"enabled"`
	TimestampFormat string `yaml:"timestamp_format"`
	TimestampKey string `yaml:"timestamp_key"`
	LevelKey string `yaml:"level_key"`
	MessageKey string `yaml:"message_key"`
	CallerKey string `yaml:"caller_key"`
	StacktraceKey string `yaml:"stacktrace_key"`
	ErrorKey string `yaml:"error_key"`
}

// LogSamplingConfig contains log sampling settings
type LogSamplingConfig struct {
	Enabled bool `yaml:"enabled"`
	Initial int `yaml:"initial"`
	Thereafter int `yaml:"thereafter"`
	Tick string `yaml:"tick"`
}

// LogHookConfig contains log hook settings
type LogHookConfig struct {
	Type string `yaml:"type"`
	Enabled bool `yaml:"enabled"`
	Levels []string `yaml:"levels"`
	Configuration map[string]interface{} `yaml:"configuration"`
}

// LogRedactionConfig contains log redaction settings
type LogRedactionConfig struct {
	Enabled bool `yaml:"enabled"`
	Patterns []string `yaml:"patterns"`
	Replacement string `yaml:"replacement"`
	Fields []string `yaml:"fields"`
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

// LoadEnhancedConfig loads enhanced configuration from file
func LoadEnhancedConfig(configPath string) (*EnhancedConfig, error) {
	if configPath == "" {
		configPath = getDefaultConfigPath()
	}
	
	// Check if config file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		// Create default config if it doesn't exist
		defaultConfig := DefaultEnhancedConfig()
		if err := SaveEnhancedConfig(defaultConfig, configPath); err != nil {
			return nil, fmt.Errorf("failed to create default config: %w", err)
		}
		return defaultConfig, nil
	}
	
	// Read config file
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}
	
	// Parse YAML
	var config EnhancedConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}
	
	// Validate and set defaults
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}
	
	config.SetDefaults()
	
	return &config, nil
}

// SaveEnhancedConfig saves enhanced configuration to file
func SaveEnhancedConfig(config *EnhancedConfig, configPath string) error {
	// Create directory if it doesn't exist
	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}
	
	// Marshal to YAML
	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	
	// Write to file
	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}
	
	return nil
}

// DefaultEnhancedConfig returns default enhanced configuration
func DefaultEnhancedConfig() *EnhancedConfig {
	return &EnhancedConfig{
		Core: &CoreConfig{
			Version: "1.0.0",
			Environment: "development",
			Debug: false,
			Verbose: false,
			Quiet: false,
			DataDir: filepath.Join(os.TempDir(), "typosentinel"),
			TempDir: filepath.Join(os.TempDir(), "typosentinel-temp"),
			MaxConcurrency: 10,
			Timeout: "30s",
			RetryAttempts: 3,
			RetryDelay: "1s",
		},
		StaticAnalysis: &StaticAnalysisConfig{
			Enabled: true,
			MaxFileSize: "10MB",
			MaxFiles: 1000,
			Timeout: "5m",
			DeepScan: false,
			ScanArchives: true,
			ScanBinaries: false,
			ScanScripts: true,
			ScanManifests: true,
			RiskThreshold: 0.7,
			Parallelism: 4,
		},
		DynamicAnalysis: &DynamicAnalysisConfig{
			Enabled: true,
			SandboxType: "docker",
			SandboxImage: "ubuntu:20.04",
			Timeout: "2m",
			MaxMemory: "512MB",
			MaxCPU: "1",
			NetworkIsolation: true,
			FileSystemIsolation: true,
			MonitorNetworkActivity: true,
			MonitorFileActivity: true,
			MonitorProcessActivity: true,
			ExecuteInstallScripts: false,
			ExecuteMainScript: false,
			CleanupAfterAnalysis: true,
			MaxExecutionTime: "30s",
			ResourceLimits: &ResourceLimits{
				MaxMemoryMB: 512,
				MaxCPUPercent: 50,
				MaxDiskMB: 1024,
				MaxNetworkKBps: 1024,
				MaxProcesses: 10,
				MaxOpenFiles: 100,
			},
		},
		MLAnalysis: &MLAnalysisConfig{
			Enabled: true,
			EmbeddingModel: "sentence-transformers/all-MiniLM-L6-v2",
			EmbeddingDimensions: 384,
			SimilarityThreshold: 0.8,
			MaliciousThreshold: 0.7,
			ReputationThreshold: 0.6,
			BatchSize: 32,
			MaxFeatures: 1000,
			CacheEmbeddings: true,
			ParallelProcessing: true,
			GPUAcceleration: false,
			FeatureStore: &FeatureStoreConfig{
				Enabled: true,
				Backend: "memory",
				TTL: "24h",
				MaxSize: 1000,
				CompressionEnabled: true,
				EncryptionEnabled: false,
				BackupEnabled: false,
				CleanupInterval: "1h",
			},
			ModelUpdates: &ModelUpdatesConfig{
				Enabled: false,
				UpdateInterval: "24h",
				AutoUpdate: false,
				VerifySignatures: true,
				BackupOldModels: true,
				MaxModelVersions: 5,
			},
		},
		ProvenanceAnalysis: &ProvenanceAnalysisConfig{
			Enabled: true,
			SigstoreEnabled: true,
			SigstoreRekorURL: "https://rekor.sigstore.dev",
			SigstoreFulcioURL: "https://fulcio.sigstore.dev",
			SigstoreCTLogURL: "https://ctfe.sigstore.dev",
			SLSAEnabled: true,
			SLSAMinLevel: 2,
			SLSARequiredBuilders: []string{
				"https://github.com/slsa-framework/slsa-github-generator",
			},
			VerifySignatures: true,
			VerifyProvenance: true,
			VerifyIntegrity: true,
			RequireTransparencyLog: false,
			TrustedPublishers: []string{},
			TrustedSigners: []string{},
			TrustedBuilders: []string{
				"https://github.com/slsa-framework/slsa-github-generator",
			},
			Timeout: "30s",
			RetryAttempts: 3,
			Verbose: false,
		},
		TypoDetection: &TypoDetectionConfig{
			Enabled: true,
			Algorithms: []string{"levenshtein", "jaro_winkler"},
			Threshold: 0.8,
			MaxDistance: 3,
			CheckSimilarNames: true,
			CheckHomoglyphs: true,
			CheckKeyboardLayout: true,
			CheckCommonTypos: true,
			LanguageSpecific: false,
			CaseSensitive: false,
		},
		MalwareDetection: &MalwareDetectionConfig{
			Enabled: true,
			HeuristicAnalysis: true,
			BehavioralAnalysis: true,
			SandboxAnalysis: true,
			CloudScanning: true,
			RealTimeProtection: true,
			QuarantineEnabled: true,
			UpdateInterval: "24h",
			MaxScanSize: "100MB",
			ScanTimeout: "5m",
			ExcludeExtensions: []string{".jpg", ".png", ".gif", ".mp4"},
			IncludeExtensions: []string{".js", ".py", ".go", ".java", ".php"},
		},
		VulnerabilityScanning: &VulnerabilityScanningConfig{
			Enabled: true,
			Databases: []string{"osv", "nvd"},
			APIKeys: make(map[string]string),
			UpdateInterval: "24h",
			SeverityThreshold: "medium",
			IncludeDevDependencies: false,
			IncludeTransitiveDependencies: true,
			MaxDepth: 5,
			FailOnVulnerabilities: false,
			Timeout: "2m",
			RetryAttempts: 3,
			CacheResults: true,
			CacheTTL: "1h",
		},
		Reporting: &ReportingConfig{
			Enabled: true,
			Formats: []string{"json"},
			IncludeSummary: true,
			IncludeDetails: true,
			IncludeRecommendations: true,
			IncludeMetadata: true,
			IncludeTimestamps: true,
			GroupByCategory: true,
			SortBySeverity: true,
			MaxReportSize: "10MB",
			CompressionEnabled: false,
			EncryptionEnabled: false,
		},
		Output: &OutputConfig{
			Format: "json",
			Stdout: true,
			ColorEnabled: true,
			ProgressBar: true,
			VerboseOutput: false,
			QuietMode: false,
			Timestamps: true,
			LineNumbers: false,
			PrettyPrint: true,
			MaxWidth: 120,
			TruncateOutput: false,
			MaxLines: 1000,
		},
		Performance: &PerformanceConfig{
			MaxConcurrency: 10,
			WorkerPoolSize: 5,
			QueueSize: 100,
			BatchSize: 10,
			MemoryLimit: "1GB",
			CPULimit: "2",
			Timeouts: &TimeoutConfig{
				Global: "30s",
				Connection: "10s",
				Read: "30s",
				Write: "30s",
				Idle: "60s",
				KeepAlive: "30s",
				Shutdown: "10s",
			},
			RateLimiting: &RateLimitingConfig{
				Enabled: false,
				RequestsPerSecond: 100,
				BurstSize: 200,
				WindowSize: "1m",
				BackoffStrategy: "exponential",
				MaxRetries: 3,
				RetryDelay: "1s",
			},
			CircuitBreaker: &CircuitBreakerConfig{
				Enabled: false,
				FailureThreshold: 5,
				SuccessThreshold: 3,
				Timeout: "60s",
				MaxRequests: 100,
				Interval: "10s",
			},
		},
		Caching: &CachingConfig{
			Enabled: true,
			Backend: "memory",
			TTL: "1h",
			MaxSize: "100MB",
			MaxEntries: 10000,
			EvictionPolicy: "lru",
			CompressionEnabled: false,
			EncryptionEnabled: false,
			PersistenceEnabled: false,
			ClusteringEnabled: false,
			ReplicationFactor: 1,
			ConsistencyLevel: "eventual",
		},
		Security: &SecurityConfig{
			EncryptionEnabled: false,
			EncryptionAlgorithm: "AES-256-GCM",
			KeyManagement: &KeyManagementConfig{
				Provider: "local",
				KeyRotationEnabled: false,
				KeyRotationInterval: "30d",
				KeyDerivationFunction: "PBKDF2",
				KeyStrength: 256,
			},
			Authentication: &AuthenticationConfig{
				Enabled: false,
				Method: "bearer",
				TokenExpiry: "1h",
				RefreshTokenEnabled: false,
				MFAEnabled: false,
				SessionTimeout: "24h",
			},
			Authorization: &AuthorizationConfig{
				Enabled: false,
				Model: "rbac",
				DefaultDeny: true,
				CacheEnabled: true,
				CacheTTL: "5m",
			},
			AuditLogging: &AuditLoggingConfig{
				Enabled: false,
				Level: "info",
				Format: "json",
				Output: "file",
				RotationEnabled: true,
				MaxSize: "100MB",
				MaxAge: "30d",
				MaxBackups: 10,
				CompressionEnabled: true,
			},
			SecureTransport: &SecureTransportConfig{
				TLSEnabled: false,
				TLSVersion: "1.3",
				InsecureSkipVerify: false,
				ClientAuth: "none",
			},
			InputValidation: &InputValidationConfig{
				Enabled: true,
				MaxInputSize: "10MB",
				SanitizationEnabled: true,
			},
			OutputSanitization: &OutputSanitizationConfig{
				Enabled: true,
				RedactSensitiveData: true,
				MaskingCharacter: "*",
				HashSensitiveData: false,
				HashAlgorithm: "SHA256",
			},
		},
		Privacy: &PrivacyConfig{
			DataMinimization: true,
			Anonymization: false,
			Pseudonymization: false,
			PrivacyByDesign: true,
			GDPRCompliance: false,
			CCPACompliance: false,
			DataRetention: &DataRetentionConfig{
				Enabled: true,
				DefaultRetentionPeriod: "30d",
				AutomaticDeletion: true,
				DeletionSchedule: "0 2 * * *",
				ArchivingEnabled: false,
			},
			ConsentManagement: &ConsentManagementConfig{
				Enabled: false,
				ConsentRequired: false,
				ConsentGranularity: "global",
				WithdrawalEnabled: true,
			},
			DataSubjectRights: &DataSubjectRightsConfig{
				Enabled: false,
				AccessRight: true,
				RectificationRight: true,
				ErasureRight: true,
				PortabilityRight: true,
				ObjectionRight: true,
				RequestProcessingTime: "30d",
			},
		},
		Integrations: &IntegrationsConfig{
			CI: &CIIntegrationConfig{
				Enabled: false,
				Providers: []string{"github", "gitlab"},
				FailOnFindings: false,
				SeverityThreshold: "high",
				ReportFormat: "json",
				ArtifactUpload: false,
				BadgeGeneration: false,
				PullRequestComments: false,
			},
			IDE: &IDEIntegrationConfig{
				Enabled: false,
				LanguageServer: false,
				RealTimeScanning: false,
				InlineWarnings: false,
				QuickFixes: false,
				CodeCompletion: false,
				Refactoring: false,
			},
			PackageManagers: &PackageManagersConfig{
				NPM: &PackageManagerConfig{
					Enabled: true,
					RegistryURL: "https://registry.npmjs.org",
					Timeout: "30s",
					RetryAttempts: 3,
					CacheEnabled: true,
					CacheTTL: "1h",
				},
				PyPI: &PackageManagerConfig{
					Enabled: true,
					RegistryURL: "https://pypi.org",
					Timeout: "30s",
					RetryAttempts: 3,
					CacheEnabled: true,
					CacheTTL: "1h",
				},
			},
			Notifications: &NotificationsConfig{
				Enabled: false,
				Channels: []NotificationChannel{},
				SeverityFilters: []string{"high", "critical"},
			},
			Webhooks: &WebhooksConfig{
				Enabled: false,
				Endpoints: []WebhookEndpoint{},
			},
			APIs: &APIsConfig{
				REST: &RESTAPIConfig{
					Enabled: false,
					Host: "localhost",
					Port: 8080,
					BasePath: "/api/v1",
				},
			},
		},
		Logging: &LoggingConfig{
			Level: "info",
			Format: "text",
			Output: []string{"stdout"},
			File: &LogFileConfig{
				Path: "typosentinel.log",
				MaxSize: "100MB",
				MaxAge: "30d",
				MaxBackups: 10,
				Compress: true,
				LocalTime: true,
			},
			Structured: &StructuredLoggingConfig{
				Enabled: false,
				TimestampFormat: "2006-01-02T15:04:05.000Z",
				TimestampKey: "timestamp",
				LevelKey: "level",
				MessageKey: "message",
				CallerKey: "caller",
				StacktraceKey: "stacktrace",
				ErrorKey: "error",
			},
			Redaction: &LogRedactionConfig{
				Enabled: true,
				Patterns: []string{"password", "token", "key", "secret"},
				Replacement: "[REDACTED]",
				Fields: []string{"password", "token", "api_key"},
			},
		},
		Monitoring: &MonitoringConfig{
			Enabled: false,
			Metrics: &MetricsConfig{
				Enabled: false,
				Provider: "prometheus",
				Interval: "15s",
				Namespace: "typosentinel",
				Labels: make(map[string]string),
				CustomMetrics: []CustomMetric{},
				HistogramBuckets: []float64{0.1, 0.5, 1.0, 2.5, 5.0, 10.0},
			},
			Tracing: &TracingConfig{
				Enabled: false,
				Provider: "jaeger",
				SamplingRate: 0.1,
				ServiceName: "typosentinel",
				ServiceVersion: "1.0.0",
				Environment: "development",
				Tags: make(map[string]string),
				BatchTimeout: "1s",
				MaxPacketSize: 65000,
			},
			Profiling: &ProfilingConfig{
				Enabled: false,
				CPUProfiling: false,
				MemoryProfiling: false,
				GoroutineProfiling: false,
				BlockProfiling: false,
				MutexProfiling: false,
				ProfileDuration: "30s",
				ProfileInterval: "1m",
				HTTPEndpoint: ":6060",
			},
			HealthChecks: &HealthChecksConfig{
				Enabled: false,
				Endpoint: "/health",
				Interval: "30s",
				Timeout: "5s",
				Checks: []HealthCheck{},
				FailureThreshold: 3,
				SuccessThreshold: 1,
			},
			Alerting: &AlertingConfig{
				Enabled: false,
				Providers: []AlertProvider{},
				Rules: []AlertRule{},
			},
		},
	}
}

// Validate validates the enhanced configuration
func (c *EnhancedConfig) Validate() error {
	if c.Core == nil {
		return fmt.Errorf("core configuration is required")
	}
	
	// Validate timeout formats
	if c.Core.Timeout != "" {
		if _, err := time.ParseDuration(c.Core.Timeout); err != nil {
			return fmt.Errorf("invalid core timeout format: %w", err)
		}
	}
	
	if c.Core.RetryDelay != "" {
		if _, err := time.ParseDuration(c.Core.RetryDelay); err != nil {
			return fmt.Errorf("invalid retry delay format: %w", err)
		}
	}
	
	// Validate static analysis config
	if c.StaticAnalysis != nil && c.StaticAnalysis.Enabled {
		if c.StaticAnalysis.Timeout != "" {
			if _, err := time.ParseDuration(c.StaticAnalysis.Timeout); err != nil {
				return fmt.Errorf("invalid static analysis timeout format: %w", err)
			}
		}
		if c.StaticAnalysis.RiskThreshold < 0 || c.StaticAnalysis.RiskThreshold > 1 {
			return fmt.Errorf("risk threshold must be between 0 and 1")
		}
	}
	
	// Validate dynamic analysis config
	if c.DynamicAnalysis != nil && c.DynamicAnalysis.Enabled {
		if c.DynamicAnalysis.Timeout != "" {
			if _, err := time.ParseDuration(c.DynamicAnalysis.Timeout); err != nil {
				return fmt.Errorf("invalid dynamic analysis timeout format: %w", err)
			}
		}
		if c.DynamicAnalysis.MaxExecutionTime != "" {
			if _, err := time.ParseDuration(c.DynamicAnalysis.MaxExecutionTime); err != nil {
				return fmt.Errorf("invalid max execution time format: %w", err)
			}
		}
	}
	
	// Validate ML analysis config
	if c.MLAnalysis != nil && c.MLAnalysis.Enabled {
		if c.MLAnalysis.SimilarityThreshold < 0 || c.MLAnalysis.SimilarityThreshold > 1 {
			return fmt.Errorf("similarity threshold must be between 0 and 1")
		}
		if c.MLAnalysis.MaliciousThreshold < 0 || c.MLAnalysis.MaliciousThreshold > 1 {
			return fmt.Errorf("malicious threshold must be between 0 and 1")
		}
		if c.MLAnalysis.ReputationThreshold < 0 || c.MLAnalysis.ReputationThreshold > 1 {
			return fmt.Errorf("reputation threshold must be between 0 and 1")
		}
	}
	
	// Validate provenance analysis config
	if c.ProvenanceAnalysis != nil && c.ProvenanceAnalysis.Enabled {
		if c.ProvenanceAnalysis.Timeout != "" {
			if _, err := time.ParseDuration(c.ProvenanceAnalysis.Timeout); err != nil {
				return fmt.Errorf("invalid provenance analysis timeout format: %w", err)
			}
		}
		if c.ProvenanceAnalysis.SLSAMinLevel < 0 || c.ProvenanceAnalysis.SLSAMinLevel > 4 {
			return fmt.Errorf("SLSA minimum level must be between 0 and 4")
		}
	}
	
	return nil
}

// SetDefaults sets default values for missing configuration fields
func (c *EnhancedConfig) SetDefaults() {
	if c.Core == nil {
		c.Core = &CoreConfig{}
	}
	
	if c.Core.Version == "" {
		c.Core.Version = "1.0.0"
	}
	
	if c.Core.Environment == "" {
		c.Core.Environment = "development"
	}
	
	if c.Core.DataDir == "" {
		c.Core.DataDir = filepath.Join(os.TempDir(), "typosentinel")
	}
	
	if c.Core.TempDir == "" {
		c.Core.TempDir = filepath.Join(os.TempDir(), "typosentinel-temp")
	}
	
	if c.Core.MaxConcurrency == 0 {
		c.Core.MaxConcurrency = 10
	}
	
	if c.Core.Timeout == "" {
		c.Core.Timeout = "30s"
	}
	
	if c.Core.RetryAttempts == 0 {
		c.Core.RetryAttempts = 3
	}
	
	if c.Core.RetryDelay == "" {
		c.Core.RetryDelay = "1s"
	}
	
	// Set defaults for other components
	if c.StaticAnalysis == nil {
		c.StaticAnalysis = &StaticAnalysisConfig{Enabled: true}
	}
	
	if c.DynamicAnalysis == nil {
		c.DynamicAnalysis = &DynamicAnalysisConfig{Enabled: false}
	}
	
	if c.MLAnalysis == nil {
		c.MLAnalysis = &MLAnalysisConfig{Enabled: false}
	}
	
	if c.ProvenanceAnalysis == nil {
		c.ProvenanceAnalysis = &ProvenanceAnalysisConfig{Enabled: false}
	}
	
	if c.TypoDetection == nil {
		c.TypoDetection = &TypoDetectionConfig{Enabled: true}
	}
	
	if c.MalwareDetection == nil {
		c.MalwareDetection = &MalwareDetectionConfig{Enabled: true}
	}
	
	if c.VulnerabilityScanning == nil {
		c.VulnerabilityScanning = &VulnerabilityScanningConfig{Enabled: true}
	}
	
	if c.Reporting == nil {
		c.Reporting = &ReportingConfig{Enabled: true}
	}
	
	if c.Output == nil {
		c.Output = &OutputConfig{Format: "json", Stdout: true}
	}
	
	if c.Performance == nil {
		c.Performance = &PerformanceConfig{MaxConcurrency: 10}
	}
	
	if c.Caching == nil {
		c.Caching = &CachingConfig{Enabled: true, Backend: "memory"}
	}
	
	if c.Security == nil {
		c.Security = &SecurityConfig{EncryptionEnabled: false}
	}
	
	if c.Privacy == nil {
		c.Privacy = &PrivacyConfig{DataMinimization: true}
	}
	
	if c.Integrations == nil {
		c.Integrations = &IntegrationsConfig{}
	}
	
	if c.Logging == nil {
		c.Logging = &LoggingConfig{Level: "info", Format: "text", Output: []string{"stdout"}}
	}
	
	if c.Monitoring == nil {
		c.Monitoring = &MonitoringConfig{Enabled: false}
	}
}

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

// MergeConfigs merges two enhanced configurations
func MergeConfigs(base, override *EnhancedConfig) *EnhancedConfig {
	if base == nil {
		return override
	}
	if override == nil {
		return base
	}
	
	// Create a deep copy of base config
	merged := *base
	
	// Override non-nil fields from override config
	if override.Core != nil {
		merged.Core = override.Core
	}
	if override.StaticAnalysis != nil {
		merged.StaticAnalysis = override.StaticAnalysis
	}
	if override.DynamicAnalysis != nil {
		merged.DynamicAnalysis = override.DynamicAnalysis
	}
	if override.MLAnalysis != nil {
		merged.MLAnalysis = override.MLAnalysis
	}
	if override.ProvenanceAnalysis != nil {
		merged.ProvenanceAnalysis = override.ProvenanceAnalysis
	}
	if override.TypoDetection != nil {
		merged.TypoDetection = override.TypoDetection
	}
	if override.MalwareDetection != nil {
		merged.MalwareDetection = override.MalwareDetection
	}
	if override.VulnerabilityScanning != nil {
		merged.VulnerabilityScanning = override.VulnerabilityScanning
	}
	if override.Reporting != nil {
		merged.Reporting = override.Reporting
	}
	if override.Output != nil {
		merged.Output = override.Output
	}
	if override.Performance != nil {
		merged.Performance = override.Performance
	}
	if override.Caching != nil {
		merged.Caching = override.Caching
	}
	if override.Security != nil {
		merged.Security = override.Security
	}
	if override.Privacy != nil {
		merged.Privacy = override.Privacy
	}
	if override.Integrations != nil {
		merged.Integrations = override.Integrations
	}
	if override.Logging != nil {
		merged.Logging = override.Logging
	}
	if override.Monitoring != nil {
		merged.Monitoring = override.Monitoring
	}
	
	return &merged
}

// Clone creates a deep copy of the enhanced configuration
func (c *EnhancedConfig) Clone() *EnhancedConfig {
	data, err := yaml.Marshal(c)
	if err != nil {
		return nil
	}
	
	var clone EnhancedConfig
	if err := yaml.Unmarshal(data, &clone); err != nil {
		return nil
	}
	
	return &clone
}

// ToYAML converts the configuration to YAML format
func (c *EnhancedConfig) ToYAML() ([]byte, error) {
	return yaml.Marshal(c)
}

// FromYAML loads configuration from YAML data
func FromYAML(data []byte) (*EnhancedConfig, error) {
	var config EnhancedConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, err
	}
	
	if err := config.Validate(); err != nil {
		return nil, err
	}
	
	config.SetDefaults()
	return &config, nil
}

// GetFeatureFlags returns enabled feature flags
func (c *EnhancedConfig) GetFeatureFlags() map[string]bool {
	flags := make(map[string]bool)
	
	if c.StaticAnalysis != nil {
		flags["static_analysis"] = c.StaticAnalysis.Enabled
	}
	if c.DynamicAnalysis != nil {
		flags["dynamic_analysis"] = c.DynamicAnalysis.Enabled
	}
	if c.MLAnalysis != nil {
		flags["ml_analysis"] = c.MLAnalysis.Enabled
	}
	if c.ProvenanceAnalysis != nil {
		flags["provenance_analysis"] = c.ProvenanceAnalysis.Enabled
	}
	if c.TypoDetection != nil {
		flags["typo_detection"] = c.TypoDetection.Enabled
	}
	if c.MalwareDetection != nil {
		flags["malware_detection"] = c.MalwareDetection.Enabled
	}
	if c.VulnerabilityScanning != nil {
		flags["vulnerability_scanning"] = c.VulnerabilityScanning.Enabled
	}
	if c.Reporting != nil {
		flags["reporting"] = c.Reporting.Enabled
	}
	if c.Caching != nil {
		flags["caching"] = c.Caching.Enabled
	}
	if c.Security != nil {
		flags["encryption"] = c.Security.EncryptionEnabled
	}
	if c.Monitoring != nil {
		flags["monitoring"] = c.Monitoring.Enabled
	}
	
	return flags
}

// IsFeatureEnabled checks if a specific feature is enabled
func (c *EnhancedConfig) IsFeatureEnabled(feature string) bool {
	flags := c.GetFeatureFlags()
	return flags[feature]
}

// GetTimeout returns the timeout for a specific component
func (c *EnhancedConfig) GetTimeout(component string) time.Duration {
	var timeoutStr string
	
	switch component {
	case "core":
		if c.Core != nil {
			timeoutStr = c.Core.Timeout
		}
	case "static_analysis":
		if c.StaticAnalysis != nil {
			timeoutStr = c.StaticAnalysis.Timeout
		}
	case "dynamic_analysis":
		if c.DynamicAnalysis != nil {
			timeoutStr = c.DynamicAnalysis.Timeout
		}
	case "provenance_analysis":
		if c.ProvenanceAnalysis != nil {
			timeoutStr = c.ProvenanceAnalysis.Timeout
		}
	case "vulnerability_scanning":
		if c.VulnerabilityScanning != nil {
			timeoutStr = c.VulnerabilityScanning.Timeout
		}
	default:
		if c.Core != nil {
			timeoutStr = c.Core.Timeout
		}
	}
	
	if timeoutStr == "" {
		return 30 * time.Second // Default timeout
	}
	
	timeout, err := time.ParseDuration(timeoutStr)
	if err != nil {
		return 30 * time.Second // Default timeout on parse error
	}
	
	return timeout
}

// GetRetryAttempts returns the retry attempts for a specific component
func (c *EnhancedConfig) GetRetryAttempts(component string) int {
	switch component {
	case "core":
		if c.Core != nil && c.Core.RetryAttempts > 0 {
			return c.Core.RetryAttempts
		}
	case "provenance_analysis":
		if c.ProvenanceAnalysis != nil && c.ProvenanceAnalysis.RetryAttempts > 0 {
			return c.ProvenanceAnalysis.RetryAttempts
		}
	case "vulnerability_scanning":
		if c.VulnerabilityScanning != nil && c.VulnerabilityScanning.RetryAttempts > 0 {
			return c.VulnerabilityScanning.RetryAttempts
		}
	}
	
	return 3 // Default retry attempts
}

// ToConfig converts EnhancedConfig to basic Config for compatibility
func (c *EnhancedConfig) ToConfig() *Config {
	config := &Config{
		Verbose: false,
		Debug:   false,
	}
	
	if c.Core != nil {
		config.Debug = c.Core.Debug
		config.Verbose = c.Core.Verbose
	}
	
	return config
}

// Summary returns a summary of the configuration
func (c *EnhancedConfig) Summary() map[string]interface{} {
	summary := make(map[string]interface{})
	
	if c.Core != nil {
		summary["version"] = c.Core.Version
		summary["environment"] = c.Core.Environment
		summary["debug"] = c.Core.Debug
	}
	
	summary["features"] = c.GetFeatureFlags()
	
	if c.Performance != nil {
		summary["max_concurrency"] = c.Performance.MaxConcurrency
	}
	
	if c.Logging != nil {
		summary["log_level"] = c.Logging.Level
	}
	
	return summary
}