package ml

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"sync"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/scanner"
)

// MLIntegrationManager manages the integration between ML models and the scanner
type MLIntegrationManager struct {
	config           *MLIntegrationConfig
	inferenceEngine  *InferenceEngine
	modelManager     *DeepLearningModelManager
	ensembleManager  *EnsembleModelManager
	featureExtractor *AdvancedFeatureExtractor
	// scanner removed to break circular dependency
	metrics   *IntegrationMetrics
	logger    *log.Logger
	mu        sync.RWMutex
	isEnabled bool
	ctx       context.Context
	cancel    context.CancelFunc
	hooks     map[string][]IntegrationHook
	filters   []ResultFilter
	enrichers []ResultEnricher
}

// MLIntegrationConfig configuration for ML integration
type MLIntegrationConfig struct {
	// Core settings
	Core *CoreIntegrationSettings `json:"core"`

	// Scanner integration settings
	Scanner *ScannerIntegrationSettings `json:"scanner"`

	// Model integration settings
	Model *ModelIntegrationSettings `json:"model"`

	// Pipeline settings
	Pipeline *PipelineIntegrationSettings `json:"pipeline"`

	// Result processing settings
	ResultProcessing *ResultProcessingSettings `json:"result_processing"`

	// Performance settings
	Performance *IntegrationPerformanceSettings `json:"performance"`

	// Monitoring settings
	Monitoring *IntegrationMonitoringSettings `json:"monitoring"`

	// Fallback settings
	Fallback *FallbackSettings `json:"fallback"`
}

// CoreIntegrationSettings core integration settings
type CoreIntegrationSettings struct {
	Enabled          bool                      `json:"enabled"`
	Mode             string                    `json:"mode"` // "async", "sync", "hybrid"
	Priority         int                       `json:"priority"`
	Timeout          time.Duration             `json:"timeout"`
	RetryPolicy      *RetryPolicySettings      `json:"retry_policy"`
	CircuitBreaker   *CircuitBreakerSettings   `json:"circuit_breaker"`
	GracefulShutdown *GracefulShutdownSettings `json:"graceful_shutdown"`
	HealthCheck      *HealthCheckSettings      `json:"health_check"`
}

// GracefulShutdownSettings graceful shutdown configuration
type GracefulShutdownSettings struct {
	Enabled        bool          `json:"enabled"`
	Timeout        time.Duration `json:"timeout"`
	DrainRequests  bool          `json:"drain_requests"`
	SaveState      bool          `json:"save_state"`
	NotifyServices bool          `json:"notify_services"`
}

// ScannerIntegrationSettings scanner integration settings
type ScannerIntegrationSettings struct {
	HookPoints         []string                    `json:"hook_points"`
	TriggerEvents      []string                    `json:"trigger_events"`
	DataExtraction     *DataExtractionSettings     `json:"data_extraction"`
	ResultInjection    *ResultInjectionSettings    `json:"result_injection"`
	ConflictResolution *ConflictResolutionSettings `json:"conflict_resolution"`
	Compatibility      *CompatibilitySettings      `json:"compatibility"`
}

// DataExtractionSettings data extraction configuration
type DataExtractionSettings struct {
	Enabled         bool                   `json:"enabled"`
	Fields          []string               `json:"fields"`
	Transformations map[string]interface{} `json:"transformations"`
	Validation      *ValidationSettings    `json:"validation"`
	Caching         bool                   `json:"caching"`
	Compression     bool                   `json:"compression"`
}

// ResultInjectionSettings result injection configuration
type ResultInjectionSettings struct {
	Enabled          bool                   `json:"enabled"`
	Strategy         string                 `json:"strategy"` // "merge", "replace", "append"
	Priority         int                    `json:"priority"`
	ConflictHandling string                 `json:"conflict_handling"`
	Formatting       map[string]interface{} `json:"formatting"`
	Validation       bool                   `json:"validation"`
}

// ConflictResolutionSettings conflict resolution configuration
type ConflictResolutionSettings struct {
	Enabled    bool                `json:"enabled"`
	Strategy   string              `json:"strategy"` // "ml_priority", "scanner_priority", "confidence_based"
	Thresholds map[string]float64  `json:"thresholds"`
	Rules      []ConflictRule      `json:"rules"`
	Escalation *EscalationSettings `json:"escalation"`
}

// ConflictRule conflict resolution rule
type ConflictRule struct {
	Name       string                 `json:"name"`
	Condition  string                 `json:"condition"`
	Action     string                 `json:"action"`
	Priority   int                    `json:"priority"`
	Parameters map[string]interface{} `json:"parameters"`
}

// TransformationRule defines a data transformation rule
type TransformationRule struct {
	Name   string                 `json:"name"`
	Type   string                 `json:"type"`
	Target string                 `json:"target"`
	Params map[string]interface{} `json:"params"`
}

// CompatibilitySettings compatibility configuration
type CompatibilitySettings struct {
	ScannerVersion string                 `json:"scanner_version"`
	APIVersion     string                 `json:"api_version"`
	BackwardCompat bool                   `json:"backward_compat"`
	ForwardCompat  bool                   `json:"forward_compat"`
	Migration      *MigrationSettings     `json:"migration"`
	Adapters       map[string]interface{} `json:"adapters"`
}

// MigrationSettings migration configuration
type MigrationSettings struct {
	Enabled         bool                   `json:"enabled"`
	AutoMigrate     bool                   `json:"auto_migrate"`
	BackupData      bool                   `json:"backup_data"`
	RollbackEnabled bool                   `json:"rollback_enabled"`
	MigrationSteps  []string               `json:"migration_steps"`
	Validation      map[string]interface{} `json:"validation"`
}

// ModelIntegrationSettings model integration settings
type ModelIntegrationSettings struct {
	ModelSelection *ModelSelectionSettings `json:"model_selection"`
	Ensemble       *EnsembleSettings       `json:"ensemble"`
	Calibration    *CalibrationSettings    `json:"calibration"`
	Explainability *ExplainabilitySettings `json:"explainability"`
	Uncertainty    *UncertaintySettings    `json:"uncertainty"`
	Adaptation     *AdaptationSettings     `json:"adaptation"`
}

// ModelSelectionSettings model selection configuration
type ModelSelectionSettings struct {
	Strategy       string              `json:"strategy"` // "static", "dynamic", "adaptive"
	Criteria       []string            `json:"criteria"`
	Weights        map[string]float64  `json:"weights"`
	Thresholds     map[string]float64  `json:"thresholds"`
	FallbackModel  string              `json:"fallback_model"`
	UpdateInterval time.Duration       `json:"update_interval"`
	Evaluation     *EvaluationSettings `json:"evaluation"`
}

// EvaluationSettings defines evaluation configuration
type EvaluationSettings struct {
	Enabled         bool                   `json:"enabled"`
	Metrics         []string               `json:"metrics"`
	ValidationSplit float64                `json:"validation_split"`
	CrossValidation bool                   `json:"cross_validation"`
	Folds           int                    `json:"folds"`
	Thresholds      map[string]float64     `json:"thresholds"`
	Reporting       bool                   `json:"reporting"`
	Parameters      map[string]interface{} `json:"parameters"`
}

// EnsembleSettings type defined in advanced_training_pipeline.go

// ExplainabilitySettings explainability configuration
type ExplainabilitySettings struct {
	Enabled       bool                   `json:"enabled"`
	Methods       []string               `json:"methods"`
	Granularity   string                 `json:"granularity"`
	Visualization bool                   `json:"visualization"`
	Interactive   bool                   `json:"interactive"`
	Caching       bool                   `json:"caching"`
	Customization map[string]interface{} `json:"customization"`
}

// AdaptationSettings model adaptation configuration
type AdaptationSettings struct {
	Enabled         bool                `json:"enabled"`
	Strategy        string              `json:"strategy"` // "online", "batch", "incremental"
	Triggers        []string            `json:"triggers"`
	Thresholds      map[string]float64  `json:"thresholds"`
	UpdateFrequency time.Duration       `json:"update_frequency"`
	Validation      *ValidationSettings `json:"validation"`
	Rollback        *RollbackSettings   `json:"rollback"`
}

// RollbackSettings rollback configuration
type RollbackSettings struct {
	Enabled        bool                   `json:"enabled"`
	Triggers       []string               `json:"triggers"`
	Thresholds     map[string]float64     `json:"thresholds"`
	Strategy       string                 `json:"strategy"`
	BackupVersions int                    `json:"backup_versions"`
	Validation     map[string]interface{} `json:"validation"`
}

// PipelineIntegrationSettings pipeline integration settings
type PipelineIntegrationSettings struct {
	Stages        []PipelineStage        `json:"stages"`
	Parallelism   *ParallelismSettings   `json:"parallelism"`
	Dependencies  *DependencySettings    `json:"dependencies"`
	ErrorHandling *ErrorHandlingSettings `json:"error_handling"`
	Optimization  *OptimizationSettings  `json:"optimization"`
	Checkpoints   *CheckpointSettings    `json:"checkpoints"`
}

// ErrorHandlingSettings defines error handling configuration
type ErrorHandlingSettings struct {
	Enabled         bool                   `json:"enabled"`
	RetryAttempts   int                    `json:"retry_attempts"`
	RetryDelay      time.Duration          `json:"retry_delay"`
	TimeoutDuration time.Duration          `json:"timeout_duration"`
	FallbackAction  string                 `json:"fallback_action"`
	Logging         bool                   `json:"logging"`
	Notifications   bool                   `json:"notifications"`
	Parameters      map[string]interface{} `json:"parameters"`
}

// PipelineStage pipeline stage definition
type PipelineStage struct {
	Name          string                 `json:"name"`
	Type          string                 `json:"type"`
	Enabled       bool                   `json:"enabled"`
	Order         int                    `json:"order"`
	Dependencies  []string               `json:"dependencies"`
	Timeout       time.Duration          `json:"timeout"`
	RetryPolicy   *RetryPolicySettings   `json:"retry_policy"`
	Configuration map[string]interface{} `json:"configuration"`
	Validation    *ValidationSettings    `json:"validation"`
}

// ParallelismSettings parallelism configuration
type ParallelismSettings struct {
	Enabled         bool                     `json:"enabled"`
	MaxWorkers      int                      `json:"max_workers"`
	Strategy        string                   `json:"strategy"` // "stage", "task", "data"
	LoadBalancing   string                   `json:"load_balancing"`
	Synchronization *SynchronizationSettings `json:"synchronization"`
	ResourceSharing bool                     `json:"resource_sharing"`
}

// SynchronizationSettings synchronization configuration
type SynchronizationSettings struct {
	Enabled            bool          `json:"enabled"`
	Method             string        `json:"method"`
	Timeout            time.Duration `json:"timeout"`
	Barriers           []string      `json:"barriers"`
	Checkpoints        []string      `json:"checkpoints"`
	ConflictResolution string        `json:"conflict_resolution"`
}

// DependencySettings dependency configuration
type DependencySettings struct {
	Resolution string                 `json:"resolution"` // "strict", "lazy", "optional"
	Validation bool                   `json:"validation"`
	Caching    bool                   `json:"caching"`
	Versioning bool                   `json:"versioning"`
	Fallbacks  map[string]interface{} `json:"fallbacks"`
	Injection  *InjectionSettings     `json:"injection"`
}

// InjectionSettings dependency injection configuration
type InjectionSettings struct {
	Enabled       bool                   `json:"enabled"`
	Strategy      string                 `json:"strategy"`
	Scope         string                 `json:"scope"`
	Lifecycle     string                 `json:"lifecycle"`
	Configuration map[string]interface{} `json:"configuration"`
}

// CheckpointSettings type defined in advanced_training_pipeline.go

// ResultProcessingSettings result processing configuration
type ResultProcessingSettings struct {
	Filtering      *FilteringSettings      `json:"filtering"`
	Enrichment     *EnrichmentSettings     `json:"enrichment"`
	Aggregation    *AggregationSettings    `json:"aggregation"`
	Transformation *TransformationSettings `json:"transformation"`
	Validation     *ValidationSettings     `json:"validation"`
	Serialization  *SerializationSettings  `json:"serialization"`
	Caching        *CachingSettings        `json:"caching"`
}

// SerializationSettings serialization configuration
type SerializationSettings struct {
	Format        string                 `json:"format"`
	Compression   bool                   `json:"compression"`
	Encryption    bool                   `json:"encryption"`
	Versioning    bool                   `json:"versioning"`
	Schema        string                 `json:"schema"`
	Validation    bool                   `json:"validation"`
	Customization map[string]interface{} `json:"customization"`
}

// IntegrationPerformanceSettings performance configuration
type IntegrationPerformanceSettings struct {
	Optimization   *OptimizationSettings   `json:"optimization"`
	ResourceLimits *ResourceLimitsSettings `json:"resource_limits"`
	LoadBalancing  *LoadBalancingSettings  `json:"load_balancing"`
	Scaling        *ScalingSettings        `json:"scaling"`
	Profiling      *ProfilingSettings      `json:"profiling"`
	Benchmarking   *BenchmarkingSettings   `json:"benchmarking"`
	Caching        *CachingSettings        `json:"caching"`
	Batching       *BatchingSettings       `json:"batching"`
	Pooling        *PoolingSettings        `json:"pooling"`
	RateLimiting   *RateLimitingSettings   `json:"rate_limiting"`
}

// BatchingSettings batch processing configuration
type BatchingSettings struct {
	Enabled  bool          `json:"enabled"`
	Size     int           `json:"size"`
	Timeout  time.Duration `json:"timeout"`
	Strategy string        `json:"strategy"`
}

// PoolingSettings worker pool configuration
type PoolingSettings struct {
	Enabled     bool          `json:"enabled"`
	MinWorkers  int           `json:"min_workers"`
	MaxWorkers  int           `json:"max_workers"`
	IdleTimeout time.Duration `json:"idle_timeout"`
	Scaling     string        `json:"scaling"`
}

// RateLimitingSettings rate limiting configuration
type RateLimitingSettings struct {
	Enabled  bool          `json:"enabled"`
	Rate     int           `json:"rate"`
	Window   time.Duration `json:"window"`
	Burst    int           `json:"burst"`
	Strategy string        `json:"strategy"`
}

// LoadBalancingSettings load balancing configuration
type LoadBalancingSettings struct {
	Enabled      bool                `json:"enabled"`
	Strategy     string              `json:"strategy"`
	Algorithm    string              `json:"algorithm"`
	Weights      map[string]float64  `json:"weights"`
	HealthChecks bool                `json:"health_checks"`
	Failover     *FailoverSettings   `json:"failover"`
	Stickiness   *StickinessSettings `json:"stickiness"`
}

// FailoverSettings failover configuration
type FailoverSettings struct {
	Enabled      bool                 `json:"enabled"`
	Strategy     string               `json:"strategy"`
	Thresholds   map[string]float64   `json:"thresholds"`
	Timeout      time.Duration        `json:"timeout"`
	RetryPolicy  *RetryPolicySettings `json:"retry_policy"`
	Notification bool                 `json:"notification"`
}

// StickinessSettings session stickiness configuration
type StickinessSettings struct {
	Enabled    bool          `json:"enabled"`
	Method     string        `json:"method"`
	Duration   time.Duration `json:"duration"`
	CookieName string        `json:"cookie_name"`
	HeaderName string        `json:"header_name"`
	Fallback   string        `json:"fallback"`
}

// ScalingSettings scaling configuration
type ScalingSettings struct {
	Enabled    bool             `json:"enabled"`
	Strategy   string           `json:"strategy"` // "horizontal", "vertical", "hybrid"
	Triggers   []ScalingTrigger `json:"triggers"`
	Limits     *ScalingLimits   `json:"limits"`
	Cooldown   time.Duration    `json:"cooldown"`
	Predictive bool             `json:"predictive"`
}

// ScalingTrigger scaling trigger definition
type ScalingTrigger struct {
	Metric     string                 `json:"metric"`
	Threshold  float64                `json:"threshold"`
	Direction  string                 `json:"direction"` // "up", "down"
	Duration   time.Duration          `json:"duration"`
	Action     string                 `json:"action"`
	Parameters map[string]interface{} `json:"parameters"`
}

// ScalingLimits scaling limits configuration
type ScalingLimits struct {
	MinInstances int                    `json:"min_instances"`
	MaxInstances int                    `json:"max_instances"`
	MinResources map[string]interface{} `json:"min_resources"`
	MaxResources map[string]interface{} `json:"max_resources"`
	BudgetLimits map[string]float64     `json:"budget_limits"`
}

// BenchmarkingSettings benchmarking configuration
type BenchmarkingSettings struct {
	Enabled    bool                `json:"enabled"`
	Suites     []string            `json:"suites"`
	Frequency  time.Duration       `json:"frequency"`
	Metrics    []string            `json:"metrics"`
	Baselines  map[string]float64  `json:"baselines"`
	Reporting  *ReportingSettings  `json:"reporting"`
	Comparison *ComparisonSettings `json:"comparison"`
}

// ReportingSettings reporting configuration
type ReportingSettings struct {
	Enabled     bool                   `json:"enabled"`
	Format      string                 `json:"format"`
	Destination string                 `json:"destination"`
	Frequency   time.Duration          `json:"frequency"`
	Template    string                 `json:"template"`
	Filtering   map[string]interface{} `json:"filtering"`
	Aggregation map[string]interface{} `json:"aggregation"`
}

// ComparisonSettings type defined in advanced_training_pipeline.go

// IntegrationMonitoringSettings monitoring configuration
type IntegrationMonitoringSettings struct {
	Metrics    *MetricsCollectionSettings `json:"metrics"`
	Logging    *LoggingSettings           `json:"logging"`
	Tracing    *TracingSettings           `json:"tracing"`
	Alerting   *AlertingSettings          `json:"alerting"`
	Dashboards *DashboardSettings         `json:"dashboards"`
	Reporting  *ReportingSettings         `json:"reporting"`
}

// DashboardSettings dashboard configuration
type DashboardSettings struct {
	Enabled       bool                   `json:"enabled"`
	Provider      string                 `json:"provider"`
	Templates     []string               `json:"templates"`
	Customization map[string]interface{} `json:"customization"`
	RefreshRate   time.Duration          `json:"refresh_rate"`
	Access        *AccessSettings        `json:"access"`
}

// AccessSettings access control configuration
type AccessSettings struct {
	Enabled        bool                   `json:"enabled"`
	Authentication bool                   `json:"authentication"`
	Authorization  bool                   `json:"authorization"`
	Roles          map[string][]string    `json:"roles"`
	Permissions    map[string]interface{} `json:"permissions"`
	AuditLogging   bool                   `json:"audit_logging"`
}

// FallbackSettings fallback configuration
type FallbackSettings struct {
	Enabled      bool                  `json:"enabled"`
	Strategy     string                `json:"strategy"` // "graceful", "fail_fast", "circuit_breaker"
	Triggers     []string              `json:"triggers"`
	Actions      []FallbackAction      `json:"actions"`
	Recovery     *RecoverySettings     `json:"recovery"`
	Notification *NotificationSettings `json:"notification"`
}

// FallbackAction fallback action definition
type FallbackAction struct {
	Name       string                 `json:"name"`
	Type       string                 `json:"type"`
	Condition  string                 `json:"condition"`
	Priority   int                    `json:"priority"`
	Timeout    time.Duration          `json:"timeout"`
	Parameters map[string]interface{} `json:"parameters"`
	Validation bool                   `json:"validation"`
}

// RecoverySettings recovery configuration
type RecoverySettings struct {
	Enabled      bool          `json:"enabled"`
	Strategy     string        `json:"strategy"`
	Attempts     int           `json:"attempts"`
	Interval     time.Duration `json:"interval"`
	Backoff      string        `json:"backoff"`
	Validation   bool          `json:"validation"`
	Notification bool          `json:"notification"`
}

// NotificationSettings type defined in advanced_training_pipeline.go

// ThrottlingSettings throttling configuration
type ThrottlingSettings struct {
	Enabled  bool          `json:"enabled"`
	Rate     int           `json:"rate"`
	Window   time.Duration `json:"window"`
	Burst    int           `json:"burst"`
	Strategy string        `json:"strategy"`
}

// IntegrationMetrics tracks integration performance metrics
type IntegrationMetrics struct {
	// Request metrics
	TotalRequests      int64 `json:"total_requests"`
	SuccessfulRequests int64 `json:"successful_requests"`
	FailedRequests     int64 `json:"failed_requests"`
	MLEnhancedRequests int64 `json:"ml_enhanced_requests"`

	// Performance metrics
	AverageLatency      time.Duration `json:"average_latency"`
	MLProcessingTime    time.Duration `json:"ml_processing_time"`
	IntegrationOverhead time.Duration `json:"integration_overhead"`
	Throughput          float64       `json:"throughput"`

	// Accuracy metrics
	MLAccuracy        float64 `json:"ml_accuracy"`
	FalsePositiveRate float64 `json:"false_positive_rate"`
	FalseNegativeRate float64 `json:"false_negative_rate"`
	ConfidenceScore   float64 `json:"confidence_score"`

	// Integration metrics
	HookExecutions       int64 `json:"hook_executions"`
	FilterApplications   int64 `json:"filter_applications"`
	EnrichmentOperations int64 `json:"enrichment_operations"`
	ConflictResolutions  int64 `json:"conflict_resolutions"`

	// Error metrics
	IntegrationErrors int64 `json:"integration_errors"`
	ModelErrors       int64 `json:"model_errors"`
	DataErrors        int64 `json:"data_errors"`
	TimeoutErrors     int64 `json:"timeout_errors"`

	// Resource metrics
	MemoryUsage int64   `json:"memory_usage"`
	CPUUsage    float64 `json:"cpu_usage"`
	GPUUsage    float64 `json:"gpu_usage"`

	// Timestamps
	StartTime  time.Time `json:"start_time"`
	LastUpdate time.Time `json:"last_update"`

	mu sync.RWMutex `json:"-"`
}

// IntegrationHook represents a hook function for integration points
type IntegrationHook func(ctx context.Context, data interface{}) (interface{}, error)

// ResultFilter represents a filter for processing results
type ResultFilter interface {
	Filter(ctx context.Context, result *IntegrationResult) (*IntegrationResult, error)
	GetName() string
	GetPriority() int
}

// ResultEnricher represents an enricher for processing results
type ResultEnricher interface {
	Enrich(ctx context.Context, result *IntegrationResult) (*IntegrationResult, error)
	GetName() string
	GetPriority() int
}

// IntegrationResult represents the result of ML integration
type IntegrationResult struct {
	ID              string                `json:"id"`
	Timestamp       time.Time             `json:"timestamp"`
	ScannerResult   *scanner.ScanResult   `json:"scanner_result"`
	MLPrediction    *ThreatPrediction     `json:"ml_prediction"`
	CombinedResult  *CombinedThreatResult `json:"combined_result"`
	Metadata        *IntegrationMetadata  `json:"metadata"`
	ProcessingSteps []ProcessingStep      `json:"processing_steps"`
	Errors          []IntegrationError    `json:"errors,omitempty"`
	Warnings        []IntegrationWarning  `json:"warnings,omitempty"`
}

// CombinedThreatResult represents the combined result from scanner and ML
type CombinedThreatResult struct {
	IsThreat        bool                 `json:"is_threat"`
	ThreatType      string               `json:"threat_type"`
	Severity        string               `json:"severity"`
	Confidence      float64              `json:"confidence"`
	Score           float64              `json:"score"`
	Sources         []string             `json:"sources"`
	Evidence        []Evidence           `json:"evidence"`
	Recommendations []string             `json:"recommendations"`
	RiskFactors     map[string]float64   `json:"risk_factors"`
	Explanation     *CombinedExplanation `json:"explanation,omitempty"`
}

// Evidence represents evidence for a threat detection
type Evidence struct {
	Source      string                 `json:"source"`
	Type        string                 `json:"type"`
	Description string                 `json:"description"`
	Confidence  float64                `json:"confidence"`
	Data        map[string]interface{} `json:"data,omitempty"`
}

// CombinedExplanation represents the combined explanation
type CombinedExplanation struct {
	ScannerExplanation string                 `json:"scanner_explanation,omitempty"`
	MLExplanation      *PredictionExplanation `json:"ml_explanation,omitempty"`
	CombinationLogic   string                 `json:"combination_logic"`
	DecisionFactors    []string               `json:"decision_factors"`
}

// IntegrationMetadata represents metadata for integration results
type IntegrationMetadata struct {
	IntegrationVersion string                 `json:"integration_version"`
	ScannerVersion     string                 `json:"scanner_version"`
	MLModelVersion     string                 `json:"ml_model_version"`
	ProcessingTime     time.Duration          `json:"processing_time"`
	ResourceUsage      *ResourceUsageInfo     `json:"resource_usage,omitempty"`
	Configuration      map[string]interface{} `json:"configuration,omitempty"`
	SessionID          string                 `json:"session_id,omitempty"`
	RequestID          string                 `json:"request_id,omitempty"`
}

// ProcessingStep represents a step in the processing pipeline
type ProcessingStep struct {
	Name      string                 `json:"name"`
	Type      string                 `json:"type"`
	StartTime time.Time              `json:"start_time"`
	EndTime   time.Time              `json:"end_time"`
	Duration  time.Duration          `json:"duration"`
	Status    string                 `json:"status"`
	Input     map[string]interface{} `json:"input,omitempty"`
	Output    map[string]interface{} `json:"output,omitempty"`
	Metrics   map[string]float64     `json:"metrics,omitempty"`
	Error     string                 `json:"error,omitempty"`
}

// IntegrationError represents an integration error
type IntegrationError struct {
	Code       string                 `json:"code"`
	Message    string                 `json:"message"`
	Source     string                 `json:"source"`
	Severity   string                 `json:"severity"`
	Timestamp  time.Time              `json:"timestamp"`
	Context    map[string]interface{} `json:"context,omitempty"`
	StackTrace string                 `json:"stack_trace,omitempty"`
}

// IntegrationWarning represents an integration warning
type IntegrationWarning struct {
	Code      string                 `json:"code"`
	Message   string                 `json:"message"`
	Source    string                 `json:"source"`
	Timestamp time.Time              `json:"timestamp"`
	Context   map[string]interface{} `json:"context,omitempty"`
}

// NewMLIntegrationManager creates a new ML integration manager
func NewMLIntegrationManager(config *MLIntegrationConfig, scanner scanner.Scanner) (*MLIntegrationManager, error) {
	if config == nil {
		config = DefaultMLIntegrationConfig()
	}

	// Initialize inference engine
	inferenceEngine, err := NewInferenceEngine(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create inference engine: %v", err)
	}

	// Initialize model manager
	modelManager := NewDeepLearningModelManager(nil)

	// Initialize ensemble manager
	ensembleManager := NewEnsembleModelManager(nil)

	// Initialize feature extractor
	featureExtractor := NewAdvancedFeatureExtractor(nil)

	ctx, cancel := context.WithCancel(context.Background())

	manager := &MLIntegrationManager{
		config:           config,
		inferenceEngine:  inferenceEngine,
		modelManager:     modelManager,
		ensembleManager:  ensembleManager,
		featureExtractor: featureExtractor,
		metrics:          NewIntegrationMetrics(),
		ctx:              ctx,
		cancel:           cancel,
		hooks:            make(map[string][]IntegrationHook),
		filters:          []ResultFilter{},
		enrichers:        []ResultEnricher{},
	}

	return manager, nil
}

// Start starts the ML integration manager
func (mim *MLIntegrationManager) Start() error {
	mim.mu.Lock()
	defer mim.mu.Unlock()

	if mim.isEnabled {
		return fmt.Errorf("ML integration manager is already running")
	}

	if !mim.config.Core.Enabled {
		return fmt.Errorf("ML integration is disabled in configuration")
	}

	// Start inference engine
	if err := mim.inferenceEngine.Start(); err != nil {
		return fmt.Errorf("failed to start inference engine: %v", err)
	}

	// Register scanner hooks
	if err := mim.registerScannerHooks(); err != nil {
		return fmt.Errorf("failed to register scanner hooks: %v", err)
	}

	// Initialize default filters and enrichers
	mim.initializeDefaultProcessors()

	mim.isEnabled = true
	mim.metrics.StartTime = time.Now()

	// Start monitoring
	go mim.startMonitoring()

	mim.logger.Printf("ML integration manager started")
	return nil
}

// Stop stops the ML integration manager
func (mim *MLIntegrationManager) Stop() error {
	mim.mu.Lock()
	defer mim.mu.Unlock()

	if !mim.isEnabled {
		return fmt.Errorf("ML integration manager is not running")
	}

	// Stop inference engine
	if err := mim.inferenceEngine.Stop(); err != nil {
		mim.logger.Printf("Error stopping inference engine: %v", err)
	}

	// Unregister scanner hooks
	mim.unregisterScannerHooks()

	mim.cancel()
	mim.isEnabled = false

	mim.logger.Printf("ML integration manager stopped")
	return nil
}

// ProcessScanResult processes a scan result with ML enhancement
func (mim *MLIntegrationManager) ProcessScanResult(ctx context.Context, scanResult *scanner.ScanResult) (*IntegrationResult, error) {
	if !mim.isEnabled {
		return nil, fmt.Errorf("ML integration manager is not enabled")
	}

	startTime := time.Now()
	result := &IntegrationResult{
		ID:              generateIntegrationID(),
		Timestamp:       startTime,
		ScannerResult:   scanResult,
		ProcessingSteps: []ProcessingStep{},
		Errors:          []IntegrationError{},
		Warnings:        []IntegrationWarning{},
	}

	// Step 1: Extract features from scan result
	step := mim.startProcessingStep("feature_extraction", "ml")
	features, err := mim.extractFeaturesFromScanResult(scanResult)
	if err != nil {
		mim.finishProcessingStep(step, "failed", nil, err)
		result.ProcessingSteps = append(result.ProcessingSteps, *step)
		return result, fmt.Errorf("feature extraction failed: %v", err)
	}
	mim.finishProcessingStep(step, "completed", map[string]interface{}{"feature_count": len(features.CombinedFeatures)}, nil)
	result.ProcessingSteps = append(result.ProcessingSteps, *step)

	// Step 2: Perform ML inference
	step = mim.startProcessingStep("ml_inference", "ml")
	inferenceRequest := mim.convertScanResultToMLInput(scanResult)
	response, err := mim.inferenceEngine.Predict(ctx, inferenceRequest.PackageData, nil)
	if err != nil {
		mim.finishProcessingStep(step, "failed", nil, err)
		result.ProcessingSteps = append(result.ProcessingSteps, *step)
		return result, fmt.Errorf("ML inference failed: %v", err)
	}
	mim.finishProcessingStep(step, "completed", map[string]interface{}{"confidence": response.Confidence}, nil)
	result.ProcessingSteps = append(result.ProcessingSteps, *step)
	result.MLPrediction = response.Prediction

	// Step 3: Combine scanner and ML results
	step = mim.startProcessingStep("result_combination", "integration")
	combinedResult, err := mim.combineResults(scanResult, response.Prediction)
	if err != nil {
		mim.finishProcessingStep(step, "failed", nil, err)
		result.ProcessingSteps = append(result.ProcessingSteps, *step)
		return result, fmt.Errorf("result combination failed: %v", err)
	}
	mim.finishProcessingStep(step, "completed", map[string]interface{}{"final_score": combinedResult.Score}, nil)
	result.ProcessingSteps = append(result.ProcessingSteps, *step)
	result.CombinedResult = combinedResult

	// Step 4: Apply filters
	step = mim.startProcessingStep("result_filtering", "post_processing")
	filteredResult, err := mim.applyFilters(ctx, result)
	if err != nil {
		mim.finishProcessingStep(step, "failed", nil, err)
		result.ProcessingSteps = append(result.ProcessingSteps, *step)
		return result, fmt.Errorf("result filtering failed: %v", err)
	}
	mim.finishProcessingStep(step, "completed", nil, nil)
	result.ProcessingSteps = append(result.ProcessingSteps, *step)
	result = filteredResult

	// Step 5: Apply enrichers
	step = mim.startProcessingStep("result_enrichment", "post_processing")
	enrichedResult, err := mim.applyEnrichers(ctx, result)
	if err != nil {
		mim.finishProcessingStep(step, "failed", nil, err)
		result.ProcessingSteps = append(result.ProcessingSteps, *step)
		return result, fmt.Errorf("result enrichment failed: %v", err)
	}
	mim.finishProcessingStep(step, "completed", nil, nil)
	result.ProcessingSteps = append(result.ProcessingSteps, *step)
	result = enrichedResult

	// Add metadata
	result.Metadata = &IntegrationMetadata{
		IntegrationVersion: "1.0",
		ScannerVersion:     mim.getScannerVersion(),
		MLModelVersion:     mim.getMLModelVersion(),
		ProcessingTime:     time.Since(startTime),
		RequestID:          result.ID,
	}

	// Update metrics
	mim.updateMetrics(result)

	return result, nil
}

// RegisterHook registers a hook for a specific integration point
func (mim *MLIntegrationManager) RegisterHook(hookPoint string, hook IntegrationHook) {
	mim.mu.Lock()
	defer mim.mu.Unlock()

	if mim.hooks[hookPoint] == nil {
		mim.hooks[hookPoint] = []IntegrationHook{}
	}
	mim.hooks[hookPoint] = append(mim.hooks[hookPoint], hook)
}

// AddFilter adds a result filter
func (mim *MLIntegrationManager) AddFilter(filter ResultFilter) {
	mim.mu.Lock()
	defer mim.mu.Unlock()

	mim.filters = append(mim.filters, filter)
	// Sort filters by priority
	mim.sortFiltersByPriority()
}

// AddEnricher adds a result enricher
func (mim *MLIntegrationManager) AddEnricher(enricher ResultEnricher) {
	mim.mu.Lock()
	defer mim.mu.Unlock()

	mim.enrichers = append(mim.enrichers, enricher)
	// Sort enrichers by priority
	mim.sortEnrichersByPriority()
}

// GetMetrics returns current integration metrics
func (mim *MLIntegrationManager) GetMetrics() *IntegrationMetrics {
	return mim.metrics.copy()
}

// GetStatus returns the current status of the integration manager
func (mim *MLIntegrationManager) GetStatus() map[string]interface{} {
	mim.mu.RLock()
	defer mim.mu.RUnlock()

	return map[string]interface{}{
		"enabled":          mim.isEnabled,
		"inference_engine": mim.inferenceEngine.GetStatus(),
		"registered_hooks": len(mim.hooks),
		"active_filters":   len(mim.filters),
		"active_enrichers": len(mim.enrichers),
		"metrics":          mim.metrics,
	}
}

// Helper methods implementation

// registerScannerHooks registers hooks with the scanner
func (mim *MLIntegrationManager) registerScannerHooks() error {
	// Register pre-scan hook
	if err := mim.registerHook("pre_scan", mim.preScanHook); err != nil {
		return fmt.Errorf("failed to register pre-scan hook: %v", err)
	}

	// Register post-scan hook
	if err := mim.registerHook("post_scan", mim.postScanHook); err != nil {
		return fmt.Errorf("failed to register post-scan hook: %v", err)
	}

	// Register package analysis hook
	if err := mim.registerHook("package_analysis", mim.packageAnalysisHook); err != nil {
		return fmt.Errorf("failed to register package analysis hook: %v", err)
	}

	return nil
}

// unregisterScannerHooks unregisters hooks from the scanner
func (mim *MLIntegrationManager) unregisterScannerHooks() {
	// Implementation depends on scanner interface
	// This is a placeholder for the actual unregistration logic
}

// registerHook registers a hook with the scanner
func (mim *MLIntegrationManager) registerHook(hookPoint string, hook IntegrationHook) error {
	// Implementation depends on scanner interface
	// This is a placeholder for the actual registration logic
	return nil
}

// preScanHook hook executed before scanning
func (mim *MLIntegrationManager) preScanHook(ctx context.Context, data interface{}) (interface{}, error) {
	// Pre-process data before scanning
	// This could include data validation, preprocessing, etc.
	return data, nil
}

// postScanHook hook executed after scanning
func (mim *MLIntegrationManager) postScanHook(ctx context.Context, data interface{}) (interface{}, error) {
	// Post-process scan results
	if scanResult, ok := data.(*scanner.ScanResult); ok {
		// Enhance scan result with ML predictions
		enhancedResult, err := mim.ProcessScanResult(ctx, scanResult)
		if err != nil {
			mim.logger.Printf("Failed to enhance scan result with ML: %v", err)
			return data, nil // Return original data on error
		}
		return enhancedResult, nil
	}
	return data, nil
}

// packageAnalysisHook hook executed during package analysis
func (mim *MLIntegrationManager) packageAnalysisHook(ctx context.Context, data interface{}) (interface{}, error) {
	// Enhance package analysis with ML insights
	return data, nil
}

// initializeDefaultProcessors initializes default filters and enrichers
func (mim *MLIntegrationManager) initializeDefaultProcessors() {
	// Add default confidence filter
	mim.AddFilter(&ConfidenceFilter{
		MinConfidence: 0.5,
		Priority:      1,
	})

	// Add default threat type filter
	mim.AddFilter(&ThreatTypeFilter{
		AllowedTypes: []string{"malware", "typosquatting", "suspicious"},
		Priority:     2,
	})

	// Add default metadata enricher
	mim.AddEnricher(&MetadataEnricher{
		Priority: 1,
	})

	// Add default explanation enricher
	mim.AddEnricher(&ExplanationEnricher{
		Priority: 2,
	})
}

// startMonitoring starts the monitoring goroutine
func (mim *MLIntegrationManager) startMonitoring() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-mim.ctx.Done():
			return
		case <-ticker.C:
			mim.collectMetrics()
		}
	}
}

// collectMetrics collects and updates metrics
func (mim *MLIntegrationManager) collectMetrics() {
	// Collect metrics from inference engine
	_ = mim.inferenceEngine.GetMetrics() // Metrics collected but not used yet

	mim.metrics.mu.Lock()
	defer mim.metrics.mu.Unlock()

	// Update metrics based on inference engine metrics
	mim.metrics.LastUpdate = time.Now()

	// Calculate derived metrics
	if mim.metrics.TotalRequests > 0 {
		mim.metrics.MLAccuracy = float64(mim.metrics.SuccessfulRequests) / float64(mim.metrics.TotalRequests)
	}
}

// extractFeaturesFromScanResult extracts features from scan result
func (mim *MLIntegrationManager) extractFeaturesFromScanResult(scanResult *scanner.ScanResult) (*ExtractedFeatures, error) {
	// Convert scan result to package data format
	packageData := mim.convertScanResultToPackageData(scanResult)

	// Extract features using the advanced feature extractor
	extractedFeatures, err := mim.featureExtractor.ExtractFeaturesFromData(packageData)
	if err != nil {
		return nil, err
	}

	// The ExtractFeaturesFromData already returns *ExtractedFeatures with all the proper fields populated
	// We can return it directly or add any additional processing if needed
	return extractedFeatures, nil
}

// convertScanResultToPackageData converts scan result to package data
func (mim *MLIntegrationManager) convertScanResultToPackageData(scanResult *scanner.ScanResult) map[string]interface{} {
	// Convert scanner.ScanResult to the format expected by feature extractor
	packageData := map[string]interface{}{
		"name":         scanResult.Package.Name,
		"version":      scanResult.Package.Version,
		"description":  "",
		"author":       "",
		"repository":   "",
		"homepage":     "",
		"keywords":     []string{},
		"license":      "",
		"dependencies": []string{},
		"scripts":      map[string]string{},
		"files":        []string{},
		"metadata":     map[string]interface{}{},
	}

	// Extract metadata if available
	if scanResult.Package.Metadata != nil {
		if scanResult.Package.Metadata.Description != "" {
			packageData["description"] = scanResult.Package.Metadata.Description
		}
		if scanResult.Package.Metadata.Author != "" {
			packageData["author"] = scanResult.Package.Metadata.Author
		}
		if scanResult.Package.Metadata.Repository != "" {
			packageData["repository"] = scanResult.Package.Metadata.Repository
		}
		if scanResult.Package.Metadata.Homepage != "" {
			packageData["homepage"] = scanResult.Package.Metadata.Homepage
		}
		if len(scanResult.Package.Metadata.Keywords) > 0 {
			packageData["keywords"] = scanResult.Package.Metadata.Keywords
		}
		if scanResult.Package.Metadata.License != "" {
			packageData["license"] = scanResult.Package.Metadata.License
		}
		if scanResult.Package.Metadata.Dependencies != nil {
			packageData["dependencies"] = scanResult.Package.Metadata.Dependencies
		}
		if scanResult.Package.Metadata.Metadata != nil {
			packageData["metadata"] = scanResult.Package.Metadata.Metadata
		}
	}

	return packageData
}

// convertScanResultToMLInput converts scan result to ML input format
func (mim *MLIntegrationManager) convertScanResultToMLInput(scanResult *scanner.ScanResult) *InferenceRequest {
	return &InferenceRequest{
		ID:          generateIntegrationID(),
		PackageData: mim.convertScanResultToPackageData(scanResult),
		Metadata: map[string]interface{}{
			"source":    "scanner",
			"timestamp": time.Now(),
		},
	}
}

// combineResults combines scanner and ML results
func (mim *MLIntegrationManager) combineResults(scanResult *scanner.ScanResult, mlPrediction *ThreatPrediction) (*CombinedThreatResult, error) {
	// Implement result combination logic based on configuration
	strategy := mim.config.Scanner.ConflictResolution.Strategy

	switch strategy {
	case "ml_priority":
		return mim.combineWithMLPriority(scanResult, mlPrediction)
	case "scanner_priority":
		return mim.combineWithScannerPriority(scanResult, mlPrediction)
	case "confidence_based":
		return mim.combineWithConfidenceBased(scanResult, mlPrediction)
	default:
		return mim.combineWithMLPriority(scanResult, mlPrediction)
	}
}

// combineWithMLPriority combines results with ML priority
func (mim *MLIntegrationManager) combineWithMLPriority(scanResult *scanner.ScanResult, mlPrediction *ThreatPrediction) (*CombinedThreatResult, error) {
	combined := &CombinedThreatResult{
		IsThreat:        mlPrediction.IsThreat,
		ThreatType:      mlPrediction.ThreatType,
		Severity:        mlPrediction.Severity,
		Confidence:      mlPrediction.Score,
		Score:           mlPrediction.Score,
		Sources:         []string{"ml", "scanner"},
		Evidence:        []Evidence{},
		Recommendations: mlPrediction.Recommendations,
		RiskFactors:     mlPrediction.RiskFactors,
	}

	// Add scanner evidence
	if len(scanResult.Threats) > 0 {
		combined.Evidence = append(combined.Evidence, Evidence{
			Source:      "scanner",
			Type:        "rule_based",
			Description: "Scanner detected threat",
			Confidence:  0.8, // Default scanner confidence
			Data: map[string]interface{}{
				"threat_type": scanResult.Threats[0].Type,
				"severity":    scanResult.Threats[0].Severity,
			},
		})
	}

	// Add ML evidence
	combined.Evidence = append(combined.Evidence, Evidence{
		Source:      "ml",
		Type:        "prediction",
		Description: "ML model prediction",
		Confidence:  mlPrediction.Score,
		Data: map[string]interface{}{
			"model_version": mim.getMLModelVersion(),
			"features_used": mlPrediction.RiskFactors,
		},
	})

	return combined, nil
}

// combineWithScannerPriority combines results with scanner priority
func (mim *MLIntegrationManager) combineWithScannerPriority(scanResult *scanner.ScanResult, mlPrediction *ThreatPrediction) (*CombinedThreatResult, error) {
	// Determine threat status from scanner results
	isThreat := len(scanResult.Threats) > 0
	threatType := "unknown"
	severity := "low"
	if len(scanResult.Threats) > 0 {
		threatType = scanResult.Threats[0].Type
		severity = scanResult.Threats[0].Severity
	}

	combined := &CombinedThreatResult{
		IsThreat:        isThreat,
		ThreatType:      threatType,
		Severity:        severity,
		Confidence:      0.8, // Default scanner confidence
		Score:           mim.calculateCombinedScore(scanResult, mlPrediction, "scanner_priority"),
		Sources:         []string{"scanner", "ml"},
		Evidence:        []Evidence{},
		Recommendations: []string{},
		RiskFactors:     make(map[string]float64),
	}

	// Add evidence from both sources
	combined.Evidence = append(combined.Evidence, Evidence{
		Source:      "scanner",
		Type:        "rule_based",
		Description: "Scanner detection",
		Confidence:  0.8,
	})

	combined.Evidence = append(combined.Evidence, Evidence{
		Source:      "ml",
		Type:        "prediction",
		Description: "ML prediction",
		Confidence:  mlPrediction.Score,
	})

	return combined, nil
}

// combineWithConfidenceBased combines results based on confidence
func (mim *MLIntegrationManager) combineWithConfidenceBased(scanResult *scanner.ScanResult, mlPrediction *ThreatPrediction) (*CombinedThreatResult, error) {
	scannerConfidence := 0.8 // Default scanner confidence
	mlConfidence := mlPrediction.Score

	// Use the result with higher confidence
	if mlConfidence > scannerConfidence {
		return mim.combineWithMLPriority(scanResult, mlPrediction)
	}
	return mim.combineWithScannerPriority(scanResult, mlPrediction)
}

// calculateCombinedScore calculates combined threat score
func (mim *MLIntegrationManager) calculateCombinedScore(scanResult *scanner.ScanResult, mlPrediction *ThreatPrediction, strategy string) float64 {
	scannerScore := 0.5 // Default scanner score
	if len(scanResult.Threats) > 0 {
		scannerScore = 0.8
	}

	mlScore := mlPrediction.Score

	switch strategy {
	case "ml_priority":
		return mlScore
	case "scanner_priority":
		return scannerScore
	case "confidence_based":
		// Weighted average based on confidence
		scannerWeight := 0.8
		mlWeight := mlPrediction.Score
		totalWeight := scannerWeight + mlWeight
		return (scannerScore*scannerWeight + mlScore*mlWeight) / totalWeight
	default:
		// Simple average
		return (scannerScore + mlScore) / 2.0
	}
}

// applyFilters applies all registered filters to the result
func (mim *MLIntegrationManager) applyFilters(ctx context.Context, result *IntegrationResult) (*IntegrationResult, error) {
	filteredResult := result

	for _, filter := range mim.filters {
		var err error
		filteredResult, err = filter.Filter(ctx, filteredResult)
		if err != nil {
			return nil, fmt.Errorf("filter %s failed: %v", filter.GetName(), err)
		}

		mim.metrics.mu.Lock()
		mim.metrics.FilterApplications++
		mim.metrics.mu.Unlock()
	}

	return filteredResult, nil
}

// applyEnrichers applies all registered enrichers to the result
func (mim *MLIntegrationManager) applyEnrichers(ctx context.Context, result *IntegrationResult) (*IntegrationResult, error) {
	enrichedResult := result

	for _, enricher := range mim.enrichers {
		var err error
		enrichedResult, err = enricher.Enrich(ctx, enrichedResult)
		if err != nil {
			return nil, fmt.Errorf("enricher %s failed: %v", enricher.GetName(), err)
		}

		mim.metrics.mu.Lock()
		mim.metrics.EnrichmentOperations++
		mim.metrics.mu.Unlock()
	}

	return enrichedResult, nil
}

// startProcessingStep starts a new processing step
func (mim *MLIntegrationManager) startProcessingStep(name, stepType string) *ProcessingStep {
	return &ProcessingStep{
		Name:      name,
		Type:      stepType,
		StartTime: time.Now(),
		Status:    "running",
	}
}

// finishProcessingStep finishes a processing step
func (mim *MLIntegrationManager) finishProcessingStep(step *ProcessingStep, status string, output map[string]interface{}, err error) {
	step.EndTime = time.Now()
	step.Duration = step.EndTime.Sub(step.StartTime)
	step.Status = status
	step.Output = output
	if err != nil {
		step.Error = err.Error()
	}
}

// sortFiltersByPriority sorts filters by priority
func (mim *MLIntegrationManager) sortFiltersByPriority() {
	// Simple bubble sort by priority
	for i := 0; i < len(mim.filters)-1; i++ {
		for j := 0; j < len(mim.filters)-i-1; j++ {
			if mim.filters[j].GetPriority() > mim.filters[j+1].GetPriority() {
				mim.filters[j], mim.filters[j+1] = mim.filters[j+1], mim.filters[j]
			}
		}
	}
}

// sortEnrichersByPriority sorts enrichers by priority
func (mim *MLIntegrationManager) sortEnrichersByPriority() {
	// Simple bubble sort by priority
	for i := 0; i < len(mim.enrichers)-1; i++ {
		for j := 0; j < len(mim.enrichers)-i-1; j++ {
			if mim.enrichers[j].GetPriority() > mim.enrichers[j+1].GetPriority() {
				mim.enrichers[j], mim.enrichers[j+1] = mim.enrichers[j+1], mim.enrichers[j]
			}
		}
	}
}

// updateMetrics updates integration metrics
func (mim *MLIntegrationManager) updateMetrics(result *IntegrationResult) {
	mim.metrics.mu.Lock()
	defer mim.metrics.mu.Unlock()

	mim.metrics.TotalRequests++
	if len(result.Errors) == 0 {
		mim.metrics.SuccessfulRequests++
	} else {
		mim.metrics.FailedRequests++
	}

	if result.MLPrediction != nil {
		mim.metrics.MLEnhancedRequests++
		mim.metrics.ConfidenceScore = result.MLPrediction.Score
	}

	if result.Metadata != nil {
		mim.metrics.MLProcessingTime = result.Metadata.ProcessingTime
	}

	mim.metrics.LastUpdate = time.Now()
}

// getScannerVersion gets the scanner version
func (mim *MLIntegrationManager) getScannerVersion() string {
	// This would typically come from the scanner interface
	return "1.0.0"
}

// getMLModelVersion gets the ML model version
func (mim *MLIntegrationManager) getMLModelVersion() string {
	// This would typically come from the model manager
	return "1.0.0"
}

// NewIntegrationMetrics creates new integration metrics
func NewIntegrationMetrics() *IntegrationMetrics {
	return &IntegrationMetrics{
		StartTime:  time.Now(),
		LastUpdate: time.Now(),
	}
}

// copy creates a copy of integration metrics
func (im *IntegrationMetrics) copy() *IntegrationMetrics {
	im.mu.RLock()
	defer im.mu.RUnlock()

	return &IntegrationMetrics{
		TotalRequests:        im.TotalRequests,
		SuccessfulRequests:   im.SuccessfulRequests,
		FailedRequests:       im.FailedRequests,
		MLEnhancedRequests:   im.MLEnhancedRequests,
		AverageLatency:       im.AverageLatency,
		MLProcessingTime:     im.MLProcessingTime,
		IntegrationOverhead:  im.IntegrationOverhead,
		Throughput:           im.Throughput,
		MLAccuracy:           im.MLAccuracy,
		FalsePositiveRate:    im.FalsePositiveRate,
		FalseNegativeRate:    im.FalseNegativeRate,
		ConfidenceScore:      im.ConfidenceScore,
		HookExecutions:       im.HookExecutions,
		FilterApplications:   im.FilterApplications,
		EnrichmentOperations: im.EnrichmentOperations,
		ConflictResolutions:  im.ConflictResolutions,
		IntegrationErrors:    im.IntegrationErrors,
		ModelErrors:          im.ModelErrors,
		DataErrors:           im.DataErrors,
		TimeoutErrors:        im.TimeoutErrors,
		MemoryUsage:          im.MemoryUsage,
		CPUUsage:             im.CPUUsage,
		GPUUsage:             im.GPUUsage,
		StartTime:            im.StartTime,
		LastUpdate:           im.LastUpdate,
	}
}

// generateIntegrationID generates a unique integration ID
func generateIntegrationID() string {
	return fmt.Sprintf("int_%d_%d", time.Now().UnixNano(), rand.Int63())
}

// DefaultMLIntegrationConfig returns a default configuration for ML integration
func DefaultMLIntegrationConfig() *MLIntegrationConfig {
	return &MLIntegrationConfig{
		Core: &CoreIntegrationSettings{
			Enabled:  true,
			Mode:     "hybrid",
			Priority: 1,
			Timeout:  30 * time.Second,
			RetryPolicy: &RetryPolicySettings{
				Enabled:      true,
				MaxRetries:   3,
				BackoffType:  "exponential",
				InitialDelay: 100 * time.Millisecond,
				MaxDelay:     5 * time.Second,
				Multiplier:   2.0,
			},
			CircuitBreaker: &CircuitBreakerSettings{
				Enabled:          true,
				FailureThreshold: 5,
				RecoveryTimeout:  30 * time.Second,
				HalfOpenRequests: 3,
			},
			GracefulShutdown: &GracefulShutdownSettings{
				Enabled:        true,
				Timeout:        30 * time.Second,
				DrainRequests:  true,
				SaveState:      true,
				NotifyServices: true,
			},
			HealthCheck: &HealthCheckSettings{
				Enabled:  true,
				Interval: 30 * time.Second,
				Timeout:  5 * time.Second,
				Endpoint: "/health",
			},
		},
		Scanner: &ScannerIntegrationSettings{
			HookPoints:    []string{"pre_scan", "post_scan", "package_analysis"},
			TriggerEvents: []string{"scan_start", "scan_complete", "threat_detected"},
			DataExtraction: &DataExtractionSettings{
				Enabled: true,
				Fields:  []string{"package_name", "version", "metadata", "dependencies"},
				Transformations: map[string]interface{}{
					"normalize_names":  true,
					"extract_features": true,
				},
				Validation: &ValidationSettings{
					Strategy:   "holdout",
					SplitRatio: []float64{0.8, 0.2},
				},
				Caching:     true,
				Compression: false,
			},
			ResultInjection: &ResultInjectionSettings{
				Enabled:          true,
				Strategy:         "merge",
				Priority:         1,
				ConflictHandling: "confidence_based",
				Formatting: map[string]interface{}{
					"include_confidence":  true,
					"include_explanation": true,
				},
				Validation: true,
			},
			ConflictResolution: &ConflictResolutionSettings{
				Enabled:  true,
				Strategy: "confidence_based",
				Thresholds: map[string]float64{
					"min_confidence": 0.7,
					"max_difference": 0.3,
				},
				Rules: []ConflictRule{
					{
						Name:      "high_confidence_ml",
						Condition: "ml_confidence > 0.9",
						Action:    "prefer_ml",
						Priority:  1,
					},
				},
				Escalation: &EscalationSettings{
					Enabled:  true,
					Levels:   []string{"warning", "critical", "emergency"},
					Timeouts: []time.Duration{5 * time.Minute, 2 * time.Minute, 1 * time.Minute},
					Channels: map[string][]string{"warning": {"log"}, "critical": {"alert"}},
				},
			},
			Compatibility: &CompatibilitySettings{
				ScannerVersion: "1.0.0",
				APIVersion:     "v1",
				BackwardCompat: true,
				ForwardCompat:  false,
				Migration: &MigrationSettings{
					Enabled:         true,
					AutoMigrate:     false,
					BackupData:      true,
					RollbackEnabled: true,
				},
			},
		},
		Model: &ModelIntegrationSettings{
			ModelSelection: &ModelSelectionSettings{
				Strategy: "adaptive",
				Criteria: []string{"accuracy", "latency", "confidence"},
				Weights: map[string]float64{
					"accuracy":   0.5,
					"latency":    0.3,
					"confidence": 0.2,
				},
				Thresholds: map[string]float64{
					"min_accuracy":   0.85,
					"max_latency":    1000,
					"min_confidence": 0.7,
				},
				FallbackModel:  "baseline",
				UpdateInterval: 24 * time.Hour,
				Evaluation: &EvaluationSettings{
					Enabled:         true,
					Metrics:         []string{"accuracy", "precision", "recall", "f1"},
					ValidationSplit: 0.2,
					CrossValidation: true,
					Folds:           5,
				},
			},
			Ensemble: &EnsembleSettings{
				Enabled: true,
				Method:  "voting",
				Models:  []string{"deep_learning", "gradient_boosting", "random_forest"},
				Weights: []float64{0.5, 0.3, 0.2},
				Voting:  "weighted",
			},
			Calibration: &CalibrationSettings{
				Enabled: true,
				Method:  "platt_scaling",
			},
			Explainability: &ExplainabilitySettings{
				Enabled:       true,
				Methods:       []string{"shap", "lime", "attention"},
				Granularity:   "feature",
				Visualization: false,
				Interactive:   false,
				Caching:       true,
			},
			Uncertainty: &UncertaintySettings{
				Enabled: true,
				Method:  "monte_carlo_dropout",
				Samples: 100,
			},
			Adaptation: &AdaptationSettings{
				Enabled:  true,
				Strategy: "incremental",
				Triggers: []string{"performance_drop", "data_drift"},
				Thresholds: map[string]float64{
					"accuracy_drop": 0.05,
					"drift_score":   0.1,
				},
				UpdateFrequency: 7 * 24 * time.Hour,
				Validation: &ValidationSettings{
					Strategy:   "holdout",
					SplitRatio: []float64{0.8, 0.2},
					CrossValidation: &CrossValidationConfig{
						Method:         "stratified_k_fold",
						Folds:          5,
						Shuffle:        true,
						RandomState:    42,
						TestSize:       0.2,
						ValidationSize: 0.1,
					},
				},
				Rollback: &RollbackSettings{
					Enabled:        true,
					Triggers:       []string{"validation_failure", "performance_degradation"},
					Strategy:       "automatic",
					BackupVersions: 3,
				},
			},
		},
		Pipeline: &PipelineIntegrationSettings{
			Stages: []PipelineStage{
				{
					Name:    "feature_extraction",
					Type:    "preprocessing",
					Enabled: true,
					Order:   1,
					Timeout: 5 * time.Second,
				},
				{
					Name:    "ml_inference",
					Type:    "prediction",
					Enabled: true,
					Order:   2,
					Timeout: 10 * time.Second,
				},
				{
					Name:    "result_combination",
					Type:    "postprocessing",
					Enabled: true,
					Order:   3,
					Timeout: 2 * time.Second,
				},
			},
			Parallelism: &ParallelismSettings{
				Enabled:         true,
				MaxWorkers:      4,
				Strategy:        "task",
				LoadBalancing:   "round_robin",
				ResourceSharing: true,
				Synchronization: &SynchronizationSettings{
					Enabled: true,
					Method:  "barrier",
					Timeout: 30 * time.Second,
				},
			},
			Dependencies: &DependencySettings{
				Resolution: "strict",
				Validation: true,
				Caching:    true,
				Versioning: true,
				Injection: &InjectionSettings{
					Enabled:   true,
					Strategy:  "constructor",
					Scope:     "singleton",
					Lifecycle: "application",
				},
			},
			ErrorHandling: &ErrorHandlingSettings{
				Enabled:         true,
				RetryAttempts:   2,
				RetryDelay:      50 * time.Millisecond,
				TimeoutDuration: 30 * time.Second,
				FallbackAction:  "use_scanner_only",
				Logging:         true,
				Notifications:   false,
			},
			Optimization: &OptimizationSettings{
				Optimizer: &OptimizerConfig{
					Type:         "adam",
					LearningRate: 0.001,
					Parameters: map[string]interface{}{
						"beta1": 0.9,
						"beta2": 0.999,
					},
				},
				LossFunction: &LossFunctionConfig{
					Type:       "categorical_crossentropy",
					Parameters: map[string]interface{}{},
				},
				Scheduler: &SchedulerConfig{
					Type:     "step",
					StepSize: 10,
					Gamma:    0.1,
				},
				EarlyStopping: &EarlyStoppingConfig{
					Enabled:  true,
					Patience: 10,
					MinDelta: 0.001,
				},
			},
			Checkpoints: &CheckpointSettings{
				Enabled:       true,
				Frequency:     5,
				Path:          "./checkpoints",
				KeepBest:      3,
				KeepLast:      5,
				Compression:   true,
				CleanupPolicy: "oldest",
				CleanupFreq:   24 * time.Hour,
			},
		},
		ResultProcessing: &ResultProcessingSettings{
			Filtering: &FilteringSettings{
				Enabled:        true,
				MinConfidence:  0.7,
				MaxUncertainty: 0.3,
				Blacklist:      []string{"known_malicious"},
				Whitelist:      []string{"trusted_sources"},
				CustomFilters: map[string]interface{}{
					"confidence_threshold": map[string]interface{}{
						"threshold": 0.7,
						"action":    "accept",
					},
				},
			},
			Enrichment: &EnrichmentSettings{
				Enabled:      true,
				DataSources:  []string{"metadata", "explanation", "risk_factors", "recommendations"},
				EnrichFields: []string{"threat_level", "confidence_score", "risk_assessment"},
				Caching:      true,
				Timeout:      30 * time.Second,
				Fallback:     map[string]interface{}{"default_score": 0.5},
			},
			Aggregation: &AggregationSettings{
				Enabled:    true,
				Method:     "weighted_average",
				GroupBy:    []string{"package_type", "source"},
				TimeWindow: 5 * time.Minute,
				Threshold:  0.8,
			},
			Transformation: &TransformationSettings{
				Enabled:  true,
				Mappings: map[string]string{"score": "normalized_score"},
				Calculations: map[string]interface{}{
					"normalize_scores": map[string]interface{}{
						"min": 0.0,
						"max": 1.0,
					},
				},
				Formatting: map[string]interface{}{"precision": 3},
			},
			Validation: &ValidationSettings{
				Strategy:        "holdout",
				SplitRatio:      []float64{0.7, 0.2, 0.1},
				CrossValidation: nil,
				Bootstrap:       nil,
				Metrics:         []string{"accuracy", "precision", "recall"},
				Thresholds:      map[string]float64{"accuracy": 0.8},
				ValidationFreq:  10,
			},
			Serialization: &SerializationSettings{
				Format:      "json",
				Compression: false,
				Encryption:  false,
				Versioning:  true,
			},
			Caching: &CachingSettings{
				Enabled:        true,
				TTL:            1 * time.Hour,
				MaxSize:        1000,
				EvictionPolicy: "lru",
				Compression:    false,
				Persistent:     false,
				CacheKey:       "default",
				Invalidation:   nil,
			},
		},
		Performance: &IntegrationPerformanceSettings{
			Caching: &CachingSettings{
				Enabled:        true,
				TTL:            30 * time.Minute,
				MaxSize:        500,
				EvictionPolicy: "lru",
				Persistent:     false,
			},
			Batching: &BatchingSettings{
				Enabled:  true,
				Size:     10,
				Timeout:  100 * time.Millisecond,
				Strategy: "adaptive",
			},
			Pooling: &PoolingSettings{
				Enabled:     true,
				MinWorkers:  2,
				MaxWorkers:  8,
				IdleTimeout: 5 * time.Minute,
				Scaling:     "auto",
			},
			RateLimiting: &RateLimitingSettings{
				Enabled:  true,
				Rate:     100,
				Window:   1 * time.Minute,
				Burst:    20,
				Strategy: "token_bucket",
			},
		},
		Monitoring: &IntegrationMonitoringSettings{
			Metrics: &MetricsCollectionSettings{
				Enabled:        true,
				Interval:       30 * time.Second,
				MetricsToTrack: []string{"accuracy", "latency", "throughput"},
				ExportFormat:   "prometheus",
				ExportPath:     "/metrics",
				Retention:      24 * time.Hour,
			},
			Logging: &LoggingSettings{
				Level:      "info",
				OutputPath: "stdout",
				Format:     "json",
				Rotation:   true,
				MaxSize:    100,
				MaxAge:     7,
				Compress:   true,
			},
			Tracing: &TracingSettings{
				Enabled:     true,
				SampleRate:  0.1,
				Exporter:    "jaeger",
				Endpoint:    "http://localhost:14268/api/traces",
				Headers:     map[string]string{},
				Compression: false,
			},
			Alerting: &AlertingSettings{
				Enabled: true,
				Rules: []AlertRule{
					{
						Name:      "high_error_rate",
						Condition: "error_rate > 0.05",
						Severity:  "warning",
						Action:    "notify",
					},
				},
				Channels: []string{"email", "slack"},
			},
		},
		Fallback: &FallbackSettings{
			Enabled:  true,
			Strategy: "graceful",
			Triggers: []string{"ml_unavailable", "timeout", "error_threshold"},
			Actions: []FallbackAction{
				{
					Name:       "scanner_fallback",
					Type:       "fallback",
					Condition:  "ml_unavailable",
					Priority:   1,
					Timeout:    30 * time.Second,
					Parameters: map[string]interface{}{"mode": "scanner_only"},
					Validation: true,
				},
			},
			Recovery: &RecoverySettings{
				Enabled:      true,
				Strategy:     "exponential",
				Attempts:     3,
				Interval:     1 * time.Minute,
				Backoff:      "exponential",
				Validation:   true,
				Notification: true,
			},
		},
	}
}
