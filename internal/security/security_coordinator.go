package security

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/Alivanroy/Typosentinel/pkg/logger"
	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// SecurityCoordinator orchestrates all security components for comprehensive threat detection
// Integrates: temporal detection, complexity analysis, trust validation, ML hardening,
// multi-vector coordination, and behavioral analysis
type SecurityCoordinator struct {
	config                     *SecurityCoordinatorConfig
	temporalDetector           *TemporalDetector
	complexityAnalyzer         *ComplexityAnalyzer
	trustValidator             *TrustValidator
	mlHardeningSystem          *MLHardeningSystem
	multiVectorCoordinator     *MultiVectorCoordinator
	behavioralAnalyzer         *BehavioralAnalyzer
	resourceExhaustionDetector *ResourceExhaustionDetector
	threatIntelligence         *ThreatIntelligence
	responseOrchestrator       *ResponseOrchestrator
	securityMetrics            *SecurityMetrics
	alertManager               *AlertManager
	logger                     logger.Logger
	mutex                      sync.RWMutex
}

// SecurityCoordinatorConfig configures the security coordinator
type SecurityCoordinatorConfig struct {
	EnableTemporalDetection           bool          `yaml:"enable_temporal_detection"`            // true
	EnableComplexityAnalysis          bool          `yaml:"enable_complexity_analysis"`           // true
	EnableTrustValidation             bool          `yaml:"enable_trust_validation"`              // true
	EnableMLHardening                 bool          `yaml:"enable_ml_hardening"`                  // true
	EnableMultiVectorDetection        bool          `yaml:"enable_multi_vector_detection"`        // true
	EnableBehavioralAnalysis          bool          `yaml:"enable_behavioral_analysis"`           // true
	EnableResourceExhaustionDetection bool          `yaml:"enable_resource_exhaustion_detection"` // true
	EnableThreatIntelligence          bool          `yaml:"enable_threat_intelligence"`           // true
	EnableResponseOrchestration       bool          `yaml:"enable_response_orchestration"`        // true
	EnableSecurityMetrics             bool          `yaml:"enable_security_metrics"`              // true
	EnableAlertManagement             bool          `yaml:"enable_alert_management"`              // true
	MaxConcurrentScans                int           `yaml:"max_concurrent_scans"`                 // 10
	ScanTimeout                       time.Duration `yaml:"scan_timeout"`                         // 30m
	ThreatScoreThreshold              float64       `yaml:"threat_score_threshold"`               // 0.7
	CriticalThreatThreshold           float64       `yaml:"critical_threat_threshold"`            // 0.9
	AutoResponseEnabled               bool          `yaml:"auto_response_enabled"`                // false
	Enabled                           bool          `yaml:"enabled"`                              // true
}

// ComprehensiveSecurityResult represents comprehensive security analysis results
type ComprehensiveSecurityResult struct {
	PackageName                string                            `json:"package_name"`
	OverallThreatScore         float64                           `json:"overall_threat_score"`
	ThreatLevel                string                            `json:"threat_level"`
	TemporalAnalysis           *TemporalThreat                   `json:"temporal_analysis"`
	ComplexityAnalysis         *ComplexityThreat                 `json:"complexity_analysis"`
	TrustValidation            *TrustValidationResult            `json:"trust_validation"`
	MLHardening                *MLHardeningResult                `json:"ml_hardening"`
	MultiVectorAnalysis        *MultiVectorAnalysisResult        `json:"multi_vector_analysis"`
	BehavioralAnalysis         *BehavioralAnalysisResult         `json:"behavioral_analysis"`
	ResourceExhaustionAnalysis *ResourceExhaustionAnalysisResult `json:"resource_exhaustion_analysis"`
	ThreatIntelligence         *ThreatIntelResult                `json:"threat_intelligence"`
	SecurityMetrics            *SecurityMetricsResult            `json:"security_metrics"`
	DetectedThreats            []DetectedThreat                  `json:"detected_threats"`
	SecurityRecommendations    []SecurityRecommendation          `json:"security_recommendations"`
	ResponseActions            []ResponseAction                  `json:"response_actions"`
	AlertsGenerated            []SecurityAlert                   `json:"alerts_generated"`
	AnalysisTimestamp          time.Time                         `json:"analysis_timestamp"`
	AnalysisDuration           time.Duration                     `json:"analysis_duration"`
	RequiresImmediateAction    bool                              `json:"requires_immediate_action"`
	Metadata                   map[string]interface{}            `json:"metadata"`
}

// DetectedThreat represents a detected security threat
type DetectedThreat struct {
	ThreatID             string                 `json:"threat_id"`
	ThreatType           string                 `json:"threat_type"`
	ThreatCategory       string                 `json:"threat_category"`
	Severity             string                 `json:"severity"`
	Confidence           float64                `json:"confidence"`
	Description          string                 `json:"description"`
	Evidence             []string               `json:"evidence"`
	DetectionSource      string                 `json:"detection_source"`
	DetectionTimestamp   time.Time              `json:"detection_timestamp"`
	AffectedComponents   []string               `json:"affected_components"`
	PotentialImpact      string                 `json:"potential_impact"`
	MitigationStrategies []string               `json:"mitigation_strategies"`
	Context              map[string]interface{} `json:"context"`
}

// SecurityRecommendation represents security recommendations
type SecurityRecommendation struct {
	RecommendationID   string    `json:"recommendation_id"`
	RecommendationType string    `json:"recommendation_type"`
	Priority           string    `json:"priority"`
	Title              string    `json:"title"`
	Description        string    `json:"description"`
	ActionItems        []string  `json:"action_items"`
	EstimatedEffort    string    `json:"estimated_effort"`
	ExpectedBenefit    string    `json:"expected_benefit"`
	Timestamp          time.Time `json:"timestamp"`
}

// ResponseAction represents automated response actions
type ResponseAction struct {
	ActionID      string                 `json:"action_id"`
	ActionType    string                 `json:"action_type"`
	ActionStatus  string                 `json:"action_status"`
	Description   string                 `json:"description"`
	ExecutionTime time.Time              `json:"execution_time"`
	Result        string                 `json:"result"`
	Parameters    map[string]interface{} `json:"parameters"`
}

// SecurityAlert represents security alerts
type SecurityAlert struct {
	AlertID         string                 `json:"alert_id"`
	AlertType       string                 `json:"alert_type"`
	Severity        string                 `json:"severity"`
	Title           string                 `json:"title"`
	Message         string                 `json:"message"`
	Timestamp       time.Time              `json:"timestamp"`
	Source          string                 `json:"source"`
	AffectedPackage string                 `json:"affected_package"`
	Context         map[string]interface{} `json:"context"`
	Acknowledged    bool                   `json:"acknowledged"`
}

// ThreatIntelligenceService provides threat intelligence capabilities
type ThreatIntelligenceService struct {
	threatFeeds     []ThreatFeed
	threatDatabase  map[string]ThreatRecord
	intelligenceAPI string
	updateInterval  time.Duration
	lastUpdate      time.Time
	mutex           sync.RWMutex
}

// ThreatFeed represents threat intelligence feeds
type ThreatFeed struct {
	FeedID      string    `json:"feed_id"`
	FeedName    string    `json:"feed_name"`
	FeedURL     string    `json:"feed_url"`
	FeedType    string    `json:"feed_type"`
	LastUpdate  time.Time `json:"last_update"`
	RecordCount int       `json:"record_count"`
	Enabled     bool      `json:"enabled"`
}

// ThreatIntelRecord represents threat intelligence records
type ThreatIntelRecord struct {
	RecordID      string                 `json:"record_id"`
	ThreatType    string                 `json:"threat_type"`
	Indicator     string                 `json:"indicator"`
	IndicatorType string                 `json:"indicator_type"`
	Confidence    float64                `json:"confidence"`
	Severity      string                 `json:"severity"`
	Description   string                 `json:"description"`
	Source        string                 `json:"source"`
	FirstSeen     time.Time              `json:"first_seen"`
	LastSeen      time.Time              `json:"last_seen"`
	Tags          []string               `json:"tags"`
	Context       map[string]interface{} `json:"context"`
}

// ThreatIntelResult represents threat intelligence analysis results
type ThreatIntelResult struct {
	MatchedThreats      []ThreatMatch `json:"matched_threats"`
	ThreatScore         float64       `json:"threat_score"`
	IntelligenceSources []string      `json:"intelligence_sources"`
	LastUpdate          time.Time     `json:"last_update"`
	Recommendations     []string      `json:"recommendations"`
}

// ThreatMatch represents matched threat intelligence
type ThreatMatch struct {
	ThreatRecord    ThreatIntelRecord `json:"threat_record"`
	MatchType       string            `json:"match_type"`
	MatchConfidence float64           `json:"match_confidence"`
	MatchedValue    string            `json:"matched_value"`
}

// ResponseOrchestrationService manages automated response actions
type ResponseOrchestrationService struct {
	responseRules   []ResponseRule
	responseActions map[string]ResponseActionHandler
	responseHistory []ResponseRecord
	escalationRules []EscalationRule
	mutex           sync.RWMutex
}

// ResponseRule defines automated response rules
type ResponseRule struct {
	RuleID           string                 `json:"rule_id"`
	RuleName         string                 `json:"rule_name"`
	TriggerCondition string                 `json:"trigger_condition"`
	ActionType       string                 `json:"action_type"`
	Parameters       map[string]interface{} `json:"parameters"`
	Enabled          bool                   `json:"enabled"`
	Priority         int                    `json:"priority"`
}

// ResponseActionHandler defines response action handlers
type ResponseActionHandler func(ctx context.Context, params map[string]interface{}) error

// ResponseRecord represents response execution records
type ResponseRecord struct {
	RecordID        string                 `json:"record_id"`
	RuleID          string                 `json:"rule_id"`
	ActionType      string                 `json:"action_type"`
	ExecutionTime   time.Time              `json:"execution_time"`
	ExecutionResult string                 `json:"execution_result"`
	Parameters      map[string]interface{} `json:"parameters"`
	Success         bool                   `json:"success"`
	ErrorMessage    string                 `json:"error_message"`
}

// EscalationRule defines escalation rules
type EscalationRule struct {
	RuleID           string        `json:"rule_id"`
	TriggerCondition string        `json:"trigger_condition"`
	EscalationDelay  time.Duration `json:"escalation_delay"`
	EscalationAction string        `json:"escalation_action"`
	Enabled          bool          `json:"enabled"`
}

// SecurityMetrics tracks security metrics
type SecurityMetrics struct {
	scanMetrics        map[string]ScanMetric
	threatMetrics      map[string]ThreatMetric
	performanceMetrics map[string]PerformanceMetric
	alertMetrics       map[string]AlertMetric
	mutex              sync.RWMutex
}

// ScanMetric represents scan metrics
type ScanMetric struct {
	MetricID        string        `json:"metric_id"`
	ScanType        string        `json:"scan_type"`
	ScanCount       int           `json:"scan_count"`
	SuccessRate     float64       `json:"success_rate"`
	AverageDuration time.Duration `json:"average_duration"`
	LastScan        time.Time     `json:"last_scan"`
}

// ThreatMetric represents threat metrics
type ThreatMetric struct {
	MetricID       string  `json:"metric_id"`
	ThreatType     string  `json:"threat_type"`
	DetectionCount int     `json:"detection_count"`
	FalsePositives int     `json:"false_positives"`
	TruePositives  int     `json:"true_positives"`
	Accuracy       float64 `json:"accuracy"`
}

// SecurityPerformanceMetric represents performance metrics
type SecurityPerformanceMetric struct {
	MetricID       string        `json:"metric_id"`
	ComponentName  string        `json:"component_name"`
	AverageLatency time.Duration `json:"average_latency"`
	Throughput     float64       `json:"throughput"`
	ErrorRate      float64       `json:"error_rate"`
	ResourceUsage  float64       `json:"resource_usage"`
}

// AlertMetric represents alert metrics
type AlertMetric struct {
	MetricID            string        `json:"metric_id"`
	AlertType           string        `json:"alert_type"`
	AlertCount          int           `json:"alert_count"`
	AcknowledgedCount   int           `json:"acknowledged_count"`
	ResolvedCount       int           `json:"resolved_count"`
	AverageResponseTime time.Duration `json:"average_response_time"`
}

// SecurityMetricsResult represents security metrics results
type SecurityMetricsResult struct {
	ScanMetrics        []ScanMetric        `json:"scan_metrics"`
	ThreatMetrics      []ThreatMetric      `json:"threat_metrics"`
	PerformanceMetrics []PerformanceMetric `json:"performance_metrics"`
	AlertMetrics       []AlertMetric       `json:"alert_metrics"`
	OverallHealth      string              `json:"overall_health"`
	HealthScore        float64             `json:"health_score"`
	GeneratedAt        time.Time           `json:"generated_at"`
}

// AlertManager manages security alerts
type AlertManager struct {
	alerts               map[string]SecurityAlert
	alertRules           []AlertRule
	notificationChannels []NotificationChannel
	alertHistory         []AlertRecord
	mutex                sync.RWMutex
}

// AlertRule defines alert generation rules
type AlertRule struct {
	RuleID           string                 `json:"rule_id"`
	RuleName         string                 `json:"rule_name"`
	TriggerCondition string                 `json:"trigger_condition"`
	Severity         string                 `json:"severity"`
	AlertTemplate    string                 `json:"alert_template"`
	Parameters       map[string]interface{} `json:"parameters"`
	Enabled          bool                   `json:"enabled"`
}

// NotificationChannel defines notification channels
type NotificationChannel struct {
	ChannelID     string                 `json:"channel_id"`
	ChannelType   string                 `json:"channel_type"`
	Configuration map[string]interface{} `json:"configuration"`
	Enabled       bool                   `json:"enabled"`
}

// AlertRecord represents alert history records
type AlertRecord struct {
	RecordID  string    `json:"record_id"`
	AlertID   string    `json:"alert_id"`
	Action    string    `json:"action"`
	Timestamp time.Time `json:"timestamp"`
	User      string    `json:"user"`
	Notes     string    `json:"notes"`
}

// NewSecurityCoordinator creates a new security coordinator
func NewSecurityCoordinator(config *SecurityCoordinatorConfig, logger logger.Logger) *SecurityCoordinator {
	sc := &SecurityCoordinator{
		config: config,
		logger: logger,
	}

	// Initialize components based on configuration
	if config.EnableTemporalDetection {
		temporalConfig := DefaultTemporalDetectorConfig()
		sc.temporalDetector = NewTemporalDetector(temporalConfig, logger)
	}

	if config.EnableComplexityAnalysis {
		complexityConfig := DefaultComplexityAnalyzerConfig()
		sc.complexityAnalyzer = NewComplexityAnalyzer(complexityConfig, logger)
	}

	if config.EnableTrustValidation {
		trustConfig := DefaultTrustValidatorConfig()
		sc.trustValidator = NewTrustValidator(trustConfig, logger)
	}

	if config.EnableResourceExhaustionDetection {
		resourceConfig := DefaultResourceExhaustionConfig()
		sc.resourceExhaustionDetector = NewResourceExhaustionDetector(resourceConfig, logger)
		// Start will be called when the coordinator starts
	}

	return sc
}

// PerformComprehensiveSecurityAnalysis performs comprehensive security analysis
func (sc *SecurityCoordinator) PerformComprehensiveSecurityAnalysis(ctx context.Context, pkg *types.Package) (*ComprehensiveSecurityResult, error) {
	sc.mutex.Lock()
	defer sc.mutex.Unlock()

	startTime := time.Now()
	sc.logger.Info("Starting comprehensive security analysis for package: " + pkg.Name)

	result := &ComprehensiveSecurityResult{
		PackageName:       pkg.Name,
		AnalysisTimestamp: startTime,
		Metadata:          make(map[string]interface{}),
	}

	var threats []DetectedThreat
	var recommendations []SecurityRecommendation
	var alerts []SecurityAlert

	// Perform temporal detection
	if sc.config.EnableTemporalDetection && sc.temporalDetector != nil {
		temporalResult, err := sc.temporalDetector.AnalyzeTemporalThreats(ctx, pkg)
		if err != nil {
			sc.logger.Error("Temporal detection failed: " + err.Error())
		} else {
			result.TemporalAnalysis = temporalResult
			threats = append(threats, sc.extractThreatsFromTemporal(temporalResult)...)
		}
	}

	// Perform complexity analysis
	if sc.config.EnableComplexityAnalysis && sc.complexityAnalyzer != nil {
		complexityResult, err := sc.complexityAnalyzer.AnalyzeComplexity(ctx, pkg)
		if err != nil {
			sc.logger.Error("Complexity analysis failed: " + err.Error())
		} else {
			result.ComplexityAnalysis = complexityResult
			threats = append(threats, sc.extractThreatsFromComplexity(complexityResult)...)
		}
	}

	// Perform trust validation
	if sc.config.EnableTrustValidation && sc.trustValidator != nil {
		trustResult, err := sc.trustValidator.ValidateTrust(ctx, pkg)
		if err != nil {
			sc.logger.Error("Trust validation failed: " + err.Error())
		} else {
			result.TrustValidation = trustResult
			threats = append(threats, sc.extractThreatsFromTrust(trustResult)...)
		}
	}

	// Perform resource exhaustion analysis
	if sc.config.EnableResourceExhaustionDetection && sc.resourceExhaustionDetector != nil {
		resourceResult, err := sc.performResourceExhaustionAnalysis(ctx, pkg)
		if err != nil {
			sc.logger.Error("Resource exhaustion analysis failed: " + err.Error())
		} else {
			result.ResourceExhaustionAnalysis = resourceResult
			threats = append(threats, sc.extractThreatsFromResourceExhaustion(resourceResult)...)
		}
	}

	// Calculate overall threat score
	result.OverallThreatScore = sc.calculateOverallThreatScore(result)
	result.ThreatLevel = sc.determineThreatLevel(result.OverallThreatScore)
	result.DetectedThreats = threats
	result.SecurityRecommendations = recommendations
	result.AlertsGenerated = alerts
	result.AnalysisDuration = time.Since(startTime)
	result.RequiresImmediateAction = result.OverallThreatScore >= sc.config.CriticalThreatThreshold

	sc.logger.Info(fmt.Sprintf("Completed comprehensive security analysis for package %s with threat score %.2f", pkg.Name, result.OverallThreatScore))
	return result, nil
}

func (sc *SecurityCoordinator) extractThreatsFromTemporal(result *TemporalThreat) []DetectedThreat {
	var threats []DetectedThreat
	if result != nil {
		threat := DetectedThreat{
			ThreatID:           result.ThreatID,
			ThreatType:         result.ThreatType,
			ThreatCategory:     "Temporal",
			Severity:           result.Severity.String(),
			Confidence:         result.ConfidenceScore,
			Description:        "Temporal threat detected",
			DetectionSource:    "TemporalDetector",
			DetectionTimestamp: time.Now(),
			Context:            result.Metadata,
		}
		threats = append(threats, threat)
	}
	return threats
}

func (sc *SecurityCoordinator) extractThreatsFromComplexity(result *ComplexityThreat) []DetectedThreat {
	var threats []DetectedThreat
	if result != nil {
		threat := DetectedThreat{
			ThreatID:           result.ThreatID,
			ThreatType:         result.ThreatType,
			ThreatCategory:     "Complexity",
			Severity:           result.Severity.String(),
			Confidence:         result.ComplexityScore,
			Description:        "Complexity threat detected",
			DetectionSource:    "ComplexityAnalyzer",
			DetectionTimestamp: time.Now(),
			Context:            result.Metadata,
		}
		threats = append(threats, threat)
	}
	return threats
}

func (sc *SecurityCoordinator) extractThreatsFromTrust(result *TrustValidationResult) []DetectedThreat {
	var threats []DetectedThreat
	// Implementation to extract threats from trust validation
	return threats
}

func (sc *SecurityCoordinator) performResourceExhaustionAnalysis(ctx context.Context, pkg *types.Package) (*ResourceExhaustionAnalysisResult, error) {
	if sc.resourceExhaustionDetector == nil {
		return nil, fmt.Errorf("resource exhaustion detector not initialized")
	}

	// Get current resource metrics
	currentMetrics := sc.resourceExhaustionDetector.GetCurrentMetrics()

	// Get detected patterns (empty for now, would need to implement this method)
	var detectedPatterns []PatternDetection

	// Get active alerts
	activeAlertsPtr := sc.resourceExhaustionDetector.GetActiveAlerts()
	activeAlerts := make([]ResourceExhaustionAlert, len(activeAlertsPtr))
	for i, alert := range activeAlertsPtr {
		if alert != nil {
			activeAlerts[i] = *alert
		}
	}

	// Get active mitigations (empty for now, would need to implement this method)
	var activeMitigations []ActiveMitigation

	// Calculate threat score based on current metrics and patterns
	threatScore := sc.calculateResourceThreatScore(currentMetrics, detectedPatterns)

	// Determine system health
	systemHealth := sc.determineSystemHealth(currentMetrics, threatScore)

	// Generate recommendations
	recommendations := sc.generateResourceRecommendations(currentMetrics, detectedPatterns)

	result := &ResourceExhaustionAnalysisResult{
		ThreatScore:       threatScore,
		ThreatLevel:       sc.determineThreatLevel(threatScore),
		CurrentMetrics:    currentMetrics,
		DetectedPatterns:  detectedPatterns,
		ActiveAlerts:      activeAlerts,
		ActiveMitigations: activeMitigations,
		Recommendations:   recommendations,
		SystemHealth:      systemHealth,
		AnalysisTimestamp: time.Now(),
		Metrics:           sc.resourceExhaustionDetector.GetDetectorMetrics(),
	}

	return result, nil
}

func (sc *SecurityCoordinator) extractThreatsFromResourceExhaustion(result *ResourceExhaustionAnalysisResult) []DetectedThreat {
	var threats []DetectedThreat

	if result == nil {
		return threats
	}

	// Extract threats from detected patterns
	for _, pattern := range result.DetectedPatterns {
		threat := DetectedThreat{
			ThreatID:           fmt.Sprintf("resource-exhaustion-%d", time.Now().Unix()),
			ThreatType:         "Resource Exhaustion",
			ThreatCategory:     "Performance",
			Severity:           sc.mapConfidenceToSeverity(pattern.Confidence),
			Confidence:         pattern.Confidence,
			Description:        fmt.Sprintf("Resource exhaustion pattern detected: %s", pattern.PatternName),
			DetectionSource:    "ResourceExhaustionDetector",
			DetectionTimestamp: pattern.DetectedAt,
			Context:            map[string]interface{}{"pattern": pattern, "evidence": pattern.Evidence},
		}
		threats = append(threats, threat)
	}

	// Extract threats from active alerts
	for _, alert := range result.ActiveAlerts {
		threat := DetectedThreat{
			ThreatID:           fmt.Sprintf("resource-alert-%s", alert.AlertID),
			ThreatType:         "Resource Alert",
			ThreatCategory:     "Performance",
			Severity:           alert.Severity.String(),
			Confidence:         0.9, // High confidence for active alerts
			Description:        alert.Message,
			DetectionSource:    "ResourceExhaustionDetector",
			DetectionTimestamp: alert.DetectedAt,
			Context:            map[string]interface{}{"alert": alert},
		}
		threats = append(threats, threat)
	}

	return threats
}

func (sc *SecurityCoordinator) calculateResourceThreatScore(metrics *ResourceUsageMetrics, patterns []PatternDetection) float64 {
	if metrics == nil {
		return 0.0
	}

	var score float64

	// Base score from resource utilization
	if metrics.CPUUsage > 80.0 {
		score += 0.3
	}
	if metrics.MemoryUsage > 1024*1024*1024 { // 1GB
		score += 0.3
	}
	if metrics.GoroutineCount > 10000 {
		score += 0.2
	}

	// Additional score from detected patterns
	for _, pattern := range patterns {
		score += pattern.Confidence * 0.1
	}

	// Cap the score at 1.0
	if score > 1.0 {
		score = 1.0
	}

	return score
}

func (sc *SecurityCoordinator) determineSystemHealth(metrics *ResourceUsageMetrics, threatScore float64) string {
	if threatScore > 0.8 {
		return "Critical"
	} else if threatScore > 0.6 {
		return "Warning"
	} else if threatScore > 0.3 {
		return "Caution"
	}
	return "Healthy"
}

func (sc *SecurityCoordinator) generateResourceRecommendations(metrics *ResourceUsageMetrics, patterns []PatternDetection) []string {
	var recommendations []string

	if metrics != nil {
		if metrics.CPUUsage > 80.0 {
			recommendations = append(recommendations, "Consider optimizing CPU-intensive operations")
		}
		if metrics.MemoryUsage > 1024*1024*1024 {
			recommendations = append(recommendations, "Monitor memory usage and implement garbage collection optimizations")
		}
		if metrics.GoroutineCount > 10000 {
			recommendations = append(recommendations, "Review goroutine management and implement proper cleanup")
		}
	}

	if len(patterns) > 0 {
		recommendations = append(recommendations, "Investigate detected resource exhaustion patterns")
	}

	return recommendations
}

func (sc *SecurityCoordinator) mapConfidenceToSeverity(confidence float64) string {
	if confidence > 0.8 {
		return "High"
	} else if confidence > 0.6 {
		return "Medium"
	}
	return "Low"
}

func (sc *SecurityCoordinator) calculateOverallThreatScore(result *ComprehensiveSecurityResult) float64 {
	var scores []float64
	var weights []float64

	if result.TemporalAnalysis != nil {
		scores = append(scores, result.TemporalAnalysis.ConfidenceScore)
		weights = append(weights, 0.15)
	}

	if result.ComplexityAnalysis != nil {
		scores = append(scores, result.ComplexityAnalysis.ComplexityScore)
		weights = append(weights, 0.15)
	}

	if result.TrustValidation != nil {
		scores = append(scores, result.TrustValidation.OverallTrustScore)
		weights = append(weights, 0.25)
	}

	if result.ResourceExhaustionAnalysis != nil {
		scores = append(scores, result.ResourceExhaustionAnalysis.ThreatScore)
		weights = append(weights, 0.25)
	}

	if len(scores) == 0 {
		return 0.0
	}

	var weightedSum, totalWeight float64
	for i, score := range scores {
		weightedSum += score * weights[i]
		totalWeight += weights[i]
	}

	return weightedSum / totalWeight
}

func (sc *SecurityCoordinator) determineThreatLevel(score float64) string {
	if score >= sc.config.CriticalThreatThreshold {
		return "CRITICAL"
	} else if score >= sc.config.ThreatScoreThreshold {
		return "HIGH"
	} else if score >= 0.5 {
		return "MEDIUM"
	} else if score >= 0.3 {
		return "LOW"
	}
	return "MINIMAL"
}
