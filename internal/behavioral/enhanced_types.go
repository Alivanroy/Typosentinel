package behavioral

import (
	"encoding/json"
	"regexp"
	"sort"
	"sync"
	"time"
)

// EnhancedBehavioralAnalysis represents the result of enhanced behavioral analysis
type EnhancedBehavioralAnalysis struct {
	PackageName         string                    `json:"package_name"`
	AnalysisTimestamp   time.Time                 `json:"analysis_timestamp"`
	Duration            time.Duration             `json:"duration"`
	TotalEvents         int                       `json:"total_events"`
	Anomalies           []EnhancedAnomaly         `json:"anomalies"`
	PatternMatches      []EnhancedPatternMatch    `json:"pattern_matches"`
	ThreatIntelHits     []ThreatIntelHit          `json:"threat_intel_hits"`
	MLPredictions       []MLPrediction            `json:"ml_predictions"`
	RiskAssessment      *RiskAssessment           `json:"risk_assessment"`
	Recommendations     []string                  `json:"recommendations"`
	Metrics             *MonitorMetrics           `json:"metrics"`
	BehaviorProfile     *BehaviorProfile          `json:"behavior_profile"`
	CorrelatedEvents    []EventCorrelation        `json:"correlated_events"`
	TimelineAnalysis    *TimelineAnalysis         `json:"timeline_analysis"`
	AttackChains        []AttackChain             `json:"attack_chains"`
	IOCs                []IOC                     `json:"iocs"`
	MITREMapping        []MITREMapping            `json:"mitre_mapping"`
	ConfidenceScore     float64                   `json:"confidence_score"`
	SeverityLevel       string                    `json:"severity_level"`
	ActionRequired      bool                      `json:"action_required"`
	Metadata            map[string]interface{}    `json:"metadata"`
}

// EnhancedAnomaly represents an advanced behavioral anomaly
type EnhancedAnomaly struct {
	ID                  string                 `json:"id"`
	Type                string                 `json:"type"`
	Category            string                 `json:"category"`
	Description         string                 `json:"description"`
	Severity            string                 `json:"severity"`
	Confidence          float64                `json:"confidence"`
	AnomalyScore        float64                `json:"anomaly_score"`
	Baseline            interface{}            `json:"baseline"`
	Observed            interface{}            `json:"observed"`
	Deviation           float64                `json:"deviation"`
	StatisticalSignificance float64            `json:"statistical_significance"`
	FirstSeen           time.Time              `json:"first_seen"`
	LastSeen            time.Time              `json:"last_seen"`
	Frequency           int                    `json:"frequency"`
	RelatedEvents       []string               `json:"related_events"`
	Context             map[string]interface{} `json:"context"`
	MITREMapping        []string               `json:"mitre_mapping"`
	Recommendations     []string               `json:"recommendations"`
}

// EnhancedPatternMatch represents an advanced pattern match
type EnhancedPatternMatch struct {
	PatternID           string                 `json:"pattern_id"`
	PatternName         string                 `json:"pattern_name"`
	Description         string                 `json:"description"`
	Severity            string                 `json:"severity"`
	Confidence          float64                `json:"confidence"`
	MatchScore          float64                `json:"match_score"`
	MatchedEvents       []string               `json:"matched_events"`
	MatchedConditions   []ConditionMatch       `json:"matched_conditions"`
	TimeWindow          time.Duration          `json:"time_window"`
	FirstMatch          time.Time              `json:"first_match"`
	LastMatch           time.Time              `json:"last_match"`
	MatchCount          int                    `json:"match_count"`
	MITREMapping        []string               `json:"mitre_mapping"`
	TTPs                []string               `json:"ttps"`
	IOCs                []string               `json:"iocs"`
	Context             map[string]interface{} `json:"context"`
	Recommendations     []string               `json:"recommendations"`
}

// ConditionMatch represents a matched condition within a pattern
type ConditionMatch struct {
	ConditionID         string      `json:"condition_id"`
	Field               string      `json:"field"`
	Operator            string      `json:"operator"`
	ExpectedValue       interface{} `json:"expected_value"`
	ActualValue         interface{} `json:"actual_value"`
	MatchScore          float64     `json:"match_score"`
	Weight              float64     `json:"weight"`
	Timestamp           time.Time   `json:"timestamp"`
}

// MLPrediction represents a machine learning prediction
type MLPrediction struct {
	ModelName           string                 `json:"model_name"`
	ModelVersion        string                 `json:"model_version"`
	PredictionType      string                 `json:"prediction_type"`
	Prediction          string                 `json:"prediction"`
	Confidence          float64                `json:"confidence"`
	Probabilities       map[string]float64     `json:"probabilities"`
	Features            map[string]float64     `json:"features"`
	FeatureImportance   map[string]float64     `json:"feature_importance"`
	Explanation         string                 `json:"explanation"`
	Timestamp           time.Time              `json:"timestamp"`
	ProcessingTime      time.Duration          `json:"processing_time"`
	Metadata            map[string]interface{} `json:"metadata"`
}

// RiskAssessment represents a comprehensive risk assessment
type RiskAssessment struct {
	OverallRiskScore    float64                `json:"overall_risk_score"`
	RiskLevel           string                 `json:"risk_level"`
	RiskFactors         []RiskFactor           `json:"risk_factors"`
	MitigatingFactors   []string               `json:"mitigating_factors"`
	AggravatingFactors  []string               `json:"aggravating_factors"`
	BusinessImpact      string                 `json:"business_impact"`
	TechnicalImpact     string                 `json:"technical_impact"`
	Likelihood          float64                `json:"likelihood"`
	Impact              float64                `json:"impact"`
	Exposure            float64                `json:"exposure"`
	Vulnerability       float64                `json:"vulnerability"`
	ThreatLevel         float64                `json:"threat_level"`
	ConfidenceLevel     float64                `json:"confidence_level"`
	RecommendedActions  []string               `json:"recommended_actions"`
	TimeToRemediation   time.Duration          `json:"time_to_remediation"`
	RiskTrend           string                 `json:"risk_trend"`
	HistoricalComparison map[string]float64    `json:"historical_comparison"`
}

// RiskFactor represents an individual risk factor
type RiskFactor struct {
	Name                string                 `json:"name"`
	Description         string                 `json:"description"`
	Category            string                 `json:"category"`
	Severity            string                 `json:"severity"`
	Weight              float64                `json:"weight"`
	Score               float64                `json:"score"`
	Contribution        float64                `json:"contribution"`
	Evidence            []string               `json:"evidence"`
	Mitigation          []string               `json:"mitigation"`
	MITREMapping        []string               `json:"mitre_mapping"`
}

// EventCorrelation represents correlated events
type EventCorrelation struct {
	CorrelationID       string                 `json:"correlation_id"`
	CorrelationType     string                 `json:"correlation_type"`
	Events              []string               `json:"events"`
	TimeWindow          time.Duration          `json:"time_window"`
	CorrelationScore    float64                `json:"correlation_score"`
	CausalRelationship  bool                   `json:"causal_relationship"`
	Description         string                 `json:"description"`
	Significance        string                 `json:"significance"`
	Metadata            map[string]interface{} `json:"metadata"`
}

// TimelineAnalysis represents temporal analysis of events
type TimelineAnalysis struct {
	StartTime           time.Time              `json:"start_time"`
	EndTime             time.Time              `json:"end_time"`
	Duration            time.Duration          `json:"duration"`
	EventDistribution   map[string]int         `json:"event_distribution"`
	PeakActivity        []ActivityPeak         `json:"peak_activity"`
	AnomalousTimeframes []TimeFrame            `json:"anomalous_timeframes"`
	Patterns            []TemporalPattern      `json:"patterns"`
	Trends              []Trend                `json:"trends"`
	Seasonality         []SeasonalPattern      `json:"seasonality"`
}

// AttackChain represents a sequence of related malicious activities
type AttackChain struct {
	ChainID             string                 `json:"chain_id"`
	Name                string                 `json:"name"`
	Description         string                 `json:"description"`
	Stages              []AttackStage          `json:"stages"`
	Severity            string                 `json:"severity"`
	Confidence          float64                `json:"confidence"`
	MITREMapping        []string               `json:"mitre_mapping"`
	KillChainPhases     []string               `json:"kill_chain_phases"`
	TTPs                []string               `json:"ttps"`
	IOCs                []string               `json:"iocs"`
	StartTime           time.Time              `json:"start_time"`
	EndTime             time.Time              `json:"end_time"`
	Duration            time.Duration          `json:"duration"`
}

// AttackStage represents a stage in an attack chain
type AttackStage struct {
	StageID             string                 `json:"stage_id"`
	Name                string                 `json:"name"`
	Description         string                 `json:"description"`
	Techniques          []string               `json:"techniques"`
	Events              []string               `json:"events"`
	Timestamp           time.Time              `json:"timestamp"`
	Duration            time.Duration          `json:"duration"`
	Success             bool                   `json:"success"`
	Impact              string                 `json:"impact"`
	MITREMapping        []string               `json:"mitre_mapping"`
}

// IOC represents an Indicator of Compromise
type IOC struct {
	Type                string                 `json:"type"`
	Value               string                 `json:"value"`
	Description         string                 `json:"description"`
	Severity            string                 `json:"severity"`
	Confidence          float64                `json:"confidence"`
	FirstSeen           time.Time              `json:"first_seen"`
	LastSeen            time.Time              `json:"last_seen"`
	Source              string                 `json:"source"`
	Tags                []string               `json:"tags"`
	Context             map[string]interface{} `json:"context"`
	ThreatTypes         []string               `json:"threat_types"`
	MalwareFamilies     []string               `json:"malware_families"`
	Campaigns           []string               `json:"campaigns"`
	Actors              []string               `json:"actors"`
}

// MITREMapping represents MITRE ATT&CK framework mapping
type MITREMapping struct {
	TacticID            string                 `json:"tactic_id"`
	TacticName          string                 `json:"tactic_name"`
	TechniqueID         string                 `json:"technique_id"`
	TechniqueName       string                 `json:"technique_name"`
	SubTechniqueID      string                 `json:"sub_technique_id"`
	SubTechniqueName    string                 `json:"sub_technique_name"`
	Description         string                 `json:"description"`
	Detection           []string               `json:"detection"`
	Mitigation          []string               `json:"mitigation"`
	References          []string               `json:"references"`
	Platforms           []string               `json:"platforms"`
	DataSources         []string               `json:"data_sources"`
	PermissionsRequired []string               `json:"permissions_required"`
}

// Supporting pattern types
type NetworkPattern struct {
	Protocols           []string               `json:"protocols"`
	Ports               []int                  `json:"ports"`
	Destinations        []string               `json:"destinations"`
	Frequency           float64                `json:"frequency"`
	DataVolume          int64                  `json:"data_volume"`
	TimePattern         string                 `json:"time_pattern"`
}

type FilePattern struct {
	Operations          []string               `json:"operations"`
	Paths               []string               `json:"paths"`
	Extensions          []string               `json:"extensions"`
	Sizes               []int64                `json:"sizes"`
	Frequency           float64                `json:"frequency"`
	AccessPattern       string                 `json:"access_pattern"`
}

type ProcessPattern struct {
	Names               []string               `json:"names"`
	Commands            []string               `json:"commands"`
	ParentProcesses     []string               `json:"parent_processes"`
	Frequency           float64                `json:"frequency"`
	Lifetime            time.Duration          `json:"lifetime"`
	ResourceUsage       map[string]float64     `json:"resource_usage"`
}

type TemporalPattern struct {
	Type                string                 `json:"type"`
	Interval            time.Duration          `json:"interval"`
	Frequency           float64                `json:"frequency"`
	Regularity          float64                `json:"regularity"`
	StartTime           time.Time              `json:"start_time"`
	EndTime             time.Time              `json:"end_time"`
	DaysOfWeek          []int                  `json:"days_of_week"`
	HoursOfDay          []int                  `json:"hours_of_day"`
}

type ActivityPeak struct {
	StartTime           time.Time              `json:"start_time"`
	EndTime             time.Time              `json:"end_time"`
	EventCount          int                    `json:"event_count"`
	EventTypes          []string               `json:"event_types"`
	Intensity           float64                `json:"intensity"`
	Anomalous           bool                   `json:"anomalous"`
}

type TimeFrame struct {
	StartTime           time.Time              `json:"start_time"`
	EndTime             time.Time              `json:"end_time"`
	Reason              string                 `json:"reason"`
	AnomalyScore        float64                `json:"anomaly_score"`
	Events              []string               `json:"events"`
}

type Trend struct {
	Metric              string                 `json:"metric"`
	Direction           string                 `json:"direction"`
	Magnitude           float64                `json:"magnitude"`
	Significance        float64                `json:"significance"`
	StartTime           time.Time              `json:"start_time"`
	EndTime             time.Time              `json:"end_time"`
	Prediction          map[string]float64     `json:"prediction"`
}

type SeasonalPattern struct {
	Type                string                 `json:"type"`
	Period              time.Duration          `json:"period"`
	Amplitude           float64                `json:"amplitude"`
	Phase               float64                `json:"phase"`
	Confidence          float64                `json:"confidence"`
	Description         string                 `json:"description"`
}

// Advanced analysis components
type StatisticalModel struct {
	Name                string                 `json:"name"`
	Type                string                 `json:"type"`
	Parameters          map[string]float64     `json:"parameters"`
	Accuracy            float64                `json:"accuracy"`
	LastUpdated         time.Time              `json:"last_updated"`
	TrainingData        int                    `json:"training_data"`
	ValidationScore     float64                `json:"validation_score"`
}

type MLAnomalyDetector struct {
	Models              map[string]*MLModel    `json:"models"`
	Thresholds          map[string]float64     `json:"thresholds"`
	FeatureScalers      map[string]interface{} `json:"feature_scalers"`
	LastUpdate          time.Time              `json:"last_update"`
}

type MLModel struct {
	Name                string                 `json:"name"`
	Type                string                 `json:"type"`
	Version             string                 `json:"version"`
	Path                string                 `json:"path"`
	Accuracy            float64                `json:"accuracy"`
	Precision           float64                `json:"precision"`
	Recall              float64                `json:"recall"`
	F1Score             float64                `json:"f1_score"`
	TrainingDate        time.Time              `json:"training_date"`
	Features            []string               `json:"features"`
	Hyperparameters     map[string]interface{} `json:"hyperparameters"`
	Metadata            map[string]interface{} `json:"metadata"`
}

type RuleEngine struct {
	Rules               []*Rule                `json:"rules"`
	RuleGroups          map[string][]*Rule     `json:"rule_groups"`
	ExecutionOrder      []string               `json:"execution_order"`
	LastUpdate          time.Time              `json:"last_update"`
}

type Rule struct {
	ID                  string                 `json:"id"`
	Name                string                 `json:"name"`
	Description         string                 `json:"description"`
	Conditions          []RuleCondition        `json:"conditions"`
	Actions             []RuleAction           `json:"actions"`
	Priority            int                    `json:"priority"`
	Enabled             bool                   `json:"enabled"`
	Tags                []string               `json:"tags"`
	Created             time.Time              `json:"created"`
	LastModified        time.Time              `json:"last_modified"`
	ExecutionCount      int64                  `json:"execution_count"`
	SuccessCount        int64                  `json:"success_count"`
}

type RuleCondition struct {
	Field               string                 `json:"field"`
	Operator            string                 `json:"operator"`
	Value               interface{}            `json:"value"`
	LogicalOperator     string                 `json:"logical_operator"`
	Negate              bool                   `json:"negate"`
	CaseSensitive       bool                   `json:"case_sensitive"`
	Regex               *regexp.Regexp         `json:"-"`
}

type RuleAction struct {
	Type                string                 `json:"type"`
	Parameters          map[string]interface{} `json:"parameters"`
	Enabled             bool                   `json:"enabled"`
}

type CorrelationEngine struct {
	CorrelationRules    []*CorrelationRule     `json:"correlation_rules"`
	TimeWindows         map[string]time.Duration `json:"time_windows"`
	EventBuffer         map[string][]EnhancedEvent `json:"event_buffer"`
	CorrelationCache    map[string]*EventCorrelation `json:"correlation_cache"`
	mu                  sync.RWMutex           `json:"-"`
}

type CorrelationRule struct {
	ID                  string                 `json:"id"`
	Name                string                 `json:"name"`
	Description         string                 `json:"description"`
	EventTypes          []string               `json:"event_types"`
	TimeWindow          time.Duration          `json:"time_window"`
	MinEvents           int                    `json:"min_events"`
	MaxEvents           int                    `json:"max_events"`
	Conditions          []CorrelationCondition `json:"conditions"`
	Weight              float64                `json:"weight"`
	Enabled             bool                   `json:"enabled"`
}

type CorrelationCondition struct {
	Field               string                 `json:"field"`
	Operator            string                 `json:"operator"`
	Value               interface{}            `json:"value"`
	Tolerance           float64                `json:"tolerance"`
}

type TemporalAnalyzer struct {
	TimeWindows         []time.Duration        `json:"time_windows"`
	PatternDetectors    map[string]*PatternDetector `json:"pattern_detectors"`
	SeasonalityDetector *SeasonalityDetector   `json:"seasonality_detector"`
	TrendAnalyzer       *TrendAnalyzer         `json:"trend_analyzer"`
}

type PatternDetector struct {
	Type                string                 `json:"type"`
	Parameters          map[string]float64     `json:"parameters"`
	Sensitivity         float64                `json:"sensitivity"`
	MinOccurrences      int                    `json:"min_occurrences"`
}

type SeasonalityDetector struct {
	Periods             []time.Duration        `json:"periods"`
	MinCycles           int                    `json:"min_cycles"`
	ConfidenceThreshold float64                `json:"confidence_threshold"`
}

type TrendAnalyzer struct {
	WindowSizes         []time.Duration        `json:"window_sizes"`
	SmoothingFactor     float64                `json:"smoothing_factor"`
	SignificanceLevel   float64                `json:"significance_level"`
}

// Feature extraction and ML components
type FeatureExtractor struct {
	Extractors          map[string]FeatureExtractorFunc `json:"-"`
	FeatureNames        []string               `json:"feature_names"`
	Normalization       map[string]NormalizationParams `json:"normalization"`
	Dimensionality      int                    `json:"dimensionality"`
}

type FeatureExtractorFunc func(monitor *EnhancedMonitor) (map[string]float64, error)

type NormalizationParams struct {
	Method              string                 `json:"method"`
	Mean                float64                `json:"mean"`
	StdDev              float64                `json:"std_dev"`
	Min                 float64                `json:"min"`
	Max                 float64                `json:"max"`
}

type PredictionEngine struct {
	Models              map[string]*MLModel    `json:"models"`
	EnsembleMethods     []string               `json:"ensemble_methods"`
	VotingStrategy      string                 `json:"voting_strategy"`
	ConfidenceThreshold float64                `json:"confidence_threshold"`
}

type TrainingDataManager struct {
	DataSources         []string               `json:"data_sources"`
	DataPath            string                 `json:"data_path"`
	LabeledData         map[string][]TrainingExample `json:"labeled_data"`
	UnlabeledData       []TrainingExample      `json:"unlabeled_data"`
	DataQuality         map[string]float64     `json:"data_quality"`
	LastUpdate          time.Time              `json:"last_update"`
}

type TrainingExample struct {
	ID                  string                 `json:"id"`
	Features            map[string]float64     `json:"features"`
	Label               string                 `json:"label"`
	Weight              float64                `json:"weight"`
	Timestamp           time.Time              `json:"timestamp"`
	Metadata            map[string]interface{} `json:"metadata"`
}

type ModelUpdater struct {
	UpdateStrategy      string                 `json:"update_strategy"`
	UpdateFrequency     time.Duration          `json:"update_frequency"`
	PerformanceThreshold float64               `json:"performance_threshold"`
	RetrainingTriggers  []string               `json:"retraining_triggers"`
	LastUpdate          time.Time              `json:"last_update"`
}

// Threat intelligence components
type ThreatIntelSource interface {
	GetName() string
	Query(indicator string) (*ThreatIntelResult, error)
	BulkQuery(indicators []string) ([]*ThreatIntelResult, error)
	GetLastUpdate() time.Time
	IsHealthy() bool
}

type ThreatIntelResult struct {
	Indicator           string                 `json:"indicator"`
	IndicatorType       string                 `json:"indicator_type"`
	ThreatTypes         []string               `json:"threat_types"`
	Malicious           bool                   `json:"malicious"`
	Confidence          float64                `json:"confidence"`
	Severity            string                 `json:"severity"`
	FirstSeen           time.Time              `json:"first_seen"`
	LastSeen            time.Time              `json:"last_seen"`
	Source              string                 `json:"source"`
	Description         string                 `json:"description"`
	Tags                []string               `json:"tags"`
	References          []string               `json:"references"`
	Context             map[string]interface{} `json:"context"`
	RelatedIndicators   []string               `json:"related_indicators"`
	Campaigns           []string               `json:"campaigns"`
	Actors              []string               `json:"actors"`
	MalwareFamilies     []string               `json:"malware_families"`
	TTPs                []string               `json:"ttps"`
}

type ThreatIntelCache struct {
	Entries             map[string]*CacheEntry `json:"entries"`
	MaxSize             int                    `json:"max_size"`
	TTL                 time.Duration          `json:"ttl"`
	HitRate             float64                `json:"hit_rate"`
	MissRate            float64                `json:"miss_rate"`
	mu                  sync.RWMutex           `json:"-"`
}

type CacheEntry struct {
	Result              *ThreatIntelResult     `json:"result"`
	Timestamp           time.Time              `json:"timestamp"`
	HitCount            int64                  `json:"hit_count"`
	LastAccessed        time.Time              `json:"last_accessed"`
}

type ThreatEnrichment struct {
	EnrichmentRules     []*EnrichmentRule      `json:"enrichment_rules"`
	ContextProviders    map[string]ContextProvider `json:"context_providers"`
	GeoIPProvider       GeoIPProvider          `json:"geo_ip_provider"`
	DNSProvider         DNSProvider            `json:"dns_provider"`
	WHOISProvider       WHOISProvider          `json:"whois_provider"`
}

type EnrichmentRule struct {
	ID                  string                 `json:"id"`
	Name                string                 `json:"name"`
	IndicatorTypes      []string               `json:"indicator_types"`
	EnrichmentTypes     []string               `json:"enrichment_types"`
	Priority            int                    `json:"priority"`
	Enabled             bool                   `json:"enabled"`
}

type ContextProvider interface {
	GetContext(indicator string) (map[string]interface{}, error)
	GetName() string
	IsAvailable() bool
}

type GeoIPProvider interface {
	Lookup(ip string) (*GeoLocation, error)
	BulkLookup(ips []string) (map[string]*GeoLocation, error)
}

type DNSProvider interface {
	Resolve(domain string) ([]string, error)
	ReverseLookup(ip string) ([]string, error)
}

type WHOISProvider interface {
	Lookup(domain string) (*WHOISRecord, error)
}

type WHOISRecord struct {
	Domain              string                 `json:"domain"`
	Registrar           string                 `json:"registrar"`
	Registrant          string                 `json:"registrant"`
	CreationDate        time.Time              `json:"creation_date"`
	ExpirationDate      time.Time              `json:"expiration_date"`
	LastUpdated         time.Time              `json:"last_updated"`
	NameServers         []string               `json:"name_servers"`
	Status              []string               `json:"status"`
	Contacts            map[string]Contact     `json:"contacts"`
}

type Contact struct {
	Name                string                 `json:"name"`
	Organization        string                 `json:"organization"`
	Email               string                 `json:"email"`
	Phone               string                 `json:"phone"`
	Address             string                 `json:"address"`
	City                string                 `json:"city"`
	State               string                 `json:"state"`
	Country             string                 `json:"country"`
	PostalCode          string                 `json:"postal_code"`
}

type ThreatIntelUpdater struct {
	Sources             []ThreatIntelSource    `json:"sources"`
	UpdateSchedule      map[string]time.Duration `json:"update_schedule"`
	LastUpdate          map[string]time.Time   `json:"last_update"`
	UpdateStatus        map[string]string      `json:"update_status"`
	ErrorCount          map[string]int         `json:"error_count"`
	mu                  sync.RWMutex           `json:"-"`
}

// Helper functions for creating instances
func NewMonitorMetrics() *MonitorMetrics {
	return &MonitorMetrics{
		TotalEvents:       0,
		EventsPerSecond:   0.0,
		AverageRiskScore:  0.0,
		HighRiskEvents:    0,
		AnomalousEvents:   0,
		ThreatIntelHits:   0,
		MLPredictions:     0,
		ProcessingLatency: 0,
		MemoryUsage:       0,
		CPUUsage:          0.0,
	}
}

func NewBehaviorProfile(packageName string) *BehaviorProfile {
	return &BehaviorProfile{
		PackageName:         packageName,
		Created:             time.Now(),
		LastUpdated:         time.Now(),
		NormalBehaviors:     make([]BehaviorPattern, 0),
		AnomalousPatterns:   make([]BehaviorPattern, 0),
		RiskFactors:         make([]string, 0),
		TrustScore:          0.5,
		ReputationScore:     0.5,
		BehaviorFingerprint: "",
		Statistics:          make(map[string]interface{}),
	}
}

func NewBehaviorBaseline() *BehaviorBaseline {
	return &BehaviorBaseline{
		Created:            time.Now(),
		LastUpdated:        time.Now(),
		EventFrequencies:   make(map[string]float64),
		NetworkPatterns:    make([]NetworkPattern, 0),
		FilePatterns:       make([]FilePattern, 0),
		ProcessPatterns:    make([]ProcessPattern, 0),
		TemporalPatterns:   make([]TemporalPattern, 0),
		StatisticalMetrics: make(map[string]float64),
		ConfidenceLevel:    0.95,
	}
}

func NewBehaviorMetrics() *BehaviorMetrics {
	return &BehaviorMetrics{
		TotalAnalyses:     0,
		AnomaliesDetected: 0,
		PatternsMatched:   0,
		ThreatIntelHits:   0,
		MLPredictions:     0,
		FalsePositives:    0,
		TruePositives:     0,
		Accuracy:          0.0,
		Precision:         0.0,
		Recall:            0.0,
		F1Score:           0.0,
		ProcessingTime:    0,
		MemoryUsage:       0,
		CPUUsage:          0.0,
		LastUpdated:       time.Now(),
	}
}

// Utility functions for behavioral analysis
func (eba *EnhancedBehavioralAnalysis) GetSeverityLevel() string {
	if eba.RiskAssessment == nil {
		return "unknown"
	}

	score := eba.RiskAssessment.OverallRiskScore
	switch {
	case score >= 0.9:
		return "critical"
	case score >= 0.7:
		return "high"
	case score >= 0.5:
		return "medium"
	case score >= 0.3:
		return "low"
	default:
		return "minimal"
	}
}

func (eba *EnhancedBehavioralAnalysis) RequiresImmediateAction() bool {
	return eba.ActionRequired && (eba.SeverityLevel == "critical" || eba.SeverityLevel == "high")
}

func (eba *EnhancedBehavioralAnalysis) GetHighestRiskAnomaly() *EnhancedAnomaly {
	if len(eba.Anomalies) == 0 {
		return nil
	}

	highest := &eba.Anomalies[0]
	for i := 1; i < len(eba.Anomalies); i++ {
		if eba.Anomalies[i].AnomalyScore > highest.AnomalyScore {
			highest = &eba.Anomalies[i]
		}
	}
	return highest
}

func (eba *EnhancedBehavioralAnalysis) GetCriticalIOCs() []IOC {
	critical := make([]IOC, 0)
	for _, ioc := range eba.IOCs {
		if ioc.Severity == "critical" || ioc.Severity == "high" {
			critical = append(critical, ioc)
		}
	}
	return critical
}

func (eba *EnhancedBehavioralAnalysis) GetMITRETactics() []string {
	tactics := make(map[string]bool)
	for _, mapping := range eba.MITREMapping {
		tactics[mapping.TacticName] = true
	}

	result := make([]string, 0, len(tactics))
	for tactic := range tactics {
		result = append(result, tactic)
	}
	sort.Strings(result)
	return result
}

func (eba *EnhancedBehavioralAnalysis) ToJSON() ([]byte, error) {
	return json.MarshalIndent(eba, "", "  ")
}

func (eba *EnhancedBehavioralAnalysis) FromJSON(data []byte) error {
	return json.Unmarshal(data, eba)
}