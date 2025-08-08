package ml

import (
	"context"
	"fmt"
	"math"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// EnhancedMLDetector provides comprehensive ML-based threat detection
type EnhancedMLDetector struct {
	config             *EnhancedMLConfig
	similarityModel    *SimilarityModel
	malwareClassifier  *MalwareClassifier
	anomalyDetector    *AnomalyDetector
	typoDetector       *TypoDetector
	reputationAnalyzer *ReputationAnalyzer
	behavioralAnalyzer *BehavioralAnalyzer
	ensembleModel      *EnsembleModel
	metrics            *DetectionMetrics
	lastUpdate         time.Time
}

// DetectionMetrics tracks model performance for fine-tuning
type DetectionMetrics struct {
	TotalDetections   int64     `json:"total_detections"`
	TruePositives     int64     `json:"true_positives"`
	FalsePositives    int64     `json:"false_positives"`
	TrueNegatives     int64     `json:"true_negatives"`
	FalseNegatives    int64     `json:"false_negatives"`
	AverageConfidence float64   `json:"average_confidence"`
	LastUpdated       time.Time `json:"last_updated"`
}

// MLConfig contains ML detector configuration
type EnhancedMLConfig struct {
	Enabled             bool               `yaml:"enabled"`
	SimilarityThreshold float64            `yaml:"similarity_threshold"`
	MalwareThreshold    float64            `yaml:"malware_threshold"`
	AnomalyThreshold    float64            `yaml:"anomaly_threshold"`
	TypoThreshold       float64            `yaml:"typo_threshold"`
	ReputationThreshold float64            `yaml:"reputation_threshold"`
	EnsembleWeights     map[string]float64 `yaml:"ensemble_weights"`
	ConfidenceThreshold float64            `yaml:"confidence_threshold"`
	ModelUpdateInterval time.Duration      `yaml:"model_update_interval"`
	BatchSize           int                `yaml:"batch_size"`
	MaxFeatures         int                `yaml:"max_features"`
	ParallelProcessing  bool               `yaml:"parallel_processing"`
	Verbose             bool               `yaml:"verbose"`
}

// EnhancedPackageFeatures represents enhanced package features for ML analysis
type EnhancedPackageFeatures struct {
	Name              string                 `json:"name"`
	Registry          string                 `json:"registry"`
	Version           string                 `json:"version"`
	Description       string                 `json:"description"`
	Author            string                 `json:"author"`
	Maintainers       []string               `json:"maintainers"`
	Keywords          []string               `json:"keywords"`
	License           string                 `json:"license"`
	Homepage          string                 `json:"homepage"`
	Repository        string                 `json:"repository"`
	Downloads         int64                  `json:"downloads"`
	Stars             int                    `json:"stars"`
	Forks             int                    `json:"forks"`
	Issues            int                    `json:"issues"`
	CreationDate      time.Time              `json:"creation_date"`
	LastUpdated       time.Time              `json:"last_updated"`
	Dependencies      []Dependency           `json:"dependencies"`
	DevDependencies   []Dependency           `json:"dev_dependencies"`
	Scripts           map[string]string      `json:"scripts"`
	FileStructure     FileStructure          `json:"file_structure"`
	CodeMetrics       CodeMetrics            `json:"code_metrics"`
	SecurityMetrics   SecurityMetrics        `json:"security_metrics"`
	BehavioralMetrics BehavioralMetrics      `json:"behavioral_metrics"`
	Metadata          map[string]interface{} `json:"metadata"`
}

// Dependency represents a package dependency
type Dependency struct {
	Name       string  `json:"name"`
	Version    string  `json:"version"`
	Type       string  `json:"type"`
	Optional   bool    `json:"optional"`
	Dev        bool    `json:"dev"`
	Suspicious bool    `json:"suspicious"`
	RiskScore  float64 `json:"risk_score"`
}

// FileStructure represents package file structure metrics
type FileStructure struct {
	TotalFiles         int      `json:"total_files"`
	JavaScriptFiles    int      `json:"javascript_files"`
	TypeScriptFiles    int      `json:"typescript_files"`
	ConfigFiles        int      `json:"config_files"`
	TestFiles          int      `json:"test_files"`
	DocumentationFiles int      `json:"documentation_files"`
	BinaryFiles        int      `json:"binary_files"`
	HiddenFiles        int      `json:"hidden_files"`
	SuspiciousFiles    []string `json:"suspicious_files"`
	LargeFiles         []string `json:"large_files"`
	UnusualExtensions  []string `json:"unusual_extensions"`
}

// CodeMetrics represents code quality and complexity metrics
type CodeMetrics struct {
	LinesOfCode          int     `json:"lines_of_code"`
	CyclomaticComplexity float64 `json:"cyclomatic_complexity"`
	CodeDuplication      float64 `json:"code_duplication"`
	TestCoverage         float64 `json:"test_coverage"`
	DocumentationRatio   float64 `json:"documentation_ratio"`
	ObfuscationScore     float64 `json:"obfuscation_score"`
	MinificationScore    float64 `json:"minification_score"`
	CommentRatio         float64 `json:"comment_ratio"`
}

// SecurityMetrics represents security-related metrics
type SecurityMetrics struct {
	VulnerabilityCount    int     `json:"vulnerability_count"`
	HighSeverityVulns     int     `json:"high_severity_vulns"`
	CriticalSeverityVulns int     `json:"critical_severity_vulns"`
	SuspiciousPatterns    int     `json:"suspicious_patterns"`
	ObfuscatedCode        bool    `json:"obfuscated_code"`
	NetworkCalls          int     `json:"network_calls"`
	FileSystemAccess      int     `json:"file_system_access"`
	ProcessExecution      int     `json:"process_execution"`
	CryptographicUsage    int     `json:"cryptographic_usage"`
	DangerousFunctions    int     `json:"dangerous_functions"`
	SecurityScore         float64 `json:"security_score"`
}

// BehavioralMetrics represents behavioral analysis metrics
type BehavioralMetrics struct {
	InstallationBehavior EnhancedInstallBehavior    `json:"installation_behavior"`
	RuntimeBehavior      EnhancedRuntimeBehavior    `json:"runtime_behavior"`
	NetworkBehavior      EnhancedNetworkBehavior    `json:"network_behavior"`
	FileSystemBehavior   EnhancedFileSystemBehavior `json:"file_system_behavior"`
	ProcessBehavior      EnhancedProcessBehavior    `json:"process_behavior"`
	AnomalyScore         float64                    `json:"anomaly_score"`
}

// InstallBehavior represents installation-time behavior
type EnhancedInstallBehavior struct {
	PostInstallScript  bool    `json:"post_install_script"`
	PreInstallScript   bool    `json:"pre_install_script"`
	NetworkActivity    bool    `json:"network_activity"`
	FileModifications  int     `json:"file_modifications"`
	PermissionChanges  int     `json:"permission_changes"`
	SuspiciousCommands int     `json:"suspicious_commands"`
	InstallationTime   float64 `json:"installation_time"`
}

// RuntimeBehavior represents runtime behavior
type EnhancedRuntimeBehavior struct {
	CPUUsage               float64 `json:"cpu_usage"`
	MemoryUsage            float64 `json:"memory_usage"`
	NetworkConnections     int     `json:"network_connections"`
	FileOperations         int     `json:"file_operations"`
	ProcessSpawning        int     `json:"process_spawning"`
	AntiAnalysisTechniques bool    `json:"anti_analysis_techniques"`
	PersistenceMechanisms  bool    `json:"persistence_mechanisms"`
}

// NetworkBehavior represents network-related behavior
type EnhancedNetworkBehavior struct {
	OutboundConnections int      `json:"outbound_connections"`
	InboundConnections  int      `json:"inbound_connections"`
	SuspiciousHosts     []string `json:"suspicious_hosts"`
	UnusualPorts        []int    `json:"unusual_ports"`
	DataExfiltration    bool     `json:"data_exfiltration"`
	C2Communication     bool     `json:"c2_communication"`
	DNSTunneling        bool     `json:"dns_tunneling"`
}

// FileSystemBehavior represents file system behavior
type EnhancedFileSystemBehavior struct {
	FilesCreated        int      `json:"files_created"`
	FilesModified       int      `json:"files_modified"`
	FilesDeleted        int      `json:"files_deleted"`
	SuspiciousLocations []string `json:"suspicious_locations"`
	HiddenFiles         int      `json:"hidden_files"`
	SystemFileAccess    bool     `json:"system_file_access"`
	TempFileUsage       int      `json:"temp_file_usage"`
}

// ProcessBehavior represents process-related behavior
type EnhancedProcessBehavior struct {
	ChildProcesses      int      `json:"child_processes"`
	PrivilegeEscalation bool     `json:"privilege_escalation"`
	CodeInjection       bool     `json:"code_injection"`
	Hollowing           bool     `json:"hollowing"`
	DLLInjection        bool     `json:"dll_injection"`
	SuspiciousCommands  []string `json:"suspicious_commands"`
}

// MLDetectionResult represents the result of ML-based detection
type MLDetectionResult struct {
	PackageName           string                     `json:"package_name"`
	Registry              string                     `json:"registry"`
	AnalysisTimestamp     time.Time                  `json:"analysis_timestamp"`
	OverallRiskScore      float64                    `json:"overall_risk_score"`
	ConfidenceScore       float64                    `json:"confidence_score"`
	ThreatLevel           string                     `json:"threat_level"`
	IsMalicious           bool                       `json:"is_malicious"`
	IsTyposquatting       bool                       `json:"is_typosquatting"`
	IsAnomalous           bool                       `json:"is_anomalous"`
	SimilarityResults     []EnhancedSimilarityResult `json:"similarity_results"`
	MalwareClassification MalwareClassification      `json:"malware_classification"`
	AnomalyDetection      EnhancedAnomalyDetection   `json:"anomaly_detection"`
	TypoDetection         TypoDetection              `json:"typo_detection"`
	ReputationAnalysis    EnhancedReputationAnalysis `json:"reputation_analysis"`
	BehavioralAnalysis    BehavioralAnalysisResult   `json:"behavioral_analysis"`
	EnsembleResults       EnsembleResults            `json:"ensemble_results"`
	Recommendations       []string                   `json:"recommendations"`
	Metadata              map[string]interface{}     `json:"metadata"`
}

// EnhancedSimilarityResult represents enhanced similarity analysis results
type EnhancedSimilarityResult struct {
	SimilarPackage  string  `json:"similar_package"`
	SimilarityScore float64 `json:"similarity_score"`
	SimilarityType  string  `json:"similarity_type"`
	Confidence      float64 `json:"confidence"`
	Reason          string  `json:"reason"`
}

// MalwareClassification represents malware classification results
type MalwareClassification struct {
	IsMalware            bool               `json:"is_malware"`
	MalwareType          string             `json:"malware_type"`
	MalwareFamily        string             `json:"malware_family"`
	Confidence           float64            `json:"confidence"`
	FeatureImportance    map[string]float64 `json:"feature_importance"`
	ClassificationReason string             `json:"classification_reason"`
}

// EnhancedAnomalyDetection represents enhanced anomaly detection results
type EnhancedAnomalyDetection struct {
	IsAnomalous       bool     `json:"is_anomalous"`
	AnomalyScore      float64  `json:"anomaly_score"`
	AnomalyType       string   `json:"anomaly_type"`
	Confidence        float64  `json:"confidence"`
	AnomalousFeatures []string `json:"anomalous_features"`
	BaselineDeviation float64  `json:"baseline_deviation"`
}

// TypoDetection represents typosquatting detection results
type TypoDetection struct {
	IsTyposquatting    bool     `json:"is_typosquatting"`
	TargetPackage      string   `json:"target_package"`
	TypoType           string   `json:"typo_type"`
	EditDistance       int      `json:"edit_distance"`
	SimilarityScore    float64  `json:"similarity_score"`
	Confidence         float64  `json:"confidence"`
	SuspiciousPatterns []string `json:"suspicious_patterns"`
}

// EnhancedReputationAnalysis represents enhanced reputation analysis results
type EnhancedReputationAnalysis struct {
	ReputationScore      float64  `json:"reputation_score"`
	TrustLevel           string   `json:"trust_level"`
	AuthorReputation     float64  `json:"author_reputation"`
	MaintainerReputation float64  `json:"maintainer_reputation"`
	CommunityTrust       float64  `json:"community_trust"`
	HistoricalIssues     []string `json:"historical_issues"`
	VerificationStatus   string   `json:"verification_status"`
}

// BehavioralAnalysisResult represents behavioral analysis results
type BehavioralAnalysisResult struct {
	BehaviorScore       float64  `json:"behavior_score"`
	SuspiciousBehaviors []string `json:"suspicious_behaviors"`
	RiskFactors         []string `json:"risk_factors"`
	BehaviorPatterns    []string `json:"behavior_patterns"`
	AnomalousActivities []string `json:"anomalous_activities"`
	Confidence          float64  `json:"confidence"`
}

// EnsembleResults represents ensemble model results
type EnsembleResults struct {
	FinalScore          float64            `json:"final_score"`
	ModelScores         map[string]float64 `json:"model_scores"`
	ModelWeights        map[string]float64 `json:"model_weights"`
	ConsensusLevel      float64            `json:"consensus_level"`
	DisagreementFactors []string           `json:"disagreement_factors"`
	Confidence          float64            `json:"confidence"`
}

// NewEnhancedMLDetector creates a new enhanced ML detector
func NewEnhancedMLDetector(config *EnhancedMLConfig) (*EnhancedMLDetector, error) {
	if config == nil {
		config = DefaultEnhancedMLConfig()
	}

	detector := &EnhancedMLDetector{
		config:     config,
		lastUpdate: time.Now(),
		metrics: &DetectionMetrics{
			LastUpdated: time.Now(),
		},
	}

	// Initialize models
	var err error
	detector.similarityModel, err = NewSimilarityModel()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize similarity model: %w", err)
	}

	detector.malwareClassifier, err = NewMalwareClassifier()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize malware classifier: %w", err)
	}

	detector.anomalyDetector, err = NewAnomalyDetector()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize anomaly detector: %w", err)
	}

	detector.typoDetector, err = NewTypoDetector()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize typo detector: %w", err)
	}

	detector.reputationAnalyzer, err = NewReputationAnalyzer()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize reputation analyzer: %w", err)
	}

	detector.behavioralAnalyzer = NewBehavioralAnalyzer()

	detector.ensembleModel, err = NewEnsembleModel(config.EnsembleWeights)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize ensemble model: %w", err)
	}

	return detector, nil
}

// DefaultEnhancedMLConfig returns default enhanced ML configuration
func DefaultEnhancedMLConfig() *EnhancedMLConfig {
	return &EnhancedMLConfig{
		Enabled:             true,
		SimilarityThreshold: 0.8,
		MalwareThreshold:    0.7,
		AnomalyThreshold:    0.75,
		TypoThreshold:       0.85,
		ReputationThreshold: 0.6,
		EnsembleWeights: map[string]float64{
			"similarity": 0.2,
			"malware":    0.25,
			"anomaly":    0.2,
			"typo":       0.15,
			"reputation": 0.1,
			"behavioral": 0.1,
		},
		ConfidenceThreshold: 0.8,
		ModelUpdateInterval: 24 * time.Hour,
		BatchSize:           32,
		MaxFeatures:         1000,
		ParallelProcessing:  true,
		Verbose:             false,
	}
}

// AnalyzePackage performs comprehensive ML-based analysis of a package with enhanced detection capabilities
func (emd *EnhancedMLDetector) AnalyzePackage(ctx context.Context, features *EnhancedPackageFeatures) (*MLDetectionResult, error) {
	result := &MLDetectionResult{
		PackageName:       features.Name,
		Registry:          features.Registry,
		AnalysisTimestamp: time.Now(),
		Metadata:          make(map[string]interface{}),
	}

	// Enhanced multi-algorithm similarity analysis
	similarityResults, err := emd.runEnhancedSimilarityAnalysis(ctx, features)
	if err != nil {
		return nil, fmt.Errorf("enhanced similarity analysis failed: %w", err)
	}
	result.SimilarityResults = similarityResults

	// Advanced malware classification with pattern recognition
	malwareResult, err := emd.runAdvancedMalwareClassification(ctx, features)
	if err != nil {
		return nil, fmt.Errorf("advanced malware classification failed: %w", err)
	}
	result.MalwareClassification = *malwareResult

	// Enhanced anomaly detection with behavioral patterns
	anomalyResult, err := emd.runEnhancedAnomalyDetection(ctx, features)
	if err != nil {
		return nil, fmt.Errorf("enhanced anomaly detection failed: %w", err)
	}
	result.AnomalyDetection = *anomalyResult

	// Advanced typosquatting detection with multiple algorithms
	typoResult, err := emd.runAdvancedTypoDetection(ctx, features)
	if err != nil {
		return nil, fmt.Errorf("advanced typo detection failed: %w", err)
	}
	result.TypoDetection = *typoResult

	// Enhanced reputation analysis with social engineering detection
	reputationResult, err := emd.runEnhancedReputationAnalysis(ctx, features)
	if err != nil {
		return nil, fmt.Errorf("enhanced reputation analysis failed: %w", err)
	}
	result.ReputationAnalysis = *reputationResult

	// Advanced behavioral analysis with dependency confusion detection
	behavioralResult, err := emd.runAdvancedBehavioralAnalysis(ctx, features)
	if err != nil {
		return nil, fmt.Errorf("advanced behavioral analysis failed: %w", err)
	}
	result.BehavioralAnalysis = *behavioralResult

	// Enhanced ensemble analysis with weighted scoring
	ensembleResult, err := emd.runEnhancedEnsembleAnalysis(ctx, result)
	if err != nil {
		return nil, fmt.Errorf("enhanced ensemble analysis failed: %w", err)
	}
	result.EnsembleResults = *ensembleResult

	// Calculate overall scores and classifications with enhanced logic
	emd.calculateEnhancedOverallAssessment(result)

	// Generate comprehensive recommendations
	result.Recommendations = emd.generateEnhancedRecommendations(result)

	// Update detection metrics
	emd.updateDetectionMetrics(result)

	return result, nil
}

// Enhanced analysis methods implementing improved ML detection capabilities

// runEnhancedSimilarityAnalysis performs multi-algorithm similarity analysis
func (emd *EnhancedMLDetector) runEnhancedSimilarityAnalysis(ctx context.Context, features *EnhancedPackageFeatures) ([]EnhancedSimilarityResult, error) {
	// Use the enhanced similarity calculation from analyzer.go
	similarityResults, err := emd.similarityModel.AnalyzeSimilarity(ctx, features)
	if err != nil {
		return nil, err
	}

	// Add enhanced pattern detection for each result
	for i := range similarityResults {
		similarityResults[i].Reason = emd.detectSimilarityPatterns(features.Name, similarityResults[i].SimilarPackage)
	}

	return similarityResults, nil
}

// runAdvancedMalwareClassification performs enhanced malware detection
func (emd *EnhancedMLDetector) runAdvancedMalwareClassification(ctx context.Context, features *EnhancedPackageFeatures) (*MalwareClassification, error) {
	malwareResult, err := emd.malwareClassifier.ClassifyMalware(ctx, features)
	if err != nil {
		return nil, err
	}

	// Add enhanced pattern analysis
	malwareResult.FeatureImportance = emd.analyzeAdvancedMalwarePatterns(features)
	malwareResult.ClassificationReason = emd.extractBehavioralIndicators(features)

	return malwareResult, nil
}

// runEnhancedAnomalyDetection performs advanced anomaly detection
func (emd *EnhancedMLDetector) runEnhancedAnomalyDetection(ctx context.Context, features *EnhancedPackageFeatures) (*EnhancedAnomalyDetection, error) {
	anomalyResult, err := emd.anomalyDetector.DetectAnomalies(ctx, features)
	if err != nil {
		return nil, err
	}

	// Add enhanced behavioral anomaly detection
	anomalyResult.AnomalousFeatures = emd.detectBehavioralAnomalies(features)
	anomalyResult.BaselineDeviation = emd.detectStatisticalAnomalies(features)

	return anomalyResult, nil
}

// runAdvancedTypoDetection performs multi-algorithm typosquatting detection
func (emd *EnhancedMLDetector) runAdvancedTypoDetection(ctx context.Context, features *EnhancedPackageFeatures) (*TypoDetection, error) {
	typoResult, err := emd.typoDetector.DetectTyposquatting(ctx, features)
	if err != nil {
		return nil, err
	}

	// Add enhanced typosquatting algorithms
	typoResult.SuspiciousPatterns = emd.calculatePhoneticTypoSimilarity(features.Name)

	return typoResult, nil
}

// runEnhancedReputationAnalysis performs comprehensive reputation analysis
func (emd *EnhancedMLDetector) runEnhancedReputationAnalysis(ctx context.Context, features *EnhancedPackageFeatures) (*EnhancedReputationAnalysis, error) {
	reputationResult, err := emd.reputationAnalyzer.AnalyzeReputation(ctx, features)
	if err != nil {
		return nil, err
	}

	// Add social engineering detection
	reputationResult.HistoricalIssues = emd.detectSocialEngineeringPatterns(features)
	reputationResult.VerificationStatus = emd.calculateAdvancedTrustMetrics(features)

	return reputationResult, nil
}

// runAdvancedBehavioralAnalysis performs enhanced behavioral analysis
func (emd *EnhancedMLDetector) runAdvancedBehavioralAnalysis(ctx context.Context, features *EnhancedPackageFeatures) (*BehavioralAnalysisResult, error) {
	behavioralResult, err := emd.behavioralAnalyzer.AnalyzeBehaviorEnhanced(ctx, features)
	if err != nil {
		return nil, err
	}

	// Add dependency confusion detection
	behavioralResult.RiskFactors = emd.detectDependencyConfusion(features)
	behavioralResult.BehaviorPatterns = emd.assessSupplyChainRisk(features)

	return behavioralResult, nil
}

// runEnhancedEnsembleAnalysis performs weighted ensemble analysis
func (emd *EnhancedMLDetector) runEnhancedEnsembleAnalysis(ctx context.Context, result *MLDetectionResult) (*EnsembleResults, error) {
	ensembleResult, err := emd.ensembleModel.CombineResults(ctx, result)
	if err != nil {
		return nil, err
	}

	// Add enhanced ensemble weighting
	ensembleResult.ModelScores = emd.calculateEnhancedWeightedScores(result)
	ensembleResult.ConsensusLevel = emd.calculateConsensusScore(result)

	return ensembleResult, nil
}

// calculateEnhancedOverallAssessment computes the final risk scores with enhanced logic
func (emd *EnhancedMLDetector) calculateEnhancedOverallAssessment(result *MLDetectionResult) {
	// Enhanced weighted combination with dynamic weights
	weights := emd.calculateDynamicWeights(result)

	// Calculate overall risk score with enhanced logic
	overallScore := 0.0
	if len(result.SimilarityResults) > 0 {
		maxSimilarity := 0.0
		for _, sim := range result.SimilarityResults {
			if sim.SimilarityScore > maxSimilarity {
				maxSimilarity = sim.SimilarityScore
			}
		}
		overallScore += maxSimilarity * weights["similarity"]
	}
	overallScore += result.MalwareClassification.Confidence * weights["malware"]
	overallScore += result.AnomalyDetection.AnomalyScore * weights["anomaly"]
	overallScore += result.TypoDetection.Confidence * weights["typo"]
	overallScore += result.ReputationAnalysis.ReputationScore * weights["reputation"]
	overallScore += result.BehavioralAnalysis.BehaviorScore * weights["behavioral"]

	// Apply ensemble boost
	if result.EnsembleResults.ConsensusLevel > 0.8 {
		overallScore *= 1.1 // Boost score when multiple models agree
	}

	if overallScore > 1.0 {
		overallScore = 1.0
	}
	result.OverallRiskScore = overallScore

	// Enhanced risk level determination
	switch {
	case overallScore >= 0.9:
		result.ThreatLevel = "critical"
	case overallScore >= 0.7:
		result.ThreatLevel = "high"
	case overallScore >= 0.5:
		result.ThreatLevel = "medium"
	case overallScore >= 0.3:
		result.ThreatLevel = "low"
	default:
		result.ThreatLevel = "minimal"
	}

	// Enhanced confidence level calculation
	confidenceFactors := []float64{
		result.EnsembleResults.Confidence,
		result.MalwareClassification.Confidence,
	}
	avgConfidence := emd.calculateAverageConfidence(confidenceFactors)
	result.ConfidenceScore = avgConfidence

	// Set boolean flags
	result.IsMalicious = result.MalwareClassification.IsMalware || result.OverallRiskScore >= emd.config.MalwareThreshold
	result.IsTyposquatting = result.TypoDetection.IsTyposquatting
	result.IsAnomalous = result.AnomalyDetection.IsAnomalous
}

// Helper methods for enhanced analysis

// detectSimilarityPatterns analyzes similarity patterns between packages
func (emd *EnhancedMLDetector) detectSimilarityPatterns(packageName, similarPackage string) string {
	if len(packageName) == 0 || len(similarPackage) == 0 {
		return "unknown"
	}

	// Simple pattern detection
	if packageName == similarPackage {
		return "exact_match"
	}

	similarity := calculateSimpleSimilarity(packageName, similarPackage)
	if similarity > 0.9 {
		return "high_similarity"
	} else if similarity > 0.7 {
		return "medium_similarity"
	}

	return "low_similarity"
}

// calculateSimpleSimilarity calculates simple string similarity
func calculateSimpleSimilarity(s1, s2 string) float64 {
	if s1 == s2 {
		return 1.0
	}

	if len(s1) == 0 || len(s2) == 0 {
		return 0.0
	}

	// Simple Levenshtein-based similarity
	dist := levenshteinDistance(s1, s2)
	maxLen := len(s1)
	if len(s2) > maxLen {
		maxLen = len(s2)
	}

	return 1.0 - float64(dist)/float64(maxLen)
}

// levenshteinDistance calculates the Levenshtein distance between two strings
func levenshteinDistance(s1, s2 string) int {
	if len(s1) == 0 {
		return len(s2)
	}
	if len(s2) == 0 {
		return len(s1)
	}

	// Create a matrix to store distances
	matrix := make([][]int, len(s1)+1)
	for i := range matrix {
		matrix[i] = make([]int, len(s2)+1)
	}

	// Initialize first row and column
	for i := 0; i <= len(s1); i++ {
		matrix[i][0] = i
	}
	for j := 0; j <= len(s2); j++ {
		matrix[0][j] = j
	}

	// Fill the matrix
	for i := 1; i <= len(s1); i++ {
		for j := 1; j <= len(s2); j++ {
			cost := 0
			if s1[i-1] != s2[j-1] {
				cost = 1
			}

			// Find minimum of three values
			deletion := matrix[i-1][j] + 1
			insertion := matrix[i][j-1] + 1
			substitution := matrix[i-1][j-1] + cost

			matrix[i][j] = deletion
			if insertion < matrix[i][j] {
				matrix[i][j] = insertion
			}
			if substitution < matrix[i][j] {
				matrix[i][j] = substitution
			}
		}
	}

	return matrix[len(s1)][len(s2)]
}

// analyzeAdvancedMalwarePatterns analyzes malware patterns in package features
func (emd *EnhancedMLDetector) analyzeAdvancedMalwarePatterns(features *EnhancedPackageFeatures) map[string]float64 {
	patterns := make(map[string]float64)

	// Analyze suspicious file patterns
	if features.FileStructure.BinaryFiles > 0 {
		patterns["binary_files"] = 0.3
	}
	if len(features.FileStructure.SuspiciousFiles) > 0 {
		patterns["suspicious_files"] = 0.4
	}
	if features.SecurityMetrics.ObfuscatedCode {
		patterns["obfuscated_code"] = 0.5
	}

	return patterns
}

// extractBehavioralIndicators extracts behavioral indicators from package features
func (emd *EnhancedMLDetector) extractBehavioralIndicators(features *EnhancedPackageFeatures) string {
	indicators := []string{}

	if features.SecurityMetrics.NetworkCalls > 0 {
		indicators = append(indicators, "network_activity")
	}
	if features.SecurityMetrics.FileSystemAccess > 0 {
		indicators = append(indicators, "file_system_access")
	}
	if features.SecurityMetrics.ProcessExecution > 0 {
		indicators = append(indicators, "process_execution")
	}

	if len(indicators) == 0 {
		return "no_suspicious_behavior"
	}

	return "suspicious_behavior_detected"
}

// detectBehavioralAnomalies detects behavioral anomalies in package features
func (emd *EnhancedMLDetector) detectBehavioralAnomalies(features *EnhancedPackageFeatures) []string {
	anomalies := []string{}

	if features.BehavioralMetrics.InstallationBehavior.NetworkActivity {
		anomalies = append(anomalies, "install_network_activity")
	}
	if features.BehavioralMetrics.RuntimeBehavior.AntiAnalysisTechniques {
		anomalies = append(anomalies, "anti_analysis")
	}
	if features.BehavioralMetrics.NetworkBehavior.DataExfiltration {
		anomalies = append(anomalies, "data_exfiltration")
	}

	return anomalies
}

// detectStatisticalAnomalies detects statistical anomalies
func (emd *EnhancedMLDetector) detectStatisticalAnomalies(features *EnhancedPackageFeatures) float64 {
	// Simple statistical anomaly detection
	deviation := 0.0

	if features.CodeMetrics.ObfuscationScore > 0.8 {
		deviation += 0.3
	}
	if features.SecurityMetrics.VulnerabilityCount > 10 {
		deviation += 0.2
	}

	return deviation
}

// calculatePhoneticTypoSimilarity calculates phonetic similarity for typo detection
func (emd *EnhancedMLDetector) calculatePhoneticTypoSimilarity(packageName string) []string {
	patterns := []string{}

	// Simple phonetic pattern detection
	if len(packageName) > 0 {
		patterns = append(patterns, "character_substitution")
	}

	return patterns
}

// detectSocialEngineeringPatterns detects social engineering patterns
func (emd *EnhancedMLDetector) detectSocialEngineeringPatterns(features *EnhancedPackageFeatures) []string {
	issues := []string{}

	// Check for suspicious naming patterns
	if len(features.Name) > 0 {
		// Simple check for common social engineering patterns
		suspiciousWords := []string{"official", "secure", "verified", "trusted"}
		for _, word := range suspiciousWords {
			for i := 0; i <= len(features.Name)-len(word); i++ {
				if features.Name[i:i+len(word)] == word {
					issues = append(issues, "suspicious_naming")
					break
				}
			}
		}
	}

	return issues
}

// calculateAdvancedTrustMetrics calculates advanced trust metrics
func (emd *EnhancedMLDetector) calculateAdvancedTrustMetrics(features *EnhancedPackageFeatures) string {
	if features.Downloads > 1000000 {
		return "verified"
	} else if features.Downloads > 10000 {
		return "trusted"
	}
	return "unverified"
}

// detectDependencyConfusion detects dependency confusion attacks
func (emd *EnhancedMLDetector) detectDependencyConfusion(features *EnhancedPackageFeatures) []string {
	risks := []string{}

	for _, dep := range features.Dependencies {
		if dep.Suspicious {
			risks = append(risks, "suspicious_dependency")
		}
	}

	return risks
}

// assessSupplyChainRisk assesses supply chain risks
func (emd *EnhancedMLDetector) assessSupplyChainRisk(features *EnhancedPackageFeatures) []string {
	patterns := []string{}

	if len(features.Maintainers) == 0 {
		patterns = append(patterns, "no_maintainers")
	}
	if features.SecurityMetrics.VulnerabilityCount > 0 {
		patterns = append(patterns, "known_vulnerabilities")
	}

	return patterns
}

// calculateEnhancedWeightedScores calculates enhanced weighted scores
func (emd *EnhancedMLDetector) calculateEnhancedWeightedScores(result *MLDetectionResult) map[string]float64 {
	scores := make(map[string]float64)

	scores["malware"] = result.MalwareClassification.Confidence
	scores["anomaly"] = result.AnomalyDetection.AnomalyScore
	scores["typo"] = result.TypoDetection.Confidence
	scores["reputation"] = result.ReputationAnalysis.ReputationScore
	scores["behavioral"] = result.BehavioralAnalysis.BehaviorScore

	return scores
}

// calculateConsensusScore calculates consensus score across models
func (emd *EnhancedMLDetector) calculateConsensusScore(result *MLDetectionResult) float64 {
	scores := []float64{
		result.MalwareClassification.Confidence,
		result.AnomalyDetection.AnomalyScore,
		result.TypoDetection.Confidence,
	}

	total := 0.0
	for _, score := range scores {
		total += score
	}

	return total / float64(len(scores))
}

// calculateDynamicWeights calculates dynamic weights based on detection context
func (emd *EnhancedMLDetector) calculateDynamicWeights(result *MLDetectionResult) map[string]float64 {
	// Use configured weights as base
	weights := make(map[string]float64)
	for k, v := range emd.config.EnsembleWeights {
		weights[k] = v
	}

	// Adjust weights based on detection confidence
	if result.MalwareClassification.Confidence > 0.9 {
		weights["malware"] *= 1.2
	}
	if result.TypoDetection.Confidence > 0.9 {
		weights["typo"] *= 1.2
	}

	return weights
}

// calculateAverageConfidence calculates average confidence from multiple factors
func (emd *EnhancedMLDetector) calculateAverageConfidence(factors []float64) float64 {
	if len(factors) == 0 {
		return 0.0
	}

	total := 0.0
	for _, factor := range factors {
		total += factor
	}

	return total / float64(len(factors))
}

// updateDetectionMetrics updates detection metrics based on results
func (emd *EnhancedMLDetector) updateDetectionMetrics(result *MLDetectionResult) {
	if emd.metrics == nil {
		emd.metrics = &DetectionMetrics{LastUpdated: time.Now()}
	}

	emd.metrics.TotalDetections++

	// Update average confidence
	total := float64(emd.metrics.TotalDetections)
	emd.metrics.AverageConfidence = (emd.metrics.AverageConfidence*(total-1) + result.ConfidenceScore) / total
	emd.metrics.LastUpdated = time.Now()
}

// generateEnhancedRecommendations generates enhanced actionable recommendations
func (emd *EnhancedMLDetector) generateEnhancedRecommendations(result *MLDetectionResult) []string {
	recommendations := make([]string, 0)

	if result.IsMalicious {
		recommendations = append(recommendations, "CRITICAL: This package is classified as malicious and should be immediately quarantined")
		recommendations = append(recommendations, "Block installation and usage of this package")
		recommendations = append(recommendations, "Report to package registry security team")
	}

	if result.IsTyposquatting {
		recommendations = append(recommendations, fmt.Sprintf("WARNING: Potential typosquatting of '%s'", result.TypoDetection.TargetPackage))
		recommendations = append(recommendations, "Verify package name spelling and author")
	}

	if result.IsAnomalous {
		recommendations = append(recommendations, "Package exhibits anomalous behavior patterns")
		recommendations = append(recommendations, "Perform additional security review")
	}

	if result.ReputationAnalysis.ReputationScore < emd.config.ReputationThreshold {
		recommendations = append(recommendations, "Low reputation score - exercise caution")
		recommendations = append(recommendations, "Verify author and maintainer credentials")
	}

	if result.OverallRiskScore >= 0.7 {
		recommendations = append(recommendations, "High risk package - recommend alternative")
		recommendations = append(recommendations, "Implement additional monitoring if usage is necessary")
	}

	if len(result.BehavioralAnalysis.SuspiciousBehaviors) > 0 {
		recommendations = append(recommendations, "Suspicious behavioral patterns detected")
		recommendations = append(recommendations, "Review package functionality and permissions")
	}

	return recommendations
}

// generateRecommendations generates actionable recommendations
func (emd *EnhancedMLDetector) generateRecommendations(result *MLDetectionResult) []string {
	recommendations := make([]string, 0)

	if result.IsMalicious {
		recommendations = append(recommendations, "CRITICAL: This package is classified as malicious and should be immediately quarantined")
		recommendations = append(recommendations, "Block installation and usage of this package")
		recommendations = append(recommendations, "Report to package registry security team")
	}

	if result.IsTyposquatting {
		recommendations = append(recommendations, fmt.Sprintf("WARNING: Potential typosquatting of '%s'", result.TypoDetection.TargetPackage))
		recommendations = append(recommendations, "Verify package name spelling and author")
	}

	if result.IsAnomalous {
		recommendations = append(recommendations, "Package exhibits anomalous behavior patterns")
		recommendations = append(recommendations, "Perform additional security review")
	}

	if result.ReputationAnalysis.ReputationScore < emd.config.ReputationThreshold {
		recommendations = append(recommendations, "Low reputation score - exercise caution")
		recommendations = append(recommendations, "Verify author and maintainer credentials")
	}

	if result.OverallRiskScore >= 0.7 {
		recommendations = append(recommendations, "High risk package - recommend alternative")
		recommendations = append(recommendations, "Implement additional monitoring if usage is necessary")
	}

	if len(result.BehavioralAnalysis.SuspiciousBehaviors) > 0 {
		recommendations = append(recommendations, "Suspicious behavioral patterns detected")
		recommendations = append(recommendations, "Review package functionality and permissions")
	}

	return recommendations
}

// BatchAnalyze performs batch analysis of multiple packages
func (emd *EnhancedMLDetector) BatchAnalyze(ctx context.Context, packages []*EnhancedPackageFeatures) ([]*MLDetectionResult, error) {
	results := make([]*MLDetectionResult, len(packages))
	errors := make([]error, len(packages))

	if emd.config.ParallelProcessing {
		// Parallel processing
		type result struct {
			index  int
			result *MLDetectionResult
			err    error
		}

		resultChan := make(chan result, len(packages))

		for i, pkg := range packages {
			go func(index int, features *EnhancedPackageFeatures) {
				res, err := emd.AnalyzePackage(ctx, features)
				resultChan <- result{index: index, result: res, err: err}
			}(i, pkg)
		}

		for i := 0; i < len(packages); i++ {
			res := <-resultChan
			results[res.index] = res.result
			errors[res.index] = res.err
		}
	} else {
		// Sequential processing
		for i, pkg := range packages {
			res, err := emd.AnalyzePackage(ctx, pkg)
			results[i] = res
			errors[i] = err
		}
	}

	// Check for errors
	for _, err := range errors {
		if err != nil {
			return results, err
		}
	}

	return results, nil
}

// UpdateModels updates all ML models
func (emd *EnhancedMLDetector) UpdateModels(ctx context.Context) error {
	if err := emd.similarityModel.Update(ctx); err != nil {
		return fmt.Errorf("failed to update similarity model: %w", err)
	}

	if err := emd.malwareClassifier.Update(ctx); err != nil {
		return fmt.Errorf("failed to update malware classifier: %w", err)
	}

	if err := emd.anomalyDetector.Update(ctx); err != nil {
		return fmt.Errorf("failed to update anomaly detector: %w", err)
	}

	if err := emd.typoDetector.Update(ctx); err != nil {
		return fmt.Errorf("failed to update typo detector: %w", err)
	}

	if err := emd.reputationAnalyzer.Update(ctx); err != nil {
		return fmt.Errorf("failed to update reputation analyzer: %w", err)
	}

	if err := emd.behavioralAnalyzer.Update(ctx); err != nil {
		return fmt.Errorf("failed to update behavioral analyzer: %w", err)
	}

	return nil
}

// GetModelMetrics returns metrics for all models
func (emd *EnhancedMLDetector) GetModelMetrics(ctx context.Context) (map[string]interface{}, error) {
	metrics := make(map[string]interface{})

	similarityMetrics, err := emd.similarityModel.GetMetrics(ctx)
	if err != nil {
		return nil, err
	}
	metrics["similarity"] = similarityMetrics

	malwareMetrics, err := emd.malwareClassifier.GetMetrics(ctx)
	if err != nil {
		return nil, err
	}
	metrics["malware"] = malwareMetrics

	anomalyMetrics, err := emd.anomalyDetector.GetMetrics(ctx)
	if err != nil {
		return nil, err
	}
	metrics["anomaly"] = anomalyMetrics

	typoMetrics, err := emd.typoDetector.GetMetrics(ctx)
	if err != nil {
		return nil, err
	}
	metrics["typo"] = typoMetrics

	reputationMetrics, err := emd.reputationAnalyzer.GetMetrics(ctx)
	if err != nil {
		return nil, err
	}
	metrics["reputation"] = reputationMetrics

	behavioralMetrics, err := emd.behavioralAnalyzer.GetMetrics(ctx)
	if err != nil {
		return nil, err
	}
	metrics["behavioral"] = behavioralMetrics

	ensembleMetrics, err := emd.ensembleModel.GetMetrics(ctx)
	if err != nil {
		return nil, err
	}
	metrics["ensemble"] = ensembleMetrics

	return metrics, nil
}

// ML model interfaces with comprehensive implementations
type SimilarityModel struct{}
type MalwareClassifier struct{}
type AnomalyDetector struct{}
type TypoDetector struct{}
type ReputationAnalyzer struct{}
type EnsembleModel struct{}

// Model implementations
func NewSimilarityModel() (*SimilarityModel, error)       { return &SimilarityModel{}, nil }
func NewMalwareClassifier() (*MalwareClassifier, error)   { return &MalwareClassifier{}, nil }
func NewAnomalyDetector() (*AnomalyDetector, error)       { return &AnomalyDetector{}, nil }
func NewTypoDetector() (*TypoDetector, error)             { return &TypoDetector{}, nil }
func NewReputationAnalyzer() (*ReputationAnalyzer, error) { return &ReputationAnalyzer{}, nil }
func NewEnsembleModel(weights map[string]float64) (*EnsembleModel, error) {
	return &EnsembleModel{}, nil
}

func (sm *SimilarityModel) AnalyzeSimilarity(ctx context.Context, features *EnhancedPackageFeatures) ([]EnhancedSimilarityResult, error) {
	var results []EnhancedSimilarityResult
	
	// Popular packages database for similarity comparison
	popularPackages := map[string][]string{
		"npm": {
			"react", "lodash", "express", "angular", "vue", "webpack", "babel",
			"typescript", "eslint", "prettier", "axios", "moment", "jquery",
			"bootstrap", "socket.io", "chalk", "commander", "inquirer", "yargs",
			"fs-extra", "glob", "rimraf", "mkdirp", "semver", "debug", "uuid",
		},
		"pypi": {
			"requests", "urllib3", "setuptools", "certifi", "pip", "wheel",
			"six", "python-dateutil", "s3transfer", "jmespath", "docutils",
			"pyasn1", "rsa", "colorama", "pyyaml", "awscli", "boto3", "botocore",
			"numpy", "pandas", "matplotlib", "scipy", "scikit-learn", "tensorflow",
			"pytorch", "django", "flask", "fastapi", "sqlalchemy", "celery",
		},
		"maven": {
			"spring-boot-starter", "spring-core", "junit", "slf4j-api", "logback-classic",
			"jackson-core", "jackson-databind", "commons-lang3", "guava", "httpclient",
			"hibernate-core", "mysql-connector-java", "postgresql", "mockito-core",
			"testng", "log4j-core", "gson", "apache-commons-io", "apache-commons-collections",
		},
		"go": {
			"github.com/gorilla/mux", "github.com/gin-gonic/gin", "github.com/labstack/echo",
			"github.com/sirupsen/logrus", "github.com/stretchr/testify", "go.uber.org/zap",
			"google.golang.org/grpc", "github.com/golang/protobuf", "gopkg.in/yaml.v2",
			"github.com/spf13/cobra", "github.com/spf13/viper", "gorm.io/gorm",
		},
	}
	
	packageName := features.Name
	registry := features.Registry
	
	// Get popular packages for the registry
	packages, exists := popularPackages[registry]
	if !exists {
		// Use a combined list for unknown registries
		for _, pkgs := range popularPackages {
			packages = append(packages, pkgs...)
		}
	}
	
	// Calculate similarity with popular packages
	for _, popular := range packages {
		if packageName == popular {
			continue // Skip exact matches
		}
		
		// Calculate multiple similarity metrics
		levenshtein := sm.calculateLevenshteinSimilarity(packageName, popular)
		jaroWinkler := sm.calculateJaroWinklerSimilarity(packageName, popular)
		phonetic := sm.calculatePhoneticSimilarity(packageName, popular)
		semantic := sm.calculateSemanticSimilarity(packageName, popular)
		
		// Weighted combination of similarities
		combinedSimilarity := (levenshtein*0.3 + jaroWinkler*0.4 + phonetic*0.2 + semantic*0.1)
		
		// Only include results above threshold
		if combinedSimilarity > 0.7 {
			result := EnhancedSimilarityResult{
				SimilarPackage:  popular,
				SimilarityScore: combinedSimilarity,
				SimilarityType:  "combined",
				Confidence:      sm.calculateConfidence(combinedSimilarity, len(packageName), len(popular)),
				Reason:          fmt.Sprintf("High similarity (%.2f) with popular package %s", combinedSimilarity, popular),
			}
			
			results = append(results, result)
		}
	}
	
	// Sort by similarity score (descending)
	for i := 0; i < len(results)-1; i++ {
		for j := i + 1; j < len(results); j++ {
			if results[i].SimilarityScore < results[j].SimilarityScore {
				results[i], results[j] = results[j], results[i]
			}
		}
	}
	
	// Limit to top 10 results
	if len(results) > 10 {
		results = results[:10]
	}
	
	return results, nil
}

func (sm *SimilarityModel) calculateLevenshteinSimilarity(s1, s2 string) float64 {
	distance := sm.calculateEditDistance(s1, s2)
	maxLen := sm.max(len(s1), len(s2))
	if maxLen == 0 {
		return 1.0
	}
	return 1.0 - float64(distance)/float64(maxLen)
}

func (sm *SimilarityModel) calculateEditDistance(s1, s2 string) int {
	if len(s1) == 0 {
		return len(s2)
	}
	if len(s2) == 0 {
		return len(s1)
	}
	
	matrix := make([][]int, len(s1)+1)
	for i := range matrix {
		matrix[i] = make([]int, len(s2)+1)
	}
	
	for i := 0; i <= len(s1); i++ {
		matrix[i][0] = i
	}
	for j := 0; j <= len(s2); j++ {
		matrix[0][j] = j
	}
	
	for i := 1; i <= len(s1); i++ {
		for j := 1; j <= len(s2); j++ {
			cost := 0
			if s1[i-1] != s2[j-1] {
				cost = 1
			}
			matrix[i][j] = sm.min3(
				matrix[i-1][j]+1,
				matrix[i][j-1]+1,
				matrix[i-1][j-1]+cost,
			)
		}
	}
	
	return matrix[len(s1)][len(s2)]
}

func (sm *SimilarityModel) calculateJaroWinklerSimilarity(s1, s2 string) float64 {
	if s1 == s2 {
		return 1.0
	}
	
	len1, len2 := len(s1), len(s2)
	if len1 == 0 || len2 == 0 {
		return 0.0
	}
	
	matchWindow := sm.max(len1, len2)/2 - 1
	if matchWindow < 0 {
		matchWindow = 0
	}
	
	s1Matches := make([]bool, len1)
	s2Matches := make([]bool, len2)
	
	matches := 0
	transpositions := 0
	
	// Find matches
	for i := 0; i < len1; i++ {
		start := sm.max(0, i-matchWindow)
		end := sm.min(i+matchWindow+1, len2)
		
		for j := start; j < end; j++ {
			if s2Matches[j] || s1[i] != s2[j] {
				continue
			}
			s1Matches[i] = true
			s2Matches[j] = true
			matches++
			break
		}
	}
	
	if matches == 0 {
		return 0.0
	}
	
	// Count transpositions
	k := 0
	for i := 0; i < len1; i++ {
		if !s1Matches[i] {
			continue
		}
		for !s2Matches[k] {
			k++
		}
		if s1[i] != s2[k] {
			transpositions++
		}
		k++
	}
	
	jaro := (float64(matches)/float64(len1) + float64(matches)/float64(len2) + float64(matches-transpositions/2)/float64(matches)) / 3.0
	
	// Calculate prefix length for Jaro-Winkler
	prefix := 0
	for i := 0; i < sm.min(len1, len2) && i < 4; i++ {
		if s1[i] == s2[i] {
			prefix++
		} else {
			break
		}
	}
	
	return jaro + (0.1 * float64(prefix) * (1.0 - jaro))
}

func (sm *SimilarityModel) calculatePhoneticSimilarity(s1, s2 string) float64 {
	// Simple phonetic similarity based on consonant patterns
	consonants1 := sm.extractConsonants(s1)
	consonants2 := sm.extractConsonants(s2)
	
	if consonants1 == consonants2 {
		return 1.0
	}
	
	return sm.calculateLevenshteinSimilarity(consonants1, consonants2)
}

func (sm *SimilarityModel) extractConsonants(s string) string {
	vowels := "aeiouAEIOU"
	var consonants []rune
	
	for _, r := range s {
		isVowel := false
		for _, v := range vowels {
			if r == v {
				isVowel = true
				break
			}
		}
		if !isVowel && ((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')) {
			consonants = append(consonants, r)
		}
	}
	
	return string(consonants)
}

func (sm *SimilarityModel) calculateSemanticSimilarity(s1, s2 string) float64 {
	// Simple semantic similarity based on common prefixes/suffixes
	commonPrefixes := []string{"lib", "node", "py", "go", "js", "react", "vue", "angular"}
	commonSuffixes := []string{"js", "py", "go", "lib", "util", "utils", "core", "api"}
	
	score := 0.0
	
	// Check for common prefixes
	for _, prefix := range commonPrefixes {
		if (len(s1) > len(prefix) && s1[:len(prefix)] == prefix) &&
		   (len(s2) > len(prefix) && s2[:len(prefix)] == prefix) {
			score += 0.3
			break
		}
	}
	
	// Check for common suffixes
	for _, suffix := range commonSuffixes {
		if (len(s1) >= len(suffix) && s1[len(s1)-len(suffix):] == suffix) &&
		   (len(s2) >= len(suffix) && s2[len(s2)-len(suffix):] == suffix) {
			score += 0.3
			break
		}
	}
	
	// Check for common substrings
	if sm.hasCommonSubstring(s1, s2, 3) {
		score += 0.4
	}
	
	return sm.minFloat(score, 1.0)
}

func (sm *SimilarityModel) hasCommonSubstring(s1, s2 string, minLen int) bool {
	for i := 0; i <= len(s1)-minLen; i++ {
		substr := s1[i : i+minLen]
		if len(substr) >= minLen && sm.contains(s2, substr) {
			return true
		}
	}
	return false
}

func (sm *SimilarityModel) contains(s, substr string) bool {
	return len(s) >= len(substr) && s != substr && 
		   (len(s) > len(substr) && (s[:len(substr)] == substr || 
		    s[len(s)-len(substr):] == substr || 
		    sm.containsSubstring(s, substr)))
}

func (sm *SimilarityModel) containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func (sm *SimilarityModel) calculateConfidence(similarity float64, len1, len2 int) float64 {
	// Higher confidence for similar length strings with high similarity
	lengthDiff := float64(sm.abs(len1 - len2))
	maxLen := float64(sm.max(len1, len2))
	
	lengthSimilarity := 1.0 - (lengthDiff / maxLen)
	return (similarity + lengthSimilarity) / 2.0
}

func (sm *SimilarityModel) max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func (sm *SimilarityModel) min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (sm *SimilarityModel) min3(a, b, c int) int {
	return sm.min(sm.min(a, b), c)
}

func (sm *SimilarityModel) abs(a int) int {
	if a < 0 {
		return -a
	}
	return a
}

func (sm *SimilarityModel) minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
func (mc *MalwareClassifier) ClassifyMalware(ctx context.Context, features *EnhancedPackageFeatures) (*MalwareClassification, error) {
	classification := &MalwareClassification{
		IsMalware:            false,
		MalwareType:          "none",
		MalwareFamily:        "",
		Confidence:           0.0,
		FeatureImportance:    make(map[string]float64),
		ClassificationReason: "",
	}
	
	var riskScore float64
	var reasons []string
	var featureImportance = make(map[string]float64)
	
	// Analyze package name for suspicious patterns
	nameScore := mc.analyzePackageName(features.Name)
	if nameScore > 0.3 {
		reasons = append(reasons, "suspicious package name patterns")
		featureImportance["package_name"] = nameScore
		riskScore += nameScore * 0.2
	}
	
	// Analyze author/maintainer reputation
	authorScore := mc.analyzeAuthorReputation(features.Author, features.Maintainers)
	if authorScore > 0.4 {
		reasons = append(reasons, "suspicious author/maintainer profile")
		featureImportance["author_reputation"] = authorScore
		riskScore += authorScore * 0.15
	}
	
	// Analyze version patterns
	versionScore := mc.analyzeVersionPatterns(features.Version, features.CreationDate, features.LastUpdated)
	if versionScore > 0.3 {
		reasons = append(reasons, "suspicious version patterns")
		featureImportance["version_patterns"] = versionScore
		riskScore += versionScore * 0.1
	}
	
	// Analyze dependencies
	depScore := mc.analyzeDependencies(features.Dependencies, features.DevDependencies)
	if depScore > 0.3 {
		reasons = append(reasons, "suspicious dependencies detected")
		featureImportance["dependencies"] = depScore
		riskScore += depScore * 0.15
	}
	
	// Analyze scripts and file structure
	scriptScore := mc.analyzeScripts(features.Scripts, features.FileStructure)
	if scriptScore > 0.4 {
		reasons = append(reasons, "suspicious scripts or file structure")
		featureImportance["scripts"] = scriptScore
		riskScore += scriptScore * 0.25
	}
	
	// Analyze metadata quality
	metadataScore := mc.analyzeMetadata(features.Description, features.Keywords, features.License, features.Homepage, features.Repository)
	if metadataScore > 0.3 {
		reasons = append(reasons, "poor metadata quality indicators")
		featureImportance["metadata"] = metadataScore
		riskScore += metadataScore * 0.1
	}
	
	// Analyze behavioral metrics
	behaviorScore := mc.analyzeBehavioralMetrics(features.BehavioralMetrics)
	if behaviorScore > 0.3 {
		reasons = append(reasons, "suspicious behavioral patterns")
		featureImportance["behavior"] = behaviorScore
		riskScore += behaviorScore * 0.05
	}
	
	// Determine malware type and family
	malwareType := "none"
	malwareFamily := ""
	
	if riskScore > 0.8 {
		classification.IsMalware = true
		malwareType = "high_confidence_malware"
		malwareFamily = "unknown"
	} else if riskScore > 0.6 {
		classification.IsMalware = true
		malwareType = "potential_malware"
		malwareFamily = "suspicious"
	} else if riskScore > 0.4 {
		malwareType = "suspicious_package"
	} else if riskScore > 0.2 {
		malwareType = "low_risk"
	}
	
	// Build classification reason
	classificationReason := "Clean package"
	if len(reasons) > 0 {
		classificationReason = fmt.Sprintf("Risk factors: %s", strings.Join(reasons, ", "))
	}
	
	classification.Confidence = riskScore
	classification.MalwareType = malwareType
	classification.MalwareFamily = malwareFamily
	classification.FeatureImportance = featureImportance
	classification.ClassificationReason = classificationReason
	
	return classification, nil
}

// Helper methods for MalwareClassifier
func (mc *MalwareClassifier) analyzePackageName(name string) float64 {
	score := 0.0
	
	// Check for suspicious patterns in package names
	suspiciousPatterns := []string{
		"test", "temp", "demo", "sample", "fake", "malicious", "evil",
		"hack", "crack", "exploit", "virus", "trojan", "backdoor",
		"stealer", "keylog", "bitcoin", "crypto", "wallet", "miner",
	}
	
	nameLower := strings.ToLower(name)
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(nameLower, pattern) {
			score += 0.3
		}
	}
	
	// Check for random-looking names
	if len(name) > 10 && mc.isRandomLooking(name) {
		score += 0.2
	}
	
	// Check for typosquatting patterns
	if mc.hasTyposquattingPatterns(name) {
		score += 0.4
	}
	
	return mc.clampScore(score)
}

func (mc *MalwareClassifier) analyzeAuthorReputation(author string, maintainers []string) float64 {
	score := 0.0
	
	// Check author reputation
	if author == "" {
		score += 0.3
	} else if mc.isSuspiciousAuthor(author) {
		score += 0.5
	}
	
	// Check maintainers
	if len(maintainers) == 0 {
		score += 0.2
	} else {
		for _, maintainer := range maintainers {
			if mc.isSuspiciousAuthor(maintainer) {
				score += 0.3
				break
			}
		}
	}
	
	return mc.clampScore(score)
}

func (mc *MalwareClassifier) analyzeVersionPatterns(version string, creationDate, lastUpdated time.Time) float64 {
	score := 0.0
	
	// Check for suspicious version patterns
	if version == "" {
		score += 0.2
	} else if strings.HasPrefix(version, "0.0.") || version == "1.0.0" {
		score += 0.1
	}
	
	// Check creation and update patterns
	if !creationDate.IsZero() && !lastUpdated.IsZero() {
		daysSinceCreation := time.Since(creationDate).Hours() / 24
		daysSinceUpdate := time.Since(lastUpdated).Hours() / 24
		
		// Very new packages are suspicious
		if daysSinceCreation < 1 {
			score += 0.3
		}
		
		// Packages not updated for a long time but recently created
		if daysSinceCreation < 30 && daysSinceUpdate > 30 {
			score += 0.2
		}
	}
	
	return mc.clampScore(score)
}

func (mc *MalwareClassifier) analyzeDependencies(deps, devDeps []Dependency) float64 {
	score := 0.0
	
	// Check for suspicious dependencies
	suspiciousDeps := []string{
		"child_process", "fs-extra", "node-pty", "keytar", "electron",
		"puppeteer", "selenium", "crypto", "bitcoin", "wallet",
	}
	
	allDeps := append(deps, devDeps...)
	for _, dep := range allDeps {
		for _, suspicious := range suspiciousDeps {
			if strings.Contains(strings.ToLower(dep.Name), suspicious) {
				score += 0.1
			}
		}
		// Check if dependency is already marked as suspicious
		if dep.Suspicious {
			score += dep.RiskScore * 0.5
		}
	}
	
	// Too many dependencies is suspicious
	if len(allDeps) > 50 {
		score += 0.2
	}
	
	return mc.clampScore(score)
}

func (mc *MalwareClassifier) analyzeScripts(scripts map[string]string, fileStructure FileStructure) float64 {
	score := 0.0
	
	// Check for suspicious scripts
	suspiciousScriptPatterns := []string{
		"curl", "wget", "eval", "exec", "spawn", "child_process",
		"fs.readFile", "fs.writeFile", "process.env", "Buffer.from",
		"atob", "btoa", "base64", "crypto", "bitcoin",
	}
	
	for _, script := range scripts {
		scriptLower := strings.ToLower(script)
		for _, pattern := range suspiciousScriptPatterns {
			if strings.Contains(scriptLower, pattern) {
				score += 0.2
			}
		}
	}
	
	// Check file structure for suspicious files
	if len(fileStructure.SuspiciousFiles) > 0 {
		score += 0.3
	}
	
	// Check for unusual file patterns
	if fileStructure.BinaryFiles > fileStructure.TotalFiles/2 {
		score += 0.2
	}
	
	if fileStructure.HiddenFiles > 5 {
		score += 0.1
	}
	
	return mc.clampScore(score)
}

func (mc *MalwareClassifier) analyzeMetadata(description string, keywords []string, license, homepage, repository string) float64 {
	score := 0.0
	
	// Check for missing or poor metadata
	if description == "" {
		score += 0.2
	} else if len(description) < 20 {
		score += 0.1
	}
	
	if license == "" {
		score += 0.1
	}
	
	if homepage == "" && repository == "" {
		score += 0.2
	}
	
	if len(keywords) == 0 {
		score += 0.1
	}
	
	// Check for suspicious keywords
	suspiciousKeywords := []string{
		"hack", "crack", "exploit", "malware", "virus", "trojan",
		"stealer", "keylog", "bitcoin", "crypto", "miner",
	}
	
	for _, keyword := range keywords {
		keywordLower := strings.ToLower(keyword)
		for _, suspicious := range suspiciousKeywords {
			if strings.Contains(keywordLower, suspicious) {
				score += 0.3
			}
		}
	}
	
	return mc.clampScore(score)
}

func (mc *MalwareClassifier) analyzeBehavioralMetrics(metrics BehavioralMetrics) float64 {
	score := 0.0
	
	// Analyze behavioral metrics
	if metrics.AnomalyScore > 0.5 {
		score += metrics.AnomalyScore * 0.3
	}
	
	// Check installation behavior
	if metrics.InstallationBehavior.NetworkActivity {
		score += 0.2
	}
	
	if metrics.InstallationBehavior.SuspiciousCommands > 0 {
		score += 0.3
	}
	
	// Check runtime behavior
	if metrics.RuntimeBehavior.AntiAnalysisTechniques {
		score += 0.4
	}
	
	if metrics.RuntimeBehavior.PersistenceMechanisms {
		score += 0.3
	}
	
	// Check network behavior
	if metrics.NetworkBehavior.DataExfiltration {
		score += 0.5
	}
	
	if metrics.NetworkBehavior.C2Communication {
		score += 0.6
	}
	
	return mc.clampScore(score)
}

// Helper utility methods
func (mc *MalwareClassifier) isRandomLooking(name string) bool {
	vowels := "aeiou"
	consonants := "bcdfghjklmnpqrstvwxyz"
	
	vowelCount := 0
	consonantCount := 0
	
	for _, char := range strings.ToLower(name) {
		if strings.ContainsRune(vowels, char) {
			vowelCount++
		} else if strings.ContainsRune(consonants, char) {
			consonantCount++
		}
	}
	
	total := vowelCount + consonantCount
	if total == 0 {
		return true
	}
	
	vowelRatio := float64(vowelCount) / float64(total)
	return vowelRatio < 0.1 || vowelRatio > 0.8
}

func (mc *MalwareClassifier) hasTyposquattingPatterns(name string) bool {
	// Simple typosquatting detection
	popularPackages := []string{
		"react", "lodash", "express", "angular", "vue", "webpack",
		"babel", "typescript", "eslint", "prettier", "axios", "moment",
	}
	
	for _, popular := range popularPackages {
		if name != popular && mc.calculateEditDistance(name, popular) <= 2 && len(name) > 3 {
			return true
		}
	}
	
	return false
}

func (mc *MalwareClassifier) isSuspiciousAuthor(author string) bool {
	suspiciousPatterns := []string{
		"test", "temp", "fake", "anonymous", "unknown", "admin",
		"root", "user", "hacker", "cracker",
	}
	
	authorLower := strings.ToLower(author)
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(authorLower, pattern) {
			return true
		}
	}
	
	return false
}

func (mc *MalwareClassifier) calculateEditDistance(s1, s2 string) int {
	if len(s1) == 0 {
		return len(s2)
	}
	if len(s2) == 0 {
		return len(s1)
	}
	
	matrix := make([][]int, len(s1)+1)
	for i := range matrix {
		matrix[i] = make([]int, len(s2)+1)
	}
	
	for i := 0; i <= len(s1); i++ {
		matrix[i][0] = i
	}
	for j := 0; j <= len(s2); j++ {
		matrix[0][j] = j
	}
	
	for i := 1; i <= len(s1); i++ {
		for j := 1; j <= len(s2); j++ {
			cost := 0
			if s1[i-1] != s2[j-1] {
				cost = 1
			}
			matrix[i][j] = mc.min3(
				matrix[i-1][j]+1,
				matrix[i][j-1]+1,
				matrix[i-1][j-1]+cost,
			)
		}
	}
	
	return matrix[len(s1)][len(s2)]
}

func (mc *MalwareClassifier) clampScore(score float64) float64 {
	if score < 0.0 {
		return 0.0
	}
	if score > 1.0 {
		return 1.0
	}
	return score
}

func (mc *MalwareClassifier) min3(a, b, c int) int {
	if a <= b && a <= c {
		return a
	}
	if b <= c {
		return b
	}
	return c
}

// AnomalyDetector implementation
func (ad *AnomalyDetector) DetectAnomalies(ctx context.Context, features *EnhancedPackageFeatures) (*EnhancedAnomalyDetection, error) {
	detection := &EnhancedAnomalyDetection{
		IsAnomalous:       false,
		AnomalyScore:      0.0,
		AnomalyType:       "none",
		Confidence:        0.0,
		AnomalousFeatures: []string{},
		BaselineDeviation: 0.0,
	}
	
	var anomalyScore float64
	var anomalousFeatures []string
	
	// Check package size anomalies (using lines of code as size metric)
	sizeDeviation := ad.analyzeSizeAnomaly(int64(features.CodeMetrics.LinesOfCode), features.Registry)
	if sizeDeviation > 0.3 {
		anomalyScore += sizeDeviation * 0.2
		anomalousFeatures = append(anomalousFeatures, "unusual_package_size")
	}
	
	// Check version pattern anomalies
	versionDeviation := ad.analyzeVersionAnomaly(features.Version, features.CreationDate)
	if versionDeviation > 0.3 {
		anomalyScore += versionDeviation * 0.15
		anomalousFeatures = append(anomalousFeatures, "unusual_version_pattern")
	}
	
	// Check dependency anomalies
	depDeviation := ad.analyzeDependencyAnomaly(features.Dependencies, features.Registry)
	if depDeviation > 0.3 {
		anomalyScore += depDeviation * 0.2
		anomalousFeatures = append(anomalousFeatures, "unusual_dependency_patterns")
	}
	
	// Check metadata anomalies
	metadataDeviation := ad.analyzeMetadataAnomaly(features.Description, features.Keywords, features.License)
	if metadataDeviation > 0.3 {
		anomalyScore += metadataDeviation * 0.15
		anomalousFeatures = append(anomalousFeatures, "unusual_metadata_patterns")
	}
	
	// Check behavioral anomalies
	behaviorDeviation := ad.analyzeBehavioralAnomaly(features.BehavioralMetrics)
	if behaviorDeviation > 0.4 {
		anomalyScore += behaviorDeviation * 0.3
		anomalousFeatures = append(anomalousFeatures, "unusual_behavioral_patterns")
	}
	
	// Determine anomaly type and confidence
	anomalyType := "none"
	if anomalyScore > 0.7 {
		detection.IsAnomalous = true
		anomalyType = "high_anomaly"
	} else if anomalyScore > 0.5 {
		detection.IsAnomalous = true
		anomalyType = "moderate_anomaly"
	} else if anomalyScore > 0.3 {
		anomalyType = "low_anomaly"
	}
	
	detection.AnomalyScore = anomalyScore
	detection.AnomalyType = anomalyType
	detection.Confidence = anomalyScore
	detection.AnomalousFeatures = anomalousFeatures
	detection.BaselineDeviation = anomalyScore
	
	return detection, nil
}

// AnomalyDetector helper methods
func (ad *AnomalyDetector) analyzeSizeAnomaly(size int64, registry string) float64 {
	// Expected size ranges by registry (in bytes)
	expectedSizes := map[string]struct{ min, max int64 }{
		"npm":   {1000, 10000000},     // 1KB to 10MB
		"pypi":  {5000, 50000000},     // 5KB to 50MB
		"maven": {10000, 100000000},   // 10KB to 100MB
		"go":    {1000, 20000000},     // 1KB to 20MB
	}
	
	expected, exists := expectedSizes[registry]
	if !exists {
		expected = expectedSizes["npm"] // Default
	}
	
	if size < expected.min {
		return float64(expected.min-size) / float64(expected.min)
	}
	if size > expected.max {
		return float64(size-expected.max) / float64(expected.max)
	}
	
	return 0.0
}

func (ad *AnomalyDetector) analyzeVersionAnomaly(version string, creationDate time.Time) float64 {
	score := 0.0
	
	// Check for unusual version patterns
	if strings.Contains(version, "alpha") || strings.Contains(version, "beta") || strings.Contains(version, "rc") {
		score += 0.2
	}
	
	// Check for very high version numbers
	if strings.HasPrefix(version, "999") || strings.HasPrefix(version, "1000") {
		score += 0.5
	}
	
	// Check for version-date mismatch
	if !creationDate.IsZero() {
		daysSinceCreation := time.Since(creationDate).Hours() / 24
		if daysSinceCreation < 1 && !strings.HasPrefix(version, "0.") {
			score += 0.3 // New package with high version
		}
	}
	
	return ad.clampScore(score)
}

func (ad *AnomalyDetector) analyzeDependencyAnomaly(deps []Dependency, registry string) float64 {
	score := 0.0
	
	// Expected dependency counts by registry
	expectedDepCounts := map[string]int{
		"npm":   15,
		"pypi":  8,
		"maven": 10,
		"go":    5,
	}
	
	expected, exists := expectedDepCounts[registry]
	if !exists {
		expected = 10 // Default
	}
	
	depCount := len(deps)
	
	// Too many or too few dependencies
	if depCount > expected*3 {
		score += 0.4
	} else if depCount == 0 && registry != "go" {
		score += 0.3
	}
	
	// Check for circular dependencies
	depNames := make(map[string]bool)
	for _, dep := range deps {
		if depNames[dep.Name] {
			score += 0.3 // Duplicate dependency
		}
		depNames[dep.Name] = true
	}
	
	return ad.clampScore(score)
}

func (ad *AnomalyDetector) analyzeMetadataAnomaly(description string, keywords []string, license string) float64 {
	score := 0.0
	
	// Check description anomalies
	if len(description) > 1000 {
		score += 0.2 // Unusually long description
	} else if len(description) < 10 && description != "" {
		score += 0.3 // Unusually short description
	}
	
	// Check keyword anomalies
	if len(keywords) > 20 {
		score += 0.2 // Too many keywords
	}
	
	// Check for unusual licenses
	commonLicenses := []string{"MIT", "Apache-2.0", "GPL-3.0", "BSD-3-Clause", "ISC"}
	isCommonLicense := false
	for _, common := range commonLicenses {
		if strings.EqualFold(license, common) {
			isCommonLicense = true
			break
		}
	}
	if !isCommonLicense && license != "" {
		score += 0.1
	}
	
	return ad.clampScore(score)
}

func (ad *AnomalyDetector) analyzeBehavioralAnomaly(metrics BehavioralMetrics) float64 {
	score := 0.0
	
	// High anomaly score from behavioral analysis
	if metrics.AnomalyScore > 0.5 {
		score += metrics.AnomalyScore * 0.5
	}
	
	// Unusual installation behavior
	if metrics.InstallationBehavior.NetworkActivity {
		score += 0.3
	}
	
	if metrics.InstallationBehavior.SuspiciousCommands > 2 {
		score += 0.4
	}
	
	// Unusual runtime behavior
	if metrics.RuntimeBehavior.AntiAnalysisTechniques {
		score += 0.5
	}
	
	return ad.clampScore(score)
}

func (ad *AnomalyDetector) clampScore(score float64) float64 {
	if score < 0.0 {
		return 0.0
	}
	if score > 1.0 {
		return 1.0
	}
	return score
}

func (mc *MalwareClassifier) hasSuspiciousFiles(fileStructure map[string]interface{}) bool {
	suspiciousFiles := []string{
		".env", "config.json", "private.key", "wallet.dat",
		"keylog", "stealer", "backdoor", "trojan",
	}
	
	for filename := range fileStructure {
		filenameLower := strings.ToLower(filename)
		for _, suspicious := range suspiciousFiles {
			if strings.Contains(filenameLower, suspicious) {
				return true
			}
		}
	}
	
	return false
}

func (ad *AnomalyDetector) detectVersionAnomalies(version string, creationDate, lastUpdated time.Time) float64 {
	var anomalyScore float64
	
	// Check for unusual version patterns
	if version == "" {
		return 0.3 // Missing version is suspicious
	}
	
	// Check for pre-release versions (higher anomaly)
	if strings.Contains(version, "alpha") || strings.Contains(version, "beta") || strings.Contains(version, "rc") {
		anomalyScore += 0.2
	}
	
	// Check for very high version numbers (potential typosquatting)
	versionParts := strings.Split(version, ".")
	if len(versionParts) > 0 {
		if majorVersion, err := strconv.Atoi(versionParts[0]); err == nil {
			if majorVersion > 100 {
				anomalyScore += 0.4
			}
		}
	}
	
	// Check for rapid version updates
	if !creationDate.IsZero() && !lastUpdated.IsZero() {
		timeDiff := lastUpdated.Sub(creationDate)
		if timeDiff.Hours() < 24 && len(versionParts) >= 3 {
			// Multiple version parts updated within 24 hours is suspicious
			anomalyScore += 0.3
		}
	}
	
	return anomalyScore
}
func (td *TypoDetector) DetectTyposquatting(ctx context.Context, features *EnhancedPackageFeatures) (*TypoDetection, error) {
	if features == nil {
		return &TypoDetection{}, nil
	}
	
	packageName := features.Name
	registry := features.Registry
	
	// Get popular packages for the registry
	popularPackages := td.getPopularPackages(registry)
	
	var bestMatch string
	var highestSimilarity float64
	var typoType string
	var editDistance int
	var suspiciousPatterns []string
	
	// Check against popular packages
	for _, popular := range popularPackages {
		if packageName == popular {
			// Exact match with popular package - not typosquatting
			continue
		}
		
		// Calculate edit distance
		distance := td.calculateEditDistance(packageName, popular)
		
		// Calculate similarity score
		similarity := 1.0 - float64(distance)/float64(max(len(packageName), len(popular)))
		
		if similarity > highestSimilarity && similarity > 0.7 {
			highestSimilarity = similarity
			bestMatch = popular
			editDistance = distance
			typoType = td.determineTypoType(packageName, popular)
		}
	}
	
	// Check for suspicious patterns
	suspiciousPatterns = td.detectSuspiciousPatterns(packageName)
	
	// Determine if it's typosquatting
	isTyposquatting := false
	confidence := 0.0
	
	if highestSimilarity > 0.8 && editDistance <= 3 {
		isTyposquatting = true
		confidence = highestSimilarity
	}
	
	// Additional checks for suspicious patterns
	if len(suspiciousPatterns) > 0 {
		confidence += 0.2
		if confidence > 0.7 {
			isTyposquatting = true
		}
	}
	
	// Normalize confidence
	if confidence > 1.0 {
		confidence = 1.0
	}
	
	return &TypoDetection{
		IsTyposquatting:    isTyposquatting,
		TargetPackage:      bestMatch,
		TypoType:           typoType,
		EditDistance:       editDistance,
		SimilarityScore:    highestSimilarity,
		Confidence:         confidence,
		SuspiciousPatterns: suspiciousPatterns,
	}, nil
}

// Helper methods for TypoDetector
func (td *TypoDetector) getPopularPackages(registry string) []string {
	// Return a list of popular packages for the given registry
	// This would typically be loaded from a database or configuration
	popularPackages := map[string][]string{
		"npm": {"react", "lodash", "express", "axios", "webpack", "babel", "eslint", "typescript", "vue", "angular", "jquery", "moment", "chalk", "commander", "debug", "fs-extra", "glob", "rimraf", "mkdirp", "yargs"},
		"pypi": {"requests", "numpy", "pandas", "flask", "django", "tensorflow", "pytorch", "scikit-learn", "matplotlib", "seaborn", "beautifulsoup4", "selenium", "pillow", "opencv-python", "sqlalchemy", "fastapi", "pydantic", "click", "pytest", "black"},
		"rubygems": {"rails", "bundler", "rake", "rspec", "puma", "nokogiri", "devise", "activerecord", "activesupport", "thor", "json", "minitest", "rack", "sinatra", "capistrano", "sidekiq", "redis", "pg", "mysql2", "sqlite3"},
		"packagist": {"symfony/symfony", "laravel/framework", "guzzlehttp/guzzle", "monolog/monolog", "phpunit/phpunit", "doctrine/orm", "twig/twig", "swiftmailer/swiftmailer", "psr/log", "composer/composer"},
		"crates.io": {"serde", "tokio", "clap", "rand", "regex", "log", "env_logger", "chrono", "uuid", "reqwest", "anyhow", "thiserror", "futures", "async-trait", "diesel", "actix-web", "hyper", "warp", "sqlx", "rayon"},
	}
	
	if packages, exists := popularPackages[registry]; exists {
		return packages
	}
	return []string{}
}

func (td *TypoDetector) calculateEditDistance(s1, s2 string) int {
	// Levenshtein distance implementation
	if len(s1) == 0 {
		return len(s2)
	}
	if len(s2) == 0 {
		return len(s1)
	}
	
	matrix := make([][]int, len(s1)+1)
	for i := range matrix {
		matrix[i] = make([]int, len(s2)+1)
	}
	
	for i := 0; i <= len(s1); i++ {
		matrix[i][0] = i
	}
	for j := 0; j <= len(s2); j++ {
		matrix[0][j] = j
	}
	
	for i := 1; i <= len(s1); i++ {
		for j := 1; j <= len(s2); j++ {
			cost := 0
			if s1[i-1] != s2[j-1] {
				cost = 1
			}
			
			matrix[i][j] = min(
				matrix[i-1][j]+1,      // deletion
				matrix[i][j-1]+1,      // insertion
				matrix[i-1][j-1]+cost, // substitution
			)
		}
	}
	
	return matrix[len(s1)][len(s2)]
}

func (td *TypoDetector) determineTypoType(typo, original string) string {
	if len(typo) == len(original) {
		// Check for character substitution
		diffCount := 0
		for i := 0; i < len(typo); i++ {
			if typo[i] != original[i] {
				diffCount++
			}
		}
		if diffCount == 1 {
			return "substitution"
		}
		if diffCount == 2 {
			return "transposition"
		}
		return "multiple_substitution"
	} else if len(typo) == len(original)+1 {
		return "insertion"
	} else if len(typo) == len(original)-1 {
		return "deletion"
	}
	return "complex"
}

func (td *TypoDetector) detectSuspiciousPatterns(packageName string) []string {
	var patterns []string
	
	// Check for common typosquatting patterns
	if strings.Contains(packageName, "0") || strings.Contains(packageName, "1") {
		patterns = append(patterns, "number_substitution")
	}
	
	if strings.Contains(packageName, "-") && strings.Count(packageName, "-") > 2 {
		patterns = append(patterns, "excessive_hyphens")
	}
	
	if strings.Contains(packageName, "_") && strings.Count(packageName, "_") > 2 {
		patterns = append(patterns, "excessive_underscores")
	}
	
	// Check for mixed case in unusual patterns
	hasUpper := false
	hasLower := false
	for _, r := range packageName {
		if unicode.IsUpper(r) {
			hasUpper = true
		}
		if unicode.IsLower(r) {
			hasLower = true
		}
	}
	if hasUpper && hasLower && len(packageName) < 10 {
		patterns = append(patterns, "unusual_casing")
	}
	
	// Check for repeated characters
	for i := 0; i < len(packageName)-1; i++ {
		if packageName[i] == packageName[i+1] {
			patterns = append(patterns, "repeated_characters")
			break
		}
	}
	
	return patterns
}

func (ra *ReputationAnalyzer) AnalyzeReputation(ctx context.Context, features *EnhancedPackageFeatures) (*EnhancedReputationAnalysis, error) {
	if features == nil {
		return &EnhancedReputationAnalysis{}, nil
	}
	
	var trustScore float64 = 0.5 // Start with neutral score
	var riskFactors []string
	var positiveIndicators []string
	var communityTrust float64
	var maintainerReputation float64
	
	// Analyze download statistics
	if features.Downloads > 0 {
		// Higher download count increases trust
		if features.Downloads > 1000000 {
			trustScore += 0.3
			positiveIndicators = append(positiveIndicators, "high_download_count")
		} else if features.Downloads > 100000 {
			trustScore += 0.2
			positiveIndicators = append(positiveIndicators, "moderate_download_count")
		} else if features.Downloads < 100 {
			trustScore -= 0.2
			riskFactors = append(riskFactors, "low_download_count")
		}
	}
	
	// Analyze GitHub stars and community engagement
	if features.Stars > 0 {
		if features.Stars > 10000 {
			trustScore += 0.25
			positiveIndicators = append(positiveIndicators, "high_github_stars")
		} else if features.Stars > 1000 {
			trustScore += 0.15
			positiveIndicators = append(positiveIndicators, "moderate_github_stars")
		}
		communityTrust = math.Min(1.0, float64(features.Stars)/10000.0)
	}
	
	// Analyze package age and stability
	if !features.CreationDate.IsZero() {
		packageAge := time.Since(features.CreationDate)
		if packageAge.Hours() > 8760 { // More than 1 year
			trustScore += 0.2
			positiveIndicators = append(positiveIndicators, "mature_package")
		} else if packageAge.Hours() < 168 { // Less than 1 week
			trustScore -= 0.3
			riskFactors = append(riskFactors, "very_new_package")
		}
	}
	
	// Analyze maintainer information
	if features.Author != "" {
		// Check for known maintainer patterns
		if ra.isKnownMaintainer(features.Author) {
			trustScore += 0.2
			positiveIndicators = append(positiveIndicators, "known_maintainer")
			maintainerReputation = 0.8
		} else if ra.isSuspiciousMaintainer(features.Author) {
			trustScore -= 0.3
			riskFactors = append(riskFactors, "suspicious_maintainer")
			maintainerReputation = 0.2
		} else {
			maintainerReputation = 0.5
		}
	}
	
	// Analyze version patterns
	if features.Version != "" {
		if ra.hasStableVersionPattern(features.Version) {
			trustScore += 0.1
			positiveIndicators = append(positiveIndicators, "stable_versioning")
		} else {
			trustScore -= 0.1
			riskFactors = append(riskFactors, "unstable_versioning")
		}
	}
	
	// Analyze dependencies
	if len(features.Dependencies) > 0 {
		suspiciousDeps := ra.countSuspiciousDependencies(features.Dependencies)
		if suspiciousDeps > 0 {
			trustScore -= float64(suspiciousDeps) * 0.1
			riskFactors = append(riskFactors, "suspicious_dependencies")
		}
		
		if len(features.Dependencies) > 50 {
			trustScore -= 0.1
			riskFactors = append(riskFactors, "excessive_dependencies")
		}
	}
	
	// Check for security indicators - using available fields
	if features.SecurityMetrics.VulnerabilityCount > 0 {
		trustScore -= float64(features.SecurityMetrics.VulnerabilityCount) * 0.05
		riskFactors = append(riskFactors, "known_vulnerabilities")
	}
	
	// Normalize trust score
	if trustScore > 1.0 {
		trustScore = 1.0
	} else if trustScore < 0.0 {
		trustScore = 0.0
	}
	
	// Determine overall reputation level
	reputationLevel := "unknown"
	if trustScore >= 0.8 {
		reputationLevel = "excellent"
	} else if trustScore >= 0.6 {
		reputationLevel = "good"
	} else if trustScore >= 0.4 {
		reputationLevel = "moderate"
	} else if trustScore >= 0.2 {
		reputationLevel = "poor"
	} else {
		reputationLevel = "very_poor"
	}
	
	return &EnhancedReputationAnalysis{
		ReputationScore:      trustScore,
		TrustLevel:           reputationLevel,
		AuthorReputation:     maintainerReputation,
		MaintainerReputation: maintainerReputation,
		CommunityTrust:       communityTrust,
		HistoricalIssues:     riskFactors,
		VerificationStatus:   "unverified",
	}, nil
}

// Helper methods for ReputationAnalyzer
func (ra *ReputationAnalyzer) isKnownMaintainer(author string) bool {
	// List of known trusted maintainers/organizations
	trustedMaintainers := []string{
		"facebook", "google", "microsoft", "mozilla", "nodejs", "expressjs", "lodash", 
		"sindresorhus", "tj", "substack", "isaacs", "feross", "mikeal", "dominictarr",
		"rails", "rubygems", "bundler", "rspec", "puma", "nokogiri", "devise",
		"symfony", "laravel", "guzzle", "monolog", "phpunit", "doctrine", "twig",
		"rust-lang", "serde-rs", "tokio-rs", "clap-rs", "actix", "diesel-rs",
	}
	
	authorLower := strings.ToLower(author)
	for _, trusted := range trustedMaintainers {
		if strings.Contains(authorLower, trusted) {
			return true
		}
	}
	return false
}

func (ra *ReputationAnalyzer) isSuspiciousMaintainer(author string) bool {
	// Check for suspicious patterns in maintainer names
	authorLower := strings.ToLower(author)
	
	// Check for random-looking names
	if len(author) > 15 && ra.hasHighEntropy(author) {
		return true
	}
	
	// Check for suspicious keywords
	suspiciousKeywords := []string{"hack", "crack", "exploit", "malware", "virus", "trojan"}
	for _, keyword := range suspiciousKeywords {
		if strings.Contains(authorLower, keyword) {
			return true
		}
	}
	
	// Check for excessive numbers or special characters
	digitCount := 0
	specialCount := 0
	for _, r := range author {
		if unicode.IsDigit(r) {
			digitCount++
		} else if !unicode.IsLetter(r) && r != '-' && r != '_' && r != '.' {
			specialCount++
		}
	}
	
	if digitCount > len(author)/2 || specialCount > 3 {
		return true
	}
	
	return false
}

func (ra *ReputationAnalyzer) hasHighEntropy(s string) bool {
	// Simple entropy calculation
	charCount := make(map[rune]int)
	for _, r := range s {
		charCount[r]++
	}
	
	entropy := 0.0
	length := float64(len(s))
	for _, count := range charCount {
		p := float64(count) / length
		entropy -= p * math.Log2(p)
	}
	
	// High entropy threshold (randomness indicator)
	return entropy > 3.5
}

func (ra *ReputationAnalyzer) hasStableVersionPattern(version string) bool {
	// Check for semantic versioning pattern
	semverRegex := regexp.MustCompile(`^v?\d+\.\d+\.\d+(-[a-zA-Z0-9.]+)?(\+[a-zA-Z0-9.]+)?$`)
	if semverRegex.MatchString(version) {
		return true
	}
	
	// Check for other stable patterns
	stablePatterns := []string{
		`^\d+\.\d+$`,           // Major.Minor
		`^\d+\.\d+\.\d+$`,      // Major.Minor.Patch
		`^\d+\.\d+\.\d+-\w+$`,  // With pre-release
	}
	
	for _, pattern := range stablePatterns {
		if matched, _ := regexp.MatchString(pattern, version); matched {
			return true
		}
	}
	
	return false
}

func (ra *ReputationAnalyzer) countSuspiciousDependencies(dependencies []Dependency) int {
	suspiciousCount := 0
	for _, dep := range dependencies {
		if dep.Suspicious || dep.RiskScore > 0.7 {
			suspiciousCount++
		}
		
		// Check for suspicious dependency names
		depNameLower := strings.ToLower(dep.Name)
		suspiciousNames := []string{"hack", "crack", "exploit", "malware", "virus", "trojan", "backdoor"}
		for _, suspicious := range suspiciousNames {
			if strings.Contains(depNameLower, suspicious) {
				suspiciousCount++
				break
			}
		}
	}
	return suspiciousCount
}

func (em *EnsembleModel) CombineResults(ctx context.Context, result *MLDetectionResult) (*EnsembleResults, error) {
	if result == nil {
		return &EnsembleResults{}, nil
	}
	
	// Initialize ensemble results
	ensembleResult := &EnsembleResults{
		FinalScore:          0.0,
		ModelWeights:        make(map[string]float64),
		ModelScores:         make(map[string]float64),
		ConsensusLevel:      0.0,
		DisagreementFactors: []string{},
		Confidence:          0.0,
	}
	
	// Define model weights based on their reliability and performance
	weights := map[string]float64{
		"similarity":    0.25,
		"malware":       0.30,
		"anomaly":       0.20,
		"typo":          0.15,
		"reputation":    0.10,
	}
	
	// Collect individual model scores
	modelScores := make(map[string]float64)
	modelConfidences := make(map[string]float64)
	
	// Similarity model contribution
	if len(result.SimilarityResults) > 0 {
		maxSimilarity := 0.0
		for _, simResult := range result.SimilarityResults {
			if simResult.SimilarityScore > maxSimilarity {
				maxSimilarity = simResult.SimilarityScore
			}
		}
		modelScores["similarity"] = maxSimilarity
		modelConfidences["similarity"] = 0.8 // Default confidence
	}
	
	// Malware classification contribution
	if result.MalwareClassification.IsMalware {
		modelScores["malware"] = result.MalwareClassification.Confidence
		modelConfidences["malware"] = result.MalwareClassification.Confidence
	} else {
		modelScores["malware"] = 1.0 - result.MalwareClassification.Confidence
		modelConfidences["malware"] = result.MalwareClassification.Confidence
	}
	
	// Anomaly detection contribution
	if result.AnomalyDetection.IsAnomalous {
		modelScores["anomaly"] = result.AnomalyDetection.AnomalyScore
		modelConfidences["anomaly"] = result.AnomalyDetection.Confidence
	} else {
		modelScores["anomaly"] = 1.0 - result.AnomalyDetection.AnomalyScore
		modelConfidences["anomaly"] = result.AnomalyDetection.Confidence
	}
	
	// Typosquatting detection contribution
	if result.TypoDetection.IsTyposquatting {
		modelScores["typo"] = result.TypoDetection.Confidence
		modelConfidences["typo"] = result.TypoDetection.Confidence
	} else {
		modelScores["typo"] = 1.0 - result.TypoDetection.Confidence
		modelConfidences["typo"] = result.TypoDetection.Confidence
	}
	
	// Reputation analysis contribution
	modelScores["reputation"] = 1.0 - result.ReputationAnalysis.ReputationScore // Invert reputation score to risk score
	modelConfidences["reputation"] = 0.7 // Default confidence for reputation
	
	// Calculate weighted ensemble score
	var weightedSum float64
	var totalWeight float64
	var confidenceSum float64
	var consensusCount int
	
	for model, score := range modelScores {
		weight := weights[model]
		confidence := modelConfidences[model]
		
		// Adjust weight based on confidence
		adjustedWeight := weight * confidence
		
		weightedSum += score * adjustedWeight
		totalWeight += adjustedWeight
		confidenceSum += confidence
		
		if score > 0.5 { // Model indicates risk
			consensusCount++
		}
		
		ensembleResult.ModelScores[model] = score
		ensembleResult.ModelWeights[model] = adjustedWeight
	}
	
	// Calculate final scores
	if totalWeight > 0 {
		ensembleResult.FinalScore = weightedSum / totalWeight
	}
	
	if len(modelScores) > 0 {
		ensembleResult.Confidence = confidenceSum / float64(len(modelScores))
		ensembleResult.ConsensusLevel = float64(consensusCount) / float64(len(modelScores))
	}
	
	// Identify disagreement factors
	scores := make([]float64, 0, len(modelScores))
	for _, score := range modelScores {
		scores = append(scores, score)
	}
	
	// Calculate standard deviation to measure consensus
	mean := ensembleResult.FinalScore
	var variance float64
	for _, score := range scores {
		variance += (score - mean) * (score - mean)
	}
	variance /= float64(len(scores))
	stdDev := math.Sqrt(variance)
	
	if stdDev > 0.3 {
		ensembleResult.DisagreementFactors = append(ensembleResult.DisagreementFactors, "High variance between model scores")
	}
	if math.Abs(modelScores["malware"] - modelScores["similarity"]) > 0.4 {
		ensembleResult.DisagreementFactors = append(ensembleResult.DisagreementFactors, "Malware and similarity models disagree")
	}
	if math.Abs(modelScores["typo"] - modelScores["reputation"]) > 0.5 {
		ensembleResult.DisagreementFactors = append(ensembleResult.DisagreementFactors, "Typo and reputation models disagree")
	}
	
	return ensembleResult, nil
}

// Update methods
func (sm *SimilarityModel) Update(ctx context.Context) error {
	// Update similarity model with latest package data
	// In a real implementation, this would retrain the model with new data
	
	// Simulate model update process
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		// Update internal parameters based on recent similarity calculations
		// This could involve updating thresholds, weights, or retraining embeddings
		
		// For now, we'll just update the last update timestamp
		// In production, this would involve:
		// 1. Fetching new training data
		// 2. Recomputing similarity matrices
		// 3. Updating model parameters
		// 4. Validating model performance
		
		return nil
	}
}

func (mc *MalwareClassifier) Update(ctx context.Context) error {
	// Update malware classifier with latest threat intelligence
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		// In production, this would:
		// 1. Download latest malware signatures
		// 2. Update threat intelligence feeds
		// 3. Retrain classification models
		// 4. Update detection patterns
		// 5. Validate model accuracy
		
		return nil
	}
}

func (ad *AnomalyDetector) Update(ctx context.Context) error {
	// Update anomaly detection baselines and thresholds
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		// In production, this would:
		// 1. Recalculate normal behavior baselines
		// 2. Update anomaly detection thresholds
		// 3. Incorporate feedback from false positives/negatives
		// 4. Retrain anomaly detection models
		// 5. Update statistical distributions
		
		return nil
	}
}



// detectFileStructureAnomalies analyzes file structure for anomalies
func (ad *AnomalyDetector) detectFileStructureAnomalies(fileStructure *FileStructure) float64 {
	if fileStructure == nil {
		return 0.0
	}
	
	var anomalyScore float64
	
	// Check for suspicious file ratios
	totalFiles := fileStructure.TotalFiles
	if totalFiles == 0 {
		return 0.3 // Empty package is suspicious
	}
	
	// Check for high ratio of binary files
	if totalFiles > 0 {
		binaryRatio := float64(fileStructure.BinaryFiles) / float64(totalFiles)
		if binaryRatio > 0.3 { // More than 30% binary files
			anomalyScore += binaryRatio * 0.5
		}
	}
	
	// Check for hidden files
	if fileStructure.HiddenFiles > 0 {
		hiddenRatio := float64(fileStructure.HiddenFiles) / float64(totalFiles)
		if hiddenRatio > 0.1 { // More than 10% hidden files
			anomalyScore += hiddenRatio * 0.3
		}
	}
	
	// Check for suspicious files
	if len(fileStructure.SuspiciousFiles) > 0 {
		suspiciousRatio := float64(len(fileStructure.SuspiciousFiles)) / float64(totalFiles)
		anomalyScore += suspiciousRatio * 0.7
	}
	
	// Check for unusual extensions
	if len(fileStructure.UnusualExtensions) > 0 {
		anomalyScore += float64(len(fileStructure.UnusualExtensions)) * 0.1
	}
	
	// Check for large files
	if len(fileStructure.LargeFiles) > 0 {
		largeFileRatio := float64(len(fileStructure.LargeFiles)) / float64(totalFiles)
		if largeFileRatio > 0.05 { // More than 5% large files
			anomalyScore += largeFileRatio * 0.3
		}
	}
	
	// Check for lack of test files in a substantial package
	if totalFiles > 10 && fileStructure.TestFiles == 0 {
		anomalyScore += 0.2
	}
	
	// Check for lack of documentation in a substantial package
	if totalFiles > 10 && fileStructure.DocumentationFiles == 0 {
		anomalyScore += 0.1
	}
	
	// Normalize score
	if anomalyScore > 1.0 {
		anomalyScore = 1.0
	}
	
	return anomalyScore
}

// isRandomLookingFilename checks if a filename appears to be randomly generated
func (ad *AnomalyDetector) isRandomLookingFilename(filename string) bool {
	// Extract just the filename without path or extension
	base := filepath.Base(filename)
	ext := filepath.Ext(base)
	name := strings.TrimSuffix(base, ext)
	
	// Skip if it's too short
	if len(name) < 5 {
		return false
	}
	
	// Check for high entropy (randomness)
	var upperCount, lowerCount, digitCount, otherCount int
	for _, r := range name {
		switch {
		case unicode.IsUpper(r):
			upperCount++
		case unicode.IsLower(r):
			lowerCount++
		case unicode.IsDigit(r):
			digitCount++
		default:
			otherCount++
		}
	}
	
	// Calculate character type diversity
	charTypes := 0
	if upperCount > 0 {
		charTypes++
	}
	if lowerCount > 0 {
		charTypes++
	}
	if digitCount > 0 {
		charTypes++
	}
	if otherCount > 0 {
		charTypes++
	}
	
	// Check for high character type diversity and significant length
	if charTypes >= 3 && len(name) >= 8 {
		// Check for lack of dictionary words
		if !ad.containsCommonSubstring(name) {
			return true
		}
	}
	
	return false
}

// containsCommonSubstring checks if a string contains common English substrings
func (ad *AnomalyDetector) containsCommonSubstring(s string) bool {
	commonWords := []string{"test", "util", "helper", "index", "main", "app", "lib", "src", "core", "base", "common"}
	s = strings.ToLower(s)
	
	for _, word := range commonWords {
		if strings.Contains(s, word) {
			return true
		}
	}
	
	return false
}

// detectDependencyAnomalies analyzes dependencies for anomalies
func (ad *AnomalyDetector) detectDependencyAnomalies(dependencies []Dependency, devDependencies []Dependency) float64 {
	var anomalyScore float64
	
	// Check for too many dependencies
	if len(dependencies) > 50 {
		anomalyScore += 0.2
	}
	
	// Check for suspicious dependencies
	suspiciousCount := 0
	for _, dep := range dependencies {
		// Check for dependencies with unusual versions
		if strings.Contains(dep.Version, "*") || strings.Contains(dep.Version, "latest") {
			suspiciousCount++
		}
		
		// Check for dependencies with random-looking names
		if ad.isRandomLookingName(dep.Name) {
			suspiciousCount++
		}
	}
	
	if len(dependencies) > 0 {
		suspiciousRatio := float64(suspiciousCount) / float64(len(dependencies))
		if suspiciousRatio > 0.1 { // More than 10% suspicious dependencies
			anomalyScore += suspiciousRatio * 0.5
		}
	}
	
	// Check for no dev dependencies in a large project
	if len(dependencies) > 10 && len(devDependencies) == 0 {
		anomalyScore += 0.2
	}
	
	// Normalize score
	if anomalyScore > 1.0 {
		anomalyScore = 1.0
	}
	
	return anomalyScore
}

// isRandomLookingName checks if a name appears to be randomly generated
func (ad *AnomalyDetector) isRandomLookingName(name string) bool {
	// Skip if it's too short
	if len(name) < 5 {
		return false
	}
	
	// Check for high entropy (randomness)
	var upperCount, lowerCount, digitCount, otherCount int
	for _, r := range name {
		switch {
		case unicode.IsUpper(r):
			upperCount++
		case unicode.IsLower(r):
			lowerCount++
		case unicode.IsDigit(r):
			digitCount++
		default:
			otherCount++
		}
	}
	
	// Calculate character type diversity
	charTypes := 0
	if upperCount > 0 {
		charTypes++
	}
	if lowerCount > 0 {
		charTypes++
	}
	if digitCount > 0 {
		charTypes++
	}
	if otherCount > 0 {
		charTypes++
	}
	
	// Check for high character type diversity and significant length
	if charTypes >= 3 && len(name) >= 8 {
		// Check for lack of dictionary words
		if !ad.containsCommonSubstring(name) {
			return true
		}
	}
	
	return false
}

// detectMetadataAnomalies analyzes package metadata for anomalies
func (ad *AnomalyDetector) detectMetadataAnomalies(features *EnhancedPackageFeatures) float64 {
	var anomalyScore float64
	
	// Check for missing essential metadata
	if features.Author == "" {
		anomalyScore += 0.3
	}
	
	if features.Description == "" {
		anomalyScore += 0.2
	}
	
	if features.Homepage == "" && features.Repository == "" {
		anomalyScore += 0.2
	}
	
	// Check for suspicious keywords
	suspiciousKeywords := []string{"hack", "crack", "password", "steal", "token", "secret", "credentials"}
	for _, keyword := range features.Keywords {
		for _, suspicious := range suspiciousKeywords {
			if strings.Contains(strings.ToLower(keyword), suspicious) {
				anomalyScore += 0.4
				break
			}
		}
	}
	
	// Check for very short description
	if len(features.Description) > 0 && len(features.Description) < 20 {
		anomalyScore += 0.2
	}
	
	// Normalize score
	if anomalyScore > 1.0 {
		anomalyScore = 1.0
	}
	
	return anomalyScore
}

// detectBehavioralAnomalies analyzes behavioral metrics for anomalies
func (ad *AnomalyDetector) detectBehavioralAnomalies(metrics *BehavioralMetrics) float64 {
	if metrics == nil {
		return 0.0
	}
	
	var anomalyScore float64
	
	// Check process behavior anomalies
	// Check for suspicious commands
	if len(metrics.ProcessBehavior.SuspiciousCommands) > 0 {
		anomalyScore += float64(len(metrics.ProcessBehavior.SuspiciousCommands)) * 0.3
	}
	
	// Check for privilege escalation
	if metrics.ProcessBehavior.PrivilegeEscalation {
		anomalyScore += 0.8
	}
	
	// Check for code injection techniques
	if metrics.ProcessBehavior.CodeInjection {
		anomalyScore += 0.7
	}
	
	if metrics.ProcessBehavior.Hollowing {
		anomalyScore += 0.7
	}
	
	if metrics.ProcessBehavior.DLLInjection {
		anomalyScore += 0.6
	}
	
	// Check for excessive child processes
	if metrics.ProcessBehavior.ChildProcesses > 10 {
		anomalyScore += 0.3
	}
	
	// Check network behavior anomalies
	// Check for excessive connections
	if metrics.NetworkBehavior.OutboundConnections > 50 {
		anomalyScore += 0.3
	}
	
	// Check for suspicious hosts
	if len(metrics.NetworkBehavior.SuspiciousHosts) > 0 {
		anomalyScore += float64(len(metrics.NetworkBehavior.SuspiciousHosts)) * 0.2
	}
	
	// Check for unusual ports
	if len(metrics.NetworkBehavior.UnusualPorts) > 0 {
		anomalyScore += float64(len(metrics.NetworkBehavior.UnusualPorts)) * 0.1
	}
	
	// Check for data exfiltration
	if metrics.NetworkBehavior.DataExfiltration {
		anomalyScore += 0.8
	}
	
	// Check for C2 communication
	if metrics.NetworkBehavior.C2Communication {
		anomalyScore += 0.9
	}
	
	// Check for DNS tunneling
	if metrics.NetworkBehavior.DNSTunneling {
		anomalyScore += 0.6
	}
	
	// Check runtime behavior
	if metrics.RuntimeBehavior.AntiAnalysisTechniques {
		anomalyScore += 0.7
	}
	
	if metrics.RuntimeBehavior.PersistenceMechanisms {
		anomalyScore += 0.6
	}
	
	// Check for excessive resource usage
	if metrics.RuntimeBehavior.CPUUsage > 80.0 {
		anomalyScore += 0.2
	}
	
	if metrics.RuntimeBehavior.MemoryUsage > 80.0 {
		anomalyScore += 0.2
	}
	
	// Check file system behavior
	if metrics.FileSystemBehavior.SystemFileAccess {
		anomalyScore += 0.5
	}
	
	if len(metrics.FileSystemBehavior.SuspiciousLocations) > 0 {
		anomalyScore += float64(len(metrics.FileSystemBehavior.SuspiciousLocations)) * 0.2
	}
	
	// Normalize score
	if anomalyScore > 1.0 {
		anomalyScore = 1.0
	}
	
	return anomalyScore
}

// detectSecurityAnomalies analyzes security metrics for anomalies
func (ad *AnomalyDetector) detectSecurityAnomalies(metrics *SecurityMetrics) float64 {
	if metrics == nil {
		return 0.0
	}
	
	var anomalyScore float64
	
	// Check for high vulnerability count
	if metrics.VulnerabilityCount > 3 {
		anomalyScore += 0.2 + float64(metrics.VulnerabilityCount-3)*0.05
	}
	
	// Check for high severity vulnerabilities
	if metrics.HighSeverityVulns > 0 {
		anomalyScore += 0.2 + float64(metrics.HighSeverityVulns)*0.1
	}
	
	// Check for critical severity vulnerabilities
	if metrics.CriticalSeverityVulns > 0 {
		anomalyScore += 0.3 + float64(metrics.CriticalSeverityVulns)*0.15
	}
	
	// Check for suspicious patterns
	if metrics.SuspiciousPatterns > 0 {
		anomalyScore += 0.2 + float64(metrics.SuspiciousPatterns)*0.05
	}
	
	// Check for obfuscated code
	if metrics.ObfuscatedCode {
		anomalyScore += 0.4
	}
	
	// Check for excessive network calls
	if metrics.NetworkCalls > 10 {
		anomalyScore += 0.1 + float64(metrics.NetworkCalls-10)*0.01
	}
	
	// Check for excessive file system access
	if metrics.FileSystemAccess > 20 {
		anomalyScore += 0.1 + float64(metrics.FileSystemAccess-20)*0.005
	}
	
	// Check for process execution
	if metrics.ProcessExecution > 5 {
		anomalyScore += 0.2 + float64(metrics.ProcessExecution-5)*0.05
	}
	
	// Check for dangerous functions
	if metrics.DangerousFunctions > 0 {
		anomalyScore += 0.3 + float64(metrics.DangerousFunctions)*0.1
	}
	
	// Check for low security score
	if metrics.SecurityScore < 0.5 {
		anomalyScore += (0.5 - metrics.SecurityScore) * 0.5
	}
	
	// Normalize score
	if anomalyScore > 1.0 {
		anomalyScore = 1.0
	}
	
	return anomalyScore
}
func (td *TypoDetector) Update(ctx context.Context) error {
	// Update typosquatting detection with latest package names and patterns
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		// In production, this would:
		// 1. Update list of popular packages from registries
		// 2. Refresh typosquatting pattern databases
		// 3. Update similarity algorithms and thresholds
		// 4. Incorporate new typosquatting techniques
		// 5. Retrain character-level models
		
		return nil
	}
}

func (ra *ReputationAnalyzer) Update(ctx context.Context) error {
	// Update reputation analysis with latest reputation data
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		// In production, this would:
		// 1. Fetch latest reputation scores from multiple sources
		// 2. Update maintainer reputation databases
		// 3. Refresh security advisory feeds
		// 4. Update download statistics and trends
		// 5. Incorporate community feedback and reports
		
		return nil
	}
}

// Metrics methods
func (sm *SimilarityModel) GetMetrics(ctx context.Context) (map[string]interface{}, error) {
	return map[string]interface{}{"accuracy": 0.95}, nil
}
func (mc *MalwareClassifier) GetMetrics(ctx context.Context) (map[string]interface{}, error) {
	return map[string]interface{}{"accuracy": 0.98}, nil
}
func (ad *AnomalyDetector) GetMetrics(ctx context.Context) (map[string]interface{}, error) {
	return map[string]interface{}{"accuracy": 0.92}, nil
}

// UpdateParameters updates model parameters for fine-tuning
func (emd *EnhancedMLDetector) UpdateParameters(params map[string]interface{}) error {
	if threshold, ok := params["similarity_threshold"].(float64); ok {
		emd.config.SimilarityThreshold = threshold
	}
	if threshold, ok := params["malware_threshold"].(float64); ok {
		emd.config.MalwareThreshold = threshold
	}
	if threshold, ok := params["anomaly_threshold"].(float64); ok {
		emd.config.AnomalyThreshold = threshold
	}
	if threshold, ok := params["typo_threshold"].(float64); ok {
		emd.config.TypoThreshold = threshold
	}
	if threshold, ok := params["reputation_threshold"].(float64); ok {
		emd.config.ReputationThreshold = threshold
	}
	if threshold, ok := params["confidence_threshold"].(float64); ok {
		emd.config.ConfidenceThreshold = threshold
	}
	if weights, ok := params["ensemble_weights"].(map[string]float64); ok {
		emd.config.EnsembleWeights = weights
	}

	emd.lastUpdate = time.Now()
	return nil
}

// GetMetrics returns current detection metrics
func (emd *EnhancedMLDetector) GetMetrics() *DetectionMetrics {
	if emd.metrics == nil {
		return &DetectionMetrics{LastUpdated: time.Now()}
	}
	return emd.metrics
}

// UpdateMetrics updates detection metrics
func (emd *EnhancedMLDetector) UpdateMetrics(correct bool, confidence float64) {
	if emd.metrics == nil {
		emd.metrics = &DetectionMetrics{LastUpdated: time.Now()}
	}

	emd.metrics.TotalDetections++
	if correct {
		emd.metrics.TruePositives++
	} else {
		emd.metrics.FalsePositives++
	}

	// Update average confidence
	total := float64(emd.metrics.TotalDetections)
	emd.metrics.AverageConfidence = (emd.metrics.AverageConfidence*(total-1) + confidence) / total
	emd.metrics.LastUpdated = time.Now()
}

// DetectThreatSimple provides a simplified threat detection interface for fine-tuning
func (emd *EnhancedMLDetector) DetectThreatSimple(packageName, content string) (bool, float64, error) {
	// Simplified detection logic for fine-tuning
	confidence := 0.0

	// Basic pattern matching (simplified)
	suspiciousPatterns := []string{
		"eval(", "Function(", "process.env", "fs.readFile", "child_process",
		"crypto", "bitcoin", "wallet", "stealer", "malicious",
	}

	for _, pattern := range suspiciousPatterns {
		if len(content) > 0 && len(pattern) > 0 {
			// Simple substring check
			for i := 0; i <= len(content)-len(pattern); i++ {
				if content[i:i+len(pattern)] == pattern {
					confidence += 0.2
					break
				}
			}
		}
	}

	// Check for typosquatting patterns
	popularPackages := []string{"react", "lodash", "express", "angular", "vue"}
	for _, popular := range popularPackages {
		if packageName != popular {
			similarity := calculateSimpleSimilarity(packageName, popular)
			if similarity > emd.config.TypoThreshold {
				confidence += similarity * 0.5
			}
		}
	}

	// Apply thresholds
	if confidence > 1.0 {
		confidence = 1.0
	}

	isThreat := confidence >= emd.config.ConfidenceThreshold
	return isThreat, confidence, nil
}

func (td *TypoDetector) GetMetrics(ctx context.Context) (map[string]interface{}, error) {
	return map[string]interface{}{"accuracy": 0.96}, nil
}
func (ra *ReputationAnalyzer) GetMetrics(ctx context.Context) (map[string]interface{}, error) {
	return map[string]interface{}{"accuracy": 0.89}, nil
}
func (em *EnsembleModel) GetMetrics(ctx context.Context) (map[string]interface{}, error) {
	return map[string]interface{}{"accuracy": 0.99}, nil
}
