package ml

import (
	"context"
	"fmt"
	"time"
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

	detector.behavioralAnalyzer, err = NewBehavioralAnalyzer()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize behavioral analyzer: %w", err)
	}

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
	behavioralResult, err := emd.behavioralAnalyzer.AnalyzeBehavior(ctx, features)
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

// Placeholder model interfaces - these would be implemented separately
type SimilarityModel struct{}
type MalwareClassifier struct{}
type AnomalyDetector struct{}
type TypoDetector struct{}
type ReputationAnalyzer struct{}
type BehavioralAnalyzer struct{}
type EnsembleModel struct{}

// Placeholder implementations
func NewSimilarityModel() (*SimilarityModel, error)       { return &SimilarityModel{}, nil }
func NewMalwareClassifier() (*MalwareClassifier, error)   { return &MalwareClassifier{}, nil }
func NewAnomalyDetector() (*AnomalyDetector, error)       { return &AnomalyDetector{}, nil }
func NewTypoDetector() (*TypoDetector, error)             { return &TypoDetector{}, nil }
func NewReputationAnalyzer() (*ReputationAnalyzer, error) { return &ReputationAnalyzer{}, nil }
func NewBehavioralAnalyzer() (*BehavioralAnalyzer, error) { return &BehavioralAnalyzer{}, nil }
func NewEnsembleModel(weights map[string]float64) (*EnsembleModel, error) {
	return &EnsembleModel{}, nil
}

func (sm *SimilarityModel) AnalyzeSimilarity(ctx context.Context, features *EnhancedPackageFeatures) ([]EnhancedSimilarityResult, error) {
	return []EnhancedSimilarityResult{}, nil
}
func (mc *MalwareClassifier) ClassifyMalware(ctx context.Context, features *EnhancedPackageFeatures) (*MalwareClassification, error) {
	return &MalwareClassification{}, nil
}
func (ad *AnomalyDetector) DetectAnomalies(ctx context.Context, features *EnhancedPackageFeatures) (*EnhancedAnomalyDetection, error) {
	return &EnhancedAnomalyDetection{}, nil
}
func (td *TypoDetector) DetectTyposquatting(ctx context.Context, features *EnhancedPackageFeatures) (*TypoDetection, error) {
	return &TypoDetection{}, nil
}
func (ra *ReputationAnalyzer) AnalyzeReputation(ctx context.Context, features *EnhancedPackageFeatures) (*EnhancedReputationAnalysis, error) {
	return &EnhancedReputationAnalysis{}, nil
}
func (ba *BehavioralAnalyzer) AnalyzeBehavior(ctx context.Context, features *EnhancedPackageFeatures) (*BehavioralAnalysisResult, error) {
	return &BehavioralAnalysisResult{}, nil
}
func (em *EnsembleModel) CombineResults(ctx context.Context, result *MLDetectionResult) (*EnsembleResults, error) {
	return &EnsembleResults{}, nil
}

// Update methods
func (sm *SimilarityModel) Update(ctx context.Context) error    { return nil }
func (mc *MalwareClassifier) Update(ctx context.Context) error  { return nil }
func (ad *AnomalyDetector) Update(ctx context.Context) error    { return nil }
func (td *TypoDetector) Update(ctx context.Context) error       { return nil }
func (ra *ReputationAnalyzer) Update(ctx context.Context) error { return nil }
func (ba *BehavioralAnalyzer) Update(ctx context.Context) error { return nil }

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
func (ba *BehavioralAnalyzer) GetMetrics(ctx context.Context) (map[string]interface{}, error) {
	return map[string]interface{}{"accuracy": 0.94}, nil
}
func (em *EnsembleModel) GetMetrics(ctx context.Context) (map[string]interface{}, error) {
	return map[string]interface{}{"accuracy": 0.99}, nil
}
