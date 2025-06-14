package ml

import (
	"context"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/typosentinel/typosentinel/internal/config"
	"github.com/typosentinel/typosentinel/pkg/types"
)

// MLAnalyzer performs machine learning-based analysis for typosquatting detection.
type MLAnalyzer struct {
	Config config.MLAnalysisConfig
}

// Config holds the configuration for the ML analyzer.
type Config struct {
	Enabled              bool    `mapstructure:"enabled"`
	SimilarityThreshold  float64 `mapstructure:"similarity_threshold"`
	MaliciousThreshold   float64 `mapstructure:"malicious_threshold"`
	ReputationThreshold  float64 `mapstructure:"reputation_threshold"`
	ModelPath            string  `mapstructure:"model_path"`
	BatchSize            int     `mapstructure:"batch_size"`
	MaxFeatures          int     `mapstructure:"max_features"`
	CacheEmbeddings      bool    `mapstructure:"cache_embeddings"`
	ParallelProcessing   bool    `mapstructure:"parallel_processing"`
	GPUAcceleration      bool    `mapstructure:"gpu_acceleration"`
}

// AnalysisResult holds the results of the ML analysis.
type AnalysisResult struct {
	SimilarityScore     float64                `json:"similarity_score"`
	MaliciousScore      float64                `json:"malicious_score"`
	ReputationScore     float64                `json:"reputation_score"`
	TyposquattingScore  float64                `json:"typosquatting_score"`
	Features            map[string]float64     `json:"features"`
	Predictions         []Prediction           `json:"predictions"`
	SimilarPackages     []SimilarPackage       `json:"similar_packages"`
	AnomalyDetection    AnomalyDetection       `json:"anomaly_detection"`
	ReputationAnalysis  ReputationAnalysis     `json:"reputation_analysis"`
	BehavioralAnalysis  BehavioralAnalysis     `json:"behavioral_analysis"`
	RiskAssessment      RiskAssessment         `json:"risk_assessment"`
	Findings            []Finding              `json:"findings"`
	Recommendations     []string               `json:"recommendations"`
	Metadata            AnalysisMetadata       `json:"metadata"`
}

// Prediction represents a model prediction.
type Prediction struct {
	Model       string  `json:"model"`
	Probability float64 `json:"probability"`
	Label       string  `json:"label"`
	Confidence  float64 `json:"confidence"`
}

// SimilarPackage represents a package similar to the analyzed one.
type SimilarPackage struct {
	Name           string  `json:"name"`
	Similarity     float64 `json:"similarity"`
	Distance       int     `json:"distance"`
	Algorithm      string  `json:"algorithm"`
	Registry       string  `json:"registry"`
	Downloads      int64   `json:"downloads"`
	LastUpdated    string  `json:"last_updated"`
	Maintainer     string  `json:"maintainer"`
	SuspiciousFlag bool    `json:"suspicious_flag"`
}

// AnomalyDetection holds anomaly detection results.
type AnomalyDetection struct {
	IsAnomaly       bool               `json:"is_anomaly"`
	AnomalyScore    float64            `json:"anomaly_score"`
	AnomalyType     string             `json:"anomaly_type"`
	AnomalyFeatures []string           `json:"anomaly_features"`
	OutlierAnalysis OutlierAnalysis    `json:"outlier_analysis"`
	PatternAnalysis PatternAnalysis    `json:"pattern_analysis"`
}

// OutlierAnalysis holds outlier detection results.
type OutlierAnalysis struct {
	IsOutlier        bool    `json:"is_outlier"`
	OutlierScore     float64 `json:"outlier_score"`
	IsolationForest  float64 `json:"isolation_forest"`
	LocalOutlier     float64 `json:"local_outlier"`
	OneClassSVM      float64 `json:"one_class_svm"`
}

// PatternAnalysis holds pattern analysis results.
type PatternAnalysis struct {
	UnusualPatterns []string `json:"unusual_patterns"`
	PatternScore    float64  `json:"pattern_score"`
	FrequencyScore  float64  `json:"frequency_score"`
	SequenceScore   float64  `json:"sequence_score"`
}

// ReputationAnalysis holds reputation analysis results.
type ReputationAnalysis struct {
	OverallScore      float64            `json:"overall_score"`
	MaintainerScore   float64            `json:"maintainer_score"`
	DownloadScore     float64            `json:"download_score"`
	AgeScore          float64            `json:"age_score"`
	CommunityScore    float64            `json:"community_score"`
	SecurityScore     float64            `json:"security_score"`
	ReputationSources []ReputationSource `json:"reputation_sources"`
}

// ReputationSource represents a source of reputation information.
type ReputationSource struct {
	Source string  `json:"source"`
	Score  float64 `json:"score"`
	Weight float64 `json:"weight"`
}

// BehavioralAnalysis holds behavioral analysis results.
type BehavioralAnalysis struct {
	InstallBehavior   InstallBehavior   `json:"install_behavior"`
	RuntimeBehavior   RuntimeBehavior   `json:"runtime_behavior"`
	NetworkBehavior   NetworkBehavior   `json:"network_behavior"`
	FileSystemBehavior FileSystemBehavior `json:"filesystem_behavior"`
}

// InstallBehavior holds install-time behavior analysis.
type InstallBehavior struct {
	SuspiciousCommands []string `json:"suspicious_commands"`
	NetworkRequests    []string `json:"network_requests"`
	FileModifications  []string `json:"file_modifications"`
	PermissionChanges  []string `json:"permission_changes"`
}

// RuntimeBehavior holds runtime behavior analysis.
type RuntimeBehavior struct {
	ProcessSpawning   []string `json:"process_spawning"`
	SystemCalls       []string `json:"system_calls"`
	ResourceUsage     []string `json:"resource_usage"`
	EnvironmentAccess []string `json:"environment_access"`
}

// NetworkBehavior holds network behavior analysis.
type NetworkBehavior struct {
	OutboundConnections []string `json:"outbound_connections"`
	DNSQueries          []string `json:"dns_queries"`
	DataExfiltration    []string `json:"data_exfiltration"`
	C2Communication     []string `json:"c2_communication"`
}

// FileSystemBehavior holds file system behavior analysis.
type FileSystemBehavior struct {
	FileCreation     []string `json:"file_creation"`
	FileDeletion     []string `json:"file_deletion"`
	FileModification []string `json:"file_modification"`
	DirectoryAccess  []string `json:"directory_access"`
}

// RiskAssessment holds overall risk assessment.
type RiskAssessment struct {
	OverallRisk    string             `json:"overall_risk"`
	RiskScore      float64            `json:"risk_score"`
	RiskFactors    []RiskFactor       `json:"risk_factors"`
	Mitigations    []string           `json:"mitigations"`
	ConfidenceLevel float64           `json:"confidence_level"`
}

// RiskFactor represents a specific risk factor.
type RiskFactor struct {
	Factor      string  `json:"factor"`
	Severity    string  `json:"severity"`
	Score       float64 `json:"score"`
	Description string  `json:"description"`
}

// Finding represents a specific ML finding.
type Finding struct {
	Type        string  `json:"type"`
	Severity    string  `json:"severity"`
	Confidence  float64 `json:"confidence"`
	Description string  `json:"description"`
	Evidence    string  `json:"evidence"`
	Model       string  `json:"model"`
}

// AnalysisMetadata holds metadata about the analysis.
type AnalysisMetadata struct {
	AnalysisTime    time.Time `json:"analysis_time"`
	Duration        string    `json:"duration"`
	ModelsUsed      []string  `json:"models_used"`
	FeaturesUsed    []string  `json:"features_used"`
	DatasetVersion  string    `json:"dataset_version"`
	ModelVersion    string    `json:"model_version"`
	AnalysisVersion string    `json:"analysis_version"`
}

// NewMLAnalyzer creates a new instance of the MLAnalyzer.
func NewMLAnalyzer(cfg config.MLAnalysisConfig) *MLAnalyzer {
	return &MLAnalyzer{
		Config: cfg,
	}
}

// DefaultConfig provides a default configuration for the ML analyzer.
func DefaultConfig() config.MLAnalysisConfig {
	return config.MLAnalysisConfig{
		SimilarityThreshold:  0.8,
		MaliciousThreshold:   0.7,
		ReputationThreshold:  0.6,
		ModelPath:            "models/",
		BatchSize:           10,
		MaxFeatures:         1000,
		CacheEmbeddings:     true,
		ParallelProcessing:  true,
		GPUAcceleration:     false,
	}
}

// Analyze performs ML-based analysis on a package.
func (a *MLAnalyzer) Analyze(ctx context.Context, pkg *types.Package) (*AnalysisResult, error) {
	startTime := time.Now()
	
	// Extract features from the package
	features := a.extractFeatures(pkg)
	
	// Perform similarity analysis
	similarityScore := a.calculateSimilarityScore(pkg)
	similarPackages := a.findSimilarPackages(pkg)
	
	// Perform malicious detection
	maliciousScore := a.detectMaliciousPackage(pkg, features)
	
	// Perform reputation analysis
	reputationAnalysis := a.analyzeReputation(pkg)
	
	// Perform anomaly detection
	anomalyDetection := a.detectAnomalies(pkg, features)
	
	// Perform behavioral analysis (placeholder)
	behavioralAnalysis := a.analyzeBehavior(pkg)
	
	// Calculate typosquatting score
	typosquattingScore := a.calculateTyposquattingScore(similarityScore, maliciousScore, reputationAnalysis.OverallScore)
	
	// Generate predictions
	predictions := a.generatePredictions(pkg, features)
	
	// Perform risk assessment
	riskAssessment := a.assessRisk(typosquattingScore, maliciousScore, reputationAnalysis.OverallScore)
	
	// Generate findings
	findings := a.generateFindings(pkg, similarityScore, maliciousScore, reputationAnalysis, anomalyDetection)
	
	// Generate recommendations
	recommendations := a.generateRecommendations(riskAssessment, findings)
	
	// Create metadata
	metadata := AnalysisMetadata{
		AnalysisTime:    startTime,
		Duration:        time.Since(startTime).String(),
		ModelsUsed:      []string{"similarity_model", "malicious_detection_model", "reputation_model"},
		FeaturesUsed:    getFeatureNames(features),
		DatasetVersion:  "1.0.0",
		ModelVersion:    "1.0.0",
		AnalysisVersion: "1.0.0",
	}
	
	return &AnalysisResult{
		SimilarityScore:    similarityScore,
		MaliciousScore:     maliciousScore,
		ReputationScore:    reputationAnalysis.OverallScore,
		TyposquattingScore: typosquattingScore,
		Features:           features,
		Predictions:        predictions,
		SimilarPackages:    similarPackages,
		AnomalyDetection:   anomalyDetection,
		ReputationAnalysis: reputationAnalysis,
		BehavioralAnalysis: behavioralAnalysis,
		RiskAssessment:     riskAssessment,
		Findings:           findings,
		Recommendations:    recommendations,
		Metadata:           metadata,
	}, nil
}

// extractFeatures extracts features from a package for ML analysis.
func (a *MLAnalyzer) extractFeatures(pkg *types.Package) map[string]float64 {
	features := make(map[string]float64)
	
	// Name-based features
	features["name_length"] = float64(len(pkg.Name))
	features["name_entropy"] = calculateEntropy(pkg.Name)
	features["name_vowel_ratio"] = calculateVowelRatio(pkg.Name)
	features["name_digit_ratio"] = calculateDigitRatio(pkg.Name)
	features["name_special_char_ratio"] = calculateSpecialCharRatio(pkg.Name)
	
	// Version-based features
	if pkg.Version != "" {
		features["version_length"] = float64(len(pkg.Version))
		features["version_parts"] = float64(len(strings.Split(pkg.Version, ".")))
	}
	
	// Metadata-based features
	if pkg.Metadata != nil {
		// Description-based features
		if pkg.Metadata.Description != "" {
			features["description_length"] = float64(len(pkg.Metadata.Description))
			features["description_entropy"] = calculateEntropy(pkg.Metadata.Description)
		}
		
		// Author-based features
		if pkg.Metadata.Author != "" {
			features["author_length"] = float64(len(pkg.Metadata.Author))
			features["author_entropy"] = calculateEntropy(pkg.Metadata.Author)
		}
		
		features["has_homepage"] = boolToFloat(pkg.Metadata.Homepage != "")
		features["has_repository"] = boolToFloat(pkg.Metadata.Repository != "")
		features["has_license"] = boolToFloat(pkg.Metadata.License != "")
		features["keyword_count"] = float64(len(pkg.Metadata.Keywords))
		features["downloads"] = float64(pkg.Metadata.Downloads)
		features["file_count"] = float64(pkg.Metadata.FileCount)
		features["size"] = float64(pkg.Metadata.Size)
	} else {
		// Default values when metadata is nil
		features["has_homepage"] = 0.0
		features["has_repository"] = 0.0
		features["has_license"] = 0.0
		features["keyword_count"] = 0.0
		features["downloads"] = 0.0
		features["file_count"] = 0.0
		features["size"] = 0.0
	}
	
	// Dependency-based features (placeholder)
	features["dependency_count"] = 0 // Would be calculated from actual dependencies
	
	return features
}

// calculateSimilarityScore calculates similarity score with known packages.
func (a *MLAnalyzer) calculateSimilarityScore(pkg *types.Package) float64 {
	// Placeholder implementation
	// In a real implementation, this would compare against a database of known packages
	// using various similarity algorithms (Levenshtein, Jaro-Winkler, etc.)
	
	// Simulate similarity calculation
	if strings.Contains(pkg.Name, "test") || strings.Contains(pkg.Name, "demo") {
		return 0.9 // High similarity for test packages
	}
	
	return 0.3 // Default low similarity
}

// findSimilarPackages finds packages similar to the analyzed one.
func (a *MLAnalyzer) findSimilarPackages(pkg *types.Package) []SimilarPackage {
	// Placeholder implementation
	// In a real implementation, this would query a database of packages
	
	similarPackages := []SimilarPackage{
		{
			Name:           "similar-package-1",
			Similarity:     0.85,
			Distance:       2,
			Algorithm:      "levenshtein",
			Registry:       "npm",
			Downloads:      1000000,
			LastUpdated:    "2023-01-01",
			Maintainer:     "trusted-maintainer",
			SuspiciousFlag: false,
		},
	}
	
	return similarPackages
}

// detectMaliciousPackage detects if a package is potentially malicious.
func (a *MLAnalyzer) detectMaliciousPackage(pkg *types.Package, features map[string]float64) float64 {
	// Placeholder implementation
	// In a real implementation, this would use trained ML models
	
	// Simple heuristic-based detection
	score := 0.0
	
	// Check for suspicious patterns in name
	if strings.Contains(pkg.Name, "hack") || strings.Contains(pkg.Name, "exploit") {
		score += 0.5
	}
	
	// Check for suspicious entropy
	if features["name_entropy"] > 4.0 {
		score += 0.3
	}
	
	// Check for suspicious character ratios
	if features["name_special_char_ratio"] > 0.3 {
		score += 0.2
	}
	
	return math.Min(score, 1.0)
}

// analyzeReputation analyzes the reputation of a package.
func (a *MLAnalyzer) analyzeReputation(pkg *types.Package) ReputationAnalysis {
	// Placeholder implementation
	// In a real implementation, this would query various reputation sources
	
	maintainerScore := 0.8 // Assume good maintainer
	downloadScore := 0.7   // Moderate downloads
	ageScore := 0.6        // Relatively new
	communityScore := 0.5  // Limited community engagement
	securityScore := 0.9   // No known security issues
	
	// Calculate overall score as weighted average
	overallScore := (maintainerScore*0.3 + downloadScore*0.2 + ageScore*0.1 + 
		communityScore*0.2 + securityScore*0.2)
	
	reputationSources := []ReputationSource{
		{Source: "npm_registry", Score: 0.8, Weight: 0.4},
		{Source: "github_stars", Score: 0.6, Weight: 0.3},
		{Source: "security_advisories", Score: 0.9, Weight: 0.3},
	}
	
	return ReputationAnalysis{
		OverallScore:      overallScore,
		MaintainerScore:   maintainerScore,
		DownloadScore:     downloadScore,
		AgeScore:          ageScore,
		CommunityScore:    communityScore,
		SecurityScore:     securityScore,
		ReputationSources: reputationSources,
	}
}

// detectAnomalies detects anomalies in package characteristics.
func (a *MLAnalyzer) detectAnomalies(pkg *types.Package, features map[string]float64) AnomalyDetection {
	// Placeholder implementation
	// In a real implementation, this would use anomaly detection algorithms
	
	anomalyScore := 0.0
	isAnomaly := false
	anomalyType := "none"
	anomalyFeatures := []string{}
	
	// Check for anomalous name entropy
	if features["name_entropy"] > 4.5 {
		anomalyScore += 0.4
		isAnomaly = true
		anomalyType = "high_entropy"
		anomalyFeatures = append(anomalyFeatures, "name_entropy")
	}
	
	// Check for anomalous name length
	if features["name_length"] > 50 {
		anomalyScore += 0.3
		isAnomaly = true
		anomalyType = "unusual_length"
		anomalyFeatures = append(anomalyFeatures, "name_length")
	}
	
	outlierAnalysis := OutlierAnalysis{
		IsOutlier:       isAnomaly,
		OutlierScore:    anomalyScore,
		IsolationForest: anomalyScore * 0.8,
		LocalOutlier:    anomalyScore * 0.9,
		OneClassSVM:     anomalyScore * 0.7,
	}
	
	patternAnalysis := PatternAnalysis{
		UnusualPatterns: []string{"high_entropy_name"},
		PatternScore:    anomalyScore,
		FrequencyScore:  0.5,
		SequenceScore:   0.6,
	}
	
	return AnomalyDetection{
		IsAnomaly:       isAnomaly,
		AnomalyScore:    anomalyScore,
		AnomalyType:     anomalyType,
		AnomalyFeatures: anomalyFeatures,
		OutlierAnalysis: outlierAnalysis,
		PatternAnalysis: patternAnalysis,
	}
}

// analyzeBehavior analyzes package behavior (placeholder).
func (a *MLAnalyzer) analyzeBehavior(pkg *types.Package) BehavioralAnalysis {
	// Placeholder implementation
	// In a real implementation, this would analyze actual package behavior
	
	return BehavioralAnalysis{
		InstallBehavior: InstallBehavior{
			SuspiciousCommands: []string{},
			NetworkRequests:    []string{},
			FileModifications:  []string{},
			PermissionChanges:  []string{},
		},
		RuntimeBehavior: RuntimeBehavior{
			ProcessSpawning:   []string{},
			SystemCalls:       []string{},
			ResourceUsage:     []string{},
			EnvironmentAccess: []string{},
		},
		NetworkBehavior: NetworkBehavior{
			OutboundConnections: []string{},
			DNSQueries:          []string{},
			DataExfiltration:    []string{},
			C2Communication:     []string{},
		},
		FileSystemBehavior: FileSystemBehavior{
			FileCreation:     []string{},
			FileDeletion:     []string{},
			FileModification: []string{},
			DirectoryAccess:  []string{},
		},
	}
}

// calculateTyposquattingScore calculates the overall typosquatting score.
func (a *MLAnalyzer) calculateTyposquattingScore(similarityScore, maliciousScore, reputationScore float64) float64 {
	// Weighted combination of scores
	// High similarity + high malicious + low reputation = high typosquatting score
	typosquattingScore := (similarityScore*0.4 + maliciousScore*0.4 + (1-reputationScore)*0.2)
	return math.Min(typosquattingScore, 1.0)
}

// generatePredictions generates ML model predictions.
func (a *MLAnalyzer) generatePredictions(pkg *types.Package, features map[string]float64) []Prediction {
	// Placeholder implementation
	// In a real implementation, this would use actual ML models
	
	predictions := []Prediction{
		{
			Model:       "similarity_model",
			Probability: 0.3,
			Label:       "benign",
			Confidence:  0.8,
		},
		{
			Model:       "malicious_detection_model",
			Probability: 0.2,
			Label:       "benign",
			Confidence:  0.7,
		},
		{
			Model:       "reputation_model",
			Probability: 0.7,
			Label:       "trusted",
			Confidence:  0.6,
		},
	}
	
	return predictions
}

// assessRisk performs overall risk assessment.
func (a *MLAnalyzer) assessRisk(typosquattingScore, maliciousScore, reputationScore float64) RiskAssessment {
	// Calculate overall risk score
	riskScore := (typosquattingScore*0.4 + maliciousScore*0.4 + (1-reputationScore)*0.2)
	
	// Determine risk level
	var overallRisk string
	switch {
	case riskScore >= 0.8:
		overallRisk = "critical"
	case riskScore >= 0.6:
		overallRisk = "high"
	case riskScore >= 0.4:
		overallRisk = "medium"
	case riskScore >= 0.2:
		overallRisk = "low"
	default:
		overallRisk = "minimal"
	}
	
	// Generate risk factors
	riskFactors := []RiskFactor{}
	if typosquattingScore > 0.5 {
		riskFactors = append(riskFactors, RiskFactor{
			Factor:      "high_similarity",
			Severity:    "medium",
			Score:       typosquattingScore,
			Description: "Package name is highly similar to popular packages",
		})
	}
	
	if maliciousScore > 0.5 {
		riskFactors = append(riskFactors, RiskFactor{
			Factor:      "malicious_indicators",
			Severity:    "high",
			Score:       maliciousScore,
			Description: "Package exhibits characteristics of malicious software",
		})
	}
	
	if reputationScore < 0.5 {
		riskFactors = append(riskFactors, RiskFactor{
			Factor:      "low_reputation",
			Severity:    "medium",
			Score:       1 - reputationScore,
			Description: "Package has low reputation or limited trust indicators",
		})
	}
	
	// Generate mitigations
	mitigations := []string{
		"Verify package authenticity through official channels",
		"Check package maintainer reputation and history",
		"Review package dependencies and permissions",
		"Monitor package behavior in a sandboxed environment",
	}
	
	// Calculate confidence level
	confidenceLevel := 0.8 // Placeholder confidence
	
	return RiskAssessment{
		OverallRisk:     overallRisk,
		RiskScore:       riskScore,
		RiskFactors:     riskFactors,
		Mitigations:     mitigations,
		ConfidenceLevel: confidenceLevel,
	}
}

// generateFindings generates specific findings from the analysis.
func (a *MLAnalyzer) generateFindings(pkg *types.Package, similarityScore, maliciousScore float64, 
	reputationAnalysis ReputationAnalysis, anomalyDetection AnomalyDetection) []Finding {
	
	findings := []Finding{}
	
	// High similarity finding
	if similarityScore > a.Config.SimilarityThreshold {
		findings = append(findings, Finding{
			Type:        "high_similarity",
			Severity:    "medium",
			Confidence:  similarityScore,
			Description: fmt.Sprintf("Package name is %.1f%% similar to known packages", similarityScore*100),
			Evidence:    fmt.Sprintf("Similarity score: %.3f", similarityScore),
			Model:       "similarity_model",
		})
	}
	
	// Malicious detection finding
	if maliciousScore > a.Config.MaliciousThreshold {
		findings = append(findings, Finding{
			Type:        "malicious_indicators",
			Severity:    "high",
			Confidence:  maliciousScore,
			Description: "Package exhibits characteristics commonly found in malicious software",
			Evidence:    fmt.Sprintf("Malicious score: %.3f", maliciousScore),
			Model:       "malicious_detection_model",
		})
	}
	
	// Low reputation finding
	if reputationAnalysis.OverallScore < a.Config.ReputationThreshold {
		findings = append(findings, Finding{
			Type:        "low_reputation",
			Severity:    "medium",
			Confidence:  1 - reputationAnalysis.OverallScore,
			Description: "Package has low reputation or limited trust indicators",
			Evidence:    fmt.Sprintf("Reputation score: %.3f", reputationAnalysis.OverallScore),
			Model:       "reputation_model",
		})
	}
	
	// Anomaly detection finding
	if anomalyDetection.IsAnomaly {
		findings = append(findings, Finding{
			Type:        "anomaly_detected",
			Severity:    "low",
			Confidence:  anomalyDetection.AnomalyScore,
			Description: fmt.Sprintf("Package exhibits anomalous characteristics: %s", anomalyDetection.AnomalyType),
			Evidence:    fmt.Sprintf("Anomaly features: %v", anomalyDetection.AnomalyFeatures),
			Model:       "anomaly_detection_model",
		})
	}
	
	return findings
}

// generateRecommendations generates recommendations based on the analysis.
func (a *MLAnalyzer) generateRecommendations(riskAssessment RiskAssessment, findings []Finding) []string {
	recommendations := []string{}
	
	// Risk-based recommendations
	switch riskAssessment.OverallRisk {
	case "critical":
		recommendations = append(recommendations, "DO NOT INSTALL: Package poses critical security risk")
		recommendations = append(recommendations, "Report package to registry security team")
	case "high":
		recommendations = append(recommendations, "Exercise extreme caution before installation")
		recommendations = append(recommendations, "Perform thorough security review")
	case "medium":
		recommendations = append(recommendations, "Review package carefully before installation")
		recommendations = append(recommendations, "Consider alternative packages")
	case "low":
		recommendations = append(recommendations, "Package appears relatively safe but monitor usage")
	default:
		recommendations = append(recommendations, "Package appears safe for installation")
	}
	
	// Finding-specific recommendations
	for _, finding := range findings {
		switch finding.Type {
		case "high_similarity":
			recommendations = append(recommendations, "Verify this is the intended package and not a typosquatting attempt")
		case "malicious_indicators":
			recommendations = append(recommendations, "Scan package with multiple security tools before use")
		case "low_reputation":
			recommendations = append(recommendations, "Research package maintainer and community feedback")
		case "anomaly_detected":
			recommendations = append(recommendations, "Investigate unusual package characteristics")
		}
	}
	
	// General security recommendations
	recommendations = append(recommendations, "Always verify package signatures when available")
	recommendations = append(recommendations, "Monitor package behavior after installation")
	recommendations = append(recommendations, "Keep packages updated to latest versions")
	
	return recommendations
}

// Helper functions

// calculateEntropy calculates the Shannon entropy of a string.
func calculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	
	freq := make(map[rune]int)
	for _, char := range s {
		freq[char]++
	}
	
	entropy := 0.0
	length := float64(len(s))
	for _, count := range freq {
		p := float64(count) / length
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}
	
	return entropy
}

// calculateVowelRatio calculates the ratio of vowels in a string.
func calculateVowelRatio(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	
	vowels := "aeiouAEIOU"
	vowelCount := 0
	for _, char := range s {
		if strings.ContainsRune(vowels, char) {
			vowelCount++
		}
	}
	
	return float64(vowelCount) / float64(len(s))
}

// calculateDigitRatio calculates the ratio of digits in a string.
func calculateDigitRatio(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	
	digitCount := 0
	for _, char := range s {
		if char >= '0' && char <= '9' {
			digitCount++
		}
	}
	
	return float64(digitCount) / float64(len(s))
}

// calculateSpecialCharRatio calculates the ratio of special characters in a string.
func calculateSpecialCharRatio(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	
	specialCount := 0
	for _, char := range s {
		if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9')) {
			specialCount++
		}
	}
	
	return float64(specialCount) / float64(len(s))
}

// boolToFloat converts a boolean to float64.
func boolToFloat(b bool) float64 {
	if b {
		return 1.0
	}
	return 0.0
}

// getFeatureNames extracts feature names from the features map.
func getFeatureNames(features map[string]float64) []string {
	names := make([]string, 0, len(features))
	for name := range features {
		names = append(names, name)
	}
	return names
}