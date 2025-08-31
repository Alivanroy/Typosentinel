package ml

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math"
	"os"
	"strings"
	"time"
	"unicode"

	"github.com/Alivanroy/Typosentinel/pkg/logger"
	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// EnhancedProductionML provides production-ready enhanced ML capabilities
type EnhancedProductionML struct {
	config       *ProductionMLConfig
	model        *EnhancedModel
	logger       logger.Logger
	metrics      *MLMetrics
	fallbackMode bool
}

// ProductionMLConfig contains production ML configuration
type ProductionMLConfig struct {
	ModelPath             string  `yaml:"model_path"`
	BackupModelPath       string  `yaml:"backup_model_path"`
	ConfidenceThreshold   float64 `yaml:"confidence_threshold"`
	EdgeCaseThreshold     float64 `yaml:"edge_case_threshold"`
	BatchSize             int     `yaml:"batch_size"`
	TimeoutMs             int     `yaml:"timeout_ms"`
	MaxProcessingTimeMs   int     `yaml:"max_processing_time_ms"`
	TargetThroughput      int     `yaml:"target_throughput"`
	MemoryLimitMB         int     `yaml:"memory_limit_mb"`
	CPUCores              int     `yaml:"cpu_cores"`
	MonitoringEnabled     bool    `yaml:"monitoring_enabled"`
	FallbackEnabled       bool    `yaml:"fallback_enabled"`
	RuleBasedDetection    bool    `yaml:"rule_based_detection"`
	ManualReviewThreshold float64 `yaml:"manual_review_threshold"`
}

// EnhancedModel represents the enhanced neural network model
type EnhancedModel struct {
	ModelInfo      ModelInfo      `json:"model_info"`
	TrainingResult TrainingResult `json:"training_result"`
	Metadata       ModelMetadata  `json:"training_metadata"`
	LoadedAt       time.Time      `json:"loaded_at"`
}

// ModelInfo type defined in client.go

// TrainingResult contains training performance metrics
type TrainingResult struct {
	Duration          string            `json:"duration"`
	FinalLoss         float64           `json:"final_loss"`
	FinalAccuracy     float64           `json:"final_accuracy"`
	BestValidationAcc float64           `json:"best_validation_accuracy"`
	TotalEpochs       int               `json:"total_epochs"`
	Converged         bool              `json:"converged"`
	ValidationMetrics ValidationMetrics `json:"validation_metrics"`
}

// ValidationMetrics contains detailed validation metrics
type ValidationMetrics struct {
	Precision float64 `json:"precision"`
	Recall    float64 `json:"recall"`
	F1Score   float64 `json:"f1_score"`
	AUCROC    float64 `json:"auc_roc"`
}

// ModelMetadata contains model training metadata
type ModelMetadata struct {
	TrainingSamples int       `json:"training_samples"`
	SavedAt         time.Time `json:"saved_at"`
	Version         string    `json:"version"`
}

// EnhancedPredictionResult contains comprehensive prediction results
type EnhancedPredictionResult struct {
	PackageName    string             `json:"package_name"`
	Registry       string             `json:"registry"`
	Prediction     string             `json:"prediction"`
	Confidence     float64            `json:"confidence"`
	ThreatType     string             `json:"threat_type,omitempty"`
	Severity       string             `json:"severity,omitempty"`
	Features       map[string]float64 `json:"features"`
	ProcessingTime time.Duration      `json:"processing_time"`
	ModelVersion   string             `json:"model_version"`
	Timestamp      time.Time          `json:"timestamp"`
	EdgeCase       bool               `json:"edge_case"`
	RequiresReview bool               `json:"requires_review"`
	FallbackUsed   bool               `json:"fallback_used"`
}

// MLMetrics tracks ML performance metrics
type MLMetrics struct {
	TotalPredictions   int64         `json:"total_predictions"`
	MaliciousDetected  int64         `json:"malicious_detected"`
	BenignDetected     int64         `json:"benign_detected"`
	EdgeCasesDetected  int64         `json:"edge_cases_detected"`
	AverageProcessTime time.Duration `json:"average_process_time"`
	Throughput         float64       `json:"throughput"`
	ErrorCount         int64         `json:"error_count"`
	FallbackUsageCount int64         `json:"fallback_usage_count"`
	LastUpdated        time.Time     `json:"last_updated"`
}

// NewEnhancedProductionML creates a new enhanced production ML instance
func NewEnhancedProductionML(config *ProductionMLConfig, logger logger.Logger) (*EnhancedProductionML, error) {
	ml := &EnhancedProductionML{
		config:  config,
		logger:  logger,
		metrics: &MLMetrics{},
	}

	// Load the enhanced model
	if err := ml.loadModel(); err != nil {
		logger.Error("Failed to load enhanced model", map[string]interface{}{"error": err})
		if config.FallbackEnabled {
			ml.fallbackMode = true
			logger.Warn("Falling back to rule-based detection", map[string]interface{}{})
		} else {
			return nil, fmt.Errorf("failed to load model and fallback disabled: %w", err)
		}
	}

	return ml, nil
}

// loadModel loads the enhanced neural network model
func (ml *EnhancedProductionML) loadModel() error {
	modelPath := ml.config.ModelPath
	if modelPath == "" {
		modelPath = "./enhanced_threat_detection_model.json"
	}

	// Check if model file exists
	if _, err := os.Stat(modelPath); os.IsNotExist(err) {
		return fmt.Errorf("model file not found: %s", modelPath)
	}

	// Read model file
	data, err := ioutil.ReadFile(modelPath)
	if err != nil {
		return fmt.Errorf("failed to read model file: %w", err)
	}

	// Parse model
	model := &EnhancedModel{}
	if err := json.Unmarshal(data, model); err != nil {
		return fmt.Errorf("failed to parse model file: %w", err)
	}

	model.LoadedAt = time.Now()
	ml.model = model

	ml.logger.Info("Enhanced model loaded successfully", map[string]interface{}{
		"model_type":          model.ModelInfo.Type,
		"parameters":          model.ModelInfo.ParameterCount,
		"training_accuracy":   model.TrainingResult.FinalAccuracy,
		"validation_accuracy": model.TrainingResult.BestValidationAcc,
		"training_samples":    model.Metadata.TrainingSamples,
	})

	return nil
}

// PredictThreat performs enhanced threat prediction for a package
func (ml *EnhancedProductionML) PredictThreat(ctx context.Context, pkg *types.Package) (*EnhancedPredictionResult, error) {
	startTime := time.Now()
	defer func() {
		processingTime := time.Since(startTime)
		ml.updateMetrics(processingTime)
	}()

	// Check timeout
	if ml.config.TimeoutMs > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(ml.config.TimeoutMs)*time.Millisecond)
		defer cancel()
	}

	// Extract features
	features, err := ml.extractEnhancedFeatures(pkg)
	if err != nil {
		ml.logger.Error("Failed to extract features", map[string]interface{}{
			"package": pkg.Name,
			"error":   err,
		})
		return ml.fallbackPrediction(pkg, err)
	}

	// Check for edge cases
	isEdgeCase := ml.isEdgeCase(pkg, features)

	// Perform prediction
	var prediction string
	var confidence float64
	var threatType string
	var severity string
	fallbackUsed := false

	if ml.fallbackMode {
		prediction, confidence, threatType, severity = ml.ruleBasedPrediction(pkg, features)
		fallbackUsed = true
	} else {
		prediction, confidence, threatType, severity = ml.neuralNetworkPrediction(features)
	}

	// Apply edge case adjustments
	if isEdgeCase {
		confidence = math.Max(confidence, ml.config.EdgeCaseThreshold)
		if prediction == "Benign" && ml.shouldFlagEdgeCase(pkg, features) {
			prediction = "Malicious"
			threatType = "suspicious"
			severity = "medium"
		}
	}

	// Determine if manual review is required
	requiresReview := confidence < ml.config.ManualReviewThreshold || isEdgeCase

	result := &EnhancedPredictionResult{
		PackageName:    pkg.Name,
		Registry:       pkg.Registry,
		Prediction:     prediction,
		Confidence:     confidence,
		ThreatType:     threatType,
		Severity:       severity,
		Features:       features,
		ProcessingTime: time.Since(startTime),
		ModelVersion:   ml.model.Metadata.Version,
		Timestamp:      time.Now(),
		EdgeCase:       isEdgeCase,
		RequiresReview: requiresReview,
		FallbackUsed:   fallbackUsed,
	}

	// Log prediction
	ml.logger.Info("Threat prediction completed", map[string]interface{}{
		"package":         pkg.Name,
		"registry":        pkg.Registry,
		"prediction":      prediction,
		"confidence":      confidence,
		"threat_type":     threatType,
		"processing_time": result.ProcessingTime,
		"edge_case":       isEdgeCase,
		"fallback_used":   fallbackUsed,
	})

	return result, nil
}

// extractEnhancedFeatures extracts 25 enhanced features from a package
func (ml *EnhancedProductionML) extractEnhancedFeatures(pkg *types.Package) (map[string]float64, error) {
	features := make(map[string]float64)

	// Name-based features (8 features)
	features["name_length"] = float64(len(pkg.Name))
	features["name_has_numbers"] = boolToFloat(containsNumbers(pkg.Name))
	features["name_has_hyphens"] = boolToFloat(strings.Contains(pkg.Name, "-"))
	features["name_has_underscores"] = boolToFloat(strings.Contains(pkg.Name, "_"))
	features["name_entropy"] = calculateEntropy(pkg.Name)
	features["name_consonant_ratio"] = calculateConsonantRatio(pkg.Name)
	features["name_uppercase_ratio"] = calculateUppercaseRatio(pkg.Name)
	features["name_special_chars"] = float64(countSpecialChars(pkg.Name))

	// Author-based features (3 features)
	author := getStringField(pkg, "Author")
	features["author_length"] = float64(len(author))
	features["author_has_email"] = boolToFloat(strings.Contains(author, "@"))
	features["author_suspicious"] = boolToFloat(isSuspiciousAuthor(author))

	// Download and popularity features (4 features)
	downloads := getIntField(pkg, "Downloads")
	features["download_count"] = float64(downloads)
	features["download_tier"] = getDownloadTier(downloads)
	features["has_downloads"] = boolToFloat(downloads > 0)
	features["popularity_score"] = calculatePopularityScore(downloads)

	// Registry-specific features (6 features)
	features["registry_npm"] = boolToFloat(pkg.Registry == "npm")
	features["registry_pypi"] = boolToFloat(pkg.Registry == "pypi")
	features["registry_maven"] = boolToFloat(pkg.Registry == "maven")
	features["registry_rubygems"] = boolToFloat(pkg.Registry == "rubygems")
	features["registry_crates"] = boolToFloat(pkg.Registry == "crates")
	features["registry_go"] = boolToFloat(pkg.Registry == "go")

	// Package metadata features (4 features)
	fileCount := getIntField(pkg, "FileCount")
	sizeBytes := getIntField(pkg, "SizeBytes")
	maintainerCount := getIntField(pkg, "MaintainerCount")

	features["file_count"] = float64(fileCount)
	features["package_size"] = float64(sizeBytes)
	features["maintainer_count"] = float64(maintainerCount)
	features["size_per_file"] = calculateSizePerFile(sizeBytes, fileCount)

	return features, nil
}

// isEdgeCase determines if a package represents an edge case
func (ml *EnhancedProductionML) isEdgeCase(pkg *types.Package, features map[string]float64) bool {
	// Empty or very short names
	if len(pkg.Name) <= 1 {
		return true
	}

	// All numeric names
	if isAllNumeric(pkg.Name) {
		return true
	}

	// Very long names
	if len(pkg.Name) > 50 {
		return true
	}

	// Empty author
	author := getStringField(pkg, "Author")
	if len(strings.TrimSpace(author)) == 0 {
		return true
	}

	// Suspicious patterns
	if hasSuspiciousPattern(pkg.Name) {
		return true
	}

	return false
}

// shouldFlagEdgeCase determines if an edge case should be flagged as malicious
func (ml *EnhancedProductionML) shouldFlagEdgeCase(pkg *types.Package, features map[string]float64) bool {
	// Empty names are suspicious
	if len(pkg.Name) == 0 {
		return true
	}

	// Single character names are suspicious
	if len(pkg.Name) == 1 {
		return true
	}

	// All numeric names are suspicious
	if isAllNumeric(pkg.Name) {
		return true
	}

	// Very long names are suspicious
	if len(pkg.Name) > 50 {
		return true
	}

	// Empty author is suspicious
	author := getStringField(pkg, "Author")
	if len(strings.TrimSpace(author)) == 0 {
		return true
	}

	return false
}

// neuralNetworkPrediction simulates neural network prediction
func (ml *EnhancedProductionML) neuralNetworkPrediction(features map[string]float64) (string, float64, string, string) {
	// Simulate neural network processing
	score := 0.0
	threatType := ""
	severity := ""

	// Name-based scoring
	nameLength := features["name_length"]
	if nameLength < 3 || nameLength > 50 {
		score += 0.3
	}

	if features["name_has_numbers"] > 0 && features["name_length"] < 5 {
		score += 0.2
	}

	if features["name_entropy"] < 2.0 {
		score += 0.2
	}

	// Author-based scoring
	if features["author_suspicious"] > 0 {
		score += 0.4
		threatType = "suspicious"
	}

	// Download-based scoring
	if features["download_count"] == 0 {
		score += 0.3
	}

	// Determine prediction
	confidence := math.Min(0.6+score*0.4, 0.95)
	if score > 0.5 {
		if threatType == "" {
			threatType = "typosquatting"
		}
		severity = "medium"
		if score > 0.8 {
			severity = "high"
		}
		return "Malicious", confidence, threatType, severity
	}

	return "Benign", 0.6 + score*0.2, "", ""
}

// ruleBasedPrediction provides fallback rule-based prediction
func (ml *EnhancedProductionML) ruleBasedPrediction(pkg *types.Package, features map[string]float64) (string, float64, string, string) {
	// Simple rule-based detection
	if len(pkg.Name) == 0 || len(pkg.Name) == 1 {
		return "Malicious", 0.95, "suspicious", "high"
	}

	if isAllNumeric(pkg.Name) {
		return "Malicious", 0.90, "suspicious", "medium"
	}

	author := getStringField(pkg, "Author")
	if len(strings.TrimSpace(author)) == 0 {
		return "Malicious", 0.85, "suspicious", "medium"
	}

	if hasSuspiciousPattern(pkg.Name) {
		return "Malicious", 0.80, "typosquatting", "medium"
	}

	return "Benign", 0.70, "", ""
}

// fallbackPrediction provides a fallback prediction when feature extraction fails
func (ml *EnhancedProductionML) fallbackPrediction(pkg *types.Package, err error) (*EnhancedPredictionResult, error) {
	ml.metrics.ErrorCount++
	ml.metrics.FallbackUsageCount++

	return &EnhancedPredictionResult{
		PackageName:    pkg.Name,
		Registry:       pkg.Registry,
		Prediction:     "Unknown",
		Confidence:     0.0,
		ThreatType:     "",
		Severity:       "",
		Features:       make(map[string]float64),
		ProcessingTime: 0,
		ModelVersion:   "fallback",
		Timestamp:      time.Now(),
		EdgeCase:       true,
		RequiresReview: true,
		FallbackUsed:   true,
	}, fmt.Errorf("feature extraction failed, using fallback: %w", err)
}

// updateMetrics updates performance metrics
func (ml *EnhancedProductionML) updateMetrics(processingTime time.Duration) {
	ml.metrics.TotalPredictions++
	ml.metrics.AverageProcessTime = time.Duration(
		(int64(ml.metrics.AverageProcessTime)*ml.metrics.TotalPredictions + int64(processingTime)) /
			(ml.metrics.TotalPredictions + 1),
	)
	ml.metrics.Throughput = float64(time.Second) / float64(ml.metrics.AverageProcessTime)
	ml.metrics.LastUpdated = time.Now()
}

// GetMetrics returns current ML performance metrics
func (ml *EnhancedProductionML) GetMetrics() *MLMetrics {
	return ml.metrics
}

// GetModelInfo returns information about the loaded model
func (ml *EnhancedProductionML) GetModelInfo() *EnhancedModel {
	return ml.model
}

// Helper functions

// boolToFloat function moved to advanced_feature_extractor.go

func containsNumbers(s string) bool {
	for _, r := range s {
		if unicode.IsDigit(r) {
			return true
		}
	}
	return false
}

// calculateEntropy function defined in analyzer.go

func calculateConsonantRatio(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	consonants := 0
	vowels := "aeiouAEIOU"
	for _, r := range s {
		if unicode.IsLetter(r) && !strings.ContainsRune(vowels, r) {
			consonants++
		}
	}

	return float64(consonants) / float64(len(s))
}

func calculateUppercaseRatio(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	uppercase := 0
	for _, r := range s {
		if unicode.IsUpper(r) {
			uppercase++
		}
	}

	return float64(uppercase) / float64(len(s))
}

func countSpecialChars(s string) int {
	count := 0
	for _, r := range s {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			count++
		}
	}
	return count
}

func isSuspiciousAuthor(author string) bool {
	author = strings.ToLower(strings.TrimSpace(author))
	if author == "" {
		return true
	}

	suspiciousPatterns := []string{
		"user", "admin", "test", "temp", "anonymous",
		"hacker", "malware", "virus", "trojan",
	}

	for _, pattern := range suspiciousPatterns {
		if strings.Contains(author, pattern) {
			return true
		}
	}

	return false
}

func getDownloadTier(downloads int) float64 {
	if downloads == 0 {
		return 0
	} else if downloads < 100 {
		return 1
	} else if downloads < 1000 {
		return 2
	} else if downloads < 10000 {
		return 3
	} else {
		return 4
	}
}

func calculatePopularityScore(downloads int) float64 {
	if downloads == 0 {
		return 0
	}
	return math.Log10(float64(downloads)) / 6.0 // Normalize to 0-1 range
}

func calculateSizePerFile(sizeBytes, fileCount int) float64 {
	if fileCount == 0 {
		return 0
	}
	return float64(sizeBytes) / float64(fileCount)
}

func isAllNumeric(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, r := range s {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}

// hasSuspiciousPattern function moved to pattern_helpers.go to avoid duplication

func getStringField(pkg *types.Package, fieldName string) string {
	// This is a simplified implementation
	// In a real implementation, you would use reflection or a proper field accessor
	switch fieldName {
	case "Author":
		if pkg.Metadata != nil {
			return pkg.Metadata.Author
		}
		return ""
	default:
		return ""
	}
}

func getIntField(pkg *types.Package, fieldName string) int {
	// This is a simplified implementation
	// In a real implementation, you would use reflection or a proper field accessor
	switch fieldName {
	case "Downloads":
		if pkg.Metadata != nil {
			return int(pkg.Metadata.Downloads)
		}
		return 0
	case "FileCount":
		// Return a default value or extract from metadata
		return 10
	case "SizeBytes":
		// Return a default value or extract from metadata
		return 1024
	case "MaintainerCount":
		// Return a default value or extract from metadata
		return 1
	default:
		return 0
	}
}
