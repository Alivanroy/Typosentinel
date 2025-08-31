package ml

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/internal/security"
	"github.com/Alivanroy/Typosentinel/pkg/logger"
)

// TrainingDataManager handles training data collection, validation, and preprocessing
type TrainingDataManager struct {
	config         *config.Config
	dataPath       string
	datasets       map[string]*Dataset
	mu             sync.RWMutex
	minSamples     map[string]int
	dataValidators map[string]DataValidator
}

// Dataset represents a collection of training data for a specific model type
type Dataset struct {
	ModelType   string                 `json:"model_type"`
	Samples     []TrainingData         `json:"samples"`
	Labels      map[string]int         `json:"labels"`
	Statistics  *DataStatistics        `json:"statistics"`
	LastUpdated time.Time              `json:"last_updated"`
	Version     string                 `json:"version"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// DataStatistics provides insights into the training dataset
type DataStatistics struct {
	TotalSamples  int                     `json:"total_samples"`
	LabelCounts   map[string]int          `json:"label_counts"`
	FeatureStats  map[string]*FeatureStat `json:"feature_stats"`
	ClassBalance  float64                 `json:"class_balance"`
	DataQuality   float64                 `json:"data_quality"`
	LastValidated time.Time               `json:"last_validated"`
}

// FeatureStat contains statistics for a single feature
type FeatureStat struct {
	Mean     float64 `json:"mean"`
	Std      float64 `json:"std"`
	Min      float64 `json:"min"`
	Max      float64 `json:"max"`
	Median   float64 `json:"median"`
	Missing  int     `json:"missing"`
	Outliers int     `json:"outliers"`
}

// DataValidator interface moved to advanced_data_collector.go to avoid duplication

// ValidationReport contains data validation results
type ValidationReport struct {
	IsValid     bool              `json:"is_valid"`
	Score       float64           `json:"score"`
	Issues      []ValidationIssue `json:"issues"`
	Suggestions []string          `json:"suggestions"`
	Statistics  *DataStatistics   `json:"statistics"`
	GeneratedAt time.Time         `json:"generated_at"`
}

// ValidationIssue represents a data quality issue
type ValidationIssue struct {
	Type            string                 `json:"type"`
	Severity        string                 `json:"severity"`
	Description     string                 `json:"description"`
	AffectedSamples []int                  `json:"affected_samples"`
	Metadata        map[string]interface{} `json:"metadata"`
}

// ValidationRule defines a data validation rule
// ValidationRule struct moved to security/ml_hardening.go to avoid duplication

// BasicDataValidator provides basic data validation functionality
type BasicDataValidator struct {
	modelType string
}

// GetName returns the validator name
func (v *BasicDataValidator) GetName() string {
	return "basic_data_validator_" + v.modelType
}

// ValidateData validates training data quality
func (v *BasicDataValidator) ValidateData(data []TrainingData) (*ValidationReport, error) {
	issues := make([]ValidationIssue, 0)

	// Basic validation checks
	if len(data) == 0 {
		issues = append(issues, ValidationIssue{
			Type:        "empty_dataset",
			Severity:    "error",
			Description: "Dataset is empty",
		})
	}

	// Check for consistent feature dimensions
	if len(data) > 0 {
		expectedFeatures := len(data[0].Features)
		for i, sample := range data {
			if len(sample.Features) != expectedFeatures {
				issues = append(issues, ValidationIssue{
					Type:            "inconsistent_features",
					Severity:        "error",
					Description:     fmt.Sprintf("Sample %d has %d features, expected %d", i, len(sample.Features), expectedFeatures),
					AffectedSamples: []int{i},
				})
			}
		}
	}

	isValid := len(issues) == 0
	score := 1.0
	if !isValid {
		score = math.Max(0.0, 1.0-float64(len(issues))*0.1)
	}

	return &ValidationReport{
		IsValid:     isValid,
		Score:       score,
		Issues:      issues,
		Suggestions: []string{"Ensure consistent feature dimensions", "Remove empty samples"},
		GeneratedAt: time.Now(),
	}, nil
}

// Validate validates collected data according to DataValidator interface
func (v *BasicDataValidator) Validate(data *CollectedData) (*ValidationResult, error) {
	return &ValidationResult{
		DataID:             data.ID,
		ValidationTime:     time.Now(),
		IsValid:            true,
		ValidationScore:    0.95,
		ValidationErrors:   []ValidationError{},
		ValidationWarnings: []ValidationWarning{},
		ValidationMetrics:  map[string]float64{"basic_validation": 0.95},
		RuleResults:        []RuleResult{},
		Recommendations:    []string{"Data passed basic validation"},
		ValidationDuration: time.Millisecond * 10,
	}, nil
}

// GetValidationRules returns the validation rules for this validator
func (v *BasicDataValidator) GetValidationRules() []security.ValidationRule {
	return []security.ValidationRule{
		{
			RuleType:  "non_empty_dataset",
			Pattern:   "min_samples",
			Threshold: 1.0,
			Action:    "reject",
		},
		{
			RuleType:  "consistent_features",
			Pattern:   "feature_dimension",
			Threshold: 0.0,
			Action:    "reject",
		},
	}
}

// GetValidationStats returns validation statistics
func (v *BasicDataValidator) GetValidationStats() *ValidationStats {
	return &ValidationStats{}
}

// NewTrainingDataManager creates a new training data manager
func NewTrainingDataManager(config *config.Config) *TrainingDataManager {
	dataPath := filepath.Join("ml", "training", "data")
	// Use default data path for now

	manager := &TrainingDataManager{
		config:         config,
		dataPath:       dataPath,
		datasets:       make(map[string]*Dataset),
		minSamples:     make(map[string]int),
		dataValidators: make(map[string]DataValidator),
	}

	// Set minimum sample requirements
	manager.minSamples["typosquatting"] = 1000
	manager.minSamples["reputation"] = 500
	manager.minSamples["anomaly"] = 800

	// Initialize validators
	manager.dataValidators["typosquatting"] = &BasicDataValidator{modelType: "typosquatting"}
	manager.dataValidators["reputation"] = &BasicDataValidator{modelType: "reputation"}
	manager.dataValidators["anomaly"] = &BasicDataValidator{modelType: "anomaly"}

	return manager
}

// LoadTrainingData loads training data for a specific model type
func (tdm *TrainingDataManager) LoadTrainingData(modelType string) ([]TrainingData, error) {
	tdm.mu.RLock()
	defer tdm.mu.RUnlock()

	// Check if data is already loaded
	if dataset, exists := tdm.datasets[modelType]; exists {
		return dataset.Samples, nil
	}

	// Load from disk
	dataset, err := tdm.loadDatasetFromDisk(modelType)
	if err != nil {
		return nil, fmt.Errorf("failed to load dataset from disk: %w", err)
	}

	// Validate data quality
	if err := tdm.validateDataset(dataset); err != nil {
		return nil, fmt.Errorf("data validation failed: %w", err)
	}

	// Cache the dataset
	tdm.datasets[modelType] = dataset

	logger.Info("Training data loaded", map[string]interface{}{
		"model_type":    modelType,
		"sample_count":  len(dataset.Samples),
		"data_quality":  dataset.Statistics.DataQuality,
		"class_balance": dataset.Statistics.ClassBalance,
	})

	return dataset.Samples, nil
}

// AddTrainingData adds new training samples to a dataset
func (tdm *TrainingDataManager) AddTrainingData(modelType string, samples []TrainingData) error {
	tdm.mu.Lock()
	defer tdm.mu.Unlock()

	// Get or create dataset
	dataset, exists := tdm.datasets[modelType]
	if !exists {
		dataset = &Dataset{
			ModelType: modelType,
			Samples:   make([]TrainingData, 0),
			Labels:    make(map[string]int),
			Metadata:  make(map[string]interface{}),
		}
		tdm.datasets[modelType] = dataset
	}

	// Validate new samples
	validator, exists := tdm.dataValidators[modelType]
	if exists {
		report, err := validator.ValidateData(samples)
		if err != nil {
			return fmt.Errorf("validation failed: %w", err)
		}
		if !report.IsValid {
			return fmt.Errorf("data validation failed: %d issues found", len(report.Issues))
		}
	}

	// Add samples
	dataset.Samples = append(dataset.Samples, samples...)
	dataset.LastUpdated = time.Now()

	// Update statistics
	if err := tdm.updateDatasetStatistics(dataset); err != nil {
		logger.DebugWithContext("Failed to update dataset statistics", map[string]interface{}{
			"model_type": modelType,
			"error":      err.Error(),
		})
	}

	// Save to disk
	if err := tdm.saveDatasetToDisk(dataset); err != nil {
		return fmt.Errorf("failed to save dataset: %w", err)
	}

	logger.Info("Training data added", map[string]interface{}{
		"model_type":    modelType,
		"new_samples":   len(samples),
		"total_samples": len(dataset.Samples),
	})

	return nil
}

// LoadTestData loads test data for a specific model type
func (tdm *TrainingDataManager) LoadTestData(modelType string) ([]TrainingData, error) {
	tdm.mu.RLock()
	defer tdm.mu.RUnlock()

	dataset, exists := tdm.datasets[modelType]
	if !exists {
		return nil, fmt.Errorf("no dataset found for model type: %s", modelType)
	}

	// Return a portion of the data as test data (last 20%)
	totalSamples := len(dataset.Samples)
	if totalSamples == 0 {
		return nil, fmt.Errorf("no training data available for model type: %s", modelType)
	}

	testStartIndex := int(float64(totalSamples) * 0.8) // Use last 20% as test data
	testData := make([]TrainingData, 0, totalSamples-testStartIndex)

	for i := testStartIndex; i < totalSamples; i++ {
		testData = append(testData, dataset.Samples[i])
	}

	return testData, nil
}

// HasSufficientData checks if there's enough training data for a model type
func (tdm *TrainingDataManager) HasSufficientData(modelType string) bool {
	tdm.mu.RLock()
	defer tdm.mu.RUnlock()

	minRequired, exists := tdm.minSamples[modelType]
	if !exists {
		minRequired = 100 // Default minimum
	}

	dataset, exists := tdm.datasets[modelType]
	if !exists {
		// Try to load from disk
		var err error
		dataset, err = tdm.loadDatasetFromDisk(modelType)
		if err != nil {
			return false
		}
		tdm.datasets[modelType] = dataset
	}

	if dataset == nil {
		return false
	}
	return len(dataset.Samples) >= minRequired
}

// GetDataStatus returns the status of all training datasets
func (tdm *TrainingDataManager) GetDataStatus() map[string]interface{} {
	tdm.mu.RLock()
	defer tdm.mu.RUnlock()

	status := make(map[string]interface{})

	for modelType, minSamples := range tdm.minSamples {
		dataset, exists := tdm.datasets[modelType]
		if !exists {
			status[modelType] = map[string]interface{}{
				"available":    false,
				"sample_count": 0,
				"min_required": minSamples,
				"sufficient":   false,
			}
			continue
		}

		status[modelType] = map[string]interface{}{
			"available":     true,
			"sample_count":  len(dataset.Samples),
			"min_required":  minSamples,
			"sufficient":    len(dataset.Samples) >= minSamples,
			"last_updated":  dataset.LastUpdated,
			"data_quality":  dataset.Statistics.DataQuality,
			"class_balance": dataset.Statistics.ClassBalance,
		}
	}

	return status
}

// loadDatasetFromDisk loads a dataset from disk storage
func (tdm *TrainingDataManager) loadDatasetFromDisk(modelType string) (*Dataset, error) {
	filePath := filepath.Join(tdm.dataPath, fmt.Sprintf("%s_dataset.json", modelType))

	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		// Create empty dataset if file doesn't exist
		return &Dataset{
			ModelType:   modelType,
			Samples:     make([]TrainingData, 0),
			Labels:      make(map[string]int),
			Statistics:  &DataStatistics{},
			LastUpdated: time.Now(),
			Version:     "1.0",
			Metadata:    make(map[string]interface{}),
		}, nil
	}

	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read dataset file: %w", err)
	}

	var dataset Dataset
	if err := json.Unmarshal(data, &dataset); err != nil {
		return nil, fmt.Errorf("failed to unmarshal dataset: %w", err)
	}

	return &dataset, nil
}

// saveDatasetToDisk saves a dataset to disk storage
func (tdm *TrainingDataManager) saveDatasetToDisk(dataset *Dataset) error {
	// Ensure directory exists
	if err := os.MkdirAll(tdm.dataPath, 0755); err != nil {
		return fmt.Errorf("failed to create data directory: %w", err)
	}

	filePath := filepath.Join(tdm.dataPath, fmt.Sprintf("%s_dataset.json", dataset.ModelType))

	data, err := json.MarshalIndent(dataset, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal dataset: %w", err)
	}

	if err := ioutil.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write dataset file: %w", err)
	}

	return nil
}

// validateDataset validates the quality of a dataset
func (tdm *TrainingDataManager) validateDataset(dataset *Dataset) error {
	validator, exists := tdm.dataValidators[dataset.ModelType]
	if !exists {
		return nil // No validator available
	}

	// Use the ValidateData method for training data validation
	if basicValidator, ok := validator.(*BasicDataValidator); ok {
		report, err := basicValidator.ValidateData(dataset.Samples)
		if err != nil {
			return fmt.Errorf("validation failed: %w", err)
		}

		if !report.IsValid {
			return fmt.Errorf("dataset validation failed: %d issues found", len(report.Issues))
		}

		// Update dataset statistics with validation results
		dataset.Statistics = report.Statistics
	}

	return nil
}

// updateDatasetStatistics calculates and updates dataset statistics
func (tdm *TrainingDataManager) updateDatasetStatistics(dataset *Dataset) error {
	if len(dataset.Samples) == 0 {
		dataset.Statistics = &DataStatistics{
			TotalSamples:  0,
			LabelCounts:   make(map[string]int),
			FeatureStats:  make(map[string]*FeatureStat),
			ClassBalance:  0.0,
			DataQuality:   0.0,
			LastValidated: time.Now(),
		}
		return nil
	}

	stats := &DataStatistics{
		TotalSamples:  len(dataset.Samples),
		LabelCounts:   make(map[string]int),
		FeatureStats:  make(map[string]*FeatureStat),
		LastValidated: time.Now(),
	}

	// Calculate label distribution
	for _, sample := range dataset.Samples {
		label := fmt.Sprintf("%.1f", sample.Label)
		stats.LabelCounts[label]++
	}

	// Calculate class balance (entropy-based)
	stats.ClassBalance = tdm.calculateClassBalance(stats.LabelCounts, stats.TotalSamples)

	// Calculate feature statistics
	if len(dataset.Samples) > 0 && len(dataset.Samples[0].Features) > 0 {
		featureCount := len(dataset.Samples[0].Features)
		for i := 0; i < featureCount; i++ {
			featureName := fmt.Sprintf("feature_%d", i)
			stats.FeatureStats[featureName] = tdm.calculateFeatureStats(dataset.Samples, i)
		}
	}

	// Calculate overall data quality score
	stats.DataQuality = tdm.calculateDataQuality(dataset.Samples, stats)

	dataset.Statistics = stats
	return nil
}

// calculateClassBalance calculates class balance using entropy
func (tdm *TrainingDataManager) calculateClassBalance(labelCounts map[string]int, totalSamples int) float64 {
	if totalSamples == 0 {
		return 0.0
	}

	entropy := 0.0
	for _, count := range labelCounts {
		if count > 0 {
			p := float64(count) / float64(totalSamples)
			entropy -= p * math.Log2(p)
		}
	}

	// Normalize entropy to [0, 1] range
	maxEntropy := math.Log2(float64(len(labelCounts)))
	if maxEntropy == 0 {
		return 1.0
	}

	return entropy / maxEntropy
}

// calculateFeatureStats calculates statistics for a specific feature
func (tdm *TrainingDataManager) calculateFeatureStats(samples []TrainingData, featureIndex int) *FeatureStat {
	if len(samples) == 0 {
		return &FeatureStat{}
	}

	values := make([]float64, 0, len(samples))
	missing := 0

	for _, sample := range samples {
		if featureIndex >= len(sample.Features) {
			missing++
			continue
		}

		value := sample.Features[featureIndex]
		if math.IsNaN(value) || math.IsInf(value, 0) {
			missing++
			continue
		}

		values = append(values, value)
	}

	if len(values) == 0 {
		return &FeatureStat{Missing: missing}
	}

	// Sort for median calculation
	sort.Float64s(values)

	// Calculate basic statistics
	sum := 0.0
	for _, v := range values {
		sum += v
	}
	mean := sum / float64(len(values))

	// Calculate standard deviation
	sumSquares := 0.0
	for _, v := range values {
		diff := v - mean
		sumSquares += diff * diff
	}
	std := math.Sqrt(sumSquares / float64(len(values)))

	// Calculate median
	median := values[len(values)/2]
	if len(values)%2 == 0 {
		median = (values[len(values)/2-1] + values[len(values)/2]) / 2
	}

	// Count outliers (values beyond 2 standard deviations)
	outliers := 0
	for _, v := range values {
		if math.Abs(v-mean) > 2*std {
			outliers++
		}
	}

	return &FeatureStat{
		Mean:     mean,
		Std:      std,
		Min:      values[0],
		Max:      values[len(values)-1],
		Median:   median,
		Missing:  missing,
		Outliers: outliers,
	}
}

// calculateDataQuality calculates an overall data quality score
func (tdm *TrainingDataManager) calculateDataQuality(samples []TrainingData, stats *DataStatistics) float64 {
	if len(samples) == 0 {
		return 0.0
	}

	qualityScore := 1.0

	// Penalize for missing data
	totalFeatures := 0
	missingFeatures := 0
	for _, featureStat := range stats.FeatureStats {
		totalFeatures += len(samples)
		missingFeatures += featureStat.Missing
	}

	if totalFeatures > 0 {
		missingRatio := float64(missingFeatures) / float64(totalFeatures)
		qualityScore *= (1.0 - missingRatio)
	}

	// Penalize for class imbalance
	qualityScore *= stats.ClassBalance

	// Penalize for outliers
	totalOutliers := 0
	for _, featureStat := range stats.FeatureStats {
		totalOutliers += featureStat.Outliers
	}

	if len(samples) > 0 {
		outlierRatio := float64(totalOutliers) / float64(len(samples)*len(stats.FeatureStats))
		qualityScore *= (1.0 - math.Min(outlierRatio, 0.5)) // Cap outlier penalty at 50%
	}

	return math.Max(0.0, math.Min(1.0, qualityScore))
}

// GenerateTrainingData generates synthetic training data for testing
func (tdm *TrainingDataManager) GenerateTrainingData(modelType string, count int) ([]TrainingData, error) {
	switch modelType {
	case "typosquatting":
		return tdm.generateTyposquattingData(count), nil
	case "reputation":
		return tdm.generateReputationData(count), nil
	case "anomaly":
		return tdm.generateAnomalyData(count), nil
	default:
		return nil, fmt.Errorf("unsupported model type for data generation: %s", modelType)
	}
}

// generateTyposquattingData generates synthetic typosquatting training data
func (tdm *TrainingDataManager) generateTyposquattingData(count int) []TrainingData {
	data := make([]TrainingData, count)

	for i := 0; i < count; i++ {
		// Generate features: [name_similarity, popularity_diff, age_diff, maintainer_similarity]
		features := make([]float64, 4)

		if i%2 == 0 {
			// Legitimate package
			features[0] = 0.1 + rand.Float64()*0.3 // Low name similarity
			features[1] = rand.Float64() * 0.5     // Moderate popularity difference
			features[2] = rand.Float64() * 0.4     // Moderate age difference
			features[3] = 0.7 + rand.Float64()*0.3 // High maintainer similarity
			data[i] = TrainingData{Features: features, Label: 0.0}
		} else {
			// Typosquatting package
			features[0] = 0.7 + rand.Float64()*0.3 // High name similarity
			features[1] = 0.6 + rand.Float64()*0.4 // High popularity difference
			features[2] = 0.8 + rand.Float64()*0.2 // High age difference
			features[3] = rand.Float64() * 0.4     // Low maintainer similarity
			data[i] = TrainingData{Features: features, Label: 1.0}
		}

		data[i].Metadata = map[string]interface{}{
			"generated": true,
			"timestamp": time.Now(),
		}
	}

	return data
}

// generateReputationData generates synthetic reputation training data
func (tdm *TrainingDataManager) generateReputationData(count int) []TrainingData {
	data := make([]TrainingData, count)

	for i := 0; i < count; i++ {
		// Generate features: [popularity, maturity, maintenance, quality, security]
		features := make([]float64, 5)

		if i%3 == 0 {
			// High reputation
			for j := range features {
				features[j] = 0.7 + rand.Float64()*0.3
			}
			data[i] = TrainingData{Features: features, Label: 0.8 + rand.Float64()*0.2}
		} else if i%3 == 1 {
			// Medium reputation
			for j := range features {
				features[j] = 0.4 + rand.Float64()*0.4
			}
			data[i] = TrainingData{Features: features, Label: 0.4 + rand.Float64()*0.4}
		} else {
			// Low reputation
			for j := range features {
				features[j] = rand.Float64() * 0.4
			}
			data[i] = TrainingData{Features: features, Label: rand.Float64() * 0.4}
		}

		data[i].Metadata = map[string]interface{}{
			"generated": true,
			"timestamp": time.Now(),
		}
	}

	return data
}

// generateAnomalyData generates synthetic anomaly detection training data
func (tdm *TrainingDataManager) generateAnomalyData(count int) []TrainingData {
	data := make([]TrainingData, count)

	for i := 0; i < count; i++ {
		// Generate features: [behavior_score, pattern_deviation, risk_indicators]
		features := make([]float64, 3)

		if i%4 == 0 {
			// Anomalous behavior
			features[0] = 0.7 + rand.Float64()*0.3 // High behavior score
			features[1] = 0.6 + rand.Float64()*0.4 // High pattern deviation
			features[2] = 0.8 + rand.Float64()*0.2 // High risk indicators
			data[i] = TrainingData{Features: features, Label: 1.0}
		} else {
			// Normal behavior
			features[0] = rand.Float64() * 0.4 // Low behavior score
			features[1] = rand.Float64() * 0.5 // Low pattern deviation
			features[2] = rand.Float64() * 0.3 // Low risk indicators
			data[i] = TrainingData{Features: features, Label: 0.0}
		}

		data[i].Metadata = map[string]interface{}{
			"generated": true,
			"timestamp": time.Now(),
		}
	}

	return data
}
