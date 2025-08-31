package ml

import (
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// EnhancedTrainingDataManager type defined in advanced_training_pipeline.go

// EnhancedDataset represents an enhanced dataset with metadata
type EnhancedDataset struct {
	Name              string                   `json:"name"`
	Description       string                   `json:"description"`
	Version           string                   `json:"version"`
	CreatedAt         time.Time                `json:"created_at"`
	UpdatedAt         time.Time                `json:"updated_at"`
	Samples           []EnhancedTrainingSample `json:"samples"`
	Metadata          map[string]interface{}   `json:"metadata"`
	Statistics        *DatasetStatistics       `json:"statistics"`
	QualityMetrics    *DataQualityMetrics      `json:"quality_metrics"`
	FeatureSchema     *FeatureSchema           `json:"feature_schema"`
	LabelDistribution map[string]int           `json:"label_distribution"`
}

// EnhancedTrainingSample represents a training sample with rich metadata
type EnhancedTrainingSample struct {
	ID             string                 `json:"id"`
	Features       []float64              `json:"features"`
	RawFeatures    map[string]interface{} `json:"raw_features"`
	Label          float64                `json:"label"`
	LabelName      string                 `json:"label_name"`
	Weight         float64                `json:"weight"`
	Difficulty     float64                `json:"difficulty"`
	Source         string                 `json:"source"`
	Timestamp      time.Time              `json:"timestamp"`
	Metadata       map[string]interface{} `json:"metadata"`
	Augmented      bool                   `json:"augmented"`
	AugmentationID string                 `json:"augmentation_id"`
	QualityScore   float64                `json:"quality_score"`
	Uncertainty    float64                `json:"uncertainty"`
}

// DataAugmentationRule defines rules for data augmentation
type DataAugmentationRule struct {
	Name        string                 `json:"name"`
	Type        string                 `json:"type"`
	Probability float64                `json:"probability"`
	Parameters  map[string]interface{} `json:"parameters"`
	Applicable  func(sample *EnhancedTrainingSample) bool
	Transform   func(sample *EnhancedTrainingSample) (*EnhancedTrainingSample, error)
}

// NormalizationStats stores statistics for feature normalization
type NormalizationStats struct {
	Means       []float64            `json:"means"`
	StdDevs     []float64            `json:"std_devs"`
	Mins        []float64            `json:"mins"`
	Maxs        []float64            `json:"maxs"`
	Medians     []float64            `json:"medians"`
	Percentiles map[string][]float64 `json:"percentiles"`
}

// FeatureSelector manages feature selection and importance
type FeatureSelector struct {
	SelectedFeatures  []int       `json:"selected_features"`
	FeatureImportance []float64   `json:"feature_importance"`
	SelectionMethod   string      `json:"selection_method"`
	Threshold         float64     `json:"threshold"`
	FeatureNames      []string    `json:"feature_names"`
	CorrelationMatrix [][]float64 `json:"correlation_matrix"`
	MutualInformation []float64   `json:"mutual_information"`
}

// DataQualityMetrics tracks data quality indicators
type DataQualityMetrics struct {
	Completeness    float64        `json:"completeness"`
	Consistency     float64        `json:"consistency"`
	Accuracy        float64        `json:"accuracy"`
	Validity        float64        `json:"validity"`
	Uniqueness      float64        `json:"uniqueness"`
	OutlierRatio    float64        `json:"outlier_ratio"`
	MissingValues   map[string]int `json:"missing_values"`
	DuplicateCount  int            `json:"duplicate_count"`
	AnomalyScores   []float64      `json:"anomaly_scores"`
	QualityIssues   []string       `json:"quality_issues"`
	Recommendations []string       `json:"recommendations"`
}

// DatasetStatistics provides comprehensive dataset statistics
type DatasetStatistics struct {
	SampleCount       int                 `json:"sample_count"`
	FeatureCount      int                 `json:"feature_count"`
	LabelCount        int                 `json:"label_count"`
	ClassDistribution map[string]float64  `json:"class_distribution"`
	FeatureStats      []FeatureStatistics `json:"feature_stats"`
	Correlations      [][]float64         `json:"correlations"`
	DataBalance       float64             `json:"data_balance"`
	Dimensionality    string              `json:"dimensionality"`
	Complexity        float64             `json:"complexity"`
}

// FeatureStatistics provides statistics for individual features
type FeatureStatistics struct {
	Name        string    `json:"name"`
	Index       int       `json:"index"`
	Count       int       `json:"count"`
	Mean        float64   `json:"mean"`
	StdDev      float64   `json:"std_dev"`
	Min         float64   `json:"min"`
	Max         float64   `json:"max"`
	Median      float64   `json:"median"`
	Mode        float64   `json:"mode"`
	Skewness    float64   `json:"skewness"`
	Kurtosis    float64   `json:"kurtosis"`
	Variance    float64   `json:"variance"`
	Range       float64   `json:"range"`
	IQR         float64   `json:"iqr"`
	Outliers    []float64 `json:"outliers"`
	MissingRate float64   `json:"missing_rate"`
	Uniqueness  float64   `json:"uniqueness"`
}

// FeatureSchema defines the structure and types of features
type FeatureSchema struct {
	Features []FeatureDefinition `json:"features"`
	Version  string              `json:"version"`
	Hash     string              `json:"hash"`
}

// FeatureDefinition defines a single feature
type FeatureDefinition struct {
	Name        string                 `json:"name"`
	Index       int                    `json:"index"`
	Type        string                 `json:"type"`
	Description string                 `json:"description"`
	Required    bool                   `json:"required"`
	Range       []float64              `json:"range"`
	Categories  []string               `json:"categories"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// DataSplit represents a data split for training/validation/testing
type DataSplit struct {
	Training   []EnhancedTrainingSample `json:"training"`
	Validation []EnhancedTrainingSample `json:"validation"`
	Testing    []EnhancedTrainingSample `json:"testing"`
	Metadata   map[string]interface{}   `json:"metadata"`
}

// NewEnhancedTrainingDataManager function defined in advanced_training_pipeline.go

// LoadDataset loads a dataset from file
func (etdm *EnhancedTrainingDataManager) LoadDataset(name, path string) error {
	etdm.mu.Lock()
	defer etdm.mu.Unlock()

	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read dataset file: %w", err)
	}

	var dataset EnhancedDataset
	if err := json.Unmarshal(data, &dataset); err != nil {
		return fmt.Errorf("failed to parse dataset: %w", err)
	}

	dataset.Name = name
	dataset.UpdatedAt = time.Now()

	// Calculate statistics and quality metrics
	if err := etdm.calculateDatasetStatistics(&dataset); err != nil {
		return fmt.Errorf("failed to calculate statistics: %w", err)
	}

	if err := etdm.assessDataQuality(&dataset); err != nil {
		return fmt.Errorf("failed to assess data quality: %w", err)
	}

	etdm.datasets[name] = &dataset
	return nil
}

// CreateDataset creates a new dataset from raw samples
func (etdm *EnhancedTrainingDataManager) CreateDataset(name, description string, samples []EnhancedTrainingSample) error {
	etdm.mu.Lock()
	defer etdm.mu.Unlock()

	dataset := &EnhancedDataset{
		Name:              name,
		Description:       description,
		Version:           "1.0.0",
		CreatedAt:         time.Now(),
		UpdatedAt:         time.Now(),
		Samples:           samples,
		Metadata:          make(map[string]interface{}),
		LabelDistribution: make(map[string]int),
	}

	// Calculate statistics and quality metrics
	if err := etdm.calculateDatasetStatistics(dataset); err != nil {
		return fmt.Errorf("failed to calculate statistics: %w", err)
	}

	if err := etdm.assessDataQuality(dataset); err != nil {
		return fmt.Errorf("failed to assess data quality: %w", err)
	}

	etdm.datasets[name] = dataset
	return nil
}

// AugmentDataset applies data augmentation to a dataset
func (etdm *EnhancedTrainingDataManager) AugmentDataset(datasetName string, augmentationFactor float64) error {
	etdm.mu.Lock()
	defer etdm.mu.Unlock()

	dataset, exists := etdm.datasets[datasetName]
	if !exists {
		return fmt.Errorf("dataset %s not found", datasetName)
	}

	originalSamples := make([]EnhancedTrainingSample, len(dataset.Samples))
	copy(originalSamples, dataset.Samples)

	augmentedSamples := make([]EnhancedTrainingSample, 0)
	targetAugmentedCount := int(float64(len(originalSamples)) * augmentationFactor)

	for i := 0; i < targetAugmentedCount; i++ {
		// Select random sample
		originalSample := originalSamples[rand.Intn(len(originalSamples))]

		// Apply random augmentation rule
		for _, rule := range etdm.augmentationRules {
			if rand.Float64() < rule.Probability && rule.Applicable(&originalSample) {
				augmentedSample, err := rule.Transform(&originalSample)
				if err != nil {
					continue
				}

				augmentedSample.ID = fmt.Sprintf("%s_aug_%d", originalSample.ID, i)
				augmentedSample.Augmented = true
				augmentedSample.AugmentationID = rule.Name
				augmentedSample.Timestamp = time.Now()

				augmentedSamples = append(augmentedSamples, *augmentedSample)
				break
			}
		}
	}

	// Add augmented samples to dataset
	dataset.Samples = append(dataset.Samples, augmentedSamples...)
	dataset.UpdatedAt = time.Now()

	// Recalculate statistics
	return etdm.calculateDatasetStatistics(dataset)
}

// NormalizeDataset normalizes features in a dataset
func (etdm *EnhancedTrainingDataManager) NormalizeDataset(datasetName string, method string) error {
	etdm.mu.Lock()
	defer etdm.mu.Unlock()

	dataset, exists := etdm.datasets[datasetName]
	if !exists {
		return fmt.Errorf("dataset %s not found", datasetName)
	}

	if len(dataset.Samples) == 0 {
		return fmt.Errorf("dataset is empty")
	}

	featureCount := len(dataset.Samples[0].Features)

	// Calculate normalization statistics
	if err := etdm.calculateNormalizationStats(datasetName, dataset, featureCount); err != nil {
		return fmt.Errorf("failed to calculate normalization stats: %w", err)
	}

	// Apply normalization
	stats, exists := etdm.normalizationStats[datasetName]
	if !exists {
		return fmt.Errorf("normalization stats not found for dataset %s", datasetName)
	}

	for i := range dataset.Samples {
		for j := range dataset.Samples[i].Features {
			switch method {
			case "z-score":
				if j < len(stats.StdDevs) && stats.StdDevs[j] > 0 {
					dataset.Samples[i].Features[j] = (dataset.Samples[i].Features[j] - stats.Means[j]) / stats.StdDevs[j]
				}
			case "min-max":
				if j < len(stats.Maxs) && j < len(stats.Mins) {
					range_ := stats.Maxs[j] - stats.Mins[j]
					if range_ > 0 {
						dataset.Samples[i].Features[j] = (dataset.Samples[i].Features[j] - stats.Mins[j]) / range_
					}
				}
			case "robust":
				if j < len(stats.Medians) && stats.Percentiles != nil {
					if p25, ok := stats.Percentiles["25"]; ok && j < len(p25) {
						if p75, ok := stats.Percentiles["75"]; ok && j < len(p75) {
							iqr := p75[j] - p25[j]
							if iqr > 0 {
								dataset.Samples[i].Features[j] = (dataset.Samples[i].Features[j] - stats.Medians[j]) / iqr
							}
						}
					}
				}
			}
		}
	}

	dataset.UpdatedAt = time.Now()
	return nil
}

// SelectFeatures performs feature selection on a dataset
func (etdm *EnhancedTrainingDataManager) SelectFeatures(datasetName string, method string, threshold float64) error {
	etdm.mu.Lock()
	defer etdm.mu.Unlock()

	dataset, exists := etdm.datasets[datasetName]
	if !exists {
		return fmt.Errorf("dataset %s not found", datasetName)
	}

	if len(dataset.Samples) == 0 {
		return fmt.Errorf("dataset is empty")
	}

	// Calculate feature importance
	featureImportance, err := etdm.calculateFeatureImportance(dataset, method)
	if err != nil {
		return fmt.Errorf("failed to calculate feature importance: %w", err)
	}

	// Select features based on importance threshold
	selectedFeatures := make([]int, 0)
	for i, importance := range featureImportance {
		if importance >= threshold {
			selectedFeatures = append(selectedFeatures, i)
		}
	}

	if len(selectedFeatures) == 0 {
		return fmt.Errorf("no features selected with threshold %f", threshold)
	}

	// Update feature selector
	etdm.featureSelector.SelectedFeatures = selectedFeatures
	etdm.featureSelector.FeatureImportance = featureImportance
	etdm.featureSelector.SelectionMethod = method
	etdm.featureSelector.Threshold = threshold

	// Apply feature selection to dataset
	for i := range dataset.Samples {
		newFeatures := make([]float64, len(selectedFeatures))
		for j, featureIdx := range selectedFeatures {
			if featureIdx < len(dataset.Samples[i].Features) {
				newFeatures[j] = dataset.Samples[i].Features[featureIdx]
			}
		}
		dataset.Samples[i].Features = newFeatures
	}

	dataset.UpdatedAt = time.Now()
	return nil
}

// SplitDataset splits a dataset into training, validation, and test sets
func (etdm *EnhancedTrainingDataManager) SplitDataset(datasetName string) (*DataSplit, error) {
	etdm.mu.RLock()
	defer etdm.mu.RUnlock()

	dataset, exists := etdm.datasets[datasetName]
	if !exists {
		return nil, fmt.Errorf("dataset %s not found", datasetName)
	}

	samples := make([]EnhancedTrainingSample, len(dataset.Samples))
	copy(samples, dataset.Samples)

	// Shuffle if enabled
	if etdm.shuffleData {
		rand.Shuffle(len(samples), func(i, j int) {
			samples[i], samples[j] = samples[j], samples[i]
		})
	}

	// Calculate split indices
	totalSamples := len(samples)
	testCount := int(float64(totalSamples) * etdm.testSplit)
	validationCount := int(float64(totalSamples) * etdm.validationSplit)
	trainingCount := totalSamples - testCount - validationCount

	if trainingCount <= 0 {
		return nil, fmt.Errorf("insufficient samples for splitting")
	}

	// Create splits
	split := &DataSplit{
		Training:   samples[:trainingCount],
		Validation: samples[trainingCount : trainingCount+validationCount],
		Testing:    samples[trainingCount+validationCount:],
		Metadata: map[string]interface{}{
			"training_count":   trainingCount,
			"validation_count": validationCount,
			"test_count":       testCount,
			"total_count":      totalSamples,
			"validation_split": etdm.validationSplit,
			"test_split":       etdm.testSplit,
			"shuffled":         etdm.shuffleData,
		},
	}

	return split, nil
}

// GetBatches returns batches of training data
func (etdm *EnhancedTrainingDataManager) GetBatches(samples []EnhancedTrainingSample) [][]EnhancedTrainingSample {
	etdm.mu.RLock()
	defer etdm.mu.RUnlock()

	if etdm.batchSize <= 0 {
		return [][]EnhancedTrainingSample{samples}
	}

	batches := make([][]EnhancedTrainingSample, 0)
	for i := 0; i < len(samples); i += etdm.batchSize {
		end := i + etdm.batchSize
		if end > len(samples) {
			end = len(samples)
		}
		batches = append(batches, samples[i:end])
	}

	return batches
}

// SaveDataset saves a dataset to file
func (etdm *EnhancedTrainingDataManager) SaveDataset(datasetName, path string) error {
	etdm.mu.RLock()
	defer etdm.mu.RUnlock()

	dataset, exists := etdm.datasets[datasetName]
	if !exists {
		return fmt.Errorf("dataset %s not found", datasetName)
	}

	// Create directory if it doesn't exist
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	data, err := json.MarshalIndent(dataset, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal dataset: %w", err)
	}

	return os.WriteFile(path, data, 0644)
}

// GetDatasetInfo returns information about a dataset
func (etdm *EnhancedTrainingDataManager) GetDatasetInfo(datasetName string) (*EnhancedDataset, error) {
	etdm.mu.RLock()
	defer etdm.mu.RUnlock()

	dataset, exists := etdm.datasets[datasetName]
	if !exists {
		return nil, fmt.Errorf("dataset %s not found", datasetName)
	}

	// Return a copy to prevent external modification
	datasetCopy := *dataset
	return &datasetCopy, nil
}

// ListDatasets returns a list of available datasets
func (etdm *EnhancedTrainingDataManager) ListDatasets() []string {
	etdm.mu.RLock()
	defer etdm.mu.RUnlock()

	names := make([]string, 0, len(etdm.datasets))
	for name := range etdm.datasets {
		names = append(names, name)
	}

	sort.Strings(names)
	return names
}

// AddAugmentationRule adds a data augmentation rule
func (etdm *EnhancedTrainingDataManager) AddAugmentationRule(rule DataAugmentationRule) {
	etdm.mu.Lock()
	defer etdm.mu.Unlock()

	etdm.augmentationRules = append(etdm.augmentationRules, rule)
}

// SetSplitRatios sets the validation and test split ratios
func (etdm *EnhancedTrainingDataManager) SetSplitRatios(validationSplit, testSplit float64) error {
	if validationSplit < 0 || testSplit < 0 || validationSplit+testSplit >= 1.0 {
		return fmt.Errorf("invalid split ratios: validation=%f, test=%f", validationSplit, testSplit)
	}

	etdm.mu.Lock()
	defer etdm.mu.Unlock()

	etdm.validationSplit = validationSplit
	etdm.testSplit = testSplit
	return nil
}

// SetBatchSize sets the batch size for training
func (etdm *EnhancedTrainingDataManager) SetBatchSize(batchSize int) error {
	if batchSize <= 0 {
		return fmt.Errorf("batch size must be positive")
	}

	etdm.mu.Lock()
	defer etdm.mu.Unlock()

	etdm.batchSize = batchSize
	return nil
}

// SetShuffleData sets whether to shuffle data during splitting
func (etdm *EnhancedTrainingDataManager) SetShuffleData(shuffle bool) {
	etdm.mu.Lock()
	defer etdm.mu.Unlock()

	etdm.shuffleData = shuffle
}

// Helper methods

func (etdm *EnhancedTrainingDataManager) calculateDatasetStatistics(dataset *EnhancedDataset) error {
	if len(dataset.Samples) == 0 {
		return fmt.Errorf("dataset is empty")
	}

	featureCount := len(dataset.Samples[0].Features)
	labelDistribution := make(map[string]int)
	classDistribution := make(map[string]float64)

	// Count labels
	for _, sample := range dataset.Samples {
		labelName := sample.LabelName
		if labelName == "" {
			labelName = fmt.Sprintf("class_%.0f", sample.Label)
		}
		labelDistribution[labelName]++
		dataset.LabelDistribution[labelName]++
	}

	// Calculate class distribution
	totalSamples := float64(len(dataset.Samples))
	for label, count := range labelDistribution {
		classDistribution[label] = float64(count) / totalSamples
	}

	// Calculate feature statistics
	featureStats := make([]FeatureStatistics, featureCount)
	for i := 0; i < featureCount; i++ {
		values := make([]float64, len(dataset.Samples))
		for j, sample := range dataset.Samples {
			if i < len(sample.Features) {
				values[j] = sample.Features[i]
			}
		}

		featureStats[i] = etdm.calculateFeatureStatistics(fmt.Sprintf("feature_%d", i), i, values)
	}

	// Calculate data balance (entropy-based)
	dataBalance := etdm.calculateDataBalance(classDistribution)

	// Determine dimensionality category
	dimensionality := "low"
	if featureCount > 100 {
		dimensionality = "high"
	} else if featureCount > 20 {
		dimensionality = "medium"
	}

	// Calculate dataset complexity (simplified)
	complexity := float64(featureCount) * math.Log(totalSamples) / 1000.0

	dataset.Statistics = &DatasetStatistics{
		SampleCount:       len(dataset.Samples),
		FeatureCount:      featureCount,
		LabelCount:        len(labelDistribution),
		ClassDistribution: classDistribution,
		FeatureStats:      featureStats,
		DataBalance:       dataBalance,
		Dimensionality:    dimensionality,
		Complexity:        complexity,
	}

	return nil
}

func (etdm *EnhancedTrainingDataManager) calculateFeatureStatistics(name string, index int, values []float64) FeatureStatistics {
	if len(values) == 0 {
		return FeatureStatistics{Name: name, Index: index}
	}

	// Sort values for percentile calculations
	sortedValues := make([]float64, len(values))
	copy(sortedValues, values)
	sort.Float64s(sortedValues)

	// Basic statistics
	mean := etdm.calculateMean(values)
	stdDev := etdm.calculateStdDev(values, mean)
	min := sortedValues[0]
	max := sortedValues[len(sortedValues)-1]
	median := etdm.calculateMedian(sortedValues)
	variance := stdDev * stdDev
	range_ := max - min

	// Percentiles for IQR
	q1 := etdm.calculatePercentile(sortedValues, 25)
	q3 := etdm.calculatePercentile(sortedValues, 75)
	iqr := q3 - q1

	// Detect outliers using IQR method
	outliers := etdm.detectOutliers(values, q1, q3, iqr)

	// Calculate skewness and kurtosis (simplified)
	skewness := etdm.calculateSkewness(values, mean, stdDev)
	kurtosis := etdm.calculateKurtosis(values, mean, stdDev)

	// Calculate uniqueness
	uniqueValues := make(map[float64]bool)
	for _, val := range values {
		uniqueValues[val] = true
	}
	uniqueness := float64(len(uniqueValues)) / float64(len(values))

	return FeatureStatistics{
		Name:        name,
		Index:       index,
		Mean:        mean,
		StdDev:      stdDev,
		Min:         min,
		Max:         max,
		Median:      median,
		Variance:    variance,
		Range:       range_,
		IQR:         iqr,
		Outliers:    outliers,
		Skewness:    skewness,
		Kurtosis:    kurtosis,
		Uniqueness:  uniqueness,
		MissingRate: 0.0, // Simplified - no missing values in this implementation
	}
}

func (etdm *EnhancedTrainingDataManager) assessDataQuality(dataset *EnhancedDataset) error {
	if len(dataset.Samples) == 0 {
		return fmt.Errorf("dataset is empty")
	}

	// Calculate completeness (simplified - assume no missing values)
	completeness := 1.0

	// Calculate consistency (check for duplicate samples)
	duplicateCount := etdm.countDuplicates(dataset.Samples)
	consistency := 1.0 - (float64(duplicateCount) / float64(len(dataset.Samples)))

	// Calculate validity (check for valid feature ranges)
	validity := etdm.calculateValidity(dataset.Samples)

	// Calculate uniqueness
	uniqueness := 1.0 - (float64(duplicateCount) / float64(len(dataset.Samples)))

	// Calculate outlier ratio
	outlierRatio := etdm.calculateOutlierRatio(dataset.Samples)

	// Generate quality issues and recommendations
	qualityIssues := make([]string, 0)
	recommendations := make([]string, 0)

	if duplicateCount > 0 {
		qualityIssues = append(qualityIssues, fmt.Sprintf("%d duplicate samples found", duplicateCount))
		recommendations = append(recommendations, "Remove duplicate samples to improve data quality")
	}

	if outlierRatio > 0.05 {
		qualityIssues = append(qualityIssues, fmt.Sprintf("High outlier ratio: %.2f%%", outlierRatio*100))
		recommendations = append(recommendations, "Consider outlier detection and removal")
	}

	if len(dataset.Samples) < 1000 {
		qualityIssues = append(qualityIssues, "Small dataset size")
		recommendations = append(recommendations, "Consider data augmentation to increase dataset size")
	}

	dataset.QualityMetrics = &DataQualityMetrics{
		Completeness:    completeness,
		Consistency:     consistency,
		Accuracy:        validity, // Using validity as accuracy proxy
		Validity:        validity,
		Uniqueness:      uniqueness,
		OutlierRatio:    outlierRatio,
		MissingValues:   make(map[string]int), // Simplified
		DuplicateCount:  duplicateCount,
		AnomalyScores:   make([]float64, 0), // Would be calculated by anomaly detection
		QualityIssues:   qualityIssues,
		Recommendations: recommendations,
	}

	return nil
}

func (etdm *EnhancedTrainingDataManager) calculateNormalizationStats(datasetName string, dataset *EnhancedDataset, featureCount int) error {
	if len(dataset.Samples) == 0 {
		return fmt.Errorf("dataset is empty")
	}

	means := make([]float64, featureCount)
	stdDevs := make([]float64, featureCount)
	mins := make([]float64, featureCount)
	maxs := make([]float64, featureCount)
	medians := make([]float64, featureCount)
	percentiles := make(map[string][]float64)
	percentiles["25"] = make([]float64, featureCount)
	percentiles["75"] = make([]float64, featureCount)

	for i := 0; i < featureCount; i++ {
		values := make([]float64, len(dataset.Samples))
		for j, sample := range dataset.Samples {
			if i < len(sample.Features) {
				values[j] = sample.Features[i]
			}
		}

		sort.Float64s(values)
		means[i] = etdm.calculateMean(values)
		stdDevs[i] = etdm.calculateStdDev(values, means[i])
		mins[i] = values[0]
		maxs[i] = values[len(values)-1]
		medians[i] = etdm.calculateMedian(values)
		percentiles["25"][i] = etdm.calculatePercentile(values, 25)
		percentiles["75"][i] = etdm.calculatePercentile(values, 75)
	}

	etdm.normalizationStats[datasetName] = &NormalizationStats{
		Means:       means,
		StdDevs:     stdDevs,
		Mins:        mins,
		Maxs:        maxs,
		Medians:     medians,
		Percentiles: percentiles,
	}

	return nil
}

func (etdm *EnhancedTrainingDataManager) calculateFeatureImportance(dataset *EnhancedDataset, method string) ([]float64, error) {
	if len(dataset.Samples) == 0 {
		return nil, fmt.Errorf("dataset is empty")
	}

	featureCount := len(dataset.Samples[0].Features)
	importance := make([]float64, featureCount)

	switch method {
	case "variance":
		// Calculate variance-based importance
		for i := 0; i < featureCount; i++ {
			values := make([]float64, len(dataset.Samples))
			for j, sample := range dataset.Samples {
				if i < len(sample.Features) {
					values[j] = sample.Features[i]
				}
			}
			mean := etdm.calculateMean(values)
			variance := 0.0
			for _, val := range values {
				diff := val - mean
				variance += diff * diff
			}
			importance[i] = variance / float64(len(values))
		}

	case "correlation":
		// Calculate correlation-based importance
		labels := make([]float64, len(dataset.Samples))
		for i, sample := range dataset.Samples {
			labels[i] = sample.Label
		}

		for i := 0; i < featureCount; i++ {
			featureValues := make([]float64, len(dataset.Samples))
			for j, sample := range dataset.Samples {
				if i < len(sample.Features) {
					featureValues[j] = sample.Features[i]
				}
			}
			importance[i] = math.Abs(etdm.calculateCorrelation(featureValues, labels))
		}

	default:
		// Default: uniform importance
		for i := range importance {
			importance[i] = 1.0
		}
	}

	// Normalize importance scores
	maxImportance := 0.0
	for _, imp := range importance {
		if imp > maxImportance {
			maxImportance = imp
		}
	}

	if maxImportance > 0 {
		for i := range importance {
			importance[i] /= maxImportance
		}
	}

	return importance, nil
}

// Statistical helper methods

func (etdm *EnhancedTrainingDataManager) calculateMean(values []float64) float64 {
	if len(values) == 0 {
		return 0.0
	}
	sum := 0.0
	for _, val := range values {
		sum += val
	}
	return sum / float64(len(values))
}

func (etdm *EnhancedTrainingDataManager) calculateStdDev(values []float64, mean float64) float64 {
	if len(values) <= 1 {
		return 0.0
	}
	variance := 0.0
	for _, val := range values {
		diff := val - mean
		variance += diff * diff
	}
	return math.Sqrt(variance / float64(len(values)-1))
}

func (etdm *EnhancedTrainingDataManager) calculateMedian(sortedValues []float64) float64 {
	n := len(sortedValues)
	if n == 0 {
		return 0.0
	}
	if n%2 == 0 {
		return (sortedValues[n/2-1] + sortedValues[n/2]) / 2.0
	}
	return sortedValues[n/2]
}

func (etdm *EnhancedTrainingDataManager) calculatePercentile(sortedValues []float64, percentile float64) float64 {
	if len(sortedValues) == 0 {
		return 0.0
	}
	index := (percentile / 100.0) * float64(len(sortedValues)-1)
	lower := int(math.Floor(index))
	upper := int(math.Ceil(index))

	if lower == upper {
		return sortedValues[lower]
	}

	weight := index - float64(lower)
	return sortedValues[lower]*(1-weight) + sortedValues[upper]*weight
}

func (etdm *EnhancedTrainingDataManager) detectOutliers(values []float64, q1, q3, iqr float64) []float64 {
	outliers := make([]float64, 0)
	lowerBound := q1 - 1.5*iqr
	upperBound := q3 + 1.5*iqr

	for _, val := range values {
		if val < lowerBound || val > upperBound {
			outliers = append(outliers, val)
		}
	}

	return outliers
}

func (etdm *EnhancedTrainingDataManager) calculateSkewness(values []float64, mean, stdDev float64) float64 {
	if len(values) == 0 || stdDev == 0 {
		return 0.0
	}

	sum := 0.0
	for _, val := range values {
		normalized := (val - mean) / stdDev
		sum += normalized * normalized * normalized
	}

	return sum / float64(len(values))
}

func (etdm *EnhancedTrainingDataManager) calculateKurtosis(values []float64, mean, stdDev float64) float64 {
	if len(values) == 0 || stdDev == 0 {
		return 0.0
	}

	sum := 0.0
	for _, val := range values {
		normalized := (val - mean) / stdDev
		sum += normalized * normalized * normalized * normalized
	}

	return (sum / float64(len(values))) - 3.0 // Excess kurtosis
}

func (etdm *EnhancedTrainingDataManager) calculateDataBalance(classDistribution map[string]float64) float64 {
	if len(classDistribution) <= 1 {
		return 1.0
	}

	// Calculate entropy
	entropy := 0.0
	for _, prob := range classDistribution {
		if prob > 0 {
			entropy -= prob * math.Log2(prob)
		}
	}

	// Normalize by maximum possible entropy
	maxEntropy := math.Log2(float64(len(classDistribution)))
	if maxEntropy == 0 {
		return 1.0
	}

	return entropy / maxEntropy
}

func (etdm *EnhancedTrainingDataManager) countDuplicates(samples []EnhancedTrainingSample) int {
	seen := make(map[string]bool)
	duplicates := 0

	for _, sample := range samples {
		// Create a simple hash of the features
		hash := etdm.hashFeatures(sample.Features)
		if seen[hash] {
			duplicates++
		} else {
			seen[hash] = true
		}
	}

	return duplicates
}

func (etdm *EnhancedTrainingDataManager) hashFeatures(features []float64) string {
	// Simple feature hashing for duplicate detection
	var builder strings.Builder
	for _, feature := range features {
		builder.WriteString(fmt.Sprintf("%.6f,", feature))
	}
	return builder.String()
}

func (etdm *EnhancedTrainingDataManager) calculateValidity(samples []EnhancedTrainingSample) float64 {
	if len(samples) == 0 {
		return 1.0
	}

	validSamples := 0
	for _, sample := range samples {
		valid := true

		// Check for NaN or infinite values
		for _, feature := range sample.Features {
			if math.IsNaN(feature) || math.IsInf(feature, 0) {
				valid = false
				break
			}
		}

		// Check label validity
		if math.IsNaN(sample.Label) || math.IsInf(sample.Label, 0) {
			valid = false
		}

		if valid {
			validSamples++
		}
	}

	return float64(validSamples) / float64(len(samples))
}

func (etdm *EnhancedTrainingDataManager) calculateOutlierRatio(samples []EnhancedTrainingSample) float64 {
	if len(samples) == 0 {
		return 0.0
	}

	// Simplified outlier detection based on feature magnitude
	outliers := 0
	for _, sample := range samples {
		for _, feature := range sample.Features {
			if math.Abs(feature) > 10.0 { // Simple threshold
				outliers++
				break
			}
		}
	}

	return float64(outliers) / float64(len(samples))
}

func (etdm *EnhancedTrainingDataManager) calculateCorrelation(x, y []float64) float64 {
	if len(x) != len(y) || len(x) == 0 {
		return 0.0
	}

	meanX := etdm.calculateMean(x)
	meanY := etdm.calculateMean(y)

	numerator := 0.0
	denomX := 0.0
	denomY := 0.0

	for i := 0; i < len(x); i++ {
		diffX := x[i] - meanX
		diffY := y[i] - meanY
		numerator += diffX * diffY
		denomX += diffX * diffX
		denomY += diffY * diffY
	}

	denominator := math.Sqrt(denomX * denomY)
	if denominator == 0 {
		return 0.0
	}

	return numerator / denominator
}

// CreateDefaultAugmentationRules creates default data augmentation rules
func CreateDefaultAugmentationRules() []DataAugmentationRule {
	return []DataAugmentationRule{
		{
			Name:        "gaussian_noise",
			Type:        "noise",
			Probability: 0.3,
			Parameters: map[string]interface{}{
				"std_dev": 0.01,
			},
			Applicable: func(sample *EnhancedTrainingSample) bool {
				return len(sample.Features) > 0
			},
			Transform: func(sample *EnhancedTrainingSample) (*EnhancedTrainingSample, error) {
				newSample := *sample
				newSample.Features = make([]float64, len(sample.Features))
				stdDev := 0.01
				if val, ok := sample.Metadata["std_dev"].(float64); ok {
					stdDev = val
				}

				for i, feature := range sample.Features {
					noise := rand.NormFloat64() * stdDev
					newSample.Features[i] = feature + noise
				}

				return &newSample, nil
			},
		},
		{
			Name:        "feature_scaling",
			Type:        "scaling",
			Probability: 0.2,
			Parameters: map[string]interface{}{
				"scale_range": []float64{0.8, 1.2},
			},
			Applicable: func(sample *EnhancedTrainingSample) bool {
				return len(sample.Features) > 0
			},
			Transform: func(sample *EnhancedTrainingSample) (*EnhancedTrainingSample, error) {
				newSample := *sample
				newSample.Features = make([]float64, len(sample.Features))
				scale := 0.8 + rand.Float64()*0.4 // Random scale between 0.8 and 1.2

				for i, feature := range sample.Features {
					newSample.Features[i] = feature * scale
				}

				return &newSample, nil
			},
		},
		{
			Name:        "feature_dropout",
			Type:        "dropout",
			Probability: 0.15,
			Parameters: map[string]interface{}{
				"dropout_rate": 0.1,
			},
			Applicable: func(sample *EnhancedTrainingSample) bool {
				return len(sample.Features) > 10 // Only apply if enough features
			},
			Transform: func(sample *EnhancedTrainingSample) (*EnhancedTrainingSample, error) {
				newSample := *sample
				newSample.Features = make([]float64, len(sample.Features))
				copy(newSample.Features, sample.Features)

				dropoutRate := 0.1
				for i := range newSample.Features {
					if rand.Float64() < dropoutRate {
						newSample.Features[i] = 0.0
					}
				}

				return &newSample, nil
			},
		},
	}
}
