package ml

import (
	"fmt"
	"math"
	"math/rand"
	"sort"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/pkg/logger"
)

// ModelEvaluator provides comprehensive model evaluation capabilities
type ModelEvaluator struct {
	metrics []EvaluationMetric
}

// EvaluationMetric defines a metric for model evaluation
type EvaluationMetric interface {
	Name() string
	Calculate(predictions, labels []float64) float64
	Description() string
}

// CrossValidator performs k-fold cross-validation
type CrossValidator struct {
	folds int
	seed  int64
}

// NewModelEvaluator creates a new model evaluator with standard metrics
func NewModelEvaluator() *ModelEvaluator {
	return &ModelEvaluator{
		metrics: []EvaluationMetric{
			&AccuracyMetric{},
			&PrecisionMetric{},
			&RecallMetric{},
			&F1ScoreMetric{},
			&AUCMetric{},
		},
	}
}

// NewCrossValidator creates a new cross-validator
func NewCrossValidator(folds int) *CrossValidator {
	return &CrossValidator{
		folds: folds,
		seed:  time.Now().UnixNano(),
	}
}

// EvaluateModel evaluates a model using various metrics
func (me *ModelEvaluator) EvaluateModel(model MLModel, testData []TrainingData) *TrainingMetrics {
	if len(testData) == 0 {
		return &TrainingMetrics{}
	}

	predictions := make([]float64, len(testData))
	labels := make([]float64, len(testData))

	// Get predictions
	for i, sample := range testData {
		prediction, err := model.Predict(sample.Features)
		if err != nil {
			logger.DebugWithContext("Prediction failed during evaluation", map[string]interface{}{
				"sample_index": i,
				"error":        err.Error(),
			})
			predictions[i] = 0.5 // Default prediction
		} else {
			predictions[i] = prediction.Probability
		}
		labels[i] = sample.Label
	}

	// Calculate metrics
	metrics := &TrainingMetrics{}
	for _, metric := range me.metrics {
		value := metric.Calculate(predictions, labels)
		switch metric.Name() {
		case "accuracy":
			metrics.Accuracy = value
		case "precision":
			metrics.Precision = value
		case "recall":
			metrics.Recall = value
		case "f1_score":
			metrics.F1Score = value
		}
	}

	return metrics
}

// ValidateModel performs k-fold cross-validation
func (cv *CrossValidator) ValidateModel(model MLModel, data []TrainingData, config *TrainingConfig) (*ValidationResult, error) {
	if len(data) < cv.folds {
		return nil, fmt.Errorf("insufficient data for %d-fold validation: need at least %d samples, got %d", cv.folds, cv.folds, len(data))
	}

	// Shuffle data
	shuffledData := make([]TrainingData, len(data))
	copy(shuffledData, data)
	cv.shuffleData(shuffledData)

	// Split into folds
	folds := cv.splitIntoFolds(shuffledData)
	foldResults := make([]*FoldResult, cv.folds)

	evaluator := NewModelEvaluator()

	// Perform cross-validation
	for i := 0; i < cv.folds; i++ {
		// Create training and test sets
		trainData, testData := cv.createTrainTestSplit(folds, i)

		// Create a copy of the model for this fold
		foldModel, err := cv.createModelCopy(model, config)
		if err != nil {
			return nil, fmt.Errorf("failed to create model copy for fold %d: %w", i, err)
		}

		// Train the model on training data
		err = foldModel.Train(trainData)
		if err != nil {
			logger.DebugWithContext("Training failed for fold", map[string]interface{}{
				"fold":  i,
				"error": err.Error(),
			})
			continue
		}

		// Evaluate on test data
		metrics := evaluator.EvaluateModel(foldModel, testData)

		foldResults[i] = &FoldResult{
			FoldIndex: i,
			Metrics:   metrics,
			TestSize:  len(testData),
			TrainSize: len(trainData),
		}
	}

	// Calculate aggregate results
	return cv.aggregateResults(foldResults), nil
}

// shuffleData randomly shuffles the training data
func (cv *CrossValidator) shuffleData(data []TrainingData) {
	rand.Seed(cv.seed)
	for i := len(data) - 1; i > 0; i-- {
		j := rand.Intn(i + 1)
		data[i], data[j] = data[j], data[i]
	}
}

// splitIntoFolds splits data into k folds
func (cv *CrossValidator) splitIntoFolds(data []TrainingData) [][]TrainingData {
	folds := make([][]TrainingData, cv.folds)
	foldSize := len(data) / cv.folds

	for i := 0; i < cv.folds; i++ {
		start := i * foldSize
		end := start + foldSize
		if i == cv.folds-1 {
			end = len(data) // Include remaining samples in last fold
		}
		folds[i] = data[start:end]
	}

	return folds
}

// createTrainTestSplit creates training and test sets for a specific fold
func (cv *CrossValidator) createTrainTestSplit(folds [][]TrainingData, testFoldIndex int) ([]TrainingData, []TrainingData) {
	var trainData []TrainingData
	var testData []TrainingData

	for i, fold := range folds {
		if i == testFoldIndex {
			testData = fold
		} else {
			trainData = append(trainData, fold...)
		}
	}

	return trainData, testData
}

// createModelCopy creates a copy of the model for cross-validation
func (cv *CrossValidator) createModelCopy(model MLModel, trainingConfig *TrainingConfig) (MLModel, error) {
	// For now, create a new model of the same type
	// In a real implementation, this would properly clone the model
	switch trainingConfig.ModelType {
	case "typosquatting":
		modelConfig := config.MLModelConfig{Enabled: true, Threshold: 0.7}
		return NewTyposquattingModel(modelConfig), nil
	case "reputation":
		modelConfig := config.MLModelConfig{Enabled: true, Threshold: 0.6}
		return NewReputationModel(modelConfig), nil
	case "anomaly":
		modelConfig := config.MLModelConfig{Enabled: true, Threshold: 0.8}
		return NewAnomalyModel(modelConfig), nil
	default:
		return nil, fmt.Errorf("unsupported model type: %s", trainingConfig.ModelType)
	}
}

// aggregateResults aggregates cross-validation results
func (cv *CrossValidator) aggregateResults(foldResults []*FoldResult) *ValidationResult {
	if len(foldResults) == 0 {
		return &ValidationResult{}
	}

	// Filter out nil results
	validResults := make([]*FoldResult, 0, len(foldResults))
	for _, result := range foldResults {
		if result != nil && result.Metrics != nil {
			validResults = append(validResults, result)
		}
	}

	if len(validResults) == 0 {
		return &ValidationResult{FoldResults: foldResults}
	}

	// Calculate means and standard deviations
	accuracies := make([]float64, len(validResults))
	precisions := make([]float64, len(validResults))
	recalls := make([]float64, len(validResults))
	f1Scores := make([]float64, len(validResults))

	for i, result := range validResults {
		accuracies[i] = result.Metrics.Accuracy
		precisions[i] = result.Metrics.Precision
		recalls[i] = result.Metrics.Recall
		f1Scores[i] = result.Metrics.F1Score
	}

	return &ValidationResult{
		FoldResults:   foldResults,
		MeanAccuracy:  cv.calculateMean(accuracies),
		StdAccuracy:   cv.calculateStd(accuracies),
		MeanPrecision: cv.calculateMean(precisions),
		StdPrecision:  cv.calculateStd(precisions),
		MeanRecall:    cv.calculateMean(recalls),
		StdRecall:     cv.calculateStd(recalls),
		MeanF1Score:   cv.calculateMean(f1Scores),
		StdF1Score:    cv.calculateStd(f1Scores),
		OverallScore:  cv.calculateOverallScore(accuracies, precisions, recalls, f1Scores),
	}
}

// calculateMean calculates the mean of a slice of values
func (cv *CrossValidator) calculateMean(values []float64) float64 {
	if len(values) == 0 {
		return 0.0
	}

	sum := 0.0
	for _, v := range values {
		sum += v
	}
	return sum / float64(len(values))
}

// calculateStd calculates the standard deviation of a slice of values
func (cv *CrossValidator) calculateStd(values []float64) float64 {
	if len(values) <= 1 {
		return 0.0
	}

	mean := cv.calculateMean(values)
	sumSquares := 0.0
	for _, v := range values {
		diff := v - mean
		sumSquares += diff * diff
	}

	return math.Sqrt(sumSquares / float64(len(values)-1))
}

// calculateOverallScore calculates an overall performance score
func (cv *CrossValidator) calculateOverallScore(accuracies, precisions, recalls, f1Scores []float64) float64 {
	if len(accuracies) == 0 {
		return 0.0
	}

	// Weighted combination of metrics
	weights := map[string]float64{
		"accuracy":  0.3,
		"precision": 0.25,
		"recall":    0.25,
		"f1_score":  0.2,
	}

	score := weights["accuracy"]*cv.calculateMean(accuracies) +
		weights["precision"]*cv.calculateMean(precisions) +
		weights["recall"]*cv.calculateMean(recalls) +
		weights["f1_score"]*cv.calculateMean(f1Scores)

	return math.Max(0.0, math.Min(1.0, score))
}

// Metric implementations

// AccuracyMetric calculates classification accuracy
type AccuracyMetric struct{}

func (m *AccuracyMetric) Name() string { return "accuracy" }
func (m *AccuracyMetric) Description() string { return "Classification accuracy" }

func (m *AccuracyMetric) Calculate(predictions, labels []float64) float64 {
	if len(predictions) != len(labels) || len(predictions) == 0 {
		return 0.0
	}

	correct := 0
	for i := range predictions {
		predicted := 0.0
		if predictions[i] > 0.5 {
			predicted = 1.0
		}
		actual := 0.0
		if labels[i] > 0.5 {
			actual = 1.0
		}
		if predicted == actual {
			correct++
		}
	}

	return float64(correct) / float64(len(predictions))
}

// PrecisionMetric calculates precision
type PrecisionMetric struct{}

func (m *PrecisionMetric) Name() string { return "precision" }
func (m *PrecisionMetric) Description() string { return "Precision (positive predictive value)" }

func (m *PrecisionMetric) Calculate(predictions, labels []float64) float64 {
	if len(predictions) != len(labels) || len(predictions) == 0 {
		return 0.0
	}

	truePositives := 0
	falsePositives := 0

	for i := range predictions {
		predicted := predictions[i] > 0.5
		actual := labels[i] > 0.5

		if predicted && actual {
			truePositives++
		} else if predicted && !actual {
			falsePositives++
		}
	}

	if truePositives+falsePositives == 0 {
		return 0.0
	}

	return float64(truePositives) / float64(truePositives+falsePositives)
}

// RecallMetric calculates recall (sensitivity)
type RecallMetric struct{}

func (m *RecallMetric) Name() string { return "recall" }
func (m *RecallMetric) Description() string { return "Recall (sensitivity)" }

func (m *RecallMetric) Calculate(predictions, labels []float64) float64 {
	if len(predictions) != len(labels) || len(predictions) == 0 {
		return 0.0
	}

	truePositives := 0
	falseNegatives := 0

	for i := range predictions {
		predicted := predictions[i] > 0.5
		actual := labels[i] > 0.5

		if predicted && actual {
			truePositives++
		} else if !predicted && actual {
			falseNegatives++
		}
	}

	if truePositives+falseNegatives == 0 {
		return 0.0
	}

	return float64(truePositives) / float64(truePositives+falseNegatives)
}

// F1ScoreMetric calculates F1 score
type F1ScoreMetric struct{}

func (m *F1ScoreMetric) Name() string { return "f1_score" }
func (m *F1ScoreMetric) Description() string { return "F1 score (harmonic mean of precision and recall)" }

func (m *F1ScoreMetric) Calculate(predictions, labels []float64) float64 {
	precision := (&PrecisionMetric{}).Calculate(predictions, labels)
	recall := (&RecallMetric{}).Calculate(predictions, labels)

	if precision+recall == 0 {
		return 0.0
	}

	return 2 * (precision * recall) / (precision + recall)
}

// AUCMetric calculates Area Under the ROC Curve
type AUCMetric struct{}

func (m *AUCMetric) Name() string { return "auc" }
func (m *AUCMetric) Description() string { return "Area Under the ROC Curve" }

func (m *AUCMetric) Calculate(predictions, labels []float64) float64 {
	if len(predictions) != len(labels) || len(predictions) == 0 {
		return 0.0
	}

	// Create pairs of (prediction, label)
	type predictionPair struct {
		prediction float64
		label      float64
	}

	pairs := make([]predictionPair, len(predictions))
	for i := range predictions {
		pairs[i] = predictionPair{predictions[i], labels[i]}
	}

	// Sort by prediction score (descending)
	sort.Slice(pairs, func(i, j int) bool {
		return pairs[i].prediction > pairs[j].prediction
	})

	// Calculate AUC using trapezoidal rule
	positives := 0
	negatives := 0
	for _, pair := range pairs {
		if pair.label > 0.5 {
			positives++
		} else {
			negatives++
		}
	}

	if positives == 0 || negatives == 0 {
		return 0.5 // Random classifier performance
	}

	auc := 0.0
	truePositives := 0
	falsePositives := 0

	for _, pair := range pairs {
		if pair.label > 0.5 {
			truePositives++
		} else {
			falsePositives++
			auc += float64(truePositives)
		}
	}

	return auc / (float64(positives) * float64(negatives))
}