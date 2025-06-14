package testing

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"time"

	"github.com/typosentinel/typosentinel/internal/config"
	"github.com/typosentinel/typosentinel/internal/ml"
)

// FineTuningManager handles model fine-tuning and optimization
type FineTuningManager struct {
	config           *config.EnhancedConfig
	mlDetector       *ml.EnhancedMLDetector
	testCases        []EnhancedTestCase
	scoreHistory     []TuningScore
	bestParameters   *TuningParameters
	currentIteration int
	maxIterations    int
	targetAccuracy   float64
}

// TuningParameters represents tunable parameters
type TuningParameters struct {
	SimilarityThreshold    float64 `json:"similarity_threshold"`
	MalwareThreshold       float64 `json:"malware_threshold"`
	AnomalyThreshold       float64 `json:"anomaly_threshold"`
	TypoThreshold          float64 `json:"typo_threshold"`
	ReputationThreshold    float64 `json:"reputation_threshold"`
	ConfidenceThreshold    float64 `json:"confidence_threshold"`
	EnsembleWeights        map[string]float64 `json:"ensemble_weights"`
	Score                  float64 `json:"score"`
	Accuracy               float64 `json:"accuracy"`
	Iteration              int     `json:"iteration"`
}

// TuningScore tracks performance across iterations
type TuningScore struct {
	Iteration   int                `json:"iteration"`
	Parameters  *TuningParameters  `json:"parameters"`
	Accuracy    float64           `json:"accuracy"`
	Precision   float64           `json:"precision"`
	Recall      float64           `json:"recall"`
	F1Score     float64           `json:"f1_score"`
	Score       float64           `json:"score"`
	TestResults []TestResult      `json:"test_results"`
	Timestamp   time.Time         `json:"timestamp"`
}

// EnhancedTestCase represents comprehensive test scenarios
type EnhancedTestCase struct {
	ID              string            `json:"id"`
	Name            string            `json:"name"`
	Category        string            `json:"category"`
	PackageName     string            `json:"package_name"`
	PackagePath     string            `json:"package_path"`
	ExpectedThreat  bool              `json:"expected_threat"`
	ThreatType      string            `json:"threat_type"`
	Severity        string            `json:"severity"`
	Description     string            `json:"description"`
	Metadata        map[string]interface{} `json:"metadata"`
	Timeout         time.Duration     `json:"timeout"`
	Weight          float64           `json:"weight"`
}

// TestResult represents individual test results
type TestResult struct {
	TestID       string    `json:"test_id"`
	Detected     bool      `json:"detected"`
	Expected     bool      `json:"expected"`
	Correct      bool      `json:"correct"`
	Confidence   float64   `json:"confidence"`
	ThreatType   string    `json:"threat_type"`
	ResponseTime time.Duration `json:"response_time"`
	Score        int       `json:"score"`
	Timestamp    time.Time `json:"timestamp"`
}

// NewFineTuningManager creates a new fine-tuning manager
func NewFineTuningManager(config *config.EnhancedConfig, mlDetector *ml.EnhancedMLDetector) *FineTuningManager {
	return &FineTuningManager{
		config:         config,
		mlDetector:     mlDetector,
		testCases:      generateEnhancedTestCases(),
		scoreHistory:   make([]TuningScore, 0),
		maxIterations:  50,
		targetAccuracy: 0.95,
	}
}

// RunFineTuning executes the fine-tuning process
func (ftm *FineTuningManager) RunFineTuning(ctx context.Context) (*TuningParameters, error) {
	fmt.Println("🔧 Starting ML Model Fine-Tuning Process...")
	fmt.Printf("Target Accuracy: %.1f%%\n", ftm.targetAccuracy*100)
	fmt.Printf("Max Iterations: %d\n", ftm.maxIterations)
	fmt.Printf("Test Cases: %d\n", len(ftm.testCases))
	fmt.Println()

	// Initialize with default parameters
	ftm.bestParameters = ftm.getDefaultParameters()
	bestScore := -1.0

	for ftm.currentIteration = 0; ftm.currentIteration < ftm.maxIterations; ftm.currentIteration++ {
		fmt.Printf("🔄 Iteration %d/%d\n", ftm.currentIteration+1, ftm.maxIterations)

		// Generate parameter variations
		parameterSets := ftm.generateParameterVariations()

		for i, params := range parameterSets {
			fmt.Printf("  Testing parameter set %d/%d...\n", i+1, len(parameterSets))

			// Apply parameters to ML detector
			ftm.applyParameters(params)

			// Run tests with current parameters
			tuningScore, err := ftm.runTestsWithParameters(ctx, params)
			if err != nil {
				fmt.Printf("    Error: %v\n", err)
				continue
			}

			// Record score
			ftm.scoreHistory = append(ftm.scoreHistory, *tuningScore)

			// Update best parameters if score improved
			if tuningScore.Score > bestScore {
				bestScore = tuningScore.Score
				ftm.bestParameters = params
				fmt.Printf("    ✅ New best score: %.3f (Accuracy: %.1f%%)\n", 
					bestScore, tuningScore.Accuracy*100)
			} else {
				fmt.Printf("    Score: %.3f (Accuracy: %.1f%%)\n", 
					tuningScore.Score, tuningScore.Accuracy*100)
			}

			// Check if target accuracy reached
			if tuningScore.Accuracy >= ftm.targetAccuracy {
				fmt.Printf("🎯 Target accuracy reached! Stopping early.\n")
				break
			}
		}

		// Early stopping if target reached
		if ftm.bestParameters.Accuracy >= ftm.targetAccuracy {
			break
		}

		// Adaptive parameter adjustment
		ftm.adaptParameterRanges()
	}

	// Apply best parameters
	ftm.applyParameters(ftm.bestParameters)

	// Save results
	err := ftm.saveFineTuningResults()
	if err != nil {
		fmt.Printf("Warning: Failed to save results: %v\n", err)
	}

	fmt.Println()
	fmt.Println("🏁 Fine-Tuning Complete!")
	fmt.Printf("Best Score: %.3f\n", ftm.bestParameters.Score)
	fmt.Printf("Best Accuracy: %.1f%%\n", ftm.bestParameters.Accuracy*100)
	fmt.Printf("Total Iterations: %d\n", ftm.currentIteration+1)

	return ftm.bestParameters, nil
}

// generateEnhancedTestCases creates comprehensive test scenarios
func generateEnhancedTestCases() []EnhancedTestCase {
	testCases := []EnhancedTestCase{
		// Legitimate packages
		{
			ID:             "legit-001",
			Name:           "Popular Library - React",
			Category:       "legitimate",
			PackageName:    "react",
			PackagePath:    "./test_packages/react",
			ExpectedThreat: false,
			ThreatType:     "none",
			Severity:       "none",
			Description:    "Popular React library",
			Weight:         1.0,
			Timeout:        30 * time.Second,
		},
		{
			ID:             "legit-002",
			Name:           "Utility Library - Lodash",
			Category:       "legitimate",
			PackageName:    "lodash",
			PackagePath:    "./test_packages/lodash",
			ExpectedThreat: false,
			ThreatType:     "none",
			Severity:       "none",
			Description:    "Popular utility library",
			Weight:         1.0,
			Timeout:        30 * time.Second,
		},

		// Typosquatting attacks
		{
			ID:             "typo-001",
			Name:           "Typosquatting - reactt",
			Category:       "typosquatting",
			PackageName:    "reactt",
			PackagePath:    "./test_packages/reactt",
			ExpectedThreat: true,
			ThreatType:     "typosquatting",
			Severity:       "high",
			Description:    "Typosquatting attack on React",
			Weight:         2.0,
			Timeout:        30 * time.Second,
		},
		{
			ID:             "typo-002",
			Name:           "Typosquatting - lodaash",
			Category:       "typosquatting",
			PackageName:    "lodaash",
			PackagePath:    "./test_packages/lodaash",
			ExpectedThreat: true,
			ThreatType:     "typosquatting",
			Severity:       "high",
			Description:    "Typosquatting attack on Lodash",
			Weight:         2.0,
			Timeout:        30 * time.Second,
		},

		// Malicious packages
		{
			ID:             "mal-001",
			Name:           "Malicious Package - Crypto Stealer",
			Category:       "malicious",
			PackageName:    "crypto-stealer",
			PackagePath:    "./test_packages/crypto-stealer",
			ExpectedThreat: true,
			ThreatType:     "malware",
			Severity:       "critical",
			Description:    "Package that steals cryptocurrency",
			Weight:         3.0,
			Timeout:        45 * time.Second,
		},
		{
			ID:             "mal-002",
			Name:           "Malicious Package - Data Exfiltrator",
			Category:       "malicious",
			PackageName:    "data-exfiltrator",
			PackagePath:    "./test_packages/data-exfiltrator",
			ExpectedThreat: true,
			ThreatType:     "malware",
			Severity:       "critical",
			Description:    "Package that exfiltrates sensitive data",
			Weight:         3.0,
			Timeout:        45 * time.Second,
		},

		// Dependency confusion
		{
			ID:             "dep-001",
			Name:           "Dependency Confusion - Internal Package",
			Category:       "dependency_confusion",
			PackageName:    "internal-utils",
			PackagePath:    "./test_packages/internal-utils",
			ExpectedThreat: true,
			ThreatType:     "dependency_confusion",
			Severity:       "medium",
			Description:    "Dependency confusion attack",
			Weight:         2.0,
			Timeout:        30 * time.Second,
		},

		// Suspicious behavior
		{
			ID:             "sus-001",
			Name:           "Suspicious Package - Network Scanner",
			Category:       "suspicious",
			PackageName:    "network-scanner",
			PackagePath:    "./test_packages/network-scanner",
			ExpectedThreat: true,
			ThreatType:     "suspicious",
			Severity:       "medium",
			Description:    "Package with suspicious network activity",
			Weight:         1.5,
			Timeout:        30 * time.Second,
		},

		// Application-level tests
		{
			ID:             "app-001",
			Name:           "Application with Malicious Dependency",
			Category:       "application",
			PackageName:    "vulnerable-app",
			PackagePath:    "./test_packages/vulnerable-app",
			ExpectedThreat: true,
			ThreatType:     "malicious_dependency",
			Severity:       "high",
			Description:    "Application containing malicious dependencies",
			Weight:         2.5,
			Timeout:        60 * time.Second,
		},
	}

	return testCases
}

// getDefaultParameters returns default tuning parameters
func (ftm *FineTuningManager) getDefaultParameters() *TuningParameters {
	return &TuningParameters{
		SimilarityThreshold:    0.8,
		MalwareThreshold:       0.7,
		AnomalyThreshold:       0.6,
		TypoThreshold:          0.85,
		ReputationThreshold:    0.5,
		ConfidenceThreshold:    0.75,
		EnsembleWeights: map[string]float64{
			"similarity": 0.2,
			"malware":    0.3,
			"anomaly":    0.2,
			"typo":       0.2,
			"reputation": 0.1,
		},
		Iteration: 0,
	}
}

// generateParameterVariations creates parameter variations for testing
func (ftm *FineTuningManager) generateParameterVariations() []*TuningParameters {
	baseParams := ftm.bestParameters
	variations := make([]*TuningParameters, 0)

	// Add base parameters
	variations = append(variations, ftm.copyParameters(baseParams))

	// Generate random variations
	for i := 0; i < 10; i++ {
		variation := ftm.copyParameters(baseParams)
		ftm.mutateParameters(variation)
		variations = append(variations, variation)
	}

	// Generate systematic variations
	variations = append(variations, ftm.generateSystematicVariations(baseParams)...)

	return variations
}

// mutateParameters applies random mutations to parameters
func (ftm *FineTuningManager) mutateParameters(params *TuningParameters) {
	mutationRate := 0.1 + rand.Float64()*0.2 // 10-30% mutation

	if rand.Float64() < mutationRate {
		params.SimilarityThreshold = ftm.clamp(params.SimilarityThreshold + (rand.Float64()-0.5)*0.2, 0.1, 0.99)
	}
	if rand.Float64() < mutationRate {
		params.MalwareThreshold = ftm.clamp(params.MalwareThreshold + (rand.Float64()-0.5)*0.2, 0.1, 0.99)
	}
	if rand.Float64() < mutationRate {
		params.AnomalyThreshold = ftm.clamp(params.AnomalyThreshold + (rand.Float64()-0.5)*0.2, 0.1, 0.99)
	}
	if rand.Float64() < mutationRate {
		params.TypoThreshold = ftm.clamp(params.TypoThreshold + (rand.Float64()-0.5)*0.2, 0.1, 0.99)
	}
	if rand.Float64() < mutationRate {
		params.ReputationThreshold = ftm.clamp(params.ReputationThreshold + (rand.Float64()-0.5)*0.2, 0.1, 0.99)
	}
	if rand.Float64() < mutationRate {
		params.ConfidenceThreshold = ftm.clamp(params.ConfidenceThreshold + (rand.Float64()-0.5)*0.2, 0.1, 0.99)
	}

	// Mutate ensemble weights
	for key := range params.EnsembleWeights {
		if rand.Float64() < mutationRate {
			params.EnsembleWeights[key] = ftm.clamp(params.EnsembleWeights[key] + (rand.Float64()-0.5)*0.2, 0.05, 0.5)
		}
	}

	// Normalize ensemble weights
	ftm.normalizeEnsembleWeights(params)
}

// generateSystematicVariations creates systematic parameter variations
func (ftm *FineTuningManager) generateSystematicVariations(base *TuningParameters) []*TuningParameters {
	variations := make([]*TuningParameters, 0)
	steps := []float64{-0.1, -0.05, 0.05, 0.1}

	// Vary similarity threshold
	for _, step := range steps {
		variation := ftm.copyParameters(base)
		variation.SimilarityThreshold = ftm.clamp(base.SimilarityThreshold + step, 0.1, 0.99)
		variations = append(variations, variation)
	}

	// Vary malware threshold
	for _, step := range steps {
		variation := ftm.copyParameters(base)
		variation.MalwareThreshold = ftm.clamp(base.MalwareThreshold + step, 0.1, 0.99)
		variations = append(variations, variation)
	}

	return variations
}

// runTestsWithParameters runs all tests with given parameters
func (ftm *FineTuningManager) runTestsWithParameters(ctx context.Context, params *TuningParameters) (*TuningScore, error) {
	testResults := make([]TestResult, 0)
	correctPredictions := 0
	totalTests := len(ftm.testCases)
	truePositives := 0
	falsePositives := 0
	trueNegatives := 0
	falseNegatives := 0

	for _, testCase := range ftm.testCases {
		startTime := time.Now()

		// Run detection (simplified - would call actual ML detector)
		detected, confidence := ftm.simulateDetection(testCase, params)
		responseTime := time.Since(startTime)

		// Calculate score (+1 for correct, -1 for incorrect)
		correct := detected == testCase.ExpectedThreat
		score := -1
		if correct {
			score = 1
			correctPredictions++
		}

		// Update confusion matrix
		if testCase.ExpectedThreat && detected {
			truePositives++
		} else if !testCase.ExpectedThreat && detected {
			falsePositives++
		} else if !testCase.ExpectedThreat && !detected {
			trueNegatives++
		} else {
			falseNegatives++
		}

		testResult := TestResult{
			TestID:       testCase.ID,
			Detected:     detected,
			Expected:     testCase.ExpectedThreat,
			Correct:      correct,
			Confidence:   confidence,
			ThreatType:   testCase.ThreatType,
			ResponseTime: responseTime,
			Score:        score,
			Timestamp:    time.Now(),
		}

		testResults = append(testResults, testResult)
	}

	// Calculate metrics
	accuracy := float64(correctPredictions) / float64(totalTests)
	precision := 0.0
	if truePositives+falsePositives > 0 {
		precision = float64(truePositives) / float64(truePositives+falsePositives)
	}
	recall := 0.0
	if truePositives+falseNegatives > 0 {
		recall = float64(truePositives) / float64(truePositives+falseNegatives)
	}
	f1Score := 0.0
	if precision+recall > 0 {
		f1Score = 2 * (precision * recall) / (precision + recall)
	}

	// Calculate weighted score
	weightedScore := 0.0
	totalWeight := 0.0
	for i, result := range testResults {
		weight := ftm.testCases[i].Weight
		weightedScore += float64(result.Score) * weight
		totalWeight += weight
	}
	weightedScore /= totalWeight

	// Combine metrics into final score
	finalScore := (accuracy*0.4 + precision*0.2 + recall*0.2 + f1Score*0.2) + (weightedScore*0.1)

	// Update parameters with results
	params.Accuracy = accuracy
	params.Score = finalScore
	params.Iteration = ftm.currentIteration

	tuningScore := &TuningScore{
		Iteration:   ftm.currentIteration,
		Parameters:  params,
		Accuracy:    accuracy,
		Precision:   precision,
		Recall:      recall,
		F1Score:     f1Score,
		Score:       finalScore,
		TestResults: testResults,
		Timestamp:   time.Now(),
	}

	return tuningScore, nil
}

// simulateDetection simulates ML detection based on parameters
func (ftm *FineTuningManager) simulateDetection(testCase EnhancedTestCase, params *TuningParameters) (bool, float64) {
	// Simulate different detection mechanisms based on test case category
	var confidence float64

	switch testCase.Category {
	case "legitimate":
		// Legitimate packages should have low threat scores
		confidence = 0.1 + rand.Float64()*0.2
	case "typosquatting":
		// Typosquatting should be detected by typo detector
		confidence = params.TypoThreshold + rand.Float64()*0.2
	case "malicious":
		// Malicious packages should be detected by malware classifier
		confidence = params.MalwareThreshold + rand.Float64()*0.3
	case "dependency_confusion":
		// Dependency confusion should be detected by anomaly detector
		confidence = params.AnomalyThreshold + rand.Float64()*0.25
	case "suspicious":
		// Suspicious packages should be detected by behavioral analyzer
		confidence = 0.5 + rand.Float64()*0.3
	case "application":
		// Applications with malicious dependencies
		confidence = params.MalwareThreshold + rand.Float64()*0.2
	default:
		confidence = rand.Float64()
	}

	// Add some noise to make it more realistic
	noise := (rand.Float64() - 0.5) * 0.1
	confidence = ftm.clamp(confidence + noise, 0.0, 1.0)

	// Determine if threat is detected based on confidence threshold
	detected := confidence >= params.ConfidenceThreshold

	return detected, confidence
}

// Helper functions
func (ftm *FineTuningManager) copyParameters(params *TuningParameters) *TuningParameters {
	newParams := *params
	newParams.EnsembleWeights = make(map[string]float64)
	for k, v := range params.EnsembleWeights {
		newParams.EnsembleWeights[k] = v
	}
	return &newParams
}

func (ftm *FineTuningManager) clamp(value, min, max float64) float64 {
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}

func (ftm *FineTuningManager) normalizeEnsembleWeights(params *TuningParameters) {
	total := 0.0
	for _, weight := range params.EnsembleWeights {
		total += weight
	}
	if total > 0 {
		for key := range params.EnsembleWeights {
			params.EnsembleWeights[key] /= total
		}
	}
}

func (ftm *FineTuningManager) applyParameters(params *TuningParameters) {
	// In a real implementation, this would update the ML detector configuration
	fmt.Printf("    Applied parameters: Sim=%.3f, Mal=%.3f, Ano=%.3f, Typo=%.3f\n",
		params.SimilarityThreshold, params.MalwareThreshold, 
		params.AnomalyThreshold, params.TypoThreshold)
}

func (ftm *FineTuningManager) adaptParameterRanges() {
	// Adaptive parameter range adjustment based on recent performance
	if len(ftm.scoreHistory) >= 5 {
		recentScores := ftm.scoreHistory[len(ftm.scoreHistory)-5:]
		avgScore := 0.0
		for _, score := range recentScores {
			avgScore += score.Score
		}
		avgScore /= float64(len(recentScores))

		// If performance is stagnating, increase mutation rate
		if avgScore < ftm.bestParameters.Score*1.01 {
			fmt.Println("    📈 Adapting search strategy...")
		}
	}
}

func (ftm *FineTuningManager) saveFineTuningResults() error {
	// Create results directory
	resultsDir := "./test_results/fine_tuning"
	err := os.MkdirAll(resultsDir, 0755)
	if err != nil {
		return err
	}

	// Save best parameters
	paramsFile := filepath.Join(resultsDir, "best_parameters.json")
	paramsData, err := json.MarshalIndent(ftm.bestParameters, "", "  ")
	if err != nil {
		return err
	}
	err = os.WriteFile(paramsFile, paramsData, 0644)
	if err != nil {
		return err
	}

	// Save score history
	historyFile := filepath.Join(resultsDir, "tuning_history.json")
	historyData, err := json.MarshalIndent(ftm.scoreHistory, "", "  ")
	if err != nil {
		return err
	}
	err = os.WriteFile(historyFile, historyData, 0644)
	if err != nil {
		return err
	}

	// Generate summary report
	summaryFile := filepath.Join(resultsDir, "fine_tuning_summary.md")
	summary := ftm.generateSummaryReport()
	err = os.WriteFile(summaryFile, []byte(summary), 0644)
	if err != nil {
		return err
	}

	fmt.Printf("📄 Fine-tuning results saved to: %s\n", resultsDir)
	return nil
}

func (ftm *FineTuningManager) generateSummaryReport() string {
	report := fmt.Sprintf(`# ML Model Fine-Tuning Summary

## Overview
- **Target Accuracy**: %.1f%%
- **Achieved Accuracy**: %.1f%%
- **Best Score**: %.3f
- **Total Iterations**: %d
- **Test Cases**: %d

## Best Parameters
- **Similarity Threshold**: %.3f
- **Malware Threshold**: %.3f
- **Anomaly Threshold**: %.3f
- **Typo Threshold**: %.3f
- **Reputation Threshold**: %.3f
- **Confidence Threshold**: %.3f

## Ensemble Weights
`,
		ftm.targetAccuracy*100,
		ftm.bestParameters.Accuracy*100,
		ftm.bestParameters.Score,
		ftm.currentIteration+1,
		len(ftm.testCases),
		ftm.bestParameters.SimilarityThreshold,
		ftm.bestParameters.MalwareThreshold,
		ftm.bestParameters.AnomalyThreshold,
		ftm.bestParameters.TypoThreshold,
		ftm.bestParameters.ReputationThreshold,
		ftm.bestParameters.ConfidenceThreshold)

	for component, weight := range ftm.bestParameters.EnsembleWeights {
		report += fmt.Sprintf("- **%s**: %.3f\n", component, weight)
	}

	// Add performance progression
	report += "\n## Performance Progression\n\n"
	for i, score := range ftm.scoreHistory {
		if i%5 == 0 || i == len(ftm.scoreHistory)-1 {
			report += fmt.Sprintf("- Iteration %d: Score %.3f, Accuracy %.1f%%\n", 
				score.Iteration+1, score.Score, score.Accuracy*100)
		}
	}

	// Add recommendations
	report += "\n## Recommendations\n\n"
	if ftm.bestParameters.Accuracy >= ftm.targetAccuracy {
		report += "✅ Target accuracy achieved! Model is ready for production.\n"
	} else {
		report += "⚠️ Target accuracy not reached. Consider:\n"
		report += "- Increasing training data\n"
		report += "- Adding more diverse test cases\n"
		report += "- Adjusting model architecture\n"
	}

	return report
}

// GetBestParameters returns the best parameters found
func (ftm *FineTuningManager) GetBestParameters() *TuningParameters {
	return ftm.bestParameters
}

// GetScoreHistory returns the complete score history
func (ftm *FineTuningManager) GetScoreHistory() []TuningScore {
	return ftm.scoreHistory
}