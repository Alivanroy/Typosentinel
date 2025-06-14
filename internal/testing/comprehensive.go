package testing

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/typosentinel/typosentinel/internal/behavioral"
	"github.com/typosentinel/typosentinel/internal/config"
	"github.com/typosentinel/typosentinel/internal/detector"
	"github.com/typosentinel/typosentinel/internal/ml"
	"github.com/typosentinel/typosentinel/internal/static"
)

// MetricsCollector handles metrics collection during testing
type MetricsCollector struct {
	detections  []DetectionMetric
	groundTruth []GroundTruthMetric
}

type DetectionMetric struct {
	TestName     string
	Detected     bool
	ThreatType   string
	Confidence   float64
	ResponseTime time.Duration
	Timestamp    time.Time
}

type GroundTruthMetric struct {
	Detected  bool
	Expected  bool
	Timestamp time.Time
}

func NewMetricsCollector() *MetricsCollector {
	return &MetricsCollector{
		detections:  make([]DetectionMetric, 0),
		groundTruth: make([]GroundTruthMetric, 0),
	}
}

func (mc *MetricsCollector) RecordDetection(testName string, detected bool, threatType string, confidence float64, responseTime time.Duration) {
	mc.detections = append(mc.detections, DetectionMetric{
		TestName:     testName,
		Detected:     detected,
		ThreatType:   threatType,
		Confidence:   confidence,
		ResponseTime: responseTime,
		Timestamp:    time.Now(),
	})
}

func (mc *MetricsCollector) RecordGroundTruth(detected bool, expected bool) {
	mc.groundTruth = append(mc.groundTruth, GroundTruthMetric{
		Detected:  detected,
		Expected:  expected,
		Timestamp: time.Now(),
	})
}

// ComprehensiveTestSuite manages the comprehensive testing process
type ComprehensiveTestSuite struct {
	config             *config.EnhancedConfig
	staticAnalyzer     *static.StaticAnalyzer
	behavioralAnalyzer *behavioral.BehavioralAnalyzer
	mlDetector         *ml.EnhancedMLDetector
	detectionEngine    *detector.Engine
	testCases          []TestCase
	results            *TestResults
	metricsCollector   *MetricsCollector
}

// TestCase represents a single test case
type TestCase struct {
	ID                string                 `json:"id"`
	Name              string                 `json:"name"`
	Description       string                 `json:"description"`
	PackagePath       string                 `json:"package_path"`
	ExpectedThreat    bool                   `json:"expected_threat"`
	ThreatType        string                 `json:"threat_type"`
	Severity          string                 `json:"severity"`
	ExpectedIOCs      []string               `json:"expected_iocs"`
	Metadata          map[string]interface{} `json:"metadata"`
	Timeout           time.Duration          `json:"timeout"`
	RequiredDetectors []string               `json:"required_detectors"`
}

// TestResults contains comprehensive test results
type TestResults struct {
	Timestamp           time.Time                   `json:"timestamp"`
	TotalTests          int                         `json:"total_tests"`
	PassedTests         int                         `json:"passed_tests"`
	FailedTests         int                         `json:"failed_tests"`
	OverallAccuracy     float64                     `json:"overall_accuracy"`
	DetectionRate       float64                     `json:"detection_rate"`
	FalsePositiveRate   float64                     `json:"false_positive_rate"`
	FalseNegativeRate   float64                     `json:"false_negative_rate"`
	AverageResponseTime time.Duration               `json:"average_response_time"`
	DetectorResults     map[string]*DetectorResults `json:"detector_results"`
	TestCaseResults     []TestCaseResult            `json:"test_case_results"`
	PerformanceMetrics  PerformanceMetrics          `json:"performance_metrics"`
	Recommendations     []string                    `json:"recommendations"`
	Summary             TestSummary                 `json:"summary"`
}

// DetectorResults contains results for a specific detector
type DetectorResults struct {
	DetectorName        string        `json:"detector_name"`
	TotalDetections     int           `json:"total_detections"`
	CorrectDetections   int           `json:"correct_detections"`
	FalsePositives      int           `json:"false_positives"`
	FalseNegatives      int           `json:"false_negatives"`
	Accuracy            float64       `json:"accuracy"`
	Precision           float64       `json:"precision"`
	Recall              float64       `json:"recall"`
	F1Score             float64       `json:"f1_score"`
	AverageResponseTime time.Duration `json:"average_response_time"`
	ErrorRate           float64       `json:"error_rate"`
	ConfidenceScores    []float64     `json:"confidence_scores"`
}

// TestCaseResult contains results for a single test case
type TestCaseResult struct {
	TestCase           TestCase                   `json:"test_case"`
	Passed             bool                       `json:"passed"`
	Detected           bool                       `json:"detected"`
	ThreatType         string                     `json:"threat_type"`
	Confidence         float64                    `json:"confidence"`
	ResponseTime       time.Duration              `json:"response_time"`
	DetectorResults    map[string]DetectionResult `json:"detector_results"`
	IOCsFound          []string                   `json:"iocs_found"`
	ErrorMessage       string                     `json:"error_message,omitempty"`
	AdditionalMetadata map[string]interface{}     `json:"additional_metadata"`
}

// DetectionResult contains result from a specific detector
type DetectionResult struct {
	Detected     bool                   `json:"detected"`
	Confidence   float64                `json:"confidence"`
	ThreatType   string                 `json:"threat_type"`
	IOCs         []string               `json:"iocs"`
	ResponseTime time.Duration          `json:"response_time"`
	Error        string                 `json:"error,omitempty"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// PerformanceMetrics contains performance-related metrics
type PerformanceMetrics struct {
	TotalExecutionTime time.Duration `json:"total_execution_time"`
	AverageTestTime    time.Duration `json:"average_test_time"`
	MedianTestTime     time.Duration `json:"median_test_time"`
	P95TestTime        time.Duration `json:"p95_test_time"`
	P99TestTime        time.Duration `json:"p99_test_time"`
	Throughput         float64       `json:"throughput"`
	MemoryUsage        float64       `json:"memory_usage"`
	CPUUsage           float64       `json:"cpu_usage"`
	ConcurrentTests    int           `json:"concurrent_tests"`
}

// TestSummary provides a high-level summary
type TestSummary struct {
	OverallGrade       string   `json:"overall_grade"`
	EffectivenessScore float64  `json:"effectiveness_score"`
	KeyFindings        []string `json:"key_findings"`
	CriticalIssues     []string `json:"critical_issues"`
	Recommendations    []string `json:"recommendations"`
	NextSteps          []string `json:"next_steps"`
	ComplianceStatus   string   `json:"compliance_status"`
}

// NewComprehensiveTestSuite creates a new test suite
func NewComprehensiveTestSuite(configPath string) (*ComprehensiveTestSuite, error) {
	// Load configuration
	enhancedConfig, err := config.LoadEnhancedConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	// Initialize components
	staticAnalyzer, err := static.NewStaticAnalyzer(static.DefaultConfig())
	if err != nil {
		return nil, fmt.Errorf("failed to create static analyzer: %w", err)
	}

	behavioralAnalyzer, err := behavioral.NewBehavioralAnalyzer(behavioral.DefaultConfig())
	if err != nil {
		return nil, fmt.Errorf("failed to create behavioral analyzer: %w", err)
	}

	mlDetector, err := ml.NewEnhancedMLDetector(ml.DefaultEnhancedMLConfig())
	if err != nil {
		return nil, fmt.Errorf("failed to create ML detector: %w", err)
	}

	detectionEngine := detector.New(enhancedConfig.ToConfig())

	// Load test cases
	testCases, err := loadTestCases()
	if err != nil {
		return nil, fmt.Errorf("failed to load test cases: %w", err)
	}

	return &ComprehensiveTestSuite{
		config:             enhancedConfig,
		staticAnalyzer:     staticAnalyzer,
		behavioralAnalyzer: behavioralAnalyzer,
		mlDetector:         mlDetector,
		detectionEngine:    detectionEngine,
		testCases:          testCases,
		results:            &TestResults{},
		metricsCollector:   NewMetricsCollector(),
	}, nil
}

// RunComprehensiveTests executes all test cases
func (cts *ComprehensiveTestSuite) RunComprehensiveTests(ctx context.Context) (*TestResults, error) {
	startTime := time.Now()
	cts.results.Timestamp = startTime
	cts.results.TotalTests = len(cts.testCases)
	cts.results.DetectorResults = make(map[string]*DetectorResults)
	cts.results.TestCaseResults = make([]TestCaseResult, 0, len(cts.testCases))

	// Initialize detector results
	detectorNames := []string{"static", "behavioral", "ml", "yara", "typo", "anomaly"}
	for _, name := range detectorNames {
		cts.results.DetectorResults[name] = &DetectorResults{
			DetectorName:     name,
			ConfidenceScores: make([]float64, 0),
		}
	}

	// Run test cases
	for i, testCase := range cts.testCases {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		fmt.Printf("Running test case %d/%d: %s\n", i+1, len(cts.testCases), testCase.Name)
		result, err := cts.runSingleTest(ctx, testCase)
		if err != nil {
			fmt.Printf("Error running test case %s: %v\n", testCase.ID, err)
			result.ErrorMessage = err.Error()
		}

		cts.results.TestCaseResults = append(cts.results.TestCaseResults, result)
		cts.updateMetrics(result)
	}

	// Calculate final metrics
	cts.calculateFinalMetrics(time.Since(startTime))
	cts.generateRecommendations()
	cts.generateSummary()

	return cts.results, nil
}

// runSingleTest executes a single test case
func (cts *ComprehensiveTestSuite) runSingleTest(ctx context.Context, testCase TestCase) (TestCaseResult, error) {
	startTime := time.Now()
	result := TestCaseResult{
		TestCase:           testCase,
		DetectorResults:    make(map[string]DetectionResult),
		IOCsFound:          make([]string, 0),
		AdditionalMetadata: make(map[string]interface{}),
	}

	// Set timeout context
	testCtx, cancel := context.WithTimeout(ctx, testCase.Timeout)
	defer cancel()

	// Run static analysis
	if contains(testCase.RequiredDetectors, "static") || len(testCase.RequiredDetectors) == 0 {
		staticResult := cts.runStaticAnalysis(testCtx, testCase.PackagePath)
		result.DetectorResults["static"] = staticResult
	}

	// Run behavioral analysis
	if contains(testCase.RequiredDetectors, "behavioral") || len(testCase.RequiredDetectors) == 0 {
		behavioralResult := cts.runBehavioralAnalysis(testCtx, testCase.PackagePath)
		result.DetectorResults["behavioral"] = behavioralResult
	}

	// Run ML detection
	if contains(testCase.RequiredDetectors, "ml") || len(testCase.RequiredDetectors) == 0 {
		mlResult := cts.runMLDetection(testCtx, testCase.PackagePath)
		result.DetectorResults["ml"] = mlResult
	}

	// Run YARA rules
	if contains(testCase.RequiredDetectors, "yara") || len(testCase.RequiredDetectors) == 0 {
		yaraResult := cts.runYARADetection(testCtx, testCase.PackagePath)
		result.DetectorResults["yara"] = yaraResult
	}

	// Run typosquatting detection
	if contains(testCase.RequiredDetectors, "typo") || len(testCase.RequiredDetectors) == 0 {
		typoResult := cts.runTyposquattingDetection(testCtx, testCase.PackagePath)
		result.DetectorResults["typo"] = typoResult
	}

	// Run anomaly detection
	if contains(testCase.RequiredDetectors, "anomaly") || len(testCase.RequiredDetectors) == 0 {
		anomalyResult := cts.runAnomalyDetection(testCtx, testCase.PackagePath)
		result.DetectorResults["anomaly"] = anomalyResult
	}

	// Aggregate results
	result.ResponseTime = time.Since(startTime)
	result.Detected, result.ThreatType, result.Confidence = cts.aggregateDetectionResults(result.DetectorResults)
	result.Passed = (result.Detected == testCase.ExpectedThreat)

	// Collect IOCs
	for _, detectorResult := range result.DetectorResults {
		result.IOCsFound = append(result.IOCsFound, detectorResult.IOCs...)
	}

	// Record metrics
	cts.metricsCollector.RecordDetection(
		testCase.Name,
		result.Detected,
		result.ThreatType,
		result.Confidence,
		result.ResponseTime,
	)

	cts.metricsCollector.RecordGroundTruth(result.Detected, testCase.ExpectedThreat)

	return result, nil
}

// Individual detector methods
func (cts *ComprehensiveTestSuite) runStaticAnalysis(ctx context.Context, packagePath string) DetectionResult {
	startTime := time.Now()
	result := DetectionResult{
		Metadata: make(map[string]interface{}),
	}

	analysisResult, err := cts.staticAnalyzer.AnalyzePackage(ctx, packagePath)
	if err != nil {
		result.Error = err.Error()
		return result
	}

	result.Detected = analysisResult.RiskScore > 0.5
	result.Confidence = analysisResult.RiskScore
	result.ThreatType = "static_analysis"
	result.ResponseTime = time.Since(startTime)

	// Extract IOCs from findings
	for _, finding := range analysisResult.Findings {
		result.IOCs = append(result.IOCs, finding.Description)
	}

	result.Metadata["findings_count"] = len(analysisResult.Findings)
	result.Metadata["risk_score"] = analysisResult.RiskScore

	return result
}

func (cts *ComprehensiveTestSuite) runBehavioralAnalysis(ctx context.Context, packagePath string) DetectionResult {
	startTime := time.Now()
	result := DetectionResult{
		Metadata: make(map[string]interface{}),
	}

	// Start monitoring
	err := cts.behavioralAnalyzer.StartMonitoring(packagePath)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer func() {
		_, _ = cts.behavioralAnalyzer.StopMonitoring(packagePath)
	}()

	// Simulate package execution (in a safe environment)
	// This would typically involve running the package in a sandbox
	time.Sleep(2 * time.Second) // Simulate execution time

	// Get analysis from StopMonitoring
	analysis, err := cts.behavioralAnalyzer.StopMonitoring(packagePath)
	if err != nil {
		result.Error = err.Error()
		return result
	}

	result.Detected = analysis.ThreatLevel != "low"
	result.Confidence = analysis.RiskScore
	result.ThreatType = "behavioral"
	result.ResponseTime = time.Since(startTime)

	// Extract IOCs from behavioral patterns
	for _, pattern := range analysis.PatternMatches {
		result.IOCs = append(result.IOCs, pattern.Description)
	}

	result.Metadata["threat_level"] = analysis.ThreatLevel
	result.Metadata["pattern_matches"] = len(analysis.PatternMatches)

	return result
}

func (cts *ComprehensiveTestSuite) runMLDetection(ctx context.Context, packagePath string) DetectionResult {
	startTime := time.Now()
	result := DetectionResult{
		Metadata: make(map[string]interface{}),
	}

	// Create package features from path
	features := &ml.EnhancedPackageFeatures{
		Name:     filepath.Base(packagePath),
		Registry: "npm", // Default to npm
	}

	analysis, err := cts.mlDetector.AnalyzePackage(ctx, features)
	if err != nil {
		result.Error = err.Error()
		return result
	}

	// Aggregate ML results
	maxConfidence := 0.0
	threatDetected := false
	threatType := "unknown"

	if len(analysis.SimilarityResults) > 0 && analysis.SimilarityResults[0].SimilarityScore > 0.8 {
		threatDetected = true
		maxConfidence = math.Max(maxConfidence, analysis.SimilarityResults[0].Confidence)
		threatType = "similarity"
	}

	if analysis.MalwareClassification.IsMalware {
		threatDetected = true
		maxConfidence = math.Max(maxConfidence, analysis.MalwareClassification.Confidence)
		threatType = "malware"
	}

	if analysis.AnomalyDetection.IsAnomalous {
		threatDetected = true
		maxConfidence = math.Max(maxConfidence, analysis.AnomalyDetection.AnomalyScore)
		threatType = "anomaly"
	}

	result.Detected = threatDetected
	result.Confidence = maxConfidence
	result.ThreatType = threatType
	result.ResponseTime = time.Since(startTime)

	if len(analysis.SimilarityResults) > 0 {
		result.Metadata["similarity_score"] = analysis.SimilarityResults[0].Confidence
	}
	result.Metadata["malware_score"] = analysis.MalwareClassification.Confidence
	result.Metadata["anomaly_score"] = analysis.AnomalyDetection.AnomalyScore

	return result
}

func (cts *ComprehensiveTestSuite) runYARADetection(ctx context.Context, packagePath string) DetectionResult {
	startTime := time.Now()
	result := DetectionResult{
		Metadata: make(map[string]interface{}),
	}

	// This would integrate with YARA engine
	// For now, simulate YARA detection based on file patterns
	matches, err := cts.simulateYARADetection(packagePath)
	if err != nil {
		result.Error = err.Error()
		return result
	}

	result.Detected = len(matches) > 0
	result.Confidence = float64(len(matches)) / 10.0 // Normalize
	if result.Confidence > 1.0 {
		result.Confidence = 1.0
	}
	result.ThreatType = "yara"
	result.ResponseTime = time.Since(startTime)
	result.IOCs = matches

	result.Metadata["matches_count"] = len(matches)

	return result
}

func (cts *ComprehensiveTestSuite) runTyposquattingDetection(ctx context.Context, packagePath string) DetectionResult {
	startTime := time.Now()
	result := DetectionResult{
		Metadata: make(map[string]interface{}),
	}

	// Extract package name from path
	packageName := filepath.Base(packagePath)

	// Check for typosquatting patterns
	isTyposquatting, confidence, similarPackages := cts.detectTyposquatting(packageName)

	result.Detected = isTyposquatting
	result.Confidence = confidence
	result.ThreatType = "typosquatting"
	result.ResponseTime = time.Since(startTime)

	if isTyposquatting {
		result.IOCs = append(result.IOCs, fmt.Sprintf("Potential typosquatting of: %v", similarPackages))
	}

	result.Metadata["similar_packages"] = similarPackages
	result.Metadata["typo_confidence"] = confidence

	return result
}

func (cts *ComprehensiveTestSuite) runAnomalyDetection(ctx context.Context, packagePath string) DetectionResult {
	startTime := time.Now()
	result := DetectionResult{
		Metadata: make(map[string]interface{}),
	}

	// Analyze package for anomalies
	anomalies, score := cts.detectAnomalies(packagePath)

	result.Detected = score > 0.7
	result.Confidence = score
	result.ThreatType = "anomaly"
	result.ResponseTime = time.Since(startTime)

	for _, anomaly := range anomalies {
		result.IOCs = append(result.IOCs, anomaly)
	}

	result.Metadata["anomaly_score"] = score
	result.Metadata["anomalies_count"] = len(anomalies)

	return result
}

// Helper methods
func (cts *ComprehensiveTestSuite) aggregateDetectionResults(results map[string]DetectionResult) (bool, string, float64) {
	maxConfidence := 0.0
	threatType := "unknown"
	detectionCount := 0

	for _, result := range results {
		if result.Detected {
			detectionCount++
			if result.Confidence > maxConfidence {
				maxConfidence = result.Confidence
				threatType = result.ThreatType
			}
		}
	}

	// Require at least 2 detectors to agree for high confidence
	detected := detectionCount >= 2 || maxConfidence > 0.8

	return detected, threatType, maxConfidence
}

func (cts *ComprehensiveTestSuite) updateMetrics(result TestCaseResult) {
	if result.Passed {
		cts.results.PassedTests++
	} else {
		cts.results.FailedTests++
	}

	// Update detector-specific metrics
	for detectorName, detectorResult := range result.DetectorResults {
		detectorMetrics := cts.results.DetectorResults[detectorName]
		detectorMetrics.TotalDetections++
		detectorMetrics.ConfidenceScores = append(detectorMetrics.ConfidenceScores, detectorResult.Confidence)

		if detectorResult.Detected == result.TestCase.ExpectedThreat {
			detectorMetrics.CorrectDetections++
		} else if detectorResult.Detected && !result.TestCase.ExpectedThreat {
			detectorMetrics.FalsePositives++
		} else if !detectorResult.Detected && result.TestCase.ExpectedThreat {
			detectorMetrics.FalseNegatives++
		}

		// Update response time
		if detectorMetrics.AverageResponseTime == 0 {
			detectorMetrics.AverageResponseTime = detectorResult.ResponseTime
		} else {
			// Simple moving average
			detectorMetrics.AverageResponseTime = (detectorMetrics.AverageResponseTime + detectorResult.ResponseTime) / 2
		}
	}
}

func (cts *ComprehensiveTestSuite) calculateFinalMetrics(totalTime time.Duration) {
	// Calculate overall metrics
	cts.results.OverallAccuracy = float64(cts.results.PassedTests) / float64(cts.results.TotalTests)

	// Calculate detector-specific metrics
	for _, detectorMetrics := range cts.results.DetectorResults {
		if detectorMetrics.TotalDetections > 0 {
			detectorMetrics.Accuracy = float64(detectorMetrics.CorrectDetections) / float64(detectorMetrics.TotalDetections)

			tp := float64(detectorMetrics.CorrectDetections - detectorMetrics.FalsePositives)
			fp := float64(detectorMetrics.FalsePositives)
			fn := float64(detectorMetrics.FalseNegatives)

			if tp+fp > 0 {
				detectorMetrics.Precision = tp / (tp + fp)
			}
			if tp+fn > 0 {
				detectorMetrics.Recall = tp / (tp + fn)
			}
			if detectorMetrics.Precision+detectorMetrics.Recall > 0 {
				detectorMetrics.F1Score = 2 * (detectorMetrics.Precision * detectorMetrics.Recall) / (detectorMetrics.Precision + detectorMetrics.Recall)
			}
		}
	}

	// Calculate performance metrics
	cts.results.PerformanceMetrics.TotalExecutionTime = totalTime
	cts.results.PerformanceMetrics.AverageTestTime = totalTime / time.Duration(cts.results.TotalTests)
	cts.results.PerformanceMetrics.Throughput = float64(cts.results.TotalTests) / totalTime.Seconds()
}

func (cts *ComprehensiveTestSuite) generateRecommendations() {
	recommendations := make([]string, 0)

	if cts.results.OverallAccuracy < 0.99 {
		recommendations = append(recommendations, "Overall accuracy below 99% target - review failed test cases")
	}

	for detectorName, metrics := range cts.results.DetectorResults {
		if metrics.Accuracy < 0.95 {
			recommendations = append(recommendations, fmt.Sprintf("%s detector accuracy below 95%% - requires tuning", detectorName))
		}
		if metrics.FalsePositives > metrics.TotalDetections/20 { // > 5%
			recommendations = append(recommendations, fmt.Sprintf("%s detector has high false positive rate", detectorName))
		}
	}

	cts.results.Recommendations = recommendations
}

func (cts *ComprehensiveTestSuite) generateSummary() {
	effectivenessScore := cts.results.OverallAccuracy
	grade := "F"

	if effectivenessScore >= 0.99 {
		grade = "A+"
	} else if effectivenessScore >= 0.95 {
		grade = "A"
	} else if effectivenessScore >= 0.90 {
		grade = "B"
	} else if effectivenessScore >= 0.80 {
		grade = "C"
	} else if effectivenessScore >= 0.70 {
		grade = "D"
	}

	cts.results.Summary = TestSummary{
		OverallGrade:       grade,
		EffectivenessScore: effectivenessScore,
		KeyFindings:        cts.generateKeyFindings(),
		CriticalIssues:     cts.identifyCriticalIssues(),
		Recommendations:    cts.results.Recommendations,
		NextSteps:          cts.generateNextSteps(),
		ComplianceStatus:   cts.determineComplianceStatus(),
	}
}

// Simulation methods (would be replaced with actual implementations)
func (cts *ComprehensiveTestSuite) simulateYARADetection(packagePath string) ([]string, error) {
	matches := make([]string, 0)

	// Check for suspicious patterns in files
	err := filepath.Walk(packagePath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && (strings.HasSuffix(path, ".js") || strings.HasSuffix(path, ".py")) {
			content, err := ioutil.ReadFile(path)
			if err != nil {
				return err
			}

			contentStr := string(content)
			// Check for suspicious patterns
			suspiciousPatterns := []string{
				"eval(",
				"exec(",
				"child_process",
				"fs.writeFile",
				"crypto.createHash",
				"process.env",
				"require('http')",
				"Buffer.from",
			}

			for _, pattern := range suspiciousPatterns {
				if strings.Contains(contentStr, pattern) {
					matches = append(matches, fmt.Sprintf("Suspicious pattern '%s' in %s", pattern, path))
				}
			}
		}

		return nil
	})

	return matches, err
}

func (cts *ComprehensiveTestSuite) detectTyposquatting(packageName string) (bool, float64, []string) {
	// Popular package names to check against
	popularPackages := []string{
		"lodash", "react", "express", "axios", "moment", "jquery", "bootstrap",
		"vue", "angular", "webpack", "babel", "eslint", "typescript", "jest",
	}

	for _, popular := range popularPackages {
		similarity := calculateStringSimilarity(packageName, popular)
		if similarity > 0.8 && packageName != popular {
			return true, similarity, []string{popular}
		}
	}

	return false, 0.0, nil
}

func (cts *ComprehensiveTestSuite) detectAnomalies(packagePath string) ([]string, float64) {
	anomalies := make([]string, 0)
	score := 0.0

	// Check for unusual file structures
	fileCount := 0
	jsFileCount := 0
	binaryFileCount := 0

	filepath.Walk(packagePath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() {
			fileCount++
			if strings.HasSuffix(path, ".js") {
				jsFileCount++
			}
			if isBinaryFile(path) {
				binaryFileCount++
			}
		}

		return nil
	})

	// Anomaly checks
	if fileCount > 1000 {
		anomalies = append(anomalies, "Unusually high file count")
		score += 0.3
	}

	if binaryFileCount > 0 {
		anomalies = append(anomalies, "Contains binary files")
		score += 0.4
	}

	if jsFileCount == 0 && fileCount > 0 {
		anomalies = append(anomalies, "No JavaScript files in JS package")
		score += 0.2
	}

	return anomalies, score
}

// Utility functions
func loadTestCases() ([]TestCase, error) {
	// Load test cases from configuration or generate them
	testCases := []TestCase{
		{
			ID:                "malicious_lodahs",
			Name:              "Malicious lodahs package",
			Description:       "Test detection of the malicious lodahs typosquatting package",
			PackagePath:       "./test_packages/lodahs",
			ExpectedThreat:    true,
			ThreatType:        "typosquatting",
			Severity:          "high",
			ExpectedIOCs:      []string{"typosquatting", "malicious_code", "data_exfiltration"},
			Timeout:           30 * time.Second,
			RequiredDetectors: []string{"static", "yara", "typo"},
		},
		{
			ID:             "clean_lodash",
			Name:           "Clean lodash package",
			Description:    "Test that legitimate lodash package is not flagged",
			PackagePath:    "./test_packages/lodash",
			ExpectedThreat: false,
			ThreatType:     "none",
			Severity:       "none",
			Timeout:        30 * time.Second,
		},
		// Add more test cases...
	}

	return testCases, nil
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func calculateStringSimilarity(s1, s2 string) float64 {
	// Simple Levenshtein distance-based similarity
	maxLen := len(s1)
	if len(s2) > maxLen {
		maxLen = len(s2)
	}

	if maxLen == 0 {
		return 1.0
	}

	distance := levenshteinDistance(s1, s2)
	return 1.0 - float64(distance)/float64(maxLen)
}

func levenshteinDistance(s1, s2 string) int {
	if len(s1) == 0 {
		return len(s2)
	}
	if len(s2) == 0 {
		return len(s1)
	}

	matrix := make([][]int, len(s1)+1)
	for i := range matrix {
		matrix[i] = make([]int, len(s2)+1)
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

func min(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}

func isBinaryFile(path string) bool {
	binaryExtensions := []string{".exe", ".dll", ".so", ".dylib", ".bin", ".dat"}
	for _, ext := range binaryExtensions {
		if strings.HasSuffix(strings.ToLower(path), ext) {
			return true
		}
	}
	return false
}

func (cts *ComprehensiveTestSuite) generateKeyFindings() []string {
	findings := make([]string, 0)

	for detectorName, metrics := range cts.results.DetectorResults {
		if metrics.Accuracy > 0.95 {
			findings = append(findings, fmt.Sprintf("%s detector performing excellently (%.1f%% accuracy)", detectorName, metrics.Accuracy*100))
		} else if metrics.Accuracy < 0.80 {
			findings = append(findings, fmt.Sprintf("%s detector underperforming (%.1f%% accuracy)", detectorName, metrics.Accuracy*100))
		}
	}

	return findings
}

func (cts *ComprehensiveTestSuite) identifyCriticalIssues() []string {
	issues := make([]string, 0)

	if cts.results.OverallAccuracy < 0.90 {
		issues = append(issues, "Overall detection accuracy critically low")
	}

	for detectorName, metrics := range cts.results.DetectorResults {
		if metrics.FalseNegatives > 0 {
			issues = append(issues, fmt.Sprintf("%s detector missing threats (%d false negatives)", detectorName, metrics.FalseNegatives))
		}
	}

	return issues
}

func (cts *ComprehensiveTestSuite) generateNextSteps() []string {
	steps := make([]string, 0)

	if cts.results.OverallAccuracy < 0.99 {
		steps = append(steps, "Analyze failed test cases and improve detection rules")
		steps = append(steps, "Retrain ML models with additional data")
		steps = append(steps, "Implement ensemble voting for better accuracy")
	}

	return steps
}

func (cts *ComprehensiveTestSuite) determineComplianceStatus() string {
	if cts.results.OverallAccuracy >= 0.99 {
		return "COMPLIANT"
	} else if cts.results.OverallAccuracy >= 0.95 {
		return "PARTIALLY_COMPLIANT"
	}
	return "NON_COMPLIANT"
}

// ExportResults exports test results to file
func (cts *ComprehensiveTestSuite) ExportResults(format string, path string) error {
	switch format {
	case "json":
		return cts.exportJSON(path)
	default:
		return fmt.Errorf("unsupported export format: %s", format)
	}
}

func (cts *ComprehensiveTestSuite) exportJSON(path string) error {
	data, err := json.MarshalIndent(cts.results, "", "  ")
	if err != nil {
		return err
	}

	filename := fmt.Sprintf("%s/test_results_%s.json", path, time.Now().Format("2006-01-02_15-04-05"))
	return ioutil.WriteFile(filename, data, 0644)
}

// Main function for running comprehensive tests
func main() {
	var (
		configPath = flag.String("config", "configs/enhanced.yaml", "Path to configuration file")
		outputPath = flag.String("output", "test_results", "Path to output directory")
		format     = flag.String("format", "json", "Output format (json, yaml, html)")
		timeout    = flag.Duration("timeout", 10*time.Minute, "Test timeout")
		verbose    = flag.Bool("verbose", false, "Enable verbose output")
		fineTune   = flag.Bool("fine-tune", false, "Enable ML model fine-tuning")
		generatePackages = flag.Bool("generate-packages", false, "Generate test packages")
	)
	flag.Parse()

	if *verbose {
		// Enable verbose logging
		fmt.Println("Verbose mode enabled")
	}

	// Load configuration
	enhancedConfig, err := config.LoadEnhancedConfig(*configPath)
	if err != nil {
		fmt.Printf("Failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	// Generate test packages if requested
	if *generatePackages {
		generator := NewTestPackageGenerator("./test_packages")
		err = generator.GenerateAllTestPackages()
		if err != nil {
			fmt.Printf("Failed to generate test packages: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Test packages generated successfully")
		return
	}

	// Initialize ML detector for fine-tuning
	mlDetector, err := ml.NewEnhancedMLDetector(ml.DefaultEnhancedMLConfig())
	if err != nil {
		fmt.Printf("Failed to initialize ML detector: %v\n", err)
		os.Exit(1)
	}

	// Run fine-tuning if requested
	if *fineTune {
		fineTuningManager := NewFineTuningManager(enhancedConfig, mlDetector)
		
		ctx, cancel := context.WithTimeout(context.Background(), *timeout)
		defer cancel()
		
		bestParams, err := fineTuningManager.RunFineTuning(ctx)
		if err != nil {
			log.Fatalf("Fine-tuning failed: %v", err)
		}
		
		fmt.Printf("Fine-tuning completed! Best accuracy: %.1f%%, Score: %.3f\n", 
			bestParams.Accuracy*100, bestParams.Score)
		return
	}

	// Initialize test suite
	testSuite, err := NewComprehensiveTestSuite(*configPath)
	if err != nil {
		log.Fatalf("Failed to initialize test suite: %v", err)
	}

	// Run comprehensive tests
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	results, err := testSuite.RunComprehensiveTests(ctx)
	if err != nil {
		log.Fatalf("Test execution failed: %v", err)
	}

	// Export results
	err = testSuite.ExportResults(*format, *outputPath)
	if err != nil {
		log.Fatalf("Report generation failed: %v", err)
	}

	fmt.Printf("Comprehensive testing completed successfully. Overall accuracy: %.1f%%\n", 
		results.OverallAccuracy*100)
}

// RunFineTuning executes the ML model fine-tuning process
func (cts *ComprehensiveTestSuite) RunFineTuning(ctx context.Context, verbose bool) error {
	// Initialize fine-tuning manager
	fineTuningManager := NewFineTuningManager(cts.config, cts.mlDetector)
	
	// Run fine-tuning process
	bestParams, err := fineTuningManager.RunFineTuning(ctx)
	if err != nil {
		return fmt.Errorf("fine-tuning failed: %v", err)
	}
	
	if verbose {
		fmt.Printf("Fine-tuning completed! Best accuracy: %.1f%%, Score: %.3f\n", 
			bestParams.Accuracy*100, bestParams.Score)
	}
	
	return nil
}