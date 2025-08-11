// Package edge implements cutting-edge supply chain security algorithms
// This module contains 51 advanced algorithms across three tiers:
// - Tier G: Production-Ready (19 algorithms)
// - Tier Y: Development-Ready (19 algorithms) 
// - Tier R: Research Phase (13 algorithms)
package edge

import (
	"context"
	"fmt"
	"time"

	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// AlgorithmTier represents the maturity level of an algorithm
type AlgorithmTier string

const (
	TierG AlgorithmTier = "PRODUCTION_READY"  // Tier G - Production Ready
	TierY AlgorithmTier = "DEVELOPMENT_READY" // Tier Y - Development Ready
	TierR AlgorithmTier = "RESEARCH_PHASE"    // Tier R - Research Phase
)

// Algorithm represents a generic edge algorithm interface
type Algorithm interface {
	Name() string
	Tier() AlgorithmTier
	Description() string
	Analyze(ctx context.Context, input interface{}) (*AnalysisResult, error)
	Configure(config map[string]interface{}) error
	GetMetrics() *AlgorithmMetrics
}

// AnalysisResult contains the output of an algorithm analysis
type AnalysisResult struct {
	AlgorithmName   string                 `json:"algorithm_name"`
	Tier           AlgorithmTier          `json:"tier"`
	ThreatScore    float64                `json:"threat_score"`     // 0.0 - 1.0
	Confidence     float64                `json:"confidence"`       // 0.0 - 1.0
	AttackVectors  []string               `json:"attack_vectors"`
	Findings       []Finding              `json:"findings"`
	Metadata       map[string]interface{} `json:"metadata"`
	ProcessingTime time.Duration          `json:"processing_time"`
	Timestamp      time.Time              `json:"timestamp"`
}

// Finding represents a specific security finding
type Finding struct {
	Type        string                 `json:"type"`
	Severity    string                 `json:"severity"`    // CRITICAL, HIGH, MEDIUM, LOW
	Description string                 `json:"description"`
	Evidence    map[string]interface{} `json:"evidence"`
	Remediation string                 `json:"remediation"`
}

// AlgorithmMetrics tracks performance and accuracy metrics
type AlgorithmMetrics struct {
	TotalAnalyses     int64         `json:"total_analyses"`
	AverageLatency    time.Duration `json:"average_latency"`
	TruePositives     int64         `json:"true_positives"`
	FalsePositives    int64         `json:"false_positives"`
	TrueNegatives     int64         `json:"true_negatives"`
	FalseNegatives    int64         `json:"false_negatives"`
	Accuracy          float64       `json:"accuracy"`
	Precision         float64       `json:"precision"`
	Recall            float64       `json:"recall"`
	F1Score           float64       `json:"f1_score"`
	LastUpdated       time.Time     `json:"last_updated"`
}

// EdgeEngine orchestrates all edge algorithms
type EdgeEngine struct {
	algorithms map[string]Algorithm
	config     *EdgeConfig
	metrics    *EngineMetrics
}

// EdgeConfig contains configuration for the edge engine
type EdgeConfig struct {
	EnabledTiers     []AlgorithmTier        `json:"enabled_tiers"`
	ParallelExecution bool                  `json:"parallel_execution"`
	MaxConcurrency   int                   `json:"max_concurrency"`
	Timeout          time.Duration         `json:"timeout"`
	AlgorithmConfigs map[string]interface{} `json:"algorithm_configs"`
}

// EngineMetrics tracks overall engine performance
type EngineMetrics struct {
	TotalPackagesAnalyzed int64                        `json:"total_packages_analyzed"`
	AlgorithmMetrics      map[string]*AlgorithmMetrics `json:"algorithm_metrics"`
	AverageProcessingTime time.Duration                `json:"average_processing_time"`
	ThreatDetectionRate   float64                      `json:"threat_detection_rate"`
	LastAnalysis          time.Time                    `json:"last_analysis"`
}

// NewEdgeEngine creates a new edge algorithm engine
func NewEdgeEngine(config *EdgeConfig) *EdgeEngine {
	return &EdgeEngine{
		algorithms: make(map[string]Algorithm),
		config:     config,
		metrics: &EngineMetrics{
			AlgorithmMetrics: make(map[string]*AlgorithmMetrics),
		},
	}
}

// RegisterAlgorithm adds an algorithm to the engine
func (e *EdgeEngine) RegisterAlgorithm(algorithm Algorithm) error {
	if algorithm == nil {
		return fmt.Errorf("algorithm cannot be nil")
	}
	
	name := algorithm.Name()
	if name == "" {
		return fmt.Errorf("algorithm name cannot be empty")
	}
	
	e.algorithms[name] = algorithm
	e.metrics.AlgorithmMetrics[name] = algorithm.GetMetrics()
	
	return nil
}

// AnalyzePackage runs all enabled algorithms on a package
func (e *EdgeEngine) AnalyzePackage(ctx context.Context, pkg *types.Package) (*EdgeAnalysisResult, error) {
	startTime := time.Now()
	
	result := &EdgeAnalysisResult{
		PackageName:    pkg.Name,
		PackageVersion: pkg.Version,
		Timestamp:      startTime,
		Results:        make([]*AnalysisResult, 0),
	}
	
	// Run algorithms based on configuration
	for name, algorithm := range e.algorithms {
		// Check if algorithm tier is enabled
		if !e.isTierEnabled(algorithm.Tier()) {
			continue
		}
		
		// Run algorithm with timeout
		algorithmCtx, cancel := context.WithTimeout(ctx, e.config.Timeout)
		
		analysisResult, err := algorithm.Analyze(algorithmCtx, pkg)
		cancel()
		
		if err != nil {
			// Log error but continue with other algorithms
			continue
		}
		
		result.Results = append(result.Results, analysisResult)
		
		// Update metrics
		e.updateMetrics(name, analysisResult)
	}
	
	// Calculate overall threat score
	result.OverallThreatScore = e.calculateOverallThreatScore(result.Results)
	result.ProcessingTime = time.Since(startTime)
	
	// Update engine metrics
	e.metrics.TotalPackagesAnalyzed++
	e.metrics.LastAnalysis = time.Now()
	
	return result, nil
}

// EdgeAnalysisResult contains the combined results from all algorithms
type EdgeAnalysisResult struct {
	PackageName        string             `json:"package_name"`
	PackageVersion     string             `json:"package_version"`
	OverallThreatScore float64            `json:"overall_threat_score"`
	Results            []*AnalysisResult  `json:"results"`
	ProcessingTime     time.Duration      `json:"processing_time"`
	Timestamp          time.Time          `json:"timestamp"`
}

// Helper methods

func (e *EdgeEngine) isTierEnabled(tier AlgorithmTier) bool {
	for _, enabledTier := range e.config.EnabledTiers {
		if enabledTier == tier {
			return true
		}
	}
	return false
}

func (e *EdgeEngine) calculateOverallThreatScore(results []*AnalysisResult) float64 {
	if len(results) == 0 {
		return 0.0
	}
	
	// Weighted average based on confidence
	var totalScore, totalWeight float64
	
	for _, result := range results {
		weight := result.Confidence
		totalScore += result.ThreatScore * weight
		totalWeight += weight
	}
	
	if totalWeight == 0 {
		return 0.0
	}
	
	return totalScore / totalWeight
}

func (e *EdgeEngine) updateMetrics(algorithmName string, result *AnalysisResult) {
	metrics := e.metrics.AlgorithmMetrics[algorithmName]
	if metrics == nil {
		metrics = &AlgorithmMetrics{}
		e.metrics.AlgorithmMetrics[algorithmName] = metrics
	}
	
	metrics.TotalAnalyses++
	metrics.LastUpdated = time.Now()
	
	// Update average latency
	if metrics.TotalAnalyses == 1 {
		metrics.AverageLatency = result.ProcessingTime
	} else {
		// Running average
		metrics.AverageLatency = time.Duration(
			(int64(metrics.AverageLatency)*metrics.TotalAnalyses + int64(result.ProcessingTime)) / 
			(metrics.TotalAnalyses + 1),
		)
	}
}

// GetAlgorithmNames returns all registered algorithm names
func (e *EdgeEngine) GetAlgorithmNames() []string {
	names := make([]string, 0, len(e.algorithms))
	for name := range e.algorithms {
		names = append(names, name)
	}
	return names
}

// GetMetrics returns current engine metrics
func (e *EdgeEngine) GetMetrics() *EngineMetrics {
	return e.metrics
}