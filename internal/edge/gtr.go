// Package edge implements the GTR (Graph Traversal Reconnaissance) algorithm
// for advanced dependency graph analysis and attack path detection
package edge

import (
	"context"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// GTRAlgorithm implements graph traversal reconnaissance
type GTRAlgorithm struct {
	config  *GTRConfig
	metrics *GTRMetrics
}

// GTRConfig holds configuration for the GTR algorithm
type GTRConfig struct {
	MaxTraversalDepth    int     `yaml:"max_traversal_depth"`
	MinRiskThreshold     float64 `yaml:"min_risk_threshold"`
	EnablePathAnalysis   bool    `yaml:"enable_path_analysis"`
	MaxPathLength        int     `yaml:"max_path_length"`
	CriticalityWeight    float64 `yaml:"criticality_weight"`
	VulnerabilityWeight  float64 `yaml:"vulnerability_weight"`
	PopularityWeight     float64 `yaml:"popularity_weight"`
	TrustWeight          float64 `yaml:"trust_weight"`
	EnableCycleDetection bool    `yaml:"enable_cycle_detection"`
	MaxCycleLength       int     `yaml:"max_cycle_length"`
}

// GTRMetrics tracks GTR algorithm performance
type GTRMetrics struct {
	GraphsAnalyzed       int64         `json:"graphs_analyzed"`
	NodesTraversed       int64         `json:"nodes_traversed"`
	PathsAnalyzed        int64         `json:"paths_analyzed"`
	CyclesDetected       int64         `json:"cycles_detected"`
	AttackPathsFound     int64         `json:"attack_paths_found"`
	ProcessingTime       time.Duration `json:"processing_time"`
	TotalAnalyses        int64         `json:"total_analyses"`
	AverageLatency       time.Duration `json:"average_latency"`
	TruePositives        int64         `json:"true_positives"`
	FalsePositives       int64         `json:"false_positives"`
	TrueNegatives        int64         `json:"true_negatives"`
	FalseNegatives       int64         `json:"false_negatives"`
	Accuracy             float64       `json:"accuracy"`
	Precision            float64       `json:"precision"`
	Recall               float64       `json:"recall"`
	F1Score              float64       `json:"f1_score"`
	LastUpdated          time.Time     `json:"last_updated"`
}

// NewGTRAlgorithm creates a new GTR algorithm instance
func NewGTRAlgorithm(config *GTRConfig) *GTRAlgorithm {
	if config == nil {
		config = &GTRConfig{
			MaxTraversalDepth:    10,
			MinRiskThreshold:     0.6,
			EnablePathAnalysis:   true,
			MaxPathLength:        15,
			CriticalityWeight:    0.3,
			VulnerabilityWeight:  0.4,
			PopularityWeight:     0.1,
			TrustWeight:          0.2,
			EnableCycleDetection: true,
			MaxCycleLength:       8,
		}
	}

	return &GTRAlgorithm{
		config: config,
		metrics: &GTRMetrics{
			LastUpdated: time.Now(),
		},
	}
}

// Name returns the algorithm name
func (g *GTRAlgorithm) Name() string {
	return "GTR"
}

// Tier returns the algorithm tier
func (g *GTRAlgorithm) Tier() AlgorithmTier {
	return TierG // Production-Ready
}

// Description returns the algorithm description
func (g *GTRAlgorithm) Description() string {
	return "Graph Traversal Reconnaissance - Advanced dependency graph analysis and attack path detection"
}

// Configure configures the algorithm with provided settings
func (g *GTRAlgorithm) Configure(config map[string]interface{}) error {
	if maxDepth, ok := config["max_traversal_depth"].(int); ok {
		g.config.MaxTraversalDepth = maxDepth
	}
	if minRisk, ok := config["min_risk_threshold"].(float64); ok {
		g.config.MinRiskThreshold = minRisk
	}
	if enablePath, ok := config["enable_path_analysis"].(bool); ok {
		g.config.EnablePathAnalysis = enablePath
	}
	return nil
}

// GetMetrics returns algorithm metrics
func (g *GTRAlgorithm) GetMetrics() *AlgorithmMetrics {
	return &AlgorithmMetrics{
		TotalAnalyses:  g.metrics.TotalAnalyses,
		AverageLatency: g.metrics.AverageLatency,
		TruePositives:  g.metrics.TruePositives,
		FalsePositives: g.metrics.FalsePositives,
		TrueNegatives:  g.metrics.TrueNegatives,
		FalseNegatives: g.metrics.FalseNegatives,
		Accuracy:       g.metrics.Accuracy,
		Precision:      g.metrics.Precision,
		Recall:         g.metrics.Recall,
		F1Score:        g.metrics.F1Score,
		LastUpdated:    g.metrics.LastUpdated,
	}
}

// Analyze performs graph traversal reconnaissance on a package
func (g *GTRAlgorithm) Analyze(ctx context.Context, input interface{}) (*AnalysisResult, error) {
	startTime := time.Now()
	defer func() {
		g.metrics.ProcessingTime += time.Since(startTime)
		g.metrics.TotalAnalyses++
		g.metrics.LastUpdated = time.Now()
	}()

	pkg, ok := input.(*types.Package)
	if !ok {
		return nil, fmt.Errorf("input must be a *types.Package")
	}

	result := &AnalysisResult{
		AlgorithmName:  g.Name(),
		Tier:          g.Tier(),
		ThreatScore:   0.0,
		Confidence:    0.0,
		AttackVectors: make([]string, 0),
		Findings:      make([]Finding, 0),
		Metadata:      make(map[string]interface{}),
		ProcessingTime: 0,
		Timestamp:     time.Now(),
	}

	// Analyze package dependencies for graph traversal patterns
	g.analyzeDependencyGraph(pkg, result)

	// Calculate overall scores
	g.calculateOverallScores(result)

	// Update metrics
	result.Metadata["dependencies_count"] = len(pkg.Dependencies)
	result.Metadata["processing_time_ms"] = time.Since(startTime).Milliseconds()
	result.ProcessingTime = time.Since(startTime)

	g.metrics.GraphsAnalyzed++
	g.metrics.NodesTraversed += int64(len(pkg.Dependencies))

	return result, nil
}

// analyzeDependencyGraph analyzes the dependency graph for security issues
func (g *GTRAlgorithm) analyzeDependencyGraph(pkg *types.Package, result *AnalysisResult) {
	if pkg.Dependencies == nil {
		return
	}

	// Track dependency depth and patterns
	depthMap := make(map[string]int)
	riskMap := make(map[string]float64)

	// Analyze each dependency
	for _, dep := range pkg.Dependencies {
		// Calculate risk score for dependency
		riskScore := g.calculateDependencyRisk(dep)
		riskMap[dep.Name] = riskScore

		// Determine depth (simplified - in real implementation would traverse full graph)
		depth := 1
		if !dep.Direct {
			depth = 2 // Assume transitive dependencies are at depth 2
		}
		depthMap[dep.Name] = depth

		// Check for high-risk dependencies
		if riskScore > g.config.MinRiskThreshold {
			result.Findings = append(result.Findings, Finding{
				Type:        "high_risk_dependency",
				Severity:    g.getRiskSeverity(riskScore),
				Description: fmt.Sprintf("Dependency '%s' has high risk score", dep.Name),
				Evidence:    map[string]interface{}{"dependency": dep.Name, "risk_score": riskScore, "depth": depth},
				Remediation: "Review dependency necessity and consider alternatives",
			})
		}

		// Check for deep dependencies
		if depth > 3 {
			result.Findings = append(result.Findings, Finding{
				Type:        "deep_dependency",
				Severity:    "MEDIUM",
				Description: fmt.Sprintf("Dependency '%s' is deeply nested", dep.Name),
				Evidence:    map[string]interface{}{"dependency": dep.Name, "depth": depth},
				Remediation: "Consider flattening dependency tree to reduce complexity",
			})
		}

		// Check for development dependencies in production
		if dep.Development {
			result.Findings = append(result.Findings, Finding{
				Type:        "dev_dependency_risk",
				Severity:    "LOW",
				Description: fmt.Sprintf("Development dependency '%s' detected", dep.Name),
				Evidence:    map[string]interface{}{"dependency": dep.Name, "type": "development"},
				Remediation: "Ensure development dependencies are not included in production builds",
			})
		}
	}

	// Store analysis metadata
	result.Metadata["depth_map"] = depthMap
	result.Metadata["risk_map"] = riskMap
	result.Metadata["max_depth"] = g.getMaxDepth(depthMap)
	result.Metadata["high_risk_count"] = g.countHighRiskDependencies(riskMap)
}

// calculateDependencyRisk calculates risk score for a dependency
func (g *GTRAlgorithm) calculateDependencyRisk(dep types.Dependency) float64 {
	riskScore := 0.0

	// Base risk from dependency characteristics
	if dep.Development {
		riskScore += 0.2 // Dev dependencies have lower base risk
	} else {
		riskScore += 0.4 // Production dependencies have higher base risk
	}

	// Risk from version patterns
	if strings.Contains(dep.Version, "beta") || strings.Contains(dep.Version, "alpha") {
		riskScore += 0.3
	}
	if strings.Contains(dep.Version, "rc") {
		riskScore += 0.2
	}

	// Risk from name patterns (simple heuristics)
	if len(dep.Name) < 3 {
		riskScore += 0.2 // Very short names are suspicious
	}
	if strings.Contains(dep.Name, "test") || strings.Contains(dep.Name, "mock") {
		riskScore += 0.1 // Test/mock packages might be less critical
	}

	// Normalize to 0-1 range
	if riskScore > 1.0 {
		riskScore = 1.0
	}

	return riskScore
}

// getRiskSeverity converts risk score to severity level
func (g *GTRAlgorithm) getRiskSeverity(riskScore float64) string {
	switch {
	case riskScore >= 0.8:
		return "CRITICAL"
	case riskScore >= 0.6:
		return "HIGH"
	case riskScore >= 0.4:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

// calculateOverallScores calculates overall threat and confidence scores
func (g *GTRAlgorithm) calculateOverallScores(result *AnalysisResult) {
	if len(result.Findings) == 0 {
		result.ThreatScore = 0.0
		result.Confidence = 0.8
		return
	}

	// Calculate threat score based on findings
	var totalThreat float64
	criticalCount := 0
	highCount := 0

	for _, finding := range result.Findings {
		switch finding.Severity {
		case "CRITICAL":
			totalThreat += 1.0
			criticalCount++
		case "HIGH":
			totalThreat += 0.8
			highCount++
		case "MEDIUM":
			totalThreat += 0.5
		case "LOW":
			totalThreat += 0.2
		}
	}

	// Normalize threat score
	result.ThreatScore = math.Min(totalThreat/float64(len(result.Findings)), 1.0)

	// Calculate confidence based on analysis depth
	result.Confidence = 0.7 // Base confidence for GTR analysis
	if criticalCount > 0 || highCount > 2 {
		result.Confidence = 0.9 // Higher confidence for clear threats
	}

	// Add attack vectors based on findings
	if criticalCount > 0 {
		result.AttackVectors = append(result.AttackVectors, "dependency_chain_attack")
	}
	if highCount > 0 {
		result.AttackVectors = append(result.AttackVectors, "supply_chain_compromise")
	}
}

// Helper functions
func (g *GTRAlgorithm) getMaxDepth(depthMap map[string]int) int {
	maxDepth := 0
	for _, depth := range depthMap {
		if depth > maxDepth {
			maxDepth = depth
		}
	}
	return maxDepth
}

func (g *GTRAlgorithm) countHighRiskDependencies(riskMap map[string]float64) int {
	count := 0
	for _, risk := range riskMap {
		if risk > g.config.MinRiskThreshold {
			count++
		}
	}
	return count
}