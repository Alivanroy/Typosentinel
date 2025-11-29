// Package edge implements the GTR (Graph Traversal Reconnaissance) algorithm
// for advanced dependency graph analysis and attack path detection
package edge

import (
	"context"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/registry"
	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// GTRAlgorithm implements graph traversal reconnaissance
type GTRAlgorithm struct {
	config       *GTRConfig
	metrics      *GTRMetrics
	mu           sync.Mutex
	npmConnector *registry.NPMConnector
	depCache     map[string][]string
	depCacheTS   map[string]time.Time
	depMu        sync.RWMutex
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
	GraphsAnalyzed   int64         `json:"graphs_analyzed"`
	NodesTraversed   int64         `json:"nodes_traversed"`
	PathsAnalyzed    int64         `json:"paths_analyzed"`
	CyclesDetected   int64         `json:"cycles_detected"`
	AttackPathsFound int64         `json:"attack_paths_found"`
	ProcessingTime   time.Duration `json:"processing_time"`
	TotalAnalyses    int64         `json:"total_analyses"`
	AverageLatency   time.Duration `json:"average_latency"`
	TruePositives    int64         `json:"true_positives"`
	FalsePositives   int64         `json:"false_positives"`
	TrueNegatives    int64         `json:"true_negatives"`
	FalseNegatives   int64         `json:"false_negatives"`
	Accuracy         float64       `json:"accuracy"`
	Precision        float64       `json:"precision"`
	Recall           float64       `json:"recall"`
	F1Score          float64       `json:"f1_score"`
	LastUpdated      time.Time     `json:"last_updated"`
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

	g := &GTRAlgorithm{
		config: config,
		metrics: &GTRMetrics{
			LastUpdated: time.Now(),
		},
		depCache:   make(map[string][]string),
		depCacheTS: make(map[string]time.Time),
	}
	g.npmConnector = registry.NewNPMConnector(&registry.Registry{Name: "npm", URL: "https://registry.npmjs.org", Type: "npm", Enabled: true})
	return g
}

// Name returns the algorithm name
func (g *GTRAlgorithm) Name() string {
	return "GTR"
}

// Tier returns the algorithm tier
func (g *GTRAlgorithm) Tier() AlgorithmTier {
	return TierCore // Production-Ready
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
	g.mu.Lock()
	defer g.mu.Unlock()
	return &AlgorithmMetrics{
		PackagesProcessed: int(g.metrics.TotalAnalyses),
		ThreatsDetected:   int(g.metrics.AttackPathsFound),
		ProcessingTime:    g.metrics.ProcessingTime,
		Accuracy:          g.metrics.Accuracy,
		Precision:         g.metrics.Precision,
		Recall:            g.metrics.Recall,
		F1Score:           g.metrics.F1Score,
		LastUpdated:       g.metrics.LastUpdated,
	}
}

// Analyze performs graph traversal reconnaissance on a package
func (g *GTRAlgorithm) Analyze(ctx context.Context, packages []string) (*AlgorithmResult, error) {
	startTime := time.Now()
	defer func() {
		g.mu.Lock()
		g.metrics.ProcessingTime += time.Since(startTime)
		g.metrics.TotalAnalyses++
		g.metrics.LastUpdated = time.Now()
		g.mu.Unlock()
	}()

	if len(packages) == 0 {
		return nil, fmt.Errorf("no packages provided")
	}

	result := &AlgorithmResult{
		Algorithm: g.Name(),
		Timestamp: time.Now(),
		Packages:  packages,
		Findings:  make([]Finding, 0),
		Metadata:  make(map[string]interface{}),
	}

	// Create a basic package structure for analysis
	pkg := &types.Package{
		Name:     packages[0],
		Version:  "latest",
		Registry: "npm",
	}

	// Analyze package dependencies for graph traversal patterns
	g.analyzeDependencyGraph(pkg, result)

	// Detect typosquatting vectors across provided package set
	g.detectTyposquatVectorsAcrossPackages(packages, result)

	// Calculate overall scores
	g.calculateOverallScores(result)

	// Update metrics
	result.Metadata["dependencies_count"] = len(pkg.Dependencies)
	result.Metadata["processing_time_ms"] = time.Since(startTime).Milliseconds()

	g.mu.Lock()
	g.metrics.GraphsAnalyzed++
	g.metrics.NodesTraversed += int64(len(pkg.Dependencies))
	g.mu.Unlock()

	return result, nil
}

// analyzeDependencyGraph analyzes the dependency graph for security issues
func (g *GTRAlgorithm) analyzeDependencyGraph(pkg *types.Package, result *AlgorithmResult) {
	if pkg.Dependencies == nil {
		// Attempt to resolve dependencies via registry
		ctx := context.Background()
		nodes, edges, depthMap, riskMap := g.resolveDependencyGraph(ctx, pkg.Name, g.config.MaxTraversalDepth)
		if len(nodes) == 0 {
			return
		}
		centrality := g.computeDegreeCentrality(pkg)
		result.Metadata["depth_map"] = depthMap
		result.Metadata["risk_map"] = riskMap
		result.Metadata["max_depth"] = g.getMaxDepth(depthMap)
		result.Metadata["high_risk_count"] = g.countHighRiskDependencies(riskMap)
		result.Metadata["centrality_map"] = centrality
		pr := g.computePageRank(nodes, edges, 0.85, 20)
		result.Metadata["pagerank_centrality"] = pr
		pathRisk := 0.0
		for name, rsk := range riskMap {
			if v, ok := pr[name]; ok {
				pathRisk += rsk * v
			}
		}
		result.Metadata["path_risk_score"] = pathRisk
		result.Metadata["nodes_count"] = len(nodes)
		ec := 0
		for _, outs := range edges {
			ec += len(outs)
		}
		result.Metadata["edges_count"] = ec
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
				ID:              fmt.Sprintf("gtr_high_risk_%s", dep.Name),
				Package:         dep.Name,
				Type:            "high_risk_dependency",
				Severity:        g.getRiskSeverity(riskScore),
				Message:         fmt.Sprintf("Dependency '%s' has high risk score", dep.Name),
				Confidence:      riskScore,
				DetectedAt:      time.Now().UTC(),
				DetectionMethod: "gtr_risk_analysis",
				Evidence: []Evidence{
					{
						Type:        "risk_score",
						Description: "Calculated risk score for dependency",
						Value:       riskScore,
						Score:       riskScore,
					},
					{
						Type:        "dependency_depth",
						Description: "Depth of dependency in graph",
						Value:       depth,
						Score:       float64(depth) / 10.0,
					},
				},
			})
		}

		// Check for deep dependencies
		if depth > 3 {
			result.Findings = append(result.Findings, Finding{
				ID:              fmt.Sprintf("gtr_deep_dep_%s", dep.Name),
				Package:         dep.Name,
				Type:            "deep_dependency",
				Severity:        "MEDIUM",
				Message:         fmt.Sprintf("Dependency '%s' is deeply nested", dep.Name),
				Confidence:      0.7,
				DetectedAt:      time.Now().UTC(),
				DetectionMethod: "gtr_depth_analysis",
				Evidence: []Evidence{
					{
						Type:        "dependency_depth",
						Description: "Depth level in dependency tree",
						Value:       depth,
						Score:       float64(depth) / 10.0,
					},
				},
			})
		}

		// Check for development dependencies in production
		if dep.Development {
			result.Findings = append(result.Findings, Finding{
				ID:              fmt.Sprintf("gtr_dev_dep_%s", dep.Name),
				Package:         dep.Name,
				Type:            "dev_dependency_risk",
				Severity:        "LOW",
				Message:         fmt.Sprintf("Development dependency '%s' detected", dep.Name),
				Confidence:      0.5,
				DetectedAt:      time.Now().UTC(),
				DetectionMethod: "gtr_dev_dependency_check",
				Evidence: []Evidence{
					{
						Type:        "dependency_type",
						Description: "Type of dependency detected",
						Value:       "development",
						Score:       0.5,
					},
				},
			})
		}
	}

	// Store analysis metadata
	result.Metadata["depth_map"] = depthMap
	result.Metadata["risk_map"] = riskMap
	result.Metadata["max_depth"] = g.getMaxDepth(depthMap)
	result.Metadata["high_risk_count"] = g.countHighRiskDependencies(riskMap)

	// Compute simple degree centrality (out-degree based on declared dependencies)
	centrality := g.computeDegreeCentrality(pkg)
	result.Metadata["centrality_map"] = centrality

	// PageRank-like centrality and path risk aggregation
	nodes := make([]string, 0)
	edges := make(map[string][]string)
	nodes = append(nodes, pkg.Name)
	for _, dep := range pkg.Dependencies {
		nodes = append(nodes, dep.Name)
		edges[pkg.Name] = append(edges[pkg.Name], dep.Name)
	}
	pr := g.computePageRank(nodes, edges, 0.85, 20)
	result.Metadata["pagerank_centrality"] = pr
	pathRisk := 0.0
	for name, rsk := range riskMap {
		if v, ok := pr[name]; ok {
			pathRisk += rsk * v
		}
	}
	result.Metadata["path_risk_score"] = pathRisk
	result.Metadata["nodes_count"] = len(nodes)
	ec := 0
	for _, outs := range edges {
		ec += len(outs)
	}
	result.Metadata["edges_count"] = ec
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
func (g *GTRAlgorithm) calculateOverallScores(result *AlgorithmResult) {
	if len(result.Findings) == 0 {
		result.Metadata["threat_score"] = 0.0
		result.Metadata["confidence"] = 0.8
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
	threatScore := math.Min(totalThreat/float64(len(result.Findings)), 1.0)
	if pr, ok := result.Metadata["pagerank_centrality"].(map[string]float64); ok {
		maxPR := 0.0
		for _, v := range pr {
			if v > maxPR {
				maxPR = v
			}
		}
		if maxPR > 0 {
			threatScore = math.Min(threatScore+math.Min(maxPR, 0.2), 1.0)
		}
	}

	// Calculate confidence based on analysis depth
	confidence := 0.7 // Base confidence for GTR analysis
	if criticalCount > 0 || highCount > 2 {
		confidence = 0.9 // Higher confidence for clear threats
	}
	result.Metadata["confidence"] = confidence

	// Add attack vectors based on findings
	attackVectors := make([]string, 0)
	if criticalCount > 0 {
		attackVectors = append(attackVectors, "dependency_chain_attack")
	}
	if highCount > 0 {
		attackVectors = append(attackVectors, "supply_chain_compromise")
	}
	result.Metadata["attack_vectors"] = attackVectors
	result.Metadata["threat_score"] = threatScore
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

// Reset resets the algorithm state
func (g *GTRAlgorithm) Reset() error {
	// Reset metrics
	g.mu.Lock()
	g.metrics = &GTRMetrics{
		LastUpdated: time.Now(),
	}
	g.mu.Unlock()
	return nil
}
func (g *GTRAlgorithm) detectTyposquatVectorsAcrossPackages(packages []string, result *AlgorithmResult) {
	if len(packages) < 2 {
		return
	}
	// Compare all pairs and flag high similarity collisions
	for i := 0; i < len(packages); i++ {
		for j := i + 1; j < len(packages); j++ {
			a := packages[i]
			b := packages[j]
			if a == "" || b == "" || a == b {
				continue
			}
			sim := levenshteinSimilarity(a, b)
			if sim >= 0.85 {
				result.Findings = append(result.Findings, Finding{
					ID:              fmt.Sprintf("gtr_typosquat_%s_%s", a, b),
					Package:         a,
					Type:            "typosquat_vector",
					Severity:        g.getRiskSeverity(sim),
					Message:         fmt.Sprintf("Package '%s' is highly similar to '%s' (%.2f)", a, b, sim),
					Confidence:      sim,
					DetectedAt:      time.Now().UTC(),
					DetectionMethod: "gtr_name_collision",
					Evidence: []Evidence{
						{Type: "name_similarity", Description: "Levenshtein-based similarity", Value: map[string]interface{}{"a": a, "b": b}, Score: sim},
					},
				})
			}
		}
	}
}

func levenshteinSimilarity(s1, s2 string) float64 {
	if len(s1) == 0 && len(s2) == 0 {
		return 1.0
	}
	d := levenshteinDistance(s1, s2)
	maxLen := math.Max(float64(len(s1)), float64(len(s2)))
	if maxLen == 0 {
		return 0.0
	}
	sim := 1.0 - float64(d)/maxLen
	if sim < 0.0 {
		sim = 0.0
	}
	if sim > 1.0 {
		sim = 1.0
	}
	return sim
}

func levenshteinDistance(s1, s2 string) int {
	if len(s1) == 0 {
		return len(s2)
	}
	if len(s2) == 0 {
		return len(s1)
	}
	m := make([][]int, len(s1)+1)
	for i := range m {
		m[i] = make([]int, len(s2)+1)
		m[i][0] = i
	}
	for j := 0; j <= len(s2); j++ {
		m[0][j] = j
	}
	for i := 1; i <= len(s1); i++ {
		for j := 1; j <= len(s2); j++ {
			cost := 0
			if s1[i-1] != s2[j-1] {
				cost = 1
			}
			m[i][j] = min3int(m[i-1][j]+1, m[i][j-1]+1, m[i-1][j-1]+cost)
		}
	}
	return m[len(s1)][len(s2)]
}

func min3int(a, b, c int) int {
	if a < b && a < c {
		return a
	}
	if b < c {
		return b
	}
	return c
}

// computeDegreeCentrality computes a simple degree centrality map
func (g *GTRAlgorithm) computeDegreeCentrality(pkg *types.Package) map[string]int {
	cm := make(map[string]int)
	if pkg == nil || pkg.Dependencies == nil {
		return cm
	}
	// Count direct dependencies per package as degree
	for _, dep := range pkg.Dependencies {
		cm[dep.Name]++
	}
	return cm
}

func (g *GTRAlgorithm) computePageRank(nodes []string, edges map[string][]string, d float64, iters int) map[string]float64 {
	n := len(nodes)
	if n == 0 {
		return map[string]float64{}
	}
	pr := make(map[string]float64)
	out := make(map[string]int)
	for _, u := range nodes {
		pr[u] = 1.0 / float64(n)
		out[u] = len(edges[u])
	}
	for k := 0; k < iters; k++ {
		next := make(map[string]float64)
		base := (1.0 - d) / float64(n)
		for _, u := range nodes {
			next[u] = base
		}
		for u, outs := range edges {
			if out[u] == 0 {
				share := d * pr[u] / float64(n)
				for _, v := range nodes {
					next[v] += share
				}
				continue
			}
			share := d * pr[u] / float64(out[u])
			for _, v := range outs {
				next[v] += share
			}
		}
		pr = next
	}
	return pr
}
func (g *GTRAlgorithm) resolveDependencyGraph(ctx context.Context, root string, maxDepth int) ([]string, map[string][]string, map[string]int, map[string]float64) {
	nodes := make([]string, 0)
	edges := make(map[string][]string)
	depthMap := make(map[string]int)
	riskMap := make(map[string]float64)
	if g.npmConnector == nil || root == "" {
		return nodes, edges, depthMap, riskMap
	}
	visited := make(map[string]bool)
	queue := []string{root}
	depthMap[root] = 0
	visited[root] = true
	nodes = append(nodes, root)
	for len(queue) > 0 {
		u := queue[0]
		queue = queue[1:]
		du := depthMap[u]
		if du >= maxDepth {
			continue
		}
		deps := g.getDependencies(ctx, u)
		if len(deps) == 0 {
			continue
		}
		for _, v := range deps {
			edges[u] = append(edges[u], v)
			if !visited[v] {
				visited[v] = true
				depthMap[v] = du + 1
				nodes = append(nodes, v)
				queue = append(queue, v)
			}
			riskMap[v] = math.Max(riskMap[v], 0.1+0.05*float64(depthMap[v]))
		}
	}
	return nodes, edges, depthMap, riskMap
}

func (g *GTRAlgorithm) getDependencies(ctx context.Context, name string) []string {
	if g.npmConnector == nil || name == "" {
		return nil
	}
	g.depMu.RLock()
	deps, ok := g.depCache[name]
	ts := g.depCacheTS[name]
	g.depMu.RUnlock()
	if ok && time.Since(ts) < 10*time.Minute {
		return deps
	}
	c, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	info, err := g.npmConnector.GetPackageInfo(c, name, "latest")
	if err != nil || info == nil {
		return nil
	}
	g.depMu.Lock()
	g.depCache[name] = info.Dependencies
	g.depCacheTS[name] = time.Now()
	g.depMu.Unlock()
	return info.Dependencies
}
