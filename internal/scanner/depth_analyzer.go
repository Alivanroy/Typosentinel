package scanner

import (
	"context"
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/pkg/logger"
	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// DependencyDepthAnalyzer provides comprehensive dependency depth analysis
type DependencyDepthAnalyzer struct {
	config *config.DependencyGraphConfig
	logger *logger.Logger
}

// NewDependencyDepthAnalyzer creates a new depth analyzer instance
func NewDependencyDepthAnalyzer(cfg *config.DependencyGraphConfig, log *logger.Logger) *DependencyDepthAnalyzer {
	return &DependencyDepthAnalyzer{
		config: cfg,
		logger: log,
	}
}

// DepthAnalysisResult contains comprehensive depth analysis results
type DepthAnalysisResult struct {
	MaxDepth          int                    `json:"max_depth"`
	AverageDepth      float64                `json:"average_depth"`
	DepthDistribution map[int]int            `json:"depth_distribution"`
	CriticalPaths     []CriticalPath         `json:"critical_paths"`
	DeepDependencies  []DeepDependency       `json:"deep_dependencies"`
	RiskByDepth       map[int]float64        `json:"risk_by_depth"`
	TransitiveRisks   []TransitiveRisk       `json:"transitive_risks"`
	DepthMetrics      DepthMetrics           `json:"depth_metrics"`
	Recommendations   []string               `json:"recommendations"`
	AnalysisMetadata  map[string]interface{} `json:"analysis_metadata"`
	AnalyzedAt        time.Time              `json:"analyzed_at"`
}

// CriticalPath represents a high-risk dependency path
type CriticalPath struct {
	Path            []string `json:"path"`
	Depth           int      `json:"depth"`
	RiskScore       float64  `json:"risk_score"`
	Vulnerabilities []string `json:"vulnerabilities"`
	ImpactRadius    int      `json:"impact_radius"`
	Criticality     string   `json:"criticality"`
}

// DeepDependency represents a dependency at significant depth
type DeepDependency struct {
	PackageName     string                 `json:"package_name"`
	Depth           int                    `json:"depth"`
	Paths           [][]string             `json:"paths"`
	RiskScore       float64                `json:"risk_score"`
	ComplexityScore float64                `json:"complexity_score"`
	Maintenance     MaintenanceInfo        `json:"maintenance"`
	Metadata        map[string]interface{} `json:"metadata"`
}

// TransitiveRisk represents risk propagated through dependency chains
type TransitiveRisk struct {
	SourcePackage   string   `json:"source_package"`
	TargetPackage   string   `json:"target_package"`
	Path            []string `json:"path"`
	Depth           int      `json:"depth"`
	RiskScore       float64  `json:"risk_score"`
	PropagationType string   `json:"propagation_type"`
	Severity        string   `json:"severity"`
	MitigationCost  float64  `json:"mitigation_cost"`
}

// DepthMetrics contains statistical metrics about dependency depths
type DepthMetrics struct {
	TotalPackages      int     `json:"total_packages"`
	DirectDependencies int     `json:"direct_dependencies"`
	TransitiveDeps     int     `json:"transitive_dependencies"`
	MaxDepth           int     `json:"max_depth"`
	AverageDepth       float64 `json:"average_depth"`
	MedianDepth        float64 `json:"median_depth"`
	DepthVariance      float64 `json:"depth_variance"`
	ComplexityIndex    float64 `json:"complexity_index"`
	RiskConcentration  float64 `json:"risk_concentration"`
}

// MaintenanceInfo contains package maintenance information
type MaintenanceInfo struct {
	LastUpdate      time.Time `json:"last_update"`
	UpdateFrequency string    `json:"update_frequency"`
	MaintainerCount int       `json:"maintainer_count"`
	IsActive        bool      `json:"is_active"`
	RiskLevel       string    `json:"risk_level"`
}

// AnalyzeDependencyDepth performs comprehensive depth analysis
func (dda *DependencyDepthAnalyzer) AnalyzeDependencyDepth(ctx context.Context, graph *DependencyGraph) (*DepthAnalysisResult, error) {
	if !dda.config.Enabled {
		return nil, nil
	}

	dda.logger.Info("Starting comprehensive dependency depth analysis")
	start := time.Now()

	result := &DepthAnalysisResult{
		DepthDistribution: make(map[int]int),
		RiskByDepth:       make(map[int]float64),
		AnalysisMetadata:  make(map[string]interface{}),
		AnalyzedAt:        time.Now(),
	}

	// Build depth map and calculate basic metrics
	depthMap := dda.buildDepthMap(graph)
	result.DepthMetrics = dda.calculateDepthMetrics(graph, depthMap)
	result.MaxDepth = result.DepthMetrics.MaxDepth
	result.AverageDepth = result.DepthMetrics.AverageDepth

	// Calculate depth distribution
	result.DepthDistribution = dda.calculateDepthDistribution(depthMap)

	// Identify critical paths
	result.CriticalPaths = dda.identifyCriticalPaths(graph, depthMap)

	// Find deep dependencies
	result.DeepDependencies = dda.findDeepDependencies(graph, depthMap)

	// Calculate risk by depth
	result.RiskByDepth = dda.calculateRiskByDepth(graph, depthMap)

	// Analyze transitive risks
	result.TransitiveRisks = dda.analyzeTransitiveRisks(graph, depthMap)

	// Generate recommendations
	result.Recommendations = dda.generateDepthRecommendations(result)

	// Add analysis metadata
	result.AnalysisMetadata["analysis_duration"] = time.Since(start).String()
	result.AnalysisMetadata["analyzer_version"] = "1.0.0"
	result.AnalysisMetadata["max_depth_limit"] = dda.config.MaxDepth

	dda.logger.Info(fmt.Sprintf("Depth analysis completed in %v", time.Since(start)))
	return result, nil
}

// buildDepthMap creates a map of package names to their depths
func (dda *DependencyDepthAnalyzer) buildDepthMap(graph *DependencyGraph) map[string]int {
	depthMap := make(map[string]int)
	visited := make(map[string]bool)

	// Find root nodes (direct dependencies)
	rootNodes := dda.findRootNodes(graph)

	// Perform BFS to calculate depths
	queue := make([]string, 0)
	for _, rootNode := range rootNodes {
		depthMap[rootNode.ID] = 1
		queue = append(queue, rootNode.ID)
		visited[rootNode.ID] = true
	}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		currentDepth := depthMap[current]

		// Find all dependencies of current node
		for _, edge := range graph.Edges {
			if edge.From == current {
				if !visited[edge.To] {
					depthMap[edge.To] = currentDepth + 1
					queue = append(queue, edge.To)
					visited[edge.To] = true
				} else {
					// Update depth if we found a shorter path
					if depthMap[edge.To] > currentDepth+1 {
						depthMap[edge.To] = currentDepth + 1
					}
				}
			}
		}
	}

	return depthMap
}

// findRootNodes identifies direct dependencies (root nodes)
func (dda *DependencyDepthAnalyzer) findRootNodes(graph *DependencyGraph) []DependencyNode {
	var rootNodes []DependencyNode
	for _, node := range graph.Nodes {
		if node.Direct {
			rootNodes = append(rootNodes, node)
		}
	}
	return rootNodes
}

// calculateDepthMetrics computes statistical metrics about dependency depths
func (dda *DependencyDepthAnalyzer) calculateDepthMetrics(graph *DependencyGraph, depthMap map[string]int) DepthMetrics {
	metrics := DepthMetrics{
		TotalPackages: len(graph.Nodes),
	}

	// Count direct vs transitive dependencies
	for _, node := range graph.Nodes {
		if node.Direct {
			metrics.DirectDependencies++
		} else {
			metrics.TransitiveDeps++
		}
	}

	// Calculate depth statistics
	depths := make([]int, 0, len(depthMap))
	totalDepth := 0
	maxDepth := 0

	for _, depth := range depthMap {
		depths = append(depths, depth)
		totalDepth += depth
		if depth > maxDepth {
			maxDepth = depth
		}
	}

	metrics.MaxDepth = maxDepth
	if len(depths) > 0 {
		metrics.AverageDepth = float64(totalDepth) / float64(len(depths))
		metrics.MedianDepth = dda.calculateMedian(depths)
		metrics.DepthVariance = dda.calculateVariance(depths, metrics.AverageDepth)
	}

	// Calculate complexity index (higher = more complex)
	metrics.ComplexityIndex = dda.calculateComplexityIndex(graph, depthMap)

	// Calculate risk concentration
	metrics.RiskConcentration = dda.calculateRiskConcentration(graph, depthMap)

	return metrics
}

// calculateDepthDistribution creates a histogram of dependency depths
func (dda *DependencyDepthAnalyzer) calculateDepthDistribution(depthMap map[string]int) map[int]int {
	distribution := make(map[int]int)
	for _, depth := range depthMap {
		distribution[depth]++
	}
	return distribution
}

// identifyCriticalPaths finds high-risk dependency paths
func (dda *DependencyDepthAnalyzer) identifyCriticalPaths(graph *DependencyGraph, depthMap map[string]int) []CriticalPath {
	var criticalPaths []CriticalPath

	// Find paths with high risk scores or significant depth
	for _, node := range graph.Nodes {
		depth := depthMap[node.ID]
		if depth >= 4 || (node.RiskData != nil && node.RiskData.RiskScore > 0.7) {
			paths := dda.findAllPathsToNode(graph, node.ID)
			for _, path := range paths {
				riskScore := dda.calculatePathRiskScore(graph, path)
				if riskScore > 0.6 {
					criticalPath := CriticalPath{
						Path:            path,
						Depth:           len(path),
						RiskScore:       riskScore,
						Vulnerabilities: dda.getPathVulnerabilities(graph, path),
						ImpactRadius:    dda.calculateImpactRadius(graph, node.ID),
						Criticality:     dda.determineCriticality(riskScore, depth),
					}
					criticalPaths = append(criticalPaths, criticalPath)
				}
			}
		}
	}

	// Sort by risk score (highest first)
	sort.Slice(criticalPaths, func(i, j int) bool {
		return criticalPaths[i].RiskScore > criticalPaths[j].RiskScore
	})

	// Limit to top 10 critical paths
	if len(criticalPaths) > 10 {
		criticalPaths = criticalPaths[:10]
	}

	return criticalPaths
}

// findDeepDependencies identifies dependencies at significant depth
func (dda *DependencyDepthAnalyzer) findDeepDependencies(graph *DependencyGraph, depthMap map[string]int) []DeepDependency {
	var deepDeps []DeepDependency
	deepThreshold := 5 // Consider depth >= 5 as "deep"

	for _, node := range graph.Nodes {
		depth := depthMap[node.ID]
		if depth >= deepThreshold {
			paths := dda.findAllPathsToNode(graph, node.ID)
			riskScore := 0.0
			if node.RiskData != nil {
				riskScore = node.RiskData.RiskScore
			}

			deepDep := DeepDependency{
				PackageName:     node.Package.Name,
				Depth:           depth,
				Paths:           paths,
				RiskScore:       riskScore,
				ComplexityScore: dda.calculateNodeComplexity(graph, node.ID),
				Maintenance:     dda.getMaintenanceInfo(node.Package),
				Metadata:        make(map[string]interface{}),
			}

			deepDep.Metadata["path_count"] = len(paths)
			if node.RiskData != nil {
				deepDep.Metadata["is_vulnerable"] = node.RiskData.IsVulnerable
				deepDep.Metadata["threat_count"] = node.RiskData.ThreatCount
			} else {
				deepDep.Metadata["is_vulnerable"] = false
				deepDep.Metadata["threat_count"] = 0
			}

			deepDeps = append(deepDeps, deepDep)
		}
	}

	// Sort by depth (deepest first)
	sort.Slice(deepDeps, func(i, j int) bool {
		return deepDeps[i].Depth > deepDeps[j].Depth
	})

	return deepDeps
}

// calculateRiskByDepth computes average risk score for each depth level
func (dda *DependencyDepthAnalyzer) calculateRiskByDepth(graph *DependencyGraph, depthMap map[string]int) map[int]float64 {
	riskByDepth := make(map[int]float64)
	depthCounts := make(map[int]int)
	depthRiskSums := make(map[int]float64)

	for _, node := range graph.Nodes {
		depth := depthMap[node.ID]
		riskScore := 0.0
		if node.RiskData != nil {
			riskScore = node.RiskData.RiskScore
		}

		depthRiskSums[depth] += riskScore
		depthCounts[depth]++
	}

	for depth, riskSum := range depthRiskSums {
		if depthCounts[depth] > 0 {
			riskByDepth[depth] = riskSum / float64(depthCounts[depth])
		}
	}

	return riskByDepth
}

// analyzeTransitiveRisks identifies risks that propagate through dependency chains
func (dda *DependencyDepthAnalyzer) analyzeTransitiveRisks(graph *DependencyGraph, depthMap map[string]int) []TransitiveRisk {
	var transitiveRisks []TransitiveRisk

	// Find high-risk nodes that can propagate risk
	for _, sourceNode := range graph.Nodes {
		if sourceNode.RiskData == nil || sourceNode.RiskData.RiskScore < 0.5 {
			continue
		}

		// Find all nodes that depend on this high-risk node
		dependentNodes := dda.findDependentNodes(graph, sourceNode.ID)
		for _, targetNodeID := range dependentNodes {
			targetNode := dda.findNodeByID(graph, targetNodeID)
			if targetNode == nil {
				continue
			}

			path := dda.findShortestPath(graph, sourceNode.ID, targetNodeID)
			if len(path) > 1 {
				transitiveRisk := TransitiveRisk{
					SourcePackage:   sourceNode.Package.Name,
					TargetPackage:   targetNode.Package.Name,
					Path:            path,
					Depth:           len(path) - 1,
					RiskScore:       dda.calculateTransitiveRiskScore(sourceNode.RiskData.RiskScore, len(path)),
					PropagationType: dda.determinePropagationType(&sourceNode, targetNode),
					Severity:        dda.determineTransitiveRiskSeverity(sourceNode.RiskData.RiskScore, len(path)),
					MitigationCost:  dda.calculateMitigationCost(len(path), sourceNode.RiskData.RiskScore),
				}
				transitiveRisks = append(transitiveRisks, transitiveRisk)
			}
		}
	}

	// Sort by risk score (highest first)
	sort.Slice(transitiveRisks, func(i, j int) bool {
		return transitiveRisks[i].RiskScore > transitiveRisks[j].RiskScore
	})

	return transitiveRisks
}

// Helper methods for calculations

func (dda *DependencyDepthAnalyzer) calculateMedian(values []int) float64 {
	sort.Ints(values)
	n := len(values)
	if n == 0 {
		return 0
	}
	if n%2 == 0 {
		return float64(values[n/2-1]+values[n/2]) / 2
	}
	return float64(values[n/2])
}

func (dda *DependencyDepthAnalyzer) calculateVariance(values []int, mean float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sum := 0.0
	for _, v := range values {
		diff := float64(v) - mean
		sum += diff * diff
	}
	return sum / float64(len(values))
}

func (dda *DependencyDepthAnalyzer) calculateComplexityIndex(graph *DependencyGraph, depthMap map[string]int) float64 {
	// Complexity based on depth distribution and edge density
	maxDepth := 0
	for _, depth := range depthMap {
		if depth > maxDepth {
			maxDepth = depth
		}
	}

	edgeDensity := float64(len(graph.Edges)) / float64(len(graph.Nodes))
	depthFactor := float64(maxDepth) / 10.0 // Normalize to 0-1 range

	return (edgeDensity + depthFactor) / 2.0
}

func (dda *DependencyDepthAnalyzer) calculateRiskConcentration(graph *DependencyGraph, depthMap map[string]int) float64 {
	// Measure how risk is concentrated in deeper levels
	totalRisk := 0.0
	deepRisk := 0.0
	deepThreshold := 4

	for _, node := range graph.Nodes {
		if node.RiskData != nil {
			totalRisk += node.RiskData.RiskScore
			if depthMap[node.ID] >= deepThreshold {
				deepRisk += node.RiskData.RiskScore
			}
		}
	}

	if totalRisk == 0 {
		return 0
	}
	return deepRisk / totalRisk
}

func (dda *DependencyDepthAnalyzer) findAllPathsToNode(graph *DependencyGraph, nodeID string) [][]string {
	// Simplified implementation - find one path per root
	var paths [][]string
	rootNodes := dda.findRootNodes(graph)

	for _, root := range rootNodes {
		path := dda.findShortestPath(graph, root.ID, nodeID)
		if len(path) > 0 {
			paths = append(paths, path)
		}
	}

	return paths
}

func (dda *DependencyDepthAnalyzer) findShortestPath(graph *DependencyGraph, from, to string) []string {
	if from == to {
		return []string{from}
	}

	queue := [][]string{{from}}
	visited := make(map[string]bool)
	visited[from] = true

	for len(queue) > 0 {
		path := queue[0]
		queue = queue[1:]
		current := path[len(path)-1]

		for _, edge := range graph.Edges {
			if edge.From == current && !visited[edge.To] {
				newPath := append([]string{}, path...)
				newPath = append(newPath, edge.To)

				if edge.To == to {
					return newPath
				}

				queue = append(queue, newPath)
				visited[edge.To] = true
			}
		}
	}

	return nil
}

func (dda *DependencyDepthAnalyzer) calculatePathRiskScore(graph *DependencyGraph, path []string) float64 {
	totalRisk := 0.0
	for _, nodeID := range path {
		node := dda.findNodeByID(graph, nodeID)
		if node != nil && node.RiskData != nil {
			totalRisk += node.RiskData.RiskScore
		}
	}
	return totalRisk / float64(len(path))
}

func (dda *DependencyDepthAnalyzer) getPathVulnerabilities(graph *DependencyGraph, path []string) []string {
	var vulnerabilities []string
	for _, nodeID := range path {
		node := dda.findNodeByID(graph, nodeID)
		if node != nil && node.RiskData != nil && node.RiskData.IsVulnerable {
			vulnerabilities = append(vulnerabilities, node.Package.Name)
		}
	}
	return vulnerabilities
}

func (dda *DependencyDepthAnalyzer) calculateImpactRadius(graph *DependencyGraph, nodeID string) int {
	// Count how many nodes depend on this node
	dependents := dda.findDependentNodes(graph, nodeID)
	return len(dependents)
}

func (dda *DependencyDepthAnalyzer) determineCriticality(riskScore float64, depth int) string {
	if riskScore > 0.8 && depth > 5 {
		return "CRITICAL"
	} else if riskScore > 0.6 || depth > 4 {
		return "HIGH"
	} else if riskScore > 0.4 || depth > 2 {
		return "MEDIUM"
	}
	return "LOW"
}

func (dda *DependencyDepthAnalyzer) calculateNodeComplexity(graph *DependencyGraph, nodeID string) float64 {
	// Complexity based on number of dependencies and dependents
	dependencies := 0
	dependents := 0

	for _, edge := range graph.Edges {
		if edge.From == nodeID {
			dependencies++
		}
		if edge.To == nodeID {
			dependents++
		}
	}

	return math.Log(float64(dependencies+dependents+1)) / math.Log(10)
}

func (dda *DependencyDepthAnalyzer) getMaintenanceInfo(pkg *types.Package) MaintenanceInfo {
	// Extract maintenance information from package metadata
	maintenance := MaintenanceInfo{
		LastUpdate:      time.Now().AddDate(0, -6, 0), // Default to 6 months ago
		UpdateFrequency: "unknown",
		MaintainerCount: 1,
		IsActive:        true,
		RiskLevel:       "LOW",
	}

	if pkg.Metadata != nil {
		if maintainers, ok := pkg.Metadata.Metadata["maintainers"]; ok {
			if maintainerList, ok := maintainers.([]interface{}); ok {
				maintenance.MaintainerCount = len(maintainerList)
			}
		}

		if lastUpdate, ok := pkg.Metadata.Metadata["last_update"]; ok {
			if updateTime, ok := lastUpdate.(time.Time); ok {
				maintenance.LastUpdate = updateTime
			}
		}
	}

	// Determine risk level based on maintenance activity
	daysSinceUpdate := time.Since(maintenance.LastUpdate).Hours() / 24
	if daysSinceUpdate > 365 {
		maintenance.RiskLevel = "HIGH"
		maintenance.IsActive = false
	} else if daysSinceUpdate > 180 {
		maintenance.RiskLevel = "MEDIUM"
	}

	return maintenance
}

func (dda *DependencyDepthAnalyzer) findDependentNodes(graph *DependencyGraph, nodeID string) []string {
	var dependents []string
	for _, edge := range graph.Edges {
		if edge.To == nodeID {
			dependents = append(dependents, edge.From)
		}
	}
	return dependents
}

func (dda *DependencyDepthAnalyzer) findNodeByID(graph *DependencyGraph, nodeID string) *DependencyNode {
	for i, node := range graph.Nodes {
		if node.ID == nodeID {
			return &graph.Nodes[i]
		}
	}
	return nil
}

func (dda *DependencyDepthAnalyzer) calculateTransitiveRiskScore(sourceRisk float64, pathLength int) float64 {
	// Risk decreases with distance but is amplified by source risk
	decayFactor := math.Pow(0.8, float64(pathLength-1))
	return sourceRisk * decayFactor
}

func (dda *DependencyDepthAnalyzer) determinePropagationType(source, target *DependencyNode) string {
	if source.RiskData != nil && source.RiskData.IsVulnerable {
		return "vulnerability_propagation"
	}
	if source.RiskData != nil && source.RiskData.ThreatCount > 0 {
		return "threat_propagation"
	}
	return "risk_propagation"
}

func (dda *DependencyDepthAnalyzer) determineTransitiveRiskSeverity(riskScore float64, pathLength int) string {
	if riskScore > 0.8 && pathLength <= 3 {
		return "HIGH"
	} else if riskScore > 0.6 && pathLength <= 5 {
		return "MEDIUM"
	}
	return "LOW"
}

func (dda *DependencyDepthAnalyzer) calculateMitigationCost(pathLength int, riskScore float64) float64 {
	// Cost increases with path length and risk score
	baseCost := 1.0
	depthMultiplier := math.Pow(1.5, float64(pathLength-1))
	riskMultiplier := 1.0 + riskScore
	return baseCost * depthMultiplier * riskMultiplier
}

func (dda *DependencyDepthAnalyzer) generateDepthRecommendations(result *DepthAnalysisResult) []string {
	var recommendations []string

	// Recommendations based on max depth
	if result.MaxDepth > 8 {
		recommendations = append(recommendations, "Consider dependency tree flattening - maximum depth exceeds recommended limits")
	}

	// Recommendations based on deep dependencies
	if len(result.DeepDependencies) > 5 {
		recommendations = append(recommendations, "Review deep dependencies for potential consolidation or removal")
	}

	// Recommendations based on critical paths
	if len(result.CriticalPaths) > 0 {
		recommendations = append(recommendations, "Address critical dependency paths with high risk scores")
	}

	// Recommendations based on transitive risks
	if len(result.TransitiveRisks) > 3 {
		recommendations = append(recommendations, "Implement dependency pinning to mitigate transitive risks")
	}

	// Recommendations based on complexity
	if result.DepthMetrics.ComplexityIndex > 0.7 {
		recommendations = append(recommendations, "Simplify dependency structure to reduce complexity")
	}

	// Recommendations based on risk concentration
	if result.DepthMetrics.RiskConcentration > 0.6 {
		recommendations = append(recommendations, "Risk is concentrated in deep dependencies - consider security audits")
	}

	if len(recommendations) == 0 {
		recommendations = append(recommendations, "Dependency depth structure appears healthy")
	}

	return recommendations
}
