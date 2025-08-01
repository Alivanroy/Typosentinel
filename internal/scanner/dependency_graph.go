package scanner

import (
	"context"
	"fmt"
	"strings"

	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/pkg/logger"
	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// DependencyGraphAnalyzerImpl implements the DependencyGraphAnalyzer interface
type DependencyGraphAnalyzerImpl struct {
	config *config.DependencyGraphConfig
	logger *logger.Logger
}

// NewDependencyGraphAnalyzer creates a new dependency graph analyzer instance
func NewDependencyGraphAnalyzer(cfg *config.DependencyGraphConfig, log *logger.Logger) *DependencyGraphAnalyzerImpl {
	return &DependencyGraphAnalyzerImpl{
		config: cfg,
		logger: log,
	}
}

// BuildDependencyGraph builds the dependency graph for packages
func (dga *DependencyGraphAnalyzerImpl) BuildDependencyGraph(ctx context.Context, packages []*types.Package) (*DependencyGraph, error) {
	if !dga.config.Enabled {
		return nil, nil
	}

	graph := &DependencyGraph{
		Nodes: []DependencyNode{},
		Edges: []DependencyEdge{},
		Depth: 0,
		Stats: GraphStatistics{},
	}

	// Build dependency graph
	dga.buildDependencyGraphFromPackages(packages, graph)

	// Calculate graph statistics
	graph.Stats = dga.calculateGraphStatistics(graph)

	return graph, nil
}

// AnalyzeTransitiveDependencies analyzes transitive dependencies for threats
func (dga *DependencyGraphAnalyzerImpl) AnalyzeTransitiveDependencies(ctx context.Context, graph *DependencyGraph) ([]TransitiveThreat, error) {
	if !dga.config.Enabled {
		return nil, nil
	}

	var threats []TransitiveThreat

	// Analyze each node for transitive threats
	for _, node := range graph.Nodes {
		if dga.hasTransitiveThreatsInNode(node) {
			threats = append(threats, TransitiveThreat{
				Package:     node.Package.Name,
				ThreatType:  "malicious_dependency",
				Severity:    types.SeverityMedium,
				Description: fmt.Sprintf("Transitive threat detected in %s", node.Package.Name),
				Path:        dga.getTransitivePathForNode(node, graph),
			})
		}
	}

	return threats, nil
}

// DetectDependencyConfusion detects dependency confusion attacks
func (dga *DependencyGraphAnalyzerImpl) DetectDependencyConfusion(ctx context.Context, graph *DependencyGraph) ([]ConfusionThreat, error) {
	if !dga.config.Enabled {
		return nil, nil
	}

	var threats []ConfusionThreat

	// Check each node for confusion risks
	for _, node := range graph.Nodes {
		if dga.isDependencyConfusionRiskForNode(node) {
			threats = append(threats, ConfusionThreat{
				Package:        node.Package.Name,
				ConfusedWith:   dga.getConfusedPackageName(node),
				Severity:       types.SeverityMedium,
				Description:    fmt.Sprintf("Potential dependency confusion for %s", node.Package.Name),
				Recommendation: "Use scoped packages and verify package sources",
			})
		}
	}

	return threats, nil
}

// AnalyzeSupplyChainRisk analyzes overall supply chain risk
func (dga *DependencyGraphAnalyzerImpl) AnalyzeSupplyChainRisk(ctx context.Context, graph *DependencyGraph) (*SupplyChainRiskAnalysis, error) {
	if !dga.config.Enabled {
		return nil, nil
	}

	analysis := &SupplyChainRiskAnalysis{
		OverallRisk:     0.0,
		RiskFactors:     []RiskFactor{},
		CriticalPaths:   [][]string{},
		Recommendations: []string{},
		Metadata:        make(map[string]interface{}),
	}

	// Calculate overall risk
	analysis.OverallRisk = dga.calculateOverallRisk(graph)

	// Identify risk factors
	analysis.RiskFactors = dga.identifyRiskFactors(graph)

	// Find critical paths
	analysis.CriticalPaths = dga.findCriticalPaths(graph)

	// Generate recommendations
	analysis.Recommendations = dga.generateRiskRecommendations(analysis)

	return analysis, nil
}

// Helper methods for graph building

func (dga *DependencyGraphAnalyzerImpl) buildDependencyGraphFromPackages(packages []*types.Package, graph *DependencyGraph) {
	// Create nodes for each package
	for i, pkg := range packages {
		node := DependencyNode{
			ID:       fmt.Sprintf("%s@%s", pkg.Name, pkg.Version),
			Package:  pkg,
			Level:    dga.calculatePackageLevel(pkg, packages),
			Direct:   i < 10, // Simplified: assume first 10 are direct
			RiskData: &NodeRiskData{
				RiskScore:    dga.calculateNodeRiskScore(pkg),
				ThreatCount:  len(pkg.Threats),
				IsVulnerable: len(pkg.Threats) > 0,
			},
			Metadata: make(map[string]interface{}),
		}
		graph.Nodes = append(graph.Nodes, node)
	}

	// Create edges for dependencies (simplified)
	for i, pkg := range packages {
		if i > 0 {
			edge := DependencyEdge{
				From:         fmt.Sprintf("%s@%s", packages[0].Name, packages[0].Version),
				To:           fmt.Sprintf("%s@%s", pkg.Name, pkg.Version),
				RelationType: "depends_on",
				Constraints:  "*",
				Metadata:     make(map[string]interface{}),
			}
			graph.Edges = append(graph.Edges, edge)
		}
	}
}

func (dga *DependencyGraphAnalyzerImpl) calculateGraphStatistics(graph *DependencyGraph) GraphStatistics {
	return GraphStatistics{
		TotalNodes:     len(graph.Nodes),
		TotalEdges:     len(graph.Edges),
		DirectDeps:     dga.countDirectDependencies(graph),
		TransitiveDeps: dga.countTransitiveDependencies(graph),
		MaxDepth:       dga.calculateMaxDepth(graph),
		CyclicDeps:     dga.detectCyclicDependencies(graph),
	}
}

func (dga *DependencyGraphAnalyzerImpl) calculatePackageLevel(pkg *types.Package, packages []*types.Package) int {
	// Simplified level calculation
	return 1
}

func (dga *DependencyGraphAnalyzerImpl) calculateNodeRiskScore(pkg *types.Package) float64 {
	score := 0.0
	if len(pkg.Threats) > 0 {
		score += 0.5
	}
	return score
}

func (dga *DependencyGraphAnalyzerImpl) countDirectDependencies(graph *DependencyGraph) int {
	count := 0
	for _, node := range graph.Nodes {
		if node.Direct {
			count++
		}
	}
	return count
}

func (dga *DependencyGraphAnalyzerImpl) countTransitiveDependencies(graph *DependencyGraph) int {
	count := 0
	for _, node := range graph.Nodes {
		if !node.Direct {
			count++
		}
	}
	return count
}

func (dga *DependencyGraphAnalyzerImpl) calculateMaxDepth(graph *DependencyGraph) int {
	maxDepth := 0
	for _, node := range graph.Nodes {
		if node.Level > maxDepth {
			maxDepth = node.Level
		}
	}
	return maxDepth
}

func (dga *DependencyGraphAnalyzerImpl) detectCyclicDependencies(graph *DependencyGraph) int {
	// Simplified cyclic detection
	return 0
}

// New helper methods for the updated interface

func (dga *DependencyGraphAnalyzerImpl) hasTransitiveThreatsInNode(node DependencyNode) bool {
	return node.RiskData != nil && node.RiskData.IsVulnerable
}

func (dga *DependencyGraphAnalyzerImpl) getTransitivePathForNode(node DependencyNode, graph *DependencyGraph) []string {
	var path []string
	path = append(path, node.Package.Name)
	// Simplified path calculation
	return path
}

func (dga *DependencyGraphAnalyzerImpl) isDependencyConfusionRiskForNode(node DependencyNode) bool {
	return !strings.Contains(node.Package.Name, "/") && !strings.Contains(node.Package.Name, "@")
}

func (dga *DependencyGraphAnalyzerImpl) getConfusedPackageName(node DependencyNode) string {
	return node.Package.Name + "-confused"
}

func (dga *DependencyGraphAnalyzerImpl) calculateOverallRisk(graph *DependencyGraph) float64 {
	totalRisk := 0.0
	for _, node := range graph.Nodes {
		if node.RiskData != nil {
			totalRisk += node.RiskData.RiskScore
		}
	}
	if len(graph.Nodes) > 0 {
		return totalRisk / float64(len(graph.Nodes))
	}
	return 0.0
}

func (dga *DependencyGraphAnalyzerImpl) identifyRiskFactors(graph *DependencyGraph) []RiskFactor {
	var factors []RiskFactor
	vulnCount := 0
	for _, node := range graph.Nodes {
		if node.RiskData != nil && node.RiskData.IsVulnerable {
			vulnCount++
		}
	}
	if vulnCount > 0 {
		factors = append(factors, RiskFactor{
			Type:  "vulnerabilities",
			Score: float64(vulnCount) / float64(len(graph.Nodes)),
		})
	}
	return factors
}

func (dga *DependencyGraphAnalyzerImpl) findCriticalPaths(graph *DependencyGraph) [][]string {
	var paths [][]string
	for _, node := range graph.Nodes {
		if node.RiskData != nil && node.RiskData.RiskScore > 0.7 {
			paths = append(paths, []string{node.Package.Name})
		}
	}
	return paths
}

func (dga *DependencyGraphAnalyzerImpl) generateRiskRecommendations(analysis *SupplyChainRiskAnalysis) []string {
	var recommendations []string
	if analysis.OverallRisk > 0.7 {
		recommendations = append(recommendations, "High risk detected - review all dependencies")
	}
	if len(analysis.CriticalPaths) > 0 {
		recommendations = append(recommendations, "Critical paths found - prioritize security updates")
	}
	return recommendations
}

// Simplified helper methods

// Helper methods for analysis

func (dga *DependencyGraphAnalyzerImpl) buildDependencyTree(dependencies []*types.Dependency) map[string]*types.Dependency {
	tree := make(map[string]*types.Dependency)
	for _, dep := range dependencies {
		tree[dep.Name] = dep
	}
	return tree
}

// Detection helper methods

func (dga *DependencyGraphAnalyzerImpl) calculateNodeRiskLevel(dep *types.Dependency) string {
	if dga.hasKnownVulnerabilities(dep) {
		return "high"
	}
	if dga.isTyposquattingRisk(dep) {
		return "medium"
	}
	return "low"
}

func (dga *DependencyGraphAnalyzerImpl) isTyposquattingRisk(dep *types.Dependency) bool {
	// Check for typosquatting indicators
	return false // Simplified for demo
}

func (dga *DependencyGraphAnalyzerImpl) isDependencyConfusionRisk(dep *types.Dependency) bool {
	// Check for dependency confusion indicators
	return !strings.Contains(dep.Name, "/") && !strings.Contains(dep.Name, "@")
}

func (dga *DependencyGraphAnalyzerImpl) isMaliciousPackage(dep *types.Dependency) bool {
	// Check against known malicious package database
	return false // Simplified for demo
}

func (dga *DependencyGraphAnalyzerImpl) hasCompromisedMaintainer(dep *types.Dependency) bool {
	// Check for compromised maintainer indicators
	return false // Simplified for demo
}

func (dga *DependencyGraphAnalyzerImpl) hasKnownVulnerabilities(dep *types.Dependency) bool {
	// Check for risk indicators based on available metadata
	return dep.Metadata.HasInstallScript || len(dep.Metadata.Maintainers) == 0
}

func (dga *DependencyGraphAnalyzerImpl) getVulnerabilitySeverity(dep *types.Dependency) types.Severity {
	if dep.Metadata.HasInstallScript {
		return types.SeverityHigh
	}
	return types.SeverityLow
}

func (dga *DependencyGraphAnalyzerImpl) getCVSSScore(dep *types.Dependency) float64 {
	if dep.Metadata.HasInstallScript {
		return 7.5 // High risk score for packages with install scripts
	}
	return 0.0
}

func (dga *DependencyGraphAnalyzerImpl) getAffectedPaths(dep *types.Dependency, dependencies []*types.Dependency) []string {
	var paths []string
	// Since Dependency doesn't have Dependencies field, check metadata dependencies
	for _, d := range dependencies {
		for _, depName := range d.Metadata.Dependencies {
			if depName == dep.Name {
				paths = append(paths, fmt.Sprintf("%s -> %s", d.Name, dep.Name))
			}
		}
	}
	return paths
}

func (dga *DependencyGraphAnalyzerImpl) getTransitiveThreatTarget(dep *types.Dependency) string {
	// Use metadata dependencies instead
	if len(dep.Metadata.Dependencies) > 0 {
		return dep.Metadata.Dependencies[0]
	}
	return ""
}

func (dga *DependencyGraphAnalyzerImpl) getTransitivePath(dep *types.Dependency) []string {
	var path []string
	path = append(path, dep.Name)
	// Use metadata dependencies instead
	for _, depName := range dep.Metadata.Dependencies {
		path = append(path, depName)
	}
	return path
}

func (dga *DependencyGraphAnalyzerImpl) hasTransitiveThreats(dep *types.Dependency) bool {
	// Check if dependency has risk indicators since Dependency doesn't have Threats field
	return dep.Metadata.HasInstallScript || len(dep.Metadata.Maintainers) == 0 || dep.Metadata.Downloads < 1000
}

// Risk calculation

func (dga *DependencyGraphAnalyzerImpl) calculateGraphRiskScore(graph *DependencyGraph) float64 {
	score := 0.0
	totalNodes := len(graph.Nodes)

	if totalNodes == 0 {
		return 0.0
	}

	// Calculate risk based on node risk data
	for _, node := range graph.Nodes {
		if node.RiskData != nil {
			score += node.RiskData.RiskScore
		}
	}

	// Calculate average score
	score = score / float64(totalNodes)

	// Ensure score is within bounds
	if score > 1.0 {
		score = 1.0
	}
	if score < 0.0 {
		score = 0.0
	}

	return score
}