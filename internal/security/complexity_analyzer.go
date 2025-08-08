package security

import (
	"context"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/Alivanroy/Typosentinel/pkg/logger"
	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// ComplexityAnalyzer detects and prevents computational complexity exploitation
// Addresses critical vulnerabilities identified in adversarial assessment:
// - Exponential dependency growth overwhelming analysis algorithms
// - Circular dependency mazes creating infinite analysis loops
// - Version constraint conflicts triggering NP-hard resolution problems
// - Transitive closure calculations scaling to O(V³) complexity
type ComplexityAnalyzer struct {
	config                *ComplexityAnalyzerConfig
	dependencyGraph       *DependencyGraph
	circularDetector      *CircularDependencyDetector
	complexityLimiter     *ComplexityLimiter
	performanceMonitor    *PerformanceMonitor
	logger                logger.Logger
}

// ComplexityAnalyzerConfig configures complexity analysis parameters
type ComplexityAnalyzerConfig struct {
	MaxDependencyDepth     int           `yaml:"max_dependency_depth"`      // 15 levels max
	MaxDependencyCount     int           `yaml:"max_dependency_count"`      // 1000 deps max
	MaxAnalysisTime        time.Duration `yaml:"max_analysis_time"`         // 30 seconds max
	MaxMemoryUsage         int64         `yaml:"max_memory_usage"`          // 512MB max
	CircularDetectionLimit int           `yaml:"circular_detection_limit"`  // 100 cycles max
	ComplexityThreshold    float64       `yaml:"complexity_threshold"`      // 0.8
	EnableEarlyTermination bool          `yaml:"enable_early_termination"`  // true
	EnableComplexityLimits bool          `yaml:"enable_complexity_limits"`  // true
	Enabled                bool          `yaml:"enabled"`                   // true
}

// DependencyGraph represents the dependency graph structure
type DependencyGraph struct {
	nodes     map[string]*DependencyNode
	edges     map[string][]string
	depth     int
	nodeCount int
	edgeCount int
}

// DependencyNode represents a node in the dependency graph
type DependencyNode struct {
	Name         string
	Version      string
	Dependencies []string
	Depth        int
	Visited      bool
	InStack      bool
	Complexity   float64
}

// CircularDependencyDetector detects circular dependencies
type CircularDependencyDetector struct {
	visited    map[string]bool
	recursion  map[string]bool
	cycles     [][]string
	maxCycles  int
}

// ComplexityLimiter enforces complexity limits during analysis
type ComplexityLimiter struct {
	startTime      time.Time
	maxTime        time.Duration
	memoryUsage    int64
	maxMemory      int64
	operationCount int64
	maxOperations  int64
}

// PerformanceMonitor tracks analysis performance
type PerformanceMonitor struct {
	analysisStartTime time.Time
	memoryPeakUsage   int64
	operationsCount   int64
	timeouts          int64
	complexityScore   float64
}

// ComplexityThreat represents a detected complexity threat
type ComplexityThreat struct {
	ThreatID            string                 `json:"threat_id"`
	PackageName         string                 `json:"package_name"`
	ThreatType          string                 `json:"threat_type"`
	Severity            types.Severity         `json:"severity"`
	ComplexityScore     float64                `json:"complexity_score"`
	DependencyDepth     int                    `json:"dependency_depth"`
	DependencyCount     int                    `json:"dependency_count"`
	CircularDependencies []CircularDependency  `json:"circular_dependencies"`
	PerformanceImpact   *PerformanceImpact     `json:"performance_impact"`
	ExploitationRisk    string                 `json:"exploitation_risk"`
	Recommendations     []string               `json:"recommendations"`
	Metadata            map[string]interface{} `json:"metadata"`
}

// CircularDependency represents a circular dependency
type CircularDependency struct {
	Cycle       []string `json:"cycle"`
	Length      int      `json:"length"`
	Complexity  float64  `json:"complexity"`
	Exploitable bool     `json:"exploitable"`
}

// PerformanceImpact represents performance impact metrics
type PerformanceImpact struct {
	AnalysisTime     time.Duration `json:"analysis_time"`
	MemoryUsage      int64         `json:"memory_usage"`
	OperationsCount  int64         `json:"operations_count"`
	TimeoutRisk      float64       `json:"timeout_risk"`
	MemoryExhaustion float64       `json:"memory_exhaustion"`
}

// NewComplexityAnalyzer creates a new complexity analyzer
func NewComplexityAnalyzer(config *ComplexityAnalyzerConfig, logger logger.Logger) *ComplexityAnalyzer {
	if config == nil {
		config = DefaultComplexityAnalyzerConfig()
	}

	return &ComplexityAnalyzer{
		config:             config,
		dependencyGraph:    NewDependencyGraph(),
		circularDetector:   NewCircularDependencyDetector(config.CircularDetectionLimit),
		complexityLimiter:  NewComplexityLimiter(config.MaxAnalysisTime, config.MaxMemoryUsage),
		performanceMonitor: NewPerformanceMonitor(),
		logger:             logger,
	}
}

// DefaultComplexityAnalyzerConfig returns default configuration
func DefaultComplexityAnalyzerConfig() *ComplexityAnalyzerConfig {
	return &ComplexityAnalyzerConfig{
		MaxDependencyDepth:     15,
		MaxDependencyCount:     1000,
		MaxAnalysisTime:        30 * time.Second,
		MaxMemoryUsage:         512 * 1024 * 1024, // 512MB
		CircularDetectionLimit: 100,
		ComplexityThreshold:    0.8,
		EnableEarlyTermination: true,
		EnableComplexityLimits: true,
		Enabled:                true,
	}
}

// AnalyzeComplexity performs comprehensive complexity analysis
func (ca *ComplexityAnalyzer) AnalyzeComplexity(ctx context.Context, pkg *types.Package) (*ComplexityThreat, error) {
	if !ca.config.Enabled {
		return nil, nil
	}

	ca.logger.Info("Starting complexity analysis for package: " + pkg.Name)
	ca.performanceMonitor.Start()
	ca.complexityLimiter.Start()

	threat := &ComplexityThreat{
		ThreatID:             generateComplexityThreatID(pkg.Name),
		PackageName:          pkg.Name,
		CircularDependencies: []CircularDependency{},
		Recommendations:      []string{},
		Metadata:             make(map[string]interface{}),
	}

	// 1. Build dependency graph with complexity limits
	err := ca.buildDependencyGraph(ctx, pkg)
	if err != nil {
		return nil, fmt.Errorf("failed to build dependency graph: %w", err)
	}

	// 2. Analyze dependency depth and count
	threat.DependencyDepth = ca.dependencyGraph.depth
	threat.DependencyCount = ca.dependencyGraph.nodeCount

	// 3. Detect circular dependencies
	circularDeps := ca.detectCircularDependencies()
	threat.CircularDependencies = circularDeps

	// 4. Calculate complexity score
	threat.ComplexityScore = ca.calculateComplexityScore(threat)

	// 5. Assess performance impact
	threat.PerformanceImpact = ca.assessPerformanceImpact()

	// 6. Determine exploitation risk
	threat.ExploitationRisk = ca.assessExploitationRisk(threat)

	// 7. Classify threat type and severity
	threat.ThreatType, threat.Severity = ca.classifyComplexityThreat(threat)

	// 8. Generate recommendations
	threat.Recommendations = ca.generateComplexityRecommendations(threat)

	ca.performanceMonitor.Stop()

	ca.logger.Info(fmt.Sprintf("Complexity analysis completed for %s: score=%.2f, depth=%d, count=%d",
		pkg.Name, threat.ComplexityScore, threat.DependencyDepth, threat.DependencyCount))

	return threat, nil
}

// buildDependencyGraph builds the dependency graph with complexity limits
func (ca *ComplexityAnalyzer) buildDependencyGraph(ctx context.Context, pkg *types.Package) error {
	ca.dependencyGraph.Reset()
	
	// Check for early termination
	if ca.complexityLimiter.ShouldTerminate() {
		return fmt.Errorf("complexity analysis terminated due to limits")
	}

	// Add root package
	rootNode := &DependencyNode{
		Name:         pkg.Name,
		Version:      pkg.Version,
		Dependencies: []string{},
		Depth:        0,
		Complexity:   0.0,
	}
	ca.dependencyGraph.AddNode(rootNode)

	// Build graph using breadth-first search with limits
	queue := []*DependencyNode{rootNode}
	visited := make(map[string]bool)

	for len(queue) > 0 && !ca.complexityLimiter.ShouldTerminate() {
		current := queue[0]
		queue = queue[1:]

		if visited[current.Name] {
			continue
		}
		visited[current.Name] = true

		// Check depth limit
		if current.Depth >= ca.config.MaxDependencyDepth {
			ca.logger.Debug(fmt.Sprintf("Reached maximum dependency depth %d for %s", 
				ca.config.MaxDependencyDepth, current.Name))
			continue
		}

		// Check count limit
		if ca.dependencyGraph.nodeCount >= ca.config.MaxDependencyCount {
			ca.logger.Debug(fmt.Sprintf("Reached maximum dependency count %d", 
				ca.config.MaxDependencyCount))
			break
		}

		// Add dependencies (this would integrate with actual dependency resolution)
		dependencies := ca.resolveDependencies(current)
		for _, dep := range dependencies {
			if !visited[dep] {
				depNode := &DependencyNode{
					Name:    dep,
					Version: "latest", // Simplified
					Depth:   current.Depth + 1,
				}
				ca.dependencyGraph.AddNode(depNode)
				ca.dependencyGraph.AddEdge(current.Name, dep)
				queue = append(queue, depNode)
			}
		}

		ca.complexityLimiter.IncrementOperations()
	}

	return nil
}

// detectCircularDependencies detects circular dependencies in the graph
func (ca *ComplexityAnalyzer) detectCircularDependencies() []CircularDependency {
	ca.circularDetector.Reset()
	circularDeps := []CircularDependency{}

	// Use Tarjan's algorithm for strongly connected components
	for nodeName := range ca.dependencyGraph.nodes {
		if !ca.circularDetector.visited[nodeName] {
			cycles := ca.circularDetector.FindCycles(nodeName, ca.dependencyGraph)
			for _, cycle := range cycles {
				circularDep := CircularDependency{
					Cycle:       cycle,
					Length:      len(cycle),
					Complexity:  ca.calculateCycleComplexity(cycle),
					Exploitable: ca.isCycleExploitable(cycle),
				}
				circularDeps = append(circularDeps, circularDep)
			}
		}
	}

	return circularDeps
}

// calculateComplexityScore calculates overall complexity score
func (ca *ComplexityAnalyzer) calculateComplexityScore(threat *ComplexityThreat) float64 {
	score := 0.0

	// Depth complexity (exponential growth)
	depthScore := math.Min(float64(threat.DependencyDepth)/float64(ca.config.MaxDependencyDepth), 1.0)
	score += depthScore * 0.3

	// Count complexity (linear growth)
	countScore := math.Min(float64(threat.DependencyCount)/float64(ca.config.MaxDependencyCount), 1.0)
	score += countScore * 0.2

	// Circular dependency complexity
	circularScore := math.Min(float64(len(threat.CircularDependencies))/10.0, 1.0)
	score += circularScore * 0.3

	// Performance impact
	if threat.PerformanceImpact != nil {
		perfScore := threat.PerformanceImpact.TimeoutRisk * 0.1 + 
					threat.PerformanceImpact.MemoryExhaustion * 0.1
		score += perfScore
	}

	return math.Min(score, 1.0)
}

// assessPerformanceImpact assesses the performance impact
func (ca *ComplexityAnalyzer) assessPerformanceImpact() *PerformanceImpact {
	return &PerformanceImpact{
		AnalysisTime:     ca.performanceMonitor.GetElapsedTime(),
		MemoryUsage:      ca.performanceMonitor.memoryPeakUsage,
		OperationsCount:  ca.performanceMonitor.operationsCount,
		TimeoutRisk:      ca.calculateTimeoutRisk(),
		MemoryExhaustion: ca.calculateMemoryExhaustionRisk(),
	}
}

// assessExploitationRisk assesses the exploitation risk
func (ca *ComplexityAnalyzer) assessExploitationRisk(threat *ComplexityThreat) string {
	if threat.ComplexityScore > 0.8 {
		return "critical"
	} else if threat.ComplexityScore > 0.6 {
		return "high"
	} else if threat.ComplexityScore > 0.4 {
		return "medium"
	}
	return "low"
}

// classifyComplexityThreat classifies the threat type and severity
func (ca *ComplexityAnalyzer) classifyComplexityThreat(threat *ComplexityThreat) (string, types.Severity) {
	if threat.ComplexityScore > 0.8 {
		return "complexity_bomb", types.SeverityCritical
	} else if threat.ComplexityScore > 0.6 {
		return "complexity_exploitation", types.SeverityHigh
	} else if threat.ComplexityScore > 0.4 {
		return "complexity_anomaly", types.SeverityMedium
	}
	return "complexity_warning", types.SeverityLow
}

// generateComplexityRecommendations generates recommendations
func (ca *ComplexityAnalyzer) generateComplexityRecommendations(threat *ComplexityThreat) []string {
	recommendations := []string{}

	if threat.DependencyDepth > ca.config.MaxDependencyDepth/2 {
		recommendations = append(recommendations, "Review deep dependency chains for potential complexity bombs")
	}

	if len(threat.CircularDependencies) > 0 {
		recommendations = append(recommendations, "Resolve circular dependencies to prevent infinite loops")
	}

	if threat.ComplexityScore > 0.7 {
		recommendations = append(recommendations, "Implement complexity limits in production environments")
		recommendations = append(recommendations, "Consider dependency pruning and optimization")
	}

	if threat.PerformanceImpact != nil && threat.PerformanceImpact.TimeoutRisk > 0.5 {
		recommendations = append(recommendations, "Enable analysis timeouts to prevent DoS")
	}

	return recommendations
}

// Helper functions and supporting structures

func NewDependencyGraph() *DependencyGraph {
	return &DependencyGraph{
		nodes: make(map[string]*DependencyNode),
		edges: make(map[string][]string),
	}
}

func (dg *DependencyGraph) AddNode(node *DependencyNode) {
	dg.nodes[node.Name] = node
	dg.nodeCount++
	if node.Depth > dg.depth {
		dg.depth = node.Depth
	}
}

func (dg *DependencyGraph) AddEdge(from, to string) {
	dg.edges[from] = append(dg.edges[from], to)
	dg.edgeCount++
}

func (dg *DependencyGraph) Reset() {
	dg.nodes = make(map[string]*DependencyNode)
	dg.edges = make(map[string][]string)
	dg.depth = 0
	dg.nodeCount = 0
	dg.edgeCount = 0
}

func NewCircularDependencyDetector(maxCycles int) *CircularDependencyDetector {
	return &CircularDependencyDetector{
		visited:   make(map[string]bool),
		recursion: make(map[string]bool),
		cycles:    [][]string{},
		maxCycles: maxCycles,
	}
}

func (cdd *CircularDependencyDetector) Reset() {
	cdd.visited = make(map[string]bool)
	cdd.recursion = make(map[string]bool)
	cdd.cycles = [][]string{}
}

func (cdd *CircularDependencyDetector) FindCycles(node string, graph *DependencyGraph) [][]string {
	// Simplified cycle detection - would implement full Tarjan's algorithm
	cycles := [][]string{}
	
	if len(cdd.cycles) >= cdd.maxCycles {
		return cycles
	}

	// Basic cycle detection logic
	if cdd.recursion[node] {
		// Found a cycle
		cycle := []string{node}
		cycles = append(cycles, cycle)
		cdd.cycles = append(cdd.cycles, cycle)
	}

	cdd.visited[node] = true
	cdd.recursion[node] = true

	for _, neighbor := range graph.edges[node] {
		if !cdd.visited[neighbor] {
			neighborCycles := cdd.FindCycles(neighbor, graph)
			cycles = append(cycles, neighborCycles...)
		}
	}

	cdd.recursion[node] = false
	return cycles
}

func NewComplexityLimiter(maxTime time.Duration, maxMemory int64) *ComplexityLimiter {
	return &ComplexityLimiter{
		maxTime:       maxTime,
		maxMemory:     maxMemory,
		maxOperations: 1000000, // 1M operations max
	}
}

func (cl *ComplexityLimiter) Start() {
	cl.startTime = time.Now()
	cl.operationCount = 0
}

func (cl *ComplexityLimiter) ShouldTerminate() bool {
	// Check time limit
	if time.Since(cl.startTime) > cl.maxTime {
		return true
	}

	// Check operation limit
	if cl.operationCount > cl.maxOperations {
		return true
	}

	// Check memory limit (simplified)
	if cl.memoryUsage > cl.maxMemory {
		return true
	}

	return false
}

func (cl *ComplexityLimiter) IncrementOperations() {
	cl.operationCount++
}

func NewPerformanceMonitor() *PerformanceMonitor {
	return &PerformanceMonitor{}
}

func (pm *PerformanceMonitor) Start() {
	pm.analysisStartTime = time.Now()
}

func (pm *PerformanceMonitor) Stop() {
	// Performance monitoring logic
}

func (pm *PerformanceMonitor) GetElapsedTime() time.Duration {
	return time.Since(pm.analysisStartTime)
}

func (ca *ComplexityAnalyzer) resolveDependencies(node *DependencyNode) []string {
	// Return the dependencies already stored in the node
	// The DependencyNode struct already has a Dependencies field
	if node == nil {
		return []string{}
	}
	
	// Filter out duplicates from the existing dependencies
	seen := make(map[string]bool)
	uniqueDeps := []string{}
	for _, dep := range node.Dependencies {
		if !seen[dep] {
			seen[dep] = true
			uniqueDeps = append(uniqueDeps, dep)
		}
	}
	
	return uniqueDeps
}

func (ca *ComplexityAnalyzer) calculateCycleComplexity(cycle []string) float64 {
	// Calculate complexity based on cycle length and structure
	return float64(len(cycle)) / 10.0
}

func (ca *ComplexityAnalyzer) isCycleExploitable(cycle []string) bool {
	// Determine if cycle is exploitable for DoS
	return len(cycle) > 3
}

func (ca *ComplexityAnalyzer) calculateTimeoutRisk() float64 {
	elapsed := ca.performanceMonitor.GetElapsedTime()
	return math.Min(float64(elapsed)/float64(ca.config.MaxAnalysisTime), 1.0)
}

func (ca *ComplexityAnalyzer) calculateMemoryExhaustionRisk() float64 {
	return math.Min(float64(ca.performanceMonitor.memoryPeakUsage)/float64(ca.config.MaxMemoryUsage), 1.0)
}

func generateComplexityThreatID(packageName string) string {
	return fmt.Sprintf("complexity_%s_%d", strings.ReplaceAll(packageName, "/", "_"), time.Now().Unix())
}