# Quick Start Guide: Getting Started Today

**Goal:** Begin implementation work immediately  
**Time to Start:** 15 minutes  
**First Task:** GTR Algorithm Implementation

---

## Step 1: Review the Plan (10 minutes)

Read these documents in order:

1. **MASTER_IMPLEMENTATION_ROADMAP.md** (5 min)
   - Understand the 8-week timeline
   - Review success criteria
   - Note the three phases

2. **EDGE_ALGORITHMS_IMPLEMENTATION_PLAN.md** (5 min)
   - Focus on GTR section (Week 1, Days 1-3)
   - Review the dependency graph builder task
   - Understand the expected output

---

## Step 2: Set Up Your Environment (5 minutes)

```bash
# 1. Navigate to project
cd /path/to/typosentinel

# 2. Create feature branch
git checkout -b feature/implement-edge-algorithms

# 3. Verify build
go build ./...

# 4. Run existing tests
go test ./internal/edge/... -v

# Expected: Tests pass but with hardcoded values
```

---

## Step 3: Start with GTR - Day 1 (Today)

### Task 1: Create Dependency Graph Structure

**File:** `internal/edge/graph.go` (new file)

```go
package edge

import (
	"fmt"
	"sync"
)

// DependencyGraph represents a package dependency network
type DependencyGraph struct {
	Nodes map[string]*Node
	Edges map[string][]Edge
	mu    sync.RWMutex
}

// Node represents a package in the graph
type Node struct {
	Package     string
	Version     string
	Registry    string
	Downloads   int64
	Maintainers []string
	RiskScore   float64
	Depth       int
	Centrality  float64
}

// Edge represents a dependency relationship
type Edge struct {
	From   string  // Package name
	To     string  // Dependency name
	Type   string  // "requires", "devRequires", "optionalRequires"
	Weight float64 // Importance weight
}

// NewDependencyGraph creates a new dependency graph
func NewDependencyGraph() *DependencyGraph {
	return &DependencyGraph{
		Nodes: make(map[string]*Node),
		Edges: make(map[string][]Edge),
	}
}

// AddNode adds a package node to the graph
func (g *DependencyGraph) AddNode(pkg string, node *Node) {
	g.mu.Lock()
	defer g.mu.Unlock()
	
	g.Nodes[pkg] = node
}

// AddEdge adds a dependency edge to the graph
func (g *DependencyGraph) AddEdge(from, to string, edgeType string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	
	edge := Edge{
		From:   from,
		To:     to,
		Type:   edgeType,
		Weight: g.calculateEdgeWeight(edgeType),
	}
	
	g.Edges[from] = append(g.Edges[from], edge)
}

// calculateEdgeWeight assigns weight based on dependency type
func (g *DependencyGraph) calculateEdgeWeight(edgeType string) float64 {
	switch edgeType {
	case "requires":
		return 1.0 // Production dependency
	case "devRequires":
		return 0.5 // Development dependency
	case "optionalRequires":
		return 0.3 // Optional dependency
	default:
		return 0.1
	}
}

// GetNeighbors returns all dependencies of a package
func (g *DependencyGraph) GetNeighbors(pkg string) []string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	
	neighbors := []string{}
	for _, edge := range g.Edges[pkg] {
		neighbors = append(neighbors, edge.To)
	}
	return neighbors
}

// CalculateCentrality calculates PageRank-style centrality for all nodes
func (g *DependencyGraph) CalculateCentrality(iterations int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	
	// Initialize centrality scores
	for pkg := range g.Nodes {
		g.Nodes[pkg].Centrality = 1.0 / float64(len(g.Nodes))
	}
	
	// Iterate PageRank algorithm
	dampingFactor := 0.85
	for i := 0; i < iterations; i++ {
		newCentrality := make(map[string]float64)
		
		for pkg := range g.Nodes {
			sum := 0.0
			
			// Sum contributions from packages that depend on this one
			for source, edges := range g.Edges {
				for _, edge := range edges {
					if edge.To == pkg {
						outDegree := len(g.Edges[source])
						if outDegree > 0 {
							sum += g.Nodes[source].Centrality / float64(outDegree)
						}
					}
				}
			}
			
			newCentrality[pkg] = (1-dampingFactor)/float64(len(g.Nodes)) + dampingFactor*sum
		}
		
		// Update centrality scores
		for pkg := range g.Nodes {
			g.Nodes[pkg].Centrality = newCentrality[pkg]
		}
	}
}

// String returns a string representation of the graph
func (g *DependencyGraph) String() string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	
	return fmt.Sprintf("Graph with %d nodes and %d edge sources", 
		len(g.Nodes), len(g.Edges))
}
```

### Task 2: Update GTR to Use the Graph

**File:** `internal/edge/gtr.go` (modify existing)

```go
// Add this to the existing GTRAlgorithm struct
type GTRAlgorithm struct {
	config *GTRConfig
	cache  map[string]*AlgorithmResult
	mu     sync.RWMutex
	graph  *DependencyGraph  // ADD THIS
}

// Update the Analyze method
func (g *GTRAlgorithm) Analyze(ctx context.Context, packages []string) (*AlgorithmResult, error) {
	startTime := time.Now()
	
	// Build dependency graph
	graph := g.buildDependencyGraph(packages)
	
	// Calculate centrality
	graph.CalculateCentrality(20) // 20 iterations
	
	// Analyze each package
	findings := []Finding{}
	totalRisk := 0.0
	
	for _, pkg := range packages {
		risk := g.calculatePackageRisk(graph, pkg)
		totalRisk += risk
		
		if risk > 0.6 {
			findings = append(findings, Finding{
				ID:          fmt.Sprintf("gtr-%s-%d", pkg, time.Now().Unix()),
				Package:     pkg,
				Type:        "high_risk_package",
				Severity:    "high",
				Message:     fmt.Sprintf("Package %s has high risk score: %.2f", pkg, risk),
				Confidence:  0.85,
				DetectedAt:  time.Now(),
			})
		}
	}
	
	// Calculate average risk
	avgRisk := totalRisk / float64(len(packages))
	
	return &AlgorithmResult{
		Algorithm:      "GTR",
		Timestamp:      time.Now(),
		Packages:       packages,
		Findings:       findings,
		ThreatScore:    avgRisk,  // REAL SCORE, NOT HARDCODED!
		Confidence:     0.85,
		ProcessingTime: time.Since(startTime),
		Metadata: map[string]interface{}{
			"graph_nodes": len(graph.Nodes),
			"graph_edges": len(graph.Edges),
		},
	}, nil
}

func (g *GTRAlgorithm) buildDependencyGraph(packages []string) *DependencyGraph {
	graph := NewDependencyGraph()
	
	// For each package, fetch its dependencies
	for _, pkg := range packages {
		// Add root node
		graph.AddNode(pkg, &Node{
			Package:  pkg,
			Depth:    0,
		})
		
		// TODO: Fetch dependencies from registry
		// For now, this is a placeholder
		// You'll implement this next
	}
	
	return graph
}

func (g *GTRAlgorithm) calculatePackageRisk(graph *DependencyGraph, pkg string) float64 {
	node, exists := graph.Nodes[pkg]
	if !exists {
		return 0.5 // Unknown package = medium risk
	}
	
	// Risk factors:
	// 1. Low centrality = less important = potentially suspicious
	// 2. Few downloads = unpopular = higher risk
	// 3. Many dependencies = complex = higher risk
	
	riskScore := 0.0
	
	// Centrality risk (inverted - low centrality = high risk)
	centralityRisk := 1.0 - node.Centrality*10  // Scale centrality
	if centralityRisk < 0 {
		centralityRisk = 0
	}
	riskScore += centralityRisk * 0.4
	
	// Dependency count risk
	depCount := len(graph.GetNeighbors(pkg))
	depRisk := float64(depCount) / 50.0  // Normalize to 50 deps
	if depRisk > 1.0 {
		depRisk = 1.0
	}
	riskScore += depRisk * 0.3
	
	// Age/download risk (implement when you have registry data)
	riskScore += 0.3  // Placeholder
	
	return riskScore
}
```

### Task 3: Test Your Work

```bash
# Run GTR tests
go test ./internal/edge/gtr_test.go -v

# Build to check for errors
go build ./internal/edge/...

# Try the CLI (won't work fully yet, but should compile)
go build -o typosentinel .
./typosentinel edge gtr express
```

### Expected Result

- ✅ Code compiles without errors
- ✅ Graph structure exists
- ✅ GTR uses the graph
- ✅ Returns non-hardcoded risk scores
- ⚠️ Still need registry integration (tomorrow)

---

## Step 4: Commit Your Progress

```bash
git add internal/edge/graph.go internal/edge/gtr.go
git commit -m "feat(gtr): Add dependency graph structure and basic risk calculation"
git push origin feature/implement-edge-algorithms
```

---

## Tomorrow (Day 2): Registry Integration

**Next Task:** Fetch actual package data from npm/PyPI

**Preview:**
```go
func (g *GTRAlgorithm) fetchPackageInfo(pkg string, registry string) (*Node, error) {
	// Call npm registry API
	resp, err := http.Get(fmt.Sprintf("https://registry.npmjs.org/%s", pkg))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	// Parse response
	var data map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&data)
	
	// Extract metadata
	return &Node{
		Package:   pkg,
		Version:   data["dist-tags"].(map[string]interface{})["latest"].(string),
		Downloads: // fetch from npm stats API
		// ... etc
	}, nil
}
```

---

## Daily Routine (Moving Forward)

1. **Morning** (30 min)
   - Review yesterday's progress
   - Check roadmap for today's tasks
   - Update daily standup

2. **Work** (6-8 hours)
   - Focus on current task
   - Write tests as you go
   - Commit frequently

3. **Evening** (30 min)
   - Test your changes
   - Update progress tracker
   - Plan tomorrow

---

## Progress Tracking Template

Create `DAILY_LOG.md`:

```markdown
# Implementation Progress Log

## Week 1

### Day 1 - [Date]
**Planned:** GTR dependency graph structure
**Completed:**
- [x] Created graph.go with DependencyGraph struct
- [x] Updated gtr.go to use graph
- [x] Basic risk calculation working
**Blockers:** None
**Tomorrow:** Registry API integration

### Day 2 - [Date]
**Planned:** Fetch package data from registries
**Completed:**
- [ ] Task 1
- [ ] Task 2
**Blockers:** [Any issues]
**Tomorrow:** [Next tasks]
```

---

## Getting Help

### If You Get Stuck

1. **Check the detailed plans:**
   - EDGE_ALGORITHMS_IMPLEMENTATION_PLAN.md
   - ML_IMPLEMENTATION_PLAN.md
   - PHASE3_PRODUCTION_READINESS.md

2. **Search for examples:**
   ```bash
   # Find similar patterns in codebase
   grep -r "DependencyGraph" internal/
   grep -r "calculateRisk" internal/
   ```

3. **Test incrementally:**
   ```bash
   # Don't wait to test
   go test ./... -v
   ```

4. **Commit often:**
   ```bash
   # Save progress frequently
   git add -A
   git commit -m "wip: progress on X"
   ```

---

## Success Criteria for Day 1

- [ ] Created `graph.go` with dependency graph structure
- [ ] Modified `gtr.go` to use the graph
- [ ] Risk score is calculated (not hardcoded 0.65)
- [ ] Code compiles without errors
- [ ] Changes committed to git

---

## Key Reminders

1. **Don't overcomplicate:** Start simple, iterate
2. **Test as you go:** Don't wait until the end
3. **Commit frequently:** Save your progress
4. **Read the plans:** Detailed instructions are in the implementation plan files
5. **Focus on Week 1:** Don't worry about Week 8 yet

---

## Your First 3 Days in Detail

### Day 1: Graph Structure ✅ (see above)

### Day 2: Registry Integration
- Fetch package metadata from npm
- Parse dependency lists
- Build complete dependency graph
- Test with real packages

### Day 3: Attack Vector Detection
- Implement typosquatting detection
- Add dependency confusion checks
- Find weak points in graph
- Real-world validation

---

## Questions & Answers

**Q: What if I can't finish Day 1 today?**
A: That's fine! This is an 8-week plan. Adjust timeline as needed.

**Q: Do I need to implement everything perfectly?**
A: No! MVP approach. Get it working, then refine.

**Q: What if I find better approaches?**
A: Great! Update the plan and keep going.

**Q: Should I worry about optimization now?**
A: No. Make it work first, optimize in Week 8.

---

## Let's Get Started! 🚀

1. Review the master roadmap (5 min)
2. Set up your environment (5 min)
3. Start implementing the graph structure (2-3 hours)
4. Test and commit (30 min)

**You've got this!** Remember: the goal is honest 85%, not perfect 100%. Ship what works, document what doesn't, iterate and improve.

---

**Ready?** Open `internal/edge/graph.go` and start coding! 💪