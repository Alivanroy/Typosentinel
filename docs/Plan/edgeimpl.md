# Edge Algorithms Implementation Plan

## Overview
Replace placeholder implementations with functional algorithms for GTR, RUNT, DIRT, and AICC.

---

## 1. GTR (Graph Traversal Reconnaissance) - Week 1

### Current State
- **File**: `internal/edge/gtr.go`
- **Status**: Skeleton with hardcoded 0.65 threat score
- **Issue**: No actual graph analysis

### Implementation Tasks

#### 1.1 Dependency Graph Builder (2 days)
```go
type DependencyGraph struct {
    Nodes map[string]*Node
    Edges map[string][]Edge
}

type Node struct {
    Package     string
    Version     string
    Downloads   int64
    Maintainers []string
    RiskScore   float64
}

type Edge struct {
    From   string
    To     string
    Type   string // "requires", "imports", "depends"
    Weight float64
}
```

**Tasks:**
- [ ] Build graph from package.json/requirements.txt/go.mod
- [ ] Parse dependency relationships
- [ ] Calculate node centrality scores
- [ ] Identify critical paths

#### 1.2 Risk Propagation Algorithm (2 days)
```go
func (g *GTRAlgorithm) calculateRiskPropagation(graph *DependencyGraph, pkg string) float64 {
    // 1. Get all paths from entry point to pkg
    paths := g.findAllPaths(graph, "root", pkg)
    
    // 2. Calculate risk for each path
    pathRisks := make([]float64, len(paths))
    for i, path := range paths {
        pathRisks[i] = g.calculatePathRisk(path)
    }
    
    // 3. Aggregate using weighted average
    return g.aggregateRisks(pathRisks)
}
```

**Risk Factors:**
- Package popularity (inverse correlation with risk)
- Maintainer reputation
- Update frequency
- Dependency depth
- Known vulnerabilities

#### 1.3 Attack Vector Detection (2 days)
```go
func (g *GTRAlgorithm) detectAttackVectors(graph *DependencyGraph) []AttackVector {
    vectors := []AttackVector{}
    
    // 1. Typosquatting opportunities
    vectors = append(vectors, g.findTyposquatTargets(graph)...)
    
    // 2. Dependency confusion paths
    vectors = append(vectors, g.findConfusionPaths(graph)...)
    
    // 3. Supply chain weak points
    vectors = append(vectors, g.findWeakPoints(graph)...)
    
    return vectors
}
```

**Detection Patterns:**
- High-value packages with similar names
- Private/public namespace conflicts
- Unmaintained critical dependencies
- Single points of failure

#### 1.4 Real-world Test Cases
```bash
# Test 1: Express.js ecosystem
typosentinel edge gtr express --threshold 0.7

# Test 2: React ecosystem  
typosentinel edge gtr react react-dom --max-depth 5

# Test 3: Known vulnerable package
typosentinel edge gtr event-stream
```

**Expected Output:**
- Threat score: 0.0-1.0 (not hardcoded 0.65!)
- Attack vectors: specific, actionable
- Processing time: <2s for 100 packages

---

## 2. RUNT (Release-Unusual Name Tokenizer) - Week 1-2

### Current State
- **File**: `internal/edge/runt.go`
- **Status**: Hardcoded similarity metrics
- **Issue**: No recursive network analysis

### Implementation Tasks

#### 2.1 Package Feature Extraction (2 days)
```go
type PackageFeatures struct {
    Name            string
    NameTokens      []string
    VersionPattern  string
    ReleaseFreq     float64
    DownloadTrend   []int64
    MaintainerCount int
    Dependencies    int
    DevDeps         int
}

func (r *RUNTAlgorithm) extractFeatures(pkg *types.Package) *PackageFeatures {
    return &PackageFeatures{
        Name:           pkg.Name,
        NameTokens:     r.tokenizeName(pkg.Name),
        VersionPattern: r.analyzeVersioning(pkg),
        ReleaseFreq:    r.calculateReleaseFrequency(pkg),
        DownloadTrend:  r.getDownloadTrend(pkg),
        // ... etc
    }
}
```

#### 2.2 Similarity Scoring (2 days)
```go
func (r *RUNTAlgorithm) calculateSimilarity(pkg1, pkg2 *PackageFeatures) float64 {
    // Multi-factor similarity
    nameSim := r.nameTokenSimilarity(pkg1.NameTokens, pkg2.NameTokens)
    versionSim := r.versionPatternSimilarity(pkg1, pkg2)
    behaviorSim := r.behavioralSimilarity(pkg1, pkg2)
    
    // Weighted combination
    return 0.5*nameSim + 0.3*behaviorSim + 0.2*versionSim
}
```

**Algorithms:**
- Token-based Jaccard similarity
- Levenshtein with position weighting
- N-gram analysis
- Phonetic matching (metaphone)

#### 2.3 Network Traversal (3 days)
```go
func (r *RUNTAlgorithm) recursiveAnalysis(pkg string, depth int, visited map[string]bool) []Finding {
    if depth == 0 || visited[pkg] {
        return []Finding{}
    }
    
    visited[pkg] = true
    findings := []Finding{}
    
    // 1. Analyze current package
    features := r.extractFeatures(pkg)
    
    // 2. Compare with ecosystem
    similar := r.findSimilarPackages(features, 0.8)
    for _, sim := range similar {
        if sim.Score > 0.9 && sim.Package != pkg {
            findings = append(findings, Finding{
                Type:     "suspicious_similarity",
                Package:  sim.Package,
                Evidence: sim.Evidence,
            })
        }
    }
    
    // 3. Recurse on dependencies
    for _, dep := range r.getDependencies(pkg) {
        findings = append(findings, r.recursiveAnalysis(dep, depth-1, visited)...)
    }
    
    return findings
}
```

#### 2.4 Validation Tests
```bash
# Test actual typosquatting
typosentinel edge runt lodash --max-depth 10

# Should detect: loadsh, lodosh, lodas, etc.
```

---

## 3. DIRT (Dependency Impact Risk Traversal) - Week 2

### Current State
- **File**: `internal/edge/dirt.go`
- **Status**: Hardcoded cascading risk values
- **Issue**: No real impact analysis

### Implementation Tasks

#### 3.1 Impact Calculation (2 days)
```go
type ImpactMetrics struct {
    DirectDependents   int
    TotalDependents    int
    DownloadImpact     int64
    CriticalityScore   float64
    BlastRadius        int
}

func (d *DIRTAlgorithm) calculateImpact(pkg string) *ImpactMetrics {
    metrics := &ImpactMetrics{}
    
    // Count dependent packages
    metrics.DirectDependents = d.getDirectDependents(pkg)
    metrics.TotalDependents = d.getTotalDependents(pkg) // recursive
    
    // Calculate download impact
    for _, dep := range d.getAllDependents(pkg) {
        metrics.DownloadImpact += d.getDownloads(dep)
    }
    
    // Criticality based on ecosystem position
    metrics.CriticalityScore = d.calculateCriticality(metrics)
    
    // Blast radius = packages affected if compromised
    metrics.BlastRadius = metrics.TotalDependents
    
    return metrics
}
```

#### 3.2 Risk Traversal (2 days)
```go
func (d *DIRTAlgorithm) traverseRiskTree(root string, maxDepth int) *RiskTree {
    tree := &RiskTree{
        Root:     root,
        Children: []*RiskNode{},
    }
    
    // BFS traversal
    queue := []struct {
        pkg   string
        depth int
    }{{root, 0}}
    
    for len(queue) > 0 {
        current := queue[0]
        queue = queue[1:]
        
        if current.depth >= maxDepth {
            continue
        }
        
        // Get dependencies
        deps := d.getDependencies(current.pkg)
        for _, dep := range deps {
            risk := d.calculatePackageRisk(dep)
            node := &RiskNode{
                Package:  dep,
                Risk:     risk,
                Depth:    current.depth + 1,
            }
            tree.Children = append(tree.Children, node)
            
            queue = append(queue, struct {
                pkg   string
                depth int
            }{dep, current.depth + 1})
        }
    }
    
    return tree
}
```

#### 3.3 Hidden Risk Detection (2 days)
```go
func (d *DIRTAlgorithm) detectHiddenRisks(pkg string) []Finding {
    findings := []Finding{}
    
    // 1. Transitive dependency risks
    transDeps := d.getTransitiveDeps(pkg, 5)
    for _, dep := range transDeps {
        if d.hasKnownVulns(dep) {
            findings = append(findings, Finding{
                Type:     "transitive_vulnerability",
                Package:  dep,
                Severity: "high",
            })
        }
    }
    
    // 2. Unmaintained dependencies
    for _, dep := range d.getAllDeps(pkg) {
        if d.isUnmaintained(dep) {
            findings = append(findings, Finding{
                Type:     "unmaintained_dependency",
                Package:  dep,
                Severity: "medium",
            })
        }
    }
    
    // 3. License conflicts
    licenseIssues := d.checkLicenseCompatibility(pkg)
    findings = append(findings, licenseIssues...)
    
    return findings
}
```

---

## 4. AICC (Adaptive Intelligence Correlation Clustering) - Week 2

### Current State
- **File**: `internal/edge/aicc.go`
- **Status**: No clustering implementation
- **Issue**: Claims "attestation" checking but does nothing

### Implementation Tasks

#### 4.1 Package Clustering (3 days)
```go
func (a *AICCAlgorithm) clusterPackages(packages []string, nClusters int) []Cluster {
    // 1. Extract features for all packages
    features := make([][]float64, len(packages))
    for i, pkg := range packages {
        features[i] = a.extractClusteringFeatures(pkg)
    }
    
    // 2. K-means clustering
    clusters := a.kMeans(features, nClusters)
    
    // 3. Identify suspicious clusters
    for i := range clusters {
        clusters[i].SuspicionScore = a.evaluateCluster(clusters[i])
    }
    
    return clusters
}

func (a *AICCAlgorithm) extractClusteringFeatures(pkg string) []float64 {
    return []float64{
        a.getNameEntropy(pkg),
        a.getVersionComplexity(pkg),
        a.getMaintenancePattern(pkg),
        a.getDependencyRatio(pkg),
        a.getDownloadVolatility(pkg),
    }
}
```

#### 4.2 Correlation Analysis (2 days)
```go
func (a *AICCAlgorithm) findCorrelations(packages []string) []Correlation {
    correlations := []Correlation{}
    
    for i := 0; i < len(packages); i++ {
        for j := i + 1; j < len(packages); j++ {
            corr := a.calculateCorrelation(packages[i], packages[j])
            if corr.Score > 0.85 {
                correlations = append(correlations, corr)
            }
        }
    }
    
    return correlations
}

func (a *AICCAlgorithm) calculateCorrelation(pkg1, pkg2 string) Correlation {
    // Correlation factors:
    // - Name similarity
    // - Temporal proximity (release timing)
    // - Maintainer overlap
    // - Download pattern similarity
    // - Dependency overlap
    
    return Correlation{
        Package1: pkg1,
        Package2: pkg2,
        Score:    combinedScore,
        Factors:  factors,
    }
}
```

#### 4.3 Adaptive Thresholds (2 days)
```go
func (a *AICCAlgorithm) adaptThresholds(historicalData []AnalysisResult) {
    // Machine learning component:
    // Adjust clustering parameters based on detection accuracy
    
    a.mu.Lock()
    defer a.mu.Unlock()
    
    // Calculate optimal thresholds from historical performance
    falsePositiveRate := a.calculateFPR(historicalData)
    falseNegativeRate := a.calculateFNR(historicalData)
    
    if falsePositiveRate > 0.1 {
        a.config.MinClusterScore += 0.05
    }
    if falseNegativeRate > 0.05 {
        a.config.MinClusterScore -= 0.03
    }
}
```

---

## Testing & Validation

### Integration Tests
```go
func TestEdgeAlgorithmsIntegration(t *testing.T) {
    // Test 1: GTR detects express typosquatting
    gtr := NewGTRAlgorithm(nil)
    result, _ := gtr.Analyze(ctx, []string{"express"})
    assert.Greater(t, len(result.Findings), 0)
    
    // Test 2: RUNT finds similar packages
    runt := NewRUNTAlgorithm(nil)
    result, _ = runt.Analyze(ctx, []string{"lodash"})
    assert.Contains(t, result.AttackVectors, "typosquatting")
    
    // Test 3: DIRT calculates real impact
    dirt := NewDIRTAlgorithm(nil)
    result, _ = dirt.Analyze(ctx, []string{"react"})
    metadata := result.Metadata["impact_metrics"].(map[string]interface{})
    assert.Greater(t, metadata["total_dependents"].(int), 1000)
    
    // Test 4: AICC clusters malicious packages
    aicc := NewAICCAlgorithm(nil)
    result, _ = aicc.Analyze(ctx, []string{"pkg1", "pkg2", "pkg3"})
    assert.NotEqual(t, result.Threat_Score, 0.75) // Not hardcoded!
}
```

### Real-world Validation
```bash
# Test against known typosquatting incidents
typosentinel edge gtr crossenv cross-env --output json

# Expected: Should detect crossenv as suspicious
# Should identify attack vector: typosquatting
# Should calculate real similarity score
```

---

## Success Criteria

### Functional Requirements
- [ ] GTR builds actual dependency graphs
- [ ] RUNT performs recursive similarity analysis
- [ ] DIRT calculates real impact metrics
- [ ] AICC performs clustering and correlation
- [ ] No hardcoded return values
- [ ] Processing time < 5s for 100 packages

### Quality Requirements
- [ ] Unit test coverage > 80%
- [ ] Integration tests pass
- [ ] Real-world validation with known incidents
- [ ] Documentation matches implementation
- [ ] Code review approved

### Business Requirements
- [ ] Can demonstrate to investors/acquirers
- [ ] Withstands technical due diligence
- [ ] Matches marketing claims
- [ ] Provides real security value

---

## Timeline

| Algorithm | Days | Dependencies |
|-----------|------|--------------|
| GTR       | 6    | None         |
| RUNT      | 7    | GTR (optional) |
| DIRT      | 6    | GTR           |
| AICC      | 7    | All above     |
| Testing   | 4    | All           |
| **TOTAL** | **30** | **~1.5 months** |

---

## Next Steps

1. **Immediate**: Start with GTR implementation
2. **Week 1**: Complete GTR and start RUNT
3. **Week 2**: Complete RUNT, start DIRT
4. **Week 3**: Complete DIRT, start AICC
5. **Week 4**: Complete AICC, integration testing
6. **Week 5**: Documentation, validation, polish

**Priority**: Focus on GTR first—it's the foundation for other algorithms.