# ML & Advanced Detection Implementation Plan

## Overview
Replace placeholder ML components with functional implementations to reach 75-85% production readiness.

---

## PHASE 2: ML & Behavioral Analysis (Weeks 3-6)

### Priority: Medium-High (needed for 75%+ readiness)

---

## 1. ML Analyzer - Core Functionality (Week 3)

### Current State
- **File**: `internal/ml/analyzer.go`
- **Issue**: Circular dependencies, disabled integration
- **Status**: Skeleton implementation

### Implementation Tasks

#### 1.1 Fix Circular Dependencies (2 days)
```go
// Problem: analyzer.go imports enhanced_algorithms.go which imports analyzer.go

// Solution: Create interface boundary
type IMLAnalyzer interface {
    Analyze(ctx context.Context, pkg *types.Package) (*AnalysisResult, error)
    AnalyzeBatch(ctx context.Context, pkgs []*types.Package) ([]*AnalysisResult, error)
}

// Move enhanced algorithms to separate package
// internal/ml/enhanced/ - no dependency on analyzer.go
// internal/ml/analyzer.go - uses enhanced via interface
```

**Tasks:**
- [ ] Create ml/enhanced package
- [ ] Define clean interfaces
- [ ] Move enhanced algorithms
- [ ] Update imports
- [ ] Verify no circular deps

#### 1.2 Feature Engineering (3 days)
```go
func (a *MLAnalyzer) extractFeatures(pkg *types.Package) []float64 {
    features := make([]float64, 0, 50)
    
    // Name-based features
    features = append(features, 
        calculateNameLength(pkg.Name),
        calculateNameEntropy(pkg.Name),
        calculateConsonantVowelRatio(pkg.Name),
        calculateSpecialCharRatio(pkg.Name),
        calculateDigitRatio(pkg.Name),
    )
    
    // Package metadata features
    features = append(features,
        normalizeDownloads(pkg.Downloads),
        normalizeAge(pkg.CreatedAt),
        normalizeUpdateFreq(pkg.LastUpdated),
        normalizeMaintainerCount(len(pkg.Maintainers)),
    )
    
    // Dependency features
    depMetrics := a.calculateDependencyMetrics(pkg)
    features = append(features,
        float64(depMetrics.DirectCount),
        float64(depMetrics.TransitiveCount),
        depMetrics.DepthScore,
        depMetrics.ComplexityScore,
    )
    
    // Similarity features
    popular := a.getPopularPackages(pkg.Registry)
    simMetrics := a.calculateSimilarityMetrics(pkg.Name, popular)
    features = append(features,
        simMetrics.MaxSimilarity,
        simMetrics.AvgSimilarity,
        simMetrics.SuspiciousCount,
    )
    
    return features
}
```

#### 1.3 Scoring Model (3 days)
```go
type ScoringModel struct {
    Weights []float64
    Bias    float64
    Scaler  *FeatureScaler
}

func (a *MLAnalyzer) calculateMaliciousScore(features []float64) float64 {
    // Simple logistic regression for now
    // Can upgrade to neural network later
    
    normalized := a.model.Scaler.Transform(features)
    
    score := a.model.Bias
    for i, feature := range normalized {
        score += feature * a.model.Weights[i]
    }
    
    // Sigmoid activation
    return 1.0 / (1.0 + math.Exp(-score))
}
```

**Model Training Data Sources:**
- Known malicious packages (from existing discoveries)
- Popular legitimate packages (npm top 1000, PyPI top 500)
- Historical typosquatting incidents
- Community-reported packages

#### 1.4 Integration (1 day)
```go
func (a *MLAnalyzer) Analyze(ctx context.Context, pkg *types.Package) (*AnalysisResult, error) {
    startTime := time.Now()
    
    // Extract features
    features := a.extractFeatures(pkg)
    
    // Calculate scores
    maliciousScore := a.calculateMaliciousScore(features)
    similarityScore := a.calculateSimilarityScore(pkg)
    reputationScore := a.calculateReputationScore(pkg)
    
    // Find similar packages
    similarPackages := a.findSimilarPackages(pkg)
    
    // Determine threat level
    threatLevel := a.determineThreatLevel(maliciousScore, similarityScore)
    
    return &AnalysisResult{
        MaliciousScore:   maliciousScore,
        SimilarityScore:  similarityScore,
        ReputationScore:  reputationScore,
        SimilarPackages:  similarPackages,
        ThreatLevel:      threatLevel,
        Confidence:       a.calculateConfidence(features),
        ProcessingTime:   time.Since(startTime),
        Timestamp:        time.Now(),
    }, nil
}
```

---

## 2. Behavioral Analysis Engine (Week 4)

### Current State
- **File**: `internal/security/resource_exhaustion_detector.go`
- **Issue**: Placeholder implementations for behavioral patterns
- **Status**: Skeleton code with TODOs

### Implementation Tasks

#### 2.1 Pattern Detection (3 days)
```go
type BehavioralPattern struct {
    ID          string
    Name        string
    Indicators  []Indicator
    Threshold   float64
    Severity    string
}

type Indicator struct {
    Type        string  // "network", "filesystem", "process", "resource"
    Metric      string
    Baseline    float64
    Current     float64
    Deviation   float64
}

func (bae *BehavioralAnalysisEngine) detectPatterns(pkg *types.Package) []BehavioralPattern {
    patterns := []BehavioralPattern{}
    
    // 1. Monitor package behavior during installation/runtime
    behavior := bae.collectBehavior(pkg)
    
    // 2. Compare against known good patterns
    for _, knownPattern := range bae.goodPatterns {
        deviation := bae.calculateDeviation(behavior, knownPattern)
        if deviation > knownPattern.Threshold {
            patterns = append(patterns, BehavioralPattern{
                ID:         generateID(),
                Name:       fmt.Sprintf("deviation_%s", knownPattern.Name),
                Indicators: bae.identifyIndicators(behavior, knownPattern),
                Threshold:  knownPattern.Threshold,
                Severity:   bae.calculateSeverity(deviation),
            })
        }
    }
    
    // 3. Check against known malicious patterns
    for _, badPattern := range bae.maliciousPatterns {
        if bae.matchesPattern(behavior, badPattern) {
            patterns = append(patterns, badPattern)
        }
    }
    
    return patterns
}
```

#### 2.2 Anomaly Detection (3 days)
```go
func (bae *BehavioralAnalysisEngine) detectAnomalies(behavior *Behavior) []Anomaly {
    anomalies := []Anomaly{}
    
    // 1. Network behavior anomalies
    if behavior.NetworkConnections > 0 {
        anomalies = append(anomalies, Anomaly{
            Type:     "unexpected_network",
            Severity: "high",
            Details:  fmt.Sprintf("Package makes %d network connections during install", behavior.NetworkConnections),
        })
    }
    
    // 2. Filesystem anomalies
    suspiciousPaths := []string{
        "/etc/passwd",
        "~/.ssh",
        "~/.aws",
        os.Getenv("HOME") + "/.npmrc",
    }
    for _, path := range behavior.FilesAccessed {
        for _, suspicious := range suspiciousPaths {
            if strings.Contains(path, suspicious) {
                anomalies = append(anomalies, Anomaly{
                    Type:     "suspicious_file_access",
                    Severity: "critical",
                    Details:  fmt.Sprintf("Accessed sensitive file: %s", path),
                })
            }
        }
    }
    
    // 3. Process anomalies
    if len(behavior.ProcessesSpawned) > 0 {
        for _, proc := range behavior.ProcessesSpawned {
            if bae.isSuspiciousProcess(proc) {
                anomalies = append(anomalies, Anomaly{
                    Type:     "suspicious_process",
                    Severity: "high",
                    Details:  fmt.Sprintf("Spawned suspicious process: %s", proc),
                })
            }
        }
    }
    
    return anomalies
}
```

#### 2.3 Evasion Detection (2 days)
```go
func (bae *BehavioralAnalysisEngine) detectEvasion(behavior *Behavior) []EvasionSignal {
    signals := []EvasionSignal{}
    
    // 1. Timing-based evasion
    if bae.detectTimingEvasion(behavior) {
        signals = append(signals, EvasionSignal{
            Type:       "timing_evasion",
            Confidence: 0.9,
            Details:    "Package uses sleep/delays to evade sandbox",
        })
    }
    
    // 2. Environment detection
    if bae.detectEnvironmentChecks(behavior) {
        signals = append(signals, EvasionSignal{
            Type:       "environment_detection",
            Confidence: 0.85,
            Details:    "Package checks for VM/sandbox environment",
        })
    }
    
    // 3. Code obfuscation
    if bae.detectObfuscation(behavior.SourceCode) {
        signals = append(signals, EvasionSignal{
            Type:       "code_obfuscation",
            Confidence: 0.8,
            Details:    "Source code appears heavily obfuscated",
        })
    }
    
    return signals
}
```

---

## 3. Enhanced Pattern Recognition (Week 5)

### Current State
- **File**: `internal/security/enhanced_pattern_recognition.go`
- **Issue**: All calculation methods return 0.0
- **Status**: Skeleton with no logic

### Implementation Tasks

#### 3.1 Entropy Analysis (2 days)
```go
func (epr *EnhancedPatternRecognizer) analyzeEntropy(pkg *types.Package) float64 {
    // Calculate Shannon entropy of package name
    entropy := 0.0
    freq := make(map[rune]int)
    
    for _, c := range pkg.Name {
        freq[c]++
    }
    
    length := float64(len(pkg.Name))
    for _, count := range freq {
        p := float64(count) / length
        if p > 0 {
            entropy -= p * math.Log2(p)
        }
    }
    
    // Normalize to [0, 1]
    maxEntropy := math.Log2(length)
    if maxEntropy > 0 {
        return entropy / maxEntropy
    }
    
    return 0.0
}
```

#### 3.2 Statistical Analysis (2 days)
```go
func (epr *EnhancedPatternRecognizer) analyzeStatisticalPatterns(pkg *types.Package) *StatisticalAnalysis {
    // Analyze package metadata distribution
    
    return &StatisticalAnalysis{
        NameLength:      len(pkg.Name),
        NameComplexity:  epr.calculateNameComplexity(pkg.Name),
        VersionEntropy:  epr.calculateVersionEntropy(pkg.Version),
        UpdatePattern:   epr.analyzeUpdatePattern(pkg),
        DependencyRatio: epr.calculateDependencyRatio(pkg),
        ZScore:          epr.calculateZScore(pkg),
    }
}

func (epr *EnhancedPatternRecognizer) calculateZScore(pkg *types.Package) float64 {
    // Compare package metrics against ecosystem baseline
    
    baseline := epr.getEcosystemBaseline(pkg.Registry)
    
    // Calculate Z-score for key metrics
    downloadZScore := (float64(pkg.Downloads) - baseline.AvgDownloads) / baseline.StdDownloads
    ageZScore := (pkg.Age.Hours() - baseline.AvgAge) / baseline.StdAge
    depZScore := (float64(len(pkg.Dependencies)) - baseline.AvgDeps) / baseline.StdDeps
    
    // Combine Z-scores
    return (downloadZScore + ageZScore + depZScore) / 3.0
}
```

#### 3.3 ML Pattern Matching (2 days)
```go
func (epr *EnhancedPatternRecognizer) matchMLPatterns(pkg *types.Package) []PatternMatch {
    matches := []PatternMatch{}
    
    features := epr.extractPatternFeatures(pkg)
    
    // Match against learned patterns
    for _, pattern := range epr.learnedPatterns {
        similarity := epr.cosineSimilarity(features, pattern.Features)
        
        if similarity > pattern.Threshold {
            matches = append(matches, PatternMatch{
                Pattern:    pattern,
                Similarity: similarity,
                Confidence: pattern.Confidence,
            })
        }
    }
    
    return matches
}
```

---

## 4. Training Data System (Week 6)

### Current State
- **Files**: `internal/ml/training_data_manager.go`, `internal/ml/enhanced_training_data.go`
- **Issue**: Placeholder data quality calculations
- **Status**: Structure exists, no real implementation

### Implementation Tasks

#### 4.1 Data Collection (2 days)
```go
func (tdm *TrainingDataManager) collectTrainingData(sources []DataSource) (*TrainingDataset, error) {
    dataset := &TrainingDataset{
        Samples: []TrainingSample{},
    }
    
    for _, source := range sources {
        // Fetch packages from source
        packages, err := source.FetchPackages()
        if err != nil {
            continue
        }
        
        for _, pkg := range packages {
            sample := TrainingSample{
                Features: extractFeatures(pkg),
                Label:    source.GetLabel(pkg), // malicious, benign, unknown
                Metadata: map[string]interface{}{
                    "source":   source.Name(),
                    "registry": pkg.Registry,
                    "name":     pkg.Name,
                },
            }
            dataset.Samples = append(dataset.Samples, sample)
        }
    }
    
    return dataset, nil
}
```

**Data Sources:**
- npm registry (top packages - benign)
- PyPI (top packages - benign)
- Known malicious packages database
- Historical typosquatting incidents
- Community reports

#### 4.2 Data Quality (2 days)
```go
func (tdm *TrainingDataManager) validateQuality(dataset *TrainingDataset) *QualityReport {
    report := &QualityReport{
        TotalSamples:   len(dataset.Samples),
        Issues:         []QualityIssue{},
    }
    
    // Check class balance
    classCounts := make(map[string]int)
    for _, sample := range dataset.Samples {
        classCounts[sample.Label]++
    }
    
    malicious := float64(classCounts["malicious"])
    benign := float64(classCounts["benign"])
    ratio := malicious / benign
    
    if ratio < 0.1 || ratio > 10.0 {
        report.Issues = append(report.Issues, QualityIssue{
            Type:     "class_imbalance",
            Severity: "high",
            Message:  fmt.Sprintf("Class ratio %.2f:1 indicates severe imbalance", ratio),
        })
    }
    
    // Check feature completeness
    for i, sample := range dataset.Samples {
        if len(sample.Features) == 0 {
            report.Issues = append(report.Issues, QualityIssue{
                Type:     "missing_features",
                Severity: "critical",
                Message:  fmt.Sprintf("Sample %d has no features", i),
            })
        }
    }
    
    // Check for duplicates
    seen := make(map[string]bool)
    for _, sample := range dataset.Samples {
        key := sample.Metadata["name"].(string)
        if seen[key] {
            report.Issues = append(report.Issues, QualityIssue{
                Type:     "duplicate",
                Severity: "medium",
                Message:  fmt.Sprintf("Duplicate package: %s", key),
            })
        }
        seen[key] = true
    }
    
    return report
}
```

#### 4.3 Model Training (2 days)
```go
func (tdm *TrainingDataManager) trainModel(dataset *TrainingDataset) (*MLModel, error) {
    // Simple logistic regression for MVP
    // Can upgrade to neural network later
    
    X := make([][]float64, len(dataset.Samples))
    y := make([]float64, len(dataset.Samples))
    
    for i, sample := range dataset.Samples {
        X[i] = sample.Features
        y[i] = boolToFloat(sample.Label == "malicious")
    }
    
    // Train using gradient descent
    model := &MLModel{
        Weights: make([]float64, len(X[0])),
        Bias:    0.0,
    }
    
    learningRate := 0.01
    epochs := 1000
    
    for epoch := 0; epoch < epochs; epoch++ {
        // Forward pass + gradient descent
        for i := range X {
            prediction := model.Predict(X[i])
            error := y[i] - prediction
            
            // Update weights
            for j := range model.Weights {
                model.Weights[j] += learningRate * error * X[i][j]
            }
            model.Bias += learningRate * error
        }
    }
    
    return model, nil
}
```

---

## Testing & Validation

### ML Model Validation
```go
func TestMLAnalyzer(t *testing.T) {
    analyzer := NewMLAnalyzer(DefaultConfig())
    
    // Test 1: Known malicious package
    maliciousPkg := &types.Package{
        Name:     "lodas", // typosquatting lodash
        Registry: "npm",
        Downloads: 50,    // low downloads
        Age:      time.Hour * 24, // new package
    }
    
    result, err := analyzer.Analyze(context.Background(), maliciousPkg)
    assert.NoError(t, err)
    assert.Greater(t, result.MaliciousScore, 0.7, "Should detect malicious package")
    
    // Test 2: Known benign package
    benignPkg := &types.Package{
        Name:     "express",
        Registry: "npm",
        Downloads: 100000000,
        Age:      time.Hour * 24 * 365 * 10, // 10 years old
    }
    
    result, err = analyzer.Analyze(context.Background(), benignPkg)
    assert.NoError(t, err)
    assert.Less(t, result.MaliciousScore, 0.3, "Should recognize legitimate package")
}
```

### Behavioral Analysis Tests
```go
func TestBehavioralAnalysis(t *testing.T) {
    engine := newBehavioralAnalysisEngine()
    
    // Test: Detect network connections
    behavior := &Behavior{
        NetworkConnections: 5,
        FilesAccessed:      []string{"/etc/passwd"},
        ProcessesSpawned:   []string{"bash", "curl"},
    }
    
    anomalies := engine.detectAnomalies(behavior)
    assert.Greater(t, len(anomalies), 0)
    
    hasNetworkAnomaly := false
    for _, a := range anomalies {
        if a.Type == "unexpected_network" {
            hasNetworkAnomaly = true
            break
        }
    }
    assert.True(t, hasNetworkAnomaly)
}
```

---

## Success Criteria

### Functional
- [ ] ML analyzer returns real scores (not 0.0)
- [ ] Behavioral analysis detects actual patterns
- [ ] Training data system collects real data
- [ ] Models can be trained and updated
- [ ] No circular dependencies

### Quality
- [ ] Unit test coverage > 75%
- [ ] Integration tests pass
- [ ] Model accuracy > 85% on test set
- [ ] False positive rate < 10%

### Business
- [ ] Can demonstrate ML capabilities
- [ ] Training data documented
- [ ] Model performance measured
- [ ] Competitive with existing solutions

---

## Timeline

| Component           | Days | Week |
|---------------------|------|------|
| ML Analyzer Core    | 8    | 3    |
| Behavioral Analysis | 8    | 4    |
| Pattern Recognition | 6    | 5    |
| Training Data       | 6    | 6    |
| Testing & Polish    | 2    | 6    |
| **TOTAL**           | **30** | **4 weeks** |

---

## Dependencies

- **Phase 1 (Edge Algorithms)**: Should be complete before starting Phase 2
- **Package Registry APIs**: Need access to npm/PyPI data
- **Historical Data**: Malicious package database
- **Compute Resources**: For model training

---

## Risk Mitigation

### Technical Risks
- **Circular dependencies**: Fixed in week 3
- **Data availability**: Use public registries + existing discoveries
- **Model accuracy**: Start with simple models, iterate

### Business Risks
- **Time constraints**: Prioritize core over advanced features
- **Resource limitations**: Use lightweight models initially
- **Data quality**: Start with high-quality curated data

---

## Next Steps

1. **Week 3**: Fix ML circular dependencies, implement feature extraction
2. **Week 4**: Build behavioral analysis engine
3. **Week 5**: Implement pattern recognition
4. **Week 6**: Training data collection and model training
5. **Validation**: Test against real-world packages

**Note**: This is a parallel effort to Phase 1. Can start after edge algorithms are 50% complete.