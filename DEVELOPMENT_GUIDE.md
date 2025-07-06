# Typosentinel Enhanced - Development Guide

This guide provides comprehensive information for developers working on Typosentinel Enhanced, covering architecture, implementation details, and development workflows.

## 📋 Table of Contents

- [Architecture Overview](#architecture-overview)
- [Core Components](#core-components)
- [Detection Engines](#detection-engines)
- [Machine Learning Integration](#machine-learning-integration)
- [Plugin System](#plugin-system)
- [Threat Intelligence](#threat-intelligence)
- [Configuration Management](#configuration-management)
- [Testing Strategy](#testing-strategy)
- [Performance Optimization](#performance-optimization)
- [Security Considerations](#security-considerations)
- [Deployment](#deployment)
- [Troubleshooting](#troubleshooting)

## 🏗️ Architecture Overview

### System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Typosentinel Enhanced                    │
├─────────────────────────────────────────────────────────────┤
│  CLI Interface  │  REST API  │  GraphQL API  │  Web UI     │
├─────────────────────────────────────────────────────────────┤
│                    Core Engine                              │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐           │
│  │  Scanner    │ │  Analyzer   │ │  Reporter   │           │
│  └─────────────┘ └─────────────┘ └─────────────┘           │
├─────────────────────────────────────────────────────────────┤
│                  Detection Engines                          │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐           │
│  │Typosquatting│ │Dependency   │ │Supply Chain │           │
│  │  Detector   │ │ Confusion   │ │  Detector   │           │
│  └─────────────┘ └─────────────┘ └─────────────┘           │
├─────────────────────────────────────────────────────────────┤
│                Machine Learning Layer                       │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐           │
│  │ Adaptive    │ │  Feature    │ │   Model     │           │
│  │ Thresholds  │ │Engineering  │ │ Management  │           │
│  └─────────────┘ └─────────────┘ └─────────────┘           │
├─────────────────────────────────────────────────────────────┤
│                 Threat Intelligence                         │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐           │
│  │   Threat    │ │   Feed      │ │  Alerting   │           │
│  │  Database   │ │  Manager    │ │   System    │           │
│  └─────────────┘ └─────────────┘ └─────────────┘           │
├─────────────────────────────────────────────────────────────┤
│                    Plugin System                            │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐           │
│  │   CI/CD     │ │  Webhooks   │ │   Custom    │           │
│  │ Integrations│ │             │ │   Plugins   │           │
│  └─────────────┘ └─────────────┘ └─────────────┘           │
├─────────────────────────────────────────────────────────────┤
│                Infrastructure Layer                         │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐           │
│  │   Config    │ │   Cache     │ │   Storage   │           │
│  │ Management  │ │   Layer     │ │   Layer     │           │
│  └─────────────┘ └─────────────┘ └─────────────┘           │
└─────────────────────────────────────────────────────────────┘
```

### Data Flow

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Package   │───▶│   Scanner   │───▶│  Detectors  │
│    Input    │    │             │    │             │
└─────────────┘    └─────────────┘    └─────────────┘
                                              │
                                              ▼
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Results   │◀───│   Analyzer  │◀───│ ML Analysis │
│   Output    │    │             │    │             │
└─────────────┘    └─────────────┘    └─────────────┘
       │                                      │
       ▼                                      ▼
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Plugins   │    │   Threat    │    │  Adaptive   │
│             │    │Intelligence │    │ Thresholds  │
└─────────────┘    └─────────────┘    └─────────────┘
```

## 🔧 Core Components

### Scanner Engine

The scanner engine is responsible for orchestrating the analysis process:

```go
// internal/scanner/engine.go
type Engine struct {
    config     *config.Config
    detectors  []detector.Detector
    analyzer   *analyzer.Analyzer
    reporter   *reporter.Reporter
    cache      cache.Cache
    metrics    metrics.Collector
}

func (e *Engine) ScanPackage(ctx context.Context, pkg *types.Package) (*types.ScanResult, error) {
    // 1. Pre-scan validation
    if err := e.validatePackage(pkg); err != nil {
        return nil, fmt.Errorf("package validation failed: %w", err)
    }
    
    // 2. Check cache
    if result := e.cache.Get(pkg.CacheKey()); result != nil {
        return result.(*types.ScanResult), nil
    }
    
    // 3. Run detectors in parallel
    results := make(chan *types.DetectionResult, len(e.detectors))
    var wg sync.WaitGroup
    
    for _, detector := range e.detectors {
        wg.Add(1)
        go func(d detector.Detector) {
            defer wg.Done()
            if result, err := d.Analyze(ctx, pkg); err == nil {
                results <- result
            }
        }(detector)
    }
    
    // 4. Collect results
    go func() {
        wg.Wait()
        close(results)
    }()
    
    var detectionResults []*types.DetectionResult
    for result := range results {
        detectionResults = append(detectionResults, result)
    }
    
    // 5. Analyze and correlate
    scanResult, err := e.analyzer.Analyze(ctx, pkg, detectionResults)
    if err != nil {
        return nil, fmt.Errorf("analysis failed: %w", err)
    }
    
    // 6. Cache result
    e.cache.Set(pkg.CacheKey(), scanResult, time.Hour)
    
    return scanResult, nil
}
```

### Package Types

```go
// pkg/types/package.go
type Package struct {
    Name         string            `json:"name"`
    Version      string            `json:"version"`
    Ecosystem    string            `json:"ecosystem"`
    Description  string            `json:"description"`
    Keywords     []string          `json:"keywords"`
    License      string            `json:"license"`
    Homepage     string            `json:"homepage"`
    Repository   *Repository       `json:"repository"`
    Maintainers  []*Maintainer     `json:"maintainers"`
    Dependencies []*Dependency     `json:"dependencies"`
    Metadata     map[string]interface{} `json:"metadata"`
    CreatedAt    time.Time         `json:"created_at"`
    UpdatedAt    time.Time         `json:"updated_at"`
}

type ScanResult struct {
    Package        *Package           `json:"package"`
    RiskScore      float64           `json:"risk_score"`
    OverallRisk    string            `json:"overall_risk"`
    Threats        []*Threat         `json:"threats"`
    Recommendations []string         `json:"recommendations"`
    Metadata       map[string]interface{} `json:"metadata"`
    ScanDuration   time.Duration     `json:"scan_duration"`
    Timestamp      time.Time         `json:"timestamp"`
}
```

## 🔍 Detection Engines

### Typosquatting Detector

Implements multiple similarity algorithms for detecting typosquatting:

```go
// internal/detector/typosquatting.go
type TyposquattingDetector struct {
    config     *Config
    algorithms []SimilarityAlgorithm
    cache      cache.Cache
    metrics    metrics.Counter
}

type SimilarityAlgorithm interface {
    Name() string
    Calculate(s1, s2 string) float64
    Weight() float64
}

// Levenshtein distance algorithm
type LevenshteinAlgorithm struct {
    weight float64
}

func (l *LevenshteinAlgorithm) Calculate(s1, s2 string) float64 {
    distance := levenshtein.Distance(s1, s2)
    maxLen := math.Max(float64(len(s1)), float64(len(s2)))
    if maxLen == 0 {
        return 1.0
    }
    return 1.0 - (float64(distance) / maxLen)
}

// Jaro-Winkler similarity algorithm
type JaroWinklerAlgorithm struct {
    weight float64
}

func (j *JaroWinklerAlgorithm) Calculate(s1, s2 string) float64 {
    return jarowinkler.Similarity(s1, s2)
}

// Combined similarity calculation
func (t *TyposquattingDetector) calculateSimilarity(target, candidate string) float64 {
    var weightedSum, totalWeight float64
    
    for _, algo := range t.algorithms {
        similarity := algo.Calculate(target, candidate)
        weight := algo.Weight()
        weightedSum += similarity * weight
        totalWeight += weight
    }
    
    if totalWeight == 0 {
        return 0
    }
    
    return weightedSum / totalWeight
}
```

### Dependency Confusion Detector

Detects potential dependency confusion attacks:

```go
// internal/detector/dependency_confusion.go
func (d *DependencyConfusionDetector) analyzeNamespaceCollision(pkg *types.Package) *NamespaceAnalysis {
    analysis := &NamespaceAnalysis{
        PackageName: pkg.Name,
        Ecosystem:   pkg.Ecosystem,
    }
    
    // Check for scope indicators
    if strings.HasPrefix(pkg.Name, "@") {
        parts := strings.Split(pkg.Name, "/")
        if len(parts) == 2 {
            analysis.HasScope = true
            analysis.Scope = parts[0]
            analysis.BaseName = parts[1]
        }
    }
    
    // Check for private repository indicators
    analysis.PrivateIndicators = d.findPrivateIndicators(pkg)
    
    // Calculate confusion score
    analysis.ConfusionScore = d.calculateConfusionScore(analysis)
    
    return analysis
}

func (d *DependencyConfusionDetector) calculateConfusionScore(analysis *NamespaceAnalysis) float64 {
    score := 0.0
    
    // High risk if no scope but has private indicators
    if !analysis.HasScope && len(analysis.PrivateIndicators) > 0 {
        score += 0.7
    }
    
    // Medium risk if scope exists but suspicious patterns
    if analysis.HasScope {
        if d.isSuspiciousScope(analysis.Scope) {
            score += 0.5
        }
    }
    
    // Additional risk factors
    score += d.analyzeVersionPatterns(analysis) * 0.3
    score += d.analyzeDownloadPatterns(analysis) * 0.2
    
    return math.Min(score, 1.0)
}
```

### Supply Chain Detector

Analyzes supply chain security indicators:

```go
// internal/detector/supply_chain.go
func (s *SupplyChainDetector) analyzeMaintainerReputation(maintainers []*types.Maintainer) *ReputationAnalysis {
    analysis := &ReputationAnalysis{
        TotalMaintainers: len(maintainers),
    }
    
    for _, maintainer := range maintainers {
        reputation := s.calculateMaintainerReputation(maintainer)
        analysis.Reputations = append(analysis.Reputations, reputation)
        
        if reputation.Score < s.config.MinReputationScore {
            analysis.LowReputationCount++
        }
        
        if reputation.IsNew {
            analysis.NewMaintainerCount++
        }
    }
    
    // Calculate overall reputation score
    if len(analysis.Reputations) > 0 {
        var totalScore float64
        for _, rep := range analysis.Reputations {
            totalScore += rep.Score
        }
        analysis.AverageScore = totalScore / float64(len(analysis.Reputations))
    }
    
    return analysis
}

func (s *SupplyChainDetector) detectAnomalies(pkg *types.Package) []*Anomaly {
    var anomalies []*Anomaly
    
    // Version pattern anomalies
    if s.hasUnusualVersionPattern(pkg.Version) {
        anomalies = append(anomalies, &Anomaly{
            Type:        "unusual_version_pattern",
            Severity:    "medium",
            Description: "Package version follows unusual pattern",
            Evidence:    pkg.Version,
        })
    }
    
    // Download pattern anomalies
    if s.hasUnusualDownloadPattern(pkg) {
        anomalies = append(anomalies, &Anomaly{
            Type:        "unusual_download_pattern",
            Severity:    "high",
            Description: "Package has unusual download patterns",
        })
    }
    
    // Metadata anomalies
    if s.hasIncompleteMetadata(pkg) {
        anomalies = append(anomalies, &Anomaly{
            Type:        "incomplete_metadata",
            Severity:    "low",
            Description: "Package has incomplete or suspicious metadata",
        })
    }
    
    return anomalies
}
```

## 🧠 Machine Learning Integration

### Adaptive Thresholds

The adaptive threshold system automatically adjusts detection thresholds based on performance feedback:

```go
// internal/ml/adaptive_thresholds.go
func (m *AdaptiveThresholdManager) adaptThresholds(ecosystem string, stats *PerformanceStats) error {
    model, exists := m.models[ecosystem]
    if !exists {
        return fmt.Errorf("no model found for ecosystem: %s", ecosystem)
    }
    
    // Calculate current performance metrics
    precision := float64(stats.TruePositives) / float64(stats.TruePositives+stats.FalsePositives)
    recall := float64(stats.TruePositives) / float64(stats.TruePositives+stats.FalseNegatives)
    f1Score := 2 * (precision * recall) / (precision + recall)
    
    // Determine if adaptation is needed
    needsAdaptation := false
    adaptationReason := ""
    
    if precision < m.config.PerformanceTargets.TargetPrecision {
        needsAdaptation = true
        adaptationReason = "low_precision"
    } else if recall < m.config.PerformanceTargets.TargetRecall {
        needsAdaptation = true
        adaptationReason = "low_recall"
    }
    
    if !needsAdaptation {
        return nil
    }
    
    // Calculate threshold adjustments
    adjustments := m.calculateThresholdAdjustments(model, stats, adaptationReason)
    
    // Apply adjustments
    for detectorType, adjustment := range adjustments {
        oldThreshold := model.Thresholds.GetThreshold(detectorType)
        newThreshold := oldThreshold + adjustment
        
        // Ensure threshold stays within bounds
        newThreshold = math.Max(0.1, math.Min(0.95, newThreshold))
        
        model.Thresholds.SetThreshold(detectorType, newThreshold)
        
        // Record the change
        change := &ThresholdChange{
            Ecosystem:     ecosystem,
            DetectorType:  detectorType,
            OldThreshold:  oldThreshold,
            NewThreshold:  newThreshold,
            Reason:        adaptationReason,
            Timestamp:     time.Now(),
        }
        
        model.History = append(model.History, change)
    }
    
    // Update model metrics
    model.Metrics.LastUpdate = time.Now()
    model.Metrics.AdaptationCount++
    model.Metrics.CurrentPrecision = precision
    model.Metrics.CurrentRecall = recall
    model.Metrics.CurrentF1Score = f1Score
    
    return nil
}
```

### Feature Engineering

```go
// internal/ml/features.go
type FeatureExtractor struct {
    config *FeatureConfig
}

func (f *FeatureExtractor) ExtractFeatures(pkg *types.Package) (*FeatureVector, error) {
    vector := &FeatureVector{
        PackageName: pkg.Name,
        Ecosystem:   pkg.Ecosystem,
        Features:    make(map[string]float64),
    }
    
    // String features
    if err := f.extractStringFeatures(pkg, vector); err != nil {
        return nil, err
    }
    
    // Numerical features
    if err := f.extractNumericalFeatures(pkg, vector); err != nil {
        return nil, err
    }
    
    // Categorical features
    if err := f.extractCategoricalFeatures(pkg, vector); err != nil {
        return nil, err
    }
    
    // Custom features
    if err := f.extractCustomFeatures(pkg, vector); err != nil {
        return nil, err
    }
    
    // Normalize features
    if err := f.normalizeFeatures(vector); err != nil {
        return nil, err
    }
    
    return vector, nil
}

func (f *FeatureExtractor) extractStringFeatures(pkg *types.Package, vector *FeatureVector) error {
    // Name entropy
    vector.Features["name_entropy"] = f.calculateEntropy(pkg.Name)
    
    // Name length
    vector.Features["name_length"] = float64(len(pkg.Name))
    
    // Character distribution
    vector.Features["digit_ratio"] = f.calculateDigitRatio(pkg.Name)
    vector.Features["special_char_ratio"] = f.calculateSpecialCharRatio(pkg.Name)
    
    // Description features
    if pkg.Description != "" {
        vector.Features["description_length"] = float64(len(pkg.Description))
        vector.Features["description_entropy"] = f.calculateEntropy(pkg.Description)
    }
    
    return nil
}
```

## 🔌 Plugin System

### Plugin Interface

All plugins implement a common interface:

```go
// internal/plugins/interface.go
type Plugin interface {
    Info() *PluginInfo
    Initialize(config map[string]interface{}) error
    Execute(ctx context.Context, result *types.ScanResult) (*PluginResult, error)
    Validate() error
    Cleanup() error
}

type PluginInfo struct {
    Name        string            `json:"name"`
    Version     string            `json:"version"`
    Description string            `json:"description"`
    Author      string            `json:"author"`
    Type        string            `json:"type"`
    Capabilities []string         `json:"capabilities"`
    Config      map[string]interface{} `json:"config"`
}

type PluginResult struct {
    Success     bool              `json:"success"`
    Message     string            `json:"message"`
    Actions     []*PluginAction   `json:"actions"`
    Metadata    map[string]interface{} `json:"metadata"`
    Duration    time.Duration     `json:"duration"`
}
```

### Plugin Manager

```go
// internal/plugins/manager.go
func (m *PluginManager) ExecutePlugins(ctx context.Context, result *types.ScanResult) error {
    var wg sync.WaitGroup
    results := make(chan *PluginExecution, len(m.plugins))
    
    for name, plugin := range m.plugins {
        wg.Add(1)
        go func(pluginName string, p Plugin) {
            defer wg.Done()
            
            start := time.Now()
            pluginResult, err := p.Execute(ctx, result)
            duration := time.Since(start)
            
            execution := &PluginExecution{
                PluginName: pluginName,
                Result:     pluginResult,
                Error:      err,
                Duration:   duration,
                Timestamp:  time.Now(),
            }
            
            results <- execution
        }(name, plugin)
    }
    
    go func() {
        wg.Wait()
        close(results)
    }()
    
    // Collect results
    for execution := range results {
        m.recordExecution(execution)
        
        if execution.Error != nil {
            m.logger.Error("Plugin execution failed",
                "plugin", execution.PluginName,
                "error", execution.Error)
        }
    }
    
    return nil
}
```

## 🛡️ Threat Intelligence

### Threat Database

The threat database stores and manages threat intelligence data:

```go
// internal/threat_intelligence/database.go
func (db *ThreatDatabase) StoreThreat(threat *ThreatIntelligence) error {
    db.mutex.Lock()
    defer db.mutex.Unlock()
    
    // Encrypt sensitive data
    encryptedData, err := db.encryptThreatData(threat)
    if err != nil {
        return fmt.Errorf("failed to encrypt threat data: %w", err)
    }
    
    // Store in database
    query := `
        INSERT OR REPLACE INTO threats (
            id, type, severity, source, indicators, 
            description, created_at, updated_at, expires_at, encrypted_data
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `
    
    _, err = db.db.Exec(query,
        threat.ID,
        threat.Type,
        threat.Severity,
        threat.Source,
        strings.Join(threat.Indicators, ","),
        threat.Description,
        threat.CreatedAt,
        threat.UpdatedAt,
        threat.ExpiresAt,
        encryptedData,
    )
    
    if err != nil {
        return fmt.Errorf("failed to store threat: %w", err)
    }
    
    // Update cache
    db.cache.Set(threat.ID, threat, time.Until(threat.ExpiresAt))
    
    // Update statistics
    db.stats.TotalThreats++
    db.stats.LastUpdate = time.Now()
    
    return nil
}
```

### Real-Time Updates

```go
// internal/threat_intelligence/updater.go
func (u *RealTimeUpdater) processUpdate(update *ThreatUpdate) error {
    // Validate update
    if err := u.validateUpdate(update); err != nil {
        return fmt.Errorf("invalid update: %w", err)
    }
    
    // Process based on update type
    switch update.Type {
    case "add":
        return u.addThreat(update.Threat)
    case "update":
        return u.updateThreat(update.Threat)
    case "remove":
        return u.removeThreat(update.ThreatID)
    default:
        return fmt.Errorf("unknown update type: %s", update.Type)
    }
}

func (u *RealTimeUpdater) startWebhookProcessor(channel *UpdateChannel) error {
    processor := &WebhookProcessor{
        channel: channel,
        server:  u.createWebhookServer(channel),
    }
    
    go func() {
        if err := processor.server.ListenAndServe(); err != nil {
            u.logger.Error("Webhook server error", "error", err)
        }
    }()
    
    u.processors[channel.Name] = processor
    return nil
}
```

## ⚙️ Configuration Management

### Enhanced Configuration

The configuration system supports complex, hierarchical settings:

```go
// internal/config/enhanced_config.go
func (c *EnhancedConfig) LoadFromFile(filename string) error {
    data, err := os.ReadFile(filename)
    if err != nil {
        return fmt.Errorf("failed to read config file: %w", err)
    }
    
    // Determine format based on file extension
    ext := strings.ToLower(filepath.Ext(filename))
    switch ext {
    case ".yaml", ".yml":
        err = yaml.Unmarshal(data, c)
    case ".json":
        err = json.Unmarshal(data, c)
    default:
        return fmt.Errorf("unsupported config format: %s", ext)
    }
    
    if err != nil {
        return fmt.Errorf("failed to parse config: %w", err)
    }
    
    // Apply defaults
    c.ApplyDefaults()
    
    // Validate configuration
    if err := c.Validate(); err != nil {
        return fmt.Errorf("invalid configuration: %w", err)
    }
    
    // Expand environment variables
    c.expandEnvironmentVariables()
    
    return nil
}

func (c *EnhancedConfig) Validate() error {
    var errors []string
    
    // Validate core settings
    if c.Core.Version == "" {
        errors = append(errors, "core.version is required")
    }
    
    // Validate detection settings
    if c.Detection.ParallelScans <= 0 {
        errors = append(errors, "detection.parallel_scans must be positive")
    }
    
    // Validate ML settings
    if c.ML.Enabled {
        if c.ML.AdaptiveThresholds.PerformanceTargets.TargetPrecision <= 0 ||
           c.ML.AdaptiveThresholds.PerformanceTargets.TargetPrecision > 1 {
            errors = append(errors, "ml.adaptive_thresholds.performance_targets.target_precision must be between 0 and 1")
        }
    }
    
    // Validate threat intelligence settings
    if c.ThreatIntelligence.Enabled {
        if c.ThreatIntelligence.Database.Path == "" {
            errors = append(errors, "threat_intelligence.database.path is required")
        }
    }
    
    if len(errors) > 0 {
        return fmt.Errorf("configuration validation failed: %s", strings.Join(errors, ", "))
    }
    
    return nil
}
```

## 🧪 Testing Strategy

### Unit Testing

```go
// internal/detector/typosquatting_test.go
func TestTyposquattingDetector_Analyze(t *testing.T) {
    tests := []struct {
        name           string
        targetPackage  string
        candidatePackage string
        expectedSimilarity float64
        expectedThreat bool
    }{
        {
            name:           "exact_match",
            targetPackage:  "lodash",
            candidatePackage: "lodash",
            expectedSimilarity: 1.0,
            expectedThreat: false,
        },
        {
            name:           "typosquatting_detected",
            targetPackage:  "lodash",
            candidatePackage: "lodahs",
            expectedSimilarity: 0.83,
            expectedThreat: true,
        },
        {
            name:           "no_similarity",
            targetPackage:  "lodash",
            candidatePackage: "express",
            expectedSimilarity: 0.0,
            expectedThreat: false,
        },
    }
    
    detector := NewTyposquattingDetector(&Config{
        SimilarityThreshold: 0.8,
        Algorithms: []string{"levenshtein", "jaro_winkler"},
    })
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            pkg := &types.Package{
                Name: tt.candidatePackage,
                Ecosystem: "npm",
            }
            
            result, err := detector.Analyze(context.Background(), pkg)
            require.NoError(t, err)
            
            if tt.expectedThreat {
                assert.True(t, len(result.Threats) > 0)
                assert.Equal(t, "typosquatting", result.Threats[0].Type)
            } else {
                assert.Equal(t, 0, len(result.Threats))
            }
        })
    }
}
```

### Integration Testing

```go
// tests/integration/enhanced_integration_test.go
func TestEndToEndWorkflow(t *testing.T) {
    // Setup test environment
    testDir := setupTestEnvironment(t)
    defer cleanupTestEnvironment(testDir)
    
    // Load test configuration
    config := loadTestConfig(t, testDir)
    
    // Initialize components
    scanner := initializeScanner(t, config)
    threatIntel := initializeThreatIntelligence(t, config)
    plugins := initializePlugins(t, config)
    
    // Test package
    testPackage := &types.Package{
        Name:      "lodahs",
        Version:   "1.0.0",
        Ecosystem: "npm",
    }
    
    // Run scan
    result, err := scanner.ScanPackage(context.Background(), testPackage)
    require.NoError(t, err)
    require.NotNil(t, result)
    
    // Verify detection results
    assert.True(t, len(result.Threats) > 0)
    assert.Equal(t, "typosquatting", result.Threats[0].Type)
    assert.True(t, result.RiskScore > 0.8)
    
    // Verify threat intelligence correlation
    correlationResult, err := threatIntel.CorrelateThreat(context.Background(), testPackage)
    require.NoError(t, err)
    
    // Verify plugin execution
    err = plugins.ExecutePlugins(context.Background(), result)
    require.NoError(t, err)
    
    // Verify adaptive thresholds update
    stats := &ml.PerformanceStats{
        TruePositives:  1,
        FalsePositives: 0,
        TrueNegatives:  10,
        FalseNegatives: 0,
    }
    
    err = scanner.UpdatePerformanceStats("npm", stats)
    require.NoError(t, err)
}
```

### Performance Testing

```go
func BenchmarkConcurrentScanning(b *testing.B) {
    scanner := setupBenchmarkScanner()
    packages := generateTestPackages(1000)
    
    b.ResetTimer()
    b.RunParallel(func(pb *testing.PB) {
        for pb.Next() {
            pkg := packages[rand.Intn(len(packages))]
            _, err := scanner.ScanPackage(context.Background(), pkg)
            if err != nil {
                b.Fatal(err)
            }
        }
    })
}
```

## 🚀 Performance Optimization

### Caching Strategy

```go
// internal/cache/multilevel.go
type MultiLevelCache struct {
    memory     cache.Cache
    persistent cache.Cache
    metrics    *CacheMetrics
}

func (c *MultiLevelCache) Get(key string) interface{} {
    // Try memory cache first
    if value := c.memory.Get(key); value != nil {
        c.metrics.MemoryHits++
        return value
    }
    
    // Try persistent cache
    if value := c.persistent.Get(key); value != nil {
        c.metrics.PersistentHits++
        // Promote to memory cache
        c.memory.Set(key, value, time.Hour)
        return value
    }
    
    c.metrics.Misses++
    return nil
}
```

### Resource Management

```go
// internal/resources/manager.go
type ResourceManager struct {
    cpuLimit    float64
    memoryLimit int64
    semaphore   chan struct{}
    monitor     *ResourceMonitor
}

func (r *ResourceManager) AcquireResources(ctx context.Context) error {
    select {
    case r.semaphore <- struct{}{}:
        return nil
    case <-ctx.Done():
        return ctx.Err()
    }
}

func (r *ResourceManager) ReleaseResources() {
    <-r.semaphore
}

func (r *ResourceManager) MonitorUsage() {
    ticker := time.NewTicker(time.Second)
    defer ticker.Stop()
    
    for range ticker.C {
        usage := r.monitor.GetCurrentUsage()
        
        if usage.CPUPercent > r.cpuLimit {
            r.throttleOperations()
        }
        
        if usage.MemoryBytes > r.memoryLimit {
            r.triggerGarbageCollection()
        }
    }
}
```

## 🔐 Security Considerations

### Encryption

```go
// internal/security/encryption.go
func (e *EncryptionManager) Encrypt(data []byte) ([]byte, error) {
    block, err := aes.NewCipher(e.key)
    if err != nil {
        return nil, err
    }
    
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }
    
    nonce := make([]byte, gcm.NonceSize())
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        return nil, err
    }
    
    ciphertext := gcm.Seal(nonce, nonce, data, nil)
    return ciphertext, nil
}
```

### Authentication

```go
// internal/security/auth.go
func (a *AuthManager) ValidateJWT(tokenString string) (*Claims, error) {
    token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
        }
        return a.jwtSecret, nil
    })
    
    if err != nil {
        return nil, err
    }
    
    if claims, ok := token.Claims.(*Claims); ok && token.Valid {
        return claims, nil
    }
    
    return nil, fmt.Errorf("invalid token")
}
```

## 📦 Deployment

### Docker Deployment

```dockerfile
# Multi-stage build
FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o typosentinel ./cmd/typosentinel

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/

COPY --from=builder /app/typosentinel .
COPY --from=builder /app/config ./config

EXPOSE 8080
CMD ["./typosentinel", "serve", "--config", "config/typosentinel.yaml"]
```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: typosentinel
spec:
  replicas: 3
  selector:
    matchLabels:
      app: typosentinel
  template:
    metadata:
      labels:
        app: typosentinel
    spec:
      containers:
      - name: typosentinel
        image: typosentinel/typosentinel:latest
        ports:
        - containerPort: 8080
        env:
        - name: CONFIG_PATH
          value: "/etc/typosentinel/config.yaml"
        volumeMounts:
        - name: config
          mountPath: /etc/typosentinel
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
      volumes:
      - name: config
        configMap:
          name: typosentinel-config
```

## 🔧 Troubleshooting

### Common Issues

1. **High Memory Usage**
   - Check cache configuration
   - Monitor concurrent scan limits
   - Review threat intelligence database size

2. **Slow Performance**
   - Enable performance profiling
   - Check database query performance
   - Review ML model complexity

3. **Plugin Failures**
   - Verify plugin configuration
   - Check network connectivity
   - Review authentication settings

### Debugging

```bash
# Enable debug logging
typosentinel scan --debug --log-level debug package.json

# Profile performance
typosentinel scan --profile-cpu --profile-memory package.json

# Check component health
typosentinel health check --verbose

# Validate configuration
typosentinel config validate --config config/typosentinel.yaml
```

### Monitoring

```bash
# View metrics
curl http://localhost:9090/metrics

# Check plugin status
typosentinel plugins status

# Monitor threat intelligence
typosentinel threats status

# View ML model performance
typosentinel ml metrics show
```

This development guide provides comprehensive information for working with Typosentinel Enhanced. For additional support, please refer to the main README or contact the development team.