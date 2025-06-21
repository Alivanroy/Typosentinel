# Typosentinel API Documentation

This document provides comprehensive documentation for the Typosentinel API, including usage examples, configuration options, and best practices.

## Table of Contents

1. [Overview](#overview)
2. [Installation](#installation)
3. [Quick Start](#quick-start)
4. [Configuration](#configuration)
5. [Core APIs](#core-apis)
6. [Package Analyzers](#package-analyzers)
7. [Threat Detection](#threat-detection)
8. [ML Integration](#ml-integration)
9. [Reputation System](#reputation-system)
10. [Performance Optimization](#performance-optimization)
11. [Benchmarking and Testing](#benchmarking-and-testing)
12. [Examples](#examples)
13. [Error Handling](#error-handling)
14. [Best Practices](#best-practices)

## Overview

Typosentinel is a comprehensive package security scanner that detects typosquatting, dependency confusion, and other supply chain attacks across multiple package managers including npm, PyPI, RubyGems, Maven, NuGet, Composer, and Cargo.

### Key Features

- **Multi-language Support**: Supports 7+ package managers
- **Advanced Threat Detection**: ML-powered typosquatting detection
- **Reputation Analysis**: Multi-source reputation scoring
- **Performance Optimized**: Concurrent processing with caching
- **Comprehensive Benchmarking**: Built-in performance testing suite
- **Memory Efficient**: Optimized memory allocation and garbage collection
- **Concurrent Scanning**: High-throughput parallel analysis capabilities
- **Extensible Architecture**: Plugin-based analyzer system

## Installation

### From Source

```bash
git clone https://github.com/alikorsi/typosentinel.git
cd typosentinel
go build -o typosentinel
```

### Using Go Install

```bash
go install github.com/alikorsi/typosentinel@latest
```

### Docker

```bash
docker pull typosentinel:latest
docker run -v $(pwd):/workspace typosentinel scan /workspace
```

## Quick Start

### Basic Scanning

```bash
# Scan current directory
typosentinel scan .

# Scan specific project
typosentinel scan /path/to/project

# Scan with specific output format
typosentinel scan . --format json --output results.json
```

### Programmatic Usage

```go
package main

import (
    "context"
    "fmt"
    "log"
    
    "typosentinel/internal/config"
    "typosentinel/internal/scanner"
)

func main() {
    // Load configuration
    cfg, err := config.Load("config.yaml")
    if err != nil {
        log.Fatal(err)
    }
    
    // Create scanner
    scanner := scanner.NewScanner(cfg)
    
    // Scan project
    ctx := context.Background()
    result, err := scanner.ScanProject(ctx, "/path/to/project")
    if err != nil {
        log.Fatal(err)
    }
    
    // Process results
    fmt.Printf("Found %d packages with %d threats\n", 
        len(result.Packages), len(result.Threats))
}
```

## Configuration

### Configuration File Structure

```yaml
# config.yaml
scanner:
  timeout: 30s
  max_concurrency: 10
  exclude_patterns:
    - ".git"
    - "node_modules"
    - ".vscode"
  include_dev_dependencies: true

analyzer:
  timeout: 30s
  max_concurrency: 10
  cache_size: 1000
  cache_ttl: 1h
  enabled_analyzers:
    - npm
    - pypi
    - rubygems
    - maven
    - nuget
    - composer
    - cargo

detector:
  enabled: true
  timeout: 30s
  max_concurrency: 10
  cache_size: 1000
  cache_ttl: 1h
  algorithms:
    - levenshtein
    - jaro_winkler
    - homoglyph
    - keyboard_layout
  thresholds:
    typosquatting: 0.8
    dependency_confusion: 0.9
    reputation: 0.7

ml_service:
  enabled: true
  endpoint: "http://localhost:8001"
  api_key: "your-api-key"
  timeout: 30s
  model_version: "1.2.0"

reputation:
  enabled: true
  cache_size: 1000
  cache_ttl: 1h
  timeout: 30s
  max_retries: 3
  retry_delay: 1s
  sources:
    - name: "virustotal"
      endpoint: "https://www.virustotal.com/api/v3"
      api_key: "your-vt-api-key"
      weight: 0.4
      enabled: true
    - name: "security_scanner"
      endpoint: "http://localhost:8002"
      api_key: "your-scanner-key"
      weight: 0.6
      enabled: true

logging:
  level: "info"
  format: "json"
  output: "stdout"

metrics:
  enabled: true
  port: 9090
  path: "/metrics"
```

### Environment Variables

```bash
# Override configuration with environment variables
export TYPOSENTINEL_ML_API_KEY="your-ml-api-key"
export TYPOSENTINEL_REPUTATION_VIRUSTOTAL_API_KEY="your-vt-key"
export TYPOSENTINEL_LOG_LEVEL="debug"
export TYPOSENTINEL_SCANNER_TIMEOUT="60s"
```

## Core APIs

### Scanner API

```go
type Scanner interface {
    ScanProject(ctx context.Context, projectPath string) (*types.ScanResult, error)
    ScanPackages(ctx context.Context, packages []*types.Package) (*types.ScanResult, error)
}

// Create scanner
scanner := scanner.NewScanner(config)

// Scan project
result, err := scanner.ScanProject(ctx, "/path/to/project")
if err != nil {
    return err
}

// Access results
fmt.Printf("Scanned %d packages\n", len(result.Packages))
fmt.Printf("Found %d threats\n", len(result.Threats))
for _, threat := range result.Threats {
    fmt.Printf("Threat: %s - %s\n", threat.Type, threat.Description)
}
```

### Analyzer API

```go
type Analyzer interface {
    AnalyzeProject(ctx context.Context, projectPath string) (*types.AnalysisResult, error)
    AnalyzePackage(ctx context.Context, pkg *types.Package) (*types.AnalysisResult, error)
    AnalyzePackages(ctx context.Context, packages []*types.Package) ([]*types.AnalysisResult, error)
    GetSupportedFiles() []string
    GetRegistry() string
}

// Create analyzer
analyzer := analyzer.NewAnalyzer(config)

// Analyze single package
pkg := &types.Package{
    Name:     "express",
    Version:  "4.18.2",
    Registry: "npm",
}

result, err := analyzer.AnalyzePackage(ctx, pkg)
if err != nil {
    return err
}

fmt.Printf("Risk Score: %.2f\n", result.RiskScore)
fmt.Printf("Threat Level: %s\n", result.ThreatLevel)
```

### Detector API

```go
type Engine interface {
    CheckPackage(ctx context.Context, pkg *types.Package) (*types.DetectionResult, error)
    CheckPackages(ctx context.Context, packages []*types.Package) ([]*types.DetectionResult, error)
    GetPopularPackages(registry string) ([]string, error)
}

// Create detector engine
engine := detector.NewEngine(config)

// Check package for threats
result, err := engine.CheckPackage(ctx, pkg)
if err != nil {
    return err
}

for _, threat := range result.Threats {
    fmt.Printf("Detected: %s (confidence: %.2f)\n", 
        threat.Type, threat.Confidence)
}
```

## Package Analyzers

### NPM Analyzer

```go
// Supports: package.json, package-lock.json, yarn.lock
npmAnalyzer := analyzer.NewNPMAnalyzer(config)

// Analyze npm project
result, err := npmAnalyzer.AnalyzeProject(ctx, "/path/to/node/project")
if err != nil {
    return err
}

// Access npm-specific information
for _, pkg := range result.Packages {
    fmt.Printf("Package: %s@%s\n", pkg.Name, pkg.Version)
    if pkg.DevDependency {
        fmt.Println("  (dev dependency)")
    }
}
```

### Python Analyzer

```go
// Supports: requirements.txt, Pipfile, pyproject.toml, setup.py
pythonAnalyzer := analyzer.NewPythonAnalyzer(config)

// Analyze Python project
result, err := pythonAnalyzer.AnalyzeProject(ctx, "/path/to/python/project")
if err != nil {
    return err
}

// Check for Python-specific threats
for _, pkg := range result.Packages {
    if strings.Contains(pkg.Name, "_") {
        fmt.Printf("Warning: Package %s uses underscores\n", pkg.Name)
    }
}
```

### Ruby Analyzer

```go
// Supports: Gemfile, Gemfile.lock
rubyAnalyzer := analyzer.NewRubyAnalyzer(config)

// Analyze Ruby project
result, err := rubyAnalyzer.AnalyzeProject(ctx, "/path/to/ruby/project")
if err != nil {
    return err
}

// Access gem information
for _, pkg := range result.Packages {
    fmt.Printf("Gem: %s (%s)\n", pkg.Name, pkg.Version)
}
```

### Multi-Language Projects

```go
// Scan project with multiple package managers
scanner := scanner.NewScanner(config)
result, err := scanner.ScanProject(ctx, "/path/to/polyglot/project")
if err != nil {
    return err
}

// Group packages by registry
packagesByRegistry := make(map[string][]*types.Package)
for _, pkg := range result.Packages {
    packagesByRegistry[pkg.Registry] = append(
        packagesByRegistry[pkg.Registry], pkg)
}

for registry, packages := range packagesByRegistry {
    fmt.Printf("%s: %d packages\n", registry, len(packages))
}
```

## Threat Detection

### Typosquatting Detection

```go
// Configure typosquatting detection
config := &config.Config{
    Detector: config.DetectorConfig{
        Algorithms: []string{
            "levenshtein",
            "jaro_winkler", 
            "homoglyph",
            "keyboard_layout",
        },
        Thresholds: map[string]float64{
            "typosquatting": 0.8,
        },
    },
}

engine := detector.NewEngine(config)

// Check for typosquatting
pkg := &types.Package{
    Name:     "expres", // Typo of "express"
    Version:  "1.0.0",
    Registry: "npm",
}

result, err := engine.CheckPackage(ctx, pkg)
if err != nil {
    return err
}

for _, threat := range result.Threats {
    if threat.Type == "typosquatting" {
        fmt.Printf("Typosquatting detected: %s\n", threat.Description)
        fmt.Printf("Similar to: %s\n", threat.SimilarPackage)
        fmt.Printf("Confidence: %.2f\n", threat.Confidence)
    }
}
```

### Dependency Confusion

```go
// Check for dependency confusion attacks
pkg := &types.Package{
    Name:     "internal-package", // Internal package name
    Version:  "2.0.0",           // Higher version than internal
    Registry: "npm",
}

result, err := engine.CheckPackage(ctx, pkg)
if err != nil {
    return err
}

for _, threat := range result.Threats {
    if threat.Type == "dependency_confusion" {
        fmt.Printf("Dependency confusion risk: %s\n", threat.Description)
        fmt.Printf("Mitigation: %s\n", threat.Mitigation)
    }
}
```

### Custom Threat Rules

```go
// Define custom threat detection rules
type CustomRule struct {
    Name        string
    Pattern     string
    Severity    string
    Description string
}

rules := []CustomRule{
    {
        Name:        "suspicious_name",
        Pattern:     ".*[0-9]{4,}.*", // Packages with many numbers
        Severity:    "medium",
        Description: "Package name contains suspicious number pattern",
    },
    {
        Name:        "short_name",
        Pattern:     "^.{1,2}$", // Very short names
        Severity:    "low",
        Description: "Package name is unusually short",
    },
}

// Apply custom rules
for _, pkg := range packages {
    for _, rule := range rules {
        matched, _ := regexp.MatchString(rule.Pattern, pkg.Name)
        if matched {
            fmt.Printf("Custom rule '%s' triggered for %s\n", 
                rule.Name, pkg.Name)
        }
    }
}
```

## ML Integration

### ML Service Configuration

```go
// Configure ML service
config := &config.Config{
    MLService: config.MLServiceConfig{
        Enabled:      true,
        Endpoint:     "http://localhost:8001",
        APIKey:       "your-api-key",
        Timeout:      30 * time.Second,
        ModelVersion: "1.2.0",
    },
}

// Create ML analyzer
mlAnalyzer := ml.NewAnalyzer(config)

// Analyze package with ML
result, err := mlAnalyzer.AnalyzePackage(ctx, pkg)
if err != nil {
    return err
}

fmt.Printf("ML Risk Score: %.2f\n", result.RiskScore)
fmt.Printf("ML Confidence: %.2f\n", result.Confidence)

// Access ML features
features := result.Features
fmt.Printf("Lexical Similarity: %.2f\n", features.LexicalSimilarity)
fmt.Printf("Homoglyph Score: %.2f\n", features.HomoglyphScore)
fmt.Printf("Reputation Score: %.2f\n", features.ReputationScore)
```

### Batch ML Analysis

```go
// Analyze multiple packages with ML
packages := []*types.Package{
    {Name: "express", Version: "4.18.2", Registry: "npm"},
    {Name: "lodash", Version: "4.17.21", Registry: "npm"},
    {Name: "axios", Version: "0.27.2", Registry: "npm"},
}

results, err := mlAnalyzer.AnalyzePackages(ctx, packages)
if err != nil {
    return err
}

for i, result := range results {
    fmt.Printf("Package %s: Risk %.2f, Confidence %.2f\n",
        packages[i].Name, result.RiskScore, result.Confidence)
}
```

### ML Model Monitoring

```go
// Monitor ML model performance
type MLMetrics struct {
    TotalRequests    int64
    SuccessfulRequests int64
    AverageLatency   time.Duration
    ErrorRate        float64
}

func monitorMLPerformance(analyzer *ml.Analyzer) {
    ticker := time.NewTicker(1 * time.Minute)
    defer ticker.Stop()
    
    for range ticker.C {
        metrics := analyzer.GetMetrics()
        fmt.Printf("ML Metrics: Requests=%d, Success=%.2f%%, Latency=%v\n",
            metrics.TotalRequests,
            float64(metrics.SuccessfulRequests)/float64(metrics.TotalRequests)*100,
            metrics.AverageLatency)
    }
}
```

## Reputation System

### Multi-Source Reputation

```go
// Configure multiple reputation sources
config := &config.Config{
    Reputation: config.ReputationConfig{
        Sources: []config.ReputationSource{
            {
                Name:     "virustotal",
                Endpoint: "https://www.virustotal.com/api/v3",
                APIKey:   "your-vt-key",
                Weight:   0.4,
                Enabled:  true,
            },
            {
                Name:     "security_scanner",
                Endpoint: "http://localhost:8002",
                APIKey:   "your-scanner-key",
                Weight:   0.6,
                Enabled:  true,
            },
        },
    },
}

// Create reputation analyzer
repAnalyzer := reputation.NewAnalyzer(config)

// Get reputation score
result, err := repAnalyzer.AnalyzePackage(ctx, pkg)
if err != nil {
    return err
}

fmt.Printf("Overall Score: %.2f\n", result.Score)
fmt.Printf("Risk Level: %s\n", result.Risk)

// Check individual sources
for _, source := range result.Sources {
    fmt.Printf("Source %s: Score %.2f (Weight %.2f)\n",
        source.Name, source.Score, source.Weight)
}
```

### Reputation Caching

```go
// Configure reputation caching
config := &config.Config{
    Reputation: config.ReputationConfig{
        CacheSize: 10000,
        CacheTTL:  24 * time.Hour, // Cache for 24 hours
    },
}

// Cache will automatically be used for subsequent requests
result1, _ := repAnalyzer.AnalyzePackage(ctx, pkg) // Network request
result2, _ := repAnalyzer.AnalyzePackage(ctx, pkg) // Cache hit
```

### Custom Reputation Sources

```go
// Implement custom reputation source
type CustomReputationSource struct {
    name     string
    endpoint string
    client   *http.Client
}

func (c *CustomReputationSource) GetReputation(pkg *types.Package) (*reputation.Response, error) {
    // Custom reputation logic
    url := fmt.Sprintf("%s/check?package=%s&registry=%s", 
        c.endpoint, pkg.Name, pkg.Registry)
    
    resp, err := c.client.Get(url)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    var result reputation.Response
    err = json.NewDecoder(resp.Body).Decode(&result)
    return &result, err
}
```

## Performance Optimization

### Concurrent Processing

```go
// Configure concurrency
config := &config.Config{
    Scanner: config.ScannerConfig{
        MaxConcurrency: runtime.NumCPU() * 2,
    },
    Analyzer: config.AnalyzerConfig{
        MaxConcurrency: 20,
    },
    Detector: config.DetectorConfig{
        MaxConcurrency: 15,
    },
}

// Process packages concurrently
func processPackagesConcurrently(packages []*types.Package, analyzer *analyzer.Analyzer) {
    semaphore := make(chan struct{}, 10) // Limit to 10 concurrent operations
    var wg sync.WaitGroup
    
    for _, pkg := range packages {
        wg.Add(1)
        go func(p *types.Package) {
            defer wg.Done()
            semaphore <- struct{}{} // Acquire
            defer func() { <-semaphore }() // Release
            
            result, err := analyzer.AnalyzePackage(ctx, p)
            if err != nil {
                log.Printf("Error analyzing %s: %v", p.Name, err)
                return
            }
            
            // Process result
            processResult(result)
        }(pkg)
    }
    
    wg.Wait()
}
```

### Caching Strategies

```go
// Configure multi-level caching
config := &config.Config{
    Analyzer: config.AnalyzerConfig{
        CacheSize: 10000,
        CacheTTL:  2 * time.Hour,
    },
    Detector: config.DetectorConfig{
        CacheSize: 5000,
        CacheTTL:  1 * time.Hour,
    },
    Reputation: config.ReputationConfig{
        CacheSize: 20000,
        CacheTTL:  24 * time.Hour,
    },
}

// Implement custom cache warming
func warmCache(analyzer *analyzer.Analyzer, popularPackages []string) {
    for _, pkgName := range popularPackages {
        pkg := &types.Package{
            Name:     pkgName,
            Version:  "latest",
            Registry: "npm",
        }
        
        go func(p *types.Package) {
            analyzer.AnalyzePackage(context.Background(), p)
        }(pkg)
    }
}
```

### Memory Optimization

```go
// Monitor memory usage
func monitorMemory() {
    ticker := time.NewTicker(30 * time.Second)
    defer ticker.Stop()
    
    for range ticker.C {
        var m runtime.MemStats
        runtime.ReadMemStats(&m)
        
        fmt.Printf("Memory: Alloc=%d KB, Sys=%d KB, NumGC=%d\n",
            m.Alloc/1024, m.Sys/1024, m.NumGC)
        
        // Force GC if memory usage is high
        if m.Alloc > 500*1024*1024 { // 500MB
            runtime.GC()
        }
    }
}

// Optimize large batch processing
func processBatchesOptimized(packages []*types.Package, batchSize int) {
    for i := 0; i < len(packages); i += batchSize {
        end := i + batchSize
        if end > len(packages) {
            end = len(packages)
        }
        
        batch := packages[i:end]
        processBatch(batch)
        
        // Force GC between batches
        runtime.GC()
    }
}
```

## Benchmarking and Testing

### Running Performance Benchmarks

Typosentinel includes a comprehensive benchmark suite for performance testing and optimization:

```go
// Run all benchmarks
go test -bench=. ./internal/benchmark/

// Run specific benchmark categories
go test -bench=BenchmarkConcurrentScans ./internal/benchmark/
go test -bench=BenchmarkMemoryUsage ./internal/benchmark/
go test -bench=BenchmarkThroughput ./internal/benchmark/

// Run benchmarks with memory profiling
go test -bench=. -benchmem ./internal/benchmark/

// Generate CPU profile during benchmarks
go test -bench=BenchmarkLargePackage -cpuprofile=cpu.prof ./internal/benchmark/
```

### Available Benchmark Categories

#### Package Size Benchmarks
- **BenchmarkSmallPackage**: Tests performance on small packages (< 10 files)
- **BenchmarkMediumPackage**: Tests performance on medium packages (10-100 files)
- **BenchmarkLargePackage**: Tests performance on large packages (> 100 files)

#### Concurrency Benchmarks
- **BenchmarkConcurrentScans2**: Tests multi-threaded scanning performance
- **BenchmarkThroughput**: Measures package processing throughput

#### Memory Benchmarks
- **BenchmarkMemoryUsage2**: Analyzes memory allocation patterns
- **BenchmarkStressTest**: Tests system limits and error handling

#### ML Analysis Benchmarks
- **BenchmarkMLAnalysis**: Tests machine learning detection performance

### Custom Benchmark Configuration

```go
// Create custom benchmark suite
suite := &benchmark.BenchmarkSuite{
    Duration:       30 * time.Second,
    Parallel:       runtime.NumCPU(),
    Iterations:     1000,
    WarmupDuration: 5 * time.Second,
    Verbose:        true,
}

// Run custom benchmarks
results := suite.RunBenchmarks()
fmt.Printf("Benchmark Results: %+v\n", results)
```

### Performance Metrics

The benchmark suite provides detailed metrics:

```go
type BenchmarkMetrics struct {
    Duration      time.Duration `json:"duration"`
    Operations    int           `json:"operations"`
    OpsPerSecond  float64       `json:"ops_per_second"`
    AvgTimePerOp  time.Duration `json:"avg_time_per_op"`
    MemoryPerOp   uint64        `json:"memory_per_op"`
    AllocsPerOp   uint64        `json:"allocs_per_op"`
    ErrorRate     float64       `json:"error_rate"`
    ThroughputMB  float64       `json:"throughput_mb"`
}
```

## Examples

### Complete Scanning Workflow

```go
package main

import (
    "context"
    "encoding/json"
    "fmt"
    "log"
    "os"
    "time"
    
    "typosentinel/internal/config"
    "typosentinel/internal/scanner"
    "typosentinel/pkg/types"
)

func main() {
    // Load configuration
    cfg, err := config.Load("config.yaml")
    if err != nil {
        log.Fatal("Failed to load config:", err)
    }
    
    // Create scanner with timeout
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
    defer cancel()
    
    scanner := scanner.NewScanner(cfg)
    
    // Scan project
    projectPath := os.Args[1]
    result, err := scanner.ScanProject(ctx, projectPath)
    if err != nil {
        log.Fatal("Scan failed:", err)
    }
    
    // Generate report
    report := generateReport(result)
    
    // Save results
    saveResults(report, "scan-results.json")
    
    // Print summary
    printSummary(result)
}

func generateReport(result *types.ScanResult) *types.Report {
    report := &types.Report{
        Timestamp:    time.Now(),
        ProjectPath:  result.ProjectPath,
        TotalPackages: len(result.Packages),
        TotalThreats:  len(result.Threats),
        ScanDuration: result.Duration,
    }
    
    // Categorize threats
    threatCounts := make(map[string]int)
    for _, threat := range result.Threats {
        threatCounts[threat.Type]++
    }
    report.ThreatBreakdown = threatCounts
    
    // Calculate risk score
    report.OverallRiskScore = calculateOverallRisk(result.Threats)
    
    return report
}

func saveResults(report *types.Report, filename string) {
    data, err := json.MarshalIndent(report, "", "  ")
    if err != nil {
        log.Printf("Failed to marshal report: %v", err)
        return
    }
    
    err = os.WriteFile(filename, data, 0644)
    if err != nil {
        log.Printf("Failed to save report: %v", err)
        return
    }
    
    fmt.Printf("Report saved to %s\n", filename)
}

func printSummary(result *types.ScanResult) {
    fmt.Printf("\n=== Scan Summary ===\n")
    fmt.Printf("Project: %s\n", result.ProjectPath)
    fmt.Printf("Packages scanned: %d\n", len(result.Packages))
    fmt.Printf("Threats found: %d\n", len(result.Threats))
    fmt.Printf("Scan duration: %v\n", result.Duration)
    
    if len(result.Threats) > 0 {
        fmt.Printf("\n=== Threats ===\n")
        for _, threat := range result.Threats {
            fmt.Printf("- %s: %s (Confidence: %.2f)\n",
                threat.Type, threat.Description, threat.Confidence)
        }
    }
}

func calculateOverallRisk(threats []*types.Threat) float64 {
    if len(threats) == 0 {
        return 0.0
    }
    
    totalRisk := 0.0
    for _, threat := range threats {
        switch threat.Severity {
        case "critical":
            totalRisk += 1.0
        case "high":
            totalRisk += 0.8
        case "medium":
            totalRisk += 0.5
        case "low":
            totalRisk += 0.2
        }
    }
    
    return totalRisk / float64(len(threats))
}
```

### CI/CD Integration

```yaml
# .github/workflows/security-scan.yml
name: Security Scan

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Go
      uses: actions/setup-go@v3
      with:
        go-version: 1.21
    
    - name: Install Typosentinel
      run: go install github.com/alikorsi/typosentinel@latest
    
    - name: Run Security Scan
      run: |
        typosentinel scan . \
          --format json \
          --output security-report.json \
          --fail-on-threats
    
    - name: Upload Security Report
      uses: actions/upload-artifact@v3
      if: always()
      with:
        name: security-report
        path: security-report.json
    
    - name: Comment PR
      if: github.event_name == 'pull_request'
      uses: actions/github-script@v6
      with:
        script: |
          const fs = require('fs');
          const report = JSON.parse(fs.readFileSync('security-report.json', 'utf8'));
          
          const comment = `## Security Scan Results
          
          - **Packages Scanned:** ${report.total_packages}
          - **Threats Found:** ${report.total_threats}
          - **Risk Score:** ${report.overall_risk_score.toFixed(2)}
          
          ${report.total_threats > 0 ? '⚠️ Security threats detected!' : '✅ No security threats found'}`;
          
          github.rest.issues.createComment({
            issue_number: context.issue.number,
            owner: context.repo.owner,
            repo: context.repo.repo,
            body: comment
          });
```

### Docker Integration

```dockerfile
# Dockerfile for Typosentinel
FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -o typosentinel .

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/

COPY --from=builder /app/typosentinel .
COPY --from=builder /app/config.yaml .

CMD ["./typosentinel"]
```

```bash
# Build and run with Docker
docker build -t typosentinel .
docker run -v $(pwd):/workspace typosentinel scan /workspace
```

## Error Handling

### Graceful Error Handling

```go
func robustScan(scanner *scanner.Scanner, projectPath string) (*types.ScanResult, error) {
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
    defer cancel()
    
    // Retry logic
    maxRetries := 3
    var lastErr error
    
    for attempt := 1; attempt <= maxRetries; attempt++ {
        result, err := scanner.ScanProject(ctx, projectPath)
        if err == nil {
            return result, nil
        }
        
        lastErr = err
        
        // Check if error is retryable
        if !isRetryableError(err) {
            break
        }
        
        // Exponential backoff
        backoff := time.Duration(attempt*attempt) * time.Second
        log.Printf("Attempt %d failed: %v. Retrying in %v...", attempt, err, backoff)
        
        select {
        case <-time.After(backoff):
            continue
        case <-ctx.Done():
            return nil, ctx.Err()
        }
    }
    
    return nil, fmt.Errorf("scan failed after %d attempts: %w", maxRetries, lastErr)
}

func isRetryableError(err error) bool {
    // Network errors, timeouts, and temporary failures are retryable
    if strings.Contains(err.Error(), "timeout") ||
       strings.Contains(err.Error(), "connection refused") ||
       strings.Contains(err.Error(), "temporary failure") {
        return true
    }
    return false
}
```

### Error Recovery

```go
func scanWithRecovery(scanner *scanner.Scanner, packages []*types.Package) []*types.ScanResult {
    results := make([]*types.ScanResult, 0, len(packages))
    errors := make([]error, 0)
    
    for _, pkg := range packages {
        func() {
            defer func() {
                if r := recover(); r != nil {
                    log.Printf("Recovered from panic while scanning %s: %v", pkg.Name, r)
                    errors = append(errors, fmt.Errorf("panic: %v", r))
                }
            }()
            
            ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
            defer cancel()
            
            result, err := scanner.ScanPackages(ctx, []*types.Package{pkg})
            if err != nil {
                log.Printf("Error scanning %s: %v", pkg.Name, err)
                errors = append(errors, err)
                return
            }
            
            results = append(results, result)
        }()
    }
    
    if len(errors) > 0 {
        log.Printf("Encountered %d errors during scanning", len(errors))
    }
    
    return results
}
```

## Best Practices

### Configuration Management

```go
// Use environment-specific configurations
func loadConfig() (*config.Config, error) {
    env := os.Getenv("ENVIRONMENT")
    if env == "" {
        env = "development"
    }
    
    configFile := fmt.Sprintf("config-%s.yaml", env)
    
    cfg, err := config.Load(configFile)
    if err != nil {
        // Fallback to default config
        cfg = config.Default()
    }
    
    // Override with environment variables
    cfg.ApplyEnvironmentOverrides()
    
    return cfg, nil
}
```

### Resource Management

```go
// Proper resource cleanup
func scanWithCleanup(projectPath string) error {
    cfg, err := loadConfig()
    if err != nil {
        return err
    }
    
    scanner := scanner.NewScanner(cfg)
    defer scanner.Close() // Cleanup resources
    
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
    defer cancel()
    
    result, err := scanner.ScanProject(ctx, projectPath)
    if err != nil {
        return err
    }
    
    return processResults(result)
}
```

### Monitoring and Observability

```go
// Add comprehensive monitoring
func monitoredScan(scanner *scanner.Scanner, projectPath string) (*types.ScanResult, error) {
    start := time.Now()
    
    // Increment scan counter
    metrics.ScanCounter.Inc()
    
    defer func() {
        // Record scan duration
        duration := time.Since(start)
        metrics.ScanDuration.Observe(duration.Seconds())
    }()
    
    ctx := context.Background()
    result, err := scanner.ScanProject(ctx, projectPath)
    
    if err != nil {
        metrics.ScanErrors.Inc()
        return nil, err
    }
    
    // Record threat metrics
    metrics.ThreatsFound.Add(float64(len(result.Threats)))
    metrics.PackagesScanned.Add(float64(len(result.Packages)))
    
    return result, nil
}
```

### Security Considerations

```go
// Secure API key handling
func secureConfig() *config.Config {
    cfg := &config.Config{}
    
    // Never hardcode API keys
    cfg.MLService.APIKey = os.Getenv("TYPOSENTINEL_ML_API_KEY")
    cfg.Reputation.Sources[0].APIKey = os.Getenv("VIRUSTOTAL_API_KEY")
    
    // Validate API keys are present
    if cfg.MLService.APIKey == "" {
        log.Fatal("ML_API_KEY environment variable is required")
    }
    
    // Use secure defaults
    cfg.Scanner.Timeout = 30 * time.Second
    cfg.Analyzer.MaxConcurrency = 10
    
    return cfg
}

// Input validation
func validatePackage(pkg *types.Package) error {
    if pkg.Name == "" {
        return errors.New("package name cannot be empty")
    }
    
    if len(pkg.Name) > 214 { // npm package name limit
        return errors.New("package name too long")
    }
    
    // Validate package name format
    validName := regexp.MustCompile(`^[a-z0-9._-]+$`)
    if !validName.MatchString(pkg.Name) {
        return errors.New("invalid package name format")
    }
    
    return nil
}
```

This comprehensive API documentation provides detailed examples and best practices for using Typosentinel effectively in various scenarios, from simple scans to complex enterprise integrations.