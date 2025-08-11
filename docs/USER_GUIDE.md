# Typosentinel User Guide

A comprehensive guide to using Typosentinel for package security scanning and threat detection.

## Table of Contents

1. [Getting Started](#getting-started)
2. [Basic Usage](#basic-usage)
3. [Advanced Features](#advanced-features)
4. [Supply Chain Security](#supply-chain-security)
5. [Edge Algorithms](#edge-algorithms)
6. [Web Interface](#web-interface)
7. [Organization Scanning](#organization-scanning)
8. [Performance Testing](#performance-testing)
9. [Configuration Guide](#configuration-guide)
10. [Language-Specific Guides](#language-specific-guides)
11. [Integration Examples](#integration-examples)
12. [Troubleshooting](#troubleshooting)
13. [FAQ](#faq)

## Getting Started

### Installation

#### Option 1: Download Binary

```bash
# Download the latest release
wget https://github.com/alikorsi/typosentinel/releases/latest/download/typosentinel-linux-amd64
chmod +x typosentinel-linux-amd64
sudo mv typosentinel-linux-amd64 /usr/local/bin/typosentinel
```

#### Option 2: Build from Source

```bash
git clone https://github.com/alikorsi/typosentinel.git
cd typosentinel
go build -o typosentinel
```

#### Option 3: Using Docker

```bash
docker pull typosentinel:latest
```

### First Scan

Run your first security scan:

```bash
# Scan current directory
typosentinel scan .

# Scan specific project
typosentinel scan /path/to/your/project
```

### Understanding Output

Typosentinel provides detailed output about detected threats:

```
🔍 Scanning project: /home/user/my-project
📦 Found 45 packages across 3 registries
⚠️  Detected 2 potential threats

=== THREATS DETECTED ===

🚨 HIGH SEVERITY - Typosquatting
Package: expres (npm)
Version: 1.0.0
Similar to: express
Confidence: 95%
Description: Package name is suspiciously similar to popular package 'express'
Mitigation: Verify package authenticity and use official 'express' package

⚠️  MEDIUM SEVERITY - Suspicious Package
Package: crypto-utils-2023 (npm)
Version: 2.1.0
Reason: Package name contains year pattern often used in malicious packages
Confidence: 78%

=== SCAN SUMMARY ===
Total packages: 45
Threats found: 2
Scan duration: 3.2s
Overall risk score: 6.5/10
```

## Basic Usage

### Command Line Interface

#### Scan Commands

```bash
# Basic scan
typosentinel scan .

# Scan with specific output format
typosentinel scan . --format json
typosentinel scan . --format yaml
typosentinel scan . --format table

# Save results to file
typosentinel scan . --output results.json

# Scan specific package managers only
typosentinel scan . --analyzers npm,pypi

# Include development dependencies
typosentinel scan . --include-dev

# Set custom timeout
typosentinel scan . --timeout 60s

# Verbose output
typosentinel scan . --verbose

# Fail on any threats (useful for CI/CD)
typosentinel scan . --fail-on-threats
```

#### Configuration Commands

```bash
# Generate default configuration
typosentinel config init

# Validate configuration
typosentinel config validate

# Show current configuration
typosentinel config show
```

#### Utility Commands

```bash
# Check specific package
typosentinel check express --registry npm

# List supported analyzers
typosentinel analyzers list

# Show version information
typosentinel version

# Show help
typosentinel help
```

### Output Formats

#### JSON Output

```bash
typosentinel scan . --format json --output results.json
```

```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "project_path": "/home/user/my-project",
  "scan_duration": "3.2s",
  "total_packages": 45,
  "total_threats": 2,
  "overall_risk_score": 6.5,
  "packages": [
    {
      "name": "express",
      "version": "4.18.2",
      "registry": "npm",
      "file_path": "package.json",
      "dev_dependency": false,
      "risk_score": 1.2,
      "threat_level": "low"
    }
  ],
  "threats": [
    {
      "id": "threat-001",
      "type": "typosquatting",
      "severity": "high",
      "package_name": "expres",
      "package_version": "1.0.0",
      "registry": "npm",
      "confidence": 0.95,
      "description": "Package name is suspiciously similar to popular package 'express'",
      "similar_package": "express",
      "mitigation": "Verify package authenticity and use official 'express' package",
      "references": [
        "https://www.npmjs.com/package/express"
      ]
    }
  ],
  "registries": {
    "npm": {
      "packages": 42,
      "threats": 2
    },
    "pypi": {
      "packages": 3,
      "threats": 0
    }
  }
}
```

#### YAML Output

```bash
typosentinel scan . --format yaml
```

```yaml
timestamp: "2024-01-15T10:30:00Z"
project_path: "/home/user/my-project"
scan_duration: "3.2s"
total_packages: 45
total_threats: 2
overall_risk_score: 6.5
packages:
  - name: express
    version: 4.18.2
    registry: npm
    file_path: package.json
    dev_dependency: false
    risk_score: 1.2
    threat_level: low
threats:
  - id: threat-001
    type: typosquatting
    severity: high
    package_name: expres
    confidence: 0.95
    description: "Package name is suspiciously similar to popular package 'express'"
    mitigation: "Verify package authenticity and use official 'express' package"
```

## Advanced Features

### Custom Configuration

Create a `typosentinel.yaml` configuration file:

```yaml
# typosentinel.yaml
scanner:
  timeout: 60s
  max_concurrency: 20
  exclude_patterns:
    - ".git"
    - "node_modules"
    - "vendor"
    - ".vscode"
  include_dev_dependencies: true

analyzer:
  timeout: 30s
  max_concurrency: 15
  cache_size: 5000
  cache_ttl: 2h
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
  algorithms:
    - levenshtein
    - jaro_winkler
    - homoglyph
    - keyboard_layout
  thresholds:
    typosquatting: 0.85
    dependency_confusion: 0.90
    reputation: 0.70

ml_service:
  enabled: true
  endpoint: "http://localhost:8001"
  timeout: 30s
  model_version: "1.2.0"

reputation:
  enabled: true
  cache_size: 10000
  cache_ttl: 24h
  sources:
    - name: "virustotal"
      weight: 0.4
      enabled: true
    - name: "security_scanner"
      weight: 0.6
      enabled: true

logging:
  level: "info"
  format: "json"
  output: "stdout"

metrics:
  enabled: true
  port: 9090
```

### Environment Variables

Override configuration with environment variables:

```bash
# API Keys (never commit these!)
export TYPOSENTINEL_ML_API_KEY="your-ml-api-key"
export TYPOSENTINEL_VIRUSTOTAL_API_KEY="your-vt-api-key"

# Service endpoints
export TYPOSENTINEL_ML_ENDPOINT="https://ml-service.example.com"
export TYPOSENTINEL_REPUTATION_ENDPOINT="https://reputation.example.com"

# Timeouts and limits
export TYPOSENTINEL_SCANNER_TIMEOUT="120s"
export TYPOSENTINEL_ANALYZER_MAX_CONCURRENCY="25"

# Logging
export TYPOSENTINEL_LOG_LEVEL="debug"
export TYPOSENTINEL_LOG_FORMAT="text"

# Run scan with environment variables
typosentinel scan .
```

### Filtering and Exclusions

#### Exclude Specific Packages

```yaml
# In configuration file
scanner:
  exclude_packages:
    - "@types/*"  # Exclude TypeScript type definitions
    - "eslint-*"  # Exclude ESLint plugins
    - "test-*"    # Exclude test utilities
```

#### Include Only Specific Registries

```bash
# Scan only npm packages
typosentinel scan . --analyzers npm

# Scan npm and PyPI only
typosentinel scan . --analyzers npm,pypi
```

#### Custom Exclude Patterns

```yaml
scanner:
  exclude_patterns:
    - "**/test/**"
    - "**/tests/**"
    - "**/__tests__/**"
    - "**/spec/**"
    - "**/docs/**"
    - "**/examples/**"
```

### Threat Severity Customization

```yaml
detector:
  severity_rules:
    typosquatting:
      high: 0.9    # Confidence >= 90% = HIGH
      medium: 0.7  # Confidence >= 70% = MEDIUM
      low: 0.5     # Confidence >= 50% = LOW
    
    dependency_confusion:
      high: 0.95
      medium: 0.8
      low: 0.6
    
    suspicious_package:
      high: 0.85
      medium: 0.65
      low: 0.4
```

## Performance Testing

### Running Benchmarks

Typosentinel includes a comprehensive benchmark suite to test and optimize performance:

```bash
# Run all benchmarks
go test -bench=. ./internal/benchmark/

# Run specific benchmark categories
go test -bench=BenchmarkSmallPackage ./internal/benchmark/
go test -bench=BenchmarkMediumPackage ./internal/benchmark/
go test -bench=BenchmarkLargePackage ./internal/benchmark/
go test -bench=BenchmarkConcurrentScans ./internal/benchmark/
go test -bench=BenchmarkMemoryUsage ./internal/benchmark/

# Run benchmarks with memory profiling
go test -bench=. -benchmem ./internal/benchmark/

# Generate detailed performance profiles
go test -bench=BenchmarkLargePackage -cpuprofile=cpu.prof ./internal/benchmark/
go test -bench=BenchmarkMemoryUsage -memprofile=mem.prof ./internal/benchmark/
```

### Benchmark Categories

#### Package Size Performance
- **Small Packages**: < 10 files, tests basic scanning overhead
- **Medium Packages**: 10-100 files, tests typical project scanning
- **Large Packages**: > 100 files, tests scalability and memory usage

#### Concurrency Testing
- **Concurrent Scans**: Multi-threaded scanning performance
- **Throughput**: Package processing rate under load
- **Stress Testing**: System limits and error handling

#### Memory Analysis
- **Memory Usage**: Allocation patterns and garbage collection
- **Memory Efficiency**: Memory per operation metrics
- **Memory Leaks**: Long-running process stability

## Supply Chain Security

Typosentinel provides comprehensive supply chain security analysis with advanced threat detection capabilities.

### Advanced Supply Chain Scanning

The `supply-chain scan-advanced` command performs comprehensive security analysis:

```bash
# Comprehensive supply chain scan
typosentinel supply-chain scan-advanced /path/to/project \
  --build-integrity \
  --zero-day \
  --graph-analysis \
  --threat-intel \
  --honeypots \
  --deep-scan \
  --risk-threshold high
```

#### Features Included:

**Build Integrity Verification:**
- Package signature verification
- Behavioral baseline creation and monitoring
- Build artifact validation
- Supply chain attack detection

**Zero-Day Detection:**
- Novel threat pattern recognition
- Behavioral anomaly detection
- Machine learning-based threat prediction
- Honeypot and trap detection

**Graph Analysis:**
- Dependency relationship mapping
- Risk propagation analysis
- Circular dependency detection
- Impact assessment

**Threat Intelligence:**
- Real-time threat feed integration
- Historical attack pattern analysis
- Community-driven threat sharing
- Automated threat correlation

### Build Integrity Verification

Verify the integrity of your build process and packages:

```bash
# Create security baseline
typosentinel supply-chain build-integrity /path/to/project \
  --baseline-create \
  --output baseline.json

# Verify against baseline
typosentinel supply-chain build-integrity /path/to/project \
  --baseline baseline.json \
  --fail-on-violations

# Skip signature verification (for testing)
typosentinel supply-chain build-integrity /path/to/project \
  --skip-signature-check
```

Example output:
```
🔒 Build Integrity Verification
📦 Analyzing 45 packages...
✅ Signatures verified: 43/45
⚠️  Baseline violations: 2
❌ Failed signature checks: 2

=== INTEGRITY ISSUES ===

🚨 CRITICAL - Unsigned Package
Package: suspicious-lib@1.2.3
Issue: No valid signature found
Risk: High - Package could be compromised

⚠️  WARNING - Baseline Violation
Package: lodash@4.17.21
Issue: Behavioral pattern changed
Previous: Network access: None
Current: Network access: HTTP requests to unknown domains
```

### Dependency Graph Analysis

Analyze your dependency relationships and identify risks:

```bash
# Basic graph analysis
typosentinel supply-chain graph-analyze /path/to/project

# Include development dependencies
typosentinel supply-chain graph-analyze /path/to/project \
  --include-dev \
  --graph-depth 10

# Generate visual graph
typosentinel supply-chain graph-analyze /path/to/project \
  --output-graph dependency-graph.svg \
  --graph-depth 5
```

Features:
- **Risk Propagation**: Identify how vulnerabilities spread through dependencies
- **Critical Paths**: Find the most important dependency chains
- **Circular Dependencies**: Detect problematic circular references
- **Orphaned Dependencies**: Find unused or unnecessary packages

### Threat Intelligence

Query threat intelligence databases for package information:

```bash
# Check specific package
typosentinel supply-chain threat-intel express npm \
  --threat-sources typosentinel,osv,nvd \
  --threat-types malware,typosquatting,backdoor

# Batch check multiple packages
typosentinel supply-chain threat-intel \
  --package-file packages.txt \
  --threat-sources all \
  --limit 50
```

Supported threat sources:
- **TypoSentinel**: Internal threat database
- **OSV**: Open Source Vulnerabilities database
- **NVD**: National Vulnerability Database
- **Custom**: Your organization's threat feeds

### SBOM Generation

Generate Software Bill of Materials for compliance and security:

```bash
# Generate SPDX SBOM
typosentinel scan /path/to/project \
  --sbom-format spdx \
  --sbom-output project-sbom.spdx.json \
  --include-vulnerabilities

# Generate CycloneDX SBOM
typosentinel scan /path/to/project \
  --sbom-format cyclonedx \
  --sbom-output project-sbom.json \
  --include-licenses

# Include vulnerability data
typosentinel scan /path/to/project \
  --sbom-format spdx \
  --check-vulnerabilities \
  --vulnerability-db osv,nvd \
  --sbom-output secure-sbom.json
```

SBOM features:
- **SPDX 2.3** and **CycloneDX 1.4** format support
- **Vulnerability integration** from multiple databases
- **License information** extraction
- **Cryptographic hashes** for package verification
- **Dependency relationships** mapping

## Edge Algorithms

TypoSentinel includes cutting-edge algorithms for advanced threat detection.

### Graph-based Threat Recognition (GTR)

Advanced graph analysis for threat detection:

```bash
# Basic GTR analysis
typosentinel edge gtr /path/to/project

# Custom threshold and depth
typosentinel edge gtr /path/to/project \
  --threshold 0.8 \
  --max-depth 5 \
  --include-metrics

# Analyze specific packages
typosentinel edge gtr \
  --packages express,lodash,axios \
  --threshold 0.9
```

GTR analyzes:
- **Package relationships** in dependency graphs
- **Behavioral patterns** across related packages
- **Anomaly detection** in package ecosystems
- **Threat propagation** through dependency chains

### Recursive Universal Network Traversal (RUNT)

Deep network analysis for comprehensive threat detection:

```bash
# RUNT analysis
typosentinel edge runt /path/to/project \
  --max-depth 10 \
  --similarity 0.75 \
  --include-features

# Target specific package
typosentinel edge runt \
  --target-package express \
  --max-depth 15
```

RUNT features:
- **Recursive traversal** of package networks
- **Similarity analysis** across package ecosystems
- **Feature extraction** for ML models
- **Universal compatibility** across package managers

### Adaptive Intelligence Correlation Clustering (AICC)

Machine learning-based clustering for threat correlation:

```bash
# AICC clustering
typosentinel edge aicc /path/to/project \
  --clusters 5 \
  --adaptive-mode \
  --include-correlation

# Analyze package groups
typosentinel edge aicc \
  --packages react,vue,angular,svelte \
  --clusters 2
```

AICC capabilities:
- **Adaptive clustering** based on package characteristics
- **Intelligence correlation** across threat indicators
- **Dynamic cluster adjustment** based on new data
- **Cross-ecosystem analysis** for comprehensive coverage

### Dependency Impact Risk Traversal (DIRT)

Analyze the impact and risk of dependencies:

```bash
# DIRT analysis
typosentinel edge dirt /path/to/project \
  --max-depth 8 \
  --risk-threshold 0.6 \
  --include-graph

# Focus on high-risk dependencies
typosentinel edge dirt /path/to/project \
  --risk-threshold 0.8 \
  --output-format json
```

DIRT analysis includes:
- **Impact assessment** of each dependency
- **Risk traversal** through dependency trees
- **Critical path identification** for security focus
- **Mitigation recommendations** for high-risk dependencies

### Edge Algorithm Benchmarking

Test the performance of edge algorithms:

```bash
# Benchmark all algorithms
typosentinel edge benchmark \
  --packages 100 \
  --workers 4 \
  --iterations 10

# Benchmark specific algorithm
typosentinel edge benchmark \
  --algorithm gtr \
  --packages 50 \
  --workers 8
```

## Web Interface

TypoSentinel includes a modern web interface for interactive security analysis.

### Starting the Web Server

```bash
# Start with default settings
typosentinel server

# Custom host and port
typosentinel server --host 0.0.0.0 --port 8080

# Development mode with hot reload
typosentinel server --dev-mode

# Production mode with optimizations
typosentinel server --config production.yaml
```

### Web Interface Features

#### Dashboard
- **Real-time metrics** and system status
- **Recent scan results** and threat summaries
- **Performance graphs** and resource usage
- **Quick action buttons** for common tasks

#### Package Scanner
- **Interactive package scanning** with real-time results
- **Drag-and-drop** project upload
- **Multiple output formats** (JSON, CSV, PDF)
- **Detailed threat analysis** with remediation suggestions

#### Analytics
- **Threat trend analysis** over time
- **Package ecosystem insights** and statistics
- **Risk assessment reports** and compliance tracking
- **Custom dashboard creation** and sharing

#### Configuration Management
- **Visual configuration editor** with validation
- **Template management** for different environments
- **Backup and restore** functionality
- **Real-time configuration updates**

### API Integration

The web interface provides a full REST API:

```bash
# Health check
curl http://localhost:8080/health

# Scan packages via API
curl -X POST http://localhost:8080/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"packages": ["express", "lodash"], "package_manager": "npm"}'

# Get scan results
curl http://localhost:8080/api/v1/results/{scan_id}
```

## Organization Scanning

Scan entire organizations across multiple platforms.

### GitHub Organization Scanning

```bash
# Scan GitHub organization
typosentinel scan-org github \
  --org company-name \
  --token $GITHUB_TOKEN \
  --max-repos 100 \
  --include-private \
  --include-forked

# Exclude archived repositories
typosentinel scan-org github \
  --org company-name \
  --token $GITHUB_TOKEN \
  --exclude-archived

# Focus on specific languages
typosentinel scan-org github \
  --org company-name \
  --token $GITHUB_TOKEN \
  --languages javascript,python,go
```

### GitLab Organization Scanning

```bash
# Scan GitLab group
typosentinel scan-org gitlab \
  --org group-name \
  --token $GITLAB_TOKEN \
  --include-subgroups

# Scan specific GitLab instance
typosentinel scan-org gitlab \
  --org group-name \
  --token $GITLAB_TOKEN \
  --gitlab-url https://gitlab.company.com
```

### Bitbucket Workspace Scanning

```bash
# Scan Bitbucket workspace
typosentinel scan-org bitbucket \
  --org workspace-name \
  --token $BITBUCKET_TOKEN \
  --include-private

# Scan specific projects
typosentinel scan-org bitbucket \
  --org workspace-name \
  --token $BITBUCKET_TOKEN \
  --projects project1,project2
```

### Organization Scan Features

- **Multi-platform support**: GitHub, GitLab, Bitbucket
- **Bulk repository processing** with parallel scanning
- **Comprehensive reporting** across all repositories
- **Risk aggregation** and organization-wide metrics
- **Compliance tracking** and audit trails
- **Integration with CI/CD** pipelines

#### ML Performance
- **ML Analysis**: Machine learning detection speed
- **Feature Extraction**: ML feature processing performance

### Performance Optimization Tips

#### Concurrent Processing
```bash
# Optimize for your system
typosentinel scan . --max-concurrency $(nproc)

# For memory-constrained environments
typosentinel scan . --max-concurrency 4
```

#### Memory Management
```bash
# Monitor memory usage during scans
typosentinel scan . --verbose --memory-profile

# For large projects, use batch processing
typosentinel scan . --batch-size 100
```

#### Caching
```yaml
# Enable aggressive caching for repeated scans
analyzer:
  cache_size: 10000
  cache_ttl: 4h

reputation:
  cache_size: 20000
  cache_ttl: 24h
```

### Interpreting Benchmark Results

```
BenchmarkSmallPackage-8         1000    1.2ms/op    512 B/op    8 allocs/op
BenchmarkMediumPackage-8         100   15.3ms/op   2048 B/op   32 allocs/op
BenchmarkLargePackage-8           10  150.5ms/op  10240 B/op  128 allocs/op
BenchmarkConcurrentScans-8       500    3.2ms/op   1024 B/op   16 allocs/op
BenchmarkMemoryUsage-8          1000    1.8ms/op    768 B/op   12 allocs/op
```

- **Operations/second**: Higher is better
- **Time per operation**: Lower is better
- **Memory per operation**: Lower is better
- **Allocations per operation**: Lower is better

### Custom Performance Testing

```go
// Create custom benchmark
func BenchmarkCustomScenario(b *testing.B) {
    // Setup test environment
    testDir := createCustomTestPackage(b)
    defer os.RemoveAll(testDir)
    
    cfg := getOptimizedConfig()
    a, err := analyzer.New(cfg)
    if err != nil {
        b.Fatalf("Failed to create analyzer: %v", err)
    }
    
    b.ResetTimer()
    b.ReportAllocs()
    
    for i := 0; i < b.N; i++ {
        options := &analyzer.ScanOptions{
            OutputFormat:        "json",
            DeepAnalysis:        true,
            SimilarityThreshold: 0.8,
        }
        _, err := a.Scan(testDir, options)
        if err != nil {
            b.Fatalf("Scan failed: %v", err)
        }
    }
}
```

## Configuration Guide

### Complete Configuration Reference

```yaml
# Complete typosentinel.yaml configuration

# Scanner configuration
scanner:
  timeout: 60s                    # Maximum scan time
  max_concurrency: 20             # Concurrent file processing
  exclude_patterns:               # Patterns to exclude
    - ".git"
    - "node_modules"
    - "vendor"
  include_dev_dependencies: true  # Include dev dependencies
  exclude_packages:               # Specific packages to exclude
    - "@types/*"
  max_file_size: 10MB            # Maximum file size to process

# Analyzer configuration
analyzer:
  timeout: 30s                   # Per-package analysis timeout
  max_concurrency: 15            # Concurrent package analysis
  cache_size: 5000              # Number of results to cache
  cache_ttl: 2h                 # Cache time-to-live
  enabled_analyzers:            # Which analyzers to use
    - npm
    - pypi
    - rubygems
    - maven
    - nuget
    - composer
    - cargo
  batch_size: 100               # Batch size for processing

# Threat detection configuration
detector:
  enabled: true
  timeout: 30s
  max_concurrency: 10
  cache_size: 1000
  cache_ttl: 1h
  
  # Detection algorithms
  algorithms:
    - levenshtein      # Edit distance
    - jaro_winkler     # String similarity
    - homoglyph        # Visual similarity
    - keyboard_layout  # Keyboard proximity
    - soundex          # Phonetic similarity
  
  # Detection thresholds (0.0 - 1.0)
  thresholds:
    typosquatting: 0.85
    dependency_confusion: 0.90
    reputation: 0.70
    suspicious_pattern: 0.75
  
  # Popular package lists for comparison
  popular_packages:
    npm: 10000         # Top N packages to compare against
    pypi: 5000
    rubygems: 3000

# Machine Learning service
ml_service:
  enabled: true
  endpoint: "http://localhost:8001"
  api_key: "${TYPOSENTINEL_ML_API_KEY}"  # Use environment variable
  timeout: 30s
  max_retries: 3
  retry_delay: 1s
  model_version: "1.2.0"
  batch_size: 50

# Reputation system
reputation:
  enabled: true
  cache_size: 10000
  cache_ttl: 24h
  timeout: 30s
  max_retries: 3
  retry_delay: 1s
  
  sources:
    - name: "virustotal"
      endpoint: "https://www.virustotal.com/api/v3"
      api_key: "${TYPOSENTINEL_VIRUSTOTAL_API_KEY}"
      weight: 0.4
      enabled: true
      timeout: 15s
    
    - name: "security_scanner"
      endpoint: "http://localhost:8002"
      api_key: "${TYPOSENTINEL_SECURITY_API_KEY}"
      weight: 0.6
      enabled: true
      timeout: 20s

# Logging configuration
logging:
  level: "info"        # debug, info, warn, error
  format: "json"       # json, text
  output: "stdout"     # stdout, stderr, file path
  file_path: "/var/log/typosentinel.log"  # If output is file
  max_size: 100MB      # Log rotation size
  max_backups: 5       # Number of backup files
  max_age: 30          # Days to keep logs

# Metrics and monitoring
metrics:
  enabled: true
  port: 9090
  path: "/metrics"
  
# Output configuration
output:
  format: "table"      # table, json, yaml
  file: ""             # Output file path
  include_metadata: true
  include_dependencies: true
  
# Performance tuning
performance:
  worker_pool_size: 50
  queue_buffer_size: 1000
  memory_limit: 1GB
  cpu_limit: 80        # Percentage
```

### Configuration Validation

```bash
# Validate your configuration
typosentinel config validate

# Show effective configuration (with environment overrides)
typosentinel config show

# Test configuration with dry run
typosentinel scan . --dry-run
```

## Enterprise Features

Typosentinel Enterprise provides advanced security features for large-scale deployments, including Role-Based Access Control (RBAC), policy management, advanced reporting, and enterprise integrations.

### Overview

Enterprise features include:
- **Repository Scanning**: Automated discovery and scanning of repositories across multiple platforms
- **Role-Based Access Control (RBAC)**: Fine-grained permission management
- **Policy Management**: Custom security policies with automated enforcement
- **Advanced Reporting**: SARIF, SPDX, CycloneDX, and executive dashboard formats
- **Enterprise Integration**: LDAP, SSO, SIEM, and audit logging
- **Scheduled Scanning**: Automated scanning with cron-like scheduling
- **Multi-tenant Support**: Isolated environments for different organizations

### Repository Scanning

#### Supported Platforms
- GitHub (github.com and GitHub Enterprise)
- GitLab (gitlab.com and self-hosted)
- Bitbucket (bitbucket.org and Bitbucket Server)
- Azure DevOps (dev.azure.com and Azure DevOps Server)

#### Configuration Example

```yaml
# enterprise-repository-config.yaml
repository:
  connectors:
    github:
      enabled: true
      token: "${GITHUB_TOKEN}"
      base_url: "https://api.github.com"
      organizations: ["myorg", "mycompany"]
      discovery:
        enabled: true
        include_forks: false
        include_archived: false
        languages: ["javascript", "python", "go"]
    
    gitlab:
      enabled: true
      token: "${GITLAB_TOKEN}"
      base_url: "https://gitlab.com/api/v4"
      groups: ["mygroup"]
      discovery:
        enabled: true
        include_subgroups: true
    
    azure_devops:
      enabled: true
      token: "${AZURE_DEVOPS_TOKEN}"
      organization: "myorganization"
      projects: ["project1", "project2"]

scheduler:
  enabled: true
  cron: "0 2 * * *"  # Daily at 2 AM
  timezone: "UTC"
  
scanning:
  concurrency: 10
  timeout: "30m"
  batch_size: 50
  
output:
  formats: ["sarif", "json", "dashboard"]
  storage:
    type: "database"
    retention_days: 90
```

#### Running Repository Scans

```bash
# Scan all repositories in an organization
typosentinel enterprise scan-org --org myorg --platform github

# Scan specific repositories
typosentinel enterprise scan-repos --repos "myorg/repo1,myorg/repo2"

# Schedule automated scans
typosentinel enterprise schedule --config enterprise-repository-config.yaml

# View scan results
typosentinel enterprise results --format dashboard
```

### Role-Based Access Control (RBAC)

#### Default Roles

**Administrator**
- Full access to all enterprise features
- Can manage policies, roles, and enforcement settings
- Can approve/reject policy violations

**Security Manager**
- Can create and modify security policies
- Can view all scan results and reports
- Can manage enforcement settings

**Security Analyst**
- Read-only access to policies and scan results
- Can view reports and dashboards
- Cannot modify configurations

**Developer**
- Can view scan results for assigned projects
- Can request policy exceptions
- Limited access to reports

#### Permission System

```yaml
# RBAC configuration
rbac:
  enabled: true
  roles:
    security_manager:
      name: "Security Manager"
      description: "Manages security policies and enforcement"
      permissions:
        - "policies:read"
        - "policies:create"
        - "policies:update"
        - "enforcement:read"
        - "enforcement:update"
        - "reports:read"
        - "dashboards:read"
    
    project_lead:
      name: "Project Lead"
      description: "Manages project-specific security settings"
      permissions:
        - "policies:read"
        - "reports:read:project"
        - "scans:trigger:project"
        - "exceptions:request"
  
  users:
    - username: "alice@company.com"
      roles: ["security_manager"]
      projects: ["*"]
    
    - username: "bob@company.com"
      roles: ["project_lead"]
      projects: ["frontend", "backend"]
```

#### API Usage

```bash
# Create a new role
curl -X POST http://localhost:8080/api/v1/enterprise/rbac/roles \
  -H "Content-Type: application/json" \
  -d '{
    "name": "custom_role",
    "description": "Custom role for specific needs",
    "permissions": ["policies:read", "reports:read"]
  }'

# Check user permissions
curl -X POST http://localhost:8080/api/v1/enterprise/rbac/users/alice@company.com/check-permission \
  -H "Content-Type: application/json" \
  -d '{
    "permission": "policies:create",
    "resource": "security-policy-1"
  }'
```

### Policy Management

#### Policy Types

**Security Policies**
- Block packages with high risk scores
- Require approval for new dependencies
- Enforce license compliance

**Compliance Policies**
- GDPR compliance checks
- Industry-specific requirements
- Custom organizational rules

#### Example Policies

```yaml
# High-risk package blocking policy
policies:
  - id: "block-high-risk"
    name: "Block High Risk Packages"
    description: "Automatically block packages with risk score > 0.8"
    enabled: true
    conditions:
      - field: "risk_score"
        operator: "gt"
        value: 0.8
    actions:
      - type: "block"
        message: "Package blocked due to high security risk"
      - type: "notify"
        channels: ["slack", "email"]
  
  # License compliance policy
  - id: "license-compliance"
    name: "License Compliance Check"
    description: "Ensure only approved licenses are used"
    enabled: true
    conditions:
      - field: "license"
        operator: "not_in"
        value: ["MIT", "Apache-2.0", "BSD-3-Clause"]
    actions:
      - type: "require_approval"
        approvers: ["legal@company.com"]
      - type: "notify"
        channels: ["legal-team"]
```

#### Policy Enforcement

```bash
# Evaluate policies against scan results
typosentinel enterprise policy evaluate --scan-result results.json

# Apply policies with enforcement
typosentinel enterprise policy enforce --config policy-config.yaml

# View policy violations
typosentinel enterprise policy violations --status pending
```

### Advanced Reporting

#### SARIF Output

```bash
# Generate SARIF report
typosentinel scan . --format sarif --output results.sarif

# Enterprise SARIF with additional metadata
typosentinel enterprise scan --format sarif --include-metadata --output enterprise-results.sarif
```

#### Executive Dashboard

```bash
# Generate executive dashboard
typosentinel enterprise dashboard --output dashboard.html

# Dashboard with custom date range
typosentinel enterprise dashboard --from 2024-01-01 --to 2024-01-31 --output monthly-dashboard.html
```

#### SPDX and CycloneDX

```bash
# Generate SPDX SBOM
typosentinel scan . --format spdx --output sbom.spdx.json

# Generate CycloneDX SBOM
typosentinel scan . --format cyclonedx --output sbom.cyclonedx.json
```

### Enterprise Integration

#### LDAP Authentication

```yaml
auth:
  ldap:
    enabled: true
    server: "ldap://ldap.company.com:389"
    bind_dn: "cn=typosentinel,ou=services,dc=company,dc=com"
    bind_password: "${LDAP_PASSWORD}"
    user_base: "ou=users,dc=company,dc=com"
    user_filter: "(uid=%s)"
    group_base: "ou=groups,dc=company,dc=com"
    group_filter: "(member=%s)"
    attributes:
      username: "uid"
      email: "mail"
      display_name: "displayName"
```

#### SSO Integration

```yaml
auth:
  sso:
    enabled: true
    provider: "saml"
    saml:
      entity_id: "typosentinel"
      sso_url: "https://sso.company.com/saml/sso"
      certificate_file: "/etc/typosentinel/sso-cert.pem"
      attribute_mapping:
        username: "NameID"
        email: "Email"
        groups: "Groups"
```

#### SIEM Integration

```yaml
siem:
  enabled: true
  splunk:
    endpoint: "https://splunk.company.com:8088/services/collector"
    token: "${SPLUNK_HEC_TOKEN}"
    index: "security"
    source: "typosentinel"
    streaming: true
    batch_size: 100
    flush_interval: "30s"
```

### Monitoring and Alerting

#### Metrics

```yaml
monitoring:
  prometheus:
    enabled: true
    port: 9090
    path: "/metrics"
  
  alerts:
    - name: "high_threat_detection"
      condition: "threats_detected_total > 10"
      duration: "5m"
      severity: "critical"
      channels: ["pagerduty", "slack"]
    
    - name: "scan_failure_rate"
      condition: "scan_failure_rate > 0.1"
      duration: "10m"
      severity: "warning"
      channels: ["email"]
```

#### Health Checks

```bash
# Check enterprise service health
curl http://localhost:8080/health/enterprise

# Detailed health status
curl http://localhost:8080/health/detailed
```

### CLI Commands

```bash
# Enterprise-specific commands
typosentinel enterprise --help

# Repository management
typosentinel enterprise repos list
typosentinel enterprise repos scan --org myorg
typosentinel enterprise repos schedule --cron "0 2 * * *"

# Policy management
typosentinel enterprise policies list
typosentinel enterprise policies create --file policy.yaml
typosentinel enterprise policies evaluate --scan-result results.json

# RBAC management
typosentinel enterprise rbac roles list
typosentinel enterprise rbac users assign --user alice@company.com --role security_manager

# Reporting
typosentinel enterprise reports generate --format dashboard --output report.html
typosentinel enterprise reports export --format sarif --date-range 30d
```

### Deployment

#### Docker Compose

```yaml
# docker-compose.enterprise.yml
version: '3.8'
services:
  typosentinel-enterprise:
    image: typosentinel:enterprise
    ports:
      - "8080:8080"
      - "9090:9090"
    environment:
      - TYPOSENTINEL_CONFIG=/config/enterprise.yaml
      - GITHUB_TOKEN=${GITHUB_TOKEN}
      - GITLAB_TOKEN=${GITLAB_TOKEN}
    volumes:
      - ./config:/config
      - ./data:/data
    depends_on:
      - postgres
      - redis
  
  postgres:
    image: postgres:15
    environment:
      - POSTGRES_DB=typosentinel
      - POSTGRES_USER=typosentinel
      - POSTGRES_PASSWORD=${DB_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
  
  redis:
    image: redis:7
    volumes:
      - redis_data:/data

volumes:
  postgres_data:
  redis_data:
```

#### Kubernetes

```yaml
# k8s-enterprise-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: typosentinel-enterprise
spec:
  replicas: 3
  selector:
    matchLabels:
      app: typosentinel-enterprise
  template:
    metadata:
      labels:
        app: typosentinel-enterprise
    spec:
      containers:
      - name: typosentinel
        image: typosentinel:enterprise
        ports:
        - containerPort: 8080
        - containerPort: 9090
        env:
        - name: TYPOSENTINEL_CONFIG
          value: "/config/enterprise.yaml"
        volumeMounts:
        - name: config
          mountPath: /config
        resources:
          requests:
            memory: "1Gi"
            cpu: "500m"
          limits:
            memory: "2Gi"
            cpu: "1000m"
      volumes:
      - name: config
        configMap:
          name: typosentinel-config
```

## Language-Specific Guides

### Node.js / npm Projects

#### Supported Files
- `package.json`
- `package-lock.json`
- `yarn.lock`
- `pnpm-lock.yaml`

#### Example Scan

```bash
# Scan Node.js project
cd /path/to/node/project
typosentinel scan .
```

#### Common npm Threats

1. **Typosquatting**: `expres` instead of `express`
2. **Dependency Confusion**: Internal package names published publicly
3. **Malicious Packages**: Packages with suspicious patterns

#### Best Practices

```json
{
  "scripts": {
    "security-scan": "typosentinel scan . --fail-on-threats",
    "presecurity-scan": "npm audit"
  }
}
```

### Python / PyPI Projects

#### Supported Files
- `requirements.txt`
- `Pipfile`
- `pyproject.toml`
- `setup.py`
- `poetry.lock`

#### Example Scan

```bash
# Scan Python project
cd /path/to/python/project
typosentinel scan .
```

#### Common PyPI Threats

1. **Typosquatting**: `requets` instead of `requests`
2. **Underscore Confusion**: `python_requests` vs `python-requests`
3. **Version Confusion**: Malicious packages with higher version numbers

#### Integration with pip

```bash
# Create requirements file and scan
pip freeze > requirements.txt
typosentinel scan .
```

### Ruby / RubyGems Projects

#### Supported Files
- `Gemfile`
- `Gemfile.lock`
- `*.gemspec`

#### Example Scan

```bash
# Scan Ruby project
cd /path/to/ruby/project
typosentinel scan .
```

#### Common RubyGems Threats

1. **Typosquatting**: `railz` instead of `rails`
2. **Namespace Confusion**: Similar gem names in different namespaces

### Java / Maven Projects

#### Supported Files
- `pom.xml`
- `build.gradle`
- `gradle.lockfile`

#### Example Scan

```bash
# Scan Java project
cd /path/to/java/project
typosentinel scan .
```

#### Common Maven Threats

1. **Group ID Confusion**: Similar group IDs with malicious artifacts
2. **Typosquatting**: `com.fasterxml.jackson` vs `com.fastxml.jackson`

### .NET / NuGet Projects

#### Supported Files
- `*.csproj`
- `packages.config`
- `project.assets.json`
- `*.sln`

#### Example Scan

```bash
# Scan .NET project
cd /path/to/dotnet/project
typosentinel scan .
```

### PHP / Composer Projects

#### Supported Files
- `composer.json`
- `composer.lock`

#### Example Scan

```bash
# Scan PHP project
cd /path/to/php/project
typosentinel scan .
```

### Rust / Cargo Projects

#### Supported Files
- `Cargo.toml`
- `Cargo.lock`

#### Example Scan

```bash
# Scan Rust project
cd /path/to/rust/project
typosentinel scan .
```

## Integration Examples

### GitHub Actions

```yaml
# .github/workflows/security.yml
name: Security Scan

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM

jobs:
  security-scan:
    runs-on: ubuntu-latest
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v3
    
    - name: Setup Go
      uses: actions/setup-go@v3
      with:
        go-version: '1.21'
    
    - name: Install Typosentinel
      run: |
        wget https://github.com/alikorsi/typosentinel/releases/latest/download/typosentinel-linux-amd64
        chmod +x typosentinel-linux-amd64
        sudo mv typosentinel-linux-amd64 /usr/local/bin/typosentinel
    
    - name: Run Security Scan
      env:
        TYPOSENTINEL_ML_API_KEY: ${{ secrets.ML_API_KEY }}
        TYPOSENTINEL_VIRUSTOTAL_API_KEY: ${{ secrets.VIRUSTOTAL_API_KEY }}
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
    
    - name: Comment on PR
      if: github.event_name == 'pull_request' && always()
      uses: actions/github-script@v6
      with:
        script: |
          const fs = require('fs');
          
          try {
            const report = JSON.parse(fs.readFileSync('security-report.json', 'utf8'));
            
            const threatsByType = {};
            report.threats.forEach(threat => {
              threatsByType[threat.type] = (threatsByType[threat.type] || 0) + 1;
            });
            
            let comment = `## 🔒 Security Scan Results\n\n`;
            comment += `- **Packages Scanned:** ${report.total_packages}\n`;
            comment += `- **Threats Found:** ${report.total_threats}\n`;
            comment += `- **Risk Score:** ${report.overall_risk_score.toFixed(1)}/10\n`;
            comment += `- **Scan Duration:** ${report.scan_duration}\n\n`;
            
            if (report.total_threats > 0) {
              comment += `### ⚠️ Threats Detected\n\n`;
              Object.entries(threatsByType).forEach(([type, count]) => {
                comment += `- **${type}**: ${count}\n`;
              });
              comment += `\n📋 [View detailed report](${context.payload.pull_request.html_url}/checks)`;
            } else {
              comment += `### ✅ No Security Threats Found\n\nAll packages passed security checks.`;
            }
            
            await github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: comment
            });
          } catch (error) {
            console.log('Could not read security report:', error.message);
          }
```

### GitLab CI

```yaml
# .gitlab-ci.yml
stages:
  - security

security-scan:
  stage: security
  image: golang:1.21-alpine
  
  before_script:
    - apk add --no-cache wget
    - wget https://github.com/alikorsi/typosentinel/releases/latest/download/typosentinel-linux-amd64
    - chmod +x typosentinel-linux-amd64
    - mv typosentinel-linux-amd64 /usr/local/bin/typosentinel
  
  script:
    - typosentinel scan . --format json --output security-report.json
  
  artifacts:
    reports:
      junit: security-report.json
    paths:
      - security-report.json
    expire_in: 1 week
  
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
    - if: $CI_PIPELINE_SOURCE == "schedule"
```

### Jenkins Pipeline

```groovy
// Jenkinsfile
pipeline {
    agent any
    
    environment {
        TYPOSENTINEL_ML_API_KEY = credentials('ml-api-key')
        TYPOSENTINEL_VIRUSTOTAL_API_KEY = credentials('virustotal-api-key')
    }
    
    stages {
        stage('Security Scan') {
            steps {
                script {
                    // Install Typosentinel
                    sh '''
                        wget https://github.com/alikorsi/typosentinel/releases/latest/download/typosentinel-linux-amd64
                        chmod +x typosentinel-linux-amd64
                        sudo mv typosentinel-linux-amd64 /usr/local/bin/typosentinel
                    '''
                    
                    // Run scan
                    sh 'typosentinel scan . --format json --output security-report.json'
                    
                    // Archive results
                    archiveArtifacts artifacts: 'security-report.json', fingerprint: true
                    
                    // Parse results
                    def report = readJSON file: 'security-report.json'
                    
                    if (report.total_threats > 0) {
                        currentBuild.result = 'UNSTABLE'
                        echo "Security threats detected: ${report.total_threats}"
                    }
                }
            }
        }
    }
    
    post {
        always {
            publishHTML([
                allowMissing: false,
                alwaysLinkToLastBuild: true,
                keepAll: true,
                reportDir: '.',
                reportFiles: 'security-report.json',
                reportName: 'Security Report'
            ])
        }
    }
}
```

### Docker Integration

```dockerfile
# Multi-stage Dockerfile with security scanning
FROM node:18-alpine AS deps
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production

# Security scan stage
FROM golang:1.21-alpine AS security
WORKDIR /app
COPY --from=deps /app/package*.json ./
RUN wget https://github.com/alikorsi/typosentinel/releases/latest/download/typosentinel-linux-amd64 -O typosentinel && \
    chmod +x typosentinel
RUN ./typosentinel scan . --fail-on-threats

# Final stage
FROM node:18-alpine AS runtime
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
EXPOSE 3000
CMD ["npm", "start"]
```

### Pre-commit Hook

```bash
#!/bin/sh
# .git/hooks/pre-commit

echo "Running security scan..."

# Run Typosentinel scan
typosentinel scan . --fail-on-threats

if [ $? -ne 0 ]; then
    echo "❌ Security scan failed. Commit blocked."
    echo "Please review and fix security issues before committing."
    exit 1
fi

echo "✅ Security scan passed."
exit 0
```

```bash
# Make hook executable
chmod +x .git/hooks/pre-commit
```

### VS Code Integration

```json
// .vscode/tasks.json
{
    "version": "2.0.0",
    "tasks": [
        {
            "label": "Security Scan",
            "type": "shell",
            "command": "typosentinel",
            "args": ["scan", ".", "--format", "json"],
            "group": "build",
            "presentation": {
                "echo": true,
                "reveal": "always",
                "focus": false,
                "panel": "shared"
            },
            "problemMatcher": {
                "owner": "typosentinel",
                "fileLocation": ["relative", "${workspaceFolder}"],
                "pattern": {
                    "regexp": "^(.*):(\\d+):(\\d+):\\s+(warning|error):\\s+(.*)$",
                    "file": 1,
                    "line": 2,
                    "column": 3,
                    "severity": 4,
                    "message": 5
                }
            }
        }
    ]
}
```

## Troubleshooting

### Common Issues

#### 1. "No package files found"

**Problem**: Typosentinel can't find any supported package files.

**Solution**:
```bash
# Check if you're in the right directory
pwd
ls -la

# Look for supported files
find . -name "package.json" -o -name "requirements.txt" -o -name "Gemfile"

# Scan specific directory
typosentinel scan /path/to/project
```

#### 2. "Timeout exceeded"

**Problem**: Scan is taking too long and timing out.

**Solution**:
```bash
# Increase timeout
typosentinel scan . --timeout 120s

# Or in configuration
echo "scanner:\n  timeout: 120s" > typosentinel.yaml
```

#### 3. "API key not configured"

**Problem**: ML or reputation services require API keys.

**Solution**:
```bash
# Set environment variables
export TYPOSENTINEL_ML_API_KEY="your-key"
export TYPOSENTINEL_VIRUSTOTAL_API_KEY="your-key"

# Or disable services
typosentinel scan . --no-ml --no-reputation
```

#### 4. "Permission denied"

**Problem**: Typosentinel can't access certain files or directories.

**Solution**:
```bash
# Check permissions
ls -la

# Run with appropriate permissions
sudo typosentinel scan .

# Or exclude problematic directories
typosentinel scan . --exclude ".git,node_modules"
```

#### 5. "High memory usage"

**Problem**: Typosentinel is using too much memory.

**Solution**:
```yaml
# Reduce concurrency in config
analyzer:
  max_concurrency: 5
  cache_size: 1000

scanner:
  max_concurrency: 5
```

### Debug Mode

```bash
# Enable debug logging
typosentinel scan . --verbose

# Or set log level
export TYPOSENTINEL_LOG_LEVEL=debug
typosentinel scan .
```

### Performance Issues

```bash
# Profile performance
typosentinel scan . --profile

# Reduce scope
typosentinel scan . --analyzers npm --exclude "test,docs"

# Use local cache
typosentinel scan . --cache-dir ~/.typosentinel/cache
```

### Network Issues

```bash
# Test connectivity
curl -I https://registry.npmjs.org/

# Use proxy
export HTTP_PROXY=http://proxy.company.com:8080
export HTTPS_PROXY=http://proxy.company.com:8080

# Disable external services
typosentinel scan . --offline
```

## FAQ

### General Questions

**Q: What package managers does Typosentinel support?**
A: Typosentinel supports npm, PyPI, RubyGems, Maven, NuGet, Composer, and Cargo.

**Q: Does Typosentinel require internet access?**
A: Yes, for ML and reputation services. You can run offline scans with `--offline` flag.

**Q: How accurate is the threat detection?**
A: Accuracy varies by threat type. Typosquatting detection typically achieves 90%+ accuracy.

**Q: Can I use Typosentinel in CI/CD pipelines?**
A: Yes, Typosentinel is designed for CI/CD integration with appropriate exit codes and output formats.

### Technical Questions

**Q: How does caching work?**
A: Typosentinel caches analysis results to improve performance. Cache TTL is configurable.

**Q: Can I add custom threat detection rules?**
A: Yes, through configuration files and custom analyzers.

**Q: What's the performance impact?**
A: Scan time depends on project size. Typical scans complete in seconds to minutes.

**Q: How do I report false positives?**
A: Create an issue on GitHub with the package details and scan results.

### Security Questions

**Q: Does Typosentinel send my code anywhere?**
A: No, only package names and versions are sent to external services (if enabled).

**Q: How should I handle API keys?**
A: Use environment variables or secure secret management systems. Never commit API keys.

**Q: What should I do if threats are detected?**
A: Review each threat, verify package authenticity, and consider alternatives or updates.

### Integration Questions

**Q: Can I integrate with Slack/Teams?**
A: Yes, using webhooks and the JSON output format.

**Q: Does it work with monorepos?**
A: Yes, Typosentinel can scan multiple package files in a single repository.

**Q: Can I exclude certain packages?**
A: Yes, using exclude patterns in configuration or command-line flags.

For more questions, check our [GitHub Issues](https://github.com/alikorsi/typosentinel/issues) or [Discussions](https://github.com/alikorsi/typosentinel/discussions).