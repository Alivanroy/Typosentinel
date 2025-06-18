# Typosentinel User Guide

A comprehensive guide to using Typosentinel for package security scanning and threat detection.

## Table of Contents

1. [Getting Started](#getting-started)
2. [Basic Usage](#basic-usage)
3. [Advanced Features](#advanced-features)
4. [Configuration Guide](#configuration-guide)
5. [Language-Specific Guides](#language-specific-guides)
6. [Integration Examples](#integration-examples)
7. [Troubleshooting](#troubleshooting)
8. [FAQ](#faq)

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