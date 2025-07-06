# Typosentinel Enhanced - Advanced Package Security Scanner

[![Go Version](https://img.shields.io/badge/Go-1.21+-blue.svg)](https://golang.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen.svg)](#)
[![Coverage](https://img.shields.io/badge/Coverage-95%25-brightgreen.svg)](#)
[![Security](https://img.shields.io/badge/Security-Enhanced-blue.svg)](#)

Typosentinel Enhanced is a next-generation package security scanner that detects typosquatting, dependency confusion, supply chain attacks, and other security threats in package ecosystems. Built with advanced machine learning, real-time threat intelligence, and comprehensive CI/CD integration capabilities.

## 🚀 Enhanced Features

### 🔍 Advanced Threat Detection
- **Typosquatting Detection**: ML-powered similarity analysis with multiple algorithms
- **Dependency Confusion**: Namespace collision and scope indicator analysis
- **Supply Chain Attacks**: Maintainer reputation, version patterns, and integrity checks
- **Adaptive Thresholds**: Ecosystem-specific ML models with performance feedback

### 🧠 Machine Learning Integration
- **Adaptive Threshold Management**: Dynamic threshold adjustment based on performance metrics
- **Ecosystem-Specific Models**: Tailored detection for npm, PyPI, and other ecosystems
- **Feature Engineering**: Advanced string, numerical, and categorical feature extraction
- **Performance Optimization**: Continuous model improvement based on feedback

### 🔗 CI/CD Platform Integration
- **GitHub Actions**: Native integration with status checks, PR comments, and issue creation
- **GitLab CI**: Security reports, merge request annotations, and pipeline status
- **Jenkins**: Test results, artifacts, and email notifications
- **Azure DevOps**: Work items, PR comments, and security reports
- **CircleCI**: Artifacts, test results, and Slack notifications
- **Generic Webhooks**: Flexible integration with any platform

### 🛡️ Real-Time Threat Intelligence
- **Multiple Threat Feeds**: Integration with npm advisories, PyPI security DB, and custom feeds
- **Real-Time Updates**: Webhook and polling-based threat intelligence updates
- **Threat Correlation**: Advanced matching with similarity analysis and caching
- **Alerting System**: Multi-channel notifications (email, Slack, webhooks)
- **Threat Database**: Encrypted storage with backup and retention policies

### ⚡ Performance & Scalability
- **Concurrent Processing**: Multi-threaded package analysis
- **Intelligent Caching**: Memory and persistent caching with TTL
- **Resource Management**: CPU and memory limits with monitoring
- **Metrics & Profiling**: Prometheus metrics and performance profiling

### 🔐 Enterprise Security
- **Encryption**: AES-256-GCM encryption for sensitive data
- **Authentication**: JWT, API key, and OAuth2 support
- **Authorization**: Role-based access control (RBAC)
- **Audit Logging**: Comprehensive security event logging
- **Rate Limiting**: API protection with configurable limits

## 📋 Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Usage Examples](#usage-examples)
- [CI/CD Integration](#cicd-integration)
- [Threat Intelligence](#threat-intelligence)
- [Machine Learning](#machine-learning)
- [API Reference](#api-reference)
- [Development](#development)
- [Contributing](#contributing)
- [License](#license)

## 🛠️ Installation

### Prerequisites

- Go 1.21 or higher
- SQLite 3.x (for threat intelligence database)
- Git

### From Source

```bash
# Clone the repository
git clone https://github.com/your-org/typosentinel.git
cd typosentinel

# Build the application
go build -o typosentinel ./cmd/typosentinel

# Install globally (optional)
go install ./cmd/typosentinel
```

### Using Go Install

```bash
go install github.com/your-org/typosentinel/cmd/typosentinel@latest
```

### Docker

```bash
# Pull the image
docker pull typosentinel/typosentinel:latest

# Run with default configuration
docker run -v $(pwd):/workspace typosentinel/typosentinel scan package.json
```

## 🚀 Quick Start

### Basic Package Scanning

```bash
# Scan a single package
typosentinel scan lodahs

# Scan with specific version
typosentinel scan lodahs@1.0.0

# Scan package.json dependencies
typosentinel scan package.json

# Scan with enhanced detection
typosentinel scan --enhanced --config config/typosentinel.yaml package.json
```

### Configuration Setup

```bash
# Generate example configuration
typosentinel config init

# Validate configuration
typosentinel config validate

# Show current configuration
typosentinel config show
```

### CI/CD Integration

```bash
# GitHub Actions integration
typosentinel scan --plugin github-actions package.json

# GitLab CI integration
typosentinel scan --plugin gitlab-ci --fail-on-critical package.json

# Webhook notifications
typosentinel scan --webhook https://hooks.slack.com/your-webhook package.json
```

## ⚙️ Configuration

Typosentinel Enhanced uses a comprehensive YAML configuration file. Copy the example configuration and customize it for your needs:

```bash
cp config/typosentinel.example.yaml config/typosentinel.yaml
```

### Key Configuration Sections

#### Core Settings
```yaml
core:
  version: "2.0.0"
  environment: "production"
  debug: false
  data_dir: "./data"
  cache_dir: "./cache"
```

#### Detection Configuration
```yaml
detection:
  enabled: true
  parallel_scans: 8
  timeout_seconds: 300
  
  typosquatting:
    enabled: true
    similarity_threshold: 0.85
    algorithms: ["levenshtein", "jaro_winkler"]
    
  dependency_confusion:
    enabled: true
    check_private_repos: true
    confusion_threshold: 0.75
    
  supply_chain:
    enabled: true
    maintainer_analysis: true
    reputation_threshold: 0.7
```

#### Machine Learning
```yaml
ml:
  enabled: true
  adaptive_thresholds:
    enabled: true
    performance_targets:
      target_precision: 0.95
      target_recall: 0.92
    ecosystems:
      npm:
        typosquatting_threshold: 0.85
        dependency_confusion_threshold: 0.80
```

#### Plugin Configuration
```yaml
plugins:
  enabled: true
  cicd:
    github_actions:
      enabled: true
      settings:
        fail_on_critical: true
        create_issues: true
        comment_on_pr: true
  
  webhooks:
    - name: "security_alerts"
      url: "https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"
      filter_severity: ["critical", "high"]
```

#### Threat Intelligence
```yaml
threat_intelligence:
  enabled: true
  database:
    type: "sqlite"
    path: "./data/threats.db"
    encryption: true
  
  feeds:
    - name: "npm_security_advisories"
      url: "https://registry.npmjs.org/-/npm/v1/security/advisories"
      update_interval_minutes: 60
  
  alerting:
    enabled: true
    channels:
      email:
        type: "email"
        settings:
          smtp_host: "smtp.gmail.com"
          to: ["security@company.com"]
```

## 📚 Usage Examples

### Advanced Scanning

```bash
# Comprehensive scan with all features
typosentinel scan \
  --config config/typosentinel.yaml \
  --enhanced \
  --threat-intelligence \
  --adaptive-thresholds \
  --output-format json \
  --output-file results.json \
  package.json

# Scan with specific ecosystem
typosentinel scan --ecosystem npm --enhanced lodahs

# Batch scanning
typosentinel scan --batch packages.txt --parallel 10

# Continuous monitoring
typosentinel monitor --interval 1h --config config/typosentinel.yaml
```

### Output Formats

```bash
# JSON output
typosentinel scan --output-format json package.json

# SARIF output (for security tools)
typosentinel scan --output-format sarif package.json

# JUnit XML (for CI/CD)
typosentinel scan --output-format junit package.json

# Human-readable table
typosentinel scan --output-format table package.json
```

### Filtering and Thresholds

```bash
# Only show critical and high severity threats
typosentinel scan --min-severity high package.json

# Custom risk threshold
typosentinel scan --risk-threshold 0.8 package.json

# Exclude specific packages
typosentinel scan --exclude "@types/*,*-dev" package.json

# Include only specific threat types
typosentinel scan --threat-types typosquatting,supply_chain package.json
```

## 🔗 CI/CD Integration

### GitHub Actions

Create `.github/workflows/security-scan.yml`:

```yaml
name: Package Security Scan

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    
    - name: Setup Go
      uses: actions/setup-go@v4
      with:
        go-version: '1.21'
    
    - name: Install Typosentinel
      run: go install github.com/your-org/typosentinel/cmd/typosentinel@latest
    
    - name: Run Security Scan
      run: |
        typosentinel scan \
          --plugin github-actions \
          --config .typosentinel.yaml \
          --fail-on-critical \
          --output-format sarif \
          --output-file security-results.sarif \
          package.json
    
    - name: Upload SARIF results
      uses: github/codeql-action/upload-sarif@v2
      if: always()
      with:
        sarif_file: security-results.sarif
```

### GitLab CI

Add to `.gitlab-ci.yml`:

```yaml
security-scan:
  stage: test
  image: golang:1.21
  before_script:
    - go install github.com/your-org/typosentinel/cmd/typosentinel@latest
  script:
    - |
      typosentinel scan \
        --plugin gitlab-ci \
        --config .typosentinel.yaml \
        --fail-on-critical \
        --output-format gitlab-sast \
        --output-file gl-sast-report.json \
        package.json
  artifacts:
    reports:
      sast: gl-sast-report.json
    expire_in: 1 week
  only:
    - merge_requests
    - main
```

### Jenkins Pipeline

```groovy
pipeline {
    agent any
    
    stages {
        stage('Security Scan') {
            steps {
                script {
                    sh '''
                        typosentinel scan \
                          --plugin jenkins \
                          --config .typosentinel.yaml \
                          --output-format junit \
                          --output-file security-results.xml \
                          package.json
                    '''
                }
            }
            post {
                always {
                    publishTestResults testResultsPattern: 'security-results.xml'
                    archiveArtifacts artifacts: 'security-*.json', allowEmptyArchive: true
                }
            }
        }
    }
}
```

### Docker Integration

```dockerfile
# Multi-stage build for security scanning
FROM golang:1.21-alpine AS scanner
RUN go install github.com/your-org/typosentinel/cmd/typosentinel@latest

FROM node:18-alpine AS app
COPY --from=scanner /go/bin/typosentinel /usr/local/bin/
COPY package*.json ./

# Run security scan before installing dependencies
RUN typosentinel scan --fail-on-critical package.json
RUN npm ci --only=production

COPY . .
EXPOSE 3000
CMD ["npm", "start"]
```

## 🛡️ Threat Intelligence

### Threat Feeds Configuration

```yaml
threat_intelligence:
  feeds:
    # Official npm security advisories
    - name: "npm_advisories"
      type: "npm_advisory"
      url: "https://registry.npmjs.org/-/npm/v1/security/advisories"
      update_interval_minutes: 60
      enabled: true
    
    # PyPI security database
    - name: "pypi_osv"
      type: "osv"
      url: "https://osv.dev/list?ecosystem=PyPI"
      update_interval_minutes: 120
      enabled: true
    
    # Custom threat feed
    - name: "company_threats"
      type: "custom"
      url: "https://threat-intel.company.com/api/v1/packages"
      api_key: "${THREAT_INTEL_API_KEY}"
      update_interval_minutes: 30
      enabled: true
```

### Custom Threat Management

```bash
# Add custom threat
typosentinel threats add \
  --type malicious_package \
  --severity critical \
  --indicator package_name:suspicious-package \
  --description "Known malicious package"

# List threats
typosentinel threats list --severity critical

# Remove threat
typosentinel threats remove threat-id-123

# Update threat feeds
typosentinel threats update --feed npm_advisories
```

### Alerting Configuration

```yaml
alerting:
  channels:
    # Email alerts
    email:
      type: "email"
      settings:
        smtp_host: "smtp.company.com"
        smtp_port: 587
        username: "alerts@company.com"
        password: "${EMAIL_PASSWORD}"
        to: ["security@company.com", "devops@company.com"]
      filters: ["critical", "high"]
    
    # Slack notifications
    slack:
      type: "slack"
      settings:
        webhook_url: "${SLACK_WEBHOOK_URL}"
        channel: "#security-alerts"
        username: "Typosentinel"
      filters: ["critical"]
    
    # Custom webhook
    webhook:
      type: "webhook"
      settings:
        url: "https://api.company.com/security/alerts"
        headers:
          Authorization: "Bearer ${API_TOKEN}"
      filters: []
```

## 🧠 Machine Learning

### Adaptive Thresholds

Typosentinel Enhanced uses machine learning to automatically adjust detection thresholds based on performance feedback:

```bash
# View current thresholds
typosentinel ml thresholds show --ecosystem npm

# Update performance stats
typosentinel ml performance update \
  --ecosystem npm \
  --true-positives 95 \
  --false-positives 3 \
  --true-negatives 892 \
  --false-negatives 10

# Force threshold adaptation
typosentinel ml thresholds adapt --ecosystem npm

# Export model metrics
typosentinel ml metrics export --format prometheus
```

### Model Training

```bash
# Prepare training data
typosentinel ml data prepare \
  --input scan-results.jsonl \
  --output training-data.json \
  --validation-split 0.2

# Train ecosystem-specific model
typosentinel ml train \
  --ecosystem npm \
  --training-data training-data.json \
  --model-output models/npm-v2.0.0.model

# Evaluate model performance
typosentinel ml evaluate \
  --model models/npm-v2.0.0.model \
  --test-data test-data.json
```

### Feature Engineering

```yaml
feature_engineering:
  string_features:
    - "package_name"
    - "description"
    - "keywords"
  numerical_features:
    - "download_count"
    - "version_count"
    - "maintainer_count"
  categorical_features:
    - "license"
    - "ecosystem"
  custom_features:
    - "name_entropy"
    - "version_pattern"
    - "maintainer_reputation"
  normalization: "standard"
  dimensionality: 128
```

## 📊 Monitoring & Metrics

### Prometheus Metrics

Typosentinel exposes comprehensive metrics for monitoring:

```bash
# Start metrics server
typosentinel metrics serve --port 9090

# View available metrics
curl http://localhost:9090/metrics
```

Key metrics include:
- `typosentinel_scans_total`: Total number of scans performed
- `typosentinel_threats_detected_total`: Total threats detected by type
- `typosentinel_scan_duration_seconds`: Scan duration histogram
- `typosentinel_ml_threshold_adaptations_total`: ML threshold changes
- `typosentinel_threat_intel_updates_total`: Threat intelligence updates

### Health Checks

```bash
# Check system health
typosentinel health check

# Check specific components
typosentinel health check --component threat-intelligence
typosentinel health check --component ml-models
typosentinel health check --component plugins
```

### Performance Profiling

```bash
# Enable CPU profiling
typosentinel scan --profile-cpu --profile-output ./profiles package.json

# Enable memory profiling
typosentinel scan --profile-memory --profile-output ./profiles package.json

# Analyze profiles
go tool pprof profiles/cpu.prof
go tool pprof profiles/mem.prof
```

## 🔧 API Reference

### REST API

Typosentinel Enhanced provides a REST API for integration:

```bash
# Start API server
typosentinel api serve --port 8080 --config config/typosentinel.yaml
```

#### Endpoints

**Scan Package**
```http
POST /api/v1/scan
Content-Type: application/json

{
  "package_name": "lodahs",
  "package_version": "1.0.0",
  "ecosystem": "npm",
  "enhanced": true
}
```

**Get Scan Results**
```http
GET /api/v1/scans/{scan_id}
```

**List Threats**
```http
GET /api/v1/threats?severity=critical&limit=50
```

**Update Threat Intelligence**
```http
POST /api/v1/threats/update
```

**Get ML Thresholds**
```http
GET /api/v1/ml/thresholds/{ecosystem}
```

### GraphQL API

```bash
# Start GraphQL server
typosentinel graphql serve --port 8080
```

Example query:
```graphql
query {
  scanPackage(name: "lodahs", version: "1.0.0", ecosystem: "npm") {
    riskScore
    overallRisk
    threats {
      type
      severity
      description
    }
    recommendations
  }
}
```

## 🧪 Development

### Development Setup

```bash
# Clone repository
git clone https://github.com/your-org/typosentinel.git
cd typosentinel

# Install dependencies
go mod download

# Install development tools
make install-tools

# Run tests
make test

# Run integration tests
make test-integration

# Run linting
make lint

# Build for all platforms
make build-all
```

### Project Structure

```
typosentinel/
├── cmd/
│   └── typosentinel/          # Main application
├── internal/
│   ├── config/                # Configuration management
│   ├── detector/              # Detection engines
│   ├── ml/                    # Machine learning components
│   ├── plugins/               # Plugin system
│   └── threat_intelligence/   # Threat intelligence
├── pkg/
│   ├── types/                 # Shared types
│   └── utils/                 # Utility functions
├── tests/
│   ├── integration/           # Integration tests
│   └── testdata/              # Test data
├── config/                    # Configuration files
├── docs/                      # Documentation
└── scripts/                   # Build and deployment scripts
```

### Testing

```bash
# Run unit tests
go test ./...

# Run tests with coverage
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out

# Run integration tests
go test -tags=integration ./tests/integration/...

# Run benchmarks
go test -bench=. ./...

# Run race condition tests
go test -race ./...
```

### Adding New Detectors

1. Create detector in `internal/detector/`
2. Implement the `Detector` interface
3. Add configuration options
4. Write comprehensive tests
5. Update documentation

Example detector interface:
```go
type Detector interface {
    Name() string
    Analyze(ctx context.Context, pkg *Package) (*Result, error)
    Configure(config Config) error
}
```

### Adding New Plugins

1. Create plugin in `internal/plugins/`
2. Implement the `Plugin` interface
3. Add to plugin registry
4. Write integration tests
5. Update documentation

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Workflow

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Run the test suite
6. Submit a pull request

### Code Style

- Follow Go conventions
- Use `gofmt` for formatting
- Write comprehensive tests
- Document public APIs
- Follow semantic versioning

### Reporting Issues

Please use GitHub Issues to report bugs or request features. Include:

- Typosentinel version
- Operating system
- Go version
- Detailed description
- Steps to reproduce
- Expected vs actual behavior

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Levenshtein Distance Algorithm](https://en.wikipedia.org/wiki/Levenshtein_distance)
- [Jaro-Winkler Similarity](https://en.wikipedia.org/wiki/Jaro%E2%80%93Winkler_distance)
- [OWASP Dependency Check](https://owasp.org/www-project-dependency-check/)
- [npm Security Advisories](https://docs.npmjs.com/about-security-advisories)
- [OSV Database](https://osv.dev/)

## 📞 Support

- 📧 Email: security@typosentinel.org
- 💬 Discord: [Typosentinel Community](https://discord.gg/typosentinel)
- 📖 Documentation: [docs.typosentinel.org](https://docs.typosentinel.org)
- 🐛 Issues: [GitHub Issues](https://github.com/your-org/typosentinel/issues)

---

**Typosentinel Enhanced** - Protecting your software supply chain with advanced threat detection and machine learning.