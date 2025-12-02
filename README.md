# Typosentinel

[![Go Version](https://img.shields.io/badge/go-1.24-blue.svg)](https://golang.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![CI](https://github.com/Alivanroy/Typosentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/Alivanroy/Typosentinel/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/Alivanroy/Typosentinel)](https://goreportcard.com/report/github.com/Alivanroy/Typosentinel)
[![Go Reference](https://pkg.go.dev/badge/github.com/Alivanroy/Typosentinel.svg)](https://pkg.go.dev/github.com/Alivanroy/Typosentinel)
[![Linux Tests](https://github.com/Alivanroy/Typosentinel/actions/workflows/linux-test.yml/badge.svg)](https://github.com/Alivanroy/Typosentinel/actions/workflows/linux-test.yml)
[![Supply Chain Firewall](https://github.com/Alivanroy/Typosentinel/actions/workflows/supply-chain-firewall.yml/badge.svg)](https://github.com/Alivanroy/Typosentinel/actions/workflows/supply-chain-firewall.yml)
[![Docker Hub Publish](https://github.com/Alivanroy/Typosentinel/actions/workflows/dockerhub-publish.yml/badge.svg)](https://github.com/Alivanroy/Typosentinel/actions/workflows/dockerhub-publish.yml)
[![Docker Pulls](https://img.shields.io/docker/pulls/vanali/typosentinel?logo=docker)](https://hub.docker.com/r/vanali/typosentinel)

**Typosentinel** is an intelligent supply chain firewall that actively blocks malicious packages, typosquatting attacks, and supply chain threats in real-time. It transforms from a security scanner into an active protection system with business-aware risk assessment and policy-based blocking.

## 📊 Project Status & Maturity

**Current Status**: Active Development (Beta)

### Production Ready ✅
- ✅ **Core Scanning**: Typosquatting detection for npm, PyPI, Go, Maven, Cargo, Ruby, PHP
- ✅ **CLI Tool**: Scan command with multiple output formats (JSON, YAML, table, SARIF)
- ✅ **Basic Detection**: Edit distance, homoglyph, and similarity-based threat detection
- ✅ **SBOM Generation**: SPDX and CycloneDX format support
- ✅ **Multi-platform**: Works on Linux, macOS, and Windows (with limitations)

### Experimental / Beta 🚧
- 🚧 **Supply Chain Firewall**: Policy enforcement and active blocking (beta)
- 🚧 **DIRT/RUNT/GTR Algorithms**: Advanced edge algorithms (tested but needs validation)
- 🚧 **ML Detection**: Machine learning-based threat detection (disabled by default)
- 🚧 **API Server**: REST API and dashboard (functional but needs hardening)
- 🚧 **Redis Cache**: Performance optimization for GTR algorithm (requires Redis)

### Platform Support
- ✅ **Linux**: Fully tested and supported
- ✅ **macOS**: Tested and supported
- ⚠️ **Windows**: Mostly working (scan specific files works, directory scan intermittent)

## 🎯 Production Readiness Matrix

| Component | Status | Recommended For | Notes |
|-----------|--------|-----------------|-------|
| **CLI Scanner** | ✅ Production Ready | All users | Core functionality stable |
| **Typosquatting Detection** | ✅ Production Ready | All users | Tested with real-world packages |
| **SBOM Generation** | ✅ Production Ready | CI/CD pipelines | SPDX & CycloneDX compliant |
| **Multi-language Support** | ✅ Production Ready | npm, PyPI, Go, Maven | Other registries in beta |
| **Supply Chain Firewall** | 🚧 Beta | Testing/staging | Needs security review for prod |
| **REST API** | 🚧 Beta | Internal tools | Authentication needs hardening |
| **DIRT/RUNT/GTR Algorithms** | 🚧 Beta | Research/validation | Performance tested, awaiting validation |
| **ML Detection** | 🔬 Experimental | Not recommended | Requires model training |
| **Docker Deployment** | ✅ Production Ready | Server deployments | Compose setup included |

**Legend**:
- ✅ Production Ready: Tested, stable, ready for critical use
- 🚧 Beta: Functional, needs more testing/hardening
- 🔬 Experimental: Proof of concept, not for production

## 🚀 Features

### Supply Chain Firewall Features 🚧
- **Active Blocking** 🚧: Real-time package interception and policy-based blocking
- **Business-Aware Risk Assessment** ✅: Asset criticality scoring (CRITICAL/INTERNAL/PUBLIC) with intelligent multipliers
- **Policy Engine** 🚧: 5 default security policies with customizable rules and thresholds
- **CI/CD Integration** ✅: GitHub Actions integration for build-time package blocking
- **Multi-Language Support** ✅: npm, PyPI, Go modules, Maven, NuGet, and more package managers

### Advanced Detection & Analysis
- **DIRT Algorithm** 🚧: Business-aware Dependency Impact Risk Traversal with asset criticality scoring
- **Campaign Intelligence** 🔬: Group related malicious packages into coordinated campaigns
- **Behavioral Analysis** 🔬: Dynamic sandbox analysis with filesystem and network monitoring
- **Threat Intelligence** 🚧: Real-time integration with multiple threat intelligence feeds
- **Enhanced Detection** ✅: Advanced algorithms for sophisticated typosquatting and supply chain attacks

### Integration & Deployment
- **Firewall Dashboard** 🚧: Real-time supply chain firewall monitoring with live activity feed
- **REST API** 🚧: Comprehensive API for CI/CD pipeline integration and policy enforcement
- **Organization Scanning** ✅: Multi-platform repository scanning (GitHub, GitLab, Bitbucket)
- **SBOM Generation** ✅: SPDX and CycloneDX software bill of materials support
- **Docker Deployment** ✅: Complete containerized deployment with monitoring and alerting

### Performance & Reliability
- **Real-time Processing** ✅: Sub-second response times for policy enforcement
- **Enterprise Ready** 🚧: Authentication, RBAC, audit logging, and compliance features
- **Policy Reporting** ✅: Detailed policy violation reports with business impact analysis
- **Multi-format Output** ✅: JSON, YAML, SARIF, table, and terminal output with firewall metrics

## 📦 Installation

### Binary Releases

Download the latest release from [GitHub Releases](https://github.com/Alivanroy/Typosentinel/releases):

```bash
# Linux
wget https://github.com/Alivanroy/Typosentinel/releases/latest/download/typosentinel-linux-amd64
chmod +x typosentinel-linux-amd64
sudo mv typosentinel-linux-amd64 /usr/local/bin/typosentinel

# macOS
wget https://github.com/Alivanroy/Typosentinel/releases/latest/download/typosentinel-darwin-amd64
chmod +x typosentinel-darwin-amd64
sudo mv typosentinel-darwin-amd64 /usr/local/bin/typosentinel

# Windows
# Download typosentinel-windows-amd64.exe and add to PATH
```

### Windows Notes

**Recommended Usage on Windows**:
```bash
# ✅ Scan specific files (reliable)
.\typosentinel.exe scan package.json --output json

# ✅ Scan specific directories (reliable)
.\typosentinel.exe scan .\src --output table

# ⚠️ Scan current directory (may be intermittent)
.\typosentinel.exe scan . --output json
```

**Known Windows Issues**:
- Directory scanning may be intermittent in large projects
- Workaround: Always specify the exact directory or manifest file to scan

### From Source

```bash
git clone https://github.com/Alivanroy/Typosentinel.git
cd Typosentinel
make build
# Binary will be created as ./typosentinel
```

### Docker Deployment

```bash
# One-line build and run (API on :8080)
docker build -t typosentinel-api . && docker run --rm -p 8080:8080 typosentinel-api

# One-line CLI scan using Docker (mounts current directory)
docker build -t typosentinel . && docker run --rm -v "$PWD:/scan" typosentinel ./typosentinel scan /scan --output json --supply-chain --advanced

# Compose: API + Postgres + optional monitoring
docker compose up -d
```

### Docker Hub

Build locally and push to Docker Hub:

```bash
# Build
docker build -t yourname/typosentinel:latest .

# Login and push
docker login -u yourname
docker push yourname/typosentinel:latest

# Run CLI
docker run --rm yourname/typosentinel:latest scan /workspace --output json

# Run API
docker run --rm -p 8080:8080 yourname/typosentinel:latest server
```

CI publish to Docker Hub:
- Add repository secrets: `DOCKERHUB_USERNAME`, `DOCKERHUB_TOKEN`
- Trigger “Docker Hub Publish” workflow (Actions) with `image_name` (e.g., `yourname/typosentinel`) and `tag` (e.g., `v1.0.3`)
- On tag pushes (`v*.*.*`), images are built and pushed as `latest` and `<tag>`.

Prebuilt image (GHCR):

```bash
docker pull ghcr.io/alivanroy/typosentinel-api:latest
docker run --rm -p 8080:8080 ghcr.io/alivanroy/typosentinel-api:latest
```

**Access Points:**
- Web Interface: http://localhost:3000
- API Server: http://localhost:8080
- API Playground: http://localhost:8080/api

### CLI Quick Start

```bash
# Build native CLI
go build -o build/typosentinel .
./build/typosentinel version
./build/typosentinel scan . --output json --supply-chain --advanced

Force registry for specific ecosystem:

```bash
./build/typosentinel scan ./my-go-project --registry go --output json
./build/typosentinel scan ./my-java-project --registry maven --output json
```

# One-line Docker CLI (Windows PowerShell)
docker build -t typosentinel . ; docker run --rm -v "${PWD}:/scan" typosentinel ./typosentinel scan /scan --output json --supply-chain --advanced
```

For detailed Docker deployment instructions, see [DOCKER.md](DOCKER.md).

## 🔧 Quick Start

### Recommended First Steps

1. **Scan a known typosquatting example**:
```bash
# Create test project
mkdir test-scan && cd test-scan
echo '{"dependencies": {"expres": "1.0.0"}}' > package.json

# Scan (should detect "expres" as typosquat of "express")
typosentinel scan . --output table
```

**Expected Output**: Should identify "expres" as a typosquatting threat

2. **Scan your real project** (recommended approach):
```bash
# Scan specific manifest file
typosentinel scan path/to/package.json --output json

# Or scan project directory
typosentinel scan path/to/project --output table
```

3. **Generate SBOM**:
```bash
typosentinel scan . --sbom-format spdx --sbom-output sbom.json
```

# Scan with enhanced detection
typosentinel scan --enhanced /path/to/project

# Scan specific package managers
typosentinel scan --package-manager npm /path/to/project
typosentinel scan --package-manager pypi /path/to/project

# Output results to file
typosentinel scan --output report.json /path/to/project

# Enable verbose logging
typosentinel scan --verbose /path/to/project
```

### Advanced Scanning

```bash
# Supply chain security scan
typosentinel supply-chain scan-advanced /path/to/project \
  --build-integrity \
  --threat-intel \
  --risk-threshold high

# Organization scanning
typosentinel scan-org github \
  --org company-name \
  --token $GITHUB_TOKEN \
  --max-repos 100

# SBOM generation
typosentinel scan /path/to/project \
  --sbom-format spdx \
  --sbom-output project-sbom.spdx.json
```

## 🌐 Web Interface & Server

### Starting the Web Server

```bash
# Start the server with default settings
typosentinel server

# Start with custom configuration
typosentinel server --port 8080 --host 0.0.0.0

# Development mode with enhanced logging
typosentinel server --dev --verbose
```

### API Authentication

Authentication is controlled via environment variables:

- `API_AUTH_ENABLED`: set to `true` or `1` to require a bearer token
- `API_KEYS`: comma‑separated list of allowed API keys (e.g., `key1,key2`)

Example curl with bearer token:

```bash
curl -s -X POST http://localhost:8080/v1/analyze \
  -H "Authorization: Bearer key1" \
  -H "Content-Type: application/json" \
  -d '{"package_name":"express","registry":"npm"}'
```

Docker run with auth enabled:

```bash
docker build -t typosentinel-api . && \
docker run --rm -p 8080:8080 \
  -e API_AUTH_ENABLED=true \
  -e API_KEYS=key1,key2 \
  typosentinel-api
```

Note: demo‑only endpoints (`/api/v1/vulnerabilities`, `/api/v1/dashboard/*`) return `501 Not Implemented`.

## 📜 Governance
- Contributing: see `CONTRIBUTING.md`
- Code of Conduct: see `CODE_OF_CONDUCT.md`
- Security Policy: see `SECURITY.md`

## 🔎 API Docs
- OpenAPI JSON: `/openapi.json`
- Interactive docs: `/docs`

### Firewall Dashboard Features

- **🛡️ Firewall Status**: Real-time supply chain firewall monitoring with live activity feed
- **📊 Security Metrics**: Policy violations, blocked packages, and threat intelligence
- **🔍 Package Analysis**: Interactive package scanning with business-aware risk assessment
- **📈 Activity Feed**: Live stream of security events and policy enforcements
- **⚙️ Policy Management**: Web-based configuration of security policies and thresholds
- **📋 Reports**: Downloadable security reports with business impact analysis

### API Endpoints

```bash
# Health and status
GET /health
GET /v1/status
GET /v1/stats

# Analyze a single package (demo mode)
POST /v1/analyze
{
  "package_name": "express",
  "registry": "npm"
}

# Batch analysis (demo mode)
POST /v1/analyze/batch
{
  "packages": [
    {"package_name": "express", "registry": "npm"},
    {"package_name": "test-package", "registry": "npm"}
  ]
}

# Vulnerabilities (mock data)
GET /api/v1/vulnerabilities?severity=critical

# Dashboard metrics (mock data)
GET /api/v1/dashboard/metrics
GET /api/v1/dashboard/performance
```

### Current Status & Honest Metrics

- API server endpoints validated end-to-end with automated tests
- Legitimate packages (e.g., `express`) return `risk_level: 0` and `risk_score: 0.0`
- Suspicious names (e.g., `test-package`, very short, numeric-included) produce appropriate threats/warnings
- Webhook endpoints scaffolded; some provider routes operate in demo mode
- Unit test coverage highlights:
  - `pkg/types`: 100%
  - `internal/supplychain`: ~54%
  - Other modules vary; several integration tests are skipped in demo mode
- API tests (tag `api`) pass; batch and rate limiting behavior validated
- Demo mode is enabled for several endpoints with mock data responses

## 🔍 Detection Methods

### Core Detection Algorithms

#### 1. String Similarity Analysis
- **Levenshtein Distance**: Character-level edit distance calculation
- **Jaro-Winkler Similarity**: Weighted string matching with prefix bias
- **Longest Common Subsequence (LCS)**: Sequence-based similarity detection
- **Cosine Similarity**: Vector-based text similarity
- **N-Gram Analysis**: Character and word n-gram comparison

#### 2. Visual Similarity Detection
- **Unicode Homoglyph Detection**: Visually similar character identification
- **Character Substitution Patterns**: Common typo pattern recognition
- **Script Mixing Detection**: Multiple Unicode script usage
- **Confusable Character Mapping**: International character confusion

#### 3. Behavioral Analysis
- **Dynamic Sandbox Analysis**: Runtime behavior monitoring in isolated containers
- **Filesystem Activity**: File creation, modification, and access patterns
- **Network Communication**: Outbound connections and data exfiltration attempts
- **Process Behavior**: Suspicious process creation and execution patterns
- **Code Execution**: Eval, shell execution, and crypto mining detection

#### 4. Campaign Intelligence
- **Package Similarity**: Code and metadata similarity analysis
- **Author Clustering**: Maintainer identity and behavior patterns
- **Network IOCs**: Shared domains, IPs, and infrastructure
- **Campaign Grouping**: Automatic grouping of related malicious packages

#### 5. Risk Scoring
- **Multi-Factor Assessment**: Vulnerability, behavior, and campaign risk factors
- **Configurable Weights**: Customizable risk factor importance
- **Confidence Scoring**: Reliability assessment of detection results
- **Automatic Recommendations**: Actionable security recommendations

### 📊 Honest Performance Metrics

Measured locally (Windows 11, i7‑12700H, Go 1.23):

- DetectEnhanced: ~246µs/op (mixed cases: expresss/lodahs/recat/axois)
- DetectEnhanced (homoglyphs): ~157µs/op (Cyrillic/Greek/visual substitutions)
- Allocations: 636 allocs/op (DetectEnhanced), 486 allocs/op (homoglyphs)
- Memory: ~40KB/op (DetectEnhanced), ~31KB/op (homoglyphs)

To reproduce: `go test -bench=. -benchmem ./tests/benchmarks/...`

Throughput benchmarks:

- Small project (50 deps): ~6.75ms/run, ~1.13MB alloc, ~14.8k allocs/run
- Medium project (200 deps): ~33.6ms/run, ~4.54MB alloc, ~59.1k allocs/run

Memory profile (typical):

- Base: ~15MB
- Per 100 packages: ~8MB additional
- Peak during enhanced analysis: ~2× base

Validated summary:

| Project size | Time/run | Memory | Allocs/run |
|--------------|----------|--------|------------|
| Small (50)   | ~6.75ms  | ~1.13MB| ~14.8k     |
| Medium (200) | ~33.6ms  | ~4.54MB| ~59.1k     |
| Large (500)  | ~75.3ms  | ~11.3MB| ~147.6k    |

## 🚀 CI/CD Integration

### GitHub Actions Supply Chain Firewall

```yaml
# .github/workflows/supply-chain-firewall.yml
name: Supply Chain Firewall
on: [push, pull_request]

jobs:
  supply-chain-protection:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Supply Chain Firewall
        uses: Alivanroy/Typosentinel/.github/actions/supply-chain-firewall@main
        with:
          policy-config: |
            policies:
              - name: "Block Critical Risk"
                condition: "risk_score >= 0.9"
                action: "BLOCK"
              - name: "Alert Typosquatting"
                condition: "typosquatting_score >= 0.8"
                action: "ALERT"
          asset-criticality: "INTERNAL"
          fail-on-policy-violation: true
```

### GitLab CI Supply Chain Protection

```yaml
# .gitlab-ci.yml
supply_chain_firewall:
  stage: security
  image: alpine:latest
  before_script:
    - apk add --no-cache wget
    - wget -O typosentinel https://github.com/Alivanroy/Typosentinel/releases/latest/download/typosentinel-linux-amd64
    - chmod +x typosentinel
  script:
    - ./typosentinel supply-chain policy-enforce --config policies.yaml --asset-criticality INTERNAL .
  artifacts:
    reports:
      sast: gl-sast-report.json
    expire_in: 1 week
  only:
    - merge_requests
    - main
```

## 📖 Documentation

### Core Documentation
- [User Guide](docs/USER_GUIDE.md) - Supply chain firewall configuration and usage
- [API Documentation](docs/API_DOCUMENTATION.md) - REST API for policy management and enforcement
- [Docker Deployment Guide](DOCKER.md) - Complete containerized firewall deployment

### Advanced Features
- [Supply Chain Policy Engine](internal/supplychain/) - Business-aware policy enforcement system
- [DIRT Algorithm](internal/edge/) - Dependency Impact Risk Traversal with asset criticality
- [Campaign Intelligence](internal/campaign/) - Coordinated threat campaign detection
- [Business-Aware Risk Assessment](internal/edge/dirt.go) - Asset criticality scoring and risk multipliers

### Development & Deployment
- [Contributing Guide](CONTRIBUTING.md) - How to contribute to the project
- [Security Policy](SECURITY.md) - Security vulnerability reporting

## ⚠️ Known Issues

### General
- **Windows Directory Scanning**: `scan .` (current directory) may be intermittent. Use `scan <specific-dir>` or `scan package.json` for reliable results.
- **Detector Initialization**: In rare cases, threat detector may not initialize properly. Logs will show warnings about skipped threat detection.
- **Large Projects**: Projects with 1000+ dependencies may experience slower scan times (optimization in progress)

### Experimental Features
- **Supply Chain Firewall**: Policy enforcement is functional but needs security hardening before trust in critical environments
- **API Authentication**: Currently supports basic auth and API keys. OAuth/JWT planned for future releases
- **Redis Cache**: Requires manual Redis setup. In-memory fallback available but less performant

### Windows-Specific
- Directory scanning of `.` may crash in edge cases (workaround: scan specific directories)
- Some E2E tests may fail on Windows (under investigation)

**Reporting Issues**: Please report bugs via [GitHub Issues](https://github.com/Alivanroy/Typosentinel/issues) with:
- OS and version
- Command run
- Full error output
- Project structure (if applicable)

## 🛠️ Development

### Prerequisites

- Go 1.23 or later
- Make (optional)
- Docker (for containerized development)

### Setup Development Environment

```bash
git clone https://github.com/Alivanroy/Typosentinel.git
cd Typosentinel
make dev-setup
```

### Available Make Targets

```bash
make help                # Show all available targets
make build              # Build the binary
make test               # Run tests
make test-coverage      # Run tests with coverage
make lint               # Run linters
make fmt                # Format code
make clean              # Clean build artifacts
make docker-build       # Build Docker image
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔒 Security

For security vulnerabilities, please see our [Security Policy](SECURITY.md).

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/Alivanroy/Typosentinel/issues)
- **Discussions**: [GitHub Discussions](https://github.com/Alivanroy/Typosentinel/discussions)

## 🙏 Acknowledgments

- Thanks to all contributors who have helped improve this project
- Inspired by the need for better supply chain security
- Built with ❤️ for the open source community

---

**Made with ❤️ by [Alivanroy](https://github.com/Alivanroy)**
### CLI Flags

- `--output {json|sarif|table}`: choose output format (SARIF requires tooling)
- `--supply-chain`: enable supply chain risk analysis
- `--advanced`: enable enhanced detection algorithms
- `--threshold <0..1>`: similarity threshold for typosquatting
- `--registry <npm|pypi|go|maven>`: force registry when auto-detection isn’t possible
Examples:

```bash
# NPM
./build/typosentinel scan ./examples/npm-clean --output json
./build/typosentinel scan ./examples/npm-vulnerable --output json

# PyPI
./build/typosentinel scan ./examples/pypi-clean --output json
./build/typosentinel scan ./examples/pypi-vulnerable --output json

# Go
./build/typosentinel scan ./examples/go-minimal --registry go --output json

# Maven
./build/typosentinel scan ./examples/maven-minimal --registry maven --output json
```
