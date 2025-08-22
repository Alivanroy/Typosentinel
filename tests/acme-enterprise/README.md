# ACME Enterprise Test Environment

A comprehensive real-world test environment simulating an enterprise organization with multiple package registries, CI/CD pipelines, and realistic attack scenarios to validate Typosentinel's production readiness.

## Overview

This test environment simulates **ACME Corporation**, a fictional enterprise with:
- Multiple development teams
- Diverse technology stacks
- Complex dependency chains
- Real-world security challenges
- Production-like CI/CD workflows

## Project Structure

```
acme-enterprise/
├── README.md
├── docker-compose.yml              # Multi-service test environment
├── environments/
│   ├── development/
│   ├── staging/
│   └── production/
├── projects/
│   ├── frontend-webapp/            # React/Vue.js with NPM dependencies
│   ├── backend-api/                # Node.js/Python API services
│   ├── mobile-app/                 # React Native with complex deps
│   ├── data-pipeline/              # Python data processing
│   ├── microservices/              # Java Spring Boot services
│   ├── legacy-system/              # .NET Framework application
│   └── devops-tools/               # Go-based internal tools
├── registries/
│   ├── npm/                        # NPM packages and configs
│   ├── pypi/                       # Python packages
│   ├── maven/                      # Java/Kotlin dependencies
│   ├── nuget/                      # .NET packages
│   ├── rubygems/                   # Ruby gems
│   └── go-modules/                 # Go modules
├── ci-cd/
│   ├── github-actions/             # GitHub Actions workflows
│   ├── gitlab-ci/                  # GitLab CI configurations
│   ├── jenkins/                    # Jenkins pipelines
│   └── azure-devops/               # Azure DevOps pipelines
├── attack-scenarios/
│   ├── zero-days/                  # Zero-day vulnerability simulations
│   ├── supply-chain/               # Supply chain attacks
│   ├── dependency-confusion/       # Dependency confusion attacks
│   ├── typosquatting/              # Advanced typosquatting
│   └── social-engineering/         # Social engineering scenarios
├── monitoring/
│   ├── prometheus/                 # Metrics collection
│   ├── grafana/                    # Dashboards
│   ├── elk-stack/                  # Logging and analysis
│   └── alerting/                   # Alert configurations
└── reports/
    ├── security-scans/             # Typosentinel scan results
    ├── vulnerability-assessments/  # Security assessments
    └── compliance/                 # Compliance reports
```

## Test Scenarios

### 1. Zero-Day Vulnerabilities
- Simulated zero-day exploits in popular packages
- Advanced persistent threats (APT) scenarios
- Supply chain compromise simulations

### 2. Multi-Registry Attacks
- Cross-registry dependency confusion
- Package name squatting across ecosystems
- Version confusion attacks

### 3. Enterprise CI/CD Integration
- Automated security scanning in pipelines
- Policy enforcement and compliance checks
- Incident response workflows

### 4. Real-World Attack Vectors
- Typosquatting campaigns
- Malicious package uploads
- Social engineering attacks on maintainers

## Getting Started

1. **Environment Setup**:
   ```bash
   cd tests/acme-enterprise
   docker-compose up -d
   ```

2. **Run Security Scans**:
   ```bash
   ./scripts/run-enterprise-scan.sh
   ```

3. **Simulate Attack Scenarios**:
   ```bash
   ./scripts/simulate-attacks.sh
   ```

4. **Generate Reports**:
   ```bash
   ./scripts/generate-reports.sh
   ```

## Key Features

- **Realistic Dependencies**: Uses actual popular packages with known vulnerabilities
- **Multi-Language Support**: Tests across NPM, PyPI, Maven, NuGet, RubyGems, Go
- **CI/CD Integration**: Real pipeline configurations for major platforms
- **Enterprise Monitoring**: Production-grade monitoring and alerting
- **Compliance Testing**: SOC2, ISO27001, and other compliance frameworks

## Security Test Matrix

| Attack Vector | NPM | PyPI | Maven | NuGet | RubyGems | Go |
|---------------|-----|------|-------|-------|----------|----|
| Typosquatting | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Dependency Confusion | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Supply Chain | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Zero-Day Simulation | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Social Engineering | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

## Expected Outcomes

- Validate Typosentinel's detection accuracy in production scenarios
- Test enterprise integration capabilities
- Measure performance under realistic loads
- Verify compliance and reporting features
- Identify areas for improvement

---

**Note**: This is a controlled test environment. All malicious packages and attack scenarios are simulated and contained within this testing framework.