# ACME Enterprise CI/CD Pipelines

Comprehensive CI/CD pipeline configurations for integrating Typosentinel security scanning across multiple platforms and package registries.

## 📋 Overview

This directory contains production-ready CI/CD pipeline configurations that demonstrate enterprise-grade integration of Typosentinel security scanning. The pipelines support:

- **Multi-Registry Scanning**: NPM, PyPI, Maven, NuGet, RubyGems, Go Modules
- **Zero-Day Detection**: Advanced threat detection and attack scenario testing
- **Enterprise Features**: Compliance reporting, risk assessment, threat intelligence
- **Parallel Execution**: Optimized performance with concurrent scans
- **Comprehensive Reporting**: JSON, SARIF, HTML, and PDF reports
- **Automated Notifications**: Slack, email, and dashboard integrations

## 🏗️ Pipeline Configurations

### GitHub Actions
**File**: `github-actions/typosentinel-scan.yml`

- **Triggers**: Push, PR, schedule, manual dispatch
- **Matrix Strategy**: Dynamic registry detection
- **Native Tool Integration**: npm audit, safety, OWASP dependency-check
- **Artifact Management**: Comprehensive report archiving
- **Security**: Secrets management and API token handling

**Key Features**:
- Automatic registry detection based on project files
- Parallel scanning across detected registries
- Integration with GitHub Security tab (SARIF uploads)
- Configurable scan types and severity thresholds
- Zero-day scenario testing capabilities

### GitLab CI/CD
**File**: `gitlab-ci/typosentinel-security.yml`

- **Stages**: validate, security-scan, analysis, report, deploy
- **Docker Integration**: Registry-specific container images
- **Caching**: Optimized dependency caching strategies
- **Compliance**: Enterprise compliance reporting
- **Dashboard**: Security dashboard integration

**Key Features**:
- Multi-stage pipeline with clear separation of concerns
- Docker-based execution environments
- Advanced caching for improved performance
- Compliance report generation
- Integration with external security dashboards

### Jenkins
**File**: `jenkins/Jenkinsfile`

- **Declarative Pipeline**: Modern Jenkins pipeline syntax
- **Parameterized Builds**: Configurable scan options
- **Parallel Execution**: Concurrent registry scanning
- **HTML Publishing**: Rich report visualization
- **Notification System**: Multi-channel alerting

**Key Features**:
- Flexible parameter-driven execution
- Docker agent support for isolated environments
- Rich HTML report publishing
- Comprehensive notification system
- Post-build actions and cleanup

## 🚀 Quick Start

### Prerequisites

1. **Typosentinel Installation**:
   ```bash
   # Download latest release
   curl -L "https://github.com/typosentinel/typosentinel/releases/latest/download/typosentinel-linux-amd64" -o typosentinel
   chmod +x typosentinel
   sudo mv typosentinel /usr/local/bin/
   ```

2. **API Token Configuration**:
   ```bash
   # Set environment variable
   export TYPOSENTINEL_API_TOKEN="your-api-token-here"
   
   # Or configure in CI/CD secrets
   # GitHub: Repository Settings > Secrets and variables > Actions
   # GitLab: Project Settings > CI/CD > Variables
   # Jenkins: Manage Jenkins > Credentials
   ```

3. **Enterprise License** (Optional):
   ```bash
   export TYPOSENTINEL_ENTERPRISE_LICENSE="your-license-key"
   ```

### GitHub Actions Setup

1. **Copy Workflow File**:
   ```bash
   mkdir -p .github/workflows
   cp cicd-pipelines/github-actions/typosentinel-scan.yml .github/workflows/
   ```

2. **Configure Secrets**:
   - `TYPOSENTINEL_API_TOKEN`: Your Typosentinel API token
   - `TYPOSENTINEL_ENTERPRISE_LICENSE`: Enterprise license key (optional)
   - `SLACK_WEBHOOK_URL`: Slack webhook for notifications (optional)

3. **Customize Configuration**:
   ```yaml
   env:
     SECURITY_THRESHOLD: "medium"  # low, medium, high, critical
     PARALLEL_SCANS: "3"          # Number of parallel scans
     FAIL_ON_CRITICAL: "true"     # Fail pipeline on critical findings
   ```

### GitLab CI/CD Setup

1. **Copy Pipeline File**:
   ```bash
   cp cicd-pipelines/gitlab-ci/typosentinel-security.yml .gitlab-ci.yml
   ```

2. **Configure Variables**:
   - `TYPOSENTINEL_API_TOKEN`: Your Typosentinel API token (masked)
   - `TYPOSENTINEL_ENTERPRISE_LICENSE`: Enterprise license key (masked)
   - `SLACK_WEBHOOK_URL`: Slack webhook URL (masked)
   - `SECURITY_DASHBOARD_URL`: Internal security dashboard URL
   - `SECURITY_DASHBOARD_TOKEN`: Dashboard API token (masked)

3. **Customize Pipeline**:
   ```yaml
   variables:
     SECURITY_THRESHOLD: "medium"
     PARALLEL_SCANS: "3"
     ENTERPRISE_MODE: "true"
   ```

### Jenkins Setup

1. **Create Pipeline Job**:
   - New Item > Pipeline
   - Configure SCM to point to your repository
   - Set Script Path to `cicd-pipelines/jenkins/Jenkinsfile`

2. **Configure Credentials**:
   ```groovy
   // Add these credentials in Jenkins
   credentials('typosentinel-api-token')
   credentials('typosentinel-enterprise-license')
   credentials('slack-webhook-url')
   credentials('security-dashboard-token')
   ```

3. **Set Build Parameters**:
   - `SCAN_TYPE`: full, quick, dependencies-only, zero-day-scenarios
   - `SEVERITY_THRESHOLD`: low, medium, high, critical
   - `FAIL_ON_CRITICAL`: true/false
   - `RUN_ZERO_DAY_TESTS`: true/false

## ⚙️ Configuration Options

### Scan Types

| Type | Description | Use Case |
|------|-------------|----------|
| `full` | Complete security scan with all features | Production releases, scheduled scans |
| `quick` | Fast scan with essential checks | Pull requests, development |
| `dependencies-only` | Focus on dependency vulnerabilities | Dependency updates |
| `zero-day-scenarios` | Advanced threat detection testing | Security validation, compliance |

### Severity Thresholds

| Level | Description | Recommended For |
|-------|-------------|----------------|
| `low` | Report all findings | Development, testing |
| `medium` | Report medium and above | Staging environments |
| `high` | Report high and critical only | Production pipelines |
| `critical` | Report only critical findings | Emergency patches |

### Registry Detection

The pipelines automatically detect package registries based on project files:

| Registry | Detection Files |
|----------|----------------|
| NPM | `package.json`, `package-lock.json`, `yarn.lock` |
| PyPI | `requirements.txt`, `setup.py`, `pyproject.toml`, `Pipfile` |
| Maven | `pom.xml`, `build.gradle`, `build.gradle.kts` |
| NuGet | `*.csproj`, `*.sln`, `packages.config` |
| RubyGems | `Gemfile`, `Gemfile.lock`, `*.gemspec` |
| Go | `go.mod`, `go.sum` |

## 📊 Reports and Artifacts

### Generated Reports

1. **JSON Reports**: Machine-readable scan results
   - `scan-results.json`: Detailed findings
   - `executive-summary.json`: High-level metrics
   - `compliance-report.json`: Compliance status

2. **SARIF Reports**: GitHub Security tab integration
   - `typosentinel.sarif`: Security findings in SARIF format

3. **HTML Reports**: Human-readable dashboards
   - `security-report.html`: Interactive security dashboard
   - Registry-specific reports for detailed analysis

4. **PDF Reports**: Executive summaries
   - `security-report.pdf`: Printable compliance report

### Artifact Structure

```
reports/
├── npm/
│   ├── scan-results.json
│   ├── typosentinel.sarif
│   └── security-report.html
├── pypi/
│   ├── scan-results.json
│   ├── safety-report.json
│   └── pip-audit.json
├── maven/
│   ├── scan-results.json
│   └── dependency-check-report.json
├── aggregated-reports/
│   ├── combined-results.json
│   ├── executive-summary.json
│   ├── compliance-report.json
│   ├── security-report.html
│   └── security-report.pdf
└── zero-day/
    ├── typosquatting-results.json
    ├── dependency-confusion-results.json
    └── supply-chain-results.json
```

## 🔔 Notifications

### Slack Integration

```yaml
# Environment variable
SLACK_WEBHOOK_URL: "https://hooks.slack.com/services/..."

# Message format
{
  "text": "🚨 ACME Enterprise Security Scan Report",
  "attachments": [
    {
      "color": "danger",
      "fields": [
        {"title": "Status", "value": "FAIL", "short": true},
        {"title": "Critical", "value": "3", "short": true},
        {"title": "Total Vulnerabilities", "value": "15", "short": true},
        {"title": "Pipeline", "value": "<link|#123>", "short": true}
      ]
    }
  ]
}
```

### Email Notifications

```yaml
# GitHub Actions
- name: Send Email
  uses: dawidd6/action-send-mail@v3
  with:
    server_address: smtp.company.com
    server_port: 587
    username: ${{ secrets.EMAIL_USERNAME }}
    password: ${{ secrets.EMAIL_PASSWORD }}
    subject: "Security Scan Results - ${{ github.repository }}"
    body: file://reports/email-summary.txt
    attachments: reports/security-report.pdf
```

## 🔒 Security Considerations

### Secrets Management

1. **Never commit secrets** to version control
2. **Use platform-specific secret stores**:
   - GitHub: Repository secrets
   - GitLab: CI/CD variables (masked)
   - Jenkins: Credentials plugin

3. **Rotate tokens regularly**
4. **Use least-privilege access**

### Network Security

```yaml
# Restrict network access
network_mode: "bridge"
security_opt:
  - "no-new-privileges:true"
read_only: true
tmpfs:
  - /tmp
  - /var/tmp
```

### Container Security

```dockerfile
# Use minimal base images
FROM alpine:3.18

# Run as non-root user
RUN adduser -D -s /bin/sh scanner
USER scanner

# Set security options
LABEL security.scan="enabled"
LABEL security.compliance="required"
```

## 🚀 Performance Optimization

### Caching Strategies

```yaml
# GitHub Actions
cache:
  key: ${{ runner.os }}-deps-${{ hashFiles('**/package-lock.json') }}
  paths:
    - ~/.npm
    - ~/.cache/pip
    - ~/.m2/repository
    - ~/.nuget/packages
    - ~/.bundle
    - ~/go/pkg/mod

# GitLab CI
cache:
  key: "${CI_COMMIT_REF_SLUG}-${CI_JOB_NAME}"
  paths:
    - .npm/
    - .pip-cache/
    - .m2/
    - .nuget/
    - .bundle/
    - .go-cache/
```

### Parallel Execution

```yaml
# Optimize parallel scans
strategy:
  matrix:
    registry: [npm, pypi, maven, nuget, rubygems, go]
  max-parallel: 3  # Adjust based on runner capacity
  fail-fast: false  # Continue other scans if one fails
```

### Resource Limits

```yaml
# Docker resource constraints
services:
  scanner:
    image: typosentinel/scanner:latest
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 4G
        reservations:
          cpus: '1.0'
          memory: 2G
```

## 🔧 Troubleshooting

### Common Issues

1. **API Token Issues**:
   ```bash
   # Test token validity
   curl -H "Authorization: Bearer $TYPOSENTINEL_API_TOKEN" \
        "https://api.typosentinel.com/health"
   ```

2. **Registry Detection Failures**:
   ```bash
   # Manually specify registries
   typosentinel scan --registry npm,pypi --force
   ```

3. **Timeout Issues**:
   ```yaml
   # Increase timeout values
   env:
     SCAN_TIMEOUT: "3600"  # 1 hour
     REGISTRY_TIMEOUT: "1800"  # 30 minutes
   ```

4. **Memory Issues**:
   ```yaml
   # Reduce parallel scans
   env:
     PARALLEL_SCANS: "1"
     MAX_MEMORY: "2G"
   ```

### Debug Mode

```bash
# Enable debug logging
export TYPOSENTINEL_LOG_LEVEL=debug
export TYPOSENTINEL_VERBOSE=true

# Run with debug output
typosentinel scan --debug --verbose
```

### Log Analysis

```bash
# Check pipeline logs
# GitHub Actions: Actions tab > Workflow run > Job logs
# GitLab CI: CI/CD > Pipelines > Job logs
# Jenkins: Build > Console Output

# Common log patterns
grep "ERROR" pipeline.log
grep "CRITICAL" scan-results.json
grep "timeout" *.log
```

## 📈 Metrics and Monitoring

### Key Metrics

```json
{
  "scan_duration": "120s",
  "packages_scanned": 1250,
  "vulnerabilities_found": 15,
  "critical_vulnerabilities": 2,
  "high_vulnerabilities": 5,
  "medium_vulnerabilities": 8,
  "registries_scanned": ["npm", "pypi", "maven"],
  "compliance_status": "FAIL",
  "risk_score": 45
}
```

### Dashboard Integration

```bash
# Send metrics to monitoring system
curl -X POST \
  -H "Authorization: Bearer $DASHBOARD_TOKEN" \
  -H "Content-Type: application/json" \
  -d @executive-summary.json \
  "https://monitoring.company.com/api/security-scans"
```

## 🤝 Contributing

### Pipeline Improvements

1. **Fork the repository**
2. **Create feature branch**: `git checkout -b feature/pipeline-enhancement`
3. **Test changes** with your CI/CD platform
4. **Submit pull request** with detailed description

### Testing Guidelines

```bash
# Test pipeline locally
# GitHub Actions
act -j security-scan

# GitLab CI
gitlab-runner exec docker security-scan

# Jenkins
# Use Jenkins Pipeline Syntax tool for validation
```

### Documentation Updates

- Update this README for new features
- Add examples for new configuration options
- Include troubleshooting steps for new issues

## 📚 Additional Resources

- [Typosentinel Documentation](https://docs.typosentinel.com)
- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [GitLab CI/CD Documentation](https://docs.gitlab.com/ee/ci/)
- [Jenkins Pipeline Documentation](https://www.jenkins.io/doc/book/pipeline/)
- [SARIF Specification](https://sarifweb.azurewebsites.net/)
- [OWASP Dependency Check](https://owasp.org/www-project-dependency-check/)

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/typosentinel/typosentinel/issues)
- **Documentation**: [Official Docs](https://docs.typosentinel.com)
- **Community**: [Discord Server](https://discord.gg/typosentinel)
- **Enterprise Support**: enterprise@typosentinel.com

---

**Generated by ACME Enterprise Security Team**  
*Last Updated: 2024*