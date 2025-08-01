# Typosentinel CI/CD Integration Templates

This directory contains comprehensive CI/CD pipeline templates for integrating Typosentinel security scanning into your development workflow. These templates provide automated security scanning, threat detection, and policy enforcement across multiple platforms.

## 🚀 Available Templates

### 1. GitHub Actions (`github-actions.yml`)
- **Platform**: GitHub
- **Features**: 
  - Automated scanning on push, PR, and schedule
  - SARIF integration for GitHub Security tab
  - PR comments with scan results
  - Artifact uploads and caching
  - Slack notifications
  - Security policy enforcement

### 2. GitLab CI/CD (`gitlab-ci.yml`)
- **Platform**: GitLab
- **Features**:
  - Multi-stage pipeline with parallel jobs
  - Incremental and full scanning
  - HTML and Markdown reporting
  - Merge request comments
  - GitLab issue creation
  - Slack integration

### 3. Jenkins Pipeline (`jenkins-pipeline.groovy`)
- **Platform**: Jenkins
- **Features**:
  - Declarative pipeline syntax
  - Parallel scan execution
  - HTML report publishing
  - Email and Slack notifications
  - JIRA integration
  - Build artifact archiving

### 4. Azure DevOps (`azure-devops.yml`)
- **Platform**: Azure DevOps
- **Features**:
  - Multi-stage YAML pipeline
  - Work item creation
  - Teams notifications
  - Test result publishing
  - HTML report generation
  - PR comments

## 📋 Prerequisites

### Common Requirements
1. **Typosentinel Account**: Sign up at [typosentinel.com](https://typosentinel.com)
2. **API Key**: Generate an API key from your Typosentinel dashboard
3. **Node.js**: Version 18+ required for the Typosentinel CLI
4. **Package Files**: Ensure your repository contains dependency files (package.json, requirements.txt, etc.)

### Platform-Specific Requirements

#### GitHub Actions
- Repository with Actions enabled
- Secrets configured for API key and webhook URLs

#### GitLab CI/CD
- GitLab project with CI/CD enabled
- Variables configured for API key and integrations

#### Jenkins
- Jenkins instance with required plugins:
  - Pipeline
  - NodeJS
  - HTML Publisher
  - Email Extension
  - Slack Notification (optional)

#### Azure DevOps
- Azure DevOps project
- Service connections for external integrations
- Variable groups for configuration

## 🔧 Setup Instructions

### 1. Choose Your Platform

Select the appropriate template for your CI/CD platform and copy it to your repository:

```bash
# GitHub Actions
cp github-actions.yml .github/workflows/typosentinel.yml

# GitLab CI/CD
cp gitlab-ci.yml .gitlab-ci.yml

# Jenkins
# Copy jenkins-pipeline.groovy to your Jenkins job configuration

# Azure DevOps
cp azure-devops.yml azure-pipelines.yml
```

### 2. Configure Secrets/Variables

#### GitHub Actions Secrets
```yaml
TYPOSENTINEL_API_KEY: "your-api-key-here"
SLACK_WEBHOOK_URL: "https://hooks.slack.com/..."
SECURITY_TEAM_EMAIL: "security@yourcompany.com"
```

#### GitLab CI/CD Variables
```yaml
TYPOSENTINEL_API_KEY: "your-api-key-here"
SLACK_WEBHOOK_URL: "https://hooks.slack.com/..."
GITLAB_TOKEN: "your-gitlab-token"
```

#### Jenkins Credentials
- `typosentinel-api-key`: Secret text
- `typosentinel-api-url`: Secret text (optional)
- `slack-webhook-url`: Secret text (optional)

#### Azure DevOps Variables
```yaml
TYPOSENTINEL_API_KEY: "your-api-key-here"
TEAMS_WEBHOOK_URL: "https://outlook.office.com/webhook/..."
```

### 3. Customize Configuration

Each template includes configurable parameters:

#### Scan Types
- `full`: Complete repository scan
- `incremental`: Scan only changed files
- `targeted`: Scan specific paths
- `auto`: Automatically determine based on trigger

#### Severity Thresholds
- `low`: Report all threats
- `medium`: Report medium and above
- `high`: Report high and critical only
- `critical`: Report only critical threats

#### Policy Enforcement
- `block_on_critical`: Fail pipeline on critical threats
- `require_approval`: Require manual approval for deployments
- `auto_quarantine`: Automatically quarantine vulnerable packages

## 📊 Scan Configuration

### Basic Configuration

Create a `.typosentinel.yml` file in your repository root:

```yaml
api:
  url: https://api.typosentinel.com
  timeout: 1800

scan:
  type: auto
  severity_threshold: medium
  include_dev_dependencies: true
  max_depth: 5
  parallel_scans: 4
  exclude_patterns:
    - "**/node_modules/**"
    - "**/vendor/**"
    - "**/.git/**"

reporting:
  formats:
    - json
    - html
    - sarif
  output_dir: ./scan-results
  upload_artifacts: true

policies:
  block_on_critical: true
  block_on_high: false
  require_approval_on_medium: true
  auto_quarantine: true
```

### Advanced Configuration

```yaml
api:
  url: https://api.typosentinel.com
  timeout: 3600
  retry_attempts: 3
  retry_delay: 30

scan:
  type: full
  severity_threshold: low
  include_dev_dependencies: true
  include_transitive: true
  max_depth: 10
  parallel_scans: 8
  custom_rules:
    - rule_id: "custom-001"
      enabled: true
    - rule_id: "custom-002"
      enabled: false
  exclude_patterns:
    - "**/test/**"
    - "**/tests/**"
    - "**/spec/**"
    - "**/node_modules/**"
    - "**/vendor/**"
    - "**/.git/**"
  include_patterns:
    - "**/package.json"
    - "**/requirements.txt"
    - "**/composer.json"
    - "**/Gemfile"
    - "**/go.mod"
    - "**/Cargo.toml"

reporting:
  formats:
    - json
    - html
    - sarif
    - junit
    - csv
  output_dir: ./typosentinel-results
  upload_artifacts: true
  generate_summary: true
  include_metadata: true

policies:
  block_on_critical: true
  block_on_high: true
  require_approval_on_medium: true
  auto_quarantine: true
  quarantine_duration: 7200  # 2 hours
  notification_channels:
    - slack
    - email
    - teams

integrations:
  slack:
    webhook_url: ${SLACK_WEBHOOK_URL}
    channel: "#security"
    notify_on_threats: true
    notify_on_success: false
  
  email:
    smtp_server: "smtp.company.com"
    smtp_port: 587
    from_address: "security@company.com"
    to_addresses:
      - "security-team@company.com"
      - "devops@company.com"
  
  jira:
    server_url: "https://company.atlassian.net"
    project_key: "SEC"
    issue_type: "Bug"
    priority: "Critical"
    create_issues: true
  
  github:
    create_issues: true
    assign_to_author: true
    labels:
      - "security"
      - "typosentinel"
  
  gitlab:
    create_issues: true
    assign_to_author: true
    labels:
      - "security"
      - "vulnerability"
  
  azure_devops:
    create_work_items: true
    area_path: "Security"
    iteration_path: "Security\\Current"
  
  teams:
    webhook_url: ${TEAMS_WEBHOOK_URL}
    notify_on_threats: true
    notify_on_success: false
```

## 🔄 Workflow Triggers

### GitHub Actions
```yaml
on:
  push:
    branches: [main, develop]
    paths: ['package*.json', 'requirements.txt']
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM
  workflow_dispatch:
    inputs:
      scan_type:
        description: 'Scan type'
        required: true
        default: 'full'
        type: choice
        options: ['full', 'incremental', 'targeted']
```

### GitLab CI/CD
```yaml
rules:
  - if: $CI_COMMIT_BRANCH == "main"
  - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  - if: $CI_PIPELINE_SOURCE == "schedule"
  - if: $CI_PIPELINE_SOURCE == "web"
  - changes:
      - package.json
      - package-lock.json
      - requirements.txt
```

### Jenkins
```groovy
triggers {
    cron('H 2 * * *')  // Daily
    pollSCM('H/15 * * * *')  // Poll every 15 minutes
}
```

### Azure DevOps
```yaml
trigger:
  branches:
    include: [main, develop]
  paths:
    include: ['package*.json', 'requirements.txt']

schedules:
  - cron: "0 2 * * *"
    displayName: Daily security scan
    branches:
      include: [main]
```

## 📈 Monitoring and Reporting

### Scan Results

Each pipeline generates comprehensive reports:

1. **JSON Report**: Machine-readable results for automation
2. **HTML Report**: Human-readable dashboard with visualizations
3. **SARIF Report**: Security Analysis Results Interchange Format
4. **JUnit Report**: Test results format for CI/CD integration

### Metrics and KPIs

Track security metrics across your organization:

- **Threat Detection Rate**: Number of threats found per scan
- **Resolution Time**: Time to fix critical vulnerabilities
- **Coverage**: Percentage of repositories with security scanning
- **Compliance**: Adherence to security policies

### Dashboards

Integrate with monitoring tools:

- **Grafana**: Create custom dashboards for security metrics
- **Datadog**: Monitor scan performance and threat trends
- **Splunk**: Analyze security logs and events
- **Azure Monitor**: Track pipeline performance and results

## 🔒 Security Best Practices

### API Key Management

1. **Use Secrets Management**: Store API keys in platform-specific secret stores
2. **Rotate Regularly**: Update API keys every 90 days
3. **Limit Scope**: Use API keys with minimal required permissions
4. **Monitor Usage**: Track API key usage and detect anomalies

### Pipeline Security

1. **Least Privilege**: Grant minimal permissions to pipeline jobs
2. **Secure Artifacts**: Encrypt sensitive scan results
3. **Audit Logs**: Enable logging for all security-related activities
4. **Network Security**: Use secure connections for all API calls

### Data Protection

1. **Encryption**: Encrypt scan results in transit and at rest
2. **Retention**: Define data retention policies for scan results
3. **Access Control**: Limit access to security reports
4. **Compliance**: Ensure compliance with data protection regulations

## 🛠️ Troubleshooting

### Common Issues

#### API Authentication Errors
```bash
Error: Invalid API key
Solution: Verify API key is correctly configured in secrets/variables
```

#### Scan Timeouts
```bash
Error: Scan timeout after 1800 seconds
Solution: Increase timeout value or optimize scan scope
```

#### Missing Dependencies
```bash
Error: Package file not found
Solution: Ensure package files exist and are committed to repository
```

#### Network Connectivity
```bash
Error: Unable to connect to Typosentinel API
Solution: Check network connectivity and firewall rules
```

### Debug Mode

Enable verbose logging for troubleshooting:

```bash
typosentinel scan --verbose --debug
```

### Support Channels

- **Documentation**: [docs.typosentinel.com](https://docs.typosentinel.com)
- **Support Email**: support@typosentinel.com
- **Community Forum**: [community.typosentinel.com](https://community.typosentinel.com)
- **GitHub Issues**: [github.com/typosentinel/cli/issues](https://github.com/typosentinel/cli/issues)

## 📚 Additional Resources

### Documentation
- [Typosentinel CLI Documentation](https://docs.typosentinel.com/cli)
- [API Reference](https://docs.typosentinel.com/api)
- [Security Best Practices](https://docs.typosentinel.com/security)
- [Integration Guides](https://docs.typosentinel.com/integrations)

### Examples
- [Sample Configurations](https://github.com/typosentinel/examples)
- [Custom Rules](https://docs.typosentinel.com/custom-rules)
- [Webhook Integrations](https://docs.typosentinel.com/webhooks)

### Community
- [Discord Server](https://discord.gg/typosentinel)
- [Twitter](https://twitter.com/typosentinel)
- [LinkedIn](https://linkedin.com/company/typosentinel)

## 🤝 Contributing

We welcome contributions to improve these CI/CD templates:

1. **Fork the Repository**: Create your own fork
2. **Create a Branch**: `git checkout -b feature/improvement`
3. **Make Changes**: Implement your improvements
4. **Test Thoroughly**: Ensure templates work correctly
5. **Submit PR**: Create a pull request with detailed description

### Template Guidelines

- **Consistency**: Follow existing patterns and naming conventions
- **Documentation**: Include clear comments and documentation
- **Flexibility**: Support multiple configuration options
- **Security**: Follow security best practices
- **Testing**: Include test scenarios and validation

## 📄 License

These templates are provided under the MIT License. See LICENSE file for details.

---

**Need Help?** Contact our support team at support@typosentinel.com or visit our [documentation](https://docs.typosentinel.com) for more information.