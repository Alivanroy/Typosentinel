# TypoSentinel Platform Configuration Examples

This directory contains comprehensive configuration examples for integrating TypoSentinel with various source code management platforms and CI/CD systems.

## Available Configurations

### Platform-Specific Configurations

- **[github-config.yaml](./github-config.yaml)** - Complete GitHub integration configuration
- **[gitlab-config.yaml](./gitlab-config.yaml)** - Complete GitLab integration configuration
- **[bitbucket-config.yaml](./bitbucket-config.yaml)** - Complete Bitbucket integration configuration
- **[azuredevops-config.yaml](./azuredevops-config.yaml)** - Complete Azure DevOps integration configuration

### Multi-Platform Configuration

- **[multi-platform-config.yaml](./multi-platform-config.yaml)** - Comprehensive configuration for all platforms simultaneously

## Quick Start

### 1. Choose Your Platform

Select the appropriate configuration file based on your source code management platform:

```bash
# For GitHub
cp examples/configs/github-config.yaml config.yaml

# For GitLab
cp examples/configs/gitlab-config.yaml config.yaml

# For Bitbucket
cp examples/configs/bitbucket-config.yaml config.yaml

# For Azure DevOps
cp examples/configs/azuredevops-config.yaml config.yaml

# For multiple platforms
cp examples/configs/multi-platform-config.yaml config.yaml
```

### 2. Set Environment Variables

Each configuration requires specific environment variables for authentication:

#### GitHub
```bash
export GITHUB_TOKEN="your_github_personal_access_token"
export GITHUB_WEBHOOK_SECRET="your_webhook_secret"
```

#### GitLab
```bash
export GITLAB_TOKEN="your_gitlab_personal_access_token"
export GITLAB_WEBHOOK_SECRET="your_webhook_secret"
```

#### Bitbucket
```bash
export BITBUCKET_USERNAME="your_bitbucket_username"
export BITBUCKET_APP_PASSWORD="your_app_password"
export BITBUCKET_WEBHOOK_SECRET="your_webhook_secret"
```

#### Azure DevOps
```bash
export AZURE_DEVOPS_TOKEN="your_azure_devops_pat"
export AZURE_DEVOPS_WEBHOOK_SECRET="your_webhook_secret"
```

### 3. Configure Your Targets

Edit the configuration file to specify your organizations, repositories, and scanning preferences:

```yaml
# Example: Configure GitHub organizations to scan
github:
  discovery:
    organizations:
      - name: "your-organization"
        filters:
          include_private: true
          languages: ["JavaScript", "Python", "Go"]
```

### 4. Run TypoSentinel

```bash
# Start the enterprise server
typosentinel-enterprise server --config config.yaml

# Or run a one-time scan
typosentinel-enterprise scan repository --org your-organization
```

## Configuration Sections

### Authentication

Each platform supports multiple authentication methods:

| Platform | Methods | Recommended |
|----------|---------|-------------|
| GitHub | Personal Token, GitHub App, OAuth | Personal Token for individuals, GitHub App for organizations |
| GitLab | Personal Token, OAuth2, Deploy Token | Personal Token |
| Bitbucket | App Password, OAuth2, Repository Token | App Password |
| Azure DevOps | Personal Token, Service Principal, Managed Identity | Personal Token |

### Discovery Configuration

Configure what repositories to discover and scan:

```yaml
discovery:
  organizations: ["org1", "org2"]
  users: ["user1"]
  repositories: ["org/repo"]
  search_queries:
    - "language:python stars:>10"
  schedule:
    interval: "1h"
    max_repos_per_run: 1000
```

### Scanning Configuration

Define what to scan and how:

```yaml
scanning:
  package_managers: ["npm", "pip", "go", "maven"]
  scan_types: ["dependency", "vulnerability", "license"]
  include_patterns: ["**/package.json", "**/requirements.txt"]
  exclude_patterns: ["**/node_modules/**", "**/test/**"]
  timeout: "30m"
  concurrency: 5
```

### Webhook Configuration

Set up real-time scanning triggers:

```yaml
webhooks:
  enabled: true
  endpoint: "https://your-domain.com/webhooks/platform"
  secret: "${WEBHOOK_SECRET}"
  events: ["push", "pull_request", "release"]
  security:
    validate_signature: true
    rate_limit: 100
```

## Platform-Specific Features

### GitHub
- GitHub Enterprise Server support
- GitHub Apps integration
- Advanced search queries
- Repository topics filtering

### GitLab
- GitLab CI/CD integration
- Container registry scanning
- Self-hosted GitLab support
- Group and project-level configuration

### Bitbucket
- Bitbucket Pipelines integration
- Pull request commenting
- Workspace and project filtering
- Bitbucket Server support

### Azure DevOps
- Azure Pipelines integration
- Azure Artifacts scanning
- Work items creation
- Service hooks configuration

## Security Best Practices

### 1. Token Management

- Use environment variables for sensitive data
- Rotate tokens regularly
- Use minimal required permissions
- Store tokens securely (e.g., Azure Key Vault, AWS Secrets Manager)

### 2. Network Security

- Use HTTPS for all communications
- Validate webhook signatures
- Restrict webhook source IPs
- Use VPN or private networks when possible

### 3. Access Control

- Follow principle of least privilege
- Use service accounts for automation
- Enable audit logging
- Regular access reviews

## Troubleshooting

### Common Issues

#### Authentication Errors
```bash
# Check token validity
curl -H "Authorization: token $GITHUB_TOKEN" https://api.github.com/user

# Verify token permissions
curl -H "Authorization: token $GITHUB_TOKEN" https://api.github.com/rate_limit
```

#### Rate Limiting
```yaml
# Adjust rate limits in configuration
rate_limit:
  requests_per_hour: 1000  # Reduce if hitting limits
  adaptive: true           # Enable adaptive limiting
  retry_delay: "10s"       # Increase retry delay
```

#### Discovery Issues
```yaml
# Enable debug logging
logging:
  level: "debug"
  log_requests: true

# Reduce discovery scope
discovery:
  max_repos_per_run: 100
  timeout: "5m"
```

### Debug Mode

Enable debug logging for troubleshooting:

```yaml
logging:
  level: "debug"
  log_requests: true
  log_webhooks: true
```

### Health Checks

Monitor platform connectivity:

```bash
# Check health endpoint
curl http://localhost:8080/health

# Check specific platform status
curl http://localhost:8080/api/v1/platforms/github/status
```

## Advanced Configuration

### Custom Filters

```yaml
filters:
  # Language-based filtering
  languages: ["JavaScript", "Python", "Go"]
  
  # Topic-based filtering
  topics: ["security", "api", "library"]
  
  # Pattern-based filtering
  exclude_patterns:
    - "test-*"
    - "demo-*"
    - "archived-*"
  
  # Size-based filtering
  max_size: 104857600  # 100MB
  min_stars: 5
```

### Caching Configuration

```yaml
cache:
  enabled: true
  backend: "redis"  # redis, memory, file
  ttl:
    repositories: "24h"
    organizations: "12h"
    users: "6h"
  redis:
    host: "localhost"
    port: 6379
    password: "${REDIS_PASSWORD}"
    database: 0
```

### Monitoring and Metrics

```yaml
monitoring:
  enabled: true
  metrics:
    - "api_requests_total"
    - "scan_duration"
    - "threats_detected"
  prometheus:
    enabled: true
    endpoint: "/metrics"
```

## Integration Examples

### CI/CD Integration

#### GitHub Actions
```yaml
# .github/workflows/security-scan.yml
name: Security Scan
on: [push, pull_request]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: TypoSentinel Scan
        run: |
          curl -X POST "$TYPOSENTINEL_ENDPOINT/api/v1/scan" \
            -H "Authorization: Bearer $TYPOSENTINEL_TOKEN" \
            -d '{"repository": "$GITHUB_REPOSITORY", "ref": "$GITHUB_SHA"}'
```

#### GitLab CI
```yaml
# .gitlab-ci.yml
security_scan:
  stage: security
  image: typosentinel/scanner:latest
  script:
    - typosentinel scan --format sarif --output security-report.sarif
  artifacts:
    reports:
      sast: security-report.sarif
```

#### Azure Pipelines
```yaml
# azure-pipelines.yml
steps:
- task: CmdLine@2
  displayName: 'TypoSentinel Security Scan'
  inputs:
    script: |
      typosentinel scan --format sarif --output $(Agent.TempDirectory)/security-report.sarif
```

### SIEM Integration

```yaml
output:
  destinations:
    - type: "webhook"
      url: "https://siem.company.com/api/events"
      format: "json"
      headers:
        Authorization: "Bearer ${SIEM_TOKEN}"
        Content-Type: "application/json"
```

## Support

For additional help:

1. Check the [main documentation](../../docs/)
2. Review [API documentation](../../docs/API_DOCUMENTATION.md)
3. See [integration examples](../../examples/)
4. Open an issue on GitHub

## Contributing

To contribute new configuration examples:

1. Fork the repository
2. Create a new configuration file
3. Add documentation
4. Test the configuration
5. Submit a pull request

## License

These configuration examples are provided under the same license as TypoSentinel.