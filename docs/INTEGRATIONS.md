# TypoSentinel Integrations

TypoSentinel supports integration with various security tools and platforms to automatically forward security events and alerts. This document explains how to configure and use these integrations.

## Table of Contents

- [Overview](#overview)
- [Configuration](#configuration)
- [Supported Integrations](#supported-integrations)
  - [Splunk](#splunk)
  - [Slack](#slack)
  - [Webhook](#webhook)
  - [Email](#email)
- [Event Filtering](#event-filtering)
- [CLI Management](#cli-management)
- [Troubleshooting](#troubleshooting)
- [Best Practices](#best-practices)

## Overview

The TypoSentinel integration system allows you to:

- **Forward security events** to SIEM platforms like Splunk
- **Send real-time alerts** to communication platforms like Slack
- **Integrate with custom systems** via webhooks
- **Email notifications** for critical threats
- **Filter events** based on severity, package names, or threat types
- **Configure retry policies** for reliable delivery
- **Monitor integration health** and performance

## Configuration

Integrations are configured in the main TypoSentinel configuration file or a separate `integrations.yaml` file.

### Basic Configuration Structure

```yaml
integrations:
  enabled: true
  
  # Global filters (optional)
  filters:
    - name: "high_severity_only"
      type: "severity"
      condition: "equals"
      value: "high"
  
  # Connector configurations
  connectors:
    my_splunk:
      type: "splunk"
      enabled: true
      settings:
        # Connector-specific settings
      retry:
        # Retry configuration
      filters:
        # Connector-specific filters
```

### Configuration File Locations

1. **Main config file**: Add `integrations` section to your main configuration
2. **Separate file**: Create `config/integrations.yaml`
3. **Environment-specific**: Use `config/integrations.{env}.yaml`

## Supported Integrations

### Splunk

Integrate with Splunk SIEM using HTTP Event Collector (HEC).

#### Configuration

```yaml
connectors:
  splunk_siem:
    type: "splunk"
    enabled: true
    settings:
      hec_url: "https://splunk.company.com:8088/services/collector/event"
      hec_token: "your-hec-token-here"
      index: "typosentinel"           # Target index
      source: "typosentinel_scanner"  # Event source
      sourcetype: "security_event"    # Event sourcetype
      verify_ssl: true                # SSL verification
      timeout: 30                     # Request timeout (seconds)
    retry:
      enabled: true
      max_attempts: 3
      initial_delay: "1s"
      max_delay: "30s"
      backoff_factor: 2.0
```

#### Setup Steps

1. **Enable HEC in Splunk**:
   - Go to Settings > Data Inputs > HTTP Event Collector
   - Create a new token with appropriate permissions
   - Note the token and HEC URL

2. **Configure Index**:
   - Ensure the target index exists
   - Set appropriate retention policies

3. **Test Connection**:
   ```bash
   typosentinel integrations test splunk_siem
   ```

#### Event Format

Events are sent in Splunk's JSON format:

```json
{
  "time": 1640995200,
  "index": "typosentinel",
  "source": "typosentinel_scanner",
  "sourcetype": "security_event",
  "event": {
    "id": "event-123",
    "type": "threat_detected",
    "severity": "high",
    "package": {
      "name": "malicious-package",
      "version": "1.0.0",
      "registry": "npm"
    },
    "threat": {
      "type": "malicious",
      "description": "Package contains malicious code",
      "risk_score": 0.95
    }
  }
}
```

### Slack

Send real-time security alerts to Slack channels.

#### Configuration

```yaml
connectors:
  security_alerts:
    type: "slack"
    enabled: true
    settings:
      webhook_url: "https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"
      channel: "#security-alerts"     # Target channel
      username: "TypoSentinel"        # Bot username
      icon_emoji: ":shield:"          # Bot icon
      mention_users: ["@security-team"] # Users to mention
      mention_channels: ["@here"]     # Channel mentions
      color_mapping:                  # Severity color mapping
        critical: "danger"
        high: "warning"
        medium: "good"
        low: "#439FE0"
    retry:
      enabled: true
      max_attempts: 2
      initial_delay: "2s"
      max_delay: "10s"
      backoff_factor: 2.0
```

#### Setup Steps

1. **Create Slack App**:
   - Go to https://api.slack.com/apps
   - Create a new app for your workspace
   - Enable Incoming Webhooks
   - Create a webhook for your target channel

2. **Configure Permissions**:
   - Add `chat:write` scope
   - Install app to workspace

3. **Test Integration**:
   ```bash
   typosentinel integrations test security_alerts
   ```

#### Message Format

Slack messages include:
- **Rich formatting** with colors based on severity
- **Structured fields** for package and threat information
- **Action buttons** (if configured)
- **User/channel mentions** for critical alerts

### Webhook

Integrate with any HTTP endpoint for custom processing.

#### Configuration

```yaml
connectors:
  custom_webhook:
    type: "webhook"
    enabled: true
    settings:
      url: "https://api.company.com/security/webhooks/typosentinel"
      method: "POST"                 # HTTP method
      headers:                       # Custom headers
        Authorization: "Bearer your-api-token"
        Content-Type: "application/json"
        X-Source: "TypoSentinel"
      timeout: 15                    # Request timeout
      verify_ssl: true               # SSL verification
      custom_payload:                # Custom payload template
        enabled: true
        template: |
          {
            "event_type": "{{.Type}}",
            "severity": "{{.Severity}}",
            "package": {
              "name": "{{.Package.Name}}",
              "version": "{{.Package.Version}}"
            },
            "threat": {
              "type": "{{.Threat.Type}}",
              "description": "{{.Threat.Description}}",
              "risk_score": {{.Threat.RiskScore}}
            },
            "timestamp": "{{.Timestamp}}"
          }
    retry:
      enabled: true
      max_attempts: 3
      initial_delay: "1s"
      max_delay: "60s"
      backoff_factor: 2.0
```

#### Template Variables

Available template variables for custom payloads:

- `{{.ID}}` - Event ID
- `{{.Type}}` - Event type
- `{{.Severity}}` - Event severity
- `{{.Timestamp}}` - Event timestamp
- `{{.Package.Name}}` - Package name
- `{{.Package.Version}}` - Package version
- `{{.Package.Registry}}` - Package registry
- `{{.Threat.Type}}` - Threat type
- `{{.Threat.Description}}` - Threat description
- `{{.Threat.RiskScore}}` - Risk score (0.0-1.0)
- `{{.Threat.Confidence}}` - Confidence score (0.0-1.0)
- `{{.Metadata.DetectionMethod}}` - Detection method
- `{{.Metadata.ProjectPath}}` - Project path
- `{{.Metadata.ScanID}}` - Scan ID

### Email

Send email notifications for security events.

#### Configuration

```yaml
connectors:
  email_alerts:
    type: "email"
    enabled: true
    settings:
      smtp_host: "smtp.company.com"   # SMTP server
      smtp_port: 587                  # SMTP port
      username: "typosentinel@company.com"
      password: "your-email-password"
      from_email: "typosentinel@company.com"
      from_name: "TypoSentinel Security Scanner"
      to_emails:                      # Recipients
        - "security-team@company.com"
        - "devops@company.com"
      cc_emails:                      # CC recipients
        - "ciso@company.com"
      subject_prefix: "[SECURITY ALERT]"
      use_tls: true                   # Use TLS encryption
      timeout: 30                     # Connection timeout
    retry:
      enabled: true
      max_attempts: 2
      initial_delay: "5s"
      max_delay: "30s"
      backoff_factor: 2.0
```

#### Email Format

Emails include:
- **HTML formatting** with severity-based styling
- **Structured information** about the threat
- **Package details** and evidence
- **Action recommendations**

## Event Filtering

Filters allow you to control which events are sent to specific integrations.

### Filter Types

#### Severity Filter

```yaml
filters:
  - name: "high_severity_only"
    type: "severity"
    condition: "equals"
    value: "high"
```

Supported severities: `critical`, `high`, `medium`, `low`

#### Package Name Filter

```yaml
filters:
  - name: "exclude_test_packages"
    type: "package_name"
    condition: "contains"
    value: "test"
    metadata:
      exclude: true  # Exclude matching packages
```

#### Threat Type Filter

```yaml
filters:
  - name: "malware_only"
    type: "threat_type"
    condition: "equals"
    value: "malicious"
```

Supported threat types: `malicious`, `typosquatting`, `suspicious`, `outdated`

### Filter Conditions

- `equals` - Exact match
- `contains` - Substring match
- `regex` - Regular expression match

### Filter Application

1. **Global filters** - Applied to all connectors
2. **Connector filters** - Applied to specific connectors
3. **Exclusion filters** - Use `metadata.exclude: true`

## CLI Management

Manage integrations using the TypoSentinel CLI.

### List Integrations

```bash
# List all configured integrations
typosentinel integrations list

# Show detailed configuration
typosentinel integrations list --verbose

# Output as JSON
typosentinel integrations list --output json
```

### Test Integration

```bash
# Test a specific integration
typosentinel integrations test splunk_siem

# Test with verbose output
typosentinel integrations test slack_alerts --verbose
```

### Check Status

```bash
# Show integration status
typosentinel integrations status

# Include detailed metrics
typosentinel integrations status --metrics

# Output as JSON
typosentinel integrations status --output json
```

## Troubleshooting

### Common Issues

#### Connection Failures

**Symptoms**: Integration tests fail with connection errors

**Solutions**:
1. Verify network connectivity to target system
2. Check firewall rules and proxy settings
3. Validate SSL certificates if using HTTPS
4. Ensure correct URLs and ports

```bash
# Test network connectivity
curl -v https://your-endpoint.com

# Check SSL certificate
openssl s_client -connect your-endpoint.com:443
```

#### Authentication Errors

**Symptoms**: 401/403 errors, authentication failures

**Solutions**:
1. Verify API tokens and credentials
2. Check token permissions and scopes
3. Ensure tokens haven't expired
4. Validate authentication headers

#### Event Delivery Failures

**Symptoms**: Events not appearing in target system

**Solutions**:
1. Check integration logs for errors
2. Verify event filtering configuration
3. Test with simplified payload
4. Monitor retry attempts and backoff

```bash
# Check integration status
typosentinel integrations status --metrics

# View detailed logs
typosentinel logs --component integrations --level debug
```

#### Performance Issues

**Symptoms**: Slow event delivery, timeouts

**Solutions**:
1. Increase timeout values
2. Adjust retry configuration
3. Implement event batching (if supported)
4. Monitor system resources

### Debug Mode

Enable debug logging for detailed troubleshooting:

```yaml
logging:
  level: debug
  components:
    integrations: debug
    events: debug
```

### Health Monitoring

Monitor integration health:

```bash
# Continuous status monitoring
watch -n 30 'typosentinel integrations status'

# Export metrics for monitoring systems
typosentinel integrations status --output json | jq '.metrics'
```

## Best Practices

### Security

1. **Secure Credentials**:
   - Use environment variables for sensitive data
   - Rotate API tokens regularly
   - Implement least-privilege access

2. **Network Security**:
   - Use HTTPS/TLS for all connections
   - Validate SSL certificates
   - Implement IP whitelisting where possible

3. **Data Protection**:
   - Avoid logging sensitive information
   - Implement data retention policies
   - Consider data encryption at rest

### Performance

1. **Retry Configuration**:
   - Use exponential backoff
   - Set reasonable maximum attempts
   - Implement circuit breakers for failing endpoints

2. **Filtering**:
   - Filter events at source to reduce load
   - Use specific filters to avoid unnecessary processing
   - Monitor filter effectiveness

3. **Monitoring**:
   - Set up health checks
   - Monitor delivery metrics
   - Alert on integration failures

### Reliability

1. **Redundancy**:
   - Configure multiple connectors for critical alerts
   - Use different communication channels
   - Implement fallback mechanisms

2. **Testing**:
   - Regularly test integrations
   - Validate configuration changes
   - Monitor for breaking changes in target APIs

3. **Documentation**:
   - Document integration configurations
   - Maintain runbooks for troubleshooting
   - Keep contact information updated

### Example Production Configuration

```yaml
integrations:
  enabled: true
  
  filters:
    - name: "production_threats"
      type: "severity"
      condition: "equals"
      value: "high"
  
  connectors:
    # Primary SIEM
    splunk_production:
      type: "splunk"
      enabled: true
      settings:
        hec_url: "${SPLUNK_HEC_URL}"
        hec_token: "${SPLUNK_HEC_TOKEN}"
        index: "security"
        verify_ssl: true
      retry:
        enabled: true
        max_attempts: 5
        initial_delay: "2s"
        max_delay: "300s"
        backoff_factor: 2.0
    
    # Critical alerts
    slack_critical:
      type: "slack"
      enabled: true
      settings:
        webhook_url: "${SLACK_WEBHOOK_URL}"
        channel: "#security-critical"
        mention_channels: ["@channel"]
      filters:
        - "critical_only"
    
    # Email backup
    email_backup:
      type: "email"
      enabled: true
      settings:
        smtp_host: "${SMTP_HOST}"
        username: "${SMTP_USERNAME}"
        password: "${SMTP_PASSWORD}"
        to_emails: ["${SECURITY_EMAIL}"]
      filters:
        - "production_threats"
```

This configuration provides:
- **Primary logging** to Splunk SIEM
- **Critical alerts** to dedicated Slack channel
- **Email backup** for high-severity threats
- **Environment-based** credential management
- **Robust retry** policies for reliability