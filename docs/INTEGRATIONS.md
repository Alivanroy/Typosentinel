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
- [Troubleshooting](#troubleshooting)

## Overview

The TypoSentinel integration system allows you to:

- **Forward security events** to SIEM platforms like Splunk
- **Send real-time alerts** to communication platforms like Slack
- **Integrate with custom systems** via webhooks
- **Email notifications** for critical threats

## Configuration

Integrations are configured in the main TypoSentinel configuration file (e.g., `config.yaml`).

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
      token: "your-hec-token-here"
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
    retry:
      enabled: true
      max_attempts: 2
      initial_delay: "2s"
      max_delay: "10s"
      backoff_factor: 2.0
```

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
    retry:
      enabled: true
      max_attempts: 3
      initial_delay: "1s"
      max_delay: "60s"
      backoff_factor: 2.0
```

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

## Troubleshooting

### Common Issues

#### Connection Failures

**Symptoms**: Integration tests fail with connection errors

**Solutions**:
1. Verify network connectivity to target system
2. Check firewall rules and proxy settings
3. Validate SSL certificates if using HTTPS
4. Ensure correct URLs and ports

#### Authentication Errors

**Symptoms**: 401/403 errors, authentication failures

**Solutions**:
1. Verify API tokens and credentials
2. Check token permissions and scopes
3. Ensure tokens haven't expired
4. Validate authentication headers
