# Enhanced SIEM Integration Guide

This guide covers the enhanced SIEM integration features in Typosentinel, including real-time streaming, custom formatting, advanced retry logic, and performance optimizations.

## Table of Contents

- [Overview](#overview)
- [New Features](#new-features)
- [Configuration](#configuration)
- [SIEM-Specific Setup](#siem-specific-setup)
- [Performance Tuning](#performance-tuning)
- [Monitoring and Metrics](#monitoring-and-metrics)
- [Troubleshooting](#troubleshooting)
- [Best Practices](#best-practices)

## Overview

The enhanced SIEM integration provides robust, scalable, and customizable event forwarding to Security Information and Event Management (SIEM) systems. It supports multiple SIEM platforms with optimized formatting and delivery mechanisms.

### Supported SIEM Platforms

- **Splunk** - HTTP Event Collector (HEC) with batch support
- **Elasticsearch** - Direct indexing with bulk API support
- **IBM QRadar** - REST API integration
- **Generic SIEM** - Configurable HTTP endpoint

## New Features

### 1. Real-Time Streaming Mode

- **Asynchronous Processing**: Events are queued and processed in the background
- **Batch Optimization**: Multiple events are sent together for better performance
- **Non-Blocking**: Application performance is not affected by SIEM latency

### 2. Advanced Retry Logic

- **Exponential Backoff**: Intelligent retry delays that increase over time
- **Configurable Retry Conditions**: Specify which HTTP status codes trigger retries
- **Circuit Breaker Pattern**: Prevents overwhelming failed SIEM endpoints

### 3. Custom Event Formatting

- **SIEM-Specific Formats**: Optimized formats for each supported SIEM
- **Custom Field Mapping**: Map Typosentinel fields to your SIEM schema
- **Static Field Injection**: Add constant values for categorization

### 4. Performance Monitoring

- **Real-Time Metrics**: Track events sent, dropped, and retry attempts
- **Health Monitoring**: Monitor SIEM endpoint availability
- **Performance Analytics**: Analyze throughput and error rates

### 5. Enhanced Error Handling

- **Detailed Error Reporting**: Comprehensive error messages with context
- **Graceful Degradation**: Continue operation even when SIEM is unavailable
- **Event Preservation**: Prevent data loss during temporary outages

## Configuration

### Basic Configuration

```yaml
siem:
  enabled: true
  type: "splunk"  # splunk, elastic, elasticsearch, qradar
  endpoint: "https://your-siem.com:8088/services/collector"
  api_key: "your-api-key"
  index: "typosentinel"
```

### Advanced Configuration

```yaml
siem:
  enabled: true
  type: "splunk"
  endpoint: "https://splunk.company.com:8088/services/collector"
  api_key: "your-hec-token"
  index: "security_events"
  
  # Performance Settings
  batch_size: 100
  streaming_mode: true
  timeout: "30s"
  compression_type: "gzip"
  
  # Retry Configuration
  retry_config:
    max_retries: 3
    initial_delay: "1s"
    max_delay: "30s"
    backoff_factor: 2.0
    retry_on_status: [429, 500, 502, 503, 504]
  
  # Custom Field Mapping
  custom_format:
    "event_type": "type"
    "timestamp": "timestamp"
    "alert_level": "severity"
    "source_system": "source"
    "repository": "repository"
    "scan_id": "scan_id"
    "description": "message"
    "threat_count": "threat_count"
    "risk_score": "risk_score"
    # Static fields
    "product": "Typosentinel"
    "vendor": "Security Team"
    "environment": "production"
```

### Configuration Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `enabled` | boolean | false | Enable/disable SIEM integration |
| `type` | string | - | SIEM platform type |
| `endpoint` | string | - | SIEM API endpoint URL |
| `api_key` | string | - | Authentication API key |
| `index` | string | - | Target index/sourcetype |
| `batch_size` | integer | 100 | Events per batch |
| `streaming_mode` | boolean | false | Enable asynchronous processing |
| `timeout` | duration | 30s | HTTP request timeout |
| `verify_ssl` | boolean | true | Verify SSL certificates |
| `compression_type` | string | none | Compression for payloads (gzip, none) |
| `custom_format` | object | - | Custom field mappings |
| `retry_config` | object | - | Retry behavior configuration |

## SIEM-Specific Setup

### Splunk Configuration

1. **Enable HTTP Event Collector (HEC)**:
   ```bash
   # In Splunk Web: Settings > Data Inputs > HTTP Event Collector
   # Create new token with appropriate index permissions
   ```

2. **Typosentinel Configuration**:
   ```yaml
   siem:
     type: "splunk"
     endpoint: "https://splunk.company.com:8088/services/collector"
     api_key: "your-hec-token"
     index: "typosentinel"
     custom_format:
       "sourcetype": "typosentinel:security"
       "host": "typosentinel-scanner"
   ```

3. **Splunk Search Examples**:
   ```spl
   # Search for high-severity events
   index=typosentinel severity=high
   
   # Threat count analysis
   index=typosentinel | stats sum(threat_count) by repository
   
   # Risk score trending
   index=typosentinel | timechart avg(risk_score) by severity
   ```

### Elasticsearch Configuration

1. **Create Index Template**:
   ```json
   {
     "index_patterns": ["typosentinel-*"],
     "mappings": {
       "properties": {
         "@timestamp": {"type": "date"},
         "event_type": {"type": "keyword"},
         "severity": {"type": "keyword"},
         "repository": {"type": "keyword"},
         "threat_count": {"type": "integer"},
         "risk_score": {"type": "float"}
       }
     }
   }
   ```

2. **Typosentinel Configuration**:
   ```yaml
   siem:
     type: "elasticsearch"
     endpoint: "https://elastic.company.com:9200"
     api_key: "your-api-key"
     index: "typosentinel-events"
     batch_size: 50
     streaming_mode: true
   ```

3. **Kibana Visualizations**:
   - Create dashboards for threat trends
   - Set up alerts for high-risk repositories
   - Monitor scan frequency and coverage

### IBM QRadar Configuration

1. **Create Custom Event Property**:
   ```bash
   # In QRadar Console: Admin > Data Sources > Event Properties
   # Add custom properties for Typosentinel fields
   ```

2. **Typosentinel Configuration**:
   ```yaml
   siem:
     type: "qradar"
     endpoint: "https://qradar.company.com/api/ariel/events"
     api_key: "your-qradar-token"
     streaming_mode: false  # QRadar works better with sync
     custom_format:
       "EventName": "type"
       "Custom_Repository": "repository"
       "Custom_ThreatCount": "threat_count"
   ```

## Performance Tuning

### High-Volume Environments

```yaml
siem:
  # Optimize for high throughput
  batch_size: 500
  streaming_mode: true
  timeout: "120s"
  compression_type: "gzip"
  
  retry_config:
    max_retries: 5
    initial_delay: "500ms"
    max_delay: "10s"
    backoff_factor: 1.8
```

### Low-Latency Requirements

```yaml
siem:
  # Optimize for low latency
  batch_size: 10
  streaming_mode: true
  timeout: "5s"
  
  retry_config:
    max_retries: 2
    initial_delay: "100ms"
    max_delay: "2s"
    backoff_factor: 2.0
```

### Resource-Constrained Environments

```yaml
siem:
  # Optimize for low resource usage
  batch_size: 25
  streaming_mode: false  # Synchronous to reduce memory
  timeout: "30s"
  
  retry_config:
    max_retries: 1
    initial_delay: "2s"
    max_delay: "10s"
```

## Monitoring and Metrics

### Available Metrics

- **Events Sent**: Total number of successfully sent events
- **Events Dropped**: Events lost due to queue overflow
- **Retry Attempts**: Number of retry operations performed
- **Last Event Time**: Timestamp of the most recent event
- **Last Error**: Most recent error message

### Accessing Metrics

```bash
# Via CLI (if implemented)
typosentinel siem metrics

# Via API (if implemented)
curl -X GET http://localhost:8080/api/v1/siem/metrics
```

### Health Checks

```bash
# Test SIEM connectivity
typosentinel siem health-check

# Validate configuration
typosentinel siem validate-config
```

## Troubleshooting

### Common Issues

#### 1. Events Not Appearing in SIEM

**Symptoms**: Events are sent but don't appear in SIEM

**Solutions**:
- Verify API key permissions
- Check index/sourcetype configuration
- Validate endpoint URL
- Review SIEM-side ingestion logs

```bash
# Test connectivity
curl -X POST "$SIEM_ENDPOINT" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"test": "event"}'
```

#### 2. High Event Drop Rate

**Symptoms**: `events_dropped` metric increasing

**Solutions**:
- Increase `batch_size`
- Enable `compression_type: "gzip"`
- Optimize SIEM endpoint performance
- Consider multiple SIEM endpoints

#### 3. Frequent Retry Attempts

**Symptoms**: `retry_attempts` metric high

**Solutions**:
- Check SIEM endpoint health
- Adjust retry configuration
- Implement rate limiting
- Review network connectivity

#### 4. Memory Usage Issues

**Symptoms**: High memory consumption

**Solutions**:
- Reduce `batch_size`
- Disable `streaming_mode`
- Implement event filtering
- Optimize custom formatting

### Debug Configuration

```yaml
siem:
  enabled: true
  type: "splunk"
  endpoint: "http://localhost:8088/services/collector"
  api_key: "debug-token"
  batch_size: 1  # Send events immediately
  streaming_mode: false  # Synchronous for easier debugging
  timeout: "10s"
  verify_ssl: false  # For local testing
  
  retry_config:
    max_retries: 0  # Disable retries for debugging
  
  custom_format:
    "debug_mode": true
    "debug_timestamp": "timestamp"
    "debug_type": "type"
    "debug_message": "message"
```

## Best Practices

### Security

1. **API Key Management**:
   - Use environment variables for API keys
   - Rotate keys regularly
   - Implement least-privilege access

2. **Network Security**:
   - Use HTTPS endpoints
   - Implement certificate pinning
   - Consider VPN or private networks

3. **Data Privacy**:
   - Review event content for sensitive data
   - Implement field filtering if needed
   - Consider data retention policies

### Performance

1. **Batch Sizing**:
   - Start with default (100) and adjust based on performance
   - Larger batches = better throughput, higher latency
   - Smaller batches = lower latency, more overhead

2. **Streaming Mode**:
   - Enable for high-volume environments
   - Disable for debugging or low-volume scenarios
   - Monitor queue depth and drop rates

3. **Retry Strategy**:
   - Configure based on SIEM reliability
   - Avoid aggressive retries that could overwhelm SIEM
   - Implement exponential backoff

### Monitoring

1. **Set Up Alerts**:
   - High drop rates
   - Frequent retry attempts
   - SIEM connectivity failures

2. **Regular Health Checks**:
   - Automated connectivity tests
   - Performance baseline monitoring
   - Capacity planning

3. **Log Analysis**:
   - Review Typosentinel logs for SIEM errors
   - Monitor SIEM ingestion logs
   - Track event processing latency

### Configuration Management

1. **Environment-Specific Configs**:
   ```yaml
   # production.yaml
   siem:
     batch_size: 500
     streaming_mode: true
     verify_ssl: true
   
   # development.yaml
   siem:
     batch_size: 10
     streaming_mode: false
     verify_ssl: false
   ```

2. **Configuration Validation**:
   - Test configurations in staging
   - Validate API connectivity before deployment
   - Use configuration management tools

3. **Documentation**:
   - Document custom field mappings
   - Maintain SIEM schema documentation
   - Keep troubleshooting runbooks updated

## Migration from Legacy Integration

If upgrading from a previous SIEM integration:

1. **Backup Current Configuration**:
   ```bash
   cp config/integrations.yaml config/integrations.yaml.backup
   ```

2. **Update Configuration Format**:
   ```yaml
   # Old format
   siem:
     enabled: true
     endpoint: "https://splunk.com:8088"
     token: "abc123"
   
   # New format
   siem:
     enabled: true
     type: "splunk"
     endpoint: "https://splunk.com:8088/services/collector"
     api_key: "abc123"
     streaming_mode: true
     batch_size: 100
   ```

3. **Test Migration**:
   - Start with `streaming_mode: false`
   - Verify events appear correctly
   - Gradually enable new features

4. **Monitor Performance**:
   - Compare throughput before/after
   - Check for any data loss
   - Validate event formatting

For additional support, consult the main [INTEGRATIONS.md](INTEGRATIONS.md) documentation or contact the development team.