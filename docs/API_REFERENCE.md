# 📚 TypoSentinel API Reference

Complete API reference for TypoSentinel's REST API, CLI commands, and programmatic interfaces.

## 📋 Table of Contents

1. [REST API](#rest-api)
2. [CLI Commands](#cli-commands)
3. [Configuration API](#configuration-api)
4. [Web Dashboard API](#web-dashboard-api)
5. [Webhook API](#webhook-api)
6. [SDK & Libraries](#sdk--libraries)
7. [Authentication](#authentication)
8. [Error Handling](#error-handling)

## 🌐 REST API

### Base URL
```
http://localhost:8080/api/v1
```

### Authentication
All API requests require authentication via API key or JWT token:
```bash
curl -H "Authorization: Bearer YOUR_API_KEY" \
     -H "Content-Type: application/json" \
     http://localhost:8080/api/v1/scans
```

### Core Endpoints

#### Scans

**POST /api/v1/scans**
Start a new security scan

```bash
curl -X POST http://localhost:8080/api/v1/scans \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -d '{
    "target": "/path/to/project",
    "preset": "balanced",
    "output_format": "json",
    "options": {
      "timeout": "60s",
      "concurrency": 4
    }
  }'
```

**Response:**
```json
{
  "scan_id": "scan_123456789",
  "status": "running",
  "created_at": "2025-01-15T10:30:00Z",
  "estimated_duration": "45s",
  "target": "/path/to/project",
  "preset": "balanced"
}
```

**GET /api/v1/scans/{scan_id}**
Get scan status and results

```bash
curl http://localhost:8080/api/v1/scans/scan_123456789 \
  -H "Authorization: Bearer YOUR_API_KEY"
```

**Response:**
```json
{
  "scan_id": "scan_123456789",
  "status": "completed",
  "created_at": "2025-01-15T10:30:00Z",
  "completed_at": "2025-01-15T10:30:45Z",
  "duration": "45s",
  "results": {
    "total_packages": 156,
    "threats_found": 3,
    "severity_breakdown": {
      "critical": 0,
      "high": 1,
      "medium": 2,
      "low": 0
    },
    "threats": [
      {
        "id": "threat_001",
        "package_name": "suspicious-package",
        "version": "1.0.0",
        "severity": "high",
        "confidence": 0.89,
        "description": "Package name closely resembles popular package 'popular-package'",
        "recommendation": "Verify package authenticity before use"
      }
    ]
  }
}
```

**GET /api/v1/scans**
List all scans with pagination

```bash
curl "http://localhost:8080/api/v1/scans?page=1&limit=20&status=completed" \
  -H "Authorization: Bearer YOUR_API_KEY"
```

**DELETE /api/v1/scans/{scan_id}**
Cancel a running scan

```bash
curl -X DELETE http://localhost:8080/api/v1/scans/scan_123456789 \
  -H "Authorization: Bearer YOUR_API_KEY"
```

#### Threats

**GET /api/v1/threats**
List detected threats with filtering

```bash
curl "http://localhost:8080/api/v1/threats?severity=high&status=active&limit=50" \
  -H "Authorization: Bearer YOUR_API_KEY"
```

**POST /api/v1/threats/{threat_id}/actions**
Take action on a threat (ignore, whitelist, etc.)

```bash
curl -X POST http://localhost:8080/api/v1/threats/threat_001/actions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -d '{
    "action": "whitelist",
    "reason": "Verified as safe after manual review",
    "expires_at": "2025-12-31T23:59:59Z"
  }'
```

#### Configuration

**GET /api/v1/config**
Get current configuration

```bash
curl http://localhost:8080/api/v1/config \
  -H "Authorization: Bearer YOUR_API_KEY"
```

**PUT /api/v1/config**
Update configuration

```bash
curl -X PUT http://localhost:8080/api/v1/config \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -d '{
    "scanner": {
      "timeout": "90s",
      "concurrency": 6
    },
    "detector": {
      "ml_threshold": 0.8
    }
  }'
```

**POST /api/v1/config/validate**
Validate configuration

```bash
curl -X POST http://localhost:8080/api/v1/config/validate \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -d '{
    "scanner": {
      "timeout": "invalid_timeout"
    }
  }'
```

#### System

**GET /api/v1/health**
System health check

```bash
curl http://localhost:8080/api/v1/health
```

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2025-01-15T10:30:00Z",
  "version": "2.1.0",
  "components": {
    "scanner": "healthy",
    "ml_pipeline": "healthy",
    "database": "healthy",
    "cache": "healthy"
  },
  "metrics": {
    "uptime": "72h30m",
    "memory_usage": "45%",
    "cpu_usage": "12%",
    "active_scans": 2
  }
}
```

**GET /api/v1/metrics**
System metrics (Prometheus format)

```bash
curl http://localhost:8080/api/v1/metrics \
  -H "Accept: application/openmetrics-text"
```

**GET /api/v1/version**
Version information

```bash
curl http://localhost:8080/api/v1/version
```

## 💻 CLI Commands

### Core Commands

#### scan
Perform security scanning

```bash
# Basic usage
typosentinel scan [path]

# With options
typosentinel scan --preset balanced --output json --timeout 60s

# Advanced options
typosentinel scan \
  --config custom-config.yaml \
  --output-file results.json \
  --format sarif \
  --exclude "node_modules/,*.test.js" \
  --concurrency 8 \
  --debug
```

**Options:**
- `--preset`: Security preset (quick, balanced, thorough, enterprise)
- `--config`: Configuration file path
- `--output`: Output format (json, yaml, sarif, table)
- `--output-file`: Output file path
- `--timeout`: Scan timeout duration
- `--concurrency`: Number of concurrent workers
- `--exclude`: Exclusion patterns
- `--include`: Inclusion patterns
- `--debug`: Enable debug mode
- `--verbose`: Verbose output
- `--dry-run`: Simulate scan without execution

#### config
Configuration management

```bash
# Initialize configuration
typosentinel config init --preset balanced --project-type go

# Validate configuration
typosentinel config validate [config-file]

# Show current configuration
typosentinel config show

# Edit configuration
typosentinel config edit

# Compare configurations
typosentinel config diff config1.yaml config2.yaml

# Merge configurations
typosentinel config merge base.yaml override.yaml

# Generate configuration from template
typosentinel config generate --template enterprise --output enterprise.yaml
```

#### server
Start web dashboard server

```bash
# Basic server
typosentinel server

# With options
typosentinel server \
  --port 3456 \
  --host 0.0.0.0 \
  --auth \
  --username admin \
  --password secure123 \
  --tls-cert cert.pem \
  --tls-key key.pem
```

**Options:**
- `--port`: Server port (default: 8080)
- `--host`: Server host (default: localhost)
- `--auth`: Enable authentication
- `--username`: Admin username
- `--password`: Admin password
- `--tls-cert`: TLS certificate file
- `--tls-key`: TLS private key file
- `--config`: Configuration file

#### ci
CI/CD integration helpers

```bash
# Setup CI/CD integration
typosentinel ci setup github --repo owner/repo

# Generate CI/CD configuration
typosentinel ci generate --platform github-actions --output .github/workflows/

# Validate CI/CD setup
typosentinel ci validate --platform gitlab-ci
```

#### cache
Cache management

```bash
# Clear cache
typosentinel cache clear

# Show cache status
typosentinel cache status

# Warm cache
typosentinel cache warm --registries npm,pypi
```

#### health
System health and diagnostics

```bash
# Basic health check
typosentinel health

# Detailed system status
typosentinel health --verbose

# Component-specific health
typosentinel health --component scanner

# Export health report
typosentinel health --export health-report.json
```

### Utility Commands

#### version
Version information

```bash
# Show version
typosentinel version

# Check for updates
typosentinel version --check-updates

# Show build information
typosentinel version --build-info
```

#### help
Contextual help system

```bash
# General help
typosentinel help

# Command-specific help
typosentinel help scan

# Interactive help
typosentinel help --interactive

# Smart suggestions
typosentinel help --suggest
```

## ⚙️ Configuration API

### Configuration Schema

```yaml
# Complete configuration schema
scanner:
  timeout: "60s"                    # Scan timeout
  concurrency: 4                    # Concurrent workers
  max_depth: 5                      # Maximum scan depth
  exclusions:                       # Exclusion patterns
    - "node_modules/"
    - "*.test.js"
  inclusions:                       # Inclusion patterns
    - "package.json"
    - "go.mod"

detector:
  ml_threshold: 0.7                 # ML confidence threshold
  similarity_threshold: 0.85        # String similarity threshold
  algorithms:                       # Detection algorithms
    - "levenshtein"
    - "jaro_winkler"
    - "ml_classifier"
  custom_rules:                     # Custom detection rules
    - pattern: ".*-test$"
      action: "ignore"

output:
  format: "json"                    # Output format
  file: "results.json"              # Output file
  include_metadata: true            # Include scan metadata
  pretty_print: true                # Pretty print JSON

registry:
  npm:
    url: "https://registry.npmjs.org"
    timeout: "30s"
  pypi:
    url: "https://pypi.org"
    timeout: "30s"
  go_proxy:
    url: "https://proxy.golang.org"
    timeout: "30s"

logging:
  level: "info"                     # Log level
  format: "json"                    # Log format
  file: "typosentinel.log"          # Log file

performance:
  cache_enabled: true               # Enable caching
  cache_ttl: "24h"                  # Cache TTL
  memory_limit: "1GB"               # Memory limit
  parallel_scans: 2                 # Parallel scans

security:
  encryption_enabled: true          # Enable encryption
  audit_logging: true               # Enable audit logs
  secure_headers: true              # Secure HTTP headers

monitoring:
  metrics_enabled: true             # Enable metrics
  health_checks: true               # Enable health checks
  prometheus_port: 9090             # Prometheus port
```

### Configuration Validation

**Validation Rules:**
- Timeout values must be valid durations (e.g., "30s", "5m")
- Concurrency must be between 1 and 32
- Thresholds must be between 0.0 and 1.0
- URLs must be valid HTTP/HTTPS URLs
- File paths must be accessible

**Validation API:**
```bash
# Validate configuration file
curl -X POST http://localhost:8080/api/v1/config/validate \
  -H "Content-Type: application/json" \
  -d @config.json
```

## 🌐 Web Dashboard API

### Dashboard Endpoints

**GET /api/v1/dashboard/metrics**
Get dashboard metrics

```bash
curl http://localhost:8080/api/v1/dashboard/metrics \
  -H "Authorization: Bearer YOUR_API_KEY"
```

**Response:**
```json
{
  "active_scans": 2,
  "completed_scans": 156,
  "total_threats": 23,
  "system_health": "healthy",
  "scan_history": [
    {
      "date": "2025-01-15",
      "scans": 12,
      "threats": 3
    }
  ],
  "threat_trends": [
    {
      "severity": "high",
      "count": 5,
      "trend": "decreasing"
    }
  ]
}
```

**GET /api/v1/dashboard/scans/recent**
Get recent scans

```bash
curl http://localhost:8080/api/v1/dashboard/scans/recent?limit=10 \
  -H "Authorization: Bearer YOUR_API_KEY"
```

**POST /api/v1/dashboard/preferences**
Update user preferences

```bash
curl -X POST http://localhost:8080/api/v1/dashboard/preferences \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -d '{
    "theme": "dark",
    "refresh_rate": 30,
    "notifications": {
      "email": true,
      "browser": false
    }
  }'
```

## 🔗 Webhook API

### Webhook Configuration

```yaml
webhooks:
  enabled: true
  endpoints:
    - url: "https://your-app.com/webhooks/typosentinel"
      events: ["scan.completed", "threat.detected"]
      secret: "your-webhook-secret"
      timeout: "30s"
      retry_attempts: 3
```

### Webhook Events

**scan.completed**
```json
{
  "event": "scan.completed",
  "timestamp": "2025-01-15T10:30:45Z",
  "scan_id": "scan_123456789",
  "data": {
    "status": "completed",
    "duration": "45s",
    "threats_found": 3,
    "severity_breakdown": {
      "critical": 0,
      "high": 1,
      "medium": 2,
      "low": 0
    }
  }
}
```

**threat.detected**
```json
{
  "event": "threat.detected",
  "timestamp": "2025-01-15T10:30:30Z",
  "scan_id": "scan_123456789",
  "data": {
    "threat_id": "threat_001",
    "package_name": "suspicious-package",
    "severity": "high",
    "confidence": 0.89,
    "description": "Package name closely resembles popular package"
  }
}
```

### Webhook Security

**Signature Verification:**
```python
import hmac
import hashlib

def verify_webhook(payload, signature, secret):
    expected = hmac.new(
        secret.encode('utf-8'),
        payload.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(f"sha256={expected}", signature)
```

## 📦 SDK & Libraries

### Go SDK

```go
package main

import (
    "context"
    "fmt"
    "github.com/typosentinel/go-sdk"
)

func main() {
    client := typosentinel.NewClient("your-api-key")
    
    // Start a scan
    scan, err := client.Scans.Create(context.Background(), &typosentinel.ScanRequest{
        Target: "/path/to/project",
        Preset: "balanced",
    })
    if err != nil {
        panic(err)
    }
    
    // Wait for completion
    result, err := client.Scans.Wait(context.Background(), scan.ID)
    if err != nil {
        panic(err)
    }
    
    fmt.Printf("Scan completed: %d threats found\n", len(result.Threats))
}
```

### Python SDK

```python
from typosentinel import Client

# Initialize client
client = Client(api_key="your-api-key")

# Start a scan
scan = client.scans.create(
    target="/path/to/project",
    preset="balanced"
)

# Wait for completion
result = client.scans.wait(scan.id)

print(f"Scan completed: {len(result.threats)} threats found")

# Process threats
for threat in result.threats:
    if threat.severity == "high":
        print(f"High severity threat: {threat.package_name}")
```

### Node.js SDK

```javascript
const { TypoSentinel } = require('@typosentinel/sdk');

const client = new TypoSentinel({
  apiKey: 'your-api-key'
});

async function scanProject() {
  // Start a scan
  const scan = await client.scans.create({
    target: '/path/to/project',
    preset: 'balanced'
  });
  
  // Wait for completion
  const result = await client.scans.wait(scan.id);
  
  console.log(`Scan completed: ${result.threats.length} threats found`);
  
  // Process high severity threats
  const highThreats = result.threats.filter(t => t.severity === 'high');
  highThreats.forEach(threat => {
    console.log(`High severity threat: ${threat.packageName}`);
  });
}

scanProject().catch(console.error);
```

## 🔐 Authentication

### API Key Authentication

```bash
# Set API key in header
curl -H "Authorization: Bearer YOUR_API_KEY" \
     http://localhost:8080/api/v1/scans
```

### JWT Token Authentication

```bash
# Login to get JWT token
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "password"
  }'

# Use JWT token
curl -H "Authorization: Bearer JWT_TOKEN" \
     http://localhost:8080/api/v1/scans
```

### OAuth2 Authentication

```bash
# OAuth2 flow
curl -X POST http://localhost:8080/api/v1/auth/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=YOUR_CLIENT_ID&client_secret=YOUR_CLIENT_SECRET"
```

## ❌ Error Handling

### Error Response Format

```json
{
  "error": {
    "code": "INVALID_REQUEST",
    "message": "Invalid scan configuration",
    "details": {
      "field": "timeout",
      "reason": "Invalid duration format"
    },
    "request_id": "req_123456789",
    "timestamp": "2025-01-15T10:30:00Z"
  }
}
```

### HTTP Status Codes

- `200` - Success
- `201` - Created
- `400` - Bad Request
- `401` - Unauthorized
- `403` - Forbidden
- `404` - Not Found
- `409` - Conflict
- `422` - Unprocessable Entity
- `429` - Rate Limited
- `500` - Internal Server Error
- `503` - Service Unavailable

### Error Codes

| Code | Description |
|------|-------------|
| `INVALID_REQUEST` | Request validation failed |
| `AUTHENTICATION_FAILED` | Authentication credentials invalid |
| `AUTHORIZATION_FAILED` | Insufficient permissions |
| `RESOURCE_NOT_FOUND` | Requested resource not found |
| `RESOURCE_CONFLICT` | Resource already exists |
| `RATE_LIMITED` | Too many requests |
| `SCAN_FAILED` | Scan execution failed |
| `CONFIG_INVALID` | Configuration validation failed |
| `INTERNAL_ERROR` | Internal server error |
| `SERVICE_UNAVAILABLE` | Service temporarily unavailable |

### Rate Limiting

```bash
# Rate limit headers
HTTP/1.1 200 OK
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1642262400
```

### Retry Logic

```python
import time
import requests

def api_request_with_retry(url, headers, max_retries=3):
    for attempt in range(max_retries):
        try:
            response = requests.get(url, headers=headers)
            
            if response.status_code == 429:
                # Rate limited, wait and retry
                retry_after = int(response.headers.get('Retry-After', 60))
                time.sleep(retry_after)
                continue
                
            if response.status_code >= 500:
                # Server error, exponential backoff
                time.sleep(2 ** attempt)
                continue
                
            return response
            
        except requests.RequestException:
            if attempt == max_retries - 1:
                raise
            time.sleep(2 ** attempt)
    
    raise Exception("Max retries exceeded")
```

## 📊 API Versioning

### Version Strategy
- Current version: `v1`
- Backward compatibility maintained for major versions
- Deprecation notices provided 6 months before removal

### Version Headers
```bash
# Specify API version
curl -H "Accept: application/vnd.typosentinel.v1+json" \
     http://localhost:8080/api/scans
```

### Migration Guide
When upgrading API versions:
1. Review changelog for breaking changes
2. Update client code for new endpoints
3. Test thoroughly in staging environment
4. Monitor for deprecation warnings

---

**Last Updated**: January 2025  
**API Version**: v1  
**Next Review**: March 2025