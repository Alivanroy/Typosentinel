# API Reference

This document provides comprehensive documentation for the Typosentinel API, including endpoints, request/response formats, authentication, and usage examples.

## API Overview

The Typosentinel API provides programmatic access to package analysis, threat detection, and security scanning capabilities. The API follows REST principles and returns JSON responses.

**Base URL**: `https://api.typosentinel.com/v1`
**API Version**: v1
**Content-Type**: `application/json`
**Rate Limiting**: 1000 requests per hour per API key

## Authentication

### API Key Authentication

All API requests require authentication using an API key passed in the request header:

```http
X-API-Key: your-api-key-here
```

### JWT Authentication

For web applications, JWT tokens can be used:

```http
Authorization: Bearer your-jwt-token-here
```

### Getting an API Key

1. Register at [Typosentinel Dashboard](https://dashboard.typosentinel.com)
2. Navigate to API Keys section
3. Generate a new API key
4. Copy and securely store your API key

## Rate Limiting

API requests are rate-limited to ensure fair usage:

- **Free Tier**: 100 requests per hour
- **Pro Tier**: 1,000 requests per hour
- **Enterprise Tier**: 10,000 requests per hour

Rate limit headers are included in all responses:

```http
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1640995200
```

## Error Handling

### Error Response Format

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid package name format",
    "details": {
      "field": "package_name",
      "value": "invalid-name!",
      "constraint": "alphanumeric characters and hyphens only"
    },
    "request_id": "req_1234567890",
    "timestamp": "2024-01-15T10:30:00Z"
  }
}
```

### HTTP Status Codes

- `200 OK`: Request successful
- `201 Created`: Resource created successfully
- `400 Bad Request`: Invalid request parameters
- `401 Unauthorized`: Authentication required
- `403 Forbidden`: Insufficient permissions
- `404 Not Found`: Resource not found
- `429 Too Many Requests`: Rate limit exceeded
- `500 Internal Server Error`: Server error
- `503 Service Unavailable`: Service temporarily unavailable

### Error Codes

| Code | Description |
|------|-------------|
| `VALIDATION_ERROR` | Request validation failed |
| `AUTHENTICATION_ERROR` | Authentication failed |
| `AUTHORIZATION_ERROR` | Insufficient permissions |
| `RATE_LIMIT_ERROR` | Rate limit exceeded |
| `PACKAGE_NOT_FOUND` | Package not found |
| `SCAN_IN_PROGRESS` | Scan already in progress |
| `INTERNAL_ERROR` | Internal server error |
| `SERVICE_UNAVAILABLE` | Service temporarily unavailable |

## Endpoints

### Package Analysis

#### Scan Package

Analyze a package for security threats and vulnerabilities.

**Endpoint**: `POST /packages/scan`

**Request Body**:
```json
{
  "package_name": "express",
  "version": "4.18.2",
  "registry": "npm",
  "options": {
    "deep_scan": true,
    "include_dependencies": true,
    "ml_analysis": true,
    "timeout": 300
  }
}
```

**Response**:
```json
{
  "scan_id": "scan_1234567890",
  "status": "completed",
  "package": {
    "name": "express",
    "version": "4.18.2",
    "registry": "npm",
    "size": 1024000,
    "files_count": 42
  },
  "results": {
    "risk_score": 2.5,
    "threat_level": "low",
    "threats_detected": 1,
    "vulnerabilities": [
      {
        "id": "CVE-2024-1234",
        "severity": "medium",
        "description": "Potential XSS vulnerability",
        "affected_versions": "<4.18.3",
        "fix_available": true,
        "fix_version": "4.18.3"
      }
    ],
    "suspicious_patterns": [],
    "dependencies": {
      "total": 15,
      "vulnerable": 1,
      "outdated": 3
    }
  },
  "metadata": {
    "scan_duration": 45.2,
    "scanned_at": "2024-01-15T10:30:00Z",
    "scanner_version": "1.2.0"
  }
}
```

#### Get Scan Status

Retrieve the status of a package scan.

**Endpoint**: `GET /packages/scan/{scan_id}`

**Response**:
```json
{
  "scan_id": "scan_1234567890",
  "status": "in_progress",
  "progress": 75,
  "estimated_completion": "2024-01-15T10:35:00Z",
  "started_at": "2024-01-15T10:30:00Z"
}
```

#### Bulk Package Scan

Scan multiple packages in a single request.

**Endpoint**: `POST /packages/scan/bulk`

**Request Body**:
```json
{
  "packages": [
    {
      "package_name": "express",
      "version": "4.18.2",
      "registry": "npm"
    },
    {
      "package_name": "lodash",
      "version": "4.17.21",
      "registry": "npm"
    }
  ],
  "options": {
    "deep_scan": false,
    "parallel": true,
    "max_concurrent": 5
  }
}
```

**Response**:
```json
{
  "batch_id": "batch_1234567890",
  "status": "queued",
  "total_packages": 2,
  "scan_ids": [
    "scan_1234567891",
    "scan_1234567892"
  ],
  "estimated_completion": "2024-01-15T10:40:00Z"
}
```

### Package Information

#### Get Package Details

Retrieve detailed information about a package.

**Endpoint**: `GET /packages/{registry}/{package_name}`

**Query Parameters**:
- `version` (optional): Specific version to retrieve
- `include_history` (optional): Include scan history

**Response**:
```json
{
  "package": {
    "name": "express",
    "registry": "npm",
    "latest_version": "4.18.2",
    "description": "Fast, unopinionated, minimalist web framework",
    "author": "TJ Holowaychuk",
    "license": "MIT",
    "homepage": "http://expressjs.com/",
    "repository": "https://github.com/expressjs/express",
    "downloads": {
      "last_week": 25000000,
      "last_month": 100000000
    },
    "versions": [
      "4.18.2",
      "4.18.1",
      "4.18.0"
    ]
  },
  "security": {
    "last_scan": "2024-01-15T10:30:00Z",
    "risk_score": 2.5,
    "threat_level": "low",
    "known_vulnerabilities": 1,
    "trust_score": 9.2
  },
  "scan_history": [
    {
      "scan_id": "scan_1234567890",
      "version": "4.18.2",
      "scanned_at": "2024-01-15T10:30:00Z",
      "risk_score": 2.5,
      "threats_found": 1
    }
  ]
}
```

#### Search Packages

Search for packages across registries.

**Endpoint**: `GET /packages/search`

**Query Parameters**:
- `q`: Search query
- `registry`: Filter by registry (npm, pypi, rubygems)
- `limit`: Number of results (default: 20, max: 100)
- `offset`: Pagination offset
- `sort`: Sort by (relevance, downloads, updated)

**Response**:
```json
{
  "results": [
    {
      "name": "express",
      "registry": "npm",
      "version": "4.18.2",
      "description": "Fast, unopinionated, minimalist web framework",
      "downloads": 25000000,
      "risk_score": 2.5,
      "last_updated": "2024-01-10T15:20:00Z"
    }
  ],
  "total": 1,
  "limit": 20,
  "offset": 0,
  "has_more": false
}
```

### Threat Intelligence

#### Get Threat Database

Retrieve threat intelligence data.

**Endpoint**: `GET /threats`

**Query Parameters**:
- `severity`: Filter by severity (critical, high, medium, low)
- `type`: Filter by threat type
- `registry`: Filter by registry
- `limit`: Number of results
- `since`: Get threats since timestamp

**Response**:
```json
{
  "threats": [
    {
      "id": "threat_1234567890",
      "type": "malicious_code",
      "severity": "high",
      "title": "Cryptocurrency miner detected",
      "description": "Package contains hidden cryptocurrency mining code",
      "affected_packages": [
        {
          "name": "malicious-package",
          "registry": "npm",
          "versions": ["1.0.0", "1.0.1"]
        }
      ],
      "indicators": [
        "crypto-mining",
        "obfuscated-code",
        "network-requests"
      ],
      "discovered_at": "2024-01-15T08:00:00Z",
      "updated_at": "2024-01-15T10:00:00Z"
    }
  ],
  "total": 1,
  "limit": 20,
  "has_more": false
}
```

#### Report Threat

Report a new security threat or suspicious package.

**Endpoint**: `POST /threats/report`

**Request Body**:
```json
{
  "package_name": "suspicious-package",
  "version": "1.0.0",
  "registry": "npm",
  "threat_type": "malicious_code",
  "severity": "high",
  "description": "Package contains obfuscated malicious code",
  "evidence": {
    "files": ["index.js", "lib/crypto.js"],
    "patterns": ["eval(", "crypto.createHash"],
    "network_requests": ["http://malicious-domain.com"]
  },
  "reporter": {
    "name": "Security Researcher",
    "email": "researcher@example.com",
    "organization": "Security Company"
  }
}
```

**Response**:
```json
{
  "report_id": "report_1234567890",
  "status": "submitted",
  "message": "Threat report submitted successfully",
  "estimated_review_time": "24h",
  "submitted_at": "2024-01-15T10:30:00Z"
}
```

### Analytics and Statistics

#### Get Scan Statistics

Retrieve scanning statistics and metrics.

**Endpoint**: `GET /analytics/stats`

**Query Parameters**:
- `period`: Time period (day, week, month, year)
- `registry`: Filter by registry
- `start_date`: Start date for custom period
- `end_date`: End date for custom period

**Response**:
```json
{
  "period": "week",
  "start_date": "2024-01-08T00:00:00Z",
  "end_date": "2024-01-15T00:00:00Z",
  "statistics": {
    "total_scans": 15420,
    "unique_packages": 8750,
    "threats_detected": 234,
    "vulnerabilities_found": 1876,
    "average_risk_score": 3.2,
    "registries": {
      "npm": 8500,
      "pypi": 4200,
      "rubygems": 2720
    },
    "threat_types": {
      "malicious_code": 45,
      "typosquatting": 89,
      "vulnerabilities": 100
    }
  },
  "trends": {
    "scans_per_day": [2100, 2300, 2150, 2400, 2200, 2180, 2090],
    "threats_per_day": [32, 38, 29, 41, 35, 33, 26]
  }
}
```

#### Get Risk Trends

Retrieve risk trend analysis.

**Endpoint**: `GET /analytics/risk-trends`

**Response**:
```json
{
  "trends": {
    "overall_risk": {
      "current": 3.2,
      "previous_period": 3.5,
      "change": -0.3,
      "trend": "decreasing"
    },
    "by_registry": {
      "npm": {
        "current": 2.8,
        "trend": "stable"
      },
      "pypi": {
        "current": 3.9,
        "trend": "increasing"
      }
    },
    "threat_categories": {
      "malicious_code": {
        "count": 45,
        "trend": "decreasing"
      },
      "typosquatting": {
        "count": 89,
        "trend": "increasing"
      }
    }
  },
  "predictions": {
    "next_week_risk": 3.1,
    "confidence": 0.85
  }
}
```

### User Management

#### Get User Profile

Retrieve user profile information.

**Endpoint**: `GET /user/profile`

**Response**:
```json
{
  "user": {
    "id": "user_1234567890",
    "username": "security_analyst",
    "email": "analyst@company.com",
    "organization": "Security Company",
    "role": "analyst",
    "created_at": "2024-01-01T00:00:00Z",
    "last_login": "2024-01-15T09:00:00Z"
  },
  "subscription": {
    "plan": "pro",
    "status": "active",
    "expires_at": "2024-12-31T23:59:59Z",
    "features": [
      "bulk_scanning",
      "api_access",
      "custom_rules",
      "priority_support"
    ]
  },
  "usage": {
    "current_period": {
      "scans_used": 750,
      "scans_limit": 1000,
      "api_calls_used": 2500,
      "api_calls_limit": 10000
    },
    "reset_date": "2024-02-01T00:00:00Z"
  }
}
```

#### Update User Preferences

Update user preferences and settings.

**Endpoint**: `PUT /user/preferences`

**Request Body**:
```json
{
  "notifications": {
    "email_alerts": true,
    "threat_updates": true,
    "scan_completion": false
  },
  "default_scan_options": {
    "deep_scan": true,
    "include_dependencies": true,
    "ml_analysis": true
  },
  "api_settings": {
    "rate_limit_notifications": true,
    "usage_warnings": true
  }
}
```

### Webhooks

#### Configure Webhooks

Set up webhooks for real-time notifications.

**Endpoint**: `POST /webhooks`

**Request Body**:
```json
{
  "url": "https://your-app.com/webhooks/typosentinel",
  "events": [
    "scan.completed",
    "threat.detected",
    "vulnerability.found"
  ],
  "secret": "your-webhook-secret",
  "active": true
}
```

**Response**:
```json
{
  "webhook_id": "webhook_1234567890",
  "url": "https://your-app.com/webhooks/typosentinel",
  "events": [
    "scan.completed",
    "threat.detected",
    "vulnerability.found"
  ],
  "active": true,
  "created_at": "2024-01-15T10:30:00Z"
}
```

#### Webhook Events

**Scan Completed**:
```json
{
  "event": "scan.completed",
  "timestamp": "2024-01-15T10:30:00Z",
  "data": {
    "scan_id": "scan_1234567890",
    "package_name": "express",
    "version": "4.18.2",
    "registry": "npm",
    "risk_score": 2.5,
    "threats_detected": 1,
    "scan_duration": 45.2
  }
}
```

**Threat Detected**:
```json
{
  "event": "threat.detected",
  "timestamp": "2024-01-15T10:30:00Z",
  "data": {
    "threat_id": "threat_1234567890",
    "package_name": "malicious-package",
    "version": "1.0.0",
    "registry": "npm",
    "threat_type": "malicious_code",
    "severity": "high",
    "description": "Cryptocurrency miner detected"
  }
}
```

## SDK and Libraries

### Official SDKs

**Node.js SDK**:
```bash
npm install @typosentinel/sdk
```

```javascript
const Typosentinel = require('@typosentinel/sdk');

const client = new Typosentinel({
  apiKey: 'your-api-key',
  baseUrl: 'https://api.typosentinel.com/v1'
});

// Scan a package
const result = await client.scanPackage({
  packageName: 'express',
  version: '4.18.2',
  registry: 'npm'
});

console.log('Risk Score:', result.riskScore);
```

**Python SDK**:
```bash
pip install typosentinel-sdk
```

```python
from typosentinel import Client

client = Client(api_key='your-api-key')

# Scan a package
result = client.scan_package(
    package_name='requests',
    version='2.28.1',
    registry='pypi'
)

print(f'Risk Score: {result.risk_score}')
```

**Go SDK**:
```bash
go get github.com/typosentinel/go-sdk
```

```go
package main

import (
    "context"
    "fmt"
    "github.com/typosentinel/go-sdk"
)

func main() {
    client := typosentinel.NewClient("your-api-key")
    
    result, err := client.ScanPackage(context.Background(), &typosentinel.ScanRequest{
        PackageName: "gin",
        Version:     "1.9.1",
        Registry:    "go",
    })
    
    if err != nil {
        panic(err)
    }
    
    fmt.Printf("Risk Score: %.2f\n", result.RiskScore)
}
```

## Code Examples

### Basic Package Scanning

```bash
# Using curl
curl -X POST https://api.typosentinel.com/v1/packages/scan \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "package_name": "express",
    "version": "4.18.2",
    "registry": "npm"
  }'
```

### Bulk Scanning with Progress Tracking

```javascript
const packages = [
  { package_name: 'express', version: '4.18.2', registry: 'npm' },
  { package_name: 'lodash', version: '4.17.21', registry: 'npm' },
  { package_name: 'react', version: '18.2.0', registry: 'npm' }
];

// Start bulk scan
const bulkResponse = await fetch('/packages/scan/bulk', {
  method: 'POST',
  headers: {
    'X-API-Key': 'your-api-key',
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({ packages })
});

const { batch_id, scan_ids } = await bulkResponse.json();

// Track progress
for (const scanId of scan_ids) {
  let status = 'in_progress';
  
  while (status === 'in_progress') {
    const statusResponse = await fetch(`/packages/scan/${scanId}`, {
      headers: { 'X-API-Key': 'your-api-key' }
    });
    
    const statusData = await statusResponse.json();
    status = statusData.status;
    
    console.log(`Scan ${scanId}: ${status} (${statusData.progress}%)`);
    
    if (status === 'in_progress') {
      await new Promise(resolve => setTimeout(resolve, 5000)); // Wait 5 seconds
    }
  }
}
```

### Real-time Threat Monitoring

```python
import requests
import time
from datetime import datetime, timedelta

def monitor_threats(api_key, check_interval=300):
    """Monitor for new threats every 5 minutes"""
    last_check = datetime.utcnow() - timedelta(hours=1)
    
    while True:
        try:
            response = requests.get(
                'https://api.typosentinel.com/v1/threats',
                headers={'X-API-Key': api_key},
                params={'since': last_check.isoformat()}
            )
            
            if response.status_code == 200:
                threats = response.json()['threats']
                
                for threat in threats:
                    print(f"New threat detected: {threat['title']}")
                    print(f"Severity: {threat['severity']}")
                    print(f"Affected packages: {len(threat['affected_packages'])}")
                    
                    # Send alert to your monitoring system
                    send_alert(threat)
                
                last_check = datetime.utcnow()
            
            time.sleep(check_interval)
            
        except Exception as e:
            print(f"Error monitoring threats: {e}")
            time.sleep(60)  # Wait 1 minute before retrying

def send_alert(threat):
    """Send threat alert to monitoring system"""
    # Implement your alerting logic here
    pass

# Start monitoring
monitor_threats('your-api-key')
```

## Best Practices

### 1. API Usage

- **Rate Limiting**: Implement exponential backoff for rate limit errors
- **Caching**: Cache scan results to avoid redundant API calls
- **Batch Processing**: Use bulk endpoints for multiple packages
- **Error Handling**: Implement proper error handling and retry logic
- **Webhooks**: Use webhooks for real-time notifications instead of polling

### 2. Security

- **API Key Security**: Store API keys securely, never in code
- **HTTPS Only**: Always use HTTPS for API requests
- **Request Validation**: Validate all input parameters
- **Rate Limiting**: Respect rate limits and implement backoff
- **Webhook Verification**: Verify webhook signatures

### 3. Performance

- **Connection Pooling**: Reuse HTTP connections
- **Compression**: Enable gzip compression for large responses
- **Pagination**: Use pagination for large result sets
- **Filtering**: Use query parameters to filter results
- **Async Processing**: Use asynchronous requests where possible

## Changelog

### v1.2.0 (2024-01-15)
- Added bulk scanning endpoints
- Improved threat intelligence API
- Added webhook support
- Enhanced error handling
- Added analytics endpoints

### v1.1.0 (2023-12-01)
- Added ML-based risk scoring
- Improved package search
- Added user management endpoints
- Enhanced rate limiting
- Added SDK support

### v1.0.0 (2023-10-01)
- Initial API release
- Basic package scanning
- Threat detection
- Authentication system
- Rate limiting

## Support

### Getting Help

- **Documentation**: [https://docs.typosentinel.com](https://docs.typosentinel.com)
- **API Status**: [https://status.typosentinel.com](https://status.typosentinel.com)
- **Support Email**: support@typosentinel.com
- **Community Forum**: [https://community.typosentinel.com](https://community.typosentinel.com)

### Reporting Issues

- **Bug Reports**: [GitHub Issues](https://github.com/typosentinel/typosentinel/issues)
- **Feature Requests**: [GitHub Discussions](https://github.com/typosentinel/typosentinel/discussions)
- **Security Issues**: security@typosentinel.com

### SLA and Uptime

- **Uptime Target**: 99.9%
- **Response Time**: < 500ms (95th percentile)
- **Support Response**: < 24 hours
- **Status Page**: [https://status.typosentinel.com](https://status.typosentinel.com)

For the latest API updates and announcements, follow [@TyposentinelAPI](https://twitter.com/TyposentinelAPI) on Twitter.

## Core Packages

### pkg/config

Configuration management for TypoSentinel.

#### Functions

- `Load(path string) (*Config, error)` - Load configuration from file
- `Validate(config *Config) error` - Validate configuration

### pkg/logger

Logging utilities with multiple output formats and levels.

#### Functions

- `New(config LoggerConfig) *Logger` - Create new logger instance
- `SetLevel(level string)` - Set logging level
- `Debug(msg string, fields ...interface{})` - Debug logging
- `Info(msg string, fields ...interface{})` - Info logging
- `Warn(msg string, fields ...interface{})` - Warning logging
- `Error(msg string, fields ...interface{})` - Error logging

### pkg/types

Common types and structures used throughout TypoSentinel.

#### Types

- `Package` - Represents a package to be analyzed
- `ScanResult` - Results of a typosquatting scan
- `ThreatLevel` - Enumeration of threat levels
- `Registry` - Package registry type (npm, pypi, etc.)

## Internal Packages

### internal/analyzer

Core analysis engine for detecting typosquatting patterns.

#### Key Functions

- `NewAnalyzer(config AnalyzerConfig) *Analyzer`
- `Analyze(pkg Package) (*AnalysisResult, error)`
- `GetSimilarPackages(name string) ([]string, error)`

### internal/detector

Detection engines for various typosquatting techniques.

#### Detectors

- `HomoglyphDetector` - Detects Unicode homoglyph attacks
- `EditDistanceDetector` - Detects packages with similar names
- `KeyboardLayoutDetector` - Detects keyboard layout-based typos
- `ReputationDetector` - Analyzes package reputation

### internal/ml

Machine learning components for advanced threat detection.

#### Components

- `BasicScorer` - Basic ML scoring algorithm
- `AdvancedScorer` - Advanced ML scoring with feature extraction
- `FeatureExtractor` - Extracts features from packages
- `ModelPipeline` - ML model pipeline management

### internal/scanner

Package scanning and analysis coordination.

#### Scanners

- `NPMScanner` - Scans npm packages
- `PyPIScanner` - Scans Python packages
- `GoScanner` - Scans Go modules
- `RubyScanner` - Scans Ruby gems
- `JavaScanner` - Scans Java packages

### internal/api/rest

REST API server implementation.

#### Components

- `Server` - Main API server
- `Middleware` - HTTP middleware components
- `Handlers` - Request handlers

### internal/database

Threat database management and updates.

#### Functions

- `NewThreatDB(config DBConfig) *ThreatDB`
- `UpdateThreats() error`
- `QueryThreats(criteria Criteria) ([]Threat, error)`

### internal/registry

Package registry clients for fetching package information.

#### Clients

- `NPMClient` - npm registry client
- `PyPIClient` - PyPI registry client
- `OptimizedClient` - Optimized registry client with caching

## CLI Commands

### Main Commands

- `typosentinel scan` - Scan packages for typosquatting
- `typosentinel serve` - Start the REST API server
- `typosentinel benchmark` - Run performance benchmarks
- `typosentinel train` - Train ML models

### Scan Command Options

```bash
typosentinel scan [flags] <package-name>

Flags:
  --registry string     Package registry (npm, pypi, go, ruby, java)
  --output string       Output format (json, yaml, table)
  --config string       Configuration file path
  --threshold float     Threat threshold (0.0-1.0)
  --verbose             Enable verbose output
```

### Serve Command Options

```bash
typosentinel serve [flags]

Flags:
  --host string         Host to bind to (default "localhost")
  --port int            Port to listen on (default 8080)
  --config string       Configuration file path
  --workers int         Number of worker goroutines (default 10)
  --timeout int         Request timeout in seconds (default 30)
```

## Configuration

For detailed configuration options, see the configuration files in the `config/` directory:

- `config.yaml` - Default configuration
- `config-optimized.yaml` - Performance-optimized configuration
- `config-full-detection.yaml` - Full detection capabilities

## Error Handling

All API functions return errors following Go conventions. HTTP API endpoints return structured error responses:

```json
{
  "error": {
    "code": "INVALID_REQUEST",
    "message": "Package name is required",
    "details": {}
  }
}
```

## Performance Considerations

- Use connection pooling for database operations
- Enable caching for registry lookups
- Configure appropriate worker pool sizes
- Monitor memory usage for large scans

## Security

For security considerations and vulnerability reporting, see [SECURITY.md](../SECURITY.md).

---

*This documentation is automatically generated. For the most up-to-date information, refer to the source code and inline documentation.*