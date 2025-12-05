# TypoSentinel API Reference

## Overview

The TypoSentinel API provides RESTful endpoints for package threat analysis. The API server is a lightweight, standalone service located in the [`api/`](../api/) directory.

## Starting the API Server

### Local Development
```bash
cd api
go run main.go
```

### Docker
```bash
docker build -t typo sentinel-api ./api
docker run -p 8080:8080 typosentinel-api
```

### Environment Variables
- `PORT`: Server port (default: `8080`)
- `API_AUTH_ENABLED`: Enable API key authentication (`true`/`false`)
- `API_KEYS`: Comma-separated list of valid API keys
- `SLACK_WEBHOOK_URL`: Slack webhook for high-risk alerts
- `SMTP_HOST`, `SMTP_USER`, `SMTP_PASS`: Email notification settings

## Endpoints

### Health & Status

#### `GET /health`
Health check endpoint.

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T10:30:00Z",
  "version": "1.0.0"
}
```

#### `GET /ready`
Readiness check with dependency status.

**Response:**
```json
{
  "ready": true,
  "timestamp": "2024-01-15T10:30:00Z",
  "redis": {
    "configured": true,
    "connected": true
  },
  "webhooks": {
    "slack": {"configured": true}
  }
}
```

#### `GET /v1/status`
Service status and feature flags.

**Response:**
```json
{
  "service": "TypoSentinel API",
  "version": "1.0.0",
  "status": "operational",
  "features": {
    "typosquatting_detection": true,
    "malware_scanning": true,
    "batch_analysis": true
  },
  "limits": {
    "requests_per_minute": 10,
    "batch_size_limit": 10
  }
}
```

### Analysis Endpoints

#### `POST /v1/analyze`
Analyze a single package for security threats.

**Request:**
```json
{
  "package_name": "lodash",
  "registry": "npm"
}
```

**Response:**
```json
{
  "package_name": "lodash",
  "registry": "npm",
  "threats": [
    {
      "type": "typosquatting",
      "severity": "medium",
      "description": "Package name similar to popular package",
      "confidence": 0.85
    }
  ],
  "warnings": [],
  "risk_level": 2,
  "risk_score": 0.65,
  "analyzed_at": "2024-01-15T10:30:00Z"
}
```

#### `POST /v1/analyze/batch`
Analyze multiple packages in a single request.

**Request:**
```json
{
  "packages": [
    {"package_name": "lodash", "registry": "npm"},
    {"package_name": "requests", "registry": "pypi"}
  ]
}
```

**Response:**
```json
{
  "results": [
    {
      "package_name": "lodash",
      "registry": "npm",
      "threats": [],
      "warnings": [],
      "risk_level": 0,
      "risk_score": 0.0,
      "analyzed_at": "2024-01-15T10:30:00Z"
    }
  ],
  "summary": {
    "total": 2,
    "high_risk": 0,
    "medium_risk": 1,
    "low_risk": 0,
    "no_threats": 1
  },
  "analyzed_at": "2024-01-15T10:30:00Z"
}
```

**Constraints:**
- Maximum 10 packages per batch request
- Rate limit: 10 requests per minute per IP

### Metrics

#### `GET /metrics`
Prometheus-format metrics.

#### `GET /metrics.json`
JSON-format metrics.

## Authentication

Set `API_AUTH_ENABLED=true` and provide API keys via `API_KEYS` environment variable:

```bash
export API_AUTH_ENABLED=true
export API_KEYS="key1,key2,key3"
```

**Request with authentication:**
```bash
curl -X POST http://localhost:8080/v1/analyze \
  -H "Authorization: Bearer your-api-key" \
  -H "Content-Type: application/json" \
  -d '{"package_name": "lodash", "registry": "npm"}'
```

## Rate Limiting

- **Default**: 10 requests per minute per IP
- **Burst**: 10 requests
- **Headers**: Rate limit info included in response headers

## Error Responses

**400 Bad Request:**
```json
{
  "error": "Package name is required"
}
```

**401 Unauthorized:**
```json
{
  "error": "Invalid API key"
}
```

**429 Too Many Requests:**
```json
{
  "error": "Rate limit exceeded",
  "message": "Too many requests. Please try again later.",
  "retry_after": "60 seconds"
}
```

## Supported Registries

- `npm` (Node.js/JavaScript)
- `pypi` (Python)
- `go` (Go modules)
- `maven` (Java)
