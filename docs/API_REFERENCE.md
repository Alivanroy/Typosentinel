# API Reference

Base URL: `http://localhost:8080`

## Authentication
- Enable with `API_AUTH_ENABLED=true`
- Provide allowed keys with `API_KEYS=key1,key2`
- Send `Authorization: Bearer <key>` on protected routes

## Endpoints

### GET `/health`
Returns service health.

Response:
```json
{"status":"healthy","timestamp":"...","version":"1.0.0"}
```

### GET `/ready`
Returns readiness.

### GET `/v1/status`
Returns service features and limits. Includes `X-Demo-Mode: true` header.

### GET `/v1/stats`
Demo stats. Returns `X-Demo-Mode: true` header.

### POST `/v1/analyze`
Analyze a single package.

Request:
```json
{"package_name":"express","registry":"npm"}
```

Response:
```json
{
  "package_name":"express",
  "registry":"npm",
  "threats":[{"type":"typosquatting","severity":"medium","description":"...","confidence":0.7}],
  "warnings":[],
  "risk_level":2,
  "risk_score":0.7,
  "analyzed_at":"..."
}
```

### POST `/v1/analyze/batch`
Analyze multiple packages (max 10).

Request:
```json
{"packages":[{"package_name":"express","registry":"npm"}]}
```

### GET `/api/v1/vulnerabilities`
Returns `501 Not Implemented` in demo.

### GET `/api/v1/dashboard/metrics`
Returns `501 Not Implemented` in demo.

### GET `/api/v1/dashboard/performance`
Returns `501 Not Implemented` in demo.

### GET `/api/v1/scans`
Returns `501 Not Implemented` (planned for v1.1). Intended to list recent scans.

## Errors
- `401 Unauthorized`: missing/invalid auth when enabled
- `429 Too Many Requests`: rate limiting
- `400 Bad Request`: invalid input
