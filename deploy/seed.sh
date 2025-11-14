#!/usr/bin/env sh
set -e
API=${API_URL:-http://typosentinel-api:8080}
curl -s -f "$API/health"
curl -s -f "$API/api/v1/docs/openapi" >/dev/null
curl -s -f -X POST "$API/api/v1/analyze" -H "Content-Type: application/json" -d '{"name":"react","ecosystem":"npm","version":"18.2.0","options":{"include_ml":true,"include_vulnerabilities":true}}' >/dev/null
curl -s -f -X POST "$API/api/v1/vulnerabilities/scan/npm/react" -H "Content-Type: application/json" -d '{"name":"react","ecosystem":"npm","version":"18.2.0"}' >/dev/null
exit 0

