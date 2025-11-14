#!/usr/bin/env sh
set -e
API=${API_URL:-http://typosentinel-api:8080}
curl -s -f "$API/health" >/dev/null
curl -s -f -X POST "$API/api/v1/database/update" -H "Content-Type: application/json" -d '{}' >/dev/null
exit 0

