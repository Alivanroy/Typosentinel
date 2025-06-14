#!/bin/bash

# Comprehensive TypoSentinel API Test Script
BASE_URL="http://localhost:8080"
API_URL="$BASE_URL/api/v1"

echo "🔍 TypoSentinel API Comprehensive Test"
echo "====================================="
echo "Base URL: $BASE_URL"
echo ""

# Test 1: Health Check
echo "1. Health Check:"
curl -s -w "\nHTTP Status: %{http_code}\n" "$BASE_URL/health"
echo ""

# Test 2: Get Available Registries
echo "2. Available Registries:"
curl -s -w "\nHTTP Status: %{http_code}\n" "$API_URL/registries"
echo ""

# Test 3: Get API Version
echo "3. API Version:"
curl -s -w "\nHTTP Status: %{http_code}\n" "$API_URL/version"
echo ""

# Test 4: Test Protected Endpoint with trailing slash
echo "4. Protected Endpoint Test (GET /api/v1/scans/):"
curl -s -w "\nHTTP Status: %{http_code}\n" "$API_URL/scans/"
echo ""

# Test 5: Test Scan Creation (POST)
echo "5. Scan Creation Test (POST /api/v1/scans/):"
curl -s -X POST "$API_URL/scans/" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer mock-token" \
  -w "\nHTTP Status: %{http_code}\n" \
  -d '{
    "dependencies": [
      {
        "name": "lodash",
        "version": "4.17.21",
        "registry": "npm",
        "source": "package.json",
        "direct": true,
        "development": false
      }
    ],
    "options": {
      "deep_analysis": true,
      "include_dev_dependencies": false,
      "similarity_threshold": 0.8
    }
  }'
echo ""

# Test 6: Test Package Endpoint
echo "6. Package Info Test (GET /api/v1/packages/npm/lodash):"
curl -s -w "\nHTTP Status: %{http_code}\n" "$API_URL/packages/npm/lodash"
echo ""

# Test 7: Test Package Version Endpoint
echo "7. Package Version Test (GET /api/v1/packages/npm/lodash/4.17.21):"
curl -s -w "\nHTTP Status: %{http_code}\n" "$API_URL/packages/npm/lodash/4.17.21"
echo ""

# Test 8: Test with different package (potential typosquatting target)
echo "8. Typosquatting Test - Similar Package (GET /api/v1/packages/npm/loadash):"
curl -s -w "\nHTTP Status: %{http_code}\n" "$API_URL/packages/npm/loadash"
echo ""

# Test 9: Test Python package
echo "9. Python Package Test (GET /api/v1/packages/pypi/requests):"
curl -s -w "\nHTTP Status: %{http_code}\n" "$API_URL/packages/pypi/requests"
echo ""

# Test 10: Test Go package
echo "10. Go Package Test (GET /api/v1/packages/go/github.com/gin-gonic/gin):"
curl -s -w "\nHTTP Status: %{http_code}\n" "$API_URL/packages/go/github.com%2Fgin-gonic%2Fgin"
echo ""

echo "✅ Test completed!"
echo ""
echo "📋 Expected Results:"
echo "- Health check: 200 OK with JSON response showing service status"
echo "- Registries: 200 OK with supported package registries (npm, pypi, go)"
echo "- Version: 200 OK with API version and build info"
echo "- Protected endpoints: 401 Unauthorized (expected without valid JWT)"
echo "- Package endpoints: 401 Unauthorized or package data (if auth works)"
echo ""
echo "🔗 Tested Endpoints:"
echo "- GET  /health (public)"
echo "- GET  /api/v1/registries (public)"
echo "- GET  /api/v1/version (public)"
echo "- POST /api/v1/scans/ (protected)"
echo "- GET  /api/v1/scans/ (protected)"
echo "- GET  /api/v1/packages/:registry/:name (protected)"
echo "- GET  /api/v1/packages/:registry/:name/:version (protected)"
echo ""
echo "📦 Test Packages Used:"
echo "- npm: lodash (popular), loadash (potential typosquatter)"
echo "- pypi: requests (popular Python package)"
echo "- go: github.com/gin-gonic/gin (popular Go framework)"