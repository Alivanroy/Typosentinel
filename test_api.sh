#!/bin/bash

# TypoSentinel API Testing Script
# This script tests the package analysis endpoints

BASE_URL="http://localhost:8080"
API_URL="$BASE_URL/api/v1"

echo "🔍 TypoSentinel API Testing Script"
echo "================================="
echo "Base URL: $BASE_URL"
echo ""

# Test 1: Health Check
echo "1. Testing Health Check..."
curl -s "$BASE_URL/health" | jq .
echo ""

# Test 2: Get Available Registries
echo "2. Testing Available Registries..."
curl -s "$API_URL/registries" | jq .
echo ""

# Test 3: Get API Version
echo "3. Testing API Version..."
curl -s "$API_URL/version" | jq .
echo ""

# Test 4: Test Authentication (should fail without token)
echo "4. Testing Protected Endpoint (should fail)..."
curl -s "$API_URL/scans" | jq .
echo ""

# Test 5: Create a scan request (with mock auth - will fail but shows structure)
echo "5. Testing Scan Creation (will fail due to auth)..."
curl -X POST "$API_URL/scans" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer mock-token" \
  -d '{
    "dependencies": [
      {
        "name": "lodash",
        "version": "4.17.21",
        "registry": "npm",
        "source": "package.json",
        "direct": true,
        "development": false
      },
      {
        "name": "express",
        "version": "4.18.2",
        "registry": "npm",
        "source": "package.json",
        "direct": true,
        "development": false
      }
    ],
    "options": {
      "deep_analysis": true,
      "include_dev_dependencies": false,
      "similarity_threshold": 0.8,
      "exclude_packages": [],
      "registries": ["npm"]
    }
  }' | jq .
echo ""

# Test 6: Test package lookup
echo "6. Testing Package Lookup (will fail due to auth)..."
curl -s "$API_URL/packages/npm/lodash" \
  -H "Authorization: Bearer mock-token" | jq .
echo ""

# Test 7: Test package version lookup
echo "7. Testing Package Version Lookup (will fail due to auth)..."
curl -s "$API_URL/packages/npm/lodash/4.17.21" \
  -H "Authorization: Bearer mock-token" | jq .
echo ""

echo "📝 Test Summary:"
echo "- Health check and public endpoints should work"
echo "- Protected endpoints will return 401 Unauthorized (expected)"
echo "- This demonstrates the API structure and required authentication"
echo ""
echo "🔐 To test with real authentication:"
echo "1. First register/login to get a JWT token"
echo "2. Replace 'mock-token' with the real JWT token"
echo "3. Re-run the protected endpoint tests"
echo ""
echo "📦 Example packages to test:"
echo "- npm: lodash, express, react, vue"
echo "- pypi: requests, numpy, django, flask"
echo "- Suspicious: lodahs, expres, reqeusts (typosquatting examples)"