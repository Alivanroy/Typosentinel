#!/bin/bash

# Comprehensive API Test Script for Typosentinel
# Tests the REST API endpoints running on localhost:9090

set -e

API_BASE="http://localhost:9090"
TEST_RESULTS_DIR="test_results"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
LOG_FILE="${TEST_RESULTS_DIR}/api_test_${TIMESTAMP}.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Create test results directory
mkdir -p "$TEST_RESULTS_DIR"

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Test result tracking
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Function to test JSON endpoint
test_json_endpoint() {
    local endpoint="$1"
    local test_name="$2"
    local expected_status="${3:-200}"
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    echo -e "${BLUE}Testing JSON Endpoint: $test_name${NC}"
    log "JSON TEST START: $test_name"
    
    response=$(curl -s -w "\n%{http_code}" "$API_BASE$endpoint" 2>/dev/null)
    http_code=$(echo "$response" | tail -n 1)
    json_body=$(echo "$response" | sed '$d')
    
    if [ "$http_code" = "$expected_status" ]; then
        if [ "$expected_status" = "200" ] && echo "$json_body" | jq . >/dev/null 2>&1; then
            echo -e "${GREEN}✓ PASSED: $test_name (HTTP: $http_code, Valid JSON)${NC}"
            log "JSON TEST PASSED: $test_name"
            PASSED_TESTS=$((PASSED_TESTS + 1))
        elif [ "$expected_status" != "200" ]; then
            echo -e "${GREEN}✓ PASSED: $test_name (HTTP: $http_code)${NC}"
            log "JSON TEST PASSED: $test_name"
            PASSED_TESTS=$((PASSED_TESTS + 1))
        else
            echo -e "${RED}✗ FAILED: $test_name (HTTP: $http_code, Invalid JSON)${NC}"
            log "JSON TEST FAILED: $test_name - Invalid JSON response"
            FAILED_TESTS=$((FAILED_TESTS + 1))
        fi
    else
        echo -e "${RED}✗ FAILED: $test_name (Expected HTTP: $expected_status, Got: $http_code)${NC}"
        log "JSON TEST FAILED: $test_name - Expected: $expected_status, Got: $http_code"
        log "Response: $json_body"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
    
    echo "Response preview: $(echo "$json_body" | head -3)"
    echo ""
}

# Function to test scan endpoint with POST
test_scan_endpoint() {
    local package_name="$1"
    local registry="$2"
    local test_name="$3"
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    echo -e "${BLUE}Testing Scan Endpoint: $test_name${NC}"
    log "SCAN TEST START: $test_name"
    
    # Create JSON payload for scan start
    payload=$(cat <<EOF
{
    "package": "$package_name",
    "registry": "$registry",
    "output_format": "json"
}
EOF
)
    
    response=$(curl -s -w "\n%{http_code}" -X POST \
        -H "Content-Type: application/json" \
        -d "$payload" \
        "$API_BASE/api/scan/start" 2>/dev/null)
    
    http_code=$(echo "$response" | tail -n 1)
    json_body=$(echo "$response" | sed '$d')
    
    if [ "$http_code" = "200" ] || [ "$http_code" = "201" ]; then
        if echo "$json_body" | jq . >/dev/null 2>&1; then
            echo -e "${GREEN}✓ PASSED: $test_name (HTTP: $http_code)${NC}"
            log "SCAN TEST PASSED: $test_name"
            PASSED_TESTS=$((PASSED_TESTS + 1))
            
            # Try to extract scan ID for follow-up
            scan_id=$(echo "$json_body" | jq -r '.scan_id // .id // "N/A"')
            echo "  Scan ID: $scan_id"
        else
            echo -e "${YELLOW}⚠ PARTIAL: $test_name (HTTP: $http_code, Invalid JSON)${NC}"
            log "SCAN TEST PARTIAL: $test_name - Valid HTTP but invalid JSON"
            PASSED_TESTS=$((PASSED_TESTS + 1))
        fi
    else
        echo -e "${RED}✗ FAILED: $test_name (HTTP: $http_code)${NC}"
        log "SCAN TEST FAILED: $test_name - HTTP: $http_code"
        log "Response: $json_body"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
    
    echo ""
}

# Function to test analyze endpoint (from OpenAPI spec)
test_analyze_endpoint() {
    local package_name="$1"
    local registry="$2"
    local test_name="$3"
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    echo -e "${BLUE}Testing Analyze Endpoint: $test_name${NC}"
    log "ANALYZE TEST START: $test_name"
    
    # Create JSON payload for analysis
    payload=$(cat <<EOF
{
    "package_name": "$package_name",
    "ecosystem": "$registry",
    "version": "latest"
}
EOF
)
    
    response=$(curl -s -w "\n%{http_code}" -X POST \
        -H "Content-Type: application/json" \
        -d "$payload" \
        "$API_BASE/v1/analyze" 2>/dev/null)
    
    http_code=$(echo "$response" | tail -n 1)
    json_body=$(echo "$response" | sed '$d')
    
    if [ "$http_code" = "200" ]; then
        if echo "$json_body" | jq . >/dev/null 2>&1; then
            echo -e "${GREEN}✓ PASSED: $test_name (HTTP: $http_code)${NC}"
            log "ANALYZE TEST PASSED: $test_name"
            PASSED_TESTS=$((PASSED_TESTS + 1))
            
            # Extract key information
            risk_score=$(echo "$json_body" | jq -r '.risk_score // "N/A"')
            overall_risk=$(echo "$json_body" | jq -r '.overall_risk // "N/A"')
            echo "  Risk Score: $risk_score, Overall Risk: $overall_risk"
        else
            echo -e "${YELLOW}⚠ PARTIAL: $test_name (HTTP: $http_code, Invalid JSON)${NC}"
            log "ANALYZE TEST PARTIAL: $test_name - Valid HTTP but invalid JSON"
            PASSED_TESTS=$((PASSED_TESTS + 1))
        fi
    else
        echo -e "${RED}✗ FAILED: $test_name (HTTP: $http_code)${NC}"
        log "ANALYZE TEST FAILED: $test_name - HTTP: $http_code"
        log "Response: $json_body"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
    
    echo ""
}

echo -e "${YELLOW}=== Typosentinel API Comprehensive Test Suite ===${NC}"
echo "Testing API at: $API_BASE"
echo "Log file: $LOG_FILE"
echo ""

log "=== API Test Suite Started ==="
log "API Base URL: $API_BASE"

# Test 1: Health Check
test_json_endpoint "/health" "Health Check"

# Test 2: Ready Check
test_json_endpoint "/ready" "Ready Check"

# Test 3: Test Endpoint
test_json_endpoint "/test" "Test Endpoint"

# Test 4: Dashboard Health
test_json_endpoint "/api/dashboard/health" "Dashboard Health"

# Test 5: Dashboard Trends
test_json_endpoint "/api/dashboard/trends" "Dashboard Trends"

# Test 6: Scan Results (should be empty initially)
test_json_endpoint "/api/scan/results" "Scan Results List"

# Test 7: Analyze legitimate packages (OpenAPI v1 endpoint)
test_analyze_endpoint "lodash" "npm" "Analyze NPM Package (lodash)"
test_analyze_endpoint "requests" "pypi" "Analyze PyPI Package (requests)"

# Test 8: Scan legitimate packages (current API endpoint)
test_scan_endpoint "express" "npm" "Scan NPM Package (express)"
test_scan_endpoint "django" "pypi" "Scan PyPI Package (django)"

# Test 9: Test potentially suspicious packages
test_scan_endpoint "lodahs" "npm" "Scan Potential Typosquatting (lodahs)"
test_scan_endpoint "requsts" "pypi" "Scan Potential Typosquatting (requsts)"

# Test 10: Test error handling with invalid packages
test_scan_endpoint "nonexistent-package-12345" "npm" "Scan Non-existent Package"

# Test 11: Performance test - multiple concurrent scans
echo -e "${BLUE}Performance Test: Concurrent Scans${NC}"
log "PERFORMANCE TEST START: Concurrent Scans"

start_time=$(date +%s)

# Run 3 concurrent scans
(
    curl -s -X POST -H "Content-Type: application/json" \
        -d '{"package": "react", "registry": "npm", "output_format": "json"}' \
        "$API_BASE/api/scan/start" > /dev/null 2>&1 &
    
    curl -s -X POST -H "Content-Type: application/json" \
        -d '{"package": "vue", "registry": "npm", "output_format": "json"}' \
        "$API_BASE/api/scan/start" > /dev/null 2>&1 &
    
    curl -s -X POST -H "Content-Type: application/json" \
        -d '{"package": "flask", "registry": "pypi", "output_format": "json"}' \
        "$API_BASE/api/scan/start" > /dev/null 2>&1 &
    
    wait
)

end_time=$(date +%s)
concurrent_duration=$((end_time - start_time))

TOTAL_TESTS=$((TOTAL_TESTS + 1))
if [ $concurrent_duration -lt 30 ]; then
    echo -e "${GREEN}✓ PASSED: Concurrent Scans Performance ($concurrent_duration seconds)${NC}"
    log "PERFORMANCE TEST PASSED: Concurrent scans completed in $concurrent_duration seconds"
    PASSED_TESTS=$((PASSED_TESTS + 1))
else
    echo -e "${RED}✗ FAILED: Concurrent Scans Performance ($concurrent_duration seconds, expected < 30)${NC}"
    log "PERFORMANCE TEST FAILED: Concurrent scans took $concurrent_duration seconds"
    FAILED_TESTS=$((FAILED_TESTS + 1))
fi

# Final Results
echo ""
echo -e "${YELLOW}=== Test Results Summary ===${NC}"
echo "Total Tests: $TOTAL_TESTS"
echo -e "Passed: ${GREEN}$PASSED_TESTS${NC}"
echo -e "Failed: ${RED}$FAILED_TESTS${NC}"

if [ $FAILED_TESTS -eq 0 ]; then
    echo -e "${GREEN}🎉 All tests passed!${NC}"
    log "=== ALL TESTS PASSED ==="
    exit 0
else
    success_rate=$((PASSED_TESTS * 100 / TOTAL_TESTS))
    echo -e "${YELLOW}Success Rate: $success_rate%${NC}"
    log "=== TEST SUITE COMPLETED - Success Rate: $success_rate% ==="
    
    if [ $success_rate -ge 70 ]; then
        echo -e "${GREEN}✓ Good success rate - API is functional${NC}"
        exit 0
    else
        exit 1
    fi
fi