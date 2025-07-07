#!/bin/bash
# API Test Script for Typosentinel Server

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
API_BASE_URL="http://localhost:9090"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RESULTS_DIR="./test_results"

# Ensure results directory exists
mkdir -p "$RESULTS_DIR"

# Test counters
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Logging function
log() {
    echo -e "$1"
}

# Test result function
record_test() {
    local test_name=$1
    local result=$2
    local details=$3
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    if [ "$result" = "PASS" ]; then
        PASSED_TESTS=$((PASSED_TESTS + 1))
        log "${GREEN}✅ PASS${NC}: $test_name"
        if [ -n "$details" ]; then
            log "   Details: $details"
        fi
    else
        FAILED_TESTS=$((FAILED_TESTS + 1))
        log "${RED}❌ FAIL${NC}: $test_name"
        if [ -n "$details" ]; then
            log "   Details: $details"
        fi
    fi
}

# Test API health endpoint
test_health_endpoint() {
    log "\n${BLUE}Test Category: API Health Check${NC}"
    
    if response=$(curl -s -w "%{http_code}" "$API_BASE_URL/health" 2>/dev/null); then
        http_code="${response: -3}"
        response_body="${response%???}"
        
        if [ "$http_code" = "200" ]; then
            record_test "Health endpoint" "PASS" "HTTP $http_code"
        else
            record_test "Health endpoint" "FAIL" "HTTP $http_code"
        fi
    else
        record_test "Health endpoint" "FAIL" "Connection failed"
    fi
}

# Test API scan endpoint
test_scan_endpoint() {
    log "\n${BLUE}Test Category: API Scan Functionality${NC}"
    
    # Test POST /api/scan/start
    scan_payload='{
        "package_name": "lodash",
        "package_manager": "npm",
        "output_format": "json"
    }'
    
    if response=$(curl -s -w "%{http_code}" -X POST \
        -H "Content-Type: application/json" \
        -d "$scan_payload" \
        "$API_BASE_URL/api/scan/start" 2>/dev/null); then
        
        http_code="${response: -3}"
        response_body="${response%???}"
        
        if [ "$http_code" = "200" ] || [ "$http_code" = "201" ]; then
            record_test "Scan start endpoint" "PASS" "HTTP $http_code"
            
            # Try to extract scan ID if available
            if echo "$response_body" | grep -q '"scan_id"'; then
                scan_id=$(echo "$response_body" | grep -o '"scan_id":"[^"]*"' | cut -d'"' -f4)
                record_test "Scan ID generation" "PASS" "ID: $scan_id"
            fi
        else
            record_test "Scan start endpoint" "FAIL" "HTTP $http_code"
        fi
    else
        record_test "Scan start endpoint" "FAIL" "Connection failed"
    fi
}

# Test API dashboard endpoints
test_dashboard_endpoints() {
    log "\n${BLUE}Test Category: Dashboard API Endpoints${NC}"
    
    # Test dashboard health
    if response=$(curl -s -w "%{http_code}" "$API_BASE_URL/api/dashboard/health" 2>/dev/null); then
        http_code="${response: -3}"
        
        if [ "$http_code" = "200" ]; then
            record_test "Dashboard health endpoint" "PASS" "HTTP $http_code"
        else
            record_test "Dashboard health endpoint" "FAIL" "HTTP $http_code"
        fi
    else
        record_test "Dashboard health endpoint" "FAIL" "Connection failed"
    fi
    
    # Test dashboard trends
    if response=$(curl -s -w "%{http_code}" "$API_BASE_URL/api/dashboard/trends" 2>/dev/null); then
        http_code="${response: -3}"
        
        if [ "$http_code" = "200" ]; then
            record_test "Dashboard trends endpoint" "PASS" "HTTP $http_code"
        else
            record_test "Dashboard trends endpoint" "FAIL" "HTTP $http_code"
        fi
    else
        record_test "Dashboard trends endpoint" "FAIL" "Connection failed"
    fi
}

# Test API scan results endpoint
test_scan_results_endpoint() {
    log "\n${BLUE}Test Category: Scan Results API${NC}"
    
    # Test GET /api/scan/results
    if response=$(curl -s -w "%{http_code}" "$API_BASE_URL/api/scan/results" 2>/dev/null); then
        http_code="${response: -3}"
        
        if [ "$http_code" = "200" ]; then
            record_test "Scan results endpoint" "PASS" "HTTP $http_code"
        else
            record_test "Scan results endpoint" "FAIL" "HTTP $http_code"
        fi
    else
        record_test "Scan results endpoint" "FAIL" "Connection failed"
    fi
}

# Test API response format
test_api_response_format() {
    log "\n${BLUE}Test Category: API Response Format${NC}"
    
    # Test JSON response format
    if response=$(curl -s "$API_BASE_URL/health" 2>/dev/null); then
        if echo "$response" | jq . >/dev/null 2>&1; then
            record_test "JSON response format" "PASS" "Valid JSON"
        else
            record_test "JSON response format" "FAIL" "Invalid JSON"
        fi
    else
        record_test "JSON response format" "FAIL" "No response"
    fi
}

# Test API performance
test_api_performance() {
    log "\n${BLUE}Test Category: API Performance${NC}"
    
    # Test response time
    start_time=$(date +%s.%N)
    if curl -s "$API_BASE_URL/health" >/dev/null 2>&1; then
        end_time=$(date +%s.%N)
        response_time=$(echo "$end_time - $start_time" | bc)
        
        if (( $(echo "$response_time < 1.0" | bc -l) )); then
            record_test "API response time" "PASS" "Time: ${response_time}s"
        else
            record_test "API response time" "FAIL" "Too slow: ${response_time}s"
        fi
    else
        record_test "API response time" "FAIL" "Request failed"
    fi
}

# Main execution
main() {
    log "${YELLOW}🚀 Starting Typosentinel API Test Suite${NC}"
    log "${YELLOW}=======================================${NC}"
    log "Testing API at: $API_BASE_URL"
    
    # Wait a moment for server to be fully ready
    sleep 2
    
    test_health_endpoint
    test_api_response_format
    test_api_performance
    test_dashboard_endpoints
    test_scan_endpoint
    test_scan_results_endpoint
    
    # Final report
    log "\n${YELLOW}📊 API Test Summary${NC}"
    log "${YELLOW}===================${NC}"
    log "Total Tests: $TOTAL_TESTS"
    log "${GREEN}Passed: $PASSED_TESTS${NC}"
    log "${RED}Failed: $FAILED_TESTS${NC}"
    
    success_rate=$((PASSED_TESTS * 100 / TOTAL_TESTS))
    log "Success Rate: ${success_rate}%"
    
    # Save results to file
    echo "API Test Results - $(date)" > "$RESULTS_DIR/api_test_$TIMESTAMP.txt"
    echo "API Base URL: $API_BASE_URL" >> "$RESULTS_DIR/api_test_$TIMESTAMP.txt"
    echo "Total Tests: $TOTAL_TESTS" >> "$RESULTS_DIR/api_test_$TIMESTAMP.txt"
    echo "Passed: $PASSED_TESTS" >> "$RESULTS_DIR/api_test_$TIMESTAMP.txt"
    echo "Failed: $FAILED_TESTS" >> "$RESULTS_DIR/api_test_$TIMESTAMP.txt"
    echo "Success Rate: ${success_rate}%" >> "$RESULTS_DIR/api_test_$TIMESTAMP.txt"
    
    if [ $FAILED_TESTS -eq 0 ]; then
        log "\n${GREEN}🎉 All API tests passed!${NC}"
        log "Results saved to: $RESULTS_DIR/api_test_$TIMESTAMP.txt"
        exit 0
    else
        log "\n${YELLOW}⚠️  Some API tests failed.${NC}"
        log "Results saved to: $RESULTS_DIR/api_test_$TIMESTAMP.txt"
        exit 1
    fi
}

# Run main function
main "$@"