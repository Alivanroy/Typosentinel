#!/bin/bash
# Simple Typosentinel Test Script

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
TYPOSENTINEL_BINARY="./typosentinel"
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

# Test 1: Binary validation
test_binary_exists() {
    log "\n${BLUE}Test Category: Binary Validation${NC}"
    
    if [ -x "$TYPOSENTINEL_BINARY" ]; then
        record_test "Binary exists and is executable" "PASS"
        
        # Test version command
        if version=$($TYPOSENTINEL_BINARY --version 2>&1); then
            record_test "Version command" "PASS" "$version"
        else
            record_test "Version command" "FAIL" "Version command failed"
        fi
    else
        record_test "Binary exists and is executable" "FAIL" "Binary not found at $TYPOSENTINEL_BINARY"
        return 1
    fi
}

# Test 2: Basic package scanning
test_basic_scanning() {
    log "\n${BLUE}Test Category: Basic Package Scanning${NC}"
    
    # Test legitimate package (should have low risk score)
    if output=$($TYPOSENTINEL_BINARY scan lodash 2>&1); then
        if echo "$output" | grep -q '"risk_score"'; then
            risk_score=$(echo "$output" | grep '"risk_score"' | head -1 | sed 's/.*"risk_score": *\([0-9.]*\).*/\1/')
            if (( $(echo "$risk_score < 0.3" | bc -l 2>/dev/null || echo 0) )); then
                record_test "Legitimate package scan (lodash)" "PASS" "Risk score: $risk_score"
            else
                record_test "Legitimate package scan (lodash)" "FAIL" "Risk score too high: $risk_score"
            fi
        else
            record_test "Legitimate package scan (lodash)" "FAIL" "No risk score in output"
        fi
    else
        record_test "Legitimate package scan (lodash)" "FAIL" "Scan command failed"
    fi
    
    # Test another legitimate package
    if output=$($TYPOSENTINEL_BINARY scan express 2>&1); then
        if echo "$output" | grep -q '"risk_score"'; then
            record_test "Legitimate package scan (express)" "PASS"
        else
            record_test "Legitimate package scan (express)" "FAIL" "No risk score in output"
        fi
    else
        record_test "Legitimate package scan (express)" "FAIL" "Scan command failed"
    fi
}

# Test 3: Output formats
test_output_formats() {
    log "\n${BLUE}Test Category: Output Formats${NC}"
    
    # Test JSON output (default)
    if output=$($TYPOSENTINEL_BINARY scan lodash 2>&1); then
        if echo "$output" | grep -q '{'; then
            record_test "JSON output format" "PASS"
        else
            record_test "JSON output format" "FAIL" "Output doesn't appear to be JSON"
        fi
    else
        record_test "JSON output format" "FAIL" "Scan command failed"
    fi
}

# Test 4: Performance test
test_performance() {
    log "\n${BLUE}Test Category: Performance${NC}"
    
    # Single package scan time
    start_time=$(date +%s)
    if $TYPOSENTINEL_BINARY scan lodash > /dev/null 2>&1; then
        end_time=$(date +%s)
        scan_time=$((end_time - start_time))
        
        if [ $scan_time -lt 10 ]; then
            record_test "Single package scan time" "PASS" "Time: ${scan_time}s"
        else
            record_test "Single package scan time" "FAIL" "Too slow: ${scan_time}s (expected < 10s)"
        fi
    else
        record_test "Single package scan time" "FAIL" "Scan command failed"
    fi
}

# Main execution
main() {
    log "${YELLOW}🚀 Starting Typosentinel Simple Test Suite${NC}"
    log "${YELLOW}=============================================${NC}"
    
    test_binary_exists
    test_basic_scanning
    test_output_formats
    test_performance
    
    # Final report
    log "\n${YELLOW}📊 Test Summary${NC}"
    log "${YELLOW}===============${NC}"
    log "Total Tests: $TOTAL_TESTS"
    log "${GREEN}Passed: $PASSED_TESTS${NC}"
    log "${RED}Failed: $FAILED_TESTS${NC}"
    
    if [ $FAILED_TESTS -eq 0 ]; then
        log "\n${GREEN}🎉 All tests passed!${NC}"
        exit 0
    else
        log "\n${RED}❌ Some tests failed.${NC}"
        exit 1
    fi
}

# Run main function
main "$@"