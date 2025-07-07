#!/bin/bash
# Typosentinel Comprehensive Test Runner
# This script runs all test categories and generates a detailed report

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
TYPOSENTINEL_BINARY="./typosentinel"
TEST_DIR="./tests"
RESULTS_DIR="./test_results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_FILE="$RESULTS_DIR/test_report_$TIMESTAMP.md"

# Ensure directories exist
mkdir -p "$RESULTS_DIR"
mkdir -p "$TEST_DIR/data"

# Test counters
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Logging function
log() {
    echo -e "$1" | tee -a "$REPORT_FILE"
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
    else
        FAILED_TESTS=$((FAILED_TESTS + 1))
        log "${RED}❌ FAIL${NC}: $test_name"
        log "   Details: $details"
    fi
}

# Initialize report
initialize_report() {
    cat > "$REPORT_FILE" << EOF
# Typosentinel Test Report
Generated: $(date)
Binary: $TYPOSENTINEL_BINARY

## Test Summary

EOF
}

# Test 1: Binary validation
test_binary_exists() {
    log "\n${BLUE}Test Category: Binary Validation${NC}"
    
    if [ -x "$TYPOSENTINEL_BINARY" ]; then
        record_test "Binary exists and is executable" "PASS"
        
        # Test version command
        if $TYPOSENTINEL_BINARY --version &> /dev/null; then
            version=$($TYPOSENTINEL_BINARY --version)
            record_test "Version command" "PASS" "Version: $version"
        else
            record_test "Version command" "FAIL" "Version command failed"
        fi
    else
        record_test "Binary exists and is executable" "FAIL" "Binary not found at $TYPOSENTINEL_BINARY"
        return 1
    fi
}

# Test 2: Known typosquatting packages
test_known_typosquatting() {
    log "\n${BLUE}Test Category: Known Typosquatting Detection${NC}"
    
    # NPM typosquatting tests
    local npm_typos=("lodahs" "expres" "reacr" "axois" "momnet" "gulp-uglifys" "node-sass2")
    
    for package in "${npm_typos[@]}"; do
        output=$($TYPOSENTINEL_BINARY scan --package "$package" --package-manager npm -o json 2>&1)
        if echo "$output" | jq -e '.risk_score > 0.7' &> /dev/null; then
            record_test "NPM typosquatting: $package" "PASS"
        else
            record_test "NPM typosquatting: $package" "FAIL" "Risk score too low or scan failed"
        fi
    done
    
    # PyPI typosquatting tests
    local pypi_typos=("requets" "numpi" "beautifoulsoup" "tenserflow" "djangp")
    
    for package in "${pypi_typos[@]}"; do
        output=$($TYPOSENTINEL_BINARY scan --package "$package" --package-manager pypi -o json 2>&1)
        if echo "$output" | jq -e '.risk_score > 0.7' &> /dev/null; then
            record_test "PyPI typosquatting: $package" "PASS"
        else
            record_test "PyPI typosquatting: $package" "FAIL" "Risk score too low or scan failed"
        fi
    done
}

# Test 3: Legitimate packages (false positive check)
test_legitimate_packages() {
    log "\n${BLUE}Test Category: Legitimate Package Detection${NC}"
    
    local legit_packages=("npm:lodash" "npm:express" "npm:react" "pypi:requests" "pypi:numpy" "pypi:django")
    
    for pkg_spec in "${legit_packages[@]}"; do
        IFS=':' read -r pm package <<< "$pkg_spec"
        output=$($TYPOSENTINEL_BINARY scan --package "$package" --package-manager "$pm" -o json 2>&1)
        
        if echo "$output" | jq -e '.risk_score < 0.3' &> /dev/null; then
            record_test "Legitimate package: $pkg_spec" "PASS"
        else
            risk_score=$(echo "$output" | jq -r '.risk_score // "N/A"')
            record_test "Legitimate package: $pkg_spec" "FAIL" "Risk score too high: $risk_score"
        fi
    done
}

# Test 4: CLI functionality
test_cli_functionality() {
    log "\n${BLUE}Test Category: CLI Functionality${NC}"
    
    # Test help command
    if $TYPOSENTINEL_BINARY --help &> /dev/null; then
        record_test "Help command" "PASS"
    else
        record_test "Help command" "FAIL" "Help command failed"
    fi
    
    # Test different output formats
    for format in json yaml csv sarif; do
        if $TYPOSENTINEL_BINARY scan --package lodash --package-manager npm -o "$format" &> /dev/null; then
            record_test "Output format: $format" "PASS"
        else
            record_test "Output format: $format" "FAIL" "Format not supported or command failed"
        fi
    done
    
    # Test configuration file
    cat > "$TEST_DIR/test_config.yaml" << EOF
log_level: debug
cache:
  enabled: true
  ttl: 3600
ml:
  enabled: true
  threshold: 0.8
EOF
    
    if $TYPOSENTINEL_BINARY scan --package test --config "$TEST_DIR/test_config.yaml" &> /dev/null; then
        record_test "Configuration file loading" "PASS"
    else
        record_test "Configuration file loading" "FAIL" "Failed to load config file"
    fi
}

# Test 5: Performance benchmarks
test_performance() {
    log "\n${BLUE}Test Category: Performance Benchmarks${NC}"
    
    # Single package scan time
    start_time=$(date +%s.%N)
    $TYPOSENTINEL_BINARY scan --package express --package-manager npm -o json &> /dev/null
    end_time=$(date +%s.%N)
    scan_time=$(echo "$end_time - $start_time" | bc)
    
    if (( $(echo "$scan_time < 2.0" | bc -l) )); then
        record_test "Single package scan time" "PASS" "Time: ${scan_time}s"
    else
        record_test "Single package scan time" "FAIL" "Too slow: ${scan_time}s (expected < 2s)"
    fi
    
    # Bulk scan performance
    cat > "$TEST_DIR/bulk_packages.txt" << EOF
lodash
express
react
axios
moment
jquery
webpack
babel-core
typescript
vue
EOF
    
    start_time=$(date +%s.%N)
    $TYPOSENTINEL_BINARY scan --package-file "$TEST_DIR/bulk_packages.txt" --package-manager npm -o json &> /dev/null
    end_time=$(date +%s.%N)
    bulk_time=$(echo "$end_time - $start_time" | bc)
    
    if (( $(echo "$bulk_time < 10.0" | bc -l) )); then
        record_test "Bulk scan (10 packages)" "PASS" "Time: ${bulk_time}s"
    else
        record_test "Bulk scan (10 packages)" "FAIL" "Too slow: ${bulk_time}s (expected < 10s)"
    fi
}

# Test 6: API functionality
test_api_functionality() {
    log "\n${BLUE}Test Category: API Functionality${NC}"
    
    # Start API server
    $TYPOSENTINEL_BINARY serve --port 8080 &> "$RESULTS_DIR/api_server.log" &
    SERVER_PID=$!
    
    # Wait for server to start
    sleep 5
    
    # Test health endpoint
    if curl -s http://localhost:8080/health | grep -q "ok"; then
        record_test "API health endpoint" "PASS"
    else
        record_test "API health endpoint" "FAIL" "Server not responding"
    fi
    
    # Test scan endpoint
    response=$(curl -s -X POST http://localhost:8080/api/v1/scan \
        -H "Content-Type: application/json" \
        -d '{"packages": ["lodash"], "package_manager": "npm"}')
    
    if echo "$response" | jq -e '.scan_id' &> /dev/null; then
        record_test "API scan endpoint" "PASS"
    else
        record_test "API scan endpoint" "FAIL" "Invalid response"
    fi
    
    # Clean up
    kill $SERVER_PID 2>/dev/null || true
}

# Test 7: Project scanning
test_project_scanning() {
    log "\n${BLUE}Test Category: Project Scanning${NC}"
    
    # Create test project
    mkdir -p "$TEST_DIR/test_project"
    
    # Create package.json
    cat > "$TEST_DIR/test_project/package.json" << EOF
{
  "name": "test-project",
  "version": "1.0.0",
  "dependencies": {
    "lodash": "^4.17.21",
    "express": "^4.18.0",
    "axios": "^1.4.0"
  },
  "devDependencies": {
    "jest": "^29.0.0",
    "eslint": "^8.0.0"
  }
}
EOF
    
    # Create requirements.txt
    cat > "$TEST_DIR/test_project/requirements.txt" << EOF
requests==2.28.0
numpy==1.24.0
django==4.2.0
pandas==2.0.0
EOF
    
    # Scan project
    output=$($TYPOSENTINEL_BINARY scan --project-path "$TEST_DIR/test_project" -o json 2>&1)
    
    if echo "$output" | jq -e '.packages | length > 0' &> /dev/null; then
        pkg_count=$(echo "$output" | jq '.packages | length')
        record_test "Project scanning" "PASS" "Found $pkg_count packages"
    else
        record_test "Project scanning" "FAIL" "No packages found"
    fi
}

# Generate final report
generate_final_report() {
    log "\n${BLUE}=== FINAL TEST SUMMARY ===${NC}"
    log "Total Tests: $TOTAL_TESTS"
    log "${GREEN}Passed: $PASSED_TESTS${NC}"
    log "${RED}Failed: $FAILED_TESTS${NC}"
    
    success_rate=$(( PASSED_TESTS * 100 / TOTAL_TESTS ))
    log "Success Rate: $success_rate%"
    
    if [ $FAILED_TESTS -eq 0 ]; then
        log "\n${GREEN}🎉 ALL TESTS PASSED!${NC}"
        log "Typosentinel is ready for deployment!"
    else
        log "\n${YELLOW}⚠️  Some tests failed. Please review the report.${NC}"
    fi
    
    log "\nDetailed report saved to: $REPORT_FILE"
}

# Main execution
main() {
    log "${BLUE}🚀 Starting Typosentinel Comprehensive Test Suite${NC}"
    log "=================================================="
    
    initialize_report
    
    # Check if binary exists
    if [ ! -f "$TYPOSENTINEL_BINARY" ]; then
        log "${RED}❌ Typosentinel binary not found: $TYPOSENTINEL_BINARY${NC}"
        log "Please build the binary first: make build"
        exit 1
    fi
    
    # Run all test categories
    test_binary_exists
    test_known_typosquatting
    test_legitimate_packages
    test_cli_functionality
    test_performance
    test_api_functionality
    test_project_scanning
    
    # Generate final report
    generate_final_report
    
    # Exit with appropriate code
    if [ $FAILED_TESTS -eq 0 ]; then
        exit 0
    else
        exit 1
    fi
}

# Run main function
main "$@"