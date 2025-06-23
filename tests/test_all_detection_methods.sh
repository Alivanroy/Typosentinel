#!/bin/bash

# TypoSentinel Comprehensive Detection Method Testing Script
# This script tests all available detection methods and engines

set -e

echo "🔍 TypoSentinel - Comprehensive Detection Method Testing"
echo "======================================================"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test results tracking
TEST_COUNT=0
PASS_COUNT=0
FAIL_COUNT=0
RESULTS_DIR="test_results_$(date +%Y%m%d_%H%M%S)"

# Create results directory
mkdir -p "$RESULTS_DIR"

# Function to run test and track results
run_test() {
    local test_name="$1"
    local command="$2"
    local expected_pattern="$3"
    
    echo -e "${BLUE}Testing: $test_name${NC}"
    echo "Command: $command"
    
    TEST_COUNT=$((TEST_COUNT + 1))
    
    # Run the command and capture output
    if output=$(eval "$command" 2>&1); then
        # Save output to file
        echo "$output" > "$RESULTS_DIR/${test_name// /_}.json"
        
        # Check if expected pattern is found (if provided)
        if [ -n "$expected_pattern" ]; then
            if echo "$output" | grep -q "$expected_pattern"; then
                echo -e "${GREEN}✓ PASS${NC}"
                PASS_COUNT=$((PASS_COUNT + 1))
            else
                echo -e "${RED}✗ FAIL - Expected pattern not found: $expected_pattern${NC}"
                FAIL_COUNT=$((FAIL_COUNT + 1))
            fi
        else
            echo -e "${GREEN}✓ PASS${NC}"
            PASS_COUNT=$((PASS_COUNT + 1))
        fi
    else
        echo -e "${RED}✗ FAIL - Command failed${NC}"
        echo "Error output: $output"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
    echo ""
}

# Build the application first
echo -e "${YELLOW}Building TypoSentinel...${NC}"
go build -o typosentinel
if [ $? -ne 0 ]; then
    echo -e "${RED}Failed to build TypoSentinel${NC}"
    exit 1
fi
echo -e "${GREEN}Build successful${NC}"
echo ""

# Test 1: Lexical Similarity Detection (Typosquatting)
echo -e "${YELLOW}=== 1. LEXICAL SIMILARITY DETECTION (TYPOSQUATTING) ===${NC}"
run_test "Typosquatting - lodahs vs lodash" \
    "./typosentinel scan lodahs --registry npm --format json --verbose" \
    "typosquatting"

run_test "Typosquatting - expres vs express" \
    "./typosentinel scan expres --registry npm --format json --verbose" \
    "typosquatting"

run_test "Typosquatting - reakt vs react" \
    "./typosentinel scan reakt --registry npm --format json --verbose" \
    "typosquatting"

run_test "Typosquatting - angualr vs angular" \
    "./typosentinel scan angualr --registry npm --format json --verbose" \
    "typosquatting"

run_test "Typosquatting - webpakc vs webpack" \
    "./typosentinel scan webpakc --registry npm --format json --verbose" \
    "typosquatting"

# Test 2: Homoglyph Detection
echo -e "${YELLOW}=== 2. HOMOGLYPH DETECTION ===${NC}"
run_test "Homoglyph - lodаsh (Cyrillic a)" \
    "./typosentinel scan lodаsh --registry npm --format json --verbose" \
    "homoglyph"

run_test "Homoglyph - еxpress (Cyrillic e)" \
    "./typosentinel scan еxpress --registry npm --format json --verbose" \
    "homoglyph"

run_test "Homoglyph - rеact (Cyrillic e)" \
    "./typosentinel scan rеact --registry npm --format json --verbose" \
    "homoglyph"

# Test 3: PyPI Package Detection
echo -e "${YELLOW}=== 3. PYPI PACKAGE DETECTION ===${NC}"
run_test "PyPI Typosquatting - reqeusts vs requests" \
    "./typosentinel scan reqeusts --registry pypi --format json --verbose" \
    "typosquatting"

run_test "PyPI Typosquatting - nmupy vs numpy" \
    "./typosentinel scan nmupy --registry pypi --format json --verbose" \
    "typosquatting"

run_test "PyPI Typosquatting - pandsa vs pandas" \
    "./typosentinel scan pandsa --registry pypi --format json --verbose" \
    "typosquatting"

run_test "PyPI Typosquatting - flaks vs flask" \
    "./typosentinel scan flaks --registry pypi --format json --verbose" \
    "typosquatting"

# Test 4: Enhanced Typosquatting Detection (Keyboard Layout)
echo -e "${YELLOW}=== 4. ENHANCED TYPOSQUATTING (KEYBOARD LAYOUT) ===${NC}"
run_test "Keyboard Layout - lodadh (adjacent keys)" \
    "./typosentinel scan lodadh --registry npm --format json --verbose" \
    "typosquatting"

run_test "Keyboard Layout - rxpress (adjacent keys)" \
    "./typosentinel scan rxpress --registry npm --format json --verbose" \
    "typosquatting"

# Test 5: Legitimate Packages (Should have low/no threats)
echo -e "${YELLOW}=== 5. LEGITIMATE PACKAGES (BASELINE) ===${NC}"
run_test "Legitimate - lodash" \
    "./typosentinel scan lodash --registry npm --format json --verbose"

run_test "Legitimate - express" \
    "./typosentinel scan express --registry npm --format json --verbose"

run_test "Legitimate - react" \
    "./typosentinel scan react --registry npm --format json --verbose"

run_test "Legitimate - requests (PyPI)" \
    "./typosentinel scan requests --registry pypi --format json --verbose"

run_test "Legitimate - numpy (PyPI)" \
    "./typosentinel scan numpy --registry pypi --format json --verbose"

# Test 6: Different Output Formats
echo -e "${YELLOW}=== 6. OUTPUT FORMAT TESTING ===${NC}"
run_test "JSON Output Format" \
    "./typosentinel scan lodahs --registry npm --format json" \
    "json"

run_test "Table Output Format" \
    "./typosentinel scan lodahs --registry npm --format table"

run_test "Compact Output Format" \
    "./typosentinel scan lodahs --registry npm --format compact"

# Test 7: Verbose and Debug Modes
echo -e "${YELLOW}=== 7. LOGGING AND DEBUG MODES ===${NC}"
run_test "Verbose Mode" \
    "./typosentinel scan lodahs --registry npm --verbose --format json"

run_test "Debug Mode" \
    "./typosentinel scan lodahs --registry npm --debug --format json"

run_test "Trace Mode" \
    "./typosentinel scan lodahs --registry npm --trace --format json"

# Test 8: Performance and Benchmarking
echo -e "${YELLOW}=== 8. PERFORMANCE TESTING ===${NC}"
run_test "Benchmark Command" \
    "./typosentinel benchmark --suite basic --duration 10s"

# Test 9: Configuration Testing
echo -e "${YELLOW}=== 9. CONFIGURATION TESTING ===${NC}"
run_test "Config Show" \
    "./typosentinel config show"

run_test "Config Validation" \
    "./typosentinel config validate"

# Test 10: Multiple Package Versions
echo -e "${YELLOW}=== 10. PACKAGE VERSION TESTING ===${NC}"
run_test "Specific Version - latest" \
    "./typosentinel scan lodahs --registry npm --pkg-version latest --format json"

run_test "Specific Version - 1.0.0" \
    "./typosentinel scan lodahs --registry npm --pkg-version 1.0.0 --format json"

# Test 11: Edge Cases
echo -e "${YELLOW}=== 11. EDGE CASES ===${NC}"
run_test "Very Short Package Name" \
    "./typosentinel scan a --registry npm --format json"

run_test "Very Long Package Name" \
    "./typosentinel scan very-long-package-name-that-might-cause-issues-with-detection-algorithms --registry npm --format json"

run_test "Package with Numbers" \
    "./typosentinel scan lodash4 --registry npm --format json"

run_test "Package with Special Characters" \
    "./typosentinel scan @types/lodash --registry npm --format json"

# Test 12: Error Handling
echo -e "${YELLOW}=== 12. ERROR HANDLING ===${NC}"
run_test "Invalid Registry" \
    "./typosentinel scan lodash --registry invalid --format json" \
    "error\|warning"

run_test "Empty Package Name" \
    "./typosentinel scan '' --registry npm --format json" \
    "error\|warning"

# Test 13: Concurrent Testing
echo -e "${YELLOW}=== 13. CONCURRENT TESTING ===${NC}"
run_test "Multiple Packages Simultaneously" \
    "./typosentinel scan lodahs expres reakt --registry npm --format json --parallel 3"

# Generate Summary Report
echo -e "${YELLOW}=== TEST SUMMARY ===${NC}"
echo "Total Tests: $TEST_COUNT"
echo -e "${GREEN}Passed: $PASS_COUNT${NC}"
echo -e "${RED}Failed: $FAIL_COUNT${NC}"
echo ""

if [ $FAIL_COUNT -eq 0 ]; then
    echo -e "${GREEN}🎉 All tests passed!${NC}"
    exit_code=0
else
    echo -e "${RED}❌ Some tests failed. Check the results in $RESULTS_DIR${NC}"
    exit_code=1
fi

# Generate detailed report
echo "Generating detailed report..."
cat > "$RESULTS_DIR/summary.txt" << EOF
TypoSentinel Detection Method Testing Summary
============================================
Test Date: $(date)
Total Tests: $TEST_COUNT
Passed: $PASS_COUNT
Failed: $FAIL_COUNT
Success Rate: $(echo "scale=2; $PASS_COUNT * 100 / $TEST_COUNT" | bc -l)%

Test Categories Covered:
- Lexical Similarity Detection (Typosquatting)
- Homoglyph Detection
- PyPI Package Detection
- Enhanced Typosquatting (Keyboard Layout)
- Legitimate Package Baseline
- Output Format Testing
- Logging and Debug Modes
- Performance Testing
- Configuration Testing
- Package Version Testing
- Edge Cases
- Error Handling
- Concurrent Testing

Results saved in: $RESULTS_DIR
EOF

echo -e "${BLUE}Detailed results saved in: $RESULTS_DIR${NC}"
echo -e "${BLUE}Summary report: $RESULTS_DIR/summary.txt${NC}"

exit $exit_code