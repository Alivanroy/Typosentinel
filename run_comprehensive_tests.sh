#!/bin/bash

# Comprehensive Typosentinel Test Suite
# This script runs various tests and generates a detailed report

set -e

echo "=== Typosentinel Comprehensive Test Suite ==="
echo "Started at: $(date)"
echo ""

# Test configuration
BINARY="./typosentinel"
REPORT_FILE="comprehensive_test_report.md"
JSON_RESULTS="test_results.json"

# Initialize report
cat > "$REPORT_FILE" << EOF
# Typosentinel Comprehensive Test Report

**Generated:** $(date)
**Test Environment:** $(uname -a)
**Binary Version:** $($BINARY --version 2>/dev/null || echo "Unknown")

## Test Results Summary

EOF

# Initialize JSON results
echo '{"test_results": [], "summary": {}}' > "$JSON_RESULTS"

# Test counters
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Function to run a test and record results
run_test() {
    local test_name="$1"
    local package_name="$2"
    local registry="$3"
    local expected_risk="$4"
    local description="$5"
    
    echo "Testing: $test_name ($package_name on $registry)"
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    # Run the scan
    local start_time=$(date +%s.%N)
    local output
    local exit_code=0
    
    output=$("$BINARY" scan "$package_name" -r "$registry" -f json 2>&1) || exit_code=$?
    local end_time=$(date +%s.%N)
    local duration=$(echo "$end_time - $start_time" | bc -l 2>/dev/null || echo "0")
    
    # Parse results
    local risk_score="N/A"
    local overall_risk="N/A"
    local status="FAIL"
    
    # Handle both successful scans (exit 0) and high-risk detections (exit 2)
    if [ $exit_code -eq 0 ] || [ $exit_code -eq 2 ]; then
        # Extract risk score and overall risk from JSON
        risk_score=$(echo "$output" | grep -o '"risk_score": [0-9.]*' | cut -d' ' -f2 | head -1 || echo "0")
        overall_risk=$(echo "$output" | grep -o '"overall_risk": "[^"]*"' | cut -d'"' -f4 | head -1 || echo "unknown")
        
        # Determine if test passed based on expected risk
        case "$expected_risk" in
            "low")
                if (( $(echo "$risk_score < 0.4" | bc -l 2>/dev/null || echo 0) )); then
                    status="PASS"
                    PASSED_TESTS=$((PASSED_TESTS + 1))
                else
                    FAILED_TESTS=$((FAILED_TESTS + 1))
                fi
                ;;
            "medium")
                if (( $(echo "$risk_score >= 0.4 && $risk_score < 0.7" | bc -l 2>/dev/null || echo 0) )); then
                    status="PASS"
                    PASSED_TESTS=$((PASSED_TESTS + 1))
                else
                    FAILED_TESTS=$((FAILED_TESTS + 1))
                fi
                ;;
            "high")
                if (( $(echo "$risk_score >= 0.7" | bc -l 2>/dev/null || echo 0) )); then
                    status="PASS"
                    PASSED_TESTS=$((PASSED_TESTS + 1))
                else
                    FAILED_TESTS=$((FAILED_TESTS + 1))
                fi
                ;;
            *)
                # For any scan, just check if it completed successfully
                status="PASS"
                PASSED_TESTS=$((PASSED_TESTS + 1))
                ;;
        esac
    else
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
    
    # Add to report
    cat >> "$REPORT_FILE" << EOF
### $test_name

- **Package:** $package_name ($registry)
- **Description:** $description
- **Expected Risk:** $expected_risk
- **Status:** $status
- **Risk Score:** $risk_score
- **Overall Risk:** $overall_risk
- **Duration:** ${duration}s
- **Exit Code:** $exit_code

EOF
    
    if [ "$status" = "FAIL" ]; then
        cat >> "$REPORT_FILE" << EOF
**Error Output:**
\`\`\`
$output
\`\`\`

EOF
    fi
    
    echo "  Result: $status (Risk: $risk_score, Overall: $overall_risk)"
    echo ""
}

# Test legitimate packages (should have low risk)
echo "=== Testing Legitimate Packages ==="
run_test "Legitimate NPM - lodash" "lodash" "npm" "low" "Popular utility library"
run_test "Legitimate NPM - react" "react" "npm" "low" "Popular UI framework"
run_test "Legitimate NPM - express" "express" "npm" "low" "Popular web framework"
run_test "Legitimate PyPI - requests" "requests" "pypi" "low" "Popular HTTP library"
run_test "Legitimate PyPI - numpy" "numpy" "pypi" "low" "Popular scientific computing library"
run_test "Legitimate PyPI - flask" "flask" "pypi" "low" "Popular web framework"

# Test potential typosquatting (should have higher risk)
echo "=== Testing Potential Typosquatting ==="
run_test "Typosquat - lodahs" "lodahs" "npm" "high" "Potential typosquat of lodash"
run_test "Typosquat - recat" "recat" "npm" "high" "Potential typosquat of react"
run_test "Typosquat - expresss" "expresss" "npm" "high" "Potential typosquat of express"
run_test "Typosquat - reqeusts" "reqeusts" "pypi" "high" "Potential typosquat of requests"
run_test "Typosquat - nmupy" "nmupy" "pypi" "high" "Potential typosquat of numpy"

# Test CLI functionality
echo "=== Testing CLI Functionality ==="
echo "Testing CLI help command..."
if "$BINARY" --help > /dev/null 2>&1; then
    echo "  CLI Help: PASS"
    PASSED_TESTS=$((PASSED_TESTS + 1))
else
    echo "  CLI Help: FAIL"
    FAILED_TESTS=$((FAILED_TESTS + 1))
fi
TOTAL_TESTS=$((TOTAL_TESTS + 1))

echo "Testing scan help command..."
if "$BINARY" scan --help > /dev/null 2>&1; then
    echo "  Scan Help: PASS"
    PASSED_TESTS=$((PASSED_TESTS + 1))
else
    echo "  Scan Help: FAIL"
    FAILED_TESTS=$((FAILED_TESTS + 1))
fi
TOTAL_TESTS=$((TOTAL_TESTS + 1))

# Test different output formats
echo "=== Testing Output Formats ==="
for format in json yaml text table; do
    echo "Testing $format format..."
    if "$BINARY" scan lodash -r npm -f "$format" > /dev/null 2>&1; then
        echo "  Format $format: PASS"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        echo "  Format $format: FAIL"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
done

# Calculate pass rate
PASS_RATE=$(echo "scale=1; $PASSED_TESTS * 100 / $TOTAL_TESTS" | bc -l 2>/dev/null || echo "0")

# Add summary to report
cat >> "$REPORT_FILE" << EOF

## Summary

- **Total Tests:** $TOTAL_TESTS
- **Passed:** $PASSED_TESTS
- **Failed:** $FAILED_TESTS
- **Pass Rate:** ${PASS_RATE}%
- **Test Duration:** $(date)

## Recommendations

EOF

if [ $FAILED_TESTS -eq 0 ]; then
    cat >> "$REPORT_FILE" << EOF
✅ **All tests passed!** Typosentinel is functioning correctly.

- The detection engine is working properly
- CLI interface is responsive
- All output formats are supported
- Risk scoring appears accurate
EOF
else
    cat >> "$REPORT_FILE" << EOF
⚠️ **Some tests failed.** Review the following:

- Check if failed packages actually exist in their registries
- Verify network connectivity for package lookups
- Review risk scoring thresholds
- Consider updating threat detection algorithms
EOF
fi

cat >> "$REPORT_FILE" << EOF

## Next Steps

1. **Review Failed Tests:** Investigate any failed tests to understand root causes
2. **Tune Detection:** Adjust risk scoring algorithms based on test results
3. **Expand Coverage:** Add more test cases for edge cases and new threat patterns
4. **Performance Testing:** Conduct load testing with larger package sets
5. **Integration Testing:** Test with real-world CI/CD pipelines

---
*Report generated by Typosentinel Test Suite*
EOF

# Final summary
echo "=== Test Suite Complete ==="
echo "Total Tests: $TOTAL_TESTS"
echo "Passed: $PASSED_TESTS"
echo "Failed: $FAILED_TESTS"
echo "Pass Rate: ${PASS_RATE}%"
echo ""
echo "Detailed report saved to: $REPORT_FILE"
echo "Completed at: $(date)"

# Exit with appropriate code
if [ $FAILED_TESTS -eq 0 ]; then
    echo "🎉 All tests passed!"
    exit 0
else
    echo "⚠️ Some tests failed. Check the report for details."
    exit 1
fi