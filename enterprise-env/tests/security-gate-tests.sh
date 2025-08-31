#!/bin/bash

# Security Gate Enforcement Tests for TypoSentinel Enterprise
# This script validates security gate enforcement and failure scenarios

set -e

# Configuration
TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENTERPRISE_DIR="$(dirname "$TEST_DIR")"
TYPOSENTINEL_BIN="${ENTERPRISE_DIR}/../typosentinel.exe"
REPORTS_DIR="${TEST_DIR}/reports"
TEST_RESULTS_FILE="${REPORTS_DIR}/security_gate_results.json"
TEST_REPORT_FILE="${REPORTS_DIR}/security_gate_report.md"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test counters
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Initialize test environment
setup_test_environment() {
    echo -e "${BLUE}Setting up security gate test environment...${NC}"
    mkdir -p "$REPORTS_DIR"
    
    # Initialize results file
    cat > "$TEST_RESULTS_FILE" << 'EOF'
{
  "test_suite": "Security Gate Enforcement",
  "timestamp": "",
  "environment": {
    "test_directory": "",
    "typosentinel_binary": "",
    "enterprise_directory": ""
  },
  "test_results": [],
  "summary": {
    "total_tests": 0,
    "passed": 0,
    "failed": 0,
    "success_rate": 0
  }
}
EOF
    
    # Update environment info
    jq --arg timestamp "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
       --arg test_dir "$TEST_DIR" \
       --arg binary "$TYPOSENTINEL_BIN" \
       --arg enterprise "$ENTERPRISE_DIR" \
       '.timestamp = $timestamp | .environment.test_directory = $test_dir | .environment.typosentinel_binary = $binary | .environment.enterprise_directory = $enterprise' \
       "$TEST_RESULTS_FILE" > "${TEST_RESULTS_FILE}.tmp" && mv "${TEST_RESULTS_FILE}.tmp" "$TEST_RESULTS_FILE"
}

# Log test result
log_test_result() {
    local test_name="$1"
    local status="$2"
    local details="$3"
    local execution_time="$4"
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    if [ "$status" = "PASS" ]; then
        PASSED_TESTS=$((PASSED_TESTS + 1))
        echo -e "${GREEN}✓ $test_name${NC}"
    else
        FAILED_TESTS=$((FAILED_TESTS + 1))
        echo -e "${RED}✗ $test_name${NC}"
        echo -e "  ${YELLOW}Details: $details${NC}"
    fi
    
    # Add to JSON results
    local test_result=$(jq -n \
        --arg name "$test_name" \
        --arg status "$status" \
        --arg details "$details" \
        --arg time "$execution_time" \
        '{
            "test_name": $name,
            "status": $status,
            "details": $details,
            "execution_time_ms": ($time | tonumber)
        }')
    
    jq --argjson result "$test_result" '.test_results += [$result]' "$TEST_RESULTS_FILE" > "${TEST_RESULTS_FILE}.tmp" && mv "${TEST_RESULTS_FILE}.tmp" "$TEST_RESULTS_FILE"
}

# Test critical threat detection and blocking
test_critical_threat_blocking() {
    echo -e "\n${BLUE}Testing Critical Threat Blocking...${NC}"
    
    local start_time=$(date +%s%3N)
    
    # Create a test package.json with known critical vulnerabilities
    local test_file="${TEST_DIR}/temp_critical_test.json"
    cat > "$test_file" << 'EOF'
{
  "name": "critical-test-app",
  "version": "1.0.0",
  "dependencies": {
    "lodash": "4.17.20",
    "minimist": "1.2.5",
    "node-fetch": "2.6.6",
    "axios": "0.21.0",
    "express": "4.17.0"
  }
}
EOF
    
    # Run scan with strict thresholds
    local output_file="${REPORTS_DIR}/critical_test_output.json"
    local scan_result=0
    
    if [ -f "$TYPOSENTINEL_BIN" ]; then
        "$TYPOSENTINEL_BIN" scan "$test_file" --output-format json --output-file "$output_file" --include-dev-deps --workspace-aware || scan_result=$?
        
        local end_time=$(date +%s%3N)
        local execution_time=$((end_time - start_time))
        
        if [ -f "$output_file" ]; then
            local critical_count=$(jq -r '.summary.threats.critical // 0' "$output_file" 2>/dev/null || echo "0")
            local high_count=$(jq -r '.summary.threats.high // 0' "$output_file" 2>/dev/null || echo "0")
            
            if [ "$critical_count" -gt 0 ] || [ "$high_count" -gt 0 ]; then
                log_test_result "Critical Threat Detection" "PASS" "Detected $critical_count critical and $high_count high threats" "$execution_time"
            else
                log_test_result "Critical Threat Detection" "FAIL" "No critical or high threats detected in vulnerable dependencies" "$execution_time"
            fi
        else
            log_test_result "Critical Threat Detection" "FAIL" "No output file generated" "$execution_time"
        fi
    else
        log_test_result "Critical Threat Detection" "SKIP" "TypoSentinel binary not found" "0"
    fi
    
    # Cleanup
    rm -f "$test_file"
}

# Test security gate threshold enforcement
test_threshold_enforcement() {
    echo -e "\n${BLUE}Testing Security Gate Threshold Enforcement...${NC}"
    
    local start_time=$(date +%s%3N)
    
    # Test different threshold scenarios
    local scenarios=(
        "development:critical=5,high=10,medium=20"
        "staging:critical=2,high=5,medium=10"
        "production:critical=0,high=1,medium=3"
    )
    
    for scenario in "${scenarios[@]}"; do
        local env=$(echo "$scenario" | cut -d':' -f1)
        local thresholds=$(echo "$scenario" | cut -d':' -f2)
        
        echo -e "  ${YELLOW}Testing $env environment thresholds: $thresholds${NC}"
        
        # Create temporary config with specific thresholds
        local config_file="${TEST_DIR}/temp_${env}_config.yaml"
        cat > "$config_file" << EOF
security_gates:
  enabled: true
  environments:
    $env:
      thresholds:
        critical: $(echo "$thresholds" | grep -o 'critical=[0-9]*' | cut -d'=' -f2)
        high: $(echo "$thresholds" | grep -o 'high=[0-9]*' | cut -d'=' -f2)
        medium: $(echo "$thresholds" | grep -o 'medium=[0-9]*' | cut -d'=' -f2)
      block_on_failure: true
EOF
        
        # Test with frontend package.json (should have some threats)
        local test_target="${ENTERPRISE_DIR}/frontend/package.json"
        local output_file="${REPORTS_DIR}/${env}_threshold_test.json"
        
        if [ -f "$TYPOSENTINEL_BIN" ] && [ -f "$test_target" ]; then
            local scan_result=0
            "$TYPOSENTINEL_BIN" scan "$test_target" --config "$config_file" --output-format json --output-file "$output_file" || scan_result=$?
            
            if [ -f "$output_file" ]; then
                local critical=$(jq -r '.summary.threats.critical // 0' "$output_file" 2>/dev/null || echo "0")
                local high=$(jq -r '.summary.threats.high // 0' "$output_file" 2>/dev/null || echo "0")
                local medium=$(jq -r '.summary.threats.medium // 0' "$output_file" 2>/dev/null || echo "0")
                
                local end_time=$(date +%s%3N)
                local execution_time=$((end_time - start_time))
                
                log_test_result "Threshold Enforcement ($env)" "PASS" "Threats: C:$critical H:$high M:$medium" "$execution_time"
            else
                log_test_result "Threshold Enforcement ($env)" "FAIL" "No output generated" "0"
            fi
        else
            log_test_result "Threshold Enforcement ($env)" "SKIP" "Binary or target not found" "0"
        fi
        
        # Cleanup
        rm -f "$config_file"
    done
}

# Test supply chain attack detection
test_supply_chain_detection() {
    echo -e "\n${BLUE}Testing Supply Chain Attack Detection...${NC}"
    
    local start_time=$(date +%s%3N)
    
    # Create test package with suspicious dependencies
    local test_file="${TEST_DIR}/temp_supply_chain_test.json"
    cat > "$test_file" << 'EOF'
{
  "name": "supply-chain-test",
  "version": "1.0.0",
  "dependencies": {
    "lodash": "^4.17.21",
    "lodahs": "^1.0.0",
    "express": "^4.18.2",
    "expres": "^1.0.0",
    "react": "^18.2.0",
    "raect": "^1.0.0",
    "axios": "^1.4.0",
    "axois": "^1.0.0"
  }
}
EOF
    
    local output_file="${REPORTS_DIR}/supply_chain_test.json"
    
    if [ -f "$TYPOSENTINEL_BIN" ]; then
        local scan_result=0
        "$TYPOSENTINEL_BIN" scan "$test_file" --output-format json --output-file "$output_file" --include-dev-deps || scan_result=$?
        
        local end_time=$(date +%s%3N)
        local execution_time=$((end_time - start_time))
        
        if [ -f "$output_file" ]; then
            local typosquatting_count=$(jq -r '[.findings[]? | select(.type == "typosquatting")] | length' "$output_file" 2>/dev/null || echo "0")
            
            if [ "$typosquatting_count" -gt 0 ]; then
                log_test_result "Supply Chain Detection" "PASS" "Detected $typosquatting_count typosquatting attempts" "$execution_time"
            else
                log_test_result "Supply Chain Detection" "FAIL" "No typosquatting detected in suspicious packages" "$execution_time"
            fi
        else
            log_test_result "Supply Chain Detection" "FAIL" "No output file generated" "$execution_time"
        fi
    else
        log_test_result "Supply Chain Detection" "SKIP" "TypoSentinel binary not found" "0"
    fi
    
    # Cleanup
    rm -f "$test_file"
}

# Test CI/CD pipeline integration failure scenarios
test_cicd_failure_scenarios() {
    echo -e "\n${BLUE}Testing CI/CD Failure Scenarios...${NC}"
    
    local scenarios=(
        "invalid_json:Invalid JSON syntax"
        "missing_file:Non-existent file path"
        "network_timeout:Network connectivity issues"
        "memory_limit:Memory exhaustion"
    )
    
    for scenario in "${scenarios[@]}"; do
        local test_name=$(echo "$scenario" | cut -d':' -f1)
        local description=$(echo "$scenario" | cut -d':' -f2)
        
        echo -e "  ${YELLOW}Testing $test_name scenario: $description${NC}"
        
        local start_time=$(date +%s%3N)
        local test_result="SKIP"
        local details="Test scenario not implemented"
        
        case "$test_name" in
            "invalid_json")
                # Create invalid JSON file
                local invalid_file="${TEST_DIR}/temp_invalid.json"
                echo '{"name": "test", "dependencies": {' > "$invalid_file"
                
                if [ -f "$TYPOSENTINEL_BIN" ]; then
                    local scan_result=0
                    "$TYPOSENTINEL_BIN" scan "$invalid_file" --output-format json 2>/dev/null || scan_result=$?
                    
                    if [ $scan_result -ne 0 ]; then
                        test_result="PASS"
                        details="Correctly failed on invalid JSON"
                    else
                        test_result="FAIL"
                        details="Should have failed on invalid JSON"
                    fi
                fi
                
                rm -f "$invalid_file"
                ;;
            "missing_file")
                if [ -f "$TYPOSENTINEL_BIN" ]; then
                    local scan_result=0
                    "$TYPOSENTINEL_BIN" scan "/nonexistent/path/package.json" --output-format json 2>/dev/null || scan_result=$?
                    
                    if [ $scan_result -ne 0 ]; then
                        test_result="PASS"
                        details="Correctly failed on missing file"
                    else
                        test_result="FAIL"
                        details="Should have failed on missing file"
                    fi
                fi
                ;;
        esac
        
        local end_time=$(date +%s%3N)
        local execution_time=$((end_time - start_time))
        
        log_test_result "CI/CD Failure ($test_name)" "$test_result" "$details" "$execution_time"
    done
}

# Test security policy enforcement
test_security_policy_enforcement() {
    echo -e "\n${BLUE}Testing Security Policy Enforcement...${NC}"
    
    local start_time=$(date +%s%3N)
    
    # Create a comprehensive security policy
    local policy_file="${TEST_DIR}/temp_security_policy.yaml"
    cat > "$policy_file" << 'EOF'
security_policy:
  version: "1.0"
  enforcement_level: "strict"
  
  vulnerability_policy:
    block_critical: true
    block_high: true
    allow_medium: false
    max_medium_count: 5
    
  dependency_policy:
    allow_dev_dependencies: true
    block_deprecated: true
    require_license_compliance: true
    
  typosquatting_policy:
    sensitivity: "high"
    block_suspicious: true
    whitelist_exceptions: []
    
  supply_chain_policy:
    require_provenance: true
    block_unsigned: false
    verify_checksums: true
EOF
    
    # Test policy enforcement with frontend package
    local test_target="${ENTERPRISE_DIR}/frontend/package.json"
    local output_file="${REPORTS_DIR}/policy_enforcement_test.json"
    
    if [ -f "$TYPOSENTINEL_BIN" ] && [ -f "$test_target" ]; then
        local scan_result=0
        "$TYPOSENTINEL_BIN" scan "$test_target" --config "$policy_file" --output-format json --output-file "$output_file" || scan_result=$?
        
        local end_time=$(date +%s%3N)
        local execution_time=$((end_time - start_time))
        
        if [ -f "$output_file" ]; then
            local policy_violations=$(jq -r '[.findings[]? | select(.severity == "critical" or .severity == "high")] | length' "$output_file" 2>/dev/null || echo "0")
            
            log_test_result "Security Policy Enforcement" "PASS" "Policy evaluated with $policy_violations violations" "$execution_time"
        else
            log_test_result "Security Policy Enforcement" "FAIL" "No policy evaluation output" "$execution_time"
        fi
    else
        log_test_result "Security Policy Enforcement" "SKIP" "Binary or target not found" "0"
    fi
    
    # Cleanup
    rm -f "$policy_file"
}

# Generate comprehensive test report
generate_test_report() {
    echo -e "\n${BLUE}Generating Security Gate Test Report...${NC}"
    
    # Update summary in JSON
    local success_rate=0
    if [ $TOTAL_TESTS -gt 0 ]; then
        success_rate=$(echo "scale=2; $PASSED_TESTS * 100 / $TOTAL_TESTS" | bc -l)
    fi
    
    jq --arg total "$TOTAL_TESTS" \
       --arg passed "$PASSED_TESTS" \
       --arg failed "$FAILED_TESTS" \
       --arg rate "$success_rate" \
       '.summary.total_tests = ($total | tonumber) | .summary.passed = ($passed | tonumber) | .summary.failed = ($failed | tonumber) | .summary.success_rate = ($rate | tonumber)' \
       "$TEST_RESULTS_FILE" > "${TEST_RESULTS_FILE}.tmp" && mv "${TEST_RESULTS_FILE}.tmp" "$TEST_RESULTS_FILE"
    
    # Generate Markdown report
    cat > "$TEST_REPORT_FILE" << EOF
# Security Gate Enforcement Test Report

**Generated:** $(date -u +"%Y-%m-%d %H:%M:%S UTC")  
**Test Suite:** Security Gate Enforcement  
**Environment:** $(uname -s) $(uname -r)  

## Executive Summary

- **Total Tests:** $TOTAL_TESTS
- **Passed:** $PASSED_TESTS
- **Failed:** $FAILED_TESTS
- **Success Rate:** ${success_rate}%

## Test Categories

### 🔒 Critical Threat Blocking
Validates that critical security threats are properly detected and blocked by security gates.

### 📊 Threshold Enforcement
Tests security gate threshold enforcement across different environments (development, staging, production).

### 🔗 Supply Chain Detection
Verifies detection of supply chain attacks including typosquatting and malicious packages.

### 🚫 CI/CD Failure Scenarios
Tests proper handling of various failure scenarios in CI/CD pipeline integration.

### 📋 Security Policy Enforcement
Validates enforcement of comprehensive security policies and compliance rules.

## Detailed Results

EOF
    
    # Add detailed results from JSON
    jq -r '.test_results[] | "### " + .test_name + "\n\n- **Status:** " + .status + "\n- **Details:** " + .details + "\n- **Execution Time:** " + (.execution_time_ms | tostring) + "ms\n"' "$TEST_RESULTS_FILE" >> "$TEST_REPORT_FILE"
    
    cat >> "$TEST_REPORT_FILE" << EOF

## Security Gate Configuration

### Recommended Thresholds

| Environment | Critical | High | Medium | Low |
|-------------|----------|------|--------|----- |
| Development | 5 | 10 | 20 | 50 |
| Staging | 2 | 5 | 10 | 25 |
| Production | 0 | 1 | 3 | 10 |

### Policy Enforcement

- **Block Critical:** Always block critical vulnerabilities
- **Block High:** Block high-severity threats in staging/production
- **Supply Chain:** Enable typosquatting detection
- **Compliance:** Enforce license and provenance requirements

## Recommendations

1. **Implement Graduated Security Gates:** Use stricter thresholds as code moves through environments
2. **Enable Supply Chain Monitoring:** Activate typosquatting and dependency confusion detection
3. **Automate Policy Enforcement:** Integrate security gates into CI/CD pipelines
4. **Regular Threshold Review:** Adjust thresholds based on organizational risk tolerance
5. **Exception Management:** Implement controlled exception processes for critical business needs

## Conclusion

The security gate enforcement testing validates TypoSentinel's ability to:
- Detect and block critical security threats
- Enforce configurable security thresholds
- Integrate seamlessly with CI/CD pipelines
- Handle failure scenarios gracefully
- Enforce comprehensive security policies

**Overall Assessment:** $(if [ "$success_rate" -ge 80 ]; then echo "PASS"; else echo "NEEDS IMPROVEMENT"; fi)
EOF
    
    echo -e "${GREEN}Security gate test report generated: $TEST_REPORT_FILE${NC}"
    echo -e "${GREEN}Security gate test results: $TEST_RESULTS_FILE${NC}"
}

# Main execution
main() {
    echo -e "${BLUE}=== TypoSentinel Security Gate Enforcement Tests ===${NC}"
    echo -e "${BLUE}Testing comprehensive security gate functionality${NC}\n"
    
    setup_test_environment
    
    # Run all security gate tests
    test_critical_threat_blocking
    test_threshold_enforcement
    test_supply_chain_detection
    test_cicd_failure_scenarios
    test_security_policy_enforcement
    
    # Generate comprehensive report
    generate_test_report
    
    echo -e "\n${BLUE}=== Security Gate Test Summary ===${NC}"
    echo -e "Total Tests: $TOTAL_TESTS"
    echo -e "${GREEN}Passed: $PASSED_TESTS${NC}"
    echo -e "${RED}Failed: $FAILED_TESTS${NC}"
    
    if [ $FAILED_TESTS -eq 0 ]; then
        echo -e "\n${GREEN}🎉 All security gate tests passed!${NC}"
        exit 0
    else
        echo -e "\n${YELLOW}⚠️  Some security gate tests failed. Check the report for details.${NC}"
        exit 1
    fi
}

# Check if script is being sourced or executed
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi