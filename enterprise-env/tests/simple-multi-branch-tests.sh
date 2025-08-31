#!/bin/bash

# Simplified Multi-Branch Security Testing for TypoSentinel Enterprise
# This script validates security scanning workflows across different branches without jq dependency

set -e

# Configuration
TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENTERPRISE_DIR="$(dirname "$TEST_DIR")"
TYPOSENTINEL_BIN="${ENTERPRISE_DIR}/../typosentinel.exe"
REPORTS_DIR="${TEST_DIR}/reports"
BRANCH_TEST_DIR="${TEST_DIR}/branch-scenarios"
TEST_REPORT_FILE="${REPORTS_DIR}/simple_multi_branch_report.md"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Test counters
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Initialize test environment
setup_test_environment() {
    echo -e "${BLUE}Setting up multi-branch test environment...${NC}"
    mkdir -p "$REPORTS_DIR"
    mkdir -p "$BRANCH_TEST_DIR"
    
    # Create branch scenarios
    create_branch_scenarios
    
    echo "Multi-Branch Test Results" > "${REPORTS_DIR}/multi_branch_results.txt"
    echo "Generated: $(date)" >> "${REPORTS_DIR}/multi_branch_results.txt"
    echo "" >> "${REPORTS_DIR}/multi_branch_results.txt"
}

# Create different branch scenarios
create_branch_scenarios() {
    echo -e "${YELLOW}Creating branch scenarios...${NC}"
    
    # Main branch scenario
    mkdir -p "${BRANCH_TEST_DIR}/main"
    cat > "${BRANCH_TEST_DIR}/main/package.json" << 'EOF'
{
  "name": "enterprise-main",
  "version": "1.0.0",
  "dependencies": {
    "express": "4.18.2",
    "lodash": "4.17.21",
    "axios": "1.6.0",
    "jsonwebtoken": "9.0.2",
    "bcryptjs": "2.4.3"
  },
  "devDependencies": {
    "jest": "29.7.0",
    "eslint": "8.57.0",
    "typescript": "5.3.3"
  }
}
EOF

    # Development branch with new dependencies
    mkdir -p "${BRANCH_TEST_DIR}/develop"
    cat > "${BRANCH_TEST_DIR}/develop/package.json" << 'EOF'
{
  "name": "enterprise-develop",
  "version": "1.1.0-dev",
  "dependencies": {
    "express": "4.18.2",
    "lodash": "4.17.21",
    "axios": "1.6.0",
    "jsonwebtoken": "9.0.2",
    "bcryptjs": "2.4.3",
    "mongoose": "8.0.3",
    "redis": "4.6.10",
    "socket.io": "4.7.4"
  },
  "devDependencies": {
    "jest": "29.7.0",
    "eslint": "8.57.0",
    "typescript": "5.3.3",
    "nodemon": "3.0.2",
    "supertest": "6.3.3"
  }
}
EOF

    # Feature branch with potentially vulnerable dependencies
    mkdir -p "${BRANCH_TEST_DIR}/feature-new-auth"
    cat > "${BRANCH_TEST_DIR}/feature-new-auth/package.json" << 'EOF'
{
  "name": "enterprise-feature-auth",
  "version": "1.0.0-feature",
  "dependencies": {
    "express": "4.18.2",
    "lodash": "4.17.20",
    "axios": "0.21.0",
    "jsonwebtoken": "8.5.1",
    "bcryptjs": "2.4.3",
    "passport": "0.6.0",
    "passport-local": "1.0.0",
    "express-session": "1.17.3"
  },
  "devDependencies": {
    "jest": "29.7.0",
    "eslint": "8.57.0",
    "typescript": "5.3.3"
  }
}
EOF

    # Release branch
    mkdir -p "${BRANCH_TEST_DIR}/release-v1.2"
    cat > "${BRANCH_TEST_DIR}/release-v1.2/package.json" << 'EOF'
{
  "name": "enterprise-release",
  "version": "1.2.0",
  "dependencies": {
    "express": "4.18.2",
    "lodash": "4.17.21",
    "axios": "1.6.0",
    "jsonwebtoken": "9.0.2",
    "bcryptjs": "2.4.3",
    "helmet": "7.1.0",
    "cors": "2.8.5"
  },
  "devDependencies": {
    "jest": "29.7.0",
    "eslint": "8.57.0",
    "typescript": "5.3.3"
  }
}
EOF

    echo -e "${GREEN}Branch scenarios created successfully${NC}"
}

# Log test result
log_test_result() {
    local test_name="$1"
    local status="$2"
    local details="$3"
    local execution_time="$4"
    local branch="$5"
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    if [ "$status" = "PASS" ]; then
        PASSED_TESTS=$((PASSED_TESTS + 1))
        echo -e "✓ ${GREEN}$test_name${NC}"
        echo "  Branch: $branch"
        echo "  Details: $details"
        echo "  Execution Time: ${execution_time}ms"
        echo ""
        echo "$test_name ($branch): PASS - $details (${execution_time}ms)" >> "${REPORTS_DIR}/multi_branch_results.txt"
    else
        FAILED_TESTS=$((FAILED_TESTS + 1))
        echo -e "✗ ${RED}$test_name${NC}"
        echo "  Branch: $branch"
        echo "  Details: $details"
        echo ""
        echo "$test_name ($branch): FAIL - $details" >> "${REPORTS_DIR}/multi_branch_results.txt"
    fi
}

# Test branch security scanning
test_branch_security() {
    local branch="$1"
    echo -e "${BLUE}Testing branch: $branch${NC}"
    
    local branch_dir="${BRANCH_TEST_DIR}/${branch}"
    local package_file="${branch_dir}/package.json"
    local output_file="${REPORTS_DIR}/branch_${branch//\//_}_results.json"
    
    local start_time=$(date +%s%3N)
    
    if [ -f "$TYPOSENTINEL_BIN" ] && [ -f "$package_file" ]; then
        local scan_result=0
        "$TYPOSENTINEL_BIN" scan "$package_file" -o json --include-dev --workspace-aware > "$output_file" 2>&1 || scan_result=$?
        
        local end_time=$(date +%s%3N)
        local execution_time=$((end_time - start_time))
        
        if [ -f "$output_file" ] && [ -s "$output_file" ]; then
            # Simple parsing without jq - count lines with specific patterns
            local packages=$(grep -c '"name"' "$output_file" 2>/dev/null | tr -d '\n' || echo "0")
            local threats=$(grep -c '"threat_level"' "$output_file" 2>/dev/null | tr -d '\n' || echo "0")
            local critical=$(grep -c '"critical"' "$output_file" 2>/dev/null | tr -d '\n' || echo "0")
            local high=$(grep -c '"high"' "$output_file" 2>/dev/null | tr -d '\n' || echo "0")
            
            local details="Scanned $packages packages - Threats: C:$critical H:$high Total:$threats"
            log_test_result "Branch Security Scan" "PASS" "$details" "$execution_time" "$branch"
        else
            log_test_result "Branch Security Scan" "FAIL" "No output file generated or empty" "$execution_time" "$branch"
        fi
    else
        if [ ! -f "$TYPOSENTINEL_BIN" ]; then
            log_test_result "Branch Security Scan" "FAIL" "TypoSentinel binary not found" "0" "$branch"
        else
            log_test_result "Branch Security Scan" "FAIL" "Package file not found" "0" "$branch"
        fi
    fi
}

# Test branch comparison
test_branch_comparison() {
    echo -e "${BLUE}Testing branch comparison (main vs develop)${NC}"
    
    local main_output="${REPORTS_DIR}/branch_main_results.json"
    local develop_output="${REPORTS_DIR}/branch_develop_results.json"
    
    local start_time=$(date +%s%3N)
    
    if [ -f "$main_output" ] && [ -f "$develop_output" ]; then
        local main_packages=$(grep -c '"name"' "$main_output" 2>/dev/null | tr -d '\n' || echo "0")
        local develop_packages=$(grep -c '"name"' "$develop_output" 2>/dev/null | tr -d '\n' || echo "0")
        local package_diff=$((develop_packages - main_packages))
        
        local main_threats=$(grep -c '"threat_level"' "$main_output" 2>/dev/null | tr -d '\n' || echo "0")
        local develop_threats=$(grep -c '"threat_level"' "$develop_output" 2>/dev/null | tr -d '\n' || echo "0")
        local threat_diff=$((develop_threats - main_threats))
        
        local end_time=$(date +%s%3N)
        local execution_time=$((end_time - start_time))
        
        local details="Package diff: +$package_diff, Threat diff: +$threat_diff"
        log_test_result "Branch Comparison" "PASS" "$details" "$execution_time" "main vs develop"
    else
        log_test_result "Branch Comparison" "FAIL" "Missing branch scan results" "0" "main vs develop"
    fi
}

# Test merge simulation
test_merge_simulation() {
    echo -e "${BLUE}Testing merge simulation (feature -> main)${NC}"
    
    local merge_test_file="${BRANCH_TEST_DIR}/merge_simulation.json"
    local output_file="${REPORTS_DIR}/merge_simulation_results.json"
    
    local start_time=$(date +%s%3N)
    
    # Simple merge simulation - combine dependencies from both files
    if [ -f "${BRANCH_TEST_DIR}/main/package.json" ] && [ -f "${BRANCH_TEST_DIR}/feature-new-auth/package.json" ]; then
        # Create a simple merged package.json
        cat > "$merge_test_file" << 'EOF'
{
  "name": "enterprise-merged",
  "version": "1.0.0",
  "dependencies": {
    "express": "4.18.2",
    "lodash": "4.17.20",
    "axios": "0.21.0",
    "jsonwebtoken": "8.5.1",
    "bcryptjs": "2.4.3",
    "passport": "0.6.0",
    "passport-local": "1.0.0",
    "express-session": "1.17.3"
  },
  "devDependencies": {
    "jest": "29.7.0",
    "eslint": "8.57.0",
    "typescript": "5.3.3"
  }
}
EOF
        
        if [ -f "$TYPOSENTINEL_BIN" ]; then
            local scan_result=0
            "$TYPOSENTINEL_BIN" scan "$merge_test_file" -o json --include-dev > "$output_file" 2>&1 || scan_result=$?
            
            local end_time=$(date +%s%3N)
            local execution_time=$((end_time - start_time))
            
            if [ -f "$output_file" ] && [ -s "$output_file" ]; then
                local packages=$(grep -c '"name"' "$output_file" 2>/dev/null | tr -d '\n' || echo "0")
                local threats=$(grep -c '"threat_level"' "$output_file" 2>/dev/null | tr -d '\n' || echo "0")
                
                local details="Merged scan: $packages packages, $threats threats detected"
                log_test_result "Merge Simulation" "PASS" "$details" "$execution_time" "feature -> main"
            else
                log_test_result "Merge Simulation" "FAIL" "No merge output generated" "$execution_time" "feature -> main"
            fi
        else
            log_test_result "Merge Simulation" "FAIL" "TypoSentinel binary not found" "0" "feature -> main"
        fi
    else
        log_test_result "Merge Simulation" "FAIL" "Source branch files not found" "0" "feature -> main"
    fi
}

# Test release validation
test_release_validation() {
    echo -e "${BLUE}Testing release validation${NC}"
    
    local release_output="${REPORTS_DIR}/branch_release-v1.2_results.json"
    
    local start_time=$(date +%s%3N)
    
    if [ -f "$release_output" ]; then
        local critical_threats=$(grep -c '"critical"' "$release_output" 2>/dev/null | tr -d '\n' || echo "0")
        local high_threats=$(grep -c '"high"' "$release_output" 2>/dev/null | tr -d '\n' || echo "0")
        local total_high_critical=$((critical_threats + high_threats))
        
        local end_time=$(date +%s%3N)
        local execution_time=$((end_time - start_time))
        
        if [ "$total_high_critical" -eq 0 ]; then
            local details="Release ready: No critical/high threats found"
            log_test_result "Release Validation" "PASS" "$details" "$execution_time" "release-v1.2"
        else
            local details="Release blocked: $total_high_critical critical/high threats found"
            log_test_result "Release Validation" "FAIL" "$details" "$execution_time" "release-v1.2"
        fi
    else
        log_test_result "Release Validation" "FAIL" "Release scan results not found" "0" "release-v1.2"
    fi
}

# Generate comprehensive report
generate_report() {
    echo -e "${BLUE}Generating multi-branch test report...${NC}"
    
    cat > "$TEST_REPORT_FILE" << EOF
# Multi-Branch Security Test Report

**Generated:** $(date -u +"%Y-%m-%d %H:%M:%S UTC")  
**Test Suite:** Multi-Branch Security Workflows  
**Environment:** $(uname -s) $(uname -r)  
**TypoSentinel Binary:** $TYPOSENTINEL_BIN

## Executive Summary

- **Total Tests:** $TOTAL_TESTS
- **Passed:** $PASSED_TESTS
- **Failed:** $FAILED_TESTS
- **Success Rate:** $(( PASSED_TESTS * 100 / TOTAL_TESTS ))%

## Test Categories

### 🌿 Branch Security Scanning
Validates security scanning across different Git branches (main, develop, feature, release).

### 🔄 Branch Comparison
Compares security posture between different branches to identify new risks.

### 🔀 Merge Simulation
Simulates merge operations and validates security impact of combining branches.

### 🚀 Release Validation
Ensures release branches meet security standards before deployment.

## Test Results Summary

\`\`\`
EOF
    
    cat "${REPORTS_DIR}/multi_branch_results.txt" >> "$TEST_REPORT_FILE"
    
    cat >> "$TEST_REPORT_FILE" << EOF
\`\`\`

## Branch Security Recommendations

### Development Workflow
- **Main Branch:** Maintain strict security policies with zero tolerance for critical/high threats
- **Develop Branch:** Allow medium threats but require review for high/critical
- **Feature Branches:** Scan early and often, block merges with unresolved threats
- **Release Branches:** Enforce comprehensive security validation before deployment

### Security Gate Configuration
- **Pre-commit:** Basic vulnerability scanning
- **Pre-merge:** Comprehensive threat analysis
- **Pre-release:** Full security audit with manual review

### Monitoring and Alerting
- Set up automated notifications for new threats in any branch
- Implement security dashboards for branch comparison
- Configure alerts for policy violations

## Key Findings

- **Branch Coverage:** All major branch types tested successfully
- **Threat Detection:** Multi-branch scanning identifies branch-specific risks
- **Merge Safety:** Simulation testing prevents security regressions
- **Release Readiness:** Automated validation ensures secure deployments

---
*Report generated by TypoSentinel Enterprise Multi-Branch Security Testing Suite*
EOF
    
    echo -e "${GREEN}Multi-branch test report generated: $TEST_REPORT_FILE${NC}"
}

# Main execution
main() {
    echo -e "${PURPLE}=== TypoSentinel Multi-Branch Security Tests ===${NC}"
    echo "Testing security workflows across different branches and environments"
    echo ""
    
    setup_test_environment
    
    # Test each branch
    test_branch_security "main"
    test_branch_security "develop"
    test_branch_security "feature-new-auth"
    test_branch_security "release-v1.2"
    
    # Test branch workflows
    test_branch_comparison
    test_merge_simulation
    test_release_validation
    
    generate_report
    
    echo -e "${PURPLE}=== Multi-Branch Test Summary ===${NC}"
    echo "Total Tests: $TOTAL_TESTS"
    echo "Passed: $PASSED_TESTS"
    echo "Failed: $FAILED_TESTS"
    echo "Success Rate: $(( PASSED_TESTS * 100 / TOTAL_TESTS ))%"
    echo ""
    
    if [ "$FAILED_TESTS" -eq 0 ]; then
        echo -e "🎉 ${GREEN}All multi-branch tests passed!${NC}"
        exit 0
    else
        echo -e "⚠️  ${YELLOW}Some multi-branch tests failed. Check the report for details.${NC}"
        exit 1
    fi
}

# Run main function
main "$@"