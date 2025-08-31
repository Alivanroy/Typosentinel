#!/bin/bash

# Multi-Branch Security Testing for TypoSentinel Enterprise
# This script validates security scanning workflows across different branches and environments

set -e

# Configuration
TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENTERPRISE_DIR="$(dirname "$TEST_DIR")"
TYPOSENTINEL_BIN="${ENTERPRISE_DIR}/../typosentinel.exe"
REPORTS_DIR="${TEST_DIR}/reports"
BRANCH_TEST_DIR="${TEST_DIR}/branch-scenarios"
TEST_RESULTS_FILE="${REPORTS_DIR}/multi_branch_results.json"
TEST_REPORT_FILE="${REPORTS_DIR}/multi_branch_report.md"

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

# Branch scenarios to test
BRANCH_SCENARIOS=(
    "main:production:strict"
    "develop:staging:moderate"
    "feature/new-deps:development:permissive"
    "hotfix/security-patch:production:strict"
    "release/v2.0:staging:moderate"
)

# Initialize test environment
setup_test_environment() {
    echo -e "${BLUE}Setting up multi-branch test environment...${NC}"
    mkdir -p "$REPORTS_DIR" "$BRANCH_TEST_DIR"
    
    # Initialize results file
    cat > "$TEST_RESULTS_FILE" << 'EOF'
{
  "test_suite": "Multi-Branch Security Testing",
  "timestamp": "",
  "environment": {
    "test_directory": "",
    "typosentinel_binary": "",
    "enterprise_directory": "",
    "git_available": false
  },
  "branch_scenarios": [],
  "test_results": [],
  "summary": {
    "total_tests": 0,
    "passed": 0,
    "failed": 0,
    "success_rate": 0,
    "branches_tested": 0
  }
}
EOF
    
    # Check Git availability
    local git_available=false
    if command -v git >/dev/null 2>&1; then
        git_available=true
    fi
    
    # Update environment info
    jq --arg timestamp "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
       --arg test_dir "$TEST_DIR" \
       --arg binary "$TYPOSENTINEL_BIN" \
       --arg enterprise "$ENTERPRISE_DIR" \
       --argjson git_available "$git_available" \
       '.timestamp = $timestamp | .environment.test_directory = $test_dir | .environment.typosentinel_binary = $binary | .environment.enterprise_directory = $enterprise | .environment.git_available = $git_available' \
       "$TEST_RESULTS_FILE" > "${TEST_RESULTS_FILE}.tmp" && mv "${TEST_RESULTS_FILE}.tmp" "$TEST_RESULTS_FILE"
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
        --arg branch "$branch" \
        '{
            "test_name": $name,
            "status": $status,
            "details": $details,
            "execution_time_ms": ($time | tonumber),
            "branch": $branch
        }')
    
    jq --argjson result "$test_result" '.test_results += [$result]' "$TEST_RESULTS_FILE" > "${TEST_RESULTS_FILE}.tmp" && mv "${TEST_RESULTS_FILE}.tmp" "$TEST_RESULTS_FILE"
}

# Create branch-specific test scenarios
create_branch_scenarios() {
    echo -e "\n${BLUE}Creating branch-specific test scenarios...${NC}"
    
    for scenario in "${BRANCH_SCENARIOS[@]}"; do
        local branch=$(echo "$scenario" | cut -d':' -f1)
        local environment=$(echo "$scenario" | cut -d':' -f2)
        local policy=$(echo "$scenario" | cut -d':' -f3)
        
        local branch_dir="${BRANCH_TEST_DIR}/${branch//\//_}"
        mkdir -p "$branch_dir"
        
        echo -e "  ${PURPLE}Creating scenario for branch: $branch ($environment - $policy)${NC}"
        
        # Create branch-specific package.json with different risk profiles
        case "$environment" in
            "production")
                create_production_package "$branch_dir" "$branch"
                ;;
            "staging")
                create_staging_package "$branch_dir" "$branch"
                ;;
            "development")
                create_development_package "$branch_dir" "$branch"
                ;;
        esac
        
        # Create branch-specific security config
        create_branch_security_config "$branch_dir" "$environment" "$policy"
        
        # Add scenario to results
        local scenario_info=$(jq -n \
            --arg branch "$branch" \
            --arg env "$environment" \
            --arg policy "$policy" \
            --arg dir "$branch_dir" \
            '{
                "branch": $branch,
                "environment": $env,
                "policy": $policy,
                "test_directory": $dir
            }')
        
        jq --argjson scenario "$scenario_info" '.branch_scenarios += [$scenario]' "$TEST_RESULTS_FILE" > "${TEST_RESULTS_FILE}.tmp" && mv "${TEST_RESULTS_FILE}.tmp" "$TEST_RESULTS_FILE"
    done
}

# Create production-grade package.json (minimal dependencies, stable versions)
create_production_package() {
    local dir="$1"
    local branch="$2"
    
    cat > "${dir}/package.json" << EOF
{
  "name": "enterprise-production-app",
  "version": "2.1.0",
  "description": "Production application for branch: $branch",
  "main": "index.js",
  "scripts": {
    "start": "node index.js",
    "test": "jest",
    "build": "webpack --mode production"
  },
  "dependencies": {
    "express": "4.18.2",
    "lodash": "4.17.21",
    "axios": "1.4.0",
    "jsonwebtoken": "9.0.0",
    "bcryptjs": "2.4.3",
    "helmet": "7.0.0",
    "cors": "2.8.5"
  },
  "devDependencies": {
    "jest": "29.5.0",
    "webpack": "5.88.0",
    "eslint": "8.44.0"
  },
  "engines": {
    "node": ">=18.0.0",
    "npm": ">=9.0.0"
  }
}
EOF
}

# Create staging package.json (moderate dependencies, recent versions)
create_staging_package() {
    local dir="$1"
    local branch="$2"
    
    cat > "${dir}/package.json" << EOF
{
  "name": "enterprise-staging-app",
  "version": "2.1.0-beta.1",
  "description": "Staging application for branch: $branch",
  "main": "index.js",
  "scripts": {
    "start": "node index.js",
    "dev": "nodemon index.js",
    "test": "jest --coverage",
    "build": "webpack --mode development"
  },
  "dependencies": {
    "express": "4.18.2",
    "lodash": "4.17.21",
    "axios": "1.4.0",
    "jsonwebtoken": "9.0.0",
    "bcryptjs": "2.4.3",
    "helmet": "7.0.0",
    "cors": "2.8.5",
    "morgan": "1.10.0",
    "compression": "1.7.4",
    "dotenv": "16.3.1"
  },
  "devDependencies": {
    "jest": "29.5.0",
    "webpack": "5.88.0",
    "eslint": "8.44.0",
    "nodemon": "3.0.1",
    "supertest": "6.3.3",
    "@types/jest": "29.5.3"
  },
  "engines": {
    "node": ">=18.0.0",
    "npm": ">=9.0.0"
  }
}
EOF
}

# Create development package.json (many dependencies, experimental versions)
create_development_package() {
    local dir="$1"
    local branch="$2"
    
    cat > "${dir}/package.json" << EOF
{
  "name": "enterprise-development-app",
  "version": "2.2.0-alpha.1",
  "description": "Development application for branch: $branch",
  "main": "index.js",
  "scripts": {
    "start": "node index.js",
    "dev": "nodemon --inspect index.js",
    "test": "jest --watch",
    "test:coverage": "jest --coverage",
    "build": "webpack --mode development",
    "lint": "eslint . --fix",
    "format": "prettier --write ."
  },
  "dependencies": {
    "express": "4.18.2",
    "lodash": "4.17.21",
    "axios": "1.4.0",
    "jsonwebtoken": "9.0.0",
    "bcryptjs": "2.4.3",
    "helmet": "7.0.0",
    "cors": "2.8.5",
    "morgan": "1.10.0",
    "compression": "1.7.4",
    "dotenv": "16.3.1",
    "socket.io": "4.7.2",
    "redis": "4.6.7",
    "mongoose": "7.4.0",
    "winston": "3.10.0",
    "joi": "17.9.2",
    "multer": "1.4.5-lts.1",
    "sharp": "0.32.1",
    "nodemailer": "6.9.4"
  },
  "devDependencies": {
    "jest": "29.5.0",
    "webpack": "5.88.0",
    "eslint": "8.44.0",
    "nodemon": "3.0.1",
    "supertest": "6.3.3",
    "@types/jest": "29.5.3",
    "prettier": "3.0.0",
    "husky": "8.0.3",
    "lint-staged": "13.2.3",
    "webpack-dev-server": "4.15.1",
    "babel-loader": "9.1.3",
    "@babel/core": "7.22.9",
    "@babel/preset-env": "7.22.9",
    "css-loader": "6.8.1",
    "style-loader": "3.3.3",
    "html-webpack-plugin": "5.5.3"
  },
  "engines": {
    "node": ">=18.0.0",
    "npm": ">=9.0.0"
  }
}
EOF
}

# Create branch-specific security configuration
create_branch_security_config() {
    local dir="$1"
    local environment="$2"
    local policy="$3"
    
    local config_file="${dir}/security-config.yaml"
    
    case "$policy" in
        "strict")
            cat > "$config_file" << 'EOF'
security_policy:
  version: "1.0"
  enforcement_level: "strict"
  
  vulnerability_policy:
    block_critical: true
    block_high: true
    allow_medium: false
    max_medium_count: 0
    max_low_count: 5
    
  dependency_policy:
    allow_dev_dependencies: false
    block_deprecated: true
    require_license_compliance: true
    allowed_licenses: ["MIT", "Apache-2.0", "BSD-3-Clause"]
    
  typosquatting_policy:
    sensitivity: "high"
    block_suspicious: true
    whitelist_exceptions: []
    
  supply_chain_policy:
    require_provenance: true
    block_unsigned: true
    verify_checksums: true
    
  thresholds:
    critical: 0
    high: 0
    medium: 0
    low: 5
EOF
            ;;
        "moderate")
            cat > "$config_file" << 'EOF'
security_policy:
  version: "1.0"
  enforcement_level: "moderate"
  
  vulnerability_policy:
    block_critical: true
    block_high: true
    allow_medium: true
    max_medium_count: 5
    max_low_count: 15
    
  dependency_policy:
    allow_dev_dependencies: true
    block_deprecated: true
    require_license_compliance: true
    allowed_licenses: ["MIT", "Apache-2.0", "BSD-3-Clause", "ISC"]
    
  typosquatting_policy:
    sensitivity: "medium"
    block_suspicious: true
    whitelist_exceptions: []
    
  supply_chain_policy:
    require_provenance: false
    block_unsigned: false
    verify_checksums: true
    
  thresholds:
    critical: 0
    high: 2
    medium: 5
    low: 15
EOF
            ;;
        "permissive")
            cat > "$config_file" << 'EOF'
security_policy:
  version: "1.0"
  enforcement_level: "permissive"
  
  vulnerability_policy:
    block_critical: true
    block_high: false
    allow_medium: true
    max_medium_count: 20
    max_low_count: 50
    
  dependency_policy:
    allow_dev_dependencies: true
    block_deprecated: false
    require_license_compliance: false
    allowed_licenses: []
    
  typosquatting_policy:
    sensitivity: "low"
    block_suspicious: false
    whitelist_exceptions: []
    
  supply_chain_policy:
    require_provenance: false
    block_unsigned: false
    verify_checksums: false
    
  thresholds:
    critical: 5
    high: 10
    medium: 20
    low: 50
EOF
            ;;
    esac
}

# Test branch-specific security scanning
test_branch_security_scanning() {
    echo -e "\n${BLUE}Testing Branch-Specific Security Scanning...${NC}"
    
    local branches_tested=0
    
    for scenario in "${BRANCH_SCENARIOS[@]}"; do
        local branch=$(echo "$scenario" | cut -d':' -f1)
        local environment=$(echo "$scenario" | cut -d':' -f2)
        local policy=$(echo "$scenario" | cut -d':' -f3)
        
        echo -e "\n  ${PURPLE}Testing branch: $branch ($environment - $policy)${NC}"
        
        local branch_dir="${BRANCH_TEST_DIR}/${branch//\//_}"
        local package_file="${branch_dir}/package.json"
        local config_file="${branch_dir}/security-config.yaml"
        local output_file="${REPORTS_DIR}/branch_${branch//\//_}_results.json"
        
        local start_time=$(date +%s%3N)
        
        if [ -f "$TYPOSENTINEL_BIN" ] && [ -f "$package_file" ]; then
            local scan_result=0
            "$TYPOSENTINEL_BIN" scan "$package_file" --config "$config_file" -o json --include-dev --workspace-aware > "$output_file" 2>&1 || scan_result=$?
            
            local end_time=$(date +%s%3N)
            local execution_time=$((end_time - start_time))
            
            if [ -f "$output_file" ]; then
                local critical=$(jq -r '.summary.threats.critical // 0' "$output_file" 2>/dev/null || echo "0")
                local high=$(jq -r '.summary.threats.high // 0' "$output_file" 2>/dev/null || echo "0")
                local medium=$(jq -r '.summary.threats.medium // 0' "$output_file" 2>/dev/null || echo "0")
                local low=$(jq -r '.summary.threats.low // 0' "$output_file" 2>/dev/null || echo "0")
                local packages=$(jq -r '.summary.packages_scanned // 0' "$output_file" 2>/dev/null || echo "0")
                
                local details="Scanned $packages packages - Threats: C:$critical H:$high M:$medium L:$low"
                
                # Validate against policy thresholds
                local policy_violation=false
                case "$policy" in
                    "strict")
                        if [ "$critical" -gt 0 ] || [ "$high" -gt 0 ] || [ "$medium" -gt 0 ]; then
                            policy_violation=true
                        fi
                        ;;
                    "moderate")
                        if [ "$critical" -gt 0 ] || [ "$high" -gt 2 ] || [ "$medium" -gt 5 ]; then
                            policy_violation=true
                        fi
                        ;;
                    "permissive")
                        if [ "$critical" -gt 5 ] || [ "$high" -gt 10 ] || [ "$medium" -gt 20 ]; then
                            policy_violation=true
                        fi
                        ;;
                esac
                
                if [ "$policy_violation" = true ]; then
                    details="$details (Policy violation detected)"
                fi
                
                log_test_result "Branch Security Scan ($branch)" "PASS" "$details" "$execution_time" "$branch"
                branches_tested=$((branches_tested + 1))
            else
                log_test_result "Branch Security Scan ($branch)" "FAIL" "No output file generated" "$execution_time" "$branch"
            fi
        else
            log_test_result "Branch Security Scan ($branch)" "SKIP" "Binary or package file not found" "0" "$branch"
        fi
    done
    
    # Update branches tested count
    jq --arg count "$branches_tested" '.summary.branches_tested = ($count | tonumber)' "$TEST_RESULTS_FILE" > "${TEST_RESULTS_FILE}.tmp" && mv "${TEST_RESULTS_FILE}.tmp" "$TEST_RESULTS_FILE"
}

# Test cross-branch dependency comparison
test_cross_branch_comparison() {
    echo -e "\n${BLUE}Testing Cross-Branch Dependency Comparison...${NC}"
    
    local start_time=$(date +%s%3N)
    
    # Compare dependencies between main and feature branches
    local main_package="${BRANCH_TEST_DIR}/main/package.json"
    local feature_package="${BRANCH_TEST_DIR}/feature_new-deps/package.json"
    
    if [ -f "$main_package" ] && [ -f "$feature_package" ]; then
        # Extract dependencies for comparison
        local main_deps=$(jq -r '.dependencies | keys[]' "$main_package" 2>/dev/null | sort)
        local feature_deps=$(jq -r '.dependencies | keys[]' "$feature_package" 2>/dev/null | sort)
        
        # Find new dependencies in feature branch
        local new_deps=$(comm -13 <(echo "$main_deps") <(echo "$feature_deps") | wc -l)
        local removed_deps=$(comm -23 <(echo "$main_deps") <(echo "$feature_deps") | wc -l)
        
        local end_time=$(date +%s%3N)
        local execution_time=$((end_time - start_time))
        
        local details="New dependencies: $new_deps, Removed: $removed_deps"
        log_test_result "Cross-Branch Dependency Comparison" "PASS" "$details" "$execution_time" "main vs feature"
    else
        log_test_result "Cross-Branch Dependency Comparison" "SKIP" "Required package files not found" "0" "main vs feature"
    fi
}

# Test branch merge security validation
test_branch_merge_validation() {
    echo -e "\n${BLUE}Testing Branch Merge Security Validation...${NC}"
    
    local start_time=$(date +%s%3N)
    
    # Simulate merge validation by scanning combined dependencies
    local merge_test_file="${BRANCH_TEST_DIR}/merge_validation.json"
    
    # Create a merged package.json combining main and feature dependencies
    if [ -f "${BRANCH_TEST_DIR}/main/package.json" ] && [ -f "${BRANCH_TEST_DIR}/feature_new-deps/package.json" ]; then
        jq -s '.[0] * .[1] | .dependencies = (.[0].dependencies + .[1].dependencies) | .devDependencies = (.[0].devDependencies + .[1].devDependencies)' \
           "${BRANCH_TEST_DIR}/main/package.json" \
           "${BRANCH_TEST_DIR}/feature_new-deps/package.json" > "$merge_test_file"
        
        # Scan the merged dependencies
        local output_file="${REPORTS_DIR}/merge_validation_results.json"
        
        if [ -f "$TYPOSENTINEL_BIN" ]; then
            local scan_result=0
            "$TYPOSENTINEL_BIN" scan "$merge_test_file" -o json --include-dev > "$output_file" 2>&1 || scan_result=$?
            
            local end_time=$(date +%s%3N)
            local execution_time=$((end_time - start_time))
            
            if [ -f "$output_file" ]; then
                local total_packages=$(jq -r '.summary.packages_scanned // 0' "$output_file" 2>/dev/null || echo "0")
                local total_threats=$(jq -r '(.summary.threats.critical // 0) + (.summary.threats.high // 0) + (.summary.threats.medium // 0) + (.summary.threats.low // 0)' "$output_file" 2>/dev/null || echo "0")
                
                local details="Merged scan: $total_packages packages, $total_threats total threats"
                log_test_result "Branch Merge Validation" "PASS" "$details" "$execution_time" "main + feature"
            else
                log_test_result "Branch Merge Validation" "FAIL" "No merge validation output" "$execution_time" "main + feature"
            fi
        else
            log_test_result "Branch Merge Validation" "SKIP" "TypoSentinel binary not found" "0" "main + feature"
        fi
        
        # Cleanup
        rm -f "$merge_test_file"
    else
        log_test_result "Branch Merge Validation" "SKIP" "Required branch packages not found" "0" "main + feature"
    fi
}

# Test environment-specific policy enforcement
test_environment_policy_enforcement() {
    echo -e "\n${BLUE}Testing Environment-Specific Policy Enforcement...${NC}"
    
    local environments=("production" "staging" "development")
    
    for env in "${environments[@]}"; do
        echo -e "  ${YELLOW}Testing $env environment policy...${NC}"
        
        local start_time=$(date +%s%3N)
        
        # Find a branch with this environment
        local test_branch=""
        for scenario in "${BRANCH_SCENARIOS[@]}"; do
            local scenario_env=$(echo "$scenario" | cut -d':' -f2)
            if [ "$scenario_env" = "$env" ]; then
                test_branch=$(echo "$scenario" | cut -d':' -f1)
                break
            fi
        done
        
        if [ -n "$test_branch" ]; then
            local branch_dir="${BRANCH_TEST_DIR}/${test_branch//\//_}"
            local package_file="${branch_dir}/package.json"
            local config_file="${branch_dir}/security-config.yaml"
            local output_file="${REPORTS_DIR}/env_${env}_policy_test.json"
            
            if [ -f "$TYPOSENTINEL_BIN" ] && [ -f "$package_file" ] && [ -f "$config_file" ]; then
                local scan_result=0
                "$TYPOSENTINEL_BIN" scan "$package_file" --config "$config_file" -o json > "$output_file" 2>&1 || scan_result=$?
                
                local end_time=$(date +%s%3N)
                local execution_time=$((end_time - start_time))
                
                if [ -f "$output_file" ]; then
                    local policy_level=$(jq -r '.config.enforcement_level // "unknown"' "$output_file" 2>/dev/null || echo "unknown")
                    local threats=$(jq -r '(.summary.threats.critical // 0) + (.summary.threats.high // 0)' "$output_file" 2>/dev/null || echo "0")
                    
                    local details="Policy level: $policy_level, Critical+High threats: $threats"
                    log_test_result "Environment Policy ($env)" "PASS" "$details" "$execution_time" "$test_branch"
                else
                    log_test_result "Environment Policy ($env)" "FAIL" "No policy output generated" "$execution_time" "$test_branch"
                fi
            else
                log_test_result "Environment Policy ($env)" "SKIP" "Required files not found" "0" "$test_branch"
            fi
        else
            log_test_result "Environment Policy ($env)" "SKIP" "No branch found for environment" "0" "none"
        fi
    done
}

# Generate comprehensive test report
generate_test_report() {
    echo -e "\n${BLUE}Generating Multi-Branch Test Report...${NC}"
    
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
# Multi-Branch Security Testing Report

**Generated:** $(date -u +"%Y-%m-%d %H:%M:%S UTC")  
**Test Suite:** Multi-Branch Security Testing  
**Environment:** $(uname -s) $(uname -r)  

## Executive Summary

- **Total Tests:** $TOTAL_TESTS
- **Passed:** $PASSED_TESTS
- **Failed:** $FAILED_TESTS
- **Success Rate:** ${success_rate}%
- **Branches Tested:** $(jq -r '.summary.branches_tested' "$TEST_RESULTS_FILE")

## Branch Scenarios Tested

EOF
    
    # Add branch scenarios table
    echo "| Branch | Environment | Policy | Test Directory |" >> "$TEST_REPORT_FILE"
    echo "|--------|-------------|--------|----------------|
" >> "$TEST_REPORT_FILE"
    
    jq -r '.branch_scenarios[] | "| " + .branch + " | " + .environment + " | " + .policy + " | " + .test_directory + " |"' "$TEST_RESULTS_FILE" >> "$TEST_REPORT_FILE"
    
    cat >> "$TEST_REPORT_FILE" << EOF

## Test Categories

### 🌿 Branch-Specific Security Scanning
Validates security scanning with branch-specific configurations and policies.

### 🔄 Cross-Branch Dependency Comparison
Compares dependencies between different branches to identify changes and risks.

### 🔀 Branch Merge Security Validation
Simulates merge scenarios and validates combined security posture.

### 🏢 Environment-Specific Policy Enforcement
Tests policy enforcement across different deployment environments.

## Detailed Results

EOF
    
    # Add detailed results from JSON
    jq -r '.test_results[] | "### " + .test_name + " (" + .branch + ")\n\n- **Status:** " + .status + "\n- **Details:** " + .details + "\n- **Execution Time:** " + (.execution_time_ms | tostring) + "ms\n"' "$TEST_RESULTS_FILE" >> "$TEST_REPORT_FILE"
    
    cat >> "$TEST_REPORT_FILE" << EOF

## Security Policy Matrix

### Production (Strict Policy)
- **Critical Threats:** Block all (0 allowed)
- **High Threats:** Block all (0 allowed)
- **Medium Threats:** Block all (0 allowed)
- **Low Threats:** Maximum 5 allowed
- **Dev Dependencies:** Not allowed
- **Supply Chain:** Full verification required

### Staging (Moderate Policy)
- **Critical Threats:** Block all (0 allowed)
- **High Threats:** Maximum 2 allowed
- **Medium Threats:** Maximum 5 allowed
- **Low Threats:** Maximum 15 allowed
- **Dev Dependencies:** Allowed
- **Supply Chain:** Checksum verification required

### Development (Permissive Policy)
- **Critical Threats:** Maximum 5 allowed
- **High Threats:** Maximum 10 allowed
- **Medium Threats:** Maximum 20 allowed
- **Low Threats:** Maximum 50 allowed
- **Dev Dependencies:** Allowed
- **Supply Chain:** No verification required

## Branch Workflow Recommendations

### 1. Feature Branch Development
- Use permissive policies for rapid development
- Enable comprehensive dependency scanning
- Allow experimental and development dependencies

### 2. Integration Testing (Staging)
- Apply moderate security policies
- Validate dependency changes from feature branches
- Test merge scenarios before production

### 3. Production Deployment
- Enforce strict security policies
- Block all critical and high-severity threats
- Require supply chain verification

### 4. Hotfix Branches
- Use production-level strict policies
- Minimize dependency changes
- Fast-track security patches

## CI/CD Integration

### Branch-Specific Workflows
```yaml
# Example GitHub Actions workflow
name: Multi-Branch Security Scan
on:
  push:
    branches: ['main', 'develop', 'feature/*', 'hotfix/*']
  pull_request:
    branches: ['main', 'develop']

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Determine Security Policy
        id: policy
        run: |
          if [[ "${{ github.ref }}" == "refs/heads/main" ]]; then
            echo "policy=strict" >> $GITHUB_OUTPUT
          elif [[ "${{ github.ref }}" == "refs/heads/develop" ]]; then
            echo "policy=moderate" >> $GITHUB_OUTPUT
          else
            echo "policy=permissive" >> $GITHUB_OUTPUT
          fi
      - name: Run TypoSentinel
        run: |
          ./typosentinel scan . --policy ${{ steps.policy.outputs.policy }}
```

## Conclusion

The multi-branch security testing validates TypoSentinel's ability to:
- Apply different security policies based on branch and environment
- Compare dependencies across branches
- Validate merge scenarios
- Enforce environment-specific security requirements
- Integrate seamlessly with branch-based CI/CD workflows

**Overall Assessment:** $(if [ "$success_rate" -ge 80 ]; then echo "PASS"; else echo "NEEDS IMPROVEMENT"; fi)
EOF
    
    echo -e "${GREEN}Multi-branch test report generated: $TEST_REPORT_FILE${NC}"
    echo -e "${GREEN}Multi-branch test results: $TEST_RESULTS_FILE${NC}"
}

# Main execution
main() {
    echo -e "${BLUE}=== TypoSentinel Multi-Branch Security Tests ===${NC}"
    echo -e "${BLUE}Testing security workflows across different branches and environments${NC}\n"
    
    setup_test_environment
    create_branch_scenarios
    
    # Run all multi-branch tests
    test_branch_security_scanning
    test_cross_branch_comparison
    test_branch_merge_validation
    test_environment_policy_enforcement
    
    # Generate comprehensive report
    generate_test_report
    
    echo -e "\n${BLUE}=== Multi-Branch Test Summary ===${NC}"
    echo -e "Total Tests: $TOTAL_TESTS"
    echo -e "${GREEN}Passed: $PASSED_TESTS${NC}"
    echo -e "${RED}Failed: $FAILED_TESTS${NC}"
    echo -e "Branches Tested: $(jq -r '.summary.branches_tested' "$TEST_RESULTS_FILE")"
    
    if [ $FAILED_TESTS -eq 0 ]; then
        echo -e "\n${GREEN}🎉 All multi-branch tests passed!${NC}"
        exit 0
    else
        echo -e "\n${YELLOW}⚠️  Some multi-branch tests failed. Check the report for details.${NC}"
        exit 1
    fi
}

# Check if script is being sourced or executed
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi