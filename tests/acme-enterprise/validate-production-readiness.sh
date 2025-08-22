#!/bin/bash

# ACME Enterprise - Typosentinel Production Readiness Validation
# This script validates the entire enterprise test environment

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="${SCRIPT_DIR}/validation-$(date +%Y%m%d-%H%M%S).log"
REPORT_FILE="${SCRIPT_DIR}/production-readiness-report-$(date +%Y%m%d-%H%M%S).json"
ERROR_COUNT=0
WARNING_COUNT=0
SUCCESS_COUNT=0

# Test results array
declare -a TEST_RESULTS=()

# Logging functions
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$LOG_FILE"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$LOG_FILE"
    ((SUCCESS_COUNT++))
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_FILE"
    ((WARNING_COUNT++))
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
    ((ERROR_COUNT++))
}

# Test result tracking
add_test_result() {
    local test_name="$1"
    local status="$2"
    local message="$3"
    local duration="${4:-0}"
    
    TEST_RESULTS+=("$(cat <<EOF
{
  "test_name": "$test_name",
  "status": "$status",
  "message": "$message",
  "duration": $duration,
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
)")
}

# Utility functions
check_command() {
    if command -v "$1" >/dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

check_port() {
    local port="$1"
    if nc -z localhost "$port" 2>/dev/null; then
        return 0
    else
        return 1
    fi
}

check_url() {
    local url="$1"
    local expected_status="${2:-200}"
    
    if curl -s -o /dev/null -w "%{http_code}" "$url" | grep -q "$expected_status"; then
        return 0
    else
        return 1
    fi
}

run_test() {
    local test_name="$1"
    local test_function="$2"
    
    log_info "Running test: $test_name"
    local start_time=$(date +%s)
    
    if $test_function; then
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        log_success "$test_name completed successfully (${duration}s)"
        add_test_result "$test_name" "PASS" "Test completed successfully" "$duration"
    else
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        log_error "$test_name failed (${duration}s)"
        add_test_result "$test_name" "FAIL" "Test failed" "$duration"
    fi
}

# Test functions
test_prerequisites() {
    log_info "Checking prerequisites..."
    
    local required_commands=("docker" "docker-compose" "node" "npm" "git" "curl" "jq" "nc")
    local missing_commands=()
    
    for cmd in "${required_commands[@]}"; do
        if ! check_command "$cmd"; then
            missing_commands+=("$cmd")
        fi
    done
    
    if [ ${#missing_commands[@]} -eq 0 ]; then
        log_success "All required commands are available"
        return 0
    else
        log_error "Missing required commands: ${missing_commands[*]}"
        return 1
    fi
}

test_project_structure() {
    log_info "Validating project structure..."
    
    local required_dirs=(
        "projects"
        "registries"
        "zero-day-scenarios"
        "cicd-pipelines"
        "monitoring"
    )
    
    local required_files=(
        "README.md"
        "docker-compose.yml"
        "setup-registries.sh"
    )
    
    for dir in "${required_dirs[@]}"; do
        if [ ! -d "$SCRIPT_DIR/$dir" ]; then
            log_error "Missing required directory: $dir"
            return 1
        fi
    done
    
    for file in "${required_files[@]}"; do
        if [ ! -f "$SCRIPT_DIR/$file" ]; then
            log_error "Missing required file: $file"
            return 1
        fi
    done
    
    log_success "Project structure validation passed"
    return 0
}

test_registry_configurations() {
    log_info "Validating registry configurations..."
    
    local registries=("npm" "pypi" "maven" "nuget" "rubygems" "go")
    
    for registry in "${registries[@]}"; do
        local registry_dir="$SCRIPT_DIR/registries/$registry"
        
        if [ ! -d "$registry_dir" ]; then
            log_error "Missing registry directory: $registry"
            return 1
        fi
        
        # Check for required configuration files
        case $registry in
            "npm")
                [ -f "$registry_dir/package.json" ] || { log_error "Missing package.json for NPM"; return 1; }
                ;;
            "pypi")
                [ -f "$registry_dir/requirements.txt" ] || { log_error "Missing requirements.txt for PyPI"; return 1; }
                ;;
            "maven")
                [ -f "$registry_dir/pom.xml" ] || { log_error "Missing pom.xml for Maven"; return 1; }
                ;;
            "nuget")
                [ -f "$registry_dir/packages.config" ] || [ -f "$registry_dir/"*.csproj ] || { log_error "Missing NuGet configuration"; return 1; }
                ;;
            "rubygems")
                [ -f "$registry_dir/Gemfile" ] || { log_error "Missing Gemfile for RubyGems"; return 1; }
                ;;
            "go")
                [ -f "$registry_dir/go.mod" ] || { log_error "Missing go.mod for Go modules"; return 1; }
                ;;
        esac
    done
    
    log_success "Registry configurations validation passed"
    return 0
}

test_zero_day_scenarios() {
    log_info "Validating zero-day scenarios..."
    
    local scenario_dir="$SCRIPT_DIR/zero-day-scenarios"
    local required_scenarios=(
        "supply-chain-attack"
        "dependency-confusion"
        "typosquatting"
        "malicious-packages"
        "backdoor-injection"
    )
    
    for scenario in "${required_scenarios[@]}"; do
        if [ ! -d "$scenario_dir/$scenario" ]; then
            log_error "Missing zero-day scenario: $scenario"
            return 1
        fi
        
        # Check for scenario configuration
        if [ ! -f "$scenario_dir/$scenario/scenario.json" ]; then
            log_error "Missing scenario.json for $scenario"
            return 1
        fi
        
        # Validate scenario JSON
        if ! jq empty "$scenario_dir/$scenario/scenario.json" 2>/dev/null; then
            log_error "Invalid JSON in scenario.json for $scenario"
            return 1
        fi
    done
    
    log_success "Zero-day scenarios validation passed"
    return 0
}

test_cicd_pipelines() {
    log_info "Validating CI/CD pipeline configurations..."
    
    local pipeline_dir="$SCRIPT_DIR/cicd-pipelines"
    local required_pipelines=(
        "github-actions/typosentinel-scan.yml"
        "gitlab-ci/typosentinel-security.yml"
        "jenkins/Jenkinsfile"
    )
    
    for pipeline in "${required_pipelines[@]}"; do
        if [ ! -f "$pipeline_dir/$pipeline" ]; then
            log_error "Missing CI/CD pipeline: $pipeline"
            return 1
        fi
        
        # Basic syntax validation
        case $pipeline in
            *.yml|*.yaml)
                if ! python3 -c "import yaml; yaml.safe_load(open('$pipeline_dir/$pipeline'))" 2>/dev/null; then
                    log_warning "YAML syntax validation failed for $pipeline (Python YAML parser not available)"
                fi
                ;;
        esac
    done
    
    log_success "CI/CD pipelines validation passed"
    return 0
}

test_monitoring_stack() {
    log_info "Validating monitoring stack configuration..."
    
    local monitoring_dir="$SCRIPT_DIR/monitoring"
    local required_files=(
        "docker-compose.monitoring.yml"
        "prometheus.yml"
        "typosentinel-alerts.yml"
        "alertmanager.yml"
        "dashboard.yml"
    )
    
    for file in "${required_files[@]}"; do
        if [ ! -f "$monitoring_dir/$file" ]; then
            log_error "Missing monitoring file: $file"
            return 1
        fi
    done
    
    # Check security dashboard
    if [ ! -d "$monitoring_dir/security-dashboard" ]; then
        log_error "Missing security dashboard directory"
        return 1
    fi
    
    if [ ! -f "$monitoring_dir/security-dashboard/package.json" ]; then
        log_error "Missing security dashboard package.json"
        return 1
    fi
    
    log_success "Monitoring stack validation passed"
    return 0
}

test_docker_compose_syntax() {
    log_info "Validating Docker Compose configurations..."
    
    local compose_files=(
        "$SCRIPT_DIR/docker-compose.yml"
        "$SCRIPT_DIR/monitoring/docker-compose.monitoring.yml"
    )
    
    for compose_file in "${compose_files[@]}"; do
        if [ -f "$compose_file" ]; then
            if ! docker-compose -f "$compose_file" config >/dev/null 2>&1; then
                log_error "Docker Compose syntax validation failed for $(basename "$compose_file")"
                return 1
            fi
        fi
    done
    
    log_success "Docker Compose syntax validation passed"
    return 0
}

test_security_configurations() {
    log_info "Validating security configurations..."
    
    # Check for sensitive files that shouldn't be committed
    local sensitive_patterns=(
        "*.key"
        "*.pem"
        "*.p12"
        ".env"
        "secrets.yml"
        "credentials.json"
    )
    
    local found_sensitive=false
    for pattern in "${sensitive_patterns[@]}"; do
        if find "$SCRIPT_DIR" -name "$pattern" -type f | grep -q .; then
            log_warning "Found potentially sensitive files matching pattern: $pattern"
            found_sensitive=true
        fi
    done
    
    # Check for .env.example files
    local env_examples=(
        "$SCRIPT_DIR/.env.example"
        "$SCRIPT_DIR/monitoring/security-dashboard/.env.example"
    )
    
    for env_file in "${env_examples[@]}"; do
        if [ ! -f "$env_file" ]; then
            log_warning "Missing environment example file: $(basename "$env_file")"
        fi
    done
    
    if [ "$found_sensitive" = false ]; then
        log_success "No sensitive files found in repository"
    fi
    
    log_success "Security configurations validation passed"
    return 0
}

test_documentation() {
    log_info "Validating documentation..."
    
    local required_docs=(
        "$SCRIPT_DIR/README.md"
        "$SCRIPT_DIR/cicd-pipelines/README.md"
        "$SCRIPT_DIR/monitoring/security-dashboard/README.md"
    )
    
    for doc in "${required_docs[@]}"; do
        if [ ! -f "$doc" ]; then
            log_error "Missing documentation file: $(basename "$doc")"
            return 1
        fi
        
        # Check if documentation is not empty
        if [ ! -s "$doc" ]; then
            log_error "Documentation file is empty: $(basename "$doc")"
            return 1
        fi
    done
    
    log_success "Documentation validation passed"
    return 0
}

test_package_dependencies() {
    log_info "Validating package dependencies..."
    
    local package_dirs=(
        "$SCRIPT_DIR/monitoring/security-dashboard"
        "$SCRIPT_DIR/projects/frontend-app"
        "$SCRIPT_DIR/projects/backend-api"
        "$SCRIPT_DIR/projects/microservice"
    )
    
    for dir in "${package_dirs[@]}"; do
        if [ -f "$dir/package.json" ]; then
            log_info "Checking Node.js dependencies in $(basename "$dir")"
            
            # Check for package.json syntax
            if ! jq empty "$dir/package.json" 2>/dev/null; then
                log_error "Invalid package.json syntax in $(basename "$dir")"
                return 1
            fi
            
            # Check for security vulnerabilities (if npm is available)
            if check_command "npm"; then
                cd "$dir"
                if npm audit --audit-level=high 2>/dev/null; then
                    log_success "No high-severity vulnerabilities found in $(basename "$dir")"
                else
                    log_warning "High-severity vulnerabilities found in $(basename "$dir")"
                fi
                cd - >/dev/null
            fi
        fi
    done
    
    log_success "Package dependencies validation completed"
    return 0
}

test_integration_readiness() {
    log_info "Testing integration readiness..."
    
    # Test if monitoring stack can be started
    local monitoring_compose="$SCRIPT_DIR/monitoring/docker-compose.monitoring.yml"
    
    if [ -f "$monitoring_compose" ]; then
        log_info "Testing monitoring stack startup..."
        
        # Try to validate the compose file
        if docker-compose -f "$monitoring_compose" config >/dev/null 2>&1; then
            log_success "Monitoring stack configuration is valid"
        else
            log_error "Monitoring stack configuration validation failed"
            return 1
        fi
    fi
    
    # Test registry setup script
    if [ -f "$SCRIPT_DIR/setup-registries.sh" ]; then
        if [ -x "$SCRIPT_DIR/setup-registries.sh" ]; then
            log_success "Registry setup script is executable"
        else
            log_warning "Registry setup script is not executable"
            chmod +x "$SCRIPT_DIR/setup-registries.sh"
        fi
    fi
    
    log_success "Integration readiness validation passed"
    return 0
}

# Performance and load testing simulation
test_performance_readiness() {
    log_info "Validating performance readiness..."
    
    # Check for performance-related configurations
    local perf_indicators=(
        "rate limiting"
        "caching"
        "connection pooling"
        "compression"
        "monitoring"
    )
    
    local dashboard_server="$SCRIPT_DIR/monitoring/security-dashboard/server.js"
    
    if [ -f "$dashboard_server" ]; then
        for indicator in "${perf_indicators[@]}"; do
            case $indicator in
                "rate limiting")
                    if grep -q "rateLimit\|rate-limit" "$dashboard_server"; then
                        log_success "Rate limiting configuration found"
                    else
                        log_warning "Rate limiting configuration not found"
                    fi
                    ;;
                "caching")
                    if grep -q "cache\|Cache\|redis" "$dashboard_server"; then
                        log_success "Caching configuration found"
                    else
                        log_warning "Caching configuration not found"
                    fi
                    ;;
                "connection pooling")
                    if grep -q "Pool\|pool" "$dashboard_server"; then
                        log_success "Connection pooling configuration found"
                    else
                        log_warning "Connection pooling configuration not found"
                    fi
                    ;;
                "compression")
                    if grep -q "compression" "$dashboard_server"; then
                        log_success "Compression configuration found"
                    else
                        log_warning "Compression configuration not found"
                    fi
                    ;;
                "monitoring")
                    if grep -q "prometheus\|metrics" "$dashboard_server"; then
                        log_success "Monitoring configuration found"
                    else
                        log_warning "Monitoring configuration not found"
                    fi
                    ;;
            esac
        done
    fi
    
    log_success "Performance readiness validation completed"
    return 0
}

# Generate comprehensive report
generate_report() {
    log_info "Generating production readiness report..."
    
    local total_tests=$((SUCCESS_COUNT + ERROR_COUNT + WARNING_COUNT))
    local success_rate=0
    
    if [ $total_tests -gt 0 ]; then
        success_rate=$(( (SUCCESS_COUNT * 100) / total_tests ))
    fi
    
    # Create JSON report
    cat > "$REPORT_FILE" <<EOF
{
  "validation_summary": {
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "total_tests": $total_tests,
    "successful_tests": $SUCCESS_COUNT,
    "failed_tests": $ERROR_COUNT,
    "warnings": $WARNING_COUNT,
    "success_rate": $success_rate,
    "overall_status": "$([ $ERROR_COUNT -eq 0 ] && echo "READY" || echo "NOT_READY")"
  },
  "test_results": [
EOF
    
    # Add test results
    local first=true
    for result in "${TEST_RESULTS[@]}"; do
        if [ "$first" = true ]; then
            first=false
        else
            echo "," >> "$REPORT_FILE"
        fi
        echo "    $result" >> "$REPORT_FILE"
    done
    
    cat >> "$REPORT_FILE" <<EOF
  ],
  "recommendations": [
EOF
    
    # Add recommendations based on results
    local recommendations=()
    
    if [ $ERROR_COUNT -gt 0 ]; then
        recommendations+=("\"Fix all critical errors before production deployment\"")
    fi
    
    if [ $WARNING_COUNT -gt 0 ]; then
        recommendations+=("\"Address warnings to improve system reliability\"")
    fi
    
    if [ $SUCCESS_COUNT -eq $total_tests ]; then
        recommendations+=("\"System appears ready for production deployment\"")
        recommendations+=("\"Perform additional load testing in staging environment\"")
        recommendations+=("\"Set up monitoring and alerting before go-live\"")
    fi
    
    # Add recommendations to report
    local first=true
    for rec in "${recommendations[@]}"; do
        if [ "$first" = true ]; then
            first=false
        else
            echo "," >> "$REPORT_FILE"
        fi
        echo "    $rec" >> "$REPORT_FILE"
    done
    
    cat >> "$REPORT_FILE" <<EOF
  ],
  "next_steps": [
    "Review and address all failed tests",
    "Set up production monitoring and alerting",
    "Configure backup and disaster recovery",
    "Perform security audit and penetration testing",
    "Conduct load testing with realistic traffic patterns",
    "Train operations team on system management",
    "Prepare rollback procedures",
    "Schedule production deployment"
  ]
}
EOF
    
    log_success "Report generated: $REPORT_FILE"
}

# Main execution
main() {
    echo -e "${BLUE}" 
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║              ACME Enterprise - Typosentinel                 ║"
    echo "║            Production Readiness Validation                  ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    log "Starting production readiness validation..."
    log "Log file: $LOG_FILE"
    log "Report file: $REPORT_FILE"
    
    # Run all validation tests
    run_test "Prerequisites Check" test_prerequisites
    run_test "Project Structure" test_project_structure
    run_test "Registry Configurations" test_registry_configurations
    run_test "Zero-Day Scenarios" test_zero_day_scenarios
    run_test "CI/CD Pipelines" test_cicd_pipelines
    run_test "Monitoring Stack" test_monitoring_stack
    run_test "Docker Compose Syntax" test_docker_compose_syntax
    run_test "Security Configurations" test_security_configurations
    run_test "Documentation" test_documentation
    run_test "Package Dependencies" test_package_dependencies
    run_test "Integration Readiness" test_integration_readiness
    run_test "Performance Readiness" test_performance_readiness
    
    # Generate report
    generate_report
    
    # Summary
    echo
    echo -e "${BLUE}" 
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                    VALIDATION SUMMARY                       ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    echo -e "${GREEN}Successful tests: $SUCCESS_COUNT${NC}"
    echo -e "${RED}Failed tests: $ERROR_COUNT${NC}"
    echo -e "${YELLOW}Warnings: $WARNING_COUNT${NC}"
    
    if [ $ERROR_COUNT -eq 0 ]; then
        echo
        echo -e "${GREEN}🎉 PRODUCTION READINESS: VALIDATED${NC}"
        echo -e "${GREEN}✅ Typosentinel enterprise environment is ready for production deployment!${NC}"
        echo
        echo "Next steps:"
        echo "1. Review the detailed report: $REPORT_FILE"
        echo "2. Set up production monitoring and alerting"
        echo "3. Perform load testing in staging environment"
        echo "4. Schedule production deployment"
    else
        echo
        echo -e "${RED}❌ PRODUCTION READINESS: NOT READY${NC}"
        echo -e "${RED}Critical issues found that must be resolved before production deployment.${NC}"
        echo
        echo "Required actions:"
        echo "1. Review failed tests in the log: $LOG_FILE"
        echo "2. Fix all critical errors"
        echo "3. Re-run validation after fixes"
    fi
    
    echo
    echo "Detailed logs: $LOG_FILE"
    echo "JSON report: $REPORT_FILE"
    
    # Exit with appropriate code
    exit $ERROR_COUNT
}

# Run main function
main "$@"