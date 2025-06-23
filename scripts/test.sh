#!/bin/bash

# TypoSentinel Test Script
# This script runs comprehensive tests for the TypoSentinel application

set -e

# Configuration
APP_NAME="typosentinel"
TEST_TIMEOUT=${TEST_TIMEOUT:-"10m"}
COVERAGE_THRESHOLD=${COVERAGE_THRESHOLD:-"80"}
TEST_DB_NAME="typosentinel_test"
TEST_DB_USER="postgres"
TEST_DB_PASSWORD="test123"
TEST_DB_HOST="localhost"
TEST_DB_PORT="5432"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check dependencies
check_dependencies() {
    log_info "Checking test dependencies..."
    
    # Check Go
    if ! command -v go &> /dev/null; then
        log_error "Go is required for running tests"
        exit 1
    fi
    
    # Check Python3
    if ! command -v python3 &> /dev/null; then
        log_error "Python3 is required for ML tests"
        exit 1
    fi
    
    # Check pip
    if ! command -v pip3 &> /dev/null; then
        log_error "pip3 is required for Python dependencies"
        exit 1
    fi
    
    # Check PostgreSQL (optional for integration tests)
    if command -v psql &> /dev/null; then
        log_info "PostgreSQL client found - integration tests will be available"
    else
        log_warning "PostgreSQL client not found - skipping database integration tests"
    fi
    
    log_success "Dependencies check completed"
}

# Setup test environment
setup_test_env() {
    log_info "Setting up test environment..."
    
    # Set test environment variables
    export GO_ENV="test"
    export DB_HOST="$TEST_DB_HOST"
    export DB_PORT="$TEST_DB_PORT"
    export DB_NAME="$TEST_DB_NAME"
    export DB_USER="$TEST_DB_USER"
    export DB_PASSWORD="$TEST_DB_PASSWORD"
    export ML_API_KEY="test-key"
    export ML_BASE_URL="http://localhost:8001"
    
    # Create test directories
    mkdir -p test-results
    mkdir -p coverage
    
    log_success "Test environment setup completed"
}

# Setup test database
setup_test_database() {
    if ! command -v psql &> /dev/null; then
        log_warning "PostgreSQL not available - skipping database setup"
        return 0
    fi
    
    log_info "Setting up test database..."
    
    # Check if PostgreSQL is running
    if ! pg_isready -h "$TEST_DB_HOST" -p "$TEST_DB_PORT" &> /dev/null; then
        log_warning "PostgreSQL is not running - skipping database tests"
        return 0
    fi
    
    # Drop test database if exists
    dropdb -h "$TEST_DB_HOST" -p "$TEST_DB_PORT" -U "$TEST_DB_USER" "$TEST_DB_NAME" 2>/dev/null || true
    
    # Create test database
    createdb -h "$TEST_DB_HOST" -p "$TEST_DB_PORT" -U "$TEST_DB_USER" "$TEST_DB_NAME" || {
        log_warning "Failed to create test database - skipping database tests"
        return 0
    }
    
    log_success "Test database setup completed"
}

# Install Python test dependencies
setup_python_deps() {
    log_info "Installing Python test dependencies..."
    
    # Check if ml directory exists and has requirements.txt
    if [ -d "ml" ] && [ -f "ml/requirements.txt" ]; then
        cd ml
        
        # Install main dependencies
        python3 -m pip install -r requirements.txt --quiet
        
        # Install test dependencies
        python3 -m pip install pytest pytest-cov pytest-asyncio httpx --quiet
        
        cd ..
        
        log_success "Python dependencies installed"
    else
        log_info "No Python ML dependencies found - ML components are implemented in Go"
    fi
}

# Run Go unit tests
run_go_unit_tests() {
    log_info "Running Go unit tests..."
    
    # Run tests with coverage
    go test -v -race -coverprofile=coverage/go-unit.out -covermode=atomic ./... -timeout="$TEST_TIMEOUT" | tee test-results/go-unit.log
    
    # Generate coverage report
    go tool cover -html=coverage/go-unit.out -o coverage/go-unit.html
    
    # Check coverage threshold
    local coverage=$(go tool cover -func=coverage/go-unit.out | grep total | awk '{print $3}' | sed 's/%//')
    if (( $(echo "$coverage < $COVERAGE_THRESHOLD" | bc -l) )); then
        log_warning "Go unit test coverage ($coverage%) is below threshold ($COVERAGE_THRESHOLD%)"
    else
        log_success "Go unit test coverage: $coverage%"
    fi
    
    log_success "Go unit tests completed"
}

# Run Go integration tests
run_go_integration_tests() {
    if ! command -v psql &> /dev/null; then
        log_warning "PostgreSQL not available - skipping Go integration tests"
        return 0
    fi
    
    if ! pg_isready -h "$TEST_DB_HOST" -p "$TEST_DB_PORT" &> /dev/null; then
        log_warning "PostgreSQL not running - skipping Go integration tests"
        return 0
    fi
    
    log_info "Running Go integration tests..."
    
    # Run integration tests with database
    go test -v -race -tags=integration -coverprofile=coverage/go-integration.out -covermode=atomic ./... -timeout="$TEST_TIMEOUT" | tee test-results/go-integration.log
    
    # Generate coverage report
    go tool cover -html=coverage/go-integration.out -o coverage/go-integration.html
    
    log_success "Go integration tests completed"
}

# Run Python unit tests
run_python_unit_tests() {
    log_info "Running Python unit tests..."
    
    # Check if ml directory exists and has Python tests
    if [ -d "ml" ] && [ -d "ml/tests" ]; then
        cd ml
        
        # Run pytest with coverage
        python3 -m pytest tests/ -v --cov=. --cov-report=html:../coverage/python-unit --cov-report=term --cov-report=xml:../coverage/python-unit.xml | tee ../test-results/python-unit.log
        
        cd ..
        
        log_success "Python unit tests completed"
    else
        log_info "No Python unit tests found - ML components are implemented in Go"
    fi
}

# Run API tests
run_api_tests() {
    log_info "Running API tests..."
    
    # Start test server in background
    local server_pid
    if [[ -f "./bin/typosentinel-server" ]]; then
        ./bin/typosentinel-server --config test-config.yaml --port 8081 &
        server_pid=$!
        
        # Wait for server to start
        sleep 5
        
        # Run API tests
        go test -v -tags=api ./tests/api/... -timeout="$TEST_TIMEOUT" | tee test-results/api.log
        
        # Stop test server
        kill $server_pid 2>/dev/null || true
    else
        log_warning "Server binary not found - skipping API tests"
    fi
    
    log_success "API tests completed"
}

# Run ML service tests
run_ml_service_tests() {
    log_info "Running ML service tests..."
    
    # Check if ml directory exists and has service
    if [ -d "ml" ] && [ -f "ml/service/api_server.py" ]; then
        cd ml
        
        # Start ML service in background
        python3 service/api_server.py --host localhost --port 8001 &
        local ml_pid=$!
        
        # Wait for service to start
        sleep 10
        
        # Run ML service tests
        python3 -m pytest tests/test_api_server.py -v | tee ../test-results/ml-service.log
        
        # Stop ML service
        kill $ml_pid 2>/dev/null || true
        
        cd ..
        
        log_success "ML service tests completed"
    else
        log_info "No ML service found - ML components are implemented in Go"
    fi
    
    cd ..
    
    log_success "ML service tests completed"
}

# Run performance tests
run_performance_tests() {
    log_info "Running performance tests..."
    
    # Run Go benchmarks
    go test -bench=. -benchmem ./... | tee test-results/performance.log
    
    log_success "Performance tests completed"
}

# Run security tests
run_security_tests() {
    log_info "Running security tests..."
    
    # Check for common security issues
    if command -v gosec &> /dev/null; then
        gosec ./... | tee test-results/security.log
    else
        log_warning "gosec not found - install with: go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest"
    fi
    
    # Check for vulnerabilities in dependencies
    if command -v govulncheck &> /dev/null; then
        govulncheck ./... | tee test-results/vulnerabilities.log
    else
        log_warning "govulncheck not found - install with: go install golang.org/x/vuln/cmd/govulncheck@latest"
    fi
    
    log_success "Security tests completed"
}

# Run linting
run_linting() {
    log_info "Running linting..."
    
    # Go linting
    if command -v golangci-lint &> /dev/null; then
        golangci-lint run ./... | tee test-results/go-lint.log
    else
        log_warning "golangci-lint not found - install from https://golangci-lint.run/usage/install/"
        # Fallback to basic tools
        go vet ./... | tee test-results/go-vet.log
        if command -v gofmt &> /dev/null; then
            gofmt -l . | tee test-results/go-fmt.log
        fi
    fi
    
    # Python linting
    if [ -d "ml" ]; then
        cd ml
        if command -v flake8 &> /dev/null; then
            flake8 . | tee ../test-results/python-lint.log
        else
            log_warning "flake8 not found - install with: pip install flake8"
        fi
        
        if command -v black &> /dev/null; then
            black --check . | tee ../test-results/python-format.log
        else
            log_warning "black not found - install with: pip install black"
        fi
        cd ..
    else
        log_info "No Python code found for linting - ML components are implemented in Go"
    fi
    
    log_success "Linting completed"
}

# Generate test report
generate_test_report() {
    log_info "Generating test report..."
    
    local report_file="test-results/test-report.html"
    
    cat > "$report_file" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>TypoSentinel Test Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f0f0f0; padding: 20px; border-radius: 5px; }
        .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
        .success { background-color: #d4edda; border-color: #c3e6cb; }
        .warning { background-color: #fff3cd; border-color: #ffeaa7; }
        .error { background-color: #f8d7da; border-color: #f5c6cb; }
        .code { background-color: #f8f9fa; padding: 10px; border-radius: 3px; font-family: monospace; }
    </style>
</head>
<body>
    <div class="header">
        <h1>TypoSentinel Test Report</h1>
        <p>Generated on: $(date)</p>
        <p>Test Environment: $(go version), $(python3 --version)</p>
    </div>
EOF
    
    # Add test results sections
    for log_file in test-results/*.log; do
        if [[ -f "$log_file" ]]; then
            local test_name=$(basename "$log_file" .log)
            echo "    <div class=\"section\">" >> "$report_file"
            echo "        <h2>$test_name</h2>" >> "$report_file"
            echo "        <div class=\"code\">" >> "$report_file"
            echo "            <pre>$(cat "$log_file" | tail -20)</pre>" >> "$report_file"
            echo "        </div>" >> "$report_file"
            echo "    </div>" >> "$report_file"
        fi
    done
    
    echo "</body></html>" >> "$report_file"
    
    log_success "Test report generated: $report_file"
}

# Cleanup test environment
cleanup_test_env() {
    log_info "Cleaning up test environment..."
    
    # Drop test database
    if command -v psql &> /dev/null && pg_isready -h "$TEST_DB_HOST" -p "$TEST_DB_PORT" &> /dev/null; then
        dropdb -h "$TEST_DB_HOST" -p "$TEST_DB_PORT" -U "$TEST_DB_USER" "$TEST_DB_NAME" 2>/dev/null || true
    fi
    
    # Kill any remaining test processes
    pkill -f "typosentinel-server.*8081" 2>/dev/null || true
    pkill -f "api_server.py.*8001" 2>/dev/null || true
    
    log_success "Test environment cleaned up"
}

# Show usage
show_usage() {
    echo "Usage: $0 [OPTIONS] [TEST_TYPE]"
    echo ""
    echo "Test Types:"
    echo "  all           Run all tests (default)"
    echo "  unit          Run unit tests only"
    echo "  integration   Run integration tests only"
    echo "  api           Run API tests only"
    echo "  ml            Run ML service tests only"
    echo "  performance   Run performance tests only"
    echo "  security      Run security tests only"
    echo "  lint          Run linting only"
    echo ""
    echo "Options:"
    echo "  -c, --coverage THRESHOLD  Set coverage threshold (default: 80)"
    echo "  -t, --timeout DURATION    Set test timeout (default: 10m)"
    echo "  --no-cleanup              Skip cleanup after tests"
    echo "  --no-setup                Skip test environment setup"
    echo "  -h, --help                Show this help message"
    echo ""
    echo "Environment Variables:"
    echo "  COVERAGE_THRESHOLD        Set coverage threshold"
    echo "  TEST_TIMEOUT              Set test timeout"
    echo "  TEST_DB_HOST              Test database host"
    echo "  TEST_DB_PORT              Test database port"
    echo "  TEST_DB_USER              Test database user"
    echo "  TEST_DB_PASSWORD          Test database password"
    echo ""
    echo "Examples:"
    echo "  $0 all"
    echo "  $0 unit --coverage 85"
    echo "  $0 integration --timeout 15m"
    echo "  $0 lint"
}

# Main execution
main() {
    local test_type="all"
    local skip_cleanup=false
    local skip_setup=false
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_usage
                exit 0
                ;;
            -c|--coverage)
                COVERAGE_THRESHOLD="$2"
                shift 2
                ;;
            -t|--timeout)
                TEST_TIMEOUT="$2"
                shift 2
                ;;
            --no-cleanup)
                skip_cleanup=true
                shift
                ;;
            --no-setup)
                skip_setup=true
                shift
                ;;
            all|unit|integration|api|ml|performance|security|lint)
                test_type="$1"
                shift
                ;;
            *)
                log_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    log_info "TypoSentinel Test Script"
    log_info "Test Type: $test_type"
    log_info "Coverage Threshold: $COVERAGE_THRESHOLD%"
    log_info "Test Timeout: $TEST_TIMEOUT"
    
    # Setup
    if [[ "$skip_setup" != "true" ]]; then
        check_dependencies
        setup_test_env
        setup_test_database
        setup_python_deps
    fi
    
    # Run tests based on type
    case $test_type in
        all)
            run_go_unit_tests
            run_go_integration_tests
            run_python_unit_tests
            run_api_tests
            run_ml_service_tests
            run_performance_tests
            run_security_tests
            run_linting
            ;;
        unit)
            run_go_unit_tests
            run_python_unit_tests
            ;;
        integration)
            run_go_integration_tests
            ;;
        api)
            run_api_tests
            ;;
        ml)
            run_python_unit_tests
            run_ml_service_tests
            ;;
        performance)
            run_performance_tests
            ;;
        security)
            run_security_tests
            ;;
        lint)
            run_linting
            ;;
        *)
            log_error "Unknown test type: $test_type"
            exit 1
            ;;
    esac
    
    # Generate report
    generate_test_report
    
    # Cleanup
    if [[ "$skip_cleanup" != "true" ]]; then
        cleanup_test_env
    fi
    
    log_success "Test script completed successfully!"
    log_info "Test results available in: test-results/"
    log_info "Coverage reports available in: coverage/"
}

# Trap to ensure cleanup on exit
trap 'cleanup_test_env' EXIT

# Run main function
main "$@"