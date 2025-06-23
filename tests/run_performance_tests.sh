#!/bin/bash

# Performance Testing Script for Typosentinel
# Implements testing plan sections P001 and P002

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
REPORT_FILE="performance_test_report.txt"
JSON_REPORT="performance_test_results.json"
TEST_DIR="/Users/alikorsi/Documents/Typosentinel"
LOG_FILE="performance_test.log"

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to log with timestamp
log_with_timestamp() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Function to check prerequisites
check_prerequisites() {
    print_status "Checking prerequisites..."
    
    # Check if Go is installed
    if ! command -v go &> /dev/null; then
        print_error "Go is not installed or not in PATH"
        exit 1
    fi
    
    # Check if we're in the right directory
    if [ ! -f "main.go" ]; then
        print_error "main.go not found. Please run this script from the Typosentinel root directory."
        exit 1
    fi
    
    # Check if test files exist
    if [ ! -f "performance_test.go" ]; then
        print_error "performance_test.go not found. Please ensure performance test files are present."
        exit 1
    fi
    
    if [ ! -f "load_test.go" ]; then
        print_error "load_test.go not found. Please ensure load test files are present."
        exit 1
    fi
    
    print_success "Prerequisites check passed"
}

# Function to setup test environment
setup_test_environment() {
    print_status "Setting up test environment..."
    
    # Create test directories if they don't exist
    mkdir -p test-analysis/npm-project
    mkdir -p test-analysis/python-project
    mkdir -p test-analysis/go-project
    
    # Create sample package.json for npm project testing
    cat > test-analysis/npm-project/package.json << 'EOF'
{
  "name": "test-large-project",
  "version": "1.0.0",
  "description": "Large test project for performance testing",
  "dependencies": {
    "lodash": "^4.17.21",
    "express": "^4.18.0",
    "react": "^18.0.0",
    "webpack": "^5.70.0",
    "babel-core": "^6.26.3",
    "eslint": "^8.0.0",
    "typescript": "^4.5.0",
    "jest": "^27.0.0",
    "moment": "^2.29.0",
    "axios": "^0.26.0",
    "underscore": "^1.13.0",
    "jquery": "^3.6.0",
    "bootstrap": "^5.1.0",
    "chalk": "^4.1.0",
    "commander": "^8.3.0",
    "inquirer": "^8.2.0",
    "yargs": "^17.3.0",
    "debug": "^4.3.0",
    "async": "^3.2.0",
    "bluebird": "^3.7.0"
  },
  "devDependencies": {
    "@types/node": "^17.0.0",
    "@types/lodash": "^4.14.0",
    "@types/express": "^4.17.0",
    "nodemon": "^2.0.0",
    "concurrently": "^7.0.0"
  }
}
EOF
    
    # Create sample requirements.txt for Python project testing
    cat > test-analysis/python-project/requirements.txt << 'EOF'
numpy==1.21.0
pandas==1.3.0
scipy==1.7.0
scikit-learn==0.24.0
matplotlib==3.4.0
seaborn==0.11.0
requests==2.25.0
flask==2.0.0
django==3.2.0
sqlalchemy==1.4.0
psycopg2==2.9.0
celery==5.1.0
redis==3.5.0
gunicorn==20.1.0
nginx==1.0.0
docker==5.0.0
kubernetes==18.20.0
tensorflow==2.5.0
pytorch==1.9.0
jupyter==1.0.0
EOF
    
    # Create sample go.mod for Go project testing
    cat > test-analysis/go-project/go.mod << 'EOF'
module test-large-go-project

go 1.19

require (
    github.com/gin-gonic/gin v1.8.1
    github.com/gorilla/mux v1.8.0
    github.com/gorilla/websocket v1.5.0
    github.com/go-redis/redis/v8 v8.11.5
    github.com/lib/pq v1.10.6
    github.com/golang-migrate/migrate/v4 v4.15.2
    github.com/stretchr/testify v1.8.0
    github.com/sirupsen/logrus v1.9.0
    github.com/spf13/cobra v1.5.0
    github.com/spf13/viper v1.12.0
    gorm.io/gorm v1.23.8
    gorm.io/driver/postgres v1.3.8
    github.com/golang-jwt/jwt/v4 v4.4.2
    github.com/go-playground/validator/v10 v10.11.0
    github.com/swaggo/swag v1.8.4
    github.com/prometheus/client_golang v1.12.2
    go.uber.org/zap v1.21.0
    go.uber.org/fx v1.18.1
    github.com/google/wire v0.5.0
    k8s.io/client-go v0.24.3
)
EOF
    
    # Create a simple main.go for the Go project
    cat > test-analysis/go-project/main.go << 'EOF'
package main

import (
    "fmt"
    "github.com/gin-gonic/gin"
    "github.com/sirupsen/logrus"
)

func main() {
    logrus.Info("Starting test application")
    r := gin.Default()
    r.GET("/health", func(c *gin.Context) {
        c.JSON(200, gin.H{"status": "ok"})
    })
    fmt.Println("Test Go application with multiple dependencies")
}
EOF
    
    print_success "Test environment setup completed"
}

# Function to run P001.1 - Single Package Performance Tests
run_single_package_tests() {
    print_status "Running P001.1 - Single Package Performance Tests..."
    log_with_timestamp "Starting single package performance tests"
    
    echo "=== P001.1: Single Package Performance Tests ===" >> "$REPORT_FILE"
    echo "Test Date: $(date)" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    
    # Run the Go tests with verbose output
    if go test -v -run "TestP001_1_SinglePackagePerformance" -timeout 10m >> "$REPORT_FILE" 2>&1; then
        print_success "Single package performance tests completed"
    else
        print_warning "Some single package performance tests may have failed - check report for details"
    fi
    
    echo "" >> "$REPORT_FILE"
    log_with_timestamp "Single package performance tests completed"
}

# Function to run P001.2 - Batch Scanning Performance Tests
run_batch_scanning_tests() {
    print_status "Running P001.2 - Batch Scanning Performance Tests..."
    log_with_timestamp "Starting batch scanning performance tests"
    
    echo "=== P001.2: Batch Scanning Performance Tests ===" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    
    # Run batch performance tests
    if go test -v -run "TestP001_2_BatchScanningPerformance" -timeout 15m >> "$REPORT_FILE" 2>&1; then
        print_success "Batch scanning performance tests completed"
    else
        print_warning "Some batch scanning performance tests may have failed - check report for details"
    fi
    
    echo "" >> "$REPORT_FILE"
    log_with_timestamp "Batch scanning performance tests completed"
}

# Function to run P001.2 - Stress Tests
run_stress_tests() {
    print_status "Running P001.2 - Stress Tests (1000 packages)..."
    log_with_timestamp "Starting stress tests"
    
    echo "=== P001.2: Stress Testing (1000 packages) ===" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    
    # Run stress tests (only if not in short mode)
    if go test -v -run "TestP001_2_StressTest" -timeout 30m >> "$REPORT_FILE" 2>&1; then
        print_success "Stress tests completed"
    else
        print_warning "Stress tests may have failed or been skipped - check report for details"
    fi
    
    echo "" >> "$REPORT_FILE"
    log_with_timestamp "Stress tests completed"
}

# Function to run P002.1 - API Load Testing
run_api_load_tests() {
    print_status "Running P002.1 - API Load Testing..."
    log_with_timestamp "Starting API load tests"
    
    echo "=== P002.1: API Load Testing ===" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    
    # Run API load tests
    if go test -v -run "TestP002_1_APILoadTesting" -timeout 20m >> "$REPORT_FILE" 2>&1; then
        print_success "API load tests completed"
    else
        print_warning "API load tests may have failed or been skipped - check report for details"
    fi
    
    echo "" >> "$REPORT_FILE"
    log_with_timestamp "API load tests completed"
}

# Function to run P002.2 - Large Project Testing
run_large_project_tests() {
    print_status "Running P002.2 - Large Project Testing..."
    log_with_timestamp "Starting large project tests"
    
    echo "=== P002.2: Large Project Testing ===" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    
    # Run large project tests
    if go test -v -run "TestP002_2_LargeProjectTesting" -timeout 25m >> "$REPORT_FILE" 2>&1; then
        print_success "Large project tests completed"
    else
        print_warning "Large project tests may have failed or been skipped - check report for details"
    fi
    
    echo "" >> "$REPORT_FILE"
    log_with_timestamp "Large project tests completed"
}

# Function to run benchmarks
run_benchmarks() {
    print_status "Running Performance Benchmarks..."
    log_with_timestamp "Starting performance benchmarks"
    
    echo "=== Performance Benchmarks ===" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    
    # Run benchmarks
    echo "Single Package Scan Benchmarks:" >> "$REPORT_FILE"
    go test -bench="BenchmarkSinglePackageScan" -benchtime=10s -timeout 10m >> "$REPORT_FILE" 2>&1 || true
    
    echo "" >> "$REPORT_FILE"
    echo "Batch Scanning Benchmarks:" >> "$REPORT_FILE"
    go test -bench="BenchmarkBatchScanning" -benchtime=5s -timeout 15m >> "$REPORT_FILE" 2>&1 || true
    
    echo "" >> "$REPORT_FILE"
    echo "API Endpoint Benchmarks:" >> "$REPORT_FILE"
    go test -bench="BenchmarkAPIEndpoint" -benchtime=3s -timeout 5m >> "$REPORT_FILE" 2>&1 || true
    
    echo "" >> "$REPORT_FILE"
    echo "Large Project Scan Benchmarks:" >> "$REPORT_FILE"
    go test -bench="BenchmarkLargeProjectScan" -benchtime=3s -timeout 10m >> "$REPORT_FILE" 2>&1 || true
    
    echo "" >> "$REPORT_FILE"
    print_success "Performance benchmarks completed"
    log_with_timestamp "Performance benchmarks completed"
}

# Function to generate system information
generate_system_info() {
    print_status "Collecting system information..."
    
    echo "=== System Information ===" >> "$REPORT_FILE"
    echo "Test Date: $(date)" >> "$REPORT_FILE"
    echo "Hostname: $(hostname)" >> "$REPORT_FILE"
    echo "Operating System: $(uname -a)" >> "$REPORT_FILE"
    echo "Go Version: $(go version)" >> "$REPORT_FILE"
    echo "CPU Info: $(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo 'N/A')" >> "$REPORT_FILE"
    echo "CPU Cores: $(sysctl -n hw.ncpu 2>/dev/null || echo 'N/A')" >> "$REPORT_FILE"
    echo "Memory: $(sysctl -n hw.memsize 2>/dev/null | awk '{print $1/1024/1024/1024 " GB"}' || echo 'N/A')" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    
    print_success "System information collected"
}

# Function to generate summary
generate_summary() {
    print_status "Generating test summary..."
    
    echo "=== Test Summary ===" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    
    # Count test results
    local passed_tests=$(grep -c "PASS:" "$REPORT_FILE" 2>/dev/null || echo "0")
    local failed_tests=$(grep -c "FAIL:" "$REPORT_FILE" 2>/dev/null || echo "0")
    local skipped_tests=$(grep -c "SKIP:" "$REPORT_FILE" 2>/dev/null || echo "0")
    
    echo "Tests Passed: $passed_tests" >> "$REPORT_FILE"
    echo "Tests Failed: $failed_tests" >> "$REPORT_FILE"
    echo "Tests Skipped: $skipped_tests" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    
    # Performance metrics summary
    echo "Performance Requirements Validation:" >> "$REPORT_FILE"
    echo "- Single package scan time: <2 seconds" >> "$REPORT_FILE"
    echo "- Memory usage: <100MB for standard packages" >> "$REPORT_FILE"
    echo "- CPU utilization: <50% on single core" >> "$REPORT_FILE"
    echo "- Batch scan (100 packages): <30 seconds" >> "$REPORT_FILE"
    echo "- Batch memory usage: <1GB for 100 packages" >> "$REPORT_FILE"
    echo "- API response time: <500ms (95th percentile)" >> "$REPORT_FILE"
    echo "- API throughput: >1000 requests/minute" >> "$REPORT_FILE"
    echo "- API error rate: <1%" >> "$REPORT_FILE"
    echo "- Large project scan: <5 minutes" >> "$REPORT_FILE"
    echo "- Large project memory: <2GB" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    
    echo "Test completed at: $(date)" >> "$REPORT_FILE"
    echo "Total test duration: $(($(date +%s) - start_time)) seconds" >> "$REPORT_FILE"
    
    print_success "Test summary generated"
}

# Function to create JSON report
create_json_report() {
    print_status "Creating JSON performance report..."
    
    cat > "$JSON_REPORT" << EOF
{
  "test_run": {
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "duration_seconds": $(($(date +%s) - start_time)),
    "hostname": "$(hostname)",
    "go_version": "$(go version | cut -d' ' -f3)",
    "os": "$(uname -s)",
    "arch": "$(uname -m)"
  },
  "test_categories": {
    "P001_1_single_package": {
      "description": "Individual package scan speed",
      "requirements": {
        "scan_time_limit": "2 seconds",
        "memory_limit": "100MB",
        "cpu_limit": "50%"
      }
    },
    "P001_2_batch_scanning": {
      "description": "Multiple package scanning",
      "requirements": {
        "100_packages_time_limit": "30 seconds",
        "100_packages_memory_limit": "1GB"
      }
    },
    "P002_1_api_load": {
      "description": "API endpoint stress testing",
      "requirements": {
        "response_time_p95": "500ms",
        "throughput": "1000 requests/minute",
        "error_rate": "<1%"
      }
    },
    "P002_2_large_project": {
      "description": "Enterprise-scale project scanning",
      "requirements": {
        "completion_time": "5 minutes",
        "memory_usage": "2GB"
      }
    }
  },
  "report_files": {
    "detailed_report": "$REPORT_FILE",
    "log_file": "$LOG_FILE"
  }
}
EOF
    
    print_success "JSON report created: $JSON_REPORT"
}

# Main execution function
main() {
    local start_time=$(date +%s)
    
    print_status "Starting Typosentinel Performance Testing Suite"
    print_status "Report will be saved to: $REPORT_FILE"
    print_status "JSON report will be saved to: $JSON_REPORT"
    print_status "Logs will be saved to: $LOG_FILE"
    
    # Initialize report file
    echo "Typosentinel Performance Test Report" > "$REPORT_FILE"
    echo "Generated on: $(date)" >> "$REPORT_FILE"
    echo "========================================" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    
    # Initialize log file
    echo "Typosentinel Performance Test Log - $(date)" > "$LOG_FILE"
    
    # Run all test phases
    check_prerequisites
    setup_test_environment
    generate_system_info
    
    # P001 Tests
    run_single_package_tests
    run_batch_scanning_tests
    run_stress_tests
    
    # P002 Tests
    run_api_load_tests
    run_large_project_tests
    
    # Benchmarks
    run_benchmarks
    
    # Generate reports
    generate_summary
    create_json_report
    
    print_success "Performance testing completed!"
    print_status "Detailed report: $REPORT_FILE"
    print_status "JSON report: $JSON_REPORT"
    print_status "Log file: $LOG_FILE"
    
    # Display quick summary
    echo ""
    print_status "Quick Summary:"
    echo "  - Report file: $REPORT_FILE"
    echo "  - JSON report: $JSON_REPORT"
    echo "  - Total duration: $(($(date +%s) - start_time)) seconds"
    echo "  - Check the report files for detailed results"
}

# Handle script arguments
case "${1:-}" in
    "--help"|"help")
        echo "Typosentinel Performance Testing Suite"
        echo ""
        echo "Usage: $0 [options]"
        echo ""
        echo "Options:"
        echo "  --help          Show this help message"
        echo "  --single        Run only single package tests (P001.1)"
        echo "  --batch         Run only batch scanning tests (P001.2)"
        echo "  --load          Run only API load tests (P002.1)"
        echo "  --large         Run only large project tests (P002.2)"
        echo "  --benchmarks    Run only benchmarks"
        echo ""
        echo "Default: Run all tests"
        exit 0
        ;;
    "--single")
        check_prerequisites
        setup_test_environment
        generate_system_info
        run_single_package_tests
        generate_summary
        create_json_report
        ;;
    "--batch")
        check_prerequisites
        setup_test_environment
        generate_system_info
        run_batch_scanning_tests
        run_stress_tests
        generate_summary
        create_json_report
        ;;
    "--load")
        check_prerequisites
        setup_test_environment
        generate_system_info
        run_api_load_tests
        generate_summary
        create_json_report
        ;;
    "--large")
        check_prerequisites
        setup_test_environment
        generate_system_info
        run_large_project_tests
        generate_summary
        create_json_report
        ;;
    "--benchmarks")
        check_prerequisites
        setup_test_environment
        generate_system_info
        run_benchmarks
        generate_summary
        create_json_report
        ;;
    *)
        main
        ;;
esac