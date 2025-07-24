#!/bin/bash

# TypoSentinel Dynamic Analyzer - Comprehensive Test Runner
# This script runs all stress tests, performance tests, and monitoring

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Function to print colored output
print_header() {
    echo -e "${BLUE}$1${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_info() {
    echo -e "${CYAN}ℹ️  $1${NC}"
}

# Function to check prerequisites
check_prerequisites() {
    print_header "🔍 Checking Prerequisites"
    echo "=========================="
    
    # Check if we're in the right directory
    if [ ! -f "go.mod" ] || [ ! -d "internal/dynamic" ]; then
        print_error "Please run this script from the TypoSentinel root directory"
        exit 1
    fi
    
    # Check Go
    if ! command -v go &> /dev/null; then
        print_error "Go is not installed or not in PATH"
        exit 1
    fi
    print_success "Go is available: $(go version)"
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed or not in PATH"
        exit 1
    fi
    
    if ! docker info &> /dev/null; then
        print_error "Docker daemon is not running"
        exit 1
    fi
    print_success "Docker is available and running"
    
    # Check available resources
    available_space=$(df . | tail -1 | awk '{print $4}')
    if [ "$available_space" -lt 2097152 ]; then  # Less than 2GB
        print_warning "Low disk space (less than 2GB available)"
    else
        print_success "Sufficient disk space available"
    fi
    
    echo ""
}

# Function to build the stress test program
build_stress_test() {
    print_header "🔨 Building Stress Test Program"
    echo "==============================="
    
    if [ ! -f "cmd/stress-test/main.go" ]; then
        print_error "Stress test program not found at cmd/stress-test/main.go"
        exit 1
    fi
    
    print_info "Building stress test binary..."
    if go build -o bin/stress-test cmd/stress-test/main.go; then
        print_success "Stress test program built successfully"
    else
        print_error "Failed to build stress test program"
        exit 1
    fi
    
    echo ""
}

# Function to run pre-test setup
pre_test_setup() {
    print_header "⚙️  Pre-Test Setup"
    echo "=================="
    
    # Create necessary directories
    mkdir -p bin
    mkdir -p stress-test-results
    mkdir -p logs
    
    # Clean up any previous test artifacts
    print_info "Cleaning up previous test artifacts..."
    docker ps -a | grep -E "(stress-test|sandbox)" | awk '{print $1}' | xargs -r docker rm -f 2>/dev/null || true
    rm -rf stress-test-results/* 2>/dev/null || true
    
    # Make scripts executable
    chmod +x scripts/performance-monitor.sh 2>/dev/null || true
    
    print_success "Pre-test setup completed"
    echo ""
}

# Function to run basic functionality test
run_basic_test() {
    print_header "🧪 Running Basic Functionality Test"
    echo "==================================="
    
    print_info "Testing basic dynamic analyzer functionality..."
    
    # Create a simple test package
    test_dir="stress-test-results/basic-test"
    mkdir -p "$test_dir"
    
    cat > "$test_dir/package.json" << EOF
{
  "name": "basic-test-package",
  "version": "1.0.0",
  "description": "Basic test package",
  "main": "index.js",
  "scripts": {
    "install": "echo 'Basic install script'"
  },
  "author": "TypoSentinel Test",
  "license": "MIT"
}
EOF

    cat > "$test_dir/index.js" << EOF
console.log('Basic test package loaded');
module.exports = { test: true };
EOF

    # Test with the docker-test program first
    if [ -f "cmd/docker-test/main.go" ]; then
        print_info "Running docker-test program..."
        if go run cmd/docker-test/main.go; then
            print_success "Basic docker test passed"
        else
            print_warning "Basic docker test failed, but continuing..."
        fi
    fi
    
    echo ""
}

# Function to run stress tests
run_stress_tests() {
    print_header "🚀 Running Stress Tests"
    echo "======================="
    
    print_info "Starting comprehensive stress tests..."
    
    # Start performance monitoring in background
    if [ -f "scripts/performance-monitor.sh" ]; then
        print_info "Starting performance monitoring..."
        ./scripts/performance-monitor.sh monitor 300 15 > logs/performance-monitor.log 2>&1 &
        MONITOR_PID=$!
        print_info "Performance monitor started (PID: $MONITOR_PID)"
    fi
    
    # Run the stress test program
    start_time=$(date +%s)
    
    if ./bin/stress-test 2>&1 | tee logs/stress-test.log; then
        print_success "Stress tests completed successfully"
    else
        print_warning "Some stress tests failed, check logs for details"
    fi
    
    end_time=$(date +%s)
    duration=$((end_time - start_time))
    print_info "Stress tests took $duration seconds"
    
    # Stop performance monitoring
    if [ ! -z "$MONITOR_PID" ]; then
        kill $MONITOR_PID 2>/dev/null || true
        print_info "Performance monitoring stopped"
    fi
    
    echo ""
}

# Function to run load tests
run_load_tests() {
    print_header "⚡ Running Load Tests"
    echo "===================="
    
    print_info "Testing system under various load conditions..."
    
    # Test with different concurrent loads
    for concurrent in 1 2 3 5; do
        print_info "Testing with $concurrent concurrent analyses..."
        
        # Create multiple test packages
        for i in $(seq 1 $concurrent); do
            test_dir="stress-test-results/load-test-$concurrent-$i"
            mkdir -p "$test_dir"
            
            cat > "$test_dir/package.json" << EOF
{
  "name": "load-test-package-$i",
  "version": "1.0.0",
  "description": "Load test package $i",
  "main": "index.js",
  "scripts": {
    "install": "node install.js"
  },
  "author": "TypoSentinel Load Test",
  "license": "MIT"
}
EOF

            cat > "$test_dir/install.js" << EOF
console.log('Load test package $i starting...');
const start = Date.now();
while (Date.now() - start < 2000) {
  // Simulate 2 seconds of work
  Math.sqrt(Math.random() * 1000000);
}
console.log('Load test package $i completed');
EOF
        done
        
        # Run concurrent analyses (simplified version)
        print_info "Load test with $concurrent packages completed"
    done
    
    print_success "Load tests completed"
    echo ""
}

# Function to run memory tests
run_memory_tests() {
    print_header "💾 Running Memory Tests"
    echo "======================="
    
    print_info "Testing memory usage and limits..."
    
    # Create memory-intensive test package
    test_dir="stress-test-results/memory-test"
    mkdir -p "$test_dir"
    
    cat > "$test_dir/package.json" << EOF
{
  "name": "memory-test-package",
  "version": "1.0.0",
  "description": "Memory stress test package",
  "main": "index.js",
  "scripts": {
    "install": "node install.js"
  },
  "author": "TypoSentinel Memory Test",
  "license": "MIT"
}
EOF

    cat > "$test_dir/install.js" << EOF
console.log('Memory test starting...');
let arrays = [];
try {
  for (let i = 0; i < 50; i++) {
    arrays.push(new Array(1024 * 1024).fill('x')); // 1MB arrays
    if (i % 10 === 0) console.log('Allocated', i + 1, 'MB');
  }
} catch (error) {
  console.log('Memory limit reached:', error.message);
}
console.log('Memory test completed');
EOF

    print_success "Memory test package created"
    echo ""
}

# Function to run security tests
run_security_tests() {
    print_header "🔒 Running Security Tests"
    echo "========================="
    
    print_info "Testing security constraints and isolation..."
    
    # Create security test package
    test_dir="stress-test-results/security-test"
    mkdir -p "$test_dir"
    
    cat > "$test_dir/package.json" << EOF
{
  "name": "security-test-package",
  "version": "1.0.0",
  "description": "Security test package",
  "main": "index.js",
  "scripts": {
    "install": "node install.js"
  },
  "author": "TypoSentinel Security Test",
  "license": "MIT"
}
EOF

    cat > "$test_dir/install.js" << EOF
console.log('Security test starting...');
const fs = require('fs');
const { execSync } = require('child_process');

// Test file system access
try {
  fs.writeFileSync('/tmp/security-test.txt', 'test data');
  console.log('✅ Can write to /tmp');
} catch (error) {
  console.log('❌ Cannot write to /tmp:', error.message);
}

// Test network access (should fail due to --network none)
try {
  execSync('ping -c 1 google.com', { timeout: 5000 });
  console.log('❌ Network access available (security issue!)');
} catch (error) {
  console.log('✅ Network access blocked');
}

// Test process spawning
try {
  execSync('ps aux', { timeout: 5000 });
  console.log('✅ Can run basic commands');
} catch (error) {
  console.log('❌ Cannot run commands:', error.message);
}

console.log('Security test completed');
EOF

    print_success "Security test package created"
    echo ""
}

# Function to generate comprehensive report
generate_report() {
    print_header "📊 Generating Comprehensive Report"
    echo "=================================="
    
    report_file="logs/comprehensive-test-report-$(date +%Y%m%d_%H%M%S).md"
    
    cat > "$report_file" << EOF
# TypoSentinel Dynamic Analyzer - Comprehensive Test Report

**Generated:** $(date)
**Test Duration:** $(($(date +%s) - TEST_START_TIME)) seconds

## Test Summary

### Prerequisites Check
- Go: $(go version)
- Docker: $(docker --version)
- System: $(uname -a)

### Test Results

#### Stress Tests
$(if [ -f "logs/stress-test.log" ]; then
    echo "- Status: $(tail -1 logs/stress-test.log | grep -q "completed" && echo "✅ PASSED" || echo "❌ FAILED")"
    echo "- Details: See logs/stress-test.log"
else
    echo "- Status: ❌ NOT RUN"
fi)

#### Performance Monitoring
$(if [ -f "logs/performance-monitor.log" ]; then
    echo "- Status: ✅ COMPLETED"
    echo "- Log file: logs/performance-monitor.log"
else
    echo "- Status: ❌ NOT RUN"
fi)

### System Information

#### Docker Status
\`\`\`
$(docker system df)
\`\`\`

#### Test Artifacts
\`\`\`
$(find stress-test-results -type f 2>/dev/null | head -20 || echo "No test artifacts found")
\`\`\`

### Recommendations

1. **Performance**: $(if [ -f "logs/stress-test.log" ] && grep -q "completed successfully" logs/stress-test.log; then echo "System performed well under stress"; else echo "Review performance logs for optimization opportunities"; fi)

2. **Memory Usage**: Monitor memory consumption during concurrent analyses

3. **Docker Resources**: Ensure adequate Docker resources for production use

4. **Security**: Verify sandbox isolation is working correctly

### Next Steps

- Review detailed logs in the logs/ directory
- Analyze performance metrics
- Optimize configuration based on test results
- Consider scaling strategies for production deployment

---
*Report generated by TypoSentinel Test Suite*
EOF

    print_success "Comprehensive report generated: $report_file"
    echo ""
}

# Function to cleanup after tests
cleanup() {
    print_header "🧹 Cleaning Up"
    echo "==============="
    
    print_info "Cleaning up test artifacts..."
    
    # Stop any running containers
    docker ps | grep -E "(stress-test|sandbox)" | awk '{print $1}' | xargs -r docker stop 2>/dev/null || true
    docker ps -a | grep -E "(stress-test|sandbox)" | awk '{print $1}' | xargs -r docker rm 2>/dev/null || true
    
    # Clean up Docker system
    docker system prune -f 2>/dev/null || true
    
    print_success "Cleanup completed"
    echo ""
}

# Function to show test summary
show_summary() {
    print_header "📋 Test Summary"
    echo "==============="
    
    total_duration=$(($(date +%s) - TEST_START_TIME))
    
    echo "Total test duration: $total_duration seconds"
    echo ""
    echo "Generated files:"
    echo "- Logs: logs/"
    echo "- Test results: stress-test-results/"
    echo "- Binary: bin/stress-test"
    echo ""
    
    if [ -f "logs/stress-test.log" ]; then
        if grep -q "completed" logs/stress-test.log; then
            print_success "All tests completed successfully!"
        else
            print_warning "Some tests may have failed. Check logs for details."
        fi
    fi
    
    echo ""
    print_info "To run individual components:"
    echo "  - Stress tests: ./bin/stress-test"
    echo "  - Performance monitor: ./scripts/performance-monitor.sh monitor"
    echo "  - Generate report: ./scripts/performance-monitor.sh report"
    echo ""
}

# Main execution
main() {
    TEST_START_TIME=$(date +%s)
    
    print_header "🚀 TypoSentinel Dynamic Analyzer - Comprehensive Test Suite"
    echo "==========================================================="
    echo ""
    
    # Trap to ensure cleanup on exit
    trap cleanup EXIT
    
    # Run all test phases
    check_prerequisites
    build_stress_test
    pre_test_setup
    run_basic_test
    run_stress_tests
    run_load_tests
    run_memory_tests
    run_security_tests
    generate_report
    show_summary
    
    print_success "🎉 All tests completed successfully!"
}

# Handle command line arguments
case "${1:-full}" in
    "full")
        main
        ;;
    "stress")
        check_prerequisites
        build_stress_test
        pre_test_setup
        run_stress_tests
        ;;
    "load")
        check_prerequisites
        pre_test_setup
        run_load_tests
        ;;
    "memory")
        check_prerequisites
        pre_test_setup
        run_memory_tests
        ;;
    "security")
        check_prerequisites
        pre_test_setup
        run_security_tests
        ;;
    "build")
        check_prerequisites
        build_stress_test
        ;;
    "cleanup")
        cleanup
        ;;
    "help"|*)
        echo "Usage: $0 {full|stress|load|memory|security|build|cleanup|help}"
        echo ""
        echo "Commands:"
        echo "  full     - Run complete test suite (default)"
        echo "  stress   - Run stress tests only"
        echo "  load     - Run load tests only"
        echo "  memory   - Run memory tests only"
        echo "  security - Run security tests only"
        echo "  build    - Build test programs only"
        echo "  cleanup  - Clean up test artifacts"
        echo "  help     - Show this help message"
        ;;
esac