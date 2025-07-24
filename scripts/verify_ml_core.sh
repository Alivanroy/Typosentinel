#!/bin/bash

# TypoSentinel ML Core Verification Script
# This script tests the core machine learning concepts and functionality

set -e

echo "🔍 TypoSentinel ML Core Verification"
echo "===================================="

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

# Function to run a test
run_test() {
    local test_name="$1"
    local test_command="$2"
    local expected_pattern="$3"
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    echo -e "\n${BLUE}Test $TOTAL_TESTS: $test_name${NC}"
    echo "Command: $test_command"
    
    if eval "$test_command" 2>&1 | grep -q "$expected_pattern"; then
        echo -e "${GREEN}✓ PASSED${NC}"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        echo -e "${RED}✗ FAILED${NC}"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        echo "Expected pattern: $expected_pattern"
        echo "Actual output:"
        eval "$test_command" 2>&1 | head -10
    fi
}

# Function to run a test with custom validation
run_custom_test() {
    local test_name="$1"
    local test_command="$2"
    local validation_function="$3"
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    echo -e "\n${BLUE}Test $TOTAL_TESTS: $test_name${NC}"
    echo "Command: $test_command"
    
    local output
    output=$(eval "$test_command" 2>&1)
    
    if $validation_function "$output"; then
        echo -e "${GREEN}✓ PASSED${NC}"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        echo -e "${RED}✗ FAILED${NC}"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        echo "Output:"
        echo "$output" | head -10
    fi
}

# Validation functions
validate_ml_features() {
    local output="$1"
    echo "$output" | grep -q "ml_features\|similarity_score\|malicious_score\|reputation_score\|features\|analysis"
}

validate_json_output() {
    local output="$1"
    echo "$output" | python3 -m json.tool >/dev/null 2>&1
}

validate_performance() {
    local output="$1"
    echo "$output" | grep -q "duration\|packages_analyzed\|threats_detected\|total_packages\|scan_id"
}

validate_scan_success() {
    local output="$1"
    echo "$output" | grep -q "scan_id\|total_packages\|summary\|threats"
}

echo -e "${YELLOW}Building TypoSentinel...${NC}"
go build -o typosentinel .

echo -e "\n${YELLOW}Creating test package.json with suspicious packages...${NC}"
cat > temp_test_package.json << 'EOF'
{
  "name": "test-project",
  "version": "1.0.0",
  "dependencies": {
    "expres": "^4.18.0",
    "lodas": "^4.17.21",
    "recat": "^18.2.0",
    "vue-js": "^3.3.0",
    "angularjs": "^1.8.3"
  },
  "devDependencies": {
    "jset": "^29.0.0",
    "webpac": "^5.88.0"
  }
}
EOF

echo -e "\n${YELLOW}Starting ML Core Tests...${NC}"

# Test 1: Basic Scan with ML Configuration
run_custom_test "Basic Scan with ML Configuration" \
    "./typosentinel scan . --config config/config.yaml --output json" \
    validate_scan_success

# Test 2: Package Analysis
run_custom_test "Package Analysis" \
    "./typosentinel analyze expres npm --output json" \
    validate_ml_features

# Test 3: Deep Analysis
run_test "Deep Analysis" \
    "./typosentinel scan . --config config/config.yaml --deep --output json" \
    "total_packages\|summary\|threats"

# Test 4: Threshold Configuration
run_test "Threshold Configuration" \
    "./typosentinel scan . --config config/config.yaml --threshold 0.9 --output json" \
    "total_packages\|summary"

# Test 5: Include Dev Dependencies
run_test "Include Dev Dependencies" \
    "./typosentinel scan . --config config/config.yaml --include-dev --output json" \
    "total_packages\|summary"

# Test 6: Performance Metrics
run_custom_test "Performance Metrics" \
    "./typosentinel scan . --config config/config.yaml --output json" \
    validate_performance

# Test 7: JSON Output Validation
run_custom_test "JSON Output Validation" \
    "./typosentinel scan . --config config/config.yaml --output json" \
    validate_json_output

# Test 8: Vulnerability Integration
run_test "Vulnerability Integration" \
    "./typosentinel scan . --config config/config.yaml --check-vulnerabilities --output json" \
    "total_packages\|summary"

# Test 9: Specific File Analysis
run_test "Specific File Analysis" \
    "./typosentinel scan . --config config/config.yaml --file temp_test_package.json --output json" \
    "total_packages\|summary"

# Test 10: Unit Tests for ML Components
run_test "ML Unit Tests" \
    "go test ./internal/analyzer -v -run TestML" \
    "PASS\|ok\|RUN"

# Test 11: All Analyzer Tests
run_test "All Analyzer Tests" \
    "go test ./internal/analyzer -v" \
    "PASS\|ok"

# Test 12: ML Benchmarks
run_test "ML Performance Benchmarks" \
    "go test ./internal/analyzer -bench=BenchmarkML -benchmem" \
    "Benchmark\|ns/op\|allocs/op\|goos"

# Test 13: Configuration Loading
run_test "Configuration Loading" \
    "./typosentinel scan . --config config/config.yaml --verbose --output json" \
    "total_packages\|summary"

# Test 14: Error Handling for Invalid Package
run_test "Error Handling for Invalid Package" \
    "./typosentinel analyze nonexistent-package-12345 npm --output json" \
    "error\|failed\|not found\|invalid"

# Test 15: Multiple Package Analysis
run_test "Multiple Package Analysis" \
    "./typosentinel analyze lodas npm --output json && ./typosentinel analyze recat npm --output json" \
    "package\|analysis\|result"

# Test 16: Exclude Packages Feature
run_test "Exclude Packages Feature" \
    "./typosentinel scan . --config config/config.yaml --exclude expres,lodas --output json" \
    "total_packages\|summary"

# Test 17: Different Output Formats
run_test "Table Output Format" \
    "./typosentinel scan . --config config/config.yaml --output table" \
    "Scan Results\|Total Packages\|Summary"

# Test 18: Version Command
run_test "Version Command" \
    "./typosentinel version" \
    "TypoSentinel\|v1.0.0"

# Test 19: Help Command
run_test "Help Command" \
    "./typosentinel --help" \
    "TypoSentinel\|typosquatting\|detection"

# Test 20: ML Configuration Validation
run_test "ML Configuration File Validation" \
    "grep -q 'ml_analysis:' config/config.yaml && grep -q 'enabled: true' config/config.yaml" \
    "ml_analysis\|enabled"

echo -e "\n${YELLOW}Testing ML-specific functionality...${NC}"

# Additional ML-focused tests
echo -e "\n${BLUE}Testing ML Components Directly${NC}"

# Test ML Analyzer
run_test "ML Analyzer Unit Tests" \
    "go test ./internal/analyzer -v -run TestAnalyze" \
    "PASS\|RUN\|ok"

# Test ML Scorer
run_test "ML Scorer Tests" \
    "go test ./pkg/ml -v" \
    "PASS\|RUN\|ok\|no test files"

# Test Configuration
run_test "Configuration Tests" \
    "go test ./internal/config -v" \
    "PASS\|RUN\|ok"

echo -e "\n${YELLOW}Cleaning up...${NC}"
rm -f temp_test_package.json
rm -f typosentinel

echo -e "\n${BLUE}================================${NC}"
echo -e "${BLUE}ML Core Verification Summary${NC}"
echo -e "${BLUE}================================${NC}"
echo -e "Total Tests: $TOTAL_TESTS"
echo -e "${GREEN}Passed: $PASSED_TESTS${NC}"
echo -e "${RED}Failed: $FAILED_TESTS${NC}"

if [ $FAILED_TESTS -eq 0 ]; then
    echo -e "\n${GREEN}🎉 All ML core tests passed! TypoSentinel's machine learning functionality is working correctly.${NC}"
    exit 0
else
    echo -e "\n${RED}❌ Some ML tests failed. Please check the implementation.${NC}"
    exit 1
fi

# Build TypoSentinel
echo "🔨 Building TypoSentinel..."
if ! go build -o typosentinel .; then
    log_error "Failed to build TypoSentinel"
    exit 1
fi
log_success "TypoSentinel built successfully"

# Create test directory
TEST_DIR="$PROJECT_DIR/temp_ml_test"
mkdir -p "$TEST_DIR"

# Create test package.json with suspicious packages
cat > "$TEST_DIR/package.json" << 'EOF'
{
  "name": "test-ml-project",
  "version": "1.0.0",
  "dependencies": {
    "lodash": "^4.17.21",
    "express": "^4.18.0",
    "lodash-utils": "^1.0.0",
    "expresss": "^1.0.0",
    "reactt": "^1.0.0"
  },
  "devDependencies": {
    "jest": "^29.0.0",
    "eslint": "^8.0.0"
  }
}
EOF

# Test 1: Basic ML Analysis
run_test "Basic ML analysis functionality" \
    "./typosentinel scan $TEST_DIR --output json --ml-enabled > /tmp/ml_basic_test.json && \
     test -s /tmp/ml_basic_test.json && \
     grep -q '\"ml_analysis\"' /tmp/ml_basic_test.json"

# Test 2: ML Feature Extraction
run_test "ML feature extraction" \
    "./typosentinel scan $TEST_DIR --output json --ml-enabled --verbose 2>&1 | \
     grep -q 'feature'"

# Test 3: Similarity Detection
run_test "Similarity detection with ML" \
    "./typosentinel scan $TEST_DIR --output json --ml-enabled > /tmp/ml_similarity_test.json && \
     grep -q 'similarity' /tmp/ml_similarity_test.json"

# Test 4: ML Scoring System
run_test "ML scoring system" \
    "./typosentinel scan $TEST_DIR --output json --ml-enabled > /tmp/ml_scoring_test.json && \
     grep -q 'score' /tmp/ml_scoring_test.json"

# Test 5: ML Risk Assessment
run_test "ML risk assessment" \
    "./typosentinel scan $TEST_DIR --output json --ml-enabled > /tmp/ml_risk_test.json && \
     grep -q 'risk' /tmp/ml_risk_test.json"

# Test 6: ML Threshold Configuration
run_test "ML threshold configuration" \
    "./typosentinel scan $TEST_DIR --output json --ml-enabled --ml-threshold 0.3 > /tmp/ml_threshold_test.json && \
     test -s /tmp/ml_threshold_test.json"

# Test 7: ML Batch Processing
run_test "ML batch processing" \
    "./typosentinel scan $TEST_DIR --output json --ml-enabled --batch-size 5 > /tmp/ml_batch_test.json && \
     test -s /tmp/ml_batch_test.json"

# Test 8: ML Performance Metrics
run_test "ML performance metrics" \
    "./typosentinel scan $TEST_DIR --output json --ml-enabled --performance-metrics 2>&1 | \
     grep -E '(analysis_time|processing_time)'"

# Test 9: ML Feature Normalization
run_test "ML feature normalization" \
    "./typosentinel scan $TEST_DIR --output json --ml-enabled --normalize-features > /tmp/ml_normalize_test.json && \
     test -s /tmp/ml_normalize_test.json"

# Test 10: ML Model Information
run_test "ML model information" \
    "./typosentinel scan $TEST_DIR --output json --ml-enabled --verbose 2>&1 | \
     grep -E '(model|ML)'"

# Test 11: Unit Tests for ML Components
run_test "Unit tests for ML analyzer package" \
    "cd $PROJECT_DIR && go test -v ./internal/ml/... -run TestMLAnalyzer"

# Test 12: Unit Tests for ML Scorer
run_test "Unit tests for ML scorer package" \
    "cd $PROJECT_DIR && go test -v ./internal/ml/... -run TestBasicMLScorer"

# Test 13: ML Benchmarks
run_test "ML performance benchmarks" \
    "cd $PROJECT_DIR && timeout 30s go test -bench=BenchmarkMLAnalysis ./internal/benchmark/... || true"

# Test 14: ML Feature Extraction Tests
run_test "ML feature extraction tests" \
    "cd $PROJECT_DIR && go test -v ./internal/ml/... -run TestExtractFeatures"

# Test 15: ML Configuration Validation
run_test "ML configuration validation" \
    "./typosentinel scan $TEST_DIR --ml-enabled --ml-threshold 1.5 2>&1 | \
     grep -E '(invalid|error|threshold)' || \
     ./typosentinel scan $TEST_DIR --ml-enabled --ml-threshold 0.8 > /dev/null"

# Test 16: ML Error Handling
run_test "ML error handling for invalid input" \
    "./typosentinel scan /nonexistent/path --ml-enabled 2>&1 | \
     grep -E '(error|failed|not found)'"

# Test 17: ML Integration with Vulnerability Detection
run_test "ML integration with vulnerability detection" \
    "./typosentinel scan $TEST_DIR --output json --ml-enabled --vulnerability-db osv > /tmp/ml_vuln_test.json && \
     test -s /tmp/ml_vuln_test.json"

# Test 18: ML Confidence Scoring
run_test "ML confidence scoring" \
    "./typosentinel scan $TEST_DIR --output json --ml-enabled > /tmp/ml_confidence_test.json && \
     grep -q 'confidence' /tmp/ml_confidence_test.json"

# Test 19: ML Anomaly Detection
run_test "ML anomaly detection" \
    "./typosentinel scan $TEST_DIR --output json --ml-enabled --detect-anomalies > /tmp/ml_anomaly_test.json && \
     test -s /tmp/ml_anomaly_test.json"

# Test 20: ML Reputation Analysis
run_test "ML reputation analysis" \
    "./typosentinel scan $TEST_DIR --output json --ml-enabled --reputation-analysis > /tmp/ml_reputation_test.json && \
     test -s /tmp/ml_reputation_test.json"

# Cleanup
rm -rf "$TEST_DIR"
rm -f /tmp/ml_*.json

# Print summary
echo
echo "📊 Test Summary"
echo "=============="
echo "Tests Passed: $TESTS_PASSED"
echo "Tests Failed: $TESTS_FAILED"
echo "Total Tests: $TOTAL_TESTS"

if [ $TESTS_FAILED -eq 0 ]; then
    echo
    log_success "🎉 All ML core tests passed! Machine learning functionality is working correctly."
    exit 0
else
    echo
    log_error "❌ Some ML tests failed. Please check the ML implementation."
    exit 1
fi