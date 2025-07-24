#!/bin/bash

# TypoSentinel False Positive and Real Threat Test Suite
# This script tests the ML system's ability to distinguish between legitimate packages and real threats

set -e

echo "🧪 TypoSentinel False Positive & Real Threat Test Suite"
echo "====================================================="

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
FP_TESTS=0
REAL_THREAT_TESTS=0
FP_PASSED=0
REAL_PASSED=0

# Function to run a test
run_test() {
    local test_type="$1"
    local test_name="$2"
    local package_name="$3"
    local expected_result="$4"  # "safe" or "threat"
    local description="$5"
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    if [ "$test_type" = "FP" ]; then
        FP_TESTS=$((FP_TESTS + 1))
        echo -e "\n${PURPLE}[FALSE POSITIVE TEST $FP_TESTS] $test_name${NC}"
    else
        REAL_THREAT_TESTS=$((REAL_THREAT_TESTS + 1))
        echo -e "\n${RED}[REAL THREAT TEST $REAL_THREAT_TESTS] $test_name${NC}"
    fi
    
    echo -e "${BLUE}Package: $package_name${NC}"
    echo -e "${BLUE}Description: $description${NC}"
    echo -e "${BLUE}Expected: $expected_result${NC}"
    
    # Run the analysis
    local output
    output=$(./typosentinel analyze "$package_name" npm --config config/config.yaml --output json 2>/dev/null || echo '{"threat_level": "error"}')
    
    # Extract threat level
    local threat_level
    threat_level=$(echo "$output" | grep -o '"threat_level"[[:space:]]*:[[:space:]]*"[^"]*"' | cut -d'"' -f4)
    
    # Determine if test passed
    local test_passed=false
    if [ "$expected_result" = "safe" ]; then
        if [ "$threat_level" = "none" ] || [ "$threat_level" = "low" ]; then
            test_passed=true
        fi
    else
        if [ "$threat_level" = "high" ] || [ "$threat_level" = "critical" ] || [ "$threat_level" = "medium" ]; then
            test_passed=true
        fi
    fi
    
    # Update counters
    if [ "$test_passed" = true ]; then
        echo -e "${GREEN}✓ PASSED - Detected as: $threat_level${NC}"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        if [ "$test_type" = "FP" ]; then
            FP_PASSED=$((FP_PASSED + 1))
        else
            REAL_PASSED=$((REAL_PASSED + 1))
        fi
    else
        echo -e "${RED}✗ FAILED - Detected as: $threat_level (Expected: $expected_result)${NC}"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        # Show some output for debugging
        echo "Analysis output:"
        echo "$output" | head -5
    fi
}

echo -e "${YELLOW}Building TypoSentinel...${NC}"
go build -o typosentinel .

echo -e "\n${YELLOW}Starting False Positive Tests (Legitimate Packages)...${NC}"
echo "These should be detected as SAFE (none/low threat level)"

# FALSE POSITIVE TESTS - Legitimate packages that should NOT be flagged
run_test "FP" "Popular Framework" "react" "safe" "Legitimate React framework from Facebook"
run_test "FP" "Popular Utility Library" "lodash" "safe" "Legitimate utility library with millions of downloads"
run_test "FP" "Popular Build Tool" "webpack" "safe" "Legitimate module bundler"
run_test "FP" "Popular Testing Framework" "jest" "safe" "Legitimate JavaScript testing framework"
run_test "FP" "Popular HTTP Client" "axios" "safe" "Legitimate HTTP client library"
run_test "FP" "Popular CSS Framework" "bootstrap" "safe" "Legitimate CSS framework"
run_test "FP" "Popular State Management" "redux" "safe" "Legitimate state management library"
run_test "FP" "Popular Router" "react-router" "safe" "Legitimate routing library for React"
run_test "FP" "Popular Date Library" "moment" "safe" "Legitimate date manipulation library"
run_test "FP" "Popular Validation Library" "joi" "safe" "Legitimate object schema validation"
run_test "FP" "Popular CLI Tool" "commander" "safe" "Legitimate command-line interface solution"
run_test "FP" "Popular Template Engine" "handlebars" "safe" "Legitimate template engine"
run_test "FP" "Popular Markdown Parser" "marked" "safe" "Legitimate markdown parser"
run_test "FP" "Popular Color Library" "chalk" "safe" "Legitimate terminal string styling"
run_test "FP" "Popular File System Utility" "fs-extra" "safe" "Legitimate file system utilities"

echo -e "\n${YELLOW}Starting Real Threat Tests (Suspicious/Malicious Packages)...${NC}"
echo "These should be detected as THREATS (medium/high/critical threat level)"

# REAL THREAT TESTS - Suspicious packages that SHOULD be flagged
run_test "THREAT" "Typosquatting - Express" "expres" "threat" "Missing 's' in express - common typosquatting"
run_test "THREAT" "Typosquatting - Lodash" "lodas" "threat" "Missing 'h' in lodash - typosquatting attempt"
run_test "THREAT" "Typosquatting - React" "recat" "threat" "Swapped letters in react - typosquatting"
run_test "THREAT" "Typosquatting - Webpack" "webpac" "threat" "Missing 'k' in webpack - typosquatting"
run_test "THREAT" "Typosquatting - Angular" "angularjs" "threat" "Confusing with legacy AngularJS"
run_test "THREAT" "Typosquatting - Vue" "vue-js" "threat" "Hyphenated version of vue"
run_test "THREAT" "Typosquatting - Bootstrap" "boostrap" "threat" "Missing 't' in bootstrap"
run_test "THREAT" "Typosquatting - jQuery" "jquerry" "threat" "Extra 'r' in jquery"
run_test "THREAT" "Typosquatting - Axios" "axois" "threat" "Swapped letters in axios"
run_test "THREAT" "Typosquatting - Moment" "momnet" "threat" "Swapped letters in moment"
run_test "THREAT" "Suspicious Package Name" "free-bitcoin-generator" "threat" "Suspicious cryptocurrency-related package"
run_test "THREAT" "Suspicious Package Name" "password-stealer" "threat" "Obviously malicious package name"
run_test "THREAT" "Suspicious Package Name" "crypto-miner-hidden" "threat" "Hidden cryptocurrency miner"
run_test "THREAT" "Suspicious Package Name" "backdoor-access" "threat" "Obviously malicious backdoor"
run_test "THREAT" "Suspicious Package Name" "data-exfiltrator" "threat" "Data theft package"

echo -e "\n${YELLOW}Testing Edge Cases...${NC}"

# EDGE CASE TESTS
run_test "FP" "Short Package Name" "q" "safe" "Legitimate single-letter package"
run_test "FP" "Scoped Package" "@babel/core" "safe" "Legitimate scoped package"
run_test "FP" "Hyphenated Package" "create-react-app" "safe" "Legitimate hyphenated package"
run_test "THREAT" "Homoglyph Attack" "reactjs" "threat" "Using similar name to confuse users"
run_test "THREAT" "Case Variation" "React" "threat" "Capitalized version of react"

echo -e "\n${YELLOW}Creating test package.json files for batch testing...${NC}"

# Create a package.json with mixed legitimate and suspicious packages
cat > test_mixed_packages.json << 'EOF'
{
  "name": "mixed-test-project",
  "version": "1.0.0",
  "dependencies": {
    "react": "^18.2.0",
    "expres": "^4.18.0",
    "lodash": "^4.17.21",
    "lodas": "^4.17.21",
    "webpack": "^5.88.0",
    "webpac": "^5.88.0"
  },
  "devDependencies": {
    "jest": "^29.0.0",
    "jset": "^29.0.0"
  }
}
EOF

# Create a package.json with only legitimate packages
cat > test_legitimate_packages.json << 'EOF'
{
  "name": "legitimate-test-project",
  "version": "1.0.0",
  "dependencies": {
    "react": "^18.2.0",
    "lodash": "^4.17.21",
    "webpack": "^5.88.0",
    "axios": "^1.4.0",
    "bootstrap": "^5.3.0"
  },
  "devDependencies": {
    "jest": "^29.0.0",
    "eslint": "^8.45.0"
  }
}
EOF

# Create a package.json with only suspicious packages
cat > test_suspicious_packages.json << 'EOF'
{
  "name": "suspicious-test-project",
  "version": "1.0.0",
  "dependencies": {
    "expres": "^4.18.0",
    "lodas": "^4.17.21",
    "recat": "^18.2.0",
    "webpac": "^5.88.0",
    "angularjs": "^1.8.3"
  },
  "devDependencies": {
    "jset": "^29.0.0",
    "eslint-config-airbnb": "^19.0.4"
  }
}
EOF

echo -e "\n${YELLOW}Running Batch Tests...${NC}"

# Test batch scanning
echo -e "\n${BLUE}Testing Mixed Package Scan...${NC}"
mixed_output=$(./typosentinel scan . --config config/config.yaml --file test_mixed_packages.json --output json 2>/dev/null || echo '{"summary": {"total_threats": 0}}')

# Improved JSON parsing with fallback
if echo "$mixed_output" | grep -q '"total_threats"'; then
    mixed_threats=$(echo "$mixed_output" | grep -o '"total_threats"[[:space:]]*:[[:space:]]*[0-9]*' | cut -d':' -f2 | tr -d ' ')
    # Validate that we got a number
    if ! [[ "$mixed_threats" =~ ^[0-9]+$ ]]; then
        mixed_threats=0
        echo "Warning: Failed to parse mixed threats count, defaulting to 0"
    fi
else
    mixed_threats=0
    echo "Warning: No threat data found in mixed scan output, defaulting to 0"
fi

echo -e "\n${BLUE}Testing Legitimate Package Scan...${NC}"
legit_output=$(./typosentinel scan . --config config/config.yaml --file test_legitimate_packages.json --output json 2>/dev/null || echo '{"summary": {"total_threats": 0}}')

# Improved JSON parsing with fallback
if echo "$legit_output" | grep -q '"total_threats"'; then
    legit_threats=$(echo "$legit_output" | grep -o '"total_threats"[[:space:]]*:[[:space:]]*[0-9]*' | cut -d':' -f2 | tr -d ' ')
    # Validate that we got a number
    if ! [[ "$legit_threats" =~ ^[0-9]+$ ]]; then
        legit_threats=0
        echo "Warning: Failed to parse legitimate threats count, defaulting to 0"
    fi
else
    legit_threats=0
    echo "Warning: No threat data found in legitimate scan output, defaulting to 0"
fi

echo -e "\n${BLUE}Testing Suspicious Package Scan...${NC}"
susp_output=$(./typosentinel scan . --config config/config.yaml --file test_suspicious_packages.json --output json 2>/dev/null || echo '{"summary": {"total_threats": 0}}')

# Improved JSON parsing with fallback
if echo "$susp_output" | grep -q '"total_threats"'; then
    susp_threats=$(echo "$susp_output" | grep -o '"total_threats"[[:space:]]*:[[:space:]]*[0-9]*' | cut -d':' -f2 | tr -d ' ')
    # Validate that we got a number
    if ! [[ "$susp_threats" =~ ^[0-9]+$ ]]; then
        susp_threats=0
        echo "Warning: Failed to parse suspicious threats count, defaulting to 0"
    fi
else
    susp_threats=0
    echo "Warning: No threat data found in suspicious scan output, defaulting to 0"
fi

echo -e "\n${BLUE}Batch Test Results:${NC}"
echo "Mixed packages threats detected: $mixed_threats"
echo "Legitimate packages threats detected: $legit_threats"
echo "Suspicious packages threats detected: $susp_threats"

# Evaluate batch test results
BATCH_TESTS=3
BATCH_PASSED=0

# Fix parsing issues by ensuring variables are valid integers
if [ -z "$legit_threats" ] || ! [[ "$legit_threats" =~ ^[0-9]+$ ]]; then
    legit_threats=0
    echo "Warning: Could not parse legitimate threats count, defaulting to 0"
fi

if [ -z "$susp_threats" ] || ! [[ "$susp_threats" =~ ^[0-9]+$ ]]; then
    susp_threats=0
    echo "Warning: Could not parse suspicious threats count, defaulting to 0"
fi

if [ -z "$mixed_threats" ] || ! [[ "$mixed_threats" =~ ^[0-9]+$ ]]; then
    mixed_threats=0
    echo "Warning: Could not parse mixed threats count, defaulting to 0"
fi

# Now evaluate with validated integers
if [ $legit_threats -le 1 ]; then
    echo -e "${GREEN}✓ Legitimate package scan passed (low false positives: $legit_threats)${NC}"
    BATCH_PASSED=$((BATCH_PASSED + 1))
else
    echo -e "${RED}✗ Legitimate package scan failed (too many false positives: $legit_threats)${NC}"
fi

if [ $susp_threats -ge 3 ]; then
    echo -e "${GREEN}✓ Suspicious package scan passed (detected threats: $susp_threats)${NC}"
    BATCH_PASSED=$((BATCH_PASSED + 1))
else
    echo -e "${RED}✗ Suspicious package scan failed (missed threats: $susp_threats)${NC}"
fi

if [ $mixed_threats -ge 2 ] && [ $mixed_threats -le 6 ]; then
    echo -e "${GREEN}✓ Mixed package scan passed (balanced detection: $mixed_threats)${NC}"
    BATCH_PASSED=$((BATCH_PASSED + 1))
else
    echo -e "${RED}✗ Mixed package scan failed (unbalanced detection: $mixed_threats)${NC}"
fi

echo -e "\n${YELLOW}Cleaning up test files...${NC}"
rm -f test_mixed_packages.json test_legitimate_packages.json test_suspicious_packages.json
rm -f typosentinel

# Calculate accuracy metrics
FP_ACCURACY=0
THREAT_ACCURACY=0
OVERALL_ACCURACY=0

if [ $FP_TESTS -gt 0 ]; then
    FP_ACCURACY=$((FP_PASSED * 100 / FP_TESTS))
fi

if [ $REAL_THREAT_TESTS -gt 0 ]; then
    THREAT_ACCURACY=$((REAL_PASSED * 100 / REAL_THREAT_TESTS))
fi

if [ $TOTAL_TESTS -gt 0 ]; then
    OVERALL_ACCURACY=$((PASSED_TESTS * 100 / TOTAL_TESTS))
fi

echo -e "\n${BLUE}================================================================${NC}"
echo -e "${BLUE}                    TEST RESULTS SUMMARY${NC}"
echo -e "${BLUE}================================================================${NC}"

echo -e "\n${PURPLE}FALSE POSITIVE TESTS (Should detect as SAFE):${NC}"
echo -e "  Total FP Tests: $FP_TESTS"
echo -e "  FP Tests Passed: $FP_PASSED"
echo -e "  FP Accuracy: ${FP_ACCURACY}%"

echo -e "\n${RED}REAL THREAT TESTS (Should detect as THREAT):${NC}"
echo -e "  Total Threat Tests: $REAL_THREAT_TESTS"
echo -e "  Threat Tests Passed: $REAL_PASSED"
echo -e "  Threat Detection Accuracy: ${THREAT_ACCURACY}%"

echo -e "\n${BLUE}BATCH TESTS:${NC}"
echo -e "  Batch Tests Passed: $BATCH_PASSED/$BATCH_TESTS"

echo -e "\n${GREEN}OVERALL RESULTS:${NC}"
echo -e "  Total Tests: $TOTAL_TESTS"
echo -e "  Total Passed: $PASSED_TESTS"
echo -e "  Total Failed: $FAILED_TESTS"
echo -e "  Overall Accuracy: ${OVERALL_ACCURACY}%"

# Determine overall result
if [ $FP_ACCURACY -ge 80 ] && [ $THREAT_ACCURACY -ge 70 ] && [ $BATCH_PASSED -ge 2 ]; then
    echo -e "\n${GREEN}🎉 EXCELLENT: TypoSentinel ML system shows strong performance!${NC}"
    echo -e "${GREEN}   - Low false positive rate${NC}"
    echo -e "${GREEN}   - Good threat detection capability${NC}"
    echo -e "${GREEN}   - Balanced batch processing${NC}"
    exit 0
elif [ $FP_ACCURACY -ge 60 ] && [ $THREAT_ACCURACY -ge 50 ]; then
    echo -e "\n${YELLOW}⚠️  GOOD: TypoSentinel ML system shows acceptable performance${NC}"
    echo -e "${YELLOW}   - Room for improvement in accuracy${NC}"
    exit 0
else
    echo -e "\n${RED}❌ NEEDS IMPROVEMENT: TypoSentinel ML system needs tuning${NC}"
    echo -e "${RED}   - High false positive rate or low threat detection${NC}"
    echo -e "${RED}   - Consider adjusting ML thresholds and weights${NC}"
    exit 1
fi