#!/bin/bash

# TypoSentinel Project Health Check Script
# This script validates the project structure, dependencies, and configuration

# Don't exit on errors - we want to collect all issues
# set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Counters
PASSED=0
FAILED=0
WARNINGS=0

# Function to print colored output
print_status() {
    echo -e "${BLUE}[CHECK]${NC} $1"
}

print_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((PASSED++))
}

print_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((FAILED++))
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
    ((WARNINGS++))
}

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

# Check project structure
check_project_structure() {
    print_status "Checking project structure..."
    
    # Essential directories
    local dirs=("cmd" "internal" "pkg" "docs" "tests" "scripts" "examples")
    for dir in "${dirs[@]}"; do
        if [ -d "$dir" ]; then
            print_pass "Directory $dir exists"
        else
            print_fail "Directory $dir is missing"
        fi
    done
    
    # Essential files
    local files=("README.md" "LICENSE" "go.mod" "go.sum" "Makefile" "main.go")
    for file in "${files[@]}"; do
        if [ -f "$file" ]; then
            print_pass "File $file exists"
        else
            print_fail "File $file is missing"
        fi
    done
    
    # Documentation files
    local docs=("CONTRIBUTING.md" "CODE_OF_CONDUCT.md" "SECURITY.md" "CHANGELOG.md")
    for doc in "${docs[@]}"; do
        if [ -f "$doc" ]; then
            print_pass "Documentation $doc exists"
        else
            print_warning "Documentation $doc is missing"
        fi
    done
}

# Check Go environment
check_go_environment() {
    print_status "Checking Go environment..."
    
    if command -v go &> /dev/null; then
        GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
        print_pass "Go $GO_VERSION is installed"
        
        # Check Go version
        if printf '%s\n%s\n' "1.23" "$GO_VERSION" | sort -V -C; then
            print_pass "Go version is 1.23 or later"
        else
            print_warning "Go version $GO_VERSION is older than recommended 1.23"
        fi
    else
        print_fail "Go is not installed"
    fi
    
    # Check GOPATH and GOROOT
    if [ -n "$GOPATH" ]; then
        print_pass "GOPATH is set: $GOPATH"
    else
        print_info "GOPATH is not set (using default)"
    fi
    
    if [ -n "$GOROOT" ]; then
        print_info "GOROOT is set: $GOROOT"
    fi
}

# Check dependencies
check_dependencies() {
    print_status "Checking Go dependencies..."
    
    if [ -f "go.mod" ]; then
        print_pass "go.mod exists"
        
        # Check if dependencies are up to date
        if go mod verify &> /dev/null; then
            print_pass "Go modules are verified"
        else
            print_fail "Go modules verification failed"
        fi
        
        # Check for unused dependencies
        if go mod tidy -diff &> /dev/null; then
            print_pass "No unused dependencies found"
        else
            print_warning "Unused dependencies detected (run 'go mod tidy')"
        fi
    else
        print_fail "go.mod is missing"
    fi
    
    if [ -f "go.sum" ]; then
        print_pass "go.sum exists"
    else
        print_warning "go.sum is missing"
    fi
}

# Check build status
check_build() {
    print_status "Checking build status..."
    
    # Try to build the project
    if go build -o /tmp/typosentinel-test ./cmd/typosentinel &> /dev/null; then
        print_pass "Project builds successfully"
        rm -f /tmp/typosentinel-test
    else
        print_fail "Project build failed"
    fi
    
    # Check for build artifacts
    if [ -f "typosentinel" ]; then
        print_info "Build artifact 'typosentinel' exists"
    fi
}

# Check tests
check_tests() {
    print_status "Checking tests..."
    
    # Count test files
    TEST_FILES=$(find . -name "*_test.go" | wc -l)
    if [ "$TEST_FILES" -gt 0 ]; then
        print_pass "Found $TEST_FILES test files"
    else
        print_warning "No test files found"
    fi
    
    # Try to run tests (quick check)
    if timeout 30s go test -short ./... &> /dev/null; then
        print_pass "Tests pass (short mode)"
    else
        print_warning "Some tests may be failing (run 'go test ./...' for details)"
    fi
}

# Check code quality tools
check_code_quality() {
    print_status "Checking code quality tools..."
    
    # Check for linting tools
    if command -v golangci-lint &> /dev/null; then
        print_pass "golangci-lint is installed"
    else
        print_warning "golangci-lint is not installed (recommended for development)"
    fi
    
    if command -v gofumpt &> /dev/null; then
        print_pass "gofumpt is installed"
    else
        print_warning "gofumpt is not installed (recommended for formatting)"
    fi
    
    if command -v govulncheck &> /dev/null; then
        print_pass "govulncheck is installed"
    else
        print_warning "govulncheck is not installed (recommended for security)"
    fi
}

# Check configuration files
check_configuration() {
    print_status "Checking configuration files..."
    
    # Check for config files
    local configs=("config.yaml" ".env.example")
    for config in "${configs[@]}"; do
        if [ -f "$config" ]; then
            print_pass "Configuration file $config exists"
        else
            print_warning "Configuration file $config is missing"
        fi
    done
    
    # Check .gitignore
    if [ -f ".gitignore" ]; then
        print_pass ".gitignore exists"
        
        # Check for common patterns
        if grep -q "*.log" .gitignore; then
            print_pass ".gitignore includes log files"
        else
            print_warning ".gitignore should include *.log"
        fi
        
        if grep -q "temp/" .gitignore; then
            print_pass ".gitignore includes temp directory"
        else
            print_warning ".gitignore should include temp/"
        fi
    else
        print_fail ".gitignore is missing"
    fi
}

# Check security
check_security() {
    print_status "Checking security..."
    
    # Check for sensitive files
    local sensitive_files=(".env" "*.key" "*.pem" "*.p12" "config.json")
    for pattern in "${sensitive_files[@]}"; do
        if find . -name "$pattern" -not -path "./.*" | grep -q .; then
            print_warning "Found potentially sensitive files matching $pattern"
        fi
    done
    
    # Check for hardcoded secrets (basic check)
    if grep -r -i "password\|secret\|token\|key" --include="*.go" . | grep -v "_test.go" | grep -v "//" | head -1 &> /dev/null; then
        print_warning "Potential hardcoded secrets found (manual review recommended)"
    else
        print_pass "No obvious hardcoded secrets found"
    fi
    
    # Check file permissions
    if [ -f "scripts/dev-setup.sh" ]; then
        if [ -x "scripts/dev-setup.sh" ]; then
            print_pass "Development scripts are executable"
        else
            print_warning "Development scripts are not executable"
        fi
    fi
}

# Check documentation
check_documentation() {
    print_status "Checking documentation..."
    
    # Check README.md content
    if [ -f "README.md" ]; then
        if grep -q "Installation" README.md; then
            print_pass "README.md includes installation instructions"
        else
            print_warning "README.md should include installation instructions"
        fi
        
        if grep -q "Usage" README.md || grep -q "Quick Start" README.md; then
            print_pass "README.md includes usage instructions"
        else
            print_warning "README.md should include usage instructions"
        fi
        
        if grep -q "Contributing" README.md || grep -q "CONTRIBUTING" README.md; then
            print_pass "README.md references contribution guidelines"
        else
            print_warning "README.md should reference contribution guidelines"
        fi
    fi
    
    # Check docs directory
    if [ -d "docs" ]; then
        DOC_COUNT=$(find docs -name "*.md" | wc -l)
        if [ "$DOC_COUNT" -gt 0 ]; then
            print_pass "Found $DOC_COUNT documentation files in docs/"
        else
            print_warning "docs/ directory exists but contains no markdown files"
        fi
    fi
}

# Check Git repository
check_git_repository() {
    print_status "Checking Git repository..."
    
    if [ -d ".git" ]; then
        print_pass "Git repository initialized"
        
        # Check for remote
        if git remote -v | grep -q "origin"; then
            REMOTE_URL=$(git remote get-url origin)
            print_pass "Git remote configured: $REMOTE_URL"
        else
            print_warning "No Git remote configured"
        fi
        
        # Check for uncommitted changes
        if git diff --quiet && git diff --cached --quiet; then
            print_pass "No uncommitted changes"
        else
            print_info "Uncommitted changes detected"
        fi
        
        # Check current branch
        CURRENT_BRANCH=$(git branch --show-current)
        print_info "Current branch: $CURRENT_BRANCH"
    else
        print_warning "Not a Git repository"
    fi
}

# Generate summary report
generate_summary() {
    echo ""
    echo "=========================================="
    echo "         HEALTH CHECK SUMMARY"
    echo "=========================================="
    echo ""
    print_info "Total checks: $((PASSED + FAILED + WARNINGS))"
    
    if [ $PASSED -gt 0 ]; then
        echo -e "${GREEN}✓ Passed: $PASSED${NC}"
    fi
    
    if [ $WARNINGS -gt 0 ]; then
        echo -e "${YELLOW}⚠ Warnings: $WARNINGS${NC}"
    fi
    
    if [ $FAILED -gt 0 ]; then
        echo -e "${RED}✗ Failed: $FAILED${NC}"
    fi
    
    echo ""
    
    if [ $FAILED -eq 0 ]; then
        if [ $WARNINGS -eq 0 ]; then
            echo -e "${GREEN}🎉 Project health: EXCELLENT${NC}"
        else
            echo -e "${YELLOW}👍 Project health: GOOD (with minor issues)${NC}"
        fi
    else
        echo -e "${RED}⚠️  Project health: NEEDS ATTENTION${NC}"
    fi
    
    echo ""
    
    if [ $WARNINGS -gt 0 ] || [ $FAILED -gt 0 ]; then
        echo "Recommendations:"
        if [ $FAILED -gt 0 ]; then
            echo "  • Address failed checks immediately"
        fi
        if [ $WARNINGS -gt 0 ]; then
            echo "  • Review warnings and consider improvements"
        fi
        echo "  • Run 'make dev-setup' to install development tools"
        echo "  • Check CONTRIBUTING.md for development guidelines"
    fi
}

# Main execution
main() {
    echo "TypoSentinel Project Health Check"
    echo "=================================="
    echo ""
    
    check_project_structure
    echo ""
    check_go_environment
    echo ""
    check_dependencies
    echo ""
    check_build
    echo ""
    check_tests
    echo ""
    check_code_quality
    echo ""
    check_configuration
    echo ""
    check_security
    echo ""
    check_documentation
    echo ""
    check_git_repository
    
    generate_summary
}

# Run main function
main "$@"