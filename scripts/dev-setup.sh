#!/bin/bash

# TypoSentinel Development Setup Script
# This script sets up the development environment for TypoSentinel

set -e

echo "🚀 Setting up TypoSentinel development environment..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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

# Check if Go is installed
check_go() {
    print_status "Checking Go installation..."
    if ! command -v go &> /dev/null; then
        print_error "Go is not installed. Please install Go 1.23 or later."
        print_status "Visit: https://golang.org/doc/install"
        exit 1
    fi
    
    GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
    print_success "Go $GO_VERSION is installed"
    
    # Check if Go version is 1.23 or later
    REQUIRED_VERSION="1.23"
    if ! printf '%s\n%s\n' "$REQUIRED_VERSION" "$GO_VERSION" | sort -V -C; then
        print_warning "Go version $GO_VERSION detected. Go 1.23+ is recommended."
    fi
}

# Check if Git is installed
check_git() {
    print_status "Checking Git installation..."
    if ! command -v git &> /dev/null; then
        print_error "Git is not installed. Please install Git."
        exit 1
    fi
    
    GIT_VERSION=$(git --version | awk '{print $3}')
    print_success "Git $GIT_VERSION is installed"
}

# Check if Make is installed
check_make() {
    print_status "Checking Make installation..."
    if ! command -v make &> /dev/null; then
        print_warning "Make is not installed. You can still build manually with 'go build'."
        print_status "To install Make:"
        print_status "  macOS: xcode-select --install"
        print_status "  Ubuntu/Debian: sudo apt-get install build-essential"
        print_status "  CentOS/RHEL: sudo yum groupinstall 'Development Tools'"
    else
        MAKE_VERSION=$(make --version | head -n1)
        print_success "$MAKE_VERSION is installed"
    fi
}

# Install Go dependencies
install_dependencies() {
    print_status "Installing Go dependencies..."
    if [ -f "go.mod" ]; then
        go mod download
        go mod tidy
        print_success "Go dependencies installed"
    else
        print_error "go.mod not found. Are you in the project root?"
        exit 1
    fi
}

# Install development tools
install_dev_tools() {
    print_status "Installing development tools..."
    
    # Install golangci-lint for linting
    if ! command -v golangci-lint &> /dev/null; then
        print_status "Installing golangci-lint..."
        go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
        print_success "golangci-lint installed"
    else
        print_success "golangci-lint already installed"
    fi
    
    # Install gofumpt for formatting
    if ! command -v gofumpt &> /dev/null; then
        print_status "Installing gofumpt..."
        go install mvdan.cc/gofumpt@latest
        print_success "gofumpt installed"
    else
        print_success "gofumpt already installed"
    fi
    
    # Install govulncheck for security scanning
    if ! command -v govulncheck &> /dev/null; then
        print_status "Installing govulncheck..."
        go install golang.org/x/vuln/cmd/govulncheck@latest
        print_success "govulncheck installed"
    else
        print_success "govulncheck already installed"
    fi
}

# Create necessary directories
setup_directories() {
    print_status "Setting up project directories..."
    
    # Create directories that might not exist
    mkdir -p temp
    mkdir -p artifacts
    mkdir -p reports
    mkdir -p coverage
    
    print_success "Project directories created"
}

# Setup Git hooks (optional)
setup_git_hooks() {
    print_status "Setting up Git hooks..."
    
    if [ -d ".git" ]; then
        # Create pre-commit hook
        cat > .git/hooks/pre-commit << 'EOF'
#!/bin/bash
# Pre-commit hook for TypoSentinel

echo "Running pre-commit checks..."

# Run tests
if ! make test; then
    echo "Tests failed. Commit aborted."
    exit 1
fi

# Run linting
if command -v golangci-lint &> /dev/null; then
    if ! make lint; then
        echo "Linting failed. Commit aborted."
        exit 1
    fi
fi

echo "Pre-commit checks passed!"
EOF
        
        chmod +x .git/hooks/pre-commit
        print_success "Git pre-commit hook installed"
    else
        print_warning "Not a Git repository. Skipping Git hooks setup."
    fi
}

# Run initial build and test
initial_build() {
    print_status "Running initial build and test..."
    
    # Build the project
    if command -v make &> /dev/null; then
        make build
        print_success "Project built successfully"
        
        # Run tests
        make test
        print_success "Tests passed"
    else
        # Fallback to go commands
        go build -o typosentinel ./cmd/typosentinel
        print_success "Project built successfully"
        
        go test ./...
        print_success "Tests passed"
    fi
}

# Display helpful information
show_help() {
    print_success "\n🎉 Development environment setup complete!"
    echo ""
    print_status "Next steps:"
    echo "  1. Read the documentation: cat README.md"
    echo "  2. View available make targets: make help"
    echo "  3. Run the application: ./typosentinel --help"
    echo "  4. Start developing: code ."
    echo ""
    print_status "Useful commands:"
    echo "  make build          # Build the binary"
    echo "  make test           # Run tests"
    echo "  make test-coverage  # Run tests with coverage"
    echo "  make lint           # Run linters"
    echo "  make fmt            # Format code"
    echo "  make clean          # Clean build artifacts"
    echo ""
    print_status "Documentation:"
    echo "  README.md                    # Project overview"
    echo "  CONTRIBUTING.md              # Contribution guidelines"
    echo "  PROJECT_STRUCTURE.md         # Project organization"
    echo "  docs/                        # Detailed documentation"
    echo ""
}

# Main execution
main() {
    echo "TypoSentinel Development Setup"
    echo "=============================="
    echo ""
    
    check_go
    check_git
    check_make
    install_dependencies
    install_dev_tools
    setup_directories
    setup_git_hooks
    initial_build
    show_help
}

# Run main function
main "$@"