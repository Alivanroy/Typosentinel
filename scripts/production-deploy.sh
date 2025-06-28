#!/bin/bash

# Production Deployment Script for TypoSentinel
# This script prepares and deploys TypoSentinel for production use

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
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

# Configuration
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BINARY_NAME="typosentinel"
DOCKER_IMAGE="typosentinel:latest"
DOCKER_PROD_IMAGE="typosentinel:production"

# Functions
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check if required tools are installed
    local required_tools=("go" "docker" "docker-compose" "make")
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            log_error "$tool is not installed or not in PATH"
            exit 1
        fi
    done
    
    # Check Go version
    local go_version
    go_version=$(go version | awk '{print $3}' | sed 's/go//')
    log_info "Go version: $go_version"
    
    # Check Docker version
    local docker_version
    docker_version=$(docker --version | awk '{print $3}' | sed 's/,//')
    log_info "Docker version: $docker_version"
    
    log_success "Prerequisites check passed"
}

clean_environment() {
    log_info "Cleaning development environment..."
    cd "$PROJECT_ROOT"
    
    # Stop any running containers
    if docker-compose ps | grep -q "Up"; then
        log_info "Stopping running containers..."
        docker-compose down
    fi
    
    # Clean build artifacts and temporary files
    make clean-all
    
    log_success "Environment cleaned"
}

run_tests() {
    log_info "Running comprehensive tests..."
    cd "$PROJECT_ROOT"
    
    # Run unit tests with coverage
    log_info "Running unit tests..."
    if ! make test; then
        log_error "Unit tests failed"
        exit 1
    fi
    
    # Run security checks
    log_info "Running security checks..."
    if command -v gosec &> /dev/null; then
        if ! make security; then
            log_warning "Security checks found issues - review before deployment"
        fi
    else
        log_warning "gosec not installed - skipping security checks"
    fi
    
    log_success "Tests completed"
}

build_production() {
    log_info "Building production binary..."
    cd "$PROJECT_ROOT"
    
    # Build optimized binary
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
        -ldflags="-s -w -X main.version=$(git describe --tags --always --dirty)" \
        -o "$BINARY_NAME" .
    
    # Verify binary
    if [[ ! -f "$BINARY_NAME" ]]; then
        log_error "Failed to build binary"
        exit 1
    fi
    
    # Test binary
    if ! "./$BINARY_NAME" --version; then
        log_error "Binary test failed"
        exit 1
    fi
    
    log_success "Production binary built successfully"
}

build_docker_image() {
    log_info "Building production Docker image..."
    cd "$PROJECT_ROOT"
    
    # Build production Docker image
    docker build -t "$DOCKER_PROD_IMAGE" .
    
    # Test Docker image
    log_info "Testing Docker image..."
    local container_id
    container_id=$(docker run -d -p 8080:8080 "$DOCKER_PROD_IMAGE")
    
    # Wait for container to start
    sleep 10
    
    # Test health endpoint
    if curl -f http://localhost:8080/health &> /dev/null; then
        log_success "Docker image health check passed"
    else
        log_warning "Docker image health check failed - container may still be starting"
    fi
    
    # Clean up test container
    docker stop "$container_id" &> /dev/null
    docker rm "$container_id" &> /dev/null
    
    log_success "Production Docker image built successfully"
}

optimize_configs() {
    log_info "Optimizing configuration for production..."
    cd "$PROJECT_ROOT"
    
    # Ensure production config exists
    if [[ ! -f "config/config.yaml" ]]; then
        log_error "Production config file not found: config/config.yaml"
        exit 1
    fi
    
    # Validate configuration
    if "./$BINARY_NAME" --config config/config.yaml --validate-config; then
        log_success "Configuration validation passed"
    else
        log_error "Configuration validation failed"
        exit 1
    fi
}

generate_deployment_artifacts() {
    log_info "Generating deployment artifacts..."
    cd "$PROJECT_ROOT"
    
    # Create deployment directory
    mkdir -p deployment
    
    # Copy essential files
    cp "$BINARY_NAME" deployment/
    cp -r config deployment/
    cp docker-compose.yml deployment/
    cp Dockerfile deployment/
    
    # Create deployment README
    cat > deployment/README.md << EOF
# TypoSentinel Production Deployment

This directory contains the production-ready TypoSentinel deployment.

## Files
- \`typosentinel\`: Production binary
- \`config/\`: Configuration files
- \`docker-compose.yml\`: Docker Compose configuration
- \`Dockerfile\`: Docker image definition

## Quick Start

### Binary Deployment
\`\`\`bash
./typosentinel serve --config config/config.yaml
\`\`\`

### Docker Deployment
\`\`\`bash
docker-compose up -d
\`\`\`

## Health Check
\`\`\`bash
curl http://localhost:8080/health
\`\`\`

## Configuration
Edit \`config/config.yaml\` to customize settings for your environment.

## Monitoring
- Health endpoint: \`/health\`
- Metrics endpoint: \`/metrics\`
- API documentation: \`/docs\`
EOF
    
    # Create version info
    cat > deployment/VERSION << EOF
Version: $(git describe --tags --always --dirty)
Build Date: $(date -u +"%Y-%m-%dT%H:%M:%SZ")
Git Commit: $(git rev-parse HEAD)
Go Version: $(go version | awk '{print $3}')
EOF
    
    log_success "Deployment artifacts generated in deployment/"
}

run_final_checks() {
    log_info "Running final production checks..."
    
    # Check binary size
    local binary_size
    binary_size=$(du -h "$BINARY_NAME" | cut -f1)
    log_info "Binary size: $binary_size"
    
    # Check Docker image size
    local image_size
    image_size=$(docker images "$DOCKER_PROD_IMAGE" --format "table {{.Size}}" | tail -n 1)
    log_info "Docker image size: $image_size"
    
    # Security check
    log_info "Running final security scan..."
    if command -v trivy &> /dev/null; then
        trivy image "$DOCKER_PROD_IMAGE" --severity HIGH,CRITICAL
    else
        log_warning "trivy not installed - skipping container security scan"
    fi
    
    log_success "Final checks completed"
}

print_deployment_summary() {
    log_success "\n=== PRODUCTION DEPLOYMENT READY ==="
    echo
    log_info "Artifacts:"
    echo "  - Binary: $BINARY_NAME"
    echo "  - Docker Image: $DOCKER_PROD_IMAGE"
    echo "  - Deployment Package: deployment/"
    echo
    log_info "Next Steps:"
    echo "  1. Review deployment/README.md"
    echo "  2. Test in staging environment"
    echo "  3. Deploy to production"
    echo "  4. Monitor health endpoints"
    echo
    log_info "Health Check:"
    echo "  curl http://localhost:8080/health"
    echo
    log_success "Deployment preparation complete!"
}

# Main execution
main() {
    log_info "Starting TypoSentinel production deployment preparation..."
    
    check_prerequisites
    clean_environment
    run_tests
    build_production
    build_docker_image
    optimize_configs
    generate_deployment_artifacts
    run_final_checks
    print_deployment_summary
}

# Handle script arguments
case "${1:-}" in
    "clean")
        clean_environment
        ;;
    "test")
        run_tests
        ;;
    "build")
        build_production
        build_docker_image
        ;;
    "deploy")
        main
        ;;
    "")
        main
        ;;
    *)
        echo "Usage: $0 [clean|test|build|deploy]"
        echo "  clean  - Clean development environment"
        echo "  test   - Run tests only"
        echo "  build  - Build production artifacts"
        echo "  deploy - Full deployment preparation (default)"
        exit 1
        ;;
esac