#!/bin/bash

# TypoSentinel Build Script
# This script builds the TypoSentinel application for multiple platforms

set -e

# Configuration
APP_NAME="typosentinel"
SERVER_NAME="typosentinel-server"
VERSION=${VERSION:-"1.0.0"}
BUILD_TIME=$(date -u '+%Y-%m-%d_%H:%M:%S')
COMMIT_HASH=${COMMIT_HASH:-$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")}
BUILD_DIR="./bin"
LDFLAGS="-X main.version=${VERSION} -X main.buildTime=${BUILD_TIME} -X main.commitHash=${COMMIT_HASH} -w -s"

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
    log_info "Checking dependencies..."
    
    if ! command -v go &> /dev/null; then
        log_error "Go is not installed or not in PATH"
        exit 1
    fi
    
    if ! command -v python3 &> /dev/null; then
        log_warning "Python3 is not installed or not in PATH (ML components will not be available)"
    fi
    
    log_success "Dependencies check completed"
}

# Clean build directory
clean() {
    log_info "Cleaning build directory..."
    rm -rf "${BUILD_DIR}"
    mkdir -p "${BUILD_DIR}"
    log_success "Build directory cleaned"
}

# Build Go applications
build_go() {
    local os=$1
    local arch=$2
    local ext=$3
    
    log_info "Building for ${os}/${arch}..."
    
    # Build CLI application
    GOOS=${os} GOARCH=${arch} go build \
        -ldflags "${LDFLAGS}" \
        -o "${BUILD_DIR}/${APP_NAME}-${os}-${arch}${ext}" \
        ./cmd/typosentinel/main.go
    
    # Build server application
    GOOS=${os} GOARCH=${arch} go build \
        -ldflags "${LDFLAGS}" \
        -o "${BUILD_DIR}/${SERVER_NAME}-${os}-${arch}${ext}" \
        ./cmd/server/main.go
    
    log_success "Built for ${os}/${arch}"
}

# Build for all platforms
build_all() {
    log_info "Building TypoSentinel v${VERSION}..."
    
    # Linux
    build_go "linux" "amd64" ""
    build_go "linux" "arm64" ""
    
    # macOS
    build_go "darwin" "amd64" ""
    build_go "darwin" "arm64" ""
    
    # Windows
    build_go "windows" "amd64" ".exe"
    
    # Create symlinks for current platform
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        ln -sf "${APP_NAME}-linux-amd64" "${BUILD_DIR}/${APP_NAME}"
        ln -sf "${SERVER_NAME}-linux-amd64" "${BUILD_DIR}/${SERVER_NAME}"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        if [[ $(uname -m) == "arm64" ]]; then
            ln -sf "${APP_NAME}-darwin-arm64" "${BUILD_DIR}/${APP_NAME}"
            ln -sf "${SERVER_NAME}-darwin-arm64" "${BUILD_DIR}/${SERVER_NAME}"
        else
            ln -sf "${APP_NAME}-darwin-amd64" "${BUILD_DIR}/${APP_NAME}"
            ln -sf "${SERVER_NAME}-darwin-amd64" "${BUILD_DIR}/${SERVER_NAME}"
        fi
    fi
    
    log_success "All builds completed"
}

# Build for current platform only
build_current() {
    log_info "Building for current platform..."
    
    go build -ldflags "${LDFLAGS}" -o "${BUILD_DIR}/${APP_NAME}" ./cmd/typosentinel/main.go
    go build -ldflags "${LDFLAGS}" -o "${BUILD_DIR}/${SERVER_NAME}" ./cmd/server/main.go
    
    log_success "Current platform build completed"
}

# Run tests
run_tests() {
    log_info "Running Go tests..."
    go test -v ./...
    
    if command -v python3 &> /dev/null; then
        log_info "Running Python tests..."
        cd ml
        if [ -f "requirements.txt" ]; then
            python3 -m pip install -r requirements.txt > /dev/null 2>&1 || log_warning "Failed to install Python dependencies"
        fi
        python3 -m pytest tests/ -v 2>/dev/null || log_warning "Python tests failed or pytest not available"
        cd ..
    fi
    
    log_success "Tests completed"
}

# Generate checksums
generate_checksums() {
    log_info "Generating checksums..."
    
    cd "${BUILD_DIR}"
    
    if command -v sha256sum &> /dev/null; then
        sha256sum * > checksums.txt
    elif command -v shasum &> /dev/null; then
        shasum -a 256 * > checksums.txt
    else
        log_warning "No checksum utility found"
        cd ..
        return
    fi
    
    cd ..
    log_success "Checksums generated"
}

# Package releases
package_releases() {
    log_info "Packaging releases..."
    
    cd "${BUILD_DIR}"
    
    # Create archives for each platform
    for binary in ${APP_NAME}-* ${SERVER_NAME}-*; do
        if [[ -f "$binary" && "$binary" != *"."* ]]; then
            platform=$(echo "$binary" | cut -d'-' -f2-)
            archive_name="typosentinel-${VERSION}-${platform}"
            
            if [[ "$platform" == *"windows"* ]]; then
                zip -q "${archive_name}.zip" "$binary" "${binary/typosentinel/typosentinel-server}" 2>/dev/null || true
            else
                tar -czf "${archive_name}.tar.gz" "$binary" "${binary/typosentinel/typosentinel-server}" 2>/dev/null || true
            fi
        fi
    done
    
    cd ..
    log_success "Releases packaged"
}

# Show build information
show_info() {
    log_info "Build Information:"
    echo "  Version: ${VERSION}"
    echo "  Build Time: ${BUILD_TIME}"
    echo "  Commit Hash: ${COMMIT_HASH}"
    echo "  Go Version: $(go version | cut -d' ' -f3)"
    echo "  Build Directory: ${BUILD_DIR}"
}

# Show usage
show_usage() {
    echo "Usage: $0 [OPTIONS] [COMMAND]"
    echo ""
    echo "Commands:"
    echo "  all       Build for all platforms (default)"
    echo "  current   Build for current platform only"
    echo "  test      Run tests"
    echo "  clean     Clean build directory"
    echo "  package   Package releases"
    echo "  info      Show build information"
    echo ""
    echo "Options:"
    echo "  -h, --help     Show this help message"
    echo "  -v, --version  Set version (default: 1.0.0)"
    echo "  --no-test      Skip tests"
    echo "  --no-clean     Skip cleaning"
    echo ""
    echo "Environment Variables:"
    echo "  VERSION        Set build version"
    echo "  COMMIT_HASH    Set commit hash"
}

# Main execution
main() {
    local command="all"
    local run_tests_flag=true
    local clean_flag=true
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_usage
                exit 0
                ;;
            -v|--version)
                VERSION="$2"
                shift 2
                ;;
            --no-test)
                run_tests_flag=false
                shift
                ;;
            --no-clean)
                clean_flag=false
                shift
                ;;
            all|current|test|clean|package|info)
                command="$1"
                shift
                ;;
            *)
                log_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    # Execute command
    case $command in
        info)
            show_info
            ;;
        clean)
            clean
            ;;
        test)
            run_tests
            ;;
        package)
            package_releases
            ;;
        current)
            check_dependencies
            if [[ $clean_flag == true ]]; then
                clean
            fi
            if [[ $run_tests_flag == true ]]; then
                run_tests
            fi
            build_current
            generate_checksums
            show_info
            ;;
        all|*)
            check_dependencies
            if [[ $clean_flag == true ]]; then
                clean
            fi
            if [[ $run_tests_flag == true ]]; then
                run_tests
            fi
            build_all
            generate_checksums
            package_releases
            show_info
            ;;
    esac
    
    log_success "Build script completed successfully!"
}

# Run main function
main "$@"