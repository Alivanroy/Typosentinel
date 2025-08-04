#!/bin/bash

# TypoSentinel Installation Script
# This script downloads and installs the latest version of TypoSentinel

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
VERSION="v1.1.0"
REPO="Alivanroy/Typosentinel"
BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"
INSTALL_DIR="/usr/local/bin"
TMP_DIR="/tmp/typosentinel-install"

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

detect_platform() {
    local os="$(uname -s)"
    local arch="$(uname -m)"
    
    case "$os" in
        Linux*)
            OS="linux"
            ;;
        Darwin*)
            OS="darwin"
            ;;
        FreeBSD*)
            OS="freebsd"
            ;;
        CYGWIN*|MINGW*|MSYS*)
            OS="windows"
            ;;
        *)
            log_error "Unsupported operating system: $os"
            exit 1
            ;;
    esac
    
    case "$arch" in
        x86_64|amd64)
            ARCH="amd64"
            ;;
        arm64|aarch64)
            ARCH="arm64"
            ;;
        *)
            log_error "Unsupported architecture: $arch"
            exit 1
            ;;
    esac
    
    log_info "Detected platform: ${OS}-${ARCH}"
}

check_dependencies() {
    local deps=("curl" "tar")
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            log_error "Required dependency '$dep' is not installed"
            exit 1
        fi
    done
    
    log_info "All dependencies are available"
}

download_and_install() {
    local filename
    local download_url
    local checksum_url
    
    if [ "$OS" = "windows" ]; then
        filename="typosentinel-${VERSION}-${OS}-${ARCH}.exe.zip"
    else
        filename="typosentinel-${VERSION}-${OS}-${ARCH}.tar.gz"
    fi
    
    download_url="${BASE_URL}/${filename}"
    checksum_url="${BASE_URL}/checksums.txt"
    
    log_info "Creating temporary directory: $TMP_DIR"
    mkdir -p "$TMP_DIR"
    cd "$TMP_DIR"
    
    log_info "Downloading TypoSentinel ${VERSION} for ${OS}-${ARCH}..."
    if ! curl -fsSL -o "$filename" "$download_url"; then
        log_error "Failed to download TypoSentinel from $download_url"
        exit 1
    fi
    
    log_info "Downloading checksums..."
    if ! curl -fsSL -o "checksums.txt" "$checksum_url"; then
        log_warning "Failed to download checksums, skipping verification"
    else
        log_info "Verifying checksum..."
        if command -v sha256sum &> /dev/null; then
            if ! grep "$filename" checksums.txt | sha256sum -c -; then
                log_error "Checksum verification failed"
                exit 1
            fi
            log_success "Checksum verification passed"
        else
            log_warning "sha256sum not available, skipping checksum verification"
        fi
    fi
    
    log_info "Extracting archive..."
    if [ "$OS" = "windows" ]; then
        if command -v unzip &> /dev/null; then
            unzip -q "$filename"
        else
            log_error "unzip is required for Windows installation"
            exit 1
        fi
    else
        tar -xzf "$filename"
    fi
    
    # Find the binary
    local binary_name="typosentinel"
    if [ "$OS" = "windows" ]; then
        binary_name="typosentinel.exe"
    fi
    
    if [ ! -f "$binary_name" ]; then
        log_error "Binary $binary_name not found in archive"
        exit 1
    fi
    
    # Install the binary
    log_info "Installing TypoSentinel to $INSTALL_DIR..."
    
    # Check if we need sudo
    if [ ! -w "$INSTALL_DIR" ]; then
        if command -v sudo &> /dev/null; then
            sudo mv "$binary_name" "$INSTALL_DIR/typosentinel"
            sudo chmod +x "$INSTALL_DIR/typosentinel"
        else
            log_error "No write permission to $INSTALL_DIR and sudo not available"
            log_info "Please run this script as root or install manually"
            exit 1
        fi
    else
        mv "$binary_name" "$INSTALL_DIR/typosentinel"
        chmod +x "$INSTALL_DIR/typosentinel"
    fi
    
    log_success "TypoSentinel installed successfully!"
}

verify_installation() {
    log_info "Verifying installation..."
    
    if command -v typosentinel &> /dev/null; then
        local installed_version
        installed_version=$(typosentinel --version 2>/dev/null | head -n1 || echo "unknown")
        log_success "TypoSentinel is installed and available in PATH"
        log_info "Installed version: $installed_version"
    else
        log_warning "TypoSentinel is not in PATH. You may need to add $INSTALL_DIR to your PATH"
        log_info "Add this to your shell profile (.bashrc, .zshrc, etc.):"
        log_info "export PATH=\"$INSTALL_DIR:\$PATH\""
    fi
}

cleanup() {
    log_info "Cleaning up temporary files..."
    rm -rf "$TMP_DIR"
}

show_usage() {
    cat << EOF
TypoSentinel Installation Script

Usage: $0 [OPTIONS]

Options:
  -v, --version VERSION    Install specific version (default: $VERSION)
  -d, --dir DIRECTORY      Install directory (default: $INSTALL_DIR)
  -h, --help              Show this help message

Examples:
  $0                      # Install latest version
  $0 -v v1.0.0           # Install specific version
  $0 -d /opt/bin         # Install to custom directory

For more information, visit: https://github.com/$REPO
EOF
}

show_next_steps() {
    cat << EOF

${GREEN}🎉 Installation Complete!${NC}

Next steps:
  1. Verify installation: ${BLUE}typosentinel --version${NC}
  2. Scan a project: ${BLUE}typosentinel scan .${NC}
  3. Analyze a package: ${BLUE}typosentinel analyze express npm${NC}
  4. Check vulnerabilities: ${BLUE}typosentinel scan . --check-vulnerabilities${NC}

Documentation: https://typosentinel.com/docs
Examples: https://typosentinel.com/examples
Support: https://github.com/$REPO/issues

Happy scanning! 🛡️
EOF
}

# Main execution
main() {
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -v|--version)
                VERSION="$2"
                shift 2
                ;;
            -d|--dir)
                INSTALL_DIR="$2"
                shift 2
                ;;
            -h|--help)
                show_usage
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    log_info "Starting TypoSentinel installation..."
    log_info "Version: $VERSION"
    log_info "Install directory: $INSTALL_DIR"
    
    detect_platform
    check_dependencies
    download_and_install
    verify_installation
    cleanup
    show_next_steps
}

# Trap to ensure cleanup on exit
trap cleanup EXIT

# Run main function
main "$@"