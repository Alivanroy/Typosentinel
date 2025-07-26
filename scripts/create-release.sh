#!/bin/bash

# TypoSentinel Release Creation Script
# This script creates a GitHub release with multi-platform binaries

set -e

VERSION=${1:-"v1.1.0"}
REPO="Alivanroy/Typosentinel"

echo "Creating GitHub release for TypoSentinel $VERSION"

# Check if gh CLI is installed
if ! command -v gh &> /dev/null; then
    echo "Error: GitHub CLI (gh) is required but not installed."
    echo "Install it from: https://cli.github.com/"
    exit 1
fi

# Check if we're authenticated
if ! gh auth status &> /dev/null; then
    echo "Error: Not authenticated with GitHub CLI."
    echo "Run: gh auth login"
    exit 1
fi

# Build release packages
echo "Building release packages..."
make package

# Create release notes
RELEASE_NOTES="## TypoSentinel $VERSION

### 🚀 Features
- **Optimized Docker Implementation**: 32MB Alpine-based image with security hardening
- **Multi-Platform Support**: Native binaries for Linux, macOS (Intel & Apple Silicon), and Windows
- **Enhanced Security**: Non-root container execution and comprehensive security scanning
- **Production Ready**: Comprehensive test suite and CI/CD pipeline

### 🔧 Improvements
- Fixed Dockerfile for production deployment
- Added automated package target for release builds
- Cross-platform checksum generation
- Performance and security optimizations
- Enhanced Docker test coverage

### 📦 Supported Platforms
- **Linux**: AMD64
- **macOS**: AMD64 (Intel) and ARM64 (Apple Silicon)
- **Windows**: AMD64

### 🐳 Docker
\`\`\`bash
docker pull ghcr.io/alivanroy/typosentinel:$VERSION
docker run --rm ghcr.io/alivanroy/typosentinel:$VERSION --help
\`\`\`

### 📥 Installation
Download the appropriate binary for your platform from the assets below, extract it, and add it to your PATH.

### 🔐 Verification
All release assets include SHA256 checksums in \`checksums.sha256\` for verification.

### 📚 Documentation
- [Docker Test Report](https://github.com/$REPO/blob/main/DOCKER_TEST_REPORT.md)
- [README](https://github.com/$REPO/blob/main/README.md)"

# Create the release
echo "Creating GitHub release..."
gh release create "$VERSION" \
    --repo "$REPO" \
    --title "TypoSentinel $VERSION" \
    --notes "$RELEASE_NOTES" \
    --draft=false \
    --prerelease=false \
    dist/typosentinel-linux-amd64.tar.gz \
    dist/typosentinel-darwin-amd64.tar.gz \
    dist/typosentinel-darwin-arm64.tar.gz \
    dist/typosentinel-windows-amd64.zip \
    dist/checksums.sha256

echo "✅ Release $VERSION created successfully!"
echo "🔗 View at: https://github.com/$REPO/releases/tag/$VERSION"