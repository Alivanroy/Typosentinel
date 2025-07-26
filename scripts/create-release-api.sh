#!/bin/bash

# Alternative GitHub Release Creation Script using GitHub API
# This script creates a GitHub release using curl and GitHub API

set -e

VERSION=${1:-"v1.1.0"}
REPO="Alivanroy/Typosentinel"
GITHUB_TOKEN=${GITHUB_TOKEN:-""}

if [ -z "$GITHUB_TOKEN" ]; then
    echo "Error: GITHUB_TOKEN environment variable is required."
    echo "Create a personal access token at: https://github.com/settings/tokens"
    echo "Then run: export GITHUB_TOKEN=your_token_here"
    exit 1
fi

echo "Creating GitHub release for TypoSentinel $VERSION using GitHub API"

# Build release packages if they don't exist
if [ ! -d "dist" ] || [ -z "$(ls -A dist)" ]; then
    echo "Building release packages..."
    make package
fi

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
RELEASE_DATA=$(cat <<EOF
{
  "tag_name": "$VERSION",
  "target_commitish": "main",
  "name": "TypoSentinel $VERSION",
  "body": $(echo "$RELEASE_NOTES" | jq -R -s .),
  "draft": false,
  "prerelease": false
}
EOF
)

RELEASE_RESPONSE=$(curl -s -X POST \
  -H "Authorization: token $GITHUB_TOKEN" \
  -H "Accept: application/vnd.github.v3+json" \
  "https://api.github.com/repos/$REPO/releases" \
  -d "$RELEASE_DATA")

RELEASE_ID=$(echo "$RELEASE_RESPONSE" | jq -r '.id')
UPLOAD_URL=$(echo "$RELEASE_RESPONSE" | jq -r '.upload_url' | sed 's/{?name,label}//')

if [ "$RELEASE_ID" = "null" ]; then
    echo "Error creating release:"
    echo "$RELEASE_RESPONSE" | jq .
    exit 1
fi

echo "Release created with ID: $RELEASE_ID"

# Upload assets
echo "Uploading release assets..."

upload_asset() {
    local file=$1
    local filename=$(basename "$file")
    local content_type=""
    
    case "$filename" in
        *.tar.gz) content_type="application/gzip" ;;
        *.zip) content_type="application/zip" ;;
        *.sha256) content_type="text/plain" ;;
        *) content_type="application/octet-stream" ;;
    esac
    
    echo "Uploading $filename..."
    curl -s -X POST \
        -H "Authorization: token $GITHUB_TOKEN" \
        -H "Content-Type: $content_type" \
        --data-binary @"$file" \
        "$UPLOAD_URL?name=$filename" > /dev/null
}

# Upload all assets
for asset in dist/typosentinel-linux-amd64.tar.gz \
             dist/typosentinel-darwin-amd64.tar.gz \
             dist/typosentinel-darwin-arm64.tar.gz \
             dist/typosentinel-windows-amd64.zip \
             dist/checksums.sha256; do
    if [ -f "$asset" ]; then
        upload_asset "$asset"
    else
        echo "Warning: Asset $asset not found"
    fi
done

echo "✅ Release $VERSION created successfully!"
echo "🔗 View at: https://github.com/$REPO/releases/tag/$VERSION"