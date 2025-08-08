#!/bin/bash
set -e

# TypoSentinel Multi-Platform Release Build Script
# This script builds TypoSentinel for multiple platforms and creates release archives

VERSION=${1:-"v1.1.0"}
BUILD_TIME=$(date -u '+%Y-%m-%d_%H:%M:%S')
REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
DIST_DIR="${REPO_ROOT}/dist"

echo "🚀 Building TypoSentinel ${VERSION} for multiple platforms..."

# Clean and create dist directory
rm -rf "${DIST_DIR}"
mkdir -p "${DIST_DIR}"

# Build flags
LDFLAGS="-X main.Version=${VERSION} -X main.BuildTime=${BUILD_TIME} -s -w"

# Platforms to build for
PLATFORMS=(
    "linux/amd64"
    "linux/arm64"
    "darwin/amd64"
    "darwin/arm64"
    "windows/amd64"
    "windows/arm64"
    "freebsd/amd64"
)

# Build for each platform
for platform in "${PLATFORMS[@]}"; do
    IFS='/' read -r GOOS GOARCH <<< "$platform"
    
    echo "📦 Building for ${GOOS}/${GOARCH}..."
    
    # Set binary name
    BINARY_NAME="typosentinel-${VERSION}-${GOOS}-${GOARCH}"
    if [ "$GOOS" = "windows" ]; then
        BINARY_NAME="${BINARY_NAME}.exe"
    fi
    
    # Build binary
    CGO_ENABLED=0 GOOS="$GOOS" GOARCH="$GOARCH" go build \
        -ldflags "$LDFLAGS" \
        -o "${DIST_DIR}/${BINARY_NAME}" \
        "${REPO_ROOT}"
    
    # Create checksum
    cd "${DIST_DIR}"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "${BINARY_NAME}" > "${BINARY_NAME}.sha256"
    else
        shasum -a 256 "${BINARY_NAME}" > "${BINARY_NAME}.sha256"
    fi
    
    # Create archive
    if [ "$GOOS" = "windows" ]; then
        zip "${BINARY_NAME}.zip" "${BINARY_NAME}" "${BINARY_NAME}.sha256"
    else
        tar -czf "${BINARY_NAME}.tar.gz" "${BINARY_NAME}" "${BINARY_NAME}.sha256"
    fi
    
    echo "✅ Built ${BINARY_NAME}"
done

# Create installation script
cat > "${DIST_DIR}/install.sh" << 'EOF'
#!/bin/bash
set -e

# TypoSentinel Installation Script
VERSION="v1.1.0"
REPO="Alivanroy/Typosentinel"

# Detect OS and architecture
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case $ARCH in
    x86_64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

case $OS in
    linux) SUFFIX="linux-${ARCH}" ;;
    darwin) SUFFIX="darwin-${ARCH}" ;;
    *) echo "Unsupported OS: $OS"; exit 1 ;;
esac

BINARY_NAME="typosentinel-${VERSION}-${SUFFIX}"
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${BINARY_NAME}.tar.gz"

echo "🛡️  Installing TypoSentinel ${VERSION} for ${OS}/${ARCH}..."

# Download and extract
curl -sSL "$DOWNLOAD_URL" | tar -xz

# Install to /usr/local/bin
sudo mv "$BINARY_NAME" /usr/local/bin/typosentinel
sudo chmod +x /usr/local/bin/typosentinel

echo "✅ TypoSentinel installed successfully!"
echo "🚀 Run 'typosentinel --help' to get started."
EOF

chmod +x "${DIST_DIR}/install.sh"

echo "🎉 Release build complete!"
echo "📁 Files created in: ${DIST_DIR}"
ls -la "${DIST_DIR}"