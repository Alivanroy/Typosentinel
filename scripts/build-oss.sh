#!/bin/bash

# Build script for Typosentinel OSS
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Build information
VERSION=${VERSION:-"dev"}
COMMIT=${COMMIT:-$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")}
DATE=${DATE:-$(date -u +"%Y-%m-%dT%H:%M:%SZ")}
LDFLAGS="-X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}"

# Output directory
OUTPUT_DIR=${OUTPUT_DIR:-"./bin"}
BINARY_NAME="typosentinel-oss"

echo -e "${BLUE}🔨 Building Typosentinel OSS${NC}"
echo -e "${BLUE}================================${NC}"
echo -e "Version: ${GREEN}${VERSION}${NC}"
echo -e "Commit:  ${GREEN}${COMMIT}${NC}"
echo -e "Date:    ${GREEN}${DATE}${NC}"
echo ""

# Create output directory
mkdir -p "${OUTPUT_DIR}"

# Build for current platform
echo -e "${YELLOW}📦 Building for current platform...${NC}"
go build -ldflags "${LDFLAGS}" -o "${OUTPUT_DIR}/${BINARY_NAME}" ./cmd/oss/

# Make executable
chmod +x "${OUTPUT_DIR}/${BINARY_NAME}"

echo -e "${GREEN}✅ Build completed successfully!${NC}"
echo -e "Binary location: ${GREEN}${OUTPUT_DIR}/${BINARY_NAME}${NC}"
echo ""

# Test the binary
echo -e "${YELLOW}🧪 Testing binary...${NC}"
if "${OUTPUT_DIR}/${BINARY_NAME}" version; then
    echo -e "${GREEN}✅ Binary test passed!${NC}"
else
    echo -e "${RED}❌ Binary test failed!${NC}"
    exit 1
fi

echo ""
echo -e "${BLUE}🚀 Usage:${NC}"
echo -e "  ${OUTPUT_DIR}/${BINARY_NAME} server --dev    # Start development server"
echo -e "  ${OUTPUT_DIR}/${BINARY_NAME} security-check  # Run security validation"
echo -e "  ${OUTPUT_DIR}/${BINARY_NAME} --help          # Show help"