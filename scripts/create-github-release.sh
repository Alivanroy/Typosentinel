#!/bin/bash
set -e

# GitHub Release Creation Script for TypoSentinel
# This script creates a GitHub release with all the built artifacts

VERSION=${1:-"v1.0.0"}
REPO="Alivanroy/Typosentinel"
DIST_DIR="./dist"

echo "🚀 Creating GitHub release for TypoSentinel ${VERSION}..."

# Check if gh CLI is installed
if ! command -v gh &> /dev/null; then
    echo "❌ GitHub CLI (gh) is not installed. Please install it first:"
    echo "   brew install gh"
    echo "   or visit: https://cli.github.com/"
    exit 1
fi

# Check if user is authenticated
if ! gh auth status &> /dev/null; then
    echo "❌ Not authenticated with GitHub. Please run:"
    echo "   gh auth login"
    exit 1
fi

# Check if dist directory exists
if [ ! -d "$DIST_DIR" ]; then
    echo "❌ Distribution directory not found. Please run the build script first:"
    echo "   ./scripts/build-release.sh ${VERSION}"
    exit 1
fi

echo "📝 Creating release notes..."

# Create the release with notes
gh release create "$VERSION" \
    --repo "$REPO" \
    --title "🛡️ TypoSentinel ${VERSION} - Complete Supply Chain Security Platform" \
    --notes-file "RELEASE_NOTES_${VERSION}.md" \
    --latest

echo "📦 Uploading release artifacts..."

# Upload all distribution files
cd "$DIST_DIR"

# Upload binary archives
for file in *.tar.gz *.zip; do
    if [ -f "$file" ]; then
        echo "⬆️  Uploading $file..."
        gh release upload "$VERSION" "$file" --repo "$REPO"
    fi
done

# Upload checksums
for file in *.sha256; do
    if [ -f "$file" ]; then
        echo "⬆️  Uploading $file..."
        gh release upload "$VERSION" "$file" --repo "$REPO"
    fi
done

# Upload installation script
if [ -f "install.sh" ]; then
    echo "⬆️  Uploading install.sh..."
    gh release upload "$VERSION" "install.sh" --repo "$REPO"
fi

cd ..

echo "✅ GitHub release created successfully!"
echo "🔗 Release URL: https://github.com/${REPO}/releases/tag/${VERSION}"

echo ""
echo "🐳 Docker image information:"
echo "   Image: ghcr.io/alivanroy/typosentinel:${VERSION}"
echo "   Pull: docker pull ghcr.io/alivanroy/typosentinel:${VERSION}"

echo ""
echo "📋 Next steps:"
echo "1. Push Docker image to registry:"
echo "   docker push ghcr.io/alivanroy/typosentinel:${VERSION}"
echo "   docker push ghcr.io/alivanroy/typosentinel:latest"
echo ""
echo "2. Update package managers (if applicable):"
echo "   - Homebrew formula"
echo "   - APT repository"
echo "   - YUM repository"
echo ""
echo "3. Announce the release:"
echo "   - Social media"
echo "   - Community forums"
echo "   - Documentation updates"