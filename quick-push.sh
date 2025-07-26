#!/bin/bash

# Quick Docker Push Script
# Usage: ./quick-push.sh YOUR_GITHUB_TOKEN

set -e

if [ -z "$1" ]; then
    echo "❌ Error: Please provide your GitHub Personal Access Token"
    echo "Usage: ./quick-push.sh YOUR_GITHUB_TOKEN"
    echo ""
    echo "Create a token at: https://github.com/settings/tokens"
    echo "Required scopes: write:packages, read:packages"
    exit 1
fi

TOKEN="$1"
REGISTRY="ghcr.io"
USERNAME="alivanroy"
IMAGE_NAME="typosentinel"
VERSION="v1.1.0"

echo "🐳 Pushing Typosentinel Docker image to GitHub Container Registry..."

# Login with the provided token
echo "$TOKEN" | docker login ghcr.io -u "$USERNAME" --password-stdin

# Push the images
echo "🚀 Pushing ${REGISTRY}/${USERNAME}/${IMAGE_NAME}:${VERSION}..."
docker push "${REGISTRY}/${USERNAME}/${IMAGE_NAME}:${VERSION}"

echo "🚀 Pushing ${REGISTRY}/${USERNAME}/${IMAGE_NAME}:latest..."
docker push "${REGISTRY}/${USERNAME}/${IMAGE_NAME}:latest"

echo ""
echo "✅ Successfully pushed Docker images!"
echo ""
echo "🔗 Your images are now available at:"
echo "   • ${REGISTRY}/${USERNAME}/${IMAGE_NAME}:${VERSION}"
echo "   • ${REGISTRY}/${USERNAME}/${IMAGE_NAME}:latest"
echo ""
echo "🧪 Test the published image:"
echo "   docker pull ${REGISTRY}/${USERNAME}/${IMAGE_NAME}:${VERSION}"
echo "   docker run -p 8080:8080 ${REGISTRY}/${USERNAME}/${IMAGE_NAME}:${VERSION}"