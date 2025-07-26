#!/bin/bash

# Push Docker Image to GitHub Container Registry
# Usage: ./push-docker.sh [version]

set -e

VERSION=${1:-"v1.1.0"}
REGISTRY="ghcr.io"
USERNAME="alivanroy"
IMAGE_NAME="typosentinel"
FULL_IMAGE_NAME="${REGISTRY}/${USERNAME}/${IMAGE_NAME}"

echo "🐳 Pushing Typosentinel Docker image v${VERSION} to GitHub Container Registry"
echo ""

# Check if images exist locally
if ! docker images | grep -q "${IMAGE_NAME}.*${VERSION}"; then
    echo "❌ Error: Docker image ${FULL_IMAGE_NAME}:${VERSION} not found locally"
    echo "Please build the image first using: docker build -t ${FULL_IMAGE_NAME}:${VERSION} ."
    exit 1
fi

echo "✅ Found local image: ${FULL_IMAGE_NAME}:${VERSION}"

# Check if we're already logged in
if ! docker info | grep -q "Username: ${USERNAME}"; then
    echo "🔐 Authenticating with GitHub Container Registry..."
    echo "Please ensure you have a GitHub Personal Access Token with 'write:packages' scope"
    echo ""
    
    # Try to use GitHub CLI token first
    if command -v gh &> /dev/null && gh auth status &> /dev/null; then
        echo "Using GitHub CLI token for authentication..."
        gh auth token | docker login ghcr.io -u "${USERNAME}" --password-stdin
    else
        echo "Please enter your GitHub Personal Access Token:"
        docker login ghcr.io -u "${USERNAME}"
    fi
fi

echo ""
echo "🚀 Pushing images..."

# Push the versioned image
echo "Pushing ${FULL_IMAGE_NAME}:${VERSION}..."
docker push "${FULL_IMAGE_NAME}:${VERSION}"

# Push latest tag if it exists
if docker images | grep -q "${IMAGE_NAME}.*latest"; then
    echo "Pushing ${FULL_IMAGE_NAME}:latest..."
    docker push "${FULL_IMAGE_NAME}:latest"
fi

echo ""
echo "✅ Successfully pushed Docker images!"
echo ""
echo "🔗 Your images are now available at:"
echo "   • ${FULL_IMAGE_NAME}:${VERSION}"
echo "   • ${FULL_IMAGE_NAME}:latest"
echo ""
echo "🧪 Test the published image:"
echo "   docker pull ${FULL_IMAGE_NAME}:${VERSION}"
echo "   docker run -p 8080:8080 ${FULL_IMAGE_NAME}:${VERSION}"
echo ""
echo "📋 View on GitHub: https://github.com/${USERNAME}/${IMAGE_NAME}/pkgs/container/${IMAGE_NAME}"