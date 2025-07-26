#!/bin/bash

# Docker Release Script for Typosentinel
# This script builds and pushes Docker images for releases

set -e

VERSION=${1:-"latest"}
REGISTRY="ghcr.io"
USERNAME="alivanroy"
IMAGE_NAME="typosentinel"
FULL_IMAGE_NAME="${REGISTRY}/${USERNAME}/${IMAGE_NAME}"

echo "🐳 Building Docker image for version: ${VERSION}"

# Build the Docker image
docker build -t "${FULL_IMAGE_NAME}:${VERSION}" .

# Also tag as latest if this is a version tag
if [[ "${VERSION}" != "latest" ]]; then
    docker tag "${FULL_IMAGE_NAME}:${VERSION}" "${FULL_IMAGE_NAME}:latest"
    echo "✅ Tagged image as both ${VERSION} and latest"
else
    echo "✅ Tagged image as latest"
fi

echo "📋 Docker images created:"
docker images | grep "${IMAGE_NAME}"

echo ""
echo "🚀 To push to GitHub Container Registry:"
echo "1. Ensure you have the correct permissions (write:packages scope)"
echo "2. Authenticate: gh auth token | docker login ghcr.io -u ${USERNAME} --password-stdin"
echo "3. Push version: docker push ${FULL_IMAGE_NAME}:${VERSION}"
if [[ "${VERSION}" != "latest" ]]; then
    echo "4. Push latest: docker push ${FULL_IMAGE_NAME}:latest"
fi

echo ""
echo "🔧 To run the container locally:"
echo "docker run -p 8080:8080 ${FULL_IMAGE_NAME}:${VERSION}"

echo ""
echo "📦 Image details:"
docker inspect "${FULL_IMAGE_NAME}:${VERSION}" --format='{{.Size}}' | awk '{print "Size: " $1/1024/1024 " MB"}'