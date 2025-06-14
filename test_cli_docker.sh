#!/bin/bash

# TypoSentinel CLI Docker Test Script
# This script demonstrates how to build and test the TypoSentinel CLI in Docker

echo "=== TypoSentinel CLI Docker Test ==="
echo

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker Desktop and try again."
    echo "   You can start Docker with: open -a Docker"
    exit 1
fi

echo "✅ Docker is running"
echo

# Build the Docker image
echo "🔨 Building TypoSentinel Docker image..."
if docker build -t typosentinel:test .; then
    echo "✅ Docker image built successfully"
else
    echo "❌ Failed to build Docker image"
    exit 1
fi
echo

# Test CLI help command
echo "📋 Testing CLI help command..."
docker run --rm typosentinel:test ./typosentinel --help
echo

# Test scan command help
echo "📋 Testing scan command help..."
docker run --rm typosentinel:test ./typosentinel scan --help
echo

# Test scanning a legitimate package
echo "🔍 Testing scan of legitimate package (lodash)..."
docker run --rm typosentinel:test ./typosentinel scan lodash --format json
echo

# Test scanning a potential typosquatting package
echo "🔍 Testing scan of potential typosquatting package (expresss)..."
docker run --rm typosentinel:test ./typosentinel scan expresss --format json
echo

# Test PyPI package scanning
echo "🔍 Testing PyPI package scan (requests)..."
docker run --rm typosentinel:test ./typosentinel scan requests --registry pypi --format json
echo

echo "✅ All Docker CLI tests completed!"
echo
echo "To run individual tests:"
echo "  docker run --rm typosentinel:test ./typosentinel scan [package-name]"
echo "  docker run --rm typosentinel:test ./typosentinel scan [package-name] --registry pypi"
echo "  docker run --rm typosentinel:test ./typosentinel scan [package-name] --format json --save-report"