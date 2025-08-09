#!/bin/bash

# Build script for Typosentinel
echo "=========================================="
echo "Typosentinel Build Script"
echo "=========================================="

# Navigate to project directory
cd /Users/alikorsi/Documents/Typosentinel

echo "Step 1: Checking Go version..."
export PATH=/opt/homebrew/bin:$PATH
go version

echo ""
echo "Step 2: Cleaning dependencies..."
go mod tidy

echo ""
echo "Step 3: Building project using make..."
make build

echo ""
echo "Step 4: Checking build result..."
if [ -f "./build/typosentinel" ]; then
    echo "✓ Build successful! Binary created at ./build/typosentinel"
    echo ""
    echo "Step 5: Testing binary functionality..."
    ./build/typosentinel version
else
    echo "✗ Build failed! Binary not found."
    exit 1
fi

echo ""
echo "=========================================="
echo "Build completed successfully!"
echo "=========================================="