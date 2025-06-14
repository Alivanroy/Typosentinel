#!/bin/bash

# TypoSentinel CLI Local Test Script
# This script demonstrates the CLI functionality without Docker

echo "=== TypoSentinel CLI Local Test ==="
echo

# Build the CLI if it doesn't exist
if [ ! -f "./typosentinel-cli" ]; then
    echo "🔨 Building TypoSentinel CLI..."
    if go build -o typosentinel-cli main.go; then
        echo "✅ CLI built successfully"
    else
        echo "❌ Failed to build CLI"
        exit 1
    fi
else
    echo "✅ CLI already exists"
fi
echo

# Test CLI help command
echo "📋 Testing CLI help command..."
./typosentinel-cli --help
echo
echo "---"
echo

# Test scan command help
echo "📋 Testing scan command help..."
./typosentinel-cli scan --help
echo
echo "---"
echo

# Test scanning a legitimate package
echo "🔍 Testing scan of legitimate package (lodash)..."
./typosentinel-cli scan lodash --format json
echo
echo "---"
echo

# Test scanning a potential typosquatting package
echo "🔍 Testing scan of potential typosquatting package (expresss)..."
./typosentinel-cli scan expresss --format json
echo
echo "---"
echo

# Test PyPI package scanning
echo "🔍 Testing PyPI package scan (requests)..."
./typosentinel-cli scan requests --registry pypi --format json
echo
echo "---"
echo

# Test with report saving
echo "💾 Testing scan with report saving..."
./typosentinel-cli scan axios --format json --save-report
echo
echo "---"
echo

# Test version command
echo "ℹ️  Testing version command..."
./typosentinel-cli --version
echo

echo "✅ All local CLI tests completed!"
echo
echo "📁 Check for generated report files:"
ls -la typosentinel-report-*.json 2>/dev/null || echo "   No report files found"
echo
echo "💡 Usage examples:"
echo "  ./typosentinel-cli scan [package-name]"
echo "  ./typosentinel-cli scan [package-name] --registry pypi"
echo "  ./typosentinel-cli scan [package-name] --format json --save-report"
echo "  ./typosentinel-cli scan [package-name] --verbose"
echo "  ./typosentinel-cli scan [package-name] --timeout 10m"