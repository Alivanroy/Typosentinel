#!/bin/bash
# scripts/pre-commit-security-scan.sh

set -e

echo "🔍 Running TypoSentinel self-scan..."

# Build current version if needed
if [ ! -f "./typosentinel" ]; then
    echo "Building TypoSentinel..."
    go build -o typosentinel ./cmd/typosentinel
fi

# Scan current dependencies
echo "Scanning Go dependencies..."
if [ -f "go.mod" ]; then
    ./typosentinel scan --ecosystem go --fail-on-threats --format json > security-report.json
    
    # Check for threats
    threat_count=$(jq '.summary.total_threats // 0' security-report.json)
    if [ "$threat_count" -gt 0 ]; then
        echo "❌ Security threats detected in dependencies!"
        jq '.threats[] | "⚠️  \(.type): \(.description)"' -r security-report.json
        exit 1
    fi
fi

# Scan Python dependencies if they exist
if [ -f "ml/requirements.txt" ]; then
    echo "Scanning Python dependencies..."
    ./typosentinel scan ml/requirements.txt --ecosystem python --fail-on-threats
fi

echo "✅ Security scan passed!"