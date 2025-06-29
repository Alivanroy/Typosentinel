#!/bin/bash
# scripts/dependency-audit.sh

set -e

echo "🔍 Running dependency audit..."

# Go dependency audit
if [ -f "go.mod" ]; then
    echo "Auditing Go dependencies..."
    
    # Check for known vulnerabilities
    govulncheck ./...
    
    # Check for outdated dependencies
    go list -u -m all | grep '\[' && {
        echo "⚠️  Outdated dependencies found. Consider updating."
    }
fi

# Python dependency audit (if pip-audit is available)
if [ -f "ml/requirements.txt" ] && command -v pip-audit &> /dev/null; then
    echo "Auditing Python dependencies..."
    cd ml && pip-audit -r requirements.txt
fi

echo "✅ Dependency audit passed!"