#!/bin/bash
# scripts/setup-pre-commit.sh

set -e

echo "🔧 Setting up pre-commit hooks for TypoSentinel..."

# Check if pre-commit is installed
if ! command -v pre-commit &> /dev/null; then
    echo "Installing pre-commit..."
    if command -v pip &> /dev/null; then
        pip install pre-commit
    elif command -v brew &> /dev/null; then
        brew install pre-commit
    else
        echo "❌ Please install pre-commit manually: https://pre-commit.com/#installation"
        exit 1
    fi
fi

# Install Go tools
echo "Installing Go development tools..."
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
go install golang.org/x/vuln/cmd/govulncheck@latest
go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest

# Install Python tools (if ml directory exists)
if [ -d "ml" ]; then
    echo "Installing Python development tools..."
    pip install black flake8 isort pip-audit
fi

# Make scripts executable
chmod +x scripts/*.sh

# Install pre-commit hooks
echo "Installing pre-commit hooks..."
pre-commit install
pre-commit install --hook-type commit-msg

# Run initial check
echo "Running initial pre-commit check..."
pre-commit run --all-files || {
    echo "⚠️  Some checks failed. Please fix the issues and commit again."
    exit 1
}

echo "✅ Pre-commit hooks setup complete!"
echo ""
echo "Usage:"
echo "  - Hooks run automatically on each commit"
echo "  - Run manually: pre-commit run --all-files"
echo "  - Update hooks: pre-commit autoupdate"