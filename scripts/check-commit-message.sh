#!/bin/bash
# scripts/check-commit-message.sh

commit_regex='^(feat|fix|docs|style|refactor|test|chore)(\(.+\))?: .{1,50}'

if ! grep -qE "$commit_regex" "$1"; then
    echo "❌ Invalid commit message format!"
    echo ""
    echo "Commit message should follow conventional commits format:"
    echo "type(scope): description"
    echo ""
    echo "Examples:"
    echo "  feat(detector): add homoglyph detection"
    echo "  fix(api): resolve rate limiting issue"
    echo "  docs(readme): update installation instructions"
    echo ""
    exit 1
fi

echo "✅ Commit message format is valid"