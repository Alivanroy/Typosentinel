#!/bin/bash
# Quick CI/CD Test Script for Typosentinel
# Suitable for integration into CI pipelines

set -e

# Exit codes
EXIT_SUCCESS=0
EXIT_FAILURE=1
EXIT_THREATS_FOUND=2

# Check if typosentinel is available
if ! command -v typosentinel &> /dev/null; then
    echo "Error: typosentinel not found in PATH"
    echo "Please install typosentinel first"
    exit $EXIT_FAILURE
fi

# Function to scan and check results
scan_project() {
    local project_path="${1:-.}"
    local severity_threshold="${2:-high}"
    local output_format="${3:-json}"
    
    echo "🔍 Scanning project at: $project_path"
    echo "Severity threshold: $severity_threshold"
    
    # Run scan
    local scan_output=$(mktemp)
    typosentinel scan --project-path "$project_path" --output "$output_format" > "$scan_output" 2>&1
    
    # Check results based on format
    if [ "$output_format" = "json" ]; then
        # Parse JSON results
        local total_threats=$(jq '[.results[].threats | length] | add // 0' "$scan_output")
        local critical_threats=$(jq '[.results[].threats[] | select(.severity == "critical")] | length' "$scan_output")
        local high_threats=$(jq '[.results[].threats[] | select(.severity == "high")] | length' "$scan_output")
        
        echo "📊 Scan Results:"
        echo "  Total threats: $total_threats"
        echo "  Critical: $critical_threats"
        echo "  High: $high_threats"
        
        # Check against threshold
        case "$severity_threshold" in
            "critical")
                if [ "$critical_threats" -gt 0 ]; then
                    echo "❌ Found $critical_threats critical threats!"
                    jq -r '.results[] | select(.threats[] | select(.severity == "critical")) | "  - \(.package.name): \(.threats[] | select(.severity == "critical") | .description)"' "$scan_output"
                    rm "$scan_output"
                    exit $EXIT_THREATS_FOUND
                fi
                ;;
            "high")
                if [ "$critical_threats" -gt 0 ] || [ "$high_threats" -gt 0 ]; then
                    echo "❌ Found high/critical severity threats!"
                    jq -r '.results[] | select(.threats[] | select(.severity == "critical" or .severity == "high")) | "  - \(.package.name): \(.threats[] | select(.severity == "critical" or .severity == "high") | .description)"' "$scan_output"
                    rm "$scan_output"
                    exit $EXIT_THREATS_FOUND
                fi
                ;;
            *)
                if [ "$total_threats" -gt 0 ]; then
                    echo "⚠️  Found $total_threats total threats"
                    jq -r '.results[] | select(.threats | length > 0) | "  - \(.package.name): \(.threats | length) threats"' "$scan_output"
                fi
                ;;
        esac
    fi
    
    # Save results for artifacts
    if [ -n "$CI" ]; then
        cp "$scan_output" "typosentinel-results.$output_format"
        echo "Results saved to: typosentinel-results.$output_format"
    fi
    
    rm "$scan_output"
    echo "✅ No threats found above threshold"
    return $EXIT_SUCCESS
}

# Main execution
main() {
    echo "🚀 Typosentinel CI/CD Security Check"
    echo "===================================="
    
    # Parse arguments
    PROJECT_PATH="${1:-.}"
    SEVERITY="${2:-high}"
    FORMAT="${3:-json}"
    
    # Show configuration
    echo "Configuration:"
    echo "  Project: $PROJECT_PATH"
    echo "  Threshold: $SEVERITY"
    echo "  Format: $FORMAT"
    echo ""
    
    # Run scan
    scan_project "$PROJECT_PATH" "$SEVERITY" "$FORMAT"
}

# Run if not sourced
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi