#!/bin/bash

# Comprehensive Package Scanning Script for ACME Frontend
# This script scans multiple packages from package.json with vulnerability detection

echo "🔍 Starting comprehensive package scanning for ACME Frontend..."

# Configuration
CONFIG_FILE="tests/acme-enterprise/typosentinel.yaml"
OUTPUT_DIR="tests/acme-enterprise/scan-results"
TYPOSENTINEL="./typosentinel"

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# Key packages to scan from frontend dependencies
PACKAGES=(
    "react"
    "react-dom"
    "axios"
    "lodash"
    "moment"
    "jquery"
    "bootstrap"
    "chart.js"
    "formik"
    "styled-components"
    "@mui/material"
    "@reduxjs/toolkit"
    "socket.io-client"
    "crypto-js"
    "jsonwebtoken"
    "uuid"
    "firebase"
    "aws-sdk"
    "three"
    "d3"
    "prismjs"
)

echo "📦 Scanning ${#PACKAGES[@]} key packages..."

# Scan each package with comprehensive analysis
for package in "${PACKAGES[@]}"; do
    echo "\n🔎 Scanning: $package"
    
    # Clean package name for filename (replace special chars)
    clean_name=$(echo "$package" | sed 's/[@\/]/_/g')
    output_file="$OUTPUT_DIR/scan_${clean_name}.json"
    
    # Run comprehensive scan
    $TYPOSENTINEL scan "$package" \
        --config "$CONFIG_FILE" \
        --thorough \
        --format json \
        --output "$output_file" \
        --verbose
    
    if [ $? -eq 0 ]; then
        echo "✅ Completed: $package -> $output_file"
    else
        echo "❌ Failed: $package"
    fi
done

echo "\n📊 Generating summary report..."

# Create a summary of all scans
summary_file="$OUTPUT_DIR/comprehensive_scan_summary.json"
echo '{' > "$summary_file"
echo '  "scan_summary": {' >> "$summary_file"
echo '    "timestamp": "'$(date -u +"%Y-%m-%dT%H:%M:%SZ")'",' >> "$summary_file"
echo '    "total_packages_scanned": '${#PACKAGES[@]}',' >> "$summary_file"
echo '    "packages": [' >> "$summary_file"

# Add each package to summary
for i in "${!PACKAGES[@]}"; do
    package="${PACKAGES[$i]}"
    clean_name=$(echo "$package" | sed 's/[@\/]/_/g')
    
    echo '      {' >> "$summary_file"
    echo '        "name": "'$package'",' >> "$summary_file"
    echo '        "scan_file": "scan_'$clean_name'.json"' >> "$summary_file"
    
    if [ $i -eq $((${#PACKAGES[@]} - 1)) ]; then
        echo '      }' >> "$summary_file"
    else
        echo '      },' >> "$summary_file"
    fi
done

echo '    ]' >> "$summary_file"
echo '  }' >> "$summary_file"
echo '}' >> "$summary_file"

echo "\n✨ Comprehensive scanning complete!"
echo "📁 Results saved in: $OUTPUT_DIR"
echo "📋 Summary report: $summary_file"
echo "\n🔍 To view results:"
echo "   ls -la $OUTPUT_DIR/"
echo "   cat $summary_file"