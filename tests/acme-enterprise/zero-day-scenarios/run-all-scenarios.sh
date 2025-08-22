#!/bin/bash

# Zero-Day Attack Scenarios Orchestrator
# 
# This script runs all zero-day attack simulations and generates
# a comprehensive report for testing Typosentinel's detection capabilities.

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/comprehensive-attack-report"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORT_DIR="${OUTPUT_DIR}/${TIMESTAMP}"

# Logging
LOG_FILE="${SCRIPT_DIR}/attack-simulation.log"

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$LOG_FILE"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$LOG_FILE"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
}

log_header() {
    echo -e "\n${PURPLE}=== $1 ===${NC}" | tee -a "$LOG_FILE"
}

# Check dependencies
check_dependencies() {
    log_header "Checking Dependencies"
    
    local missing_deps=()
    
    # Check for Node.js
    if ! command -v node &> /dev/null; then
        missing_deps+=("node")
    fi
    
    # Check for Python
    if ! command -v python3 &> /dev/null; then
        missing_deps+=("python3")
    fi
    
    # Check for Ruby
    if ! command -v ruby &> /dev/null; then
        missing_deps+=("ruby")
    fi
    
    # Check for jq for JSON processing
    if ! command -v jq &> /dev/null; then
        missing_deps+=("jq")
    fi
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        log_error "Missing dependencies: ${missing_deps[*]}"
        log_info "Please install the missing dependencies and try again."
        exit 1
    fi
    
    log_success "All dependencies are available"
}

# Setup output directories
setup_directories() {
    log_header "Setting Up Output Directories"
    
    mkdir -p "$REPORT_DIR"
    mkdir -p "${REPORT_DIR}/typosquatting"
    mkdir -p "${REPORT_DIR}/dependency-confusion"
    mkdir -p "${REPORT_DIR}/supply-chain"
    mkdir -p "${REPORT_DIR}/logs"
    mkdir -p "${REPORT_DIR}/artifacts"
    
    log_success "Output directories created at: $REPORT_DIR"
}

# Run typosquatting attack simulation
run_typosquatting_simulation() {
    log_header "Running Typosquatting Attack Simulation"
    
    local output_file="${REPORT_DIR}/typosquatting/simulation_output.log"
    local error_file="${REPORT_DIR}/typosquatting/simulation_errors.log"
    
    if node "${SCRIPT_DIR}/typosquatting-attack.js" > "$output_file" 2> "$error_file"; then
        log_success "Typosquatting simulation completed successfully"
        
        # Copy generated artifacts
        if [ -d "${SCRIPT_DIR}/attack-artifacts" ]; then
            cp -r "${SCRIPT_DIR}/attack-artifacts"/* "${REPORT_DIR}/typosquatting/" 2>/dev/null || true
        fi
        
        return 0
    else
        log_error "Typosquatting simulation failed"
        log_error "Check error log: $error_file"
        return 1
    fi
}

# Run dependency confusion attack simulation
run_dependency_confusion_simulation() {
    log_header "Running Dependency Confusion Attack Simulation"
    
    local output_file="${REPORT_DIR}/dependency-confusion/simulation_output.log"
    local error_file="${REPORT_DIR}/dependency-confusion/simulation_errors.log"
    
    if python3 "${SCRIPT_DIR}/dependency-confusion-attack.py" > "$output_file" 2> "$error_file"; then
        log_success "Dependency confusion simulation completed successfully"
        
        # Copy generated artifacts
        if [ -d "${SCRIPT_DIR}/dependency-confusion-artifacts" ]; then
            cp -r "${SCRIPT_DIR}/dependency-confusion-artifacts"/* "${REPORT_DIR}/dependency-confusion/" 2>/dev/null || true
        fi
        
        return 0
    else
        log_error "Dependency confusion simulation failed"
        log_error "Check error log: $error_file"
        return 1
    fi
}

# Run supply chain attack simulation
run_supply_chain_simulation() {
    log_header "Running Supply Chain Attack Simulation"
    
    local output_file="${REPORT_DIR}/supply-chain/simulation_output.log"
    local error_file="${REPORT_DIR}/supply-chain/simulation_errors.log"
    
    if ruby "${SCRIPT_DIR}/supply-chain-attack.rb" > "$output_file" 2> "$error_file"; then
        log_success "Supply chain simulation completed successfully"
        
        # Copy generated artifacts
        if [ -d "${SCRIPT_DIR}/supply-chain-artifacts" ]; then
            cp -r "${SCRIPT_DIR}/supply-chain-artifacts"/* "${REPORT_DIR}/supply-chain/" 2>/dev/null || true
        fi
        
        return 0
    else
        log_error "Supply chain simulation failed"
        log_error "Check error log: $error_file"
        return 1
    fi
}

# Generate comprehensive report
generate_comprehensive_report() {
    log_header "Generating Comprehensive Attack Report"
    
    local report_file="${REPORT_DIR}/comprehensive-attack-report.json"
    local summary_file="${REPORT_DIR}/attack-summary.md"
    
    # Initialize report structure
    cat > "$report_file" << EOF
{
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "simulation_id": "${TIMESTAMP}",
  "report_version": "1.0.0",
  "summary": {
    "total_scenarios": 3,
    "successful_scenarios": 0,
    "failed_scenarios": 0,
    "total_attacks_generated": 0,
    "registries_targeted": [],
    "attack_types_covered": []
  },
  "scenarios": {
    "typosquatting": {
      "status": "unknown",
      "attacks_generated": 0,
      "artifacts_location": "${REPORT_DIR}/typosquatting"
    },
    "dependency_confusion": {
      "status": "unknown",
      "attacks_generated": 0,
      "artifacts_location": "${REPORT_DIR}/dependency-confusion"
    },
    "supply_chain": {
      "status": "unknown",
      "attacks_generated": 0,
      "artifacts_location": "${REPORT_DIR}/supply-chain"
    }
  },
  "detection_challenges": {
    "high_similarity_attacks": 0,
    "obfuscated_payloads": 0,
    "time_delayed_attacks": 0,
    "environment_specific_attacks": 0,
    "legitimate_looking_metadata": 0
  },
  "risk_analysis": {
    "critical_risk_attacks": 0,
    "high_risk_attacks": 0,
    "medium_risk_attacks": 0,
    "low_risk_attacks": 0
  },
  "recommendations": [
    "Implement real-time package scanning during CI/CD",
    "Monitor for typosquatting patterns in package names",
    "Validate package metadata and maintainer information",
    "Implement dependency pinning and lock file verification",
    "Set up alerts for new packages matching internal naming patterns",
    "Regular security audits of dependency chains",
    "Implement package signature verification",
    "Monitor for suspicious package behavior post-installation"
  ]
}
EOF

    # Process individual scenario results
    local successful_scenarios=0
    local total_attacks=0
    
    # Process typosquatting results
    if [ -f "${REPORT_DIR}/typosquatting/simulation_output.log" ] && [ ! -s "${REPORT_DIR}/typosquatting/simulation_errors.log" ]; then
        ((successful_scenarios++))
        # Extract attack count from typosquatting artifacts
        local typo_attacks=$(find "${REPORT_DIR}/typosquatting" -name "*.json" -exec jq -r '.total_attacks // 0' {} \; 2>/dev/null | head -1 || echo "0")
        total_attacks=$((total_attacks + typo_attacks))
        
        # Update report
        jq --arg status "success" --argjson attacks "$typo_attacks" \
           '.scenarios.typosquatting.status = $status | .scenarios.typosquatting.attacks_generated = $attacks' \
           "$report_file" > "${report_file}.tmp" && mv "${report_file}.tmp" "$report_file"
    else
        jq '.scenarios.typosquatting.status = "failed"' "$report_file" > "${report_file}.tmp" && mv "${report_file}.tmp" "$report_file"
    fi
    
    # Process dependency confusion results
    if [ -f "${REPORT_DIR}/dependency-confusion/simulation_output.log" ] && [ ! -s "${REPORT_DIR}/dependency-confusion/simulation_errors.log" ]; then
        ((successful_scenarios++))
        local dep_attacks=$(find "${REPORT_DIR}/dependency-confusion" -name "*.json" -exec jq -r '.total_packages // 0' {} \; 2>/dev/null | head -1 || echo "0")
        total_attacks=$((total_attacks + dep_attacks))
        
        jq --arg status "success" --argjson attacks "$dep_attacks" \
           '.scenarios.dependency_confusion.status = $status | .scenarios.dependency_confusion.attacks_generated = $attacks' \
           "$report_file" > "${report_file}.tmp" && mv "${report_file}.tmp" "$report_file"
    else
        jq '.scenarios.dependency_confusion.status = "failed"' "$report_file" > "${report_file}.tmp" && mv "${report_file}.tmp" "$report_file"
    fi
    
    # Process supply chain results
    if [ -f "${REPORT_DIR}/supply-chain/simulation_output.log" ] && [ ! -s "${REPORT_DIR}/supply-chain/simulation_errors.log" ]; then
        ((successful_scenarios++))
        local supply_attacks=$(find "${REPORT_DIR}/supply-chain" -name "*.json" -exec jq -r '.total_packages // 0' {} \; 2>/dev/null | head -1 || echo "0")
        total_attacks=$((total_attacks + supply_attacks))
        
        jq --arg status "success" --argjson attacks "$supply_attacks" \
           '.scenarios.supply_chain.status = $status | .scenarios.supply_chain.attacks_generated = $attacks' \
           "$report_file" > "${report_file}.tmp" && mv "${report_file}.tmp" "$report_file"
    else
        jq '.scenarios.supply_chain.status = "failed"' "$report_file" > "${report_file}.tmp" && mv "${report_file}.tmp" "$report_file"
    fi
    
    # Update summary
    local failed_scenarios=$((3 - successful_scenarios))
    jq --argjson successful "$successful_scenarios" \
       --argjson failed "$failed_scenarios" \
       --argjson total "$total_attacks" \
       '.summary.successful_scenarios = $successful | .summary.failed_scenarios = $failed | .summary.total_attacks_generated = $total' \
       "$report_file" > "${report_file}.tmp" && mv "${report_file}.tmp" "$report_file"
    
    # Generate markdown summary
    generate_markdown_summary "$summary_file" "$report_file"
    
    log_success "Comprehensive report generated: $report_file"
    log_success "Summary report generated: $summary_file"
}

# Generate markdown summary
generate_markdown_summary() {
    local summary_file="$1"
    local report_file="$2"
    
    cat > "$summary_file" << EOF
# Zero-Day Attack Simulation Report

**Generated:** $(date)
**Simulation ID:** ${TIMESTAMP}

## Executive Summary

This report contains the results of comprehensive zero-day attack simulations designed to test Typosentinel's detection capabilities across multiple attack vectors and package registries.

### Simulation Results

- **Total Scenarios:** $(jq -r '.summary.total_scenarios' "$report_file")
- **Successful Scenarios:** $(jq -r '.summary.successful_scenarios' "$report_file")
- **Failed Scenarios:** $(jq -r '.summary.failed_scenarios' "$report_file")
- **Total Attacks Generated:** $(jq -r '.summary.total_attacks_generated' "$report_file")

### Scenario Breakdown

#### 1. Typosquatting Attacks
- **Status:** $(jq -r '.scenarios.typosquatting.status' "$report_file")
- **Attacks Generated:** $(jq -r '.scenarios.typosquatting.attacks_generated' "$report_file")
- **Artifacts Location:** \`${REPORT_DIR}/typosquatting\`

#### 2. Dependency Confusion Attacks
- **Status:** $(jq -r '.scenarios.dependency_confusion.status' "$report_file")
- **Attacks Generated:** $(jq -r '.scenarios.dependency_confusion.attacks_generated' "$report_file")
- **Artifacts Location:** \`${REPORT_DIR}/dependency-confusion\`

#### 3. Supply Chain Attacks
- **Status:** $(jq -r '.scenarios.supply_chain.status' "$report_file")
- **Attacks Generated:** $(jq -r '.scenarios.supply_chain.attacks_generated' "$report_file")
- **Artifacts Location:** \`${REPORT_DIR}/supply-chain\`

## Detection Challenges

The simulated attacks include various evasion techniques that present detection challenges:

- High similarity to legitimate packages
- Obfuscated malicious payloads
- Time-delayed activation mechanisms
- Environment-specific execution conditions
- Legitimate-looking metadata and descriptions

## Recommendations

$(jq -r '.recommendations[] | "- " + .' "$report_file")

## Files Generated

- **Comprehensive Report:** \`$(basename "$report_file")\`
- **Typosquatting Artifacts:** \`typosquatting/\`
- **Dependency Confusion Artifacts:** \`dependency-confusion/\`
- **Supply Chain Artifacts:** \`supply-chain/\`
- **Simulation Logs:** \`logs/\`

## Next Steps

1. Review individual attack scenarios in their respective directories
2. Analyze the generated malicious packages for detection patterns
3. Test Typosentinel against the generated attack data
4. Implement additional detection rules based on findings
5. Repeat simulations with updated detection capabilities

---

*This report was generated automatically by the Zero-Day Attack Simulation Framework.*
EOF
}

# Run Typosentinel against generated attacks (if available)
run_typosentinel_detection() {
    log_header "Running Typosentinel Detection Tests"
    
    # Check if Typosentinel is available
    local typosentinel_binary="${SCRIPT_DIR}/../../../typosentinel-enterprise"
    
    if [ ! -f "$typosentinel_binary" ]; then
        log_warning "Typosentinel binary not found at: $typosentinel_binary"
        log_warning "Skipping detection tests"
        return 0
    fi
    
    local detection_results="${REPORT_DIR}/detection-results.json"
    
    # Test against generated package files
    log_info "Testing Typosentinel against generated attack packages..."
    
    # Find all generated package.json files
    local package_files=()
    while IFS= read -r -d '' file; do
        package_files+=("$file")
    done < <(find "$REPORT_DIR" -name "package.json" -print0 2>/dev/null)
    
    if [ ${#package_files[@]} -eq 0 ]; then
        log_warning "No package files found for testing"
        return 0
    fi
    
    # Initialize detection results
    echo '{"detection_results": [], "summary": {"total_tested": 0, "detected": 0, "missed": 0}}' > "$detection_results"
    
    local total_tested=0
    local detected=0
    
    for package_file in "${package_files[@]}"; do
        log_info "Testing package: $(basename "$package_file")"
        
        # Run Typosentinel scan
        if "$typosentinel_binary" scan --format json "$package_file" > "${REPORT_DIR}/temp_scan_result.json" 2>/dev/null; then
            # Check if threats were detected
            local threat_count=$(jq -r '.threats | length' "${REPORT_DIR}/temp_scan_result.json" 2>/dev/null || echo "0")
            
            if [ "$threat_count" -gt 0 ]; then
                ((detected++))
                log_success "Detected threats in $(basename "$package_file"): $threat_count"
            else
                log_warning "No threats detected in $(basename "$package_file")"
            fi
            
            # Add to results
            jq --arg file "$package_file" --argjson threats "$threat_count" \
               '.detection_results += [{"file": $file, "threats_detected": $threats}]' \
               "$detection_results" > "${detection_results}.tmp" && mv "${detection_results}.tmp" "$detection_results"
        else
            log_error "Failed to scan $(basename "$package_file")"
        fi
        
        ((total_tested++))
    done
    
    # Update summary
    local missed=$((total_tested - detected))
    jq --argjson total "$total_tested" --argjson detected "$detected" --argjson missed "$missed" \
       '.summary.total_tested = $total | .summary.detected = $detected | .summary.missed = $missed' \
       "$detection_results" > "${detection_results}.tmp" && mv "${detection_results}.tmp" "$detection_results"
    
    # Clean up
    rm -f "${REPORT_DIR}/temp_scan_result.json"
    
    log_success "Detection testing completed: $detected/$total_tested packages detected"
}

# Cleanup function
cleanup() {
    log_info "Cleaning up temporary files..."
    
    # Remove temporary artifact directories
    rm -rf "${SCRIPT_DIR}/attack-artifacts" 2>/dev/null || true
    rm -rf "${SCRIPT_DIR}/dependency-confusion-artifacts" 2>/dev/null || true
    rm -rf "${SCRIPT_DIR}/supply-chain-artifacts" 2>/dev/null || true
    
    log_success "Cleanup completed"
}

# Main execution
main() {
    log_header "Zero-Day Attack Scenarios Orchestrator"
    log_info "Starting comprehensive attack simulation..."
    
    # Setup
    check_dependencies
    setup_directories
    
    # Run simulations
    local simulation_results=()
    
    if run_typosquatting_simulation; then
        simulation_results+=("typosquatting:success")
    else
        simulation_results+=("typosquatting:failed")
    fi
    
    if run_dependency_confusion_simulation; then
        simulation_results+=("dependency_confusion:success")
    else
        simulation_results+=("dependency_confusion:failed")
    fi
    
    if run_supply_chain_simulation; then
        simulation_results+=("supply_chain:success")
    else
        simulation_results+=("supply_chain:failed")
    fi
    
    # Generate reports
    generate_comprehensive_report
    
    # Run detection tests if possible
    run_typosentinel_detection
    
    # Copy logs
    cp "$LOG_FILE" "${REPORT_DIR}/logs/" 2>/dev/null || true
    
    # Final summary
    log_header "Simulation Complete"
    log_info "Results summary:"
    for result in "${simulation_results[@]}"; do
        local scenario=$(echo "$result" | cut -d: -f1)
        local status=$(echo "$result" | cut -d: -f2)
        if [ "$status" = "success" ]; then
            log_success "$scenario: ✅ Success"
        else
            log_error "$scenario: ❌ Failed"
        fi
    done
    
    log_success "All results saved to: $REPORT_DIR"
    log_info "View the summary report: ${REPORT_DIR}/attack-summary.md"
    
    # Cleanup
    cleanup
}

# Trap for cleanup on exit
trap cleanup EXIT

# Run main function
main "$@"