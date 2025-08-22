#!/bin/bash

# ACME Enterprise - Registry Setup Script
# This script sets up and configures all package registries for Typosentinel testing

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REGISTRIES_DIR="${SCRIPT_DIR}/registries"
LOG_FILE="${SCRIPT_DIR}/setup-registries.log"

# Initialize logging
echo "[$(date '+%Y-%m-%d %H:%M:%S')] Starting registry setup..." > "$LOG_FILE"

# Function to setup NPM registry
setup_npm_registry() {
    log_info "Setting up NPM registry..."
    local npm_dir="${REGISTRIES_DIR}/npm"
    
    if [[ -d "$npm_dir" ]]; then
        cd "$npm_dir"
        
        # Install dependencies if package.json exists
        if [[ -f "package.json" ]]; then
            log_info "Installing NPM dependencies..."
            if command -v npm >/dev/null 2>&1; then
                npm install --no-audit --no-fund 2>>"$LOG_FILE" || {
                    log_warning "NPM install failed, but continuing..."
                }
            else
                log_warning "NPM not found, skipping dependency installation"
            fi
        fi
        
        # Run security audit
        if command -v npm >/dev/null 2>&1; then
            log_info "Running NPM security audit..."
            npm audit --audit-level=moderate 2>>"$LOG_FILE" || {
                log_warning "NPM audit found vulnerabilities"
            }
        fi
        
        log_success "NPM registry setup completed"
    else
        log_error "NPM registry directory not found: $npm_dir"
        return 1
    fi
}

# Function to setup PyPI registry
setup_pypi_registry() {
    log_info "Setting up PyPI registry..."
    local pypi_dir="${REGISTRIES_DIR}/pypi"
    
    if [[ -d "$pypi_dir" ]]; then
        cd "$pypi_dir"
        
        # Create virtual environment if requirements.txt exists
        if [[ -f "requirements.txt" ]]; then
            log_info "Setting up Python virtual environment..."
            if command -v python3 >/dev/null 2>&1; then
                python3 -m venv venv 2>>"$LOG_FILE" || {
                    log_warning "Failed to create virtual environment"
                }
                
                if [[ -f "venv/bin/activate" ]]; then
                    source venv/bin/activate
                    log_info "Installing Python dependencies..."
                    pip install --upgrade pip 2>>"$LOG_FILE"
                    pip install -r requirements.txt 2>>"$LOG_FILE" || {
                        log_warning "Some Python packages failed to install"
                    }
                    
                    # Run security check
                    if command -v safety >/dev/null 2>&1; then
                        log_info "Running Python security check..."
                        safety check 2>>"$LOG_FILE" || {
                            log_warning "Python security check found vulnerabilities"
                        }
                    fi
                    
                    deactivate
                fi
            else
                log_warning "Python3 not found, skipping PyPI setup"
            fi
        fi
        
        log_success "PyPI registry setup completed"
    else
        log_error "PyPI registry directory not found: $pypi_dir"
        return 1
    fi
}

# Function to setup Maven registry
setup_maven_registry() {
    log_info "Setting up Maven registry..."
    local maven_dir="${REGISTRIES_DIR}/maven"
    
    if [[ -d "$maven_dir" ]]; then
        cd "$maven_dir"
        
        # Validate and compile if pom.xml exists
        if [[ -f "pom.xml" ]]; then
            if command -v mvn >/dev/null 2>&1; then
                log_info "Validating Maven project..."
                mvn validate 2>>"$LOG_FILE" || {
                    log_warning "Maven validation failed"
                }
                
                log_info "Downloading Maven dependencies..."
                mvn dependency:resolve 2>>"$LOG_FILE" || {
                    log_warning "Some Maven dependencies failed to resolve"
                }
                
                # Run security check
                log_info "Running Maven security check..."
                mvn org.owasp:dependency-check-maven:check 2>>"$LOG_FILE" || {
                    log_warning "Maven security check found vulnerabilities"
                }
            else
                log_warning "Maven not found, skipping Maven setup"
            fi
        fi
        
        log_success "Maven registry setup completed"
    else
        log_error "Maven registry directory not found: $maven_dir"
        return 1
    fi
}

# Function to setup NuGet registry
setup_nuget_registry() {
    log_info "Setting up NuGet registry..."
    local nuget_dir="${REGISTRIES_DIR}/nuget"
    
    if [[ -d "$nuget_dir" ]]; then
        cd "$nuget_dir"
        
        # Restore packages if packages.config exists
        if [[ -f "packages.config" ]]; then
            if command -v nuget >/dev/null 2>&1; then
                log_info "Restoring NuGet packages..."
                nuget restore packages.config 2>>"$LOG_FILE" || {
                    log_warning "NuGet restore failed"
                }
            else
                log_warning "NuGet not found, skipping NuGet setup"
            fi
        fi
        
        log_success "NuGet registry setup completed"
    else
        log_error "NuGet registry directory not found: $nuget_dir"
        return 1
    fi
}

# Function to setup RubyGems registry
setup_rubygems_registry() {
    log_info "Setting up RubyGems registry..."
    local rubygems_dir="${REGISTRIES_DIR}/rubygems"
    
    if [[ -d "$rubygems_dir" ]]; then
        cd "$rubygems_dir"
        
        # Install gems if Gemfile exists
        if [[ -f "Gemfile" ]]; then
            if command -v bundle >/dev/null 2>&1; then
                log_info "Installing Ruby gems..."
                bundle install 2>>"$LOG_FILE" || {
                    log_warning "Bundle install failed"
                }
                
                # Run security audit
                if command -v bundle-audit >/dev/null 2>&1; then
                    log_info "Running Ruby security audit..."
                    bundle-audit check 2>>"$LOG_FILE" || {
                        log_warning "Ruby security audit found vulnerabilities"
                    }
                fi
            else
                log_warning "Bundler not found, skipping RubyGems setup"
            fi
        fi
        
        log_success "RubyGems registry setup completed"
    else
        log_error "RubyGems registry directory not found: $rubygems_dir"
        return 1
    fi
}

# Function to setup Go modules registry
setup_go_registry() {
    log_info "Setting up Go modules registry..."
    local go_dir="${REGISTRIES_DIR}/go"
    
    if [[ -d "$go_dir" ]]; then
        cd "$go_dir"
        
        # Download modules if go.mod exists
        if [[ -f "go.mod" ]]; then
            if command -v go >/dev/null 2>&1; then
                log_info "Downloading Go modules..."
                go mod download 2>>"$LOG_FILE" || {
                    log_warning "Go mod download failed"
                }
                
                log_info "Verifying Go modules..."
                go mod verify 2>>"$LOG_FILE" || {
                    log_warning "Go mod verify failed"
                }
                
                # Run security check
                if command -v govulncheck >/dev/null 2>&1; then
                    log_info "Running Go vulnerability check..."
                    govulncheck ./... 2>>"$LOG_FILE" || {
                        log_warning "Go vulnerability check found issues"
                    }
                fi
            else
                log_warning "Go not found, skipping Go modules setup"
            fi
        fi
        
        log_success "Go modules registry setup completed"
    else
        log_error "Go modules registry directory not found: $go_dir"
        return 1
    fi
}

# Function to validate registry configurations
validate_registries() {
    log_info "Validating registry configurations..."
    
    local registries=("npm" "pypi" "maven" "nuget" "rubygems" "go")
    local valid_count=0
    
    for registry in "${registries[@]}"; do
        local registry_dir="${REGISTRIES_DIR}/${registry}"
        if [[ -d "$registry_dir" ]]; then
            log_success "Registry found: $registry"
            ((valid_count++))
        else
            log_error "Registry missing: $registry"
        fi
    done
    
    log_info "Found $valid_count out of ${#registries[@]} registries"
    
    if [[ $valid_count -eq ${#registries[@]} ]]; then
        log_success "All registries are properly configured"
        return 0
    else
        log_error "Some registries are missing or misconfigured"
        return 1
    fi
}

# Function to generate registry report
generate_report() {
    log_info "Generating registry setup report..."
    
    local report_file="${SCRIPT_DIR}/registry-setup-report.json"
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    
    cat > "$report_file" << EOF
{
  "timestamp": "$timestamp",
  "registries": {
    "npm": {
      "configured": $([ -d "${REGISTRIES_DIR}/npm" ] && echo "true" || echo "false"),
      "package_file": $([ -f "${REGISTRIES_DIR}/npm/package.json" ] && echo "true" || echo "false")
    },
    "pypi": {
      "configured": $([ -d "${REGISTRIES_DIR}/pypi" ] && echo "true" || echo "false"),
      "requirements_file": $([ -f "${REGISTRIES_DIR}/pypi/requirements.txt" ] && echo "true" || echo "false")
    },
    "maven": {
      "configured": $([ -d "${REGISTRIES_DIR}/maven" ] && echo "true" || echo "false"),
      "pom_file": $([ -f "${REGISTRIES_DIR}/maven/pom.xml" ] && echo "true" || echo "false")
    },
    "nuget": {
      "configured": $([ -d "${REGISTRIES_DIR}/nuget" ] && echo "true" || echo "false"),
      "packages_file": $([ -f "${REGISTRIES_DIR}/nuget/packages.config" ] && echo "true" || echo "false")
    },
    "rubygems": {
      "configured": $([ -d "${REGISTRIES_DIR}/rubygems" ] && echo "true" || echo "false"),
      "gemfile": $([ -f "${REGISTRIES_DIR}/rubygems/Gemfile" ] && echo "true" || echo "false")
    },
    "go": {
      "configured": $([ -d "${REGISTRIES_DIR}/go" ] && echo "true" || echo "false"),
      "mod_file": $([ -f "${REGISTRIES_DIR}/go/go.mod" ] && echo "true" || echo "false")
    }
  },
  "setup_completed": true,
  "log_file": "$LOG_FILE"
}
EOF
    
    log_success "Report generated: $report_file"
}

# Main execution
main() {
    log_info "Starting ACME Enterprise registry setup..."
    log_info "Working directory: $SCRIPT_DIR"
    log_info "Registries directory: $REGISTRIES_DIR"
    
    # Check if registries directory exists
    if [[ ! -d "$REGISTRIES_DIR" ]]; then
        log_error "Registries directory not found: $REGISTRIES_DIR"
        exit 1
    fi
    
    # Setup each registry
    local setup_errors=0
    
    setup_npm_registry || ((setup_errors++))
    setup_pypi_registry || ((setup_errors++))
    setup_maven_registry || ((setup_errors++))
    setup_nuget_registry || ((setup_errors++))
    setup_rubygems_registry || ((setup_errors++))
    setup_go_registry || ((setup_errors++))
    
    # Validate configurations
    validate_registries || ((setup_errors++))
    
    # Generate report
    generate_report
    
    # Final status
    if [[ $setup_errors -eq 0 ]]; then
        log_success "Registry setup completed successfully!"
        log_info "Log file: $LOG_FILE"
        exit 0
    else
        log_error "Registry setup completed with $setup_errors errors"
        log_info "Check log file for details: $LOG_FILE"
        exit 1
    fi
}

# Run main function
main "$@"