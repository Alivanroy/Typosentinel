#!/bin/bash

# Recursive Monorepo Scanner for TypoSentinel
# Implements the missing --recursive functionality

# Configuration
SCAN_DIR="${1:-./tests/acme-enterprise}"
OUTPUT_DIR="recursive-scan-results"
CONSOLIDATE_REPORT="consolidated-monorepo-report.json"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
LOG_FILE="recursive-scan-${TIMESTAMP}.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "[$(date +'%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log_info() {
    log "${BLUE}[INFO]${NC} $1"
}

log_success() {
    log "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    log "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    log "${RED}[ERROR]${NC} $1"
}

# Check if typosentinel exists
if [ ! -f "./typosentinel" ]; then
    log_error "TypoSentinel binary not found. Please ensure you're in the correct directory."
    exit 1
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"
log_info "Created output directory: $OUTPUT_DIR"

# Initialize consolidated report
echo '{' > "$OUTPUT_DIR/$CONSOLIDATE_REPORT"
echo '  "scan_metadata": {' >> "$OUTPUT_DIR/$CONSOLIDATE_REPORT"
echo "    \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"," >> "$OUTPUT_DIR/$CONSOLIDATE_REPORT"
echo "    \"scan_directory\": \"$SCAN_DIR\"," >> "$OUTPUT_DIR/$CONSOLIDATE_REPORT"
echo '    "scanner_version": "typosentinel-recursive-v1.0",' >> "$OUTPUT_DIR/$CONSOLIDATE_REPORT"
echo '    "scan_type": "recursive_monorepo"' >> "$OUTPUT_DIR/$CONSOLIDATE_REPORT"
echo '  },' >> "$OUTPUT_DIR/$CONSOLIDATE_REPORT"
echo '  "projects": [' >> "$OUTPUT_DIR/$CONSOLIDATE_REPORT"

# Counters
TOTAL_PROJECTS=0
SUCCESSFUL_SCANS=0
FAILED_SCANS=0
FIRST_PROJECT=true

# Function to scan a project
scan_project() {
    local project_path="$1"
    local project_type="$2"
    local manifest_file="$3"
    local project_name=$(basename "$project_path")
    
    log_info "Scanning $project_type project: $project_name"
    
    # Add comma separator for JSON (except for first project)
    if [ "$FIRST_PROJECT" = false ]; then
        echo '    ,' >> "$OUTPUT_DIR/$CONSOLIDATE_REPORT"
    fi
    FIRST_PROJECT=false
    
    # Start project entry in consolidated report
    echo '    {' >> "$OUTPUT_DIR/$CONSOLIDATE_REPORT"
    echo "      \"project_name\": \"$project_name\"," >> "$OUTPUT_DIR/$CONSOLIDATE_REPORT"
    echo "      \"project_type\": \"$project_type\"," >> "$OUTPUT_DIR/$CONSOLIDATE_REPORT"
    echo "      \"project_path\": \"$project_path\"," >> "$OUTPUT_DIR/$CONSOLIDATE_REPORT"
    echo "      \"manifest_file\": \"$manifest_file\"," >> "$OUTPUT_DIR/$CONSOLIDATE_REPORT"
    
    # Perform scan
    local scan_output_file="$OUTPUT_DIR/scan-${project_type}-${project_name}.json"
    
    if ./typosentinel scan dummy \
        --local "$manifest_file" \
        --thorough \
        --format json \
        --output "$scan_output_file" \
        --progress=false \
        --quiet 2>&1; then
        
        log_success "Successfully scanned $project_name"
        echo '      "scan_status": "success",' >> "$OUTPUT_DIR/$CONSOLIDATE_REPORT"
        echo "      \"scan_output_file\": \"$scan_output_file\"" >> "$OUTPUT_DIR/$CONSOLIDATE_REPORT"
        ((SUCCESSFUL_SCANS++))
    else
        log_error "Failed to scan $project_name"
        echo '      "scan_status": "failed",' >> "$OUTPUT_DIR/$CONSOLIDATE_REPORT"
        echo "      \"error_log\": \"$scan_output_file\"" >> "$OUTPUT_DIR/$CONSOLIDATE_REPORT"
        ((FAILED_SCANS++))
    fi
    
    echo '    }' >> "$OUTPUT_DIR/$CONSOLIDATE_REPORT"
    ((TOTAL_PROJECTS++))
}

log_info "Starting recursive monorepo scan of: $SCAN_DIR"

# Scan Node.js projects (package.json)
log_info "Searching for Node.js projects..."
TEMP_FILE=$(mktemp)
find "$SCAN_DIR" -name "package.json" -not -path "*/node_modules/*" -print > "$TEMP_FILE"
log_info "Found $(wc -l < "$TEMP_FILE") Node.js projects"
while IFS= read -r package_file; do
    if [ -n "$package_file" ]; then
        log_info "Processing: $package_file"
        project_dir=$(dirname "$package_file")
        scan_project "$project_dir" "nodejs" "$package_file"
        log_info "Completed processing: $package_file"
    fi
done < "$TEMP_FILE"
rm -f "$TEMP_FILE"

# Scan Python projects (requirements.txt)
log_info "Searching for Python projects..."
while IFS= read -r -d '' req_file; do
    project_dir=$(dirname "$req_file")
    scan_project "$project_dir" "python" "$req_file"
done < <(find "$SCAN_DIR" -name "requirements.txt" -not -path "*/venv/*" -not -path "*/.venv/*" -not -path "*/env/*" -print0)

# Scan Python projects (pyproject.toml)
log_info "Searching for Python Poetry projects..."
while IFS= read -r -d '' toml_file; do
    project_dir=$(dirname "$toml_file")
    scan_project "$project_dir" "python-poetry" "$toml_file"
done < <(find "$SCAN_DIR" -name "pyproject.toml" -not -path "*/venv/*" -not -path "*/.venv/*" -print0)

# Scan Go projects (go.mod)
log_info "Searching for Go projects..."
while IFS= read -r -d '' go_file; do
    project_dir=$(dirname "$go_file")
    scan_project "$project_dir" "go" "$go_file"
done < <(find "$SCAN_DIR" -name "go.mod" -not -path "*/vendor/*" -print0)

# Scan Java Maven projects (pom.xml)
log_info "Searching for Java Maven projects..."
while IFS= read -r -d '' pom_file; do
    project_dir=$(dirname "$pom_file")
    scan_project "$project_dir" "java-maven" "$pom_file"
done < <(find "$SCAN_DIR" -name "pom.xml" -not -path "*/target/*" -print0)

# Scan Java Gradle projects (build.gradle)
log_info "Searching for Java Gradle projects..."
while IFS= read -r -d '' gradle_file; do
    project_dir=$(dirname "$gradle_file")
    scan_project "$project_dir" "java-gradle" "$gradle_file"
done < <(find "$SCAN_DIR" -name "build.gradle" -o -name "build.gradle.kts" -not -path "*/build/*" -print0)

# Scan .NET projects (*.csproj)
log_info "Searching for .NET projects..."
while IFS= read -r -d '' csproj_file; do
    project_dir=$(dirname "$csproj_file")
    scan_project "$project_dir" "dotnet" "$csproj_file"
done < <(find "$SCAN_DIR" -name "*.csproj" -not -path "*/bin/*" -not -path "*/obj/*" -print0)

# Scan Ruby projects (Gemfile)
log_info "Searching for Ruby projects..."
while IFS= read -r -d '' gemfile; do
    project_dir=$(dirname "$gemfile")
    scan_project "$project_dir" "ruby" "$gemfile"
done < <(find "$SCAN_DIR" -name "Gemfile" -not -path "*/vendor/*" -print0)

# Scan PHP projects (composer.json)
log_info "Searching for PHP projects..."
while IFS= read -r -d '' composer_file; do
    project_dir=$(dirname "$composer_file")
    scan_project "$project_dir" "php" "$composer_file"
done < <(find "$SCAN_DIR" -name "composer.json" -not -path "*/vendor/*" -print0)

# Scan Rust projects (Cargo.toml)
log_info "Searching for Rust projects..."
while IFS= read -r -d '' cargo_file; do
    project_dir=$(dirname "$cargo_file")
    scan_project "$project_dir" "rust" "$cargo_file"
done < <(find "$SCAN_DIR" -name "Cargo.toml" -not -path "*/target/*" -print0)

# Close consolidated report
echo '  ],' >> "$OUTPUT_DIR/$CONSOLIDATE_REPORT"
echo '  "scan_summary": {' >> "$OUTPUT_DIR/$CONSOLIDATE_REPORT"
echo "    \"total_projects\": $TOTAL_PROJECTS," >> "$OUTPUT_DIR/$CONSOLIDATE_REPORT"
echo "    \"successful_scans\": $SUCCESSFUL_SCANS," >> "$OUTPUT_DIR/$CONSOLIDATE_REPORT"
echo "    \"failed_scans\": $FAILED_SCANS," >> "$OUTPUT_DIR/$CONSOLIDATE_REPORT"
if [ $TOTAL_PROJECTS -gt 0 ]; then
        echo "    \"success_rate\": \"$(( SUCCESSFUL_SCANS * 100 / TOTAL_PROJECTS ))%\"," >> "$OUTPUT_DIR/$CONSOLIDATE_REPORT"
    else
        echo '    "success_rate": "0%",' >> "$OUTPUT_DIR/$CONSOLIDATE_REPORT"
    fi
echo "    \"scan_completed_at\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"" >> "$OUTPUT_DIR/$CONSOLIDATE_REPORT"
echo '  }' >> "$OUTPUT_DIR/$CONSOLIDATE_REPORT"
echo '}' >> "$OUTPUT_DIR/$CONSOLIDATE_REPORT"

# Final summary
log_success "Recursive monorepo scan completed!"
log_info "Total projects found: $TOTAL_PROJECTS"
log_info "Successful scans: $SUCCESSFUL_SCANS"
log_info "Failed scans: $FAILED_SCANS"
if [ $TOTAL_PROJECTS -gt 0 ]; then
    log_info "Success rate: $(( SUCCESSFUL_SCANS * 100 / TOTAL_PROJECTS ))%"
else
    log_info "Success rate: 0%"
fi
log_info "Results saved in: $OUTPUT_DIR/"
log_info "Consolidated report: $OUTPUT_DIR/$CONSOLIDATE_REPORT"
log_info "Scan log: $LOG_FILE"

# List all generated files
log_info "Generated files:"
ls -la "$OUTPUT_DIR/" | tee -a "$LOG_FILE"

if [ $FAILED_SCANS -gt 0 ]; then
    log_warning "Some scans failed. Check individual scan files for details."
    exit 1
else
    log_success "All scans completed successfully!"
    exit 0
fi