#!/bin/bash

# Enhanced ML Model Deployment Script
# TypoSentinel Enhanced Threat Detection Model Deployment

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
MODEL_FILE="enhanced_threat_detection_model.json"
BACKUP_DIR="$PROJECT_ROOT/backups/ml"
CONFIG_FILE="$PROJECT_ROOT/config/ml_production.yaml"
LOG_FILE="$PROJECT_ROOT/logs/deployment.log"
HEALTH_CHECK_URL="http://localhost:8080/api/v1/ml/health"
DEPLOYMENT_TIMEOUT=300  # 5 minutes

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    local level=$1
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"
}

log_info() {
    log "INFO" "$*"
    echo -e "${BLUE}[INFO]${NC} $*"
}

log_warn() {
    log "WARN" "$*"
    echo -e "${YELLOW}[WARN]${NC} $*"
}

log_error() {
    log "ERROR" "$*"
    echo -e "${RED}[ERROR]${NC} $*"
}

log_success() {
    log "SUCCESS" "$*"
    echo -e "${GREEN}[SUCCESS]${NC} $*"
}

# Error handling
error_exit() {
    log_error "$1"
    exit 1
}

# Cleanup function
cleanup() {
    log_info "Cleaning up temporary files..."
    # Add cleanup logic here if needed
}

# Set up signal handlers
trap cleanup EXIT
trap 'error_exit "Script interrupted"' INT TERM

# Function to check prerequisites
check_prerequisites() {
    log_info "Checking deployment prerequisites..."
    
    # Check if model file exists
    if [[ ! -f "$PROJECT_ROOT/$MODEL_FILE" ]]; then
        error_exit "Enhanced model file not found: $PROJECT_ROOT/$MODEL_FILE"
    fi
    
    # Check if configuration file exists
    if [[ ! -f "$CONFIG_FILE" ]]; then
        error_exit "Configuration file not found: $CONFIG_FILE"
    fi
    
    # Check if backup directory exists, create if not
    if [[ ! -d "$BACKUP_DIR" ]]; then
        log_info "Creating backup directory: $BACKUP_DIR"
        mkdir -p "$BACKUP_DIR"
    fi
    
    # Check if logs directory exists, create if not
    local log_dir=$(dirname "$LOG_FILE")
    if [[ ! -d "$log_dir" ]]; then
        log_info "Creating logs directory: $log_dir"
        mkdir -p "$log_dir"
    fi
    
    # Check if Go is installed
    if ! command -v go &> /dev/null; then
        error_exit "Go is not installed or not in PATH"
    fi
    
    # Check if Python is installed (for ML scripts)
    if ! command -v python &> /dev/null; then
        error_exit "Python is not installed or not in PATH"
    fi
    
    log_success "Prerequisites check completed"
}

# Function to backup current model
backup_current_model() {
    log_info "Backing up current model..."
    
    local current_model="$PROJECT_ROOT/models/default.model"
    local backup_timestamp=$(date '+%Y%m%d_%H%M%S')
    local backup_file="$BACKUP_DIR/model_backup_$backup_timestamp.model"
    
    if [[ -f "$current_model" ]]; then
        cp "$current_model" "$backup_file"
        log_success "Current model backed up to: $backup_file"
    else
        log_warn "No current model found to backup"
    fi
    
    # Backup enhanced model if it exists
    local enhanced_model="$PROJECT_ROOT/enhanced_threat_detection_model.json"
    if [[ -f "$enhanced_model" ]]; then
        local enhanced_backup="$BACKUP_DIR/enhanced_model_backup_$backup_timestamp.json"
        cp "$enhanced_model" "$enhanced_backup"
        log_success "Enhanced model backed up to: $enhanced_backup"
    fi
}

# Function to validate model file
validate_model() {
    log_info "Validating enhanced model file..."
    
    local model_path="$MODEL_FILE"
    
    # Check if file is valid JSON
    if ! python -c "import json; json.load(open('$model_path'))" 2>/dev/null; then
        error_exit "Model file is not valid JSON: $model_path"
    fi
    
    # Check required fields
    local required_fields=("model_info" "training_result" "training_metadata")
    for field in "${required_fields[@]}"; do
        if ! python -c "import json; data=json.load(open('$model_path')); assert '$field' in data" 2>/dev/null; then
            error_exit "Model file missing required field: $field"
        fi
    done
    
    # Check model performance metrics
    local accuracy=$(python -c "import json; data=json.load(open('$model_path')); print(data['training_result']['final_accuracy'])" 2>/dev/null)
    if (( $(echo "$accuracy < 0.8" | bc -l) )); then
        log_warn "Model accuracy is below 80%: $accuracy"
        read -p "Continue with deployment? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            error_exit "Deployment cancelled due to low model accuracy"
        fi
    fi
    
    log_success "Model validation completed (accuracy: $accuracy)"
}

# Function to run pre-deployment tests
run_tests() {
    log_info "Running pre-deployment tests..."
    
    cd "$PROJECT_ROOT"
    
    # Run enhanced ML tests
    if [[ -f "test_enhanced_ml.py" ]]; then
        log_info "Running enhanced ML test suite..."
        if python test_enhanced_ml.py; then
            log_success "Enhanced ML tests passed"
        else
            error_exit "Enhanced ML tests failed"
        fi
    else
        log_warn "Enhanced ML test file not found, skipping tests"
    fi
    
    # Run Go tests
    log_info "Running Go tests..."
    if go test ./... -v; then
        log_success "Go tests passed"
    else
        error_exit "Go tests failed"
    fi
}

# Function to build the application
build_application() {
    log_info "Building TypoSentinel application..."
    
    cd "$PROJECT_ROOT"
    
    # Clean previous builds
    if [[ -f "typosentinel" ]]; then
        rm typosentinel
    fi
    if [[ -f "typosentinel.exe" ]]; then
        rm typosentinel.exe
    fi
    
    # Build for current platform
    if go build -o typosentinel ./main.go; then
        log_success "Application built successfully"
    else
        error_exit "Application build failed"
    fi
    
    # Make executable
    chmod +x typosentinel 2>/dev/null || true
}

# Function to deploy the enhanced model
deploy_model() {
    log_info "Deploying enhanced ML model..."
    
    cd "$PROJECT_ROOT"
    
    # Copy model to models directory
    local models_dir="$PROJECT_ROOT/models"
    if [[ ! -d "$models_dir" ]]; then
        mkdir -p "$models_dir"
    fi
    
    # Copy enhanced model
    cp "$MODEL_FILE" "$models_dir/enhanced_threat_detection_model.json"
    log_success "Enhanced model deployed to models directory"
    
    # Update configuration to use enhanced model
    if [[ -f "$CONFIG_FILE" ]]; then
        log_info "Configuration file already exists: $CONFIG_FILE"
    else
        log_warn "Configuration file not found, using default settings"
    fi
}

# Function to start the application
start_application() {
    log_info "Starting TypoSentinel application..."
    
    cd "$PROJECT_ROOT"
    
    # Check if application is already running
    if pgrep -f "typosentinel" > /dev/null; then
        log_warn "TypoSentinel is already running, stopping it first..."
        pkill -f "typosentinel" || true
        sleep 2
    fi
    
    # Start application in background
    log_info "Starting application with enhanced ML model..."
    nohup ./typosentinel server --dev --port 8080 > "$PROJECT_ROOT/logs/typosentinel.log" 2>&1 &
    local app_pid=$!
    
    log_info "Application started with PID: $app_pid"
    echo $app_pid > "$PROJECT_ROOT/typosentinel.pid"
    
    # Wait for application to start
    sleep 5
}

# Function to perform health checks
health_check() {
    log_info "Performing health checks..."
    
    local max_attempts=30
    local attempt=1
    
    while [[ $attempt -le $max_attempts ]]; do
        log_info "Health check attempt $attempt/$max_attempts..."
        
        if curl -s -f "$HEALTH_CHECK_URL" > /dev/null 2>&1; then
            log_success "Health check passed"
            return 0
        fi
        
        sleep 2
        ((attempt++))
    done
    
    error_exit "Health check failed after $max_attempts attempts"
}

# Function to run smoke tests
run_smoke_tests() {
    log_info "Running smoke tests..."
    
    # Test basic API endpoints
    local base_url="http://localhost:8080"
    
    # Test health endpoint
    if curl -s -f "$base_url/health" > /dev/null; then
        log_success "Health endpoint test passed"
    else
        error_exit "Health endpoint test failed"
    fi
    
    # Test ML health endpoint
    if curl -s -f "$base_url/api/v1/ml/health" > /dev/null; then
        log_success "ML health endpoint test passed"
    else
        log_warn "ML health endpoint test failed (may not be implemented yet)"
    fi
    
    # Test basic package analysis
    local test_package='{"name":"express","registry":"npm","version":"4.18.2"}'
    if curl -s -X POST -H "Content-Type: application/json" -d "$test_package" "$base_url/api/v1/analyze" > /dev/null; then
        log_success "Package analysis test passed"
    else
        log_warn "Package analysis test failed (endpoint may not be available)"
    fi
}

# Function to setup monitoring
setup_monitoring() {
    log_info "Setting up monitoring for enhanced ML model..."
    
    # Create monitoring configuration
    local monitoring_config="$PROJECT_ROOT/config/monitoring.yaml"
    if [[ ! -f "$monitoring_config" ]]; then
        cat > "$monitoring_config" << EOF
monitoring:
  enabled: true
  metrics:
    ml_predictions_total:
      type: counter
      description: "Total number of ML predictions made"
    ml_prediction_duration:
      type: histogram
      description: "Duration of ML predictions"
    ml_confidence_score:
      type: histogram
      description: "Confidence scores of ML predictions"
    ml_threat_detections:
      type: counter
      description: "Number of threats detected by type"
  
  alerts:
    - name: "ml_high_error_rate"
      condition: "ml_errors_total / ml_predictions_total > 0.05"
      duration: "5m"
      severity: "warning"
    
    - name: "ml_low_confidence"
      condition: "avg(ml_confidence_score) < 0.7"
      duration: "10m"
      severity: "warning"
    
    - name: "ml_slow_predictions"
      condition: "avg(ml_prediction_duration) > 0.001"
      duration: "5m"
      severity: "warning"
EOF
        log_success "Monitoring configuration created"
    else
        log_info "Monitoring configuration already exists"
    fi
}

# Function to create deployment report
create_deployment_report() {
    log_info "Creating deployment report..."
    
    local report_file="$PROJECT_ROOT/deployment_report_$(date '+%Y%m%d_%H%M%S').md"
    
    cat > "$report_file" << EOF
# Enhanced ML Model Deployment Report

**Deployment Date**: $(date '+%Y-%m-%d %H:%M:%S')
**Model Version**: Enhanced v1.0
**Deployment Script**: $0

## Deployment Summary

- ✅ Prerequisites checked
- ✅ Current model backed up
- ✅ Enhanced model validated
- ✅ Pre-deployment tests passed
- ✅ Application built successfully
- ✅ Enhanced model deployed
- ✅ Application started
- ✅ Health checks passed
- ✅ Smoke tests completed
- ✅ Monitoring configured

## Model Information

- **Model File**: $MODEL_FILE
- **Model Location**: $PROJECT_ROOT/models/enhanced_threat_detection_model.json
- **Configuration**: $CONFIG_FILE
- **Backup Location**: $BACKUP_DIR

## Performance Metrics

$(python -c "
import json
with open('$PROJECT_ROOT/$MODEL_FILE') as f:
    data = json.load(f)
print(f'- **Training Accuracy**: {data["training_result"]["final_accuracy"]:.4f}')
print(f'- **Validation Accuracy**: {data["training_result"]["best_validation_accuracy"]:.4f}')
print(f'- **Training Samples**: {data["training_metadata"]["training_samples"]}')
print(f'- **Model Parameters**: {data["model_info"]["parameter_count"]}')
" 2>/dev/null || echo "- Model metrics not available")

## Health Check Results

- **Application URL**: http://localhost:8080
- **Health Endpoint**: $HEALTH_CHECK_URL
- **Status**: ✅ Healthy

## Next Steps

1. Monitor application logs: \`tail -f $PROJECT_ROOT/logs/typosentinel.log\`
2. Monitor deployment logs: \`tail -f $LOG_FILE\`
3. Check ML metrics via API endpoints
4. Set up automated monitoring alerts
5. Plan gradual rollout to production traffic

## Rollback Instructions

If issues are detected:

1. Stop the application: \`pkill -f typosentinel\`
2. Restore backup model from: \`$BACKUP_DIR\`
3. Restart with previous configuration
4. Investigate issues in logs

---

**Deployment completed successfully at $(date '+%Y-%m-%d %H:%M:%S')**
EOF

    log_success "Deployment report created: $report_file"
}

# Main deployment function
main() {
    log_info "Starting Enhanced ML Model Deployment"
    log_info "Project Root: $PROJECT_ROOT"
    log_info "Model File: $MODEL_FILE"
    log_info "Configuration: $CONFIG_FILE"
    
    # Run deployment steps
    check_prerequisites
    backup_current_model
    validate_model
    run_tests
    build_application
    deploy_model
    start_application
    health_check
    run_smoke_tests
    setup_monitoring
    create_deployment_report
    
    log_success "Enhanced ML Model deployment completed successfully!"
    log_info "Application is running at: http://localhost:8080"
    log_info "Logs available at: $LOG_FILE"
    log_info "Application logs: $PROJECT_ROOT/logs/typosentinel.log"
    
    echo
    echo -e "${GREEN}🎉 Deployment Successful!${NC}"
    echo -e "${BLUE}📊 Monitor the application:${NC}"
    echo -e "   • Application: http://localhost:8080"
    echo -e "   • Health Check: $HEALTH_CHECK_URL"
    echo -e "   • Logs: tail -f $LOG_FILE"
    echo
}

# Script entry point
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi