#!/bin/bash

# TypoSentinel Deployment Script
# This script helps deploy TypoSentinel in various environments

set -e

# Configuration
APP_NAME="typosentinel"
VERSION=${VERSION:-"1.0.0"}
ENVIRONMENT=${ENVIRONMENT:-"development"}
CONFIG_FILE=${CONFIG_FILE:-"config.yaml"}
DOCKER_COMPOSE_FILE=${DOCKER_COMPOSE_FILE:-"docker-compose.yml"}

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Functions
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

# Check dependencies
check_dependencies() {
    log_info "Checking dependencies for ${ENVIRONMENT} deployment..."
    
    case $ENVIRONMENT in
        "docker"|"production")
            if ! command -v docker &> /dev/null; then
                log_error "Docker is required for ${ENVIRONMENT} deployment"
                exit 1
            fi
            
            if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
                log_error "Docker Compose is required for ${ENVIRONMENT} deployment"
                exit 1
            fi
            ;;
        "development"|"local")
            if ! command -v go &> /dev/null; then
                log_error "Go is required for ${ENVIRONMENT} deployment"
                exit 1
            fi
            
            if ! command -v python3 &> /dev/null; then
                log_error "Python3 is required for ML components"
                exit 1
            fi
            
            if ! command -v psql &> /dev/null; then
                log_warning "PostgreSQL client not found. Database setup may require manual intervention."
            fi
            ;;
    esac
    
    log_success "Dependencies check completed"
}

# Setup environment variables
setup_env() {
    log_info "Setting up environment variables..."
    
    # Create .env file if it doesn't exist
    if [[ ! -f ".env" ]]; then
        cat > .env << EOF
# TypoSentinel Environment Configuration

# Database
DB_PASSWORD=typosentinel123
DB_HOST=localhost
DB_PORT=5432
DB_NAME=typosentinel
DB_USER=postgres

# ML Service
ML_API_KEY=ml-service-key-123
ML_WORKERS=4

# API
DEBUG_MODE=false
LOG_LEVEL=INFO

# Monitoring (optional)
GRAFANA_USER=admin
GRAFANA_PASSWORD=admin123

# Security
API_SECRET_KEY=$(openssl rand -hex 32 2>/dev/null || echo "change-this-secret-key")
JWT_SECRET=$(openssl rand -hex 32 2>/dev/null || echo "change-this-jwt-secret")
EOF
        log_success "Created .env file with default values"
        log_warning "Please review and update the .env file with your specific configuration"
    else
        log_info "Using existing .env file"
    fi
}

# Setup configuration
setup_config() {
    log_info "Setting up configuration..."
    
    if [[ ! -f "$CONFIG_FILE" ]]; then
        log_info "Creating default configuration file..."
        
        # Build the application first to generate config
        if [[ -f "./bin/typosentinel" ]]; then
            ./bin/typosentinel config init --config "$CONFIG_FILE"
        else
            log_warning "Binary not found. Please run build script first or use Docker deployment."
            # Create a basic config file
            mkdir -p config
            cat > "$CONFIG_FILE" << EOF
api:
  host: "0.0.0.0"
  port: 8080
  debug_mode: false
  read_timeout_seconds: 30
  write_timeout_seconds: 30
  idle_timeout_seconds: 60

database:
  host: "localhost"
  port: 5432
  name: "typosentinel"
  user: "postgres"
  password: "typosentinel123"
  ssl_mode: "disable"
  max_connections: 25
  max_idle_connections: 5
  connection_max_lifetime_minutes: 30

ml_service:
  base_url: "http://localhost:8000"
  api_key: "ml-service-key-123"
  timeout_seconds: 30
  max_retries: 3

detection:
  similarity_threshold: 0.8
  homoglyph_threshold: 0.9
  reputation_threshold: 0.7
  max_suggestions: 10
  enable_ml_detection: true
  enable_reputation_check: true

registries:
  npm:
    base_url: "https://registry.npmjs.org"
    rate_limit_per_minute: 60
    timeout_seconds: 10
  pypi:
    base_url: "https://pypi.org"
    rate_limit_per_minute: 60
    timeout_seconds: 10
  go:
    base_url: "https://proxy.golang.org"
    rate_limit_per_minute: 60
    timeout_seconds: 10
EOF
        fi
        
        log_success "Configuration file created: $CONFIG_FILE"
    else
        log_info "Using existing configuration file: $CONFIG_FILE"
    fi
}

# Setup database
setup_database() {
    log_info "Setting up database..."
    
    case $ENVIRONMENT in
        "docker"|"production")
            log_info "Database will be set up via Docker Compose"
            ;;
        "development"|"local")
            # Check if PostgreSQL is running
            if command -v pg_isready &> /dev/null; then
                if pg_isready -h localhost -p 5432 &> /dev/null; then
                    log_info "PostgreSQL is running"
                    
                    # Create database if it doesn't exist
                    if ! psql -h localhost -U postgres -lqt | cut -d \| -f 1 | grep -qw typosentinel; then
                        log_info "Creating database..."
                        createdb -h localhost -U postgres typosentinel || log_warning "Failed to create database. Please create it manually."
                    fi
                else
                    log_warning "PostgreSQL is not running. Please start PostgreSQL service."
                fi
            else
                log_warning "PostgreSQL client not found. Please install PostgreSQL."
            fi
            ;;
    esac
}

# Deploy with Docker
deploy_docker() {
    log_info "Deploying with Docker Compose..."
    
    # Build images
    log_info "Building Docker images..."
    if command -v docker-compose &> /dev/null; then
        docker-compose -f "$DOCKER_COMPOSE_FILE" build
    else
        docker compose -f "$DOCKER_COMPOSE_FILE" build
    fi
    
    # Start services
    log_info "Starting services..."
    if command -v docker-compose &> /dev/null; then
        docker-compose -f "$DOCKER_COMPOSE_FILE" up -d
    else
        docker compose -f "$DOCKER_COMPOSE_FILE" up -d
    fi
    
    # Wait for services to be ready
    log_info "Waiting for services to be ready..."
    sleep 30
    
    # Check service health
    check_services_docker
    
    log_success "Docker deployment completed"
}

# Deploy locally
deploy_local() {
    log_info "Deploying locally..."
    
    # Build application if needed
    if [[ ! -f "./bin/typosentinel" ]] || [[ ! -f "./bin/typosentinel-server" ]]; then
        log_info "Building application..."
        ./scripts/build.sh current
    fi
    
    # Install Python dependencies
    log_info "Installing Python dependencies..."
    cd ml
    python3 -m pip install -r requirements.txt
    cd ..
    
    # Run database migrations
    log_info "Running database migrations..."
    ./bin/typosentinel-server config validate --config "$CONFIG_FILE" || log_warning "Configuration validation failed"
    
    log_success "Local deployment prepared"
    log_info "To start the services:"
    log_info "  1. Start ML service: cd ml/service && python api_server.py --host 0.0.0.0 --port 8000"
    log_info "  2. Start API server: ./bin/typosentinel-server --config $CONFIG_FILE"
}

# Check service health
check_services_docker() {
    log_info "Checking service health..."
    
    local max_attempts=30
    local attempt=1
    
    while [[ $attempt -le $max_attempts ]]; do
        log_info "Health check attempt $attempt/$max_attempts"
        
        # Check API health
        if curl -f http://localhost:8080/health &> /dev/null; then
            log_success "API service is healthy"
            break
        fi
        
        if [[ $attempt -eq $max_attempts ]]; then
            log_error "Services failed to start properly"
            show_logs
            exit 1
        fi
        
        sleep 10
        ((attempt++))
    done
}

# Show service logs
show_logs() {
    log_info "Showing service logs..."
    
    if command -v docker-compose &> /dev/null; then
        docker-compose -f "$DOCKER_COMPOSE_FILE" logs --tail=50
    else
        docker compose -f "$DOCKER_COMPOSE_FILE" logs --tail=50
    fi
}

# Stop services
stop_services() {
    log_info "Stopping services..."
    
    case $ENVIRONMENT in
        "docker"|"production")
            if command -v docker-compose &> /dev/null; then
                docker-compose -f "$DOCKER_COMPOSE_FILE" down
            else
                docker compose -f "$DOCKER_COMPOSE_FILE" down
            fi
            ;;
        "development"|"local")
            log_info "Please manually stop the running services"
            ;;
    esac
    
    log_success "Services stopped"
}

# Clean up
cleanup() {
    log_info "Cleaning up..."
    
    case $ENVIRONMENT in
        "docker"|"production")
            if command -v docker-compose &> /dev/null; then
                docker-compose -f "$DOCKER_COMPOSE_FILE" down -v --remove-orphans
            else
                docker compose -f "$DOCKER_COMPOSE_FILE" down -v --remove-orphans
            fi
            
            # Remove images
            docker image prune -f
            ;;
        "development"|"local")
            rm -rf ./bin
            rm -f "$CONFIG_FILE"
            ;;
    esac
    
    log_success "Cleanup completed"
}

# Show status
show_status() {
    log_info "Service Status:"
    
    case $ENVIRONMENT in
        "docker"|"production")
            if command -v docker-compose &> /dev/null; then
                docker-compose -f "$DOCKER_COMPOSE_FILE" ps
            else
                docker compose -f "$DOCKER_COMPOSE_FILE" ps
            fi
            ;;
        "development"|"local")
            echo "  Local deployment - check processes manually"
            ;;
    esac
    
    # Check API endpoint
    if curl -f http://localhost:8080/health &> /dev/null; then
        log_success "API service is accessible at http://localhost:8080"
    else
        log_warning "API service is not accessible"
    fi
    
    # Check ML service
    if curl -f http://localhost:8000/health &> /dev/null; then
        log_success "ML service is accessible at http://localhost:8000"
    else
        log_warning "ML service is not accessible"
    fi
}

# Show usage
show_usage() {
    echo "Usage: $0 [OPTIONS] [COMMAND]"
    echo ""
    echo "Commands:"
    echo "  deploy    Deploy the application (default)"
    echo "  stop      Stop running services"
    echo "  status    Show service status"
    echo "  logs      Show service logs"
    echo "  cleanup   Clean up deployment"
    echo "  setup     Setup environment only"
    echo ""
    echo "Options:"
    echo "  -e, --env ENV        Set environment (development|docker|production)"
    echo "  -c, --config FILE    Set configuration file"
    echo "  -f, --file FILE      Set docker-compose file"
    echo "  -h, --help           Show this help message"
    echo ""
    echo "Environment Variables:"
    echo "  ENVIRONMENT          Set deployment environment"
    echo "  CONFIG_FILE          Set configuration file path"
    echo "  DOCKER_COMPOSE_FILE  Set docker-compose file path"
    echo ""
    echo "Examples:"
    echo "  $0 deploy --env docker"
    echo "  $0 deploy --env development"
    echo "  $0 status"
    echo "  $0 logs"
}

# Main execution
main() {
    local command="deploy"
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_usage
                exit 0
                ;;
            -e|--env)
                ENVIRONMENT="$2"
                shift 2
                ;;
            -c|--config)
                CONFIG_FILE="$2"
                shift 2
                ;;
            -f|--file)
                DOCKER_COMPOSE_FILE="$2"
                shift 2
                ;;
            deploy|stop|status|logs|cleanup|setup)
                command="$1"
                shift
                ;;
            *)
                log_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    log_info "TypoSentinel Deployment Script"
    log_info "Environment: $ENVIRONMENT"
    log_info "Command: $command"
    
    # Execute command
    case $command in
        setup)
            check_dependencies
            setup_env
            setup_config
            setup_database
            ;;
        deploy)
            check_dependencies
            setup_env
            setup_config
            setup_database
            
            case $ENVIRONMENT in
                "docker"|"production")
                    deploy_docker
                    ;;
                "development"|"local")
                    deploy_local
                    ;;
                *)
                    log_error "Unknown environment: $ENVIRONMENT"
                    exit 1
                    ;;
            esac
            ;;
        stop)
            stop_services
            ;;
        status)
            show_status
            ;;
        logs)
            show_logs
            ;;
        cleanup)
            cleanup
            ;;
        *)
            log_error "Unknown command: $command"
            show_usage
            exit 1
            ;;
    esac
    
    log_success "Deployment script completed successfully!"
}

# Run main function
main "$@"