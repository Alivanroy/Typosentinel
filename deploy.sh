#!/bin/bash

# PlanFinale Deployment Script
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if Docker is running
check_docker() {
    if ! docker info > /dev/null 2>&1; then
        print_error "Docker is not running. Please start Docker and try again."
        exit 1
    fi
    print_success "Docker is running"
}

# Function to check if docker-compose is available
check_docker_compose() {
    if ! command -v docker-compose > /dev/null 2>&1; then
        print_error "docker-compose is not installed. Please install docker-compose and try again."
        exit 1
    fi
    print_success "docker-compose is available"
}

# Function to create environment file if it doesn't exist
create_env_file() {
    if [ ! -f .env ]; then
        print_status "Creating .env file with default values..."
        cat > .env << EOF
# PlanFinale Environment Configuration
PLANFINALE_JWT_SECRET=$(openssl rand -base64 32)
GRAFANA_PASSWORD=admin123
ENV=production
PLANFINALE_LOG_LEVEL=info
PLANFINALE_CORS_ENABLED=true
PLANFINALE_CORS_ORIGINS=http://localhost:3000
EOF
        print_success "Created .env file with secure defaults"
        print_warning "Please review and update the .env file with your specific configuration"
    else
        print_success ".env file already exists"
    fi
}

# Function to build and start services
deploy_production() {
    print_status "Building and starting PlanFinale in production mode..."
    
    # Build images
    print_status "Building Docker images..."
    docker-compose build --no-cache
    
    # Start services
    print_status "Starting services..."
    docker-compose up -d
    
    # Wait for services to be healthy
    print_status "Waiting for services to be healthy..."
    sleep 10
    
    # Check health
    if docker-compose ps | grep -q "Up (healthy)"; then
        print_success "PlanFinale deployed successfully!"
        echo ""
        echo "🚀 PlanFinale is now running:"
        echo "   Web Interface: http://localhost:3000"
        echo "   API Server:    http://localhost:8080"
        echo "   Health Check:  http://localhost:8080/health"
        echo ""
        echo "📊 Optional monitoring (use --with-monitoring flag):"
        echo "   Prometheus:    http://localhost:9090"
        echo "   Grafana:       http://localhost:3001"
        echo ""
    else
        print_error "Some services failed to start properly"
        docker-compose logs
        exit 1
    fi
}

# Function to deploy with monitoring
deploy_with_monitoring() {
    print_status "Building and starting PlanFinale with monitoring..."
    
    # Build images
    print_status "Building Docker images..."
    docker-compose build --no-cache
    
    # Start services with monitoring profile
    print_status "Starting services with monitoring..."
    docker-compose --profile monitoring up -d
    
    # Wait for services to be healthy
    print_status "Waiting for services to be healthy..."
    sleep 15
    
    print_success "PlanFinale with monitoring deployed successfully!"
    echo ""
    echo "🚀 PlanFinale is now running:"
    echo "   Web Interface: http://localhost:3000"
    echo "   API Server:    http://localhost:8080"
    echo "   Health Check:  http://localhost:8080/health"
    echo ""
    echo "📊 Monitoring services:"
    echo "   Prometheus:    http://localhost:9090"
    echo "   Grafana:       http://localhost:3001 (admin/admin123)"
    echo "   Node Exporter: http://localhost:9100"
    echo ""
}

# Function to deploy in development mode
deploy_development() {
    print_status "Starting PlanFinale in development mode..."
    
    # Use development compose file
    docker-compose -f docker-compose.yml -f docker-compose.dev.yml up -d --build
    
    print_success "PlanFinale development environment started!"
    echo ""
    echo "🚀 PlanFinale Development is now running:"
    echo "   Web Interface: http://localhost:3001 (with hot reload)"
    echo "   API Server:    http://localhost:8080 (with debug logging)"
    echo ""
}

# Function to stop services
stop_services() {
    print_status "Stopping PlanFinale services..."
    docker-compose down
    print_success "Services stopped"
}

# Function to show logs
show_logs() {
    docker-compose logs -f
}

# Function to show status
show_status() {
    print_status "PlanFinale Service Status:"
    docker-compose ps
}

# Main script logic
case "${1:-}" in
    "start"|"deploy")
        check_docker
        check_docker_compose
        create_env_file
        deploy_production
        ;;
    "start-dev"|"dev")
        check_docker
        check_docker_compose
        deploy_development
        ;;
    "start-monitoring"|"monitoring")
        check_docker
        check_docker_compose
        create_env_file
        deploy_with_monitoring
        ;;
    "stop")
        stop_services
        ;;
    "logs")
        show_logs
        ;;
    "status")
        show_status
        ;;
    "restart")
        stop_services
        sleep 2
        deploy_production
        ;;
    "help"|"-h"|"--help")
        echo "PlanFinale Deployment Script"
        echo ""
        echo "Usage: $0 [COMMAND]"
        echo ""
        echo "Commands:"
        echo "  start, deploy          Deploy PlanFinale in production mode"
        echo "  start-dev, dev         Deploy PlanFinale in development mode"
        echo "  start-monitoring       Deploy PlanFinale with monitoring stack"
        echo "  stop                   Stop all services"
        echo "  restart                Restart all services"
        echo "  logs                   Show service logs"
        echo "  status                 Show service status"
        echo "  help                   Show this help message"
        echo ""
        ;;
    *)
        print_error "Unknown command: ${1:-}"
        echo "Use '$0 help' for usage information"
        exit 1
        ;;
esac