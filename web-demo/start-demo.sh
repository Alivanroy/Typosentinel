#!/bin/bash

# TypoSentinel Web Demo Startup Script
# This script initializes and starts the complete demo environment

set -e

echo "🚀 Starting TypoSentinel Web Demo..."

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

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    print_error "Docker is not running. Please start Docker and try again."
    exit 1
fi

print_success "Docker is running"

# Check if Docker Compose is available
if ! command -v docker-compose &> /dev/null; then
    print_error "Docker Compose is not installed. Please install Docker Compose and try again."
    exit 1
fi

print_success "Docker Compose is available"

# Navigate to the web-demo directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR"

print_status "Working directory: $(pwd)"

# Create necessary directories
print_status "Creating necessary directories..."
mkdir -p nginx/ssl
mkdir -p monitoring/prometheus/data
mkdir -p monitoring/grafana/data
mkdir -p postgres/data
mkdir -p redis/data
mkdir -p certbot/www
mkdir -p certbot/conf

# Set proper permissions
print_status "Setting permissions..."
chmod +x ssl/generate-self-signed.sh

# Generate self-signed SSL certificates for development
print_status "Generating self-signed SSL certificates..."
if [ ! -f "nginx/ssl/nginx-selfsigned.crt" ]; then
    # Create SSL directory in nginx
    mkdir -p nginx/ssl
    
    # Generate private key
    openssl genrsa -out nginx/ssl/nginx-selfsigned.key 4096
    
    # Generate certificate signing request and certificate
    openssl req -new -x509 -key nginx/ssl/nginx-selfsigned.key \
        -out nginx/ssl/nginx-selfsigned.crt \
        -days 365 \
        -subj "/C=US/ST=CA/L=San Francisco/O=TypoSentinel/OU=Demo/CN=localhost"
    
    # Generate DH parameters
    openssl dhparam -out nginx/ssl/dhparam.pem 2048
    
    print_success "SSL certificates generated"
else
    print_status "SSL certificates already exist"
fi

# Build the TypoSentinel API image
print_status "Building TypoSentinel API image..."
cd api
if [ -f "go.sum" ]; then
    rm go.sum
fi
go mod tidy
cd ..

# Stop any existing containers
print_status "Stopping existing containers..."
docker-compose down --remove-orphans

# Pull latest images
print_status "Pulling latest Docker images..."
docker-compose pull

# Build custom images
print_status "Building custom images..."
docker-compose build

# Start the services
print_status "Starting services..."
docker-compose up -d

# Wait for services to be ready
print_status "Waiting for services to start..."
sleep 10

# Check service health
print_status "Checking service health..."

# Function to check if a service is healthy
check_service() {
    local service_name=$1
    local url=$2
    local max_attempts=30
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        if curl -f -s "$url" > /dev/null 2>&1; then
            print_success "$service_name is healthy"
            return 0
        fi
        
        if [ $attempt -eq $max_attempts ]; then
            print_warning "$service_name health check failed after $max_attempts attempts"
            return 1
        fi
        
        sleep 2
        ((attempt++))
    done
}

# Check individual services
check_service "Nginx" "http://localhost:80"
check_service "TypoSentinel API" "http://localhost:80/api/health"
check_service "Prometheus" "http://localhost:9090/-/healthy"
check_service "Grafana" "http://localhost:3000/api/health"

# Display service URLs
echo ""
print_success "🎉 TypoSentinel Web Demo is ready!"
echo ""
echo "📊 Service URLs:"
echo "   • Web Interface:    http://localhost (or https://localhost)"
echo "   • API Endpoint:     http://localhost/api"
echo "   • Grafana:          http://localhost:3000 (admin/admin)"
echo "   • Prometheus:       http://localhost:9090"
echo "   • API Health:       http://localhost/api/health"
echo ""
echo "🔧 Management Commands:"
echo "   • View logs:        docker-compose logs -f"
echo "   • Stop services:    docker-compose down"
echo "   • Restart:          docker-compose restart"
echo "   • View status:      docker-compose ps"
echo ""
echo "📋 Test the API:"
echo "   curl -X POST http://localhost/api/scan \\"
echo "     -H 'Content-Type: application/json' \\"
echo "     -d '{\"package\": \"lodash\", \"version\": \"latest\"}'"
echo ""
echo "📖 For detailed testing instructions, see: TESTING.md"
echo ""

# Show running containers
print_status "Running containers:"
docker-compose ps

print_success "Demo startup completed successfully! 🚀"