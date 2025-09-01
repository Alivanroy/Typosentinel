#!/bin/bash

# Typosentinel Enterprise - Production Validation Script
# This script validates the production environment setup

set -e

echo "🔍 Typosentinel Enterprise - Production Validation"
echo "================================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Validation functions
validate_file() {
    if [ -f "$1" ]; then
        echo -e "${GREEN}✓${NC} $1 exists"
        return 0
    else
        echo -e "${RED}✗${NC} $1 missing"
        return 1
    fi
}

validate_directory() {
    if [ -d "$1" ]; then
        echo -e "${GREEN}✓${NC} $1/ directory exists"
        return 0
    else
        echo -e "${RED}✗${NC} $1/ directory missing"
        return 1
    fi
}

validate_executable() {
    if [ -x "$1" ]; then
        echo -e "${GREEN}✓${NC} $1 is executable"
        return 0
    else
        echo -e "${YELLOW}!${NC} $1 is not executable (fixing...)"
        chmod +x "$1"
        return 0
    fi
}

validate_docker_compose() {
    echo -e "${BLUE}Validating Docker Compose configuration...${NC}"
    if docker-compose -f docker-compose.production.yml config > /dev/null 2>&1; then
        echo -e "${GREEN}✓${NC} Docker Compose configuration is valid"
        return 0
    else
        echo -e "${RED}✗${NC} Docker Compose configuration has errors"
        return 1
    fi
}

validate_environment() {
    echo -e "${BLUE}Validating environment configuration...${NC}"
    
    if [ ! -f ".env" ]; then
        if [ -f ".env.production" ]; then
            echo -e "${YELLOW}!${NC} Copying .env.production to .env"
            cp .env.production .env
        else
            echo -e "${RED}✗${NC} No environment file found"
            return 1
        fi
    fi
    
    # Check for required environment variables
    local required_vars=("NODE_ENV" "GO_ENV" "SECURITY_LEVEL" "SSL_ENABLED")
    local missing_vars=()
    
    for var in "${required_vars[@]}"; do
        if ! grep -q "^${var}=" .env; then
            missing_vars+=("$var")
        fi
    done
    
    if [ ${#missing_vars[@]} -eq 0 ]; then
        echo -e "${GREEN}✓${NC} All required environment variables are present"
        return 0
    else
        echo -e "${RED}✗${NC} Missing environment variables: ${missing_vars[*]}"
        return 1
    fi
}

validate_ssl_setup() {
    echo -e "${BLUE}Validating SSL certificate setup...${NC}"
    
    if [ ! -d "certificates" ]; then
        echo -e "${YELLOW}!${NC} Creating certificates directory"
        mkdir -p certificates
    fi
    
    if [ -f "certificates/server.crt" ] && [ -f "certificates/server.key" ]; then
        echo -e "${GREEN}✓${NC} SSL certificates are present"
        
        # Check certificate validity
        if openssl x509 -in certificates/server.crt -noout -checkend 86400 > /dev/null 2>&1; then
            echo -e "${GREEN}✓${NC} SSL certificate is valid"
        else
            echo -e "${YELLOW}!${NC} SSL certificate is expired or invalid"
        fi
        return 0
    else
        echo -e "${YELLOW}!${NC} SSL certificates not found - generating self-signed certificates for testing"
        openssl req -x509 -newkey rsa:4096 -keyout certificates/server.key \
            -out certificates/server.crt -days 365 -nodes \
            -subj "/C=US/ST=State/L=City/O=Typosentinel/CN=localhost" > /dev/null 2>&1
        echo -e "${GREEN}✓${NC} Self-signed certificates generated"
        return 0
    fi
}

validate_directories() {
    echo -e "${BLUE}Validating directory structure...${NC}"
    
    local required_dirs=("logs" "data" "backups" "certificates")
    
    for dir in "${required_dirs[@]}"; do
        if [ ! -d "$dir" ]; then
            echo -e "${YELLOW}!${NC} Creating $dir directory"
            mkdir -p "$dir"
        fi
        validate_directory "$dir"
    done
}

validate_dependencies() {
    echo -e "${BLUE}Validating system dependencies...${NC}"
    
    # Check Docker
    if command -v docker > /dev/null 2>&1; then
        echo -e "${GREEN}✓${NC} Docker is installed"
        
        # Check if Docker is running
        if docker info > /dev/null 2>&1; then
            echo -e "${GREEN}✓${NC} Docker is running"
        else
            echo -e "${RED}✗${NC} Docker is not running"
            return 1
        fi
    else
        echo -e "${RED}✗${NC} Docker is not installed"
        return 1
    fi
    
    # Check Docker Compose
    if command -v docker-compose > /dev/null 2>&1; then
        echo -e "${GREEN}✓${NC} Docker Compose is installed"
    else
        echo -e "${RED}✗${NC} Docker Compose is not installed"
        return 1
    fi
    
    return 0
}

validate_ports() {
    echo -e "${BLUE}Validating port availability...${NC}"
    
    local ports=("3000" "8080" "5432" "6379" "9090" "3010")
    local occupied_ports=()
    
    for port in "${ports[@]}"; do
        if netstat -tuln 2>/dev/null | grep -q ":$port " || ss -tuln 2>/dev/null | grep -q ":$port "; then
            occupied_ports+=("$port")
        fi
    done
    
    if [ ${#occupied_ports[@]} -eq 0 ]; then
        echo -e "${GREEN}✓${NC} All required ports are available"
        return 0
    else
        echo -e "${YELLOW}!${NC} Some ports are occupied: ${occupied_ports[*]}"
        echo -e "${YELLOW}!${NC} This may cause conflicts during deployment"
        return 0
    fi
}

# Main validation
echo -e "${BLUE}Starting production environment validation...${NC}"
echo ""

# Track validation results
validation_errors=0

# Core files validation
echo -e "${BLUE}1. Validating core files...${NC}"
validate_file "docker-compose.production.yml" || ((validation_errors++))
validate_file "Dockerfile.production" || ((validation_errors++))
validate_file "deploy-production.sh" || ((validation_errors++))
validate_file ".env.production" || ((validation_errors++))
validate_file "README.md" || ((validation_errors++))
validate_file "DEPLOYMENT_GUIDE.md" || ((validation_errors++))
validate_executable "deploy-production.sh" || ((validation_errors++))
echo ""

# Directory structure validation
echo -e "${BLUE}2. Validating directory structure...${NC}"
validate_directory "backend" || ((validation_errors++))
validate_directory "frontend" || ((validation_errors++))
validate_directory "microservices" || ((validation_errors++))
validate_directory "infrastructure" || ((validation_errors++))
validate_directory "shared" || ((validation_errors++))
validate_directory ".github" || ((validation_errors++))
validate_directories
echo ""

# System dependencies validation
echo -e "${BLUE}3. Validating system dependencies...${NC}"
validate_dependencies || ((validation_errors++))
echo ""

# Environment configuration validation
echo -e "${BLUE}4. Validating environment configuration...${NC}"
validate_environment || ((validation_errors++))
echo ""

# SSL setup validation
echo -e "${BLUE}5. Validating SSL setup...${NC}"
validate_ssl_setup || ((validation_errors++))
echo ""

# Docker Compose validation
echo -e "${BLUE}6. Validating Docker Compose configuration...${NC}"
validate_docker_compose || ((validation_errors++))
echo ""

# Port availability validation
echo -e "${BLUE}7. Validating port availability...${NC}"
validate_ports
echo ""

# Final validation summary
echo "================================================="
if [ $validation_errors -eq 0 ]; then
    echo -e "${GREEN}🎉 Production environment validation PASSED!${NC}"
    echo -e "${GREEN}✓ All checks completed successfully${NC}"
    echo ""
    echo -e "${BLUE}Next steps:${NC}"
    echo "1. Review and customize .env file with your specific settings"
    echo "2. Update SSL certificates with your domain certificates"
    echo "3. Run: docker-compose -f docker-compose.production.yml up -d"
    echo "4. Access the application at https://localhost"
    echo ""
    exit 0
else
    echo -e "${RED}❌ Production environment validation FAILED!${NC}"
    echo -e "${RED}✗ $validation_errors error(s) found${NC}"
    echo ""
    echo -e "${YELLOW}Please fix the above issues before deploying to production.${NC}"
    echo ""
    exit 1
fi