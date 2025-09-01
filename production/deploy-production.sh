#!/bin/bash

# Typosentinel Enterprise Production Deployment Script
# This script sets up the production environment for Typosentinel Enterprise

set -e

echo "🚀 Starting Typosentinel Enterprise Production Deployment..."

# Environment Variables
export NODE_ENV=production
export GO_ENV=production
export TYPOSENTINEL_ENV=production

# Create necessary directories
echo "📁 Creating production directories..."
mkdir -p logs
mkdir -p data
mkdir -p backups
mkdir -p certificates

# Install dependencies for all services
echo "📦 Installing production dependencies..."

# Backend dependencies
if [ -f "backend/package.json" ]; then
    echo "Installing backend Node.js dependencies..."
    cd backend && npm ci --only=production && cd ..
fi

if [ -f "backend/go.mod" ]; then
    echo "Installing backend Go dependencies..."
    cd backend && go mod download && cd ..
fi

# Frontend dependencies
if [ -f "frontend/package.json" ]; then
    echo "Installing frontend dependencies..."
    cd frontend && npm ci --only=production && cd ..
fi

# Microservices dependencies
echo "Installing microservices dependencies..."
for service in microservices/*/; do
    if [ -f "${service}package.json" ]; then
        echo "Installing dependencies for $(basename "$service")..."
        cd "$service" && npm ci --only=production && cd ../..
    elif [ -f "${service}go.mod" ]; then
        echo "Installing Go dependencies for $(basename "$service")..."
        cd "$service" && go mod download && cd ../..
    fi
done

# Build frontend for production
if [ -f "frontend/package.json" ]; then
    echo "🏗️ Building frontend for production..."
    cd frontend && npm run build && cd ..
fi

# Set up monitoring
echo "📊 Setting up monitoring..."
if [ -f "infrastructure/monitoring/docker-compose.yml" ]; then
    cd infrastructure/monitoring
    docker-compose up -d
    cd ../..
fi

# Set permissions
echo "🔒 Setting production permissions..."
chmod +x typosentinel.exe
chmod -R 755 shared/
chmod -R 644 infrastructure/security/

# Create systemd service file (Linux)
if command -v systemctl &> /dev/null; then
    echo "⚙️ Creating systemd service..."
    cat > /tmp/typosentinel.service << EOF
[Unit]
Description=Typosentinel Enterprise Security Scanner
After=network.target

[Service]
Type=simple
User=typosentinel
WorkingDirectory=$(pwd)
ExecStart=$(pwd)/typosentinel.exe server --config=infrastructure/security/enterprise-security-config.yaml
Restart=always
RestartSec=10
Environment=NODE_ENV=production
Environment=GO_ENV=production

[Install]
WantedBy=multi-user.target
EOF
    echo "Service file created at /tmp/typosentinel.service"
    echo "Run 'sudo mv /tmp/typosentinel.service /etc/systemd/system/' to install"
fi

echo "✅ Production deployment completed successfully!"
echo ""
echo "📋 Next steps:"
echo "1. Review configuration files in infrastructure/security/"
echo "2. Set up SSL certificates in certificates/ directory"
echo "3. Configure environment-specific variables"
echo "4. Start monitoring services: cd infrastructure/monitoring && docker-compose up -d"
echo "5. Run Typosentinel: ./typosentinel.exe server --config=infrastructure/security/enterprise-security-config.yaml"
echo ""
echo "🔍 For security scanning: ./typosentinel.exe supply-chain scan-advanced --deep"
echo "📊 Monitoring dashboard: http://localhost:3000 (Grafana)"
echo "📈 Metrics endpoint: http://localhost:9090 (Prometheus)"