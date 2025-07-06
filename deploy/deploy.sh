#!/bin/bash

# Typosentinel VPS Deployment Script
# This script deploys Typosentinel on a VPS with both CLI and web interface

set -e

echo "🚀 Starting Typosentinel VPS Deployment..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
DOMAIN=${1:-"your-domain.com"}
EMAIL=${2:-"admin@your-domain.com"}

echo -e "${YELLOW}Domain: $DOMAIN${NC}"
echo -e "${YELLOW}Email: $EMAIL${NC}"

# Update system
echo -e "${YELLOW}📦 Updating system packages...${NC}"
sudo apt update && sudo apt upgrade -y

# Install Docker
echo -e "${YELLOW}🐳 Installing Docker...${NC}"
if ! command -v docker &> /dev/null; then
    curl -fsSL https://get.docker.com -o get-docker.sh
    sudo sh get-docker.sh
    sudo usermod -aG docker $USER
    rm get-docker.sh
else
    echo -e "${GREEN}Docker already installed${NC}"
fi

# Install Docker Compose
echo -e "${YELLOW}🔧 Installing Docker Compose...${NC}"
if ! command -v docker-compose &> /dev/null; then
    sudo curl -L "https://github.com/docker/compose/releases/download/v2.20.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    sudo chmod +x /usr/local/bin/docker-compose
else
    echo -e "${GREEN}Docker Compose already installed${NC}"
fi

# Install Go (for CLI usage)
echo -e "${YELLOW}🔧 Installing Go...${NC}"
if ! command -v go &> /dev/null; then
    wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
    sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
    export PATH=$PATH:/usr/local/go/bin
    rm go1.21.0.linux-amd64.tar.gz
else
    echo -e "${GREEN}Go already installed${NC}"
fi

# Install Node.js (for building frontend)
echo -e "${YELLOW}📦 Installing Node.js...${NC}"
if ! command -v node &> /dev/null; then
    curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
    sudo apt-get install -y nodejs
else
    echo -e "${GREEN}Node.js already installed${NC}"
fi

# Install Certbot for SSL
echo -e "${YELLOW}🔒 Installing Certbot...${NC}"
sudo apt install -y certbot python3-certbot-nginx

# Create application directory
echo -e "${YELLOW}📁 Setting up application directory...${NC}"
sudo mkdir -p /opt/typosentinel
sudo chown $USER:$USER /opt/typosentinel
cd /opt/typosentinel

# Clone or copy application (assuming files are already uploaded)
echo -e "${YELLOW}📥 Setting up application files...${NC}"
# Note: You'll need to upload your application files to this directory

# Update configuration for production
echo -e "${YELLOW}⚙️ Updating configuration...${NC}"
sed -i "s/your-domain.com/$DOMAIN/g" deploy/docker-compose.prod.yml
sed -i "s/your-domain.com/$DOMAIN/g" web/nginx.conf

# Build and start services
echo -e "${YELLOW}🏗️ Building and starting services...${NC}"
docker-compose -f deploy/docker-compose.prod.yml up -d --build

# Wait for services to start
echo -e "${YELLOW}⏳ Waiting for services to start...${NC}"
sleep 30

# Setup SSL certificate
echo -e "${YELLOW}🔒 Setting up SSL certificate...${NC}"
sudo certbot --nginx -d $DOMAIN --email $EMAIL --agree-tos --non-interactive

# Create CLI symlink for global access
echo -e "${YELLOW}🔗 Setting up CLI access...${NC}"
sudo ln -sf /opt/typosentinel/typosentinel /usr/local/bin/typosentinel

# Create systemd service for CLI daemon (optional)
echo -e "${YELLOW}🔧 Creating systemd service...${NC}"
sudo tee /etc/systemd/system/typosentinel.service > /dev/null <<EOF
[Unit]
Description=Typosentinel Security Scanner
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=/opt/typosentinel
ExecStart=/opt/typosentinel/typosentinel serve --config config.yaml --port 8080
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable typosentinel

# Setup firewall
echo -e "${YELLOW}🔥 Configuring firewall...${NC}"
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 8080/tcp
sudo ufw --force enable

# Create demo scripts
echo -e "${YELLOW}📝 Creating demo scripts...${NC}"
mkdir -p /opt/typosentinel/demo

# CLI Demo script
tee /opt/typosentinel/demo/cli-demo.sh > /dev/null <<'EOF'
#!/bin/bash
echo "🔍 Typosentinel CLI Demo"
echo "========================"
echo
echo "1. Scanning a package for typosquatting:"
typosentinel scan --package express --registry npm
echo
echo "2. Scanning multiple packages:"
typosentinel scan --package "lodash,react,vue" --registry npm
echo
echo "3. Scanning with detailed output:"
typosentinel scan --package requests --registry pypi --verbose
echo
echo "4. Scanning Go modules:"
typosentinel scan --package github.com/gin-gonic/gin --registry go
echo
echo "Demo completed! ✅"
EOF

chmod +x /opt/typosentinel/demo/cli-demo.sh

echo -e "${GREEN}✅ Deployment completed successfully!${NC}"
echo
echo -e "${YELLOW}🌐 Web Interface:${NC} https://$DOMAIN"
echo -e "${YELLOW}🔧 API Endpoint:${NC} https://$DOMAIN/api"
echo -e "${YELLOW}💻 CLI Usage:${NC} typosentinel scan --package <package-name> --registry <npm|pypi|go>"
echo -e "${YELLOW}🎬 CLI Demo:${NC} /opt/typosentinel/demo/cli-demo.sh"
echo
echo -e "${YELLOW}📋 Service Management:${NC}"
echo "  - Start: sudo systemctl start typosentinel"
echo "  - Stop: sudo systemctl stop typosentinel"
echo "  - Status: sudo systemctl status typosentinel"
echo "  - Logs: sudo journalctl -u typosentinel -f"
echo
echo -e "${YELLOW}🐳 Docker Management:${NC}"
echo "  - View containers: docker ps"
echo "  - View logs: docker-compose -f deploy/docker-compose.prod.yml logs -f"
echo "  - Restart: docker-compose -f deploy/docker-compose.prod.yml restart"
echo
echo -e "${GREEN}🎉 Your Typosentinel demo is ready!${NC}"