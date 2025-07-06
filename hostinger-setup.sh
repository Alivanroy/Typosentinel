#!/bin/bash

# Typosentinel Hostinger VPS Quick Setup
# Run this script on your Hostinger VPS to deploy Typosentinel

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}"
echo "╔══════════════════════════════════════╗"
echo "║     Typosentinel VPS Setup           ║"
echo "║     Hostinger Optimized              ║"
echo "╚══════════════════════════════════════╝"
echo -e "${NC}"

# Get user input
read -p "Enter your domain name (e.g., demo.yourdomain.com): " DOMAIN
read -p "Enter your email for SSL certificate: " EMAIL

if [[ -z "$DOMAIN" || -z "$EMAIL" ]]; then
    echo -e "${RED}Error: Domain and email are required${NC}"
    exit 1
fi

echo -e "${YELLOW}🚀 Starting deployment for $DOMAIN...${NC}"

# Update system
echo -e "${YELLOW}📦 Updating system...${NC}"
apt update && apt upgrade -y

# Install essential packages
echo -e "${YELLOW}📦 Installing essential packages...${NC}"
apt install -y curl wget git unzip software-properties-common apt-transport-https ca-certificates gnupg lsb-release

# Install Docker
echo -e "${YELLOW}🐳 Installing Docker...${NC}"
if ! command -v docker &> /dev/null; then
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
    apt update
    apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
    systemctl enable docker
    systemctl start docker
else
    echo -e "${GREEN}Docker already installed${NC}"
fi

# Install Docker Compose
echo -e "${YELLOW}🔧 Installing Docker Compose...${NC}"
if ! command -v docker-compose &> /dev/null; then
    curl -L "https://github.com/docker/compose/releases/download/v2.20.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    chmod +x /usr/local/bin/docker-compose
else
    echo -e "${GREEN}Docker Compose already installed${NC}"
fi

# Install Go
echo -e "${YELLOW}🔧 Installing Go...${NC}"
if ! command -v go &> /dev/null; then
    wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
    rm -rf /usr/local/go && tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
    echo 'export PATH=$PATH:/usr/local/go/bin' >> /root/.bashrc
    export PATH=$PATH:/usr/local/go/bin
    rm go1.21.0.linux-amd64.tar.gz
else
    echo -e "${GREEN}Go already installed${NC}"
fi

# Install Node.js
echo -e "${YELLOW}📦 Installing Node.js...${NC}"
if ! command -v node &> /dev/null; then
    curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
    apt-get install -y nodejs
else
    echo -e "${GREEN}Node.js already installed${NC}"
fi

# Install Nginx
echo -e "${YELLOW}🌐 Installing Nginx...${NC}"
apt install -y nginx
systemctl enable nginx
systemctl start nginx

# Install Certbot
echo -e "${YELLOW}🔒 Installing Certbot...${NC}"
apt install -y certbot python3-certbot-nginx

# Setup application directory
echo -e "${YELLOW}📁 Setting up application...${NC}"
mkdir -p /opt/typosentinel
cd /opt/typosentinel

# Note: At this point, you should have uploaded your application files
echo -e "${YELLOW}📥 Please ensure your application files are in /opt/typosentinel${NC}"
echo -e "${YELLOW}You can upload using: scp -r ./Typosentinel/* root@your-vps-ip:/opt/typosentinel/${NC}"

# Wait for user confirmation
read -p "Press Enter after uploading your application files..."

# Update configuration files
echo -e "${YELLOW}⚙️ Updating configuration...${NC}"
if [ -f "deploy/docker-compose.prod.yml" ]; then
    sed -i "s/your-domain.com/$DOMAIN/g" deploy/docker-compose.prod.yml
fi

if [ -f "web/nginx.conf" ]; then
    sed -i "s/your-domain.com/$DOMAIN/g" web/nginx.conf
fi

# Create nginx configuration for the domain
echo -e "${YELLOW}🌐 Configuring Nginx...${NC}"
cat > /etc/nginx/sites-available/$DOMAIN << EOF
server {
    listen 80;
    server_name $DOMAIN;
    
    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cache_bypass \$http_upgrade;
    }
    
    location /api/ {
        proxy_pass http://localhost:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cache_bypass \$http_upgrade;
    }
}
EOF

# Enable the site
ln -sf /etc/nginx/sites-available/$DOMAIN /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl reload nginx

# Build Go application
echo -e "${YELLOW}🏗️ Building application...${NC}"
if [ -f "go.mod" ]; then
    export PATH=$PATH:/usr/local/go/bin
    go build -o typosentinel main.go
    chmod +x typosentinel
fi

# Build frontend
echo -e "${YELLOW}🏗️ Building frontend...${NC}"
if [ -d "web" ]; then
    cd web
    # Update API URL
    sed -i "s/localhost:8084/$DOMAIN/g" src/services/api.js
    sed -i "s/http:/https:/g" src/services/api.js
    npm install
    npm run build
    cd ..
fi

# Create systemd services
echo -e "${YELLOW}🔧 Creating systemd services...${NC}"

# Backend service
cat > /etc/systemd/system/typosentinel-backend.service << EOF
[Unit]
Description=Typosentinel Backend
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/typosentinel
ExecStart=/opt/typosentinel/typosentinel serve --config config.yaml --port 8080
Restart=always
RestartSec=10
Environment=PATH=/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

[Install]
WantedBy=multi-user.target
EOF

# Frontend service
cat > /etc/systemd/system/typosentinel-frontend.service << EOF
[Unit]
Description=Typosentinel Frontend
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/typosentinel/web
ExecStart=/usr/bin/npx serve -s build -l 3000
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Enable and start services
systemctl daemon-reload
systemctl enable typosentinel-backend
systemctl enable typosentinel-frontend
systemctl start typosentinel-backend
systemctl start typosentinel-frontend

# Setup SSL certificate
echo -e "${YELLOW}🔒 Setting up SSL certificate...${NC}"
certbot --nginx -d $DOMAIN --email $EMAIL --agree-tos --non-interactive

# Setup firewall
echo -e "${YELLOW}🔥 Configuring firewall...${NC}"
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 8080/tcp
ufw allow 3000/tcp
ufw --force enable

# Create CLI symlink
echo -e "${YELLOW}🔗 Setting up CLI access...${NC}"
ln -sf /opt/typosentinel/typosentinel /usr/local/bin/typosentinel

# Create demo scripts
echo -e "${YELLOW}📝 Creating demo scripts...${NC}"
mkdir -p /opt/typosentinel/demo

cat > /opt/typosentinel/demo/cli-demo.sh << 'EOF'
#!/bin/bash
echo "🔍 Typosentinel CLI Demo"
echo "========================"
echo
echo "1. Scanning npm package 'express':"
typosentinel scan --package express --registry npm
echo
echo "2. Scanning Python package 'requests':"
typosentinel scan --package requests --registry pypi
echo
echo "3. Scanning Go module:"
typosentinel scan --package github.com/gin-gonic/gin --registry go
echo
echo "✅ Demo completed!"
EOF

chmod +x /opt/typosentinel/demo/cli-demo.sh

# Final status check
echo -e "${YELLOW}🔍 Checking services...${NC}"
sleep 5
systemctl status typosentinel-backend --no-pager
systemctl status typosentinel-frontend --no-pager
systemctl status nginx --no-pager

echo -e "${GREEN}"
echo "╔══════════════════════════════════════╗"
echo "║          🎉 SUCCESS! 🎉              ║"
echo "║     Typosentinel is deployed!        ║"
echo "╚══════════════════════════════════════╝"
echo -e "${NC}"

echo -e "${YELLOW}📋 Deployment Summary:${NC}"
echo -e "${GREEN}✅ Web Interface:${NC} https://$DOMAIN"
echo -e "${GREEN}✅ API Endpoint:${NC} https://$DOMAIN/api"
echo -e "${GREEN}✅ CLI Tool:${NC} typosentinel scan --package <package> --registry <npm|pypi|go>"
echo -e "${GREEN}✅ Demo Script:${NC} /opt/typosentinel/demo/cli-demo.sh"
echo
echo -e "${YELLOW}🔧 Management Commands:${NC}"
echo "  Backend: systemctl [start|stop|restart|status] typosentinel-backend"
echo "  Frontend: systemctl [start|stop|restart|status] typosentinel-frontend"
echo "  Nginx: systemctl [start|stop|restart|status] nginx"
echo "  Logs: journalctl -u typosentinel-backend -f"
echo
echo -e "${GREEN}🚀 Your Typosentinel demo is ready for end users!${NC}"