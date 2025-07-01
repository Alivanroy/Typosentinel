# TypoSentinel Web Demo - Complete Setup Guide

🛡️ **Professional web-based demonstration of TypoSentinel's package security scanning capabilities**

## 📋 Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Detailed Setup](#detailed-setup)
- [Configuration](#configuration)
- [Deployment Options](#deployment-options)
- [Monitoring & Maintenance](#monitoring--maintenance)
- [Security Considerations](#security-considerations)
- [Troubleshooting](#troubleshooting)
- [Advanced Features](#advanced-features)

## 🎯 Overview

This web demo provides a comprehensive, professional showcase of TypoSentinel's capabilities, featuring:

- **Interactive Package Scanner** - Real-time scanning simulation for multiple ecosystems
- **Modern UI/UX** - Clean, responsive design with smooth animations
- **API Documentation** - Interactive examples and endpoint documentation
- **Monitoring Dashboard** - Real-time metrics and system status
- **Production-Ready** - Docker containerization with SSL support
- **VPS Optimized** - Specifically designed for Hostinger VPS deployment

## 🔧 Prerequisites

### System Requirements
- **OS**: Ubuntu 20.04+ / CentOS 8+ / Debian 11+
- **RAM**: Minimum 1GB, Recommended 2GB+
- **Storage**: 5GB free space
- **Network**: Public IP address with ports 80/443 access

### Software Dependencies
- Docker 20.10+
- Docker Compose 2.0+
- Git
- UFW (Uncomplicated Firewall)
- Certbot (for SSL certificates)

### Domain Requirements (Optional)
- Custom domain pointing to your VPS IP
- DNS A record configured

## 🚀 Quick Start

### Option 1: Automated Deployment (Recommended)

```bash
# 1. Clone or upload the web-demo files to your VPS
scp -r web-demo/ user@your-vps-ip:/opt/

# 2. Connect to your VPS
ssh user@your-vps-ip

# 3. Navigate to the demo directory
cd /opt/web-demo

# 4. Make the deployment script executable
chmod +x deploy.sh

# 5. Run automated deployment
sudo ./deploy.sh --domain your-domain.com --email your-email@domain.com
```

### Option 2: IP-Only Deployment

```bash
# Deploy without custom domain (uses IP address)
sudo ./deploy.sh --skip-ssl --skip-firewall
```

### Option 3: Local Development

```bash
# For local testing and development
docker-compose up -d

# Access at http://localhost
```

## 📖 Detailed Setup

### Step 1: Server Preparation

```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Install required packages
sudo apt install -y curl wget git ufw

# Create application directory
sudo mkdir -p /opt/typosentinel-demo
sudo chown $USER:$USER /opt/typosentinel-demo
```

### Step 2: Upload Demo Files

```bash
# Method 1: Direct upload via SCP
scp -r web-demo/* user@your-vps:/opt/typosentinel-demo/

# Method 2: Git clone (if using a private repository)
git clone <your-private-repo> /opt/typosentinel-demo

# Method 3: Manual upload via FTP/SFTP
# Use your preferred FTP client to upload files
```

### Step 3: Docker Installation

```bash
# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Add user to docker group
sudo usermod -aG docker $USER

# Restart session or run:
newgrp docker
```

### Step 4: SSL Certificate Setup (Optional)

```bash
# Install Certbot
sudo apt install -y certbot

# Stop any running web servers
sudo systemctl stop apache2 nginx 2>/dev/null || true

# Generate SSL certificate
sudo certbot certonly --standalone -d your-domain.com --email your-email@domain.com --agree-tos --non-interactive

# Copy certificates to demo directory
sudo mkdir -p /opt/typosentinel-demo/ssl
sudo cp /etc/letsencrypt/live/your-domain.com/fullchain.pem /opt/typosentinel-demo/ssl/
sudo cp /etc/letsencrypt/live/your-domain.com/privkey.pem /opt/typosentinel-demo/ssl/
sudo chown -R $USER:$USER /opt/typosentinel-demo/ssl
```

### Step 5: Firewall Configuration

```bash
# Configure UFW
sudo ufw --force reset
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw --force enable
```

### Step 6: Deploy Application

```bash
# Navigate to demo directory
cd /opt/typosentinel-demo

# Build and start containers
docker-compose up -d --build

# Verify deployment
docker-compose ps
docker-compose logs
```

## ⚙️ Configuration

### Environment Variables

Create a `.env` file in the demo directory:

```bash
# Application Configuration
APP_NAME=TypoSentinel Demo
APP_VERSION=1.0.0
ENVIRONMENT=production

# Server Configuration
SERVER_PORT=80
SSL_PORT=443
DOMAIN=your-domain.com

# Security Settings
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_WINDOW=3600
MAX_UPLOAD_SIZE=10M

# Monitoring
MONITORING_ENABLED=true
LOG_LEVEL=info
LOG_RETENTION_DAYS=30

# Demo Settings
DEMO_MODE=true
MOCK_API_DELAY=1000
MAX_CONCURRENT_SCANS=10
```

### Custom Branding

Modify `styles.css` to customize the appearance:

```css
/* Update primary colors */
:root {
    --primary-color: #667eea;
    --secondary-color: #764ba2;
    --accent-color: #4ade80;
    --danger-color: #f87171;
    --warning-color: #fbbf24;
}

/* Update logo and branding */
.logo {
    background-image: url('your-logo.svg');
}
```

### Nginx Configuration

The included `nginx.conf` provides:

- **Performance Optimization**: Gzip compression, caching headers
- **Security Headers**: XSS protection, content type options
- **Rate Limiting**: Protection against abuse
- **SSL Configuration**: Modern TLS settings
- **API Endpoints**: Mock API for demo functionality

## 🌐 Deployment Options

### Production Deployment (Recommended)

```bash
# Full production setup with SSL
sudo ./deploy.sh \
    --domain your-domain.com \
    --email admin@your-domain.com \
    --install-docker \
    --setup-firewall \
    --setup-ssl \
    --setup-monitoring
```

### Development Deployment

```bash
# Local development without SSL
docker-compose -f docker-compose.dev.yml up -d
```

### Staging Deployment

```bash
# Staging environment with basic security
sudo ./deploy.sh \
    --domain staging.your-domain.com \
    --email admin@your-domain.com \
    --skip-monitoring
```

## 📊 Monitoring & Maintenance

### Access Monitoring Dashboard

```bash
# Open monitoring dashboard
https://your-domain.com/monitoring.html

# Or via IP
http://your-vps-ip/monitoring.html
```

### Log Management

```bash
# View application logs
docker-compose logs -f web

# View Nginx access logs
docker-compose exec web tail -f /var/log/nginx/access.log

# View error logs
docker-compose exec web tail -f /var/log/nginx/error.log
```

### Backup & Restore

```bash
# Create backup
sudo ./backup.sh backup

# List available backups
sudo ./backup.sh list

# Restore from backup
sudo ./backup.sh restore typosentinel-demo_20241201_120000

# Cleanup old backups
sudo ./backup.sh cleanup
```

### Health Checks

```bash
# Check container health
docker-compose ps

# Check application status
curl -f http://localhost/health || echo "Service unavailable"

# Check SSL certificate
echo | openssl s_client -connect your-domain.com:443 2>/dev/null | openssl x509 -noout -dates
```

### Automatic Updates

Set up automatic SSL renewal:

```bash
# Add to crontab
sudo crontab -e

# Add this line for automatic SSL renewal
0 12 * * * /usr/bin/certbot renew --quiet && docker-compose restart web
```

## 🔒 Security Considerations

### SSL/TLS Configuration

- **Modern TLS**: Only TLS 1.2+ supported
- **Strong Ciphers**: ECDHE and AES encryption
- **HSTS**: HTTP Strict Transport Security enabled
- **Certificate Pinning**: Optional for enhanced security

### Security Headers

```nginx
# Implemented security headers
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Content-Security-Policy: default-src 'self'
```

### Rate Limiting

- **API Endpoints**: 100 requests per hour per IP
- **Static Assets**: 1000 requests per minute
- **Demo Scanner**: 10 concurrent scans maximum

### Access Control

```bash
# Restrict SSH access
sudo ufw limit ssh

# Block specific IPs (if needed)
sudo ufw deny from <malicious-ip>

# Monitor failed login attempts
sudo tail -f /var/log/auth.log
```

## 🔧 Troubleshooting

### Common Issues

#### 1. Container Won't Start

```bash
# Check Docker status
sudo systemctl status docker

# Check container logs
docker-compose logs web

# Rebuild containers
docker-compose down
docker-compose up -d --build
```

#### 2. SSL Certificate Issues

```bash
# Check certificate validity
openssl x509 -in ssl/fullchain.pem -text -noout

# Renew certificate manually
sudo certbot renew --force-renewal

# Update certificate in container
docker-compose restart web
```

#### 3. Port Conflicts

```bash
# Check what's using port 80/443
sudo netstat -tulpn | grep :80
sudo netstat -tulpn | grep :443

# Stop conflicting services
sudo systemctl stop apache2 nginx
```

#### 4. Permission Issues

```bash
# Fix file permissions
sudo chown -R $USER:$USER /opt/typosentinel-demo
sudo chmod +x deploy.sh backup.sh

# Fix SSL permissions
sudo chmod 600 ssl/privkey.pem
sudo chmod 644 ssl/fullchain.pem
```

### Performance Issues

#### High Memory Usage

```bash
# Monitor container resources
docker stats

# Limit container memory
# Add to docker-compose.yml:
mem_limit: 512m
mem_reservation: 256m
```

#### Slow Response Times

```bash
# Enable Nginx caching
# Add to nginx.conf:
location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg)$ {
    expires 1y;
    add_header Cache-Control "public, immutable";
}
```

### Debug Mode

```bash
# Enable debug logging
export LOG_LEVEL=debug
docker-compose up -d

# View detailed logs
docker-compose logs -f --tail=100 web
```

## 🚀 Advanced Features

### Custom API Integration

Replace mock API with real backend:

```javascript
// In script.js, update API endpoints
const API_BASE = 'https://api.typosentinel.com';

// Update scan function
async function scanPackage(packageName, ecosystem) {
    const response = await fetch(`${API_BASE}/scan`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer YOUR_API_KEY'
        },
        body: JSON.stringify({ package: packageName, ecosystem })
    });
    return response.json();
}
```

### Analytics Integration

```html
<!-- Add to index.html head section -->
<script async src="https://www.googletagmanager.com/gtag/js?id=GA_TRACKING_ID"></script>
<script>
  window.dataLayer = window.dataLayer || [];
  function gtag(){dataLayer.push(arguments);}
  gtag('js', new Date());
  gtag('config', 'GA_TRACKING_ID');
</script>
```

### Load Balancing

```yaml
# docker-compose.yml for multiple instances
version: '3.8'
services:
  web1:
    build: .
    ports:
      - "8001:80"
  web2:
    build: .
    ports:
      - "8002:80"
  nginx-lb:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx-lb.conf:/etc/nginx/nginx.conf
```

### Database Integration

```yaml
# Add to docker-compose.yml
services:
  postgres:
    image: postgres:13
    environment:
      POSTGRES_DB: typosentinel_demo
      POSTGRES_USER: demo_user
      POSTGRES_PASSWORD: secure_password
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "5432:5432"

volumes:
  postgres_data:
```

## 📞 Support

### Getting Help

- **Documentation**: Check this guide and README.md
- **Logs**: Always check container logs first
- **Community**: Search for similar issues online
- **Professional Support**: Contact for enterprise support

### Reporting Issues

When reporting issues, include:

1. **System Information**:
   ```bash
   uname -a
   docker --version
   docker-compose --version
   ```

2. **Container Status**:
   ```bash
   docker-compose ps
   docker-compose logs
   ```

3. **Error Messages**: Full error output
4. **Steps to Reproduce**: Detailed reproduction steps
5. **Configuration**: Relevant configuration files (sanitized)

---

## 📄 File Structure

```
web-demo/
├── index.html              # Main demo page
├── styles.css              # Styling and animations
├── script.js               # Interactive functionality
├── monitoring.html         # Monitoring dashboard
├── Dockerfile              # Container configuration
├── docker-compose.yml      # Multi-container setup
├── nginx.conf              # Web server configuration
├── deploy.sh               # Automated deployment script
├── backup.sh               # Backup and restore script
├── README.md               # Quick start guide
├── SETUP_GUIDE.md          # This comprehensive guide
├── ssl/                    # SSL certificates (created during setup)
├── logs/                   # Application logs (created during runtime)
└── .env                    # Environment variables (create manually)
```

---

**🎉 Congratulations!** You now have a professional, production-ready web demo of TypoSentinel running on your Hostinger VPS. The demo showcases the product's capabilities while providing a secure, scalable, and maintainable deployment.

For additional customization or enterprise features, refer to the advanced sections above or contact support.