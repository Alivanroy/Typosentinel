# 🚀 Typosentinel VPS Deployment Guide

This guide will help you deploy Typosentinel on your Hostinger VPS with both CLI and web interface access for end-user demonstrations.

## 📋 Prerequisites

- Hostinger VPS with Ubuntu 20.04+ or similar Linux distribution
- Domain name pointed to your VPS IP
- SSH access to your VPS
- At least 2GB RAM and 20GB storage

## 🔧 Quick Deployment

### Step 1: Upload Files to VPS

1. **Compress your project:**
   ```bash
   tar -czf typosentinel.tar.gz --exclude=node_modules --exclude=.git .
   ```

2. **Upload to VPS:**
   ```bash
   scp typosentinel.tar.gz root@your-vps-ip:/opt/
   ```

3. **SSH into VPS and extract:**
   ```bash
   ssh root@your-vps-ip
   cd /opt
   tar -xzf typosentinel.tar.gz
   mv Typosentinel typosentinel
   cd typosentinel
   ```

### Step 2: Run Deployment Script

```bash
chmod +x deploy/deploy.sh
./deploy/deploy.sh your-domain.com your-email@domain.com
```

**Example:**
```bash
./deploy/deploy.sh demo.typosentinel.com admin@demo.typosentinel.com
```

### Step 3: Verify Deployment

1. **Check web interface:** `https://your-domain.com`
2. **Test CLI:** `typosentinel scan --package express --registry npm`
3. **Run demo:** `/opt/typosentinel/demo/cli-demo.sh`

## 🎯 Manual Deployment (Alternative)

If you prefer manual setup:

### 1. System Setup

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/download/v2.20.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Install Go
wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc
```

### 2. Application Setup

```bash
# Create directory
sudo mkdir -p /opt/typosentinel
sudo chown $USER:$USER /opt/typosentinel
cd /opt/typosentinel

# Upload and extract your files here

# Update configuration
sed -i 's/your-domain.com/YOUR_ACTUAL_DOMAIN/g' deploy/docker-compose.prod.yml
sed -i 's/your-domain.com/YOUR_ACTUAL_DOMAIN/g' web/nginx.conf
```

### 3. Build and Deploy

```bash
# Build Go binary
go build -o typosentinel main.go

# Build and start containers
docker-compose -f deploy/docker-compose.prod.yml up -d --build

# Setup SSL
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d your-domain.com
```

## 🌐 Web Interface Features

Your deployed web interface will include:

- **Dashboard** with real-time metrics
- **Interactive Terminal** for live scanning demonstrations
- **Quick Action Buttons** for common scan operations
- **Scan Results Visualization** with detailed threat analysis
- **Responsive Design** for desktop and mobile demos

## 💻 CLI Usage Examples

Once deployed, demonstrate these CLI commands:

```bash
# Basic package scan
typosentinel scan --package express --registry npm

# Multiple packages
typosentinel scan --package "lodash,react,vue" --registry npm

# Python packages
typosentinel scan --package requests --registry pypi --verbose

# Go modules
typosentinel scan --package github.com/gin-gonic/gin --registry go

# Scan local project
typosentinel scan --path /path/to/project

# Generate report
typosentinel scan --package express --registry npm --output json > report.json
```

## 🎬 Demo Scenarios

### Scenario 1: Web Interface Demo
1. Open `https://your-domain.com`
2. Use the terminal interface to scan popular packages
3. Show real-time threat detection
4. Demonstrate the dashboard metrics

### Scenario 2: CLI Demo
1. SSH into the server or use local terminal
2. Run the demo script: `/opt/typosentinel/demo/cli-demo.sh`
3. Show different scan types and outputs
4. Demonstrate integration capabilities

### Scenario 3: API Demo
1. Show API endpoints: `https://your-domain.com/api`
2. Demonstrate programmatic access
3. Show integration possibilities

## 🔧 Management Commands

### Service Management
```bash
# Start/stop/restart services
sudo systemctl start typosentinel
sudo systemctl stop typosentinel
sudo systemctl restart typosentinel
sudo systemctl status typosentinel

# View logs
sudo journalctl -u typosentinel -f
```

### Docker Management
```bash
# View running containers
docker ps

# View logs
docker-compose -f deploy/docker-compose.prod.yml logs -f

# Restart services
docker-compose -f deploy/docker-compose.prod.yml restart

# Update application
git pull
docker-compose -f deploy/docker-compose.prod.yml up -d --build
```

## 🔒 Security Considerations

- SSL certificates are automatically configured
- Firewall rules are set up during deployment
- API endpoints are secured
- Regular security updates recommended

## 🐛 Troubleshooting

### Common Issues

1. **Port conflicts:**
   ```bash
   sudo netstat -tulpn | grep :80
   sudo netstat -tulpn | grep :443
   ```

2. **Docker issues:**
   ```bash
   sudo systemctl restart docker
   docker system prune -a
   ```

3. **SSL certificate issues:**
   ```bash
   sudo certbot renew --dry-run
   sudo nginx -t
   sudo systemctl reload nginx
   ```

4. **Application logs:**
   ```bash
   docker-compose -f deploy/docker-compose.prod.yml logs typosentinel-backend
   docker-compose -f deploy/docker-compose.prod.yml logs typosentinel-web
   ```

## 📞 Support

If you encounter issues:
1. Check the logs using the commands above
2. Verify your domain DNS settings
3. Ensure all ports are open in your VPS firewall
4. Contact your hosting provider if needed

## 🎉 Success!

Once deployed, you'll have:
- ✅ Web interface at `https://your-domain.com`
- ✅ API access at `https://your-domain.com/api`
- ✅ CLI tool available globally as `typosentinel`
- ✅ Automated SSL certificates
- ✅ Production-ready configuration
- ✅ Demo scripts for presentations

Your Typosentinel demo environment is ready for showcasing to end users!