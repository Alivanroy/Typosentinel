# 🚀 Typosentinel VPS Demo Deployment

**Quick deployment guide for showcasing Typosentinel on Hostinger VPS**

## 🎯 What You'll Get

After deployment, you'll have a complete Typosentinel demo environment with:

- 🌐 **Web Interface** - Interactive dashboard with terminal-like scanning interface
- 💻 **CLI Tool** - Command-line interface for demonstrations
- 🔒 **SSL Security** - Automatic HTTPS with Let's Encrypt certificates
- 📊 **Real-time Dashboard** - Metrics, activity feeds, and threat visualization
- 🎬 **Demo Scripts** - Pre-built scenarios for presentations

## ⚡ Quick Start (5 Minutes)

### Step 1: Prepare Your Files

```bash
# On your local machine
tar -czf typosentinel-demo.tar.gz --exclude=node_modules --exclude=.git .
```

### Step 2: Upload to VPS

```bash
# Upload to your Hostinger VPS
scp typosentinel-demo.tar.gz root@YOUR_VPS_IP:/opt/
```

### Step 3: Deploy

```bash
# SSH into your VPS
ssh root@YOUR_VPS_IP

# Extract files
cd /opt
tar -xzf typosentinel-demo.tar.gz
cd Typosentinel

# Run the setup script
chmod +x hostinger-setup.sh
./hostinger-setup.sh
```

**That's it!** The script will ask for your domain and email, then automatically:
- Install all dependencies (Docker, Go, Node.js, Nginx)
- Build and deploy the application
- Configure SSL certificates
- Set up systemd services
- Create demo scripts

## 🌐 Access Your Demo

Once deployed:

- **Web Interface**: `https://your-domain.com`
- **API Documentation**: `https://your-domain.com/api`
- **CLI Access**: SSH into VPS and run `typosentinel`

## 🎬 Demo Scenarios

### Web Interface Demo

1. **Open the dashboard** at `https://your-domain.com`
2. **Use the terminal interface** to run live scans:
   ```
   scan express npm
   scan requests pypi
   scan github.com/gin-gonic/gin go
   ```
3. **Show real-time results** with threat detection and analysis
4. **Demonstrate the dashboard** with metrics and activity feeds

### CLI Demo

```bash
# SSH into your VPS
ssh root@YOUR_VPS_IP

# Run the demo script
/opt/typosentinel/demo/cli-demo.sh

# Or run individual commands
typosentinel scan --package express --registry npm
typosentinel scan --package requests --registry pypi --verbose
typosentinel scan --package github.com/gin-gonic/gin --registry go
```

### API Demo

```bash
# Show API endpoints
curl https://your-domain.com/api/health
curl https://your-domain.com/api/dashboard/metrics

# Demonstrate programmatic scanning
curl -X POST https://your-domain.com/api/scan \
  -H "Content-Type: application/json" \
  -d '{"package":"express","registry":"npm"}'
```

## 🔧 Management

### Service Control

```bash
# Backend service
sudo systemctl start typosentinel-backend
sudo systemctl stop typosentinel-backend
sudo systemctl restart typosentinel-backend
sudo systemctl status typosentinel-backend

# Frontend service
sudo systemctl start typosentinel-frontend
sudo systemctl stop typosentinel-frontend
sudo systemctl restart typosentinel-frontend
sudo systemctl status typosentinel-frontend

# View logs
sudo journalctl -u typosentinel-backend -f
sudo journalctl -u typosentinel-frontend -f
```

### Updates

```bash
# Update application
cd /opt/typosentinel
git pull  # if using git
# or upload new files

# Rebuild and restart
go build -o typosentinel main.go
cd web && npm run build && cd ..
sudo systemctl restart typosentinel-backend
sudo systemctl restart typosentinel-frontend
```

## 🎯 Key Features to Highlight

### 1. **Multi-Registry Support**
- NPM packages
- PyPI packages  
- Go modules
- Maven repositories (coming soon)

### 2. **Advanced Detection Methods**
- Typosquatting detection
- Homoglyph analysis
- Reputation scoring
- ML-powered threat assessment

### 3. **Integration Ready**
- REST API
- CLI tool
- Docker containers
- CI/CD pipeline integration

### 4. **Real-time Monitoring**
- Live dashboard
- Activity feeds
- Threat trends
- Performance metrics

## 🐛 Troubleshooting

### Common Issues

**Port conflicts:**
```bash
sudo netstat -tulpn | grep :80
sudo netstat -tulpn | grep :443
sudo netstat -tulpn | grep :8080
```

**Service not starting:**
```bash
sudo journalctl -u typosentinel-backend -n 50
sudo systemctl restart typosentinel-backend
```

**SSL certificate issues:**
```bash
sudo certbot renew --dry-run
sudo nginx -t
sudo systemctl reload nginx
```

**Frontend not loading:**
```bash
sudo systemctl status typosentinel-frontend
cd /opt/typosentinel/web && npm run build
sudo systemctl restart typosentinel-frontend
```

### Getting Help

1. Check service logs: `sudo journalctl -u typosentinel-backend -f`
2. Verify domain DNS settings point to your VPS IP
3. Ensure firewall allows ports 80, 443, 8080, 3000
4. Test API directly: `curl http://localhost:8080/api/health`

## 📊 Demo Metrics

Your deployed demo will show:

- **Packages Scanned**: Real-time counter
- **Threats Detected**: Security findings
- **Registries Monitored**: NPM, PyPI, Go modules
- **Detection Accuracy**: ML model performance
- **Response Time**: API performance metrics

## 🎉 Success Indicators

✅ **Web interface loads** at `https://your-domain.com`  
✅ **Terminal interface works** for interactive scanning  
✅ **CLI tool responds** to `typosentinel --help`  
✅ **API endpoints return data** at `/api/health`  
✅ **SSL certificate is valid** (green lock in browser)  
✅ **Demo script runs successfully**  

## 🚀 Next Steps

After successful deployment:

1. **Customize branding** in `web/src/components/`
2. **Add your own demo packages** to scan
3. **Configure monitoring** and alerting
4. **Set up backup procedures**
5. **Plan for scaling** if needed

---

**🎯 Your Typosentinel demo environment is production-ready and perfect for showcasing to end users, clients, and stakeholders!**