# TypoSentinel Web Demo

A comprehensive web demonstration of TypoSentinel with SSL/TLS encryption, monitoring, and the actual TypoSentinel scanning engine integrated.

## 🌟 Features

- **Complete TypoSentinel Integration**: Real scanning engine with ML-based analysis
- **SSL/TLS Security**: Let's Encrypt certificates with automatic renewal
- **Monitoring Stack**: Prometheus metrics and Grafana dashboards
- **High Performance**: Redis caching and PostgreSQL database
- **Production Ready**: Docker containerization with health checks
- **Security Hardened**: HTTPS redirects, security headers, and CSP

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│     Nginx       │    │  TypoSentinel   │    │   PostgreSQL    │
│  (Load Balancer)│────│      API        │────│   (Database)    │
│   SSL/TLS       │    │   (Go Service)  │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         │              ┌─────────────────┐              │
         │              │      Redis      │              │
         └──────────────│     (Cache)     │──────────────┘
                        └─────────────────┘
                                 │
                    ┌─────────────────┐    ┌─────────────────┐
                    │   Prometheus    │    │     Grafana     │
                    │   (Metrics)     │────│  (Monitoring)   │
                    └─────────────────┘    └─────────────────┘
```

## 🚀 Quick Start

### Prerequisites

- Docker 20.10+
- Docker Compose 2.0+
- 4GB+ RAM available
- Ports 80, 443, 3000, 9090 available

### 1. Clone and Setup

```bash
# Navigate to the web demo directory
cd /Users/alikorsi/Documents/Typosentinel/web-demo

# Make scripts executable
chmod +x start-demo.sh
chmod +x ssl/generate-self-signed.sh
```

### 2. Start the Demo

```bash
# Start all services
./start-demo.sh
```

The script will:
- Generate SSL certificates
- Build Docker images
- Start all services
- Perform health checks
- Display service URLs

### 3. Access the Services

| Service | URL | Credentials |
|---------|-----|-------------|
| **Web Interface** | http://localhost or https://localhost | - |
| **API Endpoint** | http://localhost/api | - |
| **Grafana** | http://localhost:3000 | admin/admin |
| **Prometheus** | http://localhost:9090 | - |

### Production Deployment on Hostinger VPS

#### Prerequisites
- Ubuntu/Debian VPS with root access
- Domain name (optional but recommended)
- Basic knowledge of Linux commands

#### Automated Deployment

1. **Upload files to your VPS**:
   ```bash
   # Upload all demo files to your VPS
   scp -r web-demo/* root@your-vps-ip:/tmp/typosentinel-demo/
   ```

2. **Connect to your VPS**:
   ```bash
   ssh root@your-vps-ip
   ```

3. **Run the deployment script**:
   ```bash
   cd /tmp/typosentinel-demo
   chmod +x deploy.sh
   
   # Basic deployment (HTTP only)
   ./deploy.sh
   
   # With custom domain and SSL
   ./deploy.sh --domain demo.yourdomain.com --email your@email.com
   
   # Skip SSL setup
   ./deploy.sh --no-ssl
   
   # Skip firewall configuration
   ./deploy.sh --no-firewall
   ```

#### Manual Deployment

If you prefer manual setup:

1. **Install Docker**:
   ```bash
   curl -fsSL https://get.docker.com -o get-docker.sh
   sh get-docker.sh
   ```

2. **Install Docker Compose**:
   ```bash
   curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
   chmod +x /usr/local/bin/docker-compose
   ```

3. **Deploy the application**:
   ```bash
   mkdir -p /opt/typosentinel-demo
   cd /opt/typosentinel-demo
   
   # Copy your files here
   # Then run:
   docker-compose up -d
   ```

## Configuration

### Environment Variables

You can customize the deployment by modifying the `docker-compose.yml` file:

```yaml
environment:
  - NGINX_HOST=your-domain.com
  - NGINX_PORT=80
```

### SSL Configuration

For HTTPS support:

1. **Obtain SSL certificates** (Let's Encrypt recommended):
   ```bash
   certbot certonly --standalone -d your-domain.com
   ```

2. **Copy certificates**:
   ```bash
   mkdir -p /opt/typosentinel-demo/ssl
   cp /etc/letsencrypt/live/your-domain.com/fullchain.pem /opt/typosentinel-demo/ssl/cert.pem
   cp /etc/letsencrypt/live/your-domain.com/privkey.pem /opt/typosentinel-demo/ssl/key.pem
   ```

3. **Update nginx.conf** to enable HTTPS (uncomment HTTPS server block)

4. **Restart the container**:
   ```bash
   docker-compose restart web
   ```

### Custom Domain Setup

1. **Point your domain to your VPS IP**:
   - Create an A record: `demo.yourdomain.com` → `your-vps-ip`

2. **Update the deployment script**:
   ```bash
   ./deploy.sh --domain demo.yourdomain.com --email your@email.com
   ```

## Management Commands

### View Logs
```bash
cd /opt/typosentinel-demo
docker-compose logs -f web
```

### Restart Service
```bash
cd /opt/typosentinel-demo
docker-compose restart web
```

### Update Demo
```bash
cd /opt/typosentinel-demo
# Upload new files
docker-compose build
docker-compose up -d
```

### Stop Service
```bash
cd /opt/typosentinel-demo
docker-compose down
```

### Check Status
```bash
cd /opt/typosentinel-demo
docker-compose ps
```

## Monitoring

The deployment script sets up basic monitoring:

- **Health checks**: Automatic container restart if unhealthy
- **Log rotation**: Prevents log files from growing too large
- **Disk space monitoring**: Automatic cleanup when disk usage is high
- **Service monitoring**: Automatic restart if service goes down

### View Monitoring Logs
```bash
tail -f /var/log/typosentinel-monitor.log
```

## Customization

### Branding

To customize the demo for your brand:

1. **Update colors** in `styles.css`:
   ```css
   :root {
     --primary-color: #your-brand-color;
     --secondary-color: #your-secondary-color;
   }
   ```

2. **Replace logo** and company information in `index.html`

3. **Update contact information** in the contact section

### Adding Real Backend

To connect to a real TypoSentinel backend:

1. **Update API endpoints** in `script.js`:
   ```javascript
   const API_BASE_URL = 'https://your-api-domain.com/api/v1';
   ```

2. **Uncomment backend service** in `docker-compose.yml`

3. **Update nginx configuration** to proxy API requests

## Security Considerations

### Production Security

- **Firewall**: Only expose ports 80, 443, and 22 (SSH)
- **SSL/TLS**: Always use HTTPS in production
- **Updates**: Keep Docker and system packages updated
- **Monitoring**: Set up proper logging and monitoring
- **Backups**: Regular backups of configuration and data

### Rate Limiting

The nginx configuration includes rate limiting:
- API endpoints: 10 requests/second
- General requests: 1 request/second

## Troubleshooting

### Common Issues

1. **Port already in use**:
   ```bash
   sudo lsof -i :80
   sudo lsof -i :443
   # Kill conflicting processes or change ports
   ```

2. **Docker permission denied**:
   ```bash
   sudo usermod -aG docker $USER
   # Logout and login again
   ```

3. **SSL certificate issues**:
   ```bash
   # Check certificate validity
   openssl x509 -in /opt/typosentinel-demo/ssl/cert.pem -text -noout
   ```

4. **Container won't start**:
   ```bash
   # Check logs
   docker-compose logs web
   
   # Check container status
   docker-compose ps
   ```

### Performance Optimization

1. **Enable gzip compression** (already configured in nginx.conf)
2. **Use CDN** for static assets in production
3. **Optimize images** and use WebP format when possible
4. **Enable browser caching** (configured in nginx.conf)

## File Structure

```
web-demo/
├── index.html          # Main HTML file
├── styles.css          # CSS styles and animations
├── script.js           # JavaScript functionality
├── Dockerfile          # Docker container configuration
├── nginx.conf          # Nginx web server configuration
├── docker-compose.yml  # Docker Compose orchestration
├── deploy.sh           # Automated deployment script
└── README.md           # This file
```

## Support

For deployment assistance or customization requests:

- **Email**: support@typosentinel.com
- **Documentation**: Check the main TypoSentinel documentation
- **Issues**: Report any bugs or feature requests

## License

This demo is part of the TypoSentinel project. Please refer to the main project license for usage terms.

---

**Note**: This is a demonstration environment. For production use of TypoSentinel, please refer to the main project documentation and deployment guides.