# Typosentinel Enterprise - Production Deployment

🔒 **Enterprise-grade security scanner for supply chain protection and dependency analysis**

## Overview

Typosentinel Enterprise is a comprehensive security solution designed to protect your software supply chain from typosquatting attacks, malicious dependencies, and security vulnerabilities. This production-ready deployment includes advanced ML algorithms, SBOM generation, and enterprise monitoring capabilities.

## 🚀 Quick Start

### Prerequisites

- Docker and Docker Compose (recommended)
- Node.js 18+ (for manual installation)
- Go 1.21+ (for manual installation)
- Linux/macOS/Windows with WSL2

### Option 1: Docker Deployment (Recommended)

```bash
# Clone and navigate to production directory
cd production/

# Configure environment variables
cp .env.production .env
# Edit .env file with your specific settings

# Deploy with Docker Compose
docker-compose -f docker-compose.production.yml up -d

# Check service status
docker-compose -f docker-compose.production.yml ps
```

### Option 2: Manual Deployment

```bash
# Make deployment script executable
chmod +x deploy-production.sh

# Run deployment script
./deploy-production.sh

# Start Typosentinel
./typosentinel server --config=infrastructure/security/enterprise-security-config.yaml
```

## 🏗️ Architecture

### Core Components

- **Main Application**: Typosentinel security scanner
- **Analytics Service**: Advanced threat analysis and ML algorithms
- **Auth Service**: Enterprise authentication and authorization
- **Notification Service**: Real-time alerts and notifications
- **Payment Service**: Enterprise licensing and billing
- **User Service**: User management and access control

### Infrastructure

- **Database**: PostgreSQL for persistent data
- **Cache**: Redis for performance optimization
- **Monitoring**: Prometheus + Grafana
- **Reverse Proxy**: Nginx with SSL termination
- **Logging**: Centralized logging with structured JSON

## 🔧 Configuration

### Environment Variables

Key configuration options in `.env.production`:

```bash
# Security Settings
SECURITY_LEVEL=enterprise
ENABLE_DEEP_SCAN=true
ENABLE_THREAT_INTEL=true

# Performance
MAX_CONCURRENT_SCANS=10
SCAN_TIMEOUT=300

# SSL/TLS
SSL_ENABLED=true
SSL_CERT_PATH=certificates/server.crt
SSL_KEY_PATH=certificates/server.key
```

### SSL Certificates

1. Place your SSL certificates in the `certificates/` directory:
   - `server.crt` - SSL certificate
   - `server.key` - Private key
   - `ca.crt` - Certificate Authority (optional)

2. Update paths in `.env.production` if needed

## 🔍 Usage

### Security Scanning

```bash
# Basic security scan
./typosentinel supply-chain scan-advanced

# Deep scan with all features
./typosentinel supply-chain scan-advanced --deep --threat-intel --zero-day

# Generate SBOM
./typosentinel supply-chain scan-advanced --output json > sbom.json

# Dependency graph analysis
./typosentinel graph export --format json --include-dev
```

### API Endpoints

- **Main API**: `https://your-domain:3000/api`
- **Health Check**: `https://your-domain:8080/health`
- **Metrics**: `https://your-domain:9090/metrics`
- **Grafana Dashboard**: `https://your-domain:3010`

### Web Interface

Access the web dashboard at `https://your-domain` (port 80/443 via Nginx)

Default credentials:
- **Grafana**: admin / admin123 (change immediately)
- **Application**: Configure via auth service

## 📊 Monitoring

### Grafana Dashboards

1. **Security Overview**: Real-time threat detection metrics
2. **Performance Metrics**: Scan performance and system health
3. **Supply Chain Analysis**: Dependency risk assessment
4. **System Health**: Infrastructure monitoring

### Prometheus Metrics

- Scan execution times
- Threat detection rates
- System resource usage
- API response times
- Error rates and alerts

### Log Files

- **Application**: `logs/typosentinel.log`
- **Audit**: `logs/audit.log`
- **Nginx**: `logs/nginx/access.log`, `logs/nginx/error.log`

## 🔒 Security Features

### Advanced ML Algorithms

- **Neural Ensemble**: Multi-model threat detection
- **AICC Algorithm**: Advanced Information Criterion Classification
- **GTR Algorithm**: Graph-based Threat Recognition
- **Benchmark Suite**: Comprehensive security testing

### Enterprise Capabilities

- **SBOM Generation**: Software Bill of Materials
- **Supply Chain Analysis**: End-to-end dependency tracking
- **Build Integrity Verification**: Tamper detection
- **Zero-day Detection**: Unknown threat identification
- **Honeypot Detection**: Malicious package identification

## 🚨 Alerting

### Notification Channels

- **Webhook**: Custom HTTP endpoints
- **Slack**: Team notifications
- **Email**: SMTP-based alerts
- **Dashboard**: Real-time web notifications

### Alert Types

- **Critical**: Immediate security threats
- **High**: Significant vulnerabilities
- **Medium**: Potential risks
- **Low**: Informational alerts

## 🔧 Maintenance

### Backup

```bash
# Database backup
docker-compose exec postgres pg_dump -U typosentinel typosentinel > backup.sql

# Configuration backup
tar -czf config-backup.tar.gz infrastructure/ shared/ .env.production
```

### Updates

```bash
# Pull latest images
docker-compose -f docker-compose.production.yml pull

# Restart services
docker-compose -f docker-compose.production.yml up -d
```

### Health Checks

```bash
# Check all services
docker-compose -f docker-compose.production.yml ps

# View logs
docker-compose -f docker-compose.production.yml logs -f typosentinel

# Manual health check
curl -f http://localhost:8080/health
```

## 🐛 Troubleshooting

### Common Issues

1. **Service won't start**:
   - Check logs: `docker-compose logs service-name`
   - Verify environment variables
   - Ensure ports are available

2. **SSL certificate errors**:
   - Verify certificate paths
   - Check certificate validity
   - Ensure proper permissions

3. **Database connection issues**:
   - Check PostgreSQL status
   - Verify credentials
   - Ensure network connectivity

### Performance Tuning

- Adjust `MAX_CONCURRENT_SCANS` based on system resources
- Configure cache TTL for optimal performance
- Monitor memory usage and adjust container limits

## 📞 Support

### Enterprise Support

- **Documentation**: Full enterprise documentation available
- **Technical Support**: 24/7 enterprise support
- **Professional Services**: Implementation and consulting

### Community

- **GitHub Issues**: Bug reports and feature requests
- **Documentation**: Online documentation portal
- **Community Forum**: User discussions and support

## 📄 License

Typosentinel Enterprise - Commercial License
See LICENSE file for details.

---

**🔒 Secure your supply chain with Typosentinel Enterprise**

For enterprise inquiries and support, contact our team.
