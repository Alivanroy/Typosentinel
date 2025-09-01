# Typosentinel Enterprise - Production Deployment Guide

## 📋 Pre-Deployment Checklist

### System Requirements

**Minimum Requirements:**
- CPU: 4 cores (8 recommended)
- RAM: 8GB (16GB recommended)
- Storage: 50GB SSD (100GB recommended)
- Network: 1Gbps connection

**Supported Operating Systems:**
- Ubuntu 20.04+ / RHEL 8+ / CentOS 8+
- macOS 12+ (development only)
- Windows Server 2019+ with WSL2

### Prerequisites Installation

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install -y docker.io docker-compose-plugin git curl wget
sudo systemctl enable docker
sudo systemctl start docker
sudo usermod -aG docker $USER

# RHEL/CentOS
sudo dnf install -y docker docker-compose git curl wget
sudo systemctl enable docker
sudo systemctl start docker
sudo usermod -aG docker $USER

# Verify installation
docker --version
docker compose version
```

## 🚀 Deployment Methods

### Method 1: Docker Compose (Recommended)

#### Step 1: Environment Setup

```bash
# Create production directory
mkdir -p /opt/typosentinel-enterprise
cd /opt/typosentinel-enterprise

# Copy production files
cp -r /path/to/production/* .

# Set proper permissions
sudo chown -R $USER:$USER .
chmod +x deploy-production.sh
```

#### Step 2: Configuration

```bash
# Copy and customize environment file
cp .env.production .env

# Edit configuration (required)
nano .env
```

**Critical Environment Variables:**
```bash
# Security (REQUIRED)
JWT_SECRET="your-super-secure-jwt-secret-minimum-32-chars"
ENCRYPTION_KEY="your-encryption-key-32-chars-long"

# Database (REQUIRED)
POSTGRES_PASSWORD="secure-database-password"
REDIS_PASSWORD="secure-redis-password"

# SSL/TLS (REQUIRED for production)
SSL_ENABLED=true
SSL_CERT_PATH=certificates/server.crt
SSL_KEY_PATH=certificates/server.key

# Domain configuration
DOMAIN_NAME="your-domain.com"
API_BASE_URL="https://your-domain.com/api"
```

#### Step 3: SSL Certificate Setup

**Option A: Let's Encrypt (Recommended)**
```bash
# Install certbot
sudo apt install certbot

# Generate certificates
sudo certbot certonly --standalone -d your-domain.com

# Copy certificates
sudo mkdir -p certificates
sudo cp /etc/letsencrypt/live/your-domain.com/fullchain.pem certificates/server.crt
sudo cp /etc/letsencrypt/live/your-domain.com/privkey.pem certificates/server.key
sudo chown $USER:$USER certificates/*
```

**Option B: Self-Signed (Development Only)**
```bash
mkdir -p certificates
openssl req -x509 -newkey rsa:4096 -keyout certificates/server.key \
  -out certificates/server.crt -days 365 -nodes \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=your-domain.com"
```

#### Step 4: Deploy Services

```bash
# Start all services
docker compose -f docker-compose.production.yml up -d

# Verify deployment
docker compose -f docker-compose.production.yml ps
docker compose -f docker-compose.production.yml logs
```

#### Step 5: Health Verification

```bash
# Check service health
curl -f http://localhost:8080/health
curl -f https://your-domain.com/health

# Check database connectivity
docker compose exec postgres pg_isready -U typosentinel

# Check Redis connectivity
docker compose exec redis redis-cli ping
```

### Method 2: Manual Installation

#### Step 1: Install Dependencies

```bash
# Install Node.js 18+
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs

# Install Go 1.21+
wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc

# Install PostgreSQL
sudo apt install postgresql postgresql-contrib
sudo systemctl enable postgresql
sudo systemctl start postgresql

# Install Redis
sudo apt install redis-server
sudo systemctl enable redis-server
sudo systemctl start redis-server
```

#### Step 2: Database Setup

```bash
# Create database and user
sudo -u postgres psql << EOF
CREATE DATABASE typosentinel;
CREATE USER typosentinel WITH PASSWORD 'your-secure-password';
GRANT ALL PRIVILEGES ON DATABASE typosentinel TO typosentinel;
\q
EOF
```

#### Step 3: Application Setup

```bash
# Run deployment script
./deploy-production.sh

# Start services manually
./typosentinel server --config=infrastructure/security/enterprise-security-config.yaml &

# Start microservices
cd microservices/analytics && npm start &
cd microservices/auth && npm start &
cd microservices/notification && npm start &
cd microservices/payment && go run main.go &
cd microservices/user && go run main.go &
```

## 🔧 Production Configuration

### Security Hardening

#### 1. Firewall Configuration

```bash
# Ubuntu UFW
sudo ufw enable
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 80/tcp    # HTTP
sudo ufw allow 443/tcp   # HTTPS
sudo ufw allow 8080/tcp  # API (internal)
sudo ufw deny 5432/tcp   # PostgreSQL (block external)
sudo ufw deny 6379/tcp   # Redis (block external)

# RHEL/CentOS firewalld
sudo firewall-cmd --permanent --add-service=ssh
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --permanent --add-port=8080/tcp
sudo firewall-cmd --reload
```

#### 2. System Security

```bash
# Disable root login
sudo sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
sudo systemctl restart sshd

# Enable automatic security updates
sudo apt install unattended-upgrades
sudo dpkg-reconfigure -plow unattended-upgrades

# Set up fail2ban
sudo apt install fail2ban
sudo systemctl enable fail2ban
sudo systemctl start fail2ban
```

#### 3. Application Security

```bash
# Set secure file permissions
chmod 600 .env certificates/server.key
chmod 644 certificates/server.crt
chown root:root certificates/*

# Create dedicated user
sudo useradd -r -s /bin/false typosentinel
sudo chown -R typosentinel:typosentinel /opt/typosentinel-enterprise
```

### Performance Optimization

#### 1. System Tuning

```bash
# Increase file descriptor limits
echo "* soft nofile 65536" | sudo tee -a /etc/security/limits.conf
echo "* hard nofile 65536" | sudo tee -a /etc/security/limits.conf

# Optimize kernel parameters
echo "net.core.somaxconn = 65536" | sudo tee -a /etc/sysctl.conf
echo "net.ipv4.tcp_max_syn_backlog = 65536" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

#### 2. Database Optimization

```bash
# PostgreSQL tuning
sudo -u postgres psql << EOF
ALTER SYSTEM SET shared_buffers = '256MB';
ALTER SYSTEM SET effective_cache_size = '1GB';
ALTER SYSTEM SET maintenance_work_mem = '64MB';
ALTER SYSTEM SET checkpoint_completion_target = 0.9;
ALTER SYSTEM SET wal_buffers = '16MB';
SELECT pg_reload_conf();
EOF
```

#### 3. Application Tuning

```yaml
# Update .env for performance
MAX_CONCURRENT_SCANS=20
WORKER_POOL_SIZE=10
CACHE_TTL=3600
DATABASE_POOL_SIZE=20
REDIS_POOL_SIZE=10
```

## 📊 Monitoring Setup

### Prometheus Configuration

```yaml
# prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'typosentinel'
    static_configs:
      - targets: ['localhost:8080']
    metrics_path: '/metrics'
    scrape_interval: 10s

  - job_name: 'postgres'
    static_configs:
      - targets: ['localhost:9187']

  - job_name: 'redis'
    static_configs:
      - targets: ['localhost:9121']

  - job_name: 'node-exporter'
    static_configs:
      - targets: ['localhost:9100']
```

### Grafana Dashboard Import

```bash
# Access Grafana
open http://localhost:3010
# Login: admin / admin123

# Import dashboards
# 1. Go to + > Import
# 2. Upload dashboard JSON files from infrastructure/monitoring/grafana/
# 3. Configure data sources
```

### Log Management

```bash
# Configure log rotation
sudo tee /etc/logrotate.d/typosentinel << EOF
/opt/typosentinel-enterprise/logs/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 typosentinel typosentinel
    postrotate
        systemctl reload typosentinel
    endscript
}
EOF
```

## 🔄 Backup and Recovery

### Automated Backup Script

```bash
#!/bin/bash
# backup.sh

BACKUP_DIR="/opt/backups/typosentinel"
DATE=$(date +%Y%m%d_%H%M%S)

# Create backup directory
mkdir -p $BACKUP_DIR

# Database backup
docker compose exec -T postgres pg_dump -U typosentinel typosentinel | gzip > $BACKUP_DIR/database_$DATE.sql.gz

# Configuration backup
tar -czf $BACKUP_DIR/config_$DATE.tar.gz .env infrastructure/ shared/

# Application data backup
tar -czf $BACKUP_DIR/data_$DATE.tar.gz logs/ certificates/

# Cleanup old backups (keep 30 days)
find $BACKUP_DIR -name "*.gz" -mtime +30 -delete

echo "Backup completed: $DATE"
```

### Recovery Procedures

```bash
# Database recovery
gunzip -c /opt/backups/typosentinel/database_YYYYMMDD_HHMMSS.sql.gz | \
  docker compose exec -T postgres psql -U typosentinel typosentinel

# Configuration recovery
tar -xzf /opt/backups/typosentinel/config_YYYYMMDD_HHMMSS.tar.gz

# Restart services
docker compose -f docker-compose.production.yml restart
```

## 🚨 Troubleshooting

### Common Issues

#### 1. Service Won't Start

```bash
# Check logs
docker compose logs typosentinel
docker compose logs postgres
docker compose logs redis

# Check ports
sudo netstat -tlnp | grep :8080
sudo netstat -tlnp | grep :5432

# Check disk space
df -h

# Check memory
free -h
```

#### 2. Database Connection Issues

```bash
# Test database connection
docker compose exec postgres pg_isready -U typosentinel

# Check database logs
docker compose logs postgres

# Verify credentials
grep POSTGRES .env
```

#### 3. SSL Certificate Problems

```bash
# Check certificate validity
openssl x509 -in certificates/server.crt -text -noout

# Test SSL connection
openssl s_client -connect your-domain.com:443

# Verify certificate permissions
ls -la certificates/
```

#### 4. Performance Issues

```bash
# Check system resources
top
htop
iostat 1

# Check application metrics
curl http://localhost:8080/metrics

# Analyze slow queries
docker compose exec postgres psql -U typosentinel -c "SELECT query, mean_time FROM pg_stat_statements ORDER BY mean_time DESC LIMIT 10;"
```

### Emergency Procedures

#### Service Recovery

```bash
# Quick restart
docker compose -f docker-compose.production.yml restart

# Full rebuild
docker compose -f docker-compose.production.yml down
docker compose -f docker-compose.production.yml up -d --build

# Emergency stop
docker compose -f docker-compose.production.yml down
```

#### Data Recovery

```bash
# Restore from latest backup
./restore.sh latest

# Point-in-time recovery
./restore.sh 20240115_143000
```

## 📞 Support and Maintenance

### Regular Maintenance Tasks

**Daily:**
- Monitor system health
- Check log files for errors
- Verify backup completion

**Weekly:**
- Update security patches
- Review performance metrics
- Clean up old logs

**Monthly:**
- Update SSL certificates
- Review security configurations
- Performance optimization review

### Support Contacts

- **Technical Support**: support@typosentinel.com
- **Security Issues**: security@typosentinel.com
- **Emergency**: +1-800-TYPO-911

### Documentation

- **API Documentation**: https://docs.typosentinel.com/api
- **User Guide**: https://docs.typosentinel.com/guide
- **Security Best Practices**: https://docs.typosentinel.com/security

---

**🔒 Typosentinel Enterprise - Secure by Design**

For additional support and enterprise services, contact our team.