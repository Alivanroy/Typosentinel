# Deployment Guide

This document provides comprehensive guidance for deploying Typosentinel in various environments, from development to production.

## Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Environment Setup](#environment-setup)
- [Deployment Methods](#deployment-methods)
- [Configuration](#configuration)
- [Database Setup](#database-setup)
- [Security Configuration](#security-configuration)
- [Monitoring and Logging](#monitoring-and-logging)
- [Scaling and Performance](#scaling-and-performance)
- [Backup and Recovery](#backup-and-recovery)
- [Troubleshooting](#troubleshooting)
- [Maintenance](#maintenance)

## Overview

Typosentinel can be deployed in multiple ways depending on your infrastructure requirements:

- **Docker Containers**: Recommended for most deployments
- **Kubernetes**: For scalable, orchestrated deployments
- **Binary Deployment**: Direct installation on servers
- **Cloud Platforms**: AWS, GCP, Azure native services

## Prerequisites

### System Requirements

**Minimum Requirements**:
- CPU: 2 cores
- RAM: 4GB
- Storage: 20GB SSD
- Network: 100 Mbps

**Recommended Requirements**:
- CPU: 4+ cores
- RAM: 8GB+
- Storage: 100GB+ SSD
- Network: 1 Gbps

**Production Requirements**:
- CPU: 8+ cores
- RAM: 16GB+
- Storage: 500GB+ SSD
- Network: 10 Gbps
- Load Balancer
- Database cluster
- Redis cluster

### Software Dependencies

- **Go**: 1.21+ (for building from source)
- **Docker**: 20.10+ (for containerized deployment)
- **PostgreSQL**: 13+ (primary database)
- **Redis**: 6+ (caching and sessions)
- **Nginx**: 1.20+ (reverse proxy, optional)

### External Services

- **Package Registries**: npm, PyPI, RubyGems API access
- **Threat Intelligence**: External threat feeds (optional)
- **Monitoring**: Prometheus, Grafana (recommended)
- **Logging**: ELK Stack or similar (recommended)

## Environment Setup

### Development Environment

```bash
# Clone repository
git clone https://github.com/typosentinel/typosentinel.git
cd typosentinel

# Install dependencies
go mod download

# Setup development environment
make dev-setup

# Run with development configuration
make run-dev
```

### Staging Environment

```bash
# Build application
make build

# Run with staging configuration
./bin/typosentinel --config=configs/staging.yaml
```

### Production Environment

See specific deployment methods below.

## Deployment Methods

### Docker Deployment

#### Single Container

```bash
# Build image
docker build -t typosentinel:latest .

# Run container
docker run -d \
  --name typosentinel \
  -p 8080:8080 \
  -e DATABASE_URL="postgres://user:pass@db:5432/typosentinel" \
  -e REDIS_URL="redis://redis:6379" \
  -v /path/to/config:/app/config \
  typosentinel:latest
```

#### Docker Compose

```yaml
# docker-compose.yml
version: '3.8'

services:
  typosentinel:
    build: .
    ports:
      - "8080:8080"
    environment:
      - DATABASE_URL=postgres://typosentinel:password@postgres:5432/typosentinel
      - REDIS_URL=redis://redis:6379
    depends_on:
      - postgres
      - redis
    volumes:
      - ./configs/production.yaml:/app/config/config.yaml
      - ./logs:/app/logs
    restart: unless-stopped

  postgres:
    image: postgres:15
    environment:
      - POSTGRES_DB=typosentinel
      - POSTGRES_USER=typosentinel
      - POSTGRES_PASSWORD=password
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./scripts/init.sql:/docker-entrypoint-initdb.d/init.sql
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    command: redis-server --appendonly yes
    volumes:
      - redis_data:/data
    restart: unless-stopped

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./ssl:/etc/nginx/ssl
    depends_on:
      - typosentinel
    restart: unless-stopped

volumes:
  postgres_data:
  redis_data:
```

```bash
# Deploy with Docker Compose
docker-compose up -d

# View logs
docker-compose logs -f typosentinel

# Scale application
docker-compose up -d --scale typosentinel=3
```

### Kubernetes Deployment

#### Namespace and ConfigMap

```yaml
# k8s/namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: typosentinel
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: typosentinel-config
  namespace: typosentinel
data:
  config.yaml: |
    app:
      name: "typosentinel"
      version: "1.0.0"
      environment: "production"
    server:
      host: "0.0.0.0"
      port: 8080
      read_timeout: "30s"
      write_timeout: "30s"
    database:
      host: "postgres-service"
      port: 5432
      name: "typosentinel"
      user: "typosentinel"
      ssl_mode: "require"
    redis:
      host: "redis-service"
      port: 6379
      db: 0
```

#### Secrets

```yaml
# k8s/secrets.yaml
apiVersion: v1
kind: Secret
metadata:
  name: typosentinel-secrets
  namespace: typosentinel
type: Opaque
data:
  database-password: <base64-encoded-password>
  redis-password: <base64-encoded-password>
  jwt-secret: <base64-encoded-jwt-secret>
  api-key: <base64-encoded-api-key>
```

#### Deployment

```yaml
# k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: typosentinel
  namespace: typosentinel
  labels:
    app: typosentinel
spec:
  replicas: 3
  selector:
    matchLabels:
      app: typosentinel
  template:
    metadata:
      labels:
        app: typosentinel
    spec:
      containers:
      - name: typosentinel
        image: typosentinel:latest
        ports:
        - containerPort: 8080
        env:
        - name: DATABASE_PASSWORD
          valueFrom:
            secretKeyRef:
              name: typosentinel-secrets
              key: database-password
        - name: REDIS_PASSWORD
          valueFrom:
            secretKeyRef:
              name: typosentinel-secrets
              key: redis-password
        volumeMounts:
        - name: config
          mountPath: /app/config
        - name: logs
          mountPath: /app/logs
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "1Gi"
            cpu: "500m"
      volumes:
      - name: config
        configMap:
          name: typosentinel-config
      - name: logs
        emptyDir: {}
```

#### Service and Ingress

```yaml
# k8s/service.yaml
apiVersion: v1
kind: Service
metadata:
  name: typosentinel-service
  namespace: typosentinel
spec:
  selector:
    app: typosentinel
  ports:
  - protocol: TCP
    port: 80
    targetPort: 8080
  type: ClusterIP
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: typosentinel-ingress
  namespace: typosentinel
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/rate-limit: "100"
spec:
  tls:
  - hosts:
    - api.typosentinel.com
    secretName: typosentinel-tls
  rules:
  - host: api.typosentinel.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: typosentinel-service
            port:
              number: 80
```

```bash
# Deploy to Kubernetes
kubectl apply -f k8s/

# Check deployment status
kubectl get pods -n typosentinel
kubectl get services -n typosentinel
kubectl get ingress -n typosentinel

# View logs
kubectl logs -f deployment/typosentinel -n typosentinel

# Scale deployment
kubectl scale deployment typosentinel --replicas=5 -n typosentinel
```

### Cloud Platform Deployment

#### AWS ECS

```json
{
  "family": "typosentinel",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "1024",
  "memory": "2048",
  "executionRoleArn": "arn:aws:iam::account:role/ecsTaskExecutionRole",
  "taskRoleArn": "arn:aws:iam::account:role/ecsTaskRole",
  "containerDefinitions": [
    {
      "name": "typosentinel",
      "image": "your-account.dkr.ecr.region.amazonaws.com/typosentinel:latest",
      "portMappings": [
        {
          "containerPort": 8080,
          "protocol": "tcp"
        }
      ],
      "environment": [
        {
          "name": "DATABASE_URL",
          "value": "postgres://user:pass@rds-endpoint:5432/typosentinel"
        }
      ],
      "secrets": [
        {
          "name": "DATABASE_PASSWORD",
          "valueFrom": "arn:aws:secretsmanager:region:account:secret:typosentinel/db-password"
        }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/typosentinel",
          "awslogs-region": "us-west-2",
          "awslogs-stream-prefix": "ecs"
        }
      },
      "healthCheck": {
        "command": ["CMD-SHELL", "curl -f http://localhost:8080/health || exit 1"],
        "interval": 30,
        "timeout": 5,
        "retries": 3
      }
    }
  ]
}
```

#### Google Cloud Run

```yaml
# cloudrun.yaml
apiVersion: serving.knative.dev/v1
kind: Service
metadata:
  name: typosentinel
  annotations:
    run.googleapis.com/ingress: all
spec:
  template:
    metadata:
      annotations:
        autoscaling.knative.dev/maxScale: "10"
        run.googleapis.com/cpu-throttling: "false"
        run.googleapis.com/execution-environment: gen2
    spec:
      containerConcurrency: 100
      timeoutSeconds: 300
      containers:
      - image: gcr.io/project-id/typosentinel:latest
        ports:
        - containerPort: 8080
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: database-url
              key: url
        resources:
          limits:
            cpu: "2"
            memory: "4Gi"
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
```

```bash
# Deploy to Cloud Run
gcloud run deploy typosentinel \
  --image gcr.io/project-id/typosentinel:latest \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated \
  --set-env-vars DATABASE_URL="postgres://..." \
  --memory 4Gi \
  --cpu 2 \
  --max-instances 10
```

## Configuration

### Environment Variables

```bash
# Application
APP_NAME=typosentinel
APP_VERSION=1.0.0
APP_ENVIRONMENT=production

# Server
SERVER_HOST=0.0.0.0
SERVER_PORT=8080
SERVER_READ_TIMEOUT=30s
SERVER_WRITE_TIMEOUT=30s

# Database
DATABASE_HOST=localhost
DATABASE_PORT=5432
DATABASE_NAME=typosentinel
DATABASE_USER=typosentinel
DATABASE_PASSWORD=secure_password
DATABASE_SSL_MODE=require

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=redis_password
REDIS_DB=0

# Security
JWT_SECRET=your_jwt_secret_key
API_KEY=your_api_key
ENCRYPTION_KEY=your_encryption_key

# External Services
NPM_REGISTRY_URL=https://registry.npmjs.org
PYPI_REGISTRY_URL=https://pypi.org
RUBYGEMS_REGISTRY_URL=https://rubygems.org

# Monitoring
PROMETHEUS_ENABLED=true
PROMETHEUS_PORT=9090
JAEGER_ENDPOINT=http://jaeger:14268/api/traces

# Logging
LOG_LEVEL=info
LOG_FORMAT=json
LOG_OUTPUT=stdout
```

### Configuration Files

**Production Configuration** (`configs/production.yaml`):

```yaml
app:
  name: "typosentinel"
  version: "1.0.0"
  environment: "production"
  debug: false

server:
  host: "0.0.0.0"
  port: 8080
  read_timeout: "30s"
  write_timeout: "30s"
  idle_timeout: "120s"
  max_header_bytes: 1048576
  tls:
    enabled: true
    cert_file: "/etc/ssl/certs/typosentinel.crt"
    key_file: "/etc/ssl/private/typosentinel.key"

database:
  host: "postgres-cluster.internal"
  port: 5432
  name: "typosentinel"
  user: "typosentinel"
  password: "${DATABASE_PASSWORD}"
  ssl_mode: "require"
  max_open_conns: 25
  max_idle_conns: 5
  conn_max_lifetime: "5m"
  conn_max_idle_time: "1m"

redis:
  host: "redis-cluster.internal"
  port: 6379
  password: "${REDIS_PASSWORD}"
  db: 0
  pool_size: 10
  min_idle_conns: 5
  dial_timeout: "5s"
  read_timeout: "3s"
  write_timeout: "3s"
  pool_timeout: "4s"
  idle_timeout: "5m"

logging:
  level: "info"
  format: "json"
  output: "file"
  file:
    path: "/var/log/typosentinel/app.log"
    max_size: 100
    max_backups: 10
    max_age: 30
    compress: true

metrics:
  enabled: true
  prometheus:
    enabled: true
    port: 9090
    path: "/metrics"
  statsd:
    enabled: false

security:
  jwt:
    secret: "${JWT_SECRET}"
    expiry: "24h"
    refresh_expiry: "168h"
  api:
    key: "${API_KEY}"
    rate_limit: 1000
    rate_window: "1h"
  encryption:
    key: "${ENCRYPTION_KEY}"
    algorithm: "AES-256-GCM"

ml:
  enabled: true
  model_path: "/app/models"
  batch_size: 100
  timeout: "30s"
  cache_ttl: "1h"

scanner:
  workers: 10
  timeout: "5m"
  retry_attempts: 3
  retry_delay: "1s"
  max_file_size: 10485760
  allowed_extensions: [".js", ".py", ".rb", ".go", ".java"]

api:
  rate_limit:
    requests_per_hour: 1000
    burst: 100
  cors:
    allowed_origins: ["https://dashboard.typosentinel.com"]
    allowed_methods: ["GET", "POST", "PUT", "DELETE"]
    allowed_headers: ["Content-Type", "Authorization", "X-API-Key"]
  timeout: "30s"

feature_flags:
  ml_analysis: true
  deep_scanning: true
  bulk_operations: true
  webhooks: true
  analytics: true
```

## Database Setup

### PostgreSQL Configuration

```sql
-- Create database and user
CREATE DATABASE typosentinel;
CREATE USER typosentinel WITH ENCRYPTED PASSWORD 'secure_password';
GRANT ALL PRIVILEGES ON DATABASE typosentinel TO typosentinel;

-- Connect to typosentinel database
\c typosentinel;

-- Grant schema privileges
GRANT ALL ON SCHEMA public TO typosentinel;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO typosentinel;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO typosentinel;

-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";
CREATE EXTENSION IF NOT EXISTS "btree_gin";
```

### Database Migration

```bash
# Run migrations
./bin/typosentinel migrate up

# Check migration status
./bin/typosentinel migrate status

# Rollback migration
./bin/typosentinel migrate down 1
```

### Database Backup

```bash
#!/bin/bash
# backup.sh

DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/backups/postgres"
DB_NAME="typosentinel"
DB_USER="typosentinel"
DB_HOST="localhost"

# Create backup directory
mkdir -p $BACKUP_DIR

# Create backup
pg_dump -h $DB_HOST -U $DB_USER -d $DB_NAME -F c -b -v -f $BACKUP_DIR/typosentinel_$DATE.backup

# Compress backup
gzip $BACKUP_DIR/typosentinel_$DATE.backup

# Remove backups older than 30 days
find $BACKUP_DIR -name "*.backup.gz" -mtime +30 -delete

echo "Backup completed: typosentinel_$DATE.backup.gz"
```

## Security Configuration

### SSL/TLS Setup

```bash
# Generate SSL certificate (for development)
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes

# For production, use Let's Encrypt
certbot certonly --nginx -d api.typosentinel.com
```

### Nginx Configuration

```nginx
# /etc/nginx/sites-available/typosentinel
upstream typosentinel {
    least_conn;
    server 127.0.0.1:8080 max_fails=3 fail_timeout=30s;
    server 127.0.0.1:8081 max_fails=3 fail_timeout=30s;
    server 127.0.0.1:8082 max_fails=3 fail_timeout=30s;
}

server {
    listen 80;
    server_name api.typosentinel.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name api.typosentinel.com;

    ssl_certificate /etc/letsencrypt/live/api.typosentinel.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/api.typosentinel.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_req zone=api burst=20 nodelay;

    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;

    location / {
        proxy_pass http://typosentinel;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_connect_timeout 30s;
        proxy_send_timeout 30s;
        proxy_read_timeout 30s;
        proxy_buffering on;
        proxy_buffer_size 4k;
        proxy_buffers 8 4k;
    }

    location /health {
        proxy_pass http://typosentinel;
        access_log off;
    }

    location /metrics {
        proxy_pass http://typosentinel;
        allow 10.0.0.0/8;
        allow 172.16.0.0/12;
        allow 192.168.0.0/16;
        deny all;
    }
}
```

### Firewall Configuration

```bash
# UFW (Ubuntu)
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow from 10.0.0.0/8 to any port 9090  # Prometheus
sudo ufw enable

# iptables
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -s 10.0.0.0/8 -p tcp --dport 9090 -j ACCEPT
iptables -A INPUT -j DROP
```

## Monitoring and Logging

### Prometheus Configuration

```yaml
# prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "typosentinel_rules.yml"

scrape_configs:
  - job_name: 'typosentinel'
    static_configs:
      - targets: ['localhost:9090']
    metrics_path: '/metrics'
    scrape_interval: 10s

  - job_name: 'postgres'
    static_configs:
      - targets: ['localhost:9187']

  - job_name: 'redis'
    static_configs:
      - targets: ['localhost:9121']

  - job_name: 'nginx'
    static_configs:
      - targets: ['localhost:9113']

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093
```

### Grafana Dashboard

```json
{
  "dashboard": {
    "title": "Typosentinel Monitoring",
    "panels": [
      {
        "title": "Request Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(http_requests_total[5m])",
            "legendFormat": "{{method}} {{status}}"
          }
        ]
      },
      {
        "title": "Response Time",
        "type": "graph",
        "targets": [
          {
            "expr": "histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))",
            "legendFormat": "95th percentile"
          }
        ]
      },
      {
        "title": "Error Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(http_requests_total{status=~\"5..\"}[5m])",
            "legendFormat": "5xx errors"
          }
        ]
      }
    ]
  }
}
```

### Log Aggregation

```yaml
# filebeat.yml
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/log/typosentinel/*.log
  fields:
    service: typosentinel
    environment: production
  fields_under_root: true
  json.keys_under_root: true
  json.add_error_key: true

output.elasticsearch:
  hosts: ["elasticsearch:9200"]
  index: "typosentinel-%{+yyyy.MM.dd}"

logging.level: info
logging.to_files: true
logging.files:
  path: /var/log/filebeat
  name: filebeat
  keepfiles: 7
  permissions: 0644
```

## Scaling and Performance

### Horizontal Scaling

```bash
# Docker Swarm
docker service create \
  --name typosentinel \
  --replicas 5 \
  --network typosentinel-network \
  --publish 8080:8080 \
  typosentinel:latest

# Scale service
docker service scale typosentinel=10
```

### Load Balancing

```yaml
# HAProxy configuration
global
    daemon
    maxconn 4096

defaults
    mode http
    timeout connect 5000ms
    timeout client 50000ms
    timeout server 50000ms
    option httplog
    option dontlognull
    option redispatch
    retries 3

frontend typosentinel_frontend
    bind *:80
    bind *:443 ssl crt /etc/ssl/certs/typosentinel.pem
    redirect scheme https if !{ ssl_fc }
    default_backend typosentinel_backend

backend typosentinel_backend
    balance roundrobin
    option httpchk GET /health
    server app1 10.0.1.10:8080 check
    server app2 10.0.1.11:8080 check
    server app3 10.0.1.12:8080 check
    server app4 10.0.1.13:8080 check
    server app5 10.0.1.14:8080 check
```

### Database Optimization

```sql
-- PostgreSQL performance tuning
-- postgresql.conf
shared_buffers = 256MB
effective_cache_size = 1GB
maintenance_work_mem = 64MB
checkpoint_completion_target = 0.9
wal_buffers = 16MB
default_statistics_target = 100
random_page_cost = 1.1
effective_io_concurrency = 200
work_mem = 4MB
min_wal_size = 1GB
max_wal_size = 4GB

-- Create indexes for performance
CREATE INDEX CONCURRENTLY idx_packages_name ON packages(name);
CREATE INDEX CONCURRENTLY idx_packages_registry ON packages(registry);
CREATE INDEX CONCURRENTLY idx_scans_created_at ON scans(created_at);
CREATE INDEX CONCURRENTLY idx_threats_severity ON threats(severity);

-- Analyze tables
ANALYZE;
```

## Backup and Recovery

### Automated Backup Script

```bash
#!/bin/bash
# backup-system.sh

set -e

BACKUP_DIR="/backups"
DATE=$(date +%Y%m%d_%H%M%S)
RETENTION_DAYS=30

# Create backup directory
mkdir -p $BACKUP_DIR/{postgres,redis,config,logs}

# Database backup
echo "Backing up PostgreSQL..."
pg_dump -h $DB_HOST -U $DB_USER -d typosentinel -F c -b -v -f $BACKUP_DIR/postgres/typosentinel_$DATE.backup
gzip $BACKUP_DIR/postgres/typosentinel_$DATE.backup

# Redis backup
echo "Backing up Redis..."
redis-cli --rdb $BACKUP_DIR/redis/dump_$DATE.rdb
gzip $BACKUP_DIR/redis/dump_$DATE.rdb

# Configuration backup
echo "Backing up configuration..."
tar -czf $BACKUP_DIR/config/config_$DATE.tar.gz /app/config/

# Log backup
echo "Backing up logs..."
tar -czf $BACKUP_DIR/logs/logs_$DATE.tar.gz /var/log/typosentinel/

# Upload to S3 (optional)
if [ "$AWS_S3_BUCKET" != "" ]; then
    echo "Uploading to S3..."
    aws s3 sync $BACKUP_DIR s3://$AWS_S3_BUCKET/backups/$(date +%Y/%m/%d)/
fi

# Cleanup old backups
echo "Cleaning up old backups..."
find $BACKUP_DIR -name "*.backup.gz" -mtime +$RETENTION_DAYS -delete
find $BACKUP_DIR -name "*.rdb.gz" -mtime +$RETENTION_DAYS -delete
find $BACKUP_DIR -name "*.tar.gz" -mtime +$RETENTION_DAYS -delete

echo "Backup completed successfully"
```

### Disaster Recovery

```bash
#!/bin/bash
# restore-system.sh

set -e

BACKUP_FILE=$1
if [ -z "$BACKUP_FILE" ]; then
    echo "Usage: $0 <backup_file>"
    exit 1
fi

# Stop services
echo "Stopping services..."
sudo systemctl stop typosentinel
sudo systemctl stop nginx

# Restore database
echo "Restoring database..."
gunzip -c $BACKUP_FILE | pg_restore -h $DB_HOST -U $DB_USER -d typosentinel --clean --if-exists

# Restore Redis
echo "Restoring Redis..."
sudo systemctl stop redis
cp $REDIS_BACKUP_FILE /var/lib/redis/dump.rdb
sudo chown redis:redis /var/lib/redis/dump.rdb
sudo systemctl start redis

# Start services
echo "Starting services..."
sudo systemctl start typosentinel
sudo systemctl start nginx

# Verify health
echo "Verifying system health..."
curl -f http://localhost:8080/health

echo "Restore completed successfully"
```

## Troubleshooting

### Common Issues

**1. Application Won't Start**

```bash
# Check logs
journalctl -u typosentinel -f

# Check configuration
./bin/typosentinel --config=config.yaml --validate

# Check dependencies
netstat -tlnp | grep :5432  # PostgreSQL
netstat -tlnp | grep :6379  # Redis
```

**2. High Memory Usage**

```bash
# Check memory usage
ps aux | grep typosentinel
top -p $(pgrep typosentinel)

# Generate heap profile
curl http://localhost:8080/debug/pprof/heap > heap.prof
go tool pprof heap.prof
```

**3. Database Connection Issues**

```bash
# Test database connection
psql -h $DB_HOST -U $DB_USER -d typosentinel -c "SELECT 1;"

# Check connection pool
curl http://localhost:8080/debug/vars | jq '.database'

# Monitor connections
psql -h $DB_HOST -U $DB_USER -d typosentinel -c "SELECT * FROM pg_stat_activity;"
```

**4. Performance Issues**

```bash
# Check system resources
top
iotop
netstat -i

# Profile application
curl http://localhost:8080/debug/pprof/profile?seconds=30 > cpu.prof
go tool pprof cpu.prof

# Check slow queries
psql -h $DB_HOST -U $DB_USER -d typosentinel -c "SELECT query, mean_time, calls FROM pg_stat_statements ORDER BY mean_time DESC LIMIT 10;"
```

### Health Checks

```bash
#!/bin/bash
# health-check.sh

set -e

API_URL="http://localhost:8080"
DB_HOST="localhost"
REDIS_HOST="localhost"

echo "Checking application health..."
if curl -f $API_URL/health > /dev/null 2>&1; then
    echo "✓ Application is healthy"
else
    echo "✗ Application health check failed"
    exit 1
fi

echo "Checking database connection..."
if pg_isready -h $DB_HOST > /dev/null 2>&1; then
    echo "✓ Database is accessible"
else
    echo "✗ Database connection failed"
    exit 1
fi

echo "Checking Redis connection..."
if redis-cli -h $REDIS_HOST ping > /dev/null 2>&1; then
    echo "✓ Redis is accessible"
else
    echo "✗ Redis connection failed"
    exit 1
fi

echo "All health checks passed"
```

## Maintenance

### Regular Maintenance Tasks

```bash
#!/bin/bash
# maintenance.sh

# Update system packages
sudo apt update && sudo apt upgrade -y

# Clean up Docker
docker system prune -f
docker volume prune -f

# Vacuum database
psql -h $DB_HOST -U $DB_USER -d typosentinel -c "VACUUM ANALYZE;"

# Rotate logs
logrotate /etc/logrotate.d/typosentinel

# Check disk space
df -h

# Check certificate expiry
openssl x509 -in /etc/ssl/certs/typosentinel.crt -noout -dates

# Update threat database
curl -X POST $API_URL/admin/update-threats

echo "Maintenance completed"
```

### Monitoring Scripts

```bash
#!/bin/bash
# monitor.sh

API_URL="http://localhost:8080"
ALERT_EMAIL="admin@typosentinel.com"

# Check API response time
RESPONSE_TIME=$(curl -o /dev/null -s -w '%{time_total}' $API_URL/health)
if (( $(echo "$RESPONSE_TIME > 1.0" | bc -l) )); then
    echo "High response time: ${RESPONSE_TIME}s" | mail -s "Typosentinel Alert" $ALERT_EMAIL
fi

# Check error rate
ERROR_RATE=$(curl -s $API_URL/metrics | grep 'http_requests_total{.*status="5' | awk '{sum+=$2} END {print sum}')
if [ "$ERROR_RATE" -gt 10 ]; then
    echo "High error rate: $ERROR_RATE" | mail -s "Typosentinel Alert" $ALERT_EMAIL
fi

# Check disk space
DISK_USAGE=$(df / | tail -1 | awk '{print $5}' | sed 's/%//')
if [ "$DISK_USAGE" -gt 80 ]; then
    echo "High disk usage: ${DISK_USAGE}%" | mail -s "Typosentinel Alert" $ALERT_EMAIL
fi
```

### Update Procedures

```bash
#!/bin/bash
# update.sh

NEW_VERSION=$1
if [ -z "$NEW_VERSION" ]; then
    echo "Usage: $0 <version>"
    exit 1
fi

echo "Updating Typosentinel to version $NEW_VERSION"

# Backup current version
echo "Creating backup..."
./backup-system.sh

# Download new version
echo "Downloading new version..."
wget https://github.com/typosentinel/typosentinel/releases/download/v$NEW_VERSION/typosentinel-linux-amd64.tar.gz
tar -xzf typosentinel-linux-amd64.tar.gz

# Stop service
echo "Stopping service..."
sudo systemctl stop typosentinel

# Replace binary
echo "Updating binary..."
sudo cp typosentinel /usr/local/bin/
sudo chmod +x /usr/local/bin/typosentinel

# Run migrations
echo "Running migrations..."
/usr/local/bin/typosentinel migrate up

# Start service
echo "Starting service..."
sudo systemctl start typosentinel

# Verify update
echo "Verifying update..."
sleep 10
curl -f http://localhost:8080/health

echo "Update completed successfully"
```

This deployment guide provides comprehensive instructions for deploying Typosentinel in various environments with proper security, monitoring, and maintenance procedures. Choose the deployment method that best fits your infrastructure requirements and scale accordingly.