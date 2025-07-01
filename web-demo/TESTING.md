# TypoSentinel Web Demo Testing Guide

This document provides comprehensive testing procedures for the TypoSentinel web demo with all enabled features including SSL, monitoring, and the actual TypoSentinel API integration.

## Prerequisites

- Docker and Docker Compose installed
- Domain name configured (for Let's Encrypt SSL)
- Ports 80, 443, 3000, 3001, 9090, 9100 available

## Quick Start

```bash
# Clone and navigate to the project
cd /Users/alikorsi/Documents/Typosentinel/web-demo

# Start all services
docker-compose up -d

# Check service status
docker-compose ps
```

## Test Categories

### 1. Infrastructure Tests

#### 1.1 Docker Services Health Check
```bash
# Check all services are running
docker-compose ps

# Expected services:
# - nginx (web server)
# - typosentinel-api (main API)
# - redis (caching)
# - postgres (database)
# - prometheus (metrics)
# - grafana (monitoring)
# - node-exporter (system metrics)
# - certbot (SSL certificates)
```

#### 1.2 Network Connectivity
```bash
# Test internal network connectivity
docker-compose exec nginx ping -c 3 typosentinel-api
docker-compose exec typosentinel-api ping -c 3 redis
docker-compose exec typosentinel-api ping -c 3 postgres
docker-compose exec prometheus ping -c 3 typosentinel-api
```

#### 1.3 Port Accessibility
```bash
# Test external port access
curl -I http://localhost:80
curl -I https://localhost:443
curl -I http://localhost:3000  # Grafana
curl -I http://localhost:9090  # Prometheus
```

### 2. SSL/TLS Tests

#### 2.1 Self-Signed Certificate (Development)
```bash
# Generate self-signed certificates
docker-compose exec nginx /etc/nginx/ssl/generate-self-signed.sh

# Test SSL connection
curl -k -I https://localhost:443

# Verify certificate details
openssl s_client -connect localhost:443 -servername localhost < /dev/null
```

#### 2.2 Let's Encrypt Certificate (Production)
```bash
# Update domain in docker-compose.yml
# Replace 'yourdomain.com' with your actual domain

# Obtain certificate
docker-compose exec certbot certbot certonly --webroot -w /var/www/certbot -d yourdomain.com

# Test certificate
curl -I https://yourdomain.com

# Check certificate expiration
openssl s_client -connect yourdomain.com:443 -servername yourdomain.com < /dev/null | openssl x509 -noout -dates
```

#### 2.3 SSL Security Headers
```bash
# Test security headers
curl -I https://localhost:443

# Expected headers:
# - Strict-Transport-Security
# - X-Frame-Options: DENY
# - X-Content-Type-Options: nosniff
# - X-XSS-Protection
# - Content-Security-Policy
```

### 3. TypoSentinel API Tests

#### 3.1 API Health Check
```bash
# Test API health endpoint
curl http://localhost/api/health

# Expected response: {"status": "healthy"}
```

#### 3.2 Package Scanning Tests
```bash
# Test scanning a popular package
curl -X POST http://localhost/api/scan \
  -H "Content-Type: application/json" \
  -d '{"package": "lodash", "version": "latest"}'

# Test scanning with specific version
curl -X POST http://localhost/api/scan \
  -H "Content-Type: application/json" \
  -d '{"package": "express", "version": "4.18.0"}'

# Test bulk scanning
curl -X POST http://localhost/api/scan/bulk \
  -H "Content-Type: application/json" \
  -d '{"packages": [{"package": "react", "version": "18.0.0"}, {"package": "vue", "version": "3.0.0"}]}'
```

#### 3.3 Scan Results Tests
```bash
# Get scan history
curl http://localhost/api/scans

# Get specific scan result
curl http://localhost/api/scans/{scan_id}

# Get scan statistics
curl http://localhost/api/stats
```

#### 3.4 API Performance Tests
```bash
# Load testing with Apache Bench
ab -n 100 -c 10 http://localhost/api/health

# Stress test scanning endpoint
ab -n 50 -c 5 -p scan_payload.json -T application/json http://localhost/api/scan
```

### 4. Database Tests

#### 4.1 PostgreSQL Connectivity
```bash
# Connect to PostgreSQL
docker-compose exec postgres psql -U typosentinel -d typosentinel

# Test queries
\dt  # List tables
SELECT COUNT(*) FROM scans;
SELECT * FROM scans LIMIT 5;
```

#### 4.2 Data Persistence
```bash
# Restart database and verify data persistence
docker-compose restart postgres
docker-compose exec postgres psql -U typosentinel -d typosentinel -c "SELECT COUNT(*) FROM scans;"
```

### 5. Redis Cache Tests

#### 5.1 Redis Connectivity
```bash
# Connect to Redis
docker-compose exec redis redis-cli

# Test Redis operations
ping
set test_key "test_value"
get test_key
keys *
```

#### 5.2 Cache Performance
```bash
# Test cache hit/miss rates
docker-compose exec redis redis-cli info stats

# Monitor cache operations
docker-compose exec redis redis-cli monitor
```

### 6. Monitoring Tests

#### 6.1 Prometheus Metrics
```bash
# Access Prometheus web interface
open http://localhost:9090

# Test metric queries
curl http://localhost:9090/api/v1/query?query=up
curl http://localhost:9090/api/v1/query?query=http_requests_total

# Check targets status
curl http://localhost:9090/api/v1/targets
```

#### 6.2 Grafana Dashboard
```bash
# Access Grafana (admin/admin)
open http://localhost:3000

# Test dashboard functionality
# - Login with admin/admin
# - Navigate to TypoSentinel Dashboard
# - Verify all panels load data
# - Test time range selection
# - Test panel interactions
```

#### 6.3 Node Exporter Metrics
```bash
# Test system metrics
curl http://localhost:9100/metrics | grep node_cpu
curl http://localhost:9100/metrics | grep node_memory
curl http://localhost:9100/metrics | grep node_filesystem
```

### 7. Frontend Tests

#### 7.1 Web Interface Access
```bash
# Test main web interface
curl -I http://localhost/
curl -I https://localhost/

# Test static assets
curl -I http://localhost/css/style.css
curl -I http://localhost/js/app.js
```

#### 7.2 Frontend Functionality
```bash
# Manual testing checklist:
# - Open http://localhost in browser
# - Test package search functionality
# - Submit scan requests
# - View scan results
# - Test responsive design
# - Check browser console for errors
```

### 8. Security Tests

#### 8.1 HTTPS Redirect
```bash
# Test HTTP to HTTPS redirect
curl -I http://localhost/

# Expected: 301/302 redirect to https://
```

#### 8.2 Security Headers
```bash
# Test security headers
curl -I https://localhost/

# Verify presence of:
# - Strict-Transport-Security
# - X-Frame-Options
# - X-Content-Type-Options
# - Content-Security-Policy
```

#### 8.3 API Security
```bash
# Test rate limiting
for i in {1..100}; do curl http://localhost/api/health; done

# Test input validation
curl -X POST http://localhost/api/scan \
  -H "Content-Type: application/json" \
  -d '{"package": "<script>alert(1)</script>"}'
```

### 9. Performance Tests

#### 9.1 Load Testing
```bash
# Install Apache Bench if not available
# brew install httpd (macOS)

# Test concurrent requests
ab -n 1000 -c 50 http://localhost/
ab -n 500 -c 25 http://localhost/api/health

# Test scanning performance
ab -n 100 -c 10 -p scan_payload.json -T application/json http://localhost/api/scan
```

#### 9.2 Resource Monitoring
```bash
# Monitor resource usage during tests
docker stats

# Monitor specific services
docker stats typosentinel-api nginx postgres redis
```

### 10. Backup and Recovery Tests

#### 10.1 Database Backup
```bash
# Create database backup
docker-compose exec postgres pg_dump -U typosentinel typosentinel > backup.sql

# Test backup restoration
docker-compose exec postgres psql -U typosentinel -d typosentinel < backup.sql
```

#### 10.2 Configuration Backup
```bash
# Backup configuration files
tar -czf config_backup.tar.gz nginx/ monitoring/ ssl/

# Test configuration restoration
tar -xzf config_backup.tar.gz
```

## Automated Testing Scripts

### Test Runner Script
```bash
#!/bin/bash
# Save as test_runner.sh

echo "Starting TypoSentinel Demo Tests..."

# Health checks
echo "Testing service health..."
docker-compose ps

# API tests
echo "Testing API endpoints..."
curl -f http://localhost/api/health || echo "API health check failed"

# Database tests
echo "Testing database connectivity..."
docker-compose exec postgres pg_isready -U typosentinel || echo "Database connection failed"

# Redis tests
echo "Testing Redis connectivity..."
docker-compose exec redis redis-cli ping || echo "Redis connection failed"

# Monitoring tests
echo "Testing monitoring endpoints..."
curl -f http://localhost:9090/-/healthy || echo "Prometheus health check failed"
curl -f http://localhost:3000/api/health || echo "Grafana health check failed"

echo "Tests completed!"
```

## Troubleshooting

### Common Issues

1. **Port conflicts**: Check if ports are already in use
   ```bash
   lsof -i :80 -i :443 -i :3000 -i :9090
   ```

2. **SSL certificate issues**: Regenerate self-signed certificates
   ```bash
   docker-compose exec nginx /etc/nginx/ssl/generate-self-signed.sh
   docker-compose restart nginx
   ```

3. **Database connection issues**: Check PostgreSQL logs
   ```bash
   docker-compose logs postgres
   ```

4. **API not responding**: Check TypoSentinel API logs
   ```bash
   docker-compose logs typosentinel-api
   ```

### Log Analysis
```bash
# View all service logs
docker-compose logs

# View specific service logs
docker-compose logs nginx
docker-compose logs typosentinel-api
docker-compose logs postgres
docker-compose logs redis
docker-compose logs prometheus
docker-compose logs grafana

# Follow logs in real-time
docker-compose logs -f typosentinel-api
```

## Test Data

### Sample Scan Payloads

Create `scan_payload.json`:
```json
{
  "package": "lodash",
  "version": "4.17.21"
}
```

Create `bulk_scan_payload.json`:
```json
{
  "packages": [
    {"package": "react", "version": "18.0.0"},
    {"package": "vue", "version": "3.0.0"},
    {"package": "angular", "version": "14.0.0"}
  ]
}
```

## Continuous Testing

### Monitoring Script
```bash
#!/bin/bash
# Save as monitor.sh

while true; do
  echo "$(date): Checking services..."
  
  # Check API health
  if curl -f -s http://localhost/api/health > /dev/null; then
    echo "API: OK"
  else
    echo "API: FAILED"
  fi
  
  # Check Prometheus
  if curl -f -s http://localhost:9090/-/healthy > /dev/null; then
    echo "Prometheus: OK"
  else
    echo "Prometheus: FAILED"
  fi
  
  # Check Grafana
  if curl -f -s http://localhost:3000/api/health > /dev/null; then
    echo "Grafana: OK"
  else
    echo "Grafana: FAILED"
  fi
  
  sleep 60
done
```

## Performance Benchmarks

### Expected Performance Metrics

- **API Response Time**: < 200ms for health checks
- **Scan Processing**: < 30s for typical packages
- **Database Queries**: < 100ms for simple queries
- **Memory Usage**: < 2GB total for all services
- **CPU Usage**: < 50% under normal load

### Load Testing Targets

- **Concurrent Users**: 50-100
- **Requests per Second**: 100-500
- **Scan Throughput**: 10-20 scans/minute
- **Uptime**: 99.9%

This comprehensive testing guide ensures all aspects of the TypoSentinel web demo are thoroughly validated, from basic functionality to advanced monitoring and security features.