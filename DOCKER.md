# Typosentinel Docker Deployment Guide

This guide covers how to deploy Typosentinel using Docker and Docker Compose.

## Quick Start

### Prerequisites

- Docker 20.10+ installed and running
- Docker Compose 2.0+ installed
- At least 2GB of available RAM
- At least 5GB of available disk space

### 1. Clone and Navigate

```bash
git clone https://github.com/Alivanroy/Typosentinel.git
cd Typosentinel
```

### 2. Deploy with One Command

```bash
# Production deployment
./deploy.sh start

# Development deployment (with hot reloading)
./deploy.sh dev

# Production with monitoring stack
./deploy.sh start-monitoring
```

## Deployment Options

### Production Deployment

```bash
./deploy.sh start
```

This will:
- Build optimized Docker images
- Start the web interface on port 3000
- Start the API server on port 8080
- Create persistent volumes for data and logs
- Set up health checks

**Access Points:**
- Web Interface: http://localhost:3000
- API Server: http://localhost:8080
- Health Check: http://localhost:8080/health

### Development Deployment

```bash
./deploy.sh dev
```

This will:
- Start services with hot reloading enabled
- Mount source code as volumes for live editing
- Enable debug logging
- Use development-optimized configurations

**Access Points:**
- Web Interface: http://localhost:3001 (with hot reload)
- API Server: http://localhost:8080 (debug mode)

### Production with Monitoring

```bash
./deploy.sh start-monitoring
```

This includes everything from production deployment plus:
- Prometheus metrics collection
- Grafana dashboards
- Node Exporter for system metrics

**Additional Access Points:**
- Prometheus: http://localhost:9090
- Grafana: http://localhost:3001 (admin/admin123)
- Node Exporter: http://localhost:9100

## Manual Docker Compose

If you prefer to use Docker Compose directly:

### Production

```bash
# Create environment file
cp .env.example .env
# Edit .env with your configuration

# Start services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

### Development

```bash
# Start development environment
docker-compose -f docker-compose.yml -f docker-compose.dev.yml up -d

# View logs
docker-compose -f docker-compose.yml -f docker-compose.dev.yml logs -f
```

### With Monitoring

```bash
# Start with monitoring stack
docker-compose --profile monitoring up -d
```

## Configuration

### Environment Variables

Create a `.env` file in the project root:

```bash
# Security
TYPOSENTINEL_JWT_SECRET=your-secret-key-here

# Database
TYPOSENTINEL_DB_PATH=/app/data/typosentinel.db

# Logging
TYPOSENTINEL_LOG_LEVEL=info

# CORS
TYPOSENTINEL_CORS_ENABLED=true
TYPOSENTINEL_CORS_ORIGINS=http://localhost:3000

# Monitoring
GRAFANA_PASSWORD=your-grafana-password
```

### Production Configuration

The production configuration is located at `config/production.yaml`. Key settings:

- **Server**: Optimized timeouts and connection limits
- **Security**: JWT authentication and rate limiting
- **Database**: SQLite with connection pooling
- **Logging**: JSON format with rotation
- **CORS**: Configured for your domain

## Volumes and Data Persistence

### Persistent Volumes

- `typosentinel_data`: Application data and SQLite database
- `typosentinel_logs`: Application logs

### Volume Locations

```bash
# View volume information
docker volume ls | grep typosentinel
docker volume inspect typosentinel_data
```

### Backup Data

```bash
# Backup database
docker run --rm -v typosentinel_data:/data -v $(pwd):/backup alpine tar czf /backup/typosentinel-data-backup.tar.gz -C /data .

# Restore database
docker run --rm -v typosentinel_data:/data -v $(pwd):/backup alpine tar xzf /backup/typosentinel-data-backup.tar.gz -C /data
```

## Health Checks and Monitoring

### Health Endpoints

- **API Health**: `GET /health`
- **Web Health**: `GET /health` (nginx status)

### Monitoring Stack

When deployed with monitoring:

1. **Prometheus** collects metrics from:
   - Typosentinel API server
   - Node Exporter (system metrics)
   - Docker containers

2. **Grafana** provides dashboards for:
   - Application performance
   - System resources
   - API request metrics
   - Error rates and response times

### Custom Metrics

Typosentinel exposes custom metrics at `/metrics`:

- `typosentinel_scans_total`: Total number of package scans
- `typosentinel_scan_duration_seconds`: Scan duration histogram
- `typosentinel_active_connections`: Current active connections
- `typosentinel_errors_total`: Total number of errors

## Troubleshooting

### Common Issues

#### Services Won't Start

```bash
# Check service status
docker-compose ps

# View logs
docker-compose logs typosentinel-api
docker-compose logs typosentinel-web

# Check Docker daemon
docker info
```

#### Port Conflicts

If ports 3000 or 8080 are already in use:

```bash
# Check what's using the ports
lsof -i :3000
lsof -i :8080

# Stop conflicting services or modify docker-compose.yml ports
```

#### Permission Issues

```bash
# Fix volume permissions
docker-compose exec typosentinel-api chown -R appuser:appgroup /app/data
docker-compose exec typosentinel-api chown -R appuser:appgroup /app/logs
```

#### Database Issues

```bash
# Reset database (WARNING: This will delete all data)
docker-compose down
docker volume rm typosentinel_data
docker-compose up -d
```

### Logs and Debugging

```bash
# View all logs
docker-compose logs -f

# View specific service logs
docker-compose logs -f typosentinel-api
docker-compose logs -f typosentinel-web

# View logs with timestamps
docker-compose logs -f -t

# Follow logs from last 100 lines
docker-compose logs -f --tail=100
```

### Performance Tuning

#### Resource Limits

Edit `docker-compose.yml` to adjust resource limits:

```yaml
services:
  typosentinel-api:
    deploy:
      resources:
        limits:
          memory: 512M
          cpus: '0.5'
        reservations:
          memory: 256M
          cpus: '0.25'
```

#### Database Optimization

For high-traffic deployments, consider:

1. Using PostgreSQL instead of SQLite
2. Increasing connection pool size
3. Adding database indices
4. Implementing caching

## Security Considerations

### Production Security

1. **Change Default Passwords**: Update all default passwords in `.env`
2. **Use HTTPS**: Configure reverse proxy with SSL/TLS
3. **Network Security**: Use Docker networks and firewall rules
4. **Regular Updates**: Keep Docker images updated
5. **Secrets Management**: Use Docker secrets for sensitive data

### Reverse Proxy Setup

Example Nginx configuration for production:

```nginx
server {
    listen 80;
    server_name your-domain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name your-domain.com;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    location / {
        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
    
    location /api/ {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## Scaling and High Availability

### Horizontal Scaling

```yaml
# docker-compose.yml
services:
  typosentinel-api:
    deploy:
      replicas: 3
    
  nginx:
    image: nginx:alpine
    volumes:
      - ./nginx-lb.conf:/etc/nginx/nginx.conf
    ports:
      - "80:80"
    depends_on:
      - typosentinel-api
```

### Load Balancer Configuration

Create `nginx-lb.conf` for load balancing:

```nginx
upstream typosentinel_api {
    server typosentinel-api:8080;
    # Add more servers for scaling
}

server {
    listen 80;
    location /api/ {
        proxy_pass http://typosentinel_api;
    }
}
```

## Maintenance

### Updates

```bash
# Pull latest images
docker-compose pull

# Restart with new images
docker-compose up -d

# Clean up old images
docker image prune -f
```

### Cleanup

```bash
# Remove all Typosentinel containers and images
docker-compose down --rmi all

# Remove volumes (WARNING: This deletes all data)
docker-compose down -v

# Clean up Docker system
docker system prune -f
```

## Support

For issues and questions:

1. Check the logs first: `docker-compose logs -f`
2. Review this documentation
3. Check the main project README
4. Open an issue on the project repository

## Quick Reference

```bash
# Deploy production
./deploy.sh start

# Deploy development
./deploy.sh dev

# Deploy with monitoring
./deploy.sh start-monitoring

# Stop services
./deploy.sh stop

# View logs
./deploy.sh logs

# Check status
./deploy.sh status

# Restart services
./deploy.sh restart
```