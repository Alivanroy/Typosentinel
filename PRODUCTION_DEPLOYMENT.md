# TypoSentinel Production Deployment Guide

This guide provides comprehensive instructions for deploying TypoSentinel in production environments.

## Quick Start

### Automated Production Deployment

```bash
# Run the automated production deployment script
./scripts/production-deploy.sh
```

This script will:
- Clean the development environment
- Run comprehensive tests
- Build optimized production binaries
- Create production Docker images
- Generate deployment artifacts
- Perform security checks

### Staging Environment Validation ✅

**Status**: Successfully deployed and validated (Phase 3 Complete)

Our staging environment has been successfully deployed with:
- ✅ All services healthy (PostgreSQL, Redis, TypoSentinel API, ML Service)
- ✅ Configuration loading issues resolved
- ✅ API endpoints validated and functional
- ✅ Docker containerization working properly
- ✅ Health monitoring and service validation implemented

**Critical Fix Applied**: Configuration loading in `internal/config/structs.go` has been updated to properly merge default configurations with loaded values, resolving ML service initialization issues.

## Manual Deployment

### Prerequisites

- Go 1.21+ (for building from source)
- Docker and Docker Compose (for containerized deployment)
- 4GB+ RAM recommended
- 10GB+ disk space

### Step 1: Prepare for Production

```bash
# Clean development artifacts
make clean-production

# Run production build with all checks
make production
```

### Step 2: Configuration

1. **Copy configuration template:**
   ```bash
   cp config/config.yaml config/production.yaml
   ```

2. **Edit production configuration:**
   ```yaml
   # config/production.yaml
   core:
     log_level: "info"          # Use info or warn in production
     max_workers: 10            # Adjust based on server capacity
     timeout: "30m"
     cache_enabled: true
     cache_ttl: "24h"
   
   logging:
     level: "info"
     format: "json"             # JSON format for log aggregation
     output: "/app/logs/app.log" # Log to file in production
     rotation:
       enabled: true
       max_size: "100MB"
       max_age: 30
   
   security:
     rate_limiting:
       enabled: true
       requests_per_minute: 100
     cors:
       enabled: true
       allowed_origins: ["https://yourdomain.com"]
   ```

### Step 3: Binary Deployment

```bash
# Build optimized binary
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
  -ldflags="-s -w" \
  -o typosentinel .

# Create production directory structure
mkdir -p /opt/typosentinel/{bin,config,logs,data}

# Copy files
cp typosentinel /opt/typosentinel/bin/
cp config/production.yaml /opt/typosentinel/config/

# Create systemd service
sudo tee /etc/systemd/system/typosentinel.service > /dev/null <<EOF
[Unit]
Description=TypoSentinel Package Security Scanner
After=network.target

[Service]
Type=simple
User=typosentinel
Group=typosentinel
WorkingDirectory=/opt/typosentinel
ExecStart=/opt/typosentinel/bin/typosentinel serve --config /opt/typosentinel/config/production.yaml
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Create user and set permissions
sudo useradd -r -s /bin/false typosentinel
sudo chown -R typosentinel:typosentinel /opt/typosentinel
sudo chmod +x /opt/typosentinel/bin/typosentinel

# Start service
sudo systemctl daemon-reload
sudo systemctl enable typosentinel
sudo systemctl start typosentinel
```

### Step 4: Docker Deployment

1. **Build production image:**
   ```bash
   docker build -t typosentinel:production .
   ```

2. **Create production docker-compose.yml:**
   ```yaml
   version: '3.8'
   
   services:
     typosentinel:
       image: typosentinel:production
       ports:
         - "8080:8080"
       environment:
         - LOG_LEVEL=info
         - CONFIG_PATH=/app/config/production.yaml
         - GOMAXPROCS=4
         - GOGC=100
       volumes:
         - ./config/production.yaml:/app/config/production.yaml:ro
         - typosentinel-data:/app/data
         - typosentinel-logs:/app/logs
       restart: unless-stopped
       healthcheck:
         test: ["CMD", "wget", "--no-verbose", "--tries=1", "--spider", "http://127.0.0.1:8080/health"]
         interval: 30s
         timeout: 10s
         retries: 3
         start_period: 40s
       networks:
         - typosentinel-network
   
     redis:
       image: redis:7-alpine
       volumes:
         - redis-data:/data
       restart: unless-stopped
       networks:
         - typosentinel-network
   
   volumes:
     typosentinel-data:
     typosentinel-logs:
     redis-data:
   
   networks:
     typosentinel-network:
       driver: bridge
   ```

3. **Deploy with Docker Compose:**
   ```bash
   docker-compose up -d
   ```

## Production Considerations

### Security

1. **Network Security:**
   - Use HTTPS/TLS in production
   - Configure firewall rules
   - Use reverse proxy (nginx/Apache)
   - Enable rate limiting

2. **Authentication:**
   ```yaml
   # Add to production.yaml
   auth:
     enabled: true
     jwt_secret: "your-secure-jwt-secret"
     token_expiry: "24h"
   ```

3. **API Security:**
   - Enable CORS with specific origins
   - Use API keys for external access
   - Implement request validation

### Monitoring

1. **Health Checks:**
   ```bash
   # Application health
   curl http://localhost:8080/health
   
   # Detailed system status
   curl http://localhost:8080/v1/system/status
   
   # Metrics (Prometheus format)
   curl http://localhost:8080/metrics
   ```

2. **Log Monitoring:**
   ```bash
   # View application logs
   tail -f /opt/typosentinel/logs/app.log
   
   # Docker logs
   docker-compose logs -f typosentinel
   
   # Systemd logs
   journalctl -u typosentinel -f
   ```

3. **Performance Monitoring:**
   - Monitor CPU and memory usage
   - Track response times
   - Monitor scan queue length
   - Set up alerts for failures

### Scaling

1. **Horizontal Scaling:**
   ```yaml
   # docker-compose.yml
   services:
     typosentinel:
       deploy:
         replicas: 3
       # ... other config
   ```

2. **Load Balancing:**
   ```nginx
   # nginx.conf
   upstream typosentinel {
       server localhost:8080;
       server localhost:8081;
       server localhost:8082;
   }
   
   server {
       listen 80;
       location / {
           proxy_pass http://typosentinel;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
       }
   }
   ```

### Backup and Recovery

1. **Data Backup:**
   ```bash
   # Backup configuration
   tar -czf typosentinel-config-$(date +%Y%m%d).tar.gz /opt/typosentinel/config/
   
   # Backup data directory
   tar -czf typosentinel-data-$(date +%Y%m%d).tar.gz /opt/typosentinel/data/
   ```

2. **Database Backup (if using external DB):**
   ```bash
   # PostgreSQL example
   pg_dump typosentinel > typosentinel-db-$(date +%Y%m%d).sql
   ```

### Maintenance

1. **Updates:**
   ```bash
   # Stop service
   sudo systemctl stop typosentinel
   
   # Backup current version
   cp /opt/typosentinel/bin/typosentinel /opt/typosentinel/bin/typosentinel.backup
   
   # Deploy new version
   cp typosentinel /opt/typosentinel/bin/
   
   # Start service
   sudo systemctl start typosentinel
   ```

2. **Log Rotation:**
   ```bash
   # Configure logrotate
   sudo tee /etc/logrotate.d/typosentinel > /dev/null <<EOF
   /opt/typosentinel/logs/*.log {
       daily
       rotate 30
       compress
       delaycompress
       missingok
       notifempty
       postrotate
           systemctl reload typosentinel
       endscript
   }
   EOF
   ```

## Troubleshooting

### Common Issues

1. **Service won't start:**
   ```bash
   # Check logs
   journalctl -u typosentinel -n 50
   
   # Check configuration
   /opt/typosentinel/bin/typosentinel --config /opt/typosentinel/config/production.yaml --validate-config
   ```

2. **High memory usage:**
   - Reduce `max_workers` in configuration
   - Increase `GOGC` environment variable
   - Monitor for memory leaks

3. **Slow response times:**
   - Check network connectivity
   - Monitor external API rate limits
   - Increase cache TTL
   - Scale horizontally

### Performance Tuning

1. **Go Runtime:**
   ```bash
   # Environment variables
   export GOMAXPROCS=4        # Number of CPU cores
   export GOGC=100           # GC target percentage
   export GOMEMLIMIT=2GiB    # Memory limit
   ```

2. **Application Settings:**
   ```yaml
   # production.yaml
   core:
     max_workers: 10          # Adjust based on CPU cores
     timeout: "30m"           # Increase for large packages
     cache_enabled: true
     cache_ttl: "24h"         # Longer cache for production
   
   performance:
     batch_size: 100          # Process packages in batches
     concurrent_scans: 5      # Limit concurrent scans
     rate_limit: 1000         # Requests per minute
   ```

## Security Checklist

- [ ] Use HTTPS/TLS encryption
- [ ] Configure firewall rules
- [ ] Enable authentication
- [ ] Set up rate limiting
- [ ] Configure CORS properly
- [ ] Use non-root user
- [ ] Secure configuration files
- [ ] Enable audit logging
- [ ] Regular security updates
- [ ] Monitor for vulnerabilities

## Support

For production support:
- Check the [troubleshooting guide](docs/USER_GUIDE.md#troubleshooting)
- Review [API documentation](docs/API_DOCUMENTATION.md)
- Monitor application logs
- Use health check endpoints

## License

TypoSentinel is licensed under the MIT License. See [LICENSE](LICENSE) for details.