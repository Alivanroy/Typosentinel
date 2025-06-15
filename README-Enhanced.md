# Typosentinel Enhanced Server

The Enhanced Server is a comprehensive, production-ready implementation of Typosentinel that integrates advanced infrastructure components for scalability, monitoring, and high availability.

## 🚀 Features

### Core Infrastructure
- **Load Balancer**: Intelligent request distribution with health checks
- **Auto Scaler**: Dynamic scaling based on system metrics
- **Worker Pool**: Efficient task processing with configurable workers
- **Multi-level Cache**: L1 (memory), L2 (Redis), L3 (disk) caching system
- **Event Bus**: Asynchronous event-driven architecture
- **API Gateway**: Centralized API management with rate limiting
- **Auth Manager**: JWT-based authentication and authorization
- **Monitor**: Comprehensive health and performance monitoring
- **Config Manager**: Dynamic configuration management

### Observability
- **Metrics**: Prometheus integration with custom metrics
- **Logging**: Structured logging with ELK stack
- **Tracing**: Distributed tracing support
- **Health Checks**: Multi-level health monitoring
- **Alerting**: Configurable alerts via AlertManager

### Security
- **Authentication**: JWT tokens with refresh mechanism
- **Authorization**: Role-based access control (RBAC)
- **Rate Limiting**: Configurable rate limits per endpoint
- **Security Scanning**: Integrated vulnerability scanning
- **Audit Logging**: Comprehensive audit trails

## 📋 Prerequisites

- Docker and Docker Compose
- Go 1.21+
- Make
- Git
- jq (for JSON processing)

## 🛠️ Quick Start

### 1. Clone and Setup
```bash
git clone <repository-url>
cd Typosentinel
make deps
```

### 2. Development Environment
```bash
# Start the enhanced development environment
make dev-enhanced

# Check health
make health-enhanced

# View logs
make logs-enhanced
```

### 3. Production Environment
```bash
# Start production environment
make prod-enhanced

# Monitor services
docker-compose -f docker-compose.enhanced.yml ps
```

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Load Balancer │────│   API Gateway   │────│  Enhanced Server│
│    (HAProxy)    │    │                 │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                │                        │
                                │                        │
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Auth Manager  │────│   Event Bus     │────│  Worker Pool    │
│                 │    │                 │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                │                        │
                                │                        │
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  Cache Manager  │────│   Monitor       │────│  Auto Scaler    │
│  (L1/L2/L3)     │    │                 │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                │
                                │
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   PostgreSQL    │────│     Redis       │────│   Elasticsearch │
│                 │    │                 │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## 🔧 Configuration

The enhanced server uses a comprehensive configuration file located at `config/enhanced-server.yaml`. Key sections include:

### Server Configuration
```yaml
server:
  host: "0.0.0.0"
  port: 8080
  read_timeout: 30s
  write_timeout: 30s
  shutdown_timeout: 30s
```

### Cache Configuration
```yaml
cache:
  l1:
    max_size: 1000
    ttl: 300s
  l2:
    max_size: 10000
    ttl: 3600s
  l3:
    max_size: 100000
    ttl: 86400s
```

### Worker Pool Configuration
```yaml
worker_pool:
  min_workers: 2
  max_workers: 10
  queue_size: 1000
  worker_timeout: 300s
```

## 🚀 Deployment

### Local Development
```bash
# Build enhanced server
make build-enhanced

# Run locally
make run-enhanced
```

### Docker Deployment
```bash
# Build Docker images
make docker-build-enhanced

# Start development environment
make dev-enhanced

# Start production environment
make prod-enhanced
```

### Kubernetes Deployment
```bash
# Apply Kubernetes manifests (if available)
kubectl apply -f k8s/

# Check deployment status
kubectl get pods -l app=typosentinel-enhanced
```

## 📊 Monitoring and Observability

### Access Points
- **Enhanced Server**: http://localhost:8080
- **Grafana Dashboard**: http://localhost:3001 (admin/admin)
- **Prometheus**: http://localhost:9091
- **Kibana**: http://localhost:5601
- **HAProxy Stats**: http://localhost:8404/stats
- **AlertManager**: http://localhost:9093

### Development Tools
- **pgAdmin**: http://localhost:5050
- **Redis Commander**: http://localhost:8081
- **RabbitMQ Management**: http://localhost:15672
- **MailHog**: http://localhost:8025

### Key Metrics
- Request rate and latency
- Cache hit/miss ratios
- Worker pool utilization
- Database connection pool status
- Memory and CPU usage
- Error rates by endpoint

## 🔍 API Endpoints

### Health and Status
- `GET /health` - Basic health check
- `GET /ready` - Readiness check
- `GET /metrics` - Prometheus metrics
- `GET /stats` - Server statistics

### Authentication
- `POST /auth/login` - User login
- `POST /auth/refresh` - Token refresh
- `POST /auth/logout` - User logout

### Package Scanning
- `POST /api/v1/scan` - Scan single package
- `POST /api/v1/batch` - Batch scan packages
- `GET /api/v1/scan/{id}` - Get scan results

### Administration
- `GET /admin/workers` - Worker status
- `POST /admin/workers/scale` - Scale workers
- `GET /admin/cache/stats` - Cache statistics
- `DELETE /admin/cache/clear` - Clear cache

## 🛡️ Security

### Authentication
The enhanced server uses JWT-based authentication:

```bash
# Login to get token
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"password"}'

# Use token in requests
curl -H "Authorization: Bearer <token>" \
  http://localhost:8080/api/v1/scan
```

### Rate Limiting
Configurable rate limits are applied per endpoint and user:

```yaml
api_gateway:
  rate_limiting:
    requests_per_minute: 100
    burst_size: 10
```

## 🔧 Troubleshooting

### Common Issues

1. **Services not starting**
   ```bash
   # Check Docker logs
   make logs-enhanced
   
   # Check service health
   make health-enhanced
   ```

2. **Database connection issues**
   ```bash
   # Check PostgreSQL status
   docker-compose -f docker-compose.enhanced.yml exec postgres pg_isready
   
   # Check Redis status
   docker-compose -f docker-compose.enhanced.yml exec redis redis-cli ping
   ```

3. **High memory usage**
   ```bash
   # Check cache statistics
   curl http://localhost:8080/admin/cache/stats
   
   # Clear cache if needed
   curl -X DELETE http://localhost:8080/admin/cache/clear
   ```

4. **Worker pool issues**
   ```bash
   # Check worker status
   curl http://localhost:8080/admin/workers
   
   # Scale workers
   curl -X POST http://localhost:8080/admin/workers/scale \
     -H "Content-Type: application/json" \
     -d '{"count":5}'
   ```

### Debug Mode
```bash
# Enable debug logging
export LOG_LEVEL=debug
make run-enhanced

# Or in Docker
docker-compose -f docker-compose.enhanced.yml up -d
docker-compose -f docker-compose.enhanced.yml exec enhanced-server \
  /app/enhanced-server --log-level=debug
```

## 📈 Performance Tuning

### Cache Optimization
```yaml
cache:
  l1:
    max_size: 2000      # Increase for more memory cache
    ttl: 600s           # Adjust based on data freshness needs
  l2:
    max_size: 20000     # Increase for more Redis cache
    ttl: 7200s
```

### Worker Pool Tuning
```yaml
worker_pool:
  min_workers: 4        # Increase for higher baseline capacity
  max_workers: 20       # Increase for peak load handling
  queue_size: 2000      # Increase for burst handling
```

### Database Optimization
```yaml
database:
  max_open_conns: 25    # Adjust based on load
  max_idle_conns: 5
  conn_max_lifetime: 300s
```

## 🔄 Backup and Recovery

### Automated Backups
```bash
# Create backup
make backup-enhanced

# Restore from backup (manual process)
docker-compose -f docker-compose.enhanced.yml exec backup-service \
  /app/scripts/restore.sh <backup-file>
```

### Manual Backup
```bash
# Database backup
docker-compose -f docker-compose.enhanced.yml exec postgres \
  pg_dump -U typosentinel typosentinel > backup.sql

# Redis backup
docker-compose -f docker-compose.enhanced.yml exec redis \
  redis-cli BGSAVE
```

## 🧪 Testing

### Unit Tests
```bash
make test-unit
```

### Integration Tests
```bash
make test-integration
```

### Load Testing
```bash
# Using Apache Bench
ab -n 1000 -c 10 http://localhost:8080/health

# Using custom load test
make test-performance
```

## 📚 Additional Resources

- [Configuration Reference](config/enhanced-server.yaml)
- [API Documentation](docs/api.md)
- [Deployment Guide](docs/deployment.md)
- [Monitoring Guide](docs/monitoring.md)
- [Security Guide](docs/security.md)

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Run the test suite
6. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.