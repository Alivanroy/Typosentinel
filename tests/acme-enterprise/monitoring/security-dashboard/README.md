# ACME Security Dashboard

A comprehensive enterprise security dashboard for monitoring Typosentinel vulnerability scanning across multiple package registries.

## 🚀 Features

### Core Monitoring
- **Real-time Dashboard**: Live monitoring of security scans and vulnerabilities
- **Multi-Registry Support**: NPM, PyPI, Maven, NuGet, RubyGems, Go Modules
- **Vulnerability Tracking**: Comprehensive vulnerability management and tracking
- **Alert Management**: Real-time alerts with customizable severity thresholds
- **Compliance Monitoring**: SOC2, ISO27001, NIST, PCI-DSS compliance tracking

### Advanced Analytics
- **Zero-Day Detection**: AI-powered detection of potential zero-day vulnerabilities
- **Trend Analysis**: Historical vulnerability and security trend analysis
- **Risk Scoring**: Automated risk assessment and scoring
- **Performance Metrics**: Scan performance and system health monitoring
- **Executive Reporting**: Automated executive summary reports

### Enterprise Features
- **Role-Based Access Control**: Multi-level user access management
- **API Integration**: RESTful API for external system integration
- **Webhook Support**: Real-time webhook notifications
- **SSO Integration**: Single Sign-On support (SAML, OAuth)
- **Audit Logging**: Comprehensive audit trail and logging

### Notifications & Integrations
- **Slack Integration**: Real-time Slack notifications
- **Email Alerts**: Customizable email alert system
- **PagerDuty**: Critical alert escalation
- **Microsoft Teams**: Team collaboration notifications
- **JIRA Integration**: Automatic ticket creation
- **ServiceNow**: Enterprise service management integration

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   React SPA     │    │   Express API   │    │   PostgreSQL    │
│   Dashboard     │◄──►│   Server        │◄──►│   Database      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                │
                                ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Redis Cache   │◄──►│   Socket.IO     │    │  Elasticsearch  │
│   & Sessions    │    │   Real-time     │    │   Logs & Search │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                │
                                ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Prometheus    │    │   Typosentinel  │    │   External      │
│   Metrics       │    │   API           │    │   Integrations  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## 🚦 Prerequisites

- **Node.js**: v18.0.0 or higher
- **npm**: v9.0.0 or higher
- **PostgreSQL**: v13.0 or higher
- **Redis**: v6.0 or higher
- **Elasticsearch**: v8.0 or higher (optional)
- **Docker**: v20.0 or higher (for containerized deployment)

## 📦 Installation

### Local Development

1. **Clone the repository**
   ```bash
   git clone https://github.com/acme-enterprise/security-dashboard.git
   cd security-dashboard
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Set up environment variables**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

4. **Set up the database**
   ```bash
   # Create PostgreSQL database
   createdb typosentinel
   
   # Run database migrations
   npm run db:migrate
   
   # Seed initial data (optional)
   npm run db:seed
   ```

5. **Start Redis**
   ```bash
   redis-server
   ```

6. **Start the development server**
   ```bash
   npm run dev
   ```

7. **Access the dashboard**
   Open http://localhost:4000 in your browser

### Docker Deployment

1. **Using Docker Compose**
   ```bash
   # Start all services
   docker-compose up -d
   
   # View logs
   docker-compose logs -f
   
   # Stop services
   docker-compose down
   ```

2. **Using Docker**
   ```bash
   # Build the image
   docker build -t acme-security-dashboard .
   
   # Run the container
   docker run -p 4000:4000 \
     -e NODE_ENV=production \
     -e POSTGRES_HOST=your-db-host \
     -e REDIS_HOST=your-redis-host \
     acme-security-dashboard
   ```

### Kubernetes Deployment

1. **Apply Kubernetes manifests**
   ```bash
   kubectl apply -f k8s/
   ```

2. **Check deployment status**
   ```bash
   kubectl get pods -l app=security-dashboard
   kubectl get services
   ```

## ⚙️ Configuration

### Environment Variables

Key configuration options (see `.env.example` for complete list):

```bash
# Application
NODE_ENV=production
PORT=4000

# Database
POSTGRES_HOST=localhost
POSTGRES_DB=typosentinel
REDIS_HOST=localhost

# Typosentinel API
TYPOSENTINEL_API_URL=http://localhost:8080
TYPOSENTINEL_API_KEY=your-api-key

# Security
JWT_SECRET=your-jwt-secret
ENCRYPTION_KEY=your-encryption-key

# Notifications
SLACK_WEBHOOK_URL=your-slack-webhook
SMTP_HOST=your-smtp-host
```

### Database Schema

The application uses the following main tables:
- `users` - User accounts and authentication
- `registries` - Package registry configurations
- `scan_results` - Vulnerability scan results
- `vulnerabilities` - Detected vulnerabilities
- `alerts` - Security alerts and notifications
- `compliance_checks` - Compliance audit results
- `zero_day_detections` - Zero-day vulnerability detections

## 🔧 API Documentation

### Authentication

All API endpoints require authentication via JWT token:

```bash
Authorization: Bearer <your-jwt-token>
```

### Key Endpoints

#### Dashboard Overview
```http
GET /api/dashboard/overview?timeRange=24h
```

Response:
```json
{
  "summary": {
    "total_scans": 150,
    "total_vulnerabilities": 45,
    "risk_score": 75,
    "scan_success_rate": "94.67"
  },
  "vulnerabilities": {
    "distribution": {
      "critical": 5,
      "high": 12,
      "medium": 18,
      "low": 10
    }
  }
}
```

#### Real-time Metrics
```http
GET /api/dashboard/metrics
```

#### Vulnerability Management
```http
GET /api/vulnerabilities?severity=critical&status=active
POST /api/vulnerabilities/{id}/resolve
```

#### Alert Management
```http
GET /api/alerts?status=active
POST /api/alerts/{id}/acknowledge
```

### WebSocket Events

Real-time updates via Socket.IO:

```javascript
// Connect to real-time updates
const socket = io('http://localhost:4000');

// Subscribe to vulnerability alerts
socket.emit('subscribe', 'vulnerabilities');

// Listen for new vulnerabilities
socket.on('vulnerability:new', (data) => {
  console.log('New vulnerability detected:', data);
});

// Listen for scan completion
socket.on('scan:completed', (data) => {
  console.log('Scan completed:', data);
});
```

## 📊 Monitoring & Observability

### Prometheus Metrics

The dashboard exposes metrics at `/metrics`:

- `http_requests_total` - Total HTTP requests
- `http_request_duration_seconds` - Request duration
- `typosentinel_vulnerabilities_total` - Vulnerability counts
- `typosentinel_scan_duration_seconds` - Scan duration
- `security_alerts_total` - Alert counts

### Health Checks

```http
GET /health
```

Response:
```json
{
  "status": "healthy",
  "services": {
    "postgres": { "status": "healthy", "response_time": 5 },
    "redis": { "status": "healthy", "response_time": 2 },
    "typosentinel": { "status": "healthy", "response_time": 150 }
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### Logging

Structured JSON logging with Winston:

```json
{
  "level": "info",
  "message": "Vulnerability scan completed",
  "timestamp": "2024-01-15T10:30:00Z",
  "service": "acme-security-dashboard",
  "registry": "npm",
  "scan_id": "scan-123",
  "vulnerabilities_found": 5
}
```

## 🔒 Security

### Authentication & Authorization

- **JWT-based authentication** with configurable expiration
- **Role-based access control** (Admin, Security Analyst, Viewer)
- **Session management** with Redis
- **Password hashing** with bcrypt
- **Rate limiting** to prevent abuse

### Data Protection

- **Encryption at rest** for sensitive data
- **TLS/SSL encryption** for data in transit
- **Input validation** and sanitization
- **SQL injection protection** with parameterized queries
- **XSS protection** with content security policy

### Security Headers

```javascript
// Helmet.js security headers
Content-Security-Policy: default-src 'self'
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
```

## 🧪 Testing

### Running Tests

```bash
# Run all tests
npm test

# Run tests with coverage
npm run test:coverage

# Run tests in watch mode
npm run test:watch

# Run integration tests
npm run test:integration

# Run security tests
npm run test:security
```

### Test Structure

```
tests/
├── unit/           # Unit tests
├── integration/    # Integration tests
├── e2e/           # End-to-end tests
├── security/      # Security tests
└── fixtures/      # Test data
```

## 📈 Performance

### Optimization Features

- **Redis caching** for frequently accessed data
- **Database connection pooling** for optimal performance
- **Compression** for HTTP responses
- **Rate limiting** to prevent overload
- **Lazy loading** for large datasets
- **Pagination** for API responses

### Performance Monitoring

- **Response time tracking** with Prometheus
- **Database query optimization** with EXPLAIN ANALYZE
- **Memory usage monitoring** with Node.js metrics
- **CPU profiling** for performance bottlenecks

## 🚀 Deployment

### Production Checklist

- [ ] Set `NODE_ENV=production`
- [ ] Configure strong JWT and session secrets
- [ ] Set up SSL/TLS certificates
- [ ] Configure database connection pooling
- [ ] Set up log rotation
- [ ] Configure monitoring and alerting
- [ ] Set up backup and disaster recovery
- [ ] Perform security audit
- [ ] Load testing
- [ ] Documentation review

### Scaling Considerations

- **Horizontal scaling** with load balancers
- **Database read replicas** for read-heavy workloads
- **Redis clustering** for high availability
- **CDN integration** for static assets
- **Microservices architecture** for large deployments

## 🔧 Troubleshooting

### Common Issues

#### Database Connection Issues
```bash
# Check PostgreSQL connection
psql -h localhost -U postgres -d typosentinel

# Check database logs
tail -f /var/log/postgresql/postgresql.log
```

#### Redis Connection Issues
```bash
# Check Redis connection
redis-cli ping

# Check Redis logs
tail -f /var/log/redis/redis-server.log
```

#### High Memory Usage
```bash
# Monitor Node.js memory usage
node --inspect server.js

# Generate heap dump
kill -USR2 <node-process-id>
```

### Debug Mode

```bash
# Enable debug logging
DEBUG=* npm run dev

# Enable specific debug namespaces
DEBUG=app:* npm run dev
```

## 🤝 Contributing

### Development Workflow

1. **Fork the repository**
2. **Create a feature branch**
   ```bash
   git checkout -b feature/new-feature
   ```
3. **Make changes and add tests**
4. **Run the test suite**
   ```bash
   npm test
   npm run lint
   ```
5. **Commit changes**
   ```bash
   git commit -m "feat: add new feature"
   ```
6. **Push to your fork**
   ```bash
   git push origin feature/new-feature
   ```
7. **Create a pull request**

### Code Standards

- **ESLint** for code linting
- **Prettier** for code formatting
- **Husky** for pre-commit hooks
- **Conventional Commits** for commit messages
- **JSDoc** for code documentation

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

### Getting Help

- **Documentation**: https://docs.acme.com/security-dashboard
- **Issue Tracker**: https://github.com/acme-enterprise/security-dashboard/issues
- **Security Issues**: security@acme.com
- **General Support**: support@acme.com

### Enterprise Support

For enterprise customers:
- **24/7 Support**: Available via phone and email
- **Dedicated Support Engineer**: Assigned for critical deployments
- **Custom Training**: On-site and remote training available
- **Professional Services**: Implementation and customization services

---

**ACME Enterprise Security Team**  
Building secure software supply chains, one package at a time. 🛡️