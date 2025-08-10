# Typosentinel OSS - Open Source Security Scanner

Typosentinel OSS is the open-source version of Typosentinel, a comprehensive security scanner for detecting typosquatting, malicious packages, and supply chain attacks in software dependencies.

## 🚀 Quick Start

### Prerequisites

- Go 1.21 or later
- PostgreSQL 12+ (optional, SQLite supported)
- Redis (optional, for caching)

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Alivanroy/Typosentinel.git
   cd Typosentinel
   ```

2. **Run the security setup script:**
   ```bash
   ./scripts/setup-oss-security.sh
   ```
   This script will:
   - Generate secure configuration
   - Create environment variables
   - Set up security best practices
   - Provide deployment configurations

3. **Build and run:**
   ```bash
   # Build the OSS version
   ./scripts/build-oss.sh
   
   # Start the server in development mode
   ./bin/typosentinel-oss server --dev
   
   # Or run directly without building
   go run cmd/oss/main.go server --dev
   ```


4. **Available Commands:**
   ```bash
   # Show help
   ./bin/typosentinel-oss --help
   
   # Start server in development mode
   ./bin/typosentinel-oss server --dev --port 8080
   
   # Run security configuration check
   ./bin/typosentinel-oss security-check
   
   # Show version information
   ./bin/typosentinel-oss version
   ```

## 🔒 Security Configuration

### Required Environment Variables

The following environment variables are **required** for secure operation:

```bash
# JWT Secret (32+ characters, cryptographically secure)
TYPOSENTINEL_JWT_SECRET=your-secure-jwt-secret-here

# Admin Password (12+ characters, mixed case, numbers, symbols)
TYPOSENTINEL_ADMIN_PASSWORD=your-strong-admin-password

# Encryption Key (32 characters for AES-256)
TYPOSENTINEL_ENCRYPTION_KEY=your-encryption-key-here
```

### Optional Security Variables

```bash
# API Keys (comma-separated for multiple keys)
TYPOSENTINEL_API_KEYS=key1,key2,key3

# Database Security
TYPOSENTINEL_DB_PASSWORD=your-database-password

# TLS Configuration
TYPOSENTINEL_TLS_ENABLED=true
TYPOSENTINEL_TLS_CERT_FILE=/path/to/cert.pem
TYPOSENTINEL_TLS_KEY_FILE=/path/to/key.pem

# Security Features
TYPOSENTINEL_RATE_LIMIT_ENABLED=true
TYPOSENTINEL_AUDIT_LOGGING=true
TYPOSENTINEL_ENABLE_TEST_TOKENS=false  # NEVER enable in production
```

## 🛡️ Security Features

### Authentication & Authorization
- **JWT-based authentication** with configurable secrets
- **Strong password requirements** for admin accounts
- **API key authentication** for programmatic access
- **Role-based access control** (RBAC)

### Data Protection
- **AES-256 encryption** for sensitive data
- **Secure password hashing** with bcrypt
- **TLS/HTTPS support** for encrypted communication
- **Secure session management**

### Security Monitoring
- **Audit logging** for all security events
- **Rate limiting** to prevent abuse
- **Security headers** (HSTS, CSP, etc.)
- **CSRF and XSS protection**

### Operational Security
- **Environment-based configuration** (no hardcoded secrets)
- **Security validation** on startup
- **Secure defaults** for all configurations
- **Production readiness checks**

## 📊 Usage

### Web Interface

Access the web interface at `http://localhost:8080` (or your configured domain with HTTPS).

Default admin credentials are set via environment variables:
- Username: `admin`
- Password: `$TYPOSENTINEL_ADMIN_PASSWORD`

### API Access

#### Authentication
```bash
# Using admin credentials
curl -u admin:$TYPOSENTINEL_ADMIN_PASSWORD \
  http://localhost:8080/api/v1/scan

# Using API key
curl -H "X-API-Key: $TYPOSENTINEL_API_KEYS" \
  http://localhost:8080/api/v1/scan
```

#### Scanning Packages
```bash
# Scan a single package
curl -X POST \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $TYPOSENTINEL_API_KEYS" \
  -d '{"package": "requests", "version": "2.28.1", "ecosystem": "pypi"}' \
  http://localhost:8080/api/v1/scan

# Scan requirements file
curl -X POST \
  -H "Content-Type: multipart/form-data" \
  -H "X-API-Key: $TYPOSENTINEL_API_KEYS" \
  -F "file=@requirements.txt" \
  http://localhost:8080/api/v1/scan/file
```

## 🔧 Configuration

### Database Configuration

#### SQLite (Default)
```bash
TYPOSENTINEL_DB_TYPE=sqlite
TYPOSENTINEL_DB_PATH=./data/typosentinel.db
```

#### PostgreSQL
```bash
TYPOSENTINEL_DB_TYPE=postgres
TYPOSENTINEL_DB_HOST=localhost
TYPOSENTINEL_DB_PORT=5432
TYPOSENTINEL_DB_NAME=typosentinel
TYPOSENTINEL_DB_USER=typosentinel
TYPOSENTINEL_DB_PASSWORD=your-secure-password
TYPOSENTINEL_DB_SSLMODE=require
```

### Redis Configuration (Optional)
```bash
TYPOSENTINEL_REDIS_ENABLED=true
TYPOSENTINEL_REDIS_HOST=localhost
TYPOSENTINEL_REDIS_PORT=6379
TYPOSENTINEL_REDIS_PASSWORD=your-redis-password
TYPOSENTINEL_REDIS_DB=0
```

### Logging Configuration
```bash
TYPOSENTINEL_LOG_LEVEL=info
TYPOSENTINEL_LOG_FORMAT=json
TYPOSENTINEL_AUDIT_LOGGING=true
TYPOSENTINEL_LOG_FILE=/var/log/typosentinel/app.log
```

## 🚀 Production Deployment

### Using Systemd

1. **Copy the service file:**
   ```bash
   sudo cp scripts/systemd/typosentinel.service /etc/systemd/system/
   ```

2. **Create user and directories:**
   ```bash
   sudo useradd -r -s /bin/false typosentinel
   sudo mkdir -p /opt/typosentinel/data
   sudo chown -R typosentinel:typosentinel /opt/typosentinel
   ```

3. **Install the binary:**
   ```bash
   sudo cp typosentinel /opt/typosentinel/
   sudo cp .env /opt/typosentinel/
   sudo chmod 600 /opt/typosentinel/.env
   sudo chown typosentinel:typosentinel /opt/typosentinel/.env
   ```

4. **Start the service:**
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable typosentinel
   sudo systemctl start typosentinel
   ```

### Using Docker

```dockerfile
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o typosentinel cmd/typosentinel/main.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/typosentinel .
COPY --from=builder /app/.env .
CMD ["./typosentinel", "server"]
```

### Using Nginx Reverse Proxy

Use the provided nginx configuration:
```bash
sudo cp scripts/nginx/typosentinel.conf /etc/nginx/sites-available/
sudo ln -s /etc/nginx/sites-available/typosentinel.conf /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

## 🔍 Security Validation

### Run Security Check
```bash
go run cmd/security-check/main.go
```

This will validate:
- JWT secret strength
- Admin password complexity
- Encryption key configuration
- API key setup
- Production readiness

### Security Checklist

Follow the comprehensive security checklist in `SECURITY_CHECKLIST.md` to ensure your deployment meets security best practices.

## 📈 Monitoring

### Health Check
```bash
curl http://localhost:8080/health
```

### Metrics
```bash
curl http://localhost:8080/metrics
```

### Logs
```bash
# View application logs
journalctl -u typosentinel -f

# View audit logs
tail -f /var/log/typosentinel/audit.log
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run security checks: `go run cmd/security-check/main.go`
5. Run tests: `go test ./...`
6. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Documentation:** [docs/](docs/)
- **Issues:** [GitHub Issues](https://github.com/your-org/typosentinel/issues)
- **Security:** security@your-domain.com
- **Community:** [Discussions](https://github.com/your-org/typosentinel/discussions)

## ⚠️ Security Notice

- Never commit `.env` files to version control
- Regularly rotate secrets and API keys
- Monitor security logs for suspicious activity
- Keep Typosentinel updated with latest security patches
- Follow the security checklist for production deployments

---

**Typosentinel OSS** - Protecting your software supply chain, one package at a time. 🛡️