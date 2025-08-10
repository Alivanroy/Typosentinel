#!/bin/bash

# Typosentinel OSS Security Setup Script
# This script helps set up secure configuration for Typosentinel OSS

set -e

echo "🔒 Typosentinel OSS Security Setup"
echo "=================================="

# Check if we're in the right directory
if [ ! -f "go.mod" ] || ! grep -q "Typosentinel" go.mod; then
    echo "❌ Error: Please run this script from the Typosentinel root directory"
    exit 1
fi

# Create .env file if it doesn't exist
if [ ! -f ".env" ]; then
    echo "📝 Creating .env file..."
    touch .env
fi

# Function to generate secure random string
generate_secure_key() {
    local length=${1:-32}
    openssl rand -hex $length 2>/dev/null || head -c $length /dev/urandom | xxd -p | tr -d '\n'
}

# Function to prompt for password
prompt_password() {
    local prompt="$1"
    local password
    echo -n "$prompt"
    read -s password
    echo
    echo "$password"
}

echo
echo "🔧 Generating secure configuration..."

# Generate JWT secret
JWT_SECRET=$(generate_secure_key 32)
echo "✅ Generated JWT secret"

# Generate encryption key (32 characters for AES-256)
ENCRYPTION_KEY=$(generate_secure_key 16)  # 16 bytes = 32 hex chars
echo "✅ Generated encryption key"

# Generate API key
API_KEY=$(generate_secure_key 16)  # 16 bytes = 32 hex chars
echo "✅ Generated API key"

# Prompt for admin password
echo
echo "🔑 Admin Password Setup"
echo "Please create a strong admin password (minimum 12 characters with mixed case, numbers, and symbols):"
ADMIN_PASSWORD=$(prompt_password "Enter admin password: ")

# Validate password strength
if [ ${#ADMIN_PASSWORD} -lt 12 ]; then
    echo "❌ Error: Password must be at least 12 characters long"
    exit 1
fi

# Check for required character types
if ! echo "$ADMIN_PASSWORD" | grep -q '[A-Z]'; then
    echo "❌ Error: Password must contain at least one uppercase letter"
    exit 1
fi

if ! echo "$ADMIN_PASSWORD" | grep -q '[a-z]'; then
    echo "❌ Error: Password must contain at least one lowercase letter"
    exit 1
fi

if ! echo "$ADMIN_PASSWORD" | grep -q '[0-9]'; then
    echo "❌ Error: Password must contain at least one number"
    exit 1
fi

if ! echo "$ADMIN_PASSWORD" | grep -q '[!@#$%^&*()_+\-=\[\]{};'"'"':"\\|,.<>\/?]'; then
    echo "❌ Error: Password must contain at least one special character"
    exit 1
fi

echo "✅ Password meets security requirements"

# Create secure configuration
echo
echo "📝 Writing secure configuration to .env..."

# Backup existing .env if it exists and has content
if [ -s ".env" ]; then
    cp .env .env.backup.$(date +%Y%m%d_%H%M%S)
    echo "📋 Backed up existing .env file"
fi

# Write new configuration
cat > .env << EOF
# Typosentinel OSS Security Configuration
# Generated on $(date)

# Environment
TYPOSENTINEL_ENVIRONMENT=production

# JWT Configuration (REQUIRED)
TYPOSENTINEL_JWT_SECRET=$JWT_SECRET

# Admin Authentication (REQUIRED)
TYPOSENTINEL_ADMIN_PASSWORD=$ADMIN_PASSWORD

# Encryption (REQUIRED for production)
TYPOSENTINEL_ENCRYPTION_KEY=$ENCRYPTION_KEY

# API Security (OPTIONAL)
TYPOSENTINEL_API_KEYS=$API_KEY

# Security Settings
TYPOSENTINEL_ENABLE_TEST_TOKENS=false
TYPOSENTINEL_DISABLE_AUTH=false
TYPOSENTINEL_DEBUG=false

# Database Security (Configure as needed)
# TYPOSENTINEL_DB_PASSWORD=your-database-password

# TLS Configuration (Recommended for production)
# TYPOSENTINEL_TLS_ENABLED=true
# TYPOSENTINEL_TLS_CERT_FILE=/path/to/cert.pem
# TYPOSENTINEL_TLS_KEY_FILE=/path/to/key.pem

# Rate Limiting
TYPOSENTINEL_RATE_LIMIT_ENABLED=true
TYPOSENTINEL_RATE_LIMIT_REQUESTS=100
TYPOSENTINEL_RATE_LIMIT_WINDOW=60

# Logging
TYPOSENTINEL_LOG_LEVEL=info
TYPOSENTINEL_AUDIT_LOGGING=true
EOF

# Set secure permissions
chmod 600 .env
echo "🔒 Set secure permissions on .env file (600)"

# Create systemd service file for production
echo
echo "📋 Creating systemd service file..."
mkdir -p scripts/systemd

cat > scripts/systemd/typosentinel.service << EOF
[Unit]
Description=Typosentinel OSS Security Scanner
After=network.target

[Service]
Type=simple
User=typosentinel
Group=typosentinel
WorkingDirectory=/opt/typosentinel
ExecStart=/opt/typosentinel/typosentinel server
EnvironmentFile=/opt/typosentinel/.env
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/typosentinel/data
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF

echo "✅ Created systemd service file"

# Create nginx configuration for reverse proxy
echo
echo "📋 Creating nginx configuration..."
mkdir -p scripts/nginx

cat > scripts/nginx/typosentinel.conf << EOF
server {
    listen 80;
    server_name your-domain.com;
    return 301 https://\$server_name\$request_uri;
}

server {
    listen 443 ssl http2;
    server_name your-domain.com;

    # SSL Configuration
    ssl_certificate /path/to/your/cert.pem;
    ssl_certificate_key /path/to/your/key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # Security Headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options DENY always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self';" always;

    # Rate Limiting
    limit_req_zone \$binary_remote_addr zone=api:10m rate=10r/s;
    limit_req zone=api burst=20 nodelay;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    # Health check endpoint
    location /health {
        proxy_pass http://127.0.0.1:8080/health;
        access_log off;
    }
}
EOF

echo "✅ Created nginx configuration"

# Create security checklist
echo
echo "📋 Creating security checklist..."

cat > SECURITY_CHECKLIST.md << EOF
# Typosentinel OSS Security Checklist

## Pre-Production Security Checklist

### ✅ Authentication & Authorization
- [ ] Strong admin password configured (12+ characters, mixed case, numbers, symbols)
- [ ] JWT secret is cryptographically secure (32+ characters)
- [ ] Test tokens disabled in production
- [ ] Authentication bypass disabled
- [ ] API keys configured (if using API access)

### ✅ Encryption & Data Protection
- [ ] Encryption key configured for sensitive data
- [ ] Database passwords secured
- [ ] TLS/HTTPS enabled for production
- [ ] Secure file permissions set (600 for .env)

### ✅ Network Security
- [ ] Rate limiting enabled
- [ ] CORS properly configured
- [ ] Security headers implemented
- [ ] Reverse proxy configured (nginx/apache)
- [ ] Firewall rules configured

### ✅ System Security
- [ ] Running as non-root user
- [ ] Systemd security settings applied
- [ ] Log files secured
- [ ] Regular security updates scheduled

### ✅ Monitoring & Logging
- [ ] Audit logging enabled
- [ ] Security event monitoring configured
- [ ] Log rotation configured
- [ ] Backup strategy implemented

### ✅ Operational Security
- [ ] Secrets rotation schedule established
- [ ] Security incident response plan created
- [ ] Regular security assessments scheduled
- [ ] Staff security training completed

## Security Commands

### Run Security Check
\`\`\`bash
go run cmd/security-check/main.go
\`\`\`

### Test Configuration
\`\`\`bash
# Load environment
source .env

# Test authentication
curl -u admin:\$TYPOSENTINEL_ADMIN_PASSWORD http://localhost:8080/api/v1/health

# Test API key
curl -H "X-API-Key: \$TYPOSENTINEL_API_KEYS" http://localhost:8080/api/v1/health
\`\`\`

### Monitor Security
\`\`\`bash
# Check for failed authentication attempts
journalctl -u typosentinel | grep "auth failed"

# Monitor rate limiting
journalctl -u typosentinel | grep "rate limit"
\`\`\`

## Emergency Contacts

- Security Team: security@your-domain.com
- System Admin: admin@your-domain.com
- Emergency: +1-XXX-XXX-XXXX
EOF

echo "✅ Created security checklist"

# Final instructions
echo
echo "🎉 Security setup completed!"
echo "=========================="
echo
echo "📋 Next Steps:"
echo "1. Review the generated .env file and adjust as needed"
echo "2. Configure your database password in .env"
echo "3. Set up TLS certificates for HTTPS"
echo "4. Review and customize nginx configuration"
echo "5. Run security check: go run cmd/security-check/main.go"
echo "6. Follow the security checklist in SECURITY_CHECKLIST.md"
echo
echo "⚠️  Important Security Notes:"
echo "- Keep your .env file secure and never commit it to version control"
echo "- Regularly rotate your secrets and passwords"
echo "- Monitor logs for security events"
echo "- Keep Typosentinel updated with security patches"
echo
echo "🔒 Your Typosentinel OSS installation is now configured with security best practices!"