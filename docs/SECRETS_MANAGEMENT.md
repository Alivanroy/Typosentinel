# Secrets Management Guide

## 🔐 Overview

This guide provides comprehensive instructions for securely managing secrets, credentials, and sensitive configuration data in TypoSentinel. Proper secrets management is critical for production security.

## 🚨 Security Principles

### 1. Never Hardcode Secrets
- ❌ **NEVER** commit secrets to version control
- ❌ **NEVER** hardcode credentials in configuration files
- ❌ **NEVER** log sensitive information
- ✅ **ALWAYS** use environment variables or external secret stores
- ✅ **ALWAYS** encrypt secrets at rest
- ✅ **ALWAYS** rotate secrets regularly

### 2. Principle of Least Privilege
- Grant minimal necessary permissions
- Use service-specific credentials
- Implement time-limited access tokens
- Regular access reviews and cleanup

### 3. Defense in Depth
- Multiple layers of security
- Encryption in transit and at rest
- Access logging and monitoring
- Regular security audits

## 🔧 Supported Secret Stores

### 1. Environment Variables (Default)
Best for development and simple deployments.

```bash
# Required Environment Variables
export POSTGRES_PASSWORD="your-secure-db-password"
export JWT_SECRET="your-jwt-secret-key-min-32-chars"
export ENCRYPTION_KEY="your-encryption-key-32-bytes"
export ADMIN_PASSWORD="your-admin-password"

# Optional API Keys
export VIRUSTOTAL_API_KEY="your-virustotal-api-key"
export ML_API_KEY="your-ml-service-api-key"
export GITHUB_TOKEN="your-github-token"
```

### 2. HashiCorp Vault
Recommended for production environments.

#### Setup
```bash
# Install Vault
curl -fsSL https://apt.releases.hashicorp.com/gpg | sudo apt-key add -
sudo apt-add-repository "deb [arch=amd64] https://apt.releases.hashicorp.com $(lsb_release -cs) main"
sudo apt-get update && sudo apt-get install vault

# Start Vault server
vault server -dev

# Set environment variables
export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_TOKEN="your-vault-token"
```

#### Configuration
```yaml
# config/secrets.yaml
secrets:
  provider: "vault"
  vault:
    address: "${VAULT_ADDR}"
    token: "${VAULT_TOKEN}"
    mount_path: "secret"
    kv_version: 2
```

#### Store Secrets
```bash
# Store database credentials
vault kv put secret/typosentinel/database \
  username="postgres" \
  password="your-secure-password"

# Store JWT secret
vault kv put secret/typosentinel/jwt \
  secret="your-jwt-secret-key"

# Store API keys
vault kv put secret/typosentinel/api-keys \
  virustotal="your-vt-key" \
  github="your-github-token"
```

### 3. AWS Secrets Manager
For AWS-hosted deployments.

#### Setup
```bash
# Install AWS CLI
pip install awscli

# Configure credentials
aws configure
```

#### Configuration
```yaml
secrets:
  provider: "aws_secrets_manager"
  aws:
    region: "us-west-2"
    secret_name: "typosentinel/production"
```

#### Store Secrets
```bash
# Create secret
aws secretsmanager create-secret \
  --name "typosentinel/production" \
  --description "TypoSentinel production secrets"

# Store secret value
aws secretsmanager put-secret-value \
  --secret-id "typosentinel/production" \
  --secret-string '{
    "database_password": "your-secure-password",
    "jwt_secret": "your-jwt-secret",
    "encryption_key": "your-encryption-key"
  }'
```

### 4. Azure Key Vault
For Azure-hosted deployments.

#### Setup
```bash
# Install Azure CLI
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

# Login
az login
```

#### Configuration
```yaml
secrets:
  provider: "azure_key_vault"
  azure:
    vault_url: "https://your-vault.vault.azure.net/"
    tenant_id: "${AZURE_TENANT_ID}"
    client_id: "${AZURE_CLIENT_ID}"
    client_secret: "${AZURE_CLIENT_SECRET}"
```

#### Store Secrets
```bash
# Create Key Vault
az keyvault create \
  --name "typosentinel-vault" \
  --resource-group "typosentinel-rg" \
  --location "westus2"

# Store secrets
az keyvault secret set \
  --vault-name "typosentinel-vault" \
  --name "database-password" \
  --value "your-secure-password"

az keyvault secret set \
  --vault-name "typosentinel-vault" \
  --name "jwt-secret" \
  --value "your-jwt-secret"
```

## 🔑 Secret Types and Requirements

### 1. Database Credentials
```bash
# PostgreSQL
POSTGRES_HOST="localhost"
POSTGRES_PORT="5432"
POSTGRES_DB="typosentinel"
POSTGRES_USER="typosentinel_user"
POSTGRES_PASSWORD="$(openssl rand -base64 32)"

# Redis
REDIS_HOST="localhost"
REDIS_PORT="6379"
REDIS_PASSWORD="$(openssl rand -base64 32)"
```

### 2. JWT Secrets
```bash
# Generate secure JWT secret (minimum 32 characters)
JWT_SECRET="$(openssl rand -base64 48)"
```

### 3. Encryption Keys
```bash
# Generate encryption key (32 bytes for AES-256)
ENCRYPTION_KEY="$(openssl rand -hex 32)"

# Generate backup encryption key
BACKUP_ENCRYPTION_KEY="$(openssl rand -hex 32)"
```

### 4. API Keys
```bash
# External service API keys
VIRUSTOTAL_API_KEY="your-virustotal-api-key"
GITHUB_TOKEN="ghp_your-github-token"
ML_API_KEY="your-ml-service-api-key"
SLACK_WEBHOOK_URL="https://hooks.slack.com/services/..."
```

### 5. TLS Certificates
```bash
# Generate self-signed certificate for development
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes

# Set certificate paths
TLS_CERT_FILE="/path/to/cert.pem"
TLS_KEY_FILE="/path/to/key.pem"
```

## 🔄 Secret Rotation

### Automated Rotation
```yaml
# config/rotation.yaml
rotation:
  enabled: true
  schedule: "0 2 * * 0"  # Weekly on Sunday at 2 AM
  secrets:
    - name: "jwt_secret"
      type: "jwt"
      rotation_interval: "30d"
    - name: "api_keys"
      type: "api_key"
      rotation_interval: "90d"
    - name: "encryption_key"
      type: "encryption"
      rotation_interval: "365d"
```

### Manual Rotation
```bash
# Rotate JWT secret
./scripts/rotate-secret.sh jwt_secret

# Rotate API keys
./scripts/rotate-secret.sh api_keys

# Rotate encryption key (requires data re-encryption)
./scripts/rotate-secret.sh encryption_key --force
```

## 🛡️ Security Best Practices

### 1. Secret Generation
```bash
# Use cryptographically secure random generators
openssl rand -base64 32    # For passwords/secrets
openssl rand -hex 32       # For encryption keys
uuidgen                    # For unique identifiers

# Avoid weak patterns
❌ password123
❌ admin
❌ secret
✅ $(openssl rand -base64 32)
```

### 2. Secret Storage
```bash
# File permissions for secret files
chmod 600 /path/to/secret/file
chown app:app /path/to/secret/file

# Environment variable security
# Use process isolation
# Clear environment after use
unset SENSITIVE_VAR
```

### 3. Secret Transmission
```bash
# Always use TLS for secret transmission
curl -H "Authorization: Bearer $TOKEN" \
     https://api.example.com/secure-endpoint

# Never log secrets
# Use redacted logging
echo "Token: [REDACTED]" >> app.log
```

## 📋 Deployment Configurations

### Development Environment
```bash
# .env.development
POSTGRES_PASSWORD="dev-password-change-me"
JWT_SECRET="dev-jwt-secret-min-32-chars-change-for-prod"
ENCRYPTION_KEY="dev-encryption-key-change-for-production"
DEBUG_MODE="true"
```

### Staging Environment
```bash
# Use staging-specific secrets
POSTGRES_PASSWORD="$(vault kv get -field=password secret/typosentinel/staging/database)"
JWT_SECRET="$(vault kv get -field=secret secret/typosentinel/staging/jwt)"
ENCRYPTION_KEY="$(vault kv get -field=key secret/typosentinel/staging/encryption)"
```

### Production Environment
```bash
# Use production secret store
VAULT_ADDR="https://vault.production.com"
VAULT_TOKEN="$(cat /var/secrets/vault-token)"
SECRET_PROVIDER="vault"
```

## 🔍 Monitoring and Auditing

### Secret Access Logging
```yaml
# config/audit.yaml
audit:
  secret_access:
    enabled: true
    log_level: "info"
    include_metadata: true
    retention_days: 90
```

### Monitoring Alerts
```yaml
# config/alerts.yaml
alerts:
  secret_rotation_failed:
    enabled: true
    severity: "high"
    channels: ["slack", "email"]
  
  unauthorized_secret_access:
    enabled: true
    severity: "critical"
    channels: ["slack", "email", "pagerduty"]
```

## 🚨 Incident Response

### Secret Compromise Response
1. **Immediate Actions**
   - Rotate compromised secrets immediately
   - Revoke access tokens
   - Monitor for unauthorized access
   - Document the incident

2. **Investigation**
   - Review access logs
   - Identify scope of compromise
   - Assess potential impact
   - Implement additional controls

3. **Recovery**
   - Update all affected systems
   - Verify security controls
   - Conduct post-incident review
   - Update procedures

### Emergency Rotation Script
```bash
#!/bin/bash
# scripts/emergency-rotate.sh

echo "🚨 Emergency secret rotation initiated"

# Rotate all critical secrets
./scripts/rotate-secret.sh jwt_secret --emergency
./scripts/rotate-secret.sh api_keys --emergency
./scripts/rotate-secret.sh database_password --emergency

echo "✅ Emergency rotation completed"
```

## 📚 Additional Resources

### Tools
- [HashiCorp Vault](https://www.vaultproject.io/)
- [AWS Secrets Manager](https://aws.amazon.com/secrets-manager/)
- [Azure Key Vault](https://azure.microsoft.com/en-us/services/key-vault/)
- [Google Secret Manager](https://cloud.google.com/secret-manager)

### Security Standards
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [OWASP Secrets Management](https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password)
- [CIS Controls](https://www.cisecurity.org/controls/)

### Compliance
- [SOC 2 Type II](https://www.aicpa.org/interestareas/frc/assuranceadvisoryservices/aicpasoc2report.html)
- [ISO 27001](https://www.iso.org/isoiec-27001-information-security.html)
- [GDPR](https://gdpr.eu/)

---

**Security Contact**: security@typosentinel.com  
**Last Updated**: January 15, 2025  
**Next Review**: February 15, 2025