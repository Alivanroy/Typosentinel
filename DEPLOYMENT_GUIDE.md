# 🚀 TypoSentinel v1.0.0 Deployment Guide

This guide covers deploying TypoSentinel v1.0.0 across different platforms and environments.

## 📦 Release Assets

### Binary Downloads
All platform binaries are available at: https://github.com/Alivanroy/Typosentinel/releases/tag/v1.0.0

| Platform | Architecture | Download Link |
|----------|-------------|---------------|
| Linux | amd64 | [typosentinel-v1.0.0-linux-amd64.tar.gz](https://github.com/Alivanroy/Typosentinel/releases/download/v1.0.0/typosentinel-v1.0.0-linux-amd64.tar.gz) |
| Linux | arm64 | [typosentinel-v1.0.0-linux-arm64.tar.gz](https://github.com/Alivanroy/Typosentinel/releases/download/v1.0.0/typosentinel-v1.0.0-linux-arm64.tar.gz) |
| macOS | Intel | [typosentinel-v1.0.0-darwin-amd64.tar.gz](https://github.com/Alivanroy/Typosentinel/releases/download/v1.0.0/typosentinel-v1.0.0-darwin-amd64.tar.gz) |
| macOS | Apple Silicon | [typosentinel-v1.0.0-darwin-arm64.tar.gz](https://github.com/Alivanroy/Typosentinel/releases/download/v1.0.0/typosentinel-v1.0.0-darwin-arm64.tar.gz) |
| Windows | amd64 | [typosentinel-v1.0.0-windows-amd64.exe.zip](https://github.com/Alivanroy/Typosentinel/releases/download/v1.0.0/typosentinel-v1.0.0-windows-amd64.exe.zip) |
| Windows | arm64 | [typosentinel-v1.0.0-windows-arm64.exe.zip](https://github.com/Alivanroy/Typosentinel/releases/download/v1.0.0/typosentinel-v1.0.0-windows-arm64.exe.zip) |
| FreeBSD | amd64 | [typosentinel-v1.0.0-freebsd-amd64.tar.gz](https://github.com/Alivanroy/Typosentinel/releases/download/v1.0.0/typosentinel-v1.0.0-freebsd-amd64.tar.gz) |

## 🛠️ Installation Methods

### 1. Quick Install Script (Linux/macOS)
```bash
curl -sSL https://github.com/Alivanroy/Typosentinel/releases/download/v1.0.0/install.sh | bash
```

### 2. Manual Installation

#### Linux/macOS
```bash
# Download and extract
wget https://github.com/Alivanroy/Typosentinel/releases/download/v1.0.0/typosentinel-v1.0.0-linux-amd64.tar.gz
tar -xzf typosentinel-v1.0.0-linux-amd64.tar.gz

# Install to system path
sudo mv typosentinel-v1.0.0-linux-amd64 /usr/local/bin/typosentinel
sudo chmod +x /usr/local/bin/typosentinel

# Verify installation
typosentinel --version
```

#### Windows
```powershell
# Download and extract the ZIP file
# Move the executable to a directory in your PATH
# Or run directly from the extracted location
.\typosentinel-v1.0.0-windows-amd64.exe --version
```

### 3. Docker Deployment

#### Basic Docker Run
```bash
# Pull the image
docker pull ghcr.io/alivanroy/typosentinel:v1.0.0

# Run the container
docker run -p 8080:8080 ghcr.io/alivanroy/typosentinel:v1.0.0
```

#### Docker Compose
```yaml
version: '3.8'
services:
  typosentinel:
    image: ghcr.io/alivanroy/typosentinel:v1.0.0
    ports:
      - "8080:8080"
    environment:
      - TYPOSENTINEL_LOG_LEVEL=info
      - TYPOSENTINEL_DB_PATH=/data/typosentinel.db
    volumes:
      - typosentinel_data:/data
    restart: unless-stopped

volumes:
  typosentinel_data:
```

## 🏢 Enterprise Deployment

### Kubernetes Deployment
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: typosentinel
  namespace: security
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
        image: ghcr.io/alivanroy/typosentinel:v1.0.0
        ports:
        - containerPort: 8080
        env:
        - name: TYPOSENTINEL_LOG_LEVEL
          value: "info"
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
---
apiVersion: v1
kind: Service
metadata:
  name: typosentinel-service
  namespace: security
spec:
  selector:
    app: typosentinel
  ports:
  - port: 80
    targetPort: 8080
  type: LoadBalancer
```

### Helm Chart
```yaml
# values.yaml
replicaCount: 3

image:
  repository: ghcr.io/alivanroy/typosentinel
  tag: v1.0.0
  pullPolicy: IfNotPresent

service:
  type: LoadBalancer
  port: 80
  targetPort: 8080

ingress:
  enabled: true
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: letsencrypt-prod
  hosts:
    - host: typosentinel.company.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: typosentinel-tls
      hosts:
        - typosentinel.company.com

resources:
  limits:
    cpu: 500m
    memory: 512Mi
  requests:
    cpu: 250m
    memory: 256Mi

autoscaling:
  enabled: true
  minReplicas: 3
  maxReplicas: 10
  targetCPUUtilizationPercentage: 80
```

## 🔧 CI/CD Integration

### GitHub Actions
```yaml
name: TypoSentinel Security Scan
on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    
    - name: Download TypoSentinel
      run: |
        curl -sSL https://github.com/Alivanroy/Typosentinel/releases/download/v1.0.0/install.sh | bash
    
    - name: Run Security Scan
      run: |
        typosentinel scan . --output json > security-report.json
    
    - name: Upload Security Report
      uses: actions/upload-artifact@v3
      with:
        name: security-report
        path: security-report.json
```

### GitLab CI
```yaml
stages:
  - security

typosentinel_scan:
  stage: security
  image: ghcr.io/alivanroy/typosentinel:v1.0.0
  script:
    - typosentinel scan . --output json > security-report.json
  artifacts:
    reports:
      security: security-report.json
    expire_in: 1 week
  only:
    - main
    - merge_requests
```

### Jenkins Pipeline
```groovy
pipeline {
    agent any
    
    stages {
        stage('Security Scan') {
            steps {
                script {
                    docker.image('ghcr.io/alivanroy/typosentinel:v1.0.0').inside {
                        sh 'typosentinel scan . --output json > security-report.json'
                    }
                }
                archiveArtifacts artifacts: 'security-report.json'
            }
        }
    }
}
```

## 🌐 Platform-Specific Deployments

### AWS ECS
```json
{
  "family": "typosentinel",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "256",
  "memory": "512",
  "executionRoleArn": "arn:aws:iam::account:role/ecsTaskExecutionRole",
  "containerDefinitions": [
    {
      "name": "typosentinel",
      "image": "ghcr.io/alivanroy/typosentinel:v1.0.0",
      "portMappings": [
        {
          "containerPort": 8080,
          "protocol": "tcp"
        }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/typosentinel",
          "awslogs-region": "us-west-2",
          "awslogs-stream-prefix": "ecs"
        }
      }
    }
  ]
}
```

### Azure Container Instances
```bash
az container create \
  --resource-group myResourceGroup \
  --name typosentinel \
  --image ghcr.io/alivanroy/typosentinel:v1.0.0 \
  --ports 8080 \
  --dns-name-label typosentinel-aci \
  --location eastus
```

### Google Cloud Run
```bash
gcloud run deploy typosentinel \
  --image ghcr.io/alivanroy/typosentinel:v1.0.0 \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated \
  --port 8080
```

## 📊 Monitoring & Observability

### Prometheus Configuration
```yaml
scrape_configs:
  - job_name: 'typosentinel'
    static_configs:
      - targets: ['typosentinel:8080']
    metrics_path: '/metrics'
    scrape_interval: 30s
```

### Grafana Dashboard
Import the TypoSentinel dashboard from: `config/grafana-dashboard.json`

### Health Checks
```bash
# Health check endpoint
curl http://localhost:8080/health

# Metrics endpoint
curl http://localhost:8080/metrics

# Ready check
curl http://localhost:8080/ready
```

## 🔒 Security Configuration

### TLS Configuration
```yaml
# config.yaml
server:
  tls:
    enabled: true
    cert_file: "/etc/ssl/certs/typosentinel.crt"
    key_file: "/etc/ssl/private/typosentinel.key"
    min_version: "1.3"
```

### Authentication Setup
```yaml
auth:
  ldap:
    enabled: true
    host: "ldap.company.com"
    port: 636
    use_tls: true
    bind_dn: "cn=typosentinel,ou=service,dc=company,dc=com"
    base_dn: "dc=company,dc=com"
    user_filter: "(uid=%s)"
    group_filter: "(memberUid=%s)"
```

## 🚀 Performance Tuning

### Resource Requirements
| Deployment Size | CPU | Memory | Storage |
|----------------|-----|--------|---------|
| Small (< 1000 packages/day) | 0.5 cores | 512MB | 1GB |
| Medium (< 10000 packages/day) | 1 core | 1GB | 5GB |
| Large (< 100000 packages/day) | 2 cores | 2GB | 20GB |
| Enterprise (> 100000 packages/day) | 4+ cores | 4GB+ | 50GB+ |

### Database Optimization
```yaml
database:
  max_connections: 100
  connection_timeout: 30s
  query_timeout: 60s
  cache_size: 256MB
```

## 📞 Support & Troubleshooting

### Common Issues
1. **Port already in use**: Change the port with `--port 8081`
2. **Permission denied**: Run with appropriate permissions or use Docker
3. **Database connection failed**: Check database configuration and connectivity

### Logs
```bash
# View logs
typosentinel --log-level debug

# Docker logs
docker logs typosentinel-container

# Kubernetes logs
kubectl logs -f deployment/typosentinel
```

### Support Channels
- GitHub Issues: https://github.com/Alivanroy/Typosentinel/issues
- Documentation: https://github.com/Alivanroy/Typosentinel/tree/main/docs
- Security Reports: security@typosentinel.com

---

For more detailed configuration options, see the [Configuration Guide](docs/USER_GUIDE.md).