#!/bin/bash

# TypoSentinel Docker Quick Start Script
# This script sets up a complete TypoSentinel environment with Docker Compose

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
TYPOSENTINEL_VERSION="latest"
PROJECT_NAME="typosentinel"
BASE_DIR="$(pwd)/typosentinel-docker"

# Functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_requirements() {
    log_info "Checking system requirements..."
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed. Please install Docker first."
        exit 1
    fi
    
    # Check Docker Compose
    if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
        log_error "Docker Compose is not installed. Please install Docker Compose first."
        exit 1
    fi
    
    # Check available ports
    for port in 80 443 3000 5432 6379 8080 9090 9091; do
        if lsof -Pi :$port -sTCP:LISTEN -t >/dev/null 2>&1; then
            log_warning "Port $port is already in use. You may need to modify the configuration."
        fi
    done
    
    log_success "System requirements check completed"
}

create_directory_structure() {
    log_info "Creating directory structure..."
    
    mkdir -p "$BASE_DIR"/{config,data,logs,backups,scripts}
    mkdir -p "$BASE_DIR"/config/{grafana/{dashboards,datasources},nginx,fluentd}
    mkdir -p "$BASE_DIR"/logs/{nginx,typosentinel}
    
    log_success "Directory structure created at $BASE_DIR"
}

generate_configurations() {
    log_info "Generating configuration files..."
    
    # TypoSentinel configuration
    cat > "$BASE_DIR/config/typosentinel.yaml" << 'EOF'
# TypoSentinel Docker Configuration
scanner:
  timeout: "60s"
  max_concurrency: 5
  exclude_patterns:
    - "node_modules"
    - "vendor"
    - ".git"
  include_dev_deps: false
  scan_depth: "medium"

detector:
  thresholds:
    typosquatting: 0.8
    suspicious_name: 0.7
    dependency_confusion: 0.8
  algorithms:
    - "levenshtein"
    - "jaro_winkler"
    - "phonetic"

output:
  format: "json"
  include_package_details: true
  include_metadata: true
  pretty_print: true

database:
  type: "postgres"
  host: "postgres"
  port: 5432
  name: "typosentinel"
  user: "typosentinel"
  password: "secure_password_change_me"

cache:
  type: "redis"
  host: "redis"
  port: 6379
  db: 0

web:
  host: "0.0.0.0"
  port: 8080
  enable_auth: false
  session_timeout: "24h"

logging:
  level: "info"
  structured: true
  file: "/app/logs/typosentinel.log"
EOF

    # Redis configuration
    cat > "$BASE_DIR/config/redis.conf" << 'EOF'
# Redis configuration for TypoSentinel
bind 0.0.0.0
port 6379
timeout 300
tcp-keepalive 60
maxmemory 256mb
maxmemory-policy allkeys-lru
save 900 1
save 300 10
save 60 10000
EOF

    # PostgreSQL initialization
    cat > "$BASE_DIR/config/init.sql" << 'EOF'
-- TypoSentinel database initialization
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Scan results table
CREATE TABLE IF NOT EXISTS scan_results (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    repository VARCHAR(255) NOT NULL,
    scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(50) NOT NULL,
    threat_count INTEGER DEFAULT 0,
    risk_score DECIMAL(3,2) DEFAULT 0.0,
    results JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Threat patterns table
CREATE TABLE IF NOT EXISTS threat_patterns (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    pattern_type VARCHAR(100) NOT NULL,
    pattern_value TEXT NOT NULL,
    confidence DECIMAL(3,2) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Configuration history
CREATE TABLE IF NOT EXISTS config_history (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    config_data JSONB NOT NULL,
    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    applied_by VARCHAR(255)
);

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_scan_results_repository ON scan_results(repository);
CREATE INDEX IF NOT EXISTS idx_scan_results_scan_time ON scan_results(scan_time);
CREATE INDEX IF NOT EXISTS idx_threat_patterns_type ON threat_patterns(pattern_type);
EOF

    # Prometheus configuration
    cat > "$BASE_DIR/config/prometheus.yml" << 'EOF'
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'typosentinel'
    static_configs:
      - targets: ['typosentinel:9090']
    scrape_interval: 30s
    metrics_path: /metrics

  - job_name: 'redis'
    static_configs:
      - targets: ['redis:6379']

  - job_name: 'postgres'
    static_configs:
      - targets: ['postgres:5432']
EOF

    # Nginx configuration
    cat > "$BASE_DIR/config/nginx/nginx.conf" << 'EOF'
events {
    worker_connections 1024;
}

http {
    upstream typosentinel {
        server typosentinel:8080;
    }

    upstream grafana {
        server grafana:3000;
    }

    server {
        listen 80;
        server_name localhost;

        # Security headers
        add_header X-Frame-Options "SAMEORIGIN" always;
        add_header X-XSS-Protection "1; mode=block" always;
        add_header X-Content-Type-Options "nosniff" always;

        # TypoSentinel dashboard
        location / {
            proxy_pass http://typosentinel;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        # Grafana monitoring
        location /grafana/ {
            proxy_pass http://grafana/;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        # Health check
        location /health {
            access_log off;
            return 200 "healthy\n";
            add_header Content-Type text/plain;
        }
    }
}
EOF

    # Grafana datasource
    cat > "$BASE_DIR/config/grafana/datasources/prometheus.yml" << 'EOF'
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
EOF

    # Backup script
    cat > "$BASE_DIR/scripts/backup.sh" << 'EOF'
#!/bin/bash

# TypoSentinel backup script
BACKUP_DIR="/backups"
DATE=$(date +%Y%m%d_%H%M%S)

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Backup PostgreSQL database
pg_dump -h postgres -U typosentinel -d typosentinel > "$BACKUP_DIR/typosentinel_db_$DATE.sql"

# Compress backup
gzip "$BACKUP_DIR/typosentinel_db_$DATE.sql"

# Keep only last 7 days of backups
find "$BACKUP_DIR" -name "*.sql.gz" -mtime +7 -delete

echo "Backup completed: typosentinel_db_$DATE.sql.gz"
EOF

    chmod +x "$BASE_DIR/scripts/backup.sh"
    
    log_success "Configuration files generated"
}

copy_docker_compose() {
    log_info "Copying Docker Compose configuration..."
    
    # Copy the docker-compose.yml to the base directory
    cp "$(dirname "$0")/docker-compose.yml" "$BASE_DIR/"
    
    log_success "Docker Compose configuration copied"
}

start_services() {
    log_info "Starting TypoSentinel services..."
    
    cd "$BASE_DIR"
    
    # Pull latest images
    docker-compose pull
    
    # Start services
    docker-compose up -d
    
    # Wait for services to be ready
    log_info "Waiting for services to start..."
    sleep 30
    
    # Check service health
    if docker-compose ps | grep -q "Up"; then
        log_success "Services started successfully"
    else
        log_error "Some services failed to start. Check logs with: docker-compose logs"
        exit 1
    fi
}

display_access_info() {
    log_success "TypoSentinel Docker deployment completed!"
    echo
    echo "🌐 Access URLs:"
    echo "  • TypoSentinel Dashboard: http://localhost:8080"
    echo "  • Grafana Monitoring: http://localhost:3000 (admin/admin_change_me)"
    echo "  • Prometheus Metrics: http://localhost:9091"
    echo
    echo "📁 Project Directory: $BASE_DIR"
    echo
    echo "🔧 Useful Commands:"
    echo "  • View logs: cd $BASE_DIR && docker-compose logs -f"
    echo "  • Stop services: cd $BASE_DIR && docker-compose down"
    echo "  • Restart services: cd $BASE_DIR && docker-compose restart"
    echo "  • Update services: cd $BASE_DIR && docker-compose pull && docker-compose up -d"
    echo "  • Backup database: cd $BASE_DIR && docker-compose run --rm backup"
    echo
    echo "📖 Documentation: https://github.com/alikorsi/typosentinel/docs"
    echo
    log_warning "Remember to change default passwords in production!"
}

# Main execution
main() {
    echo "🛡️  TypoSentinel Docker Quick Start"
    echo "=================================="
    echo
    
    check_requirements
    create_directory_structure
    generate_configurations
    copy_docker_compose
    start_services
    display_access_info
}

# Run main function
main "$@"