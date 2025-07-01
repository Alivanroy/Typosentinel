#!/bin/bash

# TypoSentinel Demo Backup Script
# Creates backups of the demo application and configuration

set -e

# Configuration
APP_DIR="/opt/typosentinel-demo"
BACKUP_DIR="/opt/backups/typosentinel-demo"
RETENTION_DAYS=30
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_NAME="typosentinel-demo_${TIMESTAMP}"

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Create backup directory
create_backup_dir() {
    log_info "Creating backup directory..."
    mkdir -p "$BACKUP_DIR"
}

# Backup application files
backup_application() {
    log_info "Backing up application files..."
    
    if [ ! -d "$APP_DIR" ]; then
        log_error "Application directory $APP_DIR not found!"
        exit 1
    fi
    
    # Create backup archive
    tar -czf "$BACKUP_DIR/${BACKUP_NAME}_app.tar.gz" -C "$APP_DIR" .
    
    log_info "Application backup created: ${BACKUP_NAME}_app.tar.gz"
}

# Backup Docker data
backup_docker() {
    log_info "Backing up Docker configuration..."
    
    cd "$APP_DIR"
    
    # Export Docker images
    docker save typosentinel-demo:latest | gzip > "$BACKUP_DIR/${BACKUP_NAME}_image.tar.gz" 2>/dev/null || {
        log_warning "Could not backup Docker image (may not exist yet)"
    }
    
    # Backup Docker Compose configuration
    cp docker-compose.yml "$BACKUP_DIR/${BACKUP_NAME}_docker-compose.yml"
    
    log_info "Docker backup completed"
}

# Backup SSL certificates
backup_ssl() {
    log_info "Backing up SSL certificates..."
    
    if [ -d "$APP_DIR/ssl" ] && [ "$(ls -A $APP_DIR/ssl)" ]; then
        tar -czf "$BACKUP_DIR/${BACKUP_NAME}_ssl.tar.gz" -C "$APP_DIR" ssl/
        log_info "SSL certificates backed up"
    else
        log_warning "No SSL certificates found to backup"
    fi
}

# Backup logs
backup_logs() {
    log_info "Backing up logs..."
    
    if [ -d "$APP_DIR/logs" ] && [ "$(ls -A $APP_DIR/logs)" ]; then
        tar -czf "$BACKUP_DIR/${BACKUP_NAME}_logs.tar.gz" -C "$APP_DIR" logs/
        log_info "Logs backed up"
    else
        log_warning "No logs found to backup"
    fi
}

# Backup system configuration
backup_system_config() {
    log_info "Backing up system configuration..."
    
    # Create system config backup
    mkdir -p "$BACKUP_DIR/system_config_$TIMESTAMP"
    
    # Backup crontab
    crontab -l > "$BACKUP_DIR/system_config_$TIMESTAMP/crontab.txt" 2>/dev/null || {
        echo "No crontab found" > "$BACKUP_DIR/system_config_$TIMESTAMP/crontab.txt"
    }
    
    # Backup firewall rules
    ufw status verbose > "$BACKUP_DIR/system_config_$TIMESTAMP/ufw_status.txt" 2>/dev/null || {
        echo "UFW not configured" > "$BACKUP_DIR/system_config_$TIMESTAMP/ufw_status.txt"
    }
    
    # Backup nginx configuration (if installed separately)
    if [ -f "/etc/nginx/nginx.conf" ]; then
        cp /etc/nginx/nginx.conf "$BACKUP_DIR/system_config_$TIMESTAMP/nginx.conf"
    fi
    
    # Backup Let's Encrypt certificates (if exist)
    if [ -d "/etc/letsencrypt" ]; then
        tar -czf "$BACKUP_DIR/system_config_$TIMESTAMP/letsencrypt.tar.gz" -C "/etc" letsencrypt/ 2>/dev/null || {
            log_warning "Could not backup Let's Encrypt certificates"
        }
    fi
    
    # Create archive of system config
    tar -czf "$BACKUP_DIR/${BACKUP_NAME}_system.tar.gz" -C "$BACKUP_DIR" "system_config_$TIMESTAMP"
    rm -rf "$BACKUP_DIR/system_config_$TIMESTAMP"
    
    log_info "System configuration backed up"
}

# Create backup manifest
create_manifest() {
    log_info "Creating backup manifest..."
    
    cat > "$BACKUP_DIR/${BACKUP_NAME}_manifest.txt" << EOF
TypoSentinel Demo Backup Manifest
================================

Backup Date: $(date)
Backup Name: $BACKUP_NAME
Application Directory: $APP_DIR
Backup Directory: $BACKUP_DIR

Files in this backup:
EOF
    
    ls -la "$BACKUP_DIR" | grep "$BACKUP_NAME" >> "$BACKUP_DIR/${BACKUP_NAME}_manifest.txt"
    
    echo "" >> "$BACKUP_DIR/${BACKUP_NAME}_manifest.txt"
    echo "Docker Status at backup time:" >> "$BACKUP_DIR/${BACKUP_NAME}_manifest.txt"
    cd "$APP_DIR" && docker-compose ps >> "$BACKUP_DIR/${BACKUP_NAME}_manifest.txt" 2>/dev/null || {
        echo "Docker Compose not running" >> "$BACKUP_DIR/${BACKUP_NAME}_manifest.txt"
    }
    
    log_info "Backup manifest created"
}

# Clean old backups
cleanup_old_backups() {
    log_info "Cleaning up old backups (older than $RETENTION_DAYS days)..."
    
    find "$BACKUP_DIR" -name "typosentinel-demo_*" -type f -mtime +$RETENTION_DAYS -delete
    
    # Count remaining backups
    BACKUP_COUNT=$(find "$BACKUP_DIR" -name "typosentinel-demo_*" -type f | wc -l)
    log_info "Cleanup completed. $BACKUP_COUNT backup files remaining."
}

# Verify backup integrity
verify_backup() {
    log_info "Verifying backup integrity..."
    
    # Test each tar.gz file
    for backup_file in "$BACKUP_DIR"/${BACKUP_NAME}_*.tar.gz; do
        if [ -f "$backup_file" ]; then
            if tar -tzf "$backup_file" > /dev/null 2>&1; then
                log_info "✓ $(basename "$backup_file") - OK"
            else
                log_error "✗ $(basename "$backup_file") - CORRUPTED"
                exit 1
            fi
        fi
    done
    
    log_info "All backup files verified successfully"
}

# Show backup summary
show_summary() {
    log_info "Backup Summary:"
    echo "==========================================="
    echo "Backup Location: $BACKUP_DIR"
    echo "Backup Name: $BACKUP_NAME"
    echo "Backup Size: $(du -sh "$BACKUP_DIR" | cut -f1)"
    echo "Files created:"
    ls -la "$BACKUP_DIR" | grep "$BACKUP_NAME" | awk '{print "  " $9 " (" $5 " bytes)"}
    echo "==========================================="
}

# Restore function
restore_backup() {
    local restore_name="$1"
    
    if [ -z "$restore_name" ]; then
        log_error "Please specify backup name to restore"
        echo "Available backups:"
        ls -la "$BACKUP_DIR" | grep "typosentinel-demo_" | awk '{print $9}' | sort -u
        exit 1
    fi
    
    log_info "Restoring backup: $restore_name"
    
    # Stop current application
    cd "$APP_DIR" && docker-compose down 2>/dev/null || true
    
    # Backup current state
    if [ -d "$APP_DIR" ]; then
        mv "$APP_DIR" "${APP_DIR}_backup_$(date +%Y%m%d_%H%M%S)"
    fi
    
    # Restore application files
    mkdir -p "$APP_DIR"
    tar -xzf "$BACKUP_DIR/${restore_name}_app.tar.gz" -C "$APP_DIR"
    
    # Restore SSL certificates if they exist
    if [ -f "$BACKUP_DIR/${restore_name}_ssl.tar.gz" ]; then
        tar -xzf "$BACKUP_DIR/${restore_name}_ssl.tar.gz" -C "$APP_DIR"
    fi
    
    # Restore Docker image if it exists
    if [ -f "$BACKUP_DIR/${restore_name}_image.tar.gz" ]; then
        gunzip -c "$BACKUP_DIR/${restore_name}_image.tar.gz" | docker load
    fi
    
    # Start application
    cd "$APP_DIR" && docker-compose up -d
    
    log_info "Restore completed successfully"
}

# Main function
main() {
    case "${1:-backup}" in
        "backup")
            log_info "Starting TypoSentinel Demo backup..."
            create_backup_dir
            backup_application
            backup_docker
            backup_ssl
            backup_logs
            backup_system_config
            create_manifest
            verify_backup
            cleanup_old_backups
            show_summary
            log_info "Backup completed successfully!"
            ;;
        "restore")
            restore_backup "$2"
            ;;
        "list")
            log_info "Available backups:"
            ls -la "$BACKUP_DIR" | grep "typosentinel-demo_" | awk '{print $9}' | sort -u
            ;;
        "cleanup")
            cleanup_old_backups
            ;;
        "help")
            echo "TypoSentinel Demo Backup Script"
            echo ""
            echo "Usage: $0 [COMMAND] [OPTIONS]"
            echo ""
            echo "Commands:"
            echo "  backup          Create a new backup (default)"
            echo "  restore NAME    Restore from backup"
            echo "  list            List available backups"
            echo "  cleanup         Remove old backups"
            echo "  help            Show this help"
            echo ""
            echo "Examples:"
            echo "  $0                                    # Create backup"
            echo "  $0 restore typosentinel-demo_20241201_120000  # Restore backup"
            echo "  $0 list                               # List backups"
            ;;
        *)
            log_error "Unknown command: $1"
            echo "Use '$0 help' for usage information"
            exit 1
            ;;
    esac
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run as root (use sudo)"
    exit 1
fi

# Run main function
main "$@"