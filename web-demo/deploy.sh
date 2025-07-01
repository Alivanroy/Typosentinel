#!/bin/bash

# TypoSentinel Web Demo Deployment Script
# For Hostinger VPS deployment

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
APP_NAME="typosentinel-demo"
APP_DIR="/opt/typosentinel-demo"
DOMAIN="your-domain.com"  # Replace with your actual domain
EMAIL="your-email@domain.com"  # Replace with your email for SSL

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

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

install_docker() {
    log_info "Installing Docker..."
    
    # Update package index
    apt-get update
    
    # Install required packages
    apt-get install -y \
        apt-transport-https \
        ca-certificates \
        curl \
        gnupg \
        lsb-release
    
    # Add Docker's official GPG key
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
    
    # Set up the stable repository
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
    
    # Install Docker Engine
    apt-get update
    apt-get install -y docker-ce docker-ce-cli containerd.io
    
    # Install Docker Compose
    curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    chmod +x /usr/local/bin/docker-compose
    
    # Start and enable Docker
    systemctl start docker
    systemctl enable docker
    
    log_success "Docker installed successfully"
}

check_docker() {
    if ! command -v docker &> /dev/null; then
        log_warning "Docker not found. Installing Docker..."
        install_docker
    else
        log_info "Docker is already installed"
    fi
    
    if ! command -v docker-compose &> /dev/null; then
        log_warning "Docker Compose not found. Installing..."
        curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
        chmod +x /usr/local/bin/docker-compose
    else
        log_info "Docker Compose is already installed"
    fi
}

setup_firewall() {
    log_info "Configuring firewall..."
    
    # Install ufw if not present
    apt-get install -y ufw
    
    # Reset firewall rules
    ufw --force reset
    
    # Default policies
    ufw default deny incoming
    ufw default allow outgoing
    
    # Allow SSH (important!)
    ufw allow ssh
    ufw allow 22/tcp
    
    # Allow HTTP and HTTPS
    ufw allow 80/tcp
    ufw allow 443/tcp
    
    # Enable firewall
    ufw --force enable
    
    log_success "Firewall configured"
}

setup_ssl() {
    log_info "Setting up SSL with Let's Encrypt..."
    
    # Install certbot
    apt-get install -y certbot
    
    # Create SSL directory
    mkdir -p $APP_DIR/ssl
    
    # Generate SSL certificate (standalone mode)
    if [[ "$DOMAIN" != "your-domain.com" ]]; then
        certbot certonly --standalone --agree-tos --no-eff-email --email $EMAIL -d $DOMAIN
        
        # Copy certificates to app directory
        cp /etc/letsencrypt/live/$DOMAIN/fullchain.pem $APP_DIR/ssl/cert.pem
        cp /etc/letsencrypt/live/$DOMAIN/privkey.pem $APP_DIR/ssl/key.pem
        
        # Set up auto-renewal
        (crontab -l 2>/dev/null; echo "0 12 * * * /usr/bin/certbot renew --quiet --post-hook 'docker-compose -f $APP_DIR/docker-compose.yml restart web'") | crontab -
        
        log_success "SSL certificate generated for $DOMAIN"
    else
        log_warning "Please update the DOMAIN variable in this script with your actual domain"
        log_warning "SSL setup skipped - using HTTP only"
    fi
}

deploy_app() {
    log_info "Deploying TypoSentinel Demo..."
    
    # Create application directory
    mkdir -p $APP_DIR
    mkdir -p $APP_DIR/logs
    
    # Copy application files (assuming they're in the current directory)
    cp index.html $APP_DIR/
    cp styles.css $APP_DIR/
    cp script.js $APP_DIR/
    cp Dockerfile $APP_DIR/
    cp nginx.conf $APP_DIR/
    cp docker-compose.yml $APP_DIR/
    
    # Set proper permissions
    chown -R root:root $APP_DIR
    chmod -R 755 $APP_DIR
    
    # Navigate to app directory
    cd $APP_DIR
    
    # Stop any existing containers
    docker-compose down 2>/dev/null || true
    
    # Build and start the application
    docker-compose build
    docker-compose up -d
    
    log_success "Application deployed successfully"
}

setup_monitoring() {
    log_info "Setting up basic monitoring..."
    
    # Create monitoring script
    cat > /usr/local/bin/typosentinel-monitor.sh << 'EOF'
#!/bin/bash

# Simple monitoring script for TypoSentinel Demo
APP_DIR="/opt/typosentinel-demo"
LOG_FILE="/var/log/typosentinel-monitor.log"

check_service() {
    if ! docker-compose -f $APP_DIR/docker-compose.yml ps | grep -q "Up"; then
        echo "$(date): Service is down, attempting restart..." >> $LOG_FILE
        cd $APP_DIR
        docker-compose restart
        sleep 30
        if docker-compose ps | grep -q "Up"; then
            echo "$(date): Service restarted successfully" >> $LOG_FILE
        else
            echo "$(date): Failed to restart service" >> $LOG_FILE
        fi
    fi
}

check_disk_space() {
    DISK_USAGE=$(df / | awk 'NR==2 {print $5}' | sed 's/%//')
    if [ $DISK_USAGE -gt 90 ]; then
        echo "$(date): Disk usage is at ${DISK_USAGE}%" >> $LOG_FILE
        # Clean up old Docker images
        docker image prune -f
    fi
}

check_service
check_disk_space
EOF

    chmod +x /usr/local/bin/typosentinel-monitor.sh
    
    # Add to crontab (check every 5 minutes)
    (crontab -l 2>/dev/null; echo "*/5 * * * * /usr/local/bin/typosentinel-monitor.sh") | crontab -
    
    log_success "Monitoring setup complete"
}

show_status() {
    log_info "Deployment Status:"
    echo "=========================================="
    echo "Application Directory: $APP_DIR"
    echo "Domain: $DOMAIN"
    echo "Docker Status:"
    cd $APP_DIR
    docker-compose ps
    echo "=========================================="
    echo "Access your demo at:"
    if [[ "$DOMAIN" != "your-domain.com" ]]; then
        echo "  https://$DOMAIN"
        echo "  http://$DOMAIN"
    else
        echo "  http://$(curl -s ifconfig.me)"
    fi
    echo "=========================================="
}

show_help() {
    echo "TypoSentinel Demo Deployment Script"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --domain DOMAIN    Set the domain name for SSL"
    echo "  --email EMAIL      Set email for SSL certificate"
    echo "  --no-ssl          Skip SSL setup"
    echo "  --no-firewall     Skip firewall configuration"
    echo "  --help            Show this help message"
    echo ""
    echo "Example:"
    echo "  $0 --domain demo.typosentinel.com --email admin@typosentinel.com"
}

# Parse command line arguments
SKIP_SSL=false
SKIP_FIREWALL=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --domain)
            DOMAIN="$2"
            shift 2
            ;;
        --email)
            EMAIL="$2"
            shift 2
            ;;
        --no-ssl)
            SKIP_SSL=true
            shift
            ;;
        --no-firewall)
            SKIP_FIREWALL=true
            shift
            ;;
        --help)
            show_help
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Main deployment process
main() {
    log_info "Starting TypoSentinel Demo deployment..."
    
    # Check if running as root
    check_root
    
    # Update system
    log_info "Updating system packages..."
    apt-get update && apt-get upgrade -y
    
    # Install required packages
    apt-get install -y curl wget git htop nano
    
    # Check and install Docker
    check_docker
    
    # Setup firewall
    if [[ "$SKIP_FIREWALL" != "true" ]]; then
        setup_firewall
    fi
    
    # Deploy application
    deploy_app
    
    # Setup SSL
    if [[ "$SKIP_SSL" != "true" ]]; then
        setup_ssl
    fi
    
    # Setup monitoring
    setup_monitoring
    
    # Show final status
    show_status
    
    log_success "Deployment completed successfully!"
    log_info "Check the logs with: docker-compose -f $APP_DIR/docker-compose.yml logs -f"
}

# Run main function
main "$@"