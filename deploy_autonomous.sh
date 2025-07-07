#!/bin/bash
# EMILY Autonomous Mode Production Deployment Script
# Deploys EMILY with full autonomous capabilities in production environment

set -e

# Configuration
EMILY_DIR="/opt/emily"
SERVICE_USER="emily"
SYSTEMD_SERVICE="emily-autonomous"
LOG_DIR="/var/log/emily"
CONFIG_DIR="/etc/emily"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] ✅${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] ⚠️${NC} $1"
}

log_error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] ❌${NC} $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root for production deployment"
        exit 1
    fi
}

check_dependencies() {
    log "Checking system dependencies..."
    
    # Required packages
    local packages=(
        "python3" "python3-pip" "python3-venv"
        "aircrack-ng" "bluetooth" "bluez-tools"
        "iw" "rfkill" "tcpdump"
        "systemd" "curl" "git"
    )
    
    local missing=()
    
    for package in "${packages[@]}"; do
        if ! dpkg -l | grep -q "^ii  $package "; then
            missing+=("$package")
        fi
    done
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        log_warning "Installing missing packages: ${missing[*]}"
        apt update
        apt install -y "${missing[@]}"
    fi
    
    log_success "Dependencies verified"
}

create_user() {
    if ! id "$SERVICE_USER" &>/dev/null; then
        log "Creating service user: $SERVICE_USER"
        useradd -r -s /bin/false -d "$EMILY_DIR" "$SERVICE_USER"
        
        # Add to necessary groups for hardware access
        usermod -a -G dialout,bluetooth,netdev "$SERVICE_USER"
        log_success "Service user created"
    else
        log "Service user $SERVICE_USER already exists"
    fi
}

setup_directories() {
    log "Setting up directory structure..."
    
    # Create directories
    mkdir -p "$EMILY_DIR"
    mkdir -p "$LOG_DIR"
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$EMILY_DIR/evidence"
    mkdir -p "$EMILY_DIR/cache"
    
    # Set permissions
    chown -R "$SERVICE_USER:$SERVICE_USER" "$EMILY_DIR"
    chown -R "$SERVICE_USER:$SERVICE_USER" "$LOG_DIR"
    chmod 755 "$CONFIG_DIR"
    chmod 700 "$EMILY_DIR/evidence"
    
    log_success "Directories configured"
}

install_emily() {
    log "Installing EMILY autonomous mode..."
    
    # Copy EMILY files
    cp -r ./* "$EMILY_DIR/"
    
    # Ensure the Go binary is executable
    chmod +x "$EMILY_DIR/emily"
    
    # Create necessary directories
    mkdir -p "$EMILY_DIR/logs"
    mkdir -p "$EMILY_DIR/data"
    
    # Set permissions
    chown -R "$SERVICE_USER:$SERVICE_USER" "$EMILY_DIR"
    
    log_success "EMILY installed"
}

create_config() {
    log "Creating production configuration..."
    
    # Create YAML config for EMILY
    cat > "$EMILY_DIR/.emily.yaml" << 'EOF'
# EMILY Autonomous Mode Production Configuration
core:
  app_name: "EMILY"
  version: "1.0.0-prod"
  debug: false
  scan_interval: "30s"

detection:
  wifi:
    enabled: true
    interface: ""
  bluetooth:
    enabled: true
  cellular:
    enabled: true
  nfc:
    enabled: true

stealth:
  hidden: true
  silent: true
  encrypted_storage: true

logging:
  level: "INFO"
  file: "/var/log/emily/autonomous.log"
  max_size: "100MB"
  backup_count: 5

notifications:
  enabled: true
  alerts:
    new_device: true
    threat_level: 5
    signal_loss: false
    surveillance: true
EOF

    chown $SERVICE_USER:$SERVICE_USER "$EMILY_DIR/.emily.yaml"
    chmod 640 "$EMILY_DIR/.emily.yaml"
    
    log_success "Configuration created"
}

create_systemd_service() {
    log "Creating systemd service..."
    
    cat > "/etc/systemd/system/${SYSTEMD_SERVICE}.service" << EOF
[Unit]
Description=EMILY Autonomous Surveillance Detection System
After=network-online.target bluetooth.service
Wants=network-online.target
RequiresMountsFor=$EMILY_DIR

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$EMILY_DIR
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ExecStart=$EMILY_DIR/emily monitor --interval 30s
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=emily-autonomous

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$EMILY_DIR $LOG_DIR
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN CAP_SYS_RAWIO
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN CAP_SYS_RAWIO

# Resource limits
MemoryLimit=512M
CPUQuota=50%

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    log_success "Systemd service created"
}

setup_log_rotation() {
    log "Setting up log rotation..."
    
    cat > "/etc/logrotate.d/emily" << 'EOF'
/var/log/emily/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 emily emily
    postrotate
        systemctl reload emily-autonomous 2>/dev/null || true
    endscript
}
EOF

    log_success "Log rotation configured"
}

setup_firewall() {
    log "Configuring firewall rules..."
    
    # Allow necessary traffic for detection
    if command -v ufw &> /dev/null; then
        ufw --force reset
        ufw default deny incoming
        ufw default allow outgoing
        
        # Allow SSH (modify port as needed)
        ufw allow 22/tcp
        
        # EMILY doesn't need incoming connections in autonomous mode
        # All scanning is passive
        
        ufw --force enable
        log_success "UFW firewall configured"
    else
        log_warning "UFW not installed, skipping firewall configuration"
    fi
}

create_monitoring_script() {
    log "Creating monitoring script..."
    
    cat > "$EMILY_DIR/monitor.sh" << 'EOF'
#!/bin/bash
# EMILY Health Monitoring Script

SERVICE="emily-autonomous"
EMILY_DIR="/opt/emily"
LOG_FILE="/var/log/emily/health.log"

check_service() {
    if systemctl is-active --quiet "$SERVICE"; then
        echo "$(date): Service $SERVICE is running" >> "$LOG_FILE"
        return 0
    else
        echo "$(date): ERROR: Service $SERVICE is not running" >> "$LOG_FILE"
        systemctl restart "$SERVICE"
        return 1
    fi
}

check_resources() {
    local mem_usage=$(ps -o pid,ppid,%mem,%cpu,cmd -C python3 | grep emily | awk '{print $3}')
    local cpu_usage=$(ps -o pid,ppid,%mem,%cpu,cmd -C python3 | grep emily | awk '{print $4}')
    
    if [[ $(echo "$mem_usage > 80" | bc -l) -eq 1 ]]; then
        echo "$(date): WARNING: High memory usage: $mem_usage%" >> "$LOG_FILE"
    fi
    
    if [[ $(echo "$cpu_usage > 90" | bc -l) -eq 1 ]]; then
        echo "$(date): WARNING: High CPU usage: $cpu_usage%" >> "$LOG_FILE"
    fi
}

check_evidence_space() {
    local usage=$(df "$EMILY_DIR/evidence" | tail -1 | awk '{print $5}' | sed 's/%//')
    if [[ $usage -gt 90 ]]; then
        echo "$(date): WARNING: Evidence directory is $usage% full" >> "$LOG_FILE"
        # Clean old evidence files
        find "$EMILY_DIR/evidence" -name "*.pcap" -mtime +7 -delete
        find "$EMILY_DIR/evidence" -name "*.log" -mtime +7 -delete
    fi
}

main() {
    check_service
    check_resources
    check_evidence_space
}

main "$@"
EOF

    chmod +x "$EMILY_DIR/monitor.sh"
    chown "$SERVICE_USER:$SERVICE_USER" "$EMILY_DIR/monitor.sh"
    
    # Add to crontab for automated monitoring
    (crontab -l 2>/dev/null; echo "*/5 * * * * $EMILY_DIR/monitor.sh") | crontab -
    
    log_success "Monitoring script created"
}

finalize_installation() {
    log "Finalizing installation..."
    
    # Enable and start service
    systemctl enable "$SYSTEMD_SERVICE"
    systemctl start "$SYSTEMD_SERVICE"
    
    # Wait a moment for service to start
    sleep 5
    
    # Check service status
    if systemctl is-active --quiet "$SYSTEMD_SERVICE"; then
        log_success "EMILY autonomous mode is running"
    else
        log_error "Failed to start EMILY service"
        systemctl status "$SYSTEMD_SERVICE"
        exit 1
    fi
    
    # Display status
    echo
    echo "============================================"
    echo "   EMILY AUTONOMOUS MODE DEPLOYED"
    echo "============================================"
    echo "Service: $SYSTEMD_SERVICE"
    echo "Status: $(systemctl is-active $SYSTEMD_SERVICE)"
    echo "Logs: journalctl -u $SYSTEMD_SERVICE -f"
    echo "Config: $CONFIG_DIR/emily.conf"
    echo "Evidence: $EMILY_DIR/evidence/"
    echo
    echo "Management Commands:"
    echo "  sudo systemctl start $SYSTEMD_SERVICE"
    echo "  sudo systemctl stop $SYSTEMD_SERVICE"
    echo "  sudo systemctl restart $SYSTEMD_SERVICE"
    echo "  sudo systemctl status $SYSTEMD_SERVICE"
    echo
    echo "⚠️  REMEMBER TO:"
    echo "  1. Configure Discord webhook in $CONFIG_DIR/emily.conf"
    echo "  2. Review and adjust countermeasure settings"
    echo "  3. Test in safe environment before production use"
    echo "  4. Monitor logs for any issues"
    echo
}

main() {
    echo "============================================"
    echo "  EMILY Autonomous Mode Production Deploy"
    echo "============================================"
    echo
    
    check_root
    check_dependencies
    create_user
    setup_directories
    install_emily
    create_config
    create_systemd_service
    setup_log_rotation
    setup_firewall
    create_monitoring_script
    finalize_installation
    
    log_success "Deployment completed successfully!"
}

# Show help
if [[ "$1" == "--help" || "$1" == "-h" ]]; then
    echo "EMILY Autonomous Mode Production Deployment"
    echo
    echo "Usage: sudo ./deploy_autonomous.sh"
    echo
    echo "This script will:"
    echo "  - Install EMILY in $EMILY_DIR"
    echo "  - Create dedicated service user"
    echo "  - Set up systemd service for autonomous mode"
    echo "  - Configure logging and monitoring"
    echo "  - Set up firewall rules"
    echo "  - Enable automatic startup"
    echo
    echo "Requirements:"
    echo "  - Ubuntu/Debian-based system"
    echo "  - Root privileges"
    echo "  - Network connectivity"
    echo
    exit 0
fi

main "$@"
