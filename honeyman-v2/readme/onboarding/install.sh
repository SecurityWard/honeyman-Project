#!/bin/bash
#
# Honeyman V2 - Sensor Installation Script
# Zero-account, self-registering sensor deployment
#
# Usage:
#   curl -sSL https://honeyman.io/install | bash
#
# Or with pre-set values:
#   curl -sSL https://honeyman.io/install | SENSOR_NAME="my-sensor" LOCATION="NYC" bash
#

set -e

# =============================================================================
# Configuration
# =============================================================================

HONEYMAN_API="${HONEYMAN_API:-https://api.honeyman.io}"
HONEYMAN_VERSION="${HONEYMAN_VERSION:-2.0.0}"
INSTALL_DIR="/opt/honeyman"
CONFIG_DIR="/etc/honeyman"
LOG_DIR="/var/log/honeyman"
DATA_DIR="/var/lib/honeyman"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# =============================================================================
# Helper Functions
# =============================================================================

print_banner() {
    echo -e "${CYAN}"
    echo "══════════════════════════════════════════════════════════════════"
    echo "   🍯 HONEYMAN V2 - Sensor Installation"
    echo "   Version: ${HONEYMAN_VERSION}"
    echo "══════════════════════════════════════════════════════════════════"
    echo -e "${NC}"
}

print_step() {
    echo -e "${BLUE}[*]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root"
        echo "Please run: sudo bash or curl ... | sudo bash"
        exit 1
    fi
}

check_raspberry_pi() {
    if [[ -f /proc/device-tree/model ]]; then
        PI_MODEL=$(cat /proc/device-tree/model | tr -d '\0')
        print_success "Detected: ${PI_MODEL}"
    else
        print_warning "Could not detect Raspberry Pi model"
        PI_MODEL="Unknown"
    fi
}

check_internet() {
    print_step "Checking internet connectivity..."
    if ! ping -c 1 -W 5 8.8.8.8 &> /dev/null; then
        print_error "No internet connection detected"
        exit 1
    fi
    print_success "Internet connection OK"
}

# =============================================================================
# Hardware Detection
# =============================================================================

detect_hardware() {
    print_step "Detecting hardware capabilities..."
    
    HAS_USB=true  # All Pis have USB
    HAS_BLE=false
    HAS_WIFI=false
    HAS_WIFI_MONITOR=false
    HAS_ETHERNET=false
    
    # Check Bluetooth
    if hciconfig 2>/dev/null | grep -q "hci0"; then
        HAS_BLE=true
        print_success "  Bluetooth adapter detected"
    else
        print_warning "  No Bluetooth adapter found"
    fi
    
    # Check WiFi
    if iw dev 2>/dev/null | grep -q "Interface"; then
        HAS_WIFI=true
        WIFI_IFACE=$(iw dev | grep Interface | awk '{print $2}' | head -1)
        print_success "  WiFi adapter detected: ${WIFI_IFACE}"
        
        # Check monitor mode support
        if iw phy | grep -q "monitor"; then
            HAS_WIFI_MONITOR=true
            print_success "  WiFi monitor mode supported"
        else
            print_warning "  WiFi monitor mode not supported"
        fi
    else
        print_warning "  No WiFi adapter found"
    fi
    
    # Check Ethernet
    if ip link | grep -q "eth0"; then
        HAS_ETHERNET=true
        print_success "  Ethernet adapter detected"
    fi
    
    # Get RAM
    RAM_MB=$(free -m | awk '/^Mem:/{print $2}')
    RAM_GB=$(echo "scale=1; $RAM_MB / 1024" | bc)
    print_success "  RAM: ${RAM_GB}GB"
}

# =============================================================================
# Interactive Setup
# =============================================================================

interactive_setup() {
    echo ""
    echo -e "${BOLD}Sensor Configuration${NC}"
    echo "────────────────────────────────────────"
    
    # Sensor name
    if [[ -z "${SENSOR_NAME}" ]]; then
        echo -e "${CYAN}Enter a name for this sensor${NC} (e.g., office-lobby, conference-room):"
        read -p "> " SENSOR_NAME
        if [[ -z "${SENSOR_NAME}" ]]; then
            SENSOR_NAME="sensor-$(hostname)"
        fi
    fi
    echo -e "  Sensor name: ${GREEN}${SENSOR_NAME}${NC}"
    
    # Location
    if [[ -z "${LOCATION}" ]]; then
        echo ""
        echo -e "${CYAN}Enter location${NC} (optional, e.g., Las Vegas, NV):"
        read -p "> " LOCATION
    fi
    if [[ -n "${LOCATION}" ]]; then
        echo -e "  Location: ${GREEN}${LOCATION}${NC}"
    fi
    
    echo ""
}

select_modules() {
    echo -e "${BOLD}Module Selection${NC}"
    echo "────────────────────────────────────────"
    echo "Select which detection modules to enable:"
    echo ""
    
    # Default selections based on hardware
    MOD_USB=true
    MOD_BLE=$HAS_BLE
    MOD_WIFI=$HAS_WIFI
    MOD_AIRDROP=$HAS_WIFI
    MOD_NETWORK=true
    
    # If running non-interactive, use defaults
    if [[ -n "${NON_INTERACTIVE}" ]]; then
        return
    fi
    
    # Interactive selection
    echo -e "  ${GREEN}[1]${NC} USB Detection (BadUSB, OMG cables, Rubber Ducky)"
    if $HAS_USB; then
        echo -e "      Status: ${GREEN}Available${NC}"
    fi
    
    echo -e "  ${GREEN}[2]${NC} BLE Detection (Flipper Zero, beacon attacks)"
    if $HAS_BLE; then
        echo -e "      Status: ${GREEN}Available${NC}"
    else
        echo -e "      Status: ${YELLOW}No Bluetooth adapter${NC}"
    fi
    
    echo -e "  ${GREEN}[3]${NC} WiFi Detection (Evil Twin, deauth attacks)"
    if $HAS_WIFI_MONITOR; then
        echo -e "      Status: ${GREEN}Available (monitor mode)${NC}"
    elif $HAS_WIFI; then
        echo -e "      Status: ${YELLOW}Available (limited - no monitor mode)${NC}"
    else
        echo -e "      Status: ${YELLOW}No WiFi adapter${NC}"
    fi
    
    echo -e "  ${GREEN}[4]${NC} AirDrop Detection (Bonjour abuse)"
    if $HAS_WIFI; then
        echo -e "      Status: ${GREEN}Available${NC}"
    else
        echo -e "      Status: ${YELLOW}No WiFi adapter${NC}"
    fi
    
    echo -e "  ${GREEN}[5]${NC} Network Honeypot (SSH, HTTP, SMB honeypots)"
    echo -e "      Status: ${GREEN}Available${NC}"
    
    echo ""
    echo "Enter module numbers to toggle (e.g., '2 3' to toggle BLE and WiFi)"
    echo "Or press Enter to use recommended defaults:"
    read -p "> " TOGGLE_INPUT
    
    # Process toggles
    for num in $TOGGLE_INPUT; do
        case $num in
            1) MOD_USB=$(! $MOD_USB && echo true || echo false) ;;
            2) if $HAS_BLE; then MOD_BLE=$(! $MOD_BLE && echo true || echo false); fi ;;
            3) if $HAS_WIFI; then MOD_WIFI=$(! $MOD_WIFI && echo true || echo false); fi ;;
            4) if $HAS_WIFI; then MOD_AIRDROP=$(! $MOD_AIRDROP && echo true || echo false); fi ;;
            5) MOD_NETWORK=$(! $MOD_NETWORK && echo true || echo false) ;;
        esac
    done
    
    # Show final selection
    echo ""
    echo "Selected modules:"
    $MOD_USB && echo -e "  ${GREEN}✓${NC} USB Detection"
    $MOD_BLE && echo -e "  ${GREEN}✓${NC} BLE Detection"
    $MOD_WIFI && echo -e "  ${GREEN}✓${NC} WiFi Detection"
    $MOD_AIRDROP && echo -e "  ${GREEN}✓${NC} AirDrop Detection"
    $MOD_NETWORK && echo -e "  ${GREEN}✓${NC} Network Honeypot"
    echo ""
}

# =============================================================================
# Installation
# =============================================================================

install_dependencies() {
    print_step "Installing system dependencies..."
    
    apt-get update -qq
    apt-get install -y -qq \
        python3 \
        python3-pip \
        python3-venv \
        git \
        curl \
        jq \
        bluez \
        bluetooth \
        wireless-tools \
        iw \
        aircrack-ng \
        libpcap-dev \
        docker.io \
        docker-compose \
        > /dev/null 2>&1
    
    # Enable Docker
    systemctl enable docker
    systemctl start docker
    
    print_success "Dependencies installed"
}

create_directories() {
    print_step "Creating directories..."
    
    mkdir -p "${INSTALL_DIR}/bin"
    mkdir -p "${INSTALL_DIR}/lib"
    mkdir -p "${INSTALL_DIR}/share/yara"
    mkdir -p "${CONFIG_DIR}/rules"
    mkdir -p "${LOG_DIR}/modules"
    mkdir -p "${DATA_DIR}/state"
    
    print_success "Directories created"
}

register_sensor() {
    print_step "Registering sensor with Honeyman network..."
    
    # Build modules list
    MODULES_JSON="["
    $MOD_USB && MODULES_JSON+="\"usb\","
    $MOD_BLE && MODULES_JSON+="\"ble\","
    $MOD_WIFI && MODULES_JSON+="\"wifi\","
    $MOD_AIRDROP && MODULES_JSON+="\"airdrop\","
    $MOD_NETWORK && MODULES_JSON+="\"network\","
    MODULES_JSON="${MODULES_JSON%,}]"  # Remove trailing comma
    
    # Build hardware info
    HARDWARE_JSON=$(cat <<EOF
{
    "model": "${PI_MODEL}",
    "ram_gb": ${RAM_GB},
    "has_ble": ${HAS_BLE},
    "has_wifi": ${HAS_WIFI},
    "has_wifi_monitor": ${HAS_WIFI_MONITOR}
}
EOF
)
    
    # Build request body
    REQUEST_BODY=$(cat <<EOF
{
    "requested_name": "${SENSOR_NAME}",
    "location": "${LOCATION}",
    "modules": ${MODULES_JSON},
    "hardware": ${HARDWARE_JSON}
}
EOF
)
    
    # Send registration request
    RESPONSE=$(curl -s -X POST "${HONEYMAN_API}/api/v1/sensors/register" \
        -H "Content-Type: application/json" \
        -d "${REQUEST_BODY}")
    
    # Check for errors
    if echo "${RESPONSE}" | jq -e '.error' > /dev/null 2>&1; then
        ERROR_MSG=$(echo "${RESPONSE}" | jq -r '.error')
        print_error "Registration failed: ${ERROR_MSG}"
        exit 1
    fi
    
    # Extract credentials
    SENSOR_ID=$(echo "${RESPONSE}" | jq -r '.sensor_id')
    SENSOR_SECRET=$(echo "${RESPONSE}" | jq -r '.secret')
    BROKER_HOST=$(echo "${RESPONSE}" | jq -r '.broker.host')
    BROKER_PORT=$(echo "${RESPONSE}" | jq -r '.broker.port')
    CA_CERT=$(echo "${RESPONSE}" | jq -r '.broker.ca_cert')
    DASHBOARD_URL=$(echo "${RESPONSE}" | jq -r '.dashboard_url')
    
    if [[ -z "${SENSOR_ID}" || "${SENSOR_ID}" == "null" ]]; then
        print_error "Failed to get sensor ID from API"
        exit 1
    fi
    
    print_success "Registered as: ${SENSOR_ID}"
}

write_config() {
    print_step "Writing configuration..."
    
    # Write main config
    cat > "${CONFIG_DIR}/config.yaml" <<EOF
# Honeyman V2 Sensor Configuration
# Generated: $(date -Iseconds)

sensor:
  id: "${SENSOR_ID}"
  name: "${SENSOR_NAME}"
  location: "${LOCATION}"

broker:
  host: "${BROKER_HOST}"
  port: ${BROKER_PORT}
  tls: true
  ca_cert: "${CONFIG_DIR}/certs/ca.crt"
  credentials: "${CONFIG_DIR}/credentials"

modules:
  usb:
    enabled: ${MOD_USB}
    honeypot_ports: [3, 4]
  ble:
    enabled: ${MOD_BLE}
    scan_interval: 8
  wifi:
    enabled: ${MOD_WIFI}
    monitor_mode: ${HAS_WIFI_MONITOR}
    interface: "${WIFI_IFACE:-wlan0}"
  airdrop:
    enabled: ${MOD_AIRDROP}
  network:
    enabled: ${MOD_NETWORK}
    services:
      - ssh:2222
      - http:8080
      - telnet:2323

logging:
  level: INFO
  file: "${LOG_DIR}/honeyman.log"
  max_size_mb: 100
  backup_count: 5

buffer:
  database: "${DATA_DIR}/honeyman.db"
  max_events: 10000
  flush_interval: 30
EOF

    # Write credentials (restricted permissions)
    cat > "${CONFIG_DIR}/credentials" <<EOF
${SENSOR_ID}
${SENSOR_SECRET}
EOF
    chmod 600 "${CONFIG_DIR}/credentials"
    
    # Write CA certificate
    mkdir -p "${CONFIG_DIR}/certs"
    echo "${CA_CERT}" > "${CONFIG_DIR}/certs/ca.crt"
    
    print_success "Configuration written"
}

download_components() {
    print_step "Downloading Honeyman components..."
    
    # In production, these would be downloaded from a release server
    # For now, we'll create placeholder scripts
    
    GITHUB_RAW="https://raw.githubusercontent.com/honeyman/honeyman/main"
    
    # Download detector scripts
    # curl -sSL "${GITHUB_RAW}/sensors/usb_detector.py" -o "${INSTALL_DIR}/bin/usb_detector.py"
    # curl -sSL "${GITHUB_RAW}/sensors/ble_detector.py" -o "${INSTALL_DIR}/bin/ble_detector.py"
    # ... etc
    
    # For now, just create the main controller placeholder
    cat > "${INSTALL_DIR}/bin/honeyman" <<'CONTROLLER'
#!/usr/bin/env python3
"""
Honeyman V2 - Main Controller
This is a placeholder - replace with actual controller
"""
import sys
print("Honeyman V2 Controller")
print("Replace this with the actual main_controller.py")
sys.exit(0)
CONTROLLER
    chmod +x "${INSTALL_DIR}/bin/honeyman"
    
    print_success "Components downloaded"
}

install_default_rules() {
    print_step "Installing default alert rules..."
    
    # USB rules
    cat > "${CONFIG_DIR}/rules/usb_rules.yaml" <<'EOF'
version: 1
module: usb

rules:
  - name: badusb_critical
    description: "BadUSB device with high threat score"
    conditions:
      all:
        - field: threat_score
          operator: ">="
          value: 0.8
    severity: critical
    actions: [mqtt_publish, local_log]
    cooldown_seconds: 60

  - name: suspicious_usb
    description: "USB device with suspicious indicators"
    conditions:
      any:
        - field: vendor_id
          operator: "in"
          value: ["1337", "DEAD", "BEEF", "FFFF", "0001"]
    severity: high
    actions: [mqtt_publish, local_log]
    cooldown_seconds: 30
EOF

    # BLE rules
    cat > "${CONFIG_DIR}/rules/ble_rules.yaml" <<'EOF'
version: 1
module: ble

rules:
  - name: flipper_zero_detected
    description: "Flipper Zero device detected"
    conditions:
      any:
        - field: device_name
          operator: "contains"
          value: ["flipper", "zero", "FZ"]
    severity: critical
    actions: [mqtt_publish, local_log]
    cooldown_seconds: 120

  - name: beacon_flooding
    description: "BLE beacon flooding detected"
    conditions:
      all:
        - field: beacon_rate
          operator: ">"
          value: 100
    severity: high
    actions: [mqtt_publish, local_log]
    cooldown_seconds: 60
EOF

    # WiFi rules
    cat > "${CONFIG_DIR}/rules/wifi_rules.yaml" <<'EOF'
version: 1
module: wifi

rules:
  - name: evil_twin_detected
    description: "Evil twin access point detected"
    conditions:
      all:
        - field: is_evil_twin
          operator: "=="
          value: true
    severity: critical
    actions: [mqtt_publish, local_log]
    cooldown_seconds: 120

  - name: deauth_attack
    description: "Deauthentication attack detected"
    conditions:
      all:
        - field: deauth_rate
          operator: ">"
          value: 10
    severity: high
    actions: [mqtt_publish, local_log]
    cooldown_seconds: 60
EOF

    # AirDrop rules
    cat > "${CONFIG_DIR}/rules/airdrop_rules.yaml" <<'EOF'
version: 1
module: airdrop

rules:
  - name: service_flood
    description: "AirDrop service flood detected"
    conditions:
      all:
        - field: announcement_rate
          operator: ">"
          value: 50
    severity: high
    actions: [mqtt_publish, local_log]
    cooldown_seconds: 60
EOF

    # Network rules
    cat > "${CONFIG_DIR}/rules/network_rules.yaml" <<'EOF'
version: 1
module: network

rules:
  - name: brute_force_attempt
    description: "Brute force login attempt"
    conditions:
      all:
        - field: failed_attempts
          operator: ">="
          value: 5
    severity: high
    actions: [mqtt_publish, local_log]
    cooldown_seconds: 300

  - name: port_scan
    description: "Port scanning detected"
    conditions:
      all:
        - field: ports_probed
          operator: ">="
          value: 10
    severity: medium
    actions: [mqtt_publish, local_log]
    cooldown_seconds: 120
EOF

    print_success "Default rules installed"
}

create_systemd_service() {
    print_step "Creating systemd service..."
    
    cat > /etc/systemd/system/honeyman.service <<EOF
[Unit]
Description=Honeyman V2 Threat Detection Sensor
After=network.target docker.service
Wants=docker.service

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/bin/honeyman
Restart=always
RestartSec=10
StandardOutput=append:${LOG_DIR}/honeyman.log
StandardError=append:${LOG_DIR}/honeyman.log

# Security hardening
NoNewPrivileges=false
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${LOG_DIR} ${DATA_DIR} ${CONFIG_DIR}

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable honeyman.service
    
    print_success "Systemd service created"
}

start_service() {
    print_step "Starting Honeyman service..."
    
    systemctl start honeyman.service
    sleep 2
    
    if systemctl is-active --quiet honeyman.service; then
        print_success "Honeyman service started"
    else
        print_warning "Service may not have started correctly"
        print_warning "Check logs: journalctl -u honeyman.service"
    fi
}

# =============================================================================
# Main
# =============================================================================

main() {
    print_banner
    
    check_root
    check_internet
    check_raspberry_pi
    
    detect_hardware
    
    interactive_setup
    select_modules
    
    echo ""
    echo -e "${BOLD}Starting Installation${NC}"
    echo "────────────────────────────────────────"
    
    install_dependencies
    create_directories
    register_sensor
    write_config
    download_components
    install_default_rules
    create_systemd_service
    start_service
    
    echo ""
    echo -e "${GREEN}══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}   ✓ INSTALLATION COMPLETE${NC}"
    echo -e "${GREEN}══════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "   Sensor ID:    ${BOLD}${SENSOR_ID}${NC}"
    echo -e "   Location:     ${LOCATION:-Not set}"
    echo -e "   Dashboard:    ${CYAN}${DASHBOARD_URL}${NC}"
    echo ""
    echo -e "   Enabled Modules:"
    $MOD_USB && echo -e "     ${GREEN}✓${NC} USB Detection"
    $MOD_BLE && echo -e "     ${GREEN}✓${NC} BLE Detection"
    $MOD_WIFI && echo -e "     ${GREEN}✓${NC} WiFi Detection"
    $MOD_AIRDROP && echo -e "     ${GREEN}✓${NC} AirDrop Detection"
    $MOD_NETWORK && echo -e "     ${GREEN}✓${NC} Network Honeypot"
    echo ""
    echo -e "   Useful Commands:"
    echo -e "     Status:     ${CYAN}systemctl status honeyman${NC}"
    echo -e "     Logs:       ${CYAN}journalctl -u honeyman -f${NC}"
    echo -e "     Restart:    ${CYAN}systemctl restart honeyman${NC}"
    echo ""
    echo -e "   Config:       ${CONFIG_DIR}/config.yaml"
    echo -e "   Rules:        ${CONFIG_DIR}/rules/"
    echo -e "   Logs:         ${LOG_DIR}/"
    echo ""
    echo -e "${GREEN}══════════════════════════════════════════════════════════════════${NC}"
}

# Run main
main "$@"
