#!/bin/bash
# Honeyman — sensor installation script.
#
# Self-registering: hits POST /api/v2/sensors/register, captures the
# one-time API key, writes it to /etc/honeyman/api_key (mode 0600),
# drops a config.yaml, installs honeyman-agent, and starts it via systemd.
#
# Usage:
#   curl -sSL https://honeymanproject.com/install | sudo bash
#
# Non-interactive (e.g. for cloud-init or batch SD card flashing):
#   curl -sSL https://honeymanproject.com/install | sudo \
#     SENSOR_NAME="defcon-hotel" \
#     LOCATION="DefCon 32 hotel lobby" \
#     NON_INTERACTIVE=1 \
#     bash
#
# Environment overrides:
#   HONEYMAN_API       Backend base URL (default: https://api.honeymanproject.com)
#   SENSOR_NAME        Self-selected name (slugified; backend adds suffix)
#   LOCATION           Free-text location label
#   NON_INTERACTIVE    Skip prompts, accept hardware-detected defaults
#   AGENT_REPO         Git URL for the agent source (default: SecurityWard/honeyman-Project)
#   AGENT_REF          Git ref to install from (default: main)

set -euo pipefail

HONEYMAN_API="${HONEYMAN_API:-https://api.honeymanproject.com}"
HONEYMAN_VERSION="2.0.0"
INSTALL_DIR="/opt/honeyman"
CONFIG_DIR="/etc/honeyman"
LOG_DIR="/var/log/honeyman"
DATA_DIR="/var/lib/honeyman"
RULES_DIR="${CONFIG_DIR}/rules"
API_KEY_FILE="${CONFIG_DIR}/api_key"
CREDS_FILE="${CONFIG_DIR}/credentials"   # legacy alias, written for back-compat
AGENT_REPO="${AGENT_REPO:-https://github.com/SecurityWard/honeyman-Project.git}"
AGENT_REF="${AGENT_REF:-main}"

# When the script is piped (curl | bash) stdin is the script body, so any
# `read` would see EOF immediately and prompts would be skipped silently.
# Reattach stdin to the controlling terminal if there is one; otherwise
# force NON_INTERACTIVE so the script picks safe defaults instead of
# stalling on a never-answered prompt.
if [[ ! -t 0 ]]; then
    if [[ -r /dev/tty ]]; then
        exec < /dev/tty
    else
        NON_INTERACTIVE=1
    fi
fi

# Colors (suppressed if not a tty)
if [[ -t 1 ]]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
    BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''; BOLD=''; NC=''
fi

print_banner() {
    echo -e "${CYAN}"
    echo "=================================================================="
    echo "   Honeyman — Sensor Installation (v${HONEYMAN_VERSION})"
    echo "   Backend: ${HONEYMAN_API}"
    echo "=================================================================="
    echo -e "${NC}"
}

step()    { echo -e "${BLUE}[*]${NC} $1"; }
success() { echo -e "${GREEN}[OK]${NC} $1"; }
warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
fail()    { echo -e "${RED}[X]${NC} $1" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Pre-flight
# ---------------------------------------------------------------------------
preflight() {
    [[ $EUID -eq 0 ]] || fail "This script must be run as root (try: sudo bash)"
    command -v curl >/dev/null 2>&1 || fail "curl is required"
    command -v ping >/dev/null 2>&1 || warn "ping not found; skipping connectivity probe"
    if command -v ping >/dev/null 2>&1; then
        if ! ping -c 1 -W 5 8.8.8.8 >/dev/null 2>&1; then
            fail "No internet connection — registration requires reaching ${HONEYMAN_API}"
        fi
    fi
    success "Pre-flight passed"
}

detect_platform() {
    if [[ -f /proc/device-tree/model ]]; then
        PI_MODEL=$(tr -d '\0' < /proc/device-tree/model)
    else
        PI_MODEL="$(uname -srm)"
    fi
    PLATFORM="linux"
    case "${PI_MODEL,,}" in
        *"raspberry pi 5"*)         PLATFORM="rpi5" ;;
        *"raspberry pi 4"*)         PLATFORM="rpi4" ;;
        *"raspberry pi zero 2"*)    PLATFORM="rpizero2w" ;;
        *"raspberry pi zero"*)      PLATFORM="rpizerow" ;;
        *"raspberry pi"*)           PLATFORM="rpi" ;;
    esac
    ARCH="$(uname -m)"
    success "Platform: ${PI_MODEL} (${PLATFORM}, ${ARCH})"
}

detect_hardware() {
    step "Detecting hardware capabilities..."
    HAS_BLE=false
    HAS_WIFI=false
    HAS_WIFI_MONITOR=false

    if command -v hciconfig >/dev/null 2>&1 && hciconfig 2>/dev/null | grep -q "hci0"; then
        HAS_BLE=true
        echo "    bluetooth: yes"
    fi

    if command -v iw >/dev/null 2>&1 && iw dev 2>/dev/null | grep -q "Interface"; then
        HAS_WIFI=true
        WIFI_IFACE=$(iw dev | awk '/Interface/{print $2; exit}')
        echo "    wifi:      yes (${WIFI_IFACE})"
        if iw phy 2>/dev/null | grep -qi "monitor"; then
            HAS_WIFI_MONITOR=true
            echo "    monitor:   yes"
        fi
    fi
}

# ---------------------------------------------------------------------------
# Interactive prompts
# ---------------------------------------------------------------------------
ask_sensor_name() {
    if [[ -z "${SENSOR_NAME:-}" ]]; then
        if [[ -n "${NON_INTERACTIVE:-}" ]]; then
            SENSOR_NAME="sensor-$(hostname -s 2>/dev/null || echo unknown)"
        else
            echo
            echo "Pick a name for this sensor (lowercase, hyphens; backend appends a random suffix)."
            echo "Examples: defcon-hotel, lab-pi, conf-room-3"
            read -rp "Sensor name: " SENSOR_NAME
            [[ -z "$SENSOR_NAME" ]] && SENSOR_NAME="sensor-$(hostname -s)"
        fi
    fi
    SENSOR_NAME="$(echo "$SENSOR_NAME" | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9-' '-' | sed 's/^-*//;s/-*$//')"
    [[ -z "$SENSOR_NAME" ]] && SENSOR_NAME="sensor"
    success "Sensor name: ${SENSOR_NAME}"
}

ask_location() {
    if [[ -z "${LOCATION:-}" ]]; then
        if [[ -z "${NON_INTERACTIVE:-}" ]]; then
            echo
            read -rp "Location label (optional, e.g. 'DefCon 32 hotel lobby'): " LOCATION
        fi
    fi
    [[ -n "${LOCATION:-}" ]] && success "Location: ${LOCATION}"
}

# Module toggles. Defaults follow detected hardware. Skipped in non-interactive.
choose_modules() {
    MOD_USB=true
    MOD_BLE=$HAS_BLE
    MOD_WIFI=$HAS_WIFI
    MOD_AIRDROP=$HAS_WIFI
    MOD_NETWORK=true

    if [[ -n "${NON_INTERACTIVE:-}" ]]; then return; fi

    echo
    echo -e "${BOLD}Detection modules${NC} (defaults shown; press Enter to accept)"
    prompt_bool() {
        local name="$1" var="$2" current="$3"
        read -rp "  enable ${name} [$([[ $current == true ]] && echo Y/n || echo y/N)]: " ans
        case "${ans,,}" in
            y|yes)     eval "$var=true" ;;
            n|no)      eval "$var=false" ;;
            *)         : ;;  # keep default
        esac
    }
    prompt_bool "USB"            MOD_USB     "$MOD_USB"
    prompt_bool "BLE"            MOD_BLE     "$MOD_BLE"
    prompt_bool "WiFi"           MOD_WIFI    "$MOD_WIFI"
    prompt_bool "AirDrop/mDNS"   MOD_AIRDROP "$MOD_AIRDROP"
    prompt_bool "Network honeypot (SSH/HTTP)" MOD_NETWORK "$MOD_NETWORK"

    echo
    echo "Selected:"
    $MOD_USB     && echo "    USB"
    $MOD_BLE     && echo "    BLE"
    $MOD_WIFI    && echo "    WiFi"
    $MOD_AIRDROP && echo "    AirDrop"
    $MOD_NETWORK && echo "    Network honeypot"
}

# ---------------------------------------------------------------------------
# System dependencies
# ---------------------------------------------------------------------------
install_system_deps() {
    step "Installing system dependencies..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends \
        python3 python3-pip python3-venv \
        git curl jq \
        bluez wireless-tools iw aircrack-ng libpcap-dev \
        avahi-utils \
        ca-certificates >/dev/null
    success "System dependencies installed"
}

# ---------------------------------------------------------------------------
# Registration (self-register flow)
# ---------------------------------------------------------------------------
build_capabilities_json() {
    python3 - <<PY
import json
caps = {
    "usb":      ${MOD_USB},
    "ble":      ${MOD_BLE},
    "wifi":     ${MOD_WIFI},
    "airdrop":  ${MOD_AIRDROP},
    "network":  ${MOD_NETWORK},
}
enabled = [k for k, v in caps.items() if v]
print(json.dumps({"capabilities": caps, "enabled_detectors": enabled}))
PY
}

register_sensor() {
    step "Registering sensor with ${HONEYMAN_API}..."
    local caps_json enabled_json platform_json body http_code body_file

    caps_and_enabled="$(build_capabilities_json)"
    body=$(python3 - <<PY
import json, sys
caps_and_enabled = json.loads('''$caps_and_enabled''')
payload = {
    "requested_name":     "${SENSOR_NAME}",
    "location_label":     ${LOCATION:+'"'"$LOCATION"'"'} ${LOCATION:-null},
    "capabilities":       caps_and_enabled["capabilities"],
    "enabled_detectors":  caps_and_enabled["enabled_detectors"],
    "platform":           "${PLATFORM}",
    "architecture":       "${ARCH}",
    "agent_version":      "${HONEYMAN_VERSION}",
    "python_version":     "$(python3 --version 2>&1 | awk '{print $2}')",
}
print(json.dumps(payload))
PY
)

    body_file=$(mktemp)
    http_code=$(curl -sS -o "$body_file" -w '%{http_code}' \
        -X POST "${HONEYMAN_API}/api/v2/sensors/register" \
        -H 'Content-Type: application/json' \
        --data "$body" || echo 000)

    if [[ "$http_code" != "201" && "$http_code" != "200" ]]; then
        warn "Registration HTTP ${http_code}; response:"
        cat "$body_file" >&2
        rm -f "$body_file"
        fail "Registration failed. Check HONEYMAN_API and try again."
    fi

    SENSOR_ID=$(jq -r '.sensor_id' "$body_file")
    SENSOR_API_KEY=$(jq -r '.api_key' "$body_file")
    API_ENDPOINT=$(jq -r '.api_endpoint' "$body_file")
    MQTT_ENABLED=$(jq -r '.mqtt_enabled // false' "$body_file")
    if [[ "$MQTT_ENABLED" == "true" ]]; then
        MQTT_BROKER=$(jq -r '.mqtt_broker' "$body_file")
        MQTT_PORT=$(jq -r '.mqtt_port' "$body_file")
    fi

    rm -f "$body_file"

    [[ -n "${SENSOR_ID}" && "${SENSOR_ID}" != "null" ]] || fail "Backend did not return sensor_id"
    [[ -n "${SENSOR_API_KEY}" && "${SENSOR_API_KEY}" != "null" ]] || fail "Backend did not return api_key"

    success "Registered as: ${SENSOR_ID}"
}

# ---------------------------------------------------------------------------
# Filesystem layout + config + credentials
# ---------------------------------------------------------------------------
make_directories() {
    step "Creating directories..."
    mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$LOG_DIR" "$DATA_DIR" "$RULES_DIR"
    chmod 0755 "$CONFIG_DIR"
    success "Directories created"
}

write_credentials() {
    step "Storing API key..."
    umask 077
    printf '%s' "$SENSOR_API_KEY" > "$API_KEY_FILE"
    chmod 0600 "$API_KEY_FILE"
    # legacy 'credentials' file kept for systems that look there
    {
        printf 'sensor_id=%s\n'  "$SENSOR_ID"
        printf 'api_key=%s\n'    "$SENSOR_API_KEY"
    } > "$CREDS_FILE"
    chmod 0600 "$CREDS_FILE"
    success "API key written to $API_KEY_FILE (mode 0600)"
}

write_config() {
    step "Writing $CONFIG_DIR/config.yaml..."

    # Build the MQTT block only if the backend offered MQTT
    local mqtt_block="  # mqtt: not offered by backend (HTTPS-only deployment)"
    if [[ "${MQTT_ENABLED:-false}" == "true" ]]; then
        mqtt_block=$(cat <<EOF
  mqtt:
    broker: ${MQTT_BROKER}
    port: ${MQTT_PORT}
    use_tls: true
    qos: 1
EOF
)
    fi

    cat > "${CONFIG_DIR}/config.yaml" <<EOF
# Honeyman sensor config — generated $(date -Iseconds)

sensor_id: "${SENSOR_ID}"
sensor_name: "${SENSOR_NAME}"

rules_dir: ${RULES_DIR}
heartbeat_interval: 60

transport:
  protocol: https
  fallback: none

  https:
    base_url: ${HONEYMAN_API}
    api_prefix: /api/v2
    api_key_file: ${API_KEY_FILE}
    timeout: 30
    verify_ssl: true

${mqtt_block}

detectors:
  usb:       ${MOD_USB}
  bluetooth: ${MOD_BLE}
  wifi:      ${MOD_WIFI}
  airdrop:   ${MOD_AIRDROP}
  network:   ${MOD_NETWORK}

usb:
  hash_database_path: ${DATA_DIR}/malware_hashes.db
  scan_storage_devices: true
  max_file_size_mb: 100

location:
  enabled: true
  gps_enabled: false
${LOCATION:+  manual_label: "${LOCATION}"}

logging:
  level: INFO
  file: ${LOG_DIR}/agent.log
  max_bytes: 10485760
  backup_count: 5
EOF
    chmod 0644 "${CONFIG_DIR}/config.yaml"
    success "Config written"
}

# ---------------------------------------------------------------------------
# Agent install + rules
# ---------------------------------------------------------------------------
install_agent() {
    step "Installing honeyman-agent (from ${AGENT_REPO}@${AGENT_REF})..."
    rm -rf "${INSTALL_DIR}/src"
    git clone --depth 1 --branch "$AGENT_REF" "$AGENT_REPO" "${INSTALL_DIR}/src" >/dev/null 2>&1 \
        || fail "Could not clone agent source from ${AGENT_REPO}"
    pip3 install --quiet --break-system-packages -e "${INSTALL_DIR}/src/honeyman-v2/agent" \
        || pip3 install --quiet -e "${INSTALL_DIR}/src/honeyman-v2/agent" \
        || fail "pip install of honeyman-agent failed"
    success "Agent installed (importable as 'honeyman')"
}

copy_rules() {
    step "Copying default detection rules to ${RULES_DIR}..."
    if [[ -d "${INSTALL_DIR}/src/honeyman-v2/agent/rules" ]]; then
        cp -r "${INSTALL_DIR}/src/honeyman-v2/agent/rules/." "${RULES_DIR}/"
        success "Default rules installed ($(find "$RULES_DIR" -name '*.yaml' | wc -l) files)"
    else
        warn "No rules/ directory in agent source — skipping default rules"
    fi
}

# ---------------------------------------------------------------------------
# Systemd
# ---------------------------------------------------------------------------
install_systemd() {
    step "Installing systemd unit..."
    cat > /etc/systemd/system/honeyman-agent.service <<EOF
[Unit]
Description=Honeyman Threat Detection Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=$(command -v honeyman-agent || echo /usr/local/bin/honeyman-agent) --config ${CONFIG_DIR}/config.yaml
Restart=on-failure
RestartSec=10
StandardOutput=append:${LOG_DIR}/agent.log
StandardError=append:${LOG_DIR}/agent.log

# Hardening
NoNewPrivileges=false
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=${LOG_DIR} ${DATA_DIR} ${CONFIG_DIR}
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable honeyman-agent.service >/dev/null 2>&1
    success "systemd unit installed and enabled"
}

start_agent() {
    step "Starting honeyman-agent..."
    systemctl restart honeyman-agent.service
    sleep 3
    if systemctl is-active --quiet honeyman-agent.service; then
        success "honeyman-agent is running"
    else
        warn "honeyman-agent did not start cleanly; check: journalctl -u honeyman-agent -n 100"
    fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    print_banner
    preflight
    detect_platform
    detect_hardware
    ask_sensor_name
    ask_location
    choose_modules

    echo
    echo -e "${BOLD}Installing...${NC}"
    install_system_deps
    make_directories
    register_sensor
    write_credentials
    install_agent
    copy_rules
    write_config
    install_systemd
    start_agent

    echo
    echo -e "${GREEN}=================================================================="
    echo -e "  Honeyman sensor installed"
    echo -e "==================================================================${NC}"
    echo
    echo -e "  Sensor ID:    ${BOLD}${SENSOR_ID}${NC}"
    echo -e "  Backend:      ${HONEYMAN_API}"
    echo -e "  API key:      ${API_KEY_FILE} (mode 0600)"
    echo -e "  Config:       ${CONFIG_DIR}/config.yaml"
    echo -e "  Rules:        ${RULES_DIR}/"
    echo -e "  Logs:         ${LOG_DIR}/agent.log"
    echo
    echo -e "  Useful commands:"
    echo -e "    systemctl status honeyman-agent"
    echo -e "    journalctl -u honeyman-agent -f"
    echo -e "    systemctl restart honeyman-agent"
    echo
    echo -e "  Your sensor will appear on the dashboard within ~60 seconds."
    echo
}

main "$@"
