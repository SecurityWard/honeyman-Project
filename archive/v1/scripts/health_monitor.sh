#!/bin/bash
# Honeypot Platform Health Monitor
# Checks service health and restarts if needed

LOG_FILE="/home/burner/honeypot-minimal/logs/health_monitor.log"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

# Function to log messages
log_message() {
    echo "[$TIMESTAMP] $1" >> "$LOG_FILE"
}

# Check Docker containers
check_docker() {
    for container in honeypot-opencanary honeypot-web honeypot-elasticsearch honeypot-kibana; do
        if ! docker ps | grep -q "$container"; then
            log_message "WARNING: Container $container is not running. Attempting restart..."
            docker-compose -f /home/burner/honeypot-minimal/docker-compose.yml restart "$container"
        fi
    done
}

# Check systemd services
check_services() {
    for service in honeypot-multi-vector honeypot-wifi-detector honeypot-usb-advanced honeypot-airdrop honeypot-forwarder; do
        if ! systemctl is-active --quiet "$service"; then
            log_message "WARNING: Service $service is not running. Attempting restart..."
            sudo systemctl restart "$service"
        fi
    done
}

# Check Elasticsearch health
check_elasticsearch() {
    if ! curl -s http://localhost:9200/_cluster/health > /dev/null 2>&1; then
        log_message "ERROR: Elasticsearch not responding. Restarting..."
        docker-compose -f /home/burner/honeypot-minimal/docker-compose.yml restart elasticsearch
    fi
}

# Check VPS connectivity
check_vps() {
    if ! curl -s -m 5 http://72.60.25.24:8080/api/threats/stats > /dev/null 2>&1; then
        log_message "WARNING: VPS dashboard not reachable"
    fi
}

# Check memory usage
check_memory() {
    MEM_PERCENT=$(free | grep Mem | awk '{print int($3/$2 * 100)}')
    SWAP_PERCENT=$(free | grep Swap | awk '{print int($3/$2 * 100)}')
    
    if [ "$MEM_PERCENT" -gt 90 ]; then
        log_message "WARNING: Memory usage is at ${MEM_PERCENT}%"
    fi
    
    if [ "$SWAP_PERCENT" -gt 80 ]; then
        log_message "WARNING: Swap usage is at ${SWAP_PERCENT}%"
    fi
}

# Main health check
log_message "Starting health check..."
check_docker
check_services
check_elasticsearch
check_vps
check_memory
log_message "Health check completed"