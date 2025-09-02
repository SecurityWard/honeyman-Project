#!/bin/bash

# Honeyman Project Management Script
# Unified control for all honeypot components

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then 
        echo -e "${RED}❌ Please run as root (use sudo)${NC}"
        exit 1
    fi
}

# Function to display status
show_status() {
    echo -e "${BLUE}📊 Honeyman Project Status${NC}"
    echo "=========================="
    
    # Docker services
    echo -e "\n${YELLOW}Docker Services:${NC}"
    docker compose ps
    
    # System services
    echo -e "\n${YELLOW}System Services:${NC}"
    systemctl status honeypot-*.service --no-pager | grep -E "(●|Active:)" || true
    
    # Dashboard status (if on VPS)
    if [ -f "/root/dashboard/api/server.js" ]; then
        echo -e "\n${YELLOW}Dashboard Status:${NC}"
        systemctl status honeypot-dashboard.service --no-pager | grep -E "(●|Active:)" || true
    fi
}

# Function to start all services
start_all() {
    echo -e "${GREEN}🚀 Starting Honeyman Project...${NC}"
    
    # Start Docker services
    echo "Starting Docker services..."
    docker compose up -d elasticsearch opencanary
    
    # Wait for Elasticsearch
    echo "Waiting for Elasticsearch..."
    sleep 30
    
    # Start systemd services
    echo "Starting detection services..."
    systemctl start honeypot.target
    
    echo -e "${GREEN}✅ All services started!${NC}"
}

# Function to stop all services
stop_all() {
    echo -e "${YELLOW}🛑 Stopping Honeyman Project...${NC}"
    
    # Stop systemd services
    systemctl stop honeypot.target
    systemctl stop honeypot-*.service
    
    # Stop Docker services
    docker compose down
    
    echo -e "${GREEN}✅ All services stopped!${NC}"
}

# Function to view logs
view_logs() {
    echo -e "${BLUE}📜 Viewing logs (Ctrl+C to exit)${NC}"
    echo "================================="
    
    case "$1" in
        "docker")
            docker compose logs -f
            ;;
        "system")
            journalctl -u honeypot-* -f
            ;;
        "all")
            # Split terminal would be ideal, but fallback to system logs
            journalctl -u honeypot-* -f
            ;;
        *)
            echo "Usage: $0 logs [docker|system|all]"
            ;;
    esac
}

# Function to install systemd services
install_services() {
    echo -e "${GREEN}📦 Installing systemd services...${NC}"
    
    # Run installation script
    bash /home/burner/honeypot-minimal/install-systemd-services.sh
    
    echo -e "${GREEN}✅ Services installed!${NC}"
}

# Main menu
case "$1" in
    "start")
        check_root
        start_all
        ;;
    "stop")
        check_root
        stop_all
        ;;
    "restart")
        check_root
        stop_all
        sleep 5
        start_all
        ;;
    "status")
        show_status
        ;;
    "logs")
        view_logs "$2"
        ;;
    "install")
        check_root
        install_services
        ;;
    *)
        echo "Honeyman Project Manager"
        echo "======================="
        echo "Usage: $0 {start|stop|restart|status|logs|install}"
        echo ""
        echo "Commands:"
        echo "  start    - Start all honeypot services"
        echo "  stop     - Stop all honeypot services"
        echo "  restart  - Restart all services"
        echo "  status   - Show service status"
        echo "  logs     - View logs (docker|system|all)"
        echo "  install  - Install systemd services"
        echo ""
        echo "Examples:"
        echo "  sudo $0 start"
        echo "  $0 status"
        echo "  $0 logs system"
        exit 1
        ;;
esac