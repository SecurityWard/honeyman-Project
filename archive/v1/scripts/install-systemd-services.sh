#!/bin/bash

# Honeypot Systemd Service Installation Script
# This script installs all honeypot services for automatic startup

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
SYSTEMD_DIR="/etc/systemd/system"

echo "🚀 Installing Honeyman Project systemd services..."

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "❌ Please run as root (use sudo)"
    exit 1
fi

# Create systemd directory if not exists
mkdir -p "$SCRIPT_DIR/systemd"

# Copy all service files
echo "📋 Copying service files..."
cp "$SCRIPT_DIR/systemd/"*.service "$SYSTEMD_DIR/" 2>/dev/null || echo "⚠️  No service files found"
cp "$SCRIPT_DIR/systemd/"*.target "$SYSTEMD_DIR/" 2>/dev/null || echo "⚠️  No target files found"

# Reload systemd daemon
echo "🔄 Reloading systemd daemon..."
systemctl daemon-reload

# Enable services
echo "⚙️  Enabling services..."
systemctl enable honeypot-elasticsearch.service
systemctl enable honeypot-opencanary.service
systemctl enable honeypot-wifi-detector.service
systemctl enable honeypot-multi-vector.service
systemctl enable honeypot-forwarder.service
systemctl enable honeypot-usb-advanced.service
systemctl enable honeypot-airdrop.service
systemctl enable honeypot.target

echo "✅ Services installed and enabled!"
echo ""
echo "Available commands:"
echo "  - Start all: sudo systemctl start honeypot.target"
echo "  - Stop all:  sudo systemctl stop honeypot.target"
echo "  - Status:    sudo systemctl status honeypot-*.service"
echo "  - Logs:      sudo journalctl -u honeypot-* -f"
echo ""
echo "Services will start automatically on boot."