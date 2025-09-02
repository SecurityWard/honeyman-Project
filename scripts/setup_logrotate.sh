#!/bin/bash

# Setup logrotate for honeypot logs
# This script installs the logrotate configuration and sets up a cron job

echo "🔄 Setting up log rotation for honeypot logs..."

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "⚠️  Please run this script with sudo"
    exit 1
fi

# Copy logrotate configuration to system directory
cp /home/burner/honeypot-minimal/logrotate.conf /etc/logrotate.d/honeypot-minimal

# Set proper permissions
chmod 644 /etc/logrotate.d/honeypot-minimal

# Test the configuration
echo "✅ Testing logrotate configuration..."
logrotate -d /etc/logrotate.d/honeypot-minimal 2>&1 | head -20

# Force initial rotation for large files
echo "🔄 Running initial rotation for large files..."
logrotate -f /etc/logrotate.d/honeypot-minimal

echo "✅ Log rotation configured successfully!"
echo ""
echo "📊 Current log sizes:"
ls -lh /home/burner/honeypot-minimal/logs/*.log | awk '{print $9, $5}'
echo ""
echo "ℹ️  Logs will be rotated when they reach size limits:"
echo "   - USB/Multi-vector logs: 100MB"
echo "   - Other logs: 50MB"
echo "   - Keeps 7 days of compressed backups"
echo ""
echo "📅 Logrotate runs daily via /etc/cron.daily/logrotate"