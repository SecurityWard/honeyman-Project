#!/bin/bash

# Honeypot System Health Check Script
# Provides quick status overview of all honeypot components

echo "============================================================"
echo "🏥 HONEYPOT SYSTEM HEALTH CHECK - $(date)"
echo "============================================================"

# Check Systemd Services
echo -e "\n📊 Systemd Services:"
services=(
    "honeypot-usb-advanced"
    "honeypot-wifi-detector"
    "honeypot-ble-enhanced"
    "honeypot-airdrop"
    "honeypot-multi-vector"
    "honeypot-forwarder"
    "honeypot-canary-forwarder"
)

for service in "${services[@]}"; do
    if systemctl is-active --quiet "${service}.service"; then
        echo "  ✅ ${service}: Running"
    else
        echo "  ❌ ${service}: Stopped"
    fi
done

# Check Docker Containers
echo -e "\n🐋 Docker Containers:"
containers=(
    "honeypot-elasticsearch"
    "honeypot-kibana"
    "honeypot-web"
    "honeypot-opencanary"
)

for container in "${containers[@]}"; do
    if docker inspect -f '{{.State.Running}}' "$container" 2>/dev/null | grep -q true; then
        echo "  ✅ ${container}: Running"
    else
        echo "  ❌ ${container}: Stopped"
    fi
done

# Check Elasticsearch
echo -e "\n🔗 Infrastructure:"
if curl -s -o /dev/null -w "%{http_code}" http://localhost:9200 | grep -q "200"; then
    echo "  ✅ Elasticsearch: Healthy"
    # Get event count
    count=$(curl -s "localhost:9200/honeypot-*/_count" | python3 -c "import sys, json; print(json.load(sys.stdin).get('count', 0))" 2>/dev/null)
    echo "     Total Events: ${count}"
else
    echo "  ❌ Elasticsearch: Down"
fi

# Check VPS Dashboard
if timeout 5 curl -s -o /dev/null -w "%{http_code}" http://72.60.25.24:8080/api/threats/stats | grep -q "200"; then
    echo "  ✅ VPS Dashboard: Connected"
else
    echo "  ❌ VPS Dashboard: Unreachable"
fi

# System Resources
echo -e "\n💻 System Resources:"
echo "  CPU Usage: $(top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{print 100 - $1}')%"
echo "  Memory Usage: $(free -m | awk 'NR==2{printf "%.1f%%", $3*100/$2}')"
echo "  Disk Usage: $(df -h / | awk 'NR==2{print $5}')"
echo "  Network Connections: $(ss -tun | wc -l)"

# Recent Threats (last hour)
echo -e "\n🚨 Recent Activity (Last Hour):"
recent_count=$(curl -s -X GET "localhost:9200/honeypot-*/_count" -H 'Content-Type: application/json' -d '{
  "query": {
    "range": {
      "timestamp": {
        "gte": "now-1h"
      }
    }
  }
}' 2>/dev/null | python3 -c "import sys, json; print(json.load(sys.stdin).get('count', 0))" 2>/dev/null)
echo "  Events in last hour: ${recent_count}"

# Log file sizes
echo -e "\n📁 Log Files (Top 5 by size):"
ls -lhS /home/burner/honeypot-minimal/logs/*.log 2>/dev/null | head -5 | awk '{print "  " $9 ": " $5}'

# Overall Status
echo -e "\n============================================================"
service_count=$(systemctl list-units --type=service --state=running | grep honeypot | wc -l)
docker_count=$(docker ps --format "{{.Names}}" | grep honeypot | wc -l)

if [ "$service_count" -ge 5 ] && [ "$docker_count" -ge 3 ]; then
    echo "✅ Overall Status: HEALTHY"
elif [ "$service_count" -ge 3 ] && [ "$docker_count" -ge 2 ]; then
    echo "⚠️  Overall Status: WARNING - Some services not running"
else
    echo "❌ Overall Status: CRITICAL - Multiple services down"
fi
echo "============================================================"