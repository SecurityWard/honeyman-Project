#!/bin/bash

case "$1" in
    start)
        echo "🚀 Starting Advanced Wireless Honeypot System - Phase 3B"
        echo "======================================================"
        
        # Start base honeypot system
        docker-compose up -d
        sleep 3
        
        # Start advanced wireless monitoring
        echo "🌐 Starting advanced wireless threat detection..."
        sudo python3 advanced_wireless_detection.py > logs/advanced_wireless.log 2>&1 &
        echo $! > logs/advanced_wireless.pid
        
        # Collect initial logs
        echo "📊 Collecting initial logs..."
        python3 simple_log_collector.py > /dev/null 2>&1
        
        echo ""
        echo "✅ Advanced Wireless Honeypot System Started!"
        echo "🌐 System Capabilities:"
        echo "   🌐 Web Honeypot: http://localhost:8080"
        echo "   📊 Kibana Dashboard: http://localhost:5601"
        echo "   🔌 Enhanced USB Detection: Active"
        echo "   📁 USB Filesystem Scanning: Active"
        echo "   📡 WiFi Threat Detection: Active"
        echo "   📱 BLE Threat Detection: Active"
        echo "   📤 AirDrop Attack Detection: Active"
        echo "   💾 Elasticsearch Logging: Active"
        echo ""
        echo "📋 Management Commands:"
        echo "   ./control-phase3b.sh status      - System status"
        echo "   ./control-phase3b.sh threats     - Threat analysis"
        echo "   ./control-phase3b.sh wireless    - Wireless tests"
        echo "   ./control-phase3b.sh correlate   - Attack correlation"
        ;;
    stop)
        echo "🛑 Stopping advanced wireless honeypot system..."
        
        # Stop advanced wireless monitoring
        if [ -f logs/advanced_wireless.pid ]; then
            sudo kill $(cat logs/advanced_wireless.pid) 2>/dev/null
            rm logs/advanced_wireless.pid
            echo "🌐 Advanced wireless monitoring stopped"
        fi
        
        # Stop base system
        docker-compose down
        echo "✅ Advanced wireless honeypot system stopped"
        ;;
    status)
        echo "📊 Advanced Wireless Honeypot System Status"
        echo "==========================================="
        
        # Docker status
        echo "🐳 Core Services:"
        docker-compose ps
        
        # Advanced wireless monitoring status
        echo ""
        echo "🌐 Advanced Wireless Detection:"
        if [ -f logs/advanced_wireless.pid ] && kill -0 $(cat logs/advanced_wireless.pid) 2>/dev/null; then
            echo "   ✅ Advanced wireless detection active (PID: $(cat logs/advanced_wireless.pid))"
        else
            echo "   ❌ Advanced wireless detection not running"
        fi
        
        # Detection statistics
        echo ""
        echo "📊 Detection Statistics:"
        
        # USB events
        USB_COUNT=$(curl -s "http://localhost:9200/honeypot-logs/_search?q=usb&size=0" | grep -o '"value":[0-9]*' | head -1 | cut -d: -f2)
        echo "   USB events: ${USB_COUNT:-0}"
        
        # WiFi events
        WIFI_COUNT=$(curl -s "http://localhost:9200/honeypot-logs/_search?q=wifi&size=0" | grep -o '"value":[0-9]*' | head -1 | cut -d: -f2)
        echo "   WiFi events: ${WIFI_COUNT:-0}"
        
        # BLE events
        BLE_COUNT=$(curl -s "http://localhost:9200/honeypot-logs/_search?q=ble&size=0" | grep -o '"value":[0-9]*' | head -1 | cut -d: -f2)
        echo "   BLE events: ${BLE_COUNT:-0}"
        
        # AirDrop events
        AIRDROP_COUNT=$(curl -s "http://localhost:9200/honeypot-logs/_search?q=airdrop&size=0" | grep -o '"value":[0-9]*' | head -1 | cut -d: -f2)
        echo "   AirDrop events: ${AIRDROP_COUNT:-0}"
        
        # High-risk threats
        THREAT_COUNT=$(curl -s "http://localhost:9200/honeypot-logs/_search?q=threat_score:[0.5+TO+1.0]&size=0" | grep -o '"value":[0-9]*' | head -1 | cut -d: -f2)
        echo "   High-risk threats: ${THREAT_COUNT:-0}"
        
        # System health
        echo ""
        echo "🏥 System Health:"
        curl -s "http://localhost:9200/_cluster/health" | grep -q "yellow\|green" && echo "   ✅ Elasticsearch healthy" || echo "   ❌ Elasticsearch issue"
        curl -s "http://localhost:5601/api/status" | grep -q "available" && echo "   ✅ Kibana accessible" || echo "   ❌ Kibana issue"
        curl -s "http://localhost:8080" | grep -q "login" && echo "   ✅ Web honeypot active" || echo "   ❌ Web honeypot issue"
        ;;
    wireless)
        echo "🧪 Advanced Wireless Detection Tests"
        echo "===================================="
        
        echo "📡 Testing WiFi detection (15 seconds)..."
        timeout 15 python3 wifi_threat_detector.py &
        
        echo ""
        echo "📱 Testing BLE detection (15 seconds)..."
        timeout 15 python3 ble_threat_detector.py &
        
        echo ""
        echo "📤 Testing AirDrop detection (15 seconds)..."
        timeout 15 python3 airdrop_threat_detector.py &
        
        # Wait for all tests to complete
        wait
        
        echo ""
        echo "📊 Wireless Test Results:"
        echo "WiFi threats: $(curl -s "http://localhost:9200/honeypot-logs/_search?q=wifi&size=0" | grep -o '"value":[0-9]*' | head -1 | cut -d: -f2)"
        echo "BLE threats: $(curl -s "http://localhost:9200/honeypot-logs/_search?q=ble&size=0" | grep -o '"value":[0-9]*' | head -1 | cut -d: -f2)"
        echo "AirDrop threats: $(curl -s "http://localhost:9200/honeypot-logs/_search?q=airdrop&size=0" | grep -o '"value":[0-9]*' | head -1 | cut -d: -f2)"
        ;;
    threats)
        echo "🚨 Advanced Wireless Threat Analysis"
        echo "===================================="
        
        echo "📊 Attack Vector Summary:"
        echo "------------------------"
        
        # Physical threats
        echo "🔌 Physical Threats:"
        USB_THREATS=$(curl -s "http://localhost:9200/honeypot-logs/_search?q=usb+AND+threat_score:[0.3+TO+1.0]&size=0" | grep -o '"value":[0-9]*' | head -1 | cut -d: -f2)
        echo "   USB threats: ${USB_THREATS:-0}"
        
        # Wireless threats
        echo ""
        echo "📡 Wireless Threats:"
        WIFI_THREATS=$(curl -s "http://localhost:9200/honeypot-logs/_search?q=wifi+AND+threat_score:[0.3+TO+1.0]&size=0" | grep -o '"value":[0-9]*' | head -1 | cut -d: -f2)
        echo "   WiFi threats: ${WIFI_THREATS:-0}"
        
        BLE_THREATS=$(curl -s "http://localhost:9200/honeypot-logs/_search?q=ble+AND+threat_score:[0.3+TO+1.0]&size=0" | grep -o '"value":[0-9]*' | head -1 | cut -d: -f2)
        echo "   BLE threats: ${BLE_THREATS:-0}"
        
        AIRDROP_THREATS=$(curl -s "http://localhost:9200/honeypot-logs/_search?q=airdrop+AND+threat_score:[0.3+TO+1.0]&size=0" | grep -o '"value":[0-9]*' | head -1 | cut -d: -f2)
        echo "   AirDrop threats: ${AIRDROP_THREATS:-0}"
        
        # Recent high-risk events
        echo ""
        echo "🔥 Recent High-Risk Events (all vectors):"
        curl -s "http://localhost:9200/honeypot-logs/_search?q=threat_score:[0.5+TO+1.0]&size=5&sort=timestamp:desc&_source=timestamp,source,log_type,threat_score,message" | grep -A4 '"_source"' | head -25
        ;;
    correlate)
        echo "🔗 Advanced Cross-Vector Threat Correlation"
        echo "==========================================="
        
        echo "🔍 Multi-vector attack pattern analysis..."
        
        # Check for simultaneous wireless attacks
        echo ""
        echo "📊 Simultaneous Wireless Attack Detection:"
        curl -s "http://localhost:9200/honeypot-logs/_search?q=(wifi+OR+ble+OR+airdrop)+AND+timestamp:[now-5m+TO+now]&size=0&aggs={\"attack_vectors\":{\"terms\":{\"field\":\"source.keyword\"}}}" | grep -A10 "aggregations" || echo "No recent wireless activity"
        
        echo ""
        echo "🎯 Potential Attack Campaigns:"
        # Look for coordinated attacks across vectors
        curl -s "http://localhost:9200/honeypot-logs/_search?q=threat_score:[0.5+TO+1.0]+AND+timestamp:[now-10m+TO+now]&size=10&sort=timestamp:desc&_source=timestamp,source,threat_score,log_type" | grep -A3 '"_source"' | head -30
        
        echo ""
        echo "📱 Proximity Attack Analysis:"
        # Look for BLE + AirDrop attacks (proximity-based)
        curl -s "http://localhost:9200/honeypot-logs/_search?q=(ble+OR+airdrop)+AND+threat_score:[0.3+TO+1.0]&size=5&sort=timestamp:desc&_source=timestamp,source,device_name,service_name,threats_detected" | grep -A4 '"_source"' | head -20
        ;;
    logs)
        echo "📋 Advanced Wireless System Logs"
        echo "==============================="
        
        echo "🌐 Advanced Wireless Monitor (last 15 lines):"
        tail -15 logs/advanced_wireless.log 2>/dev/null || echo "No advanced wireless logs yet"
        
        echo ""
        echo "📊 Recent Detection Events (all wireless vectors):"
        echo "------------------------------------------------"
        curl -s "http://localhost:9200/honeypot-logs/_search?q=(usb+OR+wifi+OR+ble+OR+airdrop)&size=5&sort=timestamp:desc&_source=timestamp,source,log_type,message" | grep -A3 '"_source"' | head -30
        ;;
    dashboard)
        echo "📊 Opening Advanced Wireless Dashboard..."
        echo "🌐 Kibana URL: http://localhost:5601"
        echo ""
        echo "📋 Recommended Kibana Searches:"
        echo "   All wireless: (wifi OR ble OR airdrop)"
        echo "   Physical threats: source:usb*"
        echo "   Wireless threats: (source:wifi* OR source:ble* OR source:airdrop*)"
        echo "   High-risk: threat_score:>=0.7"
        echo "   Recent activity: timestamp:[now-1h TO now]"
        echo "   Proximity attacks: (ble OR airdrop) AND threat_score:>=0.3"
        echo ""
        
        # Check dashboard accessibility
        if curl -s "http://localhost:5601/api/status" | grep -q "available"; then
            echo "✅ Kibana dashboard accessible"
        else
            echo "❌ Kibana not responding"
        fi
        ;;
    *)
        echo "Advanced Wireless Honeypot Control System - Phase 3B"
        echo "===================================================="
        echo "Usage: $0 {start|stop|status|wireless|threats|correlate|logs|dashboard}"
        echo ""
        echo "Commands:"
        echo "  start      - Start advanced wireless honeypot system"
        echo "  stop       - Stop all components"
        echo "  status     - Show comprehensive system status"
        echo "  wireless   - Test all wireless detection systems"
        echo "  threats    - View advanced wireless threat analysis"
        echo "  correlate  - Analyze cross-vector attack patterns"
        echo "  logs       - View recent system logs"
        echo "  dashboard  - Access Kibana dashboard"
        echo ""
        echo "🌐 Phase 3B Features:"
        echo "   🔌 Advanced USB device and filesystem detection"
        echo "   📡 WiFi network threat detection and analysis"
        echo "   📱 BLE threat detection (Flipper Zero, ESP32, etc.)"
        echo "   📤 AirDrop abuse and proximity attack detection"
        echo "   🔗 Multi-vector wireless attack correlation"
        echo "   📊 Comprehensive threat scoring and intelligence"
        ;;
esac
