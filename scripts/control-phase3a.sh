#!/bin/bash

case "$1" in
    start)
        echo "🚀 Starting Multi-Vector Honeypot System - Phase 3A"
        echo "=================================================="
        
        # Start base honeypot system
        docker-compose up -d
        sleep 3
        
        # Start multi-vector monitoring
        echo "🎯 Starting multi-vector threat detection..."
        sudo python3 multi_vector_detection.py > logs/multi_vector.log 2>&1 &
        echo $! > logs/multi_vector.pid
        
        # Collect initial logs
        echo "📊 Collecting initial logs..."
        python3 simple_log_collector.py > /dev/null 2>&1
        
        echo ""
        echo "✅ Multi-Vector Honeypot System Started!"
        echo "🎯 System Capabilities:"
        echo "   🌐 Web Honeypot: http://localhost:8080"
        echo "   📊 Kibana Dashboard: http://localhost:5601"
        echo "   🔌 Enhanced USB Detection: Active"
        echo "   📁 USB Filesystem Scanning: Active"
        echo "   📡 WiFi Threat Detection: Active"
        echo "   💾 Elasticsearch Logging: Active"
        echo ""
        echo "📋 Management Commands:"
        echo "   ./control-phase3a.sh status     - System status"
        echo "   ./control-phase3a.sh threats    - Threat analysis"
        echo "   ./control-phase3a.sh wifi-test  - Test WiFi detection"
        echo "   ./control-phase3a.sh usb-test   - Test USB detection"
        ;;
    stop)
        echo "🛑 Stopping multi-vector honeypot system..."
        
        # Stop multi-vector monitoring
        if [ -f logs/multi_vector.pid ]; then
            sudo kill $(cat logs/multi_vector.pid) 2>/dev/null
            rm logs/multi_vector.pid
            echo "🎯 Multi-vector monitoring stopped"
        fi
        
        # Stop base system
        docker-compose down
        echo "✅ Multi-vector honeypot system stopped"
        ;;
    status)
        echo "📊 Multi-Vector Honeypot System Status"
        echo "====================================="
        
        # Docker status
        echo "🐳 Core Services:"
        docker-compose ps
        
        # Multi-vector monitoring status
        echo ""
        echo "🎯 Multi-Vector Detection:"
        if [ -f logs/multi_vector.pid ] && kill -0 $(cat logs/multi_vector.pid) 2>/dev/null; then
            echo "   ✅ Multi-vector detection active (PID: $(cat logs/multi_vector.pid))"
        else
            echo "   ❌ Multi-vector detection not running"
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
    wifi-test)
        echo "🧪 WiFi Threat Detection Test"
        echo "============================="
        echo "📡 Testing WiFi network scanning and threat analysis..."
        echo "⏳ Monitoring for 20 seconds..."
        echo ""
        
        # Show current WiFi state
        echo "📊 Current WiFi detection state:"
        echo "WiFi events: $(curl -s "http://localhost:9200/honeypot-logs/_search?q=wifi&size=0" | grep -o '"value":[0-9]*' | head -1 | cut -d: -f2)"
        
        echo ""
        echo "🔍 Starting WiFi threat detection test..."
        
        # Run WiFi detector for testing
        timeout 20 python3 wifi_threat_detector.py
        
        echo ""
        echo "📊 WiFi Test Results:"
        curl -s "http://localhost:9200/honeypot-logs/_search?q=wifi&size=3&sort=timestamp:desc" | grep -A3 -B1 '"message"' | head -15
        ;;
    usb-test)
        echo "🧪 USB Detection Test"
        echo "===================="
        echo "🔌 Testing USB device and filesystem detection..."
        echo "💡 Plug in a USB device during the test period"
        echo "⏳ Monitoring for 20 seconds..."
        
        # Run USB detection test
        timeout 20 sudo python3 usb_detection_enhanced.py
        
        echo ""
        echo "📊 USB Test Results:"
        curl -s "http://localhost:9200/honeypot-logs/_search?q=usb&size=3&sort=timestamp:desc" | grep -A3 -B1 '"message"' | head -15
        ;;
    threats)
        echo "🚨 Multi-Vector Threat Analysis"
        echo "==============================="
        
        echo "📊 Attack Vector Summary:"
        echo "------------------------"
        
        # USB threats
        echo "🔌 USB Threats:"
        USB_THREATS=$(curl -s "http://localhost:9200/honeypot-logs/_search?q=usb+AND+threat_score:[0.3+TO+1.0]&size=0" | grep -o '"value":[0-9]*' | head -1 | cut -d: -f2)
        echo "   USB threats detected: ${USB_THREATS:-0}"
        
        # WiFi threats
        echo ""
        echo "📡 WiFi Threats:"
        WIFI_THREATS=$(curl -s "http://localhost:9200/honeypot-logs/_search?q=wifi+AND+threat_score:[0.3+TO+1.0]&size=0" | grep -o '"value":[0-9]*' | head -1 | cut -d: -f2)
        echo "   WiFi threats detected: ${WIFI_THREATS:-0}"
        
        # Recent high-risk events
        echo ""
        echo "🔥 Recent High-Risk Events (all vectors):"
        curl -s "http://localhost:9200/honeypot-logs/_search?q=threat_score:[0.5+TO+1.0]&size=5&sort=timestamp:desc&_source=timestamp,source,log_type,threat_score,message" | grep -A4 '"_source"' | head -25
        
        echo ""
        echo "📈 Threat Timeline (last 10 events):"
        curl -s "http://localhost:9200/honeypot-logs/_search?q=(usb+OR+wifi)+AND+threat&size=10&sort=timestamp:desc&_source=timestamp,source,log_type,message" | grep -A3 '"_source"' | head -40
        ;;
    logs)
        echo "📋 Multi-Vector System Logs"
        echo "=========================="
        
        echo "🎯 Multi-Vector Monitor (last 15 lines):"
        tail -15 logs/multi_vector.log 2>/dev/null || echo "No multi-vector logs yet"
        
        echo ""
        echo "📊 Recent Detection Events (all vectors):"
        echo "-----------------------------------------"
        curl -s "http://localhost:9200/honeypot-logs/_search?q=usb+OR+wifi&size=5&sort=timestamp:desc&_source=timestamp,source,log_type,message" | grep -A3 '"_source"' | head -30
        ;;
    correlate)
        echo "🔗 Cross-Vector Threat Correlation"
        echo "=================================="
        
        echo "🔍 Looking for multi-vector attack patterns..."
        
        # Check for simultaneous attacks
        echo ""
        echo "📊 Simultaneous Attack Detection:"
        curl -s "http://localhost:9200/honeypot-logs/_search?q=timestamp:[now-5m+TO+now]&size=0&aggs={\"attack_vectors\":{\"terms\":{\"field\":\"source.keyword\"}}}" | grep -A10 "aggregations" || echo "No recent multi-vector activity"
        
        echo ""
        echo "🎯 Potential Attack Campaigns:"
        # Look for multiple threat types in short time window
        curl -s "http://localhost:9200/honeypot-logs/_search?q=threat_score:[0.5+TO+1.0]+AND+timestamp:[now-10m+TO+now]&size=10&sort=timestamp:desc&_source=timestamp,source,threat_score,log_type" | grep -A3 '"_source"' | head -30
        ;;
    dashboard)
        echo "📊 Opening Multi-Vector Dashboard..."
        echo "🌐 Kibana URL: http://localhost:5601"
        echo ""
        echo "📋 Recommended Kibana Searches:"
        echo "   All threats: threat_score:>=0.3"
        echo "   USB events: source:usb*"
        echo "   WiFi events: source:wifi*"
        echo "   High-risk: threat_score:>=0.7"
        echo "   Multi-vector: (usb OR wifi) AND timestamp:[now-1h TO now]"
        echo ""
        
        # Check dashboard accessibility
        if curl -s "http://localhost:5601/api/status" | grep -q "available"; then
            echo "✅ Kibana dashboard accessible"
        else
            echo "❌ Kibana not responding"
        fi
        ;;
    *)
        echo "Multi-Vector Honeypot Control System - Phase 3A"
        echo "==============================================="
        echo "Usage: $0 {start|stop|status|wifi-test|usb-test|threats|logs|correlate|dashboard}"
        echo ""
        echo "Commands:"
        echo "  start      - Start multi-vector honeypot system"
        echo "  stop       - Stop all components"
        echo "  status     - Show comprehensive system status"
        echo "  wifi-test  - Test WiFi threat detection (20 seconds)"
        echo "  usb-test   - Test USB detection (20 seconds)"
        echo "  threats    - View multi-vector threat analysis"
        echo "  logs       - View recent system logs"
        echo "  correlate  - Analyze cross-vector attack patterns"
        echo "  dashboard  - Access Kibana dashboard"
        echo ""
        echo "🎯 Phase 3A Features:"
        echo "   🔌 Advanced USB device and filesystem detection"
        echo "   📡 WiFi network threat detection and analysis"
        echo "   🚨 Evil twin AP and beacon flooding detection"
        echo "   🔗 Multi-vector threat correlation"
        echo "   📊 Comprehensive threat scoring and logging"
        ;;
esac
