#!/bin/bash

case "$1" in
    start)
        echo "🚀 Starting Enhanced Honeypot with Advanced USB Detection..."
        echo "=========================================================="
        
        # Start base honeypot system
        docker-compose up -d
        sleep 3
        
        # Start enhanced USB monitoring
        echo "🔌 Starting enhanced USB detection (device + filesystem)..."
        sudo python3 usb_detection_enhanced.py > logs/usb_enhanced.log 2>&1 &
        echo $! > logs/usb_enhanced.pid
        
        # Collect initial logs
        echo "📊 Collecting initial logs..."
        python3 simple_log_collector.py > /dev/null 2>&1
        
        echo ""
        echo "✅ Enhanced Honeypot System Started!"
        echo "🎯 System Capabilities:"
        echo "   🌐 Web Honeypot: http://localhost:8080"
        echo "   📊 Kibana Dashboard: http://localhost:5601"
        echo "   🔌 Enhanced USB Detection: Active"
        echo "   📁 Filesystem Scanning: Active"
        echo "   💾 Elasticsearch Logging: Active"
        echo ""
        echo "📋 Management Commands:"
        echo "   ./control-enhanced-usb.sh status   - System status"
        echo "   ./control-enhanced-usb.sh threats  - Threat summary"
        echo "   ./control-enhanced-usb.sh usb-test - Test USB detection"
        ;;
    stop)
        echo "🛑 Stopping enhanced honeypot system..."
        
        # Stop enhanced USB monitoring
        if [ -f logs/usb_enhanced.pid ]; then
            sudo kill $(cat logs/usb_enhanced.pid) 2>/dev/null
            rm logs/usb_enhanced.pid
            echo "🔌 Enhanced USB monitoring stopped"
        fi
        
        # Stop base system
        docker-compose down
        echo "✅ Enhanced honeypot system stopped"
        ;;
    status)
        echo "📊 Enhanced Honeypot System Status"
        echo "================================="
        
        # Docker status
        echo "🐳 Core Services:"
        docker-compose ps
        
        # Enhanced USB monitoring status
        echo ""
        echo "🔌 Enhanced USB Detection:"
        if [ -f logs/usb_enhanced.pid ] && kill -0 $(cat logs/usb_enhanced.pid) 2>/dev/null; then
            echo "   ✅ Enhanced USB detection active (PID: $(cat logs/usb_enhanced.pid))"
        else
            echo "   ❌ Enhanced USB detection not running"
        fi
        
        # Data and threat statistics
        echo ""
        echo "📊 Detection Statistics:"
        
        # USB device events
        USB_DEVICE_COUNT=$(curl -s "http://localhost:9200/honeypot-logs/_search?q=usb_monitor&size=0" | grep -o '"value":[0-9]*' | head -1 | cut -d: -f2)
        echo "   USB device events: ${USB_DEVICE_COUNT:-0}"
        
        # Filesystem scans
        FS_SCAN_COUNT=$(curl -s "http://localhost:9200/honeypot-logs/_search?q=filesystem&size=0" | grep -o '"value":[0-9]*' | head -1 | cut -d: -f2)
        echo "   Filesystem scans: ${FS_SCAN_COUNT:-0}"
        
        # Total threats
        THREAT_COUNT=$(curl -s "http://localhost:9200/honeypot-logs/_search?q=threat_score:[0.5+TO+1.0]&size=0" | grep -o '"value":[0-9]*' | head -1 | cut -d: -f2)
        echo "   High-risk threats: ${THREAT_COUNT:-0}"
        
        # System health
        echo ""
        echo "🏥 System Health:"
        curl -s "http://localhost:9200/_cluster/health" | grep -q "yellow\|green" && echo "   ✅ Elasticsearch healthy" || echo "   ❌ Elasticsearch issue"
        curl -s "http://localhost:5601/api/status" | grep -q "available" && echo "   ✅ Kibana accessible" || echo "   ❌ Kibana issue"
        curl -s "http://localhost:8080" | grep -q "login" && echo "   ✅ Web honeypot active" || echo "   ❌ Web honeypot issue"
        ;;
    usb-test)
        echo "🧪 Enhanced USB Detection Test"
        echo "============================="
        echo "💡 This test will monitor for USB device connections and filesystem changes"
        echo "🔌 Please plug in a USB device during the test period"
        echo "⏳ Monitoring for 25 seconds..."
        echo ""
        
        # Show current state
        echo "📊 Current USB detection state:"
        echo "Device events: $(curl -s "http://localhost:9200/honeypot-logs/_search?q=usb_monitor&size=0" | grep -o '"value":[0-9]*' | head -1 | cut -d: -f2)"
        echo "Filesystem scans: $(curl -s "http://localhost:9200/honeypot-logs/_search?q=filesystem&size=0" | grep -o '"value":[0-9]*' | head -1 | cut -d: -f2)"
        
        echo ""
        echo "🔍 Starting enhanced USB monitoring..."
        
        # Run the enhanced monitor for testing
        sudo timeout 25 python3 usb_detection_enhanced.py
        
        echo ""
        echo "📊 Test Results:"
        curl -s "http://localhost:9200/honeypot-logs/_search?q=(usb+OR+filesystem)&size=5&sort=timestamp:desc" | grep -A3 -B1 '"message"' | head -15
        ;;
    scan-test)
        echo "🧪 Filesystem Scanning Test"
        echo "==========================="
        
        # Create test directory with suspicious files
        echo "📁 Creating test filesystem with suspicious files..."
        mkdir -p /tmp/test-usb-threats
        cd /tmp/test-usb-threats
        
        # Create various threat files
        echo "[autorun]" > autorun.inf
        echo "exe header" > suspicious_hack.exe
        echo "batch script" > keylogger.bat
        echo "normal content" > document.txt
        echo "hidden payload" > .hidden_virus.exe
        echo "script content" > malware.vbs
        touch trojan_backdoor.com
        
        echo "✅ Created test threats in /tmp/test-usb-threats"
        echo ""
        echo "🔍 Running filesystem scanner on test directory..."
        
        # Test the scanner
        python3 -c "
import sys
sys.path.append('/home/burner/honeypot-minimal')
from usb_filesystem_monitor import USBFilesystemMonitor

monitor = USBFilesystemMonitor()
results = monitor.scan_mount_point('/tmp/test-usb-threats')

print(f'📊 Scan Results:')
print(f'  📁 Total files scanned: {results[\"total_files\"]}')
print(f'  🚨 Threats detected: {len(results[\"threats_found\"])}')
print(f'  ⚡ Overall threat score: {results[\"threat_score\"]:.2f}')
print()

for i, threat in enumerate(results['threats_found'], 1):
    file_name = threat['file_path'].split('/')[-1]
    threat_list = ', '.join(threat['threats'])
    score = threat['threat_score']
    print(f'  {i}. 🚨 {file_name} (score: {score:.2f})')
    print(f'     Threats: {threat_list}')

# Send to Elasticsearch for testing
monitor.send_to_elasticsearch(results)
print()
print('✅ Results sent to Elasticsearch')
"
        
        # Cleanup
        cd /home/burner/honeypot-minimal
        rm -rf /tmp/test-usb-threats
        echo ""
        echo "🧹 Test files cleaned up"
        echo "✅ Filesystem scanning test complete"
        ;;
    threats)
        echo "🚨 Enhanced USB Threat Analysis"
        echo "=============================="
        
        echo "📊 Threat Statistics:"
        echo "-------------------"
        
        # Device-level threats
        echo "🔌 USB Device Threats:"
        curl -s "http://localhost:9200/honeypot-logs/_search?q=usb_monitor&size=0&aggs={\"threat_levels\":{\"terms\":{\"field\":\"log_type.keyword\"}}}" | grep -A10 "aggregations" 2>/dev/null || echo "   No device threats detected"
        
        echo ""
        echo "📁 Filesystem Threats:"
        
        # Filesystem threats summary
        TOTAL_FS_THREATS=$(curl -s "http://localhost:9200/honeypot-logs/_search?q=filesystem&size=0&aggs={\"total_threats\":{\"sum\":{\"field\":\"threats_count\"}}}" | grep -o '"value":[0-9.]*' | cut -d: -f2)
        echo "   Total filesystem threats: ${TOTAL_FS_THREATS:-0}"
        
        # High-risk events
        echo ""
        echo "🔥 Recent High-Risk Events:"
        curl -s "http://localhost:9200/honeypot-logs/_search?q=(usb+OR+filesystem)+AND+threat_score:[0.5+TO+1.0]&size=3&sort=timestamp:desc&_source=timestamp,source,message,threat_score" | grep -A4 '"_source"' | head -20
        
        echo ""
        echo "📈 Threat Timeline (last 5 events):"
        curl -s "http://localhost:9200/honeypot-logs/_search?q=usb+OR+filesystem&size=5&sort=timestamp:desc&_source=timestamp,log_type,threat_score,message" | grep -A3 '"_source"' | head -25
        ;;
    logs)
        echo "📋 Enhanced USB System Logs"
        echo "=========================="
        
        echo "🔌 Enhanced USB Monitor (last 15 lines):"
        tail -15 logs/usb_enhanced.log 2>/dev/null || echo "No enhanced USB logs yet"
        
        echo ""
        echo "📊 Recent Detection Events:"
        echo "---------------------------"
        curl -s "http://localhost:9200/honeypot-logs/_search?q=usb+OR+filesystem&size=5&sort=timestamp:desc&_source=timestamp,source,log_type,message" | grep -A3 '"_source"' | head -30
        
        echo ""
        echo "📈 Live Monitoring:"
        echo "To see real-time logs: tail -f logs/usb_enhanced.log"
        ;;
    dashboard)
        echo "📊 Opening Kibana Dashboard..."
        echo "🌐 Kibana URL: http://localhost:5601"
        echo ""
        echo "📋 Recommended Kibana Searches:"
        echo "   USB device events: log_type:usb_threat_detection"
        echo "   Filesystem scans: log_type:usb_filesystem_scan"
        echo "   High threats: threat_score:>=0.5"
        echo "   Recent activity: timestamp:[now-1h TO now]"
        echo ""
        
        # Check if Kibana is accessible
        if curl -s "http://localhost:5601/api/status" | grep -q "available"; then
            echo "✅ Kibana is accessible"
        else
            echo "❌ Kibana not responding"
        fi
        ;;
    *)
        echo "Enhanced USB Honeypot Control System - Phase 2B"
        echo "==============================================="
        echo "Usage: $0 {start|stop|status|usb-test|scan-test|threats|logs|dashboard}"
        echo ""
        echo "Commands:"
        echo "  start      - Start enhanced honeypot with advanced USB detection"
        echo "  stop       - Stop all components"
        echo "  status     - Show comprehensive system status"
        echo "  usb-test   - Test enhanced USB detection (25 seconds)"
        echo "  scan-test  - Test filesystem scanning with sample threats"
        echo "  threats    - View detailed threat analysis and statistics"
        echo "  logs       - View recent enhanced system logs"
        echo "  dashboard  - Access Kibana dashboard for visualization"
        echo ""
        echo "🎯 Phase 2B Features:"
        echo "   🔌 Real-time USB device threat detection"
        echo "   📁 Comprehensive filesystem scanning"
        echo "   🚨 Autorun and malicious file detection"
        echo "   📊 Advanced threat scoring and correlation"
        echo "   💾 Complete Elasticsearch integration"
        ;;
esac
