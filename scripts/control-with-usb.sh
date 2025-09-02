#!/bin/bash

case "$1" in
    start)
        echo "🚀 Starting Enhanced Honeypot with USB Detection..."
        docker-compose up -d
        
        # Start USB monitoring
        echo "🔌 Starting USB threat detection..."
        sudo python3 usb_monitor.py > logs/usb_monitor.log 2>&1 &
        echo $! > logs/usb_monitor.pid
        
        echo "📊 Collecting initial logs..."
        python3 simple_log_collector.py
        
        echo "✅ Started! Capabilities:"
        echo "   🌐 Web Honeypot: http://localhost:8080"
        echo "   📊 Kibana: http://localhost:5601"
        echo "   🔌 USB Detection: Active"
        echo "   📋 Status: ./control-with-usb.sh status"
        ;;
    stop)
        echo "🛑 Stopping honeypot system..."
        
        # Stop USB monitoring
        if [ -f logs/usb_monitor.pid ]; then
            sudo kill $(cat logs/usb_monitor.pid) 2>/dev/null
            rm logs/usb_monitor.pid
            echo "🔌 USB monitoring stopped"
        fi
        
        docker-compose down
        echo "✅ System stopped"
        ;;
    status)
        echo "📊 Honeypot System Status:"
        echo "========================="
        
        # Docker status
        echo "🐳 Containers:"
        docker-compose ps
        
        # USB monitoring status
        echo ""
        echo "🔌 USB Monitoring:"
        if [ -f logs/usb_monitor.pid ] && kill -0 $(cat logs/usb_monitor.pid) 2>/dev/null; then
            echo "   ✅ USB monitoring active (PID: $(cat logs/usb_monitor.pid))"
        else
            echo "   ❌ USB monitoring not running"
        fi
        
        # Data status
        echo ""
        echo "📊 Data Status:"
        curl -s "http://localhost:9200/_cat/indices?v" 2>/dev/null || echo "   ❌ Elasticsearch not responding"
        ;;
    usb-test)
        echo "🧪 Testing USB Detection..."
        echo "💡 Plug in a USB device now..."
        echo "⏳ Monitoring for 15 seconds..."
        
        sudo timeout 15 python3 usb_monitor.py
        
        echo ""
        echo "📊 Checking logged USB events:"
        curl "http://localhost:9200/honeypot-logs/_search?q=usb&size=3&pretty" | grep -A5 -B5 "usb"
        ;;
    logs)
        echo "📋 System Logs:"
        echo "=============="
        
        echo "USB Monitor:"
        tail -10 logs/usb_monitor.log 2>/dev/null || echo "No USB logs yet"
        
        echo ""
        echo "Recent Elasticsearch entries:"
        curl -s "http://localhost:9200/honeypot-logs/_search?size=5&sort=timestamp:desc&pretty" | head -30
        ;;
    threats)
        echo "🚨 USB Threat Summary:"
        echo "===================="
        
        # Count USB threats by level
        curl -s "http://localhost:9200/honeypot-logs/_search?q=usb+AND+threat&size=0&pretty" | grep "\"value\""
        
        echo ""
        echo "Recent USB threats:"
        curl -s "http://localhost:9200/honeypot-logs/_search?q=usb+AND+threat&size=5&pretty" | grep -A3 -B1 "threat_score\|threats_detected"
        ;;
    *)
        echo "Usage: $0 {start|stop|status|usb-test|logs|threats}"
        echo ""
        echo "Commands:"
        echo "  start     - Start honeypot with USB detection"
        echo "  stop      - Stop all components"
        echo "  status    - Show system status"
        echo "  usb-test  - Test USB detection for 15 seconds"
        echo "  logs      - View recent logs"
        echo "  threats   - View USB threat summary"
        ;;
esac
