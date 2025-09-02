#!/bin/bash

case "$1" in
    start)
        echo "🚀 Starting Minimal Honeypot..."
        docker-compose up -d
        echo "✅ Started! Access points:"
        echo "   Web Honeypot: http://localhost:8080"
        echo "   Kibana: http://localhost:5601"
        echo "   SSH Honeypot: ssh admin@localhost"
        ;;
    stop)
        echo "🛑 Stopping honeypot..."
        docker-compose down
        ;;
    status)
        docker-compose ps
        ;;
    logs)
        docker-compose logs -f opencanary
        ;;
    *)
        echo "Usage: $0 {start|stop|status|logs}"
        ;;
esac
