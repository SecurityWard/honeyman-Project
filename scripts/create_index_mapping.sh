#!/bin/bash

# Create Elasticsearch index with proper mapping for all honeypot services
curl -X PUT "http://localhost:9200/honeypot-logs" \
  -H 'Content-Type: application/json' \
  -d '{
    "mappings": {
      "properties": {
        "timestamp": {
          "type": "date",
          "format": "yyyy-MM-dd HH:mm:ss||yyyy-MM-dd HH:mm:ss.SSSSSS||yyyy-MM-dd'\''T'\''HH:mm:ss.SSSSSS||strict_date_optional_time||epoch_millis"
        },
        "@timestamp": {
          "type": "date"
        },
        "honeypot_id": {
          "type": "keyword"
        },
        "source": {
          "type": "keyword"
        },
        "log_type": {
          "type": "keyword"
        },
        "threat_type": {
          "type": "keyword"
        },
        "detection_type": {
          "type": "keyword"
        },
        "threat_score": {
          "type": "float"
        },
        "risk_level": {
          "type": "keyword"
        },
        "message": {
          "type": "text"
        },
        "device_info": {
          "type": "object"
        },
        "network_info": {
          "type": "object"
        },
        "threat_analysis": {
          "type": "object"
        },
        "behavioral_data": {
          "type": "object"
        },
        "threats_detected": {
          "type": "keyword"
        },
        "src_host": {
          "type": "ip",
          "ignore_malformed": true
        },
        "src_port": {
          "type": "integer"
        },
        "dst_host": {
          "type": "ip",
          "ignore_malformed": true
        },
        "dst_port": {
          "type": "integer"
        },
        "logtype": {
          "type": "keyword"
        },
        "node_id": {
          "type": "keyword"
        },
        "forwarded": {
          "type": "boolean"
        }
      }
    }
  }'

echo ""
echo "Index mapping created successfully!"