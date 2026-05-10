#!/usr/bin/env python3
"""
OpenCanary Event Forwarder
Receives webhook events from OpenCanary and forwards them to Elasticsearch
"""
import json
import requests
import time
from datetime import datetime
from flask import Flask, request, jsonify
import threading
import logging

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class OpenCanaryForwarder:
    def __init__(self):
        self.es_url = "http://localhost:9200/honeypot-logs-new/_doc"
        
    def process_canary_event(self, event_data):
        """Process and forward OpenCanary event to Elasticsearch"""
        try:
            # Parse the event data
            if isinstance(event_data, str):
                event_data = json.loads(event_data)
            
            # Extract key information from OpenCanary event
            logtype = event_data.get('logtype', 'unknown')
            src_host = event_data.get('src_host', 'unknown')
            src_port = event_data.get('src_port', 0)
            dst_host = event_data.get('dst_host', 'localhost')
            dst_port = event_data.get('dst_port', 0)
            node_id = event_data.get('node_id', 'honeyman-01')
            
            # Calculate threat score based on event type
            threat_score = self.calculate_threat_score(logtype, event_data)
            
            # Create standardized event for Elasticsearch
            es_event = {
                'timestamp': datetime.utcnow().isoformat(),
                'honeypot_id': 'honeyman-01',
                'source': 'opencanary',
                'log_type': 'honeypot_interaction',
                'threat_type': 'canary_triggered',
                'detection_type': logtype,
                'threat_score': round(float(threat_score), 2),  # Clean float precision
                'risk_level': self.get_risk_level(threat_score),
                'src_host': src_host,
                'src_port': src_port,
                'dst_host': dst_host,
                'dst_port': dst_port,
                'node_id': node_id,
                'logtype': logtype,
                'original_event': event_data,
                'threats_detected': [logtype],
                'message': f"OpenCanary {logtype} interaction from {src_host}:{src_port}"
            }
            
            # Send to Elasticsearch
            response = requests.post(
                self.es_url,
                json=es_event,
                timeout=5
            )
            
            if response.status_code in [200, 201]:
                logger.info(f"✅ OpenCanary event logged: {logtype} from {src_host}")
                return True
            else:
                logger.error(f"❌ Failed to log OpenCanary event: {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"❌ Error processing OpenCanary event: {e}")
            return False
    
    def calculate_threat_score(self, logtype, event_data):
        """Calculate threat score based on interaction type"""
        threat_scores = {
            'ssh.login_attempt': 0.7,
            'telnet.login_attempt': 0.6,
            'ftp.login_attempt': 0.6,
            'http.request': 0.4,
            'smb.request': 0.8,
            'mysql.login_attempt': 0.8,
            'redis.command': 0.7,
            'vnc.login_attempt': 0.9,
            'mssql.login_attempt': 0.8,
            'snmp.poll': 0.5,
            'sip.request': 0.6,
            'tftp.request': 0.5,
            'nfs.request': 0.6,
            'portscan.portscan': 0.9
        }
        
        base_score = threat_scores.get(logtype, 0.3)
        
        # Increase score for multiple failed attempts
        if 'password' in event_data and event_data.get('password') != '':
            base_score += 0.1
            
        # Increase score for suspicious usernames
        username = event_data.get('username', '').lower()
        if username in ['admin', 'root', 'administrator', 'sa', 'user']:
            base_score += 0.1
            
        return min(base_score, 1.0)
    
    def get_risk_level(self, threat_score):
        """Convert threat score to risk level (clean ASCII for dashboard compatibility)"""
        if threat_score >= 0.8:
            return "CRITICAL"
        elif threat_score >= 0.6:
            return "HIGH" 
        elif threat_score >= 0.4:
            return "MEDIUM"
        else:
            return "LOW"

forwarder = OpenCanaryForwarder()

@app.route('/opencanary-webhook', methods=['POST'])
def handle_canary_webhook():
    """Handle incoming OpenCanary webhook events"""
    try:
        event_data = request.get_json()
        if event_data:
            success = forwarder.process_canary_event(event_data)
            return jsonify({'status': 'success' if success else 'error'}), 200 if success else 500
        else:
            return jsonify({'status': 'error', 'message': 'No data received'}), 400
    except Exception as e:
        logger.error(f"Error handling webhook: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({'status': 'ok', 'service': 'opencanary-forwarder'}), 200

if __name__ == '__main__':
    logger.info("🚀 Starting OpenCanary Event Forwarder")
    logger.info("📡 Listening for webhooks on port 8888")
    app.run(host='0.0.0.0', port=8888, debug=False)