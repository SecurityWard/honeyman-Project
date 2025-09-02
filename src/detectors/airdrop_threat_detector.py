#!/usr/bin/env python3
"""
AirDrop Threat Detection System - Phase 3B
Detects AirDrop abuse and proximity-based attacks
"""
import subprocess
import time
import json
import requests
import socket
from datetime import datetime
from collections import defaultdict

class AirDropThreatDetector:
    def __init__(self):
        self.known_services = {}
        self.service_appearances = defaultdict(list)
        
        # Suspicious AirDrop patterns
        self.suspicious_patterns = [
            'flipper', 'hack', 'pwn', 'test', 'exploit',
            'payload', 'shell', 'attack', 'pentest'
        ]
        
        # Suspicious device names
        self.suspicious_names = [
            'iPhone', 'iPad', 'MacBook'  # Generic names often used in attacks
        ]
        
    def scan_airdrop_services(self):
        """Scan for AirDrop services using avahi-browse"""
        services = []
        
        try:
            # Scan for _airdrop._tcp services
            result = subprocess.run(
                ['avahi-browse', '_airdrop._tcp', '-t', '-r'],
                capture_output=True, text=True, timeout=15
            )
            
            current_service = {}
            
            for line in result.stdout.split('\n'):
                line = line.strip()
                
                if line.startswith('='):
                    # New service entry
                    if current_service:
                        services.append(current_service)
                    
                    parts = line.split()
                    if len(parts) >= 4:
                        current_service = {
                            'interface': parts[1],
                            'protocol': parts[2],
                            'name': ' '.join(parts[3:]),
                            'timestamp': datetime.utcnow().isoformat(),
                            'txt_records': [],
                            'address': '',
                            'port': ''
                        }
                        
                elif 'address' in line.lower():
                    address_match = line.split('[')[-1].split(']')[0]
                    if current_service:
                        current_service['address'] = address_match
                        
                elif 'port' in line.lower():
                    port_match = line.split('[')[-1].split(']')[0]
                    if current_service:
                        current_service['port'] = port_match
                        
                elif line.startswith('"') and current_service:
                    # TXT record
                    current_service['txt_records'].append(line.strip('"'))
                    
            # Add the last service
            if current_service:
                services.append(current_service)
                
        except subprocess.TimeoutExpired:
            print("⚠️ AirDrop scan timeout")
        except Exception as e:
            print(f"❌ AirDrop scan error: {e}")
            
        return services
        
    def analyze_airdrop_threats(self, service):
        """Analyze AirDrop service for threats"""
        threats = []
        threat_score = 0.0
        
        name = service.get('name', '').lower()
        txt_records = service.get('txt_records', [])
        address = service.get('address', '')
        
        # Check service name for suspicious patterns
        for pattern in self.suspicious_patterns:
            if pattern in name:
                threats.append(f"suspicious_name_{pattern}")
                threat_score += 0.5
                
        # Check for generic/spoofed device names
        for generic_name in self.suspicious_names:
            if generic_name.lower() in name and len(name.split()) <= 2:
                threats.append(f"generic_device_name_{generic_name.lower()}")
                threat_score += 0.3
                
        # Analyze TXT records for suspicious content
        txt_content = ' '.join(txt_records).lower()
        for pattern in self.suspicious_patterns:
            if pattern in txt_content:
                threats.append(f"suspicious_txt_{pattern}")
                threat_score += 0.4
                
        # Check for rapid service announcements (attack pattern)
        current_time = time.time()
        service_key = f"{address}:{service.get('port', '')}"
        self.service_appearances[service_key].append(current_time)
        
        # Remove old appearances (>5 minutes)
        self.service_appearances[service_key] = [
            t for t in self.service_appearances[service_key]
            if current_time - t < 300
        ]
        
        # If service appears/disappears frequently
        if len(self.service_appearances[service_key]) > 3:
            threats.append("rapid_service_announcements")
            threat_score += 0.3
            
        # Check for non-standard ports
        try:
            port = int(service.get('port', 0))
            if port and (port < 1024 or port > 65000):
                threats.append("unusual_port_number")
                threat_score += 0.2
        except:
            pass
            
        # Check for private/local IP ranges (potential evil twin)
        if address:
            if (address.startswith('192.168.') or 
                address.startswith('10.') or 
                address.startswith('172.')):
                threats.append("private_ip_range")
                threat_score += 0.1
                
        return threats, min(threat_score, 1.0)
        
    def send_to_elasticsearch(self, detection_data):
        """Send AirDrop threat detection to Elasticsearch"""
        try:
            doc = {
                'timestamp': detection_data['timestamp'],
                'source': 'airdrop_threat_detector',
                'log_type': 'airdrop_threat_detection',
                'service_name': detection_data['service']['name'],
                'service_address': detection_data['service']['address'],
                'threat_score': detection_data['threat_score'],
                'threats_detected': detection_data['threats'],
                'service_info': detection_data['service'],
                'message': detection_data['message']
            }
            
            response = requests.post(
                'http://localhost:9200/honeypot-logs-new/_doc',
                json=doc,
                timeout=5
            )
            
            if response.status_code in [200, 201]:
                print(f"✅ AirDrop threat logged to Elasticsearch")
            else:
                print(f"❌ Failed to log AirDrop threat: {response.status_code}")
                
        except Exception as e:
            print(f"❌ Elasticsearch error: {e}")
            
    def get_threat_level(self, score):
        """Get threat level indicator"""
        if score >= 0.7:
            return "🚨 CRITICAL"
        elif score >= 0.5:
            return "⚠️ HIGH"
        elif score >= 0.3:
            return "🟡 MEDIUM"
        else:
            return "🟢 LOW"
            
    def monitor_airdrop_threats(self):
        """Main AirDrop threat monitoring loop"""
        print("📱 Starting AirDrop Threat Detection...")
        print("🔍 Monitoring for AirDrop abuse and proximity attacks...")
        print("💡 Suspicious AirDrop services and payloads will be detected")
        print("🛑 Press Ctrl+C to stop")
        
        try:
            while True:
                print(f"\n📱 Scanning AirDrop services... ({datetime.now().strftime('%H:%M:%S')})")
                
                # Scan for AirDrop services
                services = self.scan_airdrop_services()
                print(f"🔍 Found {len(services)} AirDrop services")
                
                # Analyze each service for threats
                for service in services:
                    threats, threat_score = self.analyze_airdrop_threats(service)
                    
                    if threat_score > 0.2:  # Only log significant threats
                        threat_level = self.get_threat_level(threat_score)
                        name = service.get('name', 'Unknown')
                        address = service.get('address', 'Unknown')
                        
                        print(f"  {threat_level} {name} ({address})")
                        print(f"    Threats: {', '.join(threats)}")
                        
                        # Log to Elasticsearch
                        detection_data = {
                            'timestamp': datetime.utcnow().isoformat(),
                            'service': service,
                            'threat_score': threat_score,
                            'threats': threats,
                            'message': f"AirDrop threat detected: {name} - {', '.join(threats)}"
                        }
                        
                        self.send_to_elasticsearch(detection_data)
                        
                # Update known services
                for service in services:
                    service_key = f"{service.get('address', '')}:{service.get('port', '')}"
                    self.known_services[service_key] = service
                    
                # Wait before next scan
                time.sleep(60)  # Scan every 60 seconds
                
        except KeyboardInterrupt:
            print("\n🛑 AirDrop threat monitoring stopped")

if __name__ == "__main__":
    detector = AirDropThreatDetector()
    detector.monitor_airdrop_threats()
