#!/usr/bin/env python3
"""
WiFi Threat Detection System - Phase 3A (Noise Reduced)
Detects wireless attacks and suspicious activity with intelligent filtering
"""
import subprocess
import time
import json
import requests
import re
import hashlib
from datetime import datetime, timedelta
from collections import defaultdict, deque

class WiFiThreatDetector:
    def __init__(self, interface=None):
        self.interface = interface or self.detect_wifi_interface()
        self.known_networks = {}
        self.beacon_rates = defaultdict(deque)
        self.probe_requests = defaultdict(list)
        self.deauth_counts = defaultdict(int)
        
        # Threat deduplication and rate limiting
        self.recent_threats = {}  # hash -> timestamp
        self.threat_cooldown = 300  # 5 minutes between duplicate alerts
        self.network_whitelist = set()  # Trusted network BSSIDs
        self.ssid_whitelist = set()    # Trusted SSIDs
        
        # Suspicious patterns
        self.suspicious_ssids = [
            'free wifi', 'free_wifi', 'freewifi', 'public',
            'guest', 'hotel', 'airport', 'starbucks',
            'mcdonalds', 'attwifi', 'xfinitywifi'
            # Removed common router names as they're often legitimate
        ]
        
        # Load whitelists from config if exists
        self.load_whitelist_config()
        
    def load_whitelist_config(self):
        """Load whitelist configuration from file"""
        try:
            with open('/home/burner/honeypot-minimal/wifi_whitelist.json', 'r') as f:
                config = json.load(f)
                self.network_whitelist.update(config.get('bssid_whitelist', []))
                self.ssid_whitelist.update(config.get('ssid_whitelist', []))
                print(f"📋 Loaded {len(self.network_whitelist)} whitelisted BSSIDs and {len(self.ssid_whitelist)} SSIDs")
        except FileNotFoundError:
            # Create default whitelist config
            default_config = {
                "bssid_whitelist": [],
                "ssid_whitelist": [
                    "eduroam",  # Common enterprise WiFi
                    "Guest Network",
                    "Visitor"
                ],
                "note": "Add trusted network BSSIDs and SSIDs to reduce false positives"
            }
            with open('/home/burner/honeypot-minimal/wifi_whitelist.json', 'w') as f:
                json.dump(default_config, f, indent=2)
            print("📋 Created default whitelist config at wifi_whitelist.json")
        except Exception as e:
            print(f"⚠️ Error loading whitelist: {e}")
    
    def detect_wifi_interface(self):
        """Auto-detect available WiFi interface"""
        try:
            result = subprocess.run(['iw', 'dev'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if 'Interface' in line:
                    interface = line.split()[-1]
                    return interface
        except:
            pass
        return None
        
    def scan_networks(self):
        """Scan for WiFi networks using iwlist"""
        networks = []
        
        if not self.interface:
            return networks
            
        try:
            # Use iwlist for scanning
            result = subprocess.run(
                ['sudo', 'iwlist', self.interface, 'scan'],
                capture_output=True, text=True, timeout=30
            )
            
            current_network = {}
            
            for line in result.stdout.split('\n'):
                line = line.strip()
                
                # New cell (network)
                if 'Cell' in line and 'Address:' in line:
                    if current_network:
                        networks.append(current_network)
                    current_network = {
                        'bssid': line.split('Address: ')[1].strip(),
                        'ssid': '',
                        'frequency': '',
                        'signal': '',
                        'security': [],
                        'timestamp': datetime.utcnow().isoformat()
                    }
                    
                # SSID/ESSID
                elif 'ESSID:' in line:
                    essid = line.split('ESSID:')[1].strip().strip('"')
                    current_network['ssid'] = essid
                    
                # Frequency
                elif 'Frequency:' in line:
                    freq = line.split('Frequency:')[1].split()[0]
                    current_network['frequency'] = freq
                    
                # Signal strength
                elif 'Signal level=' in line:
                    signal = line.split('Signal level=')[1].split()[0]
                    current_network['signal'] = signal
                    
                # Security
                elif 'WPA' in line:
                    if 'WPA' not in current_network['security']:
                        current_network['security'].append('WPA')
                elif 'WEP' in line:
                    if 'WEP' not in current_network['security']:
                        current_network['security'].append('WEP')
                elif 'RSN' in line:
                    if 'WPA2/WPA3' not in current_network['security']:
                        current_network['security'].append('WPA2/WPA3')
                        
            # Add the last network
            if current_network:
                networks.append(current_network)
                
        except subprocess.TimeoutExpired:
            print("⚠️ WiFi scan timeout")
        except Exception as e:
            print(f"❌ WiFi scan error: {e}")
            
        return networks
    
    def create_threat_hash(self, network, threat_type):
        """Create a unique hash for threat deduplication"""
        threat_string = f"{network['bssid']}:{network['ssid']}:{threat_type}"
        return hashlib.md5(threat_string.encode()).hexdigest()
    
    def is_threat_duplicate(self, threat_hash):
        """Check if this threat was recently reported"""
        now = datetime.utcnow()
        
        if threat_hash in self.recent_threats:
            last_seen = datetime.fromisoformat(self.recent_threats[threat_hash])
            if (now - last_seen).total_seconds() < self.threat_cooldown:
                return True
        
        self.recent_threats[threat_hash] = now.isoformat()
        return False
    
    def is_whitelisted(self, network):
        """Check if network is whitelisted"""
        bssid = network.get('bssid', '').lower()
        ssid = network.get('ssid', '').lower()
        
        return (bssid in self.network_whitelist or 
                ssid in self.ssid_whitelist)
    
    def analyze_network_threats(self, network):
        """Analyze individual network for threats with reduced false positives"""
        threats = []
        threat_score = 0.0
        
        # Skip whitelisted networks
        if self.is_whitelisted(network):
            return threats, threat_score
        
        ssid = network.get('ssid', '').lower()
        bssid = network.get('bssid', '')
        security = network.get('security', [])
        
        # Check for suspicious SSID names (more selective)
        for suspicious in self.suspicious_ssids:
            if suspicious in ssid and len(ssid) < 20:  # Avoid matching partial legitimate names
                threat_type = f"suspicious_ssid_{suspicious.replace(' ', '_')}"
                threat_hash = self.create_threat_hash(network, threat_type)
                
                if not self.is_threat_duplicate(threat_hash):
                    threats.append(threat_type)
                    threat_score += 0.4
                
        # Check for evil twin (improved logic - only once per SSID pair)
        if network['ssid'] and len(network['ssid']) > 2:  # Only for non-empty, meaningful SSIDs
            evil_twin_detected = False
            for known_bssid, known_network in self.known_networks.items():
                if (known_network['ssid'] == network['ssid'] and 
                    known_bssid != bssid):
                    evil_twin_detected = True
                    break
            
            if evil_twin_detected:
                threat_hash = self.create_threat_hash(network, "evil_twin_same_ssid")
                if not self.is_threat_duplicate(threat_hash):
                    threats.append("evil_twin_same_ssid")
                    threat_score += 0.8  # Higher score for this serious threat
                
        # Check for weak security (but less aggressive)
        if 'WEP' in security:  # Only WEP is truly weak, open networks are often legitimate
            threat_hash = self.create_threat_hash(network, "weak_encryption_wep")
            if not self.is_threat_duplicate(threat_hash):
                threats.append("weak_encryption_wep")
                threat_score += 0.3
            
        # Check for unusual signal strength patterns (suspicious proximity)
        try:
            signal = float(network.get('signal', 0))
            if signal > -10:  # Very strong signal (likely very close/malicious)
                threat_hash = self.create_threat_hash(network, "suspicious_proximity")
                if not self.is_threat_duplicate(threat_hash):
                    threats.append("suspicious_proximity")
                    threat_score += 0.3
        except:
            pass
            
        # Only flag hidden SSIDs if they have other suspicious characteristics
        if not ssid and len(security) == 0:  # Hidden AND open = suspicious
            threat_hash = self.create_threat_hash(network, "hidden_open_network")
            if not self.is_threat_duplicate(threat_hash):
                threats.append("hidden_open_network")
                threat_score += 0.2
                
        return threats, min(threat_score, 1.0)
        
    def detect_beacon_flooding(self, networks):
        """Detect beacon flooding attacks with improved thresholds"""
        current_time = time.time()
        flooding_networks = []
        
        for network in networks:
            bssid = network['bssid']
            
            # Track beacon timestamps
            self.beacon_rates[bssid].append(current_time)
            
            # Remove old timestamps (>60 seconds)
            while (self.beacon_rates[bssid] and 
                   current_time - self.beacon_rates[bssid][0] > 60):
                self.beacon_rates[bssid].popleft()
                
            # Check for flooding (>100 beacons per minute - increased threshold)
            if len(self.beacon_rates[bssid]) > 100:
                threat_hash = self.create_threat_hash(network, "beacon_flooding")
                if not self.is_threat_duplicate(threat_hash):
                    flooding_networks.append({
                        'bssid': bssid,
                        'ssid': network.get('ssid', 'Hidden'),
                        'beacon_rate': len(self.beacon_rates[bssid]),
                        'threat_type': 'beacon_flooding'
                    })
                
        return flooding_networks
        
    def send_to_elasticsearch(self, detection_data):
        """Send WiFi threat detection to Elasticsearch"""
        try:
            doc = {
                'timestamp': detection_data['timestamp'],
                'honeypot_id': 'honeyman-01',
                'source': 'wifi_threat_detector',
                'log_type': 'wifi_threat_detection',
                'interface': self.interface,
                'detection_type': detection_data['type'],
                'threat_score': detection_data['threat_score'],
                'threats_detected': detection_data['threats'],
                'network_info': detection_data['network_info'],
                'message': detection_data['message']
            }
            
            response = requests.post(
                'http://localhost:9200/honeypot-logs-new/_doc',
                json=doc,
                timeout=5
            )
            
            if response.status_code in [200, 201]:
                print(f"✅ WiFi threat logged to Elasticsearch")
            else:
                print(f"❌ Failed to log WiFi threat: {response.status_code}")
                
        except Exception as e:
            print(f"❌ Elasticsearch error: {e}")
            
    def get_threat_level(self, score):
        """Get threat level indicator"""
        if score >= 0.8:
            return "🚨 CRITICAL"
        elif score >= 0.6:
            return "⚠️ HIGH"
        elif score >= 0.4:
            return "🟡 MEDIUM"
        else:
            return "🟢 LOW"
    
    def cleanup_old_threats(self):
        """Clean up old threat tracking data"""
        now = datetime.utcnow()
        cutoff = now - timedelta(hours=1)  # Clean threats older than 1 hour
        
        # Clean recent threats
        to_remove = []
        for threat_hash, timestamp_str in self.recent_threats.items():
            if datetime.fromisoformat(timestamp_str) < cutoff:
                to_remove.append(threat_hash)
        
        for threat_hash in to_remove:
            del self.recent_threats[threat_hash]
            
    def monitor_wifi_threats(self):
        """Main WiFi threat monitoring loop with noise reduction"""
        print(f"📡 Starting WiFi Threat Detection (Noise Reduced)...")
        
        if not self.interface:
            print("❌ No WiFi interface available")
            return
            
        print(f"🔍 Monitoring interface: {self.interface}")
        print(f"⏱️ Threat cooldown: {self.threat_cooldown}s")
        print(f"📋 Whitelisted: {len(self.network_whitelist)} BSSIDs, {len(self.ssid_whitelist)} SSIDs")
        print("💡 Scanning for wireless threats...")
        print("🛑 Press Ctrl+C to stop")
        
        scan_count = 0
        try:
            while True:
                scan_count += 1
                print(f"\n📡 Scanning networks... ({datetime.now().strftime('%H:%M:%S')}) [Scan #{scan_count}]")
                
                # Clean up old data every 10 scans
                if scan_count % 10 == 0:
                    self.cleanup_old_threats()
                    print(f"🧹 Cleaned {len(self.recent_threats)} tracked threats")
                
                # Scan for networks
                networks = self.scan_networks()
                print(f"🔍 Found {len(networks)} networks")
                
                threats_found = 0
                # Analyze each network for threats
                for network in networks:
                    threats, threat_score = self.analyze_network_threats(network)
                    
                    if threats:
                        threats_found += 1
                        threat_level = self.get_threat_level(threat_score)
                        ssid = network.get('ssid', 'Hidden')
                        bssid = network.get('bssid', 'Unknown')
                        
                        print(f"  {threat_level} {ssid} ({bssid})")
                        print(f"    Threats: {', '.join(threats)}")
                        
                        # Log to Elasticsearch
                        detection_data = {
                            'timestamp': datetime.utcnow().isoformat(),
                            'type': 'suspicious_network',
                            'threat_score': threat_score,
                            'threats': threats,
                            'network_info': network,
                            'message': f"Suspicious WiFi network detected: {ssid} - {', '.join(threats)}"
                        }
                        
                        self.send_to_elasticsearch(detection_data)
                        
                # Check for beacon flooding
                flooding = self.detect_beacon_flooding(networks)
                for flood_network in flooding:
                    threats_found += 1
                    print(f"  🚨 CRITICAL Beacon flooding: {flood_network['ssid']} ({flood_network['beacon_rate']} beacons/min)")
                    
                    detection_data = {
                        'timestamp': datetime.utcnow().isoformat(),
                        'type': 'beacon_flooding',
                        'threat_score': 0.9,
                        'threats': ['beacon_flooding'],
                        'network_info': flood_network,
                        'message': f"Beacon flooding attack detected: {flood_network['beacon_rate']} beacons/min"
                    }
                    
                    self.send_to_elasticsearch(detection_data)
                    
                print(f"⚡ {threats_found} new threats detected in this scan")
                    
                # Update known networks
                for network in networks:
                    self.known_networks[network['bssid']] = network
                    
                # Wait before next scan (reduced frequency)
                time.sleep(15)  # Increased from default to reduce log volume
                
        except KeyboardInterrupt:
            print("\n🛑 WiFi threat monitoring stopped")
            print(f"📊 Total scans performed: {scan_count}")
            
    def monitor_network_only(self):
        """Fallback monitoring when no WiFi interface available"""
        print("🔍 Monitoring network connections...")
        try:
            while True:
                # Monitor network connections, ARP tables, etc.
                time.sleep(30)
                print("📊 Network monitoring active...")
        except KeyboardInterrupt:
            print("\n🛑 Network monitoring stopped")

if __name__ == "__main__":
    detector = WiFiThreatDetector()
    detector.monitor_wifi_threats()